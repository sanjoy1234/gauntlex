"""Tests for GAUNTLEX MCP Server — Sprint A."""

from __future__ import annotations

import asyncio
import json
import pytest

from gauntlex.mcp.server import MCPServer, _McpError, _eta, _ATTACK_COUNTS, _TOOLS


# ── Helpers ────────────────────────────────────────────────────────────────────

async def _fake_engine(run_id, spec, mode, domain, language, config, consensus_samples=1):
    """Instant mock engine — returns a minimal result dict without LLM calls."""
    return {
        "run_id": run_id,
        "status": "complete",
        "ars": 0.87,
        "passed": True,
        "gate_threshold": 0.80,
        "attack_count": 5,
        "miss_count": 1,
        "elapsed_seconds": 1.2,
        "attacks": [
            {"cwe": "CWE-89", "title": "SQL injection", "description": "sqli", "score": 1.0, "verdict": "mitigated", "severity": "high"},
            {"cwe": "CWE-79", "title": "XSS", "description": "xss", "score": 0.0, "verdict": "missed", "severity": "medium"},
        ],
    }

async def _error_engine(run_id, spec, mode, domain, language, config, consensus_samples=1):
    raise RuntimeError("engine exploded")


def _server(engine=None, config=None):
    from gauntlex.config import AppConfig, DeploymentConfig
    cfg = config if config is not None else AppConfig(deployment=DeploymentConfig(model_provider="local"))
    return MCPServer(config=cfg, engine_fn=engine or _fake_engine)


# ── Protocol / initialize ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_initialize_returns_protocol_version():
    s = _server()
    resp = await s.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "gauntlex"


@pytest.mark.asyncio
async def test_initialize_contains_tools_capability():
    s = _server()
    resp = await s.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert "tools" in resp["result"]["capabilities"]


@pytest.mark.asyncio
async def test_unknown_method_returns_error():
    s = _server()
    resp = await s.handle_message({"jsonrpc": "2.0", "id": 2, "method": "unknown/method", "params": {}})
    assert "error" in resp
    assert resp["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_notification_returns_empty_result():
    s = _server()
    resp = await s.handle_message({"jsonrpc": "2.0", "id": 3, "method": "notifications/initialized", "params": {}})
    assert resp["result"] == {}


# ── tools/list ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tools_list_returns_all_five_tools():
    s = _server()
    resp = await s.handle_message({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}})
    tools = resp["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {"gauntlex_run", "gauntlex_status", "gauntlex_vault_stats", "gauntlex_policy_list", "gauntlex_verify"}


@pytest.mark.asyncio
async def test_tools_list_each_has_input_schema():
    s = _server()
    resp = await s.handle_message({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}})
    for tool in resp["result"]["tools"]:
        assert "inputSchema" in tool, f"{tool['name']} missing inputSchema"
        assert "description" in tool, f"{tool['name']} missing description"


@pytest.mark.asyncio
async def test_gauntlex_run_has_required_spec_field():
    s = _server()
    resp = await s.handle_message({"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": {}})
    run_tool = next(t for t in resp["result"]["tools"] if t["name"] == "gauntlex_run")
    assert "spec" in run_tool["inputSchema"]["required"]


# ── gauntlex_run ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gauntlex_run_returns_run_id():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 10,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": "Build a login endpoint"}},
    })
    result = resp["result"]
    assert result["run_id"].startswith("gauntlex-mcp-")
    assert result["status"] == "started"


@pytest.mark.asyncio
async def test_gauntlex_run_consensus_samples_reaches_engine():
    """Regression: consensus_samples from tool arguments must actually reach
    the engine call, not just be accepted and dropped."""
    received = {}

    async def _recording_engine(run_id, spec, mode, domain, language, config, consensus_samples=1):
        received["consensus_samples"] = consensus_samples
        return await _fake_engine(run_id, spec, mode, domain, language, config,
                                   consensus_samples=consensus_samples)

    s = _server(engine=_recording_engine)
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 10,
        "method": "tools/call",
        "params": {
            "name": "gauntlex_run",
            "arguments": {"spec": "Build a login endpoint", "consensus_samples": 3},
        },
    })
    run_id = resp["result"]["run_id"]
    await s._tasks[run_id]  # let the task actually run before asserting
    assert received["consensus_samples"] == 3


@pytest.mark.asyncio
async def test_gauntlex_run_consensus_samples_defaults_to_one():
    received = {}

    async def _recording_engine(run_id, spec, mode, domain, language, config, consensus_samples=1):
        received["consensus_samples"] = consensus_samples
        return await _fake_engine(run_id, spec, mode, domain, language, config,
                                   consensus_samples=consensus_samples)

    s = _server(engine=_recording_engine)
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 10,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": "Build a login endpoint"}},
    })
    run_id = resp["result"]["run_id"]
    await s._tasks[run_id]
    assert received["consensus_samples"] == 1


@pytest.mark.asyncio
async def test_gauntlex_run_empty_spec_returns_error():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 11,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": ""}},
    })
    assert "error" in resp
    assert resp["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_gauntlex_run_no_provider_configured_returns_clear_error():
    """Regression: gauntlex_run must never silently fall back to Ollama when no
    model provider has been configured (via .env / .gauntlex.yml / `gauntlex
    setup`) — it should fail immediately with an actionable message, not start
    a task that only fails later when polled via gauntlex_status."""
    from gauntlex.config import AppConfig
    s = _server(config=AppConfig())  # bare config: no provider configured
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 10.5,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": "Build a login form"}},
    })
    assert "error" in resp
    assert "result" not in resp
    assert "No model provider is configured" in resp["error"]["message"]
    assert "gauntlex setup" in resp["error"]["message"]


@pytest.mark.asyncio
async def test_gauntlex_run_missing_spec_returns_error():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 12,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {}},
    })
    assert "error" in resp


@pytest.mark.asyncio
async def test_gauntlex_run_invalid_mode_defaults_to_quick():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 13,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": "spec text", "mode": "ultrafast"}},
    })
    # should succeed with mode normalised to quick
    assert "run_id" in resp["result"]


@pytest.mark.asyncio
async def test_gauntlex_run_content_includes_run_id():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 14,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": "Build a user profile API"}},
    })
    run_id = resp["result"]["run_id"]
    content_text = resp["result"]["content"][0]["text"]
    assert run_id in content_text


# ── gauntlex_status ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gauntlex_status_running_before_completion():
    s = _server()
    # Start a run (engine returns instantly but task hasn't been awaited yet)
    run_resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 20,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": "Build an API", "mode": "quick"}},
    })
    run_id = run_resp["result"]["run_id"]

    # Poll immediately — may be running or complete depending on task scheduling
    status_resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 21,
        "method": "tools/call",
        "params": {"name": "gauntlex_status", "arguments": {"run_id": run_id}},
    })
    assert status_resp["result"]["run_id"] == run_id
    assert status_resp["result"]["status"] in ("running", "complete")


@pytest.mark.asyncio
async def test_gauntlex_status_complete_after_await():
    s = _server()
    run_resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 22,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": "Build a payment API"}},
    })
    run_id = run_resp["result"]["run_id"]

    # Let the fake engine task complete
    await asyncio.sleep(0.05)

    status_resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 23,
        "method": "tools/call",
        "params": {"name": "gauntlex_status", "arguments": {"run_id": run_id}},
    })
    assert status_resp["result"]["status"] == "complete"
    result = status_resp["result"]["result"]
    assert result["ars"] == pytest.approx(0.87)
    assert result["passed"] is True


@pytest.mark.asyncio
async def test_gauntlex_status_unknown_run_id_returns_error():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 24,
        "method": "tools/call",
        "params": {"name": "gauntlex_status", "arguments": {"run_id": "nonexistent-run-id"}},
    })
    assert "error" in resp
    assert resp["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_gauntlex_status_engine_error_surfaced():
    s = _server(engine=_error_engine)
    run_resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 25,
        "method": "tools/call",
        "params": {"name": "gauntlex_run", "arguments": {"spec": "error spec"}},
    })
    run_id = run_resp["result"]["run_id"]
    await asyncio.sleep(0.05)

    status_resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 26,
        "method": "tools/call",
        "params": {"name": "gauntlex_status", "arguments": {"run_id": run_id}},
    })
    assert status_resp["result"]["status"] == "error"


# ── gauntlex_vault_stats ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vault_stats_no_vault_returns_zero(tmp_path, monkeypatch):
    # _tool_vault_stats reads .gauntlex/vault relative to cwd (not injectable via
    # config), so this must run somewhere guaranteed vault-free rather than
    # relying on the ambient repo having no vault data — that assumption broke
    # the moment `gauntlex vault` was fixed to actually get populated by real runs.
    monkeypatch.chdir(tmp_path)
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 30,
        "method": "tools/call",
        "params": {"name": "gauntlex_vault_stats", "arguments": {}},
    })
    stats = resp["result"]["stats"]
    assert stats["total"] == 0
    assert stats["by_cwe"] == {}


@pytest.mark.asyncio
async def test_vault_stats_has_content_key():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 31,
        "method": "tools/call",
        "params": {"name": "gauntlex_vault_stats", "arguments": {}},
    })
    assert "content" in resp["result"]
    assert resp["result"]["content"][0]["type"] == "text"


# ── gauntlex_policy_list ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_policy_list_returns_seven_domains():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 40,
        "method": "tools/call",
        "params": {"name": "gauntlex_policy_list", "arguments": {}},
    })
    domains = resp["result"]["domains"]
    assert len(domains) == 7


@pytest.mark.asyncio
async def test_policy_list_includes_hipaa_and_finra():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 41,
        "method": "tools/call",
        "params": {"name": "gauntlex_policy_list", "arguments": {}},
    })
    names = {d["name"] for d in resp["result"]["domains"]}
    assert "hipaa" in names
    assert "finra" in names
    assert "pci_dss" in names
    assert "nist_ssdf" in names


# ── gauntlex_verify ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_missing_run_id_returns_error():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 50,
        "method": "tools/call",
        "params": {"name": "gauntlex_verify", "arguments": {}},
    })
    assert "error" in resp
    assert resp["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_verify_nonexistent_report_returns_not_found():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 51,
        "method": "tools/call",
        "params": {"name": "gauntlex_verify", "arguments": {"run_id": "no-such-run"}},
    })
    assert resp["result"]["verified"] is False
    assert "not found" in resp["result"]["content"][0]["text"].lower()


# ── unknown tool ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unknown_tool_returns_error():
    s = _server()
    resp = await s.handle_message({
        "jsonrpc": "2.0", "id": 60,
        "method": "tools/call",
        "params": {"name": "gauntlex_nonexistent", "arguments": {}},
    })
    assert "error" in resp
    assert resp["error"]["code"] == -32601


# ── _eta helper ────────────────────────────────────────────────────────────────

def test_eta_quick():
    assert "45" in _eta("quick")

def test_eta_standard():
    assert "3" in _eta("standard")

def test_eta_thorough():
    assert "12" in _eta("thorough")

def test_eta_unknown_returns_string():
    assert isinstance(_eta("bogus"), str)


# ── attack counts ──────────────────────────────────────────────────────────────

def test_attack_counts_all_modes():
    assert _ATTACK_COUNTS["quick"] == 5
    assert _ATTACK_COUNTS["standard"] == 20
    assert _ATTACK_COUNTS["thorough"] == 50
