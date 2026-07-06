"""Tests for Domain Intelligence Adapter (DIA) — Sprint 7."""

from __future__ import annotations

import json
import pytest

from combatpair.brain.domain_intelligence import (
    McpServerConfig,
    DiaResult,
    DomainIntelligenceAdapter,
    call_mcp_tool,
    parse_mcp_servers_from_yaml,
    _format_mcp_result,
)


# ── McpServerConfig ────────────────────────────────────────────────────────────

def test_mcp_server_config_defaults():
    s = McpServerConfig(name="test", url="http://localhost:8080/mcp", tool="get_threats")
    assert s.enabled is True
    assert s.params == {}


def test_mcp_server_config_disabled():
    s = McpServerConfig(name="test", url="http://x", tool="t", enabled=False)
    assert s.enabled is False


# ── DiaResult ──────────────────────────────────────────────────────────────────

def test_dia_result_success():
    r = DiaResult(server="test", tool="get_threats", enrichment="some intel")
    assert r.success is True


def test_dia_result_failure():
    r = DiaResult(server="test", tool="get_threats", enrichment="", error="timeout")
    assert r.success is False


# ── _format_mcp_result ─────────────────────────────────────────────────────────

def test_format_mcp_result_string():
    text = _format_mcp_result("fin-intel", "get_threats", "Active CVE: CVE-2026-1234")
    assert "fin-intel" in text
    assert "CVE-2026-1234" in text
    assert "---" in text


def test_format_mcp_result_dict_with_content():
    result = {"content": [{"type": "text", "text": "Threat: SQL injection wave"}]}
    text = _format_mcp_result("server", "tool", result)
    assert "Threat: SQL injection wave" in text


def test_format_mcp_result_empty_returns_empty():
    text = _format_mcp_result("server", "tool", "")
    assert text == ""


def test_format_mcp_result_truncates_long_content():
    long_text = "A" * 5000
    text = _format_mcp_result("server", "tool", long_text)
    # Should not exceed much more than 2000 chars of content
    assert len(text) < 3000


# ── call_mcp_tool ──────────────────────────────────────────────────────────────

def test_call_mcp_tool_disabled():
    server = McpServerConfig(name="test", url="http://x", tool="t", enabled=False)
    result = call_mcp_tool(server)
    assert result.success is False
    assert result.error == "disabled"


def test_call_mcp_tool_network_error(monkeypatch):
    import httpx

    def bad_post(url, json, headers, timeout):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", bad_post)
    server = McpServerConfig(name="test", url="http://localhost:9999/mcp", tool="t")
    result = call_mcp_tool(server)
    assert result.success is False
    assert result.error != ""


def test_call_mcp_tool_success(monkeypatch):
    import httpx

    def mock_post(url, json, headers, timeout):
        class FakeResp:
            def raise_for_status(self): pass
            def json(self):
                return {
                    "jsonrpc": "2.0", "id": 1,
                    "result": {"content": [{"type": "text", "text": "CVE-2026-9999 active"}]},
                }
        return FakeResp()

    monkeypatch.setattr(httpx, "post", mock_post)
    server = McpServerConfig(name="fin-intel", url="http://mcp.example.com/mcp", tool="get_threats")
    result = call_mcp_tool(server)
    assert result.success is True
    assert "CVE-2026-9999" in result.enrichment


def test_call_mcp_tool_mcp_error_response(monkeypatch):
    import httpx

    def mock_post(url, json, headers, timeout):
        class FakeResp:
            def raise_for_status(self): pass
            def json(self):
                return {"jsonrpc": "2.0", "id": 1, "error": {"message": "tool not found"}}
        return FakeResp()

    monkeypatch.setattr(httpx, "post", mock_post)
    server = McpServerConfig(name="test", url="http://x/mcp", tool="bad_tool")
    result = call_mcp_tool(server)
    assert result.success is False
    assert "tool not found" in result.error


def test_call_mcp_tool_sends_correct_jsonrpc_payload(monkeypatch):
    import httpx
    captured = {}

    def mock_post(url, json, headers, timeout):
        captured["payload"] = json
        class FakeResp:
            def raise_for_status(self): pass
            def json(self): return {"jsonrpc": "2.0", "id": 1, "result": "ok"}
        return FakeResp()

    monkeypatch.setattr(httpx, "post", mock_post)
    server = McpServerConfig(
        name="test", url="http://x/mcp", tool="get_finra_threats",
        params={"sector": "broker-dealer"}
    )
    call_mcp_tool(server)
    p = captured["payload"]
    assert p["method"] == "tools/call"
    assert p["params"]["name"] == "get_finra_threats"
    assert p["params"]["arguments"] == {"sector": "broker-dealer"}


# ── parse_mcp_servers_from_yaml ────────────────────────────────────────────────

def test_parse_mcp_servers_empty():
    assert parse_mcp_servers_from_yaml([]) == []


def test_parse_mcp_servers_from_yaml_parses_fields():
    raw = [
        {"name": "fin-intel", "url": "http://x/mcp", "tool": "threats",
         "params": {"sector": "fintech"}, "enabled": True},
    ]
    servers = parse_mcp_servers_from_yaml(raw)
    assert len(servers) == 1
    assert servers[0].name == "fin-intel"
    assert servers[0].params == {"sector": "fintech"}


def test_parse_mcp_servers_defaults_enabled():
    raw = [{"name": "x", "url": "http://x/mcp", "tool": "t"}]
    servers = parse_mcp_servers_from_yaml(raw)
    assert servers[0].enabled is True


def test_parse_mcp_servers_none_returns_empty():
    assert parse_mcp_servers_from_yaml(None) == []  # type: ignore


# ── DomainIntelligenceAdapter ──────────────────────────────────────────────────

def test_dia_no_servers_returns_base_context():
    dia = DomainIntelligenceAdapter([])
    context, results = dia.enrich("base policy context")
    assert context == "base policy context"
    assert results == []


def test_dia_available_servers_lists_enabled():
    servers = [
        McpServerConfig("a", "http://a/mcp", "t", enabled=True),
        McpServerConfig("b", "http://b/mcp", "t", enabled=False),
    ]
    dia = DomainIntelligenceAdapter(servers)
    assert dia.available_servers() == ["a"]


def test_dia_enrich_appends_enrichment(monkeypatch):
    def mock_call(server):
        return DiaResult(server=server.name, tool=server.tool,
                         enrichment=f"Intel from {server.name}", error="")

    monkeypatch.setattr("combatpair.brain.domain_intelligence.call_mcp_tool", mock_call)

    dia = DomainIntelligenceAdapter([
        McpServerConfig("fin-intel", "http://x/mcp", "threats"),
    ])
    context, results = dia.enrich("base policy")
    assert "Intel from fin-intel" in context
    assert len(results) == 1
    assert results[0].success is True


def test_dia_enrich_skips_failed_servers(monkeypatch):
    def mock_call(server):
        return DiaResult(server=server.name, tool=server.tool,
                         enrichment="", error="timeout")

    monkeypatch.setattr("combatpair.brain.domain_intelligence.call_mcp_tool", mock_call)

    dia = DomainIntelligenceAdapter([
        McpServerConfig("bad-server", "http://x/mcp", "t"),
    ])
    context, results = dia.enrich("base policy")
    assert context == "base policy"  # unchanged — no enrichment from failed server
    assert results[0].success is False


def test_dia_enrich_multiple_servers(monkeypatch):
    def mock_call(server):
        return DiaResult(server=server.name, tool=server.tool,
                         enrichment=f"[{server.name}] threat data", error="")

    monkeypatch.setattr("combatpair.brain.domain_intelligence.call_mcp_tool", mock_call)

    dia = DomainIntelligenceAdapter([
        McpServerConfig("server-a", "http://a/mcp", "t"),
        McpServerConfig("server-b", "http://b/mcp", "t"),
    ])
    context, results = dia.enrich("base")
    assert "[server-a]" in context
    assert "[server-b]" in context
    assert len(results) == 2


# ── Config integration ─────────────────────────────────────────────────────────

def test_config_mcp_servers_default_empty():
    from combatpair.config import AppConfig
    cfg = AppConfig()
    assert cfg.mcp_servers == []


def test_config_mcp_servers_loadable():
    import tempfile, os
    from combatpair.config import AppConfig

    yaml_content = """\
version: 1
mcp_servers:
  - name: fin-intel
    url: http://localhost:8090/mcp
    tool: get_finra_threats
    params:
      sector: broker-dealer
    enabled: true
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        tmp = f.name
    try:
        cfg = AppConfig.load(tmp)
        assert len(cfg.mcp_servers) == 1
        assert cfg.mcp_servers[0]["name"] == "fin-intel"
        assert cfg.mcp_servers[0]["tool"] == "get_finra_threats"
    finally:
        os.unlink(tmp)


def test_dia_from_config_no_servers():
    from combatpair.config import AppConfig
    cfg = AppConfig()
    dia = DomainIntelligenceAdapter.from_config(cfg)
    assert dia.available_servers() == []
