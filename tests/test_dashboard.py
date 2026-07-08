"""Tests for Combat Dashboard — Sprint 10."""

from __future__ import annotations

import json
from pathlib import Path

import os

from gauntlex.dashboard.app import (
    _load_active_runs,
    _load_all_reports,
    _render_index,
    create_app,
)
from gauntlex.config import AppConfig


# ── _load_all_reports ──────────────────────────────────────────────────────────

def test_load_all_reports_empty_dir(tmp_path):
    reports = _load_all_reports(tmp_path / "nonexistent")
    assert reports == []


def test_load_all_reports_reads_json(tmp_path):
    report = {
        "run_id": "gauntlex-test-001", "ars_score": 0.85,
        "attack_count": 5, "miss_count": 1, "generated_at": "2026-06-28T12:00:00Z",
    }
    (tmp_path / "gauntlex-test-001.json").write_text(json.dumps(report))
    reports = _load_all_reports(tmp_path)
    assert len(reports) == 1
    assert reports[0]["run_id"] == "gauntlex-test-001"


def test_load_all_reports_skips_corrupt_json(tmp_path):
    (tmp_path / "good.json").write_text('{"run_id": "good", "ars_score": 0.9, "attack_count": 3, "miss_count": 0}')
    (tmp_path / "bad.json").write_text("NOT JSON {{{")
    reports = _load_all_reports(tmp_path)
    assert len(reports) == 1
    assert reports[0]["run_id"] == "good"


def test_load_all_reports_respects_limit(tmp_path):
    for i in range(10):
        (tmp_path / f"run-{i:03d}.json").write_text(
            json.dumps({"run_id": f"run-{i:03d}", "ars_score": 0.8, "attack_count": 5, "miss_count": 0})
        )
    reports = _load_all_reports(tmp_path, limit=5)
    assert len(reports) == 5


# ── _load_active_runs ────────────────────────────────────────────────────────

def _make_run_state(run_id: str, status: str, pid: int, started_at: str = "2026-07-05T19:00:00+00:00",
                     issue: str = "demo_issue.md", mode: str = "quick") -> dict:
    return {"run_id": run_id, "status": status, "pid": pid, "started_at": started_at,
            "issue": issue, "mode": mode}


def test_load_active_runs_empty_dir(tmp_path):
    assert _load_active_runs(tmp_path / "nonexistent") == []


def test_load_active_runs_returns_running_with_live_pid(tmp_path):
    # Use this test process's own PID — guaranteed alive for the test's duration.
    (tmp_path / "run-a.json").write_text(
        json.dumps(_make_run_state("gauntlex-run-a", "running", os.getpid()))
    )
    active = _load_active_runs(tmp_path)
    assert len(active) == 1
    assert active[0]["run_id"] == "gauntlex-run-a"
    assert active[0]["issue"] == "demo_issue.md"
    assert active[0]["mode"] == "quick"


def test_load_active_runs_skips_dead_pid_and_cleans_up(tmp_path):
    # PID 999999 is extremely unlikely to be alive.
    state_file = tmp_path / "run-b.json"
    state_file.write_text(json.dumps(_make_run_state("gauntlex-run-b", "running", 999999)))
    active = _load_active_runs(tmp_path)
    assert active == []
    assert not state_file.exists()  # stale state file cleaned up


def test_load_active_runs_ignores_completed_status(tmp_path):
    (tmp_path / "run-c.json").write_text(
        json.dumps(_make_run_state("gauntlex-run-c", "completed", os.getpid()))
    )
    assert _load_active_runs(tmp_path) == []


def test_load_active_runs_skips_corrupt_json(tmp_path):
    (tmp_path / "bad.json").write_text("NOT JSON {{{")
    assert _load_active_runs(tmp_path) == []


# ── _render_index ──────────────────────────────────────────────────────────────

def _make_report(run_id: str, ars: float, attacks: int = 5, missed: int = 1) -> dict:
    return {
        "run_id": run_id,
        "ars_score": ars,
        "attack_count": attacks,
        "miss_count": missed,
        "generated_at": "2026-06-28T12:00:00Z",
    }


def test_render_index_is_html():
    cfg = AppConfig()
    html = _render_index([], cfg)
    assert "<!DOCTYPE html>" in html
    assert "</html>" in html


def test_render_index_shows_total_runs():
    cfg = AppConfig()
    reports = [_make_report(f"run-{i}", 0.85) for i in range(3)]
    html = _render_index(reports, cfg)
    assert "3" in html


def test_render_index_shows_gate_threshold():
    cfg = AppConfig()
    cfg.gate.minimum_ars = 0.80
    html = _render_index([], cfg)
    assert "0.80" in html


def test_render_index_shows_pass_fail_badges():
    cfg = AppConfig()
    reports = [
        _make_report("pass-run", 0.90),
        _make_report("fail-run", 0.50),
    ]
    html = _render_index(reports, cfg)
    assert "PASS" in html
    assert "BLOCKED" in html  # redesign: failed runs show BLOCKED not FAIL


def test_render_index_download_links_present():
    cfg = AppConfig()
    reports = [_make_report("my-run-id-12345", 0.85)]
    html = _render_index(reports, cfg)
    assert "/html" in html
    assert "/sarif" in html
    assert "/junit" in html


def test_render_index_empty_shows_empty_message():
    cfg = AppConfig()
    html = _render_index([], cfg)
    assert "No runs yet" in html


def test_render_index_has_bright_background():
    cfg = AppConfig()
    html = _render_index([], cfg)
    # Light theme — bright blue-white palette
    assert "#EFF6FF" in html or "#F0F7FF" in html or "#DBEAFE" in html
    assert "#1a1a1a" not in html  # not dark mode


def test_render_index_has_ars_trend_section():
    cfg = AppConfig()
    reports = [_make_report(f"run-{i}", 0.85) for i in range(5)]
    html = _render_index(reports, cfg)
    assert "ARS Trend" in html
    assert "sparkline" in html or "svg" in html.lower()


def test_render_index_shows_active_runs():
    cfg = AppConfig()
    active = [{"run_id": "gauntlex-active-001", "issue": "demo_issue.md",
               "mode": "quick", "elapsed_seconds": 72.0, "elapsed": "1m 12s"}]
    html = _render_index([], cfg, active)
    assert "RUNNING" in html
    assert "Active Runs (1)" in html
    assert "1m 12s" in html


def test_render_index_no_active_runs_shows_nothing_extra():
    cfg = AppConfig()
    html = _render_index([], cfg, [])
    assert "Active Runs" not in html
    assert "RUNNING" not in html


def test_render_index_warns_when_no_project_found():
    """cfg.config_source is None when no .gauntlex.yml was found anywhere up the
    tree — the dashboard must warn loudly instead of silently showing 0 runs."""
    cfg = AppConfig()
    assert cfg.config_source is None
    html = _render_index([], cfg, [])
    assert "No GAUNTLEX project found" in html


def test_render_index_no_warning_when_project_found(tmp_path):
    cfg = AppConfig()
    cfg.config_source = tmp_path / ".gauntlex.yml"
    html = _render_index([], cfg, [])
    assert "No GAUNTLEX project found" not in html


def test_render_index_chart_data_is_valid_json():
    cfg = AppConfig()
    reports = [_make_report(f"run-{i}", 0.8 + i * 0.01) for i in range(3)]
    html = _render_index(reports, cfg)
    # Extract the chart JSON from the rendered HTML
    import re
    match = re.search(r"var data = (\[.*?\]);", html, re.DOTALL)
    assert match is not None
    data = json.loads(match.group(1))
    assert len(data) == 3
    assert all("x" in d and "y" in d for d in data)


# ── create_app (structure only — no live server) ───────────────────────────────

def test_create_app_requires_fastapi(monkeypatch):
    """If FastAPI is not installed, create_app should raise RuntimeError."""
    import gauntlex.dashboard.app as dash_module
    monkeypatch.setattr(dash_module, "_FASTAPI_AVAILABLE", False)
    try:
        create_app()
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "pip install gauntlex-ai[ui]" in str(e)


def test_create_app_returns_fastapi_instance():
    """If FastAPI is available, create_app() returns a FastAPI app."""
    import pytest
    try:
        from fastapi import FastAPI  # noqa: F401
    except ImportError:
        pytest.skip("fastapi not installed — skipping live app test")

    app = create_app()
    assert app is not None
    # FastAPI app has routes
    routes = [r.path for r in app.routes]
    assert "/" in routes
    assert "/api/runs" in routes
    assert "/api/runs/active" in routes
    assert "/health" in routes


# ── live endpoints (active runs + status) ──────────────────────────────────────

def _client(tmp_path):
    import pytest
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi not installed — skipping live app test")
    cfg = AppConfig()
    cfg.reports_dir = tmp_path / "reports"
    return TestClient(create_app(cfg)), cfg


def test_api_runs_active_endpoint_reflects_running_process(tmp_path):
    client, _ = _client(tmp_path)
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    (runs_dir / "r1.json").write_text(
        json.dumps(_make_run_state("gauntlex-live-001", "running", os.getpid()))
    )
    resp = client.get("/api/runs/active")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["run_id"] == "gauntlex-live-001"


def test_api_runs_active_endpoint_not_shadowed_by_run_id_route(tmp_path):
    """/api/runs/active must resolve to the active-runs list, not /api/runs/{run_id}
    with run_id='active' (a 404) — route registration order matters in FastAPI."""
    client, _ = _client(tmp_path)
    resp = client.get("/api/runs/active")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_status_page_reflects_configured_provider_not_hardcoded(tmp_path):
    import pytest
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi not installed — skipping live app test")
    cfg = AppConfig()
    cfg.reports_dir = tmp_path / "reports"
    cfg.deployment.model_provider = "anthropic"
    client = TestClient(create_app(cfg))

    resp = client.get("/status")
    assert resp.status_code == 200
    # Must reflect this config's actual provider, not the old hardcoded OpenRouter string.
    assert "Anthropic" in resp.text
    assert cfg.deployment.anthropic_model in resp.text
    assert "openai/gpt-oss-20b" not in resp.text  # the old hardcoded value


def test_status_page_shows_active_run_count(tmp_path):
    client, _ = _client(tmp_path)
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    (runs_dir / "r1.json").write_text(
        json.dumps(_make_run_state("gauntlex-live-002", "running", os.getpid()))
    )
    resp = client.get("/status")
    assert "Active Runs" in resp.text


def test_status_page_warns_when_no_project_found(tmp_path):
    """create_app(config=None) with no GAUNTLEX_CONFIG_PATH and no .gauntlex.yml
    reachable from cwd must warn on /status, not silently show an empty project."""
    import pytest
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi not installed — skipping live app test")
    cfg = AppConfig()
    cfg.reports_dir = tmp_path / "reports"
    assert cfg.config_source is None
    client = TestClient(create_app(cfg))

    resp = client.get("/status")
    assert "No GAUNTLEX project found" in resp.text


# ── pyproject.toml [ui] extra ──────────────────────────────────────────────────

def test_pyproject_has_ui_optional_dependency():
    import tomllib
    from pathlib import Path as P
    pyproject = P(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)
    ui_deps = data["project"]["optional-dependencies"].get("ui", [])
    assert any("fastapi" in d for d in ui_deps)
    assert any("uvicorn" in d for d in ui_deps)
