"""Tests for live progress display, --background flag, and gauntlex status command."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from gauntlex.cli import (
    main,
    _RunProgress,
    _render_live_panel,
    _write_run_status,
    _issue_label,
    _fmt_elapsed,
    _await_with_heartbeat,
    _run_async,
)
from gauntlex.dashboard.app import _load_active_runs


# ── _RunProgress and _render_live_panel ───────────────────────────────────────

class TestRunProgress:
    def test_spinner_cycles(self):
        state = _RunProgress()
        frames = {state.spinner() for _ in range(20)}
        assert len(frames) > 1  # cycles through different frames

    def test_default_phase_is_init(self):
        state = _RunProgress()
        assert state.phase == "init"

    def test_completed_attacks_empty_by_default(self):
        state = _RunProgress()
        assert state.completed_attacks == []


class TestRenderLivePanel:
    def test_returns_panel_object(self):
        from rich.panel import Panel
        state = _RunProgress(run_id="test-run-123", mode="quick", attack_total=5)
        panel = _render_live_panel(state)
        assert isinstance(panel, Panel)

    def test_loading_phase_shows_spec_loading(self):
        state = _RunProgress(phase="loading", issue_label="pallets/flask")
        panel = _render_live_panel(state)
        text = str(panel.renderable)
        assert "Loading" in text or "loading" in text or "1/4" in text

    def test_round_phase_shows_builder_breaker(self):
        state = _RunProgress(phase="round", round_start=time.monotonic() - 10,
                              issue_label="pallets/flask", mode="quick", attack_total=5)
        panel = _render_live_panel(state)
        text = str(panel.renderable)
        assert "Builder" in text
        assert "Breaker" in text

    def test_scoring_phase_shows_completed_attacks(self):
        state = _RunProgress(
            phase="scoring",
            attack_total=3,
            attacks_scored=2,
            completed_attacks=[
                ("CWE-89", "SQL Injection", "MITIGATED"),
                ("CWE-79", "XSS", "MISSED"),
            ],
            current_attack_cwe="CWE-352",
            current_attack_title="CSRF",
        )
        panel = _render_live_panel(state)
        text = str(panel.renderable)
        assert "CWE-89" in text
        assert "CWE-79" in text
        assert "CWE-352" in text

    def test_done_phase_shows_all_complete(self):
        state = _RunProgress(phase="done", attacks_scored=5, attack_total=5,
                              completed_attacks=[("CWE-89", "SQL", "MITIGATED")])
        panel = _render_live_panel(state)
        text = str(panel.renderable)
        assert "4/4" in text

    def test_error_message_shown(self):
        state = _RunProgress(phase="error", error="Model timed out")
        panel = _render_live_panel(state)
        text = str(panel.renderable)
        assert "Model timed out" in text


# ── _write_run_status ─────────────────────────────────────────────────────────

class TestWriteRunStatus:
    def test_creates_status_file(self, tmp_path):
        runs_dir = tmp_path / "runs"
        _write_run_status("gauntlex-test-001", runs_dir, status="running", pid=12345)
        status_file = runs_dir / "gauntlex-test-001.json"
        assert status_file.exists()
        data = json.loads(status_file.read_text())
        assert data["status"] == "running"
        assert data["pid"] == 12345
        assert data["run_id"] == "gauntlex-test-001"
        assert "updated_at" in data

    def test_updates_existing_status(self, tmp_path):
        runs_dir = tmp_path / "runs"
        _write_run_status("run-001", runs_dir, status="running")
        _write_run_status("run-001", runs_dir, status="done", ars=0.85)
        data = json.loads((runs_dir / "run-001.json").read_text())
        assert data["status"] == "done"
        assert data["ars"] == 0.85
        assert data["run_id"] == "run-001"  # preserved

    def test_creates_runs_dir_if_missing(self, tmp_path):
        runs_dir = tmp_path / "deep" / "runs"
        assert not runs_dir.exists()
        _write_run_status("run-002", runs_dir, status="starting")
        assert runs_dir.exists()


# ── Foreground `gauntlex run` must be visible to the dashboard's Active ──────
# Runs panel while in progress. Regression: the initial status write for a
# foreground (non---background) run never included `pid`, so the dashboard's
# liveness check (`_load_active_runs`, which treats a missing/dead pid as a
# stale run) deleted the status file on the very first poll — a run in
# progress would vanish from /api/runs/active the instant anyone looked.

class TestForegroundRunStatusHasPid:
    def test_run_async_writes_own_pid_before_failing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gauntlex.yml").write_text("reports_dir: .gauntlex/reports\n")

        with pytest.raises(SystemExit):
            asyncio.run(_run_async(
                issue=str(tmp_path / "does-not-exist.md"),
                mode="quick", domain="owasp_top10", intent_ref=None,
                pretty=False, config_path=None,
            ))

        status_files = list((tmp_path / ".gauntlex" / "runs").glob("*.json"))
        assert len(status_files) == 1
        data = json.loads(status_files[0].read_text())
        assert data["pid"] == os.getpid()

    def test_load_active_runs_keeps_running_entry_with_live_pid(self, tmp_path):
        runs_dir = tmp_path / "runs"
        _write_run_status("gauntlex-live-run", runs_dir,
                           status="running", phase="round", pid=os.getpid())
        active = _load_active_runs(runs_dir)
        assert [a["run_id"] for a in active] == ["gauntlex-live-run"]
        assert (runs_dir / "gauntlex-live-run.json").exists()  # not deleted as stale


# ── _issue_label ──────────────────────────────────────────────────────────────

class TestIssueLabel:
    def test_github_repo_url(self):
        assert _issue_label("https://github.com/pallets/flask") == "pallets/flask"

    def test_github_repo_url_with_trailing_slash(self):
        assert _issue_label("https://github.com/expressjs/express/") == "expressjs/express"

    def test_local_file_path(self):
        label = _issue_label("/tmp/myrepo/spec.md")
        assert label == "spec.md"

    def test_local_dir_path(self):
        label = _issue_label("/tmp/myrepo")
        assert label == "myrepo"

    def test_long_url_truncated(self):
        long_url = "https://example.com/" + "x" * 100
        label = _issue_label(long_url)
        assert len(label) <= 60


# ── _fmt_elapsed ──────────────────────────────────────────────────────────────

class TestFmtElapsed:
    def test_under_60s(self):
        assert _fmt_elapsed(45) == "45s"

    def test_exactly_60s(self):
        assert _fmt_elapsed(60) == "1m 00s"

    def test_minutes_and_seconds(self):
        assert _fmt_elapsed(125) == "2m 05s"

    def test_zero(self):
        assert _fmt_elapsed(0) == "0s"


# ── gauntlex status command ───────────────────────────────────────────────────

class TestStatusCommand:
    def test_no_runs_shows_helpful_message(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "No runs found" in result.output or "gauntlex run" in result.output

    def test_completed_run_shown_in_table(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            report = {
                "run_id": "gauntlex-test-abc",
                "ars_score": 0.85,
                "attack_count": 5,
                "miss_count": 1,
                "generated_at": "2026-07-04T12:00:00Z",
                "spec_ref": "https://github.com/pallets/flask",
                "attacks": [],
            }
            (reports_dir / "gauntlex-test-abc.json").write_text(json.dumps(report))
            result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "gauntlex-test-abc" in result.output or "0.850" in result.output

    def test_running_status_shown_with_alive_pid(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            runs_dir = Path(".gauntlex/runs")
            runs_dir.mkdir(parents=True)
            # Use current process PID so it appears "alive"
            status = {
                "run_id": "gauntlex-bg-run",
                "status": "running",
                "pid": os.getpid(),
                "issue": "https://github.com/encode/django-rest-framework",
                "mode": "quick",
                "started_at": "2026-07-04T12:00:00+00:00",
                "updated_at": "2026-07-04T12:00:01+00:00",
            }
            (runs_dir / "gauntlex-bg-run.json").write_text(json.dumps(status))
            result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "RUNNING" in result.output

    def test_dead_pid_removed_from_running(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            runs_dir = Path(".gauntlex/runs")
            runs_dir.mkdir(parents=True)
            status = {
                "run_id": "gauntlex-dead-run",
                "status": "running",
                "pid": 999999999,  # almost certainly not a real PID
                "issue": "https://github.com/pallets/flask",
                "mode": "quick",
                "started_at": "2026-07-04T12:00:00+00:00",
                "updated_at": "2026-07-04T12:00:01+00:00",
            }
            sf = runs_dir / "gauntlex-dead-run.json"
            sf.write_text(json.dumps(status))
            result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        # Stale file should be cleaned up
        assert not sf.exists()


# ── --background flag ─────────────────────────────────────────────────────────

class TestBackgroundFlag:
    def test_background_launches_subprocess_and_returns_immediately(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.pid = 99999
                mock_popen.return_value = mock_proc
                result = runner.invoke(main, [
                    "run", "--issue", "examples/demo_issue.md",
                    "--mode", "quick", "--background",
                ])
        assert result.exit_code == 0
        assert "background" in result.output.lower()
        assert mock_popen.called

    def test_background_writes_status_json(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.pid = 99998
                mock_popen.return_value = mock_proc
                runner.invoke(main, [
                    "run", "--issue", "examples/demo_issue.md",
                    "--mode", "quick", "--background",
                ])
            # Assertions must be inside the isolated_filesystem context
            # before its temp dir is cleaned up on exit
            runs_dir = Path(".gauntlex/runs")
            status_files = list(runs_dir.glob("*.json")) if runs_dir.exists() else []
            assert len(status_files) == 1
            data = json.loads(status_files[0].read_text())
            assert data["status"] == "running"
            assert data["pid"] == 99998

    def test_background_prints_run_id_and_status_hint(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.pid = 99997
                mock_popen.return_value = mock_proc
                result = runner.invoke(main, [
                    "run", "--issue", "examples/demo_issue.md",
                    "--mode", "quick", "--background",
                ])
        assert "gauntlex status" in result.output
        assert "Run ID" in result.output

    def test_background_uses_start_new_session(self):
        """Verify the subprocess is detached from the controlling terminal."""
        runner = CliRunner()
        captured = {}
        with runner.isolated_filesystem():
            def fake_popen(_, **kwargs):
                captured["kwargs"] = kwargs
                mock = MagicMock()
                mock.pid = 99996
                return mock
            with patch("subprocess.Popen", side_effect=fake_popen):
                runner.invoke(main, [
                    "run", "--issue", "examples/demo_issue.md",
                    "--mode", "quick", "--background",
                ])
        assert captured.get("kwargs", {}).get("start_new_session") is True


# ── _await_with_heartbeat ─────────────────────────────────────────────────────

class TestAwaitWithHeartbeat:
    @pytest.mark.asyncio
    async def test_fast_coro_returns_result_without_heartbeat(self):
        heartbeats = []

        async def fast():
            return "done"

        result = await _await_with_heartbeat(fast(), heartbeats.append, interval=1.0)
        assert result == "done"
        assert heartbeats == []  # never waited long enough to fire

    @pytest.mark.asyncio
    async def test_slow_coro_prints_heartbeat_and_still_returns_result(self):
        heartbeats = []

        async def slow():
            await asyncio.sleep(0.05)
            return "eventually"

        result = await _await_with_heartbeat(slow(), heartbeats.append, interval=0.01)
        assert result == "eventually"
        assert len(heartbeats) >= 2  # ~0.05s / 0.01s interval
        assert "still waiting" in heartbeats[0]

    @pytest.mark.asyncio
    async def test_exception_propagates_not_swallowed(self):
        heartbeats = []

        async def failing():
            raise ValueError("model exploded")

        with pytest.raises(ValueError, match="model exploded"):
            await _await_with_heartbeat(failing(), heartbeats.append, interval=1.0)


# ── scoring phase shows live elapsed time ─────────────────────────────────────

class TestScoringElapsedDisplay:
    def test_current_attack_shows_elapsed_when_attack_start_set(self):
        state = _RunProgress(
            phase="scoring", attack_total=3, attacks_scored=0,
            current_attack_cwe="CWE-352", current_attack_title="CSRF",
            attack_start=time.monotonic() - 5,
        )
        panel = _render_live_panel(state)
        text = str(panel.renderable)
        assert "CWE-352" in text
        assert "scoring..." in text

    def test_no_elapsed_shown_when_attack_start_unset(self):
        state = _RunProgress(
            phase="scoring", attack_total=3, attacks_scored=0,
            current_attack_cwe="CWE-352", current_attack_title="CSRF",
        )
        panel = _render_live_panel(state)
        # Should not crash and should not fabricate an elapsed time from attack_start=0
        text = str(panel.renderable)
        assert "CWE-352" in text
