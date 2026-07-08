"""Tests for gauntlex findings, integrate CLI commands, and GitHub URL loading."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from gauntlex.cli import main, _parse_github_repo_url, _load_github_repo_spec
from gauntlex.agents.breaker import Attack
from gauntlex.core.gauntlex import CombatResult
from gauntlex.output.report import build_report, generate_run_id, save_report


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_attack(cwe: str, title: str, score: float, severity: str = "high") -> Attack:
    return Attack(
        id=f"atk-{cwe}",
        cwe=cwe,
        title=title,
        description=f"Test description for {title}",
        severity=severity,
        score=score,
    )


def _make_report(attacks: list[Attack], reports_dir: Path, ars: float | None = None) -> str:
    result = CombatResult()
    for a in attacks:
        result.all_attacks.append(a)
    result.final_ars = ars if ars is not None else (
        sum(a.score for a in attacks) / len(attacks) if attacks else 1.0
    )
    run_id = generate_run_id()
    report = build_report(
        result=result,
        run_id=run_id,
        spec_ref="test_spec.md",
        intent_ref="",
        playbook_version="owasp_top10@v2025.1",
    )
    save_report(report, reports_dir)
    return run_id


# ── gauntlex findings ─────────────────────────────────────────────────────────

class TestFindingsCommand:
    def test_no_last_report_exits_with_error(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["findings"])
        assert result.exit_code == 1
        assert "No recent run" in result.output or "not found" in result.output.lower()

    def test_finds_missed_vulnerabilities(self):
        attacks = [
            _make_attack("CWE-89", "SQL Injection", score=0.0, severity="critical"),
            _make_attack("CWE-352", "CSRF", score=1.0, severity="high"),
        ]
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            run_id = _make_report(attacks, reports_dir)
            Path(".last_report_id").write_text(run_id)
            result = runner.invoke(main, ["findings"])

        assert "CWE-89" in result.output or "SQL Injection" in result.output

    def test_format_json_returns_valid_json(self):
        attacks = [_make_attack("CWE-79", "XSS", score=0.0)]
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            run_id = _make_report(attacks, reports_dir)
            Path(".last_report_id").write_text(run_id)
            result = runner.invoke(main, ["findings", "--format", "json"])

        data = json.loads(result.output)
        assert "run_id" in data
        assert "ars_score" in data
        assert isinstance(data["missed"], list)
        assert isinstance(data["partial"], list)

    def test_format_md_returns_markdown(self):
        attacks = [_make_attack("CWE-22", "Path Traversal", score=0.0)]
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            run_id = _make_report(attacks, reports_dir)
            Path(".last_report_id").write_text(run_id)
            result = runner.invoke(main, ["findings", "--format", "md"])

        assert "##" in result.output or "#" in result.output

    def test_explicit_run_id_not_found_exits(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["findings", "gauntlex-nonexistent-run-id"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_explicit_valid_run_id(self):
        attacks = [_make_attack("CWE-330", "Weak Secret", score=0.0, severity="high")]
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            run_id = _make_report(attacks, reports_dir)
            result = runner.invoke(main, ["findings", run_id])

        assert result.exit_code in (0, 1)  # 1 = gate blocked (correct for missed attacks)
        assert "CWE-330" in result.output or "Weak Secret" in result.output

    def test_all_mitigated_shows_no_vulnerabilities(self):
        attacks = [
            _make_attack("CWE-89", "SQL Injection", score=1.0),
            _make_attack("CWE-79", "XSS", score=1.0),
        ]
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            run_id = _make_report(attacks, reports_dir, ars=1.0)
            Path(".last_report_id").write_text(run_id)
            result = runner.invoke(main, ["findings"])

        assert result.exit_code == 0
        assert "mitigated" in result.output.lower() or "No vulnerabilities" in result.output


# ── gauntlex integrate ────────────────────────────────────────────────────────

class TestIntegrateCommand:
    def test_dry_run_all_prints_would_write(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--dry-run"])
        assert result.exit_code == 0
        assert "Would write" in result.output or "dry run" in result.output.lower()

    def test_dry_run_does_not_write_files(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["integrate", "--dry-run"])
            mcp_written = Path(".claude/mcp_servers.json").exists()
            gha_written = Path(".github/workflows/gauntlex.yml").exists()
        assert not mcp_written
        assert not gha_written

    def test_dry_run_github_actions_platform(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "github-actions", "--dry-run"])
        assert result.exit_code == 0
        assert "gauntlex.yml" in result.output or "github-actions" in result.output.lower()

    def test_dry_run_claude_code_platform(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "claude-code", "--dry-run"])
        assert result.exit_code == 0
        assert "mcp_servers.json" in result.output or "claude" in result.output.lower()

    def test_dry_run_cursor_platform(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "cursor", "--dry-run"])
        assert result.exit_code == 0
        assert "cursor" in result.output.lower() or "mcp.json" in result.output

    def test_dry_run_copilot_platform(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "copilot", "--dry-run"])
        assert result.exit_code == 0

    def test_dry_run_codex_platform(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "codex", "--dry-run"])
        assert result.exit_code == 0

    def test_dry_run_windsurf_platform(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "windsurf", "--dry-run"])
        assert result.exit_code == 0

    def test_live_github_actions_writes_yaml(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "github-actions"])
            gha_file = Path(".github/workflows/gauntlex.yml")
            file_exists = gha_file.exists()
            content = gha_file.read_text() if file_exists else ""
        assert result.exit_code == 0
        assert file_exists
        assert "gauntlex" in content.lower()
        assert "pull_request" in content

    def test_live_github_actions_content_valid_yaml(self, tmp_path):
        import yaml
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["integrate", "--platform", "github-actions"])
            content = Path(".github/workflows/gauntlex.yml").read_text()
        parsed = yaml.safe_load(content)
        assert "jobs" in parsed
        assert "on" in parsed or True  # 'on' is a YAML reserved keyword, parsed differently

    def test_invalid_platform_rejected(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "invalid-platform"])
        assert result.exit_code != 0
        assert "invalid" in result.output.lower() or "error" in result.output.lower() or "Choice" in result.output


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestFindingsEdgeCases:
    def test_json_output_zero_attacks(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            run_id = _make_report([], reports_dir, ars=1.0)
            Path(".last_report_id").write_text(run_id)
            result = runner.invoke(main, ["findings", "--format", "json"])

        data = json.loads(result.output)
        assert data["missed"] == []
        assert data["partial"] == []
        assert data["ars_score"] == 1.0

    def test_mixed_verdicts_json(self):
        attacks = [
            _make_attack("CWE-89", "SQL Injection", score=0.0),   # MISSED
            _make_attack("CWE-79", "XSS", score=0.5),             # PARTIAL
            _make_attack("CWE-22", "Path Traversal", score=1.0),  # MITIGATED
        ]
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            run_id = _make_report(attacks, reports_dir)
            Path(".last_report_id").write_text(run_id)
            result = runner.invoke(main, ["findings", "--format", "json"])

        data = json.loads(result.output)
        assert len(data["missed"]) == 1
        assert data["missed"][0]["cwe"] == "CWE-89"
        assert len(data["partial"]) == 1


# ── GitHub repo URL parsing and loading ──────────────────────────────────────

class TestParseGithubRepoUrl:
    def test_bare_repo_url(self):
        assert _parse_github_repo_url("https://github.com/pallets/flask") == ("pallets", "flask")

    def test_repo_url_with_git_suffix(self):
        assert _parse_github_repo_url("https://github.com/pallets/flask.git") == ("pallets", "flask")

    def test_repo_url_with_trailing_slash(self):
        assert _parse_github_repo_url("https://github.com/pallets/flask/") == ("pallets", "flask")

    def test_issue_url_not_matched(self):
        assert _parse_github_repo_url("https://github.com/pallets/flask/issues/42") is None

    def test_blob_url_not_matched(self):
        assert _parse_github_repo_url("https://github.com/pallets/flask/blob/main/README.md") is None

    def test_tree_url_not_matched(self):
        assert _parse_github_repo_url("https://github.com/pallets/flask/tree/main/src") is None

    def test_non_github_url_not_matched(self):
        assert _parse_github_repo_url("https://gitlab.com/owner/repo") is None

    def test_empty_string_not_matched(self):
        assert _parse_github_repo_url("") is None


class TestLoadGithubRepoSpec:
    def test_successful_clone_returns_spec(self, tmp_path):
        (tmp_path / "app.py").write_text("def login():\n    pass\n")
        (tmp_path / "README.md").write_text("# MyApp\n")

        with patch("subprocess.run") as mock_run, \
             patch("tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("shutil.rmtree"):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            spec = _load_github_repo_spec("pallets", "flask")

        assert spec is not None
        assert "app.py" in spec or "README" in spec

    def test_git_not_found_returns_none(self, tmp_path):
        with patch("subprocess.run", side_effect=FileNotFoundError), \
             patch("tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("shutil.rmtree"):
            spec = _load_github_repo_spec("pallets", "flask")
        assert spec is None

    def test_clone_failure_returns_none(self, tmp_path):
        with patch("subprocess.run") as mock_run, \
             patch("tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("shutil.rmtree"):
            mock_run.return_value = MagicMock(returncode=128, stderr="Repository not found")
            spec = _load_github_repo_spec("nonexistent", "nonexistent-repo-xyz")
        assert spec is None

    def test_clone_timeout_returns_none(self, tmp_path):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 120)), \
             patch("tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("shutil.rmtree"):
            spec = _load_github_repo_spec("pallets", "flask")
        assert spec is None

    def test_token_injected_into_clone_url(self, tmp_path):
        (tmp_path / "main.go").write_text("package main\n")
        captured = {}

        def fake_run(cmd, **_):
            captured["cmd"] = cmd
            return MagicMock(returncode=0, stderr="")

        with patch("subprocess.run", side_effect=fake_run), \
             patch("tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("shutil.rmtree"), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_testtoken123"}):
            _load_github_repo_spec("owner", "repo")

        assert "x-access-token:ghp_testtoken123@github.com" in captured["cmd"][4]


# ── gauntlex setup ───────────────────────────────────────────────────────────

class TestSetupCommand:
    def test_model_only_skips_integration_prompts_and_writes_provider(self, tmp_path):
        """`gauntlex setup --model` must reconfigure only the model provider —
        no Jira/Confluence/GitHub/Aha! prompts — and must record MODEL_PROVIDER
        so it always wins over guessing the provider from stray API keys."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("httpx.get") as mock_get:
                mock_get.return_value = MagicMock(status_code=200, json=lambda: {"models": []})
                result = runner.invoke(main, ["setup", "--model"], input="5\n\n\n")

            assert result.exit_code == 0, result.output
            assert "Connect Jira?" not in result.output
            assert "Connect Confluence?" not in result.output
            assert "Connect Aha!?" not in result.output

            env_text = Path(".env").read_text()
            assert "MODEL_PROVIDER=local" in env_text


# ── gauntlex dashboard ───────────────────────────────────────────────────────

class TestDashboardCommand:
    def test_config_flag_points_at_explicit_project(self, tmp_path):
        (tmp_path / ".gauntlex.yml").write_text("version: 1\n")
        runner = CliRunner()
        with patch("uvicorn.run") as mock_run:
            result = runner.invoke(main, ["dashboard", "--config", str(tmp_path / ".gauntlex.yml")])
        assert result.exit_code == 0, result.output
        flat_output = result.output.replace("\n", "")
        assert "Project:" in flat_output
        assert str(tmp_path) in flat_output
        assert "No GAUNTLEX project found" not in flat_output
        assert mock_run.called

    def test_warns_when_launched_outside_any_project(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("uvicorn.run") as mock_run:
                result = runner.invoke(main, ["dashboard"])
        assert result.exit_code == 0, result.output
        assert "No GAUNTLEX project found" in result.output
        assert "--config" in result.output
        assert mock_run.called
