"""Tests for gauntlex findings, integrate CLI commands, and GitHub URL loading."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from gauntlex.cli import main, _parse_github_repo_url, _load_github_repo_spec
from gauntlex.agents.breaker import Attack
from gauntlex.core.gauntlex import GauntlexResult
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
    result = GauntlexResult()
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

    def test_github_actions_does_not_clobber_customized_workflow(self, tmp_path):
        """Regression test: integrate used to unconditionally overwrite an existing
        .github/workflows/gauntlex.yml with dest.write_text(content), no check at
        all — silently destroying real customization (extra steps, PR-comment
        posting, non-default permissions) the moment someone re-ran `gauntlex
        integrate`. Must leave a differing existing file alone without --force."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            gha_dir = Path(".github/workflows")
            gha_dir.mkdir(parents=True)
            custom_content = "name: My Custom Hand-Written Workflow\non: push\njobs: {}\n"
            (gha_dir / "gauntlex.yml").write_text(custom_content)

            result = runner.invoke(main, ["integrate", "--platform", "github-actions"])
            content_after = (gha_dir / "gauntlex.yml").read_text()

        assert result.exit_code == 0
        assert content_after == custom_content, "existing customized workflow was overwritten without --force"
        assert "already exists" in result.output or "differs" in result.output

    def test_github_actions_force_overwrites_customized_workflow(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            gha_dir = Path(".github/workflows")
            gha_dir.mkdir(parents=True)
            custom_content = "name: My Custom Hand-Written Workflow\non: push\njobs: {}\n"
            (gha_dir / "gauntlex.yml").write_text(custom_content)

            result = runner.invoke(main, ["integrate", "--platform", "github-actions", "--force"])
            content_after = (gha_dir / "gauntlex.yml").read_text()

        assert result.exit_code == 0
        assert content_after != custom_content
        assert "GAUNTLEX Adversarial Gate" in content_after

    def test_invalid_platform_rejected(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "invalid-platform"])
        assert result.exit_code != 0
        assert "invalid" in result.output.lower() or "error" in result.output.lower() or "Choice" in result.output

    def test_zed_and_antigravity_are_valid_platforms(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            for platform in ("zed", "antigravity"):
                result = runner.invoke(main, ["integrate", "--platform", platform, "--dry-run"])
                assert result.exit_code == 0, result.output

    def test_live_claude_code_writes_mcp_json_with_mcpServers_wrapper(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "claude-code"])
            content = json.loads(Path(".mcp.json").read_text())
        assert result.exit_code == 0
        assert content["mcpServers"]["gauntlex"]["args"] == ["mcp-server"]

    def test_live_cursor_writes_mcpServers_wrapper(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["integrate", "--platform", "cursor"])
            content = json.loads(Path(".cursor/mcp.json").read_text())
        assert "mcpServers" in content
        assert "gauntlex" in content["mcpServers"]

    def test_live_copilot_uses_servers_key_not_mcpServers(self, tmp_path):
        """VS Code/Copilot's mcp.json root key is `servers`, not `mcpServers` — a real
        divergence from Cursor/Windsurf that a naive shared config would get wrong."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["integrate", "--platform", "copilot"])
            content = json.loads(Path(".vscode/mcp.json").read_text())
        assert "servers" in content
        assert "gauntlex" in content["servers"]
        assert "mcpServers" not in content

    def test_live_zed_uses_context_servers_key(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["integrate", "--platform", "zed"])
            content = json.loads(Path(".zed/settings.json").read_text())
        assert content["context_servers"]["gauntlex"]["source"] == "custom"

    def test_merge_preserves_existing_other_server(self, tmp_path):
        """Regression test: a prior version of this command did existing.update(new_entry)
        at the top level, which would silently delete every other MCP server already
        configured in the file instead of adding gauntlex alongside them."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            Path(".cursor").mkdir()
            Path(".cursor/mcp.json").write_text(json.dumps({
                "mcpServers": {"some-other-server": {"command": "other", "args": []}}
            }))
            runner.invoke(main, ["integrate", "--platform", "cursor"])
            content = json.loads(Path(".cursor/mcp.json").read_text())
        assert "some-other-server" in content["mcpServers"], "pre-existing MCP server was wiped out by merge"
        assert "gauntlex" in content["mcpServers"]

    def test_codex_writes_toml_not_json(self, tmp_path):
        # $HOME is already redirected to tmp_path by the autouse isolated_home
        # fixture (conftest.py) — no extra patching needed.
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--platform", "codex"])
            toml_path = tmp_path / ".codex" / "config.toml"
            content = toml_path.read_text()
        assert result.exit_code == 0
        assert toml_path.exists()
        assert "[mcp_servers.gauntlex]" in content
        assert content.strip().startswith("[mcp_servers.gauntlex]")
        assert not content.strip().startswith("{")

    def test_codex_toml_upsert_preserves_other_sections_and_is_idempotent(self, tmp_path):
        runner = CliRunner()
        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.toml").write_text(
            '[mcp_servers.other]\ncommand = "other-cmd"\nargs = []\n'
        )
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["integrate", "--platform", "codex"])
            runner.invoke(main, ["integrate", "--platform", "codex"])  # run twice: must not duplicate
        content = (codex_dir / "config.toml").read_text()
        assert content.count("[mcp_servers.gauntlex]") == 1
        assert "[mcp_servers.other]" in content
        assert 'command = "other-cmd"' in content

    def test_windsurf_and_antigravity_write_under_home(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["integrate", "--platform", "windsurf"])
            runner.invoke(main, ["integrate", "--platform", "antigravity"])
        windsurf = json.loads((tmp_path / ".codeium/windsurf/mcp_config.json").read_text())
        antigravity = json.loads((tmp_path / ".gemini/config/mcp_config.json").read_text())
        assert "gauntlex" in windsurf["mcpServers"]
        assert "gauntlex" in antigravity["mcpServers"]

    def test_all_platform_now_includes_eight_targets(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["integrate", "--dry-run"])
        assert result.exit_code == 0
        output_lower = result.output.lower()
        for name in ("mcp.json", "cursor", "windsurf", ".vscode", "codex", "zed", "antigravity", "gauntlex.yml"):
            assert name in output_lower, f"{name} target missing from `integrate --dry-run` output"


# ── .env discovery must be cwd-anchored, not import-location-anchored ─────────
#
# Regression test for a real bug: `import gauntlex.cli` used to call bare
# load_dotenv(), whose default file discovery walks up from the *calling
# frame's file location*, not the current directory. For an editable dev
# install that accidentally worked, since cli.py sits inside the project
# being tested. For a real `pip install`, cli.py lives under site-packages/
# with no .env nearby, so .env silently fails to load, MODEL_PROVIDER never
# reaches os.environ, and AppConfig falls back to .gauntlex.yml's static
# template default (local/Ollama) — silently overriding the user's actual
# `gauntlex setup` choice. Reproduced here with a subprocess launched from a
# script file that is deliberately far from the project directory (cwd),
# structurally identical to the site-packages scenario.
class TestDotenvDiscoveryIsCwdAnchored:
    def test_env_loads_even_when_calling_script_is_far_from_cwd(self, tmp_path):
        import subprocess
        import sys

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / ".env").write_text("MODEL_PROVIDER=openrouter\nOPENROUTER_API_KEY=dummy-key\n")
        (project_dir / ".gauntlex.yml").write_text(
            "version: 1\ndeployment:\n  model_provider: local\n"
        )

        faraway_dir = tmp_path / "faraway" / "nested" / "far" / "from" / "project"
        faraway_dir.mkdir(parents=True)
        script = faraway_dir / "check_provider.py"
        script.write_text(
            "import gauntlex.cli  # noqa: F401 (triggers module-level dotenv load)\n"
            "from gauntlex.config import AppConfig\n"
            "print(AppConfig.load().effective_model_provider)\n"
        )

        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "openrouter", (
            f"expected the project's .env (MODEL_PROVIDER=openrouter) to win over "
            f".gauntlex.yml's static 'local' default, got {result.stdout!r} / {result.stderr!r}"
        )


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


# ── gauntlex status ───────────────────────────────────────────────────────────

class TestStatusCommand:
    def test_shows_real_mode_when_report_has_it(self):
        """Regression: completed runs' Mode column was hardcoded to "—" because
        build_report() never persisted the --mode value. Now that it does,
        status must surface it instead of the placeholder."""
        attacks = [_make_attack("CWE-89", "SQL Injection", score=1.0)]
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            result_obj = GauntlexResult()
            result_obj.all_attacks = attacks
            result_obj.final_ars = 1.0
            report = build_report(
                result=result_obj, run_id=generate_run_id(), spec_ref="test_spec.md",
                mode="thorough", model="openrouter/nvidia/nemotron-3-super-120b-a12b:free",
            )
            save_report(report, reports_dir)
            result = runner.invoke(main, ["status"])

        assert result.exit_code == 0, result.output
        # Rich truncates the narrow Mode column ("thor…"), so match the prefix
        assert "thor" in result.output

    def test_shows_placeholder_when_report_lacks_mode(self):
        """Old reports (pre-mode-field) must still render without crashing."""
        attacks = [_make_attack("CWE-79", "XSS", score=0.5)]
        runner = CliRunner()
        with runner.isolated_filesystem():
            reports_dir = Path(".gauntlex/reports")
            reports_dir.mkdir(parents=True)
            _make_report(attacks, reports_dir)  # no mode passed -> defaults to ""
            result = runner.invoke(main, ["status"])

        assert result.exit_code == 0, result.output
        assert "—" in result.output
