"""Tests for AppConfig loading and defaults."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from combatpair.config import AppConfig


def test_defaults():
    cfg = AppConfig()
    assert cfg.gate.minimum_ars == 0.80
    assert cfg.gate.fail_open is False
    assert cfg.deployment.model_provider == "local"
    assert cfg.combat_pair.attack_count == 20
    assert cfg.combat_pair.rounds_max == 5


def test_load_from_yaml(tmp_path, monkeypatch):
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    yml = {
        "version": 1,
        "gate": {"minimum_ars": 0.90, "fail_open": True},
        "deployment": {"model_provider": "local", "local_model": "mistral:7b"},
        "combat_pair": {"attack_count": 5},
    }
    config_file = tmp_path / ".combatpair.yml"
    config_file.write_text(yaml.dump(yml))

    cfg = AppConfig.load(config_file)
    assert cfg.gate.minimum_ars == 0.90
    assert cfg.gate.fail_open is True
    assert cfg.deployment.local_model == "mistral:7b"
    assert cfg.combat_pair.attack_count == 5


def test_missing_config_returns_defaults(tmp_path):
    cfg = AppConfig.load(tmp_path / "nonexistent.yml")
    assert cfg.gate.minimum_ars == 0.80


def test_reports_dir_anchored_to_project_root_not_invoking_cwd(tmp_path, monkeypatch):
    """`combatpair dashboard`/`combatpair status` must resolve the same reports_dir as
    `combatpair run` regardless of which subdirectory of the project they're invoked
    from — otherwise a dashboard launched from a different terminal/cwd silently
    reads an empty, unrelated .combatpair/reports."""
    project_root = tmp_path / "project"
    subdir = project_root / "some" / "nested" / "dir"
    subdir.mkdir(parents=True)
    (project_root / ".combatpair.yml").write_text("version: 1\n")

    monkeypatch.chdir(subdir)
    cfg = AppConfig.load()
    assert cfg.reports_dir == project_root / ".combatpair" / "reports"


def test_reports_dir_anchored_at_project_root_itself(tmp_path):
    (tmp_path / ".combatpair.yml").write_text("version: 1\n")
    cfg = AppConfig.load(tmp_path / ".combatpair.yml")
    assert cfg.reports_dir == tmp_path / ".combatpair" / "reports"


def test_explicit_deployment_wins_over_stale_api_key(tmp_path, monkeypatch):
    """A user's explicit `model_provider: local` in .combatpair.yml must not be
    silently overridden just because an unrelated API key is sitting in the env."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-leftover-from-last-week")
    monkeypatch.delenv("MODEL_PROVIDER", raising=False)
    yml = {"deployment": {"model_provider": "local"}}
    config_file = tmp_path / ".combatpair.yml"
    config_file.write_text(yaml.dump(yml))

    cfg = AppConfig.load(config_file)
    assert cfg.effective_model_provider == "local"


def test_model_provider_env_wins_over_yaml(tmp_path, monkeypatch):
    """MODEL_PROVIDER (written by `combatpair setup`) is the user's most recent
    explicit choice and always takes precedence over .combatpair.yml."""
    monkeypatch.setenv("MODEL_PROVIDER", "openrouter")
    yml = {"deployment": {"model_provider": "local"}}
    config_file = tmp_path / ".combatpair.yml"
    config_file.write_text(yaml.dump(yml))

    cfg = AppConfig.load(config_file)
    assert cfg.effective_model_provider == "openrouter"


def test_zero_config_still_autodetects_from_api_key(tmp_path, monkeypatch):
    """With no .combatpair.yml and no MODEL_PROVIDER, fall back to detecting the
    provider from whichever API key is present (zero-config / CI convenience)."""
    # `combatpair.cli` calls load_dotenv() at import time, which can leak this
    # project's own .env into the test process — isolate against that here.
    monkeypatch.delenv("MODEL_PROVIDER", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    cfg = AppConfig.load(tmp_path / "nonexistent.yml")
    assert cfg.effective_model_provider == "anthropic"


# ── config_source ─────────────────────────────────────────────────────────────

def test_config_source_set_when_found(tmp_path):
    config_file = tmp_path / ".combatpair.yml"
    config_file.write_text("version: 1\n")
    cfg = AppConfig.load(config_file)
    assert cfg.config_source == config_file.resolve()


def test_config_source_none_when_not_found(tmp_path):
    cfg = AppConfig.load(tmp_path / "nonexistent.yml")
    assert cfg.config_source is None


def test_config_source_none_by_default():
    """A bare AppConfig() (not built via .load()) has no known source —
    callers must not assume a project was found just because reports_dir exists."""
    cfg = AppConfig()
    assert cfg.config_source is None


# ── last-project fallback (read-only commands like `dashboard`/`status` should ──
# ── just work from anywhere, without ever requiring an explicit --config) ───────

def test_load_remembers_project_after_finding_via_cwd(tmp_path, monkeypatch):
    project = tmp_path / "myproject"
    project.mkdir()
    (project / ".combatpair.yml").write_text("version: 1\n")
    monkeypatch.chdir(project)

    AppConfig.load()

    # isolated_home (conftest.py) points $HOME at this same tmp_path.
    last_project_file = tmp_path / ".combatpair" / "last_project"
    assert last_project_file.exists()
    assert last_project_file.read_text().strip() == str(project)


def test_load_falls_back_to_remembered_project_from_unrelated_dir(tmp_path, monkeypatch):
    project = tmp_path / "myproject"
    project.mkdir()
    (project / ".combatpair.yml").write_text("version: 1\n")
    monkeypatch.chdir(project)
    AppConfig.load()  # remembers `project`

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    cfg = AppConfig.load()
    assert cfg.config_source == (project / ".combatpair.yml").resolve()


def test_cwd_project_wins_over_remembered_project(tmp_path, monkeypatch):
    old_project = tmp_path / "old_project"
    old_project.mkdir()
    (old_project / ".combatpair.yml").write_text("version: 1\n")
    monkeypatch.chdir(old_project)
    AppConfig.load()  # remembers old_project

    new_project = tmp_path / "new_project"
    new_project.mkdir()
    (new_project / ".combatpair.yml").write_text("version: 1\n")
    monkeypatch.chdir(new_project)

    cfg = AppConfig.load()
    assert cfg.config_source == (new_project / ".combatpair.yml").resolve()


def test_explicit_config_wins_over_remembered_project(tmp_path, monkeypatch):
    old_project = tmp_path / "old_project"
    old_project.mkdir()
    (old_project / ".combatpair.yml").write_text("version: 1\n")
    monkeypatch.chdir(old_project)
    AppConfig.load()  # remembers old_project

    explicit_project = tmp_path / "explicit_project"
    explicit_project.mkdir()
    (explicit_project / ".combatpair.yml").write_text("version: 1\n")

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    cfg = AppConfig.load(explicit_project / ".combatpair.yml")
    assert cfg.config_source == (explicit_project / ".combatpair.yml").resolve()


def test_recall_returns_none_when_remembered_project_deleted(tmp_path, monkeypatch):
    project = tmp_path / "myproject"
    project.mkdir()
    (project / ".combatpair.yml").write_text("version: 1\n")
    monkeypatch.chdir(project)
    AppConfig.load()  # remembers project

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    import shutil
    shutil.rmtree(project)

    cfg = AppConfig.load()
    assert cfg.config_source is None


def test_no_project_found_and_none_remembered(tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    cfg = AppConfig.load()
    assert cfg.config_source is None
