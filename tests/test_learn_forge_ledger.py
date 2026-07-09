"""Regression tests: `gauntlex learn` must populate the Forge Ledger (the
store `gauntlex vault` actually reads), not only the optional ChromaDB-backed
Knowledge Forge.

Previously `gauntlex vault` always reported 0 entries no matter how many runs
or `gauntlex learn` calls happened, because nothing in any live code path
wrote to ForgeLedger's default directory (.gauntlex/vault) — the hook that
was designed to do this (harness/hooks/learn.py's forge_write) was never
registered, and harness.commands.learn.execute() only ever wrote to
KnowledgeForge (ChromaDB), which is a separate store `vault` doesn't read.
"""

from __future__ import annotations

from gauntlex.harness.commands.learn import execute
from gauntlex.memory.forge_ledger import ForgeLedger
from gauntlex.output.report import save_report


def _write_fake_report(reports_dir, run_id: str, attacks: list[dict]) -> None:
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "generated_at": "2026-07-09T00:00:00Z",
        "spec_ref": "examples/demo_issue.md",
        "ars_score": 0.5,
        "attacks": attacks,
        "integrity_hash": "test",
    }
    save_report(report, reports_dir)


def test_learn_writes_to_forge_ledger(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run_id = "gauntlex-test-run-0001"
    _write_fake_report(
        tmp_path / ".gauntlex" / "reports",
        run_id,
        [
            {"id": "atk-1", "cwe": "CWE-89", "title": "SQL Injection", "description": "d",
             "severity": "high", "verdict": "MISSED"},
            {"id": "atk-2", "cwe": "CWE-79", "title": "XSS", "description": "d",
             "severity": "medium", "verdict": "MITIGATED"},
        ],
    )

    result = execute(run_id)

    assert not result.skipped
    assert result.attacks_stored == 2

    ledger = ForgeLedger(vault_dir=tmp_path / ".gauntlex" / "vault")
    entries = ledger.list_entries()
    assert len(entries) == 2
    assert {e.cwe for e in entries} == {"CWE-89", "CWE-79"}


def test_learn_skips_report_with_no_attacks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run_id = "gauntlex-test-run-0002"
    _write_fake_report(tmp_path / ".gauntlex" / "reports", run_id, [])

    result = execute(run_id)

    assert result.skipped
    assert result.attacks_stored == 0


def test_learn_populates_ledger_even_without_chromadb(tmp_path, monkeypatch):
    """The Forge Ledger is plain Markdown with no external dependency and must
    get written even when the optional ChromaDB-backed Knowledge Forge isn't
    available — vault correctness shouldn't depend on an optional store."""
    monkeypatch.chdir(tmp_path)
    run_id = "gauntlex-test-run-0003"
    _write_fake_report(
        tmp_path / ".gauntlex" / "reports",
        run_id,
        [{"id": "atk-1", "cwe": "CWE-22", "title": "Path Traversal", "description": "d",
          "severity": "high", "verdict": "PARTIAL"}],
    )

    class _UnavailableForge:
        def is_available(self):
            return False

    # execute() does `from gauntlex.memory.forge import KnowledgeForge` as a
    # local import, so patch the name in its defining module — that's what
    # the local import resolves against at call time.
    monkeypatch.setattr("gauntlex.memory.forge.KnowledgeForge", _UnavailableForge)

    result = execute(run_id)

    assert not result.skipped
    assert result.attacks_stored == 1
    ledger = ForgeLedger(vault_dir=tmp_path / ".gauntlex" / "vault")
    assert len(ledger.list_entries()) == 1
