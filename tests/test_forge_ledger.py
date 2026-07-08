"""Tests for Forge Ledger — Markdown vault over Knowledge Forge data (Sprint 4)."""

from __future__ import annotations

from pathlib import Path

from gauntlex.memory.forge_ledger import ForgeLedger, _slugify, _entry_to_markdown, LedgerEntry


# ── _slugify ───────────────────────────────────────────────────────────────────

def test_slugify_basic():
    assert _slugify("SQL Injection") == "sql-injection"

def test_slugify_strips_special_chars():
    slug = _slugify("CWE-89: SQL Injection (critical!)")
    assert " " not in slug
    assert "!" not in slug

def test_slugify_max_length():
    long = "a" * 100
    assert len(_slugify(long)) <= 40

def test_slugify_empty():
    assert _slugify("") == ""


# ── _entry_to_markdown ─────────────────────────────────────────────────────────

def _make_entry(**kwargs) -> LedgerEntry:
    defaults = dict(
        cwe="CWE-89", attack_id="atk-0001", title="SQL Injection test",
        description="Attacker manipulates query via username field.",
        severity="high", effectiveness=0.0, run_id="gauntlex-test-run",
        fingerprint="python:django:sql_direct", recorded_at="2026-06-28T12:00:00Z",
    )
    defaults.update(kwargs)
    return LedgerEntry(**defaults)


def test_entry_to_markdown_has_frontmatter():
    md = _entry_to_markdown(_make_entry())
    assert md.startswith("---")
    assert "cwe: CWE-89" in md
    assert "effectiveness: 0.00" in md
    assert "verdict: MISSED" in md


def test_entry_to_markdown_mitigated_verdict():
    md = _entry_to_markdown(_make_entry(effectiveness=1.0))
    assert "verdict: MITIGATED" in md


def test_entry_to_markdown_partial_verdict():
    md = _entry_to_markdown(_make_entry(effectiveness=0.5))
    assert "verdict: PARTIAL" in md


def test_entry_to_markdown_contains_description():
    md = _entry_to_markdown(_make_entry(description="Specific exploit here."))
    assert "Specific exploit here." in md


def test_entry_to_markdown_contains_h1():
    md = _entry_to_markdown(_make_entry())
    assert "# [CWE-89]" in md


# ── ForgeLedger.write_entry ────────────────────────────────────────────────────

def test_write_entry_creates_file(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    path = ledger.write_entry(
        cwe="CWE-89", attack_id="atk-001", title="SQL Injection",
        description="Classic UNION-based injection.", severity="high",
        effectiveness=0.0, run_id="test-run-id", fingerprint="python:flask",
    )
    assert path.exists()
    assert path.suffix == ".md"


def test_write_entry_creates_cwe_subdirectory(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    ledger.write_entry(
        cwe="CWE-79", attack_id="atk-002", title="XSS",
        description="Reflected XSS via search param.", severity="medium",
        effectiveness=1.0, run_id="test-run-id",
    )
    assert (tmp_path / "CWE-79").is_dir()


def test_write_entry_content_has_frontmatter(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    path = ledger.write_entry(
        cwe="CWE-22", attack_id="atk-003", title="Path Traversal",
        description="../ escape in download endpoint.", severity="critical",
        effectiveness=0.5, run_id="test-run-abc",
    )
    content = path.read_text()
    assert "cwe: CWE-22" in content
    assert "effectiveness: 0.50" in content
    assert "verdict: PARTIAL" in content


def test_write_entry_multiple_cwes(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    ledger.write_entry("CWE-89", "atk-1", "SQL Inj", "desc1", "high", 0.0, "run-a")
    ledger.write_entry("CWE-79", "atk-2", "XSS", "desc2", "medium", 1.0, "run-a")
    ledger.write_entry("CWE-89", "atk-3", "SQLi2", "desc3", "high", 0.5, "run-a")

    assert (tmp_path / "CWE-89").is_dir()
    assert (tmp_path / "CWE-79").is_dir()
    assert len(list((tmp_path / "CWE-89").glob("*.md"))) == 2


# ── ForgeLedger.list_entries ───────────────────────────────────────────────────

def test_list_entries_returns_all(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    ledger.write_entry("CWE-89", "a1", "SQL", "d", "high", 0.0, "run1")
    ledger.write_entry("CWE-79", "a2", "XSS", "d", "medium", 1.0, "run1")
    entries = ledger.list_entries()
    assert len(entries) == 2


def test_list_entries_cwe_filter(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    ledger.write_entry("CWE-89", "a1", "SQL", "d", "high", 0.0, "run1")
    ledger.write_entry("CWE-79", "a2", "XSS", "d", "medium", 1.0, "run1")
    entries = ledger.list_entries(cwe_filter="CWE-89")
    assert len(entries) == 1
    assert entries[0].cwe == "CWE-89"


def test_list_entries_empty_vault(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path / "nonexistent")
    assert ledger.list_entries() == []


def test_list_entries_preserves_effectiveness(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    ledger.write_entry("CWE-89", "a1", "SQL", "d", "high", 0.75, "run1")
    entries = ledger.list_entries()
    assert abs(entries[0].effectiveness - 0.75) < 0.01


# ── ForgeLedger.stats ──────────────────────────────────────────────────────────

def test_stats_empty(tmp_path):
    s = ForgeLedger(vault_dir=tmp_path / "empty").stats()
    assert s["total_entries"] == 0
    assert s["avg_effectiveness"] == 0.0


def test_stats_counts(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    ledger.write_entry("CWE-89", "a1", "S1", "d", "high", 0.0, "run1")
    ledger.write_entry("CWE-89", "a2", "S2", "d", "high", 1.0, "run1")
    ledger.write_entry("CWE-79", "a3", "X1", "d", "medium", 0.5, "run1")

    s = ledger.stats()
    assert s["total_entries"] == 3
    assert s["cwe_counts"]["CWE-89"] == 2
    assert s["cwe_counts"]["CWE-79"] == 1


def test_stats_avg_effectiveness(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    ledger.write_entry("CWE-89", "a1", "S1", "d", "high", 0.0, "run1")
    ledger.write_entry("CWE-89", "a2", "S2", "d", "high", 1.0, "run1")
    s = ledger.stats()
    assert abs(s["avg_effectiveness"] - 0.5) < 0.01


def test_stats_top_cwes(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    for i in range(3):
        ledger.write_entry("CWE-89", f"a{i}", f"S{i}", "d", "high", 0.0, "run1")
    ledger.write_entry("CWE-79", "b1", "X1", "d", "medium", 1.0, "run1")
    s = ledger.stats()
    assert s["top_cwes"][0] == "CWE-89"


def test_render_stats_markdown(tmp_path):
    ledger = ForgeLedger(vault_dir=tmp_path)
    ledger.write_entry("CWE-89", "a1", "SQL", "d", "high", 0.0, "run1")
    md = ledger.render_stats_markdown()
    assert "## Forge Ledger Stats" in md
    assert "CWE-89" in md
    assert "Total entries" in md
