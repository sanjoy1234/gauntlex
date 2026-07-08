"""Tests for ForgeBot PR comment rendering."""

from __future__ import annotations

import pytest

from gauntlex.output.forge_bot import render_pr_comment, _ars_bar


# ── _ars_bar ───────────────────────────────────────────────────────────────────

def test_ars_bar_full():
    bar = _ars_bar(1.0)
    assert "██████████" in bar


def test_ars_bar_empty():
    bar = _ars_bar(0.0)
    assert "░░░░░░░░░░" in bar


def test_ars_bar_half():
    bar = _ars_bar(0.5)
    assert "█████░░░░░" in bar


# ── render_pr_comment ──────────────────────────────────────────────────────────

def _make_report(ars: float = 0.85, missed: int = 1) -> dict:
    attacks = [
        {"cwe": "CWE-89", "title": "SQL Injection", "verdict": "MITIGATED", "severity": "high"},
        {"cwe": "CWE-79", "title": "XSS", "verdict": "MISSED", "severity": "medium"},
    ]
    return {
        "run_id": "run-abc-20260627",
        "ars_score": ars,
        "attack_count": 2,
        "mitigated_count": 2 - missed,
        "miss_count": missed,
        "elapsed_seconds": 12.3,
        "pass_threshold": 0.80,
        "attacks": attacks,
        "integrity_hash": "deadbeef" * 8,
        "control_mappings": {"NIST SSDF": ["PO.1.1", "RV.1.3"], "OWASP SAMM": ["ST-1"]},
        "playbook_version": "owasp_top10@v2025.1",
    }


def test_render_passes_contains_checkmark():
    report = _make_report(ars=0.90, missed=0)
    comment = render_pr_comment(report)
    assert "✅" in comment
    assert "PASSED" in comment


def test_render_fails_contains_x():
    report = _make_report(ars=0.50, missed=1)
    comment = render_pr_comment(report)
    assert "❌" in comment
    assert "BLOCKED" in comment


def test_render_includes_run_id():
    report = _make_report()
    comment = render_pr_comment(report)
    assert "run-abc-20260627" in comment


def test_render_includes_missed_attacks():
    report = _make_report(ars=0.50, missed=1)
    comment = render_pr_comment(report)
    assert "XSS" in comment or "Unmitigated" in comment


def test_render_includes_integrity_hash():
    report = _make_report()
    comment = render_pr_comment(report)
    assert "deadbeef" in comment


def test_render_includes_control_mappings():
    report = _make_report()
    comment = render_pr_comment(report)
    assert "NIST" in comment or "PO.1.1" in comment


def test_render_returns_string():
    report = _make_report()
    comment = render_pr_comment(report)
    assert isinstance(comment, str)
    assert len(comment) > 200
