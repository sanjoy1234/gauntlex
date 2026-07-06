"""Tests for Resilience Report generation and integrity verification."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from combatpair.agents.breaker import Attack
from combatpair.core.combat_pair import CombatResult
from combatpair.output.report import (
    build_report,
    generate_run_id,
    render_markdown,
    render_html,
    render_sarif,
    render_junit_xml,
    save_report,
    load_report,
    verify_integrity,
)


def _make_result(scores: list[float]) -> CombatResult:
    attacks = [
        Attack(id=f"atk-{i:03d}", cwe="CWE-89", title="SQL Injection test",
               description="Test", score=s)
        for i, s in enumerate(scores)
    ]
    result = CombatResult()
    result.all_attacks = attacks
    result.final_ars = sum(scores) / len(scores) if scores else 1.0
    return result


def test_run_id_format():
    run_id = generate_run_id()
    assert run_id.startswith("combatpair-")
    assert len(run_id) > 20


def test_build_report_structure():
    result = _make_result([1.0, 0.5, 0.0, 1.0, 1.0])
    run_id = generate_run_id()
    report = build_report(result, run_id)

    assert report["schema_version"] == "1.0"
    assert report["run_id"] == run_id
    assert "ars_score" in report
    assert "integrity_hash" in report
    assert report["integrity_hash"].startswith("sha256:")
    assert len(report["attacks"]) == 5
    assert "control_mappings" in report
    assert "NIST_SSDF" in report["control_mappings"]


def test_integrity_hash_tamper_detection():
    result = _make_result([1.0, 0.5])
    report = build_report(result, generate_run_id())
    assert verify_integrity(report) is True

    # Tamper with an attack score
    report["attacks"][0]["score"] = 0.0
    assert verify_integrity(report) is False


def test_save_and_load_report(tmp_path):
    result = _make_result([1.0, 0.8])
    run_id = generate_run_id()
    report = build_report(result, run_id)
    save_report(report, tmp_path)

    loaded = load_report(run_id, tmp_path)
    assert loaded["run_id"] == run_id
    assert loaded["ars_score"] == report["ars_score"]


def test_render_markdown_contains_ars():
    result = _make_result([1.0, 0.5, 0.0])
    report = build_report(result, generate_run_id())
    md = render_markdown(report)
    assert "ARS Score" in md
    assert "COMBATPAIR" in md
    assert "sha256:" in md


def test_mitigated_partial_missed_counts():
    result = _make_result([1.0, 0.5, 0.0, 1.0])
    report = build_report(result, generate_run_id())
    assert report["mitigated_count"] == 2
    assert report["partial_count"] == 1
    assert report["miss_count"] == 1


# ── HTML ──────────────────────────────────────────────────────────────────────

def test_render_html_is_valid_document():
    result = _make_result([1.0, 0.5, 0.0])
    report = build_report(result, generate_run_id())
    html = render_html(report)
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html


def test_render_html_contains_ars():
    result = _make_result([1.0, 0.5, 0.0])
    report = build_report(result, generate_run_id())
    html = render_html(report)
    ars = f"{report['ars_score']:.2f}"
    assert ars in html


def test_render_html_gate_passed():
    result = _make_result([1.0, 1.0, 1.0])
    report = build_report(result, generate_run_id())
    html = render_html(report)
    assert "PASSED" in html


def test_render_html_gate_blocked():
    result = _make_result([0.0, 0.0, 0.0])
    report = build_report(result, generate_run_id())
    html = render_html(report)
    assert "BLOCKED" in html


def test_render_html_contains_integrity_hash():
    result = _make_result([1.0])
    report = build_report(result, generate_run_id())
    html = render_html(report)
    assert "sha256:" in html


# ── SARIF ─────────────────────────────────────────────────────────────────────

def test_render_sarif_is_valid_json():
    result = _make_result([1.0, 0.0])
    report = build_report(result, generate_run_id())
    sarif_str = render_sarif(report)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"


def test_render_sarif_has_runs():
    result = _make_result([1.0, 0.5, 0.0])
    report = build_report(result, generate_run_id())
    sarif = json.loads(render_sarif(report))
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "COMBATPAIR"


def test_render_sarif_missed_attack_is_error():
    result = _make_result([0.0])
    report = build_report(result, generate_run_id())
    sarif = json.loads(render_sarif(report))
    results = sarif["runs"][0]["results"]
    assert any(r["level"] == "error" for r in results)


def test_render_sarif_mitigated_attack_is_note():
    result = _make_result([1.0])
    report = build_report(result, generate_run_id())
    sarif = json.loads(render_sarif(report))
    results = sarif["runs"][0]["results"]
    assert all(r["level"] == "note" for r in results)


def test_render_sarif_has_rules_for_each_cwe():
    result = _make_result([1.0, 0.0])
    report = build_report(result, generate_run_id())
    # Both attacks use CWE-89 in _make_result — one unique rule expected
    sarif = json.loads(render_sarif(report))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 1
    assert rules[0]["id"] == "CWE-89"


# ── JUnit XML ─────────────────────────────────────────────────────────────────

def test_render_junit_xml_is_valid_xml():
    import xml.etree.ElementTree as ET
    result = _make_result([1.0, 0.5, 0.0])
    report = build_report(result, generate_run_id())
    xml_str = render_junit_xml(report)
    root = ET.fromstring(xml_str.split("\n", 1)[1])  # skip <?xml?> declaration
    assert root.tag == "testsuites"


def test_render_junit_xml_failure_for_missed():
    import xml.etree.ElementTree as ET
    result = _make_result([0.0, 1.0])
    report = build_report(result, generate_run_id())
    xml_str = render_junit_xml(report)
    root = ET.fromstring(xml_str.split("\n", 1)[1])
    failures = root.findall(".//failure")
    assert len(failures) == 1


def test_render_junit_xml_no_failure_for_mitigated():
    import xml.etree.ElementTree as ET
    result = _make_result([1.0, 1.0])
    report = build_report(result, generate_run_id())
    xml_str = render_junit_xml(report)
    root = ET.fromstring(xml_str.split("\n", 1)[1])
    failures = root.findall(".//failure")
    assert len(failures) == 0


def test_render_junit_xml_test_counts():
    import xml.etree.ElementTree as ET
    result = _make_result([1.0, 0.5, 0.0])
    report = build_report(result, generate_run_id())
    xml_str = render_junit_xml(report)
    root = ET.fromstring(xml_str.split("\n", 1)[1])
    assert root.attrib["tests"] == "3"
    assert root.attrib["failures"] == "1"


# ── Harness command ───────────────────────────────────────────────────────────

def test_harness_report_supported_formats_constant():
    from combatpair.harness.commands.report import SUPPORTED_FORMATS
    for fmt in ("md", "json", "html", "sarif", "junit"):
        assert fmt in SUPPORTED_FORMATS


def test_harness_report_unknown_format_raises():
    from combatpair.harness.commands.report import execute
    try:
        execute("any-run-id", fmt="pdf")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "pdf" in str(e)


def test_all_render_functions_produce_output():
    import json as _json
    result = _make_result([1.0, 0.5, 0.0])
    report = build_report(result, generate_run_id())

    assert len(render_markdown(report)) > 100
    assert len(render_html(report)) > 200
    assert len(_json.loads(render_sarif(report))["runs"]) == 1
    assert "<testsuites" in render_junit_xml(report)
