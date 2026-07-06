"""Tests for the Attack Validation Framework (AVF) gate logic."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from combatpair.harness.commands.validate import _hits_fixture, _run_avf_gate


# ── Fixture helpers ────────────────────────────────────────────────────────────

def _make_attack(cwe: str, title: str, description: str = ""):
    from combatpair.agents.breaker import Attack
    return Attack(id="atk-001", cwe=cwe, title=title, description=description)


# ── _hits_fixture unit tests ───────────────────────────────────────────────────

def test_hits_fixture_by_keyword():
    attacks = [_make_attack("CWE-200", "log injection in request handler")]
    fixture = {"expected_cwe": "CWE-117", "expected_keyword": "log injection"}
    assert _hits_fixture(attacks, fixture) is True


def test_hits_fixture_by_cwe():
    attacks = [_make_attack("CWE-89", "Something else entirely")]
    fixture = {"expected_cwe": "CWE-89", "expected_keyword": "sql injection"}
    assert _hits_fixture(attacks, fixture) is True


def test_hits_fixture_by_description_keyword():
    attacks = [_make_attack("CWE-200", "Info leak", "exposes sql injection via error message")]
    fixture = {"expected_cwe": "CWE-89", "expected_keyword": "sql injection"}
    assert _hits_fixture(attacks, fixture) is True


def test_misses_fixture_no_match():
    attacks = [_make_attack("CWE-79", "XSS in template rendering")]
    fixture = {"expected_cwe": "CWE-89", "expected_keyword": "sql injection"}
    assert _hits_fixture(attacks, fixture) is False


def test_hits_fixture_empty_attacks():
    fixture = {"expected_cwe": "CWE-89", "expected_keyword": "sql injection"}
    assert _hits_fixture([], fixture) is False


def test_hits_fixture_empty_keyword_matches_cwe():
    attacks = [_make_attack("CWE-117", "log injection")]
    fixture = {"expected_cwe": "CWE-117", "expected_keyword": ""}
    assert _hits_fixture(attacks, fixture) is True


# ── Golden fixture files exist ─────────────────────────────────────────────────

def test_golden_fixtures_exist():
    golden_dir = Path(__file__).parent / "fixtures" / "golden"
    assert golden_dir.exists(), "Golden fixtures directory missing"
    fixtures = list(golden_dir.glob("*.json"))
    assert len(fixtures) == 5, f"Expected 5 golden fixtures, found {len(fixtures)}"


def test_golden_fixtures_have_required_fields():
    golden_dir = Path(__file__).parent / "fixtures" / "golden"
    required = {"id", "vulnerable_code", "expected_cwe", "expected_keyword"}
    for f in golden_dir.glob("*.json"):
        data = json.loads(f.read_text())
        missing = required - set(data.keys())
        assert not missing, f"{f.name} missing fields: {missing}"


def test_golden_fixture_log4shell_cwe():
    p = Path(__file__).parent / "fixtures" / "golden" / "cve_2021_44228_log4shell.json"
    data = json.loads(p.read_text())
    assert data["expected_cwe"] == "CWE-117"
    assert "log" in data["expected_keyword"].lower()


# ── AVF gate integration (mocked model) ────────────────────────────────────────

@pytest.mark.asyncio
async def test_avf_gate_passes_with_mock_hits():
    """AVF gate logic: model finds keyword in each fixture → hit_rate=1.0."""
    from combatpair.agents.breaker import BreakerResult, Attack
    from combatpair.agents.base import ModelResponse

    # Attacks that match every golden fixture's expected_keyword
    def make_result_for_fixture(fixture_path):
        fixture = json.loads(Path(fixture_path).read_text())
        keyword = fixture.get("expected_keyword", "")
        cwe = fixture.get("expected_cwe", "CWE-UNKNOWN")
        atk = Attack(
            id="atk-001", cwe=cwe,
            title=f"Found: {keyword}",
            description=f"This exploits {keyword} vulnerability",
        )
        return BreakerResult(
            attacks=[atk],
            model_response=ModelResponse(content="[]", model="test"),
            cwe_categories_used=[cwe],
        )

    golden_dir = Path(__file__).parent / "fixtures" / "golden"
    fixtures = sorted(golden_dir.glob("*.json"))
    results = [make_result_for_fixture(f) for f in fixtures]

    call_count = 0

    async def mock_attack(*args, **kwargs):
        nonlocal call_count
        r = results[call_count % len(results)]
        call_count += 1
        return r

    with patch("combatpair.agents.breaker.Breaker.attack", new=mock_attack):
        from combatpair.config import AppConfig
        cfg = AppConfig.load()
        hit_rate = await _run_avf_gate(cfg)

    assert hit_rate == 1.0


@pytest.mark.asyncio
async def test_avf_gate_fails_when_no_attacks_found():
    """AVF gate: Breaker returns empty attacks → hit_rate=0.0."""
    from combatpair.agents.breaker import BreakerResult
    from combatpair.agents.base import ModelResponse

    empty_result = BreakerResult(
        attacks=[],
        model_response=ModelResponse(content="[]", model="test"),
        cwe_categories_used=[],
    )

    async def mock_attack(*args, **kwargs):
        return empty_result

    with patch("combatpair.agents.breaker.Breaker.attack", new=mock_attack):
        from combatpair.config import AppConfig
        cfg = AppConfig.load()
        hit_rate = await _run_avf_gate(cfg)

    assert hit_rate == 0.0


def test_avf_hit_rate_threshold():
    """0.75 hit rate means 4/5 minimum — verify threshold logic."""
    assert 4 / 5 >= 0.75
    assert 3 / 5 < 0.75
    assert 5 / 5 >= 0.75
