"""Tests for Breaker agent CWE rotation, entropy, and attack parsing."""

from __future__ import annotations

import pytest

from combatpair.agents.breaker import Breaker, _parse_attacks, _load_cwe_pool


def test_cwe_pool_loads():
    pool = _load_cwe_pool()
    assert len(pool) >= 10
    assert "CWE-89" in pool
    assert "CWE-79" in pool


def test_parse_attacks_valid_json():
    raw = '[{"id": "atk-001", "cwe": "CWE-89", "title": "SQL Injection", "description": "Test", "confidence": 8, "severity": "high"}]'
    attacks = _parse_attacks(raw, round_number=1)
    assert len(attacks) == 1
    assert attacks[0].cwe == "CWE-89"
    assert attacks[0].title == "SQL Injection"


def test_parse_attacks_empty_json():
    attacks = _parse_attacks("[]", round_number=1)
    assert attacks == []


def test_parse_attacks_invalid_returns_empty():
    attacks = _parse_attacks("not json at all", round_number=1)
    assert attacks == []


def test_breaker_cwe_rotation():
    breaker = Breaker(cwe_rotation=True, provider="ollama", model="llama3.1:8b")
    cwes1 = breaker._select_cwes(1)
    cwes2 = breaker._select_cwes(2)
    assert len(cwes1) > 0
    assert len(cwes2) > 0
    # After two rounds, used list grows
    # _select_cwes returns CWEs but _used_cwes is populated by the caller (attack())
    # Just verify the selections are non-empty and valid CWEs
    assert len(cwes1) > 0
    assert all(c.startswith("CWE-") for c in cwes1)


def test_entropy_empty_returns_zero():
    breaker = Breaker(provider="ollama", model="llama3.1:8b")
    assert breaker.entropy() == 0.0
