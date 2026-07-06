"""Tests for Arbiter ARS scoring and entropy check."""

from __future__ import annotations

import pytest

from combatpair.agents.breaker import Attack
from combatpair.core.arbiter import Arbiter, _parse_score


def _make_attack(cwe: str, score: float) -> Attack:
    a = Attack(id="test", cwe=cwe, title="Test", description="Test", score=score)
    return a


def test_ars_all_mitigated():
    attacks = [_make_attack("CWE-89", 1.0) for _ in range(5)]
    arbiter = Arbiter(provider="ollama", model="llama3.1:8b")
    assert arbiter.final_ars(attacks) == 1.0


def test_ars_all_missed():
    attacks = [_make_attack("CWE-89", 0.0) for _ in range(5)]
    arbiter = Arbiter(provider="ollama", model="llama3.1:8b")
    assert arbiter.final_ars(attacks) == 0.0


def test_ars_mixed():
    attacks = [
        _make_attack("CWE-89", 1.0),
        _make_attack("CWE-79", 0.5),
        _make_attack("CWE-22", 0.0),
        _make_attack("CWE-78", 1.0),
    ]
    arbiter = Arbiter(provider="ollama", model="llama3.1:8b")
    ars = arbiter.final_ars(attacks)
    assert ars == pytest.approx(2.5 / 4.0)


def test_ars_empty_returns_1():
    arbiter = Arbiter(provider="ollama", model="llama3.1:8b")
    assert arbiter.final_ars([]) == 1.0


def test_entropy_low_triggers_flag():
    attacks = [_make_attack("CWE-89", 0.5) for _ in range(6)]
    arbiter = Arbiter(provider="ollama", model="llama3.1:8b")
    assert arbiter.check_entropy(attacks) is True


def test_entropy_diverse_is_fine():
    cwes = ["CWE-89", "CWE-79", "CWE-22", "CWE-78", "CWE-352", "CWE-362"]
    attacks = [_make_attack(c, 0.5) for c in cwes]
    arbiter = Arbiter(provider="ollama", model="llama3.1:8b")
    assert arbiter.check_entropy(attacks) is False


def test_parse_score_mitigated():
    assert _parse_score('{"verdict": "mitigated", "score": 1.0}') == 1.0


def test_parse_score_missed():
    assert _parse_score('{"verdict": "missed", "score": 0.0}') == 0.0


def test_parse_score_invalid_returns_partial():
    assert _parse_score("not json") == 0.5
