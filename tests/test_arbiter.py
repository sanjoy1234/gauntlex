"""Tests for Arbiter ARS scoring, entropy check, and consensus scoring."""

from __future__ import annotations

import pytest

from gauntlex.agents.base import ModelResponse
from gauntlex.agents.breaker import Attack
from gauntlex.core.arbiter import Arbiter, _parse_verdict, _verdict_tier


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


def test_parse_verdict_mitigated():
    score, reason = _parse_verdict('{"verdict": "mitigated", "score": 1.0, "reason": "input is escaped"}')
    assert score == 1.0
    assert reason == "input is escaped"


def test_parse_verdict_missed():
    score, reason = _parse_verdict('{"verdict": "missed", "score": 0.0, "reason": "no validation"}')
    assert score == 0.0
    assert reason == "no validation"


def test_parse_verdict_invalid_returns_partial():
    score, reason = _parse_verdict("not json")
    assert score == 0.5
    assert reason


def test_verdict_tier_boundaries():
    assert _verdict_tier(1.0) == "mitigated"
    assert _verdict_tier(0.0) == "missed"
    assert _verdict_tier(0.5) == "partial"


# ── Consensus / self-consistency scoring ────────────────────────────────────

class _FakeCompleteArbiter(Arbiter):
    """Arbiter whose `complete()` returns a scripted sequence of responses,
    one per call, so consensus sampling can be tested without a real LLM."""

    def __init__(self, responses: list[str], **kwargs):
        super().__init__(provider="ollama", model="llama3.1:8b", **kwargs)
        self._responses = list(responses)
        self._call_count = 0

    async def complete(self, _messages):
        text = self._responses[self._call_count % len(self._responses)]
        self._call_count += 1
        return ModelResponse(content=text, model="fake")


def _verdict_json(verdict: str, score: float, reason: str) -> str:
    return f'{{"verdict": "{verdict}", "score": {score}, "reason": "{reason}"}}'


@pytest.mark.asyncio
async def test_score_attack_single_sample_sets_reason():
    arbiter = _FakeCompleteArbiter(
        [_verdict_json("mitigated", 1.0, "input is escaped")], consensus_samples=1
    )
    attack = _make_attack("CWE-89", 0.0)
    score = await arbiter._score_attack("code", attack)
    assert score == 1.0
    assert attack.reason == "input is escaped"
    assert attack.consensus_samples is None
    assert attack.consensus_agreement is None


@pytest.mark.asyncio
async def test_score_attack_consensus_unanimous():
    arbiter = _FakeCompleteArbiter(
        [_verdict_json("mitigated", 1.0, "escaped")] * 3, consensus_samples=3
    )
    attack = _make_attack("CWE-89", 0.0)
    score = await arbiter._score_attack("code", attack)
    assert score == 1.0
    assert attack.consensus_samples == 3
    assert attack.consensus_agreement == 1.0


@pytest.mark.asyncio
async def test_score_attack_consensus_split_verdict():
    responses = [
        _verdict_json("mitigated", 1.0, "looks handled"),
        _verdict_json("mitigated", 1.0, "looks handled too"),
        _verdict_json("missed", 0.0, "edge case survives"),
    ]
    arbiter = _FakeCompleteArbiter(responses, consensus_samples=3)
    attack = _make_attack("CWE-89", 0.0)
    score = await arbiter._score_attack("code", attack)
    assert score == pytest.approx((1.0 + 1.0 + 0.0) / 3, abs=1e-4)
    assert attack.consensus_samples == 3
    assert attack.consensus_agreement == pytest.approx(2 / 3, abs=1e-4)
    assert attack.reason in ("looks handled", "looks handled too")


@pytest.mark.asyncio
async def test_score_attack_consensus_full_disagreement():
    responses = [
        _verdict_json("mitigated", 1.0, "a"),
        _verdict_json("partial", 0.5, "b"),
        _verdict_json("missed", 0.0, "c"),
    ]
    arbiter = _FakeCompleteArbiter(responses, consensus_samples=3)
    attack = _make_attack("CWE-89", 0.0)
    score = await arbiter._score_attack("code", attack)
    assert score == pytest.approx(0.5)
    # No majority among 3 distinct tiers -- agreement is 1/3 for whichever
    # tier max() picks first, not a tie-break failure.
    assert attack.consensus_agreement == pytest.approx(1 / 3, abs=1e-4)
