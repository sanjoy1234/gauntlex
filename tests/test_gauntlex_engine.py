"""Tests for the Gauntlex core engine: attack-count wiring and per-round call structure."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gauntlex.agents.breaker import Attack, BreakerResult
from gauntlex.agents.builder import BuildResult
from gauntlex.config import AppConfig, DeploymentConfig, GauntlexConfig
from gauntlex.core.arbiter import Arbiter
from gauntlex.core.gauntlex import Gauntlex


def _build_result(round_number: int) -> BuildResult:
    return BuildResult(code="print('hi')", language="python", model_response=None, round_number=round_number)


def _breaker_result(round_number: int) -> BreakerResult:
    return BreakerResult(
        attacks=[Attack(id=f"atk-{round_number}", cwe="CWE-89", title="t", description="d")],
        model_response=None,
        cwe_categories_used=["CWE-89"],
        round_number=round_number,
    )


@pytest.mark.parametrize(
    "attack_count,rounds_max,expected",
    [
        (5, 5, 1),    # quick: 5 attacks / 5 rounds
        (20, 5, 4),   # standard: 20 attacks / 5 rounds
        (50, 5, 10),  # thorough: 50 attacks / 5 rounds
        (1, 5, 1),    # floors at 1, never 0
    ],
)
def test_attacks_per_round_wired_from_mode_attack_count(attack_count, rounds_max, expected):
    """Regression: cfg.gauntlex.attack_count (set from --mode) used to be computed
    but never passed anywhere — the Breaker always picked a hardcoded 3-5 CWEs per
    round regardless of mode, so `standard` (target 20) and `thorough` (target 50)
    silently produced about the same handful of attacks as `quick`. This asserts
    the configured mode target actually reaches the Breaker.
    """
    config = AppConfig(
        gauntlex=GauntlexConfig(attack_count=attack_count, rounds_max=rounds_max),
        deployment=DeploymentConfig(model_provider="local"),
    )
    engine = Gauntlex(config=config)
    assert engine.breaker.attacks_per_round == expected


@pytest.mark.asyncio
async def test_round_2_plus_calls_breaker_exactly_once():
    """Regression: for round_num > 1, the engine used to fire a concurrent
    Breaker.attack() call via asyncio.gather() (attacking the previous round's
    target) and then immediately discard that result and call Breaker.attack()
    a second time on the fresh build. That doubled Breaker cost/latency for every
    round after the first with nothing to show for it. Assert exactly one
    Breaker.attack() call happens per round now.
    """
    config = AppConfig(
        gauntlex=GauntlexConfig(attack_count=5, rounds_max=3, early_exit_threshold=1.1),
        deployment=DeploymentConfig(model_provider="local"),
    )
    engine = Gauntlex(config=config)

    engine.builder.generate = AsyncMock(side_effect=lambda spec, round_number, feedback: _build_result(round_number))
    engine.breaker.attack = AsyncMock(side_effect=lambda target, round_number, **kw: _breaker_result(round_number))

    arbiter = Arbiter(provider="ollama", model="llama3.1:8b")
    result = await engine.run("spec text", arbiter)

    assert engine.breaker.attack.call_count == 3  # once per round, not 5 (2x for rounds 2-3)
    assert engine.builder.generate.call_count == 3
    assert result.attack_count == 3  # one attack per round accumulated
