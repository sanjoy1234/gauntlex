"""
Stochastic Beam Executor (experimental) — parallel Breaker beams for exhaustive attack coverage.

Status: experimental — not in the default Gauntlex execution path.
Enable via: config.gauntlex.beam_width > 1

The Beam Executor runs N parallel Breaker instances (beams) against the same spec
and merges the unique attacks, ranked by confidence. This dramatically increases
attack surface coverage at the cost of N× token usage.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..agents.breaker import Attack, Breaker, BreakerResult
    from ..config import AppConfig


@dataclass
class BeamResult:
    attacks: list["Attack"]
    beam_count: int
    total_raw_attacks: int
    dedup_ratio: float


async def run_beam(
    spec: str,
    breakers: list["Breaker"],
    round_number: int = 1,
    recalled_attacks: str = "",
) -> BeamResult:
    """
    Run N Breaker beams concurrently and merge unique attacks.

    Args:
        spec: Target spec to attack
        breakers: List of Breaker instances (one per beam)
        round_number: Current adversarial round
        recalled_attacks: Recalled attacks from Knowledge Forge

    Returns:
        BeamResult with merged, deduplicated attacks ranked by confidence
    """
    tasks = [
        breaker.attack(
            target=spec,
            round_number=round_number,
            recalled_attacks=recalled_attacks,
        )
        for breaker in breakers
    ]

    results: list["BreakerResult"] = await asyncio.gather(*tasks, return_exceptions=True)

    all_attacks: list["Attack"] = []
    for r in results:
        if isinstance(r, Exception):
            continue
        all_attacks.extend(r.attacks)

    total_raw = len(all_attacks)
    merged = _dedup_attacks(all_attacks)

    return BeamResult(
        attacks=merged,
        beam_count=len(breakers),
        total_raw_attacks=total_raw,
        dedup_ratio=len(merged) / total_raw if total_raw else 1.0,
    )


def _dedup_attacks(attacks: list["Attack"]) -> list["Attack"]:
    """Deduplicate attacks by (cwe, title) keeping highest-confidence instance."""
    seen: dict[str, "Attack"] = {}
    for atk in attacks:
        key = f"{atk.cwe}:{atk.title.lower()[:60]}"
        if key not in seen or atk.confidence > seen[key].confidence:
            seen[key] = atk
    return sorted(seen.values(), key=lambda a: a.confidence, reverse=True)


def create_beam_breakers(
    width: int,
    config: "AppConfig",
    policy_context: str = "",
) -> list["Breaker"]:
    """
    Create N Breaker instances configured to operate as beam ensemble.

    Each beam gets an independent CWE rotation state so beams explore
    different vulnerability categories in the same round.
    """
    from ..agents.breaker import Breaker

    model_kwargs: dict = config.model_kwargs()

    return [
        Breaker(cwe_rotation=True, policy_context=policy_context, **model_kwargs)
        for _ in range(width)
    ]
