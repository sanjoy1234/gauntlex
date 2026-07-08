"""
Gauntlex — the core execution primitive.

Builder and Breaker run CONCURRENTLY via asyncio.gather() on the same specification.
This is the unique innovation: adversarial testing is not sequential — it begins
the moment the Builder starts. Multiple rounds until ARS converges or rounds_max hit.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from ..agents.breaker import Attack, BreakerResult, Breaker
from ..agents.builder import BuildResult, Builder
from ..config import AppConfig


@dataclass
class RoundResult:
    round_number: int
    build: BuildResult
    breaker: BreakerResult
    ars: float
    elapsed_seconds: float


@dataclass
class CombatResult:
    rounds: list[RoundResult] = field(default_factory=list)
    final_ars: float = 0.0
    all_attacks: list[Attack] = field(default_factory=list)
    total_elapsed_seconds: float = 0.0
    early_exit: bool = False

    @property
    def attack_count(self) -> int:
        return len(self.all_attacks)

    @property
    def mitigated_count(self) -> int:
        return sum(1 for a in self.all_attacks if a.score == 1.0)

    @property
    def partial_count(self) -> int:
        return sum(1 for a in self.all_attacks if a.score == 0.5)

    @property
    def miss_count(self) -> int:
        return sum(1 for a in self.all_attacks if a.score == 0.0)


class Gauntlex:
    """
    Runs Builder + Breaker concurrently on the same specification.

    Round 1: both start simultaneously on the spec text.
    Round 2+: Breaker receives the Builder's latest code as the target.
    Arbiter scores each round; early-exit if ARS is above threshold for N consecutive rounds.
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        recalled_attacks: str = "",
        policy_context: str = "",
        intent_context: str = "",
    ):
        self.config = config or AppConfig()
        cp = self.config.gauntlex

        model_kwargs: dict = self.config.model_kwargs()

        self.builder = Builder(**model_kwargs)
        self.breaker = Breaker(
            cwe_rotation=cp.cwe_rotation,
            policy_context=policy_context,
            break_context_enabled=cp.break_context_enabled,
            **model_kwargs,
        )
        self.recalled_attacks = recalled_attacks
        self.intent_context = intent_context
        self._rounds_max = cp.rounds_max
        self._early_exit_threshold = cp.early_exit_threshold
        self._early_exit_streak = cp.early_exit_streak

    async def run(self, spec: str, arbiter: "Arbiter") -> CombatResult:  # noqa: F821
        from .arbiter import Arbiter  # local import to avoid circular at module level

        start_total = time.monotonic()
        result = CombatResult()
        high_ars_streak = 0
        feedback = ""
        build_result = None

        for round_num in range(1, self._rounds_max + 1):
            start_round = time.monotonic()

            # Key primitive: Builder and Breaker run CONCURRENTLY
            target = build_result.code if build_result else spec
            build_result, breaker_result = await asyncio.gather(
                self.builder.generate(spec, round_number=round_num, feedback=feedback),
                self.breaker.attack(
                    target,
                    round_number=round_num,
                    recalled_attacks=self.recalled_attacks if round_num == 1 else "",
                    intent_context=self.intent_context if round_num == 1 else "",
                ),
            )

            # After concurrent phase: score round-1 Breaker against the just-built code
            # For round 2+, Breaker already attacked the previous build; now score vs new build
            if round_num > 1:
                # Re-attack the new build synchronously (Breaker already ran on prev build)
                breaker_result = await self.breaker.attack(
                    build_result.code,
                    round_number=round_num,
                    intent_context=self.intent_context,
                )

            round_ars = arbiter.score_round(build_result, breaker_result)
            elapsed = time.monotonic() - start_round

            round_result = RoundResult(
                round_number=round_num,
                build=build_result,
                breaker=breaker_result,
                ars=round_ars,
                elapsed_seconds=elapsed,
            )
            result.rounds.append(round_result)
            result.all_attacks.extend(breaker_result.attacks)

            # Build feedback for next round from unmitigated attacks
            unmitigated = [a for a in breaker_result.attacks if a.score < 0.5]
            feedback = _format_feedback(unmitigated)

            # Early-exit: stop if ARS is consistently above threshold
            if round_ars >= self._early_exit_threshold:
                high_ars_streak += 1
                if high_ars_streak >= self._early_exit_streak:
                    result.early_exit = True
                    break
            else:
                high_ars_streak = 0

        result.final_ars = arbiter.final_ars(result.all_attacks)
        result.total_elapsed_seconds = time.monotonic() - start_total
        return result


def _format_feedback(unmitigated: list[Attack]) -> str:
    if not unmitigated:
        return ""
    lines = ["Security issues found that must be fixed:"]
    for a in unmitigated[:5]:
        lines.append(f"- [{a.cwe}] {a.title}: {a.description}")
    return "\n".join(lines)
