"""
Arbiter — ARS scoring, Shannon entropy check, early-exit, diversity retry.

The Arbiter is the impartial judge. It never generates attacks (Breaker) or
code (Builder). It scores each attack against the generated code and computes
the Adversarial Resilience Score (ARS).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..agents.base import AgentMessage, BaseAgent, ModelResponse
from ..agents.breaker import Attack, BreakerResult
from ..agents.builder import BuildResult

ARBITER_SYSTEM = """\
You are a neutral security arbiter. Your job is to determine whether a piece of code
adequately mitigates a specific security attack.

Be strict. "Mitigated" means the code provably handles the attack vector.
Partially mitigated means an edge case exists but the main vector is handled.
Missed means the code is vulnerable.

Output JSON only:
{
  "verdict": "mitigated" | "partial" | "missed",
  "reason": "<one sentence explanation>",
  "score": 1.0 | 0.5 | 0.0
}
"""


class Arbiter(BaseAgent):
    """Scores attacks against generated code. One LLM call per attack by
    default, or `consensus_samples` concurrent calls per attack when a
    confidence/agreement signal is wanted (see `_score_attack`)."""

    def __init__(self, consensus_samples: int = 1, **kwargs):
        super().__init__(system_prompt=ARBITER_SYSTEM, **kwargs)
        self.consensus_samples = consensus_samples

    def score_round(self, build: BuildResult, breaker: BreakerResult) -> float:
        """Score a round synchronously by calling _score_attack per attack.

        In production this is called after asyncio event loop delivers results.
        We schedule all scoring in parallel via asyncio in the CLI layer.
        For simplicity here: returns a heuristic score without LLM calls
        (full LLM scoring is done in score_round_async).
        """
        # Heuristic: attacks with high confidence are more likely real.
        # Real scoring uses LLM (score_round_async). This is a fallback.
        if not breaker.attacks:
            for a in breaker.attacks:
                a.score = 1.0
            return 1.0

        for attack in breaker.attacks:
            # Heuristic: assign pessimistic scores until LLM arbitration runs
            attack.score = 0.5

        return self._compute_ars(breaker.attacks)

    async def score_round_async(self, build: BuildResult, breaker: BreakerResult) -> float:
        """Score all attacks in the round via LLM calls (parallel)."""
        import asyncio

        tasks = [self._score_attack(build.code, a) for a in breaker.attacks]
        scores = await asyncio.gather(*tasks, return_exceptions=True)
        for attack, score in zip(breaker.attacks, scores):
            if isinstance(score, Exception):
                attack.score = 0.5  # conservative on error
            else:
                attack.score = score
        return self._compute_ars(breaker.attacks)

    async def _score_attack(self, code: str, attack: Attack) -> float:
        """Score one attack. Sets `attack.reason` as a side effect.

        With `consensus_samples <= 1` (default), this is a single LLM call,
        same as before. With `consensus_samples > 1`, it samples the Arbiter
        that many times concurrently, scores as the mean, and additionally
        sets `attack.consensus_samples` / `attack.consensus_agreement` — the
        fraction of samples whose discrete verdict matched the modal verdict,
        a confidence signal for low-agreement (borderline) findings.
        """
        if self.consensus_samples <= 1:
            score, reason = await self._sample_verdict(code, attack)
            attack.reason = reason
            return score

        import asyncio

        samples = await asyncio.gather(
            *[self._sample_verdict(code, attack) for _ in range(self.consensus_samples)]
        )
        scores = [s for s, _ in samples]
        reasons = [r for _, r in samples]
        verdicts = [_verdict_tier(s) for s in scores]

        modal_verdict = max(set(verdicts), key=verdicts.count)
        agreement = verdicts.count(modal_verdict) / len(verdicts)
        modal_index = verdicts.index(modal_verdict)

        attack.reason = reasons[modal_index]
        attack.consensus_samples = self.consensus_samples
        attack.consensus_agreement = round(agreement, 4)
        return round(sum(scores) / len(scores), 4)

    async def _sample_verdict(self, code: str, attack: Attack) -> tuple[float, str]:
        prompt = (
            f"Code under review:\n```\n{code}\n```\n\n"
            f"Attack: [{attack.cwe}] {attack.title}\n"
            f"Description: {attack.description}\n\n"
            f"Does the code mitigate this attack? Output JSON only."
        )
        messages = [AgentMessage(role="user", content=prompt)]
        response = await self.complete(messages)
        return _parse_verdict(response.content)

    def final_ars(self, attacks: list[Attack]) -> float:
        if not attacks:
            return 1.0
        return self._compute_ars(attacks)

    @staticmethod
    def _compute_ars(attacks: list[Attack]) -> float:
        if not attacks:
            return 1.0
        total = sum(a.score for a in attacks)
        return round(total / len(attacks), 4)

    def check_entropy(self, attacks: list[Attack], threshold: float = 1.5) -> bool:
        """Return True if attack category entropy is below threshold (too repetitive)."""
        if len(attacks) < 4:
            return False
        freq: dict[str, int] = {}
        for a in attacks:
            freq[a.cwe] = freq.get(a.cwe, 0) + 1
        total = len(attacks)
        entropy = -sum((v / total) * math.log2(v / total) for v in freq.values())
        return entropy < threshold


def _parse_verdict(text: str) -> tuple[float, str]:
    """Parse the Arbiter's JSON response into (score, reason)."""
    import json
    import re

    json_match = re.search(r"\{.*?\}", text, re.DOTALL)
    if not json_match:
        return 0.5, "Could not parse a verdict from the model response."
    try:
        data = json.loads(json_match.group())
        raw = data.get("score", 0.5)
        verdict = data.get("verdict", "partial").lower()
        reason = data.get("reason") or ""
        if verdict == "mitigated":
            return 1.0, reason
        if verdict == "missed":
            return 0.0, reason
        return float(raw), reason
    except (json.JSONDecodeError, ValueError):
        return 0.5, "Could not parse a verdict from the model response."


def _verdict_tier(score: float) -> str:
    """Bucket a continuous score into a discrete tier, for agreement voting."""
    if score >= 1.0:
        return "mitigated"
    if score <= 0.0:
        return "missed"
    return "partial"
