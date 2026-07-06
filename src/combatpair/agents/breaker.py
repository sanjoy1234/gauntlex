"""Breaker agent — generates security attacks with CWE rotation."""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from pathlib import Path

from .base import AgentMessage, BaseAgent, ModelResponse
from ..core.break_context import CompressionStats, compress_breaker_inputs

BREAKER_SYSTEM = """\
You are an elite offensive security engineer performing adversarial code review.
Your job is to find real, exploitable vulnerabilities — not theoretical concerns.

Rules:
- Focus on the CWE category assigned to you for this round
- Be specific: name the exact line/function that is vulnerable
- Each attack must be actionable: describe the exploit, not just the category
- Do NOT invent vulnerabilities that are not actually present
- Score your confidence 0-10 for each finding

Output JSON array (no prose):
[
  {
    "id": "atk-<N>",
    "cwe": "CWE-XXX",
    "title": "<short title>",
    "description": "<specific exploit description>",
    "line_hint": "<function or line reference if applicable>",
    "confidence": <0-10>,
    "severity": "critical|high|medium|low"
  }
]

If you find no vulnerabilities for the assigned CWE, return an empty array [].
"""


@dataclass
class Attack:
    id: str
    cwe: str
    title: str
    description: str
    line_hint: str = ""
    confidence: int = 5
    severity: str = "medium"
    score: float = 0.0  # set by Arbiter: 1.0 mitigated / 0.5 partial / 0.0 miss


@dataclass
class BreakerResult:
    attacks: list[Attack]
    model_response: ModelResponse
    cwe_categories_used: list[str] = field(default_factory=list)
    round_number: int = 1
    compression_stats: CompressionStats | None = None


class Breaker(BaseAgent):
    def __init__(
        self,
        cwe_rotation: bool = True,
        policy_context: str = "",
        break_context_enabled: bool = True,
        **kwargs,
    ):
        super().__init__(system_prompt=BREAKER_SYSTEM, **kwargs)
        self.cwe_rotation = cwe_rotation
        self.policy_context = policy_context
        self.break_context_enabled = break_context_enabled
        self._cwe_pool = _load_cwe_pool()
        self._used_cwes: list[str] = []

    async def attack(
        self,
        target: str,
        round_number: int = 1,
        cwe_override: list[str] | None = None,
        recalled_attacks: str = "",
        intent_context: str = "",
    ) -> BreakerResult:
        """Generate attacks against a spec or code snippet, enriched with business intent."""
        cwes = cwe_override or self._select_cwes(round_number)
        self._used_cwes.extend(cwes)

        cwe_context = "\n".join(
            f"- {c}: {self._cwe_pool.get(c, 'Security vulnerability')}" for c in cwes
        )

        # BreakContext: compress all three Breaker input channels
        c_target, c_recall, c_cwe, stats = compress_breaker_inputs(
            target=target,
            recalled_attacks=recalled_attacks,
            cwe_context=cwe_context,
            enabled=self.break_context_enabled,
        )

        # Intent + Spec: business intent widens the attack surface beyond the spec alone.
        # A FINRA AML requirement + a spec saying "score this transaction" creates
        # a vulnerability surface that neither document creates alone.
        intent_section = ""
        if intent_context:
            intent_section = (
                f"\nBusiness intent (attack surface is spec + intent combined):\n"
                f"{intent_context[:2000]}\n"
            )

        policy_section = ""
        if self.policy_context:
            policy_section = f"\nCompliance context:\n{self.policy_context}\n"

        recalled_section = ""
        if c_recall:
            recalled_section = (
                f"\nHistorically effective attacks on similar codebases "
                f"(from Knowledge Forge — consider these patterns first):\n{c_recall}\n"
            )

        prompt = (
            f"Target (attack this):\n```\n{c_target}\n```\n"
            f"{intent_section}"
            f"\nAssigned CWE categories for this round:\n{c_cwe}"
            f"{policy_section}"
            f"{recalled_section}\n"
            f"Generate adversarial attacks. Return JSON array only."
        )

        messages = [AgentMessage(role="user", content=prompt)]
        response = await self.complete(messages)

        attacks = _parse_attacks(response.content, round_number)
        return BreakerResult(
            attacks=attacks,
            model_response=response,
            cwe_categories_used=cwes,
            round_number=round_number,
            compression_stats=stats,
        )

    def _select_cwes(self, round_number: int) -> list[str]:
        """Rotate through CWE pool; pick 3-5 per round without heavy repeats."""
        if not self.cwe_rotation:
            return list(self._cwe_pool.keys())[:5]

        available = [c for c in self._cwe_pool if c not in self._used_cwes[-10:]]
        if len(available) < 3:
            available = list(self._cwe_pool.keys())
            self._used_cwes.clear()

        count = min(5, len(available))
        return random.sample(available, count)

    def entropy(self) -> float:
        """Shannon entropy of CWE categories used so far."""
        if not self._used_cwes:
            return 0.0
        freq: dict[str, int] = {}
        for c in self._used_cwes:
            freq[c] = freq.get(c, 0) + 1
        total = len(self._used_cwes)
        return -sum((v / total) * math.log2(v / total) for v in freq.values())


def _extract_outermost_array(text: str) -> str | None:
    """Find the outermost [...] JSON array in text, respecting nested brackets and strings."""
    start = text.find('[')
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape_next = False
    for i, ch in enumerate(text[start:], start):
        if escape_next:
            escape_next = False
            continue
        if ch == '\\' and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _parse_attacks(text: str, round_number: int) -> list[Attack]:
    # Strip markdown code fences that some models wrap around JSON
    text = text.replace("```json", "").replace("```", "")
    extracted = _extract_outermost_array(text)
    if extracted is None:
        return []
    try:
        raw = json.loads(extracted)
    except json.JSONDecodeError:
        return []

    attacks = []
    for i, item in enumerate(raw if isinstance(raw, list) else []):
        if not isinstance(item, dict):
            continue
        try:
            attacks.append(
                Attack(
                    id=item.get("id", f"atk-{round_number:02d}{i+1:02d}"),
                    cwe=item.get("cwe", "CWE-UNKNOWN"),
                    title=item.get("title", "Unnamed attack"),
                    description=item.get("description", ""),
                    line_hint=item.get("line_hint", ""),
                    confidence=int(item.get("confidence", 5)),
                    severity=item.get("severity", "medium"),
                )
            )
        except (TypeError, ValueError):
            continue
    return attacks


def _load_cwe_pool() -> dict[str, str]:
    data_path = Path(__file__).parent.parent / "data" / "cwe_taxonomy.json"
    if data_path.exists():
        with open(data_path) as f:
            return json.load(f)
    return _FALLBACK_CWES


_FALLBACK_CWES = {
    "CWE-89":  "SQL Injection",
    "CWE-79":  "Cross-site Scripting (XSS)",
    "CWE-22":  "Path Traversal",
    "CWE-78":  "OS Command Injection",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-190": "Integer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
}
