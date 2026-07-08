"""Tagger — tags attacks by CWE category and policy domain for Knowledge Forge storage."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AttackTag:
    cwe: str
    policy_domains: list[str]
    severity: str
    confidence: int
    effectiveness: float = 0.0  # set post-run by brain/effectiveness.py


def tag_attack(
    cwe: str,
    severity: str,
    confidence: int,
    policy_domains: list[str] | None = None,
) -> AttackTag:
    return AttackTag(
        cwe=cwe,
        policy_domains=policy_domains or [],
        severity=severity,
        confidence=confidence,
    )


def tags_to_metadata(tag: AttackTag, run_id: str, round_number: int) -> dict:
    """Serialize tag to ChromaDB metadata dict (string values only)."""
    return {
        "cwe": tag.cwe,
        "policy_domains": ",".join(tag.policy_domains),
        "severity": tag.severity,
        "confidence": str(tag.confidence),
        "effectiveness": str(round(tag.effectiveness, 4)),
        "run_id": run_id,
        "round": str(round_number),
    }
