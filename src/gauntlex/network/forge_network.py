"""
Forge Network — opt-in community adversarial pattern sharing.

Users who opt in share anonymized attack patterns from their Knowledge Forge
to a central hub. In return they can pull community-discovered attacks back
into their local Forge to improve Breaker recall.

Privacy guarantees:
  - Opt-in only: GAUNTLEX_FORGE_NETWORK_ENABLED=true required
  - No code, no spec, no repo info is ever transmitted
  - Only the attack vector (description), CWE, severity, and verdict are shared
  - A stable anonymous contributor ID (SHA-256 of the machine's git remote URL)
    identifies the source; no user names or email addresses

Protocol:
  POST /patterns          — push new high-quality patterns (ARS > threshold)
  GET  /patterns?cwe=...  — pull patterns for a given CWE
  GET  /patterns/stats    — hub-level aggregate statistics

All calls are best-effort and never block a `gauntlex run`.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_DEFAULT_HUB_URL = "https://forge-network.gauntlex.dev"  # future public hub


@dataclass
class ForgeNetworkConfig:
    """Configuration for Forge Network participation."""
    enabled: bool = field(
        default_factory=lambda: os.environ.get("GAUNTLEX_FORGE_NETWORK_ENABLED", "false").lower() == "true"
    )
    hub_url: str = field(
        default_factory=lambda: os.environ.get("GAUNTLEX_FORGE_HUB_URL", _DEFAULT_HUB_URL)
    )
    min_ars_to_share: float = field(
        default_factory=lambda: float(os.environ.get("GAUNTLEX_FORGE_MIN_ARS", "0.85"))
    )
    contributor_id: str = ""
    timeout_seconds: int = 10

    @classmethod
    def from_env(cls) -> "ForgeNetworkConfig":
        cfg = cls()
        cfg.contributor_id = _derive_contributor_id()
        return cfg


def _derive_contributor_id() -> str:
    """Stable anonymous contributor ID from local git remote URL (SHA-256, truncated)."""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0 and result.stdout.strip():
            raw = result.stdout.strip()
            return hashlib.sha256(raw.encode()).hexdigest()[:16]
    except Exception:
        pass
    return hashlib.sha256(b"anonymous").hexdigest()[:16]


@dataclass
class SharedPattern:
    """An anonymized attack pattern suitable for network sharing."""
    cwe: str
    attack_vector: str          # description only — no code, no spec content
    severity: str
    verdict: str                # mitigated | partial | missed
    language: str
    contributor_id: str = ""
    pattern_id: str = ""        # assigned by hub on push

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "attack_vector": self.attack_vector,
            "severity": self.severity,
            "verdict": self.verdict,
            "language": self.language,
            "contributor_id": self.contributor_id,
        }


@dataclass
class NetworkResult:
    """Result of a Forge Network operation."""
    success: bool
    operation: str
    patterns_count: int = 0
    error: str = ""


def push_patterns(
    patterns: list[SharedPattern],
    config: ForgeNetworkConfig,
) -> NetworkResult:
    """Push anonymized patterns to the Forge Network hub. Best-effort."""
    if not config.enabled:
        return NetworkResult(success=False, operation="push", error="network disabled")
    if not patterns:
        return NetworkResult(success=True, operation="push", patterns_count=0)

    try:
        import httpx
        payload = {
            "contributor_id": config.contributor_id,
            "patterns": [p.to_dict() for p in patterns],
        }
        resp = httpx.post(
            f"{config.hub_url}/patterns",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=config.timeout_seconds,
        )
        resp.raise_for_status()
        return NetworkResult(success=True, operation="push", patterns_count=len(patterns))
    except Exception as e:
        return NetworkResult(success=False, operation="push", error=str(e))


def pull_patterns(
    cwe: str,
    config: ForgeNetworkConfig,
    limit: int = 50,
) -> tuple[list[SharedPattern], NetworkResult]:
    """Pull community patterns for a given CWE from the hub."""
    if not config.enabled:
        return [], NetworkResult(success=False, operation="pull", error="network disabled")

    try:
        import httpx
        resp = httpx.get(
            f"{config.hub_url}/patterns",
            params={"cwe": cwe, "limit": limit},
            timeout=config.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json()
        patterns = [
            SharedPattern(
                cwe=p.get("cwe", cwe),
                attack_vector=p.get("attack_vector", ""),
                severity=p.get("severity", "medium"),
                verdict=p.get("verdict", "unknown"),
                language=p.get("language", "unknown"),
                contributor_id=p.get("contributor_id", ""),
                pattern_id=p.get("pattern_id", ""),
            )
            for p in data.get("patterns", [])
        ]
        return patterns, NetworkResult(success=True, operation="pull", patterns_count=len(patterns))
    except httpx.RequestError:
        # DNS failure, connection refused, timeout, etc. — the hub is pre-launch
        # today, so this is the expected case, not an error worth a raw OS/socket
        # message (fetch_hub_stats() already degrades this gracefully; pull_patterns
        # used to leak str(e) verbatim, e.g. "[Errno 8] nodename nor servname
        # provided, or not known" — meaningless to anyone who isn't debugging DNS).
        return [], NetworkResult(
            success=False, operation="pull",
            error=f"hub unreachable (offline or not yet launched): {config.hub_url}",
        )
    except Exception as e:
        return [], NetworkResult(success=False, operation="pull", error=str(e))


def fetch_hub_stats(config: ForgeNetworkConfig) -> dict[str, Any]:
    """Fetch aggregate statistics from the hub. Returns empty dict on failure."""
    if not config.enabled:
        return {}
    try:
        import httpx
        resp = httpx.get(f"{config.hub_url}/patterns/stats", timeout=config.timeout_seconds)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


def extract_shareable_patterns(
    attacks: list[dict],
    config: ForgeNetworkConfig,
    fingerprint: dict | None = None,
) -> list[SharedPattern]:
    """
    Extract SharedPatterns from a run's attack list.

    Only includes attacks with score >= min_ars_to_share or with verdict=='missed'
    (missed attacks are the most valuable for the community to learn from).
    """
    patterns: list[SharedPattern] = []
    language = (fingerprint or {}).get("language", "unknown")

    for attack in attacks:
        score = attack.get("score", 0.0)
        verdict = _score_to_verdict(score)
        # Share: high-quality mitigations OR all misses (max learning value)
        if score >= config.min_ars_to_share or verdict == "missed":
            desc = attack.get("description", attack.get("attack", ""))
            if not desc:
                continue
            patterns.append(SharedPattern(
                cwe=attack.get("cwe", "CWE-0"),
                attack_vector=desc[:500],  # cap length — no raw code
                severity=attack.get("severity", "medium"),
                verdict=verdict,
                language=language,
                contributor_id=config.contributor_id,
            ))
    return patterns


def _score_to_verdict(score: float) -> str:
    if score >= 0.9:
        return "mitigated"
    if score >= 0.5:
        return "partial"
    return "missed"
