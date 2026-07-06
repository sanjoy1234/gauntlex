"""
Attack effectiveness scoring — 30-run rolling EMA per (CWE, codebase fingerprint).

Effectiveness score drives Knowledge Forge query weighting and Breaker template
reinforcement/deprecation decisions.
"""

from __future__ import annotations

import json
from pathlib import Path

_DEFAULT_STORE = Path(".combatpair/brain/effectiveness.json")
_EMA_ALPHA = 0.1  # weight of new observation; 0.9 weight on history


class AttackEffectivenessTracker:
    """
    Maintains rolling exponential moving average of attack effectiveness
    per (CWE, codebase_fingerprint_prefix) pair.

    Persisted to .combatpair/brain/effectiveness.json between sessions.
    """

    def __init__(self, store_path: Path | str = _DEFAULT_STORE):
        self._store_path = Path(store_path)
        self._scores: dict[str, float] = self._load()

    def update(self, cwe: str, score: float, fingerprint: str = "") -> float:
        """Update EMA for a (CWE, fingerprint) pair. Returns new EMA."""
        cluster = _cluster_key(cwe, fingerprint)
        old = self._scores.get(cluster, score)
        new = (1 - _EMA_ALPHA) * old + _EMA_ALPHA * score
        self._scores[cluster] = round(new, 4)
        self._save()
        return new

    def get(self, cwe: str, fingerprint: str = "") -> float:
        return self._scores.get(_cluster_key(cwe, fingerprint), 0.5)

    def low_effectiveness_cwes(self, threshold: float = 0.3) -> list[str]:
        """Return CWE categories with effectiveness below threshold (candidates for rewrite)."""
        result = []
        for key, eff in self._scores.items():
            if eff < threshold:
                cwe = key.split("::")[0]
                result.append(cwe)
        return list(set(result))

    def summary(self) -> dict[str, float]:
        """Aggregate effectiveness by CWE (max across fingerprint clusters)."""
        agg: dict[str, float] = {}
        for key, eff in self._scores.items():
            cwe = key.split("::")[0]
            agg[cwe] = max(agg.get(cwe, 0.0), eff)
        return dict(sorted(agg.items(), key=lambda x: x[1], reverse=True))

    def _load(self) -> dict[str, float]:
        if self._store_path.exists():
            try:
                with open(self._store_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save(self) -> None:
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._store_path, "w") as f:
            json.dump(self._scores, f, indent=2)


def _cluster_key(cwe: str, fingerprint: str) -> str:
    prefix = fingerprint.split(":")[0] if fingerprint else "unknown"
    return f"{cwe}::{prefix}"
