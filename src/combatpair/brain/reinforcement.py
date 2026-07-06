"""Pattern reinforcement and deprecation — manages Breaker template weights."""

from __future__ import annotations

import json
from pathlib import Path

_DEFAULT_STORE = Path(".combatpair/brain/reinforcement.json")
_DEPRECATION_THRESHOLD = 0.3
_DEPRECATION_MIN_RUNS = 10
_GRADUATION_THRESHOLD = 0.5


class PatternReinforcementScheduler:
    """
    Tracks hit/miss counts per CWE attack template.
    Marks templates for deprecation (too many misses) or promotion (high hits).
    """

    def __init__(self, store_path: Path | str = _DEFAULT_STORE):
        self._store_path = Path(store_path)
        self._state: dict[str, dict] = self._load()

    def record(self, cwe: str, score: float) -> None:
        if cwe not in self._state:
            self._state[cwe] = {"runs": 0, "total_score": 0.0, "consecutive_low": 0, "status": "active"}

        entry = self._state[cwe]
        entry["runs"] += 1
        entry["total_score"] += score

        avg = entry["total_score"] / entry["runs"]
        if avg < _DEPRECATION_THRESHOLD:
            entry["consecutive_low"] = entry.get("consecutive_low", 0) + 1
        else:
            entry["consecutive_low"] = 0

        if entry["consecutive_low"] >= _DEPRECATION_MIN_RUNS and entry["status"] == "active":
            entry["status"] = "deprecated"
        elif avg >= _GRADUATION_THRESHOLD and entry["status"] == "quarantine":
            entry["status"] = "active"

        self._save()

    def deprecated_cwes(self) -> list[str]:
        return [cwe for cwe, s in self._state.items() if s["status"] == "deprecated"]

    def active_cwes(self) -> list[str]:
        return [cwe for cwe, s in self._state.items() if s["status"] in ("active", "quarantine")]

    def promote_to_quarantine(self, cwe: str) -> None:
        """A rewritten template enters quarantine before graduating to active."""
        if cwe in self._state:
            self._state[cwe]["status"] = "quarantine"
            self._state[cwe]["consecutive_low"] = 0
            self._save()

    def _load(self) -> dict:
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
            json.dump(self._state, f, indent=2)
