"""Learn command — update Knowledge Forge from completed run reports."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LearnResult:
    run_id: str
    attacks_stored: int
    effectiveness_updated: bool
    skipped: bool = False
    skip_reason: str = ""


def execute(run_id: str, config_path: str | None = None) -> LearnResult:
    """
    Feed a completed run's attacks into the Knowledge Forge and update
    effectiveness tracking for the Adaptive Brain.

    Args:
        run_id: The run_id of a completed Resilience Report
        config_path: Path to .gauntlex.yml

    Returns:
        LearnResult with count of attacks stored
    """
    from gauntlex.config import AppConfig
    from gauntlex.output.report import load_report
    from gauntlex.memory.forge import KnowledgeForge
    from gauntlex.brain.effectiveness import AttackEffectivenessTracker

    cfg = AppConfig.load(config_path)

    try:
        report = load_report(run_id, cfg.reports_dir)
    except FileNotFoundError:
        return LearnResult(
            run_id=run_id,
            attacks_stored=0,
            effectiveness_updated=False,
            skipped=True,
            skip_reason=f"Report '{run_id}' not found",
        )

    forge = KnowledgeForge()
    if not forge.is_available():
        return LearnResult(
            run_id=run_id,
            attacks_stored=0,
            effectiveness_updated=False,
            skipped=True,
            skip_reason="Knowledge Forge (ChromaDB) not available",
        )

    stored = 0
    tracker = AttackEffectivenessTracker()

    for attack in report.get("attacks", []):
        cwe = attack.get("cwe", "CWE-UNKNOWN")
        title = attack.get("title", "")
        description = attack.get("description", "")
        verdict = attack.get("verdict", "MISSED")
        score = 1.0 if verdict == "MITIGATED" else (0.5 if verdict == "PARTIAL" else 0.0)

        fp = report.get("spec_fingerprint", {})

        forge.store_attack(
            attack_id=attack.get("id", f"{cwe}-{stored}"),
            description=f"{title}\n{description}",
            cwe=cwe,
            severity=attack.get("severity", "medium"),
            run_id=run_id,
            effectiveness=score,
            codebase_fingerprint=str(fp),
        )
        stored += 1

        tracker.update(cwe=cwe, score=score, fingerprint=str(fp))

    return LearnResult(
        run_id=run_id,
        attacks_stored=stored,
        effectiveness_updated=stored > 0,
    )
