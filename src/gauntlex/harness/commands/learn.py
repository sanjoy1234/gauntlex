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
    from gauntlex.memory.forge_ledger import ForgeLedger
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

    attacks = report.get("attacks", [])
    if not attacks:
        return LearnResult(
            run_id=run_id,
            attacks_stored=0,
            effectiveness_updated=False,
            skipped=True,
            skip_reason="Report has no attacks to learn from",
        )

    # ChromaDB (similarity recall for future Breaker prompts) is optional and
    # may be unavailable; the Forge Ledger (plain Markdown, no dependency) is
    # not — it must always get written so `gauntlex vault` reflects real data.
    forge = KnowledgeForge()
    forge_available = forge.is_available()
    ledger = ForgeLedger()

    stored = 0
    tracker = AttackEffectivenessTracker()

    for attack in attacks:
        cwe = attack.get("cwe", "CWE-UNKNOWN")
        title = attack.get("title", "")
        description = attack.get("description", "")
        severity = attack.get("severity", "medium")
        attack_id = attack.get("id", f"{cwe}-{stored}")
        verdict = attack.get("verdict", "MISSED")
        score = 1.0 if verdict == "MITIGATED" else (0.5 if verdict == "PARTIAL" else 0.0)

        fp = report.get("spec_fingerprint", {})

        if forge_available:
            forge.store_attack(
                attack_id=attack_id,
                description=f"{title}\n{description}",
                cwe=cwe,
                severity=severity,
                run_id=run_id,
                effectiveness=score,
                codebase_fingerprint=str(fp),
            )

        ledger.write_entry(
            cwe=cwe,
            attack_id=attack_id,
            title=title,
            description=description,
            severity=severity,
            effectiveness=score,
            run_id=run_id,
            fingerprint=str(fp),
        )

        stored += 1
        tracker.update(cwe=cwe, score=score, fingerprint=str(fp))

    return LearnResult(
        run_id=run_id,
        attacks_stored=stored,
        effectiveness_updated=stored > 0,
    )
