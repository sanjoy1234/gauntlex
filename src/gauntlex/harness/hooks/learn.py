"""learn hook — async, fires after post_run to update the Adaptive Brain."""

from __future__ import annotations

from ..runner import RunContext


async def forge_write(ctx: RunContext) -> None:
    """Write all attacks from this run into the Knowledge Forge and Forge Ledger."""
    if ctx.result is None:
        return

    from ...memory.forge import KnowledgeForge
    from ...memory.forge_ledger import ForgeLedger

    forge = KnowledgeForge()
    ledger = ForgeLedger()
    fp = ctx.metadata.get("codebase_fingerprint", "")

    for attack in ctx.result.all_attacks:
        if forge.is_available():
            forge.store_attack(
                attack_id=attack.id,
                description=attack.description,
                cwe=attack.cwe,
                severity=attack.severity,
                run_id=ctx.run_id,
                effectiveness=attack.score,
                codebase_fingerprint=fp,
            )
        ledger.write_entry(
            cwe=attack.cwe,
            attack_id=attack.id,
            title=attack.title,
            description=attack.description,
            severity=attack.severity,
            effectiveness=attack.score,
            run_id=ctx.run_id,
            fingerprint=fp,
        )

    ctx.metadata["ledger_entries_written"] = len(ctx.result.all_attacks)


async def effectiveness_update(ctx: RunContext) -> None:
    """Update the Adaptive Brain's effectiveness scores for this run's attacks."""
    if ctx.result is None:
        return

    from ...brain.effectiveness import AttackEffectivenessTracker

    tracker = AttackEffectivenessTracker()
    fp = ctx.metadata.get("codebase_fingerprint", "")
    for attack in ctx.result.all_attacks:
        tracker.update(attack.cwe, attack.score, fp)
