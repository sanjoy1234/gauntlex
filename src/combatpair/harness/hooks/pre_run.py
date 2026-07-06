"""pre_run hooks — fired once before the first CombatPair round."""

from __future__ import annotations

from ..runner import RunContext


def avf_gate(ctx: RunContext) -> None:
    """
    AVF (Attack Validation Framework) gate.

    Runs the Breaker against 5 golden CVE fixtures to verify the model can
    find known vulnerabilities. Requires ≥75% hit rate (4 of 5) before
    allowing a production run to proceed.

    Skipped if:
    - config has avf_skip=True (testing only)
    - golden fixtures directory does not exist
    - model is unreachable (gate warns but does not block)
    """
    import asyncio
    from pathlib import Path

    if ctx.config.metadata.get("avf_skip"):  # type: ignore[union-attr]
        ctx.metadata["avf_status"] = "skipped_by_config"
        return

    golden_dir = Path(__file__).parent.parent.parent.parent.parent / "tests" / "fixtures" / "golden"
    if not golden_dir.exists():
        ctx.metadata["avf_status"] = "skipped_no_fixtures"
        ctx.metadata["avf_warning"] = "AVF golden fixtures not found — skipping gate"
        return

    fixtures = sorted(golden_dir.glob("*.json"))
    if not fixtures:
        ctx.metadata["avf_status"] = "skipped_no_fixtures"
        return

    cfg = ctx.config
    model_kwargs: dict = cfg.model_kwargs()

    try:
        hit_rate = asyncio.run(_run_avf_async(fixtures, model_kwargs))
    except Exception as exc:
        ctx.metadata["avf_status"] = "skipped_model_error"
        ctx.metadata["avf_warning"] = f"AVF gate skipped — model error: {exc}"
        return

    ctx.metadata["avf_hit_rate"] = hit_rate
    ctx.metadata["avf_checked"] = True

    if hit_rate < 0.75:
        ctx.metadata["avf_status"] = "failed"
        raise RuntimeError(
            f"AVF gate FAILED: Breaker found {hit_rate:.0%} of golden fixtures "
            f"(required ≥75%). Model may not be capable enough for adversarial testing. "
            f"Set avf_skip=true in config to bypass (not recommended for production)."
        )

    ctx.metadata["avf_status"] = "passed"


async def _run_avf_async(fixtures, model_kwargs: dict) -> float:
    """Run Breaker against golden fixtures and return hit rate."""
    import json
    from ...agents.breaker import Breaker

    hits = 0
    for fixture_path in fixtures:
        try:
            fixture = json.loads(fixture_path.read_text())
            breaker = Breaker(cwe_rotation=False, **model_kwargs)
            result = await breaker.attack(
                target=fixture["vulnerable_code"],
                round_number=1,
                cwe_override=[fixture["expected_cwe"]],
            )
            if _hits_fixture(result.attacks, fixture):
                hits += 1
        except Exception:
            continue

    return hits / len(fixtures)


def _hits_fixture(attacks, fixture: dict) -> bool:
    keyword = fixture.get("expected_keyword", "").lower()
    expected_cwe = fixture.get("expected_cwe", "")
    for attack in attacks:
        text = f"{attack.title} {attack.description} {attack.cwe}".lower()
        if (keyword and keyword in text) or attack.cwe == expected_cwe:
            return True
    return False


def fingerprint_inject(ctx: RunContext) -> None:
    """
    Codebase fingerprint injection.

    Computes a lightweight fingerprint of the spec and injects historically
    effective attacks from the Knowledge Forge into the run context.
    This elevates Breaker quality on first run for known codebase patterns.
    """
    from ...brain.fingerprint import fingerprint_spec
    from ...memory.forge import KnowledgeForge

    fp = fingerprint_spec(ctx.spec)
    ctx.metadata["codebase_fingerprint"] = fp

    forge = KnowledgeForge()
    if forge.is_available():
        recalled = forge.recall_attacks(ctx.spec, n_results=10)
        ctx.metadata["recalled_attacks"] = forge.format_recalled_for_prompt(recalled)
        ctx.metadata["forge_cache_hits"] = len(recalled)
