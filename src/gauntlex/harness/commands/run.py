"""Run command — programmatic API for gauntlex run."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class RunResult:
    run_id: str
    ars: float
    passed: bool
    report: dict
    elapsed_seconds: float = 0.0


async def execute(
    spec: str,
    mode: str = "standard",
    domains: list[str] | None = None,
    config_path: str | None = None,
) -> RunResult:
    """
    Execute a full Gauntlex adversarial session.

    Args:
        spec: Spec text (code or issue description to attack)
        mode: quick / standard / thorough
        domains: Policy domains to activate (None = use config defaults)
        config_path: Path to .gauntlex.yml (None = auto-detect)

    Returns:
        RunResult with run_id, ARS score, pass/fail, and full report dict
    """
    from gauntlex.config import AppConfig
    from gauntlex.core.gauntlex import Gauntlex
    from gauntlex.core.arbiter import Arbiter
    from gauntlex.output.report import generate_run_id, build_report, save_report
    from gauntlex.policy.engine import load_domains, combine_policy_context, list_available_domains
    from gauntlex.memory.forge import KnowledgeForge
    from gauntlex.brain.language_profiles import attack_context_for_spec
    from gauntlex.brain.domain_intelligence import DomainIntelligenceAdapter

    cfg = AppConfig.load(config_path)
    mode_counts = {"quick": 5, "standard": 20, "thorough": 50}
    cfg.gauntlex.attack_count = mode_counts.get(mode, 20)

    if domains is None:
        domains = [d.split("@")[0] for d in cfg.policy.domains] or ["owasp_top10"]

    available = list_available_domains()
    valid_domains = [d for d in domains if d in available]
    policy_context = ""
    if valid_domains:
        policy_context = combine_policy_context(load_domains(valid_domains))

    # Append language-specific attack context so Breaker prioritizes ecosystem CWEs
    lang_context = attack_context_for_spec(spec)
    if lang_context:
        policy_context = (policy_context + "\n\n" + lang_context).strip()

    # DIA: enrich policy context with live MCP threat intelligence (best-effort)
    if cfg.mcp_servers:
        dia = DomainIntelligenceAdapter.from_config(cfg)
        policy_context, _dia_results = dia.enrich(policy_context)

    forge = KnowledgeForge()
    recalled = ""
    if forge.is_available():
        hits = forge.recall_attacks(spec, n_results=10)
        recalled = forge.format_recalled_for_prompt(hits)

    model_kwargs: dict = cfg.model_kwargs()

    run_id = generate_run_id()

    t0 = time.monotonic()

    arbiter = Arbiter(**model_kwargs)
    pair = Gauntlex(config=cfg, recalled_attacks=recalled, policy_context=policy_context)
    result = await pair.run(spec, arbiter)

    for rr in result.rounds:
        await arbiter.score_round_async(rr.build, rr.breaker)
    result.final_ars = arbiter.final_ars(result.all_attacks)

    playbook_ver = f"{valid_domains[0] if valid_domains else 'owasp_top10'}@v2025.1"
    report = build_report(
        result=result,
        run_id=run_id,
        spec_ref="<programmatic>",
        playbook_version=playbook_ver,
    )

    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    save_report(report, cfg.reports_dir)

    passed = result.final_ars >= cfg.gate.minimum_ars
    return RunResult(
        run_id=run_id,
        ars=result.final_ars,
        passed=passed,
        report=report,
        elapsed_seconds=round(time.monotonic() - t0, 2),
    )
