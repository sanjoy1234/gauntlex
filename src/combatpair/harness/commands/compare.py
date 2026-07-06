"""Compare command — diff two Resilience Reports by ARS and attack patterns."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AttackDelta:
    cwe: str
    title: str
    run_a_verdict: str
    run_b_verdict: str
    delta: float  # run_b_score - run_a_score


@dataclass
class CompareResult:
    run_id_a: str
    run_id_b: str
    ars_a: float
    ars_b: float
    ars_delta: float
    improved: bool
    regressed_cwes: list[str] = field(default_factory=list)
    improved_cwes: list[str] = field(default_factory=list)
    new_attacks: list[str] = field(default_factory=list)
    attack_deltas: list[AttackDelta] = field(default_factory=list)


def execute(run_id_a: str, run_id_b: str, config_path: str | None = None) -> CompareResult:
    """
    Compare two Resilience Reports and return the delta.

    Args:
        run_id_a: Earlier / baseline run_id
        run_id_b: Later / comparison run_id
        config_path: Path to .combatpair.yml

    Returns:
        CompareResult with ARS delta, regression/improvement lists
    """
    from combatpair.config import AppConfig
    from combatpair.output.report import load_report

    cfg = AppConfig.load(config_path)
    report_a = load_report(run_id_a, cfg.reports_dir)
    report_b = load_report(run_id_b, cfg.reports_dir)

    ars_a = report_a["ars_score"]
    ars_b = report_b["ars_score"]

    attacks_a: dict[str, dict] = {a["title"]: a for a in report_a.get("attacks", [])}
    attacks_b: dict[str, dict] = {a["title"]: a for a in report_b.get("attacks", [])}

    verdict_to_score = {"MITIGATED": 1.0, "PARTIAL": 0.5, "MISSED": 0.0}

    deltas: list[AttackDelta] = []
    regressed: list[str] = []
    improved_c: list[str] = []
    new_attacks: list[str] = []

    all_titles = set(attacks_a) | set(attacks_b)
    for title in all_titles:
        a_atk = attacks_a.get(title)
        b_atk = attacks_b.get(title)

        if b_atk and not a_atk:
            new_attacks.append(title)
            continue

        if a_atk and b_atk:
            score_a = verdict_to_score.get(a_atk.get("verdict", "MISSED"), 0.0)
            score_b = verdict_to_score.get(b_atk.get("verdict", "MISSED"), 0.0)
            delta = score_b - score_a

            if abs(delta) > 0.0:
                deltas.append(AttackDelta(
                    cwe=b_atk.get("cwe", ""),
                    title=title,
                    run_a_verdict=a_atk.get("verdict", "MISSED"),
                    run_b_verdict=b_atk.get("verdict", "MISSED"),
                    delta=delta,
                ))
                cwe = b_atk.get("cwe", "UNKNOWN")
                if delta < 0:
                    regressed.append(cwe)
                else:
                    improved_c.append(cwe)

    return CompareResult(
        run_id_a=run_id_a,
        run_id_b=run_id_b,
        ars_a=ars_a,
        ars_b=ars_b,
        ars_delta=round(ars_b - ars_a, 4),
        improved=ars_b > ars_a,
        regressed_cwes=regressed,
        improved_cwes=improved_c,
        new_attacks=new_attacks,
        attack_deltas=deltas,
    )
