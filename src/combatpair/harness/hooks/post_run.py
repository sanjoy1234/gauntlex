"""post_run hook — fired once after all CombatPair rounds complete."""

from __future__ import annotations

from ..runner import RunContext


def emit_report(ctx: RunContext) -> None:
    """
    Build and save the Resilience Report after a completed run.

    Writes JSON to .combatpair/reports/<run_id>.json.
    If ARS < gate threshold, fires Slack and Jira notifications (best-effort).
    Stores path in ctx.metadata["report_path"].
    """
    if ctx.result is None:
        return

    from pathlib import Path
    from ...output.report import build_report, save_report
    from ...output.notifications import notify_low_ars

    report = build_report(
        result=ctx.result,
        run_id=ctx.run_id,
        spec_ref=ctx.metadata.get("spec_ref", ""),
        commit_sha=ctx.metadata.get("commit_sha", ""),
        playbook_version=ctx.metadata.get("playbook_version", "owasp_top10@v2025.1"),
    )

    reports_dir = ctx.config.reports_dir
    path = save_report(report, reports_dir)
    ctx.metadata["report_path"] = str(path)
    ctx.metadata["report"] = report

    # Fire notifications if gate failed
    gate = ctx.config.gate
    ars = report["ars_score"]
    if ars < gate.minimum_ars:
        notif_cfg = ctx.config.notifications
        notif = notify_low_ars(
            run_id=ctx.run_id,
            ars=ars,
            attacks=report.get("attacks", []),
            gate_threshold=gate.minimum_ars,
            slack_webhook=notif_cfg.slack_webhook,
            jira_project=notif_cfg.jira_project,
        )
        ctx.metadata["notifications"] = {
            "slack_sent": notif.slack_sent,
            "jira_created": notif.jira_created,
            "jira_issue_key": notif.jira_issue_key,
        }
