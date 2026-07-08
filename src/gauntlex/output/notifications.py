"""
Notifications — Slack webhook and Jira ticket creation for low-ARS runs.

Fires when ARS < gate.minimum_ars. Both channels are optional and gated
by config: notifications.slack_webhook and notifications.jira_project.

Designed to run as a post_run hook (sync) so failures in notifications
never block the ARS gate result.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class NotificationResult:
    slack_sent: bool = False
    jira_created: bool = False
    jira_issue_key: str = ""
    slack_error: str = ""
    jira_error: str = ""


def send_slack(
    webhook_url: str,
    run_id: str,
    ars: float,
    miss_count: int,
    top_misses: list[dict],
    gate_threshold: float = 0.80,
) -> tuple[bool, str]:
    """
    Post a Slack message to the configured webhook URL.

    Returns (success, error_message).
    """
    if not webhook_url:
        return False, "no webhook configured"

    verdict = "BLOCKED" if ars < gate_threshold else "PASSED"
    color = "#B91C1C" if ars < gate_threshold else "#047857"

    miss_lines = "\n".join(
        f"• [{a.get('cwe', '?')}] {a.get('title', 'Unknown')} ({a.get('severity', 'medium')})"
        for a in top_misses[:5]
    )

    payload = {
        "attachments": [
            {
                "color": color,
                "fallback": f"GAUNTLEX ARS {ars:.2f} — {verdict}",
                "title": f"🛡️ GAUNTLEX Adversarial Gate — {verdict}",
                "title_link": "",
                "fields": [
                    {"title": "Run ID", "value": f"`{run_id}`", "short": True},
                    {"title": "ARS Score", "value": f"*{ars:.2f}*", "short": True},
                    {"title": "Gate Threshold", "value": f"{gate_threshold:.2f}", "short": True},
                    {"title": "Missed Attacks", "value": str(miss_count), "short": True},
                ],
                "text": (f"*Unmitigated attacks:*\n{miss_lines}" if miss_lines else ""),
                "footer": "GAUNTLEX Adversarial Co-Generation Engine",
            }
        ]
    }

    try:
        import httpx
        resp = httpx.post(webhook_url, json=payload, timeout=10.0)
        resp.raise_for_status()
        return True, ""
    except Exception as e:
        msg = str(e)
        logger.warning("Slack notification failed: %s", msg)
        return False, msg


def create_jira_ticket(
    jira_base_url: str,
    jira_project: str,
    jira_token: str,
    run_id: str,
    ars: float,
    miss_count: int,
    top_misses: list[dict],
) -> tuple[bool, str, str]:
    """
    Create a Jira issue for a low-ARS run.

    Returns (success, issue_key, error_message).
    Requires env vars: JIRA_BASE_URL, JIRA_TOKEN.
    """
    if not jira_project or not jira_base_url or not jira_token:
        return False, "", "missing jira_project, JIRA_BASE_URL, or JIRA_TOKEN"

    miss_items = "\n".join(
        f"* [{a.get('cwe', '?')}] {a.get('title', 'Unknown')} — {a.get('severity', 'medium')}: {a.get('description', '')[:200]}"
        for a in top_misses[:10]
    )

    summary = f"[GAUNTLEX] ARS {ars:.2f} gate failure — run {run_id[:16]}"
    description = (
        f"GAUNTLEX adversarial gate blocked a run with ARS {ars:.2f}.\n\n"
        f"Run ID: {run_id}\n"
        f"Missed attacks: {miss_count}\n\n"
        f"*Unmitigated vulnerabilities:*\n{miss_items}\n\n"
        f"Fix these security issues and re-run GAUNTLEX before merging."
    )

    payload = {
        "fields": {
            "project": {"key": jira_project},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Bug"},
            "priority": {"name": "High" if ars < 0.5 else "Medium"},
            "labels": ["security", "gauntlex", "adversarial-gate"],
        }
    }

    try:
        import httpx
        resp = httpx.post(
            f"{jira_base_url.rstrip('/')}/rest/api/2/issue",
            json=payload,
            headers={
                "Authorization": f"Bearer {jira_token}",
                "Content-Type": "application/json",
            },
            timeout=15.0,
        )
        resp.raise_for_status()
        issue_key = resp.json().get("key", "")
        return True, issue_key, ""
    except Exception as e:
        msg = str(e)
        logger.warning("Jira ticket creation failed: %s", msg)
        return False, "", msg


def notify_low_ars(
    run_id: str,
    ars: float,
    attacks: list[dict],
    gate_threshold: float,
    slack_webhook: str = "",
    jira_project: str = "",
) -> NotificationResult:
    """
    Dispatch notifications for a low-ARS run.

    Reads JIRA_BASE_URL and JIRA_TOKEN from environment variables.
    Both channels are best-effort — failures are logged but not raised.
    """
    import os

    result = NotificationResult()
    missed = [a for a in attacks if a.get("verdict") == "MISSED"]

    if slack_webhook:
        ok, err = send_slack(
            webhook_url=slack_webhook,
            run_id=run_id,
            ars=ars,
            miss_count=len(missed),
            top_misses=missed,
            gate_threshold=gate_threshold,
        )
        result.slack_sent = ok
        result.slack_error = err

    jira_base = os.environ.get("JIRA_BASE_URL", "")
    jira_token = os.environ.get("JIRA_TOKEN", "")
    if jira_project and jira_base and jira_token:
        ok, key, err = create_jira_ticket(
            jira_base_url=jira_base,
            jira_project=jira_project,
            jira_token=jira_token,
            run_id=run_id,
            ars=ars,
            miss_count=len(missed),
            top_misses=missed,
        )
        result.jira_created = ok
        result.jira_issue_key = key
        result.jira_error = err

    return result
