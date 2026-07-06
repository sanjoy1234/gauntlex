"""Post ARS as a GitHub commit status check."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import ServiceConfig


async def post_commit_status(
    owner: str,
    repo: str,
    sha: str,
    ars: float,
    run_id: str,
    minimum_ars: float = 0.80,
    installation_token: str | None = None,
) -> bool:
    """
    Post the ARS as a GitHub commit status (pending → success/failure).

    Args:
        owner: GitHub org or user
        repo: Repository name
        sha: Commit SHA to post status on
        ars: Adversarial Resilience Score (0.0 – 1.0)
        run_id: COMBATPAIR run_id for the status description
        minimum_ars: Threshold for pass/fail
        installation_token: GitHub App installation token

    Returns:
        True if status was posted successfully
    """
    token = installation_token or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return False

    passed = ars >= minimum_ars
    state = "success" if passed else "failure"
    description = (
        f"ARS {ars:.3f} {'≥' if passed else '<'} {minimum_ars:.2f} — "
        f"{'PASSED' if passed else 'BLOCKED'} [{run_id}]"
    )

    payload = {
        "state": state,
        "target_url": f"https://github.com/{owner}/{repo}/actions",
        "description": description,
        "context": "combatpair/adversarial-resilience",
    }

    try:
        import httpx
        url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{sha}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            return resp.status_code in (200, 201)
    except Exception:
        return False


def verify_webhook_signature(body: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_pr_event(payload: dict) -> dict | None:
    """
    Extract relevant PR metadata from a GitHub webhook payload.

    Returns dict with owner, repo, sha, pr_number, pr_body, or None if not a PR event.
    """
    if "pull_request" not in payload:
        return None
    pr = payload["pull_request"]
    repo = payload.get("repository", {})
    return {
        "owner": repo.get("owner", {}).get("login", ""),
        "repo": repo.get("name", ""),
        "sha": pr.get("head", {}).get("sha", ""),
        "pr_number": pr.get("number"),
        "pr_body": pr.get("body", "") or "",
        "action": payload.get("action", ""),
    }
