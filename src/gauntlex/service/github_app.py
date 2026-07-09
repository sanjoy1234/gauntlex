"""GAUNTLEX GitHub App webhook handler — CPaaS mode."""

from __future__ import annotations

import asyncio
import json
import os

from .config import ServiceConfig
from .status_check import verify_webhook_signature, parse_pr_event, post_commit_status


async def handle_webhook(body: bytes, headers: dict, config: ServiceConfig) -> dict:
    """
    Process an incoming GitHub webhook event.

    On PR open/synchronize events:
    1. Verify HMAC-SHA256 signature
    2. Extract spec from PR body
    3. Run GAUNTLEX in the configured mode
    4. Post ARS as commit status
    5. Optionally post Resilience Report as PR comment

    Args:
        body: Raw request body bytes
        headers: HTTP headers dict (must include X-Hub-Signature-256). Keys are
            matched case-insensitively — ASGI servers (uvicorn/Starlette) hand
            back lowercase header names, so a caller doing dict(request.headers)
            passes lowercase keys even though GitHub sends mixed-case ones.
        config: ServiceConfig loaded from environment

    Returns:
        dict with status, run_id, ars, and message
    """
    headers_ci = {k.lower(): v for k, v in headers.items()}
    signature = headers_ci.get("x-hub-signature-256", "")
    if not verify_webhook_signature(body, signature, config.webhook_secret):
        return {"status": "error", "message": "Invalid webhook signature"}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid JSON payload"}

    event_type = headers_ci.get("x-github-event", "")
    if event_type != "pull_request":
        return {"status": "ignored", "message": f"Ignoring event: {event_type}"}

    pr_meta = parse_pr_event(payload)
    if pr_meta is None:
        return {"status": "ignored", "message": "Not a PR event"}

    action = pr_meta.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "message": f"Ignoring PR action: {action}"}

    spec = pr_meta.get("pr_body", "").strip()
    if not spec:
        spec = f"PR #{pr_meta['pr_number']} in {pr_meta['owner']}/{pr_meta['repo']}"

    from gauntlex.harness.commands.run import execute as run_execute

    try:
        result = await run_execute(
            spec=spec,
            mode=config.gauntlex_mode,
            config_path=config.gauntlex_config_path,
        )
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

    installation_token = os.environ.get("GITHUB_TOKEN", "")
    await post_commit_status(
        owner=pr_meta["owner"],
        repo=pr_meta["repo"],
        sha=pr_meta["sha"],
        ars=result.ars,
        run_id=result.run_id,
        minimum_ars=config.minimum_ars,
        installation_token=installation_token,
    )

    if config.post_pr_comment and installation_token:
        await _post_pr_comment(
            owner=pr_meta["owner"],
            repo=pr_meta["repo"],
            pr_number=pr_meta["pr_number"],
            report=result.report,
            installation_token=installation_token,
        )

    return {
        "status": "ok",
        "run_id": result.run_id,
        "ars": result.ars,
        "passed": result.passed,
    }


async def _post_pr_comment(
    owner: str, repo: str, pr_number: int, report: dict, installation_token: str
) -> bool:
    """Post a Resilience Report summary as a PR comment."""
    from gauntlex.output.forge_bot import render_pr_comment

    comment_body = render_pr_comment(report)
    try:
        import httpx
        url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json={"body": comment_body},
                headers={
                    "Authorization": f"token {installation_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            return resp.status_code in (200, 201)
    except Exception:
        return False


def create_server(config: ServiceConfig | None = None):
    """
    Create the AIOHTTP/Starlette-compatible ASGI app for the GitHub webhook endpoint.

    Usage:
        uvicorn gauntlex.service.github_app:app --port 8080

    Note: requires `pip install starlette uvicorn` (not in core dependencies).
    """
    if config is None:
        config = ServiceConfig.from_env()

    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        async def webhook(request: Request):
            body = await request.body()
            result = await handle_webhook(
                body=body,
                headers=dict(request.headers),
                config=config,
            )
            status_code = 200 if result.get("status") != "error" else 400
            return JSONResponse(result, status_code=status_code)

        return Starlette(routes=[Route("/webhook", webhook, methods=["POST"])])

    except ImportError:
        raise RuntimeError(
            "CPaaS server requires: pip install starlette uvicorn\n"
            "Run: pip install gauntlex-ai[serve]"
        )


# ASGI app entry point for uvicorn
app = None  # populated lazily on first import with GAUNTLEX_SERVE=1
if os.environ.get("GAUNTLEX_SERVE"):
    app = create_server()
