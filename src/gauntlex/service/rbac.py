"""
Enterprise RBAC — GitHub team-based role enforcement for GAUNTLEX CPaaS.

Roles (in ascending permission order):
  Developer  — read-only: view reports, download evidence
  Reviewer   — Developer + trigger re-runs, override gate on individual PRs
  Admin      — Reviewer + manage policies, configure ARS gate, manage teams

Role membership is derived from GitHub team slugs configured via environment:
  GAUNTLEX_ADMIN_TEAMS   = "security-leads,platform-admin"
  GAUNTLEX_REVIEWER_TEAMS = "backend-leads,security-review"
  GAUNTLEX_DEV_TEAMS     = "all-engineers"   (default: any authenticated user)

Team membership is verified via GitHub REST API (GET /orgs/{org}/teams/{slug}/memberships/{username}).
All API calls are best-effort and cached for `cache_ttl_seconds` (default 300s).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from enum import IntEnum


class Role(IntEnum):
    NONE = 0
    DEVELOPER = 1
    REVIEWER = 2
    ADMIN = 3


ROLE_LABELS = {Role.NONE: "none", Role.DEVELOPER: "developer",
               Role.REVIEWER: "reviewer", Role.ADMIN: "admin"}


@dataclass
class RbacConfig:
    """RBAC configuration — loaded from environment or explicit kwargs."""
    org: str = field(default_factory=lambda: os.environ.get("GITHUB_ORG", ""))
    admin_teams: list[str] = field(default_factory=lambda: _split_env("GAUNTLEX_ADMIN_TEAMS"))
    reviewer_teams: list[str] = field(default_factory=lambda: _split_env("GAUNTLEX_REVIEWER_TEAMS"))
    dev_teams: list[str] = field(default_factory=lambda: _split_env("GAUNTLEX_DEV_TEAMS"))
    allow_any_authenticated: bool = field(
        default_factory=lambda: os.environ.get("GAUNTLEX_ALLOW_ANY_AUTH", "true").lower() == "true"
    )
    cache_ttl_seconds: int = 300

    @classmethod
    def from_env(cls) -> "RbacConfig":
        return cls()


def _split_env(key: str) -> list[str]:
    raw = os.environ.get(key, "")
    return [t.strip() for t in raw.split(",") if t.strip()]


@dataclass
class _CacheEntry:
    role: Role
    expires_at: float


class RbacEnforcer:
    """
    Resolves and caches GitHub team-based roles.

    Usage:
        enforcer = RbacEnforcer(config, github_token="ghs_...")
        role = enforcer.resolve_role(org="myorg", username="alice")
        enforcer.require(role, Role.REVIEWER)  # raises PermissionError if insufficient
    """

    def __init__(self, config: RbacConfig, github_token: str = ""):
        self._config = config
        self._token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self._cache: dict[str, _CacheEntry] = {}

    def resolve_role(self, username: str, org: str | None = None) -> Role:
        """Return the highest Role the GitHub user holds in the configured teams."""
        org = org or self._config.org
        cache_key = f"{org}/{username}"
        entry = self._cache.get(cache_key)
        if entry and time.monotonic() < entry.expires_at:
            return entry.role

        role = self._compute_role(username, org)
        self._cache[cache_key] = _CacheEntry(
            role=role,
            expires_at=time.monotonic() + self._config.cache_ttl_seconds,
        )
        return role

    def _compute_role(self, username: str, org: str) -> Role:
        if not org:
            return Role.DEVELOPER if self._config.allow_any_authenticated else Role.NONE

        # Check from highest privilege downward
        for team in self._config.admin_teams:
            if self._is_member(org, team, username):
                return Role.ADMIN
        for team in self._config.reviewer_teams:
            if self._is_member(org, team, username):
                return Role.REVIEWER
        for team in self._config.dev_teams:
            if self._is_member(org, team, username):
                return Role.DEVELOPER
        if self._config.allow_any_authenticated:
            return Role.DEVELOPER
        return Role.NONE

    def _is_member(self, org: str, team_slug: str, username: str) -> bool:
        """Query GitHub API to check team membership. Returns False on any error."""
        if not self._token:
            return False
        try:
            import httpx
            url = f"https://api.github.com/orgs/{org}/teams/{team_slug}/memberships/{username}"
            resp = httpx.get(
                url,
                headers={"Authorization": f"Bearer {self._token}", "Accept": "application/vnd.github+json"},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("state") == "active"
        except Exception:
            pass
        return False

    @staticmethod
    def require(actual: Role, minimum: Role, action: str = "perform this action") -> None:
        """Raise PermissionError if actual role is below minimum."""
        if actual < minimum:
            raise PermissionError(
                f"Role '{ROLE_LABELS[actual]}' is insufficient to {action}. "
                f"Required: '{ROLE_LABELS[minimum]}'."
            )

    def invalidate(self, username: str, org: str | None = None) -> None:
        """Remove a user's cached role (force re-fetch on next resolve)."""
        org = org or self._config.org
        self._cache.pop(f"{org}/{username}", None)

    def clear_cache(self) -> None:
        self._cache.clear()


# ── Convenience decorator for FastAPI / webhook handlers ─────────────────────

def require_role(minimum: Role):
    """
    Decorator factory for functions that receive `username` as their first arg.

    Usage:
        enforcer = RbacEnforcer(RbacConfig.from_env(), token)

        @require_role(Role.ADMIN)
        def install_policy(username, domain):
            ...
    """
    def decorator(fn):
        def wrapper(username: str, *args, **kwargs):
            # Enforcer must be available as a module-level singleton or injected
            # This is a lightweight wrapper — callers inject the enforcer via closure
            raise NotImplementedError("Use enforcer.require() directly in handlers")
        wrapper.__wrapped__ = fn
        wrapper.__minimum_role__ = minimum
        return wrapper
    return decorator
