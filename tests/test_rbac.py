"""Tests for Enterprise RBAC — Sprint 12."""

from __future__ import annotations

import time
import pytest

from gauntlex.service.rbac import (
    Role,
    RbacConfig,
    RbacEnforcer,
    ROLE_LABELS,
    require_role,
)
from gauntlex.service.config import ServiceConfig


# ── Role enum ──────────────────────────────────────────────────────────────────

def test_role_ordering():
    assert Role.NONE < Role.DEVELOPER < Role.REVIEWER < Role.ADMIN


def test_role_labels_cover_all():
    for role in Role:
        assert role in ROLE_LABELS


# ── RbacConfig ─────────────────────────────────────────────────────────────────

def test_rbac_config_defaults():
    cfg = RbacConfig(org="myorg")
    assert cfg.admin_teams == []
    assert cfg.reviewer_teams == []
    assert cfg.allow_any_authenticated is True
    assert cfg.cache_ttl_seconds == 300


def test_rbac_config_from_env(monkeypatch):
    monkeypatch.setenv("GITHUB_ORG", "acme")
    monkeypatch.setenv("GAUNTLEX_ADMIN_TEAMS", "security-leads,platform-admin")
    monkeypatch.setenv("GAUNTLEX_REVIEWER_TEAMS", "backend-leads")
    monkeypatch.setenv("GAUNTLEX_ALLOW_ANY_AUTH", "false")
    cfg = RbacConfig.from_env()
    assert cfg.org == "acme"
    assert "security-leads" in cfg.admin_teams
    assert "platform-admin" in cfg.admin_teams
    assert cfg.reviewer_teams == ["backend-leads"]
    assert cfg.allow_any_authenticated is False


# ── RbacEnforcer — no network ─────────────────────────────────────────────────

def _enforcer_with_spy(cfg: RbacConfig, member_map: dict[tuple[str, str], bool]) -> RbacEnforcer:
    """Build an enforcer that resolves membership from member_map without HTTP."""
    enforcer = RbacEnforcer(cfg, github_token="fake-token")

    def fake_is_member(org, team_slug, username):
        return member_map.get((team_slug, username), False)

    enforcer._is_member = fake_is_member
    return enforcer


def test_admin_team_member_gets_admin_role():
    cfg = RbacConfig(org="myorg", admin_teams=["security-leads"], reviewer_teams=[], dev_teams=[])
    enforcer = _enforcer_with_spy(cfg, {("security-leads", "alice"): True})
    assert enforcer.resolve_role("alice") == Role.ADMIN


def test_reviewer_team_member_gets_reviewer_role():
    cfg = RbacConfig(org="myorg", admin_teams=[], reviewer_teams=["backend-leads"], dev_teams=[])
    enforcer = _enforcer_with_spy(cfg, {("backend-leads", "bob"): True})
    assert enforcer.resolve_role("bob") == Role.REVIEWER


def test_dev_team_member_gets_developer_role():
    cfg = RbacConfig(org="myorg", admin_teams=[], reviewer_teams=[], dev_teams=["all-engineers"])
    enforcer = _enforcer_with_spy(cfg, {("all-engineers", "carol"): True})
    assert enforcer.resolve_role("carol") == Role.DEVELOPER


def test_allow_any_authenticated_grants_developer():
    cfg = RbacConfig(org="myorg", admin_teams=[], reviewer_teams=[], dev_teams=[],
                     allow_any_authenticated=True)
    enforcer = _enforcer_with_spy(cfg, {})
    assert enforcer.resolve_role("dave") == Role.DEVELOPER


def test_deny_unauthenticated_when_allow_any_false():
    cfg = RbacConfig(org="myorg", admin_teams=[], reviewer_teams=[], dev_teams=[],
                     allow_any_authenticated=False)
    enforcer = _enforcer_with_spy(cfg, {})
    assert enforcer.resolve_role("eve") == Role.NONE


def test_admin_supersedes_reviewer_team():
    cfg = RbacConfig(org="myorg", admin_teams=["admins"], reviewer_teams=["reviewers"], dev_teams=[])
    # alice is in both teams — should get ADMIN
    enforcer = _enforcer_with_spy(cfg, {("admins", "alice"): True, ("reviewers", "alice"): True})
    assert enforcer.resolve_role("alice") == Role.ADMIN


def test_no_org_configured_grants_developer_by_default():
    cfg = RbacConfig(org="", allow_any_authenticated=True)
    enforcer = RbacEnforcer(cfg)
    assert enforcer.resolve_role("frank") == Role.DEVELOPER


def test_no_org_configured_grants_none_when_disallowed():
    cfg = RbacConfig(org="", allow_any_authenticated=False)
    enforcer = RbacEnforcer(cfg)
    assert enforcer.resolve_role("frank") == Role.NONE


# ── Caching ────────────────────────────────────────────────────────────────────

def test_role_is_cached():
    cfg = RbacConfig(org="myorg", admin_teams=["admins"], cache_ttl_seconds=300)
    calls = []

    def counting_is_member(org, team_slug, username):
        calls.append((team_slug, username))
        return username == "alice" and team_slug == "admins"

    enforcer = RbacEnforcer(cfg, github_token="tok")
    enforcer._is_member = counting_is_member

    enforcer.resolve_role("alice")
    enforcer.resolve_role("alice")  # second call — should use cache
    assert len(calls) == 1          # _is_member only called once


def test_invalidate_clears_cache():
    cfg = RbacConfig(org="myorg", admin_teams=["admins"], cache_ttl_seconds=300)
    calls = []

    def counting_is_member(org, team_slug, username):
        calls.append(1)
        return False

    enforcer = RbacEnforcer(cfg, github_token="tok")
    enforcer._is_member = counting_is_member

    enforcer.resolve_role("alice")
    enforcer.invalidate("alice")
    enforcer.resolve_role("alice")
    assert len(calls) == 2  # re-fetched after invalidation


def test_clear_cache_empties_all():
    cfg = RbacConfig(org="myorg", allow_any_authenticated=True)
    enforcer = _enforcer_with_spy(cfg, {})
    enforcer.resolve_role("alice")
    enforcer.resolve_role("bob")
    enforcer.clear_cache()
    assert len(enforcer._cache) == 0


# ── require() ─────────────────────────────────────────────────────────────────

def test_require_passes_when_sufficient():
    RbacEnforcer.require(Role.ADMIN, Role.REVIEWER, "manage policies")


def test_require_raises_when_insufficient():
    with pytest.raises(PermissionError, match="insufficient"):
        RbacEnforcer.require(Role.DEVELOPER, Role.ADMIN, "manage policies")


def test_require_error_mentions_required_role():
    with pytest.raises(PermissionError, match="admin"):
        RbacEnforcer.require(Role.REVIEWER, Role.ADMIN, "something")


# ── _is_member network error resilience ───────────────────────────────────────

def test_is_member_returns_false_without_token():
    cfg = RbacConfig(org="myorg", admin_teams=["admins"])
    enforcer = RbacEnforcer(cfg, github_token="")
    # No token → should not raise, should return False
    assert enforcer._is_member("myorg", "admins", "alice") is False


def test_is_member_returns_false_on_network_error(monkeypatch):
    import httpx

    def bad_get(url, headers, timeout):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "get", bad_get)
    cfg = RbacConfig(org="myorg", admin_teams=["admins"])
    enforcer = RbacEnforcer(cfg, github_token="tok")
    assert enforcer._is_member("myorg", "admins", "alice") is False


def test_is_member_returns_false_on_404(monkeypatch):
    import httpx

    def mock_get(url, headers, timeout):
        class FakeResp:
            status_code = 404
            def json(self): return {}
        return FakeResp()

    monkeypatch.setattr(httpx, "get", mock_get)
    cfg = RbacConfig(org="myorg", admin_teams=["admins"])
    enforcer = RbacEnforcer(cfg, github_token="tok")
    assert enforcer._is_member("myorg", "admins", "alice") is False


def test_is_member_returns_true_on_200_active(monkeypatch):
    import httpx

    def mock_get(url, headers, timeout):
        class FakeResp:
            status_code = 200
            def json(self): return {"state": "active", "role": "member"}
        return FakeResp()

    monkeypatch.setattr(httpx, "get", mock_get)
    cfg = RbacConfig(org="myorg", admin_teams=["admins"])
    enforcer = RbacEnforcer(cfg, github_token="tok")
    assert enforcer._is_member("myorg", "admins", "alice") is True


# ── ServiceConfig RBAC fields ─────────────────────────────────────────────────

def test_service_config_rbac_default_disabled():
    cfg = ServiceConfig()
    assert cfg.rbac_enabled is False


def test_service_config_rbac_from_env(monkeypatch):
    monkeypatch.setenv("GAUNTLEX_RBAC_ENABLED", "true")
    monkeypatch.setenv("GITHUB_ORG", "myorg")
    cfg = ServiceConfig.from_env()
    assert cfg.rbac_enabled is True
    assert cfg.github_org == "myorg"


# ── require_role decorator ─────────────────────────────────────────────────────

def test_require_role_decorator_sets_minimum_role():
    @require_role(Role.ADMIN)
    def admin_only(username, x):
        return x * 2

    assert admin_only.__minimum_role__ == Role.ADMIN
    assert admin_only.__wrapped__ is not None
