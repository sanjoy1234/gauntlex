"""Tests for Policy Hub — combatpair policy install (Sprint 5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from combatpair.policy.hub import (
    HubDomainEntry,
    InstallResult,
    fetch_index,
    install_domain,
    list_installed,
    search_index,
)
from combatpair.policy.engine import list_available_domains, load_domain


# ── Fixtures ───────────────────────────────────────────────────────────────────

_SAMPLE_INDEX = {
    "schema_version": "1",
    "updated_at": "2026-06-28",
    "domains": [
        {
            "name": "owasp_api_security",
            "version": "2023.1",
            "description": "OWASP API Security Top 10",
            "regulatory_framework": "OWASP API Security",
            "url": "https://example.com/owasp_api_security.yaml",
            "scenarios_count": 10,
            "tags": ["api", "rest", "owasp"],
        },
        {
            "name": "nist_ssdf",
            "version": "1.1",
            "description": "NIST SSDF v1.1 scenarios",
            "regulatory_framework": "NIST SSDF 1.1",
            "url": "https://example.com/nist_ssdf.yaml",
            "scenarios_count": 8,
            "tags": ["nist", "government"],
        },
    ],
}

_SAMPLE_YAML = """\
name: owasp_api_security
version: "2023.1"
description: "OWASP API Security Top 10"
regulatory_framework: "OWASP API Security"
scenarios:
  - id: api-001
    cwe: CWE-285
    title: "Broken Object-Level Authorization"
    regulatory_ref: "API1:2023"
    description: "Attacker substitutes object ID to access another user's data."
    example: "GET /api/orders/123 → substitute 124"
"""


def _make_mock_server(tmp_path: Path, index: dict, yaml_content: str):
    """Write index and YAML to temp files; return a callable fetch_index override."""
    index_path = tmp_path / "index.json"
    index_path.write_text(json.dumps(index))

    yaml_path = tmp_path / "owasp_api_security.yaml"
    yaml_path.write_text(yaml_content)

    # Patch URLs in index to point to temp files (file:// would need httpx file support)
    # Instead, we monkeypatch fetch_index and the download in tests directly.
    return index_path, yaml_path


# ── HubDomainEntry ─────────────────────────────────────────────────────────────

def test_hub_domain_entry_fields():
    entry = HubDomainEntry(
        name="test", version="1.0", description="desc",
        regulatory_framework="OWASP", url="http://example.com/test.yaml",
        scenarios_count=5, tags=["web"],
    )
    assert entry.name == "test"
    assert entry.scenarios_count == 5
    assert "web" in entry.tags


# ── InstallResult ──────────────────────────────────────────────────────────────

def test_install_result_success(tmp_path):
    r = InstallResult(domain="test", version="1.0", installed_path=tmp_path / "test.yaml")
    assert r.success is True
    assert r.already_installed is False


def test_install_result_with_error(tmp_path):
    r = InstallResult(domain="test", version="?", installed_path=tmp_path / "test.yaml",
                      error="Not found")
    assert r.success is False


def test_install_result_already_installed(tmp_path):
    r = InstallResult(domain="test", version="1.0", installed_path=tmp_path / "test.yaml",
                      already_installed=True)
    assert r.already_installed is True
    assert r.success is True


# ── list_installed ─────────────────────────────────────────────────────────────

def test_list_installed_empty(tmp_path):
    assert list_installed(tmp_path / "nonexistent") == []


def test_list_installed_finds_yaml_files(tmp_path):
    (tmp_path / "domain_a.yaml").write_text("name: domain_a")
    (tmp_path / "domain_b.yaml").write_text("name: domain_b")
    result = list_installed(tmp_path)
    assert "domain_a" in result
    assert "domain_b" in result


def test_list_installed_ignores_non_yaml(tmp_path):
    (tmp_path / "notes.txt").write_text("not a domain")
    (tmp_path / "domain_a.yaml").write_text("name: domain_a")
    result = list_installed(tmp_path)
    assert "notes" not in result
    assert "domain_a" in result


# ── install_domain (offline: monkeypatched) ────────────────────────────────────

def test_install_domain_already_installed_no_force(tmp_path):
    dest = tmp_path / "owasp_api_security.yaml"
    dest.write_text("existing content")
    result = install_domain("owasp_api_security", policies_dir=tmp_path, force=False)
    assert result.already_installed is True
    assert dest.read_text() == "existing content"  # not overwritten


def test_install_domain_already_installed_with_force(tmp_path, monkeypatch):
    dest = tmp_path / "owasp_api_security.yaml"
    dest.write_text("old content")

    def mock_fetch(_url):
        return [HubDomainEntry(
            name="owasp_api_security", version="2023.1", description="",
            regulatory_framework="OWASP API Security",
            url="http://mock/owasp_api_security.yaml",
            scenarios_count=10, tags=[],
        )]

    def mock_get(url, **kwargs):
        class FakeResp:
            text = _SAMPLE_YAML
            def raise_for_status(self): pass
        return FakeResp()

    monkeypatch.setattr("combatpair.policy.hub.fetch_index", mock_fetch)
    import httpx
    monkeypatch.setattr(httpx, "get", mock_get)

    result = install_domain("owasp_api_security", policies_dir=tmp_path, force=True)
    assert result.success is True
    assert not result.already_installed
    assert dest.read_text() == _SAMPLE_YAML


def test_install_domain_not_in_index(tmp_path, monkeypatch):
    monkeypatch.setattr("combatpair.policy.hub.fetch_index", lambda _url: [])
    result = install_domain("nonexistent_domain", policies_dir=tmp_path)
    assert not result.success
    assert "not found" in result.error.lower()


def test_install_domain_network_error(tmp_path, monkeypatch):
    def bad_fetch(_url):
        raise RuntimeError("Connection refused")
    monkeypatch.setattr("combatpair.policy.hub.fetch_index", bad_fetch)
    result = install_domain("owasp_api_security", policies_dir=tmp_path)
    assert not result.success
    assert "Connection refused" in result.error


def test_install_domain_creates_policies_dir(tmp_path, monkeypatch):
    new_dir = tmp_path / "new_policies"
    assert not new_dir.exists()

    def mock_fetch(_url):
        return [HubDomainEntry(
            name="owasp_api_security", version="2023.1", description="",
            regulatory_framework="OWASP", url="http://mock/x.yaml",
            scenarios_count=5, tags=[],
        )]

    def mock_get(url, **kwargs):
        class FakeResp:
            text = _SAMPLE_YAML
            def raise_for_status(self): pass
        return FakeResp()

    monkeypatch.setattr("combatpair.policy.hub.fetch_index", mock_fetch)
    import httpx
    monkeypatch.setattr(httpx, "get", mock_get)

    result = install_domain("owasp_api_security", policies_dir=new_dir)
    assert result.success
    assert new_dir.exists()
    assert (new_dir / "owasp_api_security.yaml").exists()


# ── search_index (monkeypatched) ───────────────────────────────────────────────

def test_search_index_by_name(monkeypatch):
    entries = [
        HubDomainEntry("owasp_api_security", "2023.1", "OWASP API Security", "OWASP", "http://x", 10, ["api"]),
        HubDomainEntry("nist_ssdf", "1.1", "NIST SSDF", "NIST", "http://y", 8, ["government"]),
    ]
    monkeypatch.setattr("combatpair.policy.hub.fetch_index", lambda _url: entries)
    results = search_index("owasp")
    assert len(results) == 1
    assert results[0].name == "owasp_api_security"


def test_search_index_by_tag(monkeypatch):
    entries = [
        HubDomainEntry("owasp_api_security", "2023.1", "OWASP API Security", "OWASP", "http://x", 10, ["api", "rest"]),
        HubDomainEntry("nist_ssdf", "1.1", "NIST SSDF", "NIST", "http://y", 8, ["government"]),
    ]
    monkeypatch.setattr("combatpair.policy.hub.fetch_index", lambda _url: entries)
    results = search_index("api")
    assert any(e.name == "owasp_api_security" for e in results)


def test_search_index_no_match(monkeypatch):
    entries = [
        HubDomainEntry("owasp_api_security", "2023.1", "OWASP API Security", "OWASP", "http://x", 10, ["api"]),
    ]
    monkeypatch.setattr("combatpair.policy.hub.fetch_index", lambda _url: entries)
    results = search_index("pci_dss")
    assert results == []


# ── engine integration — installed domain discovery ────────────────────────────

def test_installed_domain_appears_in_list_available(tmp_path, monkeypatch):
    (tmp_path / "my_custom.yaml").write_text("name: my_custom")
    monkeypatch.setattr("combatpair.policy.engine._USER_POLICIES_DIR", tmp_path)
    domains = list_available_domains()
    assert "my_custom" in domains


def test_installed_domain_loadable(tmp_path, monkeypatch):
    (tmp_path / "owasp_api_security.yaml").write_text(_SAMPLE_YAML)
    monkeypatch.setattr("combatpair.policy.engine._USER_POLICIES_DIR", tmp_path)
    domain = load_domain("owasp_api_security")
    assert domain.name == "owasp_api_security"
    assert len(domain.scenarios) == 1
    assert domain.scenarios[0].cwe == "CWE-285"


def test_builtin_domains_still_loadable_with_user_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("combatpair.policy.engine._USER_POLICIES_DIR", tmp_path)
    domain = load_domain("owasp_top10")
    assert domain.name is not None
    assert len(domain.scenarios) > 0


# ── policy-hub index.json on disk ─────────────────────────────────────────────

def test_hub_index_json_is_valid():
    index_path = Path(__file__).parent.parent / "policy-hub" / "index.json"
    assert index_path.exists(), "policy-hub/index.json must exist"
    data = json.loads(index_path.read_text())
    assert "domains" in data
    assert len(data["domains"]) >= 1
    for d in data["domains"]:
        assert "name" in d
        assert "url" in d


def test_hub_domain_yamls_exist():
    hub_dir = Path(__file__).parent.parent / "policy-hub" / "domains"
    yamls = list(hub_dir.glob("*.yaml"))
    assert len(yamls) >= 2, "At least 2 community domain YAMLs must exist"


def test_hub_domain_yaml_loadable_via_engine(tmp_path, monkeypatch):
    hub_domains_dir = Path(__file__).parent.parent / "policy-hub" / "domains"
    monkeypatch.setattr("combatpair.policy.engine._USER_POLICIES_DIR", hub_domains_dir)
    domain = load_domain("owasp_api_security")
    assert domain.name == "owasp_api_security"
    assert len(domain.scenarios) >= 5
