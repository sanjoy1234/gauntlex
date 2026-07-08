"""Tests for the Adversarial Policy Engine (APE)."""

from __future__ import annotations

import pytest

from gauntlex.policy.engine import (
    combine_policy_context,
    list_available_domains,
    load_domain,
    load_domains,
    validate_domain_yaml,
)
from gauntlex.policy.schema import PolicyDomain, AttackScenario


# ── list_available_domains ────────────────────────────────────────────────────

def test_list_available_domains_includes_owasp():
    domains = list_available_domains()
    assert "owasp_top10" in domains


def test_list_available_domains_includes_new_domains():
    domains = list_available_domains()
    expected = {"owasp_top10", "hipaa", "finra", "pci_dss", "soc2"}
    assert expected.issubset(set(domains)), f"Missing domains: {expected - set(domains)}"


# ── load_domain ───────────────────────────────────────────────────────────────

def test_load_owasp_top10():
    d = load_domain("owasp_top10")
    assert d.name == "owasp_top10"
    assert len(d.scenarios) >= 10


def test_load_hipaa():
    d = load_domain("hipaa")
    assert d.name == "hipaa"
    assert len(d.scenarios) >= 5
    cwes = [s.cwe for s in d.scenarios]
    assert any("CWE-" in c for c in cwes)


def test_load_finra():
    d = load_domain("finra")
    assert d.name == "finra"
    assert len(d.scenarios) >= 5


def test_load_pci_dss():
    d = load_domain("pci_dss")
    assert d.name == "pci_dss"
    assert len(d.scenarios) >= 5


def test_load_soc2():
    d = load_domain("soc2")
    assert d.name == "soc2"
    assert len(d.scenarios) >= 6


def test_load_domain_not_found_raises():
    with pytest.raises(FileNotFoundError):
        load_domain("nonexistent_domain_xyz")


# ── load_domains (multi-domain) ────────────────────────────────────────────────

def test_load_domains_multiple():
    domains = load_domains(["owasp_top10", "hipaa"])
    assert len(domains) == 2
    names = [d.name for d in domains]
    assert "owasp_top10" in names
    assert "hipaa" in names


def test_load_domains_skips_invalid():
    # load_domains silently skips unknown domains
    domains = load_domains(["owasp_top10", "does_not_exist"])
    assert len(domains) == 1
    assert domains[0].name == "owasp_top10"


# ── combine_policy_context ─────────────────────────────────────────────────────

def test_combine_policy_context_returns_string():
    domains = load_domains(["owasp_top10"])
    ctx = combine_policy_context(domains)
    assert isinstance(ctx, str)
    assert len(ctx) > 100


def test_combine_policy_context_includes_scenario_titles():
    domains = load_domains(["owasp_top10"])
    ctx = combine_policy_context(domains)
    assert "SQL Injection" in ctx or "CWE-89" in ctx


def test_combine_policy_context_empty_list():
    ctx = combine_policy_context([])
    assert ctx == "" or isinstance(ctx, str)


# ── validate_domain_yaml ───────────────────────────────────────────────────────

def test_validate_owasp_has_no_errors():
    d = load_domain("owasp_top10")
    errors = validate_domain_yaml(d)
    assert errors == [], f"Unexpected validation errors: {errors}"


def test_validate_hipaa_has_no_errors():
    d = load_domain("hipaa")
    errors = validate_domain_yaml(d)
    assert errors == [], f"Unexpected validation errors: {errors}"


def test_validate_pci_dss_has_no_errors():
    d = load_domain("pci_dss")
    errors = validate_domain_yaml(d)
    assert errors == []


def test_validate_soc2_has_no_errors():
    d = load_domain("soc2")
    errors = validate_domain_yaml(d)
    assert errors == []


def test_validate_finra_has_no_errors():
    d = load_domain("finra")
    errors = validate_domain_yaml(d)
    assert errors == []


def test_validate_by_domain_name():
    errors = validate_domain_yaml("owasp_top10")
    assert errors == []


# ── PolicyDomain / AttackScenario schema ─────────────────────────────────────

def test_policy_domain_to_breaker_context():
    d = PolicyDomain(
        name="test",
        version="1.0",
        description="Test domain",
        regulatory_framework="Test Framework",
        scenarios=[
            AttackScenario(
                id="test-001",
                cwe="CWE-89",
                title="SQL Injection",
                description="Find SQL injection vectors",
                regulatory_ref="OWASP A03",
            )
        ],
    )
    ctx = d.to_breaker_context()
    assert "CWE-89" in ctx
    assert "SQL Injection" in ctx


def test_policy_domain_cwe_list():
    d = load_domain("owasp_top10")
    cwes = d.cwe_list
    assert len(cwes) > 0
    assert all(c.startswith("CWE-") for c in cwes)


def test_policy_domain_all_scenarios_have_cwes():
    for name in ["owasp_top10", "hipaa", "pci_dss", "soc2", "finra"]:
        d = load_domain(name)
        for s in d.scenarios:
            assert s.cwe.startswith("CWE-"), f"{name}/{s.id}: invalid CWE format: {s.cwe}"
