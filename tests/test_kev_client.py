"""Tests for CISA KEV catalog client — Sprint B."""

from __future__ import annotations

import pytest

from combatpair.brain.kev_client import (
    KevClient,
    KevEntry,
    KevResult,
    _format_kev_section,
    _CWE_KEYWORDS,
)

# ── KevEntry dataclass ────────────────────────────────────────────────────────

def test_kev_entry_fields():
    e = KevEntry(
        cve_id="CVE-2023-34362",
        vendor_project="Progress",
        product="MOVEit Transfer",
        vulnerability_name="SQL Injection",
        date_added="2023-06-01",
        description="SQL injection via HTTP request",
        required_action="Apply patch",
        known_ransomware=True,
        matched_cwes=["CWE-89"],
    )
    assert e.cve_id == "CVE-2023-34362"
    assert e.known_ransomware is True
    assert "CWE-89" in e.matched_cwes


# ── KevResult ─────────────────────────────────────────────────────────────────

def test_kev_result_success():
    r = KevResult(entries=[], total_in_catalog=100, query_cwes=["CWE-89"], success=True)
    assert r.success is True
    assert r.error == ""


# ── CWE keyword mapping ───────────────────────────────────────────────────────

def test_cwe_keywords_contains_sql_injection():
    assert "CWE-89" in _CWE_KEYWORDS
    assert "sql injection" in _CWE_KEYWORDS["CWE-89"]


def test_cwe_keywords_contains_ssrf():
    assert "CWE-918" in _CWE_KEYWORDS
    assert "ssrf" in _CWE_KEYWORDS["CWE-918"]


def test_cwe_keywords_contains_xss():
    assert "CWE-79" in _CWE_KEYWORDS
    assert any("xss" in kw or "cross-site" in kw for kw in _CWE_KEYWORDS["CWE-79"])


# ── _format_kev_section ───────────────────────────────────────────────────────

def test_format_kev_section_contains_cve_id():
    result = KevResult(
        entries=[KevEntry(
            cve_id="CVE-2023-34362",
            vendor_project="Progress",
            product="MOVEit Transfer",
            vulnerability_name="SQL Injection",
            date_added="2023-06-01",
            description="SQL injection allows unauthenticated access",
            required_action="Apply patch",
            known_ransomware=True,
        )],
        total_in_catalog=1000,
        query_cwes=["CWE-89"],
        success=True,
    )
    text = _format_kev_section(result)
    assert "CVE-2023-34362" in text
    assert "CISA" in text
    assert "ransomware" in text.lower()


def test_format_kev_section_total_count_shown():
    result = KevResult(entries=[], total_in_catalog=1234, query_cwes=["CWE-89"], success=True)
    text = _format_kev_section(result)
    assert "1234" in text


# ── KevClient.query_cwes (mocked HTTP) ────────────────────────────────────────

def _make_kev_catalog():
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2023-34362",
                "vendorProject": "Progress",
                "product": "MOVEit Transfer",
                "vulnerabilityName": "SQL Injection Vulnerability",
                "dateAdded": "2023-06-01",
                "shortDescription": "SQL injection allows unauthenticated remote code execution",
                "requiredAction": "Apply mitigations",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "shortDescription": "Remote code execution via JNDI injection",
                "requiredAction": "Apply patch",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2021-26855",
                "vendorProject": "Microsoft",
                "product": "Exchange Server",
                "vulnerabilityName": "SSRF Vulnerability",
                "dateAdded": "2021-03-02",
                "shortDescription": "Server-side request forgery allows unauthorized access",
                "requiredAction": "Apply cumulative update",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ]
    }


def test_query_cwes_network_error_returns_empty(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("x")))
    client = KevClient()
    result = client.query_cwes(["CWE-89"])
    assert result.success is False
    assert result.entries == []


def test_query_cwes_matches_sql_injection(monkeypatch):
    import httpx

    def mock_get(url, timeout, follow_redirects):
        class R:
            def raise_for_status(self): pass
            def json(self): return _make_kev_catalog()
        return R()

    monkeypatch.setattr(httpx, "get", mock_get)
    client = KevClient()
    result = client.query_cwes(["CWE-89"])
    assert result.success is True
    assert any("CVE-2023-34362" == e.cve_id for e in result.entries)


def test_query_cwes_matches_ssrf(monkeypatch):
    import httpx

    def mock_get(url, timeout, follow_redirects):
        class R:
            def raise_for_status(self): pass
            def json(self): return _make_kev_catalog()
        return R()

    monkeypatch.setattr(httpx, "get", mock_get)
    client = KevClient()
    result = client.query_cwes(["CWE-918"])
    assert result.success is True
    assert any("CVE-2021-26855" == e.cve_id for e in result.entries)


def test_query_cwes_respects_max_per_cwe(monkeypatch):
    import httpx

    # Create a catalog with 5 SQL injection entries
    catalog = {
        "vulnerabilities": [
            {
                "cveID": f"CVE-2023-{1000 + i}",
                "vendorProject": "Vendor",
                "product": "DB",
                "vulnerabilityName": "SQL Injection",
                "dateAdded": "2023-01-01",
                "shortDescription": "sql injection via login form",
                "requiredAction": "patch",
                "knownRansomwareCampaignUse": "Unknown",
            }
            for i in range(5)
        ]
    }

    def mock_get(url, timeout, follow_redirects):
        class R:
            def raise_for_status(self): pass
            def json(self): return catalog
        return R()

    monkeypatch.setattr(httpx, "get", mock_get)
    client = KevClient()
    result = client.query_cwes(["CWE-89"], max_per_cwe=2)
    assert len(result.entries) == 2


def test_get_exploited_for_cwes_returns_empty_on_network_error(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("x")))
    client = KevClient()
    text = client.get_exploited_for_cwes(["CWE-89"])
    assert text == ""


def test_get_exploited_for_cwes_returns_formatted_text(monkeypatch):
    import httpx

    def mock_get(url, timeout, follow_redirects):
        class R:
            def raise_for_status(self): pass
            def json(self): return _make_kev_catalog()
        return R()

    monkeypatch.setattr(httpx, "get", mock_get)
    client = KevClient()
    text = client.get_exploited_for_cwes(["CWE-89"])
    assert "CISA" in text
    assert "CVE-2023-34362" in text


def test_get_exploited_for_cwes_empty_list_returns_empty():
    client = KevClient()
    assert client.get_exploited_for_cwes([]) == ""


def test_catalog_cached_after_first_fetch(monkeypatch):
    import httpx
    call_count = {"n": 0}

    def mock_get(url, timeout, follow_redirects):
        call_count["n"] += 1
        class R:
            def raise_for_status(self): pass
            def json(self): return _make_kev_catalog()
        return R()

    monkeypatch.setattr(httpx, "get", mock_get)
    client = KevClient()
    client.query_cwes(["CWE-89"])
    client.query_cwes(["CWE-918"])  # second call — should use cached catalog
    assert call_count["n"] == 1  # only one HTTP fetch


def test_ransomware_flag_set_correctly(monkeypatch):
    import httpx

    def mock_get(url, timeout, follow_redirects):
        class R:
            def raise_for_status(self): pass
            def json(self): return _make_kev_catalog()
        return R()

    monkeypatch.setattr(httpx, "get", mock_get)
    client = KevClient()
    result = client.query_cwes(["CWE-89"])
    moveit = next(e for e in result.entries if e.cve_id == "CVE-2023-34362")
    assert moveit.known_ransomware is True
