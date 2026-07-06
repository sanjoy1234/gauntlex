"""Tests for NIST NVD API client — Sprint B."""

from __future__ import annotations

import pytest

from combatpair.brain.nvd_client import (
    NvdClient,
    NvdCve,
    NvdResult,
    _parse_nvd_response,
    _format_cve_section,
)

# ── NvdCve dataclass ──────────────────────────────────────────────────────────

def test_nvd_cve_fields():
    cve = NvdCve(
        cve_id="CVE-2023-34362",
        description="SQL injection in MOVEit Transfer",
        cvss_score=9.8,
        severity="CRITICAL",
        published="2023-06-01",
        cwe_ids=["CWE-89"],
    )
    assert cve.cve_id == "CVE-2023-34362"
    assert cve.cvss_score == 9.8
    assert "CWE-89" in cve.cwe_ids


def test_nvd_result_success():
    r = NvdResult(cves=[], total_results=0, query_cwe="CWE-89", success=True)
    assert r.success is True
    assert r.error == ""


def test_nvd_result_failure():
    r = NvdResult(cves=[], total_results=0, query_cwe="CWE-89", success=False, error="timeout")
    assert r.success is False
    assert r.error == "timeout"


# ── _parse_nvd_response ───────────────────────────────────────────────────────

def _make_nvd_response(cve_id="CVE-2023-9999", score=7.5, severity="HIGH"):
    return {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": "A test SQL injection vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": score, "baseSeverity": severity},
                    }]
                },
                "weaknesses": [{"description": [{"value": "CWE-89"}]}],
                "published": "2023-06-01T00:00:00.000",
                "references": [{"url": "https://example.com/advisory"}],
            }
        }]
    }


def test_parse_nvd_response_returns_cve():
    cves = _parse_nvd_response(_make_nvd_response(), "CWE-89")
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2023-9999"


def test_parse_nvd_response_extracts_score():
    cves = _parse_nvd_response(_make_nvd_response(score=9.8, severity="CRITICAL"), "CWE-89")
    assert cves[0].cvss_score == 9.8
    assert cves[0].severity == "CRITICAL"


def test_parse_nvd_response_extracts_cwe():
    cves = _parse_nvd_response(_make_nvd_response(), "CWE-89")
    assert "CWE-89" in cves[0].cwe_ids


def test_parse_nvd_response_published_date_truncated():
    cves = _parse_nvd_response(_make_nvd_response(), "CWE-89")
    assert cves[0].published == "2023-06-01"


def test_parse_nvd_response_empty_returns_empty():
    cves = _parse_nvd_response({"vulnerabilities": []}, "CWE-89")
    assert cves == []


def test_parse_nvd_response_no_english_desc_skipped():
    data = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2023-1111",
                "descriptions": [{"lang": "es", "value": "descripcion"}],
                "metrics": {},
                "weaknesses": [],
                "published": "2023-01-01",
                "references": [],
            }
        }]
    }
    cves = _parse_nvd_response(data, "CWE-89")
    assert cves == []


def test_parse_nvd_response_cvss_fallback_to_v30():
    data = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2023-2222",
                "descriptions": [{"lang": "en", "value": "test vuln"}],
                "metrics": {
                    "cvssMetricV30": [{
                        "cvssData": {"baseScore": 6.5, "baseSeverity": "MEDIUM"},
                    }]
                },
                "weaknesses": [],
                "published": "2023-01-01",
                "references": [],
            }
        }]
    }
    cves = _parse_nvd_response(data, "CWE-89")
    assert cves[0].cvss_score == 6.5
    assert cves[0].severity == "MEDIUM"


# ── _format_cve_section ───────────────────────────────────────────────────────

def test_format_cve_section_contains_cve_id():
    result = NvdResult(
        cves=[NvdCve("CVE-2023-34362", "SQL injection", 9.8, "CRITICAL", "2023-06-01", ["CWE-89"])],
        total_results=1,
        query_cwe="CWE-89",
        success=True,
    )
    text = _format_cve_section(result)
    assert "CVE-2023-34362" in text
    assert "CRITICAL" in text


def test_format_cve_section_empty_cves():
    result = NvdResult(cves=[], total_results=0, query_cwe="CWE-89", success=True)
    text = _format_cve_section(result)
    assert "CWE-89" in text


# ── NvdClient.query_cwe (mocked HTTP) ─────────────────────────────────────────

def test_client_no_api_key_from_env(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    client = NvdClient()
    assert client._api_key == ""


def test_client_reads_api_key_from_env(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key-abc")
    client = NvdClient()
    assert client._api_key == "test-key-abc"


def test_query_cwe_network_error_returns_failure(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("unreachable")))
    client = NvdClient()
    result = client.query_cwe("CWE-89", max_results=3)
    assert result.success is False
    assert result.error != ""


def test_query_cwe_success(monkeypatch):
    import httpx

    def mock_get(url, params, headers, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return _make_nvd_response()
        return R()

    monkeypatch.setattr(httpx, "get", mock_get)
    client = NvdClient()
    result = client.query_cwe("CWE-89")
    assert result.success is True
    assert len(result.cves) == 1


def test_get_recent_cves_returns_empty_on_error(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("x")))
    client = NvdClient()
    text = client.get_recent_cves(["CWE-89"])
    assert text == ""


def test_get_recent_cves_returns_formatted_string(monkeypatch):
    import httpx

    def mock_get(url, params, headers, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return _make_nvd_response()
        return R()

    monkeypatch.setattr(httpx, "get", mock_get)
    client = NvdClient()
    text = client.get_recent_cves(["CWE-89"])
    assert "NVD" in text or "CVE" in text


def test_get_recent_cves_empty_list_returns_empty():
    client = NvdClient()
    assert client.get_recent_cves([]) == ""
