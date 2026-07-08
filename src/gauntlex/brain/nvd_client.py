"""
NIST National Vulnerability Database (NVD) API v2.0 client.

Enriches the GAUNTLEX Breaker with live CVE intelligence from NIST's
authoritative vulnerability database. Queries for recent CVEs matching
the CWE categories being tested, providing the Breaker with current
real-world exploitation context.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  Without API key: 5 requests / 30 seconds
  With API key:   50 requests / 30 seconds
  API key: free at https://nvd.nist.gov/developers/request-an-api-key

Environment variables (never committed — set in shell or .env):
  NVD_API_KEY — optional NIST NVD API key for higher rate limits

Usage:
  client = NvdClient()
  context = client.get_recent_cves(["CWE-89", "CWE-79"], max_results=5)
  # Returns formatted text for Breaker policy context injection
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_LOOKBACK_DAYS = 90
_MAX_DESCRIPTION_LEN = 300


@dataclass
class NvdCve:
    """A single CVE record from NVD."""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published: str
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class NvdResult:
    """Result of an NVD API query."""
    cves: list[NvdCve]
    total_results: int
    query_cwe: str
    success: bool
    error: str = ""


class NvdClient:
    """
    NIST NVD API v2.0 client.

    Queries for CVEs by CWE identifier and formats results as threat
    intelligence context for the GAUNTLEX Breaker agent.

    All calls are best-effort — a network failure or API error never
    blocks a GAUNTLEX run; the Breaker simply runs without live NVD context.
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        base_url: str = _NVD_BASE_URL,
    ):
        self._api_key = api_key or os.environ.get("NVD_API_KEY", "")
        self._timeout = timeout
        self._base_url = base_url

    def get_recent_cves(
        self,
        cwe_ids: list[str],
        max_per_cwe: int = 3,
        lookback_days: int = _DEFAULT_LOOKBACK_DAYS,
    ) -> str:
        """
        Query NVD for recent CVEs matching the given CWE identifiers.

        Returns formatted text suitable for injection into the Breaker's
        policy context. Returns empty string on any error.

        Args:
            cwe_ids:      CWE identifiers to query (e.g. ["CWE-89", "CWE-79"])
            max_per_cwe:  Maximum CVEs to fetch per CWE (default 3)
            lookback_days: How many days back to search (default 90)
        """
        if not cwe_ids:
            return ""

        sections: list[str] = []
        for cwe in cwe_ids[:5]:  # cap at 5 CWEs to respect rate limits
            result = self._query_cwe(cwe, max_per_cwe, lookback_days)
            if result.success and result.cves:
                sections.append(_format_cve_section(result))

        if not sections:
            return ""

        return (
            "\n--- Live threat intelligence from NIST NVD (nvd.nist.gov) ---\n"
            + "\n".join(sections)
            + "\n--- End NVD enrichment ---\n"
        )

    def query_cwe(
        self,
        cwe_id: str,
        max_results: int = 5,
        lookback_days: int = _DEFAULT_LOOKBACK_DAYS,
    ) -> NvdResult:
        """Public entry point — query a single CWE. Returns NvdResult."""
        return self._query_cwe(cwe_id, max_results, lookback_days)

    def _query_cwe(
        self,
        cwe_id: str,
        max_results: int,
        lookback_days: int,
    ) -> NvdResult:
        """Query NVD API for CVEs matching a single CWE."""
        try:
            import httpx
        except ImportError:
            return NvdResult(cves=[], total_results=0, query_cwe=cwe_id, success=False, error="httpx not installed")

        now = datetime.now(timezone.utc)
        pub_start = (now - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        params: dict[str, Any] = {
            "cweId": cwe_id,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": min(max_results, 20),
        }

        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            resp = httpx.get(
                self._base_url,
                params=params,
                headers=headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            msg = str(e)
            logger.debug("NVD: query for %s failed: %s", cwe_id, msg)
            return NvdResult(cves=[], total_results=0, query_cwe=cwe_id, success=False, error=msg)

        cves = _parse_nvd_response(data, cwe_id)
        total = data.get("totalResults", len(cves))
        return NvdResult(cves=cves, total_results=total, query_cwe=cwe_id, success=True)


def _parse_nvd_response(data: dict, cwe_id: str) -> list[NvdCve]:
    """Parse the NVD API v2.0 response into NvdCve objects."""
    cves: list[NvdCve] = []

    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Description (prefer English)
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:_MAX_DESCRIPTION_LEN]
                break

        # CVSS score (try v3.1, fall back to v3.0, then v2.0)
        cvss_score = 0.0
        severity = "UNKNOWN"
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", entries[0].get("baseSeverity", "UNKNOWN"))
                break

        # CWE IDs from weaknesses
        cwe_ids: list[str] = []
        for w in cve_data.get("weaknesses", []):
            for wd in w.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # Published date
        published = cve_data.get("published", "")[:10]

        # Top references (max 2)
        refs = [r.get("url", "") for r in cve_data.get("references", [])[:2] if r.get("url")]

        if cve_id and desc:
            cves.append(NvdCve(
                cve_id=cve_id,
                description=desc,
                cvss_score=cvss_score,
                severity=severity.upper(),
                published=published,
                cwe_ids=cwe_ids or [cwe_id],
                references=refs,
            ))

    return cves


def _format_cve_section(result: NvdResult) -> str:
    """Format NVD results for a single CWE into a Breaker context string."""
    lines = [f"Recent {result.query_cwe} CVEs ({result.total_results} total in NVD):"]
    for cve in result.cves:
        lines.append(
            f"  {cve.cve_id} [{cve.severity} {cve.cvss_score}] {cve.published}: {cve.description}"
        )
    return "\n".join(lines)
