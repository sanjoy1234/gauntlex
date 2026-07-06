"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

Enriches the COMBATPAIR Breaker with CISA's authoritative feed of vulnerabilities
that are actively being exploited in the wild. This is higher-signal than the
full NVD CVE database — every entry in the KEV catalog has confirmed in-the-wild
exploitation, making it the most relevant threat intelligence for prioritizing
which attack scenarios the Breaker should focus on.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Access: Free, public, no API key or authentication required.

Usage:
  client = KevClient()
  context = client.get_exploited_for_cwes(["CWE-89", "CWE-79"])
  # Returns formatted text for Breaker policy context injection

The feed is cached for the duration of a COMBATPAIR process — it's a ~4MB JSON
file fetched once and filtered in memory for the relevant CWE categories.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DEFAULT_TIMEOUT = 15.0
_MAX_ENTRIES_PER_CWE = 5

# CWE keyword mapping — maps CWE IDs to product/vulnerability name keywords
# Used to filter KEV entries (which don't always carry CWE labels) by context
_CWE_KEYWORDS: dict[str, list[str]] = {
    "CWE-89":   ["sql injection", "sqli"],
    "CWE-79":   ["xss", "cross-site scripting", "cross site scripting"],
    "CWE-78":   ["command injection", "os command", "shell injection", "remote code execution"],
    "CWE-94":   ["code injection", "remote code execution", "rce"],
    "CWE-22":   ["path traversal", "directory traversal"],
    "CWE-502":  ["deserialization", "unsafe deserialization"],
    "CWE-918":  ["ssrf", "server-side request forgery"],
    "CWE-287":  ["authentication bypass", "authentication failure", "improper authentication"],
    "CWE-862":  ["missing authorization", "authorization bypass", "privilege escalation"],
    "CWE-611":  ["xxe", "xml external entity"],
    "CWE-352":  ["csrf", "cross-site request forgery"],
    "CWE-327":  ["weak encryption", "cryptographic weakness"],
    "CWE-798":  ["hardcoded credential", "hard-coded password"],
    "CWE-362":  ["race condition", "time-of-check", "toctou"],
    "CWE-770":  ["resource exhaustion", "denial of service", "dos"],
}


@dataclass
class KevEntry:
    """A single entry from the CISA KEV catalog."""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    description: str
    required_action: str
    known_ransomware: bool = False
    matched_cwes: list[str] = field(default_factory=list)


@dataclass
class KevResult:
    """Result of a KEV catalog query."""
    entries: list[KevEntry]
    total_in_catalog: int
    query_cwes: list[str]
    success: bool
    error: str = ""


class KevClient:
    """
    CISA Known Exploited Vulnerabilities (KEV) catalog client.

    Downloads the live KEV JSON feed and filters it for CWE categories
    relevant to the current COMBATPAIR run. Returns formatted Breaker context.

    The feed is fetched fresh each process — no stale cache, always current.
    Falls back to empty string on any network failure (best-effort enrichment).
    """

    def __init__(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
        feed_url: str = _KEV_FEED_URL,
    ):
        self._timeout = timeout
        self._feed_url = feed_url
        self._catalog: list[dict] | None = None  # process-level cache

    def get_exploited_for_cwes(
        self,
        cwe_ids: list[str],
        max_per_cwe: int = _MAX_ENTRIES_PER_CWE,
    ) -> str:
        """
        Return formatted KEV context for the given CWE identifiers.

        Fetches the CISA KEV catalog (once per process), filters by CWE
        keyword matching, and returns a formatted string for Breaker context.
        Returns empty string on any error.
        """
        if not cwe_ids:
            return ""

        result = self.query_cwes(cwe_ids, max_per_cwe)
        if not result.success or not result.entries:
            return ""

        return _format_kev_section(result)

    def query_cwes(
        self,
        cwe_ids: list[str],
        max_per_cwe: int = _MAX_ENTRIES_PER_CWE,
    ) -> KevResult:
        """
        Query the KEV catalog for entries matching the given CWE identifiers.
        Public entry point — returns KevResult.
        """
        catalog = self._fetch_catalog()
        if catalog is None:
            return KevResult(
                entries=[],
                total_in_catalog=0,
                query_cwes=cwe_ids,
                success=False,
                error="Failed to fetch KEV catalog",
            )

        matched: list[KevEntry] = []
        seen_cve_ids: set[str] = set()
        per_cwe_counts: dict[str, int] = {cwe: 0 for cwe in cwe_ids}

        for entry_raw in catalog:
            cve_id = entry_raw.get("cveID", "")
            if cve_id in seen_cve_ids:
                continue

            name = (entry_raw.get("vulnerabilityName") or "").lower()
            desc = (entry_raw.get("shortDescription") or "").lower()
            product = (entry_raw.get("product") or "").lower()
            combined = f"{name} {desc} {product}"

            for cwe in cwe_ids:
                if per_cwe_counts.get(cwe, 0) >= max_per_cwe:
                    continue
                keywords = _CWE_KEYWORDS.get(cwe, [])
                if any(kw in combined for kw in keywords):
                    matched.append(KevEntry(
                        cve_id=cve_id,
                        vendor_project=entry_raw.get("vendorProject", ""),
                        product=entry_raw.get("product", ""),
                        vulnerability_name=entry_raw.get("vulnerabilityName", ""),
                        date_added=entry_raw.get("dateAdded", ""),
                        description=(entry_raw.get("shortDescription") or "")[:300],
                        required_action=entry_raw.get("requiredAction", ""),
                        known_ransomware=entry_raw.get("knownRansomwareCampaignUse", "Unknown").lower() == "known",
                        matched_cwes=[cwe],
                    ))
                    per_cwe_counts[cwe] = per_cwe_counts.get(cwe, 0) + 1
                    seen_cve_ids.add(cve_id)
                    break

        return KevResult(
            entries=matched,
            total_in_catalog=len(catalog),
            query_cwes=cwe_ids,
            success=True,
        )

    def _fetch_catalog(self) -> list[dict] | None:
        """Fetch the KEV JSON feed, returning the vulnerabilities list. Cached per process."""
        if self._catalog is not None:
            return self._catalog

        try:
            import httpx
        except ImportError:
            logger.debug("KEV: httpx not installed")
            return None

        try:
            resp = httpx.get(self._feed_url, timeout=self._timeout, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
            self._catalog = data.get("vulnerabilities", [])
            logger.debug("KEV: fetched %d entries from CISA catalog", len(self._catalog))
            return self._catalog
        except Exception as e:
            logger.debug("KEV: fetch failed: %s", e)
            return None


def _format_kev_section(result: KevResult) -> str:
    """Format KEV results as a Breaker context string."""
    lines = [
        f"CISA Known Exploited Vulnerabilities matching tested CWEs "
        f"({result.total_in_catalog} total in CISA KEV catalog):",
    ]
    for e in result.entries:
        ransomware = " [ransomware-linked]" if e.known_ransomware else ""
        lines.append(
            f"  {e.cve_id} ({e.vendor_project} {e.product}){ransomware} "
            f"added:{e.date_added}: {e.description}"
        )

    return (
        "\n--- Live threat intelligence from CISA KEV (cisa.gov) ---\n"
        + "\n".join(lines)
        + "\n--- End KEV enrichment ---\n"
    )
