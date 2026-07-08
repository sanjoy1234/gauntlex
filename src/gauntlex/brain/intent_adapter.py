"""
Intent Adapter — resolves business intent from Jira, Confluence, Aha!, or spec text.

Improvement 1 from Deven feedback:
  "Business intent plus specification together define the attack surface."

The attack surface is wider than the spec alone. A FINRA AML requirement
combined with a spec that says 'score this transaction' creates a vulnerability
surface that neither document creates alone.

Resolution order (first success wins):
  1. Jira issue  — env: JIRA_URL, JIRA_EMAIL, JIRA_TOKEN
  2. Confluence  — env: CONFLUENCE_URL, CONFLUENCE_EMAIL, CONFLUENCE_TOKEN
  3. Aha!        — env: AHA_DOMAIN, AHA_API_KEY
  4. Spec text   — always available (fallback)

All adapters fail silently. If none resolve, intent_text is empty and the
Breaker works from spec alone (no degradation in behaviour).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_TIMEOUT = 8.0


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class IntentResult:
    intent_text: str = ""
    source: str = "spec"          # "jira" | "confluence" | "aha" | "spec" | "none"
    source_url: str = ""
    error: str = ""

    @property
    def resolved(self) -> bool:
        return bool(self.intent_text.strip())


# ── Jira Adapter ──────────────────────────────────────────────────────────────

def _fetch_jira(ref: str) -> IntentResult:
    """
    Fetch a Jira issue by key or URL.

    Accepts:
      - "PROJ-123"
      - "https://company.atlassian.net/browse/PROJ-123"
      - "https://company.atlassian.net/rest/api/2/issue/PROJ-123"

    Required env vars: JIRA_URL, JIRA_EMAIL, JIRA_TOKEN
    """
    base = os.environ.get("JIRA_URL", "").rstrip("/")
    email = os.environ.get("JIRA_EMAIL", "")
    token = os.environ.get("JIRA_TOKEN", "")

    if not (base and email and token):
        return IntentResult(error="JIRA_URL/JIRA_EMAIL/JIRA_TOKEN not set")

    # Extract issue key
    key = _extract_jira_key(ref)
    if not key:
        return IntentResult(error=f"Cannot extract Jira key from: {ref}")

    url = f"{base}/rest/api/2/issue/{key}"
    try:
        import httpx
        resp = httpx.get(
            url,
            auth=(email, token),
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return IntentResult(error=f"Jira fetch failed: {e}")

    fields = data.get("fields", {})
    summary = fields.get("summary", "")
    description = _extract_jira_description(fields.get("description", ""))
    acceptance = _extract_jira_acceptance(fields)

    parts = []
    if summary:
        parts.append(f"Jira {key}: {summary}")
    if description:
        parts.append(f"Description:\n{description}")
    if acceptance:
        parts.append(f"Acceptance Criteria:\n{acceptance}")

    text = "\n\n".join(parts)
    if not text:
        return IntentResult(error="Jira issue has no readable content")

    return IntentResult(
        intent_text=text,
        source="jira",
        source_url=f"{base}/browse/{key}",
    )


def _extract_jira_key(ref: str) -> str:
    """Extract PROJ-123 pattern from URL or raw key."""
    match = re.search(r"\b([A-Z][A-Z0-9_]+-\d+)\b", ref.upper())
    return match.group(1) if match else ""


def _extract_jira_description(desc) -> str:
    """Handle both string and Atlassian Document Format (ADF) descriptions."""
    if not desc:
        return ""
    if isinstance(desc, str):
        return desc[:2000]
    if isinstance(desc, dict):
        # ADF — walk the content tree
        return _adf_to_text(desc)[:2000]
    return str(desc)[:2000]


def _adf_to_text(node: dict, depth: int = 0) -> str:
    """Recursively extract plain text from Atlassian Document Format."""
    if depth > 10:
        return ""
    node_type = node.get("type", "")
    parts = []
    if node_type == "text":
        parts.append(node.get("text", ""))
    for child in node.get("content", []):
        parts.append(_adf_to_text(child, depth + 1))
    return " ".join(p for p in parts if p).strip()


def _extract_jira_acceptance(fields: dict) -> str:
    """Try common Jira custom field names for acceptance criteria."""
    for key in ("customfield_10016", "customfield_10014", "customfield_10020",
                "acceptance_criteria", "acceptanceCriteria"):
        val = fields.get(key)
        if val:
            if isinstance(val, str):
                return val[:1000]
            if isinstance(val, dict):
                return _adf_to_text(val)[:1000]
    return ""


# ── Confluence Adapter ────────────────────────────────────────────────────────

def _fetch_confluence(ref: str) -> IntentResult:
    """
    Fetch a Confluence page by URL or page ID.

    Accepts:
      - "https://company.atlassian.net/wiki/spaces/ENG/pages/123456/Page+Title"
      - "123456" (page ID)

    Required env vars: CONFLUENCE_URL, CONFLUENCE_EMAIL, CONFLUENCE_TOKEN
    """
    base = os.environ.get("CONFLUENCE_URL", "").rstrip("/")
    email = os.environ.get("CONFLUENCE_EMAIL", "")
    token = os.environ.get("CONFLUENCE_TOKEN", "")

    if not (base and email and token):
        return IntentResult(error="CONFLUENCE_URL/CONFLUENCE_EMAIL/CONFLUENCE_TOKEN not set")

    page_id = _extract_confluence_page_id(ref)
    if not page_id:
        return IntentResult(error=f"Cannot extract Confluence page ID from: {ref}")

    url = f"{base}/rest/api/content/{page_id}?expand=body.storage,title"
    try:
        import httpx
        resp = httpx.get(
            url,
            auth=(email, token),
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return IntentResult(error=f"Confluence fetch failed: {e}")

    title = data.get("title", "")
    body = data.get("body", {}).get("storage", {}).get("value", "")
    text_body = _strip_html(body)[:3000]

    text = f"Confluence page: {title}\n\n{text_body}" if title else text_body
    if not text.strip():
        return IntentResult(error="Confluence page has no readable content")

    page_url = f"{base}/wiki/pages/viewpage.action?pageId={page_id}"
    return IntentResult(intent_text=text, source="confluence", source_url=page_url)


def _extract_confluence_page_id(ref: str) -> str:
    """Extract numeric page ID from Confluence URL or return raw if numeric."""
    if ref.isdigit():
        return ref
    match = re.search(r"/pages/(\d+)", ref)
    if match:
        return match.group(1)
    match = re.search(r"pageId=(\d+)", ref)
    if match:
        return match.group(1)
    return ""


def _strip_html(html: str) -> str:
    """Strip HTML tags, keep readable text."""
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ── Aha! Adapter ──────────────────────────────────────────────────────────────

def _fetch_aha(ref: str) -> IntentResult:
    """
    Fetch an Aha! feature or requirement by URL or reference number.

    Accepts:
      - "https://company.aha.io/features/PROJ-123"
      - "PROJ-123"

    Required env vars: AHA_DOMAIN (e.g. "company"), AHA_API_KEY
    """
    domain = os.environ.get("AHA_DOMAIN", "").strip()
    api_key = os.environ.get("AHA_API_KEY", "").strip()

    if not (domain and api_key):
        return IntentResult(error="AHA_DOMAIN/AHA_API_KEY not set")

    ref_id = _extract_aha_ref(ref)
    if not ref_id:
        return IntentResult(error=f"Cannot extract Aha! reference from: {ref}")

    base = f"https://{domain}.aha.io/api/v1"
    url = f"{base}/features/{ref_id}"
    try:
        import httpx
        resp = httpx.get(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return IntentResult(error=f"Aha! fetch failed: {e}")

    feature = data.get("feature", {})
    name = feature.get("name", "")
    description = _strip_html(feature.get("description", {}).get("html", ""))[:2000]

    requirements = []
    for req in feature.get("requirements", []):
        req_name = req.get("name", "")
        req_desc = _strip_html(req.get("description", {}).get("html", ""))[:500]
        if req_name:
            requirements.append(f"- {req_name}: {req_desc}")

    parts = []
    if name:
        parts.append(f"Aha! feature: {name}")
    if description:
        parts.append(f"Description:\n{description}")
    if requirements:
        parts.append("Requirements:\n" + "\n".join(requirements[:10]))

    text = "\n\n".join(parts)
    if not text.strip():
        return IntentResult(error="Aha! feature has no readable content")

    return IntentResult(
        intent_text=text,
        source="aha",
        source_url=f"https://{domain}.aha.io/features/{ref_id}",
    )


def _extract_aha_ref(ref: str) -> str:
    """Extract feature reference like PROJ-F-123 or PROJ-123."""
    match = re.search(r"features/([A-Z0-9_-]+)", ref, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"\b([A-Z][A-Z0-9_]+-[A-Z]?-?\d+)\b", ref.upper())
    return match.group(1) if match else ""


# ── Orchestrator ──────────────────────────────────────────────────────────────

class IntentAdapter:
    """
    Resolves business intent from the first available source.

    Usage:
        adapter = IntentAdapter()
        result = adapter.resolve("PROJ-123")  # Jira key
        result = adapter.resolve("https://company.aha.io/features/PROJ-F-1")
        result = adapter.resolve(None)  # returns empty — use spec fallback
    """

    def resolve(self, ref: str | None) -> IntentResult:
        """
        Try each source in priority order. Returns the first success.
        If all fail or ref is None, returns an empty IntentResult.
        """
        if not ref or not ref.strip():
            return IntentResult(source="none")

        ref = ref.strip()

        # Detect source by URL pattern or env-var availability
        attempts = self._build_attempt_list(ref)

        for name, fn in attempts:
            result = fn(ref)
            if result.resolved:
                logger.info("IntentAdapter: resolved intent from %s (%d chars)", name, len(result.intent_text))
                return result
            logger.debug("IntentAdapter: %s skipped/failed: %s", name, result.error)

        return IntentResult(source="none", error="No intent source resolved")

    def _build_attempt_list(self, ref: str):
        """Order adapters by URL hint, then env availability."""
        attempts = []

        # Explicit URL hints take priority
        if "atlassian.net/browse" in ref or re.search(r"\b[A-Z][A-Z0-9_]+-\d+\b", ref):
            attempts.append(("jira", _fetch_jira))
        if "atlassian.net/wiki" in ref or "confluence" in ref.lower() or ref.isdigit():
            attempts.append(("confluence", _fetch_confluence))
        if "aha.io" in ref:
            attempts.append(("aha", _fetch_aha))

        # If no URL hint, try all configured sources
        if not attempts:
            if os.environ.get("JIRA_URL"):
                attempts.append(("jira", _fetch_jira))
            if os.environ.get("CONFLUENCE_URL"):
                attempts.append(("confluence", _fetch_confluence))
            if os.environ.get("AHA_DOMAIN"):
                attempts.append(("aha", _fetch_aha))

        return attempts


def format_intent_context(result: IntentResult) -> str:
    """Format intent for injection into Breaker prompt."""
    if not result.resolved:
        return ""
    source_label = {
        "jira": "Jira issue",
        "confluence": "Confluence page",
        "aha": "Aha! feature",
        "spec": "specification intent",
    }.get(result.source, result.source)

    header = f"Business intent ({source_label}"
    if result.source_url:
        header += f": {result.source_url}"
    header += "):"

    return f"{header}\n{result.intent_text}"
