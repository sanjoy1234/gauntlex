"""
Policy Hub — gauntlex policy install <domain>

Downloads community policy playbooks from the GitHub-backed Policy Hub index
and installs them into the project-local `.gauntlex/policies/` directory.

Index URL: https://raw.githubusercontent.com/sanjoy1234/gauntlex/main/policy-hub/index.json
Add new playbooks by opening a PR to the policy-hub/domains/ directory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_HUB_INDEX_URL = (
    "https://raw.githubusercontent.com/sanjoy1234/gauntlex/main/policy-hub/index.json"
)
_LOCAL_POLICIES_DIR = Path(".gauntlex/policies")
_REQUEST_TIMEOUT = 15.0


@dataclass
class HubDomainEntry:
    name: str
    version: str
    description: str
    regulatory_framework: str
    url: str
    scenarios_count: int
    tags: list[str]


@dataclass
class InstallResult:
    domain: str
    version: str
    installed_path: Path
    already_installed: bool = False
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error


def fetch_index(index_url: str = _HUB_INDEX_URL) -> list[HubDomainEntry]:
    """
    Fetch and parse the Policy Hub index.

    Returns list of available community domains.
    Raises RuntimeError if the index cannot be fetched.
    """
    import httpx

    try:
        resp = httpx.get(index_url, timeout=_REQUEST_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as e:
        raise RuntimeError(f"Failed to fetch Policy Hub index: {e}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Policy Hub index is malformed JSON: {e}") from e

    return [
        HubDomainEntry(
            name=d["name"],
            version=d.get("version", "unknown"),
            description=d.get("description", ""),
            regulatory_framework=d.get("regulatory_framework", ""),
            url=d["url"],
            scenarios_count=d.get("scenarios_count", 0),
            tags=d.get("tags", []),
        )
        for d in data.get("domains", [])
    ]


def install_domain(
    domain_name: str,
    policies_dir: Path = _LOCAL_POLICIES_DIR,
    force: bool = False,
    index_url: str = _HUB_INDEX_URL,
) -> InstallResult:
    """
    Download and install a community domain from the Policy Hub.

    Args:
        domain_name:  Name of the domain to install (e.g., 'owasp_api_security')
        policies_dir: Local directory to install into (default: .gauntlex/policies/)
        force:        Overwrite if already installed
        index_url:    Override the hub index URL (for testing)

    Returns:
        InstallResult with success/failure info and installed path
    """
    import httpx

    dest = policies_dir / f"{domain_name}.yaml"
    if dest.exists() and not force:
        return InstallResult(
            domain=domain_name, version="?", installed_path=dest, already_installed=True
        )

    try:
        entries = fetch_index(index_url)
    except RuntimeError as e:
        return InstallResult(domain=domain_name, version="?", installed_path=dest, error=str(e))

    entry = next((e for e in entries if e.name == domain_name), None)
    if entry is None:
        available = ", ".join(e.name for e in entries)
        return InstallResult(
            domain=domain_name,
            version="?",
            installed_path=dest,
            error=f"Domain '{domain_name}' not found in Policy Hub. Available: {available}",
        )

    try:
        resp = httpx.get(entry.url, timeout=_REQUEST_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        yaml_content = resp.text
    except httpx.HTTPError as e:
        return InstallResult(
            domain=domain_name, version=entry.version, installed_path=dest,
            error=f"Failed to download '{domain_name}': {e}",
        )

    policies_dir.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml_content, encoding="utf-8")

    return InstallResult(domain=domain_name, version=entry.version, installed_path=dest)


def list_installed(policies_dir: Path = _LOCAL_POLICIES_DIR) -> list[str]:
    """Return names of all locally-installed community policy domains."""
    if not policies_dir.exists():
        return []
    return [p.stem for p in sorted(policies_dir.glob("*.yaml"))]


def search_index(query: str, index_url: str = _HUB_INDEX_URL) -> list[HubDomainEntry]:
    """Search Policy Hub index by name, tag, or regulatory framework."""
    q = query.lower()
    entries = fetch_index(index_url)
    return [
        e for e in entries
        if (q in e.name.lower()
            or q in e.description.lower()
            or q in e.regulatory_framework.lower()
            or any(q in t.lower() for t in e.tags))
    ]
