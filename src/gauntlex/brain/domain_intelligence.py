"""
Domain Intelligence Adapter (DIA) — MCP consumer for live threat intelligence.

GAUNTLEX is NOT an MCP server (incompatible 60-90s runtime with MCP's sub-second
contract). Instead, DIA CONSUMES external MCP servers that provide real-time:
  - Financial threat intel (active CVEs in banking software)
  - Regulatory guidance (current FINRA/SEC enforcement priorities)
  - Vulnerability feeds (NVD enriched with domain context)

DIA is configured under mcp_servers: in .gauntlex.yml.
Each MCP server is called pre_run, and its response enriches the Breaker's
policy context with live threat data for the current run.

If an MCP server is unreachable, DIA fails silently — the run continues
with the standard playbook context.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 10.0


@dataclass
class McpServerConfig:
    name: str
    url: str
    tool: str            # MCP tool name to invoke
    params: dict = field(default_factory=dict)
    enabled: bool = True


@dataclass
class DiaResult:
    server: str
    tool: str
    enrichment: str    # formatted text appended to Breaker policy context
    raw_response: Any = None
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error


def call_mcp_tool(server: McpServerConfig) -> DiaResult:
    """
    Call a single MCP server tool and return enrichment text.

    The MCP JSON-RPC protocol:
      POST /mcp
      {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
       "params": {"name": <tool>, "arguments": <params>}}
    """
    if not server.enabled:
        return DiaResult(server=server.name, tool=server.tool,
                         enrichment="", error="disabled")

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": server.tool,
            "arguments": server.params,
        },
    }

    try:
        import httpx
        resp = httpx.post(
            server.url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        msg = str(e)
        logger.debug("DIA: MCP server '%s' unreachable: %s", server.name, msg)
        return DiaResult(server=server.name, tool=server.tool, enrichment="", error=msg)

    if "error" in data:
        err = data["error"].get("message", "MCP error")
        return DiaResult(server=server.name, tool=server.tool, enrichment="", error=err)

    raw = data.get("result", {})
    enrichment = _format_mcp_result(server.name, server.tool, raw)
    return DiaResult(server=server.name, tool=server.tool, enrichment=enrichment, raw_response=raw)


def _format_mcp_result(server: str, tool: str, result: Any) -> str:
    """Convert an MCP tool result into a Breaker policy context addition."""
    if isinstance(result, str):
        content = result
    elif isinstance(result, dict):
        # MCP content array format
        if "content" in result:
            parts = result["content"]
            content = "\n".join(
                p.get("text", "") for p in parts
                if isinstance(p, dict) and p.get("type") == "text"
            )
        else:
            content = json.dumps(result, indent=2)
    else:
        content = str(result)

    if not content.strip():
        return ""

    return (
        f"\n--- Live threat intelligence from '{server}' ({tool}) ---\n"
        f"{content[:2000]}\n"
        f"--- End DIA enrichment ---\n"
    )


class DomainIntelligenceAdapter:
    """
    Orchestrates MCP server calls and combines enrichment into policy context.

    Usage (called by pre_run hook or run.py):
        dia = DomainIntelligenceAdapter(servers)
        enriched_context = dia.enrich(base_policy_context)
    """

    def __init__(self, servers: list[McpServerConfig]):
        self._servers = servers

    @classmethod
    def from_config(cls, config: "AppConfig") -> "DomainIntelligenceAdapter":  # noqa: F821
        """Build DIA from the mcp_servers block in .gauntlex.yml."""
        from ..config import AppConfig
        raw_servers = getattr(config, "mcp_servers", [])
        servers = [
            McpServerConfig(
                name=s.get("name", "unknown"),
                url=s.get("url", ""),
                tool=s.get("tool", ""),
                params=s.get("params", {}),
                enabled=s.get("enabled", True),
            )
            for s in (raw_servers or [])
            if s.get("url") and s.get("tool")
        ]
        return cls(servers)

    def enrich(
        self,
        base_context: str,
        cwe_ids: list[str] | None = None,
        config: Any = None,
    ) -> tuple[str, list[DiaResult]]:
        """
        Enrich base_context with:
          1. MCP server calls (existing DIA behaviour)
          2. NIST NVD live CVE data (if config.nvd_enabled or NVD_API_KEY set)
          3. CISA KEV active exploitation data (if config.kev_enabled, default on)

        Returns:
            (enriched_context, list_of_dia_results)
        """
        results: list[DiaResult] = []
        enrichments: list[str] = []

        # MCP server enrichment (existing)
        for server in self._servers:
            result = call_mcp_tool(server)
            results.append(result)
            if result.success and result.enrichment:
                enrichments.append(result.enrichment)
                logger.debug("DIA: enriched from '%s' (%d chars)", server.name, len(result.enrichment))

        # Live REST API enrichment
        if cwe_ids:
            enrichments.extend(_enrich_from_live_apis(cwe_ids, config))

        if not enrichments:
            return base_context, results

        combined = base_context
        if combined:
            combined += "\n\n"
        combined += "\n".join(enrichments)
        return combined, results

    def available_servers(self) -> list[str]:
        return [s.name for s in self._servers if s.enabled]


def _enrich_from_live_apis(cwe_ids: list[str], config: Any) -> list[str]:
    """
    Call NIST NVD and CISA KEV live REST APIs and return enrichment strings.

    Both calls are best-effort — failures return empty strings silently.
    config may be None (uses env-var defaults) or a AppConfig instance.
    """
    enrichments: list[str] = []

    # CISA KEV — default on, no API key needed
    kev_enabled = getattr(config, "kev_enabled", True) if config is not None else True
    if kev_enabled:
        try:
            from .kev_client import KevClient
            kev_text = KevClient().get_exploited_for_cwes(cwe_ids)
            if kev_text:
                enrichments.append(kev_text)
        except Exception as e:
            logger.debug("DIA: KEV enrichment failed: %s", e)

    # NIST NVD — opt-in (requires NVD_API_KEY for reasonable rate limits)
    import os
    nvd_enabled = getattr(config, "nvd_enabled", False) if config is not None else False
    nvd_via_key = bool(os.environ.get("NVD_API_KEY"))
    if nvd_enabled or nvd_via_key:
        try:
            from .nvd_client import NvdClient
            lookback = getattr(config, "nvd_lookback_days", 90) if config is not None else 90
            nvd_text = NvdClient().get_recent_cves(cwe_ids, lookback_days=lookback)
            if nvd_text:
                enrichments.append(nvd_text)
        except Exception as e:
            logger.debug("DIA: NVD enrichment failed: %s", e)

    return enrichments


def parse_mcp_servers_from_yaml(raw: list[dict]) -> list[McpServerConfig]:
    """Parse the mcp_servers YAML block into McpServerConfig objects."""
    return [
        McpServerConfig(
            name=s.get("name", f"server-{i}"),
            url=s.get("url", ""),
            tool=s.get("tool", ""),
            params=s.get("params", {}),
            enabled=s.get("enabled", True),
        )
        for i, s in enumerate(raw or [])
    ]
