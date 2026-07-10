"""
GAUNTLEX MCP Server — expose GAUNTLEX as a Model Context Protocol (MCP) server.

Supports two transports:
  stdio  — local IDE integration (Claude Code, Cursor, Windsurf, Zed)
           Launch: gauntlex mcp-server
           Add to your IDE's MCP config (see README "MCP Server Integration")

  http   — team/enterprise deployment, served alongside the GAUNTLEX dashboard
           Launch: gauntlex serve --mcp  (POST /mcp)

Protocol: JSON-RPC 2.0 / MCP 2024-11-05

Tools exposed:
  gauntlex_run         — start adversarial assessment; returns run_id immediately
  gauntlex_status      — poll for results by run_id
  gauntlex_vault_stats — Knowledge Forge / Forge Ledger statistics
  gauntlex_policy_list — list available security domain playbooks
  gauntlex_verify      — verify SHA-256 integrity of a stored Resilience Report

Async run dispatch:
  gauntlex_run fires an asyncio.Task and returns in <1s.
  The event loop continues processing new messages (gauntlex_status polls)
  while the engine runs in the background.

Environment variables (never committed — set in shell or .env):
  GAUNTLEX_MCP_PORT — HTTP port for --mcp mode (default: 8080)
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable

from ..config import AppConfig

_MCP_PROTOCOL_VERSION = "2024-11-05"
_SERVER_NAME = "gauntlex"
_SERVER_VERSION = "1.0.1"
_ATTACK_COUNTS: dict[str, int] = {"quick": 5, "standard": 20, "thorough": 50}

_TOOLS = [
    {
        "name": "gauntlex_run",
        "description": (
            "Start a GAUNTLEX adversarial resilience assessment on a specification. "
            "Returns run_id immediately — the engine runs as a background task. "
            "Poll with gauntlex_status to retrieve results. "
            "Modes: quick (~45s, 5 attacks), standard (~3min, 20 attacks), thorough (~12min, 50 attacks)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "spec": {
                    "type": "string",
                    "description": (
                        "The feature specification or requirement text to assess adversarially. "
                        "Can be a GitHub issue body, user story, API contract, or any natural-language spec."
                    ),
                },
                "mode": {
                    "type": "string",
                    "enum": ["quick", "standard", "thorough"],
                    "default": "quick",
                    "description": "Assessment depth: quick=5 attacks, standard=20, thorough=50.",
                },
                "domain": {
                    "type": "string",
                    "default": "owasp_top10",
                    "description": (
                        "Security domain playbook. Options: owasp_top10, owasp_api_security, "
                        "hipaa, finra, pci_dss, soc2, nist_ssdf. "
                        "Use gauntlex_policy_list to see all options."
                    ),
                },
                "language": {
                    "type": "string",
                    "description": (
                        "Target language (auto-detected from spec if omitted). "
                        "Options: python, javascript, typescript, java, go."
                    ),
                },
            },
            "required": ["spec"],
        },
    },
    {
        "name": "gauntlex_status",
        "description": (
            "Poll for the results of a running GAUNTLEX adversarial assessment. "
            "Returns status=running while the engine is active, status=complete with "
            "full ARS score and attack breakdown when done."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {
                    "type": "string",
                    "description": "The run_id returned by gauntlex_run.",
                },
            },
            "required": ["run_id"],
        },
    },
    {
        "name": "gauntlex_vault_stats",
        "description": (
            "Get Knowledge Forge / Forge Ledger statistics: total adversarial patterns stored, "
            "broken down by CWE category. Shows the Breaker's accumulated learning from past runs."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "gauntlex_policy_list",
        "description": (
            "List all available security domain playbooks that can be used as the 'domain' "
            "parameter in gauntlex_run. Each domain steers the Breaker toward domain-specific "
            "attack scenarios (HIPAA PHI exposure, FINRA AML bypass, PCI DSS card data, etc.)."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "gauntlex_verify",
        "description": (
            "Verify the SHA-256 integrity hash of a stored Resilience Report. "
            "Confirms the report was not tampered with after generation. "
            "Use for compliance auditing and audit trail verification."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {
                    "type": "string",
                    "description": "run_id of a completed assessment to verify.",
                },
            },
            "required": ["run_id"],
        },
    },
]

EngineFunction = Callable[[str, str, str, str, "str | None", AppConfig], Awaitable[dict]]


class _McpError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class MCPServer:
    """
    JSON-RPC 2.0 / MCP 1.0 server for GAUNTLEX.

    Maintains a dict of in-flight asyncio.Tasks (one per gauntlex_run call) and
    their results. Background tasks run concurrently while the event loop processes
    new gauntlex_status poll requests.

    Supports dependency injection of engine_fn for testing (pass a mock that
    returns a result dict immediately without calling the LLM).
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        engine_fn: EngineFunction | None = None,
    ):
        self._config = config or AppConfig.load()
        self._tasks: dict[str, asyncio.Task] = {}
        self._results: dict[str, dict] = {}
        self._started: dict[str, float] = {}
        self._engine_fn: EngineFunction = engine_fn or _run_gauntlex_engine

    # ── JSON-RPC dispatch ──────────────────────────────────────────────────────

    async def handle_message(self, msg: dict) -> dict:
        """Dispatch a JSON-RPC message and return the response envelope."""
        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        try:
            result = await self._dispatch(method, params)
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}
        except _McpError as e:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": e.code, "message": e.message}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": str(e)}}

    async def _dispatch(self, method: str, params: dict) -> Any:
        if method == "initialize":
            return {
                "protocolVersion": _MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
            }
        if method == "tools/list":
            return {"tools": _TOOLS}
        if method == "tools/call":
            return await self._handle_tool_call(params)
        if method in ("notifications/initialized", "ping"):
            return {}
        raise _McpError(-32601, f"Method not found: {method}")

    async def _handle_tool_call(self, params: dict) -> dict:
        name = params.get("name", "")
        args = params.get("arguments") or {}

        if name == "gauntlex_run":
            return await self._tool_run(args)
        if name == "gauntlex_status":
            return self._tool_status(args)
        if name == "gauntlex_vault_stats":
            return self._tool_vault_stats(args)
        if name == "gauntlex_policy_list":
            return self._tool_policy_list(args)
        if name == "gauntlex_verify":
            return self._tool_verify(args)
        raise _McpError(-32601, f"Unknown tool: {name}")

    # ── Tool implementations ───────────────────────────────────────────────────

    async def _tool_run(self, args: dict) -> dict:
        spec = (args.get("spec") or "").strip()
        if not spec:
            raise _McpError(-32602, "spec is required and must not be empty")

        mode = args.get("mode", "quick")
        if mode not in _ATTACK_COUNTS:
            mode = "quick"
        domain = args.get("domain") or "owasp_top10"
        language = args.get("language")

        run_id = f"gauntlex-mcp-{uuid.uuid4().hex[:8]}"
        task = asyncio.create_task(
            self._engine_fn(run_id, spec, mode, domain, language, self._config)
        )
        self._tasks[run_id] = task
        self._started[run_id] = time.monotonic()
        task.add_done_callback(lambda t: self._on_task_done(run_id, t))

        return {
            "content": [{
                "type": "text",
                "text": (
                    f"Adversarial assessment started.\n"
                    f"run_id: {run_id}\n"
                    f"mode:   {mode} ({_ATTACK_COUNTS[mode]} attacks)\n"
                    f"domain: {domain}\n\n"
                    f"Poll for results:\n"
                    f"  gauntlex_status(run_id='{run_id}')\n\n"
                    f"Expected completion: {_eta(mode)}"
                ),
            }],
            "run_id": run_id,
            "status": "started",
        }

    def _on_task_done(self, run_id: str, task: asyncio.Task) -> None:
        if task.cancelled():
            self._results[run_id] = {"run_id": run_id, "status": "cancelled"}
        elif task.exception() is not None:
            self._results[run_id] = {
                "run_id": run_id,
                "status": "error",
                "error": str(task.exception()),
            }
        else:
            self._results[run_id] = task.result()

    def _tool_status(self, args: dict) -> dict:
        run_id = (args.get("run_id") or "").strip()
        if not run_id:
            raise _McpError(-32602, "run_id is required")
        if run_id not in self._tasks:
            raise _McpError(-32602, f"Unknown run_id: {run_id}")

        elapsed = time.monotonic() - self._started.get(run_id, 0)

        if run_id in self._results:
            r = self._results[run_id]
            status = r.get("status", "complete")

            if status == "error":
                text = f"Run {run_id} failed: {r.get('error', 'unknown error')}"
            elif status == "cancelled":
                text = f"Run {run_id} was cancelled."
            else:
                ars = r.get("ars", 0.0)
                passed = r.get("passed", False)
                symbol = "✅ PASSED" if passed else "❌ FAILED"
                lines = [
                    "Adversarial assessment complete",
                    f"run_id:    {run_id}",
                    f"ARS Score: {ars:.3f}  {symbol}  (gate: ≥ {r.get('gate_threshold', 0.80):.2f})",
                    f"Elapsed:   {elapsed:.0f}s",
                    f"Attacks:   {r.get('attack_count', 0)} total · {r.get('miss_count', 0)} missed",
                    "",
                    "Attack breakdown:",
                ]
                icons = {"mitigated": "✅", "partial": "⚠️ ", "missed": "❌"}
                for atk in r.get("attacks", []):
                    icon = icons.get(atk.get("verdict", ""), "  ")
                    cwe = atk.get("cwe", "")
                    title = atk.get("title", "")[:55]
                    score = atk.get("score", 0.0)
                    lines.append(f"  {icon} {cwe:<10} {title:<55}  score:{score:.1f}")
                text = "\n".join(lines)

            return {
                "content": [{"type": "text", "text": text}],
                "run_id": run_id,
                "status": status if status in ("error", "cancelled") else "complete",
                "result": r,
            }

        return {
            "content": [{
                "type": "text",
                "text": f"Assessment running... {elapsed:.0f}s elapsed\nrun_id: {run_id}",
            }],
            "run_id": run_id,
            "status": "running",
            "elapsed_seconds": round(elapsed, 1),
        }

    def _tool_vault_stats(self, args: dict) -> dict:
        vault_dir = Path(".gauntlex/vault")
        if not vault_dir.exists():
            return {
                "content": [{"type": "text", "text": "No Forge Ledger entries yet. Run a GAUNTLEX assessment to populate the vault."}],
                "stats": {"total": 0, "by_cwe": {}},
            }

        by_cwe: dict[str, int] = {}
        for d in sorted(vault_dir.iterdir()):
            if d.is_dir() and d.name.startswith("CWE-"):
                n = sum(1 for f in d.iterdir() if f.suffix == ".md")
                if n:
                    by_cwe[d.name] = n

        total = sum(by_cwe.values())
        lines = [f"Forge Ledger — {total} entries across {len(by_cwe)} CWE categories", ""]
        for cwe, n in sorted(by_cwe.items(), key=lambda x: -x[1])[:10]:
            bar = "█" * min(n, 30)
            lines.append(f"  {cwe:<12} {bar}  {n:>3}")

        return {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "stats": {"total": total, "by_cwe": by_cwe},
        }

    def _tool_policy_list(self, args: dict) -> dict:
        domains = [
            ("owasp_top10",        10, "OWASP Top 10 2021 — injection, broken auth, XSS, IDOR"),
            ("owasp_api_security", 10, "OWASP API Security — BOLA, SSRF, mass assignment, resource exhaustion"),
            ("hipaa",              10, "HIPAA Security Rule — PHI at rest, disclosure, de-identification"),
            ("finra",               9, "FINRA Rule 4370 / AML — broker-dealer auth gaps, AML bypass"),
            ("pci_dss",             8, "PCI DSS 4.0 — cardholder data, key management, network segmentation"),
            ("soc2",                7, "SOC 2 CC6/CC7/CC8 — logical access, system operations, change mgmt"),
            ("nist_ssdf",           8, "NIST SP 800-218 SSDF — PW.4 input validation, RV.2, supply chain"),
        ]
        lines = ["Available GAUNTLEX security domain playbooks:", ""]
        for name, n, desc in domains:
            lines.append(f"  {name:<25} {n:>2} scenarios  {desc}")
        lines += ["", "Usage: gauntlex_run(spec='...', domain='hipaa')"]

        return {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "domains": [{"name": n, "scenarios": s, "description": d} for n, s, d in domains],
        }

    def _tool_verify(self, args: dict) -> dict:
        run_id = (args.get("run_id") or "").strip()
        if not run_id:
            raise _McpError(-32602, "run_id is required")

        report_path = self._config.reports_dir / f"{run_id}.json"
        if not report_path.exists():
            return {
                "content": [{"type": "text", "text": f"Report not found: {run_id}"}],
                "verified": False,
                "run_id": run_id,
            }

        try:
            from ..output.report import load_report, _compute_hash
            report = load_report(run_id, self._config.reports_dir)
            stored = report.get("integrity_hash", "")
            computed = _compute_hash(report.get("attacks", []))
            verified = stored == computed
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Verification error: {e}"}],
                "verified": False,
                "run_id": run_id,
            }

        symbol = "✅ VERIFIED" if verified else "❌ TAMPERED"
        text = (
            f"Integrity verification: {symbol}\n"
            f"run_id:        {run_id}\n"
            f"stored_hash:   {stored[:32]}...\n"
            f"computed_hash: {computed[:32]}...\n"
            f"match:         {verified}"
        )
        return {
            "content": [{"type": "text", "text": text}],
            "verified": verified,
            "run_id": run_id,
            "stored_hash": stored,
            "computed_hash": computed,
        }

    # ── Stdio transport ────────────────────────────────────────────────────────

    async def run_stdio(self) -> None:
        """
        Run MCP server over stdio (Content-Length framed JSON-RPC).

        Reads from sys.stdin.buffer, writes to sys.stdout.buffer.
        Uses run_in_executor so blocking reads don't freeze background tasks.
        """
        loop = asyncio.get_event_loop()

        while True:
            try:
                # Blocking read — run_in_executor keeps the event loop free
                raw_header = await loop.run_in_executor(None, sys.stdin.buffer.readline)
                if not raw_header:
                    break

                header = raw_header.decode("utf-8", errors="replace").strip()
                if not header.startswith("Content-Length:"):
                    continue

                try:
                    length = int(header.split(":", 1)[1].strip())
                except ValueError:
                    continue

                # Consume blank separator line (\r\n)
                await loop.run_in_executor(None, sys.stdin.buffer.readline)

                body_bytes = await loop.run_in_executor(None, sys.stdin.buffer.read, length)

                try:
                    msg = json.loads(body_bytes)
                except json.JSONDecodeError:
                    continue

                # Notifications (no id) — no response required
                if "id" not in msg:
                    continue

                response = await self.handle_message(msg)
                out_bytes = json.dumps(response).encode("utf-8")
                prefix = f"Content-Length: {len(out_bytes)}\r\n\r\n".encode("utf-8")
                await loop.run_in_executor(None, _write_stdout, prefix + out_bytes)

            except (EOFError, BrokenPipeError, KeyboardInterrupt):
                break
            except Exception:
                break

    # ── HTTP handler (for FastAPI /mcp endpoint) ───────────────────────────────

    async def handle_http_request(self, body: dict) -> dict:
        """Handle a raw JSON-RPC dict from HTTP POST /mcp. Returns response dict."""
        return await self.handle_message(body)


# ── Private helpers ────────────────────────────────────────────────────────────

def _write_stdout(data: bytes) -> None:
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _eta(mode: str) -> str:
    return {"quick": "~45 seconds", "standard": "~3 minutes", "thorough": "~12 minutes"}.get(mode, "unknown")


# ── Default engine function ────────────────────────────────────────────────────

async def _run_gauntlex_engine(
    run_id: str,
    spec: str,
    mode: str,
    domain: str,
    language: str | None,
    config: AppConfig,
) -> dict:
    """
    Run the GAUNTLEX Gauntlex engine on an inline spec and return a result dict.

    This is the MCP-facing entry point — equivalent to `gauntlex run` but:
      - takes spec text directly (not a file path)
      - returns a structured dict (no stdout printing)
      - does not call sys.exit()
    """
    from ..core.gauntlex import Gauntlex
    from ..core.arbiter import Arbiter
    from ..output.report import build_report, save_report
    from ..policy.engine import load_domains, combine_policy_context, list_available_domains
    from ..memory.forge import KnowledgeForge

    cfg = AppConfig()
    # Copy config fields without mutating the original
    for field_name in config.__dataclass_fields__:
        setattr(cfg, field_name, getattr(config, field_name))

    cfg.gauntlex.attack_count = _ATTACK_COUNTS.get(mode, 5)

    domains = [d.strip() for d in domain.split(",")]
    available = list_available_domains()
    valid_domains = [d for d in domains if d.split("@")[0] in available]

    policy_context = ""
    if valid_domains:
        try:
            loaded = load_domains(valid_domains)
            policy_context = combine_policy_context(loaded)
        except Exception:
            pass

    recalled = ""
    forge = KnowledgeForge()
    if forge.is_available():
        try:
            hits = forge.recall_attacks(spec, n_results=10)
            recalled = forge.format_recalled_for_prompt(hits)
        except Exception:
            pass

    arbiter = Arbiter(**cfg.model_kwargs())
    pair = Gauntlex(config=cfg, recalled_attacks=recalled, policy_context=policy_context)

    result = await pair.run(spec, arbiter)

    for rr in result.rounds:
        await arbiter.score_round_async(rr.build, rr.breaker)
    result.final_ars = arbiter.final_ars(result.all_attacks)

    report = build_report(
        result=result,
        run_id=run_id,
        spec_ref="mcp://inline",
        playbook_version=f"{(valid_domains or ['owasp_top10'])[0]}@v2025.1",
        mode=mode, model=f"{pair.builder.provider}/{pair.builder.model}",
    )

    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    save_report(report, cfg.reports_dir)

    passed = result.final_ars >= cfg.gate.minimum_ars
    return {
        "run_id": run_id,
        "status": "complete",
        "ars": result.final_ars,
        "passed": passed,
        "gate_threshold": cfg.gate.minimum_ars,
        "attack_count": result.attack_count,
        "miss_count": result.miss_count,
        "elapsed_seconds": result.total_elapsed_seconds,
        "attacks": [
            {
                "cwe": a.cwe,
                "title": a.title,
                "description": a.description,
                "score": a.score,
                "verdict": "mitigated" if a.score >= 0.9 else "partial" if a.score >= 0.5 else "missed",
                "severity": a.severity,
            }
            for a in result.all_attacks
        ],
    }
