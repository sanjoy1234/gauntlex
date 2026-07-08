"""
Combat Dashboard — FastAPI web UI for GAUNTLEX.

Optional install: pip install gauntlex-ai[ui]
Launch:           gauntlex dashboard --port 8080

Features:
  - ARS trend chart over recent runs
  - Per-run attack breakdown with verdict colors
  - Compliance evidence download (JSON, SARIF, HTML)
  - Forge Ledger vault browser
  - Bright/light theme throughout (#FAFAFA background)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Guard against FastAPI/Uvicorn not being installed
try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    FastAPI = None  # type: ignore

from ..config import AppConfig
from ..output.report import load_report, render_html, render_sarif, render_junit_xml


def _require_fastapi():
    if not _FASTAPI_AVAILABLE:
        raise RuntimeError(
            "Combat Dashboard requires FastAPI and Uvicorn. "
            "Install with: pip install gauntlex-ai[ui]"
        )


def create_app(config: AppConfig | None = None):  # returns FastAPI when installed
    _require_fastapi()

    # GAUNTLEX_CONFIG_PATH is set by `gauntlex dashboard --config ...` / `gauntlex serve
    # --config ...` — needed because uvicorn calls this factory with no arguments, so an
    # explicit --config can't be passed through directly.
    cfg = config or AppConfig.load(os.environ.get("GAUNTLEX_CONFIG_PATH"))
    runs_dir = cfg.reports_dir.parent / "runs"
    app = FastAPI(title="GAUNTLEX Combat Dashboard", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        reports = _load_all_reports(cfg.reports_dir)
        active = _load_active_runs(runs_dir)
        return HTMLResponse(_render_index(reports, cfg, active))

    @app.get("/api/runs")
    async def list_runs():
        reports = _load_all_reports(cfg.reports_dir)
        return JSONResponse([
            {
                "run_id": r["run_id"],
                "ars_score": r["ars_score"],
                "attack_count": r["attack_count"],
                "miss_count": r["miss_count"],
                "generated_at": r.get("generated_at", ""),
                "passed": r["ars_score"] >= cfg.gate.minimum_ars,
            }
            for r in reports
        ])

    @app.get("/api/runs/active")
    async def list_active_runs():
        """Runs currently in progress — foreground or --background. Not yet in
        /api/runs, since no report exists until the run completes."""
        return JSONResponse(_load_active_runs(runs_dir))

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str):
        try:
            report = load_report(run_id, cfg.reports_dir)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        return JSONResponse(report)

    @app.get("/api/runs/{run_id}/html")
    async def download_html(run_id: str):
        try:
            report = load_report(run_id, cfg.reports_dir)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        content = render_html(report)
        return Response(
            content=content,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{run_id}.html"'},
        )

    @app.get("/api/runs/{run_id}/sarif")
    async def download_sarif(run_id: str):
        try:
            report = load_report(run_id, cfg.reports_dir)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        content = render_sarif(report)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{run_id}.sarif"'},
        )

    @app.get("/api/runs/{run_id}/junit")
    async def download_junit(run_id: str):
        try:
            report = load_report(run_id, cfg.reports_dir)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        content = render_junit_xml(report)
        return Response(
            content=content,
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="{run_id}.xml"'},
        )

    @app.get("/api/vault/stats")
    async def vault_stats():
        from ..memory.forge_ledger import ForgeLedger
        ledger = ForgeLedger()
        return JSONResponse(ledger.stats())

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "gauntlex-dashboard"}

    _provider_labels = {
        "anthropic": "Anthropic", "openrouter": "OpenRouter",
        "huggingface": "HuggingFace", "openai_compat": "OpenAI-compatible",
        "local": "Ollama (local)",
    }

    @app.get("/status", response_class=HTMLResponse)
    async def status_page():
        """Human-readable status/health page — linked from the Live button."""
        reports = _load_all_reports(cfg.reports_dir)
        active = _load_active_runs(runs_dir)
        total = len(reports)
        n_passed = sum(1 for r in reports if r["ars_score"] >= cfg.gate.minimum_ars)
        avg_ars = round(sum(r["ars_score"] for r in reports) / total, 3) if total else 0.0
        last_run = reports[0]["generated_at"][:16].replace("T", " ") if reports else "—"
        provider = cfg.effective_model_provider
        model_label = f"{_provider_labels.get(provider, provider)} ({cfg.model_kwargs().get('model', '')})"
        active_row = (
            f'<div class="row"><span class="lbl">Active Runs</span>'
            f'<span class="val {"warn" if active else "ok"}">{len(active)}</span></div>'
        ) if active else ""
        no_project_banner = ""
        if cfg.config_source is None:
            no_project_banner = f"""
  <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:10px;padding:14px 16px;margin-bottom:20px;font-size:12px;color:#991B1B;line-height:1.6">
    &#x26A0;&#xFE0F; <strong>No GAUNTLEX project found</strong> — nothing remembered from a
    previous run either. Reports are being read from {cfg.reports_dir}.
    Fix: run any <code>gauntlex</code> command inside your project once, then this will
    resolve automatically from anywhere.
  </div>"""
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GAUNTLEX — System Status</title>
<style>
body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#EFF6FF;margin:0;padding:40px;color:#111827}}
.card{{background:#fff;border:1px solid #BFDBFE;border-radius:16px;padding:32px 40px;max-width:680px;margin:0 auto;box-shadow:0 4px 24px rgba(37,99,235,.10)}}
h1{{font-size:22px;font-weight:900;color:#1E40AF;margin-bottom:4px;display:flex;align-items:center;gap:10px}}
.dot{{width:12px;height:12px;border-radius:50%;background:#22C55E;display:inline-block;animation:blink 1.6s ease-in-out infinite;box-shadow:0 0 0 0 rgba(34,197,94,.6)}}
@keyframes blink{{0%,100%{{box-shadow:0 0 0 0 rgba(34,197,94,.6)}}50%{{box-shadow:0 0 0 8px rgba(34,197,94,.0)}}}}
.sub{{font-size:13px;color:#6B7280;margin-bottom:28px}}
.row{{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #F0F9FF}}
.row:last-child{{border-bottom:none}}
.lbl{{font-size:13px;font-weight:600;color:#374151}}
.val{{font-size:14px;font-weight:800;color:#1E40AF}}
.ok{{color:#059669}}.warn{{color:#D97706}}
a{{display:inline-block;margin-top:28px;padding:10px 24px;background:#1E40AF;color:#fff;border-radius:8px;text-decoration:none;font-weight:700;font-size:13px}}
a:hover{{background:#2563EB}}
</style></head><body>
<div class="card">
  <h1><span class="dot"></span> GAUNTLEX — System Status</h1>
  <div class="sub">Adversarial Co-Generation Engine &mdash; all systems operational</div>
  {no_project_banner}
  <div class="row"><span class="lbl">Service</span><span class="val ok">&#x2705; gauntlex-dashboard</span></div>
  <div class="row"><span class="lbl">Model / Provider</span><span class="val">{model_label}</span></div>
  {active_row}
  <div class="row"><span class="lbl">Total Runs</span><span class="val">{total}</span></div>
  <div class="row"><span class="lbl">Gate Passed</span><span class="val ok">{n_passed} / {total}</span></div>
  <div class="row"><span class="lbl">Avg ARS Score</span><span class="val {'ok' if avg_ars >= cfg.gate.minimum_ars else 'warn'}">{avg_ars:.3f}</span></div>
  <div class="row"><span class="lbl">Gate Threshold</span><span class="val">{cfg.gate.minimum_ars:.2f}</span></div>
  <div class="row"><span class="lbl">Last Run</span><span class="val">{last_run}</span></div>
  <div class="row"><span class="lbl">Dashboard auto-refresh</span><span class="val ok">Every 30s</span></div>
  <a href="/">&#x2190; Back to Dashboard</a>
</div></body></html>"""
        return HTMLResponse(html)

    @app.get("/api", response_class=HTMLResponse)
    async def api_reference():
        """Human-readable API reference page — linked from the JSON API button."""
        base = "http://127.0.0.1:8080"
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GAUNTLEX — JSON API Reference</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#EFF6FF;color:#111827;padding:0}}
header{{background:linear-gradient(135deg,#1E3A8A,#2563EB);padding:20px 40px;color:#fff}}
header h1{{font-size:20px;font-weight:900}}
header p{{font-size:12px;color:rgba(255,255,255,.75);margin-top:4px}}
.body{{max-width:900px;margin:32px auto;padding:0 24px}}
.ep{{background:#fff;border:1px solid #BFDBFE;border-radius:12px;padding:22px 26px;margin-bottom:16px;box-shadow:0 2px 8px rgba(37,99,235,.06)}}
.method{{display:inline-block;font-size:10px;font-weight:800;padding:3px 8px;border-radius:5px;margin-right:8px;letter-spacing:.05em}}
.get{{background:#D1FAE5;color:#065F46}}.post{{background:#DBEAFE;color:#1E40AF}}
.path{{font-family:monospace;font-size:14px;font-weight:700;color:#1E40AF}}
.desc{{font-size:13px;color:#4B5563;margin-top:8px;line-height:1.6}}
.try-it{{display:inline-block;margin-top:12px;padding:5px 14px;background:#EFF6FF;color:#1D4ED8;border-radius:6px;text-decoration:none;font-size:11px;font-weight:700;border:1px solid #BFDBFE}}
.try-it:hover{{background:#DBEAFE}}
.tag{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#9CA3AF;margin:24px 0 10px}}
a.back{{display:inline-block;margin-bottom:24px;color:#1D4ED8;text-decoration:none;font-size:13px;font-weight:600}}
a.back:hover{{text-decoration:underline}}
</style></head><body>
<header>
  <h1>&#x26A4; GAUNTLEX &mdash; JSON API Reference</h1>
  <p>Base URL: <code>{base}</code> &nbsp;&bull;&nbsp; All endpoints return JSON &nbsp;&bull;&nbsp; No auth required for localhost</p>
</header>
<div class="body">
<a class="back" href="/">&#x2190; Back to Dashboard</a>
<div class="tag">Run Management</div>
<div class="ep">
  <span class="method get">GET</span><span class="path">/api/runs</span>
  <div class="desc">List all adversarial assessment runs. Returns run_id, ars_score, attack_count, miss_count, generated_at, and gate pass/fail for each run.</div>
  <a class="try-it" href="/api/runs" target="_blank">Try it &#x2192;</a>
</div>
<div class="ep">
  <span class="method get">GET</span><span class="path">/api/runs/&#123;run_id&#125;</span>
  <div class="desc">Full report JSON for a specific run including all attack details, verdicts, CWE mappings, and remediation guidance.</div>
</div>
<div class="ep">
  <span class="method get">GET</span><span class="path">/api/runs/&#123;run_id&#125;/html</span>
  <div class="desc">Download executive-ready HTML report for a run (attachment). Includes ARS score, vulnerability cards, severity breakdown, and remediation table.</div>
</div>
<div class="ep">
  <span class="method get">GET</span><span class="path">/api/runs/&#123;run_id&#125;/sarif</span>
  <div class="desc">Download SARIF 2.1.0 file for GitHub Code Scanning / SAST tool integration. Can be uploaded directly to GitHub Security tab.</div>
</div>
<div class="ep">
  <span class="method get">GET</span><span class="path">/api/runs/&#123;run_id&#125;/junit</span>
  <div class="desc">Download JUnit XML for CI dashboards (Jenkins, CircleCI, etc.). Each attack appears as a test case with pass/fail verdict.</div>
</div>
<div class="tag">Knowledge Forge</div>
<div class="ep">
  <span class="method get">GET</span><span class="path">/api/vault/stats</span>
  <div class="desc">Knowledge Forge statistics — total adversarial patterns stored, CWE category breakdown, and accumulated learning from past runs.</div>
  <a class="try-it" href="/api/vault/stats" target="_blank">Try it &#x2192;</a>
</div>
<div class="tag">MCP Integration</div>
<div class="ep">
  <span class="method post">POST</span><span class="path">/mcp</span>
  <div class="desc">JSON-RPC 2.0 MCP endpoint. POST a <code>tools/list</code> or <code>tools/call</code> request. Used by AI coding assistants (Claude Code, Cursor, Copilot) in HTTP transport mode.<br><br>
  <code style="font-size:11px;background:#F3F4F6;padding:4px 8px;border-radius:4px">curl -X POST /mcp -d '{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{}}}}'</code>
  </div>
</div>
<div class="tag">Health</div>
<div class="ep">
  <span class="method get">GET</span><span class="path">/health</span>
  <div class="desc">Raw health check. Returns <code>{{"status":"ok","service":"gauntlex-dashboard"}}</code>. Used by load balancers and monitoring systems.</div>
  <a class="try-it" href="/status" target="_blank">View status page &#x2192;</a>
</div>
</div></body></html>"""
        return HTMLResponse(html)

    # ── MCP HTTP endpoint (JSON-RPC 2.0) ──────────────────────────────────────
    from ..mcp.server import MCPServer as _MCPServer

    _mcp_server = _MCPServer(config=cfg)

    @app.post("/mcp")
    async def mcp_endpoint(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                status_code=400,
            )
        response = await _mcp_server.handle_http_request(body)
        return JSONResponse(response)

    @app.get("/mcp/tools")
    async def mcp_tools_list():
        """Raw JSON tool list (for programmatic use)."""
        response = await _mcp_server.handle_message({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
        })
        return JSONResponse(response.get("result", {}).get("tools", []))

    @app.get("/mcp", response_class=HTMLResponse)
    async def mcp_tools_page():
        """Human-readable MCP tools documentation — linked from the MCP Tools button."""
        response = await _mcp_server.handle_message({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
        })
        tools = response.get("result", {}).get("tools", [])

        cards_html = ""
        for t in tools:
            name = t.get("name", "")
            desc = t.get("description", "")
            schema = t.get("inputSchema", {})
            props = schema.get("properties", {})
            required = schema.get("required", [])
            params_html = ""
            for pname, pdef in props.items():
                req_badge = ('<span style="background:#FEE2E2;color:#991B1B;font-size:9px;font-weight:700;'
                             'padding:1px 5px;border-radius:4px;margin-left:4px">required</span>'
                             if pname in required else "")
                params_html += (
                    f'<div style="padding:8px 0;border-bottom:1px solid #F3F4F6">'
                    f'<code style="font-size:12px;color:#7C3AED;background:#F5F3FF;padding:2px 6px;border-radius:4px">{pname}</code>'
                    f'{req_badge}'
                    f'<span style="font-size:11px;color:#6B7280;margin-left:8px">{pdef.get("type","any")}</span>'
                    f'<div style="font-size:12px;color:#4B5563;margin-top:4px;line-height:1.5">{pdef.get("description","")[:200]}</div>'
                    f'</div>'
                )
            cards_html += f"""
<div style="background:#fff;border:1px solid #BFDBFE;border-radius:12px;padding:22px 26px;margin-bottom:16px;box-shadow:0 2px 8px rgba(37,99,235,.06)">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <code style="font-size:14px;font-weight:800;color:#1E40AF;background:#EFF6FF;padding:4px 10px;border-radius:6px">{name}</code>
  </div>
  <div style="font-size:13px;color:#374151;line-height:1.65;margin-bottom:12px">{desc[:400]}</div>
  {'<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#9CA3AF;margin-bottom:8px">Parameters</div>' + params_html if params_html else '<div style="font-size:12px;color:#9CA3AF;font-style:italic">No parameters required</div>'}
</div>"""

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GAUNTLEX — MCP Tools</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#EFF6FF;color:#111827}}
header{{background:linear-gradient(135deg,#1E3A8A,#2563EB);padding:20px 40px;color:#fff}}
header h1{{font-size:20px;font-weight:900}}
header p{{font-size:12px;color:rgba(255,255,255,.75);margin-top:4px}}
.body{{max-width:860px;margin:32px auto;padding:0 24px}}
a.back{{display:inline-block;margin-bottom:24px;color:#1D4ED8;text-decoration:none;font-size:13px;font-weight:600}}
a.back:hover{{text-decoration:underline}}
.intro{{background:#fff;border:1px solid #BFDBFE;border-radius:12px;padding:20px 26px;margin-bottom:20px;font-size:13px;color:#4B5563;line-height:1.7}}
.intro strong{{color:#1E40AF}}
</style></head><body>
<header>
  <h1>&#x1F9E0; GAUNTLEX &mdash; MCP Tools</h1>
  <p>{len(tools)} tools available &nbsp;&bull;&nbsp; Works with Claude Code, Cursor, Windsurf, GitHub Copilot, Codex</p>
</header>
<div class="body">
<a class="back" href="/">&#x2190; Back to Dashboard</a>
<div class="intro">
  <strong>Model Context Protocol (MCP)</strong> lets your AI coding assistant call GAUNTLEX directly from chat.
  Run <code style="background:#EFF6FF;padding:2px 6px;border-radius:4px;font-size:12px">gauntlex integrate</code> to wire it up automatically,
  or configure manually with endpoint <code style="background:#EFF6FF;padding:2px 6px;border-radius:4px;font-size:12px">http://127.0.0.1:8080/mcp</code>.
  The stdio transport (<code style="background:#EFF6FF;padding:2px 6px;border-radius:4px;font-size:12px">gauntlex mcp-server</code>) is recommended for local development.
</div>
{cards_html}
</div></body></html>"""
        return HTMLResponse(html)

    return app


def _fmt_elapsed(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 60}m {s % 60:02d}s" if s >= 60 else f"{s}s"


def _short_issue(issue: str) -> str:
    if issue.startswith("https://github.com/"):
        parts = issue.rstrip("/").split("/")
        if len(parts) >= 5:
            return f"{parts[3]}/{parts[4]}"
    return Path(issue).name[:60] or issue[:60]


def _load_active_runs(runs_dir: Path) -> list[dict]:
    """Runs currently in progress — foreground or --background. Mirrors the
    liveness check `gauntlex status` uses, so the dashboard and CLI always agree."""
    if not runs_dir.exists():
        return []
    active = []
    for sf in sorted(runs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(sf.read_text())
        except Exception:
            continue
        if data.get("status") not in ("running", "starting"):
            continue

        pid = data.get("pid")
        alive = False
        if pid:
            try:
                os.kill(int(pid), 0)
                alive = True
            except (ProcessLookupError, PermissionError, ValueError, TypeError):
                pass
        if not alive:
            sf.unlink(missing_ok=True)  # stale — process died without updating status
            continue

        elapsed_seconds = 0.0
        started = data.get("started_at", "")
        if started:
            try:
                dt = datetime.fromisoformat(started)
                elapsed_seconds = (datetime.now(timezone.utc) - dt).total_seconds()
            except Exception:
                pass

        active.append({
            "run_id": data.get("run_id", sf.stem),
            "issue": _short_issue(data.get("issue", "")),
            "mode": data.get("mode", ""),
            "elapsed_seconds": elapsed_seconds,
            "elapsed": _fmt_elapsed(elapsed_seconds),
        })
    return active


def _load_all_reports(reports_dir: Path, limit: int = 100) -> list[dict]:
    if not reports_dir.exists():
        return []
    reports = []
    for f in sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with open(f) as fh:
                reports.append(json.load(fh))
        except Exception:
            continue
        if len(reports) >= limit:
            break
    return reports


def _render_index(reports: list[dict], cfg: AppConfig, active_runs: list[dict] | None = None) -> str:
    """Executive-ready Combat Dashboard — animated infographics, self-explanatory offline."""
    gate = cfg.gate.minimum_ars
    total = len(reports)
    n_passed = sum(1 for r in reports if r["ars_score"] >= gate)
    n_failed = total - n_passed
    avg_ars = sum(r["ars_score"] for r in reports) / total if total else 0.0
    pass_rate = int(n_passed / total * 100) if total else 0
    avg_col = "#059669" if avg_ars >= gate else "#DC2626"
    avg_label = "SECURE" if avg_ars >= gate else "AT RISK"

    # Donut chart: aggregate attack outcomes across all reports
    t_mitigated = t_partial = t_missed = 0
    for r in reports:
        for a in r.get("attacks", []):
            v = a.get("verdict", "")
            if v == "MITIGATED":
                t_mitigated += 1
            elif v == "PARTIAL":
                t_partial += 1
            else:
                t_missed += 1
    t_total_atk = max(t_mitigated + t_partial + t_missed, 1)
    _C = 339.292  # SVG donut circumference (r=54)
    def _seg(n: int) -> float: return round(n / t_total_atk * _C, 2)
    mit_seg = _seg(t_mitigated)
    par_seg = _seg(t_partial)
    mis_seg = _seg(t_missed)
    mit_pct = int(t_mitigated / t_total_atk * 100)
    par_pct = int(t_partial / t_total_atk * 100)
    mis_pct = 100 - mit_pct - par_pct
    _q = round(_C / 4, 2)
    mit_off = -_q
    par_off = round(-_q + mit_seg, 2)
    mis_off = round(-_q + mit_seg + par_seg, 2)

    # Sparkline
    chart_data = [{"x": i + 1, "y": round(r["ars_score"], 3)}
                  for i, r in enumerate(reversed(reports[:20]))]
    chart_json = json.dumps(chart_data)
    gate_y_pct = round((1 - gate) * 100, 1)

    # Run rows
    sev_colors = {"critical": "#DC2626", "high": "#EA580C", "medium": "#D97706", "low": "#059669"}
    rows_html = ""
    for r in reports[:50]:
        ars = r["ars_score"]
        ok = ars >= gate
        run_id = r["run_id"]
        short = run_id[-16:]
        ts = r.get("generated_at", "")[:16].replace("T", " ")
        missed = r.get("miss_count", 0)
        attacks_n = r.get("attack_count", 0)
        top_finding = ""
        for a in r.get("attacks", []):
            if a.get("verdict") == "MISSED":
                sev = a.get("severity", "medium")
                sc = sev_colors.get(sev, "#6B7280")
                top_finding = (
                    f'<span style="background:{sc};color:#fff;padding:1px 5px;'
                    f'border-radius:3px;font-size:10px;font-weight:700">{sev.upper()}</span>'
                    f' <span style="font-size:11px">[{a.get("cwe","")}] {a.get("title","")[:46]}</span>'
                )
                break
        if not top_finding and ok:
            top_finding = '<span style="color:#059669;font-size:11px;font-weight:600">&#x2705; All attacks mitigated</span>'
        elif not top_finding:
            top_finding = '<span style="color:#9CA3AF;font-size:11px">—</span>'
        ars_col = "#059669" if ok else "#DC2626"
        gate_badge = (
            '<span style="background:#D1FAE5;color:#065F46;padding:2px 8px;'
            'border-radius:10px;font-size:11px;font-weight:700">PASS</span>'
        ) if ok else (
            '<span style="background:#FEE2E2;color:#991B1B;padding:2px 8px;'
            'border-radius:10px;font-size:11px;font-weight:700">BLOCKED</span>'
        )
        rows_html += (
            f'<tr class="run-row" onclick="window.open(\'/api/runs/{run_id}/html\',\'_blank\')">'
            f'<td><code class="run-code">{short}</code></td>'
            f'<td><span style="font-size:16px;font-weight:900;color:{ars_col}">{ars:.3f}</span></td>'
            f'<td>{gate_badge}</td>'
            f'<td style="text-align:center;color:#374151">{attacks_n}</td>'
            f'<td style="text-align:center;font-weight:700;color:{"#DC2626" if missed else "#6B7280"}">{missed}</td>'
            f'<td>{top_finding}</td>'
            f'<td style="color:#9CA3AF;font-size:11px">{ts}</td>'
            f'<td style="white-space:nowrap">'
            f'<a href="/api/runs/{run_id}/html" onclick="event.stopPropagation()" class="dl-btn dl-html">HTML</a> '
            f'<a href="/api/runs/{run_id}/sarif" onclick="event.stopPropagation()" class="dl-btn dl-sarif">SARIF</a> '
            f'<a href="/api/runs/{run_id}/junit" onclick="event.stopPropagation()" class="dl-btn dl-junit">JUnit</a>'
            f'</td></tr>\n'
        )

    empty_html = "" if reports else (
        '<div class="empty-state">'
        '<div class="empty-icon">&#x26A4;</div>'
        '<div class="empty-title">No runs yet</div>'
        '<div class="empty-sub">Run your first adversarial session from the CLI:</div>'
        '<code class="empty-cmd">gauntlex run --issue examples/demo_issue.md --pretty</code>'
        '</div>'
    )
    table_html = ""
    if reports:
        table_html = (
            '<div style="overflow-x:auto"><table class="runs-table">'
            '<thead><tr>'
            '<th>Run ID</th><th>ARS</th><th>Gate</th>'
            '<th style="text-align:center">Attacks</th><th style="text-align:center">Missed</th>'
            '<th>Top Finding</th><th>Timestamp</th><th>Export</th>'
            f'</tr></thead><tbody>{rows_html}</tbody></table></div>'
        )

    # ── Active runs (in progress — foreground or --background) ───────────────
    active_runs = active_runs or []
    active_html = ""
    # ── No project found at all — not via cwd, not remembered from a previous
    # run either. Warn instead of silently showing 0 runs. This should be rare:
    # normally the dashboard remembers whatever project you last ran gauntlex in.
    no_project_html = ""
    if cfg.config_source is None:
        no_project_html = f"""
<div class="runs-card" style="border-color:#FCA5A5;margin-bottom:20px">
  <div class="card-hdr" style="background:linear-gradient(90deg,#FEF2F2,#fff);border-bottom-color:#FCA5A5;color:#991B1B">
    &#x26A0;&#xFE0F; No GAUNTLEX project found
  </div>
  <div style="padding:16px 20px;font-size:13px;color:#374151;line-height:1.7">
    This dashboard was launched from <code class="run-code">{Path.cwd()}</code>, which isn't inside
    a GAUNTLEX project, and nothing was remembered from a previous run on this machine either.
    It's reading (and will only ever find reports in) <code class="run-code">{cfg.reports_dir}</code>.<br><br>
    <strong>Fix:</strong> run any <code class="run-code">gauntlex</code> command inside your project once
    (e.g. <code class="run-code">gauntlex status</code>) — after that, <code class="run-code">gauntlex dashboard</code>
    will find it automatically from anywhere, no flags needed.
  </div>
</div>
"""
    if active_runs:
        active_rows = "".join(
            '<tr class="run-row">'
            f'<td><code class="run-code">{a["run_id"][-16:]}</code></td>'
            '<td><span class="running-badge"><span class="running-dot"></span>RUNNING</span></td>'
            f'<td style="color:#374151">{a["issue"]}</td>'
            f'<td style="color:#374151">{a["mode"] or "—"}</td>'
            f'<td style="color:#6B7280;font-size:11px">{a["elapsed"]} elapsed</td>'
            '</tr>\n'
            for a in active_runs
        )
        active_html = f"""
<div class="runs-card" style="border-color:#FDE68A">
  <div class="card-hdr" style="background:linear-gradient(90deg,#FFFBEB,#fff);border-bottom-color:#FDE68A;color:#92400E">
    &#x23F3; Active Runs ({len(active_runs)}) &mdash; parallel &amp; background sessions in progress
    <span style="margin-left:auto;font-size:11px;font-weight:400;color:#92400E">Page auto-refreshes every 30s</span>
  </div>
  <div style="overflow-x:auto"><table class="runs-table">
    <thead><tr><th>Run ID</th><th>Status</th><th>Issue / Repo</th><th>Mode</th><th>Started</th></tr></thead>
    <tbody>{active_rows}</tbody>
  </table></div>
</div>
"""

    # ── CSS (raw — no f-string escaping needed) ───────────────────────────────
    css = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#EFF6FF;color:#111827;min-height:100vh;overflow-x:hidden}

/* ── Header ── */
header{background:linear-gradient(135deg,#1E3A8A 0%,#2563EB 60%,#3B82F6 100%);padding:0 32px;height:64px;display:flex;align-items:center;gap:16px;box-shadow:0 4px 16px rgba(30,58,138,.35);position:sticky;top:0;z-index:100}
.hdr-logo{font-size:24px;animation:pulse-logo 2s ease-in-out infinite}
@keyframes pulse-logo{0%,100%{transform:scale(1)}50%{transform:scale(1.15)}}
header h1{font-size:19px;font-weight:900;color:#fff;letter-spacing:-.02em}
header .sub{font-size:11px;color:rgba(255,255,255,.7);font-weight:400;margin-top:1px}
.gate-badge{background:rgba(255,255,255,.18);color:#fff;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;border:1px solid rgba(255,255,255,.3);backdrop-filter:blur(4px)}
.hdr-nav{margin-left:auto;display:flex;gap:8px}
.hdr-nav a{color:rgba(255,255,255,.85);text-decoration:none;font-size:12px;font-weight:500;padding:5px 12px;border-radius:8px;border:1px solid rgba(255,255,255,.25);transition:all .2s}
.hdr-nav a:hover{background:rgba(255,255,255,.2);color:#fff}
.refresh-dot{width:7px;height:7px;border-radius:50%;background:#4ADE80;display:inline-block;animation:blink 1.8s ease-in-out infinite;margin-right:4px}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}

/* ── Hero explainer ── */
.hero{background:linear-gradient(135deg,#1E40AF 0%,#0EA5E9 100%);color:#fff;padding:28px 32px;margin-bottom:28px}
.hero-inner{max-width:1280px;margin:0 auto;display:flex;align-items:center;gap:32px}
.hero-text h2{font-size:22px;font-weight:900;margin-bottom:8px}
.hero-text p{font-size:13px;line-height:1.65;color:rgba(255,255,255,.88);max-width:620px}
.hero-pills{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
.pill{background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.3);padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600;color:#fff;backdrop-filter:blur(4px)}

/* ── Main layout ── */
.main{padding:0 32px 40px;max-width:1280px;margin:0 auto}

/* ── Stat cards ── */
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:#fff;border:1px solid #BFDBFE;border-radius:14px;padding:22px 24px;box-shadow:0 2px 8px rgba(37,99,235,.08);position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s;animation:card-in .5s ease both}
.stat-card:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(37,99,235,.15)}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;border-radius:14px 14px 0 0}
.stat-card.blue::before{background:linear-gradient(90deg,#2563EB,#60A5FA)}
.stat-card.green::before{background:linear-gradient(90deg,#059669,#34D399)}
.stat-card.red::before{background:linear-gradient(90deg,#DC2626,#F87171)}
.stat-card.amber::before{background:linear-gradient(90deg,#D97706,#FCD34D)}
@keyframes card-in{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.stat-card:nth-child(2){animation-delay:.08s}
.stat-card:nth-child(3){animation-delay:.16s}
.stat-card:nth-child(4){animation-delay:.24s}
.stat-lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:#6B7280;margin-bottom:8px;display:flex;align-items:center;gap:5px}
.stat-val{font-size:36px;font-weight:900;line-height:1;transition:color .3s}
.stat-sub{font-size:11px;color:#9CA3AF;margin-top:5px}
.stat-icon{font-size:28px;position:absolute;right:18px;top:18px;opacity:.12}

/* ── Trend + Donut row ── */
.mid-row{display:grid;grid-template-columns:1fr 340px;gap:16px;margin-bottom:20px}
.card{background:#fff;border:1px solid #BFDBFE;border-radius:14px;overflow:hidden;box-shadow:0 2px 8px rgba(37,99,235,.07)}
.card-hdr{padding:14px 20px;background:linear-gradient(90deg,#EFF6FF,#fff);border-bottom:1px solid #DBEAFE;font-size:13px;font-weight:700;color:#1E40AF;display:flex;align-items:center;gap:8px}
.chart-body{padding:16px 20px;height:140px;position:relative}
svg.spark{width:100%;height:100%}

/* ── Gauge ── */
.gauge-wrap{padding:20px;display:flex;flex-direction:column;align-items:center}
svg.gauge{width:200px;height:110px;overflow:visible}
.gauge-label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#6B7280;margin-top:8px}
.gauge-val{font-size:28px;font-weight:900;text-align:center}

/* ── Pipeline ── */
.pipeline-card{background:#fff;border:1px solid #BFDBFE;border-radius:14px;overflow:hidden;box-shadow:0 2px 8px rgba(37,99,235,.07);margin-bottom:20px}
.pipeline-body{padding:24px 32px}
.pipeline-title{font-size:13px;font-weight:700;color:#1E40AF;margin-bottom:18px;display:flex;align-items:center;gap:8px}
.flow{display:flex;align-items:center;gap:0;justify-content:center;flex-wrap:wrap;gap:0}
.flow-node{background:linear-gradient(135deg,#EFF6FF,#DBEAFE);border:2px solid #93C5FD;border-radius:12px;padding:12px 18px;text-align:center;min-width:110px;position:relative;transition:all .3s}
.flow-node:hover{transform:scale(1.05);box-shadow:0 4px 16px rgba(37,99,235,.25)}
.flow-node .fn-icon{font-size:20px;margin-bottom:4px}
.flow-node .fn-lbl{font-size:11px;font-weight:700;color:#1E40AF}
.flow-node .fn-sub{font-size:10px;color:#6B7280;margin-top:2px}
.flow-node.accent{background:linear-gradient(135deg,#FEF3C7,#FDE68A);border-color:#F59E0B}
.flow-node.accent .fn-lbl{color:#92400E}
.flow-node.danger{background:linear-gradient(135deg,#FEE2E2,#FECACA);border-color:#FCA5A5}
.flow-node.danger .fn-lbl{color:#991B1B}
.flow-node.success{background:linear-gradient(135deg,#D1FAE5,#A7F3D0);border-color:#6EE7B7}
.flow-node.success .fn-lbl{color:#065F46}
.flow-arrow{display:flex;align-items:center;padding:0 4px;color:#93C5FD;font-size:18px;position:relative;overflow:hidden}
.flow-arrow::after{content:'';position:absolute;top:50%;width:8px;height:8px;background:#3B82F6;border-radius:50%;transform:translateY(-50%);animation:arrow-dot 1.8s linear infinite;opacity:.8}
@keyframes arrow-dot{0%{left:-8px;opacity:0}20%{opacity:1}80%{opacity:1}100%{left:100%;opacity:0}}
.concurrent-wrap{display:flex;flex-direction:column;gap:4px;align-items:center}
.concurrent-badge{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#2563EB;background:#EFF6FF;border:1px solid #BFDBFE;border-radius:4px;padding:1px 6px;margin-bottom:2px}

/* ── Active runs ── */
.running-badge{display:inline-flex;align-items:center;gap:6px;background:#FEF3C7;color:#92400E;padding:3px 10px;border-radius:10px;font-size:11px;font-weight:700}
.running-dot{width:7px;height:7px;border-radius:50%;background:#D97706;display:inline-block;animation:blink 1.4s ease-in-out infinite}

/* ── Runs table ── */
.runs-card{background:#fff;border:1px solid #BFDBFE;border-radius:14px;overflow:hidden;box-shadow:0 2px 8px rgba(37,99,235,.07);margin-bottom:20px}
.runs-table{width:100%;border-collapse:collapse;font-size:13px}
.runs-table thead tr{background:linear-gradient(90deg,#EFF6FF,#F0F9FF)}
.runs-table th{padding:11px 14px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#1E40AF;border-bottom:2px solid #BFDBFE;white-space:nowrap}
.runs-table td{padding:11px 14px;border-bottom:1px solid #F0F9FF}
.run-row{cursor:pointer;transition:background .15s}
.run-row:hover td{background:#F0F9FF}
.run-row:last-child td{border-bottom:none}
.run-code{font-size:10px;font-family:'Menlo','Monaco',monospace;color:#374151;background:#F3F4F6;padding:2px 6px;border-radius:4px}
.dl-btn{text-decoration:none;padding:3px 8px;border-radius:5px;font-size:10px;font-weight:700;transition:all .15s}
.dl-html{background:#EFF6FF;color:#1D4ED8}
.dl-html:hover{background:#DBEAFE}
.dl-sarif{background:#F0FDF4;color:#065F46}
.dl-sarif:hover{background:#D1FAE5}
.dl-junit{background:#FFF7ED;color:#92400E}
.dl-junit:hover{background:#FED7AA}

/* ── CLI Quick Start ── */
.cli-card{background:linear-gradient(135deg,#0F172A 0%,#1E293B 100%);border-radius:14px;overflow:hidden;margin-bottom:20px;box-shadow:0 4px 20px rgba(0,0,0,.25)}
.cli-hdr{padding:14px 24px;border-bottom:1px solid rgba(255,255,255,.08);display:flex;align-items:center;gap:10px}
.cli-dots{display:flex;gap:5px}
.cli-dot{width:11px;height:11px;border-radius:50%}
.cli-title{color:rgba(255,255,255,.5);font-size:12px;font-weight:500;margin-left:8px;font-family:monospace}
.cli-body{padding:20px 24px;display:grid;grid-template-columns:1fr 1fr;gap:16px}
.cli-block{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:14px 16px}
.cli-block-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#94A3B8;margin-bottom:10px}
.cli-line{font-family:'Menlo','Monaco','Courier New',monospace;font-size:12px;color:#E2E8F0;margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;line-height:1.5}
.cli-line:last-child{margin-bottom:0}
.cli-prompt{color:#4ADE80;flex-shrink:0}
.cli-cmd{color:#7DD3FC}
.cli-arg{color:#FCD34D}
.cli-flag{color:#C084FC}
.cli-comment{color:#4B5563;font-size:11px;margin-left:6px}

/* ── Empty state ── */
.empty-state{padding:56px;text-align:center;color:#6B7280}
.empty-icon{font-size:48px;margin-bottom:16px;animation:float 3s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.empty-title{font-size:17px;font-weight:700;color:#374151;margin-bottom:6px}
.empty-sub{font-size:13px;margin-bottom:14px}
.empty-cmd{display:inline-block;background:#1E293B;color:#7DD3FC;padding:8px 16px;border-radius:8px;font-family:monospace;font-size:13px}

/* ── Footer ── */
footer{margin-top:8px;padding:16px 32px;border-top:1px solid #DBEAFE;font-size:12px;color:#9CA3AF;text-align:center}

/* ── Animations ── */
@keyframes fade-in{from{opacity:0}to{opacity:1}}
.fade-in{animation:fade-in .4s ease both}
"""

    # ── JS (plain string — Python values injected via .replace()) ────────────
    js_template = r"""
(function() {
  /* Count-up animation for stat values */
  document.querySelectorAll('[data-count]').forEach(function(el) {
    var target = parseFloat(el.dataset.count);
    var isFloat = el.dataset.count.indexOf('.') !== -1;
    var decimals = isFloat ? el.dataset.count.split('.')[1].length : 0;
    var start = 0, dur = 900, startTime = null;
    function step(ts) {
      if (!startTime) startTime = ts;
      var prog = Math.min((ts - startTime) / dur, 1);
      var ease = 1 - Math.pow(1 - prog, 3);
      var val = start + (target - start) * ease;
      el.textContent = isFloat ? val.toFixed(decimals) : Math.round(val).toString();
      if (prog < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  });

  /* Animated sparkline */
  var data = CHART_DATA;
  var gate = GATE_VAL;
  if (data.length) {
    var svg = document.getElementById('sparkline');
    var W = 860, H = 100;
    var n = data.length;
    var minY = Math.min.apply(null, data.map(function(d){return d.y;}));
    var maxY = Math.max.apply(null, data.map(function(d){return d.y;}));
    var rng = Math.max(maxY - minY, 0.1);
    function px(d, i) {
      return {
        x: n < 2 ? W/2 : (i / (n - 1)) * W,
        y: H - ((d.y - (minY - rng*0.1)) / (rng * 1.2)) * H
      };
    }
    var pts = data.map(px);

    /* Gradient fill */
    var defs = document.createElementNS('http://www.w3.org/2000/svg','defs');
    var grad = document.createElementNS('http://www.w3.org/2000/svg','linearGradient');
    grad.id = 'spk-grad'; grad.setAttribute('x1','0'); grad.setAttribute('x2','0');
    grad.setAttribute('y1','0'); grad.setAttribute('y2','1');
    var s1 = document.createElementNS('http://www.w3.org/2000/svg','stop');
    s1.setAttribute('offset','0%'); s1.setAttribute('stop-color','#3B82F6'); s1.setAttribute('stop-opacity','0.2');
    var s2 = document.createElementNS('http://www.w3.org/2000/svg','stop');
    s2.setAttribute('offset','100%'); s2.setAttribute('stop-color','#3B82F6'); s2.setAttribute('stop-opacity','0.01');
    grad.appendChild(s1); grad.appendChild(s2); defs.appendChild(grad); svg.appendChild(defs);

    /* Area fill */
    var aPath = 'M' + pts[0].x + ',' + H;
    pts.forEach(function(p) { aPath += ' L' + p.x.toFixed(1) + ',' + p.y.toFixed(1); });
    aPath += ' L' + pts[pts.length-1].x + ',' + H + ' Z';
    var area = document.createElementNS('http://www.w3.org/2000/svg','path');
    area.setAttribute('d', aPath); area.setAttribute('fill','url(#spk-grad)');
    svg.appendChild(area);

    /* Line */
    var linePath = pts.map(function(p,i){return (i===0?'M':'L')+p.x.toFixed(1)+','+p.y.toFixed(1);}).join(' ');
    var line = document.createElementNS('http://www.w3.org/2000/svg','path');
    line.setAttribute('d', linePath); line.setAttribute('fill','none');
    line.setAttribute('stroke','#2563EB'); line.setAttribute('stroke-width','2.5');
    line.setAttribute('stroke-linejoin','round'); line.setAttribute('stroke-linecap','round');
    var len = line.getTotalLength ? line.getTotalLength() : 2000;
    line.style.strokeDasharray = len; line.style.strokeDashoffset = len;
    line.style.transition = 'stroke-dashoffset 1.4s ease';
    svg.appendChild(line);
    setTimeout(function(){ line.style.strokeDashoffset = '0'; }, 100);

    /* Dots */
    pts.forEach(function(p, i) {
      var c = document.createElementNS('http://www.w3.org/2000/svg','circle');
      c.setAttribute('cx', p.x.toFixed(1)); c.setAttribute('cy', p.y.toFixed(1)); c.setAttribute('r','5');
      c.setAttribute('fill', data[i].y >= gate ? '#059669' : '#DC2626');
      c.setAttribute('stroke','#fff'); c.setAttribute('stroke-width','2');
      c.style.opacity = '0'; c.style.transition = 'opacity .3s ' + (0.8 + i * 0.04) + 's';
      svg.appendChild(c);
      setTimeout(function(el){ el.style.opacity = '1'; }, 50, c);

      /* Tooltip */
      c.addEventListener('mouseenter', function(e) {
        var tt = document.getElementById('spk-tt');
        if (!tt) { tt = document.createElement('div'); tt.id='spk-tt'; tt.style.cssText='position:fixed;background:#1E293B;color:#fff;padding:6px 10px;border-radius:6px;font-size:11px;pointer-events:none;z-index:999;box-shadow:0 4px 12px rgba(0,0,0,.4)'; document.body.appendChild(tt); }
        tt.textContent = 'ARS: ' + data[i].y.toFixed(3) + (data[i].y >= gate ? ' ✓ PASS' : ' ✗ BLOCKED');
        tt.style.left = (e.clientX + 12) + 'px'; tt.style.top = (e.clientY - 30) + 'px'; tt.style.display = 'block';
      });
      c.addEventListener('mouseleave', function() { var tt=document.getElementById('spk-tt'); if(tt) tt.style.display='none'; });
    });
  }

  /* Donut chart animation */
  document.querySelectorAll('.donut-seg').forEach(function(seg) {
    var target = parseFloat(seg.dataset.target);
    seg.style.transition = 'stroke-dashoffset 1.2s ease .3s';
    setTimeout(function() { seg.style.strokeDashoffset = target; }, 50);
  });

})();
"""

    js = (js_template
          .replace("CHART_DATA", chart_json)
          .replace("GATE_VAL", str(gate)))

    # ── SVG donut segments ────────────────────────────────────────────────────
    def _donut_seg(color: str, dash: float, start_off: float, animated_off: float, title: str) -> str:
        return (
            f'<circle class="donut-seg" cx="120" cy="120" r="54" fill="none" stroke="{color}"'
            f' stroke-width="20" stroke-dasharray="{dash} {_C}"'
            f' stroke-dashoffset="{start_off}" data-target="{animated_off}"'
            f' transform="rotate(-90 120 120)"><title>{title}</title></circle>'
        )

    seg_mit = _donut_seg("#059669", mit_seg, -mit_off + _C, mit_off,
                          f"Mitigated {mit_pct}% ({t_mitigated})")
    seg_par = _donut_seg("#F59E0B", par_seg, -par_off + _C, par_off,
                          f"Partial {par_pct}% ({t_partial})")
    seg_mis = _donut_seg("#DC2626", mis_seg, -mis_off + _C, mis_off,
                          f"Missed {mis_pct}% ({t_missed})")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>GAUNTLEX Combat Dashboard</title>
<style>{css}</style>
</head>
<body>

<!-- ── Header ─────────────────────────────────────────────────────────── -->
<header>
  <span class="hdr-logo">&#x2694;&#xFE0F;</span>
  <div>
    <div style="display:flex;align-items:center;gap:10px">
      <h1>GAUNTLEX</h1>
      <span class="gate-badge">ARS &ge; {gate:.2f}</span>
    </div>
    <div class="sub">Adversarial Co-Generation Engine &mdash; Builder + Breaker run concurrently</div>
  </div>
  <nav class="hdr-nav" style="margin-left:auto">
    <a href="/mcp">MCP Tools</a>
    <a href="/api">JSON API</a>
    <a href="/status"><span class="refresh-dot"></span>Live</a>
  </nav>
</header>

<!-- ── Hero explainer ─────────────────────────────────────────────────── -->
<div class="hero">
  <div class="hero-inner">
    <div style="font-size:64px;line-height:1;flex-shrink:0">&#x1F6E1;&#xFE0F;</div>
    <div class="hero-text">
      <h2>Security Testing That Matches the Speed of Development</h2>
      <p>GAUNTLEX generates <strong>code and attacks simultaneously</strong> — the Builder writes,
         the Breaker attacks, the Arbiter scores. Every run produces an
         <strong>Adversarial Resilience Score (ARS)</strong> that gates your CI/CD pipeline.
         Near-zero setup. No manual test authoring. Works from CLI, IDE, or GitHub Actions.</p>
      <div class="hero-pills">
        <span class="pill">&#x1F50C; Zero manual setup</span>
        <span class="pill">&#x26A1; Concurrent Builder &amp; Breaker</span>
        <span class="pill">&#x1F512; ARS Gate</span>
        <span class="pill">&#x1F4CB; Compliance-ready SARIF/JUnit</span>
        <span class="pill">&#x1F9E0; Intent + Spec aware</span>
      </div>
    </div>
  </div>
</div>

<div class="main">

<!-- ── No project found warning ───────────────────────────────────────── -->
{no_project_html}

<!-- ── Active runs (in progress) ─────────────────────────────────────── -->
{active_html}

<!-- ── Stat cards ────────────────────────────────────────────────────── -->
<div class="stat-row">
  <div class="stat-card blue">
    <div class="stat-icon">&#x1F3AF;</div>
    <div class="stat-lbl">&#x1F4CA; Total Runs</div>
    <div class="stat-val" style="color:#1E40AF" data-count="{total}">{total}</div>
    <div class="stat-sub">adversarial sessions</div>
  </div>
  <div class="stat-card green">
    <div class="stat-icon">&#x2705;</div>
    <div class="stat-lbl">&#x1F7E2; Gate Passed</div>
    <div class="stat-val" style="color:#059669" data-count="{n_passed}">{n_passed}</div>
    <div class="stat-sub">{pass_rate}% pass rate</div>
  </div>
  <div class="stat-card red">
    <div class="stat-icon">&#x1F6AB;</div>
    <div class="stat-lbl">&#x1F534; Gate Blocked</div>
    <div class="stat-val" style="color:#DC2626" data-count="{n_failed}">{n_failed}</div>
    <div class="stat-sub">PRs prevented from shipping</div>
  </div>
  <div class="stat-card amber">
    <div class="stat-icon">&#x1F4AF;</div>
    <div class="stat-lbl">&#x26A1; Avg ARS Score</div>
    <div class="stat-val" style="color:{avg_col}" data-count="{avg_ars:.3f}">{avg_ars:.3f}</div>
    <div class="stat-sub" style="font-weight:700;color:{avg_col}">{avg_label}</div>
  </div>
</div>

<!-- ── ARS Trend + Donut ──────────────────────────────────────────────── -->
<div class="mid-row">
  <div class="card">
    <div class="card-hdr">&#x1F4C8; Adversarial Resilience Score &mdash; Trend
      <span style="margin-left:auto;font-size:11px;font-weight:400;color:#6B7280">
        Last {min(20, total)} runs &nbsp;|&nbsp; Gate line shown in red
      </span>
    </div>
    <div class="chart-body">
      <svg class="spark" id="sparkline" viewBox="0 0 860 100" preserveAspectRatio="none">
        <!-- Gate line -->
        <line x1="0" y1="{gate_y_pct}" x2="860" y2="{gate_y_pct}"
              stroke="#FCA5A5" stroke-width="1.5" stroke-dasharray="8,5" opacity=".8"/>
        <text x="4" y="{gate_y_pct - 4}" font-size="9" fill="#EF4444" font-weight="700">Gate {gate:.2f}</text>
      </svg>
    </div>
  </div>

  <div class="card">
    <div class="card-hdr">&#x1F4CA; Attack Outcomes</div>
    <div class="gauge-wrap">
      <svg viewBox="0 0 240 240" width="200" height="200" style="margin:-20px 0">
        <!-- Background ring -->
        <circle cx="120" cy="120" r="54" fill="none" stroke="#F3F4F6" stroke-width="20"/>
        <!-- Segments (start fully hidden, animate in via JS) -->
        {seg_mit}
        {seg_par}
        {seg_mis}
        <!-- Center label -->
        <text x="120" y="114" text-anchor="middle" font-size="22" font-weight="900" fill="#111827">{t_total_atk}</text>
        <text x="120" y="130" text-anchor="middle" font-size="9" fill="#6B7280" font-weight="600">ATTACKS</text>
      </svg>
      <div style="display:flex;gap:14px;margin-top:-8px">
        <div style="display:flex;align-items:center;gap:4px;font-size:11px">
          <span style="width:10px;height:10px;border-radius:50%;background:#059669;display:inline-block"></span>
          <span style="font-weight:600;color:#059669">{mit_pct}%</span> <span style="color:#6B7280">mitigated</span>
        </div>
        <div style="display:flex;align-items:center;gap:4px;font-size:11px">
          <span style="width:10px;height:10px;border-radius:50%;background:#F59E0B;display:inline-block"></span>
          <span style="font-weight:600;color:#D97706">{par_pct}%</span> <span style="color:#6B7280">partial</span>
        </div>
        <div style="display:flex;align-items:center;gap:4px;font-size:11px">
          <span style="width:10px;height:10px;border-radius:50%;background:#DC2626;display:inline-block"></span>
          <span style="font-weight:600;color:#DC2626">{mis_pct}%</span> <span style="color:#6B7280">missed</span>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ── How It Works pipeline ─────────────────────────────────────────── -->
<div class="pipeline-card">
  <div class="card-hdr">&#x26A1; How GAUNTLEX Works &mdash; Live Pipeline</div>
  <div class="pipeline-body">
    <p style="font-size:12px;color:#6B7280;margin-bottom:20px">
      Each run executes this pipeline. Builder and Breaker run <strong>concurrently</strong>
      &mdash; no waiting for one before the other. Arbiter scores each attack. ARS gate
      decides pass or block. The whole cycle completes in seconds.
    </p>
    <div class="flow">
      <div class="flow-node">
        <div class="fn-icon">&#x1F4C4;</div>
        <div class="fn-lbl">Spec / Issue</div>
        <div class="fn-sub">GitHub · file · folder</div>
      </div>
      <div class="flow-arrow">&#x279C;</div>
      <div class="flow-node accent">
        <div class="fn-icon">&#x1F9E0;</div>
        <div class="fn-lbl">Intent Adapter</div>
        <div class="fn-sub">Jira · Confluence · Aha!</div>
      </div>
      <div class="flow-arrow">&#x279C;</div>
      <div class="concurrent-wrap">
        <div class="concurrent-badge">Concurrent</div>
        <div style="display:flex;gap:8px">
          <div class="flow-node success">
            <div class="fn-icon">&#x1F6E0;&#xFE0F;</div>
            <div class="fn-lbl">Builder</div>
            <div class="fn-sub">writes code</div>
          </div>
          <div class="flow-node danger">
            <div class="fn-icon">&#x1F5E1;&#xFE0F;</div>
            <div class="fn-lbl">Breaker</div>
            <div class="fn-sub">attacks code</div>
          </div>
        </div>
      </div>
      <div class="flow-arrow">&#x279C;</div>
      <div class="flow-node accent">
        <div class="fn-icon">&#x2696;&#xFE0F;</div>
        <div class="fn-lbl">Arbiter</div>
        <div class="fn-sub">scores each attack</div>
      </div>
      <div class="flow-arrow">&#x279C;</div>
      <div class="flow-node" style="background:linear-gradient(135deg,#EFF6FF,#DBEAFE);border-color:#3B82F6">
        <div class="fn-icon">&#x1F4AF;</div>
        <div class="fn-lbl">ARS Score</div>
        <div class="fn-sub">&Sigma;(scores) / N</div>
      </div>
      <div class="flow-arrow">&#x279C;</div>
      <div class="flow-node {'success' if avg_ars >= gate else 'danger'}">
        <div class="fn-icon">{'&#x2705;' if avg_ars >= gate else '&#x1F6AB;'}</div>
        <div class="fn-lbl">Gate</div>
        <div class="fn-sub">{'PASS &mdash; ship it' if avg_ars >= gate else 'BLOCKED &mdash; fix first'}</div>
      </div>
    </div>
  </div>
</div>

<!-- ── Runs table ─────────────────────────────────────────────────────── -->
<div class="runs-card">
  <div class="card-hdr">&#x26A4; Run History ({total})
    <span style="margin-left:auto;font-size:11px;font-weight:400;color:#6B7280">Click any row to open full HTML report</span>
  </div>
  {empty_html}{table_html}
</div>

<!-- ── CLI Quick Start ────────────────────────────────────────────────── -->
<div class="cli-card">
  <div class="cli-hdr">
    <div class="cli-dots">
      <div class="cli-dot" style="background:#FF5F57"></div>
      <div class="cli-dot" style="background:#FEBC2E"></div>
      <div class="cli-dot" style="background:#28C840"></div>
    </div>
    <span class="cli-title">Terminal &mdash; GAUNTLEX CLI Quick Start</span>
  </div>
  <div class="cli-body">
    <div class="cli-block">
      <div class="cli-block-title">&#x1F680; Run adversarial testing</div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--issue</span> <span class="cli-arg">examples/demo_issue.md</span> <span class="cli-flag">--pretty</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--issue</span> <span class="cli-arg">https://github.com/org/repo/issues/42</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--issue</span> <span class="cli-arg">./src/</span> <span class="cli-flag">--intent</span> <span class="cli-arg">PROJ-123</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--rounds</span> <span class="cli-arg">3</span> <span class="cli-flag">--format</span> <span class="cli-arg">sarif</span></span></div>
    </div>
    <div class="cli-block">
      <div class="cli-block-title">&#x1F527; Setup &amp; Integration</div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex integrate</span> <span class="cli-arg">all</span> <span class="cli-comment"># Claude Code, Cursor, Copilot, Codex, Windsurf</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex integrate</span> <span class="cli-arg">github-actions</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex findings</span> <span class="cli-comment"># last run vulnerability report</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex dashboard</span> <span class="cli-flag">--port</span> <span class="cli-arg">8080</span> <span class="cli-comment"># this UI</span></span></div>
    </div>
    <div class="cli-block">
      <div class="cli-block-title">&#x1F4E6; Multi-repo testing</div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--issue</span> <span class="cli-arg">https://github.com/axios/axios</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--issue</span> <span class="cli-arg">https://github.com/pallets/flask</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--issue</span> <span class="cli-arg">https://github.com/gin-gonic/gin</span></span></div>
    </div>
    <div class="cli-block">
      <div class="cli-block-title">&#x1F3C6; Output formats</div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--format</span> <span class="cli-arg">html</span> <span class="cli-comment"># exec report</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--format</span> <span class="cli-arg">sarif</span> <span class="cli-comment"># SAST tools</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex run</span> <span class="cli-flag">--format</span> <span class="cli-arg">junit</span> <span class="cli-comment"># CI pipelines</span></span></div>
      <div class="cli-line"><span class="cli-prompt">$</span><span><span class="cli-cmd">gauntlex findings</span> <span class="cli-flag">--format</span> <span class="cli-arg">md</span> <span class="cli-comment"># PR comment</span></span></div>
    </div>
  </div>
</div>

</div><!-- /main -->
<footer>GAUNTLEX Adversarial Co-Generation Engine &nbsp;&bull;&nbsp; Built by Sanjoy Ghosh &nbsp;&bull;&nbsp; Auto-refreshes every 30s</footer>

<script>{js}</script>
</body>
</html>"""
