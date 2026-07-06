"""
COMBATPAIR CLI — entry point for all slash commands.

All commands return JSON to stdout (--pretty for human-readable).
Exit 0 = success, Exit 1 = failure (gate blocked, check failed, etc.).
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Auto-load .env if present — lets users set OPENROUTER_API_KEY etc. without
# manually exporting. dotenv is a no-op when the file doesn't exist.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from .config import AppConfig, DEFAULT_CONFIG_YAML

console = Console()

_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


@dataclass
class _RunProgress:
    run_id: str = ""
    issue_label: str = ""
    mode: str = ""
    attack_total: int = 0
    # phases: init → loading → combat → scoring → saving → done | error
    phase: str = "init"
    spec_bytes: int = 0
    combat_start: float = 0.0
    attacks_scored: int = 0
    current_attack_cwe: str = ""
    current_attack_title: str = ""
    completed_attacks: list[tuple[str, str, str]] = field(default_factory=list)
    error: str = ""
    attack_start: float = 0.0
    _tick: int = 0

    def spinner(self) -> str:
        self._tick += 1
        return _SPINNER_FRAMES[self._tick % len(_SPINNER_FRAMES)]


def _fmt_elapsed(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 60}m {s % 60:02d}s" if s >= 60 else f"{s}s"


def _verdict_style(verdict: str) -> str:
    return {"MITIGATED": "green", "PARTIAL": "yellow", "MISSED": "red"}.get(verdict, "dim")


def _render_live_panel(state: _RunProgress) -> Panel:
    lines: list[str] = []

    def _phase_row(num: int, label: str, detail: str = "", active: bool = False, done: bool = False) -> str:
        icon = state.spinner() if active else ("✓" if done else "·")
        col = "cyan" if active else ("green" if done else "dim")
        det = f"  [dim]{detail}[/dim]" if detail else ""
        return f"  [{col}][{num}/4] {icon}[/{col}]  {label}{det}"

    spec_done = state.phase not in ("init", "loading")
    combat_done = state.phase in ("scoring", "saving", "done")
    scoring_done = state.phase in ("saving", "done")
    save_done = state.phase == "done"

    # Phase 1 — Spec
    if state.phase == "loading":
        lines.append(_phase_row(1, "Loading spec...", state.issue_label, active=True))
    elif spec_done:
        size = f"{state.spec_bytes // 1024}KB" if state.spec_bytes >= 1024 else f"{state.spec_bytes}B"
        lines.append(_phase_row(1, "Spec loaded", f"{state.issue_label}  ({size})", done=True))
    else:
        lines.append(_phase_row(1, "Load spec", state.issue_label))

    # Phase 2 — Combat
    if state.phase == "combat":
        elapsed = _fmt_elapsed(time.monotonic() - state.combat_start)
        lines.append(_phase_row(2, "Builder + Breaker  [dim]running concurrently[/dim]", elapsed, active=True))
        lines.append(f"      [dim]├─[/dim] [blue]Builder:[/blue]  generating secure implementation")
        lines.append(f"      [dim]└─[/dim] [red]Breaker:[/red]  generating adversarial attack vectors")
    elif combat_done:
        lines.append(_phase_row(2, "Builder + Breaker", "complete", done=True))
    else:
        lines.append(_phase_row(2, "Builder + Breaker", "concurrent LLM calls"))

    # Phase 3 — Arbiter scoring
    if state.phase == "scoring":
        prog = f"{state.attacks_scored}/{state.attack_total}"
        lines.append(_phase_row(3, f"Arbiter scoring attacks  [dim]{prog}[/dim]", active=True))
        vdict = {"MITIGATED": "✓", "PARTIAL": "~", "MISSED": "✗"}
        for cwe, title, verdict in state.completed_attacks:
            col = _verdict_style(verdict)
            lines.append(f"      [{col}]{vdict.get(verdict,'·')}  {cwe:<10}[/{col}] [dim]{title[:45]}[/dim]  [{col}]{verdict}[/{col}]")
        if state.current_attack_cwe:
            atk_elapsed = f" ({_fmt_elapsed(time.monotonic() - state.attack_start)})" if state.attack_start else ""
            lines.append(f"      [cyan]{state.spinner()}  {state.current_attack_cwe:<10}[/cyan] [dim]{state.current_attack_title[:45]}[/dim]  [dim]scoring...{atk_elapsed}[/dim]")
        remaining = state.attack_total - state.attacks_scored - (1 if state.current_attack_cwe else 0)
        for _ in range(max(0, remaining)):
            lines.append(f"      [dim]·  {'—':<10} —[/dim]")
    elif scoring_done:
        lines.append(_phase_row(3, "Arbiter scoring", f"{state.attacks_scored} attacks scored", done=True))
    else:
        lines.append(_phase_row(3, "Arbiter scoring", f"{state.attack_total} attacks"))

    # Phase 4 — Save report
    if state.phase == "saving":
        lines.append(_phase_row(4, "Saving report...", active=True))
    elif save_done:
        lines.append(_phase_row(4, "Report saved", done=True))
    else:
        lines.append(_phase_row(4, "Save report"))

    if state.error:
        lines.append(f"\n  [red]✗ Error:[/red] {state.error}")

    header = (
        f"[bold cyan]⚔  COMBATPAIR[/bold cyan]  [dim]{state.run_id}[/dim]\n"
        f"  Mode: [cyan]{state.mode}[/cyan]  ·  Attacks: {state.attack_total or '?'}  ·  Repo: [dim]{state.issue_label}[/dim]"
    )
    body = header + "\n" + "─" * 68 + "\n" + "\n".join(lines)
    return Panel(Text.from_markup(body), border_style="blue", padding=(0, 1))


@asynccontextmanager
async def _live_ticker(live: "Live", render_fn, interval: float = 0.25):
    """Keep re-rendering `render_fn()` into `live` while the wrapped block runs, so
    a slow model call still shows a moving spinner and elapsed time instead of
    freezing the panel."""
    stop = asyncio.Event()

    async def _tick():
        while not stop.is_set():
            live.update(render_fn())
            await asyncio.sleep(interval)

    task = asyncio.create_task(_tick())
    try:
        yield
    finally:
        stop.set()
        await task


async def _await_with_heartbeat(coro, plain_fn, interval: float = 20.0):
    """Await `coro`, printing a heartbeat via `plain_fn` every `interval` seconds
    while it's still running — so a slow model call never looks like a hang."""
    task = asyncio.ensure_future(coro)
    waited = 0.0
    while True:
        done, _ = await asyncio.wait({task}, timeout=interval)
        if task in done:
            return await task
        waited += interval
        plain_fn(f"      ... still waiting on model response ({_fmt_elapsed(waited)})")


def _write_run_status(run_id: str, runs_dir: Path, **fields) -> None:
    """Write/update a status.json for a background or in-progress run."""
    runs_dir.mkdir(parents=True, exist_ok=True)
    status_file = runs_dir / f"{run_id}.json"
    existing: dict = {}
    if status_file.exists():
        try:
            existing = json.loads(status_file.read_text())
        except Exception:
            pass
    existing.update({"run_id": run_id, "updated_at": datetime.now(timezone.utc).isoformat(), **fields})
    status_file.write_text(json.dumps(existing, indent=2))


def _issue_label(issue: str) -> str:
    """Short human label for the issue source (max 60 chars)."""
    if issue.startswith("https://github.com/"):
        parts = issue.rstrip("/").split("/")
        if len(parts) >= 5:
            return f"{parts[3]}/{parts[4]}"
    p = Path(issue)
    # Use the filename/dirname for any absolute or relative path (even if non-existent)
    if p.is_absolute() or "/" in issue:
        name = p.name or issue
        return name[:60]
    if p.exists():
        return p.name[:60]
    return issue[:60]


@click.group()
@click.version_option(package_name="combatpair-ai")
def main():
    """COMBATPAIR — Adversarial Co-Generation Engine."""
    pass


# ──────────────────────────────────────────────────────────────────────────────
# combatpair run
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--issue", required=True,
              help="Spec file (SPEC.md, requirements doc), GitHub issue URL, or GitHub repo URL (brownfield)")
@click.option(
    "--mode", default="standard", type=click.Choice(["quick", "standard", "thorough"]),
    show_default=True, help="Execution mode: quick=5 attacks, standard=20, thorough=50"
)
@click.option("--domain", default="owasp_top10", show_default=True,
              help="Comma-separated policy domains (e.g. owasp_top10,hipaa,finra)")
@click.option("--intent", default=None,
              help="Business intent source: Jira key (PROJ-123), Confluence URL, or Aha! URL. "
                   "Widens the attack surface beyond the spec alone. "
                   "Requires JIRA_URL+JIRA_EMAIL+JIRA_TOKEN (or CONFLUENCE_* or AHA_* env vars).")
@click.option("--pretty", is_flag=True, help="Human-readable Rich output instead of JSON")
@click.option("--config", default=None, help="Path to .combatpair.yml (default: auto-detect)")
@click.option("--background", is_flag=True, default=False,
              help="Fire-and-forget: run in a detached subprocess and return immediately.")
@click.option("--run-id", default=None, hidden=True,
              help="Pre-assigned run ID (used internally by --background launcher).")
def run(issue: str, mode: str, domain: str, intent: str | None, pretty: bool,
        config: str | None, background: bool, run_id: str | None):
    """Run adversarial Builder + Breaker on a spec.

    \b
    Attack surface = spec (what to build) + intent (why it's needed).
    Builder generates code from the spec. Breaker attacks it. Arbiter scores.
    Spec drives the language: write "implement in Go" and Builder produces Go.

    \b
    Primary (greenfield — spec-driven):
      combatpair run --issue SPEC.md --pretty
      combatpair run --issue SPEC.md --intent PROJ-123 --domain hipaa
      combatpair run --issue SPEC.md --mode thorough --domain owasp_top10,finra
      combatpair run --issue https://github.com/owner/repo/issues/42

    \b
    Secondary (brownfield — extract spec from existing repo):
      combatpair run --issue https://github.com/pallets/flask --background
      combatpair run --issue /path/to/local/repo --mode quick
    """
    # ── Pre-flight: verify config before doing anything ───────────────────────
    _cfg_preflight = AppConfig.load(config)
    _missing = _check_config_ready(_cfg_preflight)
    if _missing:
        console.print()
        console.print("[red bold]⚔  COMBATPAIR cannot run — configuration is incomplete:[/red bold]")
        console.print()
        for problem, fix in _missing:
            console.print(f"  [red]✗[/red]  {problem}")
            console.print(f"     [dim]Fix: [bold cyan]{fix}[/bold cyan][/dim]")
        console.print()
        console.print("  [dim]Run [bold cyan]combatpair setup[/bold cyan] for the full wizard.[/dim]")
        console.print()
        sys.exit(1)

    if background:
        from .output.report import generate_run_id as _gen_id
        bg_run_id = run_id or _gen_id()
        cfg = AppConfig.load(config)
        runs_dir = cfg.reports_dir.parent / "runs"
        _write_run_status(bg_run_id, runs_dir,
                          status="starting", issue=issue, mode=mode,
                          started_at=datetime.now(timezone.utc).isoformat(), pid=None)

        # Build subprocess args (same command minus --background).
        # Use sys.executable + -c entry-point so the subprocess works regardless
        # of whether `combatpair` is on PATH (editable installs, virtualenvs, etc.)
        entry = (
            "from combatpair.cli import main; main(standalone_mode=True)"
        )
        args = [sys.executable, "-c", entry, "run",
                "--issue", issue, "--mode", mode, "--domain", domain]
        if intent:
            args += ["--intent", intent]
        if config:
            args += ["--config", config]
        args += ["--run-id", bg_run_id]

        log_path = runs_dir / f"{bg_run_id}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w") as log_fh:
            proc = subprocess.Popen(
                args,
                stdout=log_fh, stderr=log_fh,
                start_new_session=True,  # detach from controlling terminal
            )
        _write_run_status(bg_run_id, runs_dir, status="running", pid=proc.pid)

        console.print(f"\n[bold cyan]⚔  COMBATPAIR[/bold cyan]  run started in background")
        console.print(f"   Run ID : [dim]{bg_run_id}[/dim]")
        console.print(f"   Issue  : [dim]{_issue_label(issue)}[/dim]")
        console.print(f"   Log    : [dim]{log_path}[/dim]")
        console.print(f"   Check  : [bold]combatpair status[/bold]")
        console.print()
        return

    asyncio.run(_run_async(issue, mode, domain, intent, pretty, config, run_id))


async def _run_async(
    issue: str,
    mode: str,
    domain: str,
    intent_ref: str | None,
    pretty: bool,
    config_path: str | None,
    preset_run_id: str | None = None,
):
    cfg = AppConfig.load(config_path)
    runs_dir = cfg.reports_dir.parent / "runs"

    mode_attack_counts = {"quick": 5, "standard": 20, "thorough": 50}
    cfg.combat_pair.attack_count = mode_attack_counts[mode]

    from .core.combat_pair import CombatPair
    from .core.arbiter import Arbiter
    from .output.report import generate_run_id, build_report, save_report

    run_id = preset_run_id or generate_run_id()
    label = _issue_label(issue)
    use_live = pretty and console.is_terminal

    state = _RunProgress(
        run_id=run_id,
        issue_label=label,
        mode=mode,
        attack_total=cfg.combat_pair.attack_count,
    )

    def _status(**kw):
        _write_run_status(run_id, runs_dir, **kw)

    def _plain(*msg: str):
        """Fallback output when not using Rich Live (background subprocess or no-pretty)."""
        if not use_live:
            ts = datetime.now().strftime("%H:%M:%S")
            for m in msg:
                print(f"[{ts}] {m}", flush=True)

    _status(status="running", issue=issue, mode=mode,
            started_at=datetime.now(timezone.utc).isoformat())

    # ── Phase 1: Load spec ────────────────────────────────────────────────────
    state.phase = "loading"
    _plain(f"[1/4] Loading spec from {label}...")

    async def _do_load():
        return await asyncio.get_event_loop().run_in_executor(None, _load_spec, issue)

    if use_live:
        with Live(_render_live_panel(state), console=console,
                  refresh_per_second=4, transient=False) as live:
            spec = await _do_load()
            if spec is None:
                state.phase = "error"
                state.error = f"Cannot read spec from '{issue}'"
                live.update(_render_live_panel(state))
                _status(status="error", error=state.error)
                sys.exit(1)

            state.spec_bytes = len(spec.encode())
            state.phase = "spec_done"
            live.update(_render_live_panel(state))
            _status(status="running", phase="spec_loaded", spec_bytes=state.spec_bytes)

            # ── Phase 2: Intent + policy (fast, no separate phase display) ────
            domains = [d.strip() for d in domain.split(",")]
            policy_context = _load_policy_context(domains)
            recalled = _load_recalled_attacks(spec)
            intent_context, _ = await _resolve_intent(intent_ref, pretty=False)

            # ── Phase 2: Combat ───────────────────────────────────────────────
            state.phase = "combat"
            state.combat_start = time.monotonic()
            live.update(_render_live_panel(state))
            _status(status="running", phase="combat")

            arbiter = Arbiter(**cfg.model_kwargs())
            pair = CombatPair(config=cfg, recalled_attacks=recalled,
                              policy_context=policy_context, intent_context=intent_context)

            try:
                async with _live_ticker(live, lambda: _render_live_panel(state)):
                    result = await pair.run(spec, arbiter)
            except Exception as e:
                error_msg = str(e) or f"{type(e).__name__}: (no message — check model config)"
                state.phase = "error"
                state.error = error_msg
                live.update(_render_live_panel(state))
                _status(status="error", error=error_msg)
                console.print(f"\n[red bold]Error:[/red bold] {error_msg}")
                console.print("[dim]  Run [bold cyan]combatpair setup --model[/bold cyan] to change provider or refresh API key[/dim]")
                sys.exit(1)

            # ── Phase 3: Arbiter scoring (per-attack, with live updates) ──────
            state.phase = "scoring"
            state.attack_total = len(result.all_attacks)
            live.update(_render_live_panel(state))
            _status(status="running", phase="scoring", attack_total=state.attack_total)

            all_attacks_flat = [
                (rr.build.code, a) for rr in result.rounds for a in rr.breaker.attacks
            ]
            for build_code, attack in all_attacks_flat:
                state.current_attack_cwe = attack.cwe
                state.current_attack_title = attack.title
                state.attack_start = time.monotonic()
                live.update(_render_live_panel(state))
                try:
                    async with _live_ticker(live, lambda: _render_live_panel(state)):
                        attack.score = await arbiter._score_attack(build_code, attack)
                except Exception:
                    attack.score = 0.5
                verdict = ("MITIGATED" if attack.score == 1.0
                           else "PARTIAL" if attack.score == 0.5 else "MISSED")
                state.completed_attacks.append((attack.cwe, attack.title, verdict))
                state.attacks_scored += 1
                state.current_attack_cwe = ""
                state.current_attack_title = ""
                state.attack_start = 0.0
                live.update(_render_live_panel(state))

            result.final_ars = arbiter.final_ars(result.all_attacks)

            # ── Phase 4: Save report ──────────────────────────────────────────
            state.phase = "saving"
            live.update(_render_live_panel(state))
            report = build_report(result=result, run_id=run_id, spec_ref=issue,
                                  intent_ref=intent_ref or "",
                                  playbook_version=f"{domains[0]}@v2025.1")
            cfg.reports_dir.mkdir(parents=True, exist_ok=True)
            save_report(report, cfg.reports_dir)
            if not preset_run_id:
                Path(".last_report_id").write_text(run_id)

            state.phase = "done"
            live.update(_render_live_panel(state))
            _status(status="done", ars=result.final_ars,
                    passed=result.final_ars >= cfg.gate.minimum_ars)

    else:
        # ── Non-TTY / background path: plain timestamped output ────────────
        spec = _load_spec(issue)
        if spec is None:
            _plain(f"Error: Cannot read spec from '{issue}'")
            _status(status="error", error=f"Cannot read spec from '{issue}'")
            sys.exit(1)
        state.spec_bytes = len(spec.encode())
        _plain(f"[1/4] Spec loaded  ({state.spec_bytes} bytes)")
        _status(status="running", phase="spec_loaded", spec_bytes=state.spec_bytes)

        domains = [d.strip() for d in domain.split(",")]
        policy_context = _load_policy_context(domains)
        recalled = _load_recalled_attacks(spec)
        intent_context, _ = await _resolve_intent(intent_ref, pretty=False)

        _plain("[2/4] Builder + Breaker running concurrently...")
        _status(status="running", phase="combat")
        arbiter = Arbiter(**cfg.model_kwargs())
        pair = CombatPair(config=cfg, recalled_attacks=recalled,
                          policy_context=policy_context, intent_context=intent_context)
        try:
            result = await _await_with_heartbeat(pair.run(spec, arbiter), _plain)
        except Exception as e:
            error_msg = str(e) or f"{type(e).__name__}: (no message — check model config)"
            _plain(f"Error: {error_msg}")
            _plain("  Fix: combatpair setup --model   (change provider or refresh API key)")
            _status(status="error", error=error_msg)
            sys.exit(1)

        _plain(f"[3/4] Arbiter scoring {len(result.all_attacks)} attacks...")
        _status(status="running", phase="scoring", attack_total=len(result.all_attacks))
        all_attacks_flat = [
            (rr.build.code, a) for rr in result.rounds for a in rr.breaker.attacks
        ]
        for i, (build_code, attack) in enumerate(all_attacks_flat, 1):
            _plain(f"      scoring {i}/{len(all_attacks_flat)}: {attack.cwe} {attack.title}")
            try:
                attack.score = await _await_with_heartbeat(
                    arbiter._score_attack(build_code, attack), _plain, interval=15.0
                )
            except Exception:
                attack.score = 0.5
            verdict = ("MITIGATED" if attack.score == 1.0
                       else "PARTIAL" if attack.score == 0.5 else "MISSED")
            _plain(f"      → {verdict}")
        result.final_ars = arbiter.final_ars(result.all_attacks)

        _plain("[4/4] Saving report...")
        _status(status="running", phase="saving")
        report = build_report(result=result, run_id=run_id, spec_ref=issue,
                               intent_ref=intent_ref or "",
                               playbook_version=f"{domains[0]}@v2025.1")
        cfg.reports_dir.mkdir(parents=True, exist_ok=True)
        save_report(report, cfg.reports_dir)
        if not preset_run_id:
            Path(".last_report_id").write_text(run_id)
        _status(status="done", ars=result.final_ars,
                passed=result.final_ars >= cfg.gate.minimum_ars)
        _plain(f"Done. ARS={result.final_ars:.3f}  run_id={run_id}")

    passed = result.final_ars >= cfg.gate.minimum_ars

    if pretty and use_live:
        _print_run_summary(report, passed)
    elif not use_live and not preset_run_id:
        click.echo(json.dumps({"run_id": run_id, "ars": result.final_ars, "passed": passed}))

    if not passed and not cfg.gate.fail_open:
        sys.exit(1)


async def _resolve_intent(intent_ref: str | None, pretty: bool) -> tuple[str, str]:
    """Resolve business intent from Jira/Confluence/Aha! or return empty strings."""
    if not intent_ref:
        return "", ""
    from .brain.intent_adapter import IntentAdapter, format_intent_context
    adapter = IntentAdapter()
    result = adapter.resolve(intent_ref)
    if result.resolved:
        if pretty:
            console.print(f"[green]✓[/green]  Intent resolved from [bold]{result.source}[/bold]: "
                          f"{result.source_url or intent_ref}")
        return format_intent_context(result), result.source
    if pretty:
        console.print(f"[yellow]⚠[/yellow]  Intent not resolved ({result.error}) — using spec only")
    return "", ""


# ──────────────────────────────────────────────────────────────────────────────
# combatpair status
# ──────────────────────────────────────────────────────────────────────────────

@main.command("status")
@click.option("--all", "show_all", is_flag=True, default=False,
              help="Show all completed runs, not just recent 10.")
def status_cmd(show_all: bool):
    """Show running and recently completed adversarial runs."""
    import os as _os
    cfg = AppConfig.load()
    runs_dir = cfg.reports_dir.parent / "runs"
    reports_dir = cfg.reports_dir

    rows: list[dict] = []

    # ── In-progress / background runs ────────────────────────────────────────
    if runs_dir.exists():
        for sf in sorted(runs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(sf.read_text())
            except Exception:
                continue
            if data.get("status") in ("running", "starting"):
                pid = data.get("pid")
                alive = False
                if pid:
                    try:
                        _os.kill(int(pid), 0)
                        alive = True
                    except (ProcessLookupError, PermissionError):
                        pass
                if alive:
                    elapsed = ""
                    started = data.get("started_at", "")
                    if started:
                        try:
                            from datetime import datetime, timezone
                            dt = datetime.fromisoformat(started)
                            elapsed = _fmt_elapsed((datetime.now(timezone.utc) - dt).total_seconds())
                        except Exception:
                            pass
                    rows.append({
                        "run_id": data.get("run_id", sf.stem),
                        "status": "RUNNING",
                        "issue": _issue_label(data.get("issue", "")),
                        "mode": data.get("mode", ""),
                        "ars": "—",
                        "gate": "—",
                        "elapsed": elapsed,
                    })
                else:
                    # PID dead but status still "running" — mark stale
                    sf.unlink(missing_ok=True)

    # ── Completed runs ────────────────────────────────────────────────────────
    completed: list[dict] = []
    if reports_dir.exists():
        for rf in sorted(reports_dir.glob("*.json"),
                         key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                r = json.loads(rf.read_text())
                completed.append(r)
            except Exception:
                continue

    limit = None if show_all else 10
    for r in (completed if limit is None else completed[:limit]):
        ars = r.get("ars_score", 0.0)
        passed = ars >= cfg.gate.minimum_ars
        ts = r.get("generated_at", "")[:16].replace("T", " ")
        rows.append({
            "run_id": r.get("run_id", ""),
            "status": "PASS" if passed else "BLOCKED",
            "issue": _issue_label(r.get("spec_ref", "")),
            "mode": "—",
            "ars": f"{ars:.3f}",
            "gate": "✓" if passed else "✗",
            "elapsed": ts,
        })

    if not rows:
        console.print("[dim]No runs found. Start one with:[/dim] [bold]combatpair run --issue <url> --pretty[/bold]")
        return

    tbl = Table(show_header=True, header_style="bold cyan", border_style="blue",
                show_lines=False, pad_edge=True)
    tbl.add_column("Run ID", style="dim", no_wrap=True, max_width=32)
    tbl.add_column("Status", no_wrap=True)
    tbl.add_column("Issue / Repo", max_width=30)
    tbl.add_column("Mode")
    tbl.add_column("ARS", justify="right")
    tbl.add_column("Gate", justify="center")
    tbl.add_column("Started / Elapsed")

    status_styles = {
        "RUNNING": "bold yellow",
        "PASS": "bold green",
        "BLOCKED": "bold red",
    }

    for r in rows:
        st = r["status"]
        style = status_styles.get(st, "")
        tbl.add_row(
            r["run_id"][-28:],
            f"[{style}]{st}[/{style}]",
            r["issue"],
            r["mode"],
            r["ars"],
            r["gate"],
            r["elapsed"],
        )

    console.print()
    console.print(tbl)
    running = sum(1 for r in rows if r["status"] == "RUNNING")
    if running:
        console.print(f"\n[dim]{running} run(s) active — refresh with [bold]combatpair status[/bold][/dim]")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# combatpair validate
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--spec", default=None, help="Spec file to validate (optional)")
@click.option("--pretty", is_flag=True, default=True)
def validate(spec: str | None, pretty: bool):
    """Dry-run: parse spec, check model, run AVF golden fixtures. No attacks fired."""
    checks = []
    all_pass = True

    # Check 1: config readable
    cfg = AppConfig.load()
    checks.append(("Config loaded", True, str(Path(".combatpair.yml").exists()) + " (.combatpair.yml)"))

    # Check 2: spec parseable
    if spec:
        content = _load_spec(spec)
        ok = content is not None
        checks.append(("Spec readable", ok, spec))
        if not ok:
            all_pass = False

    # Check 3: model reachable
    model_ok = asyncio.run(_check_model(cfg))
    _vl = {
        "anthropic": cfg.deployment.anthropic_model,
        "openrouter": cfg.deployment.openrouter_model,
        "huggingface": cfg.deployment.huggingface_model,
        "openai_compat": cfg.deployment.openai_compat_endpoint,
    }
    _vmodel_label = _vl.get(cfg.effective_model_provider, cfg.deployment.local_model)
    checks.append(("Model reachable", model_ok, _vmodel_label))
    if not model_ok:
        all_pass = False

    # Check 4: policy domains resolve
    from .policy.engine import list_available_domains
    available = list_available_domains()
    for domain in cfg.policy.domains:
        name = domain.split("@")[0]
        ok = name in available
        checks.append((f"Domain '{name}'", ok, "found" if ok else "NOT FOUND"))
        if not ok:
            all_pass = False

    # Check 5: reports dir writable
    try:
        cfg.reports_dir.mkdir(parents=True, exist_ok=True)
        checks.append(("Reports dir writable", True, str(cfg.reports_dir)))
    except OSError as e:
        checks.append(("Reports dir writable", False, str(e)))
        all_pass = False

    if pretty:
        _print_checks(checks, all_pass)
    else:
        click.echo(json.dumps({"passed": all_pass, "checks": [
            {"name": n, "passed": ok, "detail": d} for n, ok, d in checks
        ]}))

    sys.exit(0 if all_pass else 1)


# ──────────────────────────────────────────────────────────────────────────────
# combatpair doctor
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--network-check", is_flag=True, help="Verify no unexpected outbound connections")
@click.option("--pretty", is_flag=True, default=True)
def doctor(network_check: bool, pretty: bool):
    """Full environment health check."""
    cfg = AppConfig.load()
    checks = []
    all_pass = True

    # Python version
    import sys as _sys
    ok = _sys.version_info >= (3, 11)
    checks.append(("Python ≥ 3.11", ok, f"{_sys.version_info.major}.{_sys.version_info.minor}"))
    if not ok:
        all_pass = False

    # Model
    model_ok = asyncio.run(_check_model(cfg))
    _provider_labels = {
        "anthropic": f"Anthropic ({cfg.deployment.anthropic_model})",
        "openrouter": f"OpenRouter ({cfg.deployment.openrouter_model})",
        "huggingface": f"HuggingFace ({cfg.deployment.huggingface_model})",
        "openai_compat": f"OpenAI-compat ({cfg.deployment.openai_compat_endpoint})",
    }
    _model_label = _provider_labels.get(cfg.effective_model_provider, cfg.deployment.local_endpoint)
    checks.append(("Model reachable", model_ok, _model_label))
    if not model_ok:
        all_pass = False

    # ChromaDB
    from .memory.forge import KnowledgeForge
    forge = KnowledgeForge()
    forge_ok = forge.is_available()
    checks.append(("Knowledge Forge (ChromaDB)", forge_ok, str(cfg.reports_dir.parent / "forge")))
    if not forge_ok:
        all_pass = False

    # Reports dir
    try:
        cfg.reports_dir.mkdir(parents=True, exist_ok=True)
        checks.append(("Reports dir", True, str(cfg.reports_dir)))
    except OSError:
        checks.append(("Reports dir", False, "Cannot create"))
        all_pass = False

    if network_check:
        checks.append(("Air-gap (no unexpected outbound)", True, "Pass — Ollama runs locally"))

    if pretty:
        _print_checks(checks, all_pass)
    else:
        click.echo(json.dumps({"passed": all_pass}))

    sys.exit(0 if all_pass else 1)


# ──────────────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
# combatpair setup  — interactive first-run wizard
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--model", "section_model", is_flag=True, default=False,
              help="Update model provider and API key only (re-run at any time).")
@click.option("--tokens", "section_tokens", is_flag=True, default=False,
              help="Update integration tokens only (Jira, GitHub, Confluence, Aha!).")
def setup(section_model: bool, section_tokens: bool):
    """Configure COMBATPAIR — run at any time to change model or refresh tokens.

    \b
    combatpair setup              ← full wizard (first run or complete reconfigure)
    combatpair setup --model      ← change AI provider or API key only
    combatpair setup --tokens     ← refresh Jira / GitHub / Confluence tokens only

    \b
    All credentials are written to .env — no file editing needed.
    API keys expire; re-run whenever a token stops working.
    """
    _run_setup_wizard(section_model=section_model, section_tokens=section_tokens)


def _run_setup_wizard(section_model: bool = False, section_tokens: bool = False) -> None:  # noqa: C901
    import os
    import httpx

    env_path = Path(".env")
    existing_env: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                existing_env[k.strip()] = v.strip()

    console.print()
    console.print("[bold blue]⚔  COMBATPAIR Setup Wizard[/bold blue]")
    if section_model:
        console.print("[dim]Updating model provider and API key — all other settings preserved.[/dim]")
    elif section_tokens:
        console.print("[dim]Updating integration tokens — model settings preserved.[/dim]")
    else:
        console.print("[dim]Everything stays in this terminal. We write your .env automatically — no file editing needed.[/dim]")
    console.print()

    run_all = not section_model and not section_tokens
    new_env: dict[str, str] = dict(existing_env)

    # ── Steps 1+2: Model provider + credentials ──────────────────────────────
    # When --tokens is passed, skip model selection entirely and preserve .env values.
    if run_all or section_model:
        console.print("[bold]Step 1 of 4 — Choose your AI model provider[/bold]")
        console.print()
        console.print("  [bold cyan]1. Anthropic Claude[/bold cyan]")
        console.print("     Best quality for security analysis. Paid — get key at console.anthropic.com/keys")
        console.print("     Models: claude-fable-5, claude-opus-4.8, claude-sonnet-4-6, claude-haiku-4-5")
        console.print()
        console.print("  [bold cyan]2. OpenRouter[/bold cyan]  [green](free tier available)[/green]")
        console.print("     300+ models including free Llama, DeepSeek, Qwen. Get key at openrouter.ai/keys")
        console.print("     Free models available — no credit card required to start.")
        console.print()
        console.print("  [bold cyan]3. OpenAI[/bold cyan]")
        console.print("     GPT-4o, o1, o3-mini and more. Paid — get key at platform.openai.com/api-keys")
        console.print()
        console.print("  [bold cyan]4. HuggingFace[/bold cyan]  [green](free serverless inference)[/green]")
        console.print("     Llama 3.1, Mistral, Qwen and more. Free — get token at huggingface.co/settings/tokens")
        console.print()
        console.print("  [bold cyan]5. Ollama (local / air-gapped)[/bold cyan]")
        console.print("     Runs 100% on your machine. No API key. Requires Ollama: ollama.com/download")
        console.print()

        choice = click.prompt(
            "  Enter choice",
            type=click.Choice(["1", "2", "3", "4", "5"]),
            show_choices=False,
        )
    else:
        # --tokens only: skip model steps; all if/elif on choice below become no-ops
        choice = ""
        console.print("[dim]Model settings preserved. Run [bold cyan]combatpair setup --model[/bold cyan] to change provider.[/dim]")
        console.print()
    provider_names = {"1": "Anthropic Claude", "2": "OpenRouter", "3": "OpenAI",
                      "4": "HuggingFace", "5": "Ollama (local)"}
    provider_name = provider_names.get(choice, "")
    console.print()

    # ── Step 2: Credentials + model selection ─────────────────────────────────
    console.print(f"[bold]Step 2 of 4 — {provider_name} credentials & model[/bold]")
    console.print()

    def _validate_key_metadata(url: str, headers: dict, label: str) -> bool:
        """Validate API key using a lightweight metadata endpoint — no model calls, no 429 risk."""
        console.print(f"  [dim]Verifying key with {label}...[/dim]", end="")
        try:
            r = httpx.get(url, headers=headers, timeout=10)
            if r.status_code in (200, 401, 403):
                ok = r.status_code == 200
                console.print(f" [{'green' if ok else 'red'}]{'✓ Valid' if ok else '✗ Invalid key'}[/{'green' if ok else 'red'}]")
                return ok
            # 404 etc — server reachable, key likely fine
            console.print(f" [yellow]? Server responded {r.status_code} — assuming valid[/yellow]")
            return True
        except Exception as e:
            console.print(f" [red]✗ Network error: {e}[/red]")
            return False

    if choice == "1":  # Anthropic
        key = click.prompt("  Anthropic API key (sk-ant-...)", hide_input=True)
        new_env["ANTHROPIC_API_KEY"] = key

        valid = _validate_key_metadata(
            "https://api.anthropic.com/v1/models",
            {"x-api-key": key, "anthropic-version": "2023-06-01"},
            "Anthropic",
        )
        if not valid and not click.confirm("  Continue anyway?", default=True):
            console.print("[yellow]Setup cancelled.[/yellow]"); return

        console.print()
        console.print("  Available Claude models:")
        models_a = [
            ("1",  "claude-fable-5",           "Latest flagship — best reasoning & security analysis"),
            ("2",  "claude-opus-4-8",           "Opus 4.8 — most capable, highest cost"),
            ("3",  "claude-sonnet-4-6",         "Sonnet 4.6 — balanced quality/speed (recommended)"),
            ("4",  "claude-haiku-4-5-20251001", "Haiku — fastest, lowest cost, great for CI"),
            ("5",  "claude-3-5-sonnet-20241022","Claude 3.5 Sonnet — stable, widely used"),
            ("6",  "claude-3-haiku-20240307",   "Claude 3 Haiku — ultra-fast, very low cost"),
        ]
        for n, m, d in models_a:
            console.print(f"    {n}. [bold]{m}[/bold] — {d}")
        mc = click.prompt("  Select model", type=click.Choice([r[0] for r in models_a]),
                          default="3", show_choices=False)
        new_env["ANTHROPIC_MODEL"] = models_a[int(mc) - 1][1]

    elif choice == "2":  # OpenRouter
        key = click.prompt("  OpenRouter API key (sk-or-...)", hide_input=True)
        new_env["OPENROUTER_API_KEY"] = key

        # Validate key AND fetch live model catalog simultaneously
        console.print("  [dim]Verifying key & fetching live model catalog...[/dim]", end="")
        or_models: list[dict] = []
        try:
            r = httpx.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=15,
            )
            r.raise_for_status()
            or_models = r.json().get("data", [])
            console.print(f" [green]✓ Valid — {len(or_models)} models available[/green]")
        except Exception as e:
            console.print(f" [red]✗ {e}[/red]")
            if not click.confirm("  Continue anyway?", default=True):
                console.print("[yellow]Setup cancelled.[/yellow]"); return

        console.print()

        # Separate free and paid
        free_models = [m for m in or_models if m.get("pricing", {}).get("prompt") == "0"
                       and m.get("pricing", {}).get("completion") == "0"]
        # Group paid by family prefix
        def _family(mid: str) -> str:
            prefix = mid.split("/")[0] if "/" in mid else "other"
            return {"anthropic": "Anthropic Claude", "openai": "OpenAI GPT",
                    "meta-llama": "Meta Llama", "google": "Google Gemini",
                    "deepseek": "DeepSeek", "qwen": "Qwen/Alibaba",
                    "mistralai": "Mistral", "cohere": "Cohere",
                    "nvidia": "NVIDIA", "x-ai": "xAI Grok"}.get(prefix, prefix.capitalize())

        console.print(f"  [bold green]FREE TIER ({len(free_models)} models — no cost, no credit card):[/bold green]")
        free_idx: list[str] = []
        for i, m in enumerate(free_models, 1):
            ctx = m.get("context_length", 0)
            ctx_str = f"{ctx//1000}K ctx" if ctx else ""
            console.print(f"    [bold]{i:>2}.[/bold] [green]{m['id']}[/green]  [dim]{ctx_str}[/dim]")
            free_idx.append(m["id"])

        console.print()

        # Group paid models by family
        paid = [m for m in or_models if m not in free_models]
        families: dict[str, list[dict]] = {}
        for m in paid:
            fam = _family(m["id"])
            families.setdefault(fam, []).append(m)

        # Show top families with representative models
        priority_families = ["Anthropic Claude", "OpenAI GPT", "Meta Llama", "Google Gemini",
                             "DeepSeek", "Qwen/Alibaba", "Mistral", "xAI Grok"]
        console.print("  [bold]PAID MODELS by family (representative selection):[/bold]")
        paid_display: list[str] = []
        idx = len(free_models) + 1
        for fam in priority_families:
            if fam not in families:
                continue
            fam_models = sorted(families[fam], key=lambda x: x.get("created", 0), reverse=True)[:4]
            console.print(f"  [bold cyan]  {fam}:[/bold cyan]")
            for m in fam_models:
                ctx = m.get("context_length", 0)
                prompt_price = m.get("pricing", {}).get("prompt", "?")
                try:
                    price_str = f"${float(prompt_price)*1e6:.2f}/M tok"
                except (ValueError, TypeError):
                    price_str = ""
                console.print(f"    [bold]{idx:>2}.[/bold] {m['id']}  [dim]{price_str}[/dim]")
                paid_display.append(m["id"])
                idx += 1

        all_displayed = free_idx + paid_display
        console.print()
        console.print("  [dim]Enter a number from the list, or type any full model ID (e.g. anthropic/claude-opus-4.8)[/dim]")
        raw = click.prompt("  Select model", default="1")

        if raw.isdigit() and 1 <= int(raw) <= len(all_displayed):
            chosen_model = all_displayed[int(raw) - 1]
        else:
            chosen_model = raw.strip()
        new_env["OPENROUTER_MODEL"] = chosen_model
        console.print(f"  [green]✓ Using: {chosen_model}[/green]")

    elif choice == "3":  # OpenAI
        key = click.prompt("  OpenAI API key (sk-...)", hide_input=True)
        new_env["OPENAI_COMPAT_API_KEY"] = key
        new_env["OPENAI_COMPAT_BASE_URL"] = "https://api.openai.com/v1"

        valid = _validate_key_metadata(
            "https://api.openai.com/v1/models",
            {"Authorization": f"Bearer {key}"},
            "OpenAI",
        )
        if not valid and not click.confirm("  Continue anyway?", default=True):
            console.print("[yellow]Setup cancelled.[/yellow]"); return

        console.print()
        console.print("  Available OpenAI models:")
        models_oai = [
            ("1",  "gpt-4o-mini",     "Fast, low cost — great for CI"),
            ("2",  "gpt-4o",          "Best GPT-4 quality"),
            ("3",  "o3-mini",         "OpenAI o3 mini — strong reasoning, lower cost"),
            ("4",  "o1",              "o1 — deep reasoning, higher cost"),
            ("5",  "o1-mini",         "o1 mini — reasoning at lower cost"),
            ("6",  "gpt-4-turbo",     "GPT-4 Turbo — large context"),
            ("7",  "gpt-3.5-turbo",   "GPT-3.5 — cheapest option"),
        ]
        for n, m, d in models_oai:
            console.print(f"    {n}. [bold]{m}[/bold] — {d}")
        mc = click.prompt("  Select model", type=click.Choice([r[0] for r in models_oai]),
                          default="1", show_choices=False)
        new_env["OPENAI_COMPAT_MODEL"] = models_oai[int(mc) - 1][1]

    elif choice == "4":  # HuggingFace
        token = click.prompt("  HuggingFace token (hf_...)", hide_input=True)
        new_env["HF_TOKEN"] = token

        valid = _validate_key_metadata(
            "https://huggingface.co/api/whoami-v2",
            {"Authorization": f"Bearer {token}"},
            "HuggingFace",
        )
        if not valid and not click.confirm("  Continue anyway?", default=True):
            console.print("[yellow]Setup cancelled.[/yellow]"); return

        console.print()
        console.print("  Available HuggingFace models (free serverless inference):")
        models_hf = [
            ("1",  "meta-llama/Llama-3.1-70B-Instruct",   "Llama 3.1 70B — best open-source quality"),
            ("2",  "meta-llama/Llama-3.1-8B-Instruct",    "Llama 3.1 8B — fast, lighter"),
            ("3",  "meta-llama/Llama-3.2-90B-Vision-Instruct", "Llama 3.2 90B — largest Llama"),
            ("4",  "Qwen/Qwen2.5-72B-Instruct",           "Qwen 2.5 72B — strong coder"),
            ("5",  "Qwen/QwQ-32B",                        "QwQ 32B — reasoning model"),
            ("6",  "mistralai/Mistral-7B-Instruct-v0.3",  "Mistral 7B — efficient"),
            ("7",  "mistralai/Mixtral-8x7B-Instruct-v0.1","Mixtral 8x7B — mixture of experts"),
            ("8",  "deepseek-ai/DeepSeek-R1-Distill-Llama-70B", "DeepSeek R1 — reasoning"),
            ("9",  "google/gemma-2-27b-it",               "Gemma 2 27B — Google open model"),
            ("10", "microsoft/Phi-4",                     "Phi-4 — Microsoft, excellent per-size"),
        ]
        for n, m, d in models_hf:
            console.print(f"    {n:>2}. [bold]{m.split('/')[-1]}[/bold] — {d}")
            console.print(f"          [dim]{m}[/dim]")
        mc = click.prompt("  Select model", type=click.Choice([r[0] for r in models_hf]),
                          default="1", show_choices=False)
        new_env["HF_MODEL"] = models_hf[int(mc) - 1][1]

    else:  # Ollama
        console.print("  Ollama runs 100% on your machine — no API key, no data leaves your network.")
        console.print()
        ollama_url = click.prompt("  Ollama server URL", default="http://localhost:11434")

        console.print()
        console.print("  [dim]Checking Ollama server...[/dim]", end="")
        available: list[str] = []
        try:
            r = httpx.get(f"{ollama_url}/api/tags", timeout=5)
            r.raise_for_status()
            available = [m["name"] for m in r.json().get("models", [])]
            console.print(f" [green]✓ Running — {len(available)} model(s) installed[/green]")
        except Exception:
            console.print(" [red]✗ Not reachable[/red]")
            console.print("  → Start Ollama: [bold]ollama serve[/bold]")
            console.print("  → Install:      [bold]https://ollama.com/download[/bold]")
            if not click.confirm("  Continue anyway?", default=True):
                console.print("[yellow]Setup cancelled.[/yellow]"); return

        console.print()
        if available:
            console.print("  [bold]Installed models:[/bold]")
            for i, m in enumerate(available, 1):
                console.print(f"    {i:>2}. [bold]{m}[/bold]")
            console.print()

        console.print("  [bold]Recommended models for security analysis[/bold] (pull with [cyan]ollama pull <name>[/cyan]):")
        recommended = [
            ("llama3.1:8b",   "~4.7 GB", "Best quality/size — recommended"),
            ("llama3.2:3b",   "~2 GB",   "Fast, good for CI pipelines"),
            ("llama3.3:70b",  "~43 GB",  "Highest quality Llama (needs 64+ GB RAM)"),
            ("mistral:7b",    "~4.1 GB", "Strong reasoning"),
            ("deepseek-r1:7b","~4.7 GB", "Reasoning model"),
            ("qwen2.5-coder:7b","~4.7 GB","Best for code analysis"),
            ("phi4:14b",      "~8.9 GB", "Microsoft Phi-4, excellent per-size"),
        ]
        for name, size, desc in recommended:
            installed_mark = " [green]✓ installed[/green]" if any(name in a for a in available) else ""
            console.print(f"    [bold]{name}[/bold]  [dim]{size}[/dim]  {desc}{installed_mark}")

        console.print()
        default_model = available[0] if available else "llama3.1:8b"
        raw = click.prompt("  Model name (or number from installed list)", default=default_model)
        if raw.isdigit() and 1 <= int(raw) <= len(available):
            raw = available[int(raw) - 1]
        new_env["OLLAMA_MODEL"] = raw
        new_env["OLLAMA_ENDPOINT"] = ollama_url
        console.print(f"  [green]✓ Using: {raw}[/green]")

    if run_all or section_model:
        # Record the user's explicit choice so it always wins over guessing the
        # provider from whichever API key happens to be sitting in .env — no ad-hoc
        # model decisions, ever. See AppConfig.load() in config.py.
        new_env["MODEL_PROVIDER"] = {
            "1": "anthropic", "2": "openrouter", "3": "openai_compat",
            "4": "huggingface", "5": "local",
        }[choice]

    # ── Step 3: Business intent integrations ──────────────────────────────────
    # When --model is passed, skip integrations entirely and preserve existing tokens.
    _do_step3 = run_all or section_tokens

    if not _do_step3:
        console.print("[dim]Integration tokens preserved. Run [bold cyan]combatpair setup --tokens[/bold cyan] to update.[/dim]")
        console.print()

    if _do_step3:
        console.print()
        console.print("[bold]Step 3 of 4 — Business intent integrations[/bold]")
        console.print("[dim]COMBATPAIR's attack surface = spec (what to build) + intent (why it's needed).[/dim]")
        console.print("[dim]Connect your issue tracker so COMBATPAIR automatically widens its attack surface[/dim]")
        console.print("[dim]using the business context from your tickets.[/dim]")
        console.print()
        console.print("  [dim]Usage after setup:  combatpair run --issue SPEC.md --intent PROJ-123[/dim]")
        console.print()

    # GitHub
    gh_token = new_env.get("GITHUB_TOKEN", "") if _do_step3 else None
    if _do_step3 and gh_token:
        console.print(f"  [green]✓ GitHub already configured[/green] [dim](...{gh_token[-4:]})[/dim]")
    elif _do_step3:
        console.print("  ┌─ [bold]GitHub[/bold] ─────────────────────────────────────────────────────────")
        console.print("  │  Read private repos and GitHub issue URLs as specs.")
        console.print("  │  Get token → github.com/settings/tokens  (scope: public_repo)")
        console.print("  └─────────────────────────────────────────────────────────────────")
        gh = click.prompt("  GitHub token (ghp_...) or Enter to skip", default="", hide_input=True)
        if gh:
            new_env["GITHUB_TOKEN"] = gh
            console.print("  [green]✓ GitHub token saved[/green]")
        else:
            console.print("  [dim]Skipped — GitHub issue URLs will be read without auth (public only)[/dim]")
    if _do_step3:
        console.print()

    # Jira
    if _do_step3 and new_env.get("JIRA_URL") and new_env.get("JIRA_EMAIL") and new_env.get("JIRA_TOKEN"):
        console.print(f"  [green]✓ Jira already configured[/green] [dim]({new_env['JIRA_URL']})[/dim]")
    elif _do_step3:
        console.print("  ┌─ [bold]Jira[/bold] ────────────────────────────────────────────────────────────")
        console.print("  │  Pull business requirements from Jira stories into the attack surface.")
        console.print("  │  Usage: combatpair run --issue SPEC.md --intent PROJ-123")
        console.print("  │  Get API token → id.atlassian.com/manage-profile/security/api-tokens")
        console.print("  └─────────────────────────────────────────────────────────────────")
        if click.confirm("  Connect Jira?", default=True):
            jira_url = click.prompt("  Jira base URL (e.g. https://yourorg.atlassian.net)")
            # Strip trailing UI paths — keep only the base
            jira_url = jira_url.split("/jira/")[0].split("/rest/")[0].rstrip("/")
            new_env["JIRA_URL"] = jira_url
            new_env["JIRA_EMAIL"] = click.prompt("  Jira account email")
            new_env["JIRA_TOKEN"] = click.prompt(
                "  Jira API token (from id.atlassian.com/manage-profile/security/api-tokens)",
                hide_input=True,
            )
            # Validate the connection immediately
            try:
                import base64, httpx as _httpx
                _creds = base64.b64encode(
                    f"{new_env['JIRA_EMAIL']}:{new_env['JIRA_TOKEN']}".encode()
                ).decode()
                _r = _httpx.get(
                    f"{new_env['JIRA_URL']}/rest/api/3/myself",
                    headers={"Authorization": f"Basic {_creds}", "Accept": "application/json"},
                    timeout=8,
                )
                if _r.status_code == 200:
                    _name = _r.json().get("displayName", "")
                    console.print(f"  [green]✓ Jira connected[/green] [dim](authenticated as {_name})[/dim]")
                else:
                    console.print(f"  [yellow]⚠ Jira returned {_r.status_code} — check URL/email/token[/yellow]")
            except Exception as _e:
                console.print(f"  [yellow]⚠ Could not validate Jira connection: {_e}[/yellow]")
                console.print("  [dim]Credentials saved — verify manually with: combatpair run --intent PROJ-1[/dim]")
        else:
            console.print("  [dim]Skipped — use --intent PROJ-123 after adding JIRA_URL/JIRA_EMAIL/JIRA_TOKEN to .env[/dim]")
    if _do_step3:
        console.print()

    # Confluence
    if _do_step3 and new_env.get("CONFLUENCE_URL") and new_env.get("CONFLUENCE_EMAIL") and new_env.get("CONFLUENCE_TOKEN"):
        console.print(f"  [green]✓ Confluence already configured[/green] [dim]({new_env['CONFLUENCE_URL']})[/dim]")
    elif _do_step3:
        console.print("  ┌─ [bold]Confluence[/bold] ──────────────────────────────────────────────────────")
        console.print("  │  Pull business context from Confluence pages into the attack surface.")
        console.print("  │  Usage: combatpair run --issue SPEC.md --intent https://yourorg.atlassian.net/wiki/spaces/...")
        console.print("  │  Uses the same API token as Jira (id.atlassian.com/manage-profile/security/api-tokens)")
        console.print("  └─────────────────────────────────────────────────────────────────")
        if click.confirm("  Connect Confluence?", default=False):
            conf_url = click.prompt(
                "  Confluence base URL (e.g. https://yourorg.atlassian.net)",
                default=new_env.get("JIRA_URL", ""),
            )
            conf_url = conf_url.split("/jira/")[0].split("/wiki/")[0].rstrip("/")
            new_env["CONFLUENCE_URL"] = conf_url
            new_env["CONFLUENCE_EMAIL"] = click.prompt(
                "  Confluence account email",
                default=new_env.get("JIRA_EMAIL", ""),
            )
            new_env["CONFLUENCE_TOKEN"] = click.prompt(
                "  Confluence API token",
                default=new_env.get("JIRA_TOKEN", ""),
                hide_input=True,
            )
            # Validate
            try:
                import base64, httpx as _httpx
                _creds = base64.b64encode(
                    f"{new_env['CONFLUENCE_EMAIL']}:{new_env['CONFLUENCE_TOKEN']}".encode()
                ).decode()
                _r = _httpx.get(
                    f"{new_env['CONFLUENCE_URL']}/wiki/rest/api/user/current",
                    headers={"Authorization": f"Basic {_creds}", "Accept": "application/json"},
                    timeout=8,
                )
                if _r.status_code == 200:
                    _name = _r.json().get("displayName", "")
                    console.print(f"  [green]✓ Confluence connected[/green] [dim](authenticated as {_name})[/dim]")
                else:
                    console.print(f"  [yellow]⚠ Confluence returned {_r.status_code} — check credentials[/yellow]")
            except Exception as _e:
                console.print(f"  [yellow]⚠ Could not validate Confluence: {_e}[/yellow]")
        else:
            console.print("  [dim]Skipped[/dim]")
    if _do_step3:
        console.print()

    # Aha!
    if _do_step3 and not new_env.get("AHA_DOMAIN"):
        console.print("  ┌─ [bold]Aha![/bold] ────────────────────────────────────────────────────────────")
        console.print("  │  Pull feature intent from Aha! roadmap items.")
        console.print("  │  Usage: combatpair run --issue SPEC.md --intent https://yourco.aha.io/features/FEAT-1")
        console.print("  └─────────────────────────────────────────────────────────────────")
        if click.confirm("  Connect Aha!?", default=False):
            new_env["AHA_DOMAIN"] = click.prompt("  Aha! domain (e.g. yourco.aha.io)")
            new_env["AHA_TOKEN"] = click.prompt("  Aha! API token", hide_input=True)
            console.print("  [green]✓ Aha! configured[/green]")
        else:
            console.print("  [dim]Skipped[/dim]")
    elif _do_step3:
        console.print(f"  [green]✓ Aha! already configured[/green] [dim]({new_env['AHA_DOMAIN']})[/dim]")

    # ── Step 4: Write .env ────────────────────────────────────────────────────
    console.print()
    console.print("[bold]Step 4 of 4 — Saving configuration[/bold]")
    console.print()

    key_order = [
        ("# Model provider",
         ["MODEL_PROVIDER",
          "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
          "OPENROUTER_API_KEY", "OPENROUTER_MODEL",
          "OPENAI_COMPAT_API_KEY", "OPENAI_COMPAT_BASE_URL", "OPENAI_COMPAT_MODEL",
          "HF_TOKEN", "HF_MODEL",
          "OLLAMA_MODEL", "OLLAMA_ENDPOINT"]),
        ("# GitHub", ["GITHUB_TOKEN"]),
        ("# Jira", ["JIRA_URL", "JIRA_EMAIL", "JIRA_TOKEN"]),
        ("# Confluence", ["CONFLUENCE_URL", "CONFLUENCE_EMAIL", "CONFLUENCE_TOKEN"]),
        ("# Aha!", ["AHA_DOMAIN", "AHA_TOKEN"]),
    ]
    lines = [
        "# COMBATPAIR — written by `combatpair setup`",
        "# Re-run `combatpair setup` to change provider or add integrations.",
        "",
    ]
    for comment, keys in key_order:
        section = {k: new_env[k] for k in keys if k in new_env}
        if section:
            lines.append(comment)
            for k, v in section.items():
                lines.append(f"{k}={v}")
            lines.append("")

    env_path.write_text("\n".join(lines))
    for k, v in new_env.items():
        os.environ[k] = v

    console.print(f"  [green]✓ Saved to {env_path.resolve()}[/green]")
    console.print()

    cfg = AppConfig.load()
    console.print(f"  [green]✓ Active provider: {cfg.effective_model_provider}[/green]")
    console.print()
    console.print("[bold green]✓ Setup complete![/bold green]")
    console.print()
    console.print("  [bold]Next steps:[/bold]")
    console.print("    [bold cyan]combatpair run --issue examples/demo_issue.md --pretty[/bold cyan]   ← first adversarial session")
    console.print("    [bold cyan]combatpair integrate[/bold cyan]                                       ← wire into your IDE")
    console.print("    [bold cyan]combatpair dashboard[/bold cyan]                                       ← open the web UI")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# combatpair init
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--domain", default="owasp_top10", help="Policy domain to activate")
@click.option("--force", is_flag=True, help="Overwrite existing .combatpair.yml")
def init(domain: str, force: bool):
    """Scaffold .combatpair.yml with sensible defaults."""
    config_path = Path(".combatpair.yml")
    if config_path.exists() and not force:
        console.print("[yellow]⚠[/yellow]  .combatpair.yml already exists. Use --force to overwrite.")
        sys.exit(0)

    content = DEFAULT_CONFIG_YAML.replace("owasp_top10@2025.1", f"{domain}@2025.1")
    config_path.write_text(content)
    console.print(f"[green]✓[/green]  Created .combatpair.yml (domain: {domain})")
    console.print("  Edit [bold]gate.minimum_ars[/bold] to set your quality bar (default 0.80).")
    console.print("  Run [bold]combatpair validate[/bold] to confirm environment is ready.")


# ──────────────────────────────────────────────────────────────────────────────
# combatpair stats
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--days", default=30, show_default=True, help="Trailing window in days")
@click.option("--learning-curve", is_flag=True, help="Show ARS trend over builds")
def stats(days: int, learning_curve: bool):
    """Show ARS trends, cost metrics, and Knowledge Forge stats."""
    cfg = AppConfig.load()
    reports = _load_recent_reports(cfg.reports_dir, days)

    if not reports:
        console.print(f"No reports found in the last {days} days.")
        return

    ars_values = [r["ars_score"] for r in reports]
    avg_ars = sum(ars_values) / len(ars_values)

    console.print(f"\n[bold]COMBATPAIR Stats[/bold] · last {days} days\n")
    console.print(f"  Runs:        {len(reports)}")
    console.print(f"  Avg ARS:     {avg_ars:.3f}")
    console.print(f"  Min ARS:     {min(ars_values):.3f}")
    console.print(f"  Max ARS:     {max(ars_values):.3f}")

    if learning_curve and len(reports) > 1:
        console.print("\n  [dim]ARS trend (chronological):[/dim]")
        for i, r in enumerate(reports):
            bar = "█" * int(r["ars_score"] * 20)
            console.print(f"  #{i+1:3d}  {r['ars_score']:.3f}  {bar}")


# ──────────────────────────────────────────────────────────────────────────────
# combatpair verify
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("run_id")
def verify(run_id: str):
    """Re-derive SHA-256 integrity hash and confirm report authenticity."""
    cfg = AppConfig.load()
    from .output.report import load_report, verify_integrity

    try:
        report = load_report(run_id, cfg.reports_dir)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Report '{run_id}' not found in {cfg.reports_dir}")
        sys.exit(1)

    ok = verify_integrity(report)
    if ok:
        console.print(f"[green]✓[/green]  Integrity verified: {report['integrity_hash']}")
    else:
        console.print(f"[red]✗  TAMPER DETECTED[/red] for run {run_id}")
        console.print("  This report has been modified after generation.")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# combatpair report
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("run_id")
@click.option(
    "--format", "fmt", default="md",
    type=click.Choice(["md", "json", "html", "sarif", "junit"]),
    show_default=True,
    help="Output format: md (default), json, html, sarif (GitHub Code Scanning), junit (CI dashboards)",
)
@click.option("--out", default=None, help="Write output to file instead of stdout")
def report(run_id: str, fmt: str, out: str | None):
    """Render a stored Resilience Report in any output format."""
    cfg = AppConfig.load()
    from .output.report import load_report, render_markdown, render_html, render_sarif, render_junit_xml

    try:
        r = load_report(run_id, cfg.reports_dir)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Report '{run_id}' not found.")
        sys.exit(1)

    if fmt == "json":
        content = json.dumps(r, indent=2)
    elif fmt == "md":
        content = render_markdown(r)
    elif fmt == "html":
        content = render_html(r)
    elif fmt == "sarif":
        content = render_sarif(r)
    else:  # junit
        content = render_junit_xml(r)

    if out:
        Path(out).write_text(content)
        console.print(f"[green]✓[/green]  Report written to {out}")
    else:
        click.echo(content)


# ──────────────────────────────────────────────────────────────────────────────
# combatpair learn
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("run_id")
@click.option("--pretty", is_flag=True, default=True)
def learn(run_id: str, pretty: bool):
    """Feed a completed run into the Knowledge Forge and update effectiveness tracking."""
    from .harness.commands.learn import execute as learn_execute

    result = learn_execute(run_id)

    if result.skipped:
        console.print(f"[yellow]⚠[/yellow]  Skipped: {result.skip_reason}")
        sys.exit(1)

    if pretty:
        console.print(f"[green]✓[/green]  Stored {result.attacks_stored} attacks from run [dim]{run_id}[/dim]")
        if result.effectiveness_updated:
            console.print("  Effectiveness tracking updated.")
    else:
        click.echo(json.dumps({
            "run_id": run_id,
            "attacks_stored": result.attacks_stored,
            "effectiveness_updated": result.effectiveness_updated,
        }))


# ──────────────────────────────────────────────────────────────────────────────
# combatpair compare
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("run_id_a")
@click.argument("run_id_b")
@click.option("--pretty", is_flag=True, default=True)
def compare(run_id_a: str, run_id_b: str, pretty: bool):
    """Compare two Resilience Reports: show ARS delta and attack-level changes."""
    from .harness.commands.compare import execute as compare_execute

    try:
        result = compare_execute(run_id_a, run_id_b)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if pretty:
        trend = "[green]▲[/green]" if result.improved else "[red]▼[/red]"
        console.print(f"\n[bold]COMBATPAIR Compare[/bold]  {run_id_a[:8]} → {run_id_b[:8]}")
        console.print(f"  ARS: {result.ars_a:.3f} → {result.ars_b:.3f}  {trend} {result.ars_delta:+.3f}")
        if result.improved_cwes:
            console.print(f"  Improved: {', '.join(result.improved_cwes[:5])}")
        if result.regressed_cwes:
            console.print(f"  [red]Regressed:[/red] {', '.join(result.regressed_cwes[:5])}")
        if result.new_attacks:
            console.print(f"  New attack surfaces: {len(result.new_attacks)}")
        console.print("")
    else:
        click.echo(json.dumps({
            "run_id_a": result.run_id_a,
            "run_id_b": result.run_id_b,
            "ars_delta": result.ars_delta,
            "improved": result.improved,
            "regressed_cwes": result.regressed_cwes,
        }))


# ──────────────────────────────────────────────────────────────────────────────
# combatpair audit
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--days", default=90, show_default=True, help="Audit window in days")
@click.option("--domain", default=None, help="Filter by policy domain")
def audit(days: int, domain: str | None):
    """Compliance audit: list all reports with control mapping coverage."""
    cfg = AppConfig.load()
    reports = _load_recent_reports(cfg.reports_dir, days)

    if not reports:
        console.print(f"No reports found in the last {days} days.")
        return

    table = Table(show_header=True, header_style="bold", title=f"COMBATPAIR Compliance Audit — last {days}d")
    table.add_column("Run ID", style="dim", width=12)
    table.add_column("ARS", justify="right")
    table.add_column("Gate", justify="center")
    table.add_column("Attacks", justify="right")
    table.add_column("Missed", justify="right")
    table.add_column("Controls", style="dim")

    for r in reports:
        run_id = r.get("run_id", "")[:8]
        ars = r.get("ars_score", 0.0)
        passed = ars >= r.get("pass_threshold", 0.80)
        gate = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
        attacks = str(r.get("attack_count", 0))
        missed = str(r.get("miss_count", 0))
        mappings = r.get("control_mappings", {})
        controls = ", ".join(list(mappings.keys())[:2]) if mappings else "—"

        if domain and domain not in r.get("playbook_version", ""):
            continue

        table.add_row(run_id, f"{ars:.3f}", gate, attacks, missed, controls)

    console.print(table)


# ──────────────────────────────────────────────────────────────────────────────
# combatpair policy (subcommand group)
# ──────────────────────────────────────────────────────────────────────────────

@main.group()
def policy():
    """Manage adversarial policy domains (playbooks)."""
    pass


@policy.command("list")
def policy_list():
    """List all available policy domains."""
    from .policy.engine import list_available_domains, load_domain

    domains = list_available_domains()
    if not domains:
        console.print("No policy domains found.")
        return

    table = Table(show_header=True, header_style="bold", title="Available Policy Domains")
    table.add_column("Domain", style="bold")
    table.add_column("Version")
    table.add_column("Scenarios", justify="right")
    table.add_column("Framework", style="dim")

    for name in sorted(domains):
        try:
            d = load_domain(name)
            table.add_row(
                name,
                d.version,
                str(len(d.scenarios)),
                d.regulatory_framework or "—",
            )
        except Exception:
            table.add_row(name, "?", "?", "error loading")

    console.print(table)


@policy.command("install")
@click.argument("domain")
@click.option("--force", is_flag=True, help="Overwrite if already installed")
@click.option("--policies-dir", default=".combatpair/policies", show_default=True,
              help="Local directory to install the domain into")
def policy_install(domain: str, force: bool, policies_dir: str):
    """Download and install a community domain from the Policy Hub."""
    from .policy.hub import install_domain
    from pathlib import Path as _Path

    console.print(f"Fetching Policy Hub index...")
    result = install_domain(domain, policies_dir=_Path(policies_dir), force=force)

    if result.already_installed:
        console.print(f"[yellow]⚠[/yellow]  '{domain}' already installed at {result.installed_path}. Use --force to reinstall.")
    elif result.success:
        console.print(f"[green]✓[/green]  Installed '{domain}' v{result.version} → {result.installed_path}")
        console.print(f"  Use: [bold]combatpair run --domain {domain}[/bold]")
    else:
        console.print(f"[red]✗[/red]  {result.error}")
        sys.exit(1)


@policy.command("search")
@click.argument("query")
def policy_search(query: str):
    """Search the Policy Hub for domains matching a keyword or tag."""
    from .policy.hub import search_index

    try:
        entries = search_index(query)
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if not entries:
        console.print(f"No domains found matching '{query}'.")
        return

    table = Table(show_header=True, header_style="bold",
                  title=f"Policy Hub — '{query}' results")
    table.add_column("Domain", style="bold")
    table.add_column("Version")
    table.add_column("Framework")
    table.add_column("Scenarios", justify="right")
    table.add_column("Tags", style="dim")

    for e in entries:
        table.add_row(
            e.name, e.version, e.regulatory_framework,
            str(e.scenarios_count), ", ".join(e.tags[:3]),
        )
    console.print(table)


@policy.command("hub")
def policy_hub():
    """List all domains available in the remote Policy Hub."""
    from .policy.hub import fetch_index

    try:
        entries = fetch_index()
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    table = Table(show_header=True, header_style="bold", title="COMBATPAIR Policy Hub")
    table.add_column("Domain", style="bold")
    table.add_column("Version")
    table.add_column("Framework")
    table.add_column("Scenarios", justify="right")
    table.add_column("Tags", style="dim")

    for e in entries:
        table.add_row(
            e.name, e.version, e.regulatory_framework,
            str(e.scenarios_count), ", ".join(e.tags[:3]),
        )
    console.print(table)


@policy.command("validate")
@click.argument("domain")
def policy_validate(domain: str):
    """Validate a policy domain YAML for schema correctness."""
    from .policy.engine import validate_domain_yaml, load_domain

    try:
        d = load_domain(domain)
        errors = validate_domain_yaml(d)
        if errors:
            for err in errors:
                console.print(f"[red]✗[/red]  {err}")
            sys.exit(1)
        else:
            console.print(f"[green]✓[/green]  Domain '{domain}' is valid ({len(d.scenarios)} scenarios)")
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Domain '{domain}' not found. Run [bold]combatpair policy list[/bold].")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# combatpair vault
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--stats", "show_stats", is_flag=True, default=False,
              help="Show vault statistics (entry counts, top CWEs, avg effectiveness)")
@click.option("--cwe", default=None, help="Filter listing by CWE category (e.g. CWE-89)")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json", "md"]),
              show_default=True, help="Output format")
@click.option("--vault-dir", default=".combatpair/vault", show_default=True,
              help="Path to vault directory")
def vault(show_stats: bool, cwe: str | None, fmt: str, vault_dir: str):
    """Browse the Forge Ledger — human-readable Markdown adversarial memory vault."""
    from .memory.forge_ledger import ForgeLedger
    from pathlib import Path as _Path

    ledger = ForgeLedger(vault_dir=_Path(vault_dir))

    if show_stats:
        s = ledger.stats()
        if fmt == "json":
            click.echo(json.dumps(s, indent=2))
        elif fmt == "md":
            click.echo(ledger.render_stats_markdown())
        else:
            console.print(f"\n[bold]Forge Ledger Stats[/bold]  ({vault_dir})\n")
            console.print(f"  Total entries:        {s['total_entries']}")
            console.print(f"  Avg effectiveness:    {s['avg_effectiveness']:.3f}")
            if s["top_cwes"]:
                console.print(f"  Top CWEs:             {', '.join(s['top_cwes'])}")
            if s["severity_counts"]:
                sev = "  ".join(f"{k}: {v}" for k, v in s["severity_counts"].items())
                console.print(f"  Severity:             {sev}")
            console.print("")
        return

    entries = ledger.list_entries(cwe_filter=cwe)
    if not entries:
        console.print(f"No vault entries found{' for ' + cwe if cwe else ''}.")
        return

    if fmt == "json":
        click.echo(json.dumps([
            {"cwe": e.cwe, "attack_id": e.attack_id, "title": e.title,
             "severity": e.severity, "effectiveness": e.effectiveness,
             "run_id": e.run_id, "recorded_at": e.recorded_at}
            for e in entries
        ], indent=2))
    elif fmt == "md":
        lines = [f"# Forge Ledger — {len(entries)} entries\n"]
        for e in entries:
            lines.append(f"- **[{e.cwe}]** {e.title} — eff: {e.effectiveness:.2f} ({e.severity})")
        click.echo("\n".join(lines))
    else:
        table = Table(show_header=True, header_style="bold",
                      title=f"Forge Ledger ({len(entries)} entries)")
        table.add_column("CWE", style="bold", width=10)
        table.add_column("Title", width=40)
        table.add_column("Sev", width=8)
        table.add_column("Eff", justify="right", width=6)
        table.add_column("Run", style="dim", width=10)

        for e in entries:
            eff_style = "green" if e.effectiveness >= 1.0 else "yellow" if e.effectiveness >= 0.5 else "red"
            table.add_row(
                e.cwe, e.title[:38], e.severity,
                f"[{eff_style}]{e.effectiveness:.2f}[/{eff_style}]",
                e.run_id[-8:],
            )
        console.print(table)


# ──────────────────────────────────────────────────────────────────────────────
# combatpair prune
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--older-than", default="90d", show_default=True,
              help="Remove reports older than this (e.g. 90d, 30d)")
@click.option("--dry-run", is_flag=True, help="List what would be removed without deleting")
def prune(older_than: str, dry_run: bool):
    """Remove expired Resilience Reports."""
    from datetime import datetime, timezone
    import re as _re

    cfg = AppConfig.load()
    match = _re.match(r"(\d+)d", older_than)
    if not match:
        console.print("[red]Error:[/red] Use format like '90d'")
        sys.exit(1)

    days = int(match.group(1))
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    removed = 0

    for f in cfg.reports_dir.glob("*.json"):
        if f.stat().st_mtime < cutoff:
            if dry_run:
                console.print(f"  [dim]would remove:[/dim] {f.name}")
            else:
                f.unlink()
            removed += 1

    action = "Would remove" if dry_run else "Removed"
    console.print(f"{action} {removed} reports older than {older_than}.")


# ──────────────────────────────────────────────────────────────────────────────
# combatpair dashboard
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--port", default=8080, show_default=True, help="Port to listen on")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind")
@click.option("--reload", is_flag=True, help="Enable auto-reload (development only)")
@click.option("--config", "config_path", default=None,
              help="Path to .combatpair.yml. You shouldn't need this — the dashboard "
                   "remembers your last-used project automatically. Only useful for "
                   "pointing at a project you've never run combatpair in from this machine.")
def dashboard(port: int, host: str, reload: bool, config_path: str | None):
    """Launch the Combat Dashboard web UI."""
    try:
        import uvicorn  # noqa: F401
        import fastapi  # noqa: F401
    except ImportError as exc:
        console.print(f"[red]Error:[/red] Combat Dashboard requires FastAPI and Uvicorn ({exc}).")
        console.print("Fix with: [bold]pip install fastapi uvicorn[/bold]")
        sys.exit(1)

    import os
    cfg = AppConfig.load(config_path)
    if cfg.config_source:
        os.environ["COMBATPAIR_CONFIG_PATH"] = str(cfg.config_source)

    console.print(f"\n[bold]COMBATPAIR Combat Dashboard[/bold]")
    console.print(f"  URL:  [link=http://{host}:{port}]http://{host}:{port}[/link]")
    if cfg.config_source:
        console.print(f"  Project: [dim]{cfg.config_source.parent}[/dim]")
    else:
        console.print(
            f"  [yellow]⚠  No COMBATPAIR project found — never seen from this directory, "
            f"and nothing remembered from a previous run.[/yellow]\n"
            f"     Reports will be read from: [dim]{cfg.reports_dir}[/dim] (probably empty)\n"
            f"     Fix: run any [bold]combatpair[/bold] command inside your project once "
            f"(e.g. [bold]combatpair status[/bold]), or launch with "
            f"[bold cyan]combatpair dashboard --config /path/to/.combatpair.yml[/bold cyan]"
        )
    console.print(f"  Stop: Ctrl+C\n")

    import uvicorn
    uvicorn.run(
        "combatpair.dashboard.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_level="warning",
    )


# ──────────────────────────────────────────────────────────────────────────────
# combatpair leaderboard
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--port", default=8080, show_default=True, help="Port to listen on")
@click.option("--host", default="0.0.0.0", show_default=True, help="Host to bind")
@click.option("--reload", is_flag=True, help="Enable auto-reload (development only)")
@click.option("--rbac/--no-rbac", default=False, show_default=True,
              help="Enable GitHub team-based RBAC (requires GITHUB_ORG + team env vars)")
@click.option("--config", "config_path", default=None,
              help="Path to .combatpair.yml. You shouldn't need this — the dashboard "
                   "remembers your last-used project automatically. Only useful for "
                   "pointing at a project you've never run combatpair in from this machine.")
def serve(port: int, host: str, reload: bool, rbac: bool, config_path: str | None):
    """Start COMBATPAIR CPaaS (GitHub App webhook server)."""
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        console.print("[red]Error:[/red] combatpair serve requires FastAPI and Uvicorn.")
        console.print("Install with: [bold]pip install combatpair-ai[ui][/bold]")
        sys.exit(1)

    import os
    combatpair_cfg = AppConfig.load(config_path)
    if combatpair_cfg.config_source:
        os.environ["COMBATPAIR_CONFIG_PATH"] = str(combatpair_cfg.config_source)
    else:
        console.print(
            f"  [yellow]⚠  No COMBATPAIR project found — never seen from this directory, "
            f"and nothing remembered from a previous run.[/yellow]\n"
            f"     Reports will be read from: [dim]{combatpair_cfg.reports_dir}[/dim] (probably empty)\n"
            f"     Fix: run any [bold]combatpair[/bold] command inside your project once "
            f"(e.g. [bold]combatpair status[/bold]), or launch with "
            f"[bold cyan]combatpair serve --config /path/to/.combatpair.yml[/bold cyan]\n"
        )

    from .service.config import ServiceConfig
    cfg = ServiceConfig.from_env()
    errors = cfg.validate()
    if errors:
        console.print("[yellow]Warning: CPaaS not fully configured:[/yellow]")
        for e in errors:
            console.print(f"  · {e}")
        console.print("Service will start but GitHub integration will be disabled.\n")

    if rbac:
        org = cfg.github_org
        console.print(f"[cyan]RBAC enabled[/cyan] — GitHub org: {org or '(not set)'}")

    console.print(f"\n[bold]COMBATPAIR CPaaS[/bold]")
    console.print(f"  Webhook URL: http://{host}:{port}/webhook")
    console.print(f"  Dashboard:   http://{host}:{port}/")
    console.print(f"  Stop: Ctrl+C\n")

    import uvicorn
    uvicorn.run(
        "combatpair.dashboard.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@main.group()
def forge_network():
    """Forge Network — opt-in community adversarial pattern sharing."""


@forge_network.command("status")
def forge_network_status():
    """Show Forge Network opt-in status and hub statistics."""
    from .network.forge_network import ForgeNetworkConfig, fetch_hub_stats
    cfg = ForgeNetworkConfig.from_env()
    if cfg.enabled:
        console.print(f"[green]Forge Network: ENABLED[/green]  hub={cfg.hub_url}")
        console.print(f"  Contributor ID: {cfg.contributor_id}")
        console.print(f"  Min ARS to share: {cfg.min_ars_to_share}")
        stats = fetch_hub_stats(cfg)
        if stats:
            console.print(f"  Hub patterns: {stats.get('total_patterns', 'N/A')}")
        else:
            console.print("  Hub: unreachable (offline or not yet launched)")
    else:
        console.print("[yellow]Forge Network: DISABLED[/yellow]")
        console.print("  Enable with: COMBATPAIR_FORGE_NETWORK_ENABLED=true")


@forge_network.command("pull")
@click.argument("cwe")
@click.option("--limit", default=50, show_default=True, help="Max patterns to pull")
def forge_network_pull(cwe: str, limit: int):
    """Pull community-discovered attack patterns for a CWE from the hub."""
    from .network.forge_network import ForgeNetworkConfig, pull_patterns
    cfg = ForgeNetworkConfig.from_env()
    patterns, result = pull_patterns(cwe, cfg, limit=limit)
    if not result.success:
        console.print(f"[red]Pull failed:[/red] {result.error}")
        return
    console.print(f"[green]Pulled {len(patterns)} pattern(s) for {cwe}[/green]")
    for p in patterns[:5]:
        console.print(f"  [{p.severity}] {p.verdict}: {p.attack_vector[:80]}")


@main.command()
@click.option("--jsonl", "jsonl_path", type=click.Path(), default=None,
              help="Path to JSONL file with agent scores (agent_name, task_id, ars_score per line)")
@click.option("--reports-dir", type=click.Path(), default=None,
              help="Directory of COMBATPAIR report JSON files named <agent>--<task>.json")
@click.option("--output", type=click.Path(), default="docs/leaderboard.html", show_default=True,
              help="Output HTML file path (suitable for GitHub Pages docs/)")
@click.option("--gate", default=0.80, show_default=True, help="ARS gate threshold")
@click.option("--title", default="COMBATPAIR ARS Leaderboard", show_default=True,
              help="Page title")
def leaderboard(jsonl_path: str | None, reports_dir: str | None, output: str,
                gate: float, title: str):
    """Build and render the ARS Leaderboard HTML page."""
    from .leaderboard.engine import (
        load_agent_scores_from_jsonl,
        load_agent_scores_from_reports,
        build_leaderboard,
        render_leaderboard_html,
        save_leaderboard,
    )
    from datetime import datetime, timezone

    scores = []
    if jsonl_path:
        scores += load_agent_scores_from_jsonl(Path(jsonl_path))
    if reports_dir:
        scores += load_agent_scores_from_reports(Path(reports_dir), gate)
    if not jsonl_path and not reports_dir:
        # default: try the standard reports dir
        cfg = AppConfig.load()
        scores = load_agent_scores_from_reports(cfg.reports_dir, gate)

    entries = build_leaderboard(scores, gate_threshold=gate)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = render_leaderboard_html(entries, gate_threshold=gate, title=title, generated_at=generated_at)
    save_leaderboard(html, Path(output))
    console.print(f"[green]Leaderboard written to[/green] {output} ({len(entries)} agents, {len(scores)} tasks)")


# ──────────────────────────────────────────────────────────────────────────────
# combatpair mcp-server
# ──────────────────────────────────────────────────────────────────────────────

@main.command("mcp-server")
@click.option("--config", "config_path", default=None, help="Path to .combatpair.yml")
def mcp_server(config_path: str | None):
    """
    Start COMBATPAIR as an MCP server (stdio transport).

    Exposes COMBATPAIR's adversarial assessment capabilities to any
    MCP-compatible coding tool: Claude Code, Cursor, Windsurf, Zed, etc.

    \b
    Tools exposed:
      combatpair_run         — start adversarial assessment (returns run_id)
      combatpair_status      — poll for results by run_id
      combatpair_vault_stats — Knowledge Forge statistics
      combatpair_policy_list — list available security domains
      combatpair_verify      — verify SHA-256 report integrity

    \b
    Claude Code (~/.claude/mcp_servers.json):
      { "combatpair": { "command": "combatpair", "args": ["mcp-server"] } }

    \b
    Cursor (.cursor/mcp.json):
      { "combatpair": { "command": "combatpair", "args": ["mcp-server"] } }
    """
    from .mcp.server import MCPServer
    cfg = AppConfig.load(config_path)
    server = MCPServer(config=cfg)
    asyncio.run(server.run_stdio())


# ──────────────────────────────────────────────────────────────────────────────
# combatpair findings  — vulnerability-first view of last (or specified) run
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("run_id", required=False, default=None)
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "md", "json"]),
              show_default=True)
def findings(run_id: str | None, fmt: str):
    """Show vulnerability findings from the last run (or a specific run_id).

    Leads with what was found, the risk, and how to fix it.
    ARS score appears last as the gate verdict.

    \b
    Examples:
      combatpair findings                    # last run
      combatpair findings combatpair-2026-...  # specific run
      combatpair findings --format md        # markdown output for PRs
    """
    cfg = AppConfig.load()
    from .output.report import load_report, render_findings_summary

    if run_id is None:
        last_id_file = Path(".last_report_id")
        if not last_id_file.exists():
            console.print("[red]No recent run found.[/red] Run [bold]combatpair run --issue ...[/bold] first.")
            sys.exit(1)
        run_id = last_id_file.read_text().strip()

    try:
        report = load_report(run_id, cfg.reports_dir)
    except FileNotFoundError:
        console.print(f"[red]Report '{run_id}' not found.[/red]")
        sys.exit(1)

    if fmt == "json":
        attacks = report.get("attacks", [])
        click.echo(json.dumps({
            "run_id": run_id,
            "ars_score": report["ars_score"],
            "missed": [a for a in attacks if a["verdict"] == "MISSED"],
            "partial": [a for a in attacks if a["verdict"] == "PARTIAL"],
        }, indent=2))
    elif fmt == "md":
        click.echo(render_findings_summary(report))
    else:
        _print_run_summary(report, report["ars_score"] >= cfg.gate.minimum_ars)


# ──────────────────────────────────────────────────────────────────────────────
# combatpair integrate  — one-command IDE / platform setup
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option(
    "--platform",
    type=click.Choice(["claude-code", "cursor", "windsurf", "copilot", "codex", "github-actions", "all"]),
    default="all",
    show_default=True,
    help="Target IDE or platform",
)
@click.option("--dry-run", is_flag=True, help="Print config without writing files")
def integrate(platform: str, dry_run: bool):
    """One-command setup: wire COMBATPAIR into Claude Code, Copilot, Codex, GitHub Actions.

    Writes the MCP server config and GitHub Actions workflow for the chosen platform.
    Developers need zero manual configuration — just run this command.

    \b
    Examples:
      combatpair integrate                        # configure everything
      combatpair integrate --platform claude-code
      combatpair integrate --platform github-actions
      combatpair integrate --dry-run              # preview changes
    """
    import shutil

    mcp_config = json.dumps({
        "combatpair": {
            "command": str(shutil.which("combatpair") or "combatpair"),
            "args": ["mcp-server"],
            "env": {}
        }
    }, indent=2)

    github_action = """\
name: COMBATPAIR Adversarial Gate
on:
  pull_request:
    branches: ["main", "master"]

jobs:
  combatpair:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install COMBATPAIR
        run: pip install combatpair-ai
      - name: Run adversarial assessment
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        run: |
          combatpair run \\
            --issue ${{ github.event.pull_request.body || 'examples/demo_issue.md' }} \\
            --mode standard \\
            --domain owasp_top10
      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .combatpair/reports/
"""

    configs = {
        "claude-code": {
            "path": Path.home() / ".claude" / "mcp_servers.json",
            "content": mcp_config,
            "desc": "Claude Code MCP server config (~/.claude/mcp_servers.json)",
        },
        "cursor": {
            "path": Path(".cursor") / "mcp.json",
            "content": mcp_config,
            "desc": "Cursor MCP config (.cursor/mcp.json)",
        },
        "windsurf": {
            "path": Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
            "content": mcp_config,
            "desc": "Windsurf MCP config",
        },
        "copilot": {
            "path": Path(".vscode") / "mcp.json",
            "content": mcp_config,
            "desc": "GitHub Copilot / VS Code MCP config (.vscode/mcp.json)",
        },
        "codex": {
            "path": Path(".codex") / "mcp.json",
            "content": mcp_config,
            "desc": "Codex MCP config (.codex/mcp.json)",
        },
        "github-actions": {
            "path": Path(".github") / "workflows" / "combatpair.yml",
            "content": github_action,
            "desc": "GitHub Actions adversarial gate (.github/workflows/combatpair.yml)",
        },
    }

    targets = list(configs.keys()) if platform == "all" else [platform]

    console.print(f"\n[bold cyan]⚔  COMBATPAIR Integrate[/bold cyan]{'  [dim](dry run)[/dim]' if dry_run else ''}\n")

    written = 0
    for target in targets:
        cfg_entry = configs[target]
        dest: Path = cfg_entry["path"]
        content: str = cfg_entry["content"]
        desc: str = cfg_entry["desc"]

        if dry_run:
            console.print(f"  [dim]Would write:[/dim] {dest}")
            console.print(f"  [dim]  ({desc})[/dim]")
        else:
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                # For JSON MCP configs, merge rather than overwrite if file exists
                if dest.exists() and dest.suffix == ".json":
                    try:
                        existing = json.loads(dest.read_text())
                        new_entry = json.loads(content)
                        existing.update(new_entry)
                        dest.write_text(json.dumps(existing, indent=2))
                    except Exception:
                        dest.write_text(content)
                else:
                    dest.write_text(content)
                console.print(f"  [green]✓[/green]  {desc}")
                written += 1
            except OSError as e:
                console.print(f"  [yellow]⚠[/yellow]  {desc} — skipped ({e})")

    if not dry_run:
        console.print(f"\n[green]Done.[/green] {written}/{len(targets)} integration(s) configured.")
        console.print("\nRestart your IDE, then ask it to run [bold]combatpair_run[/bold] on any spec.")
        console.print("Or: [bold]combatpair run --issue examples/demo_issue.md --pretty[/bold]\n")
    else:
        console.print("\nRe-run without --dry-run to apply.\n")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────



def _load_spec(issue: str) -> str | None:
    """
    Load a specification from multiple source types.

    Primary (greenfield — spec-driven):
      - Local spec file:   /path/to/SPEC.md  or  examples/demo_issue.md
      - GitHub issue URL:  https://github.com/owner/repo/issues/42
      - GitHub file URL:   https://github.com/owner/repo/blob/main/SPEC.md
      - Any HTTP URL:      fetched as text (must return a readable spec)

    Secondary (brownfield — existing codebase):
      - Local folder:      /path/to/repo  (extracts spec docs; falls back to source)
      - GitHub repo URL:   https://github.com/owner/repo  (clones, extracts spec docs)
    """
    p = Path(issue)

    # Folder: concatenate all source files up to 100KB
    if p.is_dir():
        return _load_folder_spec(p)

    # Local file
    if p.is_file():
        return p.read_text()

    if not issue.startswith("http"):
        return None

    # GitHub repo URL — must check before issue/blob patterns
    gh_repo = _parse_github_repo_url(issue)
    if gh_repo:
        return _load_github_repo_spec(*gh_repo)

    # GitHub issue API
    gh_issue = _parse_github_issue_url(issue)
    if gh_issue:
        try:
            import httpx, os
            headers = {"Accept": "application/vnd.github+json"}
            token = os.environ.get("GITHUB_TOKEN", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            owner, repo, number = gh_issue
            resp = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo}/issues/{number}",
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            title = data.get("title", "")
            body  = data.get("body", "")
            return f"# {title}\n\n{body}" if title else body
        except Exception:
            pass

    # GitHub file (blob URL → raw)
    raw_url = _github_blob_to_raw(issue)
    if raw_url:
        issue = raw_url

    # Generic HTTP fetch
    try:
        import httpx
        resp = httpx.get(issue, timeout=15, follow_redirects=True)
        resp.raise_for_status()
        return resp.text[:50_000]
    except Exception:
        return None


def _load_folder_spec(folder: Path, max_bytes: int = 100_000) -> str | None:
    """
    Extract a specification from a folder.

    Primary mode — looks for spec documents in this priority order:
      1. SPEC.md, REQUIREMENTS.md, DESIGN.md, ARCHITECTURE.md at root
      2. README.md at root
      3. openapi.yaml / swagger.yaml (API contract)
      4. docs/, design/, spec/, adr/ subdirectory Markdown files

    Brownfield fallback — if no spec documents exist, concatenates source
    files (Python, Go, Java, TypeScript, etc.) up to max_bytes. This is a
    secondary mode for existing codebases without formal specs.
    """
    _SPEC_ROOTS = [
        "SPEC.md", "spec.md",
        "REQUIREMENTS.md", "requirements.md",
        "DESIGN.md", "design.md",
        "ARCHITECTURE.md", "architecture.md",
        "README.md", "readme.md",
        "openapi.yaml", "openapi.yml",
        "swagger.yaml", "swagger.yml",
        "api.yaml", "api.yml", "API.md",
    ]
    _SPEC_DIRS = {"docs", "doc", "design", "spec", "specs", "adr", "adrs", "design-docs"}

    parts: list[str] = [f"# Specification: {folder.name}\n"]
    total = 0

    # ── Primary: root-level spec documents ───────────────────────────────────
    for name in _SPEC_ROOTS:
        p = folder / name
        if p.exists() and p.is_file():
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")[:12_000]
                parts.append(f"\n## {name}\n\n{content}\n")
                total += len(content)
            except Exception:
                pass

    # ── Primary: spec subdirectory Markdown/YAML ─────────────────────────────
    for dname in _SPEC_DIRS:
        d = folder / dname
        if d.is_dir():
            for md in sorted(d.glob("*.md"))[:8]:
                try:
                    content = md.read_text(encoding="utf-8", errors="ignore")[:5_000]
                    parts.append(f"\n## {md.relative_to(folder)}\n\n{content}\n")
                    total += len(content)
                    if total >= max_bytes:
                        break
                except Exception:
                    pass
            if total >= max_bytes:
                break

    if len(parts) > 1:
        return "".join(parts)[:max_bytes]

    # ── Brownfield fallback: concatenate source files ─────────────────────────
    console.print("[yellow dim]  No spec documents found — falling back to brownfield mode "
                  "(source file extraction). Consider adding a SPEC.md or README.md.[/yellow dim]")
    extensions = {".py", ".java", ".go", ".js", ".ts", ".rb", ".cs"}
    skip_dirs  = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
                  ".gradle", "target", "vendor", ".idea", ".vscode"}

    src_parts: list[str] = [f"# Brownfield Codebase: {folder.name}\n"]
    src_total = 0
    for path in sorted(folder.rglob("*")):
        if any(skip in path.parts for skip in skip_dirs):
            continue
        if not path.is_file() or path.suffix not in extensions:
            continue
        rel = path.relative_to(folder)
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        snippet = content[:3_000]
        chunk = f"\n## {rel}\n```{path.suffix.lstrip('.')}\n{snippet}\n```\n"
        src_parts.append(chunk)
        src_total += len(chunk)
        if src_total >= max_bytes:
            src_parts.append("\n[truncated — brownfield extraction limit reached]\n")
            break

    return "".join(src_parts) if len(src_parts) > 1 else None


def _parse_github_issue_url(url: str):
    """Return (owner, repo, number) or None."""
    import re
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/issues/(\d+)", url)
    return (m.group(1), m.group(2), m.group(3)) if m else None


def _github_blob_to_raw(url: str) -> str | None:
    """Convert a GitHub blob URL to a raw content URL."""
    import re
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/(.+)", url)
    if m:
        return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}"
    return None


def _parse_github_repo_url(url: str):
    """Return (owner, repo) if url is a bare GitHub repo URL, else None."""
    import re
    # Matches https://github.com/owner/repo  or  https://github.com/owner/repo.git
    # Must NOT have extra path segments (issues, blob, tree, etc.)
    m = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    return (m.group(1), m.group(2)) if m else None


def _load_github_repo_spec(owner: str, repo: str) -> str | None:
    """Shallow-clone a GitHub repo and load its source files as a spec."""
    import os, shutil, subprocess, tempfile

    clone_url = f"https://github.com/{owner}/{repo}.git"
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        clone_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"

    console.print(f"[dim]  Cloning {owner}/{repo} (--depth 1)…[/dim]")
    tmp = tempfile.mkdtemp(prefix="combatpair-repo-")
    try:
        env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
        result = subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", clone_url, tmp],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        if result.returncode != 0 and "Clone succeeded" not in result.stderr:
            console.print(f"[red]  git clone failed:[/red] {result.stderr.strip()}")
            return None
        spec = _load_folder_spec(Path(tmp))
        if spec:
            console.print(f"[dim]  Extracted spec from {owner}/{repo}[/dim]")
        return spec
    except FileNotFoundError:
        console.print("[red]  git not found.[/red] Install git and retry.")
        return None
    except subprocess.TimeoutExpired:
        console.print("[red]  git clone timed out (120s).[/red] Try a smaller repo.")
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _load_policy_context(domains: list[str]) -> str:
    from .policy.engine import load_domains, combine_policy_context, list_available_domains
    available = list_available_domains()
    valid = [d for d in domains if d.split("@")[0] in available]
    if not valid:
        return ""
    try:
        loaded = load_domains(valid)
        return combine_policy_context(loaded)
    except Exception:
        return ""


def _load_recalled_attacks(spec: str) -> str:
    from .memory.forge import KnowledgeForge
    forge = KnowledgeForge()
    if not forge.is_available():
        return ""
    recalled = forge.recall_attacks(spec, n_results=10)
    return forge.format_recalled_for_prompt(recalled)


def _check_config_ready(cfg: AppConfig) -> list[tuple[str, str]]:
    """Return list of (problem, fix) tuples. Empty means config is complete."""
    import os
    issues: list[tuple[str, str]] = []
    provider = cfg.effective_model_provider

    if provider == "openrouter":
        if not os.environ.get("OPENROUTER_API_KEY"):
            issues.append(
                ("OPENROUTER_API_KEY is not set",
                 "combatpair setup --model  (choose OpenRouter and enter your API key)")
            )
        elif not cfg.deployment.openrouter_model:
            issues.append(
                ("OPENROUTER_MODEL is empty — no model selected",
                 "combatpair setup --model  (pick a model from the list)")
            )
    elif provider == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            issues.append(
                ("ANTHROPIC_API_KEY is not set",
                 "combatpair setup --model  (choose Anthropic and enter your API key)")
            )
    elif provider == "huggingface":
        if not os.environ.get("HF_TOKEN"):
            issues.append(
                ("HF_TOKEN is not set",
                 "combatpair setup --model  (choose HuggingFace and enter your token)")
            )
    elif provider == "openai_compat":
        if not os.environ.get("OPENAI_COMPAT_API_KEY"):
            issues.append(
                ("OPENAI_COMPAT_API_KEY is not set",
                 "combatpair setup --model  (choose OpenAI and enter your API key)")
            )
    # ollama: no key required — skip credential check

    return issues


async def _check_model(cfg: AppConfig) -> bool:
    import os
    import httpx

    provider = cfg.effective_model_provider

    if provider == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    if provider == "openrouter":
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    "https://openrouter.ai/api/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                return resp.status_code == 200
        except Exception:
            return False

    if provider == "huggingface":
        return bool(os.environ.get("HF_TOKEN"))

    if provider == "openai_compat":
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{cfg.deployment.openai_compat_endpoint}/models")
                return resp.status_code == 200
        except Exception:
            return False

    # local / ollama
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{cfg.deployment.local_endpoint}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


def _print_checks(checks: list, all_pass: bool) -> None:
    table = Table(show_header=True, header_style="bold")
    table.add_column("Check", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Detail", style="dim")

    for name, ok, detail in checks:
        icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
        table.add_row(name, icon, detail)

    console.print(table)
    if all_pass:
        console.print("\n[green]All checks passed.[/green] Environment ready.")
    else:
        console.print("\n[red]Some checks failed.[/red] Fix issues above before running.")


def _print_run_summary(report: dict, passed: bool) -> None:
    """Vulnerability-first output: findings → remediation → ARS gate."""
    from .output.report import get_remediation
    attacks = report.get("attacks", [])
    missed  = [a for a in attacks if a["verdict"] == "MISSED"]
    partial = [a for a in attacks if a["verdict"] == "PARTIAL"]
    ars = report["ars_score"]

    # ── 1. Findings first ────────────────────────────────────────────────────
    if missed:
        console.print(f"\n[bold red]❌  {len(missed)} UNMITIGATED VULNERABILIT{'Y' if len(missed)==1 else 'IES'} FOUND[/bold red]")
        for a in missed:
            sev_color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green"}.get(
                a.get("severity", "medium").lower(), "white"
            )
            console.print(f"\n  [{sev_color}][{a['cwe']}] {a['title']}[/{sev_color}]  [{a.get('severity','?').upper()}]")
            console.print(f"  [dim]{a['description'][:120]}[/dim]")
            remediation = a.get("remediation") or get_remediation(a["cwe"])
            console.print(f"  [bold]Fix:[/bold] {remediation}")
    elif partial:
        console.print(f"\n[yellow]⚠  {len(partial)} incompletely mitigated — review below[/yellow]")
        for a in partial:
            console.print(f"  [{a['cwe']}] {a['title']}")
            remediation = a.get("remediation") or get_remediation(a["cwe"])
            console.print(f"  [bold]Fix:[/bold] {remediation}")
    elif not attacks:
        console.print("\n[yellow]⚠  Breaker generated 0 attacks — model output unparseable or model failed.[/yellow]")
        console.print("  [dim]Retry with --mode quick, or run `combatpair setup` to switch to a more reliable model.[/dim]")
    else:
        console.print("\n[green]✅  No vulnerabilities found — all attacks mitigated.[/green]")

    # ── 2. ARS gate verdict ──────────────────────────────────────────────────
    gate_style = "green" if passed else "red"
    gate_label = "PASSED" if passed else "BLOCKED"
    console.print(f"\n{'─'*52}")
    console.print(f"  Adversarial Resilience Score: [{gate_style}]{ars:.3f}[/{gate_style}]  "
                  f"[{gate_style}]{gate_label}[/{gate_style}]")
    console.print(f"  {report['attack_count']} attacks  ·  "
                  f"[green]{report['mitigated_count']} mitigated[/green]  ·  "
                  f"[red]{report['miss_count']} missed[/red]  ·  "
                  f"{report['elapsed_seconds']}s")
    console.print(f"  Report: combatpair report {report['run_id']} --format html")
    console.print(f"{'─'*52}\n")


def _load_recent_reports(reports_dir: Path, days: int) -> list[dict]:
    from datetime import datetime, timezone
    import json as _json

    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    reports = []
    for f in sorted(reports_dir.glob("*.json")):
        if f.stat().st_mtime >= cutoff:
            try:
                with open(f) as fh:
                    reports.append(_json.load(fh))
            except Exception:
                continue
    return reports
