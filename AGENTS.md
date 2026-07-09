# AGENTS.md

Instructions for AI coding agents (Codex, Cursor, Cline, Windsurf, Gemini CLI,
Claude Code, and any other agent that reads this file) working in this repo.

## What this project is

GAUNTLEX is an adversarial co-generation engine. It runs two agents
concurrently against the same specification — **Builder** (writes the
implementation) and **Breaker** (writes adversarial attacks against that same
spec) — then an **Arbiter** scores every attack and produces an Adversarial
Resilience Score (ARS). See [README.md](README.md) for the full pitch.

Package name on PyPI: `gauntlex-ai`. CLI entry point: `gauntlex`.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
gauntlex doctor        # verify model connectivity + ChromaDB before anything else
```

## Running the test suite

```bash
python -m pytest -q
```

Run this after any change under `src/gauntlex/`. The suite is fast (~2s,
500+ tests) because it mocks external model calls — it verifies wiring and
logic, not live model behavior. If you touch anything that calls out to a
real model, MCP transport, or CLI subprocess, also do a live smoke test (see
below) since the mocked suite will not catch integration-only breakage.

## Live smoke test (do this for any change to `cli.py`, `harness/`, or `mcp/`)

```bash
gauntlex run --issue examples/demo_issue.md --mode quick --pretty
gauntlex status
gauntlex findings
```

`--mode quick` keeps this under ~2 minutes. Do not use `--mode thorough` for
routine verification.

## Key CLI commands an agent will typically need

| Command | Purpose |
|---|---|
| `gauntlex run --issue <file\|url> --mode quick\|standard\|thorough` | Run Builder+Breaker, get an ARS score |
| `gauntlex doctor` | Environment health check — run this first if anything fails |
| `gauntlex validate` | Dry run, zero attacks fired, just checks config/connectivity |
| `gauntlex findings` | Vulnerability-first summary of the last run |
| `gauntlex status` | List recent runs and pass/fail gate state |
| `gauntlex mcp-server` | Start GAUNTLEX as an MCP server (stdio) |
| `gauntlex integrate --platform all` | Wire GAUNTLEX's MCP config into every supported IDE/agent at once |

## Code conventions

- No comments unless explaining non-obvious *why* (a workaround, an
  invariant, a subtle constraint). Never comment on *what* the code does.
- Don't add error handling for cases that can't happen; only validate at
  real boundaries (user input, external APIs, network calls).
- Match existing patterns in the file you're editing before introducing a
  new one — this codebase favors small, direct functions over abstraction
  layers.
- Zero outbound network calls by default outside of the model provider call
  itself — the harness hook system (`src/gauntlex/harness/`) is
  hooks-are-plain-callables, no framework dependency.

## Directory map

- `src/gauntlex/cli.py` — all CLI commands (Click)
- `src/gauntlex/core/` — Builder/Breaker/Arbiter agents
- `src/gauntlex/harness/` — hook-chain execution runner + commands
- `src/gauntlex/mcp/server.py` — MCP stdio server
- `src/gauntlex/policy/domains/*.yaml` — compliance domain playbooks (OWASP, HIPAA, PCI DSS, FINRA, SOC2)
- `src/gauntlex/dashboard/` — FastAPI dashboard (`gauntlex dashboard`)
- `.claude/skills/gauntlex/` — Claude Code skills (also packaged as a plugin — see `.claude-plugin/`)
- `.gauntlex/` — per-project runtime state (reports, vault, brain) — gitignored, created on first run

## Before committing

1. `python -m pytest -q` must pass.
2. If you touched `cli.py`, `harness/`, or `mcp/server.py`, run the live
   smoke test above — the mocked test suite will not catch a broken CLI
   subprocess call or a wrong MCP config path.
3. Don't invent new top-level CLI commands without checking `README.md`'s
   CLI reference table — keep it in sync if you add or rename one.
