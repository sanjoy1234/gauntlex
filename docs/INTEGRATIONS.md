# GAUNTLEX — AI Coding Tool Integrations

How `gauntlex integrate` wires GAUNTLEX into every major AI coding tool, exactly
what it writes, and the safety guarantees behind it. See the main
[README](../README.md#ide--agent-integrations) for the quick-start commands —
this page is the "why" and "exactly what" behind them.

---

## The command

```bash
gauntlex integrate --dry-run             # preview only, writes nothing
gauntlex integrate                       # wire up every supported target
gauntlex integrate --platform <target>   # wire up just one
gauntlex integrate --force               # overwrite a hand-customized file (see below)
```

`--platform` accepts: `claude-code`, `cursor`, `windsurf`, `copilot`, `codex`,
`zed`, `antigravity`, `github-actions`, or `all` (the default).

Every generated config resolves the `gauntlex` command via `shutil.which`,
writing the **absolute path** to the installed binary when discoverable, so
the target tool doesn't depend on inheriting your shell's `PATH`.

---

## Per-platform target matrix

| Platform | Exact path | Format / wrapper key | Notes |
|---|---|---|---|
| `claude-code` | `.mcp.json` (project-scoped) | JSON — `mcpServers` | |
| `cursor` | `.cursor/mcp.json` | JSON — `mcpServers` | |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` | JSON — `mcpServers` | user-home scoped, not per-project |
| `copilot` | `.vscode/mcp.json` | JSON — `servers` | VS Code uses a different wrapper key than the MCP-standard `mcpServers` |
| `codex` | `~/.codex/config.toml` | TOML — `[mcp_servers.gauntlex]` | Codex ignores JSON here — must be TOML |
| `zed` | `.zed/settings.json` | JSON — `context_servers` | entries wrapped with `"source": "custom"` |
| `antigravity` | `~/.gemini/config/mcp_config.json` | JSON — `mcpServers` | shared by Antigravity IDE + CLI |
| `github-actions` | `.github/workflows/gauntlex.yml` | YAML (Actions workflow) | the one non-mergeable, template-guarded target |

Every JSON target shares one entry shape —
`{"command": gauntlex_cmd, "args": ["mcp-server"], "env": {}}` — which just
tells the host tool to spawn `gauntlex mcp-server` over stdio. The only real
per-platform work is the wrapper key and file location, not the entry content.

---

## Merge safety — three write strategies

`integrate` doesn't treat every file the same way. It picks a strategy per
format:

**TOML (Codex)** — a scoped regex finds the existing `[mcp_servers.gauntlex]`
table (bounded by the next top-level `[table]` header or EOF) and replaces
just that block. Every other table — e.g. your own `[mcp_servers.other]` — is
left byte-for-byte intact. Running `integrate --platform codex` twice is
idempotent: exactly one `gauntlex` block, sibling tables untouched.

**JSON (claude-code, cursor, windsurf, copilot, zed)** — the merge happens
**one level below** the wrapper key
(`existing[merge_key].update(new_entry)`, not `existing.update(...)` at the
top level). An earlier version of this command merged at the top level,
which silently deleted every other MCP server already configured in the
file — that regression is now covered by a dedicated test. Re-running
`integrate` today for a project that already has, say, a filesystem or
Postgres MCP server configured alongside GAUNTLEX leaves that sibling entry
untouched.

**GitHub Actions workflow (the one non-mergeable format)** — there's no safe
way to splice a generated workflow into a hand-edited one. An earlier version
of `integrate` overwrote `.github/workflows/gauntlex.yml` unconditionally —
no check at all — which meant re-running `integrate` could silently destroy
hand-added customization (PR-comment posting, custom permissions, extra
steps) with zero warning. The fix: if the destination exists **and** differs
from the freshly generated template, `integrate` now skips the write and
prints a warning instead — unless `--force` is explicitly passed.

---

## GitHub Actions workflow template

Generated at `.github/workflows/gauntlex.yml`:

- Triggers on `pull_request` to `main`/`master`.
- `ubuntu-latest` job: checkout → `actions/setup-python@v5` (3.12) →
  `pip install gauntlex-ai`.
- Runs `gauntlex run --issue ${{ github.event.pull_request.body || 'examples/demo_issue.md' }} --mode standard --domain owasp_top10`.
- Always uploads `.gauntlex/reports/` via `github/codeql-action/upload-sarif@v3`
  to GitHub Code Scanning.
- Model credential: `OPENROUTER_API_KEY` as a repo secret.

> **Known inconsistency:** the Docker Compose file (`docker-compose.yml`)
> instead passes `ANTHROPIC_API_KEY`. The two deployment templates assume
> different providers by default — set whichever secret matches your actual
> configured provider (see `gauntlex setup`), not necessarily the one named
> in the template you're looking at.

---

## The Claude Code plugin marketplace — a separate, parallel path

Distinct from `gauntlex integrate --platform claude-code`, this repo also
ships a full Claude Code plugin under `.claude-plugin/`:

- **`marketplace.json`** — the manifest `/plugin marketplace add sanjoy1234/gauntlex`
  reads; declares one plugin entry (`name: gauntlex`, `source: ./`).
- **`plugin.json`** — the manifest `/plugin install gauntlex@gauntlex` reads;
  wires `"skills": ["./.claude/skills/gauntlex"]` and
  `"mcpServers": {"gauntlex": {"command": "gauntlex", "args": ["mcp-server"]}}`.

The plugin path never writes `.mcp.json` at all — Claude Code reads the MCP
wiring straight out of `plugin.json` once the plugin is installed. The skills
directory registers one `SKILL.md` per subcommand (`run`, `verify`, `doctor`,
`compare`, `report`, `learn`, `validate`), each a thin instruction wrapper
that shells out to the installed `gauntlex` binary — not a reimplementation.

---

## The MCP server itself

`gauntlex mcp-server` (stdio, for local IDE use) and `gauntlex serve --mcp`
(HTTP, for team/enterprise deployment alongside the dashboard) both expose
the same JSON-RPC 2.0 / MCP `2024-11-05` server with **five tools**:

| Tool | Purpose |
|---|---|
| `gauntlex_run` | Starts an assessment asynchronously and returns a `run_id` immediately — the event loop keeps servicing status polls while the engine runs in the background. |
| `gauntlex_status` | Polls by `run_id`; returns `running`/`complete`/`error`/`cancelled`, ARS score, gate pass/fail, and a per-attack breakdown once complete. |
| `gauntlex_vault_stats` | Reads the Forge Ledger (`.gauntlex/vault/CWE-*/*.md`) directly off disk to report entry counts by CWE. |
| `gauntlex_policy_list` | Returns the 7 built-in policy domains with scenario counts. |
| `gauntlex_verify` | Recomputes a SHA-256 over a stored report's attacks and compares it to the stored `integrity_hash`, to detect tampering. |

---

## Zero-config alternative

For any tool that reads `AGENTS.md` automatically (Codex, Cursor, Cline,
Windsurf, Gemini CLI) — no install step at all. This repo's own
[AGENTS.md](../AGENTS.md) is the reference pattern if you're building on top
of GAUNTLEX rather than just using it.
