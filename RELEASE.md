# GAUNTLEX Release Notes

> "Release notes written before the code."
> — GAUNTLEX Design Principle 6 (Stanford TKI — Rule 6: Ship Confidence)

---

## v1.0.2 — Monday 2026-07-13

**Metadata-only release — adds the ownership-verification marker required to publish GAUNTLEX's MCP server on the official Model Context Protocol Registry. No functional changes.**

### Changed

- Added `<!-- mcp-name: io.github.sanjoy1234/gauntlex -->` to `README.md`, which becomes the PyPI package description — this is how the MCP Registry verifies the PyPI package (`gauntlex-ai`) belongs to this GitHub-authenticated publisher.
- Version bumped in lockstep across `pyproject.toml`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, the MCP server's `_SERVER_VERSION`, and the SARIF report driver version, per the sync workflow in `DISTRIBUTION.md`.

---

## v1.0.1 — Friday 2026-07-10

**Bug fix + a new capability — `gauntlex status` and `gauntlex leaderboard` both silently misreported data due to the same missing schema field, and the leaderboard now runs live inside the dashboard, not just as a static file.**

### Fixed

- **Reports now record `mode` and `model`.** `build_report()` previously had
  neither field at all. Two visible symptoms, one root cause:
  - `gauntlex status`'s Mode column always showed `—` regardless of which
    `--mode` a run actually used.
  - `gauntlex leaderboard` (and its `--reports-dir` mode) always collapsed
    every run into a single `agent_name="unknown"` row — it expected report
    filenames in an `<agent>--<task>.json` convention that `gauntlex run`
    never actually produces, so every report fell into the same fallback
    bucket regardless of which model generated it.
  Both are fixed at the source: every report-producing call site (`cli.py`
  ×2, `mcp/server.py`, `harness/commands/run.py`) now passes the real
  `mode` and `f"{provider}/{model}"` into `build_report()`, `gauntlex
  status` reads the real value instead of the placeholder, and the
  leaderboard groups by the report's own `model` field first (falling back
  to the old filename convention, then `"unknown"`, only for reports
  produced before this fix). **Reports generated before this release have
  no `model` field and will still show as `"unknown"` — this is the
  designed backward-compatible fallback, not a residual bug.** Any run
  going forward gets grouped correctly.

- **GAUNTLEX no longer assumes Ollama when no model provider is configured.**
  Every entrypoint (CLI `run`/`doctor`/`validate`, the MCP server, the
  dashboard) previously fell back to a hardcoded Ollama default whenever no
  provider had been explicitly chosen — a `pip install` or `uvx` user who
  hadn't run `gauntlex setup` saw `Cannot reach Ollama at
  http://localhost:11434` instead of a clear "not configured" message.
  `AppConfig.model_provider` now defaults to `None`; `model_kwargs()` raises
  `ModelProviderNotConfiguredError` pointing at `gauntlex setup`, and every
  entrypoint surfaces that message instead of attempting a connection.
  Verified across three separate install paths — editable dev install, a
  genuinely clean `pip install` of a built wheel, and `uvx --from <wheel>` —
  on two different Click versions.
- **`--pretty` flag behavior was ambiguous across Click versions.**
  `is_flag=True, default=True` without a `--no-pretty` counterpart silently
  toggles to `False` when the flag is explicitly passed, on Click 8.2.x (but
  not 8.4.x) — so `gauntlex doctor --pretty` could print raw JSON instead of
  a table depending on which Click version pip happened to resolve.
  `pyproject.toml` only pins `click>=8.1`, so both resolve on a fresh
  install. All four affected commands (`validate`, `doctor`, `learn`,
  `compare`) now use the unambiguous `--pretty/--no-pretty` pair.
- **Claude Code plugin skill docs hardcoded Ollama as the model check.**
  `.claude-plugin`'s `doctor`/`validate` SKILL.md files told Claude to
  report "Ollama reachable" / `GET http://localhost:11434/` as *the* model
  check, independent of whichever provider was actually configured — this
  is what made the Claude Code plugin render "Ollama not running" even
  after the underlying CLI was already fixed. Both files now instruct
  Claude to report whichever provider the command's own output names.

### Added

- **`gauntlex dashboard` now serves a live leaderboard.** New `/leaderboard`
  HTML page and `/api/leaderboard` JSON endpoint on the same running
  server — re-reads `.gauntlex/reports/` on every request, no separate
  build step. The dashboard's header nav gained a 🏆 Leaderboard link, and
  the leaderboard page links back to the Dashboard, both sharing the exact
  same theme (extracted into a shared `_DASHBOARD_CSS` constant, verified
  byte-for-byte identical to the prior inline version — a pure refactor,
  not a redesign). The standalone `gauntlex leaderboard` CLI command is
  unchanged and still exists for static-site publishing (e.g. GitHub
  Pages) — the two are complementary, not a replacement.
- **`scripts/release.sh` + `DISTRIBUTION.md`** — a repeatable release
  workflow. `DISTRIBUTION.md` tracks every place GAUNTLEX is published
  (PyPI, the GitHub repo, the Claude Code plugin marketplace, and a
  placeholder section for future MCP registries) and exactly how to update
  each. `release.sh` enforces that `pyproject.toml`, `.claude-plugin/plugin.json`,
  and `.claude-plugin/marketplace.json` all agree on the version before
  anything ships, runs the full test suite, builds sdist+wheel, and
  installs the freshly built wheel into a throwaway venv to catch packaging
  regressions before they're public. Publish (`--publish`) and git tag/push
  (`--tag`) are opt-in flags, not defaults — nothing public happens by
  accident.
- 17 new regression tests (8 leaderboard engine, 9 dashboard integration),
  plus additional coverage for the no-default-provider and `--pretty` fixes
  above. Full suite: 612 passed. Live-verified: started the real dashboard
  server, curled every pre-existing endpoint to confirm zero regression,
  and confirmed via headless-Chrome screenshot that both pages render
  correctly and match visually.

---

## v1.0.0 — Friday 2026-07-10

**First stable release — two real defects found and fixed via live end-to-end scenario testing, both touching the core engine's correctness guarantees.**

### Fixed

- **Mode attack count now actually works.** `--mode quick/standard/thorough`
  (5/20/50 attacks) previously had **no effect on generation at all** — every
  run fired a hardcoded 3–5 CWEs per round regardless of mode, for the entire
  life of v0.1.0. `cfg.gauntlex.attack_count` is now spread across
  `rounds_max` rounds via a new `attacks_per_round` parameter threaded
  through the Breaker, so mode selection actually controls attack volume.
  Real totals land close to but not always exactly at the target (a
  `thorough` run produced 26/50 attacks in live testing) — see the
  [Deep Dive](docs/DEEP_DIVE.md#feature-1--the-gauntlex-engine) for why.
- **Found and fixed a second bug in the same code path:** for round 2+, the
  engine was firing two Breaker LLM calls per round — one wasted (fired
  concurrently with the Builder, then immediately discarded) and one real.
  Now exactly one call per round, which also meaningfully speeds up
  `standard`/`thorough` runs.
- **`gauntlex vault` / `gauntlex vault --stats` now actually work.**
  Previously always reported 0 entries — nothing in any live code path wrote
  to the Forge Ledger's storage directory (a hook designed to do this was
  defined but never registered). `gauntlex learn` now writes to both the
  Knowledge Forge (ChromaDB) and the Forge Ledger, and every `gauntlex run`
  auto-learns on completion (best-effort) so the vault reflects real data
  without a separate manual step. Verified live end-to-end (vault entry
  count increased automatically after a run with no manual `gauntlex learn`
  call).
- Carried forward from prior testing: an Ollama read-timeout mismatch that
  produced a misleading bare exception instead of a clear timeout error
  under slow CPU inference; `gauntlex serve` / `gauntlex serve --rbac`
  hardening; a leaked raw exception message in `gauntlex forge-network`; and
  a fix preventing `gauntlex integrate --platform github-actions` from
  silently clobbering a hand-customized workflow file.

### Added

- `gauntlex integrate` now supports `zed` and `antigravity` as platform
  targets, in addition to the existing claude-code/cursor/windsurf/copilot/
  codex/github-actions set.
- Claude Code plugin marketplace scaffold (`.claude-plugin/`) — install via
  `/plugin marketplace add sanjoy1234/gauntlex` then `/plugin install gauntlex@gauntlex`.
- [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) — full reference for every
  AI coding tool integration: exact file paths, merge-safety guarantees, the
  GitHub Actions template, and the MCP server's five tools.
- 11 new/updated regression tests covering both fixes. Full suite: 588 passed.

### Known issues (not yet fixed)

- `gauntlex policy hub` / `policy search` / `policy install` for
  non-bundled domains are blocked — the `policy-hub/` content directory
  doesn't exist in this repo yet (this is a missing-content gap, not a code
  bug).
- The GitHub Actions template generated by `gauntlex integrate` uses
  `OPENROUTER_API_KEY`, while `docker-compose.yml` uses `ANTHROPIC_API_KEY`
  — the two deployment paths default to different providers; set whichever
  secret matches your actual configured provider.

---

## v0.1.0 — Monday 2026-06-30

**First public release — Adversarial Co-Generation Engine**

### What's New

GAUNTLEX v0.1.0 introduces the world's first production Python library that runs
a Builder agent and a Breaker agent **concurrently** — not sequentially — on the
same specification. The result is an Adversarial Resilience Score (ARS) and a
tamper-evident Resilience Report, delivered as a first-class CI/CD artifact.

No existing tool (Devin, OpenHands, GitHub Copilot, Amazon Q) does this.
They all generate code and test it after the fact. GAUNTLEX attacks during
construction via `asyncio.gather(builder, breaker)`.

### Core Engine

- **Gauntlex** — `asyncio.gather(builder.generate, breaker.attack)` concurrent execution
- **Adversarial Resilience Score (ARS)** — `Σ(attack_scores) / N` where 1.0=mitigated, 0.5=partial, 0.0=miss
- **Arbiter** — impartial LLM judge, never generates attacks or code
- **Resilience Report** — JSON artifact with SHA-256 integrity hash + NIST SSDF / SOC 2 / OWASP SAMM / ISO 27001 control mappings
- **Tiered modes** — `quick` (5 attacks), `standard` (20), `thorough` (50)
- **Early-exit optimization** — stops when ARS ≥ threshold for N consecutive rounds

### Enterprise Layer

- **Knowledge Forge** — ChromaDB cross-build adversarial memory; recalled attacks inject into Breaker prompt
- **Adversarial Policy Engine (APE)** — YAML playbooks per regulatory domain:
  - `owasp_top10` — 12 scenarios (A01–A10)
  - `hipaa` — 6 PHI security scenarios (§164.312)
  - `pci_dss` — 6 cardholder data scenarios (PCI DSS v4.0)
  - `soc2` — 7 Trust Service Criteria scenarios (CC and A series)
  - `finra` — 6 broker-dealer security scenarios (Rules 4370, 3110, SEC 17a-4)
- **Attack Validation Framework (AVF)** — 5 golden CVE fixtures; Breaker must find ≥75% before any production run
- **CWE Taxonomy** — 20 CWE categories with Shannon entropy guard and rotation
- **Adaptive Brain** — codebase fingerprinting, 30-run EMA effectiveness tracking, pattern reinforcement/deprecation, meta-agent prompt evolution

### Harness

- **GauntlexHarness** — custom hook chain (pre_run, post_round, post_run, learn); no LangChain, no AutoGen
- **Harness Commands** — programmatic API layer (run, validate, learn, compare, doctor, init, report, verify)
- **Developer CLI Skills** — `/gauntlex:run`, `/gauntlex:validate`, `/gauntlex:learn`, `/gauntlex:compare`, `/gauntlex:doctor`, `/gauntlex:report`, `/gauntlex:verify`

### CLI

```
gauntlex run       --issue <spec> --mode quick|standard|thorough
gauntlex validate  [--spec <file>]
gauntlex doctor    [--network-check]
gauntlex learn     <run_id>
gauntlex compare   <run_id_a> <run_id_b>
gauntlex audit     [--days N]
gauntlex policy    list | validate <domain>
gauntlex stats     [--days N] [--learning-curve]
gauntlex report    <run_id> [--format md|json]
gauntlex verify    <run_id>
gauntlex prune     [--older-than 90d] [--dry-run]
gauntlex init      [--domain <domain>]
```

### Infrastructure

- **GitHub Action** — posts ARS as PR comment; blocks merge when ARS < threshold
- **Docker** — `docker compose up` for full stack (GAUNTLEX + ChromaDB)
- **CPaaS** — `service/` layer for GitHub App webhook handler (Gauntlex-as-a-Service)
- **ForgeBot** — auto-post Resilience Report as GitHub PR comment
- **Beam Executor** — experimental stochastic parallel Breaker ensemble (N beams)

### Model Support

- **Ollama (default)** — zero cost, air-gapped, no API key required
  - Recommended: `llama3.1:8b` (standard) or `llama3.1:70b` (thorough)
- **Anthropic Claude** — set `ANTHROPIC_API_KEY` to auto-switch
  - Uses `claude-sonnet-4-6` by default

### `fail_open: false`

By default, GAUNTLEX **blocks** the merge when ARS falls below `gate.minimum_ars` (default: 0.80).
This is intentional. Security is not optional. Set `fail_open: true` in `.gauntlex.yml` to downgrade
to a warning if your team is still calibrating thresholds.

### ARS Formula

```
ARS = Σ(score_i) / N
  where score_i ∈ {1.0 = mitigated, 0.5 = partial, 0.0 = missed}
```

An ARS of 1.0 means the Builder mitigated every attack the Breaker found.
An ARS of 0.0 means none were mitigated — the code ships with every discovered vulnerability open.

### Ship Gate

```bash
bash scripts/ship_gate.sh
```

All 7 checks must pass:
1. Package installs cleanly (`pip install -e .`)
2. Environment health (`gauntlex doctor --network-check`)
3. AVF gate (`gauntlex validate` — Breaker finds ≥75% of golden CVE fixtures)
4. Unit tests (`pytest tests/ -q` — 50+ tests passing)
5. Standalone demo (`python examples/standalone_demo.py --mode quick`)
6. CLI integration (`gauntlex init → validate → run`)
7. Report integrity (`gauntlex verify <latest_run_id>`)

### Breaking Changes

None — this is the initial release.

### Upgrade Path

```bash
pip install gauntlex-ai==0.1.0
gauntlex init  # creates .gauntlex.yml with defaults
gauntlex validate  # verify environment
```

---

## Roadmap

### v0.2.0 — Week 2 (2026-07-07)

- TypeScript / JavaScript language support in Fingerprint engine
- Playwright integration for frontend XSS detection
- HIPAA playbook refinements for EHR-specific patterns
- HTML report format for Resilience Report
- `gauntlex serve` — start CPaaS GitHub App server

### v0.3.0 — Week 4 (2026-07-21)

- Community pattern sharing (opt-in Knowledge Forge federation)
- SARIF output format for GitHub Code Scanning integration
- JUnit XML output for CI/CD dashboards
- GPT-4o provider support

### v1.0.0 — Q3 2026

- Production-grade CPaaS with multi-tenant support
- SOC 2 Type II certification pathway
- Enterprise RBAC and audit trail
- SLA: 99.9% webhook delivery, <2min p99 ARS generation

---

*GAUNTLEX is MIT licensed. Contributions welcome — see [CONTRIBUTING-PLAYBOOKS.md](CONTRIBUTING-PLAYBOOKS.md).*
