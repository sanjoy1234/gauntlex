# GAUNTLEX Release Notes

> "Release notes written before the code."
> — GAUNTLEX Design Principle 6 (Stanford TKI — Rule 6: Ship Confidence)

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
