← [Back to README](../README.md)

# Domain Intelligence — Compliance Coverage & Live Threat Data

This page answers one question as precisely as possible: **for a given regulated
domain, what does GAUNTLEX actually cover today, what is static content versus
live data, and what does an enterprise need to bring itself?**

It exists because "supports HIPAA and FINRA" can mean very different things —
a static checklist, a live regulatory feed, or something in between. This page
draws the line explicitly, domain by domain, so there is no ambiguity before
you point GAUNTLEX at a regulated codebase.

---

## Table of contents

- [Two different things people call "domain intelligence"](#two-different-things-people-call-domain-intelligence)
- [Built-in compliance domains — what ships today](#built-in-compliance-domains--what-ships-today)
- [Live threat data — what's actually live vs. static](#live-threat-data--whats-actually-live-vs-static)
- [The Domain Intelligence Adapter (DIA) — how enrichment works](#the-domain-intelligence-adapter-dia--how-enrichment-works)
- [GAUNTLEX as an MCP server vs. GAUNTLEX as an MCP consumer](#gauntlex-as-an-mcp-server-vs-gauntlex-as-an-mcp-consumer)
- [Policy Hub — community and installable domains](#policy-hub--community-and-installable-domains)
- [Bring your own domain](#bring-your-own-domain)
- [Roadmap domains — not yet available](#roadmap-domains--not-yet-available)
- [Summary table](#summary-table)

---

## Two different things people call "domain intelligence"

Before anything else, two mechanisms need to be pulled apart, because they get
conflated constantly and the difference matters for what you should expect:

1. **Policy domains** — versioned YAML playbooks that tell the Breaker which
   attack scenarios to prioritize for a regulated context (e.g. "for HIPAA,
   weight PHI exposure and access-control scenarios higher"). These are
   **static content**, authored and versioned like any other config. They do
   not change at runtime and they do not call out to the internet.

2. **Live threat intelligence** — real-time vulnerability and exploitation
   data pulled from external feeds (CISA KEV, NIST NVD, or an enterprise's own
   MCP server) and injected into the Breaker's context *at the moment a run
   starts*. This is the part that is actually "live."

**A policy domain being available does not mean it has a dedicated live feed.**
Today, live enrichment is CWE-based and cuts *across* every domain — it is not
scoped per regulation. The rest of this page explains exactly what that means.

---

## Built-in compliance domains — what ships today

Five domains ship in `src/gauntlex/policy/domains/` and are available with no
install step. This table is generated directly from the source YAML files, not
from marketing copy — scenario counts are exact as of this writing (run
`gauntlex policy list` yourself to confirm):

| Domain | Scenarios | Regulatory framework | Representative scenario |
|---|---|---|---|
| `finra` | 9 | FINRA Rules 4370, 3110; SEC Rule 17a-4; CFTC Regulation 1.31 | Business continuity single points of failure (FINRA 4370); immutable trade-supervision audit trail (FINRA 3110) |
| `hipaa` | 9 | HIPAA Security Rule (45 CFR §§160, 164) | Missing access control on PHI endpoints (§164.312(a)(1)); hardcoded emergency-access credentials (§164.312(a)(2)) |
| `owasp_top10` | 12 | OWASP Top 10 (2021/2025) | Broken access control (A01); cryptographic failures (A02); SQL injection (A03) |
| `pci_dss` | 6 | PCI DSS v4.0 | Cleartext PAN storage (Req. 3); CVV/CVC retention after authorization (Req. 3.2.1) |
| `soc2` | 7 | AICPA SOC 2 Trust Service Criteria (2017, with 2022 points of focus) | Logical access controls (CC6.1); MFA enforcement gaps (CC6.3) |

**43 scenarios total across the 5 built-in domains.** Each scenario in every
domain carries a `cwe` identifier, a specific `regulatory_ref` (the exact rule
or control, not just the framework name), a description of what the Breaker
looks for, and a concrete code-level example. None of this is generic OWASP
boilerplate re-labeled per domain — each domain's scenarios were written
against that regulation's actual text.

Select a domain per run:

```bash
gauntlex run --issue spec.md --domain hipaa
gauntlex run --issue spec.md --domain finra
```

If no `--domain` is passed, GAUNTLEX defaults to `owasp_top10`.

---

## Live threat data — what's actually live vs. static

This is the section most worth reading carefully.

| Source | Status | Scope | Cost / setup |
|---|---|---|---|
| **CISA KEV** (Known Exploited Vulnerabilities catalog) | **Live** — fetched fresh every run | Cross-cutting by CWE, not domain-specific | Free, public, no API key, on by default |
| **NIST NVD** (National Vulnerability Database) | **Live** — queried per CWE, 90-day lookback by default | Cross-cutting by CWE, not domain-specific | Free; works without a key at 5 req/30s, or with a free `NVD_API_KEY` at 50 req/30s |
| **Custom enterprise MCP server** (e.g. an internal FINRA threat-intel feed) | **Live, if you provide one** | Whatever the server returns | You operate and configure it — GAUNTLEX provides the plumbing, not the feed |
| The 5 built-in policy domains themselves (FINRA, HIPAA, OWASP Top 10, PCI DSS, SOC2) | **Static** — versioned YAML, updated via GAUNTLEX releases | Domain-specific scenarios | Included, no setup |

The honest way to say this: **GAUNTLEX does not ship a dedicated "live FINRA
feed" or "live HIPAA feed" today.** What it ships is two free, no-configuration
live CVE/exploitation feeds (KEV and NVD) that enrich *whatever CWEs the
current run is testing*, regardless of which policy domain selected those
CWEs. A HIPAA run testing CWE-284 (missing access control) gets the same live
KEV/NVD enrichment for CWE-284 that an OWASP Top 10 run testing the same CWE
would get. The regulatory specificity comes from the static scenario content;
the liveness comes from the CWE-based feeds layered on top.

If your organization needs a genuinely domain-specific live feed — say, a real
FINRA enforcement-actions feed or an internal fraud-pattern service — the
[Domain Intelligence Adapter](#the-domain-intelligence-adapter-dia--how-enrichment-works)
is exactly the extension point for wiring that in. GAUNTLEX does not bundle
one because GAUNTLEX does not have a relationship with FINRA, HIPAA regulators,
or any other body — the built-in feeds are the two that are genuinely free and
public (CISA and NIST).

### CISA KEV in detail

- Feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Fetched fresh at the start of every GAUNTLEX process (no stale cache across runs)
- Matched to the run's CWEs via keyword matching against vulnerability name,
  description, and product fields (KEV entries don't always carry CWE labels
  directly)
- Every entry in KEV has **confirmed in-the-wild exploitation** — this is
  higher-signal than the full CVE firehose, which is why it's on by default
- On by default; no configuration needed; fails silently (never blocks a run)
  if CISA's feed is unreachable

### NIST NVD in detail

- API: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Queried per CWE with a configurable lookback window (default 90 days)
- Off by default without an API key (the unauthenticated rate limit — 5
  requests/30s — is too easily exhausted mid-run); set `NVD_API_KEY` (free
  from NIST) to enable it automatically, or set `nvd_enabled: true` in
  `.gauntlex.yml`
- Returns CVSS score, severity, publish date, and up to 2 references per CVE

Neither feed blocks a run if unreachable — both are strictly additive context
for the Breaker, and both fail silently on any network error.

---

## The Domain Intelligence Adapter (DIA) — how enrichment works

DIA is the component that assembles all live enrichment (KEV, NVD, and any
custom MCP servers you've configured) into a single block of context appended
to the Breaker's policy prompt before a run starts.

```yaml
# .gauntlex.yml
mcp_servers:
  - name: fin-intel
    url: http://your-internal-threat-intel-server:8090/mcp
    tool: get_finra_threats
    params: { sector: broker-dealer }
    enabled: true

nvd_enabled: true          # opt-in; or just set NVD_API_KEY
nvd_lookback_days: 90      # default
kev_enabled: true          # default — on unless explicitly disabled
```

Order of operations for a single run:

1. Any configured custom `mcp_servers` are called first (JSON-RPC 2.0
   `tools/call`, 10-second timeout each).
2. CISA KEV is queried for the run's CWE set (if enabled — default yes).
3. NIST NVD is queried for the same CWE set (if enabled — default no, unless
   `NVD_API_KEY` is set).
4. All successful responses are concatenated into the Breaker's policy
   context. Any source that errors or times out is dropped silently — a
   network failure never blocks or degrades a run beyond simply not having
   that source's enrichment.

This is the extension point for enterprise-specific live intelligence: point
`mcp_servers` at whatever internal system holds your organization's real-time
threat data (a SIEM, a fraud-detection service, an internal CVE-tracking tool)
and DIA will fold its output into every run the same way it folds in KEV/NVD.

---

## GAUNTLEX as an MCP server vs. GAUNTLEX as an MCP consumer

These are two independent, unrelated MCP relationships that both happen to
exist in GAUNTLEX. Keeping them separate matters:

|  | **GAUNTLEX as MCP server** | **GAUNTLEX as MCP consumer (DIA)** |
|---|---|---|
| Direction | Your IDE calls GAUNTLEX | GAUNTLEX calls an external server |
| Purpose | Let a coding tool trigger and poll adversarial runs | Enrich a run with live external threat data |
| Launch | `gauntlex mcp-server` (stdio) or `gauntlex serve --mcp` (HTTP) | Configured via `mcp_servers:` in `.gauntlex.yml` |
| Tools involved | 5 tools GAUNTLEX exposes (below) | Whatever tool the external server exposes (you choose the tool name in config) |
| Who runs the server | You, alongside your IDE | Whoever operates the threat-intel system (could be your security team, could be a vendor) |

### GAUNTLEX as an MCP server

Exposes 5 tools over stdio (`gauntlex mcp-server`) or HTTP (`gauntlex serve
--mcp`), confirmed supported for local stdio integration with **Claude Code,
Cursor, Windsurf, and Zed**:

| Tool | Purpose |
|---|---|
| `gauntlex_run` | Start an adversarial assessment; returns a `run_id` in under a second |
| `gauntlex_status` | Poll a `run_id` for progress or the final result |
| `gauntlex_vault_stats` | Knowledge Forge / Forge Ledger statistics |
| `gauntlex_policy_list` | List the policy domains available in this project |
| `gauntlex_verify` | Re-derive and confirm the SHA-256 integrity hash of a stored report |

`gauntlex_run` returns immediately and the assessment continues as a
background `asyncio.Task` — necessary because a full run can take anywhere
from under a minute to several minutes depending on mode and model provider,
far longer than MCP's interactive-use expectations.

Separately, `gauntlex integrate` can auto-generate MCP config and CI wiring
for a broader set of platforms — **Claude Code, Cursor, Windsurf, GitHub
Copilot, Codex, and GitHub Actions** — via `--platform <name>` or `--platform
all`. That list is intentionally broader than the raw MCP-server IDE list
above: `integrate` also writes CI workflow files for platforms that don't
speak MCP directly.

### GAUNTLEX as an MCP consumer (DIA)

Covered above — configured entirely under `mcp_servers:`, calling whatever
external MCP tool you point it at.

---

## Policy Hub — community and installable domains

Beyond the 5 built-in domains, two additional domains are available as
installable extras, sourced from this repository's own `policy-hub/` index:

| Domain | Scenarios | Regulatory framework |
|---|---|---|
| `owasp_api_security` | 10 | OWASP API Security Top 10 (2023) — BOLA, BOPLA, SSRF, unsafe deserialization across REST/GraphQL/gRPC |
| `nist_ssdf` | 8 | NIST Secure Software Development Framework v1.1 (PW/RV practices) |

```bash
gauntlex policy hub                       # browse everything in the hub index
gauntlex policy install owasp_api_security
gauntlex policy search "broker dealer"    # search by name, tag, or regulatory framework
```

Installed domains land in `.gauntlex/policies/` and take precedence over a
built-in domain of the same name, which is the intended override mechanism
for organization-specific customization of a shipped playbook.

**Mechanism note:** the hub index is fetched from
`raw.githubusercontent.com/sanjoy1234/gauntlex/main/policy-hub/index.json` —
i.e. it reads directly from this repository's own default branch. That means
`gauntlex policy install` only works once this repository is public on
GitHub with the `policy-hub/` directory present on `main`, which is expected
to be the case going forward.

---

## Bring your own domain

A custom domain is a YAML file with the same schema as the built-in ones —
no code changes required:

```yaml
name: my_custom_domain
version: "1.0"
description: Internal threat model for <your system>
regulatory_framework: <your framework or internal standard>

scenarios:
  - id: custom-001
    cwe: CWE-XXX
    title: Short scenario title
    description: >
      What the Breaker should look for and why it matters for this domain.
    regulatory_ref: <the specific control or rule this maps to>
    example: "a short code-level example of what this looks like"
```

Drop it in `.gauntlex/policies/<name>.yaml` and reference it with `--domain
<name>`. Validate the schema before relying on it:

```bash
gauntlex policy validate .gauntlex/policies/my_custom_domain.yaml
```

This is the same mechanism the 5 built-in domains and the 2 hub domains use —
there is no separate "enterprise" schema or hidden capability gate.

---

## Roadmap domains — not yet available

The following are **not implemented today** — do not configure a run expecting
them:

- **GDPR** — data minimization, right-to-erasure, consent-tracking scenarios
- **FedRAMP** — federal cloud compliance controls (FISMA High baseline)
- **DORA** — EU Digital Operational Resilience Act

If your evaluation depends on one of these, the fastest path today is
[bring your own domain](#bring-your-own-domain) using the same YAML schema —
several of the built-in domains' scenarios overlap in substance (access
control, audit logging, encryption at rest) even where the regulatory
citation differs.

---

## Summary table

| Domain | Status | Scenarios | Live threat data? |
|---|---|---|---|
| `owasp_top10` | Built-in | 12 | Yes — via KEV/NVD (CWE-based, not domain-specific) |
| `finra` | Built-in | 9 | Yes — via KEV/NVD (CWE-based, not domain-specific) |
| `hipaa` | Built-in | 9 | Yes — via KEV/NVD (CWE-based, not domain-specific) |
| `soc2` | Built-in | 7 | Yes — via KEV/NVD (CWE-based, not domain-specific) |
| `pci_dss` | Built-in | 6 | Yes — via KEV/NVD (CWE-based, not domain-specific) |
| `owasp_api_security` | Policy Hub (install) | 10 | Yes — via KEV/NVD |
| `nist_ssdf` | Policy Hub (install) | 8 | Yes — via KEV/NVD |
| GDPR | Roadmap | — | Not available |
| FedRAMP | Roadmap | — | Not available |
| DORA | Roadmap | — | Not available |
| *Your own domain* | Bring-your-own YAML | You define | Yes — same KEV/NVD/custom-MCP enrichment applies to any domain |

"Live threat data" in every row above means the same thing: CISA KEV (always,
free) plus NIST NVD (opt-in, free) plus any custom MCP server you configure —
applied by CWE, not selected per regulatory domain. No domain gets a different
or more privileged live feed than any other; the difference between domains is
entirely in the static scenario content and its regulatory citations.

---

← [Back to README](../README.md) · [Deep Dive](DEEP_DIVE.md)
