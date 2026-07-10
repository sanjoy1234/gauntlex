# Contributing Playbooks to GAUNTLEX

The Adversarial Policy Engine (APE) is driven by YAML playbooks. Each playbook maps
a regulatory framework to concrete CWE attack scenarios. Contributing a new playbook
extends GAUNTLEX's coverage to a new compliance domain.

---

## Playbook Schema

Each playbook is a YAML file in `src/gauntlex/policy/domains/`. The schema:

```yaml
name: <domain_name>             # e.g. hipaa
version: "<YYYY.N>"             # e.g. "2025.1"
description: <one-line summary>
regulatory_framework: <framework name>

scenarios:
  - id: <domain>-<NNN>          # e.g. hipaa-001
    cwe: CWE-<number>           # must be a valid CWE ID
    title: <short title>
    description: >
      <specific attack scenario description — what to look for,
      what makes it a finding, not just a generic description>
    regulatory_ref: <framework section>  # e.g. HIPAA §164.312(a)(1)
    example: |                  # optional: concrete vulnerable code example
      <code snippet>
```

---

## Validation

Before opening a PR, validate your playbook:

```bash
gauntlex policy validate your_domain_name
```

(the domain name, e.g. `hipaa` — not a file path; it's resolved from
`src/gauntlex/policy/domains/` automatically)

All errors must be resolved. The validator checks:
- Required fields present (`name`, `version`, `description`, `regulatory_framework`, `scenarios`)
- Each scenario has `cwe`, `title`, `description`
- CWE IDs follow the `CWE-<number>` format

---

## Playbook Quality Bar

For a playbook scenario to be accepted:

1. **Specific**: The `description` must name exact code patterns to look for, not just
   the CWE category name. "Look for SQL injection" is not enough. "Find user-controlled
   strings concatenated into `cursor.execute()` or ORM `raw()` calls" is specific.

2. **Actionable**: The Breaker must be able to generate a concrete attack from the
   description without additional context.

3. **Calibrated to AI-generated code**: AI coders make specific mistakes. The scenarios
   should be tuned to patterns that AI code generators produce (e.g., missing input
   validation at API boundaries, hardcoded credentials in configuration code).

4. **Regulatory mapping is accurate**: The `regulatory_ref` must point to an actual
   section in the named framework, not a paraphrase.

---

## Available Playbooks

| Domain | Status | Scenarios |
|--------|--------|-----------|
| `owasp_top10` | ✅ Shipped | 12 |
| `finra` | ✅ Shipped | 9 |
| `hipaa` | ✅ Shipped | 9 |
| `soc2` | ✅ Shipped | 7 |
| `pci_dss` | ✅ Shipped | 6 |

Two more (`owasp_api_security`, `nist_ssdf`) are available via
`gauntlex policy install` rather than bundled by default — see the
[Domain Intelligence](docs/DOMAIN_INTELLIGENCE.md) page for the full,
always-current list and exactly what's live vs. static per domain.

---

## Versioning

Playbook versions follow `YYYY.N` — year + increment. A new version is published
when scenarios are materially changed (not just description fixes). The version is
included in every Resilience Report's `playbook_version` field for audit traceability.

Breaking changes (scenario removal, CWE reassignment) require a minor version bump
and a migration note in `CHANGELOG.md`.

---

## Opening a PR

1. Fork the repository
2. Create your playbook at `src/gauntlex/policy/domains/<name>.yaml`
3. Run `gauntlex policy:validate --file <path>`
4. Add a test in `tests/test_policy.py` that loads your domain
5. Open a PR with the regulatory framework document as a reference link
