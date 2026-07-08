---
name: gauntlex:validate
description: Dry-run GAUNTLEX validation — parses the spec, resolves policy playbooks, checks model availability, and runs the AVF golden fixture gate. No attacks are fired. Exit 1 if any check fails.
---

# /gauntlex:validate

Validates the GAUNTLEX environment and spec WITHOUT firing any real attacks.

## Usage

```
/gauntlex:validate [--spec <file>]
```

## Execution

```bash
gauntlex validate --spec "$SPEC_FILE"
```

## What It Checks

1. **AVF gate:** Breaker must find >75% of seeded vulnerabilities in the 5 golden CVE fixtures
2. **Model reachability:** Ollama endpoint (`http://localhost:11434`) or Anthropic API key present
3. **ChromaDB:** Knowledge Forge writable at `.gauntlex/forge/`
4. **Playbook resolution:** All domains listed in `.gauntlex.yml` have corresponding YAML files
5. **Spec parseable:** The spec file (if provided) can be read and is non-empty

## Output to User

Report each check as PASS/FAIL with a reason. If any FAIL:
- Explain the specific failure
- Give the command to fix it (e.g., `ollama pull llama3.1:8b` if model missing)

If all pass: "Environment validated — ready to run."
