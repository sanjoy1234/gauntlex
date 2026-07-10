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
2. **Model reachability:** GAUNTLEX never assumes a provider — it checks whichever provider was explicitly configured (Anthropic, OpenRouter, HuggingFace, OpenAI-compatible, or local Ollama, set via `gauntlex setup`, `MODEL_PROVIDER`, or `.gauntlex.yml`). If nothing is configured, this fails with "not configured — run `gauntlex setup`"
3. **ChromaDB:** Knowledge Forge writable at `.gauntlex/forge/`
4. **Playbook resolution:** All domains listed in `.gauntlex.yml` have corresponding YAML files
5. **Spec parseable:** The spec file (if provided) can be read and is non-empty

## Output to User

Report each check as PASS/FAIL with a reason, using the exact Detail text from
the command output for the model check — do not assume or guess a provider.
If any FAIL:
- Explain the specific failure
- Give the fix command shown in the output (`gauntlex setup` if no provider is
  configured at all; otherwise the provider-specific fix, e.g. `ollama pull
  llama3.1:8b` only if Ollama is the provider actually configured)

If all pass: "Environment validated — ready to run."
