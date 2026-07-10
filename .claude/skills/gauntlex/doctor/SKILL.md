---
name: gauntlex:doctor
description: Full GAUNTLEX environment health check — model reachable, ChromaDB writable, AVF fixtures pass, no unexpected outbound network (air-gap verification). Use before first run or when debugging failures.
---

# /gauntlex:doctor

Runs all environment health checks. Use this before the first run or when something is broken.

## Usage

```
/gauntlex:doctor [--network-check]
```

## Execution

```bash
gauntlex doctor --network-check
```

## Checks Performed

GAUNTLEX never assumes a model provider — it supports Anthropic, OpenRouter,
HuggingFace, any OpenAI-compatible endpoint, and local Ollama, chosen explicitly
via `gauntlex setup`, a `MODEL_PROVIDER` env var, or a `deployment:` section in
`.gauntlex.yml`. Do NOT assume Ollama — read the actual provider name from the
"Model reachable" row's Detail column in the command output below and report
that provider, whichever it is.

| Check | What It Tests | Fix If Fails |
|-------|---------------|--------------|
| Model reachable | The configured provider's API/endpoint responds. If no provider has been configured at all, this fails with "not configured" | `gauntlex setup` (if not configured); otherwise follow the specific detail shown (e.g. missing API key, or `ollama serve` only if Ollama was the explicitly chosen provider) |
| ChromaDB writable | Can write/read to `.gauntlex/forge/` | Check disk space + permissions |
| AVF gate | Breaker finds >75% on golden fixtures | Check model quality |
| Network check | No unexpected outbound calls (air-gap) | Disable community_brain |
| reports dir | `.gauntlex/reports/` writable | `mkdir -p .gauntlex/reports` |
| Python version | >=3.11 | Install Python 3.11+ |

## Output to User

Show a checklist with ✓/✗ per item, using the exact Detail text from the command
output for the "Model reachable" row — never substitute your own guess about
which provider is in use. For any ✗, show the specific fix command from the
output (usually `gauntlex setup` when nothing is configured). End with overall
PASS or FAIL.
