---
name: combatpair:learn
description: Ingest a completed COMBATPAIR run into the Knowledge Forge and update the Adaptive Brain's attack effectiveness scores. Call after reviewing a completed run to reinforce learning.
---

# /combatpair:learn

Ingests a run's results into the Knowledge Forge (ChromaDB) and updates the Adaptive Brain.

## Usage

```
/combatpair:learn --run-id <run_id> --outcome pass|fail
```

## Execution

```bash
combatpair learn --run-id "$RUN_ID" --outcome "$OUTCOME"
```

## What It Does

1. Reads `.combatpair/reports/<run_id>.json`
2. Writes each attack into ChromaDB with CWE tag + codebase fingerprint
3. Updates rolling 30-run EMA effectiveness scores per (CWE, fingerprint-cluster)
4. Schedules Breaker prompt rewrite via meta_agent if any CWE < 0.3 effectiveness over 30 runs
5. Prints updated effectiveness summary

## Output to User

- Number of attacks ingested
- Any CWE categories now flagged for prompt rewrite
- Updated top-5 effective attack categories for this codebase type
- "Forge entries: <N> total" — shows the brain is growing
