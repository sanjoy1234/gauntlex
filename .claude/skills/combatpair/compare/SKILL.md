---
name: combatpair:compare
description: Diff two COMBATPAIR Resilience Reports — shows ARS delta, attack category shifts, new CWE coverage, and whether the codebase is improving or regressing. Returns exit 1 if ARS regression > 0.05.
---

# /combatpair:compare

Compares two COMBATPAIR runs to show security trend.

## Usage

```
/combatpair:compare --run-a <id> --run-b <id>
```

`run-a` = earlier run (baseline), `run-b` = later run (current).

## Execution

```bash
combatpair compare --run-a "$RUN_A" --run-b "$RUN_B"
```

## Output to User

Show a diff table:

| Metric | Run A (baseline) | Run B (current) | Delta |
|--------|-----------------|-----------------|-------|
| ARS | 0.80 | 0.87 | +0.07 ✓ |
| Attacks | 20 | 20 | — |
| Mitigated | 16 | 17 | +1 |
| New CWEs found | — | CWE-362 | new |
| Forge cache hits | 0% | 34% | +34% |

If ARS delta < -0.05: warn "REGRESSION DETECTED — ARS dropped by X. Review unmitigated attacks."
