---
name: gauntlex:verify
description: Re-derive the SHA-256 integrity hash over a Resilience Report's attack array and confirm it matches the stored hash. Detects tampered reports.
---

# /gauntlex:verify

Re-derives the report's integrity hash and confirms it matches — proves the artifact has not been altered.

## Usage

```
/gauntlex:verify --run-id <run_id>
```

## Execution

```bash
gauntlex verify --run-id "$RUN_ID"
```

## What It Does

1. Reads `.gauntlex/reports/<run_id>.json`
2. Extracts the `attacks` array
3. Re-derives SHA-256 over the JSON-serialized, lexicographically sorted attack array
4. Compares against `integrity_hash` field in the report
5. Exit 0 = match (report is authentic); Exit 1 = mismatch (report tampered)

## Output to User

- PASS: "Report <run_id> integrity verified. Hash matches: sha256:<hash>"
- FAIL: "TAMPER DETECTED. Expected <stored_hash>, computed <derived_hash>. Do not use this report for compliance."
