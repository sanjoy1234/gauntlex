---
name: gauntlex:report
description: Render a stored GAUNTLEX Resilience Report as Markdown, HTML, or structured JSON. Can attach to a GitHub PR comment.
---

# /gauntlex:report

Renders a stored Resilience Report in the requested format.

## Usage

```
/gauntlex:report --run-id <id> [--format md|html|json] [--post-pr]
```

## Execution

```bash
gauntlex report --run-id "$RUN_ID" --format "$FORMAT"
```

## Output to User

For `--format md`: Show the full Resilience Report in Markdown inline.  
For `--format json`: Show the structured JSON schema.  
For `--format html`: Save to `.gauntlex/reports/<run_id>.html` and show path.

Include the integrity hash at the bottom: `SHA-256: <hash>` — this proves the report has not been altered.

## Compliance Note

Tell the user: "This report can be submitted as evidence for SOC 2 Type II (CC7.1, CC8.1), ISO 27001 (A.14.2.8, A.14.2.9), and NIST SSDF (RV.2.2, RV.3.1, PW.8.1) control requirements."
