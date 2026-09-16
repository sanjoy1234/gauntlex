# bench/

Reproducible measurement harnesses, separate from `tests/` (which mocks every
model call) and separate from `research/` (academic, independently scoped).
Everything here makes real model calls and writes its raw output to
`bench/results/` so a claim can be checked against actual JSON, not a
paraphrase of one.

## `concurrent_vs_sequential.py`

Measures the two things GAUNTLEX's core architecture actually claims:
wall-clock speed (concurrent `max(build, break)` vs. sequential
`build + break`) and what a spec-anchored Breaker catches that a
code-anchored one doesn't, on the same spec, same CWE set, same model, one
real run of each arrangement.

```bash
python bench/concurrent_vs_sequential.py --spec examples/demo_issue.md
python bench/concurrent_vs_sequential.py --spec examples/demo_issue.md --runs 5
python bench/concurrent_vs_sequential.py --model nvidia/nemotron-3.5-lightning:free
```

Write-up of one run's results, in Part 2 of [`docs/self_report/REPORT.md`](../docs/self_report/REPORT.md).

Free-tier OpenRouter models queue and occasionally 502 under load — the
script does one honest attempt per invocation and fails loudly rather than
silently retrying or falling back to a mock; wrap it in your own retry loop
if you're scripting unattended runs against a free-tier model.
