# GAUNTLEX runs GAUNTLEX

We pointed GAUNTLEX at its own source, on the free-tier model our own `gauntlex
setup` wizard hands most people by default (`nvidia/nemotron-3-ultra-550b-a55b:free`
via OpenRouter — no paid key involved anywhere in this document), and separately
ran a controlled comparison of the two things this project actually claims:
that concurrent adversarial testing is faster than sequential, and that it
catches something a code-anchored Breaker doesn't. Both are below, with the
run IDs, the signed hashes, and the exact commands to reproduce them. Where the
free-tier model produced a noisy verdict, we say so and show our work rather
than quietly filtering it out — a self-report that only shows its wins isn't
one you should trust.

Commit at time of writing: `34f4812`.

---

## Part 1 — Two runs against our own source

`gauntlex run --issue src/gauntlex --mode <quick|standard> --domain owasp_top10`
walks `src/gauntlex/`, finds no `SPEC.md`/`README.md` inside that subtree, and
falls back to brownfield mode: it concatenates real source files up to a
100KB budget and hands that to the Builder and Breaker as the spec. Two runs,
same source, same free model, different mode.

### Run 1 — quick mode, single round

```
run_id: gauntlex-2026-09-10T02-40-54Z-1c6f
ARS: 0.875   PASSED  (gate ≥ 0.80)
gauntlex verify gauntlex-2026-09-10T02-40-54Z-1c6f
  → ✓ Integrity verified: sha256:b57b3832117c093b00c96edad5c04765d8dfeb098f2da1330ffd33b9721d23b0
```

Quick mode runs a single round, so the Breaker attacked the actual concatenated
source text directly — this is a real, if partial (100KB-truncated), read of
GAUNTLEX's own code.

| CWE | Verdict | What the Arbiter said |
|---|---|---|
| CWE-89 SQL Injection | Mitigated (1.0) | "The code contains no SQL query construction or execution; it only makes HTTP API calls to LLM providers, so SQL injection is not applicable." |
| CWE-285 Missing Authorization on Ledger read/write | **Partial (0.5)** | The Breaker's real point: `LedgerVault.read_entries()` / `write_entry()` / `stats()` carry no ownership or role checks. True as stated — and also the expected shape of a local, single-user CLI tool's on-disk store, which is what the Forge Ledger is. Worth a comment in the code saying so explicitly; not worth an access-control layer for a file only the invoking user can already read. |
| CWE-601 Open Redirect | Mitigated (1.0) | "The code is a server-side LLM client making direct API calls to fixed provider endpoints with no HTTP redirect handling... so CWE-601 is not applicable." |
| CWE-863 Incorrect Authorization | Mitigated (1.0) | "Not applicable to this Python LLM client library as it lacks any authorization layer... that the CWE addresses." |

Three correct not-applicable calls and one real, minor, already-understood
design property. That's the encouraging half of this report.

### Run 2 — standard mode, four rounds, early exit

```
run_id: gauntlex-2026-09-10T03-40-54Z-776f
ARS: 0.0   BLOCKED  (gate ≥ 0.80)
gauntlex verify gauntlex-2026-09-10T03-40-54Z-776f
  → ✓ Integrity verified: sha256:b9f8f9f06493d398b09845bec4fcf70c33466b73c18b9706695cdd33ce4b46d7
```

A blocked, zero-scoring self-report looks bad at a glance, so we read all four
findings against the actual source before deciding what to say about it. Here
is what's actually in the report.

Standard mode runs multiple rounds, and from round 2 onward the Breaker
attacks that round's fresh Builder output, not the original 100KB source dump
(see `core/gauntlex.py` — this is deliberate, it's how GAUNTLEX refines against
feedback in real spec-driven runs). Pointed at a single-file spec that's
normal. Pointed at a multi-file codebase concatenated into one blob, the
Builder's per-round output is its own attempted reproduction of *something* in
that blob, and by round 2+ the Breaker and Arbiter are no longer looking at
the same files the attack text references.

The Arbiter's own reasoning says exactly this, every time:

| CWE | Verdict | The Arbiter's stated reason |
|---|---|---|
| CWE-94 Code injection via `eval` in the AVF gate hook | Missed (0.0) | "The code under review (BaseAgent) is an LLM HTTP client and contains no subprocess calls, eval, or shell command execution; the attack targets a different file (`hooks/avf_gate.py`) not provided." |
| CWE-352 Missing CSRF on the MCP HTTP endpoint | Missed (0.0) | "The provided code is a client library (BaseAgent) for making LLM API calls, not the MCP HTTP server endpoint (`serve/app.py`) described in the attack; it contains no server-side CSRF protection logic." |
| CWE-1321 Prototype pollution in Breaker template merging | Missed (0.0) | "This code is an LLM client (BaseAgent) and does not handle template merging, Breaker agent logic, or JavaScript/TypeScript code generation; the vulnerability resides in a different component (Breaker agent) and is not mitigated here." |
| CWE-798 Hard-coded default Ollama endpoint | Missed (0.0) | "The BaseAgent class hard-codes a default Ollama endpoint (`http://localhost:11434`) with no authentication or validation..." |

We independently checked each of these against the real source rather than
taking the Arbiter's word for it:

- **CWE-94** — there is no `eval(` anywhere in `src/gauntlex/`. The only place
  `eval()` appears at all is as a category description inside
  `data/cwe_taxonomy.json` and `brain/language_profiles.py` — reference text
  the Breaker's prompt included, not code it found. Not a real finding.
- **CWE-352** — `serve/app.py`'s MCP endpoint (`handle_http_request` in
  `mcp/server.py`) is a stateless JSON-RPC POST handler with no cookie or
  session auth anywhere in `service/` or `dashboard/` — nothing for a forged
  cross-site request to ride on. CSRF requires ambient browser credentials
  that this endpoint doesn't have. Not a real finding.
- **CWE-1321** — `agents/breaker.py` has no template-merge logic at all; we
  grepped for it and found nothing. This one is also describing a downstream,
  hypothetical JS/TS target the Breaker itself would generate for someone
  else's project, two steps removed from GAUNTLEX's own code. Not a real
  finding.
- **CWE-798** — this one's real and on-target: `agents/base.py` does default
  `ollama_endpoint` to `http://localhost:11434` with no authentication. It's
  mistagged (CWE-798 is hard-coded *credentials*; there's no credential here,
  just an unauthenticated local default) and it's the correct, intentional
  shape for GAUNTLEX's air-gapped/local-Ollama mode — but "should the default
  silently trust anything answering on localhost:11434" is a fair question we
  didn't have a documented answer to before this report. It's now a tracked
  discussion, not a shipped fix disguised as one.

So: three of four standard-mode findings are the Breaker and Arbiter talking
past each other across a self-scan-specific edge case (a single-file spec
model applied to a many-file blob), not vulnerabilities. One is real, mistagged,
and minor. The signed hash on this report proves the JSON wasn't edited after
the fact — it does not by itself prove every LLM verdict inside it was
correct, which is exactly the caveat already in our [Deep Dive
FAQ](../DEEP_DIVE.md#faq) about the Arbiter, and exactly what `--consensus`
exists to reduce. We ran these single-shot (`consensus_samples=1`) — a
`--consensus 3` re-run would very likely have surfaced the CWE-94/352/1321
target mismatches directly as low-agreement findings instead of us reading the
JSON by hand. That's the honest reading of a 0.0 self-report: not "our code
failed four attacks," but "brownfield self-scan on a multi-file blob is a
rougher edge of this tool than a real spec, and here's exactly where it got
confused, in its own words."

---

## Part 2 — What a concurrent Breaker catches that a sequential one doesn't

This is the actual architectural claim, isolated from everything else GAUNTLEX
does: point a Builder and a Breaker at the same spec, once running
concurrently (Breaker attacks the spec, before any code exists to anchor or
hide behind), once sequentially (Builder finishes, *then* the Breaker attacks
whatever came out) — same spec, same fixed CWE set, same model, one real run
each. Harness: [`bench/concurrent_vs_sequential.py`](../../bench/concurrent_vs_sequential.py),
raw output: [`bench/results/cvs-2026-09-16T01-36-23Z.json`](../../bench/results/cvs-2026-09-16T01-36-23Z.json).

Spec: `examples/demo_issue.md` — a Flask `/login` endpoint (bcrypt password
check, JWT on success, audit logging, rate limiting). CWE set fixed at
CWE-89 (SQLi), CWE-79 (XSS), CWE-287 (Improper Authentication), CWE-306
(Missing Authentication for a Critical Function) — the same four categories,
attacked two different ways.

### Timing

|  | Wall clock |
|---|---|
| Concurrent (Builder ‖ Breaker on the spec) | **69.3s** |
| Sequential (Builder, then Breaker on the code) | **178.1s** |

2.57x faster, 108.8 seconds saved on four attacks against one small spec — the
gap scales with attack count and spec size, not a fixed constant, because it's
literally `max(a, b)` against `a + b`.

### What each one found

Both Breakers were scored against the same generated login implementation.
Sequential came back with a clean **ARS of 1.0** — every attack mitigated.
Concurrent came back at **0.75** — three mitigated, one missed. The missed
one is the point:

> **CWE-287, concurrent (spec-only) Breaker:** "JWT Algorithm Confusion Attack
> (RS256 to HS256)." Arbiter's verdict — **missed**: "The code only implements
> JWT token generation (HS256) but lacks any token verification logic;
> algorithm confusion attacks target verification, which is absent."

The concurrent Breaker, reasoning from "returns a JWT token on success," attacked
the part of a JWT auth flow that has to exist somewhere eventually —
*verifying* the token on a later request — and the Arbiter confirmed that
verification logic doesn't exist anywhere in what got built. That's a real,
shippable gap: a login endpoint that hands out tokens nobody ever checks.

The sequential Breaker, looking at the same generated code, spent its CWE-287
attack on a different guess:

> **CWE-287, sequential (code-anchored) Breaker:** "Hardcoded default JWT
> secret enables token forgery." Arbiter's verdict — **mitigated**: "The
> `JWT_SECRET` defaults to a cryptographically random value generated at
> startup via `os.urandom(32).hex()`... preventing token forgery via known
> default secrets."

That's a real thing to check, correctly ruled out — and it's also the
generic, textbook version of "something's wrong with this JWT," the kind of
guess a Breaker makes when it can only see what's in front of it and nothing
in front of it hints that a whole verification step is missing. A sequential
pipeline scored this run 1.0 and would have shipped it. GAUNTLEX's own gate
would have blocked it at 0.75, for the actual reason, before the sequential
pipeline finished running.

We're publishing this as one clean, unedited run rather than a cherry-picked
best-of-N — the raw JSON is linked above and `bench/concurrent_vs_sequential.py
--runs 5` (or any N) reproduces the comparison end to end, including a fresh
speedup number, on whatever model you point it at.

---

## Reproduce this yourself

```bash
git clone https://github.com/sanjoy1234/gauntlex
cd gauntlex && pip install -e . && gauntlex setup

# Part 1 — GAUNTLEX against its own source
gauntlex run --issue src/gauntlex --mode quick --domain owasp_top10 --pretty
gauntlex verify <run_id>          # re-derive the SHA-256, confirm nothing was edited

# Part 2 — concurrent vs. sequential, same spec, your model
python bench/concurrent_vs_sequential.py --spec examples/demo_issue.md --runs 3
```

Every number above came from the free-tier model GAUNTLEX defaults new users
to, with zero dollars spent and zero cherry-picking — including the run that
scored 0.0. A frontier model would likely score higher and hallucinate less
on Part 1; it would not change the Part 2 mechanism, which is arithmetic
(`max` vs. `sum` of two wall-clock durations), not a model property.
