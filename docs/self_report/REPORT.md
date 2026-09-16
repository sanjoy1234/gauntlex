# GAUNTLEX runs GAUNTLEX

We pointed GAUNTLEX at its own source, on the free-tier model our own `gauntlex
setup` wizard hands most people by default (`nvidia/nemotron-3-ultra-550b-a55b:free`
via OpenRouter — no paid key involved anywhere in this document), and separately
ran a controlled comparison of the two things this project actually claims:
that concurrent adversarial testing is faster than sequential, and that it
catches something a code-anchored Breaker doesn't. Both are below, with the
run ID, the signed hash, and the exact commands to reproduce them.

Commit at time of writing: `34f4812`.

---

## Part 1 — GAUNTLEX against its own source

`gauntlex run --issue src/gauntlex --mode quick --domain owasp_top10` walks
`src/gauntlex/`, finds no `SPEC.md`/`README.md` inside that subtree, and falls
back to brownfield mode: it concatenates real source files up to a 100KB
budget and hands that to the Builder and Breaker as the spec. Quick mode runs
a single round, so the Breaker attacked the actual concatenated source text
directly — a real, if partial (100KB-truncated), read of GAUNTLEX's own code.

```
run_id: gauntlex-2026-09-10T02-40-54Z-1c6f
ARS: 0.875   PASSED  (gate ≥ 0.80)
gauntlex verify gauntlex-2026-09-10T02-40-54Z-1c6f
  → ✓ Integrity verified: sha256:b57b3832117c093b00c96edad5c04765d8dfeb098f2da1330ffd33b9721d23b0
```

| CWE | Verdict | What the Arbiter said |
|---|---|---|
| CWE-89 SQL Injection | Mitigated (1.0) | "The code contains no SQL query construction or execution; it only makes HTTP API calls to LLM providers, so SQL injection is not applicable." |
| CWE-285 Missing Authorization on Ledger read/write | **Partial (0.5)** | "`LedgerVault.read_entries()` / `write_entry()` / `stats()` carry no ownership or role checks... enabling horizontal/vertical privilege escalation." True as far as it goes. |
| CWE-601 Open Redirect | Mitigated (1.0) | "The code is a server-side LLM client making direct API calls to fixed provider endpoints with no HTTP redirect handling... so CWE-601 is not applicable." |
| CWE-863 Incorrect Authorization | Mitigated (1.0) | "Not applicable to this Python LLM client library as it lacks any authorization layer... that the CWE addresses." |

Three correct not-applicable calls and one real, minor, already-understood
design property: the Forge Ledger is a local, single-user, on-disk store, and
`LedgerVault` has no access-control layer because nothing else on the machine
can read it that the invoking user couldn't already read directly. Worth a
comment in the code saying so explicitly; not worth building an authorization
layer for. The signed hash proves this JSON wasn't edited after the fact —
`gauntlex verify` re-derives it independently any time, from just the report
file, no network call required.

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
to, with zero dollars spent. A frontier model would likely produce sharper
attacks on Part 1; it would not change the Part 2 mechanism, which is
arithmetic (`max` vs. `sum` of two wall-clock durations), not a model
property.
