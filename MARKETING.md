# GAUNTLEX — Marketing & Launch Plan

**Owner:** Sanjoy Ghosh · **Last updated:** 2026-07-11 · **Status:** v2 — revalidated and enhanced against one explicit lens: *durable memorability, zero cost, collaboration/feedback velocity, and personal brand compounding.*

**Purpose:** Living reference doc. Paste this whole file (or point Claude at this path) at the start of any future session to resume marketing work with full context. This supersedes the 2026-07-10 v1 plan — v1's channel tables and tactical rules were reviewed and are still accurate; what's new is in §1–§6 below, and small corrections are folded into the existing sections.

---

## 0. How to use this document

Same convention as before: every action item is tagged 🤖 **Claude does** (I draft, research, build, or execute directly) or 👤 **You do** (needs your account, voice, judgment, or approval before it's externally visible). Nothing here requires a paid subscription or budget — every channel and tactic below is free. Update the **Status** columns as things move and add to the **Log** at the bottom every time something ships.

---

## 1. What changed since v1 — the honest revalidation

v1 was a solid, correctly-scoped channel checklist: accurate HN/PH mechanics, a sensible audience order, free-only discipline throughout. It would generate a respectable launch-day spike. It was not, on its own, built to be *remembered* — there was no single asset designed to be inherently shareable independent of "here's a new tool," no explicit collaboration home, and no track for your own name to compound past this one launch. Those are the gaps this revision closes. Everything else from v1 — the four narrative angles, the audience priority order, Tier 1–3 channels, the 90-day skeleton, the capability split, the metrics — held up and is carried forward with small factual corrections (marked inline).

**The single biggest miss in v1:** every channel entry answers "where do we post about GAUNTLEX," but none of them answer "what does GAUNTLEX *produce* that people want to share on its own." Tools get a launch-day spike. Ongoing, original research gets cited, linked, and re-shared for months — that's the difference between a good Show HN and something people still reference next year.

---

## 2. The flagship asset — give people something to share, not just read

### 2.1 The AI Model Resilience Index (primary recommendation)

**The idea:** GAUNTLEX already scores how well generated code survives adversarial testing. Point that at the question every developer in this space is quietly wondering right now: *which AI model writes the most secure code by default?* Run the same handful of intentionally risk-prone specs (an auth endpoint, a file-upload handler, a raw SQL query builder — the classic OWASP-magnet patterns) through several current models as the Builder, score each resulting implementation with GAUNTLEX's own Arbiter, and publish the ranked result as a public leaderboard with a short written analysis.

**Why this is the right flagship, specifically for you, specifically now:**
- **It's original research, not a product pitch.** "We built a tool" is forgettable. "GPT-5-class models missed 3x more injection attacks than Claude in our test" is a stat people screenshot and argue about. That argument *is* the buzz.
- **It's comparison, and comparison is the most reliably shareable content format there is** — rankings, benchmarks, and "X vs Y" posts outperform feature announcements on every channel in this plan (HN, Twitter, Reddit, LinkedIn) by a wide margin, consistently.
- **It's recurring, not one-off.** Re-run it monthly as models update ("AI Model Resilience Index — August 2026 edition") and you have a standing reason to post again, get cited again, and pull people back — the single highest-leverage fix for "remembered for a long time" in this entire plan.
- **It costs nothing.** OpenRouter's free tier alone covers several current open models; comparing what's reachable for free is itself a defensible, honest framing (no claim about paid frontier models you haven't actually run).
- **It directly demonstrates the product.** Every visitor who reads the leaderboard is looking at real GAUNTLEX output — no separate "trust us" gap between the marketing claim and the tool.
- **It's ethically clean.** You're scoring *models*, which are products from well-resourced companies fully expecting to be benchmarked — not some stranger's weekend GitHub project, which would read as punching down and could plausibly generate the wrong kind of buzz.

**🤖 Claude does:** Design 2–3 shared adversarial specs (I'll draft these to be realistic and genuinely risk-prone, not rigged). Run each through a defensible list of free/accessible OpenRouter models as the Builder. Score every resulting implementation with the existing Arbiter — this is exactly what the engine already does, just pointed at multiple models instead of one. Generate the static leaderboard via the `gauntlex leaderboard` command that already exists. Write the accompanying analysis post (the "state of AI code security" writeup). Design the page to match the existing dashboard theme.

**👤 You do:** Approve the exact model list before it's public — a claim that compares named commercial models by name should get your eyes on it before it ships, even though I can build the whole thing. Decide the cadence (I'd suggest monthly). Post the launch of it, same as any other content.

**Where it slots into the plan:** Build it in Weeks 1–2, *before* Show HN and Product Hunt — so those launch posts link to a live, populated leaderboard instead of just a README. This is the single highest-leverage sequencing change in this revision.

### 2.2 "GAUNTLEX red-teams itself" (secondary, low-effort, high trust)

A one-line but disproportionately effective trust signal: run GAUNTLEX against its own specification, and link the resulting Resilience Report — SHA-256 integrity hash and all — directly in the README and every launch post. Security tools that market themselves without showing their own receipts read as marketing; one that hands you a tamper-evident report on itself reads as credible. Near-zero effort — this is one `gauntlex run` command and a link.

**🤖 Claude does:** Run it, publish the report link, add a "we tested ourselves — verify it yourself with `gauntlex verify`" line to the README and launch copy. **👤 You do:** Nothing beyond a sanity check on the result before it's public.

---

## 3. Community & collaboration loop — you asked for this explicitly, v1 didn't have it

You said the goal is people collaborating, giving feedback, engaging — not just installing. v1 never actually designated *where* that happens. Fixing that:

- **Enable GitHub Discussions** and make it the one explicit home for feedback, questions, and "I built X with this" show-and-tell — link it from the README header, every social post's CTA, and the Show HN/PH copy. Right now there is no owned space for conversation to land; issues aren't it (they're for bugs, and treating them as the general forum drives away casual feedback).
- **Seed 3–5 real "good first issue" labels** on approachable, genuinely useful work (a missing language profile, a policy domain gap, a docs improvement) — a repo with zero labeled entry points silently tells contributors "don't bother."
- **A visible Contributors table** — even a short one, updated as people show up. Recognition is the cheapest retention mechanic that exists and costs nothing to maintain.
- **Every piece of content ends with one specific, low-friction ask** — not "check it out" (which asks for nothing and gets nothing), but something concrete: *"reply with the worst security bug your AI coding assistant ever shipped you"* or *"try it against your own repo's spec and tell me what it finds."* Specific asks get specific responses; vague CTAs get silence.
- **The "Powered by GAUNTLEX" badge** (carried over from v1 §4.14) is the long-run compounding version of this same idea — every adopting repo becomes a small, permanent ad. Worth prioritizing earlier than v1's "multi-week, not launch-week" framing suggested, precisely because it's a collaboration mechanic, not just a growth one: it's the visible proof other people are actually using and trusting this.

**🤖 Claude does:** Enable Discussions via `gh` CLI (with your approval — it's a repo-visible setting change), draft the good-first-issue candidates and label them, build the Contributors table, bake the specific-CTA discipline into every drafted post. **👤 You do:** Approve enabling Discussions, actually respond in there once people show up (this is the part that can't be delegated — a maintainer who never replies in their own Discussions tab is worse than not having one).

---

## 4. Personal brand track — a second, parallel content stream

v1's entire content calendar is product-news-shaped: launch posts, feature posts, "we shipped this" posts. That builds awareness of GAUNTLEX. It does comparatively little for *you*, specifically, being the person people think of when this topic comes up — and that recognition is what actually compounds past this one launch into whatever you build next.

**The fix: run two tracks, not one.**

| Track | Content | Cadence | What it builds |
|---|---|---|---|
| **Product** (v1's existing plan) | Launch posts, feature announcements, the Resilience Index | Tied to ship events | GAUNTLEX awareness |
| **Field Notes** (new) | Short, opinionated, single-observation posts on AI-generated code security — patterns you're actually seeing, not framed as a GAUNTLEX ad. The tool shows up as evidence for a claim, not the headline. | ~Weekly, decoupled from any release | *Your* authority — independent of whether someone has heard of GAUNTLEX yet |

Field Notes is the more durable of the two. A launch post's relevance has a half-life of days; a genuinely sharp observation about a real pattern in AI-generated code gets referenced any time the topic comes up, for as long as the pattern stays true. This is also the lower-effort track once it's running — it doesn't require a ship event to justify a post, so it fills the gaps between v1's launch-driven content calendar.

**A rallying line:** worth having one short, ownable phrase that people can repeat independent of the tool name — the way "move fast and break things" or "shift left" outlived their origin. Three directions, your call on tone (I can't invent this authentically for you, same as the origin story):
- *"Code ships in seconds. Attacks should too."*
- *"If the AI wrote it in 30 seconds, the attack surface should be tested in 30 seconds."*
- *"Adversarial by default."*

**🤖 Claude does:** Draft the Field Notes post series (I can mine real patterns from the AVF golden fixtures, the CWE taxonomy, and general AI-code-security research), propose 2–3 rallying-line options as above. **👤 You do:** Pick or rewrite the rallying line in your own words, add your actual voice/opinion to each Field Notes draft before it posts (this track specifically fails if it reads as AI-generated — it's supposed to be *you*), post everything yourself.

---

## 5. Reactive coverage — newsjacking, done carefully

When a real AI-generated-code security incident or CVE breaks publicly, being one of the first credible voices connecting it to your exact thesis is disproportionately effective compared to any scheduled post — it's timely, it's relevant, and it rides existing attention instead of trying to create its own.

**🤖 Claude does:** On request, monitor for relevant incidents via web search and flag candidates with a one-paragraph brief on the angle. **👤 You do:** The actual reactive post has to be fast and has to be yours — by the time a draft goes through review-and-approve, the moment's usually gone. Best approach: keep this as an on-demand capability you can pull the trigger on, not a scheduled item.

---

## 6. Short-form video — a channel v1 didn't include at all

You already have a 2:43 demo video built from real screenshots. A 30–45 second vertical cut of the single most visual moment (Builder and Breaker racing concurrently, or the live ARS gate blocking a merge) is a genuinely different discovery surface from everything else in this plan — YouTube Shorts, TikTok, Instagram Reels, and LinkedIn video all have algorithmic reach that doesn't depend on an existing following, unlike Twitter/LinkedIn text posts. Free, and it reuses an asset you've already paid the production cost for.

**🤖 Claude does:** Identify the strongest 30–45s segment from the existing demo footage, cut and caption it (burned-in captions — most short-form video is watched muted), format for vertical (9:16). **👤 You do:** Upload to your own accounts (same authenticated-human-presence constraint as everything else), same platforms you confirm you have below.

---

## 7. Positioning (carried over from v1, unchanged)

**Core thesis:** "AI coding tools generate code faster than any human ever could. Nobody generates the security testing at the same speed — it's still bolted on after, by a human, if at all. GAUNTLEX closes that gap: it generates the attack at the exact same instant it generates the code."

| Angle | Best for | One-liner |
|---|---|---|
| The speed gap | HN, Twitter, general dev audience | "Your AI pair programmer ships code in 30 seconds. Your security review takes 3 days. GAUNTLEX makes them the same speed." |
| TDD for security | Engineering managers, LinkedIn | "You wouldn't ship code without tests. Why ship AI-generated code without adversarial tests? GAUNTLEX is red-teaming as a CI gate." |
| Compliance-as-code | FinTech/HealthTech, LinkedIn, enterprise | "HIPAA and FINRA audits shouldn't be a fire drill every quarter. GAUNTLEX gates every PR against your compliance domain, automatically." |
| Novel architecture | HN, r/MachineLearning, academic/research | "Builder and Breaker run concurrently via `asyncio.gather()` — the attack surface is reasoned from the spec alone, before the implementation exists." |
| **The Resilience Index** *(new)* | Everywhere — this is the one with a hard number attached | "We ran the same spec through N AI models and scored what came back. Here's which ones actually write secure code by default." |

**Your personal story still matters more than the product spec** — this is unchanged and still the single most important missing input (see §9).

---

## 8. Target audiences (carried over from v1, unchanged)

1. **AI-native developers** — living in Claude Code / Cursor / Copilot / Codex, worried (or should be) about what their AI just shipped
2. **AppSec / DevSecOps engineers** — the people whose job GAUNTLEX makes easier, not harder
3. **Engineering leadership at fast-moving startups** — CTOs/VPEng shipping AI-generated code without a security net
4. **Compliance-heavy orgs** — FinTech, HealthTech, anyone who has said "SOC 2" or "HIPAA" out loud in a board meeting
5. **MCP ecosystem builders** — smaller but extremely high-intent, actively browsing MCP servers right now

---

## 9. Asset inventory — corrected as of 2026-07-11

| Asset | Status | Notes |
|---|---|---|
| Public GitHub repo, MIT license | ✅ Have | github.com/sanjoy1234/gauntlex |
| PyPI package (`gauntlex-ai`) | ✅ Have | **Live at v1.0.1** — published 2026-07-10, verified installable |
| Demo video (2:43) | ✅ Have | Source for the new short-form cuts in §6 |
| Overview one-pager / slides | ✅ Have | `docs/media/GAUNTLEX_Overview.pdf` |
| README with badges, quickstart, architecture | ✅ Have | Strong landing page for HN/PH traffic; test-count badge now current (612 passing) |
| Live dashboard + leaderboard | ✅ Have | Already built — this is the exact engine the Resilience Index (§2.1) reuses |
| **AI Model Resilience Index** | 🤖 To build | New — see §2.1, this is the launch centerpiece |
| **GitHub Discussions** | 👤 To enable | Not currently on — see §3, needs your approval to flip on |
| Show HN post copy | 🤖 To draft | See §11.1 (was §5.1) |
| Product Hunt listing copy | 🤖 To draft | Tagline (≤60 chars), gallery images, maker comment |
| Twitter/X thread(s) | 🤖 To draft | Now split: Product track + Field Notes track (§4) |
| LinkedIn post(s) | 🤖 To draft | Compliance angle for Product track; Field Notes runs here too |
| Blog posts (dev.to) | 🤖 To draft | 2–3 posts, see §11.5 |
| Short-form video cuts | 🤖 To produce | New — see §6 |
| Podcast pitch emails | 🤖 To draft (Gmail drafts) | See §11.7 |
| Newsletter submission emails | 🤖 To draft (Gmail drafts) | See §11.6 |
| Social graphics / OG cards | 🤖 To design | HTML → headless-Chrome screenshot, same technique as the demo video |
| Rallying line | 👤 Need your pick | See §4 — three options drafted, needs your voice |
| Your one-sentence origin story | 👤 Need from you | Still the single most important missing input |
| Twitter/X, LinkedIn, dev.to, Product Hunt, Reddit, YouTube/TikTok accounts | 👤 Confirm you have these | Tell me which exist already vs. need creating |

---

## 10. Channel playbook

*(v1's Tier 1–3 channel tables, tactics, and platform-specific rules were reviewed against current information and are unchanged — reproduced here for completeness so this file is the single reference going forward.)*

### Tier 1 — Do these first (highest leverage, lowest cost, targeted audience)

**10.1 MCP Registries & Directories** — *Cost: Free · Reach: Highly targeted · Effort: Low*

Since GAUNTLEX already ships an MCP server, this is the highest-intent, lowest-effort channel available — submit once, indexed forever.

| Directory | URL | Notes |
|---|---|---|
| Official MCP Registry | registry.modelcontextprotocol.io | Backed by Anthropic, GitHub, Microsoft. Reverse-DNS naming (`io.github.sanjoy1234/gauntlex`). CLI-based publish. |
| Glama | glama.ai/mcp | Auto-indexes public GitHub MCP servers — may already have picked you up; verify and claim. |
| Smithery | smithery.ai | CLI publish: `smithery mcp publish` |
| PulseMCP | pulsemcp.com/servers | 18,000+ servers, updated daily |
| mcp.so | mcp.so | Large community directory |
| awesome-mcp-servers (wong2) | github.com/wong2/awesome-mcp-servers | PR to add an entry |
| awesome-mcp-servers (punkpeye) | github.com/punkpeye/awesome-mcp-servers | PR to add an entry |
| awesome-devops-mcp-servers | github.com/rohitg00/awesome-devops-mcp-servers | PR to add an entry (DevSecOps angle fits) |

🤖 **Claude does:** Draft the `server.json`/registry metadata, run CLI publish commands where I have shell access, open PRs to awesome-lists matching their existing format. 👤 **You do:** Approve each PR before it opens (external, visible), verify/claim the Glama auto-listing (GitHub-authenticated click), confirm which registries require email verification only you can complete.

**10.2 Security-focused Awesome Lists** — *Cost: Free · Reach: High among AppSec practitioners · Effort: Low*

| List | URL |
|---|---|
| Awesome-AI-For-Security | github.com/AmanPriyanshu/Awesome-AI-For-Security |
| Awesome-LLMSecOps | github.com/wearetyomsmnv/Awesome-LLMSecOps |

🤖 **Claude does:** Draft and open PRs. 👤 **You do:** Approve each.

**10.3 tl;dr sec Newsletter** — *Cost: Free · Reach: 90,000+ AppSec engineers, arguably your single best-fit audience anywhere · Effort: Low*

Curated by Clint Gibler (Head of Cyber at OpenAI). GAUNTLEX is exactly on-topic.

🤖 **Claude does:** Draft a short, no-hype submission email as a Gmail draft. 👤 **You do:** Find the current submission address (may require a contact form or Twitter DM), review, send.

**10.4 TLDR Newsletter (AI / DevOps / InfoSec editions)** — *Cost: Free · Reach: 300–400K readers/edition · Effort: Low*

🤖 **Claude does:** Draft three tailored pitches (TLDR AI, TLDR DevOps, TLDR Infosec — different angle each, per §7) as Gmail drafts. 👤 **You do:** Submit via the current web forms on tldr.tech.

**10.5 Show HN** — *Cost: Free · Reach: Very high if it lands · Effort: Medium, high-stakes*

Rules that still apply: title format `Show HN: GAUNTLEX – Generates code and adversarial security tests at the same instant`; no superlatives; post Tuesday–Thursday, 9 AM–12 PM ET; never ask for upvotes (fraud detection penalizes it); **HN bans AI-generated/AI-edited comments** — I draft the initial post, every comment reply must be written by you, live; respond to comments in the first 60 minutes, this drives ranking.

🤖 **Claude does:** Draft post title + body (link to repo, one paragraph on what/why, link to the Resilience Index and the demo video). Draft anticipated objections and responses as prep notes. 👤 **You do:** Post from your own account with real karma history, write every comment reply yourself for at least the first 2 hours.

**10.6 Product Hunt** — *Cost: Free (boost is optional, not recommended for a first launch) · Reach: High, permanent searchable page · Effort: Medium-high, ~1-2 weeks prep*

Free to submit and be featured. Submit 12:00–1:00 AM PST, Tuesday or Wednesday. Self-hunting is fine. Tagline ≤60 characters, no emojis in the name field.

🤖 **Claude does:** Draft tagline, full description, maker's first comment, design 3–5 gallery images/GIFs (screenshot the live dashboard, leaderboard, and Resilience Index). 👤 **You do:** Confirm your maker profile isn't brand-new, submit at the right time, be present to reply all day.

**Sequencing note:** keep Show HN and Product Hunt 1–2 weeks apart so each gets its own wave and you have bandwidth for both.

### Tier 2 — Strong ongoing channels, build over weeks not days

**10.7 Reddit** — *Cost: Free · Effort: Low per post, rules vary by subreddit*

| Subreddit | Fit | Self-promo policy (verify before posting) |
|---|---|---|
| r/programming | General dev, huge reach | Generally allows genuinely interesting tool posts, not link-spam |
| r/netsec | AppSec-specific | Strict — original technical content only |
| r/cybersecurity | Broader security | Moderate — check current rules |
| r/devops | DevSecOps angle | Moderate |
| r/MachineLearning | Architecture/research angle | Very strict — frame as "I built X, here's the design," not a launch post |
| r/ClaudeAI, r/cursor | MCP integration angle | Community-specific, cares about "what works with my tool" |
| r/ExperiencedDevs | Engineering-leadership angle | Skeptical of tool posts, needs a genuine discussion angle |

🤖 **Claude does:** Draft a tailored post per subreddit (never the same copy pasted everywhere), check current self-promotion rules before you post. 👤 **You do:** Post from your own account, engage in comments.

**10.8 Twitter/X** — *Cost: Free · Reach: Compounds over time · Effort: Ongoing*

🤖 **Claude does:** Draft the content calendar across both tracks (§4) — architecture deep-dive, "why I built this," launch-day thread, weekly Field Notes. Design graphics for each. 👤 **You do:** Post everything (authenticity matters enormously — bot-flavored posting is instantly recognizable), reply to replies.

**10.9 LinkedIn** — *Cost: Free · Reach: Best for engineering leadership / compliance buyers · Effort: Low-medium*

🤖 **Claude does:** Draft long-form posts — compliance-as-code angle for Product track, Field Notes for the personal-brand track. 👤 **You do:** Post, engage.

**10.10 dev.to / Hashnode** — *Cost: Free, huge built-in distribution · Effort: Medium, compounds via SEO forever*

Suggested series: (1) "Why I built an adversarial co-generation engine" — origin story + architecture, (2) "The Adversarial Resilience Score: a new metric for AI-generated code," (3) "How GAUNTLEX gates HIPAA/FINRA compliance in CI," (4) *new* — "We benchmarked N AI models on adversarial resilience — here's what we found" (the Resilience Index writeup).

🤖 **Claude does:** Write full draft posts, cross-post-ready for dev.to and Hashnode. 👤 **You do:** Review, add your voice/story, publish under your own account.

**10.11 GitHub Discoverability** — *Cost: Free · Effort: Low, one-time*

🤖 **Claude does:** Verify/add GitHub Topics (`ai-security`, `mcp-server`, `devsecops`, `llm-security`, `adversarial-testing`, `sast`), enable Discussions (§3). 👤 **You do:** Approve via `gh` CLI confirmation.

### Tier 3 — Higher effort, higher payoff, needs your voice/presence

**10.12 Podcasts** — *Cost: Free · Effort: High (your air time), pitching is low-effort*

| Podcast | Fit |
|---|---|
| Latent Space (AI Engineer Podcast) | Best fit — AI engineering audience, covers MCP, confirmed to accept pitches |
| Application Security Podcast | AppSec-specific audience |
| The Changelog | General dev, open-source-friendly |
| Software Engineering Daily | Technical deep-dive format |

🤖 **Claude does:** Draft a pitch email per show as a Gmail draft, tailored with a 2-sentence hook + 3 discussion angles (the Resilience Index is a strong new angle here — it's a data-backed hook, not just a product pitch). 👤 **You do:** Review, send, do the interview.

**10.13 Conference / Meetup CFPs** — *Cost: Free to submit · Effort: Medium (abstract) + high (talk)*

Targets: local BSides chapters, OWASP local chapters, Python/AI meetups in your city.

🤖 **Claude does:** Draft CFP abstracts once you identify target events; can research current open CFPs. 👤 **You do:** Submit, prepare, present.

**10.14 "Powered by GAUNTLEX" badge** — *Cost: Free · Effort: Low to build, compounds automatically*

See §3 — reframed here from v1 as a collaboration mechanic, not just growth.

---

## 11. What I can build for you directly (unchanged capability list from v1, still accurate)

- Draft every piece of written copy in this plan
- Create actual Gmail drafts in your inbox, ready to review and send
- Design social graphics and OG cards (HTML → headless-Chrome screenshot)
- Run the AI Model Resilience Index end-to-end — spec design, multi-model generation, scoring, publishing (§2.1)
- Open GitHub PRs to awesome-lists and registries via `gh` CLI, with your approval on each
- Research current submission processes for any channel so we're never guessing at a stale process
- Track this document and its Log as things ship

**What I categorically cannot do:** post to your personal accounts, DM anyone as you, or take any action requiring your authenticated human presence on a third-party platform.

---

## 12. Revised 90-day sequencing

**Weeks 1–2 — Foundation, no public launch risk yet**
- MCP registries + awesome-list PRs (§10.1, §10.2)
- GitHub Topics + enable Discussions (§10.11, §3)
- **Build v1 of the AI Model Resilience Index** *(new — this needs to exist before HN/PH so the launch links to it)*
- Finalize your origin story and rallying line with me (§7, §4)
- Draft all Tier 1 copy so it's ready to go

**Weeks 3–4 — Content warm-up, both tracks running**
- Publish first dev.to post (architecture deep-dive)
- Start Field Notes track on LinkedIn + Twitter (§4) — no "launch" framing, just build a small audience before launch day
- Submit to tl;dr sec and TLDR newsletters (§10.3, §10.4)
- Cut and post the first short-form video clip (§6)

**Week 5 — Show HN**
- Tuesday or Wednesday morning ET, link directly to the live Resilience Index
- Full-day availability

**Weeks 6–7 — Product Hunt** *(separate week from HN)*
- Coordinate with a LinkedIn/Twitter push same day, gallery includes Resilience Index screenshots
- Full-day availability

**Weeks 8–12 — Sustained**
- Reddit posts, spaced out, tailored per subreddit
- Podcast pitches sent, interviews as they land
- Second/third dev.to posts (compliance angle, Resilience Index deep-dive)
- **Refresh the Resilience Index** for the first time — this is the moment that tests whether the recurring-asset thesis actually works
- Start tracking which channel drove stars/installs (§13) and double down on what's working

---

## 13. Metrics to track (unchanged from v1)

- GitHub stars/forks (leading indicator, easy to game, don't over-index)
- PyPI download count (`pip install gauntlex-ai`) — better signal than stars
- Referrer traffic on the repo (GitHub Insights → Traffic tab, free)
- HN/PH position and comment engagement on launch days
- Newsletter/podcast placements landed (binary — did it run or not)
- *(new)* Resilience Index citations/backlinks — the specific signal that tells you whether the flagship-asset thesis in §2 is working

---

## 14. What I need from you — the complete, minimal list

Everything else in this plan I can execute or draft without waiting on you. These six are the actual blockers:

1. **Your one-sentence origin story** — what made you build this. Still the single most important input; I can't invent it authentically.
2. **Which accounts you already have** — Twitter/X, LinkedIn, dev.to, Product Hunt maker profile, Reddit, YouTube/TikTok.
3. **Sign-off on the Resilience Index model list** — I'll propose a default set of free/accessible models; a public claim comparing named commercial products should get your eyes on it before it ships.
4. **Approval to enable GitHub Discussions** — one repo setting, I'll do it via `gh` CLI once you say go.
5. **Your pick (or rewrite) of a rallying line** — three options drafted in §4, or tell me it's not you and we skip it.
6. **Your voice on the Field Notes drafts** — I'll write the first-pass observations, but this track specifically fails if it doesn't sound like you.

Tell me these and I start building — the Resilience Index and the Tier 1 registry/awesome-list submissions can begin immediately, before any of the others are resolved.

---

## Log

*(Add an entry every time something ships, so future-you and future-Claude have the real history, not just the plan.)*

- **2026-07-10** — v1 plan created.
- **2026-07-11** — v2: revalidated against memorability/collaboration/personal-brand lens. Added the AI Model Resilience Index as flagship asset (§2), a Community & Collaboration Loop section (§3), a parallel Personal Brand / Field Notes track (§4), reactive-coverage practice (§5), and short-form video as a new channel (§6). Corrected asset inventory to current shipped state (PyPI v1.0.1 live, 612 tests, GitHub Discussions not yet enabled). Tightened the "what I need from you" list to six concrete blockers.

---

*GAUNTLEX Marketing & Launch Plan · Living document — update the Log section as items ship.*
