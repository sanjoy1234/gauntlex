import json, os

OUT = "/private/tmp/claude-501/-Users-sanjoyghosh-gauntlex/0201ac04-5ed4-408f-9a00-b27c4829f2bd/scratchpad/v3build/panels"

TEMPLATE = """<title>panel</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{width:403px;height:900px;overflow:hidden;background:#0a0f1e;
    border-left:4px solid #3b6fd8;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Arial,sans-serif;
    color:#eef1f8;position:relative}}
  .inner{{padding:44px 40px 0 40px}}
  .eyebrow{{display:inline-block;font-family:ui-monospace,"SF Mono","JetBrains Mono",Menlo,monospace;
    font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#8fb3ff;
    background:rgba(91,141,239,.14);border:1px solid rgba(91,141,239,.35);
    padding:5px 14px;border-radius:20px;margin-bottom:22px}}
  h1{{font-size:{headline_size}px;line-height:1.14;font-weight:800;letter-spacing:-.01em;margin-bottom:22px}}
  hr{{border:none;border-top:1px solid rgba(255,255,255,.14);margin-bottom:26px}}
  ul{{list-style:none}}
  li{{display:flex;gap:12px;margin-bottom:{bullet_gap}px;font-size:{bullet_size}px;line-height:1.42}}
  li::before{{content:"";width:6px;height:6px;border-radius:50%;background:#5b8def;flex:none;margin-top:9px}}
  li b{{color:#fff;font-weight:600;display:block}}
  li span{{color:#93a1c4;display:block;margin-top:1px}}
  .footer{{position:absolute;bottom:34px;left:40px;right:40px;display:flex;justify-content:space-between;
    font-family:ui-monospace,"SF Mono","JetBrains Mono",Menlo,monospace;font-size:13px;color:#57628a}}
</style>
<div class="inner">
  <div class="eyebrow">{eyebrow}</div>
  <h1>{headline}</h1>
  <hr>
  <ul>
    {bullets_html}
  </ul>
</div>
<div class="footer"><span>GAUNTLEX</span><span>{counter}</span></div>
"""

def bullet_html(b):
    if isinstance(b, tuple):
        bold, rest = b
        return f'<li><div><b>{bold}</b><span>{rest}</span></div></li>'
    return f'<li><div><b>{b}</b></div></li>'

SCENES = {
  "scene_01": dict(
    eyebrow="SETUP", headline="One command.<br>Every model provider.",
    bullets=[
      ("Anthropic, OpenRouter, HuggingFace, OpenAI-compatible,", "or local Ollama — your call, never a lock-in"),
      ("pip install gauntlex-ai,", "or zero-install via uvx — both land in the same wizard"),
      ("Validated and ready to run", "in under a minute"),
    ], counter="01 / 13"),
  "scene_02": dict(
    eyebrow="SETUP", headline="Business context,<br>wired in automatically",
    bullets=[
      ("Jira, Confluence, or Aha! connect automatically", "— more trackers on the roadmap"),
      ("Build intent from your spec, business intent from your tracker", "— GAUNTLEX reasons from both"),
      ("Setup complete", "in under a minute"),
    ], counter="02 / 13"),
  "scene_03": dict(
    eyebrow="CORE ENGINE", headline="Attacks generate<br>while code does",
    bullets=[
      ("Every vulnerability found before the first commit", "— not after code review, not after a pentest cycle"),
      ("The attack surface is reasoned from intent alone", "— no implementation for a blind spot to hide in"),
      ("The only engine that tests code at the moment it's written", "not the moment it ships"),
    ], counter="03 / 13"),
  "scene_04": dict(
    eyebrow="FINDINGS", headline="Real vulnerabilities,<br>real fixes",
    bullets=[
      ("Every finding maps to NIST SSDF, OWASP SAMM, SOC 2, and ISO 27001", "— audit-ready, not just CWE-tagged"),
      ("Severity-ranked:", "critical to low"),
      ("A fix an engineer can ship in the same PR", "— not a wall of text to triage later"),
    ], counter="04 / 13"),
  "scene_05": dict(
    eyebrow="THE GATE", headline="One number:<br>Adversarial Resilience Score",
    bullets=[
      ("One score gates the merge", "— no manual sign-off, no judgment call"),
      ("Below threshold, the PR is blocked automatically", "— the same enforcement as a failing CI check"),
      ("Configurable per team", "— security posture is a policy decision, not a suggestion"),
    ], counter="05 / 13"),
  "scene_06": dict(
    eyebrow="TRACKING", headline="Every run,<br>tracked automatically",
    bullets=[
      ("Full visibility across every run", "— the record an audit conversation actually needs"),
      ("PASS or BLOCKED", "at a glance"),
      ("Full timestamped", "audit trail"),
    ], counter="06 / 13"),
  "scene_07": dict(
    eyebrow="COMPLIANCE", headline="Regulated domains,<br>built in",
    bullets=[
      ("HIPAA · FINRA · PCI DSS · SOC 2 · OWASP", "— five regulated-industry playbooks, ready on day one"),
      ("Each playbook maps to the actual regulation", "— FINRA Rule 4370, HIPAA §164.312, PCI DSS v4.0, not a generic checklist"),
      ("Every attack scenario reasons from", "what your specific industry auditor will ask"),
    ], counter="07 / 13"),
  "scene_08": dict(
    eyebrow="NO MERCY", headline="It doesn't<br>pull punches",
    bullets=[
      ("Hardcoded JWT secrets:", "caught"),
      ("Missing authorization checks:", "caught"),
      ("Automatically gated in the CI pipeline", "— blocks the PR, not a Slack message after the fact"),
    ], counter="08 / 13"),
  "scene_09": dict(
    eyebrow="DASHBOARD", headline="Every repo,<br>one dashboard",
    bullets=[
      ("Built for scale", "— 5 repos or 50, the same real-time view across the entire portfolio"),
      ("ARS trend across", "every run, every repository"),
      ("Gate pass/block", "at a glance"),
      ("Project- and business-unit-level rollups", "— on the roadmap"),
    ], counter="09 / 13", headline_size=38, bullet_gap=18),
  "scene_10": dict(
    eyebrow="ARCHITECTURE", headline="See exactly<br>how it works",
    bullets=[
      ("Spec &rarr; Builder + Breaker &rarr; Arbiter &rarr; Gate", "— full traceability from intent to enforcement"),
      ("The whole cycle completes in minutes,", "not a sprint"),
      ("No black box", "— every stage auditable, every decision explainable"),
    ], counter="11 / 13"),
  "scene_11": dict(
    eyebrow="RANGE", headline="A command for<br>every workflow",
    bullets=[
      ("Any repo, any language", "— Flask, axios, Gin, or your own GitHub URL"),
      ("SARIF for code scanning, JUnit for CI, HTML for stakeholders", "— one export per audience"),
      ("Rounds, formats, intents", "— one CLI, zero context-switching"),
    ], counter="12 / 13"),
  "scene_12": dict(
    eyebrow="INTEGRATIONS", headline="Works with the<br>tools you already use",
    bullets=[
      ("Claude Code · Cursor · Windsurf · Copilot", "Codex · Zed · Antigravity · GitHub Actions"),
      ("Each tool wired the way it actually expects", "— its own MCP config or workflow file, detected and written automatically"),
      ("One command", "wires every target"),
    ], counter="13 / 13"),
}

for name, s in SCENES.items():
    bullets_html = "\n    ".join(bullet_html(b) for b in s["bullets"])
    html = TEMPLATE.format(
        eyebrow=s["eyebrow"], headline=s["headline"], bullets_html=bullets_html,
        counter=s["counter"],
        headline_size=s.get("headline_size", 40),
        bullet_size=s.get("bullet_size", 17.5),
        bullet_gap=s.get("bullet_gap", 24),
    )
    with open(os.path.join(OUT, name + ".html"), "w") as f:
        f.write(html)
    print("wrote", name)
