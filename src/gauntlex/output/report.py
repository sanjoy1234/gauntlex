"""
Resilience Report — JSON, Markdown, HTML, SARIF, and JUnit XML outputs.

The report is tamper-evident: integrity_hash is SHA-256 over the
lexicographically sorted JSON-serialized attack array.
"""

from __future__ import annotations

import hashlib
import json
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from ..core.gauntlex import CombatResult

CONTROL_MAPPINGS = {
    "NIST_SSDF": ["RV.2.2", "RV.3.1", "PW.8.1"],
    "OWASP_SAMM": ["Verification/Security-Testing/2"],
    "SOC2_CC": ["CC7.1", "CC8.1"],
    "ISO_27001": ["A.14.2.8", "A.14.2.9"],
}


def generate_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    suffix = uuid.uuid4().hex[:4]
    return f"gauntlex-{ts}-{suffix}"


_REMEDIATION_HINTS: dict[str, str] = {
    "CWE-89":  "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
    "CWE-79":  "Escape all output with context-aware encoding. Use a trusted templating engine with auto-escape.",
    "CWE-22":  "Canonicalize paths and validate they remain within the allowed base directory.",
    "CWE-78":  "Avoid shell=True. Use subprocess with argument lists. Validate and whitelist all inputs.",
    "CWE-352": "Require CSRF tokens on all state-changing requests. Use SameSite cookies.",
    "CWE-862": "Enforce authorization checks server-side on every request. Never trust client-side roles.",
    "CWE-306": "Add authentication to all sensitive endpoints. Do not rely on obscurity.",
    "CWE-502": "Avoid deserializing untrusted data. Use safe formats (JSON) with schema validation.",
    "CWE-918": "Validate and allowlist outbound URLs. Never forward raw user-supplied URLs.",
    "CWE-611": "Disable external entity processing in your XML parser. Use a safe configuration.",
    "CWE-434": "Validate file type by content (magic bytes), not extension. Store uploads outside web root.",
    "CWE-798": "Remove hardcoded credentials. Use environment variables or a secrets manager.",
    "CWE-200": "Audit all error messages and logs. Never expose stack traces or internal paths to clients.",
    "CWE-362": "Use proper locking (mutexes/semaphores). Identify and protect all shared state.",
    "CWE-476": "Add null checks before dereferencing. Use Optional types where appropriate.",
    "CWE-190": "Use checked arithmetic or big-integer types. Validate ranges before arithmetic operations.",
    "CWE-125": "Use safe array bounds checking. Prefer standard library containers with bounds enforcement.",
    "CWE-787": "Validate buffer sizes before writes. Use memory-safe languages or safe abstractions.",
}


def get_remediation(cwe: str) -> str:
    """Return a concise remediation hint for a CWE."""
    return _REMEDIATION_HINTS.get(cwe, "Review the CWE definition and apply defense-in-depth controls.")


def build_report(
    result: CombatResult,
    run_id: str,
    spec_ref: str = "",
    commit_sha: str = "",
    playbook_version: str = "owasp_top10@v2025.1",
    intent_ref: str = "",
) -> dict:
    """Build the structured Resilience Report as a Python dict (serializable to JSON)."""
    attacks_serialized = [
        {
            "id": a.id,
            "cwe": a.cwe,
            "title": a.title,
            "description": a.description,
            "line_hint": a.line_hint,
            "confidence": a.confidence,
            "severity": a.severity,
            "score": a.score,
            "verdict": _score_to_verdict(a.score),
            "remediation": get_remediation(a.cwe),
        }
        for a in result.all_attacks
    ]

    # Hash is computed AFTER remediation is included so verify_integrity stays consistent
    integrity_hash = _compute_hash(attacks_serialized)

    return {
        "schema_version": "1.0",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "spec_ref": spec_ref,
        "intent_ref": intent_ref,
        "commit_sha": commit_sha,
        "ars_score": result.final_ars,
        "attack_count": result.attack_count,
        "mitigated_count": result.mitigated_count,
        "partial_count": result.partial_count,
        "miss_count": result.miss_count,
        "rounds_completed": len(result.rounds),
        "early_exit": result.early_exit,
        "elapsed_seconds": round(result.total_elapsed_seconds, 2),
        "playbook_version": playbook_version,
        "attacks": attacks_serialized,
        "control_mappings": CONTROL_MAPPINGS,
        "integrity_hash": integrity_hash,
    }


def save_report(report: dict, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{report['run_id']}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


def load_report(run_id: str, reports_dir: Path) -> dict:
    path = reports_dir / f"{run_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Report not found: {path}")
    with open(path) as f:
        return json.load(f)


def verify_integrity(report: dict) -> bool:
    """Re-derive hash and compare. Returns True if report is authentic."""
    stored = report.get("integrity_hash", "")
    derived = _compute_hash(report.get("attacks", []))
    return stored == derived


def render_findings_summary(report: dict) -> str:
    """
    Vulnerability-first summary: what was found, what is the risk, how to fix it.
    ARS score appears last as the gate verdict — not the headline.
    """
    attacks = report.get("attacks", [])
    missed = [a for a in attacks if a.get("verdict") == "MISSED"]
    partial = [a for a in attacks if a.get("verdict") == "PARTIAL"]
    ars = report["ars_score"]
    gate = "PASSED" if ars >= 0.80 else "BLOCKED"

    lines = ["## GAUNTLEX Security Findings", ""]

    if not missed and not partial:
        lines.append("✅  No unmitigated vulnerabilities found in this run.")
    else:
        if missed:
            lines += [f"### ❌  Critical — {len(missed)} Unmitigated Vulnerability(ies)", ""]
            for a in missed:
                lines += [
                    f"**[{a['cwe']}] {a['title']}** · Severity: {a['severity'].upper()}",
                    f"  {a['description']}",
                    f"  **Fix:** {a.get('remediation', get_remediation(a['cwe']))}",
                    "",
                ]
        if partial:
            lines += [f"### ⚠️  Partial — {len(partial)} Incompletely Mitigated", ""]
            for a in partial:
                lines += [
                    f"**[{a['cwe']}] {a['title']}** · Severity: {a['severity'].upper()}",
                    f"  {a['description']}",
                    f"  **Fix:** {a.get('remediation', get_remediation(a['cwe']))}",
                    "",
                ]

    lines += [
        "---",
        f"**Adversarial Resilience Score: {ars:.2f}** · Gate: {gate} · "
        f"{report['attack_count']} attacks · {report['miss_count']} missed · "
        f"{report['elapsed_seconds']}s",
        f"`Run: {report['run_id']}`",
    ]
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    ars = report["ars_score"]
    gate = "✅ PASSED" if ars >= 0.80 else "❌ BLOCKED"
    verdict_icon = {
        "MITIGATED": "✅", "PARTIAL": "⚠️", "MISSED": "❌"
    }

    # Lead with findings, not the score
    lines = [
        render_findings_summary(report),
        "",
        "---",
        "## Full Attack Breakdown",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Run ID | `{report['run_id']}` |",
        f"| ARS Score | **{ars:.2f}** |",
        f"| Gate | {gate} |",
        f"| Attacks | {report['attack_count']} fired · {report['mitigated_count']} mitigated · {report['miss_count']} missed |",
        f"| Rounds | {report['rounds_completed']} |",
        f"| Elapsed | {report['elapsed_seconds']}s |",
        f"| Playbook | `{report['playbook_version']}` |",
        f"",
        f"| ID | CWE | Title | Severity | Verdict | Remediation |",
        f"|----|-----|-------|----------|---------|-------------|",
    ]

    for a in report.get("attacks", []):
        icon = verdict_icon.get(a["verdict"], "?")
        remediation = a.get("remediation", get_remediation(a["cwe"]))
        lines.append(
            f"| {a['id']} | `{a['cwe']}` | {a['title']} | {a['severity']} | {icon} {a['verdict']} | {remediation[:80]}... |"
        )

    lines += [
        f"",
        f"### Compliance Control Mappings",
        f"",
        f"| Framework | Controls |",
        f"|-----------|---------|",
    ]
    for framework, controls in report.get("control_mappings", {}).items():
        lines.append(f"| {framework} | {', '.join(controls)} |")

    lines += [
        f"",
        f"---",
        f"*Integrity: `{report['integrity_hash']}`*",
        f"*Generated by [GAUNTLEX](https://github.com/sanjoy1234/gauntlex)*",
    ]

    return "\n".join(lines)


def render_html(report: dict) -> str:
    """Render a self-contained HTML Resilience Report — findings first, bright colors."""
    ars = report["ars_score"]
    gate = "PASSED" if ars >= 0.80 else "BLOCKED"
    gate_color = "#059669" if ars >= 0.80 else "#DC2626"
    gate_bg = "#D1FAE5" if ars >= 0.80 else "#FEE2E2"

    attacks = report.get("attacks", [])
    missed = [a for a in attacks if a.get("verdict") == "MISSED"]
    partial = [a for a in attacks if a.get("verdict") == "PARTIAL"]

    # ── Findings cards (vulnerability-first) ─────────────────────────────────
    finding_cards = ""
    sev_colors = {
        "critical": ("#7F1D1D", "#FEF2F2", "#FCA5A5"),
        "high":     ("#92400E", "#FFFBEB", "#FCD34D"),
        "medium":   ("#1E40AF", "#EFF6FF", "#93C5FD"),
        "low":      ("#065F46", "#F0FDF4", "#6EE7B7"),
    }
    for a in missed + partial:
        sev = a.get("severity", "medium").lower()
        txt_col, bg_col, border_col = sev_colors.get(sev, ("#374151", "#F9FAFB", "#D1D5DB"))
        verdict_label = "❌ UNMITIGATED" if a["verdict"] == "MISSED" else "⚠️ PARTIAL"
        remediation = a.get("remediation", get_remediation(a["cwe"]))
        finding_cards += f"""
<div class="finding-card" style="border-left:4px solid {border_col};background:{bg_col}">
  <div class="finding-header">
    <span class="finding-cwe" style="background:{border_col};color:{txt_col}">{a['cwe']}</span>
    <span class="finding-title">{a['title']}</span>
    <span class="finding-sev" style="color:{txt_col}">{sev.upper()}</span>
    <span class="verdict-tag" style="color:{txt_col}">{verdict_label}</span>
  </div>
  <p class="finding-desc">{a['description']}</p>
  <div class="finding-fix"><strong>Fix:</strong> {remediation}</div>
</div>"""

    all_rows = ""
    _v_icon = {"MITIGATED": "&#x2705;", "PARTIAL": "&#x26A0;&#xFE0F;", "MISSED": "&#x274C;"}
    _v_color = {"MITIGATED": "#059669", "PARTIAL": "#D97706", "MISSED": "#DC2626"}
    for a in attacks:
        v = a["verdict"]
        v_col = _v_color.get(v, "#111827")
        v_ico = _v_icon.get(v, "?")
        a_id = a["id"]
        a_cwe = a["cwe"]
        a_title = a["title"]
        a_sev = a.get("severity", "—").upper()
        a_rem = a.get("remediation", get_remediation(a["cwe"]))[:90]
        all_rows += (
            "<tr>"
            f"<td><code>{a_id}</code></td>"
            f"<td><code style=\"background:#EFF6FF;color:#1E40AF;padding:2px 6px;border-radius:3px\">{a_cwe}</code></td>"
            f"<td style=\"font-weight:500\">{a_title}</td>"
            f"<td>{a_sev}</td>"
            f"<td style=\"color:{v_col};font-weight:700\">{v_ico} {v}</td>"
            f"<td style=\"font-size:12px;color:#6B7280\">{a_rem}&#x2026;</td>"
            "</tr>\n"
        )

    control_rows = ""
    for framework, controls in report.get("control_mappings", {}).items():
        ctrl_str = ", ".join(controls)
        control_rows += f"<tr><td><strong style=\"color:#1E40AF\">{framework}</strong></td><td>{ctrl_str}</td></tr>\n"

    intent_meta = ""
    if report.get("intent_ref"):
        intent_meta = f"&nbsp;·&nbsp; Intent: <a href='{report['intent_ref']}' style='color:#2563EB'>{report['intent_ref']}</a>"

    no_findings_msg = ""
    if not missed and not partial:
        no_findings_msg = """
<div style="background:#D1FAE5;border:1px solid #6EE7B7;border-radius:8px;padding:20px 24px;margin-bottom:24px;display:flex;align-items:center;gap:12px">
  <span style="font-size:28px">✅</span>
  <div>
    <div style="font-weight:700;color:#065F46;font-size:15px">No unmitigated vulnerabilities found</div>
    <div style="color:#047857;font-size:13px;margin-top:2px">All adversarial attacks were mitigated or partially addressed.</div>
  </div>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GAUNTLEX Resilience Report — {report['run_id']}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#F0F7FF;color:#111827;min-height:100vh}}
  header{{background:linear-gradient(135deg,#1E40AF 0%,#3B82F6 100%);padding:20px 32px;color:#fff}}
  header h1{{font-size:20px;font-weight:800;letter-spacing:-.01em}}
  header .meta{{font-size:12px;opacity:.8;margin-top:4px;font-family:monospace}}
  .main{{max-width:1000px;margin:0 auto;padding:28px 24px}}
  .gate-bar{{display:flex;align-items:center;gap:20px;background:#fff;border-radius:10px;padding:20px 24px;margin-bottom:20px;border:1px solid #DBEAFE;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
  .gate-verdict{{font-size:28px;font-weight:900;color:{gate_color}}}
  .gate-badge{{background:{gate_bg};color:{gate_color};border:1.5px solid {gate_color};border-radius:6px;padding:4px 14px;font-size:13px;font-weight:800;letter-spacing:.04em}}
  .ars-label{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#6B7280}}
  .stat-chips{{display:flex;gap:10px;flex-wrap:wrap;margin-left:auto}}
  .chip{{background:#EFF6FF;color:#1E40AF;border-radius:20px;padding:4px 12px;font-size:12px;font-weight:700}}
  .chip.red{{background:#FEE2E2;color:#DC2626}}
  .chip.amber{{background:#FFFBEB;color:#D97706}}
  .chip.green{{background:#D1FAE5;color:#059669}}
  .section-title{{font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;color:#1E40AF;margin:24px 0 12px;display:flex;align-items:center;gap:8px}}
  .finding-card{{border-radius:8px;padding:16px 18px;margin-bottom:12px}}
  .finding-header{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}}
  .finding-cwe{{font-family:monospace;font-size:11px;font-weight:800;padding:2px 8px;border-radius:4px}}
  .finding-title{{font-weight:700;font-size:14px;color:#111827;flex:1}}
  .finding-sev{{font-size:11px;font-weight:800;letter-spacing:.05em}}
  .verdict-tag{{font-size:11px;font-weight:700;margin-left:auto}}
  .finding-desc{{font-size:13px;color:#374151;line-height:1.5;margin-bottom:10px}}
  .finding-fix{{font-size:12px;background:rgba(255,255,255,.7);border-radius:4px;padding:8px 12px;color:#374151;border-left:3px solid #3B82F6}}
  table{{width:100%;border-collapse:collapse;font-size:13px;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #DBEAFE;margin-bottom:20px}}
  th{{background:#EFF6FF;padding:10px 14px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#1E40AF;border-bottom:2px solid #BFDBFE}}
  td{{padding:10px 14px;border-bottom:1px solid #EFF6FF}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#F8FAFF}}
  code{{font-family:monospace;font-size:11px}}
  .integrity{{font-size:11px;color:#9CA3AF;font-family:monospace;margin-top:20px;padding-top:14px;border-top:1px solid #E5E7EB}}
  footer{{text-align:center;padding:20px;font-size:12px;color:#9CA3AF}}
</style>
</head>
<body>
<header>
  <h1>⚔️ GAUNTLEX Resilience Report</h1>
  <div class="meta">Run: {report['run_id']} &nbsp;·&nbsp; {report.get('generated_at','')[:19].replace('T',' ')} UTC &nbsp;·&nbsp; Playbook: {report.get('playbook_version','')}{intent_meta}</div>
</header>

<div class="main">

  <div class="gate-bar">
    <div>
      <div class="ars-label">Adversarial Resilience Score</div>
      <div class="gate-verdict">{ars:.2f} <span style="font-size:16px;font-weight:500;color:#6B7280">/ 1.00</span></div>
    </div>
    <div><span class="gate-badge">CI/CD GATE: {gate}</span></div>
    <div class="stat-chips">
      <span class="chip">{report.get('attack_count',0)} attacks</span>
      <span class="chip green">{report.get('mitigated_count',0)} mitigated</span>
      <span class="chip amber">{report.get('partial_count',0)} partial</span>
      <span class="chip red">{report.get('miss_count',0)} missed</span>
      <span class="chip">{report.get('elapsed_seconds',0)}s</span>
    </div>
  </div>

  <div class="section-title">🔍 Vulnerability Findings</div>
  {no_findings_msg}{finding_cards}

  <div class="section-title">📋 Full Attack Breakdown</div>
  <table>
  <thead><tr><th>ID</th><th>CWE</th><th>Vulnerability</th><th>Severity</th><th>Verdict</th><th>Remediation</th></tr></thead>
  <tbody>{all_rows}</tbody>
  </table>

  <div class="section-title">🏛️ Compliance Control Mappings</div>
  <table>
  <thead><tr><th>Framework</th><th>Controls</th></tr></thead>
  <tbody>{control_rows}</tbody>
  </table>

  <div class="integrity">SHA-256 Integrity: {report.get('integrity_hash','')}</div>
</div>

<footer>GAUNTLEX Adversarial Co-Generation Engine &nbsp;·&nbsp; Built by Sanjoy Ghosh</footer>
</body>
</html>"""


def render_sarif(report: dict) -> str:
    """Render a SARIF 2.1.0 document for GitHub Code Scanning integration."""
    verdict_to_level = {"MITIGATED": "note", "PARTIAL": "warning", "MISSED": "error"}

    # Build unique rule set from attacks
    seen_cwes: dict[str, dict] = {}
    for a in report.get("attacks", []):
        cwe = a["cwe"]
        if cwe not in seen_cwes:
            cwe_num = cwe.replace("CWE-", "")
            seen_cwes[cwe] = {
                "id": cwe,
                "name": a["title"].replace(" ", ""),
                "shortDescription": {"text": a["title"]},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "properties": {"tags": ["security", cwe]},
            }

    results = []
    for a in report.get("attacks", []):
        verdict = a.get("verdict", "MISSED")
        results.append({
            "ruleId": a["cwe"],
            "level": verdict_to_level.get(verdict, "error"),
            "message": {
                "text": (
                    f"[{a['cwe']}] {a['title']} — {verdict}. "
                    f"Confidence: {a.get('confidence', 'medium')}. "
                    f"{a.get('description', '')[:200]}"
                )
            },
            "properties": {
                "severity": a.get("severity", "medium"),
                "verdict": verdict,
                "ars_contribution": a.get("score", 0.0),
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GAUNTLEX",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/sanjoy1234/gauntlex",
                        "rules": list(seen_cwes.values()),
                    }
                },
                "results": results,
                "properties": {
                    "run_id": report.get("run_id", ""),
                    "ars_score": report.get("ars_score", 0.0),
                    "playbook_version": report.get("playbook_version", ""),
                    "integrity_hash": report.get("integrity_hash", ""),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_junit_xml(report: dict) -> str:
    """Render JUnit XML for CI/CD dashboard integration (Jenkins, Azure DevOps, etc.)."""
    attacks = report.get("attacks", [])
    failures = sum(1 for a in attacks if a.get("verdict") == "MISSED")
    elapsed = report.get("elapsed_seconds", 0)
    run_id = report.get("run_id", "unknown")
    playbook = report.get("playbook_version", "gauntlex")

    suites = ET.Element("testsuites", {
        "name": "GAUNTLEX Adversarial Gate",
        "tests": str(len(attacks)),
        "failures": str(failures),
        "time": str(elapsed),
    })
    suite = ET.SubElement(suites, "testsuite", {
        "name": run_id,
        "tests": str(len(attacks)),
        "failures": str(failures),
        "time": str(elapsed),
        "timestamp": report.get("generated_at", "")[:19],
    })

    # Suite-level property: ARS score
    props = ET.SubElement(suite, "properties")
    ET.SubElement(props, "property", {"name": "ars_score", "value": str(report.get("ars_score", 0))})
    ET.SubElement(props, "property", {"name": "playbook", "value": playbook})

    for a in attacks:
        verdict = a.get("verdict", "MISSED")
        tc = ET.SubElement(suite, "testcase", {
            "name": f"[{a['cwe']}] {a['title']}",
            "classname": playbook,
            "time": "0",
        })
        if verdict == "MISSED":
            fail = ET.SubElement(tc, "failure", {
                "message": f"Attack not mitigated: {a['title']}",
                "type": "SecurityVulnerability",
            })
            fail.text = (
                f"CWE: {a['cwe']}\n"
                f"Severity: {a.get('severity', 'unknown')}\n"
                f"Confidence: {a.get('confidence', 'medium')}\n"
                f"Description: {a.get('description', '')[:300]}"
            )
        elif verdict == "PARTIAL":
            warn = ET.SubElement(tc, "system-out")
            warn.text = f"Partial mitigation: {a['title']} — review edge cases. CWE: {a['cwe']}"

    ET.indent(suites, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suites, encoding="unicode")


def _score_to_verdict(score: float) -> str:
    if score >= 1.0:
        return "MITIGATED"
    if score >= 0.5:
        return "PARTIAL"
    return "MISSED"


def _compute_hash(attacks: list[dict]) -> str:
    canonical = json.dumps(attacks, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
