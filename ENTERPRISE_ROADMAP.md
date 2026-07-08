# GAUNTLEX — Enterprise Integration Roadmap

**Status:** Planned — not yet implemented  
**Audience:** Engineering leadership, enterprise sales  
**Author:** Sanjoy Ghosh

---

## Why This Matters

The current dashboard works for a developer or a small team demo.
To land enterprise contracts (regulated industries: finance, insurance, healthcare),
GAUNTLEX must speak the systems those teams already live in. This document
maps each missing enterprise feature to the exact systems and APIs required.

---

## Priority Stack (Highest → Lowest ROI)

| # | Integration | Unlocks | Effort |
|---|-------------|---------|--------|
| 1 | ServiceNow CMDB | Service/project grouping, compliance evidence | High |
| 2 | Jira auto-ticketing (extend existing adapter) | MTTR tracking | Medium |
| 3 | Splunk HEC | SOC team visibility, SIEM correlation | Medium |
| 4 | Jenkins plugin / Azure DevOps task | CI coverage beyond GitHub Actions | Medium |
| 5 | PagerDuty | Regression alerts, on-call routing | Low |
| 6 | ServiceNow GRC | Compliance audit evidence (PCI, HIPAA, SOC2) | High |
| 7 | Grafana datasource plugin | Engineering leadership dashboards | Low |
| 8 | Vanta / Drata | Mid-market SOC2 automation path | Medium |

---

## Feature 1 — Project / Service Grouping

**Problem:** All runs are a flat list. Enterprise has 50+ services across 12 teams.
A CTO needs: "Show me all BLOCKED runs for the `payment-service` repo."

### Systems Required

| System | Role | API |
|--------|------|-----|
| **ServiceNow CMDB** | Authoritative service catalog — what services exist, who owns them | REST API: pull CI records by application tag |
| **GitHub Enterprise / GitLab** | Repo → team → domain mapping | GitHub Teams API |
| **Backstage** | Internal developer portal (`catalog-info.yaml` per repo defines owner/domain/tier) | Backstage Catalog API |
| **AWS Service Catalog / Azure Service Tree** | Cloud-hosted service inventory | Cloud resource tag APIs |

**Note:** Without ServiceNow CMDB or Backstage, there is no authoritative
service list. You cannot group what you cannot enumerate. This integration
must come first.

---

## Feature 2 — MTTR (Mean Time to Remediate)

**Problem:** The dashboard shows runs but has no vulnerability lifecycle.
Key security KPI: how long from "vulnerability found" to "vulnerability fixed"?

### Systems Required

| System | Role | Integration |
|--------|------|-------------|
| **Jira** | Dev-team ticket lifecycle (adapter exists — extend it) | Jira Webhooks: notify GAUNTLEX when issue → "Done" |
| **ServiceNow ITSM** | Enterprise security incident management (CRITICAL findings) | ServiceNow Incident API: create, link, resolve |
| **PagerDuty** | SLA timer: alert fires → resolved | PagerDuty Events API v2 |
| **GitHub Issues** | Lightweight orgs | GitHub Webhooks on issue close |
| **Tempo (Jira plugin)** | Engineering hours logged against remediation tickets | Tempo Worklog API |

**Note:** MTTR only means something if GAUNTLEX owns the ticket lifecycle —
creates the ticket, links it to the run, and gets notified on close.
If ticket creation is manual, the data is garbage.

---

## Feature 3 — Cost / ROI Panel

**Problem:** CTOs justify budgets. Need a dollar figure that a CFO will accept.
Required: cost to find vulnerability here vs. cost to find it in production.

### Systems Required

| System | Role | Integration |
|--------|------|-------------|
| **Jira / Tempo** | Engineering hours logged against remediation → actual cost | Tempo Worklog API + configured blended rate |
| **Workday / BambooHR / ADP** | Blended engineering hourly rate (loaded cost per level) | Read-only HR API for cost band |
| **HackerOne / Bugcrowd** | Bug bounty market rate → "what would an attacker get paid to find this?" | Bounty program API or static CVSS → payout table |
| **IBM Cost of Breach** | Industry benchmark: avg $4.88M per breach (2024) | Static data — no live integration, but must be attribution-mapped by CWE severity |

**Practical path:** Let admin configure `blended_engineer_hourly_rate` in `.gauntlex.yml`.
Pull remediation hours from Jira/Tempo. Multiply. Use HackerOne benchmarks for
"value of findings" — publicly defensible market data.

---

## Feature 4 — Week-over-Week Posture Trend

**Problem:** Sparkline shows per-run ARS. CTO needs: "Is posture improving this quarter?"
Requires connecting each GAUNTLEX run to a deployment event.

### Systems Required

| System | Role | Integration |
|--------|------|-------------|
| **Jenkins** | Most common enterprise CI — trigger GAUNTLEX on build | Jenkins Post-Build plugin or pipeline step with `BUILD_NUMBER` tag |
| **Azure DevOps Pipelines** | Microsoft enterprise shops (large segment) | ADO REST API — create pipeline task extension |
| **Harness / Tekton** | Cloud-native enterprise CI | Webhook trigger + run metadata pushback |
| **Datadog / New Relic** | Deployment markers — correlate "ARS dropped" with "version 2.4.1 deployed" | Datadog Deployment Events API |
| **Grafana** | Engineering teams live in Grafana — ARS as a datasource | JSON datasource plugin against `/api/runs` |
| **GitHub Actions** | Already supported — extend to write run metadata back to Actions summary | Actions summary API |

**Note:** Week-over-week trend without deployment attribution is a vanity metric.
A CTO will ask: "Did the score drop because of the new auth PR or because the model changed?"
Runs must be tagged with commit SHA and pipeline run ID.

---

## Feature 5 — Compliance Coverage Map (PCI-DSS, HIPAA, SOC2, NIST)

**Problem:** Enterprise security governance needs: "How many services are PCI-DSS covered?"
Must map CWE findings → compliance control requirements → GRC system evidence.

### Systems Required

| System | Role | Integration |
|--------|------|-------------|
| **ServiceNow GRC** | Enterprise compliance management — controls, assessments, audit evidence | ServiceNow GRC API: push run as control evidence artifact |
| **Archer RSA** | Large financial services GRC standard | REST API: post findings as control test results |
| **Vanta** | Mid-market SOC2 automation (Fintech, SaaS) | Vanta API: custom evidence upload |
| **Drata** | SOC2/ISO 27001 automation | Drata API: evidence records |
| **OneTrust** | Privacy + compliance (GDPR, CCPA) | REST API for evidence records |
| **NIST NVD API** | CWE → CVE enrichment → CVSS → compliance impact | Live pull (partially in GAUNTLEX already) |

**Note:** ServiceNow GRC is the gatekeeper in every regulated enterprise.
If GAUNTLEX findings don't appear as evidence artifacts in ServiceNow GRC,
the CISO's team cannot use them for audits. Getting *approved as an evidence source*
requires vendor security review — typically a 90-day enterprise sales process,
not just a code integration.

---

## Feature 6 — Regression Alerts

**Problem:** When a previously-PASS service goes BLOCKED, the right person must
be notified immediately — not wait for someone to notice a row color change.

### Systems Required

| System | Role | Integration |
|--------|------|-------------|
| **PagerDuty** | On-call alerting — deduplicated, routed by team/service ownership | PagerDuty Events API v2 — severity-mapped alerts |
| **Splunk SIEM** | Security events correlated with auth logs, WAF, other signals | Splunk HEC (HTTP Event Collector) — CEF/JSON format |
| **Microsoft Sentinel** | Azure-native SIEM (dominant in Microsoft enterprise shops) | SARIF → Azure Monitor Logs / Sentinel workspace |
| **Datadog Security** | Engineering-team SIEM — often already deployed | Datadog Events API + Monitors on ARS metric |
| **Slack / Microsoft Teams** | Human notification — last mile | Incoming webhook per team channel |
| **OpsGenie** | Alternative to PagerDuty, common in Atlassian shops | REST API |

**Note:** Splunk is the SIEM of record at Fortune 500 security teams.
If GAUNTLEX events don't appear in Splunk, the SOC team will never see them.
A Splunk TA (Technology Add-on) is a 2-week build + separate Splunkbase certification.

---

## Build Order When Ready

1. **ServiceNow CMDB** — unlocks grouping, GRC evidence, compliance map at once
2. **Jira auto-ticketing** — MTTR is the budget-justification metric; adapter exists, make it automatic
3. **Splunk HEC** — gets GAUNTLEX into SOC workflow with zero behavioral change on their part
4. **Jenkins plugin / ADO task** — covers CI systems beyond GitHub Actions
5. **PagerDuty** — closes "who gets paged" question
6. **ServiceNow GRC** — compliance audit evidence path; required for regulated industries
7. **Grafana datasource** — low effort, high visibility for engineering leadership
8. **Vanta / Drata** — faster mid-market SOC2 path than ServiceNow GRC

---

## What NOT to Build First

- Power BI / Tableau / Looker — these consume data from Splunk/ServiceNow automatically
- Custom SIEM — don't build one; push into the SIEM the customer already has
- Email reporting — Slack/Teams covers this with lower friction
