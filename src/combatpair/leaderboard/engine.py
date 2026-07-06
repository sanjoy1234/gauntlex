"""
ARS Leaderboard — processes SWE-bench agent patch outputs through COMBATPAIR Breaker
and produces a ranked leaderboard published as a GitHub Pages static site.

Workflow:
  1. Load SWE-bench agent results (JSONL — one dict per task_id)
  2. For each task, simulate Breaker + Arbiter scoring (or replay from a report dir)
  3. Aggregate per-agent ARS scores
  4. Render a static HTML leaderboard page (bright/light theme, sortable table)

Usage:
  from combatpair.leaderboard.engine import LeaderboardEntry, build_leaderboard, render_leaderboard_html
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


@dataclass
class AgentScore:
    """Per-task Breaker score for a single SWE-bench agent."""
    agent_name: str
    task_id: str
    ars_score: float
    attack_count: int
    miss_count: int
    patch_sha: str = ""


@dataclass
class LeaderboardEntry:
    """Aggregated ARS stats for one agent across all evaluated tasks."""
    agent_name: str
    task_count: int
    avg_ars: float
    median_ars: float
    min_ars: float
    max_ars: float
    total_attacks: int
    total_misses: int
    pass_rate: float              # fraction of tasks above gate threshold
    gate_threshold: float = 0.80

    @property
    def rank_score(self) -> float:
        """Primary sort key: avg_ars * 0.6 + pass_rate * 0.4."""
        return self.avg_ars * 0.6 + self.pass_rate * 0.4


def load_agent_scores_from_reports(reports_dir: Path, gate: float = 0.80) -> list[AgentScore]:
    """
    Load ARS scores from existing COMBATPAIR report JSON files.

    Report filenames are expected to embed agent names as:
      <agent_name>--<task_id>.json   (double-dash separator)
    Falls back to treating the whole stem as task_id with agent_name="unknown".
    """
    scores: list[AgentScore] = []
    if not reports_dir.exists():
        return scores
    for f in sorted(reports_dir.glob("*.json")):
        try:
            with open(f) as fh:
                report = json.load(fh)
            stem = f.stem
            if "--" in stem:
                agent_name, task_id = stem.split("--", 1)
            else:
                agent_name, task_id = "unknown", stem
            scores.append(AgentScore(
                agent_name=agent_name,
                task_id=task_id,
                ars_score=float(report.get("ars_score", 0.0)),
                attack_count=int(report.get("attack_count", 0)),
                miss_count=int(report.get("miss_count", 0)),
            ))
        except Exception:
            continue
    return scores


def load_agent_scores_from_jsonl(jsonl_path: Path) -> list[AgentScore]:
    """
    Load scores from a JSONL file where each line is a dict with at minimum:
      agent_name, task_id, ars_score
    Optional fields: attack_count, miss_count, patch_sha
    """
    scores: list[AgentScore] = []
    if not jsonl_path.exists():
        return scores
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                scores.append(AgentScore(
                    agent_name=d["agent_name"],
                    task_id=d["task_id"],
                    ars_score=float(d.get("ars_score", 0.0)),
                    attack_count=int(d.get("attack_count", 0)),
                    miss_count=int(d.get("miss_count", 0)),
                    patch_sha=d.get("patch_sha", ""),
                ))
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
    return scores


def build_leaderboard(scores: list[AgentScore], gate_threshold: float = 0.80) -> list[LeaderboardEntry]:
    """Aggregate per-task scores into per-agent LeaderboardEntry rows, sorted by rank_score desc."""
    by_agent: dict[str, list[AgentScore]] = {}
    for s in scores:
        by_agent.setdefault(s.agent_name, []).append(s)

    entries: list[LeaderboardEntry] = []
    for agent_name, agent_scores in by_agent.items():
        ars_vals = [s.ars_score for s in agent_scores]
        entries.append(LeaderboardEntry(
            agent_name=agent_name,
            task_count=len(agent_scores),
            avg_ars=statistics.mean(ars_vals),
            median_ars=statistics.median(ars_vals),
            min_ars=min(ars_vals),
            max_ars=max(ars_vals),
            total_attacks=sum(s.attack_count for s in agent_scores),
            total_misses=sum(s.miss_count for s in agent_scores),
            pass_rate=sum(1 for v in ars_vals if v >= gate_threshold) / len(ars_vals),
            gate_threshold=gate_threshold,
        ))

    return sorted(entries, key=lambda e: e.rank_score, reverse=True)


def render_leaderboard_html(
    entries: list[LeaderboardEntry],
    gate_threshold: float = 0.80,
    title: str = "COMBATPAIR ARS Leaderboard",
    generated_at: str = "",
) -> str:
    """Render a self-contained, sortable HTML leaderboard page (bright/light theme)."""

    rows = ""
    for rank, e in enumerate(entries, 1):
        medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(rank, f"#{rank}")
        pass_cls = "pass" if e.pass_rate >= 0.8 else ("warn" if e.pass_rate >= 0.5 else "fail")
        rows += f"""
        <tr>
          <td class="rank">{medal}</td>
          <td class="agent-name">{e.agent_name}</td>
          <td class="num {'hi' if e.avg_ars >= gate_threshold else 'lo'}">{e.avg_ars:.3f}</td>
          <td class="num">{e.median_ars:.3f}</td>
          <td class="num lo">{e.min_ars:.3f}</td>
          <td class="num hi">{e.max_ars:.3f}</td>
          <td class="num">{e.task_count}</td>
          <td class="num {pass_cls}-pct">{e.pass_rate * 100:.1f}%</td>
          <td class="num">{e.total_attacks}</td>
          <td class="num lo">{e.total_misses}</td>
        </tr>"""

    empty_msg = "" if entries else '<p class="empty">No leaderboard data yet. Run <code>combatpair leaderboard --jsonl scores.jsonl</code> to generate.</p>'
    gen_line = f"<p>Generated: {generated_at}</p>" if generated_at else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,-apple-system,sans-serif;background:#F8FAFC;color:#111827;min-height:100vh}}
  header{{background:#fff;border-bottom:2px solid #DBEAFE;padding:20px 40px}}
  header h1{{font-size:22px;font-weight:800;color:#1E40AF}}
  header p{{color:#6B7280;font-size:13px;margin-top:4px}}
  .main{{padding:40px;max-width:1100px;margin:0 auto}}
  .meta{{display:flex;gap:16px;margin-bottom:24px;font-size:12px;color:#9CA3AF}}
  .meta strong{{color:#374151}}
  .section{{background:#fff;border:1px solid #E5E7EB;border-radius:10px;overflow:hidden}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#F0F9FF;padding:10px 14px;text-align:left;font-size:11px;font-weight:700;
       text-transform:uppercase;letter-spacing:.07em;color:#1E40AF;border-bottom:2px solid #DBEAFE;
       cursor:pointer;user-select:none}}
  th:hover{{background:#DBEAFE}}
  td{{padding:10px 14px;border-bottom:1px solid #F3F4F6}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#F9FAFB}}
  .rank{{font-size:16px;text-align:center;width:50px}}
  .agent-name{{font-weight:700;color:#111827}}
  .num{{text-align:right;font-variant-numeric:tabular-nums}}
  .hi{{color:#047857;font-weight:700}}
  .lo{{color:#B91C1C;font-weight:700}}
  .pass-pct{{color:#047857;font-weight:700}}
  .warn-pct{{color:#D97706;font-weight:700}}
  .fail-pct{{color:#B91C1C;font-weight:700}}
  .empty{{padding:48px;text-align:center;color:#9CA3AF}}
  footer{{margin-top:48px;padding:16px 40px;border-top:1px solid #E5E7EB;font-size:12px;color:#9CA3AF;text-align:center}}
</style>
</head>
<body>
<header>
  <h1>⚔️ {title}</h1>
  <p>ARS Gate: {gate_threshold:.2f} · Rank score = avg_ARS×0.6 + pass_rate×0.4</p>
</header>
<div class="main">
  <div class="meta">
    <span><strong>{len(entries)}</strong> agents ranked</span>
    {gen_line}
  </div>
  <div class="section">
    {empty_msg}
    {'<table id="lb"><thead><tr><th>Rank</th><th>Agent</th><th data-col="2">Avg ARS ▼</th><th data-col="3">Median</th><th data-col="4">Min</th><th data-col="5">Max</th><th data-col="6">Tasks</th><th data-col="7">Pass%</th><th data-col="8">Attacks</th><th data-col="9">Misses</th></tr></thead><tbody>' + rows + '</tbody></table>' if entries else ''}
  </div>
</div>
<footer>COMBATPAIR Adversarial Co-Generation Engine · Built by Sanjoy Ghosh</footer>
<script>
// Simple client-side sort for the leaderboard table
(function(){{
  var table = document.getElementById('lb');
  if (!table) return;
  var tbody = table.querySelector('tbody');
  var sortCol = 2, sortAsc = false;
  table.querySelectorAll('th[data-col]').forEach(function(th) {{
    th.addEventListener('click', function() {{
      var col = parseInt(th.getAttribute('data-col'));
      if (sortCol === col) {{ sortAsc = !sortAsc; }} else {{ sortCol = col; sortAsc = false; }}
      var rows = Array.from(tbody.querySelectorAll('tr'));
      rows.sort(function(a, b) {{
        var av = parseFloat(a.cells[col].textContent) || 0;
        var bv = parseFloat(b.cells[col].textContent) || 0;
        return sortAsc ? av - bv : bv - av;
      }});
      rows.forEach(function(r) {{ tbody.appendChild(r); }});
    }});
  }});
}})();
</script>
</body>
</html>"""


def save_leaderboard(html: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
