"""Tests for ARS Leaderboard engine — Sprint 11."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from combatpair.leaderboard.engine import (
    AgentScore,
    LeaderboardEntry,
    build_leaderboard,
    load_agent_scores_from_jsonl,
    load_agent_scores_from_reports,
    render_leaderboard_html,
    save_leaderboard,
)


# ── AgentScore / LeaderboardEntry ─────────────────────────────────────────────

def test_agent_score_defaults():
    s = AgentScore(agent_name="gpt4o", task_id="django-1", ars_score=0.85, attack_count=5, miss_count=1)
    assert s.patch_sha == ""


def test_leaderboard_entry_rank_score():
    e = LeaderboardEntry(
        agent_name="a", task_count=10, avg_ars=0.90, median_ars=0.90,
        min_ars=0.70, max_ars=1.0, total_attacks=50, total_misses=5,
        pass_rate=0.80, gate_threshold=0.80,
    )
    # rank_score = 0.90*0.6 + 0.80*0.4 = 0.54 + 0.32 = 0.86
    assert abs(e.rank_score - 0.86) < 1e-9


# ── load_agent_scores_from_jsonl ──────────────────────────────────────────────

def test_load_jsonl_missing_file(tmp_path):
    scores = load_agent_scores_from_jsonl(tmp_path / "nofile.jsonl")
    assert scores == []


def test_load_jsonl_parses_records(tmp_path):
    data = [
        {"agent_name": "gpt4o", "task_id": "django-1", "ars_score": 0.90, "attack_count": 5, "miss_count": 0},
        {"agent_name": "gpt4o", "task_id": "django-2", "ars_score": 0.75, "attack_count": 4, "miss_count": 1},
        {"agent_name": "gemini", "task_id": "django-1", "ars_score": 0.60, "attack_count": 3, "miss_count": 2},
    ]
    f = tmp_path / "scores.jsonl"
    f.write_text("\n".join(json.dumps(d) for d in data))
    scores = load_agent_scores_from_jsonl(f)
    assert len(scores) == 3
    assert scores[0].agent_name == "gpt4o"
    assert scores[0].ars_score == 0.90


def test_load_jsonl_skips_malformed_lines(tmp_path):
    f = tmp_path / "scores.jsonl"
    f.write_text(
        '{"agent_name": "gpt4o", "task_id": "t1", "ars_score": 0.8}\n'
        'NOT JSON\n'
        '{"agent_name": "gemini", "task_id": "t2", "ars_score": 0.7}\n'
    )
    scores = load_agent_scores_from_jsonl(f)
    assert len(scores) == 2


def test_load_jsonl_skips_lines_missing_required_fields(tmp_path):
    f = tmp_path / "scores.jsonl"
    f.write_text(
        '{"agent_name": "gpt4o", "ars_score": 0.8}\n'   # missing task_id
        '{"agent_name": "ok", "task_id": "t1", "ars_score": 0.9}\n'
    )
    scores = load_agent_scores_from_jsonl(f)
    assert len(scores) == 1
    assert scores[0].agent_name == "ok"


# ── load_agent_scores_from_reports ────────────────────────────────────────────

def test_load_reports_empty_dir(tmp_path):
    scores = load_agent_scores_from_reports(tmp_path / "nonexistent")
    assert scores == []


def test_load_reports_parses_agent_and_task_from_filename(tmp_path):
    report = {"run_id": "r1", "ars_score": 0.85, "attack_count": 6, "miss_count": 1}
    (tmp_path / "gpt4o--django-001.json").write_text(json.dumps(report))
    scores = load_agent_scores_from_reports(tmp_path)
    assert len(scores) == 1
    assert scores[0].agent_name == "gpt4o"
    assert scores[0].task_id == "django-001"
    assert scores[0].ars_score == 0.85


def test_load_reports_fallback_agent_name_when_no_double_dash(tmp_path):
    report = {"run_id": "r1", "ars_score": 0.70, "attack_count": 3, "miss_count": 1}
    (tmp_path / "plain-run-id.json").write_text(json.dumps(report))
    scores = load_agent_scores_from_reports(tmp_path)
    assert scores[0].agent_name == "unknown"


def test_load_reports_skips_corrupt_json(tmp_path):
    (tmp_path / "gpt4o--t1.json").write_text("{not valid}")
    scores = load_agent_scores_from_reports(tmp_path)
    assert scores == []


# ── build_leaderboard ─────────────────────────────────────────────────────────

def _make_scores(agent: str, ars_list: list[float]) -> list[AgentScore]:
    return [
        AgentScore(agent_name=agent, task_id=f"t{i}", ars_score=v, attack_count=5, miss_count=0)
        for i, v in enumerate(ars_list)
    ]


def test_build_leaderboard_empty():
    assert build_leaderboard([]) == []


def test_build_leaderboard_single_agent():
    scores = _make_scores("gpt4o", [0.80, 0.90, 1.00])
    entries = build_leaderboard(scores, gate_threshold=0.80)
    assert len(entries) == 1
    e = entries[0]
    assert e.agent_name == "gpt4o"
    assert e.task_count == 3
    assert abs(e.avg_ars - 0.90) < 1e-9
    assert e.pass_rate == 1.0


def test_build_leaderboard_sorted_by_rank_score():
    scores = _make_scores("weak", [0.50, 0.55]) + _make_scores("strong", [0.95, 1.00])
    entries = build_leaderboard(scores, gate_threshold=0.80)
    assert entries[0].agent_name == "strong"
    assert entries[1].agent_name == "weak"


def test_build_leaderboard_pass_rate_calculation():
    scores = _make_scores("agent", [0.90, 0.90, 0.50, 0.50])  # 2/4 pass
    entries = build_leaderboard(scores, gate_threshold=0.80)
    assert entries[0].pass_rate == 0.50


def test_build_leaderboard_aggregates_attacks_and_misses():
    scores = [
        AgentScore("a", "t1", 0.80, attack_count=6, miss_count=2),
        AgentScore("a", "t2", 0.90, attack_count=4, miss_count=1),
    ]
    entries = build_leaderboard(scores)
    e = entries[0]
    assert e.total_attacks == 10
    assert e.total_misses == 3


# ── render_leaderboard_html ───────────────────────────────────────────────────

def test_render_empty_leaderboard():
    html = render_leaderboard_html([])
    assert "<!DOCTYPE html>" in html
    assert "No leaderboard data" in html


def test_render_shows_agent_name():
    scores = _make_scores("gpt4o", [0.85, 0.90])
    entries = build_leaderboard(scores)
    html = render_leaderboard_html(entries)
    assert "gpt4o" in html


def test_render_shows_medals():
    scores = _make_scores("alpha", [0.95]) + _make_scores("beta", [0.80]) + _make_scores("gamma", [0.60])
    entries = build_leaderboard(scores)
    html = render_leaderboard_html(entries)
    assert "🥇" in html
    assert "🥈" in html
    assert "🥉" in html


def test_render_has_bright_theme():
    html = render_leaderboard_html([])
    assert "#F8FAFC" in html or "#F0F9FF" in html
    assert "#1a1a1a" not in html  # no dark mode


def test_render_has_sortable_script():
    scores = _make_scores("x", [0.85])
    html = render_leaderboard_html(build_leaderboard(scores))
    assert "data-col" in html
    assert "sort" in html.lower()


def test_render_custom_title():
    html = render_leaderboard_html([], title="My Custom Board")
    assert "My Custom Board" in html


def test_render_generated_at_stamp():
    html = render_leaderboard_html([], generated_at="2026-06-28 12:00 UTC")
    assert "2026-06-28 12:00 UTC" in html


def test_render_gate_threshold_shown():
    html = render_leaderboard_html([], gate_threshold=0.75)
    assert "0.75" in html


# ── save_leaderboard ──────────────────────────────────────────────────────────

def test_save_leaderboard_creates_file(tmp_path):
    out = tmp_path / "sub" / "leaderboard.html"
    save_leaderboard("<html/>", out)
    assert out.exists()
    assert out.read_text() == "<html/>"


def test_save_leaderboard_creates_parent_dirs(tmp_path):
    out = tmp_path / "docs" / "nested" / "lb.html"
    save_leaderboard("content", out)
    assert out.exists()
