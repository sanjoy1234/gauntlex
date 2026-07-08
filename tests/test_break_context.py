"""Tests for BreakContext token compression — Sprint 2."""

from __future__ import annotations

import pytest

from gauntlex.core.break_context import (
    compress_target,
    compress_forge_recall,
    compress_cwe_context,
    compress_breaker_inputs,
    CompressionStats,
)


# ── compress_target ────────────────────────────────────────────────────────────

# 80+ lines of mostly boring math helpers with ONE security-critical function buried inside
_NOISY_CODE = """\
# This module handles data processing
# Author: test
# Version: 1.0

import os

def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

def multiply(a, b):
    return a * b

def divide(a, b):
    if b == 0:
        raise ValueError("division by zero")
    return a / b

def square(n):
    return n * n

def cube(n):
    return n * n * n

def clamp(v, lo, hi):
    return max(lo, min(hi, v))

def lerp(a, b, t):
    return a + (b - a) * t

def sign(n):
    if n > 0:
        return 1
    if n < 0:
        return -1
    return 0

def is_even(n):
    return n % 2 == 0

def is_odd(n):
    return n % 2 != 0

def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def authenticate_user(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = db.execute(query)
    return cursor.fetchone()

def sum_list(lst):
    return sum(lst)

def product_list(lst):
    result = 1
    for v in lst:
        result *= v
    return result

def flatten(lst):
    out = []
    for item in lst:
        if isinstance(item, list):
            out.extend(flatten(item))
        else:
            out.append(item)
    return out

def zip_dicts(a, b):
    return {k: (a.get(k), b.get(k)) for k in set(a) | set(b)}

def chunk(lst, n):
    return [lst[i:i+n] for i in range(0, len(lst), n)]

def dedupe(lst):
    seen = set()
    return [x for x in lst if not (x in seen or seen.add(x))]
"""


def test_compress_target_reduces_length():
    compressed, kept, total = compress_target(_NOISY_CODE)
    assert kept < total
    assert len(compressed) < len(_NOISY_CODE)


def test_compress_target_keeps_security_lines():
    compressed, _, _ = compress_target(_NOISY_CODE)
    assert "authenticate_user" in compressed
    assert "password" in compressed
    assert "query" in compressed
    assert "cursor" in compressed


def test_compress_target_keeps_imports():
    compressed, _, _ = compress_target(_NOISY_CODE)
    assert "import os" in compressed


def test_compress_target_short_text_passthrough():
    short = "def foo(): return 1"
    compressed, kept, total = compress_target(short)
    assert compressed == short
    assert kept == total


def test_compress_target_empty_passthrough():
    compressed, kept, total = compress_target("")
    assert compressed == ""


def test_compress_target_returns_counts():
    _, kept, total = compress_target(_NOISY_CODE)
    assert kept > 0
    assert total > kept


# ── compress_forge_recall ──────────────────────────────────────────────────────

_RECALL_UNIQUE = """\
SQL injection via username parameter — high confidence attack using UNION SELECT to extract data
---
Path traversal in file download endpoint — attacker supplies ../../etc/passwd to escape root
---
XSS in search results page — unsanitized user input reflected into HTML response"""

_RECALL_DUPLICATE = """\
SQL injection via username parameter using UNION SELECT technique extracts sensitive data from database
---
SQL injection via username parameter using UNION SELECT technique retrieves sensitive data from database
---
Path traversal attack escaping sandbox via dotdot sequences"""


def test_compress_forge_recall_removes_duplicates():
    compressed, after, before = compress_forge_recall(_RECALL_DUPLICATE)
    assert before == 3
    assert after < before  # the two SQL injection duplicates should collapse


def test_compress_forge_recall_keeps_unique_attacks():
    compressed, after, before = compress_forge_recall(_RECALL_UNIQUE)
    assert before == 3
    assert after == 3  # all unique, none dropped


def test_compress_forge_recall_truncates_long_entries():
    long_recall = "A" * 500 + "\n---\n" + "B" * 500
    compressed, _, _ = compress_forge_recall(long_recall, max_per_attack=200)
    for block in compressed.split("---"):
        assert len(block.strip()) <= 200 + 3  # +3 for ellipsis


def test_compress_forge_recall_empty():
    compressed, after, before = compress_forge_recall("")
    assert compressed == ""
    assert after == 0
    assert before == 0


def test_compress_forge_recall_single_entry():
    single = "SQL injection via username"
    compressed, after, before = compress_forge_recall(single)
    assert before == 1
    assert after == 1


# ── compress_cwe_context ───────────────────────────────────────────────────────

_CWE_CONTEXT = """\
- CWE-89: SQL Injection occurs when user-supplied input is not properly sanitized
  before being included in SQL queries, allowing attackers to manipulate the query logic
- CWE-79: Cross-site Scripting allows attackers to inject client-side scripts into web pages
  viewed by other users, potentially stealing session cookies or credentials
- CWE-22: Path Traversal allows attackers to access files outside the intended directory"""


def test_compress_cwe_context_output_shorter():
    compressed = compress_cwe_context(_CWE_CONTEXT)
    assert len(compressed) < len(_CWE_CONTEXT)


def test_compress_cwe_context_preserves_all_cwes():
    compressed = compress_cwe_context(_CWE_CONTEXT)
    assert "CWE-89" in compressed
    assert "CWE-79" in compressed
    assert "CWE-22" in compressed


def test_compress_cwe_context_single_line_entries():
    compressed = compress_cwe_context(_CWE_CONTEXT)
    for line in compressed.splitlines():
        assert len(line) <= 124  # 120 + "…" could be 4 chars


def test_compress_cwe_context_passthrough_if_no_match():
    plain = "No CWE prefixes here at all"
    result = compress_cwe_context(plain)
    assert result == plain


# ── compress_breaker_inputs ────────────────────────────────────────────────────

def test_compress_breaker_inputs_returns_stats():
    target, recall, cwe, stats = compress_breaker_inputs(
        target=_NOISY_CODE,
        recalled_attacks=_RECALL_UNIQUE,
        cwe_context=_CWE_CONTEXT,
    )
    assert isinstance(stats, CompressionStats)
    assert stats.original_chars > 0
    assert stats.compressed_chars > 0
    assert 0.0 <= stats.reduction_pct <= 100.0


def test_compress_breaker_inputs_reduces_total_chars():
    _, _, _, stats = compress_breaker_inputs(
        target=_NOISY_CODE,
        recalled_attacks=_RECALL_UNIQUE,
        cwe_context=_CWE_CONTEXT,
    )
    assert stats.compressed_chars < stats.original_chars
    assert stats.reduction_pct > 0


def test_compress_breaker_inputs_disabled_passthrough():
    c_target, c_recall, c_cwe, stats = compress_breaker_inputs(
        target=_NOISY_CODE,
        recalled_attacks=_RECALL_UNIQUE,
        cwe_context=_CWE_CONTEXT,
        enabled=False,
    )
    assert c_target == _NOISY_CODE
    assert c_recall == _RECALL_UNIQUE
    assert c_cwe == _CWE_CONTEXT
    assert stats.reduction_pct == 0.0


def test_compress_breaker_inputs_stats_line_counts():
    _, _, _, stats = compress_breaker_inputs(
        target=_NOISY_CODE,
        recalled_attacks=_RECALL_UNIQUE,
        cwe_context=_CWE_CONTEXT,
    )
    assert stats.target_lines_total > 0
    assert stats.target_lines_kept > 0
    assert stats.target_lines_kept <= stats.target_lines_total


def test_compress_breaker_inputs_empty_recall():
    _, _, _, stats = compress_breaker_inputs(
        target=_NOISY_CODE,
        recalled_attacks="",
        cwe_context=_CWE_CONTEXT,
    )
    assert stats.recall_attacks_before == 0
    assert stats.recall_attacks_after == 0


# ── Breaker integration ────────────────────────────────────────────────────────

def test_breaker_has_break_context_enabled_attribute():
    from gauntlex.agents.breaker import Breaker
    b = Breaker(provider="ollama", model="llama3.1:8b")
    assert b.break_context_enabled is True


def test_breaker_break_context_disabled_via_constructor():
    from gauntlex.agents.breaker import Breaker
    b = Breaker(provider="ollama", model="llama3.1:8b", break_context_enabled=False)
    assert b.break_context_enabled is False


def test_breaker_result_has_compression_stats_field():
    from gauntlex.agents.breaker import BreakerResult
    from gauntlex.agents.base import ModelResponse
    r = BreakerResult(
        attacks=[],
        model_response=ModelResponse(content="[]", model="test"),
        compression_stats=None,
    )
    assert r.compression_stats is None


def test_config_break_context_enabled_default():
    from gauntlex.config import GauntlexConfig
    assert GauntlexConfig().break_context_enabled is True


def test_config_break_context_enabled_loadable():
    import tempfile, os
    from pathlib import Path
    from gauntlex.config import AppConfig
    yaml_content = "version: 1\ngauntlex:\n  break_context_enabled: false\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        tmp = f.name
    try:
        cfg = AppConfig.load(tmp)
        assert cfg.gauntlex.break_context_enabled is False
    finally:
        os.unlink(tmp)
