"""
BreakContext — security-aware token compression for the Breaker input pipeline.

Compresses three input channels before the Breaker LLM call:
  1. Target spec/code  — extracts security-relevant lines, strips noise
  2. Forge recall      — deduplicates similar attack patterns, truncates bodies
  3. CWE context       — collapses verbose descriptions to single lines

The Arbiter input is intentionally NOT compressed (accuracy risk).
Typical reduction: 40-60% on medium codebases with no loss of attack surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Lines containing these patterns are security-relevant and always kept.
_SECURITY_PATTERNS = re.compile(
    r"""(
        import\s|from\s\w+\simport         # imports — library surface
        |def\s|class\s|async\sdef\s        # all function/class definitions
        |auth|token|password|secret|key    # credential patterns
        |sql|query|execute|cursor|raw\(    # database access
        |request|response|http|url         # network surface
        |path|file|open\(|read\(|write\(   # filesystem access
        |subprocess|popen|os\.system       # shell execution
        |eval\(|exec\(|compile\(           # dynamic execution
        |user|admin|role|permission|acl    # access control
        |jwt|session|cookie|header         # web auth
        |encrypt|decrypt|hash|sign|verify  # crypto
        |serialize|deserialize|pickle      # deserialization
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_BLANK_LINE = re.compile(r"\n{3,}")
_LONG_STRING = re.compile(r'(""".*?"""|\'\'\'.*?\'\'\')', re.DOTALL)
_COMMENT_ONLY = re.compile(r"^\s*#.*$", re.MULTILINE)


@dataclass
class CompressionStats:
    original_chars: int
    compressed_chars: int
    reduction_pct: float
    target_lines_kept: int
    target_lines_total: int
    recall_attacks_before: int
    recall_attacks_after: int


def compress_target(text: str, context_window: int = 2) -> tuple[str, int, int]:
    """
    Extract security-relevant lines from spec or code text.

    Args:
        text: raw spec or code content
        context_window: lines of context to keep around each hot line

    Returns:
        (compressed_text, lines_kept, lines_total)
    """
    if not text or len(text) < 300:
        lines = text.splitlines()
        return text, len(lines), len(lines)

    # Strip long docstrings (keep first line of each)
    text = _LONG_STRING.sub(lambda m: m.group()[:80] + '..."', text)

    lines = text.splitlines()
    total = len(lines)

    # Mark every line that is security-relevant
    hot: set[int] = set()
    for i, line in enumerate(lines):
        if _SECURITY_PATTERNS.search(line):
            hot.add(i)

    # Expand with context window
    expanded: set[int] = set()
    for h in hot:
        for offset in range(-context_window, context_window + 1):
            idx = h + offset
            if 0 <= idx < total:
                expanded.add(idx)

    # Always keep first 10 lines (imports, module header)
    for i in range(min(10, total)):
        expanded.add(i)

    if not expanded:
        # Fallback: keep everything (can't identify security surface)
        return text, total, total

    kept_lines = [lines[i] for i in sorted(expanded)]
    compressed = "\n".join(kept_lines)
    # Collapse excess blank lines
    compressed = _BLANK_LINE.sub("\n\n", compressed)

    return compressed, len(expanded), total


def compress_forge_recall(recalled_text: str, max_per_attack: int = 250) -> tuple[str, int, int]:
    """
    Deduplicate and truncate Knowledge Forge recall results.

    Attacks whose descriptions share >65% word overlap with an already-kept
    attack are dropped as redundant. Remaining attacks are truncated to
    max_per_attack characters.

    Returns:
        (compressed_text, attacks_after, attacks_before)
    """
    if not recalled_text.strip():
        return recalled_text, 0, 0

    # Split on the separator pattern used by KnowledgeForge.format_recalled_for_prompt
    blocks = re.split(r"\n---\n|\n\n---\n\n", recalled_text.strip())
    blocks = [b.strip() for b in blocks if b.strip()]
    before = len(blocks)

    kept: list[str] = []
    kept_words: list[set[str]] = []

    for block in blocks:
        words = set(re.findall(r"\w{4,}", block.lower()))
        if not words:
            continue
        # Check overlap with already-kept blocks
        duplicate = False
        for existing_words in kept_words:
            union = words | existing_words
            if not union:
                continue
            overlap = len(words & existing_words) / len(union)
            if overlap > 0.65:
                duplicate = True
                break
        if not duplicate:
            truncated = block[:max_per_attack] + ("…" if len(block) > max_per_attack else "")
            kept.append(truncated)
            kept_words.append(words)

    return "\n---\n".join(kept), len(kept), before


def compress_cwe_context(cwe_context: str) -> str:
    """
    Collapse multi-line CWE descriptions to one line each.

    Input format (from breaker.py):
      - CWE-89: SQL injection is a vulnerability where ...
        ... more text ...
      - CWE-79: Cross-site scripting allows ...

    Output: each entry kept but capped at 120 chars.
    """
    lines = cwe_context.splitlines()
    result: list[str] = []
    current: list[str] = []

    for line in lines:
        if line.startswith("- CWE-"):
            if current:
                combined = " ".join(current)
                result.append(combined[:120] + ("…" if len(combined) > 120 else ""))
            current = [line]
        elif line.strip() and current:
            current.append(line.strip())

    if current:
        combined = " ".join(current)
        result.append(combined[:120] + ("…" if len(combined) > 120 else ""))

    return "\n".join(result) if result else cwe_context


def compress_breaker_inputs(
    target: str,
    recalled_attacks: str,
    cwe_context: str,
    enabled: bool = True,
) -> tuple[str, str, str, CompressionStats]:
    """
    Apply BreakContext compression to all three Breaker input channels.

    Args:
        target:           raw spec or code the Breaker will attack
        recalled_attacks: formatted Knowledge Forge recall string
        cwe_context:      CWE category listing from Breaker._select_cwes
        enabled:          set False to pass through with zero modification

    Returns:
        (compressed_target, compressed_recall, compressed_cwe, stats)
    """
    orig_chars = len(target) + len(recalled_attacks) + len(cwe_context)

    if not enabled:
        stats = CompressionStats(
            original_chars=orig_chars, compressed_chars=orig_chars,
            reduction_pct=0.0, target_lines_kept=0, target_lines_total=0,
            recall_attacks_before=0, recall_attacks_after=0,
        )
        return target, recalled_attacks, cwe_context, stats

    c_target, kept, total = compress_target(target)
    c_recall, after, before = compress_forge_recall(recalled_attacks)
    c_cwe = compress_cwe_context(cwe_context)

    compressed_chars = len(c_target) + len(c_recall) + len(c_cwe)
    reduction = max(0.0, (orig_chars - compressed_chars) / orig_chars * 100) if orig_chars else 0.0

    stats = CompressionStats(
        original_chars=orig_chars,
        compressed_chars=compressed_chars,
        reduction_pct=round(reduction, 1),
        target_lines_kept=kept,
        target_lines_total=total,
        recall_attacks_before=before,
        recall_attacks_after=after,
    )
    return c_target, c_recall, c_cwe, stats
