"""
Forge Ledger — human-readable Markdown vault over Knowledge Forge data.

Writes one Markdown file per attack into:
  .gauntlex/vault/<CWE-XXX>/<run_id>-<attack_id>.md

Each file carries YAML frontmatter for programmatic reading plus prose for
human auditors. The vault serves as the paper trail for compliance reviewers
who need to inspect the adversarial memory without running a ChromaDB query.

CLI: gauntlex vault --stats
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_VAULT_DIR = Path(".gauntlex/vault")
_SLUG_RE = re.compile(r"[^\w\-]")


def _slugify(text: str, max_len: int = 40) -> str:
    slug = _SLUG_RE.sub("-", text.lower()).strip("-")
    return slug[:max_len].rstrip("-")


@dataclass
class LedgerEntry:
    cwe: str
    attack_id: str
    title: str
    description: str
    severity: str
    effectiveness: float
    run_id: str
    fingerprint: str
    recorded_at: str


def _entry_to_markdown(entry: LedgerEntry) -> str:
    eff_label = (
        "MITIGATED" if entry.effectiveness >= 1.0
        else "PARTIAL" if entry.effectiveness >= 0.5
        else "MISSED"
    )
    return f"""\
---
cwe: {entry.cwe}
attack_id: {entry.attack_id}
severity: {entry.severity}
effectiveness: {entry.effectiveness:.2f}
verdict: {eff_label}
run_id: {entry.run_id}
fingerprint: {entry.fingerprint}
recorded_at: {entry.recorded_at}
---

# [{entry.cwe}] {entry.title}

**Severity:** {entry.severity}
**Effectiveness:** {entry.effectiveness:.2f} ({eff_label})
**Run:** `{entry.run_id}`
**Codebase fingerprint:** `{entry.fingerprint}`
**Recorded:** {entry.recorded_at}

## Description

{entry.description}
"""


class ForgeLedger:
    """Writes and reads the Markdown vault of adversarial memory entries."""

    def __init__(self, vault_dir: Path | str = _DEFAULT_VAULT_DIR):
        self._vault = Path(vault_dir)

    def write_entry(
        self,
        cwe: str,
        attack_id: str,
        title: str,
        description: str,
        severity: str,
        effectiveness: float,
        run_id: str,
        fingerprint: str = "",
    ) -> Path:
        """Write a single attack as a Markdown file in the vault. Returns the path written."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = LedgerEntry(
            cwe=cwe,
            attack_id=attack_id,
            title=title,
            description=description,
            severity=severity,
            effectiveness=effectiveness,
            run_id=run_id,
            fingerprint=fingerprint,
            recorded_at=now,
        )

        cwe_dir = self._vault / cwe.upper()
        cwe_dir.mkdir(parents=True, exist_ok=True)

        slug = _slugify(title)
        filename = f"{run_id[-8:]}-{attack_id}-{slug}.md"
        path = cwe_dir / filename
        # File lock prevents corruption when multiple gauntlex runs write concurrently
        import fcntl
        lock_path = cwe_dir / ".write.lock"
        with open(lock_path, "w") as lf:
            try:
                fcntl.flock(lf, fcntl.LOCK_EX)
                path.write_text(_entry_to_markdown(entry), encoding="utf-8")
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
        return path

    def list_entries(self, cwe_filter: str | None = None) -> list[LedgerEntry]:
        """Read all vault entries, optionally filtered by CWE category."""
        entries: list[LedgerEntry] = []
        if not self._vault.exists():
            return entries

        pattern = (cwe_filter.upper() if cwe_filter else "*")
        for cwe_dir in sorted(self._vault.glob(pattern)):
            if not cwe_dir.is_dir():
                continue
            for md_file in sorted(cwe_dir.glob("*.md")):
                entry = _parse_entry(md_file)
                if entry:
                    entries.append(entry)
        return entries

    def stats(self) -> dict:
        """
        Return summary statistics for the vault.

        Keys:
          total_entries        — total Markdown files in vault
          cwe_counts           — dict[CWE, count] sorted by count desc
          severity_counts      — dict[severity, count]
          avg_effectiveness    — float mean across all entries
          top_cwes             — top 5 CWEs by entry count
        """
        entries = self.list_entries()
        if not entries:
            return {
                "total_entries": 0,
                "cwe_counts": {},
                "severity_counts": {},
                "avg_effectiveness": 0.0,
                "top_cwes": [],
            }

        cwe_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        total_eff = 0.0

        for e in entries:
            cwe_counts[e.cwe] = cwe_counts.get(e.cwe, 0) + 1
            severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1
            total_eff += e.effectiveness

        sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)
        return {
            "total_entries": len(entries),
            "cwe_counts": dict(sorted_cwes),
            "severity_counts": severity_counts,
            "avg_effectiveness": round(total_eff / len(entries), 3),
            "top_cwes": [cwe for cwe, _ in sorted_cwes[:5]],
        }

    def render_stats_markdown(self) -> str:
        s = self.stats()
        lines = [
            "## Forge Ledger Stats",
            "",
            f"- **Total entries:** {s['total_entries']}",
            f"- **Average effectiveness:** {s['avg_effectiveness']:.3f}",
            "",
            "### Top CWE Categories",
            "",
        ]
        for cwe, count in list(s["cwe_counts"].items())[:10]:
            lines.append(f"- `{cwe}`: {count} entries")

        if s["severity_counts"]:
            lines += ["", "### Severity Distribution", ""]
            for sev, count in sorted(s["severity_counts"].items()):
                lines.append(f"- {sev}: {count}")

        return "\n".join(lines)


def _parse_entry(path: Path) -> LedgerEntry | None:
    """Parse YAML frontmatter from a vault Markdown file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    if not text.startswith("---"):
        return None

    # Extract frontmatter block between the two --- delimiters
    end = text.find("\n---\n", 3)
    if end == -1:
        return None
    frontmatter = text[3:end]

    fields: dict[str, str] = {}
    for line in frontmatter.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip()] = v.strip()

    # Extract title from the first H1 in the body
    title = ""
    for line in text[end:].splitlines():
        if line.startswith("# "):
            title = re.sub(r"^\[CWE-\d+\]\s*", "", line[2:]).strip()
            break

    try:
        return LedgerEntry(
            cwe=fields.get("cwe", ""),
            attack_id=fields.get("attack_id", ""),
            title=title,
            description="",
            severity=fields.get("severity", "medium"),
            effectiveness=float(fields.get("effectiveness", "0")),
            run_id=fields.get("run_id", ""),
            fingerprint=fields.get("fingerprint", ""),
            recorded_at=fields.get("recorded_at", ""),
        )
    except ValueError:
        return None
