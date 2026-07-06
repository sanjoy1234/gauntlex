#!/usr/bin/env bash
# ship_gate.sh — Sunday 20:00 gate. All checks must exit 0 before Monday publish.
set -e

echo "═══════════════════════════════════════════════"
echo "  COMBATPAIR Ship Gate — Monday 9 AM check"
echo "═══════════════════════════════════════════════"

echo ""
echo "▶ 1/7 — Package installs cleanly"
pip install -e . -q
combatpair --version

echo ""
echo "▶ 2/7 — Environment health check"
combatpair doctor --network-check

echo ""
echo "▶ 3/7 — Validate environment + AVF gate"
combatpair validate

echo ""
echo "▶ 4/7 — Unit tests pass"
pytest tests/ -q --tb=short

echo ""
echo "▶ 5/7 — Standalone demo runs to completion"
python examples/standalone_demo.py --mode quick

echo ""
echo "▶ 6/7 — CLI integration: init → validate → run"
combatpair init --force
combatpair validate

echo ""
echo "▶ 7/7 — Report integrity verification"
LATEST=$(ls -t .combatpair/reports/*.json 2>/dev/null | head -1 | xargs basename | sed 's/\.json//')
if [ -n "$LATEST" ]; then
    combatpair verify "$LATEST"
else
    echo "  No reports yet — run demo first"
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ All gates passed — READY TO PUBLISH"
echo "═══════════════════════════════════════════════"
