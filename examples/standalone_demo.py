#!/usr/bin/env python3
"""
COMBATPAIR standalone demo — no installation required beyond the package itself.

Demonstrates the full CombatPair flow on a realistic Flask authentication spec.
Uses Ollama by default (zero cost). Set ANTHROPIC_API_KEY to use Anthropic API.

Usage:
    python examples/standalone_demo.py
    python examples/standalone_demo.py --mode quick
    ANTHROPIC_API_KEY=sk-... python examples/standalone_demo.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

# Ensure package is importable from repo root
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from combatpair.config import AppConfig
from combatpair.core.combat_pair import CombatPair
from combatpair.core.arbiter import Arbiter
from combatpair.output.report import build_report, generate_run_id, render_markdown, save_report
from combatpair.brain.fingerprint import fingerprint_spec

DEMO_SPEC = """
Implement a Python Flask endpoint POST /login that:
- Accepts JSON body: {"username": str, "password": str}
- Looks up the user in a SQLite database by username
- Verifies the password against a stored bcrypt hash
- Returns a JWT token on success (expires in 1 hour)
- Returns HTTP 401 on failure
- Logs all login attempts for audit trail
- Rate limits: max 5 failed attempts per IP per minute
""".strip()

BANNER = """
╔══════════════════════════════════════════════════════╗
║  COMBATPAIR — Adversarial Co-Generation Engine         ║
║  Concurrent Builder + Breaker on the same spec       ║
╚══════════════════════════════════════════════════════╝
"""


async def run_demo(mode: str = "quick") -> None:
    print(BANNER)

    mode_attacks = {"quick": 5, "standard": 20, "thorough": 50}
    attack_count = mode_attacks.get(mode, 5)

    provider = "anthropic" if os.environ.get("ANTHROPIC_API_KEY") else "ollama"
    model = "claude-haiku-4-5-20251001" if provider == "anthropic" else "llama3.1:8b"

    print(f"Mode:     {mode} ({attack_count} attacks)")
    print(f"Provider: {provider} / {model}")
    print(f"Spec fingerprint: {fingerprint_spec(DEMO_SPEC)}")
    print()

    # Check model availability
    if provider == "ollama":
        try:
            import httpx
            resp = httpx.get("http://localhost:11434/api/tags", timeout=3.0)
            if resp.status_code != 200:
                print("⚠  Ollama is not running. Start it with: ollama serve")
                print("   Then: ollama pull llama3.1:8b")
                print("   Or set ANTHROPIC_API_KEY to use Anthropic API instead.")
                return
        except Exception:
            print("⚠  Cannot reach Ollama at http://localhost:11434")
            print("   Start Ollama: ollama serve && ollama pull llama3.1:8b")
            print("   Or set ANTHROPIC_API_KEY to use Anthropic API.")
            return

    cfg = AppConfig()
    cfg.combat_pair.attack_count = attack_count
    cfg.combat_pair.rounds_max = 2
    cfg.deployment.model_provider = provider
    if provider == "anthropic":
        cfg.deployment.anthropic_model = model
    else:
        cfg.deployment.local_model = model

    model_kwargs = {"provider": provider, "model": model}

    print("Starting CombatPair...")
    print("  Builder and Breaker running CONCURRENTLY via asyncio.gather()")
    print()

    arbiter = Arbiter(**model_kwargs)
    pair = CombatPair(config=cfg)

    try:
        result = await pair.run(DEMO_SPEC, arbiter)
    except Exception as e:
        print(f"Error during run: {e}")
        print("Check that your model is running and accessible.")
        return

    # LLM arbiter scoring
    print("Scoring attacks with Arbiter...")
    for round_result in result.rounds:
        await arbiter.score_round_async(round_result.build, round_result.breaker)
    result.final_ars = arbiter.final_ars(result.all_attacks)

    # Generate report
    run_id = generate_run_id()
    report = build_report(result, run_id, spec_ref="examples/demo_issue.md")

    # Save to .combatpair/reports/
    reports_dir = Path(".combatpair/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = save_report(report, reports_dir)

    # Print results
    print()
    print("=" * 55)
    print(f"  ARS Score:    {result.final_ars:.3f}")
    passed = result.final_ars >= 0.80
    print(f"  Gate:         {'✅ PASSED' if passed else '❌ FAILED (ARS < 0.80)'}")
    print(f"  Attacks:      {result.attack_count} fired")
    print(f"  Mitigated:    {result.mitigated_count}")
    print(f"  Missed:       {result.miss_count}")
    print(f"  Elapsed:      {result.total_elapsed_seconds:.1f}s")
    print(f"  Early exit:   {result.early_exit}")
    print(f"  Report:       {report_path}")
    print("=" * 55)

    if result.miss_count > 0:
        print("\nUnmitigated attacks:")
        for a in result.all_attacks:
            if a.score == 0.0:
                print(f"  ✗ [{a.cwe}] {a.title}")

    print(f"\nIntegrity hash: {report['integrity_hash']}")
    print("\nFull Markdown report:\n")
    print(render_markdown(report))


def main():
    mode = "quick"
    for arg in sys.argv[1:]:
        if arg.startswith("--mode="):
            mode = arg.split("=", 1)[1]
        elif arg == "--mode" and sys.argv.index(arg) + 1 < len(sys.argv):
            mode = sys.argv[sys.argv.index(arg) + 1]
    asyncio.run(run_demo(mode=mode))


if __name__ == "__main__":
    main()
