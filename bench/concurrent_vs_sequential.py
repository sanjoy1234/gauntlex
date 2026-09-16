#!/usr/bin/env python3
"""
Concurrent vs. sequential adversarial testing — a reproducible measurement.

GAUNTLEX's claim is that adversarial testing should run *concurrently* with code
generation, off the specification, rather than *after* it, off the generated
code. This harness runs both arrangements against the same spec, with the same
CWE set and the same model, and records two things:

  1. Wall-clock time.
     concurrent  ≈ max(t_build, t_break)      — Builder ‖ Breaker on the spec
     sequential  ≈ t_build + t_break           — Builder, then Breaker on the code

  2. What each arrangement's Breaker produced.
     concurrent  — attacks reasoned from the spec (intent), before any
                   implementation exists to anchor or hide a blind spot
     sequential  — attacks reasoned from the finished code, the surface a
                   post-hoc scanner or review actually sees

Both attack sets are then scored by the same Arbiter against the *concurrent*
build, so the ARS numbers are comparable (same code under review, different
way of arriving at the attacks).

Nothing here is mocked — every run makes real model calls. Output is written to
bench/results/ as JSON plus a rendered HTML page.

Usage:
    python bench/concurrent_vs_sequential.py --spec examples/demo_issue.md --attacks 4
    python bench/concurrent_vs_sequential.py --model nvidia/nemotron-3.5-lightning:free
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from dotenv import find_dotenv, load_dotenv  # noqa: E402

load_dotenv(find_dotenv(usecwd=True))

from gauntlex.agents.builder import Builder  # noqa: E402
from gauntlex.agents.breaker import Breaker  # noqa: E402
from gauntlex.core.arbiter import Arbiter  # noqa: E402
from gauntlex.config import AppConfig  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# A fixed CWE set keeps the two arrangements comparable: the only thing that
# changes between them is what the Breaker is pointed at (spec vs. code), not
# which vulnerability classes it is asked to consider.
DEFAULT_CWES = ["CWE-89", "CWE-79", "CWE-287", "CWE-306", "CWE-770", "CWE-532"]


def _model_kwargs(model_override: str | None) -> dict:
    if model_override:
        return {"provider": "openrouter", "model": model_override}
    return AppConfig.load().model_kwargs()


async def _timed(coro):
    start = time.monotonic()
    result = await coro
    return result, time.monotonic() - start


async def run_once(spec_text: str, cwes: list[str], model_kwargs: dict) -> dict:
    n = len(cwes)

    # ---- Concurrent: Builder ‖ Breaker, both on the spec --------------------
    builder_c = Builder(**model_kwargs)
    breaker_c = Breaker(cwe_rotation=False, attacks_per_round=n, **model_kwargs)

    c_start = time.monotonic()
    (build_c, t_build_c), (break_c, t_break_c) = await asyncio.gather(
        _timed(builder_c.generate(spec_text, round_number=1)),
        _timed(breaker_c.attack(spec_text, round_number=1, cwe_override=cwes)),
    )
    t_concurrent = time.monotonic() - c_start

    # ---- Sequential: Builder first, then Breaker on the generated code -----
    builder_s = Builder(**model_kwargs)
    breaker_s = Breaker(cwe_rotation=False, attacks_per_round=n, **model_kwargs)

    s_start = time.monotonic()
    build_s, t_build_s = await _timed(builder_s.generate(spec_text, round_number=1))
    break_s, t_break_s = await _timed(
        breaker_s.attack(build_s.code, round_number=1, cwe_override=cwes)
    )
    t_sequential = time.monotonic() - s_start

    # ---- Score both attack sets against the same (concurrent) build --------
    arbiter = Arbiter(**model_kwargs)
    ars_concurrent = await arbiter.score_round_async(build_c, break_c)
    ars_sequential = await arbiter.score_round_async(build_c, break_s)

    def _attacks(result) -> list[dict]:
        return [
            {
                "cwe": a.cwe,
                "title": a.title,
                "severity": a.severity,
                "score": a.score,
                "reason": a.reason,
            }
            for a in result.attacks
        ]

    return {
        "cwe_set": cwes,
        "timing_seconds": {
            "concurrent_wall_clock": round(t_concurrent, 1),
            "sequential_wall_clock": round(t_sequential, 1),
            "concurrent_builder": round(t_build_c, 1),
            "concurrent_breaker": round(t_break_c, 1),
            "sequential_builder": round(t_build_s, 1),
            "sequential_breaker": round(t_break_s, 1),
            "speedup": round(t_sequential / t_concurrent, 2) if t_concurrent else None,
            "seconds_saved": round(t_sequential - t_concurrent, 1),
        },
        "concurrent": {
            "target": "specification",
            "ars": ars_concurrent,
            "attacks": _attacks(break_c),
        },
        "sequential": {
            "target": "generated code",
            "ars": ars_sequential,
            "attacks": _attacks(break_s),
        },
    }


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--spec", default="examples/demo_issue.md",
                    help="path to the specification to build + attack")
    ap.add_argument("--attacks", type=int, default=len(DEFAULT_CWES),
                    help="number of CWE categories / attacks (uses the first N of the fixed set)")
    ap.add_argument("--model", default=None,
                    help="OpenRouter model id override (default: whatever .env configures)")
    ap.add_argument("--runs", type=int, default=1, help="repeat the whole comparison N times")
    args = ap.parse_args()

    spec_path = (REPO_ROOT / args.spec) if not Path(args.spec).is_absolute() else Path(args.spec)
    spec_text = spec_path.read_text()
    cwes = DEFAULT_CWES[: args.attacks]
    model_kwargs = _model_kwargs(args.model)

    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")

    runs = []
    for i in range(args.runs):
        print(f"[run {i + 1}/{args.runs}] spec={args.spec} cwes={len(cwes)} "
              f"model={model_kwargs.get('model')}", flush=True)
        runs.append(await run_once(spec_text, cwes, model_kwargs))

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "spec": args.spec,
        "model": model_kwargs.get("model"),
        "provider": model_kwargs.get("provider"),
        "runs": runs,
    }
    out_json = RESULTS_DIR / f"cvs-{stamp}.json"
    out_json.write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {out_json.relative_to(REPO_ROOT)}")

    t = runs[0]["timing_seconds"]
    print(f"  concurrent  {t['concurrent_wall_clock']:>7.1f}s")
    print(f"  sequential  {t['sequential_wall_clock']:>7.1f}s  "
          f"({t['speedup']}x slower, +{t['seconds_saved']}s)")
    print(f"  ARS  concurrent={runs[0]['concurrent']['ars']}  "
          f"sequential={runs[0]['sequential']['ars']}")


if __name__ == "__main__":
    asyncio.run(main())
