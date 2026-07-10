"""Validate command — programmatic API for gauntlex validate + AVF gate."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


@dataclass
class ValidateResult:
    all_passed: bool
    checks: list[CheckResult] = field(default_factory=list)
    avf_hit_rate: float = 0.0
    avf_skipped: bool = False


async def execute(
    spec_path: str | None = None,
    run_avf: bool = True,
    config_path: str | None = None,
) -> ValidateResult:
    """
    Validate environment, model connectivity, policy domains, and AVF gate.

    Args:
        spec_path: Optional spec file to check readability
        run_avf: Whether to run Breaker against AVF golden fixtures (requires live model)
        config_path: Path to .gauntlex.yml

    Returns:
        ValidateResult with per-check results and AVF hit rate
    """
    from pathlib import Path
    from gauntlex.config import AppConfig
    from gauntlex.policy.engine import list_available_domains

    cfg = AppConfig.load(config_path)
    checks: list[CheckResult] = []
    all_passed = True

    checks.append(CheckResult("Config loaded", True, ".gauntlex.yml"))

    if spec_path:
        ok = Path(spec_path).exists()
        checks.append(CheckResult("Spec readable", ok, spec_path))
        if not ok:
            all_passed = False

    model_ok = await _check_model(cfg)
    _pl = {
        "anthropic": cfg.deployment.anthropic_model,
        "openrouter": cfg.deployment.openrouter_model,
        "huggingface": cfg.deployment.huggingface_model,
        "openai_compat": cfg.deployment.openai_compat_endpoint,
        "local": cfg.deployment.local_model,
    }
    _model_label = _pl.get(cfg.effective_model_provider, "not configured — run `gauntlex setup`")
    checks.append(CheckResult("Model reachable", model_ok, _model_label))
    if not model_ok:
        all_passed = False

    available = list_available_domains()
    for domain in cfg.policy.domains:
        name = domain.split("@")[0]
        ok = name in available
        checks.append(CheckResult(f"Domain '{name}'", ok, "found" if ok else "NOT FOUND"))
        if not ok:
            all_passed = False

    try:
        cfg.reports_dir.mkdir(parents=True, exist_ok=True)
        checks.append(CheckResult("Reports dir writable", True, str(cfg.reports_dir)))
    except OSError as e:
        checks.append(CheckResult("Reports dir writable", False, str(e)))
        all_passed = False

    avf_hit_rate = 0.0
    avf_skipped = False

    if run_avf and model_ok:
        avf_hit_rate = await _run_avf_gate(cfg)
        avf_ok = avf_hit_rate >= 0.75
        detail = f"{avf_hit_rate:.0%} ({int(round(avf_hit_rate * 5))}/5 fixtures found)"
        checks.append(CheckResult("AVF gate (≥75% fixture hits)", avf_ok, detail))
        if not avf_ok:
            all_passed = False
    else:
        avf_skipped = True
        reason = "model unavailable" if not model_ok else "disabled"
        checks.append(CheckResult("AVF gate", True, f"SKIPPED — {reason}"))

    return ValidateResult(
        all_passed=all_passed,
        checks=checks,
        avf_hit_rate=avf_hit_rate,
        avf_skipped=avf_skipped,
    )


async def _check_model(cfg) -> bool:
    import os
    import httpx

    provider = cfg.effective_model_provider
    if provider is None:
        return False
    if provider == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if provider == "openrouter":
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    "https://openrouter.ai/api/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                return resp.status_code == 200
        except Exception:
            return False
    if provider == "huggingface":
        return bool(os.environ.get("HF_TOKEN"))
    if provider == "openai_compat":
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{cfg.deployment.openai_compat_endpoint}/models")
                return resp.status_code == 200
        except Exception:
            return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{cfg.deployment.local_endpoint}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


async def _run_avf_gate(cfg) -> float:
    """Run Breaker against golden CVE fixtures. Returns hit rate 0.0–1.0."""
    import json
    from pathlib import Path
    from gauntlex.agents.breaker import Breaker

    golden_dir = Path(__file__).parent.parent.parent.parent.parent / "tests" / "fixtures" / "golden"
    if not golden_dir.exists():
        return 0.0

    fixtures = sorted(golden_dir.glob("*.json"))
    if not fixtures:
        return 0.0

    model_kwargs: dict = cfg.model_kwargs()

    hits = 0
    for fixture_path in fixtures:
        try:
            fixture = json.loads(fixture_path.read_text())
            breaker = Breaker(cwe_rotation=False, **model_kwargs)
            result = await breaker.attack(
                target=fixture["vulnerable_code"],
                round_number=1,
                cwe_override=[fixture["expected_cwe"]],
            )
            if _hits_fixture(result.attacks, fixture):
                hits += 1
        except Exception:
            continue

    return hits / len(fixtures)


def _hits_fixture(attacks, fixture: dict) -> bool:
    keyword = fixture.get("expected_keyword", "").lower()
    expected_cwe = fixture.get("expected_cwe", "")
    for attack in attacks:
        text = f"{attack.title} {attack.description} {attack.cwe}".lower()
        if (keyword and keyword in text) or attack.cwe == expected_cwe:
            return True
    return False
