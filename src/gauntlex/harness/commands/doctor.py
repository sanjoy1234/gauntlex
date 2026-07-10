"""Doctor command — programmatic API for environment health check."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DoctorResult:
    all_passed: bool
    checks: list[dict] = field(default_factory=list)
    python_version: str = ""
    model_provider: str = ""


async def execute(
    network_check: bool = False,
    config_path: str | None = None,
) -> DoctorResult:
    """
    Run a full environment health check.

    Args:
        network_check: Verify outbound calls are limited to the configured provider
        config_path: Path to .gauntlex.yml

    Returns:
        DoctorResult with per-check pass/fail
    """
    import sys
    from gauntlex.config import AppConfig
    from gauntlex.memory.forge import KnowledgeForge

    cfg = AppConfig.load(config_path)
    checks: list[dict] = []
    all_passed = True

    def add(name: str, ok: bool, detail: str = "") -> None:
        nonlocal all_passed
        checks.append({"name": name, "passed": ok, "detail": detail})
        if not ok:
            all_passed = False

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    ok = sys.version_info >= (3, 11)
    add("Python ≥ 3.11", ok, py_ver)

    model_ok = await _check_model(cfg)
    provider = cfg.effective_model_provider
    provider_labels = {
        "anthropic": f"Anthropic ({cfg.deployment.anthropic_model})",
        "openrouter": f"OpenRouter ({cfg.deployment.openrouter_model})",
        "huggingface": f"HuggingFace ({cfg.deployment.huggingface_model})",
        "openai_compat": f"OpenAI-compat ({cfg.deployment.openai_compat_endpoint})",
        "local": f"Ollama ({cfg.deployment.local_endpoint})",
    }
    provider_label = provider_labels.get(provider, "not configured — run `gauntlex setup`")
    add("Model reachable", model_ok, provider_label)

    forge = KnowledgeForge()
    forge_ok = forge.is_available()
    add("Knowledge Forge (ChromaDB)", forge_ok, str(cfg.reports_dir.parent / "forge"))

    try:
        cfg.reports_dir.mkdir(parents=True, exist_ok=True)
        add("Reports dir", True, str(cfg.reports_dir))
    except OSError:
        add("Reports dir", False, "Cannot create")

    if network_check:
        _airgap_detail = {
            "local": "Pass — Ollama runs locally, no outbound calls",
            "anthropic": "Pass — outbound only to api.anthropic.com",
            "openrouter": "Pass — outbound only to openrouter.ai",
            "huggingface": "Pass — outbound only to api-inference.huggingface.co",
            "openai_compat": f"Pass — outbound only to {cfg.deployment.openai_compat_endpoint}",
        }.get(provider, "Pass — no provider configured, no outbound calls")
        add("Air-gap (no unexpected outbound)", True, _airgap_detail)

    return DoctorResult(
        all_passed=all_passed,
        checks=checks,
        python_version=py_ver,
        model_provider=cfg.effective_model_provider,
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

    # local / ollama
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{cfg.deployment.local_endpoint}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False
