"""AppConfig — loads and validates .gauntlex.yml."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml


class ModelProviderNotConfiguredError(RuntimeError):
    """Raised by AppConfig.model_kwargs() when no model provider has been
    explicitly configured — GAUNTLEX never assumes a default provider."""

    def __init__(self) -> None:
        super().__init__(
            "No model provider is configured. GAUNTLEX never assumes a default "
            "model or provider — you have to choose one explicitly.\n\n"
            "  Fix:  gauntlex setup   (interactive wizard — pick a free OpenRouter "
            "model, Anthropic, HuggingFace, OpenAI-compatible, or local Ollama)\n\n"
            "  Or set one of these environment variables yourself:\n"
            "    OPENROUTER_API_KEY, ANTHROPIC_API_KEY, HF_TOKEN, OPENAI_COMPAT_API_KEY\n"
            "  Or set MODEL_PROVIDER explicitly (e.g. MODEL_PROVIDER=local for Ollama)."
        )


@dataclass
class GauntlexConfig:
    attack_count: int = 20
    rounds_max: int = 5
    cwe_rotation: bool = True
    early_exit_threshold: float = 0.95
    early_exit_streak: int = 3
    break_context_enabled: bool = True  # BreakContext token compression for Breaker input
    consensus_samples: int = 1  # >1 enables Arbiter self-consistency (multi-sample) scoring


@dataclass
class PolicyConfig:
    domains: list[str] = field(default_factory=lambda: ["owasp_top10@2025.1"])


@dataclass
class GateConfig:
    minimum_ars: float = 0.80
    fail_open: bool = False
    exempt_labels: list[str] = field(default_factory=lambda: ["gauntlex-exempt", "hotfix"])


@dataclass
class DeploymentConfig:
    # None means "not configured yet" — GAUNTLEX never silently assumes a provider.
    # It only becomes non-None via an explicit `deployment:` section in .gauntlex.yml,
    # an explicit MODEL_PROVIDER env var (both written by `gauntlex setup`), or a
    # recognized provider API key being present. See AppConfig.load().
    model_provider: Literal["local", "anthropic", "openrouter", "huggingface", "openai_compat"] | None = None
    # Ollama (local)
    local_model: str = "llama3.1:8b"
    local_endpoint: str = "http://localhost:11434"
    # Anthropic
    anthropic_model: str = "claude-haiku-4-5-20251001"
    # OpenRouter — free and paid open-source models
    openrouter_model: str = "meta-llama/llama-3.3-70b-instruct:free"
    # HuggingFace Inference API
    huggingface_model: str = "meta-llama/Llama-3.1-70B-Instruct"
    # Generic OpenAI-compatible (vLLM, Together AI, Groq, Azure OpenAI, etc.)
    openai_compat_endpoint: str = "http://localhost:8000/v1"
    openai_compat_model: str = "llama3.1:8b"


@dataclass
class RbacConfig:
    admin_teams: list[str] = field(default_factory=list)
    reviewer_teams: list[str] = field(default_factory=list)


@dataclass
class NotificationsConfig:
    jira_project: str = ""
    slack_webhook: str = ""


@dataclass
class AppConfig:
    version: int = 1
    gauntlex: GauntlexConfig = field(default_factory=GauntlexConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    gate: GateConfig = field(default_factory=GateConfig)
    deployment: DeploymentConfig = field(default_factory=DeploymentConfig)
    rbac: RbacConfig = field(default_factory=RbacConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    retention_days: int = 365
    community_brain: bool = False
    mcp_servers: list[dict] = field(default_factory=list)  # Domain Intelligence Adapter

    # Live threat intelligence — REST API enrichment (no API key required for KEV)
    nvd_enabled: bool = False   # NIST NVD API v2.0; set NVD_API_KEY env var for higher rate limits
    kev_enabled: bool = True    # CISA Known Exploited Vulnerabilities feed (free, no key needed)
    nvd_lookback_days: int = 90  # How many days back to query NVD (default: 90 days)

    # resolved at load time
    reports_dir: Path = field(default_factory=lambda: Path(".gauntlex/reports"))
    # Path to the .gauntlex.yml actually found, or None if none was found anywhere
    # up the directory tree — lets callers (e.g. the dashboard) warn the user
    # instead of silently showing an empty project.
    config_source: Path | None = field(default=None)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "AppConfig":
        """Load config from .gauntlex.yml.

        Resolution order when `path` isn't given explicitly:
          1. Walk up from cwd (same convention as git/npm) — correct when you're
             inside the project you mean to test.
          2. Fall back to the last project any `gauntlex` command successfully
             resolved on this machine — so read-only commands like `gauntlex
             dashboard`/`gauntlex status` just work from anywhere (a fresh
             terminal at $HOME, a different tab, etc.) without ever needing an
             explicit --config. Whichever project you're actually inside always
             wins over this fallback.
        """
        explicit = path is not None
        via_cwd_walk = False
        if path is None:
            path = _find_config()
            via_cwd_walk = path is not None
            if path is None:
                path = _recall_last_project()

        cfg = cls()
        deployment_explicit = False

        # Anchor reports_dir to the project root (where .gauntlex.yml lives), not to
        # whatever directory the process happens to be invoked from. Without this,
        # `gauntlex dashboard` run from a different terminal/cwd than `gauntlex run`
        # silently reads/writes a completely different, empty .gauntlex/reports.
        found = path is not None and Path(path).exists()
        project_root = Path(path).resolve().parent if found else Path.cwd()
        cfg.reports_dir = project_root / ".gauntlex" / "reports"
        cfg.config_source = Path(path).resolve() if found else None
        if found and (explicit or via_cwd_walk):
            # Only remember projects found via cwd-walk or an explicit --config —
            # never re-remember a project we only reached via the fallback itself.
            _remember_project(project_root)

        if found:
            with open(path) as f:
                raw = yaml.safe_load(f) or {}

            cfg.version = raw.get("version", 1)

            if cp := raw.get("gauntlex"):
                cfg.gauntlex = GauntlexConfig(
                    attack_count=cp.get("attack_count", 20),
                    rounds_max=cp.get("rounds_max", 5),
                    cwe_rotation=cp.get("cwe_rotation", True),
                    early_exit_threshold=cp.get("early_exit_threshold", 0.95),
                    early_exit_streak=cp.get("early_exit_streak", 3),
                    break_context_enabled=cp.get("break_context_enabled", True),
                    consensus_samples=cp.get("consensus_samples", 1),
                )

            if p := raw.get("policy"):
                cfg.policy = PolicyConfig(domains=p.get("domains", ["owasp_top10@2025.1"]))

            if g := raw.get("gate"):
                cfg.gate = GateConfig(
                    minimum_ars=g.get("minimum_ars", 0.80),
                    fail_open=g.get("fail_open", False),
                    exempt_labels=g.get("exempt_labels", ["gauntlex-exempt", "hotfix"]),
                )

            if d := raw.get("deployment"):
                cfg.deployment = DeploymentConfig(
                    model_provider=d.get("model_provider"),
                    local_model=d.get("local_model", "llama3.1:8b"),
                    local_endpoint=d.get("local_endpoint", "http://localhost:11434"),
                    anthropic_model=d.get("anthropic_model", "claude-haiku-4-5-20251001"),
                    openrouter_model=d.get("openrouter_model", "meta-llama/llama-3.3-70b-instruct:free"),
                    huggingface_model=d.get("huggingface_model", "meta-llama/Llama-3.1-70B-Instruct"),
                    openai_compat_endpoint=d.get("openai_compat_endpoint", "http://localhost:8000/v1"),
                    openai_compat_model=d.get("openai_compat_model", "llama3.1:8b"),
                )
                # Only "model_provider:" being present in the yaml counts as an explicit
                # choice. A `deployment:` section can exist purely to set local_model /
                # local_endpoint / etc. without opting into a provider — that must still
                # fall through to the env-key auto-detect below, not silently become "local".
                deployment_explicit = d.get("model_provider") is not None

            if r := raw.get("rbac"):
                cfg.rbac = RbacConfig(
                    admin_teams=r.get("admin_teams", []),
                    reviewer_teams=r.get("reviewer_teams", []),
                )

            if n := raw.get("notifications"):
                cfg.notifications = NotificationsConfig(
                    jira_project=n.get("jira_project", ""),
                    slack_webhook=n.get("slack_webhook", ""),
                )

            cfg.retention_days = raw.get("retention_days", 365)
            cfg.community_brain = raw.get("community_brain", False)
            cfg.mcp_servers = raw.get("mcp_servers", [])
            cfg.nvd_enabled = raw.get("nvd_enabled", False)
            cfg.kev_enabled = raw.get("kev_enabled", True)
            cfg.nvd_lookback_days = raw.get("nvd_lookback_days", 90)

        # MODEL_PROVIDER is written by `gauntlex setup` on every model reconfiguration —
        # it is the user's most recent explicit choice and always wins. It must never be
        # silently overridden by guessing from whichever API key happens to be set.
        if p := os.environ.get("MODEL_PROVIDER"):
            cfg.deployment.model_provider = p
        elif not deployment_explicit:
            # No explicit `deployment:` section in .gauntlex.yml (and no MODEL_PROVIDER
            # recorded yet) — fall back to detecting the provider from whichever key is
            # present. This only exists for zero-config / CI deployments; it never
            # overrides an explicit choice made via .gauntlex.yml or `gauntlex setup`.
            #
            # If none of these are set, model_provider stays None (its dataclass
            # default) — GAUNTLEX must never silently assume Ollama. A developer who
            # actually wants local Ollama has to say so, either via `gauntlex setup`
            # (writes MODEL_PROVIDER=local) or an explicit `deployment:` section in
            # .gauntlex.yml. Every entrypoint (CLI, MCP server, harness API) treats
            # model_provider is None as "not configured" and reports it instead of
            # guessing — see model_kwargs() below.
            if os.environ.get("OPENROUTER_API_KEY"):
                cfg.deployment.model_provider = "openrouter"
            elif os.environ.get("ANTHROPIC_API_KEY"):
                cfg.deployment.model_provider = "anthropic"
            elif os.environ.get("HF_TOKEN"):
                cfg.deployment.model_provider = "huggingface"
            elif os.environ.get("OPENAI_COMPAT_API_KEY"):
                cfg.deployment.model_provider = "openai_compat"

        # Per-provider model overrides
        if m := os.environ.get("OLLAMA_MODEL"):
            cfg.deployment.local_model = m
        if m := os.environ.get("OPENROUTER_MODEL"):
            cfg.deployment.openrouter_model = m
        if m := os.environ.get("HF_MODEL"):
            cfg.deployment.huggingface_model = m
        if m := os.environ.get("OPENAI_COMPAT_MODEL"):
            cfg.deployment.openai_compat_model = m
        if ep := os.environ.get("OPENAI_COMPAT_BASE_URL"):
            cfg.deployment.openai_compat_endpoint = ep

        return cfg

    def model_kwargs(self) -> dict:
        """Return BaseAgent kwargs for the effective provider.

        Raises ModelProviderNotConfiguredError if no provider was ever explicitly
        chosen — never silently falls back to Ollama or any other provider.
        """
        p = self.effective_model_provider
        if p is None:
            raise ModelProviderNotConfiguredError()
        if p == "anthropic":
            return {"provider": "anthropic", "model": self.deployment.anthropic_model}
        if p == "openrouter":
            return {"provider": "openrouter", "model": self.deployment.openrouter_model}
        if p == "huggingface":
            return {"provider": "huggingface", "model": self.deployment.huggingface_model}
        if p == "openai_compat":
            return {
                "provider": "openai_compat",
                "model": self.deployment.openai_compat_model,
                "openai_compat_endpoint": self.deployment.openai_compat_endpoint,
            }
        return {
            "provider": "ollama",
            "model": self.deployment.local_model,
            "ollama_endpoint": self.deployment.local_endpoint,
        }

    def config_issues(self) -> list[tuple[str, str]]:
        """Return (problem, fix) tuples describing why the configured provider
        isn't ready to use. Empty list means it's ready. Shared by every
        entrypoint (CLI, MCP server) so the "not configured" message is
        identical no matter how GAUNTLEX was invoked."""
        issues: list[tuple[str, str]] = []
        provider = self.effective_model_provider

        if provider is None:
            issues.append((
                "No model provider is configured — GAUNTLEX never assumes a default",
                "gauntlex setup  (interactive wizard: OpenRouter free tier, Anthropic, "
                "HuggingFace, OpenAI, or local Ollama)",
            ))
            return issues

        if provider == "openrouter":
            if not os.environ.get("OPENROUTER_API_KEY"):
                issues.append(
                    ("OPENROUTER_API_KEY is not set",
                     "gauntlex setup --model  (choose OpenRouter and enter your API key)")
                )
            elif not self.deployment.openrouter_model:
                issues.append(
                    ("OPENROUTER_MODEL is empty — no model selected",
                     "gauntlex setup --model  (pick a model from the list)")
                )
        elif provider == "anthropic":
            if not os.environ.get("ANTHROPIC_API_KEY"):
                issues.append(
                    ("ANTHROPIC_API_KEY is not set",
                     "gauntlex setup --model  (choose Anthropic and enter your API key)")
                )
        elif provider == "huggingface":
            if not os.environ.get("HF_TOKEN"):
                issues.append(
                    ("HF_TOKEN is not set",
                     "gauntlex setup --model  (choose HuggingFace and enter your token)")
                )
        elif provider == "openai_compat":
            if not os.environ.get("OPENAI_COMPAT_API_KEY"):
                issues.append(
                    ("OPENAI_COMPAT_API_KEY is not set",
                     "gauntlex setup --model  (choose OpenAI and enter your API key)")
                )
        # ollama: explicitly chosen, no key required — nothing further to check

        return issues

    @property
    def effective_model_provider(self) -> str:
        """The provider actually in effect. Resolved once in `load()` — no live
        re-derivation here, so it can never disagree with what `load()` decided."""
        return self.deployment.model_provider


def _find_config() -> Path | None:
    """Walk up from cwd looking for .gauntlex.yml."""
    current = Path.cwd()
    for parent in [current, *current.parents]:
        candidate = parent / ".gauntlex.yml"
        if candidate.exists():
            return candidate
    return None


def _last_project_file() -> Path:
    # Resolved fresh on every call (not a module-level constant) so tests can
    # isolate it by monkeypatching the HOME env var.
    return Path.home() / ".gauntlex" / "last_project"


def _remember_project(project_root: Path) -> None:
    """Record the most recently used project globally, so read-only commands
    (dashboard, status) can find it later even from outside the project tree."""
    try:
        f = _last_project_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(str(project_root))
    except OSError:
        pass  # best-effort — never block a command over this


def _recall_last_project() -> Path | None:
    """The last project any `gauntlex` command resolved on this machine, if its
    .gauntlex.yml still exists."""
    try:
        f = _last_project_file()
        if not f.exists():
            return None
        candidate = Path(f.read_text().strip()) / ".gauntlex.yml"
        return candidate if candidate.exists() else None
    except OSError:
        return None


DEFAULT_CONFIG_YAML = """\
version: 1

gauntlex:
  attack_count: 20
  rounds_max: 5
  cwe_rotation: true
  consensus_samples: 1  # >1 enables Arbiter self-consistency scoring (see --consensus)

policy:
  domains:
    - owasp_top10@2025.1

gate:
  minimum_ars: 0.80
  fail_open: false
  exempt_labels: [gauntlex-exempt, hotfix]

# ── Model provider (pick one — GAUNTLEX never assumes one for you) ───────────
#
#  local       — Ollama, zero cost, air-gapped. Uncomment below to opt in.
#  openrouter  — set OPENROUTER_API_KEY; free tier available
#  anthropic   — set ANTHROPIC_API_KEY
#  huggingface — set HF_TOKEN
#  openai_compat — any OpenAI-compatible endpoint (vLLM, Together AI, Groq, etc.)
#
# Env vars take precedence: OPENROUTER_API_KEY > ANTHROPIC_API_KEY > HF_TOKEN > config
# `gauntlex init` leaves model_provider unset below — GAUNTLEX never assumes a
# provider for you. Uncomment one line to opt in explicitly, or run
# `gauntlex setup` for the interactive wizard (recommended — it also writes
# your API key to .env for you).
# ─────────────────────────────────────────────────────────────────────────────
deployment:
  # model_provider: local

  # Ollama (local)
  local_model: llama3.1:8b
  local_endpoint: http://localhost:11434

  # OpenRouter — free open-source models, zero-cost tier available
  # Best free models for adversarial security tasks:
  #   meta-llama/llama-3.3-70b-instruct:free    ← recommended (70B, reliable JSON/code)
  #   qwen/qwen3-coder:free                      ← code-specialized, great for CWE analysis
  #   nousresearch/hermes-3-llama-3.1-405b:free  ← most powerful free option (405B)
  #   openai/gpt-oss-120b:free                   ← 120B OSS model
  #   nvidia/nemotron-3-ultra-550b-a55b:free      ← largest free model available
  openrouter_model: meta-llama/llama-3.3-70b-instruct:free

  # Anthropic Claude
  anthropic_model: claude-haiku-4-5-20251001

  # HuggingFace Serverless Inference API (free tier)
  huggingface_model: meta-llama/Llama-3.1-70B-Instruct

  # Generic OpenAI-compatible (vLLM, Together AI, Groq, Azure OpenAI, etc.)
  # Set OPENAI_COMPAT_API_KEY and OPENAI_COMPAT_BASE_URL env vars
  openai_compat_endpoint: http://localhost:8000/v1
  openai_compat_model: llama3.1:8b

notifications:
  jira_project: ""
  slack_webhook: ""

retention_days: 365
community_brain: false
"""
