"""CPaaS service configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class ServiceConfig:
    """Configuration for the COMBATPAIR GitHub App service."""

    github_app_id: str = field(default_factory=lambda: os.environ.get("GITHUB_APP_ID", ""))
    github_private_key_path: str = field(
        default_factory=lambda: os.environ.get("GITHUB_PRIVATE_KEY_PATH", "")
    )
    webhook_secret: str = field(
        default_factory=lambda: os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    )
    port: int = field(default_factory=lambda: int(os.environ.get("COMBATPAIR_SERVICE_PORT", "8080")))
    host: str = field(default_factory=lambda: os.environ.get("COMBATPAIR_SERVICE_HOST", "0.0.0.0"))

    combatpair_mode: str = field(default_factory=lambda: os.environ.get("COMBATPAIR_MODE", "standard"))
    minimum_ars: float = field(
        default_factory=lambda: float(os.environ.get("COMBATPAIR_MIN_ARS", "0.80"))
    )
    post_status: bool = field(
        default_factory=lambda: os.environ.get("COMBATPAIR_POST_STATUS", "true").lower() == "true"
    )
    post_pr_comment: bool = field(
        default_factory=lambda: os.environ.get("COMBATPAIR_POST_COMMENT", "true").lower() == "true"
    )
    combatpair_config_path: str | None = None

    # RBAC
    rbac_enabled: bool = field(
        default_factory=lambda: os.environ.get("COMBATPAIR_RBAC_ENABLED", "false").lower() == "true"
    )
    github_org: str = field(default_factory=lambda: os.environ.get("GITHUB_ORG", ""))

    @classmethod
    def from_env(cls) -> "ServiceConfig":
        return cls()

    def is_configured(self) -> bool:
        """Return True if all required GitHub App credentials are present."""
        return bool(self.github_app_id and self.github_private_key_path)

    def validate(self) -> list[str]:
        """Return list of missing/invalid config issues."""
        errors: list[str] = []
        if not self.github_app_id:
            errors.append("GITHUB_APP_ID not set")
        if not self.github_private_key_path:
            errors.append("GITHUB_PRIVATE_KEY_PATH not set")
        elif not __import__("pathlib").Path(self.github_private_key_path).exists():
            errors.append(f"Private key file not found: {self.github_private_key_path}")
        if not self.webhook_secret:
            errors.append("GITHUB_WEBHOOK_SECRET not set")
        return errors
