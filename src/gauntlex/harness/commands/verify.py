"""Verify command — re-derive and confirm report integrity hash."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VerifyResult:
    run_id: str
    integrity_hash: str
    verified: bool
    tampered: bool


def execute(run_id: str, config_path: str | None = None) -> VerifyResult:
    """
    Re-derive the SHA-256 integrity hash and verify it matches the stored value.

    Args:
        run_id: The run_id to verify
        config_path: Path to .gauntlex.yml

    Returns:
        VerifyResult — tampered=True means the report was modified after generation
    """
    from gauntlex.config import AppConfig
    from gauntlex.output.report import load_report, verify_integrity

    cfg = AppConfig.load(config_path)
    report = load_report(run_id, cfg.reports_dir)
    ok = verify_integrity(report)

    return VerifyResult(
        run_id=run_id,
        integrity_hash=report.get("integrity_hash", ""),
        verified=ok,
        tampered=not ok,
    )
