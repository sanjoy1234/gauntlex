"""Report command — programmatic API for rendering Resilience Reports."""

from __future__ import annotations

from dataclasses import dataclass

SUPPORTED_FORMATS = ("md", "json", "html", "sarif", "junit")


@dataclass
class ReportResult:
    run_id: str
    format: str
    content: str
    path: str


def execute(
    run_id: str,
    fmt: str = "md",
    config_path: str | None = None,
) -> ReportResult:
    """
    Load and render a stored Resilience Report.

    Supported formats:
      md    — Markdown (default, suitable for PR comments)
      json  — Raw JSON (machine-readable, full schema)
      html  — Self-contained HTML page (open in any browser)
      sarif — SARIF 2.1.0 (GitHub Code Scanning integration)
      junit — JUnit XML (Jenkins, Azure DevOps, CI dashboards)
    """
    import json
    from combatpair.config import AppConfig
    from combatpair.output.report import (
        load_report,
        render_markdown,
        render_html,
        render_sarif,
        render_junit_xml,
    )

    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Unknown format '{fmt}'. Supported: {', '.join(SUPPORTED_FORMATS)}")

    cfg = AppConfig.load(config_path)
    report = load_report(run_id, cfg.reports_dir)
    report_path = str(cfg.reports_dir / f"{run_id}.json")

    render_map = {
        "json": lambda r: json.dumps(r, indent=2),
        "md": render_markdown,
        "html": render_html,
        "sarif": render_sarif,
        "junit": render_junit_xml,
    }
    content = render_map[fmt](report)

    return ReportResult(run_id=run_id, format=fmt, content=content, path=report_path)
