"""
Adversarial Policy Engine (APE) — loads YAML playbooks and injects into Breaker prompt.

Playbooks are versioned YAML files in policy/domains/. Each domain maps
regulatory controls to specific CWE attack scenarios.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .schema import AttackScenario, PolicyDomain

_DOMAINS_DIR = Path(__file__).parent / "domains"
_USER_POLICIES_DIR = Path(".gauntlex/policies")


def load_domain(domain_spec: str) -> PolicyDomain:
    """Load a policy domain by name or name@version (e.g., 'owasp_top10@2025.1').

    Search order: .gauntlex/policies/ (installed) → built-in policy/domains/.
    """
    name = domain_spec.split("@")[0].strip()
    # Check user-installed policies first, then fall back to built-ins
    yaml_path = _USER_POLICIES_DIR / f"{name}.yaml"
    if not yaml_path.exists():
        yaml_path = _DOMAINS_DIR / f"{name}.yaml"

    if not yaml_path.exists():
        raise FileNotFoundError(
            f"Policy domain '{name}' not found. "
            f"Available: {list_available_domains()}"
        )

    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    scenarios = [
        AttackScenario(
            id=s.get("id", f"s{i:03d}"),
            cwe=s.get("cwe", "CWE-UNKNOWN"),
            title=s.get("title", ""),
            description=s.get("description", ""),
            regulatory_ref=s.get("regulatory_ref", ""),
            example=s.get("example", ""),
        )
        for i, s in enumerate(raw.get("scenarios", []))
    ]

    return PolicyDomain(
        name=raw.get("name", name),
        version=raw.get("version", "unknown"),
        description=raw.get("description", ""),
        regulatory_framework=raw.get("regulatory_framework", ""),
        scenarios=scenarios,
    )


def load_domains(domain_specs: list[str]) -> list[PolicyDomain]:
    """Load multiple domains; silently skip any that are not found."""
    result = []
    for spec in domain_specs:
        try:
            result.append(load_domain(spec))
        except FileNotFoundError:
            continue
    return result


def combine_policy_context(domains: list[PolicyDomain]) -> str:
    """Combine multiple domains into a single Breaker context string."""
    if not domains:
        return ""
    return "\n\n---\n\n".join(d.to_breaker_context() for d in domains)


def list_available_domains() -> list[str]:
    """Return all domain names: built-in + user-installed (deduped, sorted)."""
    builtin = {p.stem for p in _DOMAINS_DIR.glob("*.yaml")}
    installed = {p.stem for p in _USER_POLICIES_DIR.glob("*.yaml")} if _USER_POLICIES_DIR.exists() else set()
    return sorted(builtin | installed)


def validate_domain_yaml(domain_or_path) -> list[str]:
    """
    Validate a policy domain against the expected schema.

    Accepts:
    - A domain name string (e.g., 'owasp_top10')
    - A file path (str or Path) to a YAML file
    - A PolicyDomain object (validates the already-loaded domain)

    Returns list of error strings; empty list = valid.
    """
    from .schema import PolicyDomain as _PolicyDomain

    if isinstance(domain_or_path, _PolicyDomain):
        return _validate_domain_obj(domain_or_path)

    path = Path(domain_or_path)
    if not path.suffix:
        path = _DOMAINS_DIR / f"{domain_or_path}.yaml"

    errors = []
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]
    except FileNotFoundError:
        return [f"File not found: {path}"]

    required_top = ["name", "version", "description", "regulatory_framework", "scenarios"]
    for field_name in required_top:
        if field_name not in raw:
            errors.append(f"Missing required field: {field_name}")

    for i, s in enumerate(raw.get("scenarios", [])):
        for field_name in ["cwe", "title", "description"]:
            if field_name not in s:
                errors.append(f"Scenario {i}: missing '{field_name}'")

    return errors


def _validate_domain_obj(domain: "PolicyDomain") -> list[str]:
    """Validate an already-loaded PolicyDomain object."""
    errors = []
    if not domain.name:
        errors.append("Missing required field: name")
    if not domain.version:
        errors.append("Missing required field: version")
    if not domain.regulatory_framework:
        errors.append("Missing required field: regulatory_framework")
    if not domain.scenarios:
        errors.append("Missing required field: scenarios")
    for i, s in enumerate(domain.scenarios):
        if not s.cwe:
            errors.append(f"Scenario {i}: missing 'cwe'")
        if not s.title:
            errors.append(f"Scenario {i}: missing 'title'")
        if not s.description:
            errors.append(f"Scenario {i}: missing 'description'")
    return errors
