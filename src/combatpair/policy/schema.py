"""PolicyDomain and AttackPlaybook dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AttackScenario:
    id: str
    cwe: str
    title: str
    description: str
    regulatory_ref: str = ""
    example: str = ""


@dataclass
class PolicyDomain:
    name: str
    version: str
    description: str
    regulatory_framework: str
    scenarios: list[AttackScenario] = field(default_factory=list)

    @property
    def cwe_list(self) -> list[str]:
        return list({s.cwe for s in self.scenarios})

    def to_breaker_context(self) -> str:
        """Format domain as context string for Breaker prompt injection."""
        lines = [
            f"Policy Domain: {self.name} v{self.version}",
            f"Framework: {self.regulatory_framework}",
            f"",
            f"Attack scenarios to prioritize:",
        ]
        for s in self.scenarios[:10]:  # cap at 10 to stay within token budget
            lines.append(f"  [{s.cwe}] {s.title}: {s.description}")
            if s.regulatory_ref:
                lines.append(f"    Regulatory ref: {s.regulatory_ref}")
        return "\n".join(lines)
