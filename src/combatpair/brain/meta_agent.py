"""
Meta-agent — rewrites stale Breaker prompt templates.

Fired when a CWE category has >5 consecutive misses (effectiveness < 0.3).
Uses cheapest available model (haiku or ollama). Runs async, never on critical path.
New templates enter quarantine (10-run validation period) before graduating to production.
"""

from __future__ import annotations

from dataclasses import dataclass

META_AGENT_SYSTEM = """\
You are a red team engineer specializing in attack template design.
You will be given a CWE category and examples of attack prompts that have been
failing to find real vulnerabilities in AI-generated code.

Your job is to write a better, more specific attack prompt template that:
1. Is more actionable — names specific code patterns to look for
2. Uses concrete exploit scenarios, not generic descriptions
3. Is calibrated to AI-generated code patterns (common mistakes AI coders make)
4. Stays within 200 words

Return ONLY the new attack template text. No prose, no headers.
"""


@dataclass
class RewrittenTemplate:
    cwe: str
    old_template: str
    new_template: str
    rationale: str = ""


async def rewrite_template(
    cwe: str,
    old_template: str,
    failing_examples: list[str],
    provider: str = "ollama",
    model: str = "llama3.1:8b",
) -> RewrittenTemplate:
    """Generate a replacement Breaker template for a low-effectiveness CWE."""
    from ..agents.base import AgentMessage, BaseAgent

    agent = BaseAgent(
        system_prompt=META_AGENT_SYSTEM,
        provider=provider,
        model=model,
        temperature=0.9,
    )

    examples_text = "\n".join(f"- {e}" for e in failing_examples[:5])
    prompt = (
        f"CWE: {cwe}\n\n"
        f"Current failing template:\n{old_template}\n\n"
        f"Recent examples where this template found nothing:\n{examples_text}\n\n"
        f"Write a better attack template for {cwe}:"
    )

    response = await agent.complete([AgentMessage(role="user", content=prompt)])
    return RewrittenTemplate(
        cwe=cwe,
        old_template=old_template,
        new_template=response.content.strip(),
    )
