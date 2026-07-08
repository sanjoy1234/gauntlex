"""Builder agent — generates code implementations from a specification."""

from __future__ import annotations

from dataclasses import dataclass

from .base import AgentMessage, BaseAgent, ModelResponse

BUILDER_SYSTEM = """\
You are a senior software engineer implementing a feature specification.
Your job is to produce clean, secure, production-ready code.

Rules:
- Output only code, no prose explanations unless critical
- Use the language implied by the spec (default Python)
- Apply defensive programming: validate inputs, handle edge cases
- Never introduce SQL injection, XSS, path traversal, or race conditions
- If the spec is ambiguous, choose the safer interpretation

Format your response as:
```<language>
<code>
```
"""


@dataclass
class BuildResult:
    code: str
    language: str
    model_response: ModelResponse
    round_number: int


class Builder(BaseAgent):
    def __init__(self, **kwargs):
        super().__init__(system_prompt=BUILDER_SYSTEM, **kwargs)

    async def generate(self, spec: str, round_number: int = 1, feedback: str = "") -> BuildResult:
        """Generate or refine an implementation of the given spec."""
        content = spec
        if feedback:
            content = (
                f"Specification:\n{spec}\n\n"
                f"Previous attempt had these issues found by security review:\n{feedback}\n\n"
                f"Please produce a revised, more secure implementation."
            )

        messages = [AgentMessage(role="user", content=content)]
        response = await self.complete(messages)

        code, lang = _extract_code(response.content)
        return BuildResult(
            code=code,
            language=lang,
            model_response=response,
            round_number=round_number,
        )


def _extract_code(text: str) -> tuple[str, str]:
    """Extract code block from markdown-formatted response."""
    import re

    pattern = r"```(\w+)?\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        lang = match.group(1) or "python"
        return match.group(2).strip(), lang
    return text.strip(), "python"
