"""BaseAgent — unified async model interface for Ollama and Anthropic."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
import httpx


@dataclass
class AgentMessage:
    role: str  # "user" | "assistant"
    content: str


@dataclass
class ModelResponse:
    content: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def estimated_cost_usd(self) -> float:
        """Rough estimate; 0.0 for local Ollama runs."""
        if self.model.startswith("ollama/") or "/" not in self.model:
            return 0.0
        # Haiku pricing: ~$0.25/MTok input, $1.25/MTok output
        return (self.prompt_tokens * 0.25 + self.completion_tokens * 1.25) / 1_000_000


class BaseAgent:
    """
    Unified async LLM interface.

    Supported providers:
      ollama      — local Ollama server, zero cost, air-gapped (default)
      anthropic   — Anthropic Claude API (set ANTHROPIC_API_KEY)
      openrouter  — OpenRouter.ai API (set OPENROUTER_API_KEY)
                    Any model including free tier: deepseek/deepseek-chat-v3-0324:free
      huggingface — HuggingFace Inference API (set HF_TOKEN)
      openai_compat — generic OpenAI-compatible endpoint (set OPENAI_COMPAT_API_KEY
                      and OPENAI_COMPAT_BASE_URL); covers vLLM, Together AI, etc.

    Provider resolution order (when provider arg is None):
      1. OPENROUTER_API_KEY → openrouter
      2. ANTHROPIC_API_KEY  → anthropic
      3. HF_TOKEN           → huggingface
      4. fallback           → ollama
    """

    OPENROUTER_BASE = "https://openrouter.ai/api/v1"
    HUGGINGFACE_BASE = "https://api-inference.huggingface.co/v1"

    def __init__(
        self,
        system_prompt: str,
        model: str | None = None,
        provider: str | None = None,
        ollama_endpoint: str = "http://localhost:11434",
        openai_compat_endpoint: str | None = None,
        temperature: float = 0.7,
    ):
        self.system_prompt = system_prompt
        self.temperature = temperature
        self.ollama_endpoint = ollama_endpoint.rstrip("/")
        self._openai_compat_endpoint = openai_compat_endpoint

        if provider:
            self._provider = provider
        elif os.environ.get("OPENROUTER_API_KEY"):
            self._provider = "openrouter"
        elif os.environ.get("ANTHROPIC_API_KEY"):
            self._provider = "anthropic"
        elif os.environ.get("HF_TOKEN"):
            self._provider = "huggingface"
        else:
            self._provider = "ollama"

        if model:
            self._model = model
        elif self._provider == "anthropic":
            self._model = "claude-haiku-4-5-20251001"
        elif self._provider == "openrouter":
            self._model = os.environ.get(
                "OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free"
            )
        elif self._provider == "huggingface":
            self._model = os.environ.get(
                "HF_MODEL", "meta-llama/Llama-3.1-70B-Instruct"
            )
        elif self._provider == "openai_compat":
            self._model = os.environ.get("OPENAI_COMPAT_MODEL", "llama3.1:8b")
        else:
            self._model = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def model(self) -> str:
        return self._model

    async def complete(self, messages: list[AgentMessage]) -> ModelResponse:
        """Send messages and return a single completion."""
        if self._provider == "anthropic":
            return await self._anthropic_complete(messages)
        if self._provider in ("openrouter", "huggingface", "openai_compat"):
            return await self._openai_compat_complete(messages)
        return await self._ollama_complete(messages)

    async def _ollama_complete(self, messages: list[AgentMessage]) -> ModelResponse:
        prompt = self._build_ollama_prompt(messages)
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        async with httpx.AsyncClient(timeout=180.0) as client:
            resp = await client.post(f"{self.ollama_endpoint}/api/generate", json=payload)
            resp.raise_for_status()
            data = resp.json()
        return ModelResponse(
            content=data["response"].strip(),
            model=f"ollama/{self._model}",
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
        )

    async def _anthropic_complete(self, messages: list[AgentMessage]) -> ModelResponse:
        import anthropic

        client = anthropic.AsyncAnthropic()
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        response = await client.messages.create(
            model=self._model,
            max_tokens=16384,
            system=self.system_prompt,
            messages=api_messages,
        )
        content = response.content[0].text if response.content else ""
        return ModelResponse(
            content=content.strip(),
            model=self._model,
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
        )

    async def _openai_compat_complete(self, messages: list[AgentMessage]) -> ModelResponse:
        """
        OpenAI-compatible chat completions endpoint.

        Covers: OpenRouter, HuggingFace Inference API, Together AI, vLLM, Groq, etc.
        Fails fast with a clear error — no silent model fallbacks.
        """
        if self._provider == "openrouter":
            base_url = self.OPENROUTER_BASE
            api_key = os.environ.get("OPENROUTER_API_KEY", "")
            extra_headers = {
                "HTTP-Referer": "https://github.com/sanjoy1234/combatpair",
                "X-Title": "COMBATPAIR Adversarial Co-Generation Engine",
            }
        elif self._provider == "huggingface":
            base_url = self.HUGGINGFACE_BASE
            api_key = os.environ.get("HF_TOKEN", "")
            extra_headers = {}
        else:  # openai_compat
            base_url = (
                self._openai_compat_endpoint
                or os.environ.get("OPENAI_COMPAT_BASE_URL", "http://localhost:8000/v1")
            ).rstrip("/")
            api_key = os.environ.get("OPENAI_COMPAT_API_KEY", "no-key")
            extra_headers = {}

        api_messages = [{"role": "system", "content": self.system_prompt}]
        api_messages += [{"role": m.role, "content": m.content} for m in messages]

        payload = {
            "model": self._model,
            "messages": api_messages,
            "temperature": self.temperature,
            "max_tokens": 16384,
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            **extra_headers,
        }

        # Hard ceiling: free-tier models can queue for many minutes.
        # asyncio.wait_for imposes a strict wall-clock limit that httpx's chunk-level
        # timeout cannot enforce for slow queue scenarios.
        _CALL_TIMEOUT_S = 300  # 5 minutes max per LLM call

        data: dict = {}

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=10.0)
        ) as client:
            for attempt in range(3):  # max 3 attempts (initial + 2 retries on 429/503)
                try:
                    resp = await asyncio.wait_for(
                        client.post(
                            f"{base_url}/chat/completions",
                            json=payload,
                            headers=headers,
                        ),
                        timeout=_CALL_TIMEOUT_S,
                    )
                except (asyncio.TimeoutError, TimeoutError):
                    raise RuntimeError(
                        f"[model timeout] {self._model} did not respond within {_CALL_TIMEOUT_S}s.\n"
                        f"  The free-tier queue is too slow. Fix: set OPENROUTER_MODEL to a faster model\n"
                        f"  or add ANTHROPIC_API_KEY to use Claude instead."
                    )
                except httpx.ConnectError as exc:
                    raise RuntimeError(
                        f"[connection error] Cannot reach {base_url}: {exc}.\n"
                        f"  Check your network connection and API key."
                    )
                except httpx.ReadTimeout:
                    raise RuntimeError(
                        f"[read timeout] {self._model} connection established but response stalled.\n"
                        f"  Try a different model or check API status."
                    )

                if resp.status_code in (429, 503):
                    if attempt < 2:
                        retry_after = float(resp.headers.get("retry-after", 2 ** (attempt + 1)))
                        wait = min(retry_after, 30)
                        await asyncio.sleep(wait)
                        continue
                    # All retries exhausted — fail with clear message
                    body = resp.text[:300]
                    raise RuntimeError(
                        f"[rate limit] {self._model} returned HTTP {resp.status_code} after 3 attempts.\n"
                        f"  {body}\n"
                        f"  Fix: wait and retry, switch model, or upgrade your API plan."
                    )

                if resp.status_code == 401:
                    raise RuntimeError(
                        f"[auth error] HTTP 401 from {self._provider}.\n"
                        f"  Check your API key (OPENROUTER_API_KEY / ANTHROPIC_API_KEY / HF_TOKEN)."
                    )

                if resp.status_code == 402:
                    raise RuntimeError(
                        f"[billing] HTTP 402 from {self._provider} — insufficient credits.\n"
                        f"  Top up your account or switch to a free-tier model."
                    )

                if resp.status_code >= 400:
                    body = resp.text[:300]
                    raise RuntimeError(
                        f"[api error] HTTP {resp.status_code} from {self._model}:\n  {body}"
                    )

                # HTTP 200 — parse body
                try:
                    data = resp.json()
                except Exception:
                    raise RuntimeError(
                        f"[parse error] {self._model} returned HTTP 200 but non-JSON body:\n"
                        f"  {resp.text[:200]}"
                    )

                if "error" in data and "choices" not in data:
                    err_detail = data["error"]
                    if isinstance(err_detail, dict):
                        err_msg = err_detail.get("message", str(err_detail))
                        err_code = err_detail.get("code", "")
                    else:
                        err_msg = str(err_detail)
                        err_code = ""
                    raise RuntimeError(
                        f"[model error] {self._model} returned an error (code={err_code}):\n"
                        f"  {err_msg}\n"
                        f"  Fix: switch model via OPENROUTER_MODEL or check API quota."
                    )

                # Valid response
                break

        if not data.get("choices"):
            raise RuntimeError(
                f"[empty response] {self._model} returned no choices.\n"
                f"  This can happen when the model is overloaded. Retry or switch model."
            )

        # Reasoning models (QwQ, DeepSeek-R1, gpt-oss-20b, etc.) return content=null
        # with finish_reason=length when they exhaust max_tokens during internal thinking.
        # Never use truncated reasoning as code/attacks — fail with a clear message.
        msg = data["choices"][0]["message"]
        finish_reason = data["choices"][0].get("finish_reason", "stop")
        raw_content = msg.get("content")

        if raw_content is None and finish_reason == "length":
            raise RuntimeError(
                f"[token budget] {data.get('model', self._model)} returned content=null "
                f"(finish_reason=length).\n"
                f"  This model exhausted {payload['max_tokens']} tokens on internal reasoning "
                f"before producing output.\n"
                f"  Fix: set OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free "
                f"(a non-reasoning instruction model)."
            )

        choice = raw_content or msg.get("reasoning") or msg.get("reasoning_content") or ""
        if not choice:
            raise RuntimeError(
                f"[empty content] {data.get('model', self._model)} returned an empty response.\n"
                f"  Try a different model."
            )

        usage = data.get("usage", {})
        return ModelResponse(
            content=choice.strip(),
            model=data.get("model", self._model),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
        )

    def _build_ollama_prompt(self, messages: list[AgentMessage]) -> str:
        parts = [f"System: {self.system_prompt}\n"]
        for m in messages:
            parts.append(f"{m.role.capitalize()}: {m.content}")
        parts.append("Assistant:")
        return "\n\n".join(parts)
