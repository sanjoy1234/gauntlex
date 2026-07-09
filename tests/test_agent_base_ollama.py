"""Tests for BaseAgent's Ollama completion path — timeout and error handling.

Regression coverage for a real bug found running `gauntlex run` against
llama3.1:8b (this project's own default/recommended local model) on CPU-only
consumer hardware: the request timed out at 180s with a bare, unhelpful
"ReadTimeout: (no message — check model config)" — no specific handling,
and a ceiling far tighter than the 300s "hard ceiling" philosophy already
used for hosted providers elsewhere in this same file.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from gauntlex.agents.base import BaseAgent, AgentMessage


def _agent() -> BaseAgent:
    return BaseAgent(system_prompt="test", provider="ollama", model="llama3.1:8b")


@pytest.mark.asyncio
async def test_ollama_read_timeout_raises_friendly_error_not_bare_exception():
    agent = _agent()
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.ReadTimeout("timed out")
        with pytest.raises(RuntimeError) as exc_info:
            await agent._ollama_complete([AgentMessage(role="user", content="hi")])
    message = str(exc_info.value)
    assert "300s" in message
    assert "llama3.1:8b" in message
    assert message != ""  # must not fall through to the CLI's generic fallback


@pytest.mark.asyncio
async def test_ollama_connect_error_raises_friendly_error():
    agent = _agent()
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.ConnectError("connection refused")
        with pytest.raises(RuntimeError) as exc_info:
            await agent._ollama_complete([AgentMessage(role="user", content="hi")])
    message = str(exc_info.value)
    assert "ollama serve" in message
    assert agent.ollama_endpoint in message


@pytest.mark.asyncio
async def test_ollama_client_timeout_is_300_seconds_not_180():
    """The old 180s ceiling was too tight for CPU-only 8B inference — this is
    the specific value that must not silently regress back down."""
    agent = _agent()
    captured_kwargs = {}

    real_init = httpx.AsyncClient.__init__

    def capture_init(self, *args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, "__init__", capture_init), \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_response = AsyncMock()
        mock_response.json = lambda: {"response": "ok", "prompt_eval_count": 1, "eval_count": 1}
        mock_response.raise_for_status = lambda: None
        mock_post.return_value = mock_response
        await agent._ollama_complete([AgentMessage(role="user", content="hi")])

    assert captured_kwargs.get("timeout") == 300.0
