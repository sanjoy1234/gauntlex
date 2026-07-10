"""
Harness runner — hook chain + slash command dispatcher.

Custom harness: no LangChain, no AutoGen, no framework dependency.
Zero outbound calls by default. Hooks are plain Python callables.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from ..config import AppConfig
from ..core.gauntlex import GauntlexResult


@dataclass
class RunContext:
    """Shared state passed to every hook in the chain."""
    run_id: str
    spec: str
    config: AppConfig
    result: GauntlexResult | None = None
    ars: float = 0.0
    round_number: int = 0
    round_attacks: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


HookFn = Callable[[RunContext], None]
AsyncHookFn = Callable[[RunContext], Any]


class GauntlexHarness:
    """
    Execution harness: registers hooks, fires them at lifecycle events.

    Hook lifecycle events:
      pre_run     — once before first round
      post_round  — after each round (entropy check, diversity retry)
      post_run    — once after all rounds (emit report, notify)
      learn       — async, after post_run (Knowledge Forge write, brain update)
    """

    HOOK_EVENTS = ("pre_run", "post_round", "post_run", "learn")

    def __init__(self, config: AppConfig | None = None):
        self.config = config or AppConfig()
        self._hooks: dict[str, list[tuple[HookFn, bool]]] = defaultdict(list)
        self._register_builtin_hooks()

    def register(self, event: str, fn: HookFn | AsyncHookFn, async_: bool = False) -> None:
        if event not in self.HOOK_EVENTS:
            raise ValueError(f"Unknown hook event '{event}'. Must be one of {self.HOOK_EVENTS}")
        self._hooks[event].append((fn, async_))

    async def fire(self, event: str, ctx: RunContext) -> None:
        """Fire all hooks registered for an event."""
        sync_hooks = [(fn, False) for fn, async_ in self._hooks[event] if not async_]
        async_hooks = [(fn, True) for fn, async_ in self._hooks[event] if async_]

        for fn, _ in sync_hooks:
            fn(ctx)

        if async_hooks:
            await asyncio.gather(*[fn(ctx) for fn, _ in async_hooks])

    def fire_sync(self, event: str, ctx: RunContext) -> None:
        """Fire only synchronous hooks (for use outside async context)."""
        for fn, async_ in self._hooks[event]:
            if not async_:
                fn(ctx)

    def _register_builtin_hooks(self) -> None:
        from .hooks.pre_run import avf_gate, fingerprint_inject
        from .hooks.post_round import entropy_guard
        from .hooks.post_run import emit_report

        self.register("pre_run", avf_gate)
        self.register("pre_run", fingerprint_inject)
        self.register("post_round", entropy_guard)
        self.register("post_run", emit_report)
