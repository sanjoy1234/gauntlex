"""Tests for the GauntlexHarness hook chain."""

from __future__ import annotations

import pytest

from gauntlex.harness.runner import GauntlexHarness, RunContext
from gauntlex.config import AppConfig


# ── RunContext ─────────────────────────────────────────────────────────────────

def test_run_context_defaults():
    cfg = AppConfig.load()
    ctx = RunContext(run_id="run-test-001", spec="test spec", config=cfg)
    assert ctx.run_id == "run-test-001"
    assert ctx.spec == "test spec"
    assert isinstance(ctx.metadata, dict)
    assert ctx.round_attacks == []


# ── Hook registration ──────────────────────────────────────────────────────────

def test_register_sync_hook():
    harness = GauntlexHarness.__new__(GauntlexHarness)
    harness._hooks = {"pre_run": [], "post_round": [], "post_run": [], "learn": []}

    called = []

    def my_hook(ctx):
        called.append(True)

    harness.register("pre_run", my_hook, async_=False)
    assert len(harness._hooks["pre_run"]) == 1


def test_register_invalid_event_raises():
    harness = GauntlexHarness.__new__(GauntlexHarness)
    harness._hooks = {"pre_run": [], "post_round": [], "post_run": [], "learn": []}

    with pytest.raises(ValueError, match="Unknown hook event"):
        harness.register("invalid_event", lambda ctx: None, async_=False)


# ── fire() sync hooks ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fire_sync_hook_executes():
    harness = GauntlexHarness.__new__(GauntlexHarness)
    harness._hooks = {"pre_run": [], "post_round": [], "post_run": [], "learn": []}

    results = []

    def capture(ctx):
        results.append(ctx.metadata.get("test_key"))

    harness.register("pre_run", capture, async_=False)

    cfg = AppConfig.load()
    ctx = RunContext(run_id="run-fire-test", spec="spec", config=cfg)
    ctx.metadata["test_key"] = "hello"

    await harness.fire("pre_run", ctx)
    assert results == ["hello"]


@pytest.mark.asyncio
async def test_fire_async_hook_executes():
    harness = GauntlexHarness.__new__(GauntlexHarness)
    harness._hooks = {"pre_run": [], "post_round": [], "post_run": [], "learn": []}

    results = []

    async def async_hook(ctx):
        results.append("async_ran")

    harness.register("pre_run", async_hook, async_=True)

    cfg = AppConfig.load()
    ctx = RunContext(run_id="run-async-test", spec="spec", config=cfg)
    await harness.fire("pre_run", ctx)
    assert results == ["async_ran"]


@pytest.mark.asyncio
async def test_fire_multiple_hooks_in_order():
    harness = GauntlexHarness.__new__(GauntlexHarness)
    harness._hooks = {"pre_run": [], "post_round": [], "post_run": [], "learn": []}

    order = []
    harness.register("pre_run", lambda ctx: order.append(1), async_=False)
    harness.register("pre_run", lambda ctx: order.append(2), async_=False)

    cfg = AppConfig.load()
    ctx = RunContext(run_id="run-order-test", spec="spec", config=cfg)
    await harness.fire("pre_run", ctx)
    assert order == [1, 2]


# ── Built-in hooks registered ──────────────────────────────────────────────────

def test_harness_init_registers_builtin_hooks():
    cfg = AppConfig.load()
    harness = GauntlexHarness(config=cfg)
    assert len(harness._hooks["pre_run"]) >= 1    # avf_gate + fingerprint_inject
    assert len(harness._hooks["post_round"]) >= 1  # entropy_guard
    assert len(harness._hooks["post_run"]) >= 1    # emit_report
    # learn hooks are registered by the runner externally (not built-in)


# ── harness/commands programmatic API ─────────────────────────────────────────

def test_harness_commands_importable():
    from gauntlex.harness.commands import run, validate, learn, compare
    from gauntlex.harness.commands import doctor, init, report, verify
    assert callable(run.execute)
    assert callable(validate.execute)
    assert callable(learn.execute)
    assert callable(compare.execute)
    assert callable(doctor.execute)
    assert callable(init.execute)
    assert callable(report.execute)
    assert callable(verify.execute)
