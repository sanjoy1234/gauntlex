"""Shared pytest fixtures — hermetic isolation for the whole test suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Isolate $HOME for every test.

    AppConfig.load() remembers the last-used project under
    ~/.gauntlex/last_project so commands like `gauntlex dashboard` can find it
    from anywhere. Without this fixture, tests running on a machine that has
    actually used gauntlex (i.e. any dev machine) would silently pick up the
    real project instead of the empty/isolated filesystem they expect.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
