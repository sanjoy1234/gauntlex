# GAUNTLEX Distribution Log

This file is the single source of truth for **every place GAUNTLEX is published**,
and exactly how to push a new version to each one. It exists because the project
ships to more than one destination (PyPI package, GitHub source, Claude Code
plugin marketplace, and — going forward — MCP registries as they get added),
and each destination carries its own copy of the version number. If they drift,
users get inconsistent behavior depending on which install path they used —
which is exactly the class of bug this file exists to prevent.

**Rule: `pyproject.toml`'s `version` field is the single source of truth.**
Every other destination's version must match it exactly before a release ships.
`scripts/release.sh` enforces this automatically — see below.

---

## Registered destinations

| # | Destination | What it serves | Version lives in | How to update | Auth needed | Status |
|---|---|---|---|---|---|---|
| 1 | **PyPI** — [pypi.org/project/gauntlex-ai](https://pypi.org/project/gauntlex-ai/) | `pip install gauntlex-ai`, `uvx gauntlex-ai` (no `--from`) | `pyproject.toml` → `version` | `scripts/release.sh --publish` (runs `python -m build` + `twine upload dist/*`) | `~/.pypirc` or `TWINE_USERNAME`/`TWINE_PASSWORD` (or `UV_PUBLISH_TOKEN` for `uv publish`) — **not present on this machine as of 2026-07-10 18:31; `scripts/release.sh --publish` attempted and stopped cleanly at the credential gate, nothing uploaded** | Live at **1.0.0** — stale. 1.0.1 built (`dist/gauntlex_ai-1.0.1-*`) and ready to upload the moment credentials are available — see hand-off below. |
| 2 | **GitHub repo (source of truth)** — [github.com/sanjoy1234/gauntlex](https://github.com/sanjoy1234/gauntlex) `main` branch | `pip install git+https://github.com/sanjoy1234/gauntlex.git@main`, `uvx --from git+https://github.com/sanjoy1234/gauntlex.git gauntlex`, and is what destinations #3 reads from directly | N/A — always matches whatever's committed | `git push origin main` (+ `git push --tags` for release tags) | Existing `git` push access | **Current** — commit `a4eeba7` (includes this release's fixes) pushed 2026-07-10. `v1.0.1` tag intentionally not yet created — tags are meant to mark what's actually live on PyPI; will tag once row 1 is done (`scripts/release.sh --tag`, or re-run with `--publish --tag` together). |
| 3 | **Claude Code Plugin Marketplace** — installed via `/plugin marketplace add sanjoy1234/gauntlex` then `/plugin install gauntlex@gauntlex` | Claude Code users installing the `/gauntlex:*` skills + MCP server | `.claude-plugin/plugin.json` → `version`, **and** `.claude-plugin/marketplace.json` → `plugins[0].version` (two separate fields, both must match `pyproject.toml`) | No separate upload step — it reads directly from destination #2 (GitHub `main`). Bumping the version fields and pushing to `main` is the entire update. | Same as #2 | **Current** — both files at 1.0.1, pushed in the same commit as row 2. |

### Not yet registered (add a row here the day it happens — don't just remember it)

| Destination | Planned | Notes |
|---|---|---|
| MCP registry / directory (e.g. official MCP registry, Smithery, or similar) | Mentioned as "tomorrow" per 2026-07-10 conversation | When registered: add a row above with its URL, where its version/manifest lives, the exact publish command, and auth requirements — same as rows 1–3. |
| Homebrew / npm wrapper / Docker Hub / VS Code marketplace | Not planned yet | Add only if actually pursued — don't pre-populate speculative rows. |

---

## Release checklist (what `scripts/release.sh` automates)

1. **Version sync check** — reads `pyproject.toml`'s version, fails loudly if
   `.claude-plugin/plugin.json` or `.claude-plugin/marketplace.json` disagree.
2. **Test gate** — full `pytest tests/ -q` suite must pass.
3. **Build** — `python -m build` produces `dist/gauntlex_ai-X.Y.Z-py3-none-any.whl` + sdist.
4. **Local install smoke test** — installs the freshly built wheel into a throwaway
   venv and runs `gauntlex doctor` + `gauntlex init` to catch packaging regressions
   (missing files, broken entry points) before anything is public.
5. **`--publish`** (opt-in flag, not run by default) — uploads to PyPI via `twine`.
   Requires credentials; the script checks for `~/.pypirc` or `TWINE_*`/`UV_PUBLISH_*`
   env vars first and stops with instructions if none are found, rather than
   prompting for a token interactively (tokens should never be typed into a chat
   session or committed to shell history).
6. **`--tag`** (opt-in flag) — creates `git tag vX.Y.Z` and pushes it + `main`.

Steps 1–4 are safe to run anytime (nothing public happens). Steps 5–6 are the
only ones that touch a shared/public destination — run them deliberately, not
as a side effect of an unrelated code change.

## When you bump the version

1. Edit `pyproject.toml`'s `version` field.
2. Run `scripts/release.sh` (no flags) — it will tell you if `plugin.json` /
   `marketplace.json` are out of sync and exactly which lines to change.
3. Add a dated entry to `RELEASE.md` describing what changed (this project's
   convention is release notes written before/alongside the code, not after).
4. Run `scripts/release.sh --publish --tag` once you're ready to actually ship,
   or run the two steps it prints manually if credentials live somewhere I
   (Claude) shouldn't have automatic access to.
5. Update the "Status" column in the destinations table above for every
   destination that changed.
