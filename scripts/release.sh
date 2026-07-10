#!/usr/bin/env bash
# release.sh — GAUNTLEX release workflow. See DISTRIBUTION.md for the full
# destinations log this script keeps in sync.
#
# Default (no flags): version-sync check + test gate + build + local install
# smoke test. Nothing public happens.
#
#   --publish   also upload dist/* to PyPI via twine (needs credentials)
#   --tag       also create + push a git tag for this version
#
# Usage:
#   scripts/release.sh                  # safe, local-only checks
#   scripts/release.sh --publish --tag  # full release
set -euo pipefail
cd "$(dirname "$0")/.."

DO_PUBLISH=false
DO_TAG=false
for arg in "$@"; do
    case "$arg" in
        --publish) DO_PUBLISH=true ;;
        --tag) DO_TAG=true ;;
        *) echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

echo "═══════════════════════════════════════════════"
echo "  GAUNTLEX Release Workflow"
echo "═══════════════════════════════════════════════"

# ── 1. Version sync check ───────────────────────────────────────────────────
echo ""
echo "▶ 1/5 — Version sync check (pyproject.toml is the source of truth)"

VERSION=$(python3 -c "
import tomllib
with open('pyproject.toml', 'rb') as f:
    print(tomllib.load(f)['project']['version'])
")
echo "  pyproject.toml version: $VERSION"

python3 - "$VERSION" <<'EOF'
import json, sys
version = sys.argv[1]
errors = []

with open(".claude-plugin/plugin.json") as f:
    plugin = json.load(f)
if plugin.get("version") != version:
    errors.append(f".claude-plugin/plugin.json has version={plugin.get('version')!r}, expected {version!r}")

with open(".claude-plugin/marketplace.json") as f:
    marketplace = json.load(f)
mkt_version = marketplace.get("plugins", [{}])[0].get("version")
if mkt_version != version:
    errors.append(f".claude-plugin/marketplace.json plugins[0].version={mkt_version!r}, expected {version!r}")

if errors:
    print("  \033[31m✗ Version mismatch:\033[0m")
    for e in errors:
        print(f"    - {e}")
    print(f"\n  Fix: set both files' version field to \"{version}\" to match pyproject.toml, then re-run.")
    sys.exit(1)
print("  \033[32m✓\033[0m plugin.json and marketplace.json both match")
EOF

# ── 2. Test gate ─────────────────────────────────────────────────────────────
echo ""
echo "▶ 2/5 — Full test suite"
python3 -m pytest tests/ -q --tb=short

# ── 3. Build ─────────────────────────────────────────────────────────────────
echo ""
echo "▶ 3/5 — Build sdist + wheel"
rm -rf dist/ build/ src/*.egg-info
python3 -m build --outdir dist/ >/tmp/gauntlex_build.log 2>&1 || { cat /tmp/gauntlex_build.log; exit 1; }
ls -la dist/

# ── 4. Local install smoke test ─────────────────────────────────────────────
echo ""
echo "▶ 4/5 — Install the built wheel into a throwaway venv and smoke test"
SMOKE_VENV=$(mktemp -d)/venv
python3 -m venv "$SMOKE_VENV"
"$SMOKE_VENV/bin/pip" install --quiet "$(ls dist/*.whl)"
SMOKE_DIR=$(mktemp -d)
(
  cd "$SMOKE_DIR"
  "$SMOKE_VENV/bin/gauntlex" init >/dev/null
  # doctor is expected to fail (no model provider configured in a throwaway
  # env) — we're only checking it starts, imports cleanly, and never assumes
  # Ollama. A clean "not configured" message is success; a crash is not.
  set +e
  OUT=$("$SMOKE_VENV/bin/gauntlex" doctor --pretty 2>&1)
  set -e
  echo "$OUT" | grep -q "not configured" || { printf "  \033[31m\xe2\x9c\x97 unexpected doctor output:\033[0m\n"; echo "$OUT"; exit 1; }
  echo "$OUT" | grep -qi "11434\|ollama" && { printf "  \033[31m\xe2\x9c\x97 doctor leaked an Ollama assumption in a clean env\033[0m\n"; exit 1; }
  printf "  \033[32m\xe2\x9c\x93\033[0m fresh wheel installs and runs cleanly, no Ollama assumption\n"
)
rm -rf "$SMOKE_VENV" "$SMOKE_DIR"

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ Local checks passed for v$VERSION"
echo "═══════════════════════════════════════════════"

# ── 5. Publish + tag (opt-in, touches public destinations) ─────────────────
if [ "$DO_PUBLISH" = true ]; then
    echo ""
    echo "▶ 5/5 — Publish to PyPI"
    if [ -f "$HOME/.pypirc" ] || [ -n "${TWINE_USERNAME:-}${TWINE_PASSWORD:-}${UV_PUBLISH_TOKEN:-}" ]; then
        python3 -m twine upload dist/*
        printf "  \033[32m\xe2\x9c\x93\033[0m published gauntlex-ai==$VERSION to PyPI\n"
    else
        printf "  \033[33m\xe2\x9a\xa0 No PyPI credentials found\033[0m (~/.pypirc or TWINE_*/UV_PUBLISH_TOKEN env vars).\n"
        echo "  Nothing was uploaded. To publish manually once you have a token:"
        echo "    python3 -m twine upload dist/*"
        exit 1
    fi
else
    echo ""
    echo "(skipping PyPI publish — run with --publish once ready)"
fi

if [ "$DO_TAG" = true ]; then
    echo ""
    echo "▶ Tagging v$VERSION"
    git tag "v$VERSION"
    git push origin main
    git push origin "v$VERSION"
    printf "  \033[32m\xe2\x9c\x93\033[0m pushed v$VERSION tag + main to GitHub\n"
else
    echo "(skipping git tag/push — run with --tag once ready)"
fi

echo ""
echo "Don't forget: update the Status column in DISTRIBUTION.md for every"
echo "destination this release actually reached."
