#!/usr/bin/env bash
# Idempotent local setup: scratch area, git-ignored assistant shims, and git hooks.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

mkdir -p .agents/brain/inbox .agents/brain/outbox .agents/brain/tasks .agents/brain/assets

# Shims point assistant tools at the single committed contract and stay git-ignored.
for shim in CLAUDE.md GEMINI.md ANTIGRAVITY.md CURSOR.md .cursorrules; do
    printf 'Read AGENTS.md and follow it.\n' > "$shim"
done

if ! command -v pre-commit >/dev/null 2>&1; then
    printf 'bootstrap: pre-commit is not installed (install via pipx or uv tool install pre-commit)\n' >&2
    exit 1
fi

pre-commit install --install-hooks --hook-type pre-commit --hook-type commit-msg

printf 'Bootstrap complete. Run make check.\n'
