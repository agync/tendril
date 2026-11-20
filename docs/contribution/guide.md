---
type: Guide
title: Contribution guide
description: The working procedure, from scoping a change to the pre-push review gate.
status: draft
tags: [contribution, workflow, review]
---

# Contribution guide

## Setup and verification

```bash
make setup    # install git hooks, generate local shims, create scratch directories
make check    # run formatting, clippy, pre-commit hooks, docs validation, and tests
```

Run `make help` to see all available targets.

## Working procedure

```mermaid
flowchart LR
  S["Scope in one sentence"] --> W["Worktree on fresh branch"]
  W --> P["Plan"]
  P --> I["Implement with tests and docs"]
  I --> C["make check"]
  C --> R["Skeptical review"]
  R --> H["Human approves push"]
```

| Step | Rule |
|---|---|
| Scope | One sentence naming unit of work, target, and outcome; split unrelated edits |
| Worktree | One worktree per change; conventional branch (`feat/`, `fix/`, `docs/`, `refactor/`, `chore/`) rebased on `main` |
| Commits | Conventional Commits, 50/72 limits, summary-only preferred, explicit paths, zero trailers |
| Bindings | Keep host-language wrappers thin; never duplicate wire, roster, or grant logic |
| Docs | Update `spec/` and `docs/` (including parent `index.md` and `docs/logs/` via `make docs/log`) in the same commit |
| Verify | Run `make check` and confirm all hooks, lints, docs checks, and tests pass |
| Review | Run a skeptical maintainer review before requesting a push; humans approve outward actions |
