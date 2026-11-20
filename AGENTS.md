# AGENTS.md

Operational contract for humans and agents working in this repository.

## Project

Tendril is an Apache-2.0 SDK for private device-to-device links without a trusted third party. A single Rust core owns identity, pairing, sealed Noise sessions, default-deny capability grants, and path selection policy; thin bindings expose the core to Rust, Go, Python, TypeScript (Node and browser WASM), Swift, and Kotlin over pluggable, untrusted path providers. Normative protocol rules live in `spec/` and public documentation lives in `docs/`.

## Invariants

- **No elevation.** Never run `sudo`, a system package manager, or a privileged setup script unless a human explicitly requests elevation.
- **Core is the trust boundary.** Assume every network path and relay is hostile. Do not leak plaintext, keys, or authority checks into providers.
- **One core, thin bindings.** Never duplicate wire, pairing, roster, or grant logic in host-language bindings.
- **Default-deny grants.** Confirming identity (`pair.confirm`) and granting capabilities (`pair.mint`) are distinct steps. Fail closed on expired, revoked, or missing capabilities.
- **Public-ready by default.** Nothing committed carries internal hostnames, absolute home paths, private tokens, internal task identifiers, or local file URIs.
- **Zero AI slop.** No em-dashes or en-dashes, no marketing fluff, no filler prose, no comments that restate the code.
- **Tool-agnostic repository.** Never commit assistant-specific files or folders (`CLAUDE.md`, `GEMINI.md`, `.claude/`, `.gemini/`, etc.). They are git-ignored and generated locally by `.agents/bootstrap.sh`.
- **Scratch stays local.** `.agents/brain/` is git-ignored for local notes, plans, and trackers. Never commit it.
- **Tightly scoped, logical commits.** One unit of work per branch/PR in its own worktree off latest `main`. Stage explicit paths; never `git add -A`.
- **Automation over manual conformance.** Pre-commit hooks and `make check` enforce formatting, lints, docs, and invariants. Never bypass hooks.
- **Docs move with the change.** Protocol and behavior changes update `spec/` and `docs/` (including parent `index.md` and `docs/logs/` via `make docs/log`) in the same commit.

## Automation and conventions

- Run `make setup` once in a fresh checkout to install git hooks and local shims.
- Run `make help` to list available targets; `make check` is the full verification gate.
- Commit messages follow Conventional Commits (50-char summary, 72-char body wrap, summary-only preferred, zero commit trailers such as `Co-Authored-By`).
- Documentation in `docs/` is an OKF v0.2 bundle validated by `make docs/check`.

## Verification

A change is done only when `make check` passes with real captured output and all relevant tests are green. A skeptical-maintainer review (`.agents/agents/maintainer-reviewer.md`) precedes any push, and a human explicitly approves every outward action.

## Contributor guide

See [the contributor guide](docs/contribution/guide.md) and [CONTRIBUTING.md](CONTRIBUTING.md).
