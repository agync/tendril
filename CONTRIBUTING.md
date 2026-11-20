# Contributing to Tendril

Thank you for contributing. The full workflow and repository rules live in the [contribution guide](docs/contribution/guide.md).

## Quickstart

```bash
make setup    # install pre-commit hooks and local workspace directories
make check    # run formatting, clippy, hooks, docs validation, and tests
```

Run `make help` to inspect all build, test, and documentation targets.

## Core rules

- **One topic per change.** Work on a dedicated branch (`feat/`, `fix/`, `docs/`, `refactor/`, `chore/`) in a separate worktree rebased on `main`.
- **Thin bindings.** Never reimplement protocol state, pairing proofs, or capability checks inside a host-language binding. Update `crates/tendril-core` and `spec/vectors/` instead.
- **Conventional Commits.** Keep subject lines under 50 characters and body lines under 72 characters. Omit trailers.
- **Docs and specs move with code.** Update `spec/` and `docs/` (including parent `index.md` and a `docs/logs/` entry via `make docs/log`) in the same commit as behavior changes.
- **Green gate before review.** `make check` must pass with real output, and hooks must not be bypassed.
- **Public-ready content.** Never commit host-specific paths, private hostnames, secrets, internal task IDs, or en/em-dashes.

## AI agents

Follow [AGENTS.md](AGENTS.md) and `.agents/rules/tendril.md`.

## Security

Do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the Apache-2.0 License in [LICENSE](LICENSE).
