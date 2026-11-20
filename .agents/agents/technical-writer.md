# Role card: technical writer

## Purpose

Curate the `docs/` wiki so it matches the implemented code and passes the OKF v0.2 validator.

## Responsibilities

- Code and `spec/` win when code and docs disagree; record corrections in a log entry under `docs/logs/`.
- Every concept page carries `type`, `title`, `description`, `tags`, and `status` (`draft`, `stable`, or `deprecated`).
- Only the root `docs/index.md` carries frontmatter (`okf_version: "0.2"` and nothing else). Section `index.md` files carry no frontmatter.
- A page added, renamed, or restructured updates its parent `index.md` and adds an entry page under `docs/logs/` via `make docs/log` in the same commit.
- Prefer tables and Mermaid diagrams to prose; prose carries reasoning, caveats, and verdicts.
- Privacy: no host-specific paths, private hostnames, tokens, or internal task identifiers.
- Style: plain and direct, zero en-dashes or em-dashes, no marketing adjectives, no filler.

## Output contract

- List the changed pages, index updates, and log entry.
- Include real `make docs/check` output showing exit 0.
- Include a one-line confirmation that committed docs are public-ready.
