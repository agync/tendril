.DEFAULT_GOAL := help

export PATH := $(HOME)/.local/bin:$(PATH)

OKF_WIKI ?= $(HOME)/.agents/skills/okf-wiki
DOCS := docs
KIND ?= Update
FMT_HOOKS := trailing-whitespace end-of-file-fixer mixed-line-ending

# Pass free-text messages via the environment so quotes and backticks survive shell expansion.
override MSG := $(value MSG)
export MSG

.PHONY: help setup build test rust/lint lint lint/staged fmt fmt/check check clean vectors/check docs/check docs/build docs/serve docs/log hooks/require hooks/update

##@ Bootstrap

setup: ## Install git hooks, generate local tool shims, and create the scratch area
	.agents/bootstrap.sh

##@ Build & Quality

build: ## Build all workspace crates and targets
	cargo build --workspace --all-targets

test: ## Run the workspace test suite
	cargo test --workspace --all-features

rust/lint: ## Run rustfmt check and clippy with warnings denied
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

lint: hooks/require rust/lint docs/check ## Run all linters, hooks, and docs checks
	pre-commit run --all-files

lint/staged: hooks/require ## Run pre-commit hooks on staged files only
	pre-commit run

fmt: hooks/require ## Format Rust sources and fix whitespace and line endings
	cargo fmt --all
	@for hook in $(FMT_HOOKS); do pre-commit run "$$hook" --all-files || true; done

fmt/check: ## Fail if Rust formatting differs from rustfmt output
	cargo fmt --all -- --check

vectors/check: ## Verify canonical conformance vectors in Rust and Go
	cargo test -p tendril-core --test vectors
	cd spec/vectors/verify_go && go test ./...

check: lint test vectors/check ## Full quality gate
	@printf 'check: ok\n'

clean: ## Remove build artifacts
	cargo clean

##@ Docs

docs/check: ## Validate the OKF v0.2 docs bundle
	@command -v okf >/dev/null || { printf 'docs/check: okf is not installed. Install with:\n  GOBIN="$$HOME/.local/bin" GOTOOLCHAIN=auto go install github.com/okfcli/okf/cmd/okf@latest\n' >&2; exit 1; }
	okf validate $(DOCS) > /dev/null

docs/build: ## Validate and render the OKF docs bundle
	@[ -f "$(OKF_WIKI)/scripts/bundle-check.sh" ] || { printf 'docs/build: okf-wiki skill not found at %s (set OKF_WIKI)\n' "$(OKF_WIKI)" >&2; exit 1; }
	bash "$(OKF_WIKI)/scripts/bundle-check.sh" --render $(DOCS)

docs/serve: ## Render and serve the OKF docs bundle locally
	@[ -f "$(OKF_WIKI)/scripts/wiki-serve.sh" ] || { printf 'docs/serve: okf-wiki skill not found at %s (set OKF_WIKI)\n' "$(OKF_WIKI)" >&2; exit 1; }
	bash "$(OKF_WIKI)/scripts/wiki-serve.sh" $(DOCS)

docs/log: ## Add a wiki log entry page: make docs/log MSG="..." [KIND=Update]
	@[ -n "$$MSG" ] || { printf '\n  ERROR: set MSG="..."\n\n' >&2; exit 2; }
	@[ -f "$(OKF_WIKI)/scripts/log-entry.py" ] || { printf 'docs/log: okf-wiki skill not found at %s (set OKF_WIKI)\n' "$(OKF_WIKI)" >&2; exit 1; }
	python3 "$(OKF_WIKI)/scripts/log-entry.py" add --bundle "$(DOCS)" --kind "$(KIND)" "$$MSG"

##@ Utilities

hooks/require:
	@command -v pre-commit >/dev/null || { printf 'pre-commit is not installed; run make setup after installing it\n' >&2; exit 1; }

hooks/update: hooks/require ## Update pinned pre-commit hook revisions
	pre-commit autoupdate

# The escaped slash ends nothing in POSIX awk, keeping bare `make` portable across awk implementations.
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
	  /^[a-zA-Z0-9_\/-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
