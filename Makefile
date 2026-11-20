.DEFAULT_GOAL := help

export PATH := $(HOME)/.cargo/bin:$(HOME)/.local/bin:$(PATH)

OKF_WIKI ?= $(HOME)/.agents/skills/okf-wiki
DOCS := docs
KIND ?= Update
FMT_HOOKS := trailing-whitespace end-of-file-fixer mixed-line-ending
SHLIB_EXT := $(if $(filter Darwin,$(shell uname -s)),dylib,so)
JNI_OS := $(if $(filter Darwin,$(shell uname -s)),darwin,linux)

# Pass free-text messages via the environment so quotes and backticks survive shell expansion.
override MSG := $(value MSG)
export MSG

.PHONY: help setup build test rust/lint lint lint/staged fmt fmt/check check clean vectors/check bindings/go bindings/python bindings/node bindings/wasm bindings/wasm-p2p bindings/web bindings/jni bindings/android bindings/check docs/check docs/build docs/serve docs/log hooks/require hooks/update

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
	cargo fmt --manifest-path bindings/python/Cargo.toml -- --check
	cargo clippy --manifest-path bindings/python/Cargo.toml --all-targets -- -D warnings
	cargo fmt --manifest-path bindings/node/Cargo.toml -- --check
	cargo clippy --manifest-path bindings/node/Cargo.toml --all-targets -- -D warnings

lint: hooks/require rust/lint docs/check ## Run all linters, hooks, and docs checks
	pre-commit run --all-files

lint/staged: hooks/require ## Run pre-commit hooks on staged files only
	pre-commit run

fmt: hooks/require ## Format Rust sources and fix whitespace and line endings
	cargo fmt --all
	cargo fmt --manifest-path bindings/python/Cargo.toml
	cargo fmt --manifest-path bindings/node/Cargo.toml
	@for hook in $(FMT_HOOKS); do pre-commit run "$$hook" --all-files || true; done

fmt/check: ## Fail if Rust formatting differs from rustfmt output
	cargo fmt --all -- --check
	cargo fmt --manifest-path bindings/python/Cargo.toml -- --check
	cargo fmt --manifest-path bindings/node/Cargo.toml -- --check

vectors/check: ## Verify canonical conformance vectors in Rust and Go
	cargo test -p tendril-core --test vectors
	cd spec/vectors/verify_go && go test ./...

check: lint test vectors/check bindings/check ## Full quality gate
	@printf 'check: ok\n'

clean: ## Remove build artifacts
	cargo clean
	cargo clean --manifest-path bindings/python/Cargo.toml
	cargo clean --manifest-path bindings/node/Cargo.toml
	rm -f bindings/python/tendril/_tendril.so bindings/node/index.node
	rm -rf bindings/web/pkg bindings/web/pkg-p2p bindings/kotlin/build-jni

##@ Bindings

bindings/go: ## Build tendril-ffi and run Go cgo tests with -race
	cargo build -p tendril-ffi --lib
	cargo build -p tendril-cli --bin tendril-conformance-peer
	cd bindings/go && go vet ./... && go test -race ./...

bindings/python: ## Build PyO3 extension and run Python conformance tests
	cargo build -p tendril-cli --bin tendril-conformance-peer
	cargo build --manifest-path bindings/python/Cargo.toml
	cp -f bindings/python/target/debug/lib_tendril.$(SHLIB_EXT) bindings/python/tendril/_tendril.so
	cd bindings/python && python3 -m unittest discover -s tests -v

bindings/node: ## Build N-API addon and run Node conformance tests
	cargo build -p tendril-cli --bin tendril-conformance-peer
	cargo build --manifest-path bindings/node/Cargo.toml
	cp -f bindings/node/target/debug/libtendril_node.$(SHLIB_EXT) bindings/node/index.node
	cd bindings/node && node --test

bindings/wasm: ## Build tendril-wasm for wasm32-unknown-unknown and generate browser bindings
	cargo build --release --target wasm32-unknown-unknown -p tendril-wasm
	wasm-bindgen --target web --out-dir bindings/web/pkg target/wasm32-unknown-unknown/release/tendril_wasm.wasm

bindings/wasm-p2p: ## Build opt-in p2p-iroh browser WASM module into bindings/web/pkg-p2p
	CC_wasm32_unknown_unknown=clang \
	AR_wasm32_unknown_unknown="$$(command -v llvm-ar || command -v ar)" \
	cargo build --release --target wasm32-unknown-unknown -p tendril-wasm --features p2p-iroh
	wasm-bindgen --target web --out-dir bindings/web/pkg-p2p target/wasm32-unknown-unknown/release/tendril_wasm.wasm

bindings/web: bindings/wasm bindings/wasm-p2p ## Run headless Chrome Web SDK conformance and live relay E2E tests
	cargo build -p tendril-relay --bin tendril-relay
	cargo build -p tendril-cli --bin tendril-conformance-peer
	node bindings/web/test/browser_e2e.mjs

bindings/jni: ## Build tendril_jni shared library and run host JVM conformance tests
	cargo build -p tendril-ffi --lib
	cargo build -p tendril-cli --bin tendril-conformance-peer
	@JDK_HOME="$${JAVA_HOME:-$$(dirname "$$(dirname "$$(readlink -f "$$(command -v javac)")")")}"; \
	mkdir -p bindings/kotlin/build-jni/classes; \
	gcc -shared -fPIC -Wall -Wextra -Werror \
	  -I"$$JDK_HOME/include" -I"$$JDK_HOME/include/$(JNI_OS)" \
	  -Icrates/tendril-ffi/include bindings/kotlin/jni/tendril_jni.c \
	  -L"$$(pwd)/target/debug" -ltendril_ffi -Wl,-rpath,"$$(pwd)/target/debug" \
	  -o bindings/kotlin/build-jni/libtendril_jni.$(SHLIB_EXT); \
	javac -d bindings/kotlin/build-jni/classes \
	  bindings/kotlin/src/main/java/dev/tendril/TendrilNative.java \
	  bindings/kotlin/test/TendrilJniConformanceTest.java; \
	java --enable-native-access=ALL-UNNAMED \
	  -Djava.library.path="$$(pwd)/bindings/kotlin/build-jni" \
	  -cp bindings/kotlin/build-jni/classes dev.tendril.TendrilJniConformanceTest

bindings/android: ## Cross-compile tendril-ffi for aarch64-linux-android using local Android NDK
	@NDK_ROOT="$${ANDROID_NDK_HOME:-$$(ls -d "$(HOME)"/Android/Sdk/ndk/* 2>/dev/null | sort -V | tail -n 1)}"; \
	NDK_BIN="$$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"; \
	CLANG="$$(ls "$$NDK_BIN"/aarch64-linux-android*-clang 2>/dev/null | sort -V | awk -F'android|-clang' '$$2 >= 26 {print $$0; exit}')"; \
	test -x "$$CLANG" || { printf 'bindings/android: no Android NDK aarch64 clang >= API 26 found under %s\n' "$$NDK_ROOT" >&2; exit 1; }; \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$$CLANG" \
	CC_aarch64_linux_android="$$CLANG" \
	AR_aarch64_linux_android="$$NDK_BIN/llvm-ar" \
	cargo build --release --target aarch64-linux-android -p tendril-ffi --lib

bindings/check: bindings/go bindings/python bindings/node bindings/web bindings/jni ## Verify Go, Python, Node, Web WASM, and Kotlin JNI bindings

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
