#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CF_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${CF_DIR}/../.." && pwd)"

if [ "${TENDRIL_SKIP_WASM_BUILD:-0}" = "1" ] && [ -f "${CF_DIR}/pkg/tendril_wasm_bg.wasm" ]; then
  exit 0
fi

NPM_PKG_DIR="${CF_DIR}/node_modules/@tendril-sdk/web/pkg"
if [ -f "${NPM_PKG_DIR}/tendril_wasm.js" ] && [ -f "${NPM_PKG_DIR}/tendril_wasm_bg.wasm" ]; then
  if grep -q 'relay_protocol_constants_json' "${NPM_PKG_DIR}/tendril_wasm.js" &&
     grep -q 'validate_relay_ticket_schema_json' "${NPM_PKG_DIR}/tendril_wasm.js"; then
    mkdir -p "${CF_DIR}/pkg"
    cp -f "${NPM_PKG_DIR}"/tendril_wasm* "${CF_DIR}/pkg/"
    exit 0
  fi
fi

WB_VERSION="0.2.130"
RUST_CHANNEL="1.97.1"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

if [ -f "${REPO_ROOT}/Cargo.toml" ] && [ -d "${REPO_ROOT}/crates/tendril-wasm" ]; then
  SRC_ROOT="${REPO_ROOT}"
else
  SRC_REPO="${TENDRIL_SOURCE_REPO:-https://github.com/agync/tendril.git}"
  SRC_REF="${TENDRIL_SOURCE_REF:-main}"
  if [ -d "${SRC_REPO}" ]; then
    git clone --quiet "${SRC_REPO}" "${TMP_DIR}/src"
    git -C "${TMP_DIR}/src" checkout --quiet "${SRC_REF}"
  else
    git clone --quiet --depth 1 --branch "${SRC_REF}" "${SRC_REPO}" "${TMP_DIR}/src"
  fi
  SRC_ROOT="${TMP_DIR}/src"
fi

if [ -x "${CF_DIR}/.tools/cargo/bin/cargo" ]; then
  export RUSTUP_HOME="${CF_DIR}/.tools/rustup"
  export CARGO_HOME="${CF_DIR}/.tools/cargo"
  PATH="${CARGO_HOME}/bin:${PATH}"
  export PATH
  export RUSTUP_TOOLCHAIN="${RUST_CHANNEL}"
fi

if ! command -v cargo >/dev/null 2>&1; then
  if [ -n "${WORKERS_CI:-}${CF_PAGES:-}${CI:-}" ]; then
    export RUSTUP_HOME="${CF_DIR}/.tools/rustup"
    export CARGO_HOME="${CF_DIR}/.tools/cargo"
    mkdir -p "${RUSTUP_HOME}" "${CARGO_HOME}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
      sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_CHANNEL}" \
        --target wasm32-unknown-unknown
    PATH="${CARGO_HOME}/bin:${PATH}"
    export PATH
    export RUSTUP_TOOLCHAIN="${RUST_CHANNEL}"
  else
    printf 'build.sh: cargo is required to build tendril-wasm\n' >&2
    exit 1
  fi
fi

if command -v rustup >/dev/null 2>&1; then
  if [ -n "${WORKERS_CI:-}${CF_PAGES:-}" ]; then
    export RUSTUP_TOOLCHAIN="${RUST_CHANNEL}"
    rustup toolchain install "${RUST_CHANNEL}" --profile minimal --target wasm32-unknown-unknown
  elif ! rustup target list --installed | grep -qx 'wasm32-unknown-unknown'; then
    rustup target add wasm32-unknown-unknown
  fi
fi

TOOLS_BIN="${CF_DIR}/.tools/bin"
if [ -x "${TOOLS_BIN}/wasm-bindgen" ]; then
  PATH="${TOOLS_BIN}:${PATH}"
  export PATH
fi

CURRENT_WB="$(wasm-bindgen --version 2>/dev/null || true)"
if [ "${CURRENT_WB}" != "wasm-bindgen ${WB_VERSION}" ]; then
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  WB_TARGET=""
  WB_SHA256=""
  case "${OS}:${ARCH}" in
    Linux:x86_64)
      WB_TARGET="x86_64-unknown-linux-musl"
      WB_SHA256="9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f"
      ;;
    Linux:aarch64 | Linux:arm64)
      WB_TARGET="aarch64-unknown-linux-musl"
      WB_SHA256="99ffc93ce80081b91632e2b539b782821a8f3439ab0fddc645287462b2f55d3d"
      ;;
    Darwin:x86_64)
      WB_TARGET="x86_64-apple-darwin"
      WB_SHA256="eb209c115b7cb95832423c1aa3f4d06d6c53f63ef74fc4b6fb79ef0b2eea5f10"
      ;;
    Darwin:arm64 | Darwin:aarch64)
      WB_TARGET="aarch64-apple-darwin"
      WB_SHA256="b90ddb9357f584b1af897d58ad77e4cce2b48fc17e2a967bc249a87f72809444"
      ;;
    *)
      printf 'build.sh: install wasm-bindgen %s manually for %s/%s (found: %s)\n' \
        "${WB_VERSION}" "${OS}" "${ARCH}" "${CURRENT_WB:-none}" >&2
      exit 1
      ;;
  esac
  mkdir -p "${TOOLS_BIN}"
  TGZ="wasm-bindgen-${WB_VERSION}-${WB_TARGET}.tar.gz"
  URL="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WB_VERSION}/${TGZ}"
  curl -fsSL --retry 3 -o "${TMP_DIR}/${TGZ}" "${URL}"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s/%s\n' "${WB_SHA256}" "${TMP_DIR}" "${TGZ}" | sha256sum --check --status -
  else
    printf '%s  %s/%s\n' "${WB_SHA256}" "${TMP_DIR}" "${TGZ}" | shasum -a 256 --check --status -
  fi
  tar -xzf "${TMP_DIR}/${TGZ}" --strip-components=1 -C "${TOOLS_BIN}" \
    "wasm-bindgen-${WB_VERSION}-${WB_TARGET}/wasm-bindgen"
  chmod +x "${TOOLS_BIN}/wasm-bindgen"
  PATH="${TOOLS_BIN}:${PATH}"
  export PATH
fi

(
  cd "${SRC_ROOT}"
  TARGET_DIR="${CARGO_TARGET_DIR:-target}"
  cargo build --locked --release --target wasm32-unknown-unknown -p tendril-wasm
  wasm-bindgen --target web --out-dir "${CF_DIR}/pkg" \
    "${TARGET_DIR}/wasm32-unknown-unknown/release/tendril_wasm.wasm"
)
