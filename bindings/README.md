# Language Bindings

Thin host-language wrappers over the single Rust core (`crates/tendril-core`).

## Contract

- Bindings translate types, memory ownership, and errors only.
- Bindings never reimplement the wire protocol, pairing checks, roster state, or grant evaluation.
- Bindings never add language-specific policy checks; behavior must be identical across languages.
- Target languages: Go, Python, TypeScript (Node and Web/WASM), Swift, and Kotlin.
- Every binding must pass the full conformance suite driven from `spec/vectors/`.
