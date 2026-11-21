# Tendril

A private, end-to-end encrypted link SDK for desktop, mobile, web, and servers with no trusted third party in the middle.

## Overview

Tendril extracts the pairing ceremony, sealed session protocol, capability grant evaluation, and hostile-path policy into a single Rust core exposed through thin language bindings. Every network path (local, direct LAN/WAN, overlay, P2P, relay, or proxy broker) is treated as untrusted byte transport underneath one Noise session.

| Layer | Responsibility | Key Properties |
|---|---|---|
| Host App | Keystore storage, roster persistence, pairing UI | Supplies platform storage and renders code/fingerprint checks |
| Thin Bindings | Rust, Go, Python, TypeScript (Node and Web WASM), Swift, Kotlin | Translates types and errors only; zero duplicated protocol logic |
| Tendril Core | Identity, pairing proof, Noise XXhfs hybrid PQ session, capability grants, path policy | Sole trust boundary; default-deny grants; conformance-tested |
| Path Providers | Local, Direct, Overlay, P2P, Relay, Broker | Untrusted byte pipes; cannot decrypt, forge, or widen grants |

## Repository layout

| Path | Contents |
|---|---|
| `crates/` | Rust workspace (`tendril-core` and future runtime, relay, CLI, FFI, and WASM crates) |
| `bindings/` | Thin host-language packages (Go, Python, TypeScript, Swift, Kotlin) |
| `spec/` | Normative wire, pairing, grant, and relay specifications plus `vectors/` |
| `docs/` | OKF v0.2 documentation bundle |

## Development

Requires Rust (2024 edition), GNU `make`, [pre-commit](https://pre-commit.com), and [okf](https://github.com/okfcli/okf) for documentation checks.

```bash
make setup    # install git hooks, local scratch dirs, and git-ignored tool shims
make check    # run all lints, format checks, docs validation, and tests
make help     # list all targets
```

## Documentation

The [documentation bundle](docs/index.md) is kept as an OKF v0.2 wiki:

- [Overview](docs/overview.md): goals, non-goals, and design boundaries
- [Architecture](docs/architecture/index.md): layered trust boundary and module responsibilities
- [Decisions](docs/adr/index.md): architecture decision records
- [Contribution](docs/contribution/index.md): workflow, conventions, and review gates

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). AI coding agents also follow [AGENTS.md](AGENTS.md).

## Security

Report security issues privately. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
