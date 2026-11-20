# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately to the repository maintainers using GitHub private vulnerability reporting on the repository's Security tab. Do not open a public issue or pull request for an unpatched security vulnerability.

Include the affected crate or binding version, operating system or runtime, and minimal reproduction steps.

## In scope

- Cryptographic handshake, pairing proof, rotation verification, and framing in `crates/tendril-core`
- Capability grant parsing, canonical signature verification, delegation subset checks, and revocation
- Language bindings (`bindings/`) and C ABI / WASM boundaries
- Relay forwarding components and wire specifications (`spec/`)

## Security model and explicit limits

Tendril guarantees mutual authentication of pinned static keys, per-session forward secrecy, frame integrity and confidentiality, and default-deny capability checks against peer grants.

Tendril explicitly does **not** guarantee:

- **Metadata hiding or anonymity.** Relays, overlays, and network observers still see connection endpoints, frame counts, frame sizes, and timing.
- **Instant offline revocation.** A revoked peer cannot learn of revocation until it attempts to reconnect or rekey.
- **Protection against a compromised endpoint.** A compromised device with unlocked keys can exercise the capabilities it holds until revoked.
- **Browser held-link parity.** Browser WASM clients rely on WebSockets and polling and cannot open raw UDP sockets or hold background connections when suspended.

## Supported versions

Only the latest release and the `main` branch are actively supported with security updates.
