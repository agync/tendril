---
type: Design
title: Capability grants and revocation
description: Default-deny capability grammar, RFC 8785 JCS signing, recursive delegation checks, and monotonic revocation lists.
status: stable
tags: [design, grants, security]
---

# Capability grants and revocation

Confirming a peer's identity (`pair.confirm`) pins its cryptographic key and permits opening an authenticated session, while granting application authority (`pair.mint`) is a separate default-deny step.

## Capability grammar

Capabilities follow `namespace.verb` or `namespace.verb:resource`:

- `namespace` and `verb` match `^[a-z][a-z0-9_]{0,31}$`.
- `resource` uses printable non-whitespace ASCII and allows at most one trailing `'*'` prefix wildcard; matching operates on opaque ASCII strings, while `canonicalize_capability_path`, `Capability::covers_path`, `grant_allows_path`, `authorize_path_capability`, and `SessionMachine::authorize_path` reject traversal, dot segments, backslashes, `//`, and trailing slashes for path-scoped checks.
- Reserved core capabilities are `session.open`, `pair.confirm`, `pair.enroll` (optional `:<host_id>` scope), `pair.mint`, `roster.read`, and `roster.revoke`.

## Signing and delegation

Grants are serialized without `sig` using RFC 8785 JSON Canonicalization Scheme (JCS), prefixed with `"tendril-grant-v1\0"`, and signed with the issuer's Ed25519 signing key. Optional `uses` (`uses == 1`) and `machine: true` are reserved exclusively for single-use enrollment tokens (`uses == 0` fails closed everywhere). Regular `intent = session` authorization (`verify_grant_with_chain` and `authorize_grant`) rejects any grant (leaf or ancestor) specifying `uses` or `machine: true`, preventing single-use enrollment tokens from crossing into application sessions. `delegated_from` carries the single immediate parent nested recursively up to the authoritative root verifier.

Delegation chains (`delegated_from`) require every link to:

1. Hold `pair.mint` in the parent grant.
2. Match `child.issuer == parent.subject`.
3. Narrow or preserve every requested capability under the parent's resource bounds.
4. Keep `child.not_before >= parent.not_before` and `child.not_after <= parent.not_after`.
5. Stay within the maximum delegation depth (`4`) with no nonce or subject cycles.

## Fail-closed evaluation order

| Step | Check | Failure Action |
|---|---|---|
| 1 | Parse `v == 1`, non-empty `nonce`, depth `<= 4`, no nonce/subject cycles, valid `caps` | Deny |
| 2 | Verify `grant.subject` matches authenticated session `device_id` (or child `issuer`) | Deny |
| 3 | Check `not_before.saturating_sub(30s) <= now < not_after` and `not_before < not_after` | Deny |
| 4 | Check verified `RevocationList` for `grant.subject`, `grant.issuer`, and `grant.nonce` | Deny |
| 5 | Require authoritative root `issuer` when empty, or `delegated_from.len() == 1` | Deny |
| 6 | Confirm `grant.issuer` is `active` in roster and strictly verify Ed25519 signature | Deny |
| 7 | Check subset rules and recursively evaluate `delegated_from[0]` from step 1 | Deny |
| 8 | Match requested capability against `caps` and emit structured `AuditEvent` record | Return result |

Normative details live in `spec/grants-v1.md`.
