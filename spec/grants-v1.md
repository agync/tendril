# Tendril Capability Grants Specification v1

Status: **Normative (v1)**

Conventions follow `spec/wire-v1.md`. All grants default to deny: confirming a peer's identity permits establishing an authenticated session, and permits no application action unless covered by a valid, unrevoked grant.

---

## 1. Capability Grammar

A capability string has one of two forms:

```text
namespace.verb
namespace.verb:resource
```

- `namespace` MUST match `^[a-z][a-z0-9_]{0,31}$`.
- `verb` MUST match `^[a-z][a-z0-9_]{0,31}$`.
- `resource` (when `:resource` is present) MUST be non-empty printable ASCII (`0x21..=0x7E`, no whitespace or control characters) and MAY contain at most one `'*'` character, which MUST appear as the final byte of `resource` (prefix wildcard).
- Mid-string wildcards, negation prefixes, and regular expressions are forbidden.

### 1.1 Reserved Core Capabilities

| Capability | Meaning |
|---|---|
| `session.open` | Open an authenticated session (always required; empty `caps` denies all app actions) |
| `pair.confirm` | Confirm a `pending` peer on the roster |
| `pair.mint` | Issue or delegate a narrower capability grant |
| `roster.read` | Inspect known peers and grant status |
| `roster.revoke` | Revoke a peer or grant nonce |

### 1.2 Capability Coverage Rules

Capability `granted` covers `requested` if and only if:

1. `granted.namespace == requested.namespace` and `granted.verb == requested.verb`.
2. Resource matching:
   - If `granted.resource` is `None`: `requested.resource` MUST be `None`.
   - If `granted.resource` is `Some(g)` without trailing `'*'`: `requested.resource` MUST be `Some(r)` with `r == g` (exact match).
   - If `granted.resource` is `Some(prefix + "*")`: `requested.resource` MUST be `Some(r)`:
     - When `requested` is a concrete action (no trailing `'*'`), `r` MUST start with `prefix`.
     - When `requested` is itself a delegated wildcard `req_prefix + "*"`, `req_prefix` MUST start with `prefix`.
- Resource matching operates on opaque ASCII strings; path-scoped applications MUST canonicalize paths (resolving `.`, `..`, and duplicate separators) before authorization checks.

---

## 2. Grant Wire Format and Canonical Signing

```jsonc
Grant = {
  "v": 1,
  "issuer": string,                 // issuer device_id
  "subject": string,                // subject device_id
  "caps": [string],                 // sorted or listed capability strings
  "not_before": string,             // RFC 3339 UTC instant at whole-second precision (YYYY-MM-DDTHH:MM:SSZ, no fractional seconds or numeric offsets)
  "not_after": string,              // RFC 3339 UTC instant at whole-second precision (YYYY-MM-DDTHH:MM:SSZ, no fractional seconds or numeric offsets)
  "nonce": string,                  // b64url 16-byte unique grant identifier
  "delegated_from"?: [Grant],       // optional 1-element array containing the immediate parent Grant (nested recursively)
  "uses"?: uint64,                  // optional max uses (reserved for single-use enrollment tokens)
  "machine"?: bool,                 // optional machine enrollment marker
  "sig": string                     // b64url 64-byte Ed25519 signature by issuer signing key
}
```

### 2.1 Signature Input

To sign or verify a `Grant`, serialize the object **without** the `"sig"` field using RFC 8785 JSON Canonicalization Scheme (JCS), and prepend the 17-byte domain separator:

```text
signed_bytes = "tendril-grant-v1\0" (17 B) || UTF-8(RFC8785_JCS(grant_without_sig))
```

Canonical encoding and strict JSON decoding rules:

- Optional fields (`delegated_from` when empty, `uses` and `machine` when unset) MUST be omitted from Grant JSON (not encoded as `[]` or `null`).
- Verifiers MUST reject unknown JSON fields (`deny_unknown_fields`) on `Grant` and `RevocationList`.
- Verification MUST use strict Ed25519 signature verification against the issuer's pinned Ed25519 signing public key.

---

## 3. Delegation Subset Rules

A peer holding `parent` may mint a delegated `child` grant (attaching `[parent]` in `child.delegated_from`, nesting recursively up to a root grant issued by the authoritative verifier) only if ALL of the following hold:

1. `parent.caps` covers `pair.mint`.
2. `child.issuer == parent.subject`.
3. Every capability in `child.caps` is covered by at least one capability in `parent.caps` using Section 1.2 coverage rules.
4. Time window narrowing: `child.not_before >= parent.not_before` and `child.not_after <= parent.not_after`.
5. Maximum delegation depth (default `4`) is not exceeded, and no cycle of nonces or subjects exists.
6. Neither `parent` nor any ancestor grant nonce or issuer device appears on the active `RevocationList`.

---

## 4. Revocation List (`RevocationList`)

```jsonc
RevocationList = {
  "v": 1,
  "issuer": string,                 // issuer device_id
  "seq": uint64,                    // strictly monotonic sequence counter
  "revoked_devices": [string],      // revoked device_ids
  "revoked_nonces": [string],       // revoked grant nonces (b64url)
  "ts": string,                     // RFC 3339 UTC instant at whole-second precision (YYYY-MM-DDTHH:MM:SSZ, no fractional seconds or numeric offsets)
  "sig": string                     // b64url 64-byte Ed25519 signature
}
```

Signature input:

```text
signed_bytes = "tendril-crl-v1\0" (15 B) || UTF-8(RFC8785_JCS(crl_without_sig))
```

Verifiers MUST reject any `RevocationList` with a `seq` lower than the highest verified `seq` already persisted for that issuer.

---

## 5. Fail-Closed Evaluation Order

Every grant check (at session connect, on `0x04 REKEY`, and on `authorize(requested_cap)`) executes the following checks in order and denies on the first failure (performing cheap structural, time, CRL, and root checks before Ed25519 signature verification):

1. Validate `grant.v == 1`, non-empty `nonce`, delegation depth `<= 4`, no nonce or subject cycles, and syntactically valid `caps`. When a `RevocationList` is supplied, also fail closed if `crl.v != 1`, `crl.issuer != root_issuer`, `crl.ts` is invalid UTC, or strict Ed25519 verification of `crl.sig` under `root_issuer`'s pinned signing key fails.
2. Verify `grant.subject` matches the authenticated session peer `device_id` (or `child.issuer` during recursion).
3. Check time bounds with a maximum `30 s` clock-skew allowance: `grant.not_before.saturating_sub(30s) <= now < grant.not_after` and `grant.not_before < grant.not_after`.
4. Check `RevocationList` for `grant.subject`, `grant.issuer`, and `grant.nonce`.
5. If `delegated_from` is omitted (root grant), verify `grant.issuer` equals the authoritative root verifier; otherwise require `delegated_from.len() == 1`.
6. Look up `grant.issuer` in the roster (confirming `active` status) and strictly verify `grant.sig`.
7. If `delegated_from` is present, verify delegation subset rules (Section 3) against the immediate parent and recursively evaluate that parent link starting from step 1.
8. Match `requested_cap` against `grant.caps` (denying by default if unmatched) and emit a structured `AuditEvent { ts, subject, cap, grant_nonce, allow, reason }`.
