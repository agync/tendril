# Proof Standard and Severity Calibration

## Evidence contract

Every reported finding must carry an explicit `Proof Status`:

- **`PROVEN_BY_TEST`:** Backed by a defensive reproduction test added and executed inside the lane's isolated audit worktree, citing the exact test command and observed output.
  - Keep reproduction tests defensive and hermetic (`127.0.0.1:0`, temp dirs, in-memory streams).
  - Do not build standalone exploit scripts, external scanners, or DoS tools targeting outside hosts.
- **`PROVEN_BY_CODE_TRACE`:** Used only when runtime execution is unavailable in the audit environment (for example Apple `XCTest`/Swift on Linux, Android Keystore hardware APIs, or passive network metadata behavior). Provide an exact line-by-line code, wire-format, or state-machine trace proving reachability and failure.

Do not promote unverified hypotheses, lint preferences, or theoretical issues lacking a concrete trigger path into findings. Record clean checks and unverified avenues under `Checked Clean` or `Out of Scope`.

## Required finding format

Use this structure for every candidate finding in Wave 1 and every confirmed finding in Wave 2:

```markdown
#### `SEC-XX` (or `PRIV-XX`): Concise title naming component and failure mode
- **Priority:** `P0` | **Severity:** `High` | **Disposition:** `CONFIRMED`
- **Locations:** `path/to/file.rs:10-25`
- **Proof Status:** `PROVEN_BY_TEST` (or `PROVEN_BY_CODE_TRACE`)
  - Verified command & output (or step-by-step trace)
- **Real-World Assessment:**
  - **Adversary:** Who exploits or triggers this (network position / privilege)
  - **Preconditions:** Required configuration, state, or interaction
  - **Likelihood:** `Low` | `Medium` | `High`
  - **Impact:** Concrete effect on Confidentiality, Integrity, Availability, or Privacy
- **Recommended Remediation:** Minimal architectural fix matching repository invariants
- **Effort:** `S` (< 1 day) | `M` (1-3 days) | `L` (> 3 days)
```

## Severity calibration rubric

Calibrate severity by **realistic impact and preconditions**, not worst-case buzzwords:

| Severity | Criteria |
|---|---|
| **Critical** | Pre-auth remote RCE/memory corruption, total private-key recovery, or trivial unauthenticated authentication/encryption bypass in default configurations. |
| **High** | Pin hijacking, forged/bypassed revocation or authorization, serious cross-user pre-auth DoS, default plaintext private-key custody on mobile, or systemic metadata leaks violating core privacy posture (such as self-hosted custom relays phoning public DNS). |
| **Medium** | Cryptographic or protocol flaws requiring atypical preconditions (`e_I == 0`, low-order peer keys, long-session auto-rekey boundary + oversize write), reverse-proxy IP-bucket collapse, NUL/JCS divergence, non-loopback cleartext transport defaults, or unbounded client-side stream queues. |
| **Low** | Defense-in-depth gaps, local multi-user `/proc` or filesystem permission races under non-default parent dirs, demo server hardening, timing or error oracles already throttled upstream, stale poll-window clock snapshots mitigated at `authorize()`. |
| **Informational** | Reserved/unwired fields (`Grant.uses`), debug log hygiene (`BrokerDialer`), CLI stdout sensitivity, or documented v1 architectural tradeoffs. |

## Priority mapping and anti-inflation checks

| Priority | Action Gate | Typical Assignment |
|---|---|---|
| `P0` | **Immediate Blocker** (fix before any external audit or Phase work) | `Critical` findings, `High` auth/pin/revocation bypasses, permanent availability deadlocks (`InboundRouter`). |
| `P1` | **Pre-Public Release** (fix before public 1.0 / general deployment) | Remaining `High` findings plus `Medium` protocol, rate-limit, FFI boundary, and transport TLS issues. |
| `P2` | **Defense-in-Depth & Hardening** | Lower-likelihood `Medium` and actionable `Low` bugs (`JCS`, `Capability` path helper, demo hardening, `snow` zeroization). |
| `P3` | **Informational & Tracked Tradeoffs** | Non-blocking hygiene, explicit v1 non-goals documented in `docs/overview.md`, or Phase-N interactions. |

Before keeping a severity in Wave 1 or Wave 2, always ask:
1. Is this already documented as an explicit v1 non-goal in `docs/overview.md`?
2. Is it mitigated upstream or downstream (for example, `SessionMachine` enforces `Roster::ingest_crl` even though standalone `verify_grant_json` skips CRL signature, issuer, and monotonicity verification)? If yes, scope the finding accurately to the unmitigated surface.
3. Can an attacker actually reach it without already controlling the victim's private keys or host root?
