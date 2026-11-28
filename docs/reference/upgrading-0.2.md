---
type: Reference
title: Upgrading to 0.2
description: Breaking changes between 0.1 and 0.2 and what callers need to change.
status: stable
tags: [reference, upgrade, breaking-changes, release]
---

# Upgrading to 0.2

0.2.0 was tagged but not published; 0.2.1 is the first release that ships these changes. Each item below changes behaviour or an API that a 0.1 caller may depend on.

- **C ABI refusal result.** After a host refuses a session, `tendril_session_send_data`, `tendril_session_rekey` and `tendril_session_close` return `TENDRIL_ERR_REFUSED` (`-8`) instead of `TENDRIL_ERR_PROTOCOL` (`-6`), and `TendrilResult` gains that value. Read the reason with `tendril_last_error_code` (`refused_revoked`, `refused_pending`, `refused`).
- **Swift refusal error.** `TendrilError` gains the `.refused(TendrilRefusal)` case. Exhaustive `switch` statements over `TendrilError` need a new arm.
- **Revocation notices by default.** `revoke_peer` (C ABI, Python, Node) and `tendril revoke` record a refusal notice per the endpoint refusal policy, so the revoked device is told it was revoked. Pass `notify: false` or `--no-notify` to revoke silently.
- **Refusals on the wire.** A host now answers a known revoked or pending peer with an authenticated refusal (Wire v1 close `4001` or `4004`, a sealed refusal on Wire v2) instead of dropping it silently. Strangers still see no difference.
