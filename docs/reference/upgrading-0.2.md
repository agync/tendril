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
