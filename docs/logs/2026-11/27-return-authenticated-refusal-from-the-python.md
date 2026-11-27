---
type: Log Entry
title: "Return authenticated refusal from the Python, Node and Web bindings"
description: "Python raises RefusedError, Node rejects with a refused code and closeCode, the browser ranks refused codes, and closed events carry refusal."
tags: [log, update]
kind: Update
status: stable
---

Return authenticated refusal from `bindings/python`, `bindings/node`, `bindings/web` and `crates/tendril-wasm`. A refused Wire v2 connect, and a send, rekey or close on a session the host ended with a refusal, raises `tendril.RefusedError` in Python (a `RuntimeError` with `reason`, `close_code` and `code`) and rejects with an `Error` carrying `code` (`refused_revoked`, `refused_pending` or `refused`) and `closeCode` in Node. The browser reports the same codes on `TendrilAttemptError` and ranks them between `peer_revoked` and `version_downgrade`. The `closed` event of a session the endpoint dialed carries `refusal` in all three, so a Wire v1 refusal that arrives after connect is visible.

Python and Node `revoke_peer` and `revokePeer` now record a refusal notice per the endpoint policy, with `notify=False` for a silent revoke, and gain `set_refusal_policy`, `clear_refusal_notice` and their camelCase twins. Node's `index.js` moves the code and close code from a private message tag onto the error, because an async N-API method can reject only with a status code.
