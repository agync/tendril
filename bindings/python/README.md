# tendril-sdk

Python (`import tendril`) PyO3 ABI3 bindings over `tendril-core` and `tendril-runtime` for private, end-to-end encrypted device-to-device links.

## Installation

Prebuilt `abi3` wheels for Python >= 3.9 are published on PyPI for Linux `x86_64`, Linux `arm64`, and macOS `arm64`:

```bash
uv add tendril-sdk
# or
pip install tendril-sdk
```

## Example

```python
import json
import tendril

host = tendril.Endpoint("./laptop-state", "laptop")
addr = host.serve_direct("127.0.0.1:0")
code = host.issue_code("lan")

req = json.loads(host.pair_accept(5000))
host.confirm_peer(req["device_id"], req["sas"])  # after comparing the check string
grant = host.mint_grant(req["device_id"], ["notes.sync"], ttl_secs=3600)

session = host.accept_session(5000)
assert session.authorize("notes.sync")
```

## Refusals

A host that knows this device and refuses it says so, instead of timing out. A refused `connect_v2` raises `tendril.RefusedError`, a `RuntimeError` with `reason` (`"revoked"`, `"pending"` or `"other"`), `close_code` and `code` (`refused_revoked`, `refused_pending`, `refused`):

```python
try:
    session = client.connect_v2(addr, "laptop", grant)
except tendril.RefusedError as err:
    if err.reason == "revoked":
        ...  # the host blocks this device key for good: re-pairing needs a new device identity
    elif err.reason == "pending":
        ...  # the host has not confirmed this device yet: retry with backoff
```

A Wire v1 connect returns before the refusal arrives. Its `poll_event` then reports a `closed` event with `"refusal": "revoked"`, and the next `send_data`, `rekey` or `close` raises the same error. A host sends at most one notice per peer in a short window, so a rapid retry can fail with a plain `RuntimeError`.

On the host, `revoke_peer(peer_id)` records a notice per the refusal policy and `revoke_peer(peer_id, notify=False)` revokes silently. `set_refusal_policy(pending=True, revoked_notice_ttl_secs=2592000)` sets the policy (a TTL of `0` records no notice) and `clear_refusal_notice(peer_id)` drops a notice while the peer stays revoked.

## P2P sockets

A P2P endpoint probes the local router for a port mapping and binds its QUIC UDP sockets on every interface. Turn the probe off or pin the bind addresses in the transport configuration:

```python
host.configure_transports_json('{"p2p_port_mapping": false, "p2p_bind_addrs": ["0.0.0.0:0"]}')
```

The sockets a P2P endpoint opens, and which option controls each, are listed in [Sockets a P2P endpoint opens](https://github.com/agync/tendril/blob/main/docs/design/providers-and-relay-ladder.md#sockets-a-p2p-endpoint-opens).

## Links

- Documentation: https://tendril.agync.dev
- Repository: https://github.com/agync/tendril
- License: Apache-2.0
