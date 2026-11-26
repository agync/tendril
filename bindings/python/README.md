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
