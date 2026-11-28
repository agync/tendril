"""Partial stub of the package; names without a stub fall back to `Any`."""

from typing import Any, TypedDict

class P2pTransportConfig(TypedDict, total=False):
    """The P2P socket keys of the JSON given to `Endpoint.configure_transports_json`.

    `p2p_port_mapping` defaults to `True` on desktop/server listeners, `False` on iOS/Android
    listeners, and `False` on all dialers; `False` keeps a P2P endpoint from probing the router
    for a UPnP, NAT-PMP or PCP mapping. `p2p_ephemeral` set to `True` uses an ephemeral node key
    and disables `n0` Pkarr/DNS publishing on Day-1 `serve_p2p` unless `p2p_pkarr` is also
    `True`. `p2p_bind_addrs` lists at most one IPv4 and one IPv6 socket address (`"0.0.0.0:0"`,
    `"[::]:0"`) for the QUIC UDP sockets; the default is every interface. An invalid entry raises
    `ValueError` naming `p2p_bind_addrs`. `p2p_relay_mode` accepts `"n0"` as an alias of
    `"default"`.
    """

    p2p_relay_mode: str
    p2p_port_mapping: bool
    p2p_ephemeral: bool
    p2p_bind_addrs: list[str]

class RefusedError(RuntimeError):
    """A host that knows this device refused the session over an authenticated channel.

    Raised by a refused Wire v2 `connect_v2` (or `connect_with_options` with `wire` 2), and by
    `send_data`, `rekey` and `close` on a session the host ended with a refusal. A Wire v1 connect
    returns before the refusal arrives and never raises it: the session then reports a `closed`
    event whose `refusal` field is set, and the next `send_data`, `rekey` or `close` raises this
    error. `poll_event` never raises it.

    `reason` is `"revoked"` (close code 4001: the host blocks this device key for good, so
    re-pairing needs a new device identity; offer to forget the host), `"pending"` (4004: the host
    has not confirmed this device yet; retry with backoff) or `"other"` (4400 to 4499).
    `close_code` is the wire close code and `code` the stable machine code (`"refused_revoked"`,
    `"refused_pending"` or `"refused"`).

    A host sends at most one notice per peer in a short window, so a rapid retry can fail with a
    plain `RuntimeError` instead.
    """

    reason: str
    close_code: int
    code: str

def verify_route_set(payload: bytes, signing_pub: bytes) -> str:
    """Decodes a `0x0C ROUTE_SET` payload and verifies its hybrid signature.

    Returns JSON `{"seq", "issued_at", "routes"}` only when the structure and the signature
    against the 1984-byte `signing_pub` are both valid. Raises `ValueError` with the message
    `signing key invalid`, `route set decode failed` or `route set signature invalid`.
    There is no unverified decode.
    """

def verify_wake_tag(wake_secret: bytes, wake_tag_b64: str, now_unix_secs: int) -> bool:
    """Verifies an epoch-blinded wake tag over the +-1 hour window against a 32-byte secret."""

def __getattr__(name: str) -> Any: ...
