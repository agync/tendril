"""Partial stub of the package; names without a stub fall back to `Any`."""

from typing import Any, TypedDict

class P2pTransportConfig(TypedDict, total=False):
    """The P2P socket keys of the JSON given to `Endpoint.configure_transports_json`.

    `p2p_port_mapping` is `True` by default; `False` keeps a P2P endpoint from probing the router
    for a UPnP, NAT-PMP or PCP mapping. `p2p_bind_addrs` lists at most one IPv4 and one IPv6
    socket address (`"0.0.0.0:0"`, `"[::]:0"`) for the QUIC UDP sockets; the default is every
    interface. An invalid entry raises `ValueError` naming `p2p_bind_addrs`. `p2p_relay_mode`
    accepts `"n0"` as an alias of `"default"`.
    """

    p2p_relay_mode: str
    p2p_port_mapping: bool
    p2p_bind_addrs: list[str]

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
