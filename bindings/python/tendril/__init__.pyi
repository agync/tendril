"""Partial stub of the package; names without a stub fall back to `Any`."""

from typing import Any

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
