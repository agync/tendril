//! Typed error taxonomy for `tendril-core`.

use thiserror::Error;

/// Errors emitted by `tendril-core` protocol, cryptographic, and grant checks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid preamble length: expected {expected}, got {actual}")]
    InvalidPreambleLength { expected: usize, actual: usize },

    #[error("invalid preamble magic")]
    BadPreambleMagic,

    #[error("unsupported wire version: {0}")]
    UnsupportedVersion(u8),

    #[error("unknown preamble intent: 0x{0:02x}")]
    UnknownIntent(u8),

    #[error("non-zero reserved preamble byte: 0x{0:02x}")]
    NonZeroReserved(u8),

    #[error("frame length {len} exceeds maximum {max}")]
    FrameTooLarge { len: usize, max: usize },

    #[error("truncated frame: expected {expected} bytes, got {actual}")]
    TruncatedFrame { expected: usize, actual: usize },

    #[error("empty inner transport frame")]
    EmptyInnerFrame,

    #[error("unknown inner transport frame type: 0x{0:02x}")]
    UnknownInnerFrameType(u8),

    #[error("invalid inner transport frame payload: {0}")]
    InvalidInnerFramePayload(&'static str),

    #[error("invalid key or buffer length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("invalid base64url encoding: {0}")]
    Base64Decode(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("argon2 derivation failed: {0}")]
    Argon2(String),

    #[error("noise protocol error: {0}")]
    Noise(String),

    #[error("invalid RFC 3339 UTC timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("host key changed with empty rotation chain")]
    RotationEmptyChain,

    #[error("rotation chain does not extend pinned signing key")]
    RotationRootMismatch,

    #[error(
        "rotation chain sequence must increase strictly: expected >= {expected_min}, got {got}"
    )]
    RotationNonMonotonicSeq { expected_min: u64, got: u64 },

    #[error("rotation chain is not contiguous")]
    RotationNonContiguous,

    #[error("rotation fork detected at sequence {seq}")]
    RotationForkDetected { seq: u64 },

    #[error("rotation chain does not reach presented host keys")]
    RotationEndpointMismatch,

    #[error("host key could not be verified against pin or rotation chain")]
    HostKeyUnverified,

    #[error("invalid capability syntax: {0}")]
    InvalidCapability(String),

    #[error("canonical JSON error: {0}")]
    CanonicalJson(String),

    #[error("grant check failed: {0}")]
    GrantDenied(String),

    #[error("delegation check failed: {0}")]
    DelegationDenied(String),
}
