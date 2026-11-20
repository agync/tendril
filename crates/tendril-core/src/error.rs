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

    #[error("random generator error: {0}")]
    Rng(String),

    #[error("JSON serialization error: {0}")]
    Json(String),

    #[error("protocol violation: {0}")]
    ProtocolViolation(&'static str),

    #[error("peer not found in roster: {0}")]
    PeerNotFound(String),

    #[error("peer is still pending confirmation: {0}")]
    PeerPending(String),

    #[error("peer is revoked: {0}")]
    PeerRevoked(String),

    #[error("incomplete peer pin in roster: {0}")]
    IncompletePin(String),

    #[error("pairing code invalid")]
    PairingCodeInvalid,

    #[error("pairing code expired")]
    PairingCodeExpired,

    #[error("pairing code burned after maximum failed attempts")]
    PairingCodeBurned,

    #[error("pairing path disallowed: {0}")]
    PairingPathDisallowed(&'static str),

    #[error("invalid pairing URI: {0}")]
    InvalidPairingUri(String),

    #[error("unsupported CRL version: {0}")]
    CrlUnsupportedVersion(u8),

    #[error("CRL issuer mismatch: expected {expected}, got {got}")]
    CrlIssuerMismatch { expected: String, got: String },

    #[error("stale or conflicting CRL sequence: current {current}, got {got}")]
    CrlStaleSeq { current: u64, got: u64 },

    #[error("session closed (code {code}): {reason}")]
    SessionClosed { code: u16, reason: String },

    #[error("state machine not ready: {0}")]
    NotReady(&'static str),

    #[error("read buffer limit exceeded: {len} > {max}")]
    BufferOverflow { len: usize, max: usize },
}

impl CoreError {
    /// Maps an error from a pairing claim into its bounded wire `PairResponse::Error` code.
    #[must_use]
    pub const fn pair_error_code(&self) -> &'static str {
        match self {
            Self::PairingCodeExpired => "code_expired",
            Self::PairingCodeBurned => "code_burned",
            Self::PeerRevoked(_) => "revoked",
            Self::PairingPathDisallowed(_) => "path_disallowed",
            Self::ProtocolViolation(_)
            | Self::BadPreambleMagic
            | Self::UnsupportedVersion(_)
            | Self::UnknownIntent(_)
            | Self::NonZeroReserved(_)
            | Self::InvalidPreambleLength { .. }
            | Self::FrameTooLarge { .. }
            | Self::TruncatedFrame { .. }
            | Self::EmptyInnerFrame
            | Self::UnknownInnerFrameType(_)
            | Self::InvalidInnerFramePayload(_)
            | Self::Json(_)
            | Self::BufferOverflow { .. } => "protocol_error",
            _ => "unauthorized",
        }
    }
}
