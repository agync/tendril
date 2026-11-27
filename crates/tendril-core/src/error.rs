//! Typed error taxonomy for `tendril-core`.

use std::fmt;

use thiserror::Error;

use crate::session::SessionCloseCode;

/// Why a responder refused to admit an authenticated, known initiator.
///
/// Mirrors the refusal rows of the close-code registry (`spec/wire-v1.md` Section 5.4.1).
/// `Other` carries an admission-refusal code in `4400..=4499`; build it with
/// [`AdmissionRefusalCode::new`], which rejects values outside that range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    /// The host revoked this peer (close code `4001`).
    Revoked,
    /// The host has not yet confirmed this peer (close code `4004`).
    Pending,
    /// A reserved admission refusal (close codes `4400..=4499`).
    Other(AdmissionRefusalCode),
}

/// A close code in the reserved admission-refusal range `4400..=4499`.
///
/// The range is checked at construction, so a [`RefusalReason`] can never carry a code that
/// would contradict the registry in `spec/wire-v1.md` Section 5.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdmissionRefusalCode(u16);

impl AdmissionRefusalCode {
    /// Returns the code when it lies in `4400..=4499`, else `None`.
    #[must_use]
    pub const fn new(code: u16) -> Option<Self> {
        match code {
            4400..=4499 => Some(Self(code)),
            _ => None,
        }
    }

    /// Returns the wire close code.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl RefusalReason {
    /// Maps a received `0x07 CLOSE` code to a refusal reason.
    ///
    /// Returns `None` for every non-refusal code, including `4002 grant_expired` and
    /// `4003 key_unverified`. Only an initiator may apply this mapping.
    #[must_use]
    pub const fn from_close_code(code: u16) -> Option<Self> {
        match code {
            SessionCloseCode::PEER_REVOKED => Some(Self::Revoked),
            SessionCloseCode::PEER_PENDING => Some(Self::Pending),
            _ => match AdmissionRefusalCode::new(code) {
                Some(other) => Some(Self::Other(other)),
                None => None,
            },
        }
    }

    /// Returns the wire close code of this reason.
    #[must_use]
    pub const fn close_code(self) -> u16 {
        match self {
            Self::Revoked => SessionCloseCode::PEER_REVOKED,
            Self::Pending => SessionCloseCode::PEER_PENDING,
            Self::Other(code) => code.get(),
        }
    }

    /// Returns the stable machine code for errors carrying this reason.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Revoked => "refused_revoked",
            Self::Pending => "refused_pending",
            Self::Other(_) => "refused",
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked => f.write_str("revoked"),
            Self::Pending => f.write_str("pending"),
            Self::Other(code) => write!(f, "refused (code {})", code.get()),
        }
    }
}

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

    #[error("invalid preamble flags 0x{flags:02x} for intent 0x{intent:02x}")]
    InvalidPreambleFlags { intent: u8, flags: u8 },

    #[error(
        "wire version downgrade rejected: peer requires >= v{peer_min}, negotiated v{negotiated}"
    )]
    VersionDowngrade { peer_min: u8, negotiated: u8 },

    #[error("PAKE pairing authentication failed")]
    PairingAuthFailed,

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

    /// An initiator learned, through an authenticated refusal, that the host knows it but
    /// will not admit it (`spec/wire-v1.md` Section 5.4).
    #[error("peer refused the session: {reason}")]
    PeerRefused { reason: RefusalReason },

    #[error("enrollment token invalid: {0}")]
    EnrollmentTokenInvalid(String),

    #[error("enrollment token expired")]
    EnrollmentTokenExpired,

    #[error("enrollment token already used")]
    EnrollmentTokenReplayed,

    #[error("enrollment anchor untrusted: {0}")]
    EnrollmentAnchorUntrusted(String),

    #[error("enrollment burn log capacity exceeded")]
    EnrollmentBurnLogFull,

    #[error("state machine not ready: {0}")]
    NotReady(&'static str),

    #[error("read buffer limit exceeded: {len} > {max}")]
    BufferOverflow { len: usize, max: usize },

    #[error("invalid group manifest: {0}")]
    InvalidGroupManifest(String),

    #[error("group capability outside group scope: {0}")]
    InvalidGroupCapabilityScope(String),

    #[error("group manifest sequence rollback: current {current}, got {got}")]
    GroupSeqRollback { current: u64, got: u64 },

    #[error("group manifest fork detected at sequence {seq}")]
    GroupManifestFork { seq: u64 },

    #[error("group member is revoked: {0}")]
    GroupMemberRevoked(String),

    #[error("group not found: {0}")]
    GroupNotFound(String),

    #[error("group authorization denied: {0}")]
    GroupUnauthorized(String),

    #[error("group manifest too large: {len} > {max}")]
    GroupManifestTooLarge { len: usize, max: usize },

    #[error("group wire version downgrade rejected: stored floor v{current}, got v{got}")]
    GroupWireDowngrade { current: u8, got: u8 },
}

impl CoreError {
    /// Returns the stable machine code of this error: the snake-case variant name.
    ///
    /// Bindings expose this string so callers branch on it, never on message text. The match
    /// is exhaustive, so a new variant cannot ship without a code. [`CoreError::PeerRefused`]
    /// maps to `refused_revoked`, `refused_pending` or `refused` by its reason.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidPreambleLength { .. } => "invalid_preamble_length",
            Self::BadPreambleMagic => "bad_preamble_magic",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::UnknownIntent(_) => "unknown_intent",
            Self::NonZeroReserved(_) => "non_zero_reserved",
            Self::InvalidPreambleFlags { .. } => "invalid_preamble_flags",
            Self::VersionDowngrade { .. } => "version_downgrade",
            Self::PairingAuthFailed => "pairing_auth_failed",
            Self::FrameTooLarge { .. } => "frame_too_large",
            Self::TruncatedFrame { .. } => "truncated_frame",
            Self::EmptyInnerFrame => "empty_inner_frame",
            Self::UnknownInnerFrameType(_) => "unknown_inner_frame_type",
            Self::InvalidInnerFramePayload(_) => "invalid_inner_frame_payload",
            Self::InvalidLength { .. } => "invalid_length",
            Self::Base64Decode(_) => "base64_decode",
            Self::InvalidSignature => "invalid_signature",
            Self::Argon2(_) => "argon2",
            Self::Noise(_) => "noise",
            Self::InvalidTimestamp(_) => "invalid_timestamp",
            Self::RotationEmptyChain => "rotation_empty_chain",
            Self::RotationRootMismatch => "rotation_root_mismatch",
            Self::RotationNonMonotonicSeq { .. } => "rotation_non_monotonic_seq",
            Self::RotationNonContiguous => "rotation_non_contiguous",
            Self::RotationForkDetected { .. } => "rotation_fork_detected",
            Self::RotationEndpointMismatch => "rotation_endpoint_mismatch",
            Self::HostKeyUnverified => "host_key_unverified",
            Self::InvalidCapability(_) => "invalid_capability",
            Self::CanonicalJson(_) => "canonical_json",
            Self::GrantDenied(_) => "grant_denied",
            Self::DelegationDenied(_) => "delegation_denied",
            Self::Rng(_) => "rng",
            Self::Json(_) => "json",
            Self::ProtocolViolation(_) => "protocol_violation",
            Self::PeerNotFound(_) => "peer_not_found",
            Self::PeerPending(_) => "peer_pending",
            Self::PeerRevoked(_) => "peer_revoked",
            Self::IncompletePin(_) => "incomplete_pin",
            Self::PairingCodeInvalid => "pairing_code_invalid",
            Self::PairingCodeExpired => "pairing_code_expired",
            Self::PairingCodeBurned => "pairing_code_burned",
            Self::PairingPathDisallowed(_) => "pairing_path_disallowed",
            Self::InvalidPairingUri(_) => "invalid_pairing_uri",
            Self::CrlUnsupportedVersion(_) => "crl_unsupported_version",
            Self::CrlIssuerMismatch { .. } => "crl_issuer_mismatch",
            Self::CrlStaleSeq { .. } => "crl_stale_seq",
            Self::SessionClosed { .. } => "session_closed",
            Self::PeerRefused { reason } => reason.code(),
            Self::EnrollmentTokenInvalid(_) => "enrollment_token_invalid",
            Self::EnrollmentTokenExpired => "enrollment_token_expired",
            Self::EnrollmentTokenReplayed => "enrollment_token_replayed",
            Self::EnrollmentAnchorUntrusted(_) => "enrollment_anchor_untrusted",
            Self::EnrollmentBurnLogFull => "enrollment_burn_log_full",
            Self::NotReady(_) => "not_ready",
            Self::BufferOverflow { .. } => "buffer_overflow",
            Self::InvalidGroupManifest(_) => "invalid_group_manifest",
            Self::InvalidGroupCapabilityScope(_) => "invalid_group_capability_scope",
            Self::GroupSeqRollback { .. } => "group_seq_rollback",
            Self::GroupManifestFork { .. } => "group_manifest_fork",
            Self::GroupMemberRevoked(_) => "group_member_revoked",
            Self::GroupNotFound(_) => "group_not_found",
            Self::GroupUnauthorized(_) => "group_unauthorized",
            Self::GroupManifestTooLarge { .. } => "group_manifest_too_large",
            Self::GroupWireDowngrade { .. } => "group_wire_downgrade",
        }
    }

    /// Maps an error from a pairing claim into its bounded wire `PairResponse::Error` code.
    #[must_use]
    pub const fn pair_error_code(&self) -> &'static str {
        match self {
            Self::PairingCodeExpired => "code_expired",
            Self::PairingCodeBurned => "code_burned",
            Self::EnrollmentTokenExpired => "token_expired",
            Self::EnrollmentTokenReplayed => "token_replayed",
            Self::EnrollmentAnchorUntrusted(_) => "untrusted_anchor",
            Self::EnrollmentBurnLogFull => "rate_limited",
            Self::PeerRevoked(_) => "revoked",
            Self::PairingPathDisallowed(_) => "path_disallowed",
            Self::ProtocolViolation(_)
            | Self::BadPreambleMagic
            | Self::UnsupportedVersion(_)
            | Self::UnknownIntent(_)
            | Self::NonZeroReserved(_)
            | Self::InvalidPreambleFlags { .. }
            | Self::VersionDowngrade { .. }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionCloseCode;

    #[test]
    fn refusal_reason_maps_registry_codes() {
        assert_eq!(
            RefusalReason::from_close_code(4001),
            Some(RefusalReason::Revoked)
        );
        assert_eq!(
            RefusalReason::from_close_code(4004),
            Some(RefusalReason::Pending)
        );
        assert_eq!(
            RefusalReason::from_close_code(4400),
            Some(RefusalReason::Other(
                AdmissionRefusalCode::new(4400).unwrap()
            ))
        );
        assert_eq!(
            RefusalReason::from_close_code(4450),
            Some(RefusalReason::Other(
                AdmissionRefusalCode::new(4450).unwrap()
            ))
        );
        assert_eq!(
            RefusalReason::from_close_code(4499),
            Some(RefusalReason::Other(
                AdmissionRefusalCode::new(4499).unwrap()
            ))
        );
    }

    #[test]
    fn refusal_reason_rejects_non_refusal_codes() {
        for code in [
            0,
            1000,
            1002,
            1008,
            1011,
            4000,
            4002,
            4003,
            4005,
            4399,
            4500,
            u16::MAX,
        ] {
            assert_eq!(RefusalReason::from_close_code(code), None, "code {code}");
        }
        assert_eq!(
            RefusalReason::from_close_code(SessionCloseCode::GRANT_EXPIRED),
            None
        );
        assert_eq!(
            RefusalReason::from_close_code(SessionCloseCode::KEY_UNVERIFIED),
            None
        );
    }

    #[test]
    fn refusal_reason_round_trips_through_close_code() {
        for code in [4001u16, 4004, 4400, 4450, 4499] {
            let reason = RefusalReason::from_close_code(code).unwrap();
            assert_eq!(reason.close_code(), code);
        }
    }

    #[test]
    fn peer_refused_codes_are_stable() {
        let code = |reason| CoreError::PeerRefused { reason }.code();
        assert_eq!(code(RefusalReason::Revoked), "refused_revoked");
        assert_eq!(code(RefusalReason::Pending), "refused_pending");
        assert_eq!(
            code(RefusalReason::Other(
                AdmissionRefusalCode::new(4401).unwrap()
            )),
            "refused"
        );
    }

    #[test]
    fn peer_refused_displays_reason() {
        let err = CoreError::PeerRefused {
            reason: RefusalReason::Revoked,
        };
        assert_eq!(err.to_string(), "peer refused the session: revoked");
    }

    #[test]
    fn admission_refusal_code_accepts_only_the_reserved_range() {
        assert_eq!(
            AdmissionRefusalCode::new(4400).map(AdmissionRefusalCode::get),
            Some(4400)
        );
        assert_eq!(
            AdmissionRefusalCode::new(4499).map(AdmissionRefusalCode::get),
            Some(4499)
        );
        for code in [0, 1000, 4001, 4002, 4004, 4399, 4500, u16::MAX] {
            assert_eq!(AdmissionRefusalCode::new(code), None, "code {code}");
        }
    }

    #[test]
    fn existing_codes_keep_their_strings() {
        assert_eq!(CoreError::BadPreambleMagic.code(), "bad_preamble_magic");
        assert_eq!(CoreError::HostKeyUnverified.code(), "host_key_unverified");
        assert_eq!(
            CoreError::SessionClosed {
                code: 1000,
                reason: String::new()
            }
            .code(),
            "session_closed"
        );
        assert_eq!(CoreError::PeerRevoked(String::new()).code(), "peer_revoked");
        assert_eq!(CoreError::PeerPending(String::new()).code(), "peer_pending");
        assert_eq!(CoreError::Argon2(String::new()).code(), "argon2");
    }

    /// The stable code strings are a binding contract: bindings branch on them.
    #[test]
    fn stable_code_table_is_pinned() {
        let table: Vec<(CoreError, &str)> = vec![
            (
                CoreError::InvalidPreambleLength {
                    expected: 0,
                    actual: 0,
                },
                "invalid_preamble_length",
            ),
            (CoreError::BadPreambleMagic, "bad_preamble_magic"),
            (CoreError::UnsupportedVersion(0), "unsupported_version"),
            (CoreError::UnknownIntent(0), "unknown_intent"),
            (CoreError::NonZeroReserved(0), "non_zero_reserved"),
            (
                CoreError::InvalidPreambleFlags {
                    intent: 0,
                    flags: 0,
                },
                "invalid_preamble_flags",
            ),
            (
                CoreError::VersionDowngrade {
                    peer_min: 0,
                    negotiated: 0,
                },
                "version_downgrade",
            ),
            (CoreError::PairingAuthFailed, "pairing_auth_failed"),
            (
                CoreError::FrameTooLarge { len: 0, max: 0 },
                "frame_too_large",
            ),
            (
                CoreError::TruncatedFrame {
                    expected: 0,
                    actual: 0,
                },
                "truncated_frame",
            ),
            (CoreError::EmptyInnerFrame, "empty_inner_frame"),
            (
                CoreError::UnknownInnerFrameType(0),
                "unknown_inner_frame_type",
            ),
            (
                CoreError::InvalidInnerFramePayload(""),
                "invalid_inner_frame_payload",
            ),
            (
                CoreError::InvalidLength {
                    expected: 0,
                    actual: 0,
                },
                "invalid_length",
            ),
            (CoreError::Base64Decode(String::new()), "base64_decode"),
            (CoreError::InvalidSignature, "invalid_signature"),
            (CoreError::Argon2(String::new()), "argon2"),
            (CoreError::Noise(String::new()), "noise"),
            (
                CoreError::InvalidTimestamp(String::new()),
                "invalid_timestamp",
            ),
            (CoreError::RotationEmptyChain, "rotation_empty_chain"),
            (CoreError::RotationRootMismatch, "rotation_root_mismatch"),
            (
                CoreError::RotationNonMonotonicSeq {
                    expected_min: 0,
                    got: 0,
                },
                "rotation_non_monotonic_seq",
            ),
            (CoreError::RotationNonContiguous, "rotation_non_contiguous"),
            (
                CoreError::RotationForkDetected { seq: 0 },
                "rotation_fork_detected",
            ),
            (
                CoreError::RotationEndpointMismatch,
                "rotation_endpoint_mismatch",
            ),
            (CoreError::HostKeyUnverified, "host_key_unverified"),
            (
                CoreError::InvalidCapability(String::new()),
                "invalid_capability",
            ),
            (CoreError::CanonicalJson(String::new()), "canonical_json"),
            (CoreError::GrantDenied(String::new()), "grant_denied"),
            (
                CoreError::DelegationDenied(String::new()),
                "delegation_denied",
            ),
            (CoreError::Rng(String::new()), "rng"),
            (CoreError::Json(String::new()), "json"),
            (CoreError::ProtocolViolation(""), "protocol_violation"),
            (CoreError::PeerNotFound(String::new()), "peer_not_found"),
            (CoreError::PeerPending(String::new()), "peer_pending"),
            (CoreError::PeerRevoked(String::new()), "peer_revoked"),
            (CoreError::IncompletePin(String::new()), "incomplete_pin"),
            (CoreError::PairingCodeInvalid, "pairing_code_invalid"),
            (CoreError::PairingCodeExpired, "pairing_code_expired"),
            (CoreError::PairingCodeBurned, "pairing_code_burned"),
            (
                CoreError::PairingPathDisallowed(""),
                "pairing_path_disallowed",
            ),
            (
                CoreError::InvalidPairingUri(String::new()),
                "invalid_pairing_uri",
            ),
            (
                CoreError::CrlUnsupportedVersion(0),
                "crl_unsupported_version",
            ),
            (
                CoreError::CrlIssuerMismatch {
                    expected: String::new(),
                    got: String::new(),
                },
                "crl_issuer_mismatch",
            ),
            (
                CoreError::CrlStaleSeq { current: 0, got: 0 },
                "crl_stale_seq",
            ),
            (
                CoreError::SessionClosed {
                    code: 0,
                    reason: String::new(),
                },
                "session_closed",
            ),
            (
                CoreError::PeerRefused {
                    reason: RefusalReason::Revoked,
                },
                "refused_revoked",
            ),
            (
                CoreError::PeerRefused {
                    reason: RefusalReason::Pending,
                },
                "refused_pending",
            ),
            (
                CoreError::PeerRefused {
                    reason: RefusalReason::Other(AdmissionRefusalCode::new(4401).unwrap()),
                },
                "refused",
            ),
            (
                CoreError::EnrollmentTokenInvalid(String::new()),
                "enrollment_token_invalid",
            ),
            (
                CoreError::EnrollmentTokenExpired,
                "enrollment_token_expired",
            ),
            (
                CoreError::EnrollmentTokenReplayed,
                "enrollment_token_replayed",
            ),
            (
                CoreError::EnrollmentAnchorUntrusted(String::new()),
                "enrollment_anchor_untrusted",
            ),
            (CoreError::EnrollmentBurnLogFull, "enrollment_burn_log_full"),
            (CoreError::NotReady(""), "not_ready"),
            (
                CoreError::BufferOverflow { len: 0, max: 0 },
                "buffer_overflow",
            ),
            (
                CoreError::InvalidGroupManifest(String::new()),
                "invalid_group_manifest",
            ),
            (
                CoreError::InvalidGroupCapabilityScope(String::new()),
                "invalid_group_capability_scope",
            ),
            (
                CoreError::GroupSeqRollback { current: 0, got: 0 },
                "group_seq_rollback",
            ),
            (
                CoreError::GroupManifestFork { seq: 0 },
                "group_manifest_fork",
            ),
            (
                CoreError::GroupMemberRevoked(String::new()),
                "group_member_revoked",
            ),
            (CoreError::GroupNotFound(String::new()), "group_not_found"),
            (
                CoreError::GroupUnauthorized(String::new()),
                "group_unauthorized",
            ),
            (
                CoreError::GroupManifestTooLarge { len: 0, max: 0 },
                "group_manifest_too_large",
            ),
            (
                CoreError::GroupWireDowngrade { current: 0, got: 0 },
                "group_wire_downgrade",
            ),
        ];
        assert_eq!(table.len(), 65);
        for (err, expected) in &table {
            assert_eq!(err.code(), *expected, "{err:?}");
        }
        let mut codes: Vec<&str> = table.iter().map(|(_, c)| *c).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), table.len(), "codes are unique");
    }
}
