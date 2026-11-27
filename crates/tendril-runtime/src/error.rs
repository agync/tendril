//! Typed error definitions for the Tendril async runtime and path providers.

use tendril_core::RefusalReason;
use tendril_core::error::CoreError;
use thiserror::Error;

use crate::providers::egress::SkipReason;

/// Errors returned by `tendril-runtime` transports, persistence, and session drivers.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("core protocol error: {0}")]
    Core(#[from] CoreError),

    #[error("transport i/o failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("operation timed out: {0}")]
    Timeout(&'static str),

    #[error("frame size {size} exceeds ceiling {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("pre-authentication rate limit exceeded: {0}")]
    RateLimited(&'static str),

    #[error("capacity exceeded: {0}")]
    CapacityExceeded(&'static str),

    #[error("transport stream closed")]
    Closed,

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("path policy failed: {0}")]
    Policy(&'static str),

    #[error("storage error: {0}")]
    Storage(String),

    /// The dial-time egress check refused the destination before any connect: a lookup that
    /// failed, timed out or returned nothing (`unresolved`), or an answer in the blocked set.
    #[error("egress refused ({reason}): {detail}")]
    Egress { reason: SkipReason, detail: String },

    /// The peer closed an initiator-role session (`0x07 CLOSE`). Only an initiator maps a
    /// refusal close code to [`RuntimeError::refusal`]; a responder that receives the same code
    /// keeps a plain [`CoreError::SessionClosed`] (`spec/wire-v1.md` Section 5.4). The text is
    /// that of `Core(SessionClosed)`.
    #[error("core protocol error: session closed (code {code}): {reason}")]
    InitiatorClosed { code: u16, reason: String },

    /// A relay answered `offline`: the dialed host holds no registration there now. The display
    /// text is [`RelayOffline::message`], unchanged from the untyped error it replaces.
    #[error("{}", .0.message())]
    RelayOffline(RelayOffline),
}

/// Which relay refusal a [`RuntimeError::RelayOffline`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOffline {
    /// A `/v1/relay` dial answered `offline`.
    V1Dial,
    /// A `/v2/relay` dial answered `offline`.
    V2Dial,
    /// Every candidate of a Day-2 connect to a relay-only peer answered `offline` for the
    /// pinned key, and no recovery URI was given.
    PinnedKey,
}

impl RelayOffline {
    /// The stable error text.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::V1Dial => "relay dial rejected: offline",
            Self::V2Dial => "v2 relay dial rejected: offline",
            Self::PinnedKey => {
                "relay mailbox offline for pinned key; host may have rotated: reconnect over \
                 another route or supply a fresh pairing URI"
            }
        }
    }
}

impl RuntimeError {
    /// Wraps an error of an initiator-role session: a [`CoreError::SessionClosed`] becomes
    /// [`RuntimeError::InitiatorClosed`] so [`Self::refusal`] can classify its close code, and
    /// every other error becomes [`RuntimeError::Core`].
    ///
    /// Call it only where the session is known to be an initiator. A responder must keep the
    /// plain [`CoreError::SessionClosed`]. Nothing calls it outside tests until the initiator
    /// drivers adopt it.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_initiator_core(err: CoreError) -> Self {
        match err {
            CoreError::SessionClosed { code, reason } => Self::InitiatorClosed { code, reason },
            other => Self::Core(other),
        }
    }

    /// The stable machine code of this error.
    ///
    /// A refusal reports its [`RefusalReason::code`] (`refused_revoked`, `refused_pending` or
    /// `refused`), a [`RuntimeError::Core`] its [`CoreError::code`], and an initiator close that
    /// is not a refusal `session_closed`. The other variants report a fixed lowercase name.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        if let Some(reason) = self.refusal() {
            return reason.code();
        }
        match self {
            Self::Core(err) => err.code(),
            Self::InitiatorClosed { .. } => "session_closed",
            Self::Io(_) => "io",
            Self::Timeout(_) => "timeout",
            Self::FrameTooLarge { .. } => "frame_too_large",
            Self::RateLimited(_) => "rate_limited",
            Self::CapacityExceeded(_) => "capacity_exceeded",
            Self::Closed => "closed",
            Self::Protocol(_) => "protocol",
            Self::Policy(_) => "policy",
            Self::Storage(_) => "storage",
            Self::Egress { .. } => "egress",
            Self::RelayOffline(_) => "relay_offline",
        }
    }

    /// The reason of an authenticated refusal, `None` for every other error.
    ///
    /// A refusal is [`CoreError::PeerRefused`], or a peer close with a refusal code seen on an
    /// initiator-role session ([`RuntimeError::InitiatorClosed`]). The same close code on a
    /// responder, or on a plain [`CoreError::SessionClosed`], is not a refusal.
    #[must_use]
    pub const fn refusal(&self) -> Option<RefusalReason> {
        match self {
            Self::Core(CoreError::PeerRefused { reason }) => Some(*reason),
            Self::InitiatorClosed { code, .. } => RefusalReason::from_close_code(*code),
            _ => None,
        }
    }

    /// The hint-level skip reason of an [`RuntimeError::Egress`] refusal; `None` for every other
    /// error, including transport I/O after the check passed.
    #[must_use]
    pub const fn skip_reason(&self) -> Option<SkipReason> {
        match self {
            Self::Egress { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// `true` for a relay `offline` refusal ([`RuntimeError::RelayOffline`]).
    #[must_use]
    pub const fn is_relay_offline(&self) -> bool {
        matches!(self, Self::RelayOffline(_))
    }
}

#[cfg(test)]
mod tests {
    use tendril_core::session::SessionCloseCode;
    use tendril_core::{AdmissionRefusalCode, RefusalReason};

    use super::*;

    fn closed(code: u16) -> CoreError {
        CoreError::SessionClosed {
            code,
            reason: String::new(),
        }
    }

    #[test]
    fn peer_refused_is_a_refusal() {
        let err = RuntimeError::Core(CoreError::PeerRefused {
            reason: RefusalReason::Pending,
        });
        assert_eq!(err.refusal(), Some(RefusalReason::Pending));
    }

    #[test]
    fn initiator_close_with_a_refusal_code_is_a_refusal() {
        let other = AdmissionRefusalCode::new(4450).unwrap();
        for (code, reason) in [
            (SessionCloseCode::PEER_REVOKED, RefusalReason::Revoked),
            (SessionCloseCode::PEER_PENDING, RefusalReason::Pending),
            (4450, RefusalReason::Other(other)),
        ] {
            let err = RuntimeError::from_initiator_core(closed(code));
            assert_eq!(err.refusal(), Some(reason), "code {code}");
        }
    }

    #[test]
    fn initiator_close_with_another_code_is_not_a_refusal() {
        for code in [
            SessionCloseCode::NORMAL,
            SessionCloseCode::PROTOCOL_ERROR,
            SessionCloseCode::POLICY_VIOLATION,
            SessionCloseCode::GRANT_EXPIRED,
            SessionCloseCode::KEY_UNVERIFIED,
            4500,
        ] {
            let err = RuntimeError::from_initiator_core(closed(code));
            assert_eq!(err.refusal(), None, "code {code}");
        }
    }

    #[test]
    fn responder_keeps_a_received_refusal_code_as_a_plain_close() {
        for code in [
            SessionCloseCode::PEER_REVOKED,
            SessionCloseCode::PEER_PENDING,
        ] {
            let err = RuntimeError::Core(closed(code));
            assert_eq!(err.refusal(), None, "code {code}");
            assert!(matches!(
                err,
                RuntimeError::Core(CoreError::SessionClosed { code: c, .. }) if c == code
            ));
        }
    }

    #[test]
    fn initiator_wrapper_keeps_the_close_text_and_other_errors() {
        let plain = closed(SessionCloseCode::PEER_REVOKED);
        let wrapped = RuntimeError::from_initiator_core(plain.clone());
        assert_eq!(wrapped.to_string(), RuntimeError::Core(plain).to_string());
        let other = RuntimeError::from_initiator_core(CoreError::BadPreambleMagic);
        assert!(matches!(
            other,
            RuntimeError::Core(CoreError::BadPreambleMagic)
        ));
        assert_eq!(other.refusal(), None);
    }

    #[test]
    fn unrelated_errors_are_not_refusals() {
        assert_eq!(RuntimeError::Closed.refusal(), None);
        assert_eq!(
            RuntimeError::Core(CoreError::PeerRevoked("p".into())).refusal(),
            None
        );
    }

    #[test]
    fn code_reports_refusals_core_codes_and_close() {
        let refused = |reason| RuntimeError::Core(CoreError::PeerRefused { reason }).code();
        assert_eq!(refused(RefusalReason::Revoked), "refused_revoked");
        assert_eq!(refused(RefusalReason::Pending), "refused_pending");
        let other = AdmissionRefusalCode::new(4450).unwrap();
        assert_eq!(refused(RefusalReason::Other(other)), "refused");

        let initiator = |code| RuntimeError::from_initiator_core(closed(code)).code();
        assert_eq!(initiator(SessionCloseCode::PEER_REVOKED), "refused_revoked");
        assert_eq!(initiator(SessionCloseCode::PEER_PENDING), "refused_pending");
        assert_eq!(initiator(4450), "refused");
        assert_eq!(initiator(SessionCloseCode::NORMAL), "session_closed");
        assert_eq!(initiator(SessionCloseCode::GRANT_EXPIRED), "session_closed");

        let responder = RuntimeError::Core(closed(SessionCloseCode::PEER_REVOKED));
        assert_eq!(responder.code(), "session_closed");
        assert_eq!(
            RuntimeError::Core(CoreError::PeerRevoked("p".into())).code(),
            CoreError::PeerRevoked("p".into()).code()
        );
    }

    #[test]
    fn code_covers_the_runtime_variants() {
        let io = RuntimeError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        assert_eq!(io.code(), "io");
        assert_eq!(RuntimeError::Timeout("t").code(), "timeout");
        assert_eq!(RuntimeError::Closed.code(), "closed");
        assert_eq!(RuntimeError::Protocol("p".into()).code(), "protocol");
        assert_eq!(RuntimeError::Policy("p").code(), "policy");
        assert_eq!(RuntimeError::Storage("s".into()).code(), "storage");
        assert_eq!(RuntimeError::RateLimited("r").code(), "rate_limited");
        assert_eq!(
            RuntimeError::CapacityExceeded("c").code(),
            "capacity_exceeded"
        );
        assert_eq!(
            RuntimeError::FrameTooLarge { size: 2, max: 1 }.code(),
            "frame_too_large"
        );
        assert_eq!(
            RuntimeError::RelayOffline(RelayOffline::V1Dial).code(),
            "relay_offline"
        );
    }
}
