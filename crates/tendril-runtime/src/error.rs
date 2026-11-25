//! Typed error definitions for the Tendril async runtime and path providers.

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
