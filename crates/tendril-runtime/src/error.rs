//! Typed error definitions for the Tendril async runtime and path providers.

use tendril_core::error::CoreError;
use thiserror::Error;

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

    #[error("transport stream closed")]
    Closed,

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("path policy failed: {0}")]
    Policy(&'static str),

    #[error("storage error: {0}")]
    Storage(String),
}
