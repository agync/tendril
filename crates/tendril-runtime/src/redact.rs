//! Redaction for error text, logs and binding exceptions (CLI, FFI, Python, Node).
//!
//! The helpers are the core ones ([`tendril_core::redact`]), so core types such as
//! `DroppedHint::redacted_hint` follow the same rules. Prefer redacting each hint, URL or origin
//! before it is formatted into a message; [`redact_text`] and [`redact_error`] are the last
//! line for text built elsewhere.

pub use tendril_core::redact::{
    REDACTED, redact_hint, redact_host, redact_json_error, redact_text, redact_url, redact_url_str,
};

use crate::error::RuntimeError;

/// [`redact_text`] of the error's display text.
#[must_use]
pub fn redact_error(err: &RuntimeError) -> String {
    redact_text(&err.to_string())
}
