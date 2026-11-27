//! Same-host IPC path provider (`local`).
//!
//! Unix domain sockets on Unix, named pipes on Windows. Both backends expose the same
//! [`LocalListener`] and [`LocalDialer`] API and restrict access to the current user: a `0o600`
//! socket file on Unix, an owner-only DACL on Windows.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{LocalDialer, LocalListener};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{LocalDialer, LocalListener};
