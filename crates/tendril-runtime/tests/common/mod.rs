//! Shared helpers for runtime integration tests.

#![allow(dead_code)]

use std::path::PathBuf;

/// Returns a local IPC endpoint path: a socket under `dir` on Unix, a unique named pipe on
/// Windows.
pub fn ipc_path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        dir.path().join(name)
    }
    #[cfg(windows)]
    {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let _ = dir;
        let stem = name.strip_suffix(".sock").unwrap_or(name);
        PathBuf::from(format!(
            r"\\.\pipe\tendril-test-{}-{}-{stem}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
