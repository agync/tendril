//! Unix domain socket backend for the `local` provider.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use tendril_core::policy::ProviderId;
use tokio::net::{UnixListener, UnixStream};

use super::super::bind_private_unix_listener;
use crate::error::RuntimeError;
use crate::provider::{DEFAULT_WRITE_TIMEOUT, IoPathStream, PathDialer, PathListener, PathStream};

/// Listener accepting local IPC streams on a `0o600` Unix domain socket.
pub struct LocalListener {
    listener: UnixListener,
    path: PathBuf,
    write_timeout: Duration,
}

impl LocalListener {
    /// Binds a Unix domain socket listener at `path`, replacing only a verified stale socket.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let path = path.as_ref().to_path_buf();
        let listener = bind_private_unix_listener(&path, false)?;
        Ok(Self {
            listener,
            path,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        })
    }

    /// Overrides the write backpressure timeout applied to accepted streams.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Returns the filesystem socket path bound by this listener.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for LocalListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[async_trait]
impl PathListener for LocalListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(Box::new(IoPathStream::new(
            ProviderId::Local,
            None,
            self.write_timeout,
            stream,
        )))
    }

    fn local_endpoint(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

/// Dialer connecting to local Unix domain socket listeners.
#[derive(Debug, Clone)]
pub struct LocalDialer {
    write_timeout: Duration,
}

impl Default for LocalDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalDialer {
    /// Constructs a `LocalDialer` with [`DEFAULT_WRITE_TIMEOUT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Connects directly to `socket_path`.
    pub async fn connect(
        &self,
        socket_path: impl AsRef<Path>,
    ) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = UnixStream::connect(socket_path.as_ref()).await?;
        Ok(Box::new(IoPathStream::new(
            ProviderId::Local,
            None,
            self.write_timeout,
            stream,
        )))
    }
}

#[async_trait]
impl PathDialer for LocalDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Local
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let path = endpoint
            .strip_prefix("local:")
            .or_else(|| endpoint.strip_prefix("unix://"))
            .unwrap_or(endpoint);
        self.connect(path).await
    }
}
