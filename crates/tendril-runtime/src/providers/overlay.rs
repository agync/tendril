//! Tailscale / WireGuard overlay path provider (`overlay`).
//!
//! Supports direct binding/dialing over host tailnet interfaces as well as a scoped helper mode
//! communicating purely over `0o600` Unix domain sockets without exposing localhost TCP ports.

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tendril_core::policy::ProviderId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};

use crate::error::RuntimeError;
use crate::provider::{DEFAULT_WRITE_TIMEOUT, IoPathStream, PathDialer, PathListener, PathStream};

const HELPER_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HELPER_LINE_LEN: usize = 1024;
const MAX_CONCURRENT_HELPER_ACCEPTS: usize = 64;

/// Requested overlay resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverlayMode {
    Disabled,
    Host,
    Helper,
    #[default]
    Auto,
}

/// Resolved overlay execution strategy returned by [`select_overlay_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayResolvedMode {
    Unavailable,
    Host,
    Helper,
}

/// Configuration for the overlay rung using file or environment credential indirection only.
#[derive(Debug, Clone, Default)]
pub struct OverlayConfig {
    pub mode: OverlayMode,
    pub helper_bin: Option<PathBuf>,
    pub helper_args: Vec<String>,
    pub auth_key_env: Option<String>,
    pub auth_key_file: Option<PathBuf>,
    pub control_url: Option<String>,
    pub tag: Option<String>,
}

impl OverlayConfig {
    /// Returns true when a scoped helper binary and non-inline credential reference are configured.
    #[must_use]
    pub fn helper_configured(&self) -> bool {
        if self.helper_bin.is_none() {
            return false;
        }
        if self.auth_key_file.is_some() {
            return true;
        }
        self.auth_key_env
            .as_deref()
            .is_some_and(|var| !std::env::var(var).unwrap_or_default().trim().is_empty())
    }
}

/// Resolves whether overlay runs via a scoped helper, host tailnet socket, or stays unavailable.
#[must_use]
pub fn select_overlay_mode(config: &OverlayConfig, host_reachable: bool) -> OverlayResolvedMode {
    match config.mode {
        OverlayMode::Disabled => OverlayResolvedMode::Unavailable,
        OverlayMode::Helper => {
            if config.helper_configured() {
                OverlayResolvedMode::Helper
            } else {
                OverlayResolvedMode::Unavailable
            }
        }
        OverlayMode::Host => {
            if host_reachable {
                OverlayResolvedMode::Host
            } else {
                OverlayResolvedMode::Unavailable
            }
        }
        OverlayMode::Auto => {
            if config.helper_configured() {
                OverlayResolvedMode::Helper
            } else if host_reachable {
                OverlayResolvedMode::Host
            } else {
                OverlayResolvedMode::Unavailable
            }
        }
    }
}

/// Reports whether `ip` belongs to the Tailscale CGNAT (`100.64.0.0/10`) or IPv6 ULA (`fd7a:115c:a1e0::/48`) range.
#[must_use]
pub fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => (u32::from(v4) & 0xffc0_0000) == 0x6440_0000,
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            seg[0] == 0xfd7a && seg[1] == 0x115c && seg[2] == 0xa1e0
        }
    }
}

/// TCP listener representing host overlay connectivity (`overlay`).
pub struct OverlayListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    write_timeout: Duration,
    allow_ips: Option<HashSet<IpAddr>>,
    require_tailnet_ip: bool,
}

impl OverlayListener {
    /// Binds an overlay listener on `addr` (enforcing tailnet source IPs unless `allow_ips` or
    /// [`Self::with_allow_non_tailnet`] overrides it).
    pub async fn bind(
        addr: SocketAddr,
        allow_ips: Option<HashSet<IpAddr>>,
    ) -> Result<Self, RuntimeError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let require_tailnet_ip = allow_ips.is_none();
        Ok(Self {
            listener,
            local_addr,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            allow_ips,
            require_tailnet_ip,
        })
    }

    /// Overrides whether non-tailnet source IPs are permitted when `allow_ips` is unset.
    #[must_use]
    pub fn with_allow_non_tailnet(mut self, allow: bool) -> Self {
        self.require_tailnet_ip = !allow;
        self
    }

    /// Overrides the write backpressure timeout applied to accepted streams.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Returns the bound socket address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[async_trait]
impl PathListener for OverlayListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            if let Some(allowed) = &self.allow_ips {
                if !allowed.contains(&peer.ip()) {
                    drop(stream);
                    continue;
                }
            } else if self.require_tailnet_ip && !is_tailnet_ip(peer.ip()) {
                drop(stream);
                continue;
            }
            let _ = stream.set_nodelay(true);
            return Ok(Box::new(IoPathStream::new(
                ProviderId::Overlay,
                Some(peer.ip()),
                self.write_timeout,
                stream,
            )));
        }
    }

    fn local_endpoint(&self) -> String {
        format!("overlay://{}", self.local_addr)
    }
}

/// Dialer connecting to overlay host endpoints (`overlay://host:port` or `host:port`).
#[derive(Debug, Clone)]
pub struct OverlayDialer {
    write_timeout: Duration,
    connect_timeout: Duration,
}

impl Default for OverlayDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlayDialer {
    /// Constructs an `OverlayDialer` with [`DEFAULT_WRITE_TIMEOUT`] and a 10 s connect timeout.
    #[must_use]
    pub fn new() -> Self {
        Self {
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Overrides the TCP connect timeout.
    #[must_use]
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }
}

#[async_trait]
impl PathDialer for OverlayDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Overlay
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let target = endpoint.strip_prefix("overlay://").unwrap_or(endpoint);
        let stream = timeout(self.connect_timeout, TcpStream::connect(target))
            .await
            .map_err(|_| RuntimeError::Timeout("overlay tcp connect timed out"))??;
        let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
        let _ = stream.set_nodelay(true);
        Ok(Box::new(IoPathStream::new(
            ProviderId::Overlay,
            peer_ip,
            self.write_timeout,
            stream,
        )))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct HelperControlMsg {
    op: Option<String>,
    target: Option<String>,
    peer_ip: Option<String>,
    ok: Option<bool>,
    error: Option<String>,
}

async fn read_line_bounded(
    stream: &mut UnixStream,
    limit: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    let deadline = Instant::now() + limit;
    let mut raw = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        if raw.len() >= MAX_HELPER_LINE_LEN {
            return Err(RuntimeError::Protocol(
                "overlay helper control line exceeded bound".to_owned(),
            ));
        }
        let n = timeout_at(deadline, stream.read(&mut byte))
            .await
            .map_err(|_| RuntimeError::Timeout("overlay helper handshake timed out"))??;
        if n == 0 {
            return Err(RuntimeError::Closed);
        }
        if byte[0] == b'\n' {
            return Ok(raw);
        }
        raw.push(byte[0]);
    }
}

async fn accept_one_helper(
    mut stream: UnixStream,
    write_timeout: Duration,
) -> Option<Box<dyn PathStream>> {
    let line = read_line_bounded(&mut stream, HELPER_CONTROL_TIMEOUT)
        .await
        .ok()?;
    let ctrl = serde_json::from_slice::<HelperControlMsg>(&line).ok()?;
    if ctrl.op.as_deref() != Some("accept") {
        return None;
    }
    let peer_ip = ctrl
        .peer_ip
        .as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok());
    let ack = b"{\"ok\":true}\n";
    timeout(write_timeout, stream.write_all(ack))
        .await
        .ok()?
        .ok()?;
    Some(Box::new(IoPathStream::new(
        ProviderId::Overlay,
        peer_ip,
        write_timeout,
        stream,
    )))
}

/// Scoped overlay listener receiving helper-bridged connections over a `0o600` Unix socket.
pub struct OverlayHelperListener {
    socket_path: PathBuf,
    accepted_rx: mpsc::Receiver<Box<dyn PathStream>>,
    accept_task: JoinHandle<()>,
}

impl OverlayHelperListener {
    /// Binds an IPC socket for inbound overlay helper streams inside a `0o700` parent directory.
    pub fn bind(socket_path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let socket_path = socket_path.as_ref().to_path_buf();
        let listener = super::bind_private_unix_listener(&socket_path, true)?;
        let write_timeout = DEFAULT_WRITE_TIMEOUT;
        let (accepted_tx, accepted_rx) = mpsc::channel(MAX_CONCURRENT_HELPER_ACCEPTS);
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_HELPER_ACCEPTS));
        let accept_task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                            drop(stream);
                            continue;
                        };
                        let tx_c = accepted_tx.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Some(path_stream) =
                                accept_one_helper(stream, write_timeout).await
                            {
                                let _ = tx_c.send(path_stream).await;
                            }
                        });
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "overlay helper unix accept error");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        });
        Ok(Self {
            socket_path,
            accepted_rx,
            accept_task,
        })
    }

    /// Returns the filesystem Unix socket path bound for helper IPC.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for OverlayHelperListener {
    fn drop(&mut self) {
        self.accept_task.abort();
        let _ = fs::remove_file(&self.socket_path);
    }
}

#[async_trait]
impl PathListener for OverlayHelperListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.accepted_rx.recv().await.ok_or(RuntimeError::Closed)
    }

    fn local_endpoint(&self) -> String {
        format!("overlay-helper://{}", self.socket_path.to_string_lossy())
    }
}

/// Dialer connecting through a scoped overlay helper `0o600` Unix socket (zero localhost TCP ports).
#[derive(Debug, Clone)]
pub struct OverlayHelperDialer {
    socket_path: PathBuf,
    write_timeout: Duration,
}

impl OverlayHelperDialer {
    /// Creates a dialer targeting the helper's Unix control/stream socket.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }
}

#[async_trait]
impl PathDialer for OverlayHelperDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Overlay
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let target = endpoint
            .strip_prefix("overlay-helper://")
            .unwrap_or(endpoint);
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let req = serde_json::json!({
            "op": "dial",
            "target": target,
        })
        .to_string();
        let line = format!("{req}\n");
        timeout(self.write_timeout, stream.write_all(line.as_bytes()))
            .await
            .map_err(|_| RuntimeError::Timeout("overlay helper dial write timed out"))??;

        let reply_bytes = read_line_bounded(&mut stream, HELPER_CONTROL_TIMEOUT).await?;
        let reply: HelperControlMsg = serde_json::from_slice(&reply_bytes).map_err(|err| {
            RuntimeError::Protocol(format!("invalid overlay helper reply: {err}"))
        })?;
        if reply.ok != Some(true) {
            return Err(RuntimeError::Protocol(
                reply
                    .error
                    .unwrap_or_else(|| "overlay helper rejected dial".to_owned()),
            ));
        }

        Ok(Box::new(IoPathStream::new(
            ProviderId::Overlay,
            None,
            self.write_timeout,
            stream,
        )))
    }
}
