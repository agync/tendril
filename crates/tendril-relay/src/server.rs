//! Stateless async WebSocket relay server implementing `spec/relay-v1.md` and `spec/relay-v2.md`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use tendril_core::crypto::{b64url_decode_array, b64url_encode, random_bytes};
use tendril_core::v2::{
    RELAY_V2_EPOCH_SECS, canonical_relay_host, epoch_for_unix, epoch_within_skew,
    verify_v2_relay_accept, verify_v2_relay_register,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant as TokioInstant, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderMap, StatusCode};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::protocol::{
    MAX_RELAY_FRAME_LEN, RELAY_PATH, RELAY_V2_PATH, RelayClientMsg, RelayServerMsg,
    RelayV2ClientMsg, RelayV2ServerMsg, verify_relay_accept, verify_relay_register,
};
use crate::rate_limit::{IpTokenLimiter, normalize_rate_limit_ip};

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

static RELAY_RING_INIT: Once = Once::new();

fn ensure_rustls_ring_provider() {
    RELAY_RING_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// IPv4 or IPv6 CIDR matcher used to configure trusted reverse proxies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpCidr {
    /// Checks whether `ip` (unwrapping IPv4-mapped IPv6 addresses) belongs to this CIDR range.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let canonical = match ip {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        };
        match (self, canonical) {
            (Self::V4 { network, prefix }, IpAddr::V4(v4)) => {
                let mask = if *prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - *prefix)
                };
                (u32::from(v4) & mask) == *network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(v6)) => {
                let mask = if *prefix == 0 {
                    0u128
                } else {
                    !0u128 << (128 - *prefix)
                };
                (u128::from(v6) & mask) == *network
            }
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Some((ip_s, pfx_s)) = trimmed.split_once('/') {
            let ip: IpAddr = ip_s
                .parse()
                .map_err(|e| format!("invalid CIDR address '{ip_s}': {e}"))?;
            let prefix: u8 = pfx_s
                .parse()
                .map_err(|e| format!("invalid CIDR prefix '{pfx_s}': {e}"))?;
            match ip {
                IpAddr::V4(v4) => {
                    if prefix > 32 {
                        return Err(format!("IPv4 CIDR prefix {prefix} > 32"));
                    }
                    let mask = if prefix == 0 {
                        0u32
                    } else {
                        !0u32 << (32 - prefix)
                    };
                    Ok(Self::V4 {
                        network: u32::from(v4) & mask,
                        prefix,
                    })
                }
                IpAddr::V6(v6) => {
                    if prefix > 128 {
                        return Err(format!("IPv6 CIDR prefix {prefix} > 128"));
                    }
                    if prefix >= 96
                        && let Some(v4) = v6.to_ipv4_mapped()
                    {
                        let pfx4 = prefix - 96;
                        let mask4 = if pfx4 == 0 {
                            0u32
                        } else {
                            !0u32 << (32 - pfx4)
                        };
                        return Ok(Self::V4 {
                            network: u32::from(v4) & mask4,
                            prefix: pfx4,
                        });
                    }
                    let mask = if prefix == 0 {
                        0u128
                    } else {
                        !0u128 << (128 - prefix)
                    };
                    Ok(Self::V6 {
                        network: u128::from(v6) & mask,
                        prefix,
                    })
                }
            }
        } else {
            let ip: IpAddr = trimmed
                .parse()
                .map_err(|e| format!("invalid IP/CIDR '{trimmed}': {e}"))?;
            match ip {
                IpAddr::V4(v4) => Ok(Self::V4 {
                    network: u32::from(v4),
                    prefix: 32,
                }),
                IpAddr::V6(v6) => {
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        Ok(Self::V4 {
                            network: u32::from(v4),
                            prefix: 32,
                        })
                    } else {
                        Ok(Self::V6 {
                            network: u128::from(v6),
                            prefix: 128,
                        })
                    }
                }
            }
        }
    }
}

/// Configuration for [`RelayServer`].
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub listen_addr: SocketAddr,
    pub host: String,
    pub max_pending_per_mailbox: usize,
    pub max_active_per_ip: usize,
    pub max_active_per_mailbox: usize,
    pub max_total_connections: usize,
    pub max_mailboxes: usize,
    pub max_tracked_ips: usize,
    pub ip_burst_capacity: u32,
    pub ip_refill_per_sec: u32,
    pub accept_timeout: Duration,
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub trusted_proxies: Vec<IpCidr>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            host: "localhost".to_owned(),
            max_pending_per_mailbox: 8,
            max_active_per_ip: 64,
            max_active_per_mailbox: 64,
            max_total_connections: 4096,
            max_mailboxes: 1024,
            max_tracked_ips: 4096,
            ip_burst_capacity: 60,
            ip_refill_per_sec: 20,
            accept_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(300),
            write_timeout: Duration::from_secs(1),
            tls_cert_path: None,
            tls_key_path: None,
            trusted_proxies: Vec::new(),
        }
    }
}

/// Errors produced by [`RelayServer`] and [`RelayHandle`].
#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay i/o failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("relay background task failed: {0}")]
    TaskJoin(String),
    #[error("invalid relay configuration: {0}")]
    InvalidConfig(String),
    #[error("tls setup failed: {0}")]
    Tls(String),
}

/// Handle to a background [`RelayServer`] instance.
#[derive(Debug)]
pub struct RelayHandle {
    addr: SocketAddr,
    uses_tls: bool,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl RelayHandle {
    /// Returns the local socket address the relay is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns a `ws://` or `wss://` URL pointing at the canonical `/v1/relay` path.
    #[must_use]
    pub fn ws_url(&self) -> String {
        let scheme = if self.uses_tls { "wss" } else { "ws" };
        format!("{scheme}://{}{RELAY_PATH}", self.addr)
    }

    /// Returns a `ws://` or `wss://` URL pointing at the `/v2/relay` path.
    #[must_use]
    pub fn ws_v2_url(&self) -> String {
        let scheme = if self.uses_tls { "wss" } else { "ws" };
        format!("{scheme}://{}{RELAY_V2_PATH}", self.addr)
    }

    /// Signals graceful shutdown and awaits server task exit.
    pub async fn stop(mut self) -> Result<(), RelayError> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|e| RelayError::TaskJoin(e.to_string()))?;
        }
        Ok(())
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

enum RelayTcpStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for RelayTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RelayTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
struct MailboxEntry {
    reg_id: u64,
    incoming_tx: mpsc::Sender<String>,
}

#[derive(Clone)]
struct IncomingV2Notification {
    mailbox_id: String,
    epoch: u64,
    conn_id: String,
    dial_nonce: String,
    dial_token: String,
}

#[derive(Clone)]
struct MailboxV2Entry {
    reg_id: u64,
    epoch: u64,
    incoming_tx: mpsc::Sender<IncomingV2Notification>,
}

struct PendingDial {
    dial_id: u64,
    target_pub: [u8; 32],
    match_tx: oneshot::Sender<AcceptorTransfer>,
}

struct PendingV2Dial {
    dial_id: u64,
    target_mailbox: [u8; 32],
    epoch: u64,
    match_tx: oneshot::Sender<AcceptorV2Transfer>,
}

struct AcceptorTransfer {
    ws: WebSocketStream<RelayTcpStream>,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    _stream_guard: MailboxStreamGuard,
}

struct AcceptorV2Transfer {
    ws: WebSocketStream<RelayTcpStream>,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    _stream_guard: MailboxV2StreamGuard,
}

struct RelayTables {
    next_id: u64,
    mailboxes: HashMap<[u8; 32], MailboxEntry>,
    pending: HashMap<[u8; 16], PendingDial>,
    pending_counts: HashMap<[u8; 32], usize>,
    active_per_mailbox: HashMap<[u8; 32], usize>,
    v2_mailboxes: HashMap<[u8; 32], MailboxV2Entry>,
    v2_pending: HashMap<[u8; 16], PendingV2Dial>,
    v2_pending_counts: HashMap<[u8; 32], usize>,
    v2_active_per_mailbox: HashMap<[u8; 32], usize>,
}

impl RelayTables {
    fn new() -> Self {
        Self {
            next_id: 1,
            mailboxes: HashMap::new(),
            pending: HashMap::new(),
            pending_counts: HashMap::new(),
            active_per_mailbox: HashMap::new(),
            v2_mailboxes: HashMap::new(),
            v2_pending: HashMap::new(),
            v2_pending_counts: HashMap::new(),
            v2_active_per_mailbox: HashMap::new(),
        }
    }

    fn total_mailbox_count(&self) -> usize {
        self.mailboxes.len().saturating_add(self.v2_mailboxes.len())
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }
}

struct RelayState {
    config: RelayConfig,
    limiter: Mutex<IpTokenLimiter>,
    active_connections: AtomicUsize,
    active_per_ip: Mutex<HashMap<IpAddr, usize>>,
    tables: Mutex<RelayTables>,
}

impl RelayState {
    fn new(config: RelayConfig) -> Self {
        let limiter = IpTokenLimiter::new(
            config.max_tracked_ips,
            config.ip_burst_capacity,
            config.ip_refill_per_sec,
        );
        Self {
            config,
            limiter: Mutex::new(limiter),
            active_connections: AtomicUsize::new(0),
            active_per_ip: Mutex::new(HashMap::new()),
            tables: Mutex::new(RelayTables::new()),
        }
    }

    fn try_acquire_global(self: &Arc<Self>) -> Option<GlobalConnGuard> {
        let cap = self.config.max_total_connections.max(1);
        loop {
            let cur = self.active_connections.load(Ordering::Acquire);
            if cur >= cap {
                return None;
            }
            if self
                .active_connections
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(GlobalConnGuard {
                    state: Arc::clone(self),
                });
            }
        }
    }

    fn try_acquire_ip(self: &Arc<Self>, ip: IpAddr) -> Option<IpConnGuard> {
        let key = normalize_rate_limit_ip(ip);
        {
            let mut limiter = self.limiter.lock().expect("limiter mutex poisoned");
            if !limiter.allow(key, Instant::now()) {
                return None;
            }
        }
        let mut active = self
            .active_per_ip
            .lock()
            .expect("active_per_ip mutex poisoned");
        let count = active.entry(key).or_insert(0);
        if *count >= self.config.max_active_per_ip {
            return None;
        }
        *count += 1;
        Some(IpConnGuard {
            state: Arc::clone(self),
            ip: key,
        })
    }
}

struct GlobalConnGuard {
    state: Arc<RelayState>,
}

impl Drop for GlobalConnGuard {
    fn drop(&mut self) {
        self.state.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

struct IpConnGuard {
    state: Arc<RelayState>,
    ip: IpAddr,
}

impl Drop for IpConnGuard {
    fn drop(&mut self) {
        let mut active = self
            .state
            .active_per_ip
            .lock()
            .expect("active_per_ip mutex poisoned");
        if let Some(count) = active.get_mut(&self.ip) {
            if *count <= 1 {
                active.remove(&self.ip);
            } else {
                *count -= 1;
            }
        }
    }
}

struct MailboxRegGuard {
    state: Arc<RelayState>,
    mailbox_pub: [u8; 32],
    reg_id: u64,
}

impl Drop for MailboxRegGuard {
    fn drop(&mut self) {
        let mut tables = self.state.tables.lock().expect("tables mutex poisoned");
        if tables
            .mailboxes
            .get(&self.mailbox_pub)
            .is_some_and(|entry| entry.reg_id == self.reg_id)
        {
            tables.mailboxes.remove(&self.mailbox_pub);
        }
    }
}

struct PendingDialGuard {
    state: Arc<RelayState>,
    target_pub: [u8; 32],
    conn_id: [u8; 16],
    dial_id: u64,
}

impl Drop for PendingDialGuard {
    fn drop(&mut self) {
        let mut tables = self.state.tables.lock().expect("tables mutex poisoned");
        let matches = tables
            .pending
            .get(&self.conn_id)
            .is_some_and(|p| p.dial_id == self.dial_id);
        if matches {
            tables.pending.remove(&self.conn_id);
            decrement_count(&mut tables.pending_counts, &self.target_pub);
        }
    }
}

struct MailboxStreamGuard {
    state: Arc<RelayState>,
    mailbox_pub: [u8; 32],
}

impl Drop for MailboxStreamGuard {
    fn drop(&mut self) {
        let mut tables = self.state.tables.lock().expect("tables mutex poisoned");
        decrement_count(&mut tables.active_per_mailbox, &self.mailbox_pub);
    }
}

struct MailboxV2RegGuard {
    state: Arc<RelayState>,
    mailbox_id: [u8; 32],
    reg_id: u64,
}

impl Drop for MailboxV2RegGuard {
    fn drop(&mut self) {
        let mut tables = self
            .state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if tables
            .v2_mailboxes
            .get(&self.mailbox_id)
            .is_some_and(|entry| entry.reg_id == self.reg_id)
        {
            tables.v2_mailboxes.remove(&self.mailbox_id);
        }
    }
}

struct PendingV2DialGuard {
    state: Arc<RelayState>,
    target_mailbox: [u8; 32],
    conn_id: [u8; 16],
    dial_id: u64,
}

impl Drop for PendingV2DialGuard {
    fn drop(&mut self) {
        let mut tables = self
            .state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let matches = tables
            .v2_pending
            .get(&self.conn_id)
            .is_some_and(|p| p.dial_id == self.dial_id);
        if matches {
            tables.v2_pending.remove(&self.conn_id);
            decrement_count(&mut tables.v2_pending_counts, &self.target_mailbox);
        }
    }
}

struct MailboxV2StreamGuard {
    state: Arc<RelayState>,
    mailbox_id: [u8; 32],
}

impl Drop for MailboxV2StreamGuard {
    fn drop(&mut self) {
        let mut tables = self
            .state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        decrement_count(&mut tables.v2_active_per_mailbox, &self.mailbox_id);
    }
}

fn decrement_count(map: &mut HashMap<[u8; 32], usize>, key: &[u8; 32]) {
    if let Some(count) = map.get_mut(key) {
        if *count <= 1 {
            map.remove(key);
        } else {
            *count -= 1;
        }
    }
}

/// Stateless WebSocket ciphertext relay listening on `/v1/relay`.
pub struct RelayServer {
    listener: TcpListener,
    addr: SocketAddr,
    state: Arc<RelayState>,
    tls_acceptor: Option<TlsAcceptor>,
}

impl RelayServer {
    /// Binds a TCP listener using `config`, optionally enabling native `rustls` TLS.
    pub async fn bind(config: RelayConfig) -> Result<Self, RelayError> {
        let tls_acceptor = match (&config.tls_cert_path, &config.tls_key_path) {
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                return Err(RelayError::InvalidConfig(
                    "both tls_cert_path and tls_key_path must be set".to_owned(),
                ));
            }
            (Some(cert_path), Some(key_path)) => {
                ensure_rustls_ring_provider();
                let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
                    .map_err(|e| {
                        RelayError::Tls(format!("read cert '{}': {e}", cert_path.display()))
                    })?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        RelayError::Tls(format!("parse cert '{}': {e}", cert_path.display()))
                    })?;
                if certs.is_empty() {
                    return Err(RelayError::Tls(format!(
                        "no certificates found in '{}'",
                        cert_path.display()
                    )));
                }
                let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
                    RelayError::Tls(format!("read private key '{}': {e}", key_path.display()))
                })?;
                let server_cfg = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| RelayError::Tls(format!("invalid TLS cert/key pair: {e}")))?;
                Some(TlsAcceptor::from(Arc::new(server_cfg)))
            }
        };
        let listener = TcpListener::bind(config.listen_addr).await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(RelayState::new(config));
        Ok(Self {
            listener,
            addr,
            state,
            tls_acceptor,
        })
    }

    /// Returns the local socket address bound by this relay.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns a `ws://` or `wss://` URL pointing at `/v1/relay`.
    #[must_use]
    pub fn ws_url(&self) -> String {
        let scheme = if self.tls_acceptor.is_some() {
            "wss"
        } else {
            "ws"
        };
        format!("{scheme}://{}{RELAY_PATH}", self.addr)
    }

    /// Returns a `ws://` or `wss://` URL pointing at `/v2/relay`.
    #[must_use]
    pub fn ws_v2_url(&self) -> String {
        let scheme = if self.tls_acceptor.is_some() {
            "wss"
        } else {
            "ws"
        };
        format!("{scheme}://{}{RELAY_V2_PATH}", self.addr)
    }

    /// Runs the accept loop until `shutdown` fires.
    pub async fn serve_until(self, mut shutdown: oneshot::Receiver<()>) -> Result<(), RelayError> {
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!(addr = %self.addr, "relay shutting down");
                    return Ok(());
                }
                accept_res = self.listener.accept() => {
                    match accept_res {
                        Ok((stream, peer_addr)) => {
                            let Some(global_guard) = self.state.try_acquire_global() else {
                                tracing::debug!(ip = %peer_addr.ip(), "rejected relay connection at global cap");
                                drop(stream);
                                continue;
                            };
                            let peer_ip = peer_addr.ip();
                            let from_trusted_proxy = self
                                .state
                                .config
                                .trusted_proxies
                                .iter()
                                .any(|cidr| cidr.contains(peer_ip));
                            let ip_guard = if from_trusted_proxy {
                                None
                            } else {
                                let Some(guard) = self.state.try_acquire_ip(peer_ip) else {
                                    tracing::debug!(ip = %peer_ip, "rejected relay connection by rate/ip cap");
                                    drop(stream);
                                    continue;
                                };
                                Some(guard)
                            };
                            let state = Arc::clone(&self.state);
                            let tls = self.tls_acceptor.clone();
                            tokio::spawn(async move {
                                handle_connection(stream, peer_ip, global_guard, ip_guard, tls, state).await;
                            });
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "relay tcp accept error");
                        }
                    }
                }
            }
        }
    }

    /// Spawns the relay server on a background Tokio task and returns a control handle.
    #[must_use]
    pub fn spawn(self) -> RelayHandle {
        let addr = self.addr;
        let uses_tls = self.tls_acceptor.is_some();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = self.serve_until(shutdown_rx).await;
        });
        RelayHandle {
            addr,
            uses_tls,
            shutdown_tx: Some(shutdown_tx),
            task: Some(task),
        }
    }
}

async fn send_json<T: Serialize>(
    ws: &mut WebSocketStream<RelayTcpStream>,
    msg: &T,
    write_timeout: Duration,
) -> bool {
    let Ok(text) = serde_json::to_string(msg) else {
        return false;
    };
    timeout(write_timeout, ws.send(Message::Text(text.into())))
        .await
        .is_ok_and(|res| res.is_ok())
}

async fn send_error_and_close(
    ws: &mut WebSocketStream<RelayTcpStream>,
    code: &str,
    write_timeout: Duration,
) {
    let _ = send_json(
        ws,
        &RelayServerMsg::Error {
            code: code.to_owned(),
        },
        write_timeout,
    )
    .await;
    let _ = timeout(write_timeout, ws.close(None)).await;
}

async fn send_v2_error_and_close(
    ws: &mut WebSocketStream<RelayTcpStream>,
    code: &str,
    write_timeout: Duration,
) {
    let _ = send_json(
        ws,
        &RelayV2ServerMsg::Error {
            code: code.to_owned(),
        },
        write_timeout,
    )
    .await;
    let _ = timeout(write_timeout, ws.close(None)).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelayProtocolVersion {
    V1,
    V2,
}

fn parse_forwarded_ip_token(raw: &str) -> Option<IpAddr> {
    let mut s = raw.trim().trim_matches('"');
    if s.is_empty() {
        return None;
    }
    if let Some(bracketed) = s.strip_prefix('[')
        && let Some((inner, _)) = bracketed.split_once(']')
    {
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sock) = s.parse::<SocketAddr>() {
        return Some(sock.ip());
    }
    if let Some((h, port)) = s.rsplit_once(':')
        && port.parse::<u16>().is_ok()
    {
        s = h;
        return s.parse::<IpAddr>().ok();
    }
    None
}

fn extract_trusted_client_ip(
    headers: &HeaderMap,
    trusted_proxies: &[IpCidr],
    peer_ip: IpAddr,
) -> IpAddr {
    let mut candidates = Vec::new();
    for val in headers.get_all("forwarded") {
        if let Ok(s) = val.to_str() {
            for entry in s.split(',') {
                for param in entry.split(';') {
                    let trimmed = param.trim();
                    if trimmed.len() > 4
                        && trimmed[..4].eq_ignore_ascii_case("for=")
                        && let Some(ip) = parse_forwarded_ip_token(&trimmed[4..])
                    {
                        candidates.push(ip);
                    }
                }
            }
        }
    }
    if candidates.is_empty() {
        for val in headers.get_all("x-forwarded-for") {
            if let Ok(s) = val.to_str() {
                for part in s.split(',') {
                    if let Some(ip) = parse_forwarded_ip_token(part) {
                        candidates.push(ip);
                    }
                }
            }
        }
    }
    for ip in candidates.into_iter().rev() {
        if !trusted_proxies.iter().any(|cidr| cidr.contains(ip)) {
            return ip;
        }
    }
    peer_ip
}

async fn handle_connection(
    stream: TcpStream,
    peer_ip: IpAddr,
    global_guard: GlobalConnGuard,
    pre_acquired_ip: Option<IpConnGuard>,
    tls_acceptor: Option<TlsAcceptor>,
    state: Arc<RelayState>,
) {
    let _ = stream.set_nodelay(true);
    let io_stream = match tls_acceptor {
        Some(acceptor) => match timeout(state.config.accept_timeout, acceptor.accept(stream)).await
        {
            Ok(Ok(tls_stream)) => RelayTcpStream::Tls(Box::new(tls_stream)),
            Ok(Err(_)) | Err(_) => return,
        },
        None => RelayTcpStream::Plain(stream),
    };

    let ws_config = WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_RELAY_FRAME_LEN * 2)
        .max_message_size(Some(MAX_RELAY_FRAME_LEN))
        .max_frame_size(Some(MAX_RELAY_FRAME_LEN));

    let extracted_ip = Arc::new(Mutex::new(None::<IpAddr>));
    let matched_version = Arc::new(Mutex::new(None::<RelayProtocolVersion>));
    let extract_trusted = pre_acquired_ip.is_none();
    let trusted_proxies = state.config.trusted_proxies.clone();
    let extracted_slot = Arc::clone(&extracted_ip);
    let version_slot = Arc::clone(&matched_version);

    #[allow(clippy::result_large_err)]
    let validate_req = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let version = match req.uri().path() {
            RELAY_PATH => RelayProtocolVersion::V1,
            RELAY_V2_PATH => RelayProtocolVersion::V2,
            _ => {
                let mut err = ErrorResponse::new(Some("not found".to_owned()));
                *err.status_mut() = StatusCode::NOT_FOUND;
                return Err(err);
            }
        };
        *version_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(version);
        if extract_trusted {
            let resolved = extract_trusted_client_ip(req.headers(), &trusted_proxies, peer_ip);
            *extracted_slot.lock().expect("extracted_ip mutex poisoned") = Some(resolved);
        }
        Ok(resp)
    };

    let Ok(Ok(mut ws)) = timeout(
        state.config.accept_timeout,
        accept_hdr_async_with_config(io_stream, validate_req, Some(ws_config)),
    )
    .await
    else {
        return;
    };

    let version = matched_version
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .unwrap_or(RelayProtocolVersion::V1);

    let ip_guard = match pre_acquired_ip {
        Some(g) => g,
        None => {
            let resolved = extracted_ip
                .lock()
                .expect("extracted_ip mutex poisoned")
                .unwrap_or(peer_ip);
            let Some(g) = state.try_acquire_ip(resolved) else {
                match version {
                    RelayProtocolVersion::V1 => {
                        send_error_and_close(&mut ws, "rate_limited", state.config.write_timeout)
                            .await;
                    }
                    RelayProtocolVersion::V2 => {
                        send_v2_error_and_close(
                            &mut ws,
                            "rate_limited",
                            state.config.write_timeout,
                        )
                        .await;
                    }
                }
                return;
            };
            g
        }
    };

    if version == RelayProtocolVersion::V2 {
        handle_v2_connection(ws, global_guard, ip_guard, state).await;
        return;
    }

    let Ok(nonce) = random_bytes::<32>() else {
        return;
    };
    let challenge = RelayServerMsg::Challenge {
        nonce: b64url_encode(&nonce),
        host: state.config.host.clone(),
        max_frame: MAX_RELAY_FRAME_LEN,
    };
    if !send_json(&mut ws, &challenge, state.config.write_timeout).await {
        return;
    }

    let first_msg = match timeout(state.config.accept_timeout, ws.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        Ok(Some(Ok(_))) => {
            send_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
            return;
        }
        Ok(None | Some(Err(_))) => return,
        Err(_) => {
            send_error_and_close(&mut ws, "timeout", state.config.write_timeout).await;
            return;
        }
    };

    let Ok(cmd) = serde_json::from_str::<RelayClientMsg>(&first_msg) else {
        send_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };

    match cmd {
        RelayClientMsg::Register { pub_key, sig } => {
            handle_register(ws, global_guard, ip_guard, state, &nonce, pub_key, sig).await;
        }
        RelayClientMsg::Dial {
            target_pub,
            conn_id,
        } => {
            handle_dial(ws, global_guard, ip_guard, state, target_pub, conn_id).await;
        }
        RelayClientMsg::Accept {
            pub_key,
            conn_id,
            sig,
        } => {
            handle_accept(
                ws,
                global_guard,
                ip_guard,
                state,
                &nonce,
                pub_key,
                conn_id,
                sig,
            )
            .await;
        }
    }
}

async fn handle_register(
    mut ws: WebSocketStream<RelayTcpStream>,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    nonce: &[u8; 32],
    pub_key_b64: String,
    sig_b64: String,
) {
    let Ok(mailbox_pub) = verify_relay_register(&pub_key_b64, &sig_b64, &state.config.host, nonce)
    else {
        send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    };

    let chan_cap = state
        .config
        .max_pending_per_mailbox
        .saturating_mul(2)
        .max(8);
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<String>(chan_cap);
    let reg_id_opt = {
        let mut tables = state.tables.lock().expect("tables mutex poisoned");
        if !tables.mailboxes.contains_key(&mailbox_pub)
            && tables.total_mailbox_count() >= state.config.max_mailboxes.max(1)
        {
            None
        } else {
            let reg_id = tables.alloc_id();
            tables.mailboxes.insert(
                mailbox_pub,
                MailboxEntry {
                    reg_id,
                    incoming_tx,
                },
            );
            Some(reg_id)
        }
    };
    let Some(reg_id) = reg_id_opt else {
        send_error_and_close(&mut ws, "capacity_exceeded", state.config.write_timeout).await;
        return;
    };
    let _reg_guard = MailboxRegGuard {
        state: Arc::clone(&state),
        mailbox_pub,
        reg_id,
    };

    if !send_json(
        &mut ws,
        &RelayServerMsg::Registered {
            pub_key: pub_key_b64,
        },
        state.config.write_timeout,
    )
    .await
    {
        return;
    }

    loop {
        tokio::select! {
            maybe_conn = incoming_rx.recv() => {
                let Some(conn_id) = maybe_conn else {
                    break;
                };
                if !send_json(&mut ws, &RelayServerMsg::Incoming { conn_id }, state.config.write_timeout).await {
                    break;
                }
            }
            maybe_ws = ws.next() => {
                match maybe_ws {
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => break,
                }
            }
        }
    }
    let _ = timeout(state.config.write_timeout, ws.close(None)).await;
}

async fn handle_dial(
    mut ws: WebSocketStream<RelayTcpStream>,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    target_pub_b64: String,
    conn_id_b64: String,
) {
    let (Ok(target_pub), Ok(conn_id)) = (
        b64url_decode_array::<32>(&target_pub_b64),
        b64url_decode_array::<16>(&conn_id_b64),
    ) else {
        send_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };

    let (match_tx, match_rx) = oneshot::channel::<AcceptorTransfer>();
    let enqueue_res: Result<(mpsc::Sender<String>, u64), &'static str> = {
        let mut tables = state.tables.lock().expect("tables mutex poisoned");
        if let Some(mailbox) = tables.mailboxes.get(&target_pub).cloned() {
            let active_count = tables
                .active_per_mailbox
                .get(&target_pub)
                .copied()
                .unwrap_or(0);
            let pending_count = tables.pending_counts.get(&target_pub).copied().unwrap_or(0);
            if active_count >= state.config.max_active_per_mailbox
                || pending_count >= state.config.max_pending_per_mailbox
            {
                Err("rate_limited")
            } else if tables.pending.contains_key(&conn_id) {
                Err("invalid_request")
            } else {
                let dial_id = tables.alloc_id();
                *tables.pending_counts.entry(target_pub).or_insert(0) += 1;
                tables.pending.insert(
                    conn_id,
                    PendingDial {
                        dial_id,
                        target_pub,
                        match_tx,
                    },
                );
                Ok((mailbox.incoming_tx, dial_id))
            }
        } else {
            Err("offline")
        }
    };
    let (incoming_tx, dial_id) = match enqueue_res {
        Ok(pair) => pair,
        Err(code) => {
            send_error_and_close(&mut ws, code, state.config.write_timeout).await;
            return;
        }
    };

    let _pending_guard = PendingDialGuard {
        state: Arc::clone(&state),
        target_pub,
        conn_id,
        dial_id,
    };

    match incoming_tx.try_send(conn_id_b64.clone()) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            send_error_and_close(&mut ws, "rate_limited", state.config.write_timeout).await;
            return;
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            send_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
            return;
        }
    }

    let acceptor = match timeout(state.config.accept_timeout, match_rx).await {
        Ok(Ok(transfer)) => transfer,
        Ok(Err(_)) => {
            send_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
            return;
        }
        Err(_) => {
            send_error_and_close(&mut ws, "timeout", state.config.write_timeout).await;
            return;
        }
    };

    if !send_json(
        &mut ws,
        &RelayServerMsg::Ready {
            conn_id: conn_id_b64,
        },
        state.config.write_timeout,
    )
    .await
    {
        return;
    }

    bridge_streams(
        ws,
        acceptor.ws,
        state.config.write_timeout,
        state.config.idle_timeout,
    )
    .await;
    drop(acceptor._global_guard);
    drop(acceptor._ip_guard);
    drop(acceptor._stream_guard);
}

#[allow(clippy::too_many_arguments)]
async fn handle_accept(
    mut ws: WebSocketStream<RelayTcpStream>,
    global_guard: GlobalConnGuard,
    ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    nonce: &[u8; 32],
    pub_key_b64: String,
    conn_id_b64: String,
    sig_b64: String,
) {
    let Ok((acceptor_pub, conn_id)) = verify_relay_accept(
        &pub_key_b64,
        &conn_id_b64,
        &sig_b64,
        &state.config.host,
        nonce,
    ) else {
        send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    };

    enum ClaimResult {
        Claimed {
            target_pub: [u8; 32],
            match_tx: oneshot::Sender<AcceptorTransfer>,
        },
        NotFound,
        WrongOwner,
        RateLimited,
    }

    let claim = {
        let mut tables = state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match tables.pending.get(&conn_id) {
            None => ClaimResult::NotFound,
            Some(entry) if entry.target_pub != acceptor_pub => ClaimResult::WrongOwner,
            Some(entry) => {
                let active_count = tables
                    .active_per_mailbox
                    .get(&entry.target_pub)
                    .copied()
                    .unwrap_or(0);
                if active_count >= state.config.max_active_per_mailbox {
                    ClaimResult::RateLimited
                } else {
                    let pending = tables.pending.remove(&conn_id).expect("checked Some above");
                    decrement_count(&mut tables.pending_counts, &pending.target_pub);
                    *tables
                        .active_per_mailbox
                        .entry(pending.target_pub)
                        .or_insert(0) += 1;
                    ClaimResult::Claimed {
                        target_pub: pending.target_pub,
                        match_tx: pending.match_tx,
                    }
                }
            }
        }
    };

    let (target_pub, match_tx) = match claim {
        ClaimResult::Claimed {
            target_pub,
            match_tx,
        } => (target_pub, match_tx),
        ClaimResult::NotFound => {
            send_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
            return;
        }
        ClaimResult::WrongOwner => {
            send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
            return;
        }
        ClaimResult::RateLimited => {
            send_error_and_close(&mut ws, "rate_limited", state.config.write_timeout).await;
            return;
        }
    };

    let stream_guard = MailboxStreamGuard {
        state: Arc::clone(&state),
        mailbox_pub: target_pub,
    };

    if !send_json(
        &mut ws,
        &RelayServerMsg::Ready {
            conn_id: conn_id_b64,
        },
        state.config.write_timeout,
    )
    .await
    {
        return;
    }

    let _ = match_tx.send(AcceptorTransfer {
        ws,
        _global_guard: global_guard,
        _ip_guard: ip_guard,
        _stream_guard: stream_guard,
    });
}

async fn handle_v2_connection(
    mut ws: WebSocketStream<RelayTcpStream>,
    global_guard: GlobalConnGuard,
    ip_guard: IpConnGuard,
    state: Arc<RelayState>,
) {
    let Ok(canonical_host) = canonical_relay_host(&state.config.host) else {
        send_v2_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };
    let Ok(nonce) = random_bytes::<32>() else {
        return;
    };
    let server_epoch = epoch_for_unix(current_unix_secs());
    let challenge = RelayV2ServerMsg::Challenge {
        nonce: b64url_encode(&nonce),
        host: canonical_host.clone(),
        epoch: server_epoch,
        max_frame: MAX_RELAY_FRAME_LEN,
    };
    if !send_json(&mut ws, &challenge, state.config.write_timeout).await {
        return;
    }

    let first_msg = match timeout(state.config.accept_timeout, ws.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        Ok(Some(Ok(_))) => {
            send_v2_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
            return;
        }
        Ok(None | Some(Err(_))) => return,
        Err(_) => {
            send_v2_error_and_close(&mut ws, "timeout", state.config.write_timeout).await;
            return;
        }
    };

    let Ok(cmd) = serde_json::from_str::<RelayV2ClientMsg>(&first_msg) else {
        send_v2_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };

    match cmd {
        RelayV2ClientMsg::Register {
            mailbox_id,
            epoch,
            sig,
        } => {
            handle_v2_register(
                ws,
                global_guard,
                ip_guard,
                state,
                &canonical_host,
                server_epoch,
                &nonce,
                mailbox_id,
                epoch,
                sig,
            )
            .await;
        }
        RelayV2ClientMsg::Dial {
            target_mailbox_id,
            epoch,
            conn_id,
            dial_token,
        } => {
            handle_v2_dial(
                ws,
                global_guard,
                ip_guard,
                state,
                server_epoch,
                &nonce,
                target_mailbox_id,
                epoch,
                conn_id,
                dial_token,
            )
            .await;
        }
        RelayV2ClientMsg::Accept {
            mailbox_id,
            epoch,
            conn_id,
            sig,
        } => {
            handle_v2_accept(
                ws,
                global_guard,
                ip_guard,
                state,
                &canonical_host,
                server_epoch,
                &nonce,
                mailbox_id,
                epoch,
                conn_id,
                sig,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_register(
    mut ws: WebSocketStream<RelayTcpStream>,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    canonical_host: &str,
    server_epoch: u64,
    nonce: &[u8; 32],
    mailbox_id_b64: String,
    epoch: u64,
    sig_b64: String,
) {
    let (Ok(mailbox_id), Ok(sig)) = (
        b64url_decode_array::<32>(&mailbox_id_b64),
        b64url_decode_array::<64>(&sig_b64),
    ) else {
        send_v2_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };
    if !epoch_within_skew(server_epoch, epoch)
        || verify_v2_relay_register(&mailbox_id, epoch, canonical_host, nonce, &sig).is_err()
    {
        send_v2_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }

    let chan_cap = state
        .config
        .max_pending_per_mailbox
        .saturating_mul(2)
        .max(8);
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<IncomingV2Notification>(chan_cap);
    let reg_id_opt = {
        let mut tables = state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !tables.v2_mailboxes.contains_key(&mailbox_id)
            && tables.total_mailbox_count() >= state.config.max_mailboxes.max(1)
        {
            None
        } else {
            let reg_id = tables.alloc_id();
            tables.v2_mailboxes.insert(
                mailbox_id,
                MailboxV2Entry {
                    reg_id,
                    epoch,
                    incoming_tx,
                },
            );
            Some(reg_id)
        }
    };
    let Some(reg_id) = reg_id_opt else {
        send_v2_error_and_close(&mut ws, "capacity_exceeded", state.config.write_timeout).await;
        return;
    };
    let reg_guard = MailboxV2RegGuard {
        state: Arc::clone(&state),
        mailbox_id,
        reg_id,
    };

    if !send_json(
        &mut ws,
        &RelayV2ServerMsg::Registered {
            mailbox_id: mailbox_id_b64,
            epoch,
        },
        state.config.write_timeout,
    )
    .await
    {
        return;
    }

    let expire_secs = epoch
        .saturating_add(2)
        .saturating_mul(RELAY_V2_EPOCH_SECS)
        .saturating_sub(current_unix_secs());
    let epoch_expiry = tokio::time::sleep(Duration::from_secs(expire_secs));
    tokio::pin!(epoch_expiry);
    let idle_sleep = tokio::time::sleep(state.config.idle_timeout.max(Duration::from_millis(1)));
    tokio::pin!(idle_sleep);
    let mut awaiting_pong = false;

    loop {
        tokio::select! {
            () = &mut epoch_expiry => {
                break;
            }
            () = &mut idle_sleep => {
                if awaiting_pong {
                    break;
                }
                if !timeout(
                    state.config.write_timeout,
                    ws.send(Message::Ping(Vec::new().into())),
                )
                .await
                .is_ok_and(|res| res.is_ok())
                {
                    break;
                }
                awaiting_pong = true;
                idle_sleep
                    .as_mut()
                    .reset(TokioInstant::now() + state.config.accept_timeout.max(Duration::from_millis(1)));
            }
            maybe_note = incoming_rx.recv() => {
                let Some(note) = maybe_note else {
                    break;
                };
                if !send_json(
                    &mut ws,
                    &RelayV2ServerMsg::Incoming {
                        mailbox_id: note.mailbox_id,
                        epoch: note.epoch,
                        conn_id: note.conn_id,
                        dial_nonce: note.dial_nonce,
                        dial_token: note.dial_token,
                    },
                    state.config.write_timeout,
                )
                .await
                {
                    break;
                }
            }
            maybe_ws = ws.next() => {
                match maybe_ws {
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        awaiting_pong = false;
                        idle_sleep
                            .as_mut()
                            .reset(TokioInstant::now() + state.config.idle_timeout.max(Duration::from_millis(1)));
                    }
                    _ => break,
                }
            }
        }
    }
    drop(reg_guard);
    let _ = timeout(state.config.write_timeout, ws.close(None)).await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_dial(
    mut ws: WebSocketStream<RelayTcpStream>,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    server_epoch: u64,
    dial_nonce: &[u8; 32],
    target_mailbox_b64: String,
    epoch: u64,
    conn_id_b64: String,
    dial_token_b64: String,
) {
    let (Ok(target_mailbox), Ok(conn_id), Ok(_dial_token)) = (
        b64url_decode_array::<32>(&target_mailbox_b64),
        b64url_decode_array::<16>(&conn_id_b64),
        b64url_decode_array::<32>(&dial_token_b64),
    ) else {
        send_v2_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };
    if !epoch_within_skew(server_epoch, epoch) {
        send_v2_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
        return;
    }

    let (match_tx, mut match_rx) = oneshot::channel::<AcceptorV2Transfer>();
    let enqueue_res: Result<(mpsc::Sender<IncomingV2Notification>, u64), &'static str> = {
        let mut tables = state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mailbox) = tables.v2_mailboxes.get(&target_mailbox).cloned() {
            if mailbox.epoch != epoch {
                Err("offline")
            } else {
                let active_count = tables
                    .v2_active_per_mailbox
                    .get(&target_mailbox)
                    .copied()
                    .unwrap_or(0);
                let pending_count = tables
                    .v2_pending_counts
                    .get(&target_mailbox)
                    .copied()
                    .unwrap_or(0);
                if active_count >= state.config.max_active_per_mailbox
                    || pending_count >= state.config.max_pending_per_mailbox
                {
                    Err("rate_limited")
                } else if tables.v2_pending.contains_key(&conn_id) {
                    Err("invalid_request")
                } else {
                    let dial_id = tables.alloc_id();
                    *tables.v2_pending_counts.entry(target_mailbox).or_insert(0) += 1;
                    tables.v2_pending.insert(
                        conn_id,
                        PendingV2Dial {
                            dial_id,
                            target_mailbox,
                            epoch,
                            match_tx,
                        },
                    );
                    Ok((mailbox.incoming_tx, dial_id))
                }
            }
        } else {
            Err("offline")
        }
    };
    let (incoming_tx, dial_id) = match enqueue_res {
        Ok(pair) => pair,
        Err(code) => {
            send_v2_error_and_close(&mut ws, code, state.config.write_timeout).await;
            return;
        }
    };

    let _pending_guard = PendingV2DialGuard {
        state: Arc::clone(&state),
        target_mailbox,
        conn_id,
        dial_id,
    };

    let note = IncomingV2Notification {
        mailbox_id: target_mailbox_b64,
        epoch,
        conn_id: conn_id_b64.clone(),
        dial_nonce: b64url_encode(dial_nonce),
        dial_token: dial_token_b64,
    };
    match incoming_tx.try_send(note) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            send_v2_error_and_close(&mut ws, "rate_limited", state.config.write_timeout).await;
            return;
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            send_v2_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
            return;
        }
    }

    let accept_deadline = tokio::time::sleep(state.config.accept_timeout);
    tokio::pin!(accept_deadline);
    let acceptor = loop {
        tokio::select! {
            res = &mut match_rx => match res {
                Ok(transfer) => break transfer,
                Err(_) => {
                    send_v2_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
                    return;
                }
            },
            () = &mut accept_deadline => {
                send_v2_error_and_close(&mut ws, "timeout", state.config.write_timeout).await;
                return;
            }
            maybe_ws = ws.next() => {
                match maybe_ws {
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => return,
                }
            }
        }
    };

    if !send_json(
        &mut ws,
        &RelayV2ServerMsg::Ready {
            conn_id: conn_id_b64,
        },
        state.config.write_timeout,
    )
    .await
    {
        return;
    }

    bridge_streams(
        ws,
        acceptor.ws,
        state.config.write_timeout,
        state.config.idle_timeout,
    )
    .await;
    drop(acceptor._global_guard);
    drop(acceptor._ip_guard);
    drop(acceptor._stream_guard);
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_accept(
    mut ws: WebSocketStream<RelayTcpStream>,
    global_guard: GlobalConnGuard,
    ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    canonical_host: &str,
    server_epoch: u64,
    nonce: &[u8; 32],
    mailbox_id_b64: String,
    epoch: u64,
    conn_id_b64: String,
    sig_b64: String,
) {
    let (Ok(acceptor_mailbox), Ok(conn_id), Ok(sig)) = (
        b64url_decode_array::<32>(&mailbox_id_b64),
        b64url_decode_array::<16>(&conn_id_b64),
        b64url_decode_array::<64>(&sig_b64),
    ) else {
        send_v2_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };

    if !epoch_within_skew(server_epoch, epoch)
        || verify_v2_relay_accept(
            &acceptor_mailbox,
            epoch,
            canonical_host,
            nonce,
            &conn_id,
            &sig,
        )
        .is_err()
    {
        send_v2_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }

    enum ClaimResult {
        Claimed {
            target_mailbox: [u8; 32],
            match_tx: oneshot::Sender<AcceptorV2Transfer>,
        },
        NotFound,
        WrongOwner,
        RateLimited,
    }

    let claim = {
        let mut tables = state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match tables.v2_pending.get(&conn_id) {
            None => ClaimResult::NotFound,
            Some(entry) if entry.target_mailbox != acceptor_mailbox || entry.epoch != epoch => {
                ClaimResult::WrongOwner
            }
            Some(entry) => {
                let active_count = tables
                    .v2_active_per_mailbox
                    .get(&entry.target_mailbox)
                    .copied()
                    .unwrap_or(0);
                if active_count >= state.config.max_active_per_mailbox {
                    ClaimResult::RateLimited
                } else {
                    let pending = tables
                        .v2_pending
                        .remove(&conn_id)
                        .expect("checked Some above");
                    decrement_count(&mut tables.v2_pending_counts, &pending.target_mailbox);
                    *tables
                        .v2_active_per_mailbox
                        .entry(pending.target_mailbox)
                        .or_insert(0) += 1;
                    ClaimResult::Claimed {
                        target_mailbox: pending.target_mailbox,
                        match_tx: pending.match_tx,
                    }
                }
            }
        }
    };

    let (target_mailbox, match_tx) = match claim {
        ClaimResult::Claimed {
            target_mailbox,
            match_tx,
        } => (target_mailbox, match_tx),
        ClaimResult::NotFound => {
            send_v2_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
            return;
        }
        ClaimResult::WrongOwner => {
            send_v2_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
            return;
        }
        ClaimResult::RateLimited => {
            send_v2_error_and_close(&mut ws, "rate_limited", state.config.write_timeout).await;
            return;
        }
    };

    let stream_guard = MailboxV2StreamGuard {
        state: Arc::clone(&state),
        mailbox_id: target_mailbox,
    };

    if !send_json(
        &mut ws,
        &RelayV2ServerMsg::Ready {
            conn_id: conn_id_b64,
        },
        state.config.write_timeout,
    )
    .await
    {
        return;
    }

    let _ = match_tx.send(AcceptorV2Transfer {
        ws,
        _global_guard: global_guard,
        _ip_guard: ip_guard,
        _stream_guard: stream_guard,
    });
}

async fn bridge_streams(
    dialer_ws: WebSocketStream<RelayTcpStream>,
    acceptor_ws: WebSocketStream<RelayTcpStream>,
    write_timeout: Duration,
    idle_timeout: Duration,
) {
    let (mut dialer_tx, mut dialer_rx) = dialer_ws.split();
    let (mut acceptor_tx, mut acceptor_rx) = acceptor_ws.split();
    let start = Instant::now();
    let last_activity_ms = Arc::new(AtomicU64::new(0));

    let activity_a = Arc::clone(&last_activity_ms);
    let forward_a_to_b = async move {
        while let Some(item) = dialer_rx.next().await {
            let Ok(msg) = item else {
                break;
            };
            match msg {
                Message::Binary(data) => {
                    if data.is_empty() || data.len() > MAX_RELAY_FRAME_LEN {
                        break;
                    }
                    let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    activity_a.store(elapsed, Ordering::Relaxed);
                    if !timeout(write_timeout, acceptor_tx.send(Message::Binary(data)))
                        .await
                        .is_ok_and(|res| res.is_ok())
                    {
                        break;
                    }
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) | Message::Close(_) | Message::Frame(_) => break,
            }
        }
    };

    let activity_b = Arc::clone(&last_activity_ms);
    let forward_b_to_a = async move {
        while let Some(item) = acceptor_rx.next().await {
            let Ok(msg) = item else {
                break;
            };
            match msg {
                Message::Binary(data) => {
                    if data.is_empty() || data.len() > MAX_RELAY_FRAME_LEN {
                        break;
                    }
                    let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    activity_b.store(elapsed, Ordering::Relaxed);
                    if !timeout(write_timeout, dialer_tx.send(Message::Binary(data)))
                        .await
                        .is_ok_and(|res| res.is_ok())
                    {
                        break;
                    }
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) | Message::Close(_) | Message::Frame(_) => break,
            }
        }
    };

    let idle_ms = u64::try_from(idle_timeout.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    let idle_watchdog = async move {
        loop {
            let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let last_ms = last_activity_ms.load(Ordering::Relaxed);
            let elapsed_since = now_ms.saturating_sub(last_ms);
            if elapsed_since >= idle_ms {
                break;
            }
            let remaining = idle_ms - elapsed_since;
            tokio::time::sleep(Duration::from_millis(remaining)).await;
        }
    };

    tokio::select! {
        _ = forward_a_to_b => {}
        _ = forward_b_to_a => {}
        _ = idle_watchdog => {}
    }
}

/// Helper for client-side WebSocket connectors to distinguish TCP vs TLS streams cleanly.
pub type ClientWsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
