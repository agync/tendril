//! Stateless async WebSocket relay server implementing `spec/relay-v1.md` and `spec/relay-v2.md`.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tendril_core::crypto::{
    b64url_decode_array, b64url_encode, is_valid_ed25519_public_key, random_bytes,
};
use tendril_core::relay_auth::{
    RELAY_TICKET_CLOCK_SKEW_SECS, RelayAuthProof, RelayAuthRole, RelayAuthScope,
    validate_relay_auth_secret, verify_relay_auth_hmac, verify_relay_ticket,
};
use tendril_core::v2::{
    RELAY_V2_EPOCH_SECS, canonical_relay_host, epoch_for_unix, epoch_within_skew,
    verify_v2_relay_accept, verify_v2_relay_register,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, timeout, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderMap, StatusCode};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use zeroize::Zeroizing;

use crate::protocol::{
    MAX_RELAY_FRAME_LEN, MAX_STANDBY_PER_MAILBOX, RELAY_HEALTH_PATH, RELAY_PATH, RELAY_V2_PATH,
    RelayClientMsg, RelayServerMsg, RelayV2ClientMsg, RelayV2ServerMsg, decode_init_frame,
    verify_relay_accept, verify_relay_register,
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

/// Maximum byte size accepted for `--auth-secret-file`.
pub const MAX_AUTH_SECRET_FILE_BYTES: usize = 16 * 1024;
/// Maximum byte size accepted for `--tls-key`.
pub const MAX_TLS_KEY_FILE_BYTES: usize = 256 * 1024;

/// Reads a private key or secret file after verifying it is a regular non-symlink file
/// within `max_bytes` and, on Unix, has owner-only permissions (`mode & 0o077 == 0`).
pub fn read_private_file(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let sym_meta = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat {label} '{}': {err}", path.display()))?;
    if sym_meta.file_type().is_symlink() {
        return Err(format!(
            "{label} '{}' must not be a symlink",
            path.display()
        ));
    }
    if !sym_meta.file_type().is_file() {
        return Err(format!(
            "{label} '{}' must be a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (sym_meta.mode() & 0o077) != 0 {
            return Err(format!(
                "{label} '{}' must have owner-only permissions (0600 or stricter)",
                path.display()
            ));
        }
    }
    if sym_meta.len() > max_bytes as u64 {
        return Err(format!(
            "{label} '{}' exceeds maximum size of {max_bytes} bytes",
            path.display()
        ));
    }

    let file = std::fs::File::open(path)
        .map_err(|err| format!("failed to open {label} '{}': {err}", path.display()))?;
    let fd_meta = file
        .metadata()
        .map_err(|err| format!("failed to stat open {label} '{}': {err}", path.display()))?;
    if !fd_meta.file_type().is_file() {
        return Err(format!(
            "{label} '{}' must be a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (fd_meta.mode() & 0o077) != 0 {
            return Err(format!(
                "{label} '{}' must have owner-only permissions (0600 or stricter)",
                path.display()
            ));
        }
        if fd_meta.dev() != sym_meta.dev() || fd_meta.ino() != sym_meta.ino() {
            return Err(format!("{label} '{}' changed during open", path.display()));
        }
    }
    if fd_meta.len() > max_bytes as u64 {
        return Err(format!(
            "{label} '{}' exceeds maximum size of {max_bytes} bytes",
            path.display()
        ));
    }

    let mut buf = Zeroizing::new(Vec::new());
    let limit = (max_bytes as u64).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut buf)
        .map_err(|err| format!("failed to read {label} '{}': {err}", path.display()))?;
    if buf.len() > max_bytes {
        return Err(format!(
            "{label} '{}' exceeds maximum size of {max_bytes} bytes",
            path.display()
        ));
    }
    Ok(buf)
}

/// Header inspected when extracting the client IP from a trusted reverse proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustedProxyHeader {
    #[default]
    Xff,
    Forwarded,
}

/// Configuration for [`RelayServer`].
#[derive(Clone)]
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
    pub pong_timeout: Duration,
    pub write_timeout: Duration,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub trusted_proxies: Vec<IpCidr>,
    pub trusted_proxy_header: TrustedProxyHeader,
    pub allowed_mailboxes: Vec<[u8; 32]>,
    pub auth_secret: Option<Zeroizing<Vec<u8>>>,
    pub trusted_issuers: Vec<[u8; 32]>,
    /// Option 1A scope. [`RelayServer::bind`] rejects [`RelayAuthScope::All`] when a mailbox
    /// allowlist is the only admission control, since no proof could then admit a `dial`.
    pub auth_scope: RelayAuthScope,
    /// Test-only clock seam overriding wall-clock Unix seconds for deterministic expiry tests.
    pub clock: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
    /// Test-only seam awaited at each [`RelayTestPoint`] so tests can order racing handlers.
    #[doc(hidden)]
    pub test_hook: Option<RelayTestHook>,
}

/// Points at which the relay awaits [`RelayConfig::test_hook`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayTestPoint {
    /// An `accept` claimed a pending dial and has not answered either socket yet.
    AcceptClaimed,
    /// A pending dial saw its control connection end or its accept deadline pass.
    DialTeardown,
    /// A registration reached its admission deadline and has not been torn down yet.
    RegistrationExpired,
    /// A parked standby socket reached its admission deadline and has not closed yet.
    StandbyExpired,
}

/// Hook type of [`RelayConfig::test_hook`].
#[doc(hidden)]
pub type RelayTestHook =
    Arc<dyn Fn(RelayTestPoint) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

impl fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayConfig")
            .field("listen_addr", &self.listen_addr)
            .field("host", &self.host)
            .field("max_pending_per_mailbox", &self.max_pending_per_mailbox)
            .field("max_active_per_ip", &self.max_active_per_ip)
            .field("max_active_per_mailbox", &self.max_active_per_mailbox)
            .field("max_total_connections", &self.max_total_connections)
            .field("max_mailboxes", &self.max_mailboxes)
            .field("max_tracked_ips", &self.max_tracked_ips)
            .field("ip_burst_capacity", &self.ip_burst_capacity)
            .field("ip_refill_per_sec", &self.ip_refill_per_sec)
            .field("accept_timeout", &self.accept_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("pong_timeout", &self.pong_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("trusted_proxy_header", &self.trusted_proxy_header)
            .field("allowed_mailboxes", &self.allowed_mailboxes.len())
            .field(
                "auth_secret",
                &self.auth_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("trusted_issuers", &self.trusted_issuers.len())
            .field("auth_scope", &self.auth_scope)
            .field("clock", &self.clock.as_ref().map(|_| "<clock>"))
            .field("test_hook", &self.test_hook.as_ref().map(|_| "<hook>"))
            .finish()
    }
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
            pong_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(1),
            tls_cert_path: None,
            tls_key_path: None,
            trusted_proxies: Vec::new(),
            trusted_proxy_header: TrustedProxyHeader::default(),
            allowed_mailboxes: Vec::new(),
            auth_secret: None,
            trusted_issuers: Vec::new(),
            auth_scope: RelayAuthScope::All,
            clock: None,
            test_hook: None,
        }
    }
}

impl RelayConfig {
    fn has_tier2_or_3(&self) -> bool {
        self.auth_secret.is_some() || !self.trusted_issuers.is_empty()
    }

    fn requires_register_admission(&self) -> bool {
        !self.allowed_mailboxes.is_empty() || self.has_tier2_or_3()
    }

    fn requires_dial_admission(&self) -> bool {
        self.has_tier2_or_3() && self.auth_scope.includes_dial()
    }

    fn challenge_auth_required(&self) -> Option<Vec<String>> {
        if !self.requires_register_admission() {
            return None;
        }
        if self.requires_dial_admission() {
            Some(vec!["register".to_owned(), "dial".to_owned()])
        } else {
            Some(vec!["register".to_owned()])
        }
    }

    fn now_unix_secs(&self) -> u64 {
        self.clock
            .as_ref()
            .map_or_else(current_unix_secs, |clock| clock())
    }

    async fn test_point(&self, point: RelayTestPoint) {
        if let Some(hook) = &self.test_hook {
            hook(point).await;
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
struct IncomingV1Notification {
    conn_id: String,
    init_frame: Option<String>,
}

#[derive(Clone)]
struct MailboxEntry {
    reg_id: u64,
    fast_open: bool,
    incoming_tx: mpsc::Sender<IncomingV1Notification>,
    /// Notified when the relay ends this registration from another handler.
    ended: Arc<Notify>,
    /// Set before `ended` is notified when a live registration was displaced by a newer one.
    displaced: Arc<AtomicBool>,
    /// Unix second from which this registration has expired, if its admission bounds it.
    deadline_unix: Option<u64>,
}

#[derive(Clone)]
struct IncomingV2Notification {
    mailbox_id: String,
    epoch: u64,
    conn_id: String,
    dial_nonce: String,
    dial_token: String,
    init_frame: Option<String>,
}

#[derive(Clone)]
struct MailboxV2Entry {
    reg_id: u64,
    epoch: u64,
    fast_open: bool,
    incoming_tx: mpsc::Sender<IncomingV2Notification>,
    /// Notified when the relay ends this registration from another handler.
    ended: Arc<Notify>,
    /// Set before `ended` is notified when a live registration was displaced by a newer one.
    displaced: Arc<AtomicBool>,
    /// Unix second from which this registration has expired.
    deadline_unix: Option<u64>,
}

struct PendingDial {
    dial_id: u64,
    reg_id: u64,
    target_pub: [u8; 32],
    match_tx: oneshot::Sender<AcceptorTransfer>,
}

struct PendingV2Dial {
    dial_id: u64,
    reg_id: u64,
    target_mailbox: [u8; 32],
    epoch: u64,
    match_tx: oneshot::Sender<AcceptorTransfer>,
}

type RelayWsStream = WebSocketStream<PrefixedStream<RelayTcpStream>>;

struct AcceptorTransfer {
    ws: RelayWsStream,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    _stream_guard: MailboxStreamGuard,
}

struct StandbyDispatch<N> {
    notification: N,
    stream_guard: MailboxStreamGuard,
    transfer_tx: oneshot::Sender<AcceptorTransfer>,
}

struct StandbySlot<N> {
    id: u64,
    reg_id: u64,
    deadline_unix: Option<u64>,
    dispatch_tx: oneshot::Sender<StandbyDispatch<N>>,
}

impl<N> StandbySlot<N> {
    /// Reports whether this slot can still take a dial for registration `reg_id` at `now_unix`.
    fn usable(&self, reg_id: u64, now_unix: u64) -> bool {
        self.reg_id == reg_id
            && !self.dispatch_tx.is_closed()
            && !deadline_passed(self.deadline_unix, now_unix)
    }
}

fn deadline_passed(deadline_unix: Option<u64>, now_unix: u64) -> bool {
    deadline_unix.is_some_and(|deadline| now_unix >= deadline)
}

struct RelayTables {
    next_id: u64,
    mailboxes: HashMap<[u8; 32], MailboxEntry>,
    standby: HashMap<[u8; 32], VecDeque<StandbySlot<IncomingV1Notification>>>,
    pending: HashMap<[u8; 16], PendingDial>,
    pending_counts: HashMap<[u8; 32], usize>,
    active_per_mailbox: HashMap<[u8; 32], usize>,
    v2_mailboxes: HashMap<[u8; 32], MailboxV2Entry>,
    v2_standby: HashMap<[u8; 32], VecDeque<StandbySlot<IncomingV2Notification>>>,
    v2_pending: HashMap<[u8; 16], PendingV2Dial>,
    v2_pending_counts: HashMap<[u8; 32], usize>,
    v2_active_per_mailbox: HashMap<[u8; 32], usize>,
}

impl RelayTables {
    fn new() -> Self {
        Self {
            next_id: 1,
            mailboxes: HashMap::new(),
            standby: HashMap::new(),
            pending: HashMap::new(),
            pending_counts: HashMap::new(),
            active_per_mailbox: HashMap::new(),
            v2_mailboxes: HashMap::new(),
            v2_standby: HashMap::new(),
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

    /// Ends `/v1/relay` registration `reg_id` of `key`: removes it if it is still current, its
    /// parked standby sockets, and its pending dials. Dropping a pending dial's `match_tx` fails
    /// that dial with `offline`.
    fn end_v1_registration(&mut self, key: &[u8; 32], reg_id: u64) {
        if self
            .mailboxes
            .get(key)
            .is_some_and(|entry| entry.reg_id == reg_id)
        {
            self.mailboxes.remove(key);
            self.standby.remove(key);
        }
        let before = self.pending.len();
        self.pending
            .retain(|_, dial| !(dial.target_pub == *key && dial.reg_id == reg_id));
        for _ in self.pending.len()..before {
            decrement_count(&mut self.pending_counts, key);
        }
    }

    /// Ends every registration whose deadline has passed at `now_unix`, signalling each owner
    /// to close without `replaced`.
    fn purge_expired(&mut self, now_unix: u64) {
        let v1: Vec<_> = self
            .mailboxes
            .iter()
            .filter(|(_, entry)| deadline_passed(entry.deadline_unix, now_unix))
            .map(|(key, entry)| (*key, entry.reg_id, Arc::clone(&entry.ended)))
            .collect();
        for (key, reg_id, ended) in v1 {
            ended.notify_one();
            self.end_v1_registration(&key, reg_id);
        }
        let v2: Vec<_> = self
            .v2_mailboxes
            .iter()
            .filter(|(_, entry)| deadline_passed(entry.deadline_unix, now_unix))
            .map(|(key, entry)| (*key, entry.reg_id, Arc::clone(&entry.ended)))
            .collect();
        for (key, reg_id, ended) in v2 {
            ended.notify_one();
            self.end_v2_registration(&key, reg_id);
        }
    }

    /// `/v2/relay` counterpart of [`Self::end_v1_registration`].
    fn end_v2_registration(&mut self, key: &[u8; 32], reg_id: u64) {
        if self
            .v2_mailboxes
            .get(key)
            .is_some_and(|entry| entry.reg_id == reg_id)
        {
            self.v2_mailboxes.remove(key);
            self.v2_standby.remove(key);
        }
        let before = self.v2_pending.len();
        self.v2_pending
            .retain(|_, dial| !(dial.target_mailbox == *key && dial.reg_id == reg_id));
        for _ in self.v2_pending.len()..before {
            decrement_count(&mut self.v2_pending_counts, key);
        }
    }
}

struct RelayState {
    config: RelayConfig,
    limiter: Mutex<IpTokenLimiter>,
    active_connections: AtomicUsize,
    pre_upgrade_semaphore: Arc<Semaphore>,
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
        let pre_upgrade_cap = (config.max_total_connections / 4).max(1);
        Self {
            config,
            limiter: Mutex::new(limiter),
            active_connections: AtomicUsize::new(0),
            pre_upgrade_semaphore: Arc::new(Semaphore::new(pre_upgrade_cap)),
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
        let mut tables = self
            .state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tables.end_v1_registration(&self.mailbox_pub, self.reg_id);
    }
}

struct PendingDialGuard {
    state: Arc<RelayState>,
    target_pub: [u8; 32],
    conn_id: [u8; 16],
    dial_id: u64,
}

impl PendingDialGuard {
    /// Withdraws this dial unless an `accept` already claimed it; returns whether it withdrew.
    fn withdraw(&self) -> bool {
        let mut tables = self.state.tables.lock().expect("tables mutex poisoned");
        let matches = tables
            .pending
            .get(&self.conn_id)
            .is_some_and(|p| p.dial_id == self.dial_id);
        if matches {
            tables.pending.remove(&self.conn_id);
            decrement_count(&mut tables.pending_counts, &self.target_pub);
        }
        matches
    }
}

impl Drop for PendingDialGuard {
    fn drop(&mut self) {
        self.withdraw();
    }
}

struct MailboxStreamGuard {
    state: Arc<RelayState>,
    key: [u8; 32],
    is_v2: bool,
}

impl Drop for MailboxStreamGuard {
    fn drop(&mut self) {
        let mut tables = self
            .state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let map = if self.is_v2 {
            &mut tables.v2_active_per_mailbox
        } else {
            &mut tables.active_per_mailbox
        };
        decrement_count(map, &self.key);
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
        tables.end_v2_registration(&self.mailbox_id, self.reg_id);
    }
}

struct PendingV2DialGuard {
    state: Arc<RelayState>,
    target_mailbox: [u8; 32],
    conn_id: [u8; 16],
    dial_id: u64,
}

impl PendingV2DialGuard {
    /// Withdraws this dial unless an `accept` already claimed it; returns whether it withdrew.
    fn withdraw(&self) -> bool {
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
        matches
    }
}

impl Drop for PendingV2DialGuard {
    fn drop(&mut self) {
        self.withdraw();
    }
}

struct StandbySlotGuard {
    state: Arc<RelayState>,
    key: [u8; 32],
    standby_id: u64,
    is_v2: bool,
}

fn remove_standby_slot<N>(
    pool_map: &mut HashMap<[u8; 32], VecDeque<StandbySlot<N>>>,
    key: &[u8; 32],
    standby_id: u64,
) {
    if let Some(pool) = pool_map.get_mut(key) {
        pool.retain(|slot| slot.id != standby_id);
        if pool.is_empty() {
            pool_map.remove(key);
        }
    }
}

impl Drop for StandbySlotGuard {
    fn drop(&mut self) {
        let mut tables = self
            .state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_v2 {
            remove_standby_slot(&mut tables.v2_standby, &self.key, self.standby_id);
        } else {
            remove_standby_slot(&mut tables.standby, &self.key, self.standby_id);
        }
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
        for (label, keys) in [
            ("allowed_mailboxes", &config.allowed_mailboxes),
            ("trusted_issuers", &config.trusted_issuers),
        ] {
            if !keys.iter().all(is_valid_ed25519_public_key) {
                return Err(RelayError::InvalidConfig(format!(
                    "{label} must contain only valid Ed25519 public keys"
                )));
            }
        }
        if !config.allowed_mailboxes.is_empty()
            && !config.has_tier2_or_3()
            && config.auth_scope.includes_dial()
        {
            return Err(RelayError::InvalidConfig(
                "auth_scope all needs a shared secret or trusted issuers; a mailbox allowlist \
                 alone admits only register"
                    .to_owned(),
            ));
        }
        if let Some(secret) = &config.auth_secret {
            validate_relay_auth_secret(secret)
                .map_err(|err| RelayError::InvalidConfig(err.to_string()))?;
        }
        if config.has_tier2_or_3() {
            canonical_relay_host(&config.host)
                .map_err(|err| RelayError::InvalidConfig(err.to_string()))?;
        }
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
                let key_bytes = read_private_file(key_path, MAX_TLS_KEY_FILE_BYTES, "tls-key")
                    .map_err(RelayError::Tls)?;
                let key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    RelayError::Tls(format!("parse private key '{}': {e}", key_path.display()))
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
                            let (ip_guard, pre_upgrade_permit) = if from_trusted_proxy {
                                let Ok(permit) =
                                    self.state.pre_upgrade_semaphore.clone().try_acquire_owned()
                                else {
                                    tracing::debug!(
                                        ip = %peer_ip,
                                        "rejected trusted-proxy connection at pre-upgrade cap"
                                    );
                                    drop(stream);
                                    continue;
                                };
                                (None, Some(permit))
                            } else {
                                let Some(guard) = self.state.try_acquire_ip(peer_ip) else {
                                    tracing::debug!(ip = %peer_ip, "rejected relay connection by rate/ip cap");
                                    drop(stream);
                                    continue;
                                };
                                (Some(guard), None)
                            };
                            let state = Arc::clone(&self.state);
                            let tls = self.tls_acceptor.clone();
                            tokio::spawn(async move {
                                handle_connection(
                                    stream,
                                    peer_ip,
                                    global_guard,
                                    ip_guard,
                                    pre_upgrade_permit,
                                    tls,
                                    state,
                                )
                                .await;
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
    ws: &mut WebSocketStream<PrefixedStream<RelayTcpStream>>,
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
    ws: &mut WebSocketStream<PrefixedStream<RelayTcpStream>>,
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
    close_after_error(ws, write_timeout).await;
}

async fn send_v2_error_and_close(
    ws: &mut WebSocketStream<PrefixedStream<RelayTcpStream>>,
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
    close_after_error(ws, write_timeout).await;
}

/// Closes `ws` and briefly reads what the peer still sends, so the error frame written just
/// before is not discarded by a reset when unread input is pending at close.
async fn close_after_error(
    ws: &mut WebSocketStream<PrefixedStream<RelayTcpStream>>,
    write_timeout: Duration,
) {
    const ERROR_DRAIN: Duration = Duration::from_millis(250);
    let _ = timeout(write_timeout, ws.close(None)).await;
    let _ = timeout(ERROR_DRAIN, async {
        while let Some(Ok(_)) = ws.next().await {}
    })
    .await;
}

fn is_mailbox_allowlisted(config: &RelayConfig, key: &[u8; 32]) -> bool {
    config
        .allowed_mailboxes
        .iter()
        .any(|allowed| bool::from(allowed.ct_eq(key)))
}

fn verify_admission_proof(
    config: &RelayConfig,
    op: &str,
    role: RelayAuthRole,
    nonce: &[u8; 32],
    target_key: &[u8; 32],
    auth: Option<&RelayAuthProof>,
) -> bool {
    let Some(proof) = auth else {
        return false;
    };
    match proof {
        RelayAuthProof::Hmac { mac } => {
            let Some(secret) = config.auth_secret.as_ref() else {
                return false;
            };
            verify_relay_auth_hmac(secret.as_slice(), op, &config.host, nonce, target_key, mac)
                .is_ok()
        }
        RelayAuthProof::Ticket { ticket } => {
            if config.trusted_issuers.is_empty() {
                return false;
            }
            verify_relay_ticket(
                ticket,
                &config.trusted_issuers,
                &config.host,
                role,
                target_key,
                config.now_unix_secs(),
            )
            .is_ok()
        }
    }
}

fn verify_register_or_accept_admission(
    config: &RelayConfig,
    op: &str,
    nonce: &[u8; 32],
    mailbox_key: &[u8; 32],
    auth: Option<&RelayAuthProof>,
) -> bool {
    if !config.requires_register_admission() {
        return true;
    }
    if is_mailbox_allowlisted(config, mailbox_key) {
        return true;
    }
    verify_admission_proof(
        config,
        op,
        RelayAuthRole::Register,
        nonce,
        mailbox_key,
        auth,
    )
}

fn verify_dial_admission(
    config: &RelayConfig,
    nonce: &[u8; 32],
    target_key: &[u8; 32],
    auth: Option<&RelayAuthProof>,
) -> bool {
    if !config.requires_dial_admission() {
        return true;
    }
    verify_admission_proof(config, "dial", RelayAuthRole::Dial, nonce, target_key, auth)
}

/// Returns the Unix second at which an admitted `register` or `standby` stops being valid: the
/// first second after `not_after + RELAY_TICKET_CLOCK_SKEW_SECS` when a ticket admitted it.
fn admission_deadline_unix(
    config: &RelayConfig,
    mailbox_key: &[u8; 32],
    auth: Option<&RelayAuthProof>,
) -> Option<u64> {
    if !config.requires_register_admission() || is_mailbox_allowlisted(config, mailbox_key) {
        return None;
    }
    match auth {
        Some(RelayAuthProof::Ticket { ticket }) => Some(
            ticket
                .not_after
                .saturating_add(RELAY_TICKET_CLOCK_SKEW_SECS)
                .saturating_add(1),
        ),
        _ => None,
    }
}

/// Unix second at which a `/v2/relay` registration for `epoch` rotates out of the window.
fn v2_epoch_deadline_unix(epoch: u64) -> u64 {
    epoch.saturating_add(2).saturating_mul(RELAY_V2_EPOCH_SECS)
}

/// Earliest of two optional Unix deadlines.
fn earliest_deadline(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Resolves once the relay clock reaches `deadline_unix`, or never when it is `None`.
async fn unix_deadline(config: &RelayConfig, deadline_unix: Option<u64>) {
    let Some(deadline) = deadline_unix else {
        return std::future::pending().await;
    };
    if config.clock.is_some() {
        let mut poll = tokio::time::interval(Duration::from_millis(20));
        poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
        while config.now_unix_secs() < deadline {
            poll.tick().await;
        }
        return;
    }
    // Sleep in short chunks against the sub-second wall clock so neither second truncation
    // nor a wall-clock jump delays the deadline by more than one chunk.
    let deadline_ms = u128::from(deadline).saturating_mul(1000);
    loop {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let Some(left_ms) = deadline_ms.checked_sub(now_ms).filter(|left| *left > 0) else {
            return;
        };
        let chunk = u64::try_from(left_ms.min(1000)).unwrap_or(1000);
        tokio::time::sleep(Duration::from_millis(chunk)).await;
    }
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
    trusted_header: TrustedProxyHeader,
    peer_ip: IpAddr,
) -> IpAddr {
    let mut candidates = Vec::new();
    match trusted_header {
        TrustedProxyHeader::Forwarded => {
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
        }
        TrustedProxyHeader::Xff => {
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
    }
    for ip in candidates.into_iter().rev() {
        if !trusted_proxies.iter().any(|cidr| cidr.contains(ip)) {
            return ip;
        }
    }
    peer_ip
}

const MAX_HTTP_HEAD_BYTES: usize = 8192;

#[derive(Clone, Copy, PartialEq, Eq)]
enum HealthMethod {
    Get,
    Head,
}

struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let avail = &this.prefix[this.pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn find_header_end(buf: &[u8], start_search: usize) -> Option<usize> {
    buf[start_search..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|rel| start_search + rel)
}

fn parse_plain_healthz_request(head: &[u8]) -> Option<HealthMethod> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = match parts.next()? {
        "GET" => HealthMethod::Get,
        "HEAD" => HealthMethod::Head,
        _ => return None,
    };
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || target != RELAY_HEALTH_PATH
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return None;
    }
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_whitespace()) {
            return None;
        }
        if name.eq_ignore_ascii_case("upgrade") || name.eq_ignore_ascii_case("sec-websocket-key") {
            return None;
        }
        if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        {
            return None;
        }
    }
    Some(method)
}

async fn write_healthz_response(
    io: &mut RelayTcpStream,
    method: HealthMethod,
    write_timeout: Duration,
) {
    let payload: &[u8] = match method {
        HealthMethod::Get => {
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nok"
        }
        HealthMethod::Head => {
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        }
    };
    let _ = timeout(write_timeout, async {
        io.write_all(payload).await?;
        io.flush().await?;
        io.shutdown().await
    })
    .await;
}

async fn handle_connection(
    stream: TcpStream,
    peer_ip: IpAddr,
    global_guard: GlobalConnGuard,
    pre_acquired_ip: Option<IpConnGuard>,
    pre_upgrade_permit: Option<OwnedSemaphorePermit>,
    tls_acceptor: Option<TlsAcceptor>,
    state: Arc<RelayState>,
) {
    let _ = stream.set_nodelay(true);
    let upgrade_timeout = Duration::from_secs(5).min(state.config.accept_timeout);
    let mut io_stream = match tls_acceptor {
        Some(acceptor) => match timeout(upgrade_timeout, acceptor.accept(stream)).await {
            Ok(Ok(tls_stream)) => RelayTcpStream::Tls(Box::new(tls_stream)),
            Ok(Err(_)) | Err(_) => return,
        },
        None => RelayTcpStream::Plain(stream),
    };

    const MAX_CONTROL_WS_MSG_LEN: usize = 128 * 1024;
    let upgrade_deadline = TokioInstant::now() + upgrade_timeout;
    let mut head_buf = Vec::new();
    let mut head_end = None;
    while head_buf.len() < MAX_HTTP_HEAD_BYTES {
        let prev_len = head_buf.len();
        let mut chunk = [0u8; 1024];
        let max_read = (MAX_HTTP_HEAD_BYTES - prev_len).min(chunk.len());
        let Ok(Ok(n)) = timeout_at(upgrade_deadline, io_stream.read(&mut chunk[..max_read])).await
        else {
            return;
        };
        if n == 0 {
            return;
        }
        head_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&head_buf, prev_len.saturating_sub(3)) {
            head_end = Some(pos);
            break;
        }
    }

    if let Some(end) = head_end
        && let Some(method) = parse_plain_healthz_request(&head_buf[..end])
    {
        write_healthz_response(&mut io_stream, method, state.config.write_timeout).await;
        return;
    }

    let prefixed_stream = PrefixedStream::new(head_buf, io_stream);
    let ws_config = WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_CONTROL_WS_MSG_LEN * 2)
        .max_message_size(Some(MAX_CONTROL_WS_MSG_LEN))
        .max_frame_size(Some(MAX_CONTROL_WS_MSG_LEN));

    let extracted_ip = Arc::new(Mutex::new(None::<IpAddr>));
    let matched_version = Arc::new(Mutex::new(None::<RelayProtocolVersion>));
    let extract_trusted = pre_acquired_ip.is_none();
    let trusted_proxies = state.config.trusted_proxies.clone();
    let trusted_header = state.config.trusted_proxy_header;
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
            let resolved =
                extract_trusted_client_ip(req.headers(), &trusted_proxies, trusted_header, peer_ip);
            *extracted_slot.lock().expect("extracted_ip mutex poisoned") = Some(resolved);
        }
        Ok(resp)
    };

    let Ok(Ok(mut ws)) = timeout_at(
        upgrade_deadline,
        accept_hdr_async_with_config(prefixed_stream, validate_req, Some(ws_config)),
    )
    .await
    else {
        return;
    };
    drop(pre_upgrade_permit);

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
        auth_required: state.config.challenge_auth_required(),
        fast_open: Some(true),
        standby: Some(true),
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
        RelayClientMsg::Register {
            pub_key,
            sig,
            auth,
            fast_open,
        } => {
            handle_register(
                ws,
                global_guard,
                ip_guard,
                state,
                &nonce,
                pub_key,
                sig,
                auth,
                fast_open.unwrap_or(false),
            )
            .await;
        }
        RelayClientMsg::Standby { pub_key, sig, auth } => {
            handle_standby(
                ws,
                global_guard,
                ip_guard,
                state,
                &nonce,
                pub_key,
                sig,
                auth,
            )
            .await;
        }
        RelayClientMsg::Dial {
            target_pub,
            conn_id,
            auth,
            init_frame,
        } => {
            handle_dial(
                ws,
                global_guard,
                ip_guard,
                state,
                &nonce,
                target_pub,
                conn_id,
                auth,
                init_frame,
            )
            .await;
        }
        RelayClientMsg::Accept {
            pub_key,
            conn_id,
            sig,
            auth,
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
                auth,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_register(
    mut ws: RelayWsStream,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    nonce: &[u8; 32],
    pub_key_b64: String,
    sig_b64: String,
    auth: Option<RelayAuthProof>,
    fast_open: bool,
) {
    let Ok(mailbox_pub) = verify_relay_register(&pub_key_b64, &sig_b64, &state.config.host, nonce)
    else {
        send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    };
    if !verify_register_or_accept_admission(
        &state.config,
        "register",
        nonce,
        &mailbox_pub,
        auth.as_ref(),
    ) {
        send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }
    let deadline = admission_deadline_unix(&state.config, &mailbox_pub, auth.as_ref());

    let chan_cap = state
        .config
        .max_pending_per_mailbox
        .saturating_mul(2)
        .max(8);
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<IncomingV1Notification>(chan_cap);
    let ended = Arc::new(Notify::new());
    let displaced = Arc::new(AtomicBool::new(false));
    let reg_id_opt = {
        let now = state.config.now_unix_secs();
        let mut tables = state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let max_mailboxes = state.config.max_mailboxes.max(1);
        if !tables.mailboxes.contains_key(&mailbox_pub)
            && tables.total_mailbox_count() >= max_mailboxes
        {
            tables.purge_expired(now);
        }
        if !tables.mailboxes.contains_key(&mailbox_pub)
            && tables.total_mailbox_count() >= max_mailboxes
        {
            None
        } else {
            let reg_id = tables.alloc_id();
            tables.standby.remove(&mailbox_pub);
            let previous = tables.mailboxes.insert(
                mailbox_pub,
                MailboxEntry {
                    reg_id,
                    fast_open,
                    incoming_tx,
                    ended: Arc::clone(&ended),
                    displaced: Arc::clone(&displaced),
                    deadline_unix: deadline,
                },
            );
            if let Some(previous) = previous {
                // An expired registration is ended quietly; only a live one is displaced.
                if !deadline_passed(previous.deadline_unix, now) {
                    previous.displaced.store(true, Ordering::Release);
                }
                previous.ended.notify_one();
                tables.end_v1_registration(&mailbox_pub, previous.reg_id);
            }
            Some(reg_id)
        }
    };
    let Some(reg_id) = reg_id_opt else {
        send_error_and_close(&mut ws, "capacity_exceeded", state.config.write_timeout).await;
        return;
    };
    let reg_guard = MailboxRegGuard {
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

    let expiry = unix_deadline(&state.config, deadline);
    tokio::pin!(expiry);
    let idle_sleep = tokio::time::sleep(state.config.idle_timeout.max(Duration::from_millis(1)));
    tokio::pin!(idle_sleep);
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
            biased;
            () = ended.notified() => break,
            () = &mut expiry => {
                state.config.test_point(RelayTestPoint::RegistrationExpired).await;
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
                    .reset(TokioInstant::now() + state.config.pong_timeout.max(Duration::from_millis(1)));
            }
            maybe_note = incoming_rx.recv() => {
                let Some(note) = maybe_note else {
                    break;
                };
                if !send_json(
                    &mut ws,
                    &RelayServerMsg::Incoming {
                        conn_id: note.conn_id,
                        init_frame: note.init_frame,
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
    drop(incoming_rx);
    // The flag is set under the tables lock before the newer registration's entry drops this
    // one's sender, so it is visible here whichever branch ended the loop.
    if displaced.load(Ordering::Acquire) {
        send_error_and_close(&mut ws, "replaced", state.config.write_timeout).await;
    } else {
        let _ = timeout(state.config.write_timeout, ws.close(None)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn park_standby_socket<N, AckMsg, IncMsg>(
    mut ws: RelayWsStream,
    global_guard: GlobalConnGuard,
    ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    standby_guard: StandbySlotGuard,
    mut dispatch_rx: oneshot::Receiver<StandbyDispatch<N>>,
    ack_msg: &AckMsg,
    deadline_unix: Option<u64>,
    build_incoming: impl FnOnce(N) -> IncMsg,
) where
    AckMsg: Serialize,
    IncMsg: Serialize,
{
    if !send_json(&mut ws, ack_msg, state.config.write_timeout).await {
        return;
    }

    let expiry = unix_deadline(&state.config, deadline_unix);
    tokio::pin!(expiry);
    let idle_sleep = tokio::time::sleep(state.config.idle_timeout.max(Duration::from_millis(1)));
    tokio::pin!(idle_sleep);
    let mut awaiting_pong = false;

    loop {
        tokio::select! {
            biased;
            () = &mut expiry => {
                state.config.test_point(RelayTestPoint::StandbyExpired).await;
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
                    .reset(TokioInstant::now() + state.config.pong_timeout.max(Duration::from_millis(1)));
            }
            dispatch = &mut dispatch_rx => {
                drop(standby_guard);
                let Ok(dispatch) = dispatch else {
                    let _ = timeout(state.config.write_timeout, ws.close(None)).await;
                    return;
                };
                let inc_msg = build_incoming(dispatch.notification);
                if send_json(&mut ws, &inc_msg, state.config.write_timeout).await {
                    let _ = dispatch.transfer_tx.send(AcceptorTransfer {
                        ws,
                        _global_guard: global_guard,
                        _ip_guard: ip_guard,
                        _stream_guard: dispatch.stream_guard,
                    });
                } else {
                    let _ = timeout(state.config.write_timeout, ws.close(None)).await;
                }
                return;
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
    drop(standby_guard);
    let _ = timeout(state.config.write_timeout, ws.close(None)).await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_standby(
    mut ws: RelayWsStream,
    global_guard: GlobalConnGuard,
    ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    nonce: &[u8; 32],
    pub_key_b64: String,
    sig_b64: String,
    auth: Option<RelayAuthProof>,
) {
    let Ok(mailbox_pub) = verify_relay_register(&pub_key_b64, &sig_b64, &state.config.host, nonce)
    else {
        send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    };
    if !verify_register_or_accept_admission(
        &state.config,
        "register",
        nonce,
        &mailbox_pub,
        auth.as_ref(),
    ) {
        send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }
    let deadline = admission_deadline_unix(&state.config, &mailbox_pub, auth.as_ref());

    let (dispatch_tx, dispatch_rx) = oneshot::channel();
    let enqueue: Result<u64, &'static str> = {
        let now = state.config.now_unix_secs();
        let mut tables = state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match tables.mailboxes.get(&mailbox_pub).cloned() {
            Some(entry) if deadline_passed(entry.deadline_unix, now) => {
                tables.end_v1_registration(&mailbox_pub, entry.reg_id);
                Err("offline")
            }
            Some(entry) => {
                let reg_id = entry.reg_id;
                let standby_id = tables.alloc_id();
                let pool = tables.standby.entry(mailbox_pub).or_default();
                pool.retain(|slot| slot.usable(reg_id, now));
                if pool.len() >= MAX_STANDBY_PER_MAILBOX {
                    Err("rate_limited")
                } else {
                    pool.push_back(StandbySlot {
                        id: standby_id,
                        reg_id,
                        deadline_unix: deadline,
                        dispatch_tx,
                    });
                    Ok(standby_id)
                }
            }
            None => Err("offline"),
        }
    };
    let standby_id = match enqueue {
        Ok(id) => id,
        Err(code) => {
            send_error_and_close(&mut ws, code, state.config.write_timeout).await;
            return;
        }
    };
    let guard = StandbySlotGuard {
        state: Arc::clone(&state),
        key: mailbox_pub,
        standby_id,
        is_v2: false,
    };

    park_standby_socket(
        ws,
        global_guard,
        ip_guard,
        state,
        guard,
        dispatch_rx,
        &RelayServerMsg::StandbyReady,
        deadline,
        |note| RelayServerMsg::Incoming {
            conn_id: note.conn_id,
            init_frame: note.init_frame,
        },
    )
    .await;
}

enum DialDispatchResult<N> {
    StandbyHit(Box<AcceptorTransfer>, bool),
    Pending {
        incoming_tx: mpsc::Sender<N>,
        dial_id: u64,
        mailbox_fast_open: bool,
    },
}

async fn deliver_ready_and_bridge<R: Serialize>(
    mut dialer_ws: RelayWsStream,
    mut acceptor: AcceptorTransfer,
    ready_msg: &R,
    binary_inject: Option<Vec<u8>>,
    write_timeout: Duration,
    idle_timeout: Duration,
) {
    if !send_json(&mut dialer_ws, ready_msg, write_timeout).await {
        return;
    }
    if let Some(bytes) = binary_inject
        && !timeout(
            write_timeout,
            acceptor.ws.send(Message::Binary(bytes.into())),
        )
        .await
        .is_ok_and(|res| res.is_ok())
    {
        return;
    }
    bridge_streams(dialer_ws, acceptor.ws, write_timeout, idle_timeout).await;
    drop(acceptor._global_guard);
    drop(acceptor._ip_guard);
    drop(acceptor._stream_guard);
}

#[allow(clippy::too_many_arguments)]
async fn handle_dial(
    mut ws: RelayWsStream,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    nonce: &[u8; 32],
    target_pub_b64: String,
    conn_id_b64: String,
    auth: Option<RelayAuthProof>,
    init_frame_b64: Option<String>,
) {
    let (Ok(target_pub), Ok(conn_id)) = (
        b64url_decode_array::<32>(&target_pub_b64),
        b64url_decode_array::<16>(&conn_id_b64),
    ) else {
        send_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };
    if !verify_dial_admission(&state.config, nonce, &target_pub, auth.as_ref()) {
        send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }
    let init_bytes = match decode_init_frame(init_frame_b64.as_deref()) {
        Ok(bytes) => bytes,
        Err(code) => {
            send_error_and_close(&mut ws, code, state.config.write_timeout).await;
            return;
        }
    };

    let (match_tx, mut match_rx) = oneshot::channel::<AcceptorTransfer>();
    let mut match_tx_opt = Some(match_tx);

    let dispatch_res: Result<DialDispatchResult<IncomingV1Notification>, &'static str> = loop {
        enum Step {
            TryStandby(
                StandbySlot<IncomingV1Notification>,
                MailboxStreamGuard,
                oneshot::Receiver<AcceptorTransfer>,
                oneshot::Sender<AcceptorTransfer>,
                bool,
            ),
            Fallback(mpsc::Sender<IncomingV1Notification>, u64, bool),
            Err(&'static str),
        }

        let step = {
            let now = state.config.now_unix_secs();
            let mut tables = state
                .tables
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut current = tables.mailboxes.get(&target_pub).cloned();
            if let Some(expired) =
                current.take_if(|mailbox| deadline_passed(mailbox.deadline_unix, now))
            {
                tables.end_v1_registration(&target_pub, expired.reg_id);
            }
            if let Some(mailbox) = current {
                let active_count = tables
                    .active_per_mailbox
                    .get(&target_pub)
                    .copied()
                    .unwrap_or(0);
                let pending_count = tables.pending_counts.get(&target_pub).copied().unwrap_or(0);
                if active_count >= state.config.max_active_per_mailbox
                    || pending_count >= state.config.max_pending_per_mailbox
                {
                    Step::Err("rate_limited")
                } else if tables.pending.contains_key(&conn_id) {
                    Step::Err("invalid_request")
                } else {
                    let mut popped = None;
                    if let Some(pool) = tables.standby.get_mut(&target_pub) {
                        while let Some(slot) = pool.pop_front() {
                            if slot.usable(mailbox.reg_id, now) {
                                popped = Some(slot);
                                break;
                            }
                        }
                        if pool.is_empty() {
                            tables.standby.remove(&target_pub);
                        }
                    }
                    if let Some(slot) = popped {
                        *tables.active_per_mailbox.entry(target_pub).or_insert(0) += 1;
                        let stream_guard = MailboxStreamGuard {
                            state: Arc::clone(&state),
                            key: target_pub,
                            is_v2: false,
                        };
                        let (transfer_tx, transfer_rx) = oneshot::channel();
                        Step::TryStandby(
                            slot,
                            stream_guard,
                            transfer_rx,
                            transfer_tx,
                            mailbox.fast_open,
                        )
                    } else {
                        let dial_id = tables.alloc_id();
                        *tables.pending_counts.entry(target_pub).or_insert(0) += 1;
                        tables.pending.insert(
                            conn_id,
                            PendingDial {
                                dial_id,
                                reg_id: mailbox.reg_id,
                                target_pub,
                                match_tx: match_tx_opt.take().expect("single fallback insert"),
                            },
                        );
                        Step::Fallback(mailbox.incoming_tx, dial_id, mailbox.fast_open)
                    }
                }
            } else {
                Step::Err("offline")
            }
        };

        match step {
            Step::Err(code) => break Err(code),
            Step::Fallback(incoming_tx, dial_id, mailbox_fast_open) => {
                break Ok(DialDispatchResult::Pending {
                    incoming_tx,
                    dial_id,
                    mailbox_fast_open,
                });
            }
            Step::TryStandby(slot, stream_guard, transfer_rx, transfer_tx, mailbox_fast_open) => {
                let dispatch = StandbyDispatch {
                    notification: IncomingV1Notification {
                        conn_id: conn_id_b64.clone(),
                        init_frame: if mailbox_fast_open {
                            init_frame_b64.clone()
                        } else {
                            None
                        },
                    },
                    stream_guard,
                    transfer_tx,
                };
                if slot.dispatch_tx.send(dispatch).is_err() {
                    continue;
                }
                if let Ok(acceptor) = transfer_rx.await {
                    break Ok(DialDispatchResult::StandbyHit(
                        Box::new(acceptor),
                        mailbox_fast_open,
                    ));
                }
            }
        }
    };

    let (incoming_tx, dial_id, mailbox_fast_open) = match dispatch_res {
        Ok(DialDispatchResult::StandbyHit(acceptor, mailbox_fast_open)) => {
            deliver_ready_and_bridge(
                ws,
                *acceptor,
                &RelayServerMsg::Ready {
                    conn_id: conn_id_b64,
                },
                if mailbox_fast_open { None } else { init_bytes },
                state.config.write_timeout,
                state.config.idle_timeout,
            )
            .await;
            return;
        }
        Ok(DialDispatchResult::Pending {
            incoming_tx,
            dial_id,
            mailbox_fast_open,
        }) => (incoming_tx, dial_id, mailbox_fast_open),
        Err(code) => {
            send_error_and_close(&mut ws, code, state.config.write_timeout).await;
            return;
        }
    };

    let pending_guard = PendingDialGuard {
        state: Arc::clone(&state),
        target_pub,
        conn_id,
        dial_id,
    };

    let note = IncomingV1Notification {
        conn_id: conn_id_b64.clone(),
        init_frame: if mailbox_fast_open {
            init_frame_b64
        } else {
            None
        },
    };
    match incoming_tx.try_send(note) {
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

    // A claimed dial waits for its acceptor, whose `ready` write is bounded by `write_timeout`.
    let accept_deadline = tokio::time::sleep(state.config.accept_timeout);
    tokio::pin!(accept_deadline);
    let mut claimed = false;
    let acceptor = loop {
        tokio::select! {
            biased;
            res = &mut match_rx => match res {
                Ok(transfer) => break transfer,
                Err(_) => {
                    send_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
                    return;
                }
            },
            () = incoming_tx.closed(), if !claimed => {
                state.config.test_point(RelayTestPoint::DialTeardown).await;
                if pending_guard.withdraw() {
                    send_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
                    return;
                }
                claimed = true;
            }
            () = &mut accept_deadline, if !claimed => {
                state.config.test_point(RelayTestPoint::DialTeardown).await;
                if pending_guard.withdraw() {
                    send_error_and_close(&mut ws, "timeout", state.config.write_timeout).await;
                    return;
                }
                claimed = true;
            }
            maybe_ws = ws.next() => {
                match maybe_ws {
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => return,
                }
            }
        }
    };

    let binary_inject = if mailbox_fast_open { None } else { init_bytes };
    deliver_ready_and_bridge(
        ws,
        acceptor,
        &RelayServerMsg::Ready {
            conn_id: conn_id_b64,
        },
        binary_inject,
        state.config.write_timeout,
        state.config.idle_timeout,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_accept(
    mut ws: RelayWsStream,
    global_guard: GlobalConnGuard,
    ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    nonce: &[u8; 32],
    pub_key_b64: String,
    conn_id_b64: String,
    sig_b64: String,
    auth: Option<RelayAuthProof>,
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
    if !verify_register_or_accept_admission(
        &state.config,
        "accept",
        nonce,
        &acceptor_pub,
        auth.as_ref(),
    ) {
        send_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }

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
        let now = state.config.now_unix_secs();
        match tables.pending.get(&conn_id) {
            None => ClaimResult::NotFound,
            Some(entry) if entry.target_pub != acceptor_pub => ClaimResult::WrongOwner,
            Some(entry)
                if !tables
                    .mailboxes
                    .get(&entry.target_pub)
                    .is_some_and(|owner| {
                        owner.reg_id == entry.reg_id && !deadline_passed(owner.deadline_unix, now)
                    }) =>
            {
                // The dial's registration has ended or expired: end it, which fails the dial.
                let (key, reg_id) = (entry.target_pub, entry.reg_id);
                if let Some(owner) = tables.mailboxes.get(&key).filter(|o| o.reg_id == reg_id) {
                    owner.ended.notify_one();
                }
                tables.end_v1_registration(&key, reg_id);
                ClaimResult::NotFound
            }
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
        key: target_pub,
        is_v2: false,
    };
    state.config.test_point(RelayTestPoint::AcceptClaimed).await;

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
    mut ws: RelayWsStream,
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
    let server_epoch = epoch_for_unix(state.config.now_unix_secs());
    let challenge = RelayV2ServerMsg::Challenge {
        nonce: b64url_encode(&nonce),
        host: canonical_host.clone(),
        epoch: server_epoch,
        max_frame: MAX_RELAY_FRAME_LEN,
        auth_required: state.config.challenge_auth_required(),
        fast_open: Some(true),
        standby: Some(true),
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
            auth,
            fast_open,
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
                auth,
                fast_open.unwrap_or(false),
            )
            .await;
        }
        RelayV2ClientMsg::Standby {
            mailbox_id,
            epoch,
            sig,
            auth,
        } => {
            handle_v2_standby(
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
                auth,
            )
            .await;
        }
        RelayV2ClientMsg::Dial {
            target_mailbox_id,
            epoch,
            conn_id,
            dial_token,
            auth,
            init_frame,
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
                auth,
                init_frame,
            )
            .await;
        }
        RelayV2ClientMsg::Accept {
            mailbox_id,
            epoch,
            conn_id,
            sig,
            auth,
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
                auth,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_register(
    mut ws: RelayWsStream,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    canonical_host: &str,
    server_epoch: u64,
    nonce: &[u8; 32],
    mailbox_id_b64: String,
    epoch: u64,
    sig_b64: String,
    auth: Option<RelayAuthProof>,
    fast_open: bool,
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
        || !verify_register_or_accept_admission(
            &state.config,
            "register",
            nonce,
            &mailbox_id,
            auth.as_ref(),
        )
    {
        send_v2_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }
    let deadline = earliest_deadline(
        Some(v2_epoch_deadline_unix(epoch)),
        admission_deadline_unix(&state.config, &mailbox_id, auth.as_ref()),
    );

    let chan_cap = state
        .config
        .max_pending_per_mailbox
        .saturating_mul(2)
        .max(8);
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<IncomingV2Notification>(chan_cap);
    let ended = Arc::new(Notify::new());
    let displaced = Arc::new(AtomicBool::new(false));
    let reg_id_opt = {
        let now = state.config.now_unix_secs();
        let mut tables = state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let max_mailboxes = state.config.max_mailboxes.max(1);
        if !tables.v2_mailboxes.contains_key(&mailbox_id)
            && tables.total_mailbox_count() >= max_mailboxes
        {
            tables.purge_expired(now);
        }
        if !tables.v2_mailboxes.contains_key(&mailbox_id)
            && tables.total_mailbox_count() >= max_mailboxes
        {
            None
        } else {
            let reg_id = tables.alloc_id();
            tables.v2_standby.remove(&mailbox_id);
            let previous = tables.v2_mailboxes.insert(
                mailbox_id,
                MailboxV2Entry {
                    reg_id,
                    epoch,
                    fast_open,
                    incoming_tx,
                    ended: Arc::clone(&ended),
                    displaced: Arc::clone(&displaced),
                    deadline_unix: deadline,
                },
            );
            if let Some(previous) = previous {
                if !deadline_passed(previous.deadline_unix, now) {
                    previous.displaced.store(true, Ordering::Release);
                }
                previous.ended.notify_one();
                tables.end_v2_registration(&mailbox_id, previous.reg_id);
            }
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

    let expiry = unix_deadline(&state.config, deadline);
    tokio::pin!(expiry);
    let idle_sleep = tokio::time::sleep(state.config.idle_timeout.max(Duration::from_millis(1)));
    tokio::pin!(idle_sleep);
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
            biased;
            () = ended.notified() => break,
            () = &mut expiry => {
                state.config.test_point(RelayTestPoint::RegistrationExpired).await;
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
                    .reset(TokioInstant::now() + state.config.pong_timeout.max(Duration::from_millis(1)));
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
                        init_frame: note.init_frame,
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
    drop(incoming_rx);
    if displaced.load(Ordering::Acquire) {
        send_v2_error_and_close(&mut ws, "replaced", state.config.write_timeout).await;
    } else {
        let _ = timeout(state.config.write_timeout, ws.close(None)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_standby(
    mut ws: RelayWsStream,
    global_guard: GlobalConnGuard,
    ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    canonical_host: &str,
    server_epoch: u64,
    nonce: &[u8; 32],
    mailbox_id_b64: String,
    epoch: u64,
    sig_b64: String,
    auth: Option<RelayAuthProof>,
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
        || !verify_register_or_accept_admission(
            &state.config,
            "register",
            nonce,
            &mailbox_id,
            auth.as_ref(),
        )
    {
        send_v2_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }
    let deadline = earliest_deadline(
        Some(v2_epoch_deadline_unix(epoch)),
        admission_deadline_unix(&state.config, &mailbox_id, auth.as_ref()),
    );

    let (dispatch_tx, dispatch_rx) = oneshot::channel();
    let enqueue: Result<u64, &'static str> = {
        let mut tables = state
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = state.config.now_unix_secs();
        match tables.v2_mailboxes.get(&mailbox_id).cloned() {
            Some(entry) if deadline_passed(entry.deadline_unix, now) => {
                tables.end_v2_registration(&mailbox_id, entry.reg_id);
                Err("offline")
            }
            Some(entry) if entry.epoch != epoch => Err("offline"),
            Some(entry) => {
                let reg_id = entry.reg_id;
                let standby_id = tables.alloc_id();
                let pool = tables.v2_standby.entry(mailbox_id).or_default();
                pool.retain(|slot| slot.usable(reg_id, now));
                if pool.len() >= MAX_STANDBY_PER_MAILBOX {
                    Err("rate_limited")
                } else {
                    pool.push_back(StandbySlot {
                        id: standby_id,
                        reg_id,
                        deadline_unix: deadline,
                        dispatch_tx,
                    });
                    Ok(standby_id)
                }
            }
            None => Err("offline"),
        }
    };
    let standby_id = match enqueue {
        Ok(id) => id,
        Err(code) => {
            send_v2_error_and_close(&mut ws, code, state.config.write_timeout).await;
            return;
        }
    };
    let guard = StandbySlotGuard {
        state: Arc::clone(&state),
        key: mailbox_id,
        standby_id,
        is_v2: true,
    };

    park_standby_socket(
        ws,
        global_guard,
        ip_guard,
        state,
        guard,
        dispatch_rx,
        &RelayV2ServerMsg::StandbyReady {
            mailbox_id: mailbox_id_b64,
            epoch,
        },
        deadline,
        |note| RelayV2ServerMsg::Incoming {
            mailbox_id: note.mailbox_id,
            epoch: note.epoch,
            conn_id: note.conn_id,
            dial_nonce: note.dial_nonce,
            dial_token: note.dial_token,
            init_frame: note.init_frame,
        },
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_dial(
    mut ws: RelayWsStream,
    _global_guard: GlobalConnGuard,
    _ip_guard: IpConnGuard,
    state: Arc<RelayState>,
    server_epoch: u64,
    dial_nonce: &[u8; 32],
    target_mailbox_b64: String,
    epoch: u64,
    conn_id_b64: String,
    dial_token_b64: String,
    auth: Option<RelayAuthProof>,
    init_frame_b64: Option<String>,
) {
    let (Ok(target_mailbox), Ok(conn_id), Ok(_dial_token)) = (
        b64url_decode_array::<32>(&target_mailbox_b64),
        b64url_decode_array::<16>(&conn_id_b64),
        b64url_decode_array::<32>(&dial_token_b64),
    ) else {
        send_v2_error_and_close(&mut ws, "invalid_request", state.config.write_timeout).await;
        return;
    };
    if !verify_dial_admission(&state.config, dial_nonce, &target_mailbox, auth.as_ref()) {
        send_v2_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }
    let init_bytes = match decode_init_frame(init_frame_b64.as_deref()) {
        Ok(bytes) => bytes,
        Err(code) => {
            send_v2_error_and_close(&mut ws, code, state.config.write_timeout).await;
            return;
        }
    };
    if !epoch_within_skew(server_epoch, epoch) {
        send_v2_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
        return;
    }

    let dial_nonce_b64 = b64url_encode(dial_nonce);
    let (match_tx, mut match_rx) = oneshot::channel::<AcceptorTransfer>();
    let mut match_tx_opt = Some(match_tx);

    let dispatch_res: Result<DialDispatchResult<IncomingV2Notification>, &'static str> = loop {
        enum Step {
            TryStandby(
                StandbySlot<IncomingV2Notification>,
                MailboxStreamGuard,
                oneshot::Receiver<AcceptorTransfer>,
                oneshot::Sender<AcceptorTransfer>,
                bool,
            ),
            Fallback(mpsc::Sender<IncomingV2Notification>, u64, bool),
            Err(&'static str),
        }

        let step = {
            let now = state.config.now_unix_secs();
            let mut tables = state
                .tables
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut current = tables.v2_mailboxes.get(&target_mailbox).cloned();
            if let Some(expired) =
                current.take_if(|mailbox| deadline_passed(mailbox.deadline_unix, now))
            {
                tables.end_v2_registration(&target_mailbox, expired.reg_id);
            }
            if let Some(mailbox) = current {
                if mailbox.epoch != epoch {
                    Step::Err("offline")
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
                        Step::Err("rate_limited")
                    } else if tables.v2_pending.contains_key(&conn_id) {
                        Step::Err("invalid_request")
                    } else {
                        let mut popped = None;
                        if let Some(pool) = tables.v2_standby.get_mut(&target_mailbox) {
                            while let Some(slot) = pool.pop_front() {
                                if slot.usable(mailbox.reg_id, now) {
                                    popped = Some(slot);
                                    break;
                                }
                            }
                            if pool.is_empty() {
                                tables.v2_standby.remove(&target_mailbox);
                            }
                        }
                        if let Some(slot) = popped {
                            *tables
                                .v2_active_per_mailbox
                                .entry(target_mailbox)
                                .or_insert(0) += 1;
                            let stream_guard = MailboxStreamGuard {
                                state: Arc::clone(&state),
                                key: target_mailbox,
                                is_v2: true,
                            };
                            let (transfer_tx, transfer_rx) = oneshot::channel();
                            Step::TryStandby(
                                slot,
                                stream_guard,
                                transfer_rx,
                                transfer_tx,
                                mailbox.fast_open,
                            )
                        } else {
                            let dial_id = tables.alloc_id();
                            *tables.v2_pending_counts.entry(target_mailbox).or_insert(0) += 1;
                            tables.v2_pending.insert(
                                conn_id,
                                PendingV2Dial {
                                    dial_id,
                                    reg_id: mailbox.reg_id,
                                    target_mailbox,
                                    epoch,
                                    match_tx: match_tx_opt.take().expect("single fallback insert"),
                                },
                            );
                            Step::Fallback(mailbox.incoming_tx, dial_id, mailbox.fast_open)
                        }
                    }
                }
            } else {
                Step::Err("offline")
            }
        };

        match step {
            Step::Err(code) => break Err(code),
            Step::Fallback(incoming_tx, dial_id, mailbox_fast_open) => {
                break Ok(DialDispatchResult::Pending {
                    incoming_tx,
                    dial_id,
                    mailbox_fast_open,
                });
            }
            Step::TryStandby(slot, stream_guard, transfer_rx, transfer_tx, mailbox_fast_open) => {
                let dispatch = StandbyDispatch {
                    notification: IncomingV2Notification {
                        mailbox_id: target_mailbox_b64.clone(),
                        epoch,
                        conn_id: conn_id_b64.clone(),
                        dial_nonce: dial_nonce_b64.clone(),
                        dial_token: dial_token_b64.clone(),
                        init_frame: if mailbox_fast_open {
                            init_frame_b64.clone()
                        } else {
                            None
                        },
                    },
                    stream_guard,
                    transfer_tx,
                };
                if slot.dispatch_tx.send(dispatch).is_err() {
                    continue;
                }
                if let Ok(acceptor) = transfer_rx.await {
                    break Ok(DialDispatchResult::StandbyHit(
                        Box::new(acceptor),
                        mailbox_fast_open,
                    ));
                }
            }
        }
    };

    let (incoming_tx, dial_id, mailbox_fast_open) = match dispatch_res {
        Ok(DialDispatchResult::StandbyHit(acceptor, mailbox_fast_open)) => {
            deliver_ready_and_bridge(
                ws,
                *acceptor,
                &RelayV2ServerMsg::Ready {
                    conn_id: conn_id_b64,
                },
                if mailbox_fast_open { None } else { init_bytes },
                state.config.write_timeout,
                state.config.idle_timeout,
            )
            .await;
            return;
        }
        Ok(DialDispatchResult::Pending {
            incoming_tx,
            dial_id,
            mailbox_fast_open,
        }) => (incoming_tx, dial_id, mailbox_fast_open),
        Err(code) => {
            send_v2_error_and_close(&mut ws, code, state.config.write_timeout).await;
            return;
        }
    };

    let pending_guard = PendingV2DialGuard {
        state: Arc::clone(&state),
        target_mailbox,
        conn_id,
        dial_id,
    };

    let note = IncomingV2Notification {
        mailbox_id: target_mailbox_b64,
        epoch,
        conn_id: conn_id_b64.clone(),
        dial_nonce: dial_nonce_b64,
        dial_token: dial_token_b64,
        init_frame: if mailbox_fast_open {
            init_frame_b64
        } else {
            None
        },
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

    // A claimed dial waits for its acceptor, whose `ready` write is bounded by `write_timeout`.
    let accept_deadline = tokio::time::sleep(state.config.accept_timeout);
    tokio::pin!(accept_deadline);
    let mut claimed = false;
    let acceptor = loop {
        tokio::select! {
            biased;
            res = &mut match_rx => match res {
                Ok(transfer) => break transfer,
                Err(_) => {
                    send_v2_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
                    return;
                }
            },
            () = incoming_tx.closed(), if !claimed => {
                state.config.test_point(RelayTestPoint::DialTeardown).await;
                if pending_guard.withdraw() {
                    send_v2_error_and_close(&mut ws, "offline", state.config.write_timeout).await;
                    return;
                }
                claimed = true;
            }
            () = &mut accept_deadline, if !claimed => {
                state.config.test_point(RelayTestPoint::DialTeardown).await;
                if pending_guard.withdraw() {
                    send_v2_error_and_close(&mut ws, "timeout", state.config.write_timeout).await;
                    return;
                }
                claimed = true;
            }
            maybe_ws = ws.next() => {
                match maybe_ws {
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => return,
                }
            }
        }
    };

    let binary_inject = if mailbox_fast_open { None } else { init_bytes };
    deliver_ready_and_bridge(
        ws,
        acceptor,
        &RelayV2ServerMsg::Ready {
            conn_id: conn_id_b64,
        },
        binary_inject,
        state.config.write_timeout,
        state.config.idle_timeout,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_accept(
    mut ws: RelayWsStream,
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
    auth: Option<RelayAuthProof>,
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
        || !verify_register_or_accept_admission(
            &state.config,
            "accept",
            nonce,
            &acceptor_mailbox,
            auth.as_ref(),
        )
    {
        send_v2_error_and_close(&mut ws, "unauthorized", state.config.write_timeout).await;
        return;
    }

    enum ClaimResult {
        Claimed {
            target_mailbox: [u8; 32],
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
        let now = state.config.now_unix_secs();
        match tables.v2_pending.get(&conn_id) {
            None => ClaimResult::NotFound,
            Some(entry) if entry.target_mailbox != acceptor_mailbox || entry.epoch != epoch => {
                ClaimResult::WrongOwner
            }
            Some(entry)
                if !tables
                    .v2_mailboxes
                    .get(&entry.target_mailbox)
                    .is_some_and(|owner| {
                        owner.reg_id == entry.reg_id && !deadline_passed(owner.deadline_unix, now)
                    }) =>
            {
                let (key, reg_id) = (entry.target_mailbox, entry.reg_id);
                if let Some(owner) = tables.v2_mailboxes.get(&key).filter(|o| o.reg_id == reg_id) {
                    owner.ended.notify_one();
                }
                tables.end_v2_registration(&key, reg_id);
                ClaimResult::NotFound
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

    let stream_guard = MailboxStreamGuard {
        state: Arc::clone(&state),
        key: target_mailbox,
        is_v2: true,
    };
    state.config.test_point(RelayTestPoint::AcceptClaimed).await;

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

    let _ = match_tx.send(AcceptorTransfer {
        ws,
        _global_guard: global_guard,
        _ip_guard: ip_guard,
        _stream_guard: stream_guard,
    });
}

async fn bridge_streams(
    dialer_ws: RelayWsStream,
    acceptor_ws: RelayWsStream,
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
