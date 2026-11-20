//! Iroh QUIC P2P path provider (`p2p`, zero-config hole-punching + public relay fallback).

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr};
use tendril_core::policy::ProviderId;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::error::RuntimeError;
use crate::provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathStream,
};

/// ALPN registered on iroh endpoints carrying Tendril `Intent::Pair` and `Intent::Session`.
pub const TENDRIL_P2P_ALPN: &[u8] = b"tendril/p2p/v1";

const P2P_STREAM_MAGIC: u8 = 0x54;
const P2P_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const P2P_ACCEPT_BI_TIMEOUT: Duration = Duration::from_secs(3);
const P2P_MAGIC_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_ACCEPTS: usize = 64;
const MAX_CONCURRENT_ACCEPTS_PER_PEER: usize = 4;

struct PeerAcceptGuard {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<iroh::EndpointId, usize>>>,
    peer: iroh::EndpointId,
}

impl PeerAcceptGuard {
    fn try_acquire(
        counts: Arc<std::sync::Mutex<std::collections::HashMap<iroh::EndpointId, usize>>>,
        peer: iroh::EndpointId,
    ) -> Option<Self> {
        let mut map = counts.lock().unwrap_or_else(|err| err.into_inner());
        let entry = map.entry(peer).or_insert(0);
        if *entry >= MAX_CONCURRENT_ACCEPTS_PER_PEER {
            return None;
        }
        *entry += 1;
        drop(map);
        Some(Self { counts, peer })
    }
}

impl Drop for PeerAcceptGuard {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(count) = map.get_mut(&self.peer) {
            if *count <= 1 {
                map.remove(&self.peer);
            } else {
                *count -= 1;
            }
        }
    }
}

/// Relay strategy used when constructing [`P2pListener`] and [`P2pDialer`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum P2pRelayMode {
    /// Zero-setup public relays and global peer discovery (`presets::N0`).
    #[default]
    Default,
    /// Self-hosted or regional `iroh-relay` HTTPS URL (`https://...`).
    Custom(String),
    /// Direct UDP socket addresses only (no relay server).
    Disabled,
}

struct EndpointGuard {
    endpoint: Endpoint,
    closed: AtomicBool,
}

impl EndpointGuard {
    fn new(endpoint: Endpoint) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            closed: AtomicBool::new(false),
        })
    }

    async fn close_now(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.endpoint.close().await;
        }
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let ep = self.endpoint.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    ep.close().await;
                });
            }
        }
    }
}

/// Parses an optional P2P relay mode selector (`"default"`, `"disabled"`/`"local"`, or `http(s)://...`).
pub fn parse_p2p_relay_mode(mode: Option<&str>) -> Result<P2pRelayMode, RuntimeError> {
    match mode.map(str::trim) {
        None | Some("" | "default") => Ok(P2pRelayMode::Default),
        Some("disabled" | "local") => Ok(P2pRelayMode::Disabled),
        Some(url) if url.starts_with("https://") || url.starts_with("http://") => {
            super::validate_iroh_relay_url(url)?;
            let _ = RelayUrl::from_str(url).map_err(|err| {
                RuntimeError::Protocol(format!("invalid iroh relay URL '{url}': {err}"))
            })?;
            Ok(P2pRelayMode::Custom(url.to_owned()))
        }
        Some(other) => Err(RuntimeError::Protocol(format!(
            "invalid p2p relay mode '{other}' (expected default, disabled, local, or relay URL)"
        ))),
    }
}

async fn build_iroh_endpoint(
    relay_mode: &P2pRelayMode,
    alpns: Vec<Vec<u8>>,
    secret_seed: Option<Zeroizing<[u8; 32]>>,
) -> Result<Endpoint, RuntimeError> {
    let mut builder = match relay_mode {
        P2pRelayMode::Default => Endpoint::builder(presets::N0).relay_mode(RelayMode::Default),
        P2pRelayMode::Custom(url_str) => {
            super::validate_iroh_relay_url(url_str)?;
            let url = RelayUrl::from_str(url_str).map_err(|err| {
                RuntimeError::Protocol(format!("invalid iroh relay URL '{url_str}': {err}"))
            })?;
            Endpoint::builder(presets::N0).relay_mode(RelayMode::Custom(url.into()))
        }
        P2pRelayMode::Disabled => {
            Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled)
        }
    };
    if let Some(seed) = secret_seed {
        let sk = SecretKey::from_bytes(&seed);
        builder = builder.secret_key(sk);
    }
    builder
        .alpns(alpns)
        .bind()
        .await
        .map_err(|err| RuntimeError::Protocol(format!("iroh endpoint bind failed: {err}")))
}

/// Formats an [`EndpointAddr`] as a compact `iroh://<endpoint_id>[?addr=...&relay=...]` string.
#[must_use]
pub fn format_p2p_endpoint(addr: &EndpointAddr) -> String {
    let mut query = Vec::new();
    for sock in addr.ip_addrs() {
        query.push(format!("addr={sock}"));
    }
    for relay in addr.relay_urls() {
        query.push(format!("relay={relay}"));
    }
    if query.is_empty() {
        format!("iroh://{}", addr.id)
    } else {
        format!("iroh://{}?{}", addr.id, query.join("&"))
    }
}

/// Parses an `iroh://<endpoint_id>[?addr=...&relay=...]` endpoint string into [`EndpointAddr`].
pub fn parse_p2p_endpoint(endpoint: &str) -> Result<EndpointAddr, RuntimeError> {
    parse_p2p_endpoint_filtered(endpoint, true)
}

/// Parses an `iroh://...` endpoint URI while always stripping metadata/link-local IPs
/// and optionally stripping private/loopback/reserved `?addr=` hints.
pub fn parse_p2p_endpoint_filtered(
    endpoint: &str,
    allow_private_addrs: bool,
) -> Result<EndpointAddr, RuntimeError> {
    if endpoint.chars().any(char::is_control) {
        return Err(RuntimeError::Protocol(
            "iroh endpoint contains control characters".into(),
        ));
    }
    let raw = endpoint.strip_prefix("iroh://").unwrap_or(endpoint);
    let (id_part, query_part) = raw.split_once('?').unwrap_or((raw, ""));
    let id = EndpointId::from_str(id_part).map_err(|err| {
        RuntimeError::Protocol(format!("invalid iroh endpoint id '{id_part}': {err}"))
    })?;

    let mut addrs = Vec::new();
    if !query_part.is_empty() {
        for pair in query_part.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, val) = pair.split_once('=').ok_or_else(|| {
                RuntimeError::Protocol(format!("invalid iroh query param '{pair}'"))
            })?;
            match key {
                "addr" => {
                    let sock: SocketAddr = val.parse().map_err(|err| {
                        RuntimeError::Protocol(format!("invalid iroh socket addr '{val}': {err}"))
                    })?;
                    if super::is_metadata_or_link_local_ip(sock.ip())
                        || (!allow_private_addrs && super::is_private_or_reserved_ip(sock.ip()))
                    {
                        continue;
                    }
                    addrs.push(TransportAddr::Ip(sock));
                }
                "relay" => {
                    super::validate_iroh_relay_url(val)?;
                    let url = RelayUrl::from_str(val).map_err(|err| {
                        RuntimeError::Protocol(format!("invalid iroh relay URL '{val}': {err}"))
                    })?;
                    addrs.push(TransportAddr::Relay(url));
                }
                other => {
                    return Err(RuntimeError::Protocol(format!(
                        "unknown iroh endpoint query parameter '{other}'"
                    )));
                }
            }
        }
    }
    Ok(EndpointAddr::from_parts(id, addrs))
}

/// Bidirectional QUIC stream over an `iroh` P2P connection implementing [`PathStream`].
pub struct P2pStream {
    guard: Option<Arc<EndpointGuard>>,
    conn: Option<Connection>,
    peer_ip: Option<IpAddr>,
    peer_transport_id: String,
    send: SendStream,
    recv: RecvStream,
    write_timeout: Duration,
}

impl P2pStream {
    fn new(
        guard: Arc<EndpointGuard>,
        conn: Connection,
        send: SendStream,
        recv: RecvStream,
        write_timeout: Duration,
    ) -> Self {
        let peer_transport_id = conn.remote_id().to_string();
        Self {
            guard: Some(guard),
            conn: Some(conn),
            peer_ip: None,
            peer_transport_id,
            send,
            recv,
            write_timeout,
        }
    }
}

impl Drop for P2pStream {
    fn drop(&mut self) {
        let _ = self.send.finish();
        if let (Some(conn), Some(guard)) = (self.conn.take(), self.guard.take())
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                // Keep QUIC connection open briefly so flushed stream frames and FIN deliver.
                let _ = timeout(Duration::from_millis(250), conn.closed()).await;
                drop(conn);
                drop(guard);
            });
        }
    }
}

#[async_trait]
impl PathStream for P2pStream {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    fn peer_transport_id(&self) -> Option<String> {
        Some(self.peer_transport_id.clone())
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes.len() > MAX_OUTER_FRAME_LEN {
            return Err(RuntimeError::FrameTooLarge {
                size: bytes.len(),
                max: MAX_OUTER_FRAME_LEN,
            });
        }
        match timeout(self.write_timeout, self.send.write_all(bytes)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(RuntimeError::Protocol(err.to_string())),
            Err(_) => Err(RuntimeError::Timeout("p2p stream write timed out")),
        }
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.recv.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(err) => Err(RuntimeError::Protocol(err.to_string())),
        }
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        let _ = self.send.finish();
        let _ = timeout(Duration::from_millis(50), self.send.stopped()).await;
        drop(self.conn.take());
        if let Some(guard) = self.guard.take()
            && let Ok(g) = Arc::try_unwrap(guard)
        {
            g.close_now().await;
        }
        Ok(())
    }
}

/// Listener accepting QUIC peer connections via `iroh` (`p2p`).
pub struct P2pListener {
    guard: Arc<EndpointGuard>,
    local_ep: String,
    accepted_rx: mpsc::Receiver<P2pStream>,
    accept_task: JoinHandle<()>,
    write_timeout: Duration,
}

impl P2pListener {
    /// Binds a new `iroh` P2P endpoint listener under `relay_mode` with a fresh ephemeral key.
    pub async fn bind(relay_mode: P2pRelayMode) -> Result<Self, RuntimeError> {
        Self::bind_inner(relay_mode, None).await
    }

    /// Binds a new `iroh` P2P endpoint listener under `relay_mode` with a deterministic secret seed.
    pub async fn bind_with_secret(
        relay_mode: P2pRelayMode,
        secret_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, RuntimeError> {
        Self::bind_inner(relay_mode, Some(secret_seed)).await
    }

    async fn bind_inner(
        relay_mode: P2pRelayMode,
        secret_seed: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, RuntimeError> {
        let endpoint =
            build_iroh_endpoint(&relay_mode, vec![TENDRIL_P2P_ALPN.to_vec()], secret_seed).await?;
        if !matches!(relay_mode, P2pRelayMode::Disabled) {
            let _ = timeout(Duration::from_secs(3), endpoint.online()).await;
        }
        let local_ep = format_p2p_endpoint(&endpoint.addr());
        let write_timeout = DEFAULT_WRITE_TIMEOUT;
        let guard = EndpointGuard::new(endpoint);
        let (accepted_tx, accepted_rx) = mpsc::channel(32);
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let peer_accepts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let guard_clone = Arc::clone(&guard);

        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = guard_clone.endpoint.accept().await {
                let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                    continue;
                };
                let tx_c = accepted_tx.clone();
                let stream_guard = Arc::clone(&guard_clone);
                let peer_counts = Arc::clone(&peer_accepts);
                tokio::spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(conn)) = timeout(P2P_CONNECT_TIMEOUT, incoming).await else {
                        return;
                    };
                    let Some(_peer_guard) =
                        PeerAcceptGuard::try_acquire(peer_counts, conn.remote_id())
                    else {
                        return;
                    };
                    let Ok(Ok((send, mut recv))) =
                        timeout(P2P_ACCEPT_BI_TIMEOUT, conn.accept_bi()).await
                    else {
                        return;
                    };
                    let mut magic = [0u8; 1];
                    if let Ok(Ok(())) =
                        timeout(P2P_MAGIC_TIMEOUT, recv.read_exact(&mut magic)).await
                        && magic[0] == P2P_STREAM_MAGIC
                    {
                        let stream = P2pStream::new(stream_guard, conn, send, recv, write_timeout);
                        let _ = timeout(P2P_ACCEPT_BI_TIMEOUT, tx_c.send(stream)).await;
                    }
                });
            }
        });

        Ok(Self {
            guard,
            local_ep,
            accepted_rx,
            accept_task,
            write_timeout,
        })
    }

    /// Returns the underlying `iroh` endpoint identifier.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.guard.endpoint.id()
    }

    /// Returns a fresh serialized `iroh://...` address snapshot (useful once relays finish homing).
    #[must_use]
    pub fn current_endpoint(&self) -> String {
        format_p2p_endpoint(&self.guard.endpoint.addr())
    }

    /// Returns the configured per-write timeout.
    #[must_use]
    pub fn write_timeout(&self) -> Duration {
        self.write_timeout
    }
}

impl Drop for P2pListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

#[async_trait]
impl PathListener for P2pListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = self.accepted_rx.recv().await.ok_or(RuntimeError::Closed)?;
        Ok(Box::new(stream))
    }

    fn local_endpoint(&self) -> String {
        let current = format_p2p_endpoint(&self.guard.endpoint.addr());
        if current == format!("iroh://{}", self.guard.endpoint.id()) {
            self.local_ep.clone()
        } else {
            current
        }
    }
}

/// Dialer opening authenticated Tendril byte streams over `iroh` (`iroh://...`).
pub struct P2pDialer {
    guard: Arc<EndpointGuard>,
    write_timeout: Duration,
    allow_private_addrs: bool,
}

impl P2pDialer {
    /// Binds a client `iroh` endpoint configured with `relay_mode`.
    pub async fn bind(relay_mode: P2pRelayMode) -> Result<Self, RuntimeError> {
        let allow_private_addrs = matches!(relay_mode, P2pRelayMode::Disabled);
        let endpoint = build_iroh_endpoint(&relay_mode, Vec::new(), None).await?;
        Ok(Self {
            guard: EndpointGuard::new(endpoint),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            allow_private_addrs,
        })
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Allows dialing private/loopback `?addr=` hints on relayed P2P connections.
    #[must_use]
    pub fn with_allow_private_addrs(mut self, allow: bool) -> Self {
        self.allow_private_addrs = allow;
        self
    }

    /// Gracefully closes the client endpoint handle when no active streams still hold it.
    pub async fn close(self) {
        if let Ok(guard) = Arc::try_unwrap(self.guard) {
            guard.close_now().await;
        }
    }
}

#[async_trait]
impl PathDialer for P2pDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let addr = parse_p2p_endpoint_filtered(endpoint, self.allow_private_addrs)?;
        let conn = timeout(
            P2P_HANDSHAKE_TIMEOUT,
            self.guard.endpoint.connect(addr, TENDRIL_P2P_ALPN),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("p2p connect timed out"))?
        .map_err(|err| RuntimeError::Protocol(format!("p2p connect failed: {err}")))?;

        let (mut send, recv) = timeout(P2P_HANDSHAKE_TIMEOUT, conn.open_bi())
            .await
            .map_err(|_| RuntimeError::Timeout("p2p open_bi timed out"))?
            .map_err(|err| RuntimeError::Protocol(format!("p2p open_bi failed: {err}")))?;

        // Write a 1-byte stream marker immediately so the peer's QUIC accept_bi() resolves.
        timeout(self.write_timeout, send.write_all(&[P2P_STREAM_MAGIC]))
            .await
            .map_err(|_| RuntimeError::Timeout("p2p stream opener write timed out"))?
            .map_err(|err| RuntimeError::Protocol(format!("p2p stream opener failed: {err}")))?;

        Ok(Box::new(P2pStream::new(
            Arc::clone(&self.guard),
            conn,
            send,
            recv,
            self.write_timeout,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_p2p_endpoint_supports_ipv6_relay_and_rejects_unknown_params() {
        let ep_id = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        let addr_ipv6 = "[::1]:4433";
        let relay = "https://relay.example/";
        let uri = format!("iroh://{ep_id}?addr={addr_ipv6}&relay={relay}");
        let parsed = parse_p2p_endpoint(&uri).expect("parse ipv6 + relay URI");
        assert_eq!(parsed.id, ep_id);
        assert_eq!(parsed.ip_addrs().count(), 1);
        assert_eq!(parsed.relay_urls().count(), 1);

        let bare = parse_p2p_endpoint(&format!("iroh://{ep_id}")).expect("bare endpoint");
        assert_eq!(bare.id, ep_id);
        assert_eq!(bare.ip_addrs().count(), 0);

        let err = parse_p2p_endpoint(&format!("iroh://{ep_id}?unknown=1"));
        assert!(matches!(err, Err(RuntimeError::Protocol(_))));
    }
}
