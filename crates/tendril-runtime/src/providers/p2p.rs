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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum IncomingSourceKey {
    Ip(IpAddr),
    Peer(EndpointId),
    Other,
}

fn normalize_incoming_source(addr: &iroh::endpoint::IncomingAddr) -> IncomingSourceKey {
    match addr {
        iroh::endpoint::IncomingAddr::Ip(sock) => {
            let ip = match sock.ip() {
                IpAddr::V4(v4) => IpAddr::V4(v4),
                IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) => IpAddr::V4(v4),
                    None => {
                        let seg = v6.segments();
                        IpAddr::V6(std::net::Ipv6Addr::new(
                            seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0,
                        ))
                    }
                },
            };
            IncomingSourceKey::Ip(ip)
        }
        iroh::endpoint::IncomingAddr::Relay { endpoint_id, .. } => {
            IncomingSourceKey::Peer(*endpoint_id)
        }
        _ => IncomingSourceKey::Other,
    }
}

struct PeerAcceptGuard<K: Eq + std::hash::Hash> {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<K, usize>>>,
    key: K,
}

impl<K: Eq + std::hash::Hash + Clone> PeerAcceptGuard<K> {
    fn try_acquire(
        counts: Arc<std::sync::Mutex<std::collections::HashMap<K, usize>>>,
        key: K,
        limit: usize,
    ) -> Option<Self> {
        let mut map = counts.lock().unwrap_or_else(|err| err.into_inner());
        let entry = map.entry(key.clone()).or_insert(0);
        if *entry >= limit {
            return None;
        }
        *entry += 1;
        drop(map);
        Some(Self { counts, key })
    }
}

impl<K: Eq + std::hash::Hash> Drop for PeerAcceptGuard<K> {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(count) = map.get_mut(&self.key) {
            if *count <= 1 {
                map.remove(&self.key);
            } else {
                *count -= 1;
            }
        }
    }
}

/// Relay strategy used when constructing [`P2pListener`] and [`P2pDialer`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum P2pRelayMode {
    /// Zero-setup public relays (`RelayMode::Default`).
    #[default]
    Default,
    /// Self-hosted or regional `iroh-relay` HTTPS URL (`https://...`).
    Custom(String),
    /// Direct UDP socket addresses only (no relay server).
    Disabled,
}

/// Privacy and discovery options controlling `iroh` P2P endpoint construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pOptions {
    pub relay_mode: P2pRelayMode,
    pub publish_pkarr: bool,
    pub resolve_pkarr: bool,
    pub advertise_direct_addrs: bool,
    pub allow_private_addrs: bool,
}

impl Default for P2pOptions {
    fn default() -> Self {
        Self::for_listener(P2pRelayMode::Default)
    }
}

impl P2pOptions {
    /// Default privacy-preserving options for a listening [`P2pListener`].
    ///
    /// - [`P2pRelayMode::Default`]: publishes and resolves via `n0` Pkarr/DNS; omits direct `?addr=` hints.
    /// - [`P2pRelayMode::Custom`]: disables `n0` Pkarr/DNS (`presets::Minimal`) and omits direct `?addr=` hints.
    /// - [`P2pRelayMode::Disabled`]: disables `n0` Pkarr/DNS and advertises local `?addr=` hints.
    #[must_use]
    pub fn for_listener(relay_mode: P2pRelayMode) -> Self {
        let is_default = matches!(relay_mode, P2pRelayMode::Default);
        let is_disabled = matches!(relay_mode, P2pRelayMode::Disabled);
        Self {
            relay_mode,
            publish_pkarr: is_default,
            resolve_pkarr: is_default,
            advertise_direct_addrs: is_disabled,
            allow_private_addrs: is_disabled,
        }
    }

    /// Default privacy-preserving options for a dialing [`P2pDialer`].
    ///
    /// Never enables `PkarrPublisher` so ephemeral client identities are never published.
    #[must_use]
    pub fn for_dialer(relay_mode: P2pRelayMode) -> Self {
        let is_default = matches!(relay_mode, P2pRelayMode::Default);
        let is_disabled = matches!(relay_mode, P2pRelayMode::Disabled);
        Self {
            relay_mode,
            publish_pkarr: false,
            resolve_pkarr: is_default,
            advertise_direct_addrs: false,
            allow_private_addrs: is_disabled,
        }
    }

    /// Enables or disables publishing this endpoint to `n0` Pkarr/DNS.
    #[must_use]
    pub fn with_publish_pkarr(mut self, publish: bool) -> Self {
        self.publish_pkarr = publish;
        self
    }

    /// Enables or disables resolving peer endpoints via `n0` Pkarr/DNS.
    #[must_use]
    pub fn with_resolve_pkarr(mut self, resolve: bool) -> Self {
        self.resolve_pkarr = resolve;
        self
    }

    /// Controls whether [`P2pListener`] serializes non-metadata `?addr=` direct socket hints.
    #[must_use]
    pub fn with_advertise_direct_addrs(mut self, advertise: bool) -> Self {
        self.advertise_direct_addrs = advertise;
        self
    }

    /// Controls whether [`P2pDialer`] accepts private/loopback `?addr=` hints.
    #[must_use]
    pub fn with_allow_private_addrs(mut self, allow: bool) -> Self {
        self.allow_private_addrs = allow;
        self
    }
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
    if mode.is_some_and(|raw| raw.chars().any(char::is_control)) {
        return Err(RuntimeError::Protocol(
            "iroh relay URL contains control characters".into(),
        ));
    }
    match mode.map(str::trim) {
        None | Some("" | "default") => Ok(P2pRelayMode::Default),
        Some("disabled" | "local") => Ok(P2pRelayMode::Disabled),
        Some(url) if url.starts_with("https://") || url.starts_with("http://") => {
            let validated = super::validate_iroh_relay_url(url)?;
            let canonical = validated.as_str().to_owned();
            let _ = RelayUrl::from_str(&canonical).map_err(|err| {
                RuntimeError::Protocol(format!("invalid iroh relay URL '{url}': {err}"))
            })?;
            Ok(P2pRelayMode::Custom(canonical))
        }
        Some(other) => Err(RuntimeError::Protocol(format!(
            "invalid p2p relay mode '{other}' (expected default, disabled, local, or relay URL)"
        ))),
    }
}

async fn build_iroh_endpoint(
    options: &P2pOptions,
    alpns: Vec<Vec<u8>>,
    secret_seed: Option<Zeroizing<[u8; 32]>>,
) -> Result<Endpoint, RuntimeError> {
    let mut builder = match &options.relay_mode {
        P2pRelayMode::Default => Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Default),
        P2pRelayMode::Custom(url_str) => {
            let validated = super::validate_iroh_relay_url(url_str)?;
            let url = RelayUrl::from_str(validated.as_str()).map_err(|err| {
                RuntimeError::Protocol(format!("invalid iroh relay URL '{url_str}': {err}"))
            })?;
            Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(url.into()))
        }
        P2pRelayMode::Disabled => {
            Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled)
        }
    };
    if options.publish_pkarr {
        builder = builder.address_lookup(iroh::address_lookup::PkarrPublisher::n0_dns());
    }
    if options.resolve_pkarr {
        builder = builder.address_lookup(iroh::address_lookup::PkarrResolver::n0_dns());
        builder = builder.address_lookup(iroh::address_lookup::DnsAddressLookup::n0_dns());
    }
    if let Some(seed) = secret_seed {
        let sk = SecretKey::from_bytes(&seed);
        builder = builder.secret_key(sk);
    }
    if !alpns.is_empty() {
        builder = builder.alpns(alpns);
    }
    builder
        .bind()
        .await
        .map_err(|err| RuntimeError::Protocol(format!("iroh endpoint bind failed: {err}")))
}

/// Formats an [`EndpointAddr`] without direct `?addr=` IP hints (`iroh://<endpoint_id>[?relay=...]`).
#[must_use]
pub fn format_p2p_endpoint(addr: &EndpointAddr) -> String {
    format_p2p_endpoint_with_addrs(addr, false)
}

/// Formats an [`EndpointAddr`] as `iroh://<endpoint_id>[?addr=...&relay=...]`, omitting `?addr=`
/// hints unless `include_addrs` is `true` and unconditionally skipping link-local/metadata IPs.
#[must_use]
pub fn format_p2p_endpoint_with_addrs(addr: &EndpointAddr, include_addrs: bool) -> String {
    let mut query = Vec::new();
    if include_addrs {
        for sock in addr.ip_addrs() {
            if !super::is_metadata_or_link_local_ip(sock.ip()) {
                query.push(format!("addr={sock}"));
            }
        }
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
                    let validated = super::validate_iroh_relay_url(val)?;
                    let url = RelayUrl::from_str(validated.as_str()).map_err(|err| {
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
    advertise_direct_addrs: bool,
    accepted_rx: mpsc::Receiver<P2pStream>,
    accept_task: JoinHandle<()>,
    write_timeout: Duration,
}

impl P2pListener {
    /// Binds a new `iroh` P2P endpoint listener under `relay_mode` with a fresh ephemeral key.
    pub async fn bind(relay_mode: P2pRelayMode) -> Result<Self, RuntimeError> {
        Self::bind_with_options(P2pOptions::for_listener(relay_mode), None).await
    }

    /// Binds a new `iroh` P2P endpoint listener under `relay_mode` with a deterministic secret seed.
    pub async fn bind_with_secret(
        relay_mode: P2pRelayMode,
        secret_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, RuntimeError> {
        Self::bind_with_options(P2pOptions::for_listener(relay_mode), Some(secret_seed)).await
    }

    /// Binds a new `iroh` P2P endpoint listener with explicit privacy and lookup options.
    pub async fn bind_with_options(
        options: P2pOptions,
        secret_seed: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, RuntimeError> {
        let endpoint =
            build_iroh_endpoint(&options, vec![TENDRIL_P2P_ALPN.to_vec()], secret_seed).await?;
        if !matches!(options.relay_mode, P2pRelayMode::Disabled) {
            let _ = timeout(Duration::from_secs(3), endpoint.online()).await;
        }
        let advertise_direct_addrs = options.advertise_direct_addrs;
        let local_ep = format_p2p_endpoint_with_addrs(&endpoint.addr(), advertise_direct_addrs);
        let write_timeout = DEFAULT_WRITE_TIMEOUT;
        let guard = EndpointGuard::new(endpoint);
        let (accepted_tx, accepted_rx) = mpsc::channel(32);
        let incoming_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let pre_accepts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let peer_accepts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let guard_clone = Arc::clone(&guard);

        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = guard_clone.endpoint.accept().await {
                let source_key = normalize_incoming_source(&incoming.remote_addr());
                let Some(pre_guard) = PeerAcceptGuard::try_acquire(
                    Arc::clone(&pre_accepts),
                    source_key,
                    MAX_CONCURRENT_ACCEPTS_PER_PEER,
                ) else {
                    incoming.ignore();
                    continue;
                };
                let Ok(pre_permit) = Arc::clone(&incoming_sem).try_acquire_owned() else {
                    drop(pre_guard);
                    incoming.ignore();
                    continue;
                };
                let tx_c = accepted_tx.clone();
                let stream_guard = Arc::clone(&guard_clone);
                let peer_counts = Arc::clone(&peer_accepts);
                let post_sem = Arc::clone(&sem);
                tokio::spawn(async move {
                    let conn_res = timeout(P2P_CONNECT_TIMEOUT, incoming).await;
                    drop(pre_permit);
                    drop(pre_guard);
                    let Ok(Ok(conn)) = conn_res else {
                        return;
                    };
                    let Ok(_permit) = post_sem.try_acquire_owned() else {
                        conn.close(0u32.into(), b"rate_limited");
                        return;
                    };
                    let Some(_peer_guard) = PeerAcceptGuard::try_acquire(
                        peer_counts,
                        conn.remote_id(),
                        MAX_CONCURRENT_ACCEPTS_PER_PEER,
                    ) else {
                        conn.close(0u32.into(), b"rate_limited");
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
            advertise_direct_addrs,
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
        format_p2p_endpoint_with_addrs(&self.guard.endpoint.addr(), self.advertise_direct_addrs)
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
        let current = format_p2p_endpoint_with_addrs(
            &self.guard.endpoint.addr(),
            self.advertise_direct_addrs,
        );
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
        Self::bind_with_options(P2pOptions::for_dialer(relay_mode)).await
    }

    /// Binds a client `iroh` endpoint with explicit privacy and lookup options.
    pub async fn bind_with_options(options: P2pOptions) -> Result<Self, RuntimeError> {
        let allow_private_addrs = options.allow_private_addrs;
        let endpoint = build_iroh_endpoint(&options, Vec::new(), None).await?;
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

    #[test]
    fn incoming_source_key_normalizes_ipv6_prefix_and_caps_concurrent_guards() {
        let counts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let a1 = normalize_incoming_source(&iroh::endpoint::IncomingAddr::Ip(
            "[2001:db8:1:2::10]:4433".parse().expect("sock"),
        ));
        let a2 = normalize_incoming_source(&iroh::endpoint::IncomingAddr::Ip(
            "[2001:db8:1:2:ffff::99]:5555".parse().expect("sock"),
        ));
        assert_eq!(a1, a2);

        let g1 = PeerAcceptGuard::try_acquire(Arc::clone(&counts), a1.clone(), 4).expect("1");
        let g2 = PeerAcceptGuard::try_acquire(Arc::clone(&counts), a1.clone(), 4).expect("2");
        let g3 = PeerAcceptGuard::try_acquire(Arc::clone(&counts), a1.clone(), 4).expect("3");
        let g4 = PeerAcceptGuard::try_acquire(Arc::clone(&counts), a2, 4).expect("4");
        assert!(PeerAcceptGuard::try_acquire(Arc::clone(&counts), a1.clone(), 4).is_none());
        let other = normalize_incoming_source(&iroh::endpoint::IncomingAddr::Ip(
            "192.0.2.50:4433".parse().expect("sock"),
        ));
        let g_other = PeerAcceptGuard::try_acquire(Arc::clone(&counts), other, 4).expect("other");
        drop((g1, g2, g3, g4, g_other));
        assert!(counts.lock().expect("lock").is_empty());
    }
}
