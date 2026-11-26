//! Direct WebTransport (HTTP/3 over QUIC) path provider (`wt://`).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tendril_core::crypto::{b64url_decode_array, b64url_encode};
use tendril_core::pairing::is_valid_pairing_endpoint_hint;
use tendril_core::policy::ProviderId;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use wtransport::config::{DnsLookupFuture, DnsResolver, IpBindConfig};
use wtransport::endpoint::endpoint_side;
use wtransport::tls::Sha256Digest;
use wtransport::tls::self_signed::time::{Duration as TimeDuration, OffsetDateTime};
use wtransport::{
    ClientConfig, Connection, Endpoint, Identity, RecvStream, SendStream, ServerConfig, VarInt,
};

use super::egress::{
    DestClass, EgressAddrPolicy, SkipReason, classify_destination, resolve_checked,
    scoped_addr_policy,
};
use super::ensure_rustls_ring_provider;
use crate::error::RuntimeError;
use crate::provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathReader, PathStream,
    PathWriter,
};
use crate::redact::{redact_text, redact_url_str};

const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_ACCEPTS: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const CLOSE_FINISH_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone)]
pub(crate) struct ParsedWtUrl {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) https_url: String,
    pub(crate) certhash: Option<[u8; 32]>,
}

pub(crate) fn parse_wt_url(raw: &str) -> Result<ParsedWtUrl, RuntimeError> {
    let invalid = || {
        RuntimeError::Protocol(format!(
            "invalid webtransport endpoint {}",
            redact_url_str(raw)
        ))
    };
    if !is_valid_pairing_endpoint_hint(raw) {
        return Err(invalid());
    }
    let rest = raw.strip_prefix("wt://").ok_or_else(invalid)?;
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(invalid());
    }
    let port_str = if let Some(bracket_rest) = authority.strip_prefix('[') {
        let (inner, after) = bracket_rest.split_once(']').ok_or_else(invalid)?;
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err(invalid());
        }
        after.strip_prefix(':').ok_or_else(invalid)?
    } else {
        let (h, p) = authority.rsplit_once(':').ok_or_else(invalid)?;
        if h.is_empty() || h.contains(':') {
            return Err(invalid());
        }
        p
    };
    let port = port_str
        .parse::<u16>()
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(invalid)?;

    let (base_rest, query_opt) = rest
        .split_once('?')
        .map_or((rest, None), |(b, q)| (b, Some(q)));
    let certhash = if let Some(query) = query_opt {
        let val = query.strip_prefix("certhash=").ok_or_else(invalid)?;
        if val.len() != 43
            || !val
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(invalid());
        }
        Some(b64url_decode_array::<32>(val).map_err(|_| invalid())?)
    } else {
        None
    };

    let parsed = url::Url::parse(&format!("https://{base_rest}")).map_err(|_| invalid())?;
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(invalid());
    }

    let (host, authority_host) = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => {
            if classify_destination(IpAddr::V4(v4)) == DestClass::Blocked {
                return Err(RuntimeError::Egress {
                    reason: SkipReason::BlockedAddress,
                    detail: format!("wt host '{v4}' is not permitted"),
                });
            }
            let s = v4.to_string();
            (s.clone(), s)
        }
        Some(url::Host::Ipv6(v6)) => {
            if classify_destination(IpAddr::V6(v6)) == DestClass::Blocked {
                return Err(RuntimeError::Egress {
                    reason: SkipReason::BlockedAddress,
                    detail: format!("wt host '[{v6}]' is not permitted"),
                });
            }
            let s = v6.to_string();
            (s.clone(), format!("[{s}]"))
        }
        Some(url::Host::Domain(domain)) => {
            let trimmed = domain.trim_end_matches('.');
            if trimmed.is_empty() {
                return Err(invalid());
            }
            if trimmed.eq_ignore_ascii_case("metadata.google.internal") {
                return Err(RuntimeError::Egress {
                    reason: SkipReason::BlockedAddress,
                    detail: "cloud metadata hostname is not permitted".into(),
                });
            }
            (trimmed.to_owned(), trimmed.to_owned())
        }
        None => return Err(invalid()),
    };
    let path_suffix = if parsed.path() == "/" && !base_rest[authority.len()..].starts_with('/') {
        ""
    } else {
        parsed.path()
    };
    let https_url = format!("https://{authority_host}:{port}{path_suffix}");

    Ok(ParsedWtUrl {
        host,
        port,
        https_url,
        certhash,
    })
}

fn default_sans_for(addr: SocketAddr) -> Vec<String> {
    let mut sans = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |s: String| {
        if seen.insert(s.clone()) {
            sans.push(s);
        }
    };
    push("localhost".to_owned());
    push("127.0.0.1".to_owned());
    push("::1".to_owned());
    if !addr.ip().is_unspecified() {
        push(addr.ip().to_string());
    }
    sans
}

fn format_host_port(host: &str, port: u16) -> String {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if bare.contains(':') {
        format!("[{bare}]:{port}")
    } else {
        format!("{bare}:{port}")
    }
}

/// WebTransport (HTTP/3 over QUIC) listener implementing the `direct` path provider.
pub struct WtListener {
    local_addr: SocketAddr,
    certhash: String,
    advertised_host: Option<String>,
    endpoint: Arc<Endpoint<endpoint_side::Server>>,
    accepted_rx: mpsc::Receiver<Box<dyn PathStream>>,
    accept_task: JoinHandle<()>,
}

impl WtListener {
    /// Binds a WebTransport listener at `addr` with a 10-day self-signed ECDSA P-256 certificate.
    pub async fn bind(addr: SocketAddr) -> Result<Self, RuntimeError> {
        Self::bind_with_san(addr, default_sans_for(addr)).await
    }

    /// Binds a WebTransport listener at `addr` with explicit certificate SANs.
    pub async fn bind_with_san(addr: SocketAddr, sans: Vec<String>) -> Result<Self, RuntimeError> {
        super::egress::check_bind_addr(addr)?;
        ensure_rustls_ring_provider();
        let not_before = OffsetDateTime::now_utc() - TimeDuration::hours(1);
        let identity = Identity::self_signed_builder()
            .subject_alt_names(sans)
            .not_before(not_before)
            .validity_days(10)
            .build()
            .map_err(|err| RuntimeError::Protocol(format!("invalid webtransport SAN: {err}")))?;
        let cert_hash = identity
            .certificate_chain()
            .as_slice()
            .first()
            .map(wtransport::tls::Certificate::hash)
            .ok_or_else(|| RuntimeError::Protocol("missing self-signed certificate".into()))?;
        let certhash = b64url_encode(cert_hash.as_ref());

        let config = ServerConfig::builder()
            .with_bind_address(addr)
            .with_identity(identity)
            .max_idle_timeout(Some(IDLE_TIMEOUT))
            .map_err(|err| RuntimeError::Protocol(format!("invalid idle timeout: {err}")))?
            .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
            .build();

        let endpoint = Arc::new(Endpoint::server(config)?);
        let local_addr = endpoint.local_addr()?;

        let (accepted_tx, accepted_rx) = mpsc::channel::<Box<dyn PathStream>>(32);
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let ep_loop = Arc::clone(&endpoint);
        let accept_task = tokio::spawn(async move {
            loop {
                let incoming = ep_loop.accept().await;
                let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let tx_c = accepted_tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let handshake_and_enqueue = async {
                        let req = incoming.await.ok()?;
                        let conn = req.accept().await.ok()?;
                        let peer_ip = conn.remote_address().ip();
                        let (send, recv) = conn.accept_bi().await.ok()?;
                        let stream = WtPathStream::new(
                            conn,
                            send,
                            recv,
                            Some(peer_ip),
                            DEFAULT_WRITE_TIMEOUT,
                        );
                        let _ = tx_c.send(Box::new(stream)).await;
                        Some(())
                    };
                    let _ = timeout(ACCEPT_HANDSHAKE_TIMEOUT, handshake_and_enqueue).await;
                });
            }
        });

        Ok(Self {
            local_addr,
            certhash,
            advertised_host: None,
            endpoint,
            accepted_rx,
            accept_task,
        })
    }

    /// Overrides the advertised host used by [`PathListener::local_endpoint`].
    #[must_use]
    pub fn with_advertised_host(mut self, host: impl Into<String>) -> Self {
        self.advertised_host = Some(host.into());
        self
    }

    /// Returns the local UDP socket address bound by this listener.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the 43-character base64url SHA-256 certificate hash for `?certhash=`.
    #[must_use]
    pub fn certhash(&self) -> &str {
        &self.certhash
    }

    /// Formats a `wt://` endpoint for a concrete host or IP using this listener's bound port and
    /// certificate hash.
    #[must_use]
    pub fn endpoint_for(&self, host: &str) -> String {
        format!(
            "wt://{}?certhash={}",
            format_host_port(host, self.local_addr.port()),
            self.certhash
        )
    }
}

impl Drop for WtListener {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.endpoint.close(VarInt::from_u32(0), b"listener closed");
    }
}

#[async_trait]
impl PathListener for WtListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.accepted_rx.recv().await.ok_or(RuntimeError::Closed)
    }

    fn local_endpoint(&self) -> String {
        match &self.advertised_host {
            Some(host) => self.endpoint_for(host),
            None => format!("wt://{}?certhash={}", self.local_addr, self.certhash),
        }
    }
}

#[derive(Debug)]
struct PinnedDnsResolver(SocketAddr);

impl DnsResolver for PinnedDnsResolver {
    fn resolve(&self, _host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let addr = self.0;
        Box::pin(async move { Ok(Some(addr)) })
    }
}

/// Dialer opening WebTransport bidirectional streams (`wt://`).
#[derive(Debug, Clone)]
pub struct WtDialer {
    write_timeout: Duration,
    connect_timeout: Duration,
}

impl Default for WtDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl WtDialer {
    /// Constructs a `WtDialer` with [`DEFAULT_WRITE_TIMEOUT`] and a 10 s connect timeout.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub const fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Overrides the WebTransport connect timeout.
    #[must_use]
    pub const fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    async fn dial_addr(
        &self,
        parsed: &ParsedWtUrl,
        addr: SocketAddr,
        endpoint_display: &str,
    ) -> Result<Box<dyn PathStream>, RuntimeError> {
        let bind_cfg = match addr {
            SocketAddr::V4(_) => IpBindConfig::InAddrAnyV4,
            SocketAddr::V6(_) => IpBindConfig::InAddrAnyV6,
        };
        let builder = ClientConfig::builder().with_bind_config(bind_cfg);
        let builder = match parsed.certhash {
            Some(digest) => builder.with_server_certificate_hashes([Sha256Digest::new(digest)]),
            None => builder.with_native_certs(),
        };
        let config = builder
            .max_idle_timeout(Some(IDLE_TIMEOUT))
            .map_err(|err| RuntimeError::Protocol(format!("invalid idle timeout: {err}")))?
            .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
            .dns_resolver(PinnedDnsResolver(addr))
            .build();

        let client_ep = Endpoint::client(config)?;
        let connect_fut = async {
            let conn = client_ep.connect(&parsed.https_url).await.map_err(|err| {
                RuntimeError::Protocol(format!(
                    "webtransport dial {endpoint_display} failed: {}",
                    redact_text(&err.to_string())
                ))
            })?;
            let (send, recv) = conn
                .open_bi()
                .await
                .map_err(|err| {
                    RuntimeError::Protocol(format!(
                        "webtransport open_bi failed: {}",
                        redact_text(&err.to_string())
                    ))
                })?
                .await
                .map_err(|err| {
                    RuntimeError::Protocol(format!(
                        "webtransport bi stream failed: {}",
                        redact_text(&err.to_string())
                    ))
                })?;
            let peer_ip = conn.remote_address().ip();
            Ok::<_, RuntimeError>(WtPathStream::new(
                conn,
                send,
                recv,
                Some(peer_ip),
                self.write_timeout,
            ))
        };

        let stream = timeout(self.connect_timeout, connect_fut)
            .await
            .map_err(|_| RuntimeError::Timeout("webtransport connect timed out"))??;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl PathDialer for WtDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        ensure_rustls_ring_provider();
        let parsed = parse_wt_url(endpoint)?;
        let policy = scoped_addr_policy().unwrap_or_else(|| Arc::new(EgressAddrPolicy::default()));
        let addrs = resolve_checked(&parsed.host, parsed.port, &*policy).await?;
        let display = redact_url_str(endpoint);

        let mut last_err = None;
        for addr in addrs {
            match self.dial_addr(&parsed, addr, &display).await {
                Ok(stream) => return Ok(stream),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            RuntimeError::Protocol("webtransport dial failed: no resolved address".into())
        }))
    }
}

struct WtConnGuard(Connection);

impl Drop for WtConnGuard {
    fn drop(&mut self) {
        self.0.close(VarInt::from_u32(0), b"");
    }
}

/// Bidirectional `PathStream` over a single WebTransport HTTP/3 stream.
pub struct WtPathStream {
    conn: Arc<WtConnGuard>,
    send: SendStream,
    recv: RecvStream,
    peer_ip: Option<IpAddr>,
    write_timeout: Duration,
}

impl WtPathStream {
    fn new(
        conn: Connection,
        send: SendStream,
        recv: RecvStream,
        peer_ip: Option<IpAddr>,
        write_timeout: Duration,
    ) -> Self {
        Self {
            conn: Arc::new(WtConnGuard(conn)),
            send,
            recv,
            peer_ip,
            write_timeout,
        }
    }
}

async fn wt_send_chunk(
    send: &mut SendStream,
    write_timeout: Duration,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    if bytes.len() > MAX_OUTER_FRAME_LEN {
        return Err(RuntimeError::FrameTooLarge {
            size: bytes.len(),
            max: MAX_OUTER_FRAME_LEN,
        });
    }
    match timeout(write_timeout, send.write_all(bytes)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(RuntimeError::Protocol(redact_text(&err.to_string()))),
        Err(_) => Err(RuntimeError::Timeout("webtransport stream write timed out")),
    }
}

async fn wt_recv_chunk(recv: &mut RecvStream, buf: &mut [u8]) -> Result<usize, RuntimeError> {
    if buf.is_empty() {
        return Ok(0);
    }
    match recv.read(buf).await {
        Ok(Some(n)) => Ok(n),
        Ok(None) => Ok(0),
        Err(err) => Err(RuntimeError::Protocol(redact_text(&err.to_string()))),
    }
}

async fn wt_close_stream(send: &mut SendStream, conn: &WtConnGuard) {
    let _ = timeout(CLOSE_FINISH_TIMEOUT, send.finish()).await;
    conn.0.close(VarInt::from_u32(0), b"");
}

struct WtReadHalf {
    recv: RecvStream,
    _conn: Arc<WtConnGuard>,
}

struct WtWriteHalf {
    send: SendStream,
    _conn: Arc<WtConnGuard>,
    write_timeout: Duration,
}

#[async_trait]
impl PathReader for WtReadHalf {
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        wt_recv_chunk(&mut self.recv, buf).await
    }
}

#[async_trait]
impl PathWriter for WtWriteHalf {
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        wt_send_chunk(&mut self.send, self.write_timeout, bytes).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        let _ = timeout(CLOSE_FINISH_TIMEOUT, self.send.finish()).await;
        Ok(())
    }
}

#[async_trait]
impl PathStream for WtPathStream {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        wt_send_chunk(&mut self.send, self.write_timeout, bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        wt_recv_chunk(&mut self.recv, buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        wt_close_stream(&mut self.send, &self.conn).await;
        Ok(())
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        (
            Box::new(WtReadHalf {
                recv: self.recv,
                _conn: Arc::clone(&self.conn),
            }),
            Box::new(WtWriteHalf {
                send: self.send,
                _conn: self.conn,
                write_timeout: self.write_timeout,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::providers::egress::{AddrPolicy, HostResolver, with_addr_policy};

    #[derive(Debug)]
    struct CountingBlockAllPolicy {
        lookups: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct CountingResolver(Arc<AtomicUsize>);

    #[async_trait]
    impl HostResolver for CountingResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    impl AddrPolicy for CountingBlockAllPolicy {
        fn check(&self, ip: IpAddr) -> Result<(), SkipReason> {
            if classify_destination(ip) == DestClass::Blocked
                || classify_destination(ip) == DestClass::Loopback
            {
                Err(SkipReason::BlockedAddress)
            } else {
                Ok(())
            }
        }

        fn resolver(&self) -> &dyn HostResolver {
            Box::leak(Box::new(CountingResolver(Arc::clone(&self.lookups))))
        }
    }

    #[tokio::test]
    async fn wt_dialer_rejects_percent_encoded_and_integer_ssrf_without_dns() {
        let lookups = Arc::new(AtomicUsize::new(0));
        let policy: Arc<dyn AddrPolicy> = Arc::new(CountingBlockAllPolicy {
            lookups: Arc::clone(&lookups),
        });
        let dialer = WtDialer::new();

        // Percent-encoded host fails closed at URL validation without touching DNS.
        let pct_err = with_addr_policy(
            Arc::clone(&policy),
            dialer.dial("wt://%31%36%39.254.169.254:4433"),
        )
        .await
        .err()
        .expect("percent-encoded host must be rejected");
        assert!(matches!(pct_err, RuntimeError::Protocol(_)), "{pct_err}");
        assert_eq!(lookups.load(Ordering::SeqCst), 0);

        // Integer loopback obfuscation normalizes to 127.0.0.1 and fails policy without DNS.
        let int_err = with_addr_policy(Arc::clone(&policy), dialer.dial("wt://2130706433:4433"))
            .await
            .err()
            .expect("integer loopback host must fail policy");
        assert_eq!(int_err.skip_reason(), Some(SkipReason::BlockedAddress));
        assert_eq!(lookups.load(Ordering::SeqCst), 0);

        // Integer metadata IP fails closed without DNS even under default policy.
        let meta_err = dialer
            .dial("wt://2852039166:4433")
            .await
            .err()
            .expect("integer metadata IP must be rejected");
        assert!(matches!(meta_err, RuntimeError::Protocol(_)), "{meta_err}");
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wt_write_half_close_preserves_peer_reads_until_fin() {
        let mut listener = WtListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind");
        let ep = listener.local_endpoint();
        let server_task = tokio::spawn(async move {
            let mut srv = listener.accept().await.expect("accept");
            let mut buf = [0u8; 64];
            let n = srv.recv_chunk(&mut buf).await.expect("recv ping");
            assert_eq!(&buf[..n], b"ping");
            let eof = srv.recv_chunk(&mut buf).await.expect("recv fin");
            assert_eq!(eof, 0);
            srv.send_chunk(b"pong-after-fin")
                .await
                .expect("send after peer half-close");
            srv.close().await.expect("close server");
        });

        let client = WtDialer::new().dial(&ep).await.expect("dial");
        let (mut reader, mut writer) = client.into_split();
        writer.send_chunk(b"ping").await.expect("send ping");
        writer.close().await.expect("close write half");

        let mut buf = [0u8; 64];
        let n = reader.recv_chunk(&mut buf).await.expect("recv pong");
        assert_eq!(&buf[..n], b"pong-after-fin");
        server_task.await.expect("server task");
    }
}
