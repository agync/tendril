//! Built-in untrusted path provider implementations (`local`, `direct`, `overlay`, `p2p`, `relay`, `broker`).

pub mod broker;
pub mod direct;
pub mod local;
pub mod overlay;
#[cfg(feature = "p2p-iroh")]
pub mod p2p;
pub mod relay;
pub mod relay_v2;

use std::collections::VecDeque;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tendril_core::policy::ProviderId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::error::RuntimeError;
use crate::provider::{MAX_OUTER_FRAME_LEN, PathDialer, PathReader, PathStream, PathWriter};

pub use broker::{BrokerDialer, BrokerListener, BrokerServerConfig};
pub use direct::{DirectDialer, DirectListener};
pub use local::{LocalDialer, LocalListener};
pub use overlay::{
    OverlayConfig, OverlayDialer, OverlayHelperDialer, OverlayHelperListener, OverlayListener,
    OverlayMode, OverlayResolvedMode, is_tailnet_ip, select_overlay_mode,
};
#[cfg(feature = "p2p-iroh")]
pub use p2p::{
    MAX_P2P_CUSTOM_RELAYS, P2pDialer, P2pListener, P2pOptions, P2pRelayAuth, P2pRelayMode,
    TENDRIL_P2P_ALPN, format_p2p_endpoint, format_p2p_endpoint_with_addrs, parse_p2p_endpoint,
    parse_p2p_endpoint_filtered, parse_p2p_relay_mode, parse_p2p_relay_modes,
};
pub use relay::{EmbeddedRelay, RelayClientAuth, RelayDialer, RelayListener};
pub use relay_v2::{RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig};

/// Dials any supported Tendril endpoint (`iroh://`, `overlay://`, `broker+ws(s)://`,
/// `ws(s)://`, `unix://`/`/...`, or `host:port`) via its matching [`PathDialer`].
///
/// For `ws(s)://`, `relay_host` overrides the expected TLS and challenge hostname.
/// For `iroh://`, `relay_host` selects the P2P relay mode (`"default"`, `"disabled"`/`"local"`,
/// or `https://...`); when `None` and `TENDRIL_P2P_LOCAL=1`, local-only mode is selected.
pub async fn dial_endpoint(
    endpoint: &str,
    relay_host: Option<&str>,
) -> Result<Box<dyn PathStream>, RuntimeError> {
    dial_endpoint_with_auth(endpoint, relay_host, RelayClientAuth::None).await
}

/// Dials any supported Tendril endpoint while attaching optional [`RelayClientAuth`] for
/// `ws(s)://` relay endpoints.
pub async fn dial_endpoint_with_auth(
    endpoint: &str,
    relay_host: Option<&str>,
    relay_auth: RelayClientAuth,
) -> Result<Box<dyn PathStream>, RuntimeError> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        #[cfg(feature = "p2p-iroh")]
        {
            let mode = match normalized_host {
                Some(spec) => parse_p2p_relay_mode(Some(spec))?,
                None if std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1") => {
                    P2pRelayMode::Disabled
                }
                None => P2pRelayMode::Default,
            };
            let dialer = P2pDialer::bind(mode).await?;
            return match dialer.dial(endpoint).await {
                Ok(stream) => Ok(stream),
                Err(err) => {
                    dialer.close().await;
                    Err(err)
                }
            };
        }
        #[cfg(not(feature = "p2p-iroh"))]
        {
            let _ = normalized_host;
            return Err(RuntimeError::Protocol(
                "p2p-iroh feature is not enabled in tendril-runtime".to_owned(),
            ));
        }
    }
    if endpoint.starts_with("overlay://") {
        return OverlayDialer::new().dial(endpoint).await;
    }
    if endpoint.starts_with("broker+ws://") || endpoint.starts_with("broker+wss://") {
        return BrokerDialer::new().dial(endpoint).await;
    }
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        let mut dialer = RelayDialer::new().with_auth(relay_auth);
        if let Some(host) = normalized_host {
            dialer = dialer.with_expected_host(host);
        }
        return dialer.dial(endpoint).await;
    }
    if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        return LocalDialer::new().dial(endpoint).await;
    }
    DirectDialer::new().dial(endpoint).await
}

static RUSTLS_RING_INIT: Once = Once::new();

pub(crate) fn ensure_rustls_ring_provider() {
    RUSTLS_RING_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub(crate) fn ws_binary_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_OUTER_FRAME_LEN * 2)
        .max_message_size(Some(MAX_OUTER_FRAME_LEN))
        .max_frame_size(Some(MAX_OUTER_FRAME_LEN))
}

#[cfg(unix)]
pub(crate) fn set_mode_0600(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_mode_0600(_path: &Path) -> Result<(), RuntimeError> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn create_private_dir_0700(dir: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(RuntimeError::Storage(format!(
            "refusing symlink or non-directory '{}'",
            dir.display()
        )));
    }
    if (meta.permissions().mode() & 0o077) != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn create_private_dir_0700(dir: &Path) -> Result<(), RuntimeError> {
    fs::create_dir_all(dir)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn bind_private_unix_listener(
    path: &Path,
    enforce_parent_0700: bool,
) -> Result<tokio::net::UnixListener, RuntimeError> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
    static STAGE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
                return Err(RuntimeError::Storage(format!(
                    "refusing to unlink symlink or non-socket path '{}'",
                    path.display()
                )));
            }
            fs::remove_file(path)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(RuntimeError::Io(err)),
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if enforce_parent_0700 {
        create_private_dir_0700(parent)?;
    } else if fs::symlink_metadata(parent).is_err() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    let parent_meta = fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(RuntimeError::Storage(format!(
            "socket parent directory '{}' must be a real directory",
            parent.display()
        )));
    }

    if (parent_meta.permissions().mode() & 0o077) != 0 {
        let seq = STAGE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stage_dir = parent.join(format!(".t-{}-{seq}", std::process::id()));
        let stage_sock = stage_dir.join("s");
        if stage_sock.as_os_str().as_encoded_bytes().len() < 104 {
            fs::DirBuilder::new().mode(0o700).create(&stage_dir)?;
            let res = (|| -> Result<tokio::net::UnixListener, RuntimeError> {
                fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700))?;
                let listener = tokio::net::UnixListener::bind(&stage_sock)?;
                set_mode_0600(&stage_sock)?;
                match fs::symlink_metadata(path) {
                    Ok(_) => {
                        return Err(RuntimeError::Storage(format!(
                            "concurrent path created at '{}'",
                            path.display()
                        )));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(RuntimeError::Io(err)),
                }
                fs::rename(&stage_sock, path)?;
                Ok(listener)
            })();
            let _ = fs::remove_file(&stage_sock);
            let _ = fs::remove_dir(&stage_dir);
            return res;
        }
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    let sock_meta = fs::symlink_metadata(path)?;
    if sock_meta.file_type().is_symlink() || !sock_meta.file_type().is_socket() {
        return Err(RuntimeError::Storage(format!(
            "bound path '{}' is not a unix socket",
            path.display()
        )));
    }
    set_mode_0600(path)?;
    Ok(listener)
}

#[cfg(not(unix))]
pub(crate) fn bind_private_unix_listener(
    path: &Path,
    enforce_parent_0700: bool,
) -> Result<tokio::net::UnixListener, RuntimeError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && (enforce_parent_0700 || !parent.exists())
    {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(tokio::net::UnixListener::bind(path)?)
}

/// Shared WebSocket binary-frame `PathStream` used by `relay` and `broker` providers.
pub(crate) struct WsBinaryPathStream<S> {
    provider: ProviderId,
    peer_ip: Option<IpAddr>,
    ws: WebSocketStream<S>,
    write_timeout: Duration,
    max_recv_len: usize,
    pending_read: VecDeque<u8>,
}

impl<S> WsBinaryPathStream<S> {
    pub(crate) fn new(
        provider: ProviderId,
        peer_ip: Option<IpAddr>,
        ws: WebSocketStream<S>,
        write_timeout: Duration,
        max_recv_len: usize,
    ) -> Self {
        Self {
            provider,
            peer_ip,
            ws,
            write_timeout,
            max_recv_len,
            pending_read: VecDeque::new(),
        }
    }
}

async fn ws_send_chunk<Snk, E>(
    sink: &mut Snk,
    write_timeout: Duration,
    bytes: &[u8],
) -> Result<(), RuntimeError>
where
    Snk: Sink<Message, Error = E> + Unpin,
    E: std::fmt::Display,
{
    if bytes.len() > MAX_OUTER_FRAME_LEN {
        return Err(RuntimeError::FrameTooLarge {
            size: bytes.len(),
            max: MAX_OUTER_FRAME_LEN,
        });
    }
    match timeout(
        write_timeout,
        sink.send(Message::Binary(bytes.to_vec().into())),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(RuntimeError::Protocol(err.to_string())),
        Err(_) => Err(RuntimeError::Timeout("websocket stream write timed out")),
    }
}

async fn ws_recv_chunk<Strm, E>(
    stream: &mut Strm,
    pending_read: &mut VecDeque<u8>,
    max_recv_len: usize,
    buf: &mut [u8],
) -> Result<usize, RuntimeError>
where
    Strm: Stream<Item = Result<Message, E>> + Unpin,
    E: std::fmt::Display,
{
    if buf.is_empty() {
        return Ok(0);
    }
    if !pending_read.is_empty() {
        let take = buf.len().min(pending_read.len());
        for slot in &mut buf[..take] {
            *slot = pending_read.pop_front().expect("checked non-empty");
        }
        return Ok(take);
    }

    while let Some(item) = stream.next().await {
        match item {
            Ok(Message::Binary(data)) => {
                if data.len() > max_recv_len {
                    return Err(RuntimeError::FrameTooLarge {
                        size: data.len(),
                        max: max_recv_len,
                    });
                }
                if data.is_empty() {
                    return Err(RuntimeError::Protocol(
                        "empty websocket binary frame".to_owned(),
                    ));
                }
                let take = buf.len().min(data.len());
                buf[..take].copy_from_slice(&data[..take]);
                if take < data.len() {
                    pending_read.extend(&data[take..]);
                }
                return Ok(take);
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            Ok(Message::Close(_)) => return Ok(0),
            Ok(other) => {
                return Err(RuntimeError::Protocol(format!(
                    "unexpected non-binary websocket frame: {other:?}"
                )));
            }
            Err(err) => return Err(RuntimeError::Protocol(err.to_string())),
        }
    }
    Ok(0)
}

struct WsReadHalf<S> {
    stream: SplitStream<WebSocketStream<S>>,
    max_recv_len: usize,
    pending_read: VecDeque<u8>,
}

struct WsWriteHalf<S> {
    sink: SplitSink<WebSocketStream<S>, Message>,
    write_timeout: Duration,
}

#[async_trait]
impl<S> PathReader for WsReadHalf<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        ws_recv_chunk(
            &mut self.stream,
            &mut self.pending_read,
            self.max_recv_len,
            buf,
        )
        .await
    }
}

#[async_trait]
impl<S> PathWriter for WsWriteHalf<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        ws_send_chunk(&mut self.sink, self.write_timeout, bytes).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        let _ = timeout(self.write_timeout, self.sink.close()).await;
        Ok(())
    }
}

#[async_trait]
impl<S> PathStream for WsBinaryPathStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        ws_send_chunk(&mut self.ws, self.write_timeout, bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        ws_recv_chunk(&mut self.ws, &mut self.pending_read, self.max_recv_len, buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        let _ = timeout(self.write_timeout, self.ws.close(None)).await;
        Ok(())
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        let (sink, stream) = self.ws.split();
        (
            Box::new(WsReadHalf {
                stream,
                max_recv_len: self.max_recv_len,
                pending_read: self.pending_read,
            }),
            Box::new(WsWriteHalf {
                sink,
                write_timeout: self.write_timeout,
            }),
        )
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

fn strip_host_brackets(host: &str) -> &str {
    let trimmed = host.trim();
    trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed)
}

/// Returns `true` if `host` refers to loopback (`localhost`, `*.localhost`, `127.0.0.0/8`, or `::1`).
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let bare = strip_host_brackets(host).trim_end_matches('.');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return match canonical_ip(ip) {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        };
    }
    let suffix = b".localhost";
    let bare_bytes = bare.as_bytes();
    bare.eq_ignore_ascii_case("localhost")
        || (bare_bytes.len() > suffix.len()
            && bare_bytes[bare_bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
}

/// Returns `true` if `ip` is a cloud metadata, link-local, or unspecified address.
#[must_use]
pub fn is_metadata_or_link_local_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    }
}

/// Returns `true` if `ip` is private, loopback, link-local, CGNAT, documentation, multicast, or reserved.
#[cfg(feature = "p2p-iroh")]
#[must_use]
pub(crate) fn is_private_or_reserved_ip(ip: IpAddr) -> bool {
    if is_metadata_or_link_local_ip(ip) {
        return true;
    }
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || oct[0] == 0
                || (oct[0] == 100 && (oct[1] & 0xc0) == 64)
                || (oct[0] == 192 && oct[1] == 0 && oct[2] == 0)
                || (oct[0] == 198 && (oct[1] & 0xfe) == 18)
                || oct[0] >= 240
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_multicast()
                || (segs[0] & 0xfe00) == 0xfc00
                || (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] & 0xffc0) == 0xfec0
                || (segs[0] == 0x2001 && segs[1] == 0x0db8)
                || (segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0)
                || segs == [0, 0, 0, 0, 0, 0, 0, 0]
        }
    }
}

fn validate_url_host_safety(parsed: &url::Url) -> Result<&str, RuntimeError> {
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RuntimeError::Protocol(
            "URL userinfo credentials are not permitted".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(RuntimeError::Protocol(
            "URL fragments are not permitted".into(),
        ));
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| RuntimeError::Protocol("URL is missing a host".into()))?;
    let bare = strip_host_brackets(host);
    if bare
        .trim_end_matches('.')
        .eq_ignore_ascii_case("metadata.google.internal")
    {
        return Err(RuntimeError::Protocol(
            "cloud metadata hostname is not permitted".into(),
        ));
    }
    if let Ok(ip) = bare.trim_end_matches('.').parse::<IpAddr>()
        && is_metadata_or_link_local_ip(ip)
    {
        return Err(RuntimeError::Protocol(format!(
            "link-local or metadata address '{ip}' is not permitted"
        )));
    }
    Ok(bare)
}

/// Validates a WebSocket relay URL (`ws` or `wss`).
pub(crate) fn validate_ws_url(
    url_str: &str,
    allow_insecure_ws: bool,
) -> Result<url::Url, RuntimeError> {
    if url_str.chars().any(char::is_control) {
        return Err(RuntimeError::Protocol(
            "websocket URL contains control characters".into(),
        ));
    }
    let trimmed = url_str.trim();
    let parsed = url::Url::parse(trimmed).map_err(|err| {
        RuntimeError::Protocol(format!("invalid websocket URL '{url_str}': {err}"))
    })?;
    let is_cleartext = match parsed.scheme() {
        "wss" => false,
        "ws" => true,
        other => {
            return Err(RuntimeError::Protocol(format!(
                "unsupported websocket scheme '{other}'"
            )));
        }
    };
    let bare_host = validate_url_host_safety(&parsed)?;
    if is_cleartext && !allow_insecure_ws && !is_loopback_host(bare_host) {
        return Err(RuntimeError::Protocol(format!(
            "cleartext {}:// requires explicit opt-in outside loopback",
            parsed.scheme()
        )));
    }
    Ok(parsed)
}

/// Validates a broker WebSocket URL (`broker+ws(s)://` or `ws(s)://`) and returns the normalized `ws(s)://` URL.
pub(crate) fn validate_broker_ws_url(
    url_str: &str,
    allow_insecure_ws: bool,
) -> Result<url::Url, RuntimeError> {
    if url_str.chars().any(char::is_control) {
        return Err(RuntimeError::Protocol(
            "websocket URL contains control characters".into(),
        ));
    }
    let trimmed = url_str.trim();
    if trimmed
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("broker+"))
    {
        let rest = &trimmed[7..];
        let is_ws = rest
            .get(..5)
            .is_some_and(|s| s.eq_ignore_ascii_case("ws://"))
            || rest
                .get(..6)
                .is_some_and(|s| s.eq_ignore_ascii_case("wss://"));
        if !is_ws {
            return Err(RuntimeError::Protocol(format!(
                "broker endpoint must use broker+ws(s):// or ws(s)://: '{url_str}'"
            )));
        }
        return validate_ws_url(rest, allow_insecure_ws);
    }
    validate_ws_url(trimmed, allow_insecure_ws)
}

/// Validates an `iroh` custom relay URL (`https://` anywhere, or `http://` only on loopback).
#[cfg(feature = "p2p-iroh")]
pub(crate) fn validate_iroh_relay_url(url_str: &str) -> Result<url::Url, RuntimeError> {
    if url_str.chars().any(char::is_control) {
        return Err(RuntimeError::Protocol(
            "iroh relay URL contains control characters".into(),
        ));
    }
    let trimmed = url_str.trim();
    let parsed = url::Url::parse(trimmed).map_err(|err| {
        RuntimeError::Protocol(format!("invalid iroh relay URL '{url_str}': {err}"))
    })?;
    if parsed.query().is_some() {
        return Err(RuntimeError::Protocol(
            "iroh relay URL must not contain a query string".into(),
        ));
    }
    let is_http = match parsed.scheme() {
        "https" => false,
        "http" => true,
        other => {
            return Err(RuntimeError::Protocol(format!(
                "unsupported iroh relay URL scheme '{other}'"
            )));
        }
    };
    let bare_host = validate_url_host_safety(&parsed)?;
    if is_http && !is_loopback_host(bare_host) {
        return Err(RuntimeError::Protocol(
            "cleartext http:// iroh relay URL is permitted only for loopback hosts".into(),
        ));
    }
    Ok(parsed)
}
