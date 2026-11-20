//! Built-in untrusted path provider implementations (`local`, `direct`, `overlay`, `p2p`, `relay`, `broker`).

pub mod broker;
pub mod direct;
pub mod local;
pub mod overlay;
#[cfg(feature = "p2p-iroh")]
pub mod p2p;
pub mod relay;

use std::collections::VecDeque;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tendril_core::policy::ProviderId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::error::RuntimeError;
use crate::provider::{MAX_OUTER_FRAME_LEN, PathDialer, PathStream};

pub use broker::{BrokerDialer, BrokerListener, BrokerServerConfig};
pub use direct::{DirectDialer, DirectListener};
pub use local::{LocalDialer, LocalListener};
pub use overlay::{
    OverlayConfig, OverlayDialer, OverlayHelperDialer, OverlayHelperListener, OverlayListener,
    OverlayMode, OverlayResolvedMode, is_tailnet_ip, select_overlay_mode,
};
#[cfg(feature = "p2p-iroh")]
pub use p2p::{
    P2pDialer, P2pListener, P2pRelayMode, TENDRIL_P2P_ALPN, format_p2p_endpoint,
    parse_p2p_endpoint, parse_p2p_relay_mode,
};
pub use relay::{EmbeddedRelay, RelayDialer, RelayListener};

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
        let mut dialer = RelayDialer::new();
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
pub(crate) fn set_dir_mode_0700(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_dir_mode_0700(_path: &Path) -> Result<(), RuntimeError> {
    Ok(())
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

#[async_trait]
impl<S> PathStream for WsBinaryPathStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes.len() > MAX_OUTER_FRAME_LEN {
            return Err(RuntimeError::FrameTooLarge {
                size: bytes.len(),
                max: MAX_OUTER_FRAME_LEN,
            });
        }
        match timeout(
            self.write_timeout,
            self.ws.send(Message::Binary(bytes.to_vec().into())),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(RuntimeError::Protocol(err.to_string())),
            Err(_) => Err(RuntimeError::Timeout("websocket stream write timed out")),
        }
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.pending_read.is_empty() {
            let take = buf.len().min(self.pending_read.len());
            for slot in &mut buf[..take] {
                *slot = self.pending_read.pop_front().expect("checked non-empty");
            }
            return Ok(take);
        }

        while let Some(item) = self.ws.next().await {
            match item {
                Ok(Message::Binary(data)) => {
                    if data.len() > self.max_recv_len {
                        return Err(RuntimeError::FrameTooLarge {
                            size: data.len(),
                            max: self.max_recv_len,
                        });
                    }
                    if data.is_empty() {
                        continue;
                    }
                    let take = buf.len().min(data.len());
                    buf[..take].copy_from_slice(&data[..take]);
                    if take < data.len() {
                        self.pending_read.extend(&data[take..]);
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

    async fn close(&mut self) -> Result<(), RuntimeError> {
        let _ = timeout(self.write_timeout, self.ws.close(None)).await;
        Ok(())
    }
}
