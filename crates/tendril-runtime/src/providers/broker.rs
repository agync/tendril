//! Untrusted HTTPS/WSS tunnel / reverse-proxy adapter path provider (`broker`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use tendril_core::policy::ProviderId;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, StatusCode};
use tokio_tungstenite::{MaybeTlsStream, accept_hdr_async_with_config};

use super::{
    WsBinaryPathStream, connect_ws_resolved, ensure_rustls_ring_provider, ws_binary_config,
};
use crate::error::RuntimeError;
use crate::provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathStream,
};

const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_UPGRADES: usize = 64;

/// Listener configuration for accepting broker-proxied WebSocket streams.
#[derive(Debug, Clone)]
pub struct BrokerServerConfig {
    pub listen_addr: SocketAddr,
    pub path: String,
    pub auth_header: Option<(String, String)>,
    pub write_timeout: Duration,
}

impl Default for BrokerServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            path: "/tendril/v1/stream".to_owned(),
            auth_header: None,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }
}

/// WebSocket listener accepting reverse-proxied or brokered `PathStream` connections (`broker`).
pub struct BrokerListener {
    local_addr: SocketAddr,
    path: String,
    accepted_rx: mpsc::Receiver<Box<dyn PathStream>>,
    accept_task: JoinHandle<()>,
}

impl BrokerListener {
    /// Binds a broker listener according to `config`.
    pub async fn bind(config: BrokerServerConfig) -> Result<Self, RuntimeError> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let path = config.path.clone();
        let expected_path = Arc::new(config.path);
        let auth_header = config.auth_header.map(Arc::new);
        let write_timeout = config.write_timeout;

        let (accepted_tx, accepted_rx) = mpsc::channel::<Box<dyn PathStream>>(32);
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_UPGRADES));

        let accept_task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                            drop(stream);
                            continue;
                        };
                        let _ = stream.set_nodelay(true);
                        let path_c = Arc::clone(&expected_path);
                        let auth_c = auth_header.clone();
                        let tx_c = accepted_tx.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Some(ws_stream) = accept_one_broker_ws(
                                stream,
                                peer_addr,
                                path_c.as_str(),
                                auth_c.as_deref(),
                                write_timeout,
                            )
                            .await
                            {
                                let _ = tx_c.send(ws_stream).await;
                            }
                        });
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "broker listener tcp accept error");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            path,
            accepted_rx,
            accept_task,
        })
    }

    /// Returns the bound TCP socket address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for BrokerListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

fn http_error_response(status: StatusCode, body: &'static str) -> ErrorResponse {
    let mut resp = ErrorResponse::new(Some(body.to_owned()));
    *resp.status_mut() = status;
    resp
}

#[allow(clippy::result_large_err)]
async fn accept_one_broker_ws(
    stream: TcpStream,
    peer_addr: SocketAddr,
    expected_path: &str,
    auth_header: Option<&(String, String)>,
    write_timeout: Duration,
) -> Option<Box<dyn PathStream>> {
    let expected_path = expected_path.to_owned();
    let auth_header = auth_header.cloned();

    let cb = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        if req.method().as_str() != "GET" || req.uri().path() != expected_path {
            return Err(http_error_response(StatusCode::NOT_FOUND, "not found"));
        }
        if let Some((hdr_name, expected_val)) = &auth_header {
            let mut vals = req.headers().get_all(hdr_name.as_str()).iter();
            let provided = match (vals.next().and_then(|v| v.to_str().ok()), vals.next()) {
                (Some(v), None) => v,
                _ => {
                    return Err(http_error_response(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                    ));
                }
            };
            let matches = provided.len() == expected_val.len()
                && provided
                    .as_bytes()
                    .ct_eq(expected_val.as_bytes())
                    .unwrap_u8()
                    == 1;
            if !matches {
                return Err(http_error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                ));
            }
        }
        Ok(resp)
    };

    let upgraded = timeout(
        UPGRADE_TIMEOUT,
        accept_hdr_async_with_config(MaybeTlsStream::Plain(stream), cb, Some(ws_binary_config())),
    )
    .await
    .ok()?
    .ok()?;

    Some(Box::new(WsBinaryPathStream::new(
        ProviderId::Broker,
        Some(peer_addr.ip()),
        upgraded,
        write_timeout,
        MAX_OUTER_FRAME_LEN,
    )))
}

#[async_trait]
impl PathListener for BrokerListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.accepted_rx.recv().await.ok_or(RuntimeError::Closed)
    }

    fn local_endpoint(&self) -> String {
        format!("broker+ws://{}{}", self.local_addr, self.path)
    }
}

/// Dialer connecting through an HTTP/HTTPS WebSocket broker (`broker+ws://`, `broker+wss://`, `ws://`, `wss://`).
#[derive(Clone)]
pub struct BrokerDialer {
    headers: Vec<(String, String)>,
    write_timeout: Duration,
    allow_insecure_ws: bool,
}

impl std::fmt::Debug for BrokerDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, _)| (k.as_str(), "<redacted>"))
            .collect();
        f.debug_struct("BrokerDialer")
            .field("headers", &redacted)
            .field("write_timeout", &self.write_timeout)
            .field("allow_insecure_ws", &self.allow_insecure_ws)
            .finish()
    }
}

impl Default for BrokerDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerDialer {
    /// Creates a `BrokerDialer` with [`DEFAULT_WRITE_TIMEOUT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            allow_insecure_ws: false,
        }
    }

    /// Explicitly permits cleartext `ws://` / `broker+ws://` outside loopback hosts.
    #[must_use]
    pub fn with_allow_insecure_ws(mut self, allow: bool) -> Self {
        self.allow_insecure_ws = allow;
        self
    }

    /// Attaches an HTTP request header (such as a tunnel bearer token) to WebSocket upgrades.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }
}

#[async_trait]
impl PathDialer for BrokerDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Broker
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let validated = super::validate_broker_ws_url(endpoint, self.allow_insecure_ws)?;
        let mut req = validated
            .as_str()
            .into_client_request()
            .map_err(|err| RuntimeError::Protocol(format!("invalid broker URL: {err}")))?;
        for (name, val) in &self.headers {
            let hdr_name = HeaderName::from_bytes(name.as_bytes()).map_err(|err| {
                RuntimeError::Protocol(format!("invalid header name '{name}': {err}"))
            })?;
            let hdr_val = HeaderValue::from_str(val).map_err(|err| {
                RuntimeError::Protocol(format!("invalid header value for '{name}': {err}"))
            })?;
            req.headers_mut().insert(hdr_name, hdr_val);
        }

        ensure_rustls_ring_provider();
        let (ws, _resp) = timeout(
            UPGRADE_TIMEOUT,
            connect_ws_resolved(req, Some(ws_binary_config()), "broker websocket connect"),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("broker websocket connect timed out"))??;

        Ok(Box::new(WsBinaryPathStream::new(
            ProviderId::Broker,
            None,
            ws,
            self.write_timeout,
            MAX_OUTER_FRAME_LEN,
        )))
    }
}
