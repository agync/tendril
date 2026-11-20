//! Untrusted WebSocket relay path provider (`relay`) speaking `spec/relay-v1.md`.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{b64url_decode_array, b64url_encode, random_bytes};
use tendril_core::policy::ProviderId;
use tendril_relay::protocol::{
    MAX_RELAY_FRAME_LEN, RelayClientMsg, RelayServerMsg, sign_relay_accept, sign_relay_register,
};
use tendril_relay::server::ClientWsStream;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::error::RuntimeError;
use crate::provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathStream,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_ACCEPTS: usize = 16;

static RUSTLS_INIT: Once = Once::new();

fn ensure_rustls_ring_provider() {
    RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn client_ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_RELAY_FRAME_LEN * 2)
        .max_message_size(Some(MAX_RELAY_FRAME_LEN))
        .max_frame_size(Some(MAX_RELAY_FRAME_LEN))
}

async fn recv_control_msg(ws: &mut ClientWsStream) -> Result<RelayServerMsg, RuntimeError> {
    while let Some(item) = timeout(CONTROL_TIMEOUT, ws.next())
        .await
        .map_err(|_| RuntimeError::Timeout("relay control read timed out"))?
    {
        match item {
            Ok(Message::Text(text)) => {
                let msg = serde_json::from_str::<RelayServerMsg>(&text).map_err(|err| {
                    RuntimeError::Protocol(format!("invalid relay control json: {err}"))
                })?;
                return Ok(msg);
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            Ok(Message::Close(_)) => return Err(RuntimeError::Closed),
            Ok(other) => {
                return Err(RuntimeError::Protocol(format!(
                    "unexpected relay control frame: {other:?}"
                )));
            }
            Err(err) => return Err(RuntimeError::Protocol(err.to_string())),
        }
    }
    Err(RuntimeError::Closed)
}

async fn send_control_msg(
    ws: &mut ClientWsStream,
    msg: &RelayClientMsg,
    write_timeout: Duration,
) -> Result<(), RuntimeError> {
    let text = serde_json::to_string(msg)
        .map_err(|err| RuntimeError::Protocol(format!("serialize relay control failed: {err}")))?;
    match timeout(write_timeout, ws.send(Message::Text(text.into()))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(RuntimeError::Protocol(err.to_string())),
        Err(_) => Err(RuntimeError::Timeout("relay control write timed out")),
    }
}

fn extract_url_host(relay_url: &str) -> Result<String, RuntimeError> {
    let after_scheme = relay_url
        .strip_prefix("wss://")
        .or_else(|| relay_url.strip_prefix("ws://"))
        .ok_or_else(|| {
            RuntimeError::Protocol(format!("relay URL must use ws:// or wss://: '{relay_url}'"))
        })?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, hostport)| hostport);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return Err(RuntimeError::Protocol(format!(
            "missing host in relay URL: '{relay_url}'"
        )));
    }
    Ok(host.to_owned())
}

async fn connect_and_verify_challenge(
    relay_url: &str,
    expected_host: Option<&str>,
) -> Result<(ClientWsStream, String, [u8; 32]), RuntimeError> {
    let required_host = match expected_host {
        Some(h) if !h.is_empty() => h.to_owned(),
        _ => extract_url_host(relay_url)?,
    };
    ensure_rustls_ring_provider();
    let (mut ws, _) = timeout(
        CONTROL_TIMEOUT,
        connect_async_with_config(relay_url, Some(client_ws_config()), false),
    )
    .await
    .map_err(|_| RuntimeError::Timeout("relay websocket connect timed out"))?
    .map_err(|err| RuntimeError::Protocol(format!("relay websocket connect failed: {err}")))?;

    let RelayServerMsg::Challenge {
        nonce,
        host,
        max_frame,
    } = recv_control_msg(&mut ws).await?
    else {
        return Err(RuntimeError::Protocol(
            "expected relay challenge frame".to_owned(),
        ));
    };
    if max_frame < MAX_RELAY_FRAME_LEN {
        return Err(RuntimeError::Protocol(format!(
            "relay max_frame {max_frame} below required {MAX_RELAY_FRAME_LEN}"
        )));
    }
    if host != required_host {
        return Err(RuntimeError::Protocol(format!(
            "relay host mismatch: expected '{required_host}', got '{host}'"
        )));
    }
    let nonce_bytes = b64url_decode_array::<32>(&nonce)?;
    Ok((ws, host, nonce_bytes))
}

/// Active binary bridge stream over a Tendril v1 WebSocket relay.
pub struct RelayStream {
    ws: ClientWsStream,
    write_timeout: Duration,
    pending_read: VecDeque<u8>,
}

impl RelayStream {
    fn new(ws: ClientWsStream, write_timeout: Duration) -> Self {
        Self {
            ws,
            write_timeout,
            pending_read: VecDeque::new(),
        }
    }
}

#[async_trait]
impl PathStream for RelayStream {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Relay
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        None
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
            Err(_) => Err(RuntimeError::Timeout("relay stream write timed out")),
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
                    if data.len() > MAX_RELAY_FRAME_LEN {
                        return Err(RuntimeError::FrameTooLarge {
                            size: data.len(),
                            max: MAX_RELAY_FRAME_LEN,
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
                        "unexpected non-binary relay frame: {other:?}"
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

/// Listener holding an authenticated mailbox control WebSocket and accepting relayed streams.
pub struct RelayListener {
    accepted_rx: mpsc::Receiver<RelayStream>,
    endpoint: String,
    mailbox_pub_b64: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    control_task: Option<JoinHandle<()>>,
}

impl RelayListener {
    /// Connects to `relay_url`, proves mailbox ownership with `signing_key`, and starts listening.
    pub async fn bind(
        relay_url: impl Into<String>,
        expected_host: Option<String>,
        signing_key: SigningKey,
        write_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        let relay_url = relay_url.into();
        let (mut control_ws, challenge_host, nonce) =
            connect_and_verify_challenge(&relay_url, expected_host.as_deref()).await?;
        let (pub_b64, sig_b64) = sign_relay_register(&signing_key, &challenge_host, &nonce);
        send_control_msg(
            &mut control_ws,
            &RelayClientMsg::Register {
                pub_key: pub_b64.clone(),
                sig: sig_b64,
            },
            write_timeout,
        )
        .await?;

        match recv_control_msg(&mut control_ws).await? {
            RelayServerMsg::Registered { pub_key } if pub_key == pub_b64 => {}
            RelayServerMsg::Error { code } => {
                return Err(RuntimeError::Protocol(format!(
                    "relay register rejected: {code}"
                )));
            }
            other => {
                return Err(RuntimeError::Protocol(format!(
                    "unexpected relay register response: {other:?}"
                )));
            }
        }

        let endpoint = format!("{relay_url}#{pub_b64}");
        let mailbox_pub_b64 = pub_b64.clone();
        let (accepted_tx, accepted_rx) = mpsc::channel(32);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let accept_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let signing_key = Arc::new(signing_key);

        let control_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        let _ = timeout(write_timeout, control_ws.close(None)).await;
                        break;
                    }
                    maybe_msg = control_ws.next() => {
                        match maybe_msg {
                            Some(Ok(Message::Text(text))) => {
                                if let Ok(RelayServerMsg::Incoming { conn_id }) =
                                    serde_json::from_str::<RelayServerMsg>(&text)
                                {
                                    let Ok(permit) = Arc::clone(&accept_sem).try_acquire_owned() else {
                                        tracing::warn!("relay listener dropping incoming dial at accept cap");
                                        continue;
                                    };
                                    let relay_url_c = relay_url.clone();
                                    let exp_host_c = expected_host.clone();
                                    let key_c = Arc::clone(&signing_key);
                                    let pub_c = pub_b64.clone();
                                    let tx_c = accepted_tx.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Ok(stream) = accept_one_stream(
                                            &relay_url_c,
                                            exp_host_c.as_deref(),
                                            &key_c,
                                            &pub_c,
                                            &conn_id,
                                            write_timeout,
                                        )
                                        .await
                                        {
                                            let _ = tx_c.send(stream).await;
                                        }
                                    });
                                }
                            }
                            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                            None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                            Some(Ok(_)) => {}
                        }
                    }
                }
            }
        });

        Ok(Self {
            accepted_rx,
            endpoint,
            mailbox_pub_b64,
            shutdown_tx: Some(shutdown_tx),
            control_task: Some(control_task),
        })
    }

    /// Returns the base64url Ed25519 mailbox public key registered on the relay.
    #[must_use]
    pub fn mailbox_pub_b64(&self) -> &str {
        &self.mailbox_pub_b64
    }
}

impl Drop for RelayListener {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.control_task.take() {
            handle.abort();
        }
    }
}

#[async_trait]
impl PathListener for RelayListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = self.accepted_rx.recv().await.ok_or(RuntimeError::Closed)?;
        Ok(Box::new(stream))
    }

    fn local_endpoint(&self) -> String {
        self.endpoint.clone()
    }
}

async fn accept_one_stream(
    relay_url: &str,
    expected_host: Option<&str>,
    signing_key: &SigningKey,
    pub_b64: &str,
    conn_id_b64: &str,
    write_timeout: Duration,
) -> Result<RelayStream, RuntimeError> {
    let conn_id_bytes = b64url_decode_array::<16>(conn_id_b64)?;
    let (mut ws, host, nonce) = connect_and_verify_challenge(relay_url, expected_host).await?;
    let sig_b64 = sign_relay_accept(signing_key, &host, &nonce, &conn_id_bytes);
    send_control_msg(
        &mut ws,
        &RelayClientMsg::Accept {
            pub_key: pub_b64.to_owned(),
            conn_id: conn_id_b64.to_owned(),
            sig: sig_b64,
        },
        write_timeout,
    )
    .await?;

    match recv_control_msg(&mut ws).await? {
        RelayServerMsg::Ready { conn_id } if conn_id == conn_id_b64 => {
            Ok(RelayStream::new(ws, write_timeout))
        }
        RelayServerMsg::Error { code } => Err(RuntimeError::Protocol(format!(
            "relay accept rejected: {code}"
        ))),
        other => Err(RuntimeError::Protocol(format!(
            "unexpected relay accept response: {other:?}"
        ))),
    }
}

/// Dialer connecting through a Tendril v1 WebSocket relay (`ws://` or `wss://`).
#[derive(Debug, Clone)]
pub struct RelayDialer {
    expected_host: Option<String>,
    write_timeout: Duration,
}

impl Default for RelayDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayDialer {
    /// Constructs a `RelayDialer` with [`DEFAULT_WRITE_TIMEOUT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_host: None,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }

    /// Requires the server `Challenge.host` field to match `host`.
    #[must_use]
    pub fn with_expected_host(mut self, host: impl Into<String>) -> Self {
        self.expected_host = Some(host.into());
        self
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Connects through `relay_url` to `target_signing_pub`.
    pub async fn connect(
        &self,
        relay_url: &str,
        target_signing_pub: &[u8; 32],
    ) -> Result<Box<dyn PathStream>, RuntimeError> {
        let (mut ws, _host, _nonce) =
            connect_and_verify_challenge(relay_url, self.expected_host.as_deref()).await?;
        let conn_id_bytes = random_bytes::<16>()?;
        let conn_id_b64 = b64url_encode(&conn_id_bytes);
        let target_b64 = b64url_encode(target_signing_pub);
        send_control_msg(
            &mut ws,
            &RelayClientMsg::Dial {
                target_pub: target_b64,
                conn_id: conn_id_b64.clone(),
            },
            self.write_timeout,
        )
        .await?;

        match recv_control_msg(&mut ws).await? {
            RelayServerMsg::Ready { conn_id } if conn_id == conn_id_b64 => {
                Ok(Box::new(RelayStream::new(ws, self.write_timeout)))
            }
            RelayServerMsg::Error { code } => Err(RuntimeError::Protocol(format!(
                "relay dial rejected: {code}"
            ))),
            other => Err(RuntimeError::Protocol(format!(
                "unexpected relay dial response: {other:?}"
            ))),
        }
    }
}

#[async_trait]
impl PathDialer for RelayDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Relay
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let (url, target_b64) = endpoint.split_once('#').ok_or_else(|| {
            RuntimeError::Protocol(format!(
                "relay endpoint must include '#<b64url_signing_pub>': '{endpoint}'"
            ))
        })?;
        let target_pub = b64url_decode_array::<32>(target_b64)?;
        self.connect(url, &target_pub).await
    }
}
