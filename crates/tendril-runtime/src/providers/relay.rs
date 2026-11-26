//! Untrusted WebSocket relay path provider (`relay`) speaking `spec/relay-v1.md`.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{b64url_decode_array, b64url_encode, random_bytes};
use tendril_core::policy::ProviderId;
use tendril_core::relay_auth::{
    RelayAuthProof, RelayAuthSecret, RelayTicket, compute_relay_auth_hmac_b64, origin_allowed,
};
use tendril_relay::protocol::{
    MAX_RELAY_FRAME_LEN, RelayClientMsg, RelayServerMsg, sign_relay_accept, sign_relay_register,
};
use tendril_relay::server::{ClientWsStream, RelayConfig, RelayHandle, RelayServer};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant as TokioInstant, timeout};
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use super::{
    ActiveStandbyGuard, STANDBY_POOL_SIZE, StandbyPoolHandle, StandbySlotOutcome,
    WsBinaryPathStream, await_standby_ready_with_deadline, connect_ws_resolved,
    decode_incoming_init_frame, encode_fast_open_init_frame, ensure_rustls_ring_provider,
    spawn_standby_pool_supervisor, ws_binary_config, ws_control_config,
};
use crate::error::{RelayOffline, RuntimeError};
use crate::provider::{DEFAULT_WRITE_TIMEOUT, PathDialer, PathListener, PathStream};
use crate::redact::{redact_hint, redact_url_str};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const CONTROL_PING_MIN_MS: u64 = 22_500;
pub(crate) const CONTROL_PING_MAX_MS: u64 = 37_500;
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_CONCURRENT_ACCEPTS: usize = 16;

/// Keepalive timing of a [`RelayListener`] control socket.
#[derive(Clone, Copy)]
struct ControlTimings {
    idle_timeout: Duration,
    ping_delay: fn() -> Duration,
}

impl Default for ControlTimings {
    fn default() -> Self {
        Self {
            idle_timeout: CONTROL_IDLE_TIMEOUT,
            ping_delay: jittered_ping_delay,
        }
    }
}

pub(crate) fn jittered_ping_delay() -> Duration {
    let raw = u32::from_le_bytes(random_bytes::<4>().unwrap_or([0; 4]));
    Duration::from_millis(
        CONTROL_PING_MIN_MS + u64::from(raw) % (CONTROL_PING_MAX_MS - CONTROL_PING_MIN_MS + 1),
    )
}

/// Client-side admission credentials presented to `/v1/relay` and `/v2/relay` servers.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum RelayClientAuth {
    #[default]
    None,
    HmacSecret(RelayAuthSecret),
    Ticket(RelayTicket),
}

impl fmt::Debug for RelayClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("RelayClientAuth::None"),
            Self::HmacSecret(_) => f.write_str("RelayClientAuth::HmacSecret(<redacted>)"),
            Self::Ticket(ticket) => f
                .debug_tuple("RelayClientAuth::Ticket")
                .field(ticket)
                .finish(),
        }
    }
}

pub(crate) fn build_relay_auth_proof(
    auth: &RelayClientAuth,
    auth_required: Option<&[String]>,
    op: &str,
    challenge_host: &str,
    nonce: &[u8; 32],
    pub_or_target: &[u8; 32],
) -> Result<Option<RelayAuthProof>, RuntimeError> {
    let required_scope = match op {
        "register" | "accept" => "register",
        "dial" => "dial",
        other => {
            return Err(RuntimeError::Protocol(format!(
                "unsupported relay auth operation '{other}'"
            )));
        }
    };
    let Some(reqs) = auth_required else {
        return Ok(None);
    };
    if !reqs.iter().any(|r| r == required_scope) {
        return Ok(None);
    }
    match auth {
        RelayClientAuth::None => Ok(None),
        RelayClientAuth::HmacSecret(secret) => {
            let mac = compute_relay_auth_hmac_b64(
                secret.as_bytes(),
                op,
                challenge_host,
                nonce,
                pub_or_target,
            )?;
            Ok(Some(RelayAuthProof::Hmac { mac }))
        }
        RelayClientAuth::Ticket(ticket) => Ok(Some(RelayAuthProof::Ticket {
            ticket: ticket.clone(),
        })),
    }
}

fn client_ws_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    ws_binary_config()
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
            RuntimeError::Protocol(format!(
                "relay URL must use ws:// or wss://: {}",
                redact_url_str(relay_url)
            ))
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
            "missing host in relay URL: {}",
            redact_url_str(relay_url)
        )));
    }
    Ok(host.to_owned())
}

async fn connect_and_verify_challenge(
    relay_url: &str,
    expected_host: Option<&str>,
    ws_config: WebSocketConfig,
) -> Result<
    (
        ClientWsStream,
        String,
        [u8; 32],
        Option<Vec<String>>,
        bool,
        bool,
    ),
    RuntimeError,
> {
    let required_host = match expected_host {
        Some(h) if !h.is_empty() => h.to_owned(),
        _ => extract_url_host(relay_url)?,
    };
    ensure_rustls_ring_provider();
    let (mut ws, _) = timeout(
        CONTROL_TIMEOUT,
        connect_ws_resolved(relay_url, Some(ws_config), "relay websocket connect"),
    )
    .await
    .map_err(|_| RuntimeError::Timeout("relay websocket connect timed out"))??;

    let RelayServerMsg::Challenge {
        nonce,
        host,
        max_frame,
        auth_required,
        fast_open,
        standby,
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
    Ok((
        ws,
        host,
        nonce_bytes,
        auth_required,
        fast_open == Some(true),
        standby == Some(true),
    ))
}

/// Active binary bridge stream over a Tendril v1 WebSocket relay.
pub struct RelayStream {
    inner: WsBinaryPathStream<MaybeTlsStream<TcpStream>>,
    fast_open_sent: bool,
}

impl RelayStream {
    pub(crate) fn new(ws: ClientWsStream, write_timeout: Duration) -> Self {
        Self::with_initial_bytes(ws, write_timeout, Vec::new())
    }

    pub(crate) fn with_initial_bytes(
        ws: ClientWsStream,
        write_timeout: Duration,
        initial_bytes: Vec<u8>,
    ) -> Self {
        Self {
            inner: WsBinaryPathStream::with_initial_bytes(
                ProviderId::Relay,
                None,
                ws,
                write_timeout,
                MAX_RELAY_FRAME_LEN,
                initial_bytes,
            ),
            fast_open_sent: false,
        }
    }

    pub(crate) fn with_fast_open_sent(mut self, sent: bool) -> Self {
        self.fast_open_sent = sent;
        self
    }

    /// Returns `true` when the caller's 0-RTT `init_frame` was accepted inside `Dial`.
    #[must_use]
    pub fn fast_open_sent(&self) -> bool {
        self.fast_open_sent
    }
}

#[async_trait]
impl PathStream for RelayStream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.peer_ip()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.inner.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }

    fn into_split(
        self: Box<Self>,
    ) -> (
        Box<dyn crate::provider::PathReader>,
        Box<dyn crate::provider::PathWriter>,
    ) {
        Box::new(self.inner).into_split()
    }
}

/// Listener holding an authenticated mailbox control WebSocket and accepting relayed streams.
pub struct RelayListener {
    accepted_rx: mpsc::Receiver<RelayStream>,
    endpoint: String,
    mailbox_pub_b64: String,
    active_standby_sockets: Arc<AtomicUsize>,
    replaced: Arc<AtomicBool>,
    standby_pool: Option<StandbyPoolHandle>,
    shutdown_tx: Arc<watch::Sender<bool>>,
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
        Self::bind_with_auth(
            relay_url,
            expected_host,
            signing_key,
            write_timeout,
            RelayClientAuth::None,
        )
        .await
    }

    /// Connects to `relay_url` with admission credentials `auth`, proves mailbox ownership with
    /// `signing_key`, and starts listening.
    pub async fn bind_with_auth(
        relay_url: impl Into<String>,
        expected_host: Option<String>,
        signing_key: SigningKey,
        write_timeout: Duration,
        auth: RelayClientAuth,
    ) -> Result<Self, RuntimeError> {
        Self::bind_with_timings(
            relay_url,
            expected_host,
            signing_key,
            write_timeout,
            auth,
            ControlTimings::default(),
        )
        .await
    }

    async fn bind_with_timings(
        relay_url: impl Into<String>,
        expected_host: Option<String>,
        signing_key: SigningKey,
        write_timeout: Duration,
        auth: RelayClientAuth,
        timings: ControlTimings,
    ) -> Result<Self, RuntimeError> {
        let parsed = super::validate_ws_url(&relay_url.into(), false)?;
        let relay_url = parsed.as_str().to_owned();
        let (
            mut control_ws,
            challenge_host,
            nonce,
            auth_required,
            server_fast_open,
            server_standby,
        ) = connect_and_verify_challenge(&relay_url, expected_host.as_deref(), ws_control_config())
            .await?;
        let (pub_b64, sig_b64) = sign_relay_register(&signing_key, &challenge_host, &nonce);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let reg_auth = build_relay_auth_proof(
            &auth,
            auth_required.as_deref(),
            "register",
            &challenge_host,
            &nonce,
            &pub_bytes,
        )?;
        send_control_msg(
            &mut control_ws,
            &RelayClientMsg::Register {
                pub_key: pub_b64.clone(),
                sig: sig_b64,
                auth: reg_auth,
                fast_open: server_fast_open.then_some(true),
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
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let shutdown_tx = Arc::new(shutdown_tx);
        let replaced = Arc::new(AtomicBool::new(false));
        let accept_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let active_standby_sockets = Arc::new(AtomicUsize::new(0));
        let signing_key = Arc::new(signing_key);
        let auth = Arc::new(auth);

        // Watch the control socket before waiting on standby readiness, so a registration that
        // ends during that wait (replaced, expired, or dropped) stops the pool at once.
        let pool_stop = Arc::clone(&shutdown_tx);
        let replaced_flag = Arc::clone(&replaced);
        let ctl_accept_sem = Arc::clone(&accept_sem);
        let ctl_key = Arc::clone(&signing_key);
        let ctl_auth = Arc::clone(&auth);
        let ctl_url = relay_url.clone();
        let ctl_host = expected_host.clone();
        let ctl_pub = pub_b64.clone();
        let ctl_accepted_tx = accepted_tx.clone();
        let control_task = tokio::spawn(async move {
            let mut accept_tasks: JoinSet<()> = JoinSet::new();
            let idle_sleep = tokio::time::sleep(timings.idle_timeout);
            tokio::pin!(idle_sleep);
            let ping_sleep = tokio::time::sleep((timings.ping_delay)());
            tokio::pin!(ping_sleep);
            let mut shut_down = false;
            loop {
                if *shutdown_rx.borrow() {
                    shut_down = true;
                    break;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        shut_down = true;
                        break;
                    }
                    () = &mut idle_sleep => break,
                    () = &mut ping_sleep => {
                        ping_sleep
                            .as_mut()
                            .reset(TokioInstant::now() + (timings.ping_delay)());
                        if !timeout(write_timeout, control_ws.send(Message::Ping(Vec::new().into())))
                            .await
                            .is_ok_and(|res| res.is_ok())
                        {
                            break;
                        }
                    }
                    Some(_) = accept_tasks.join_next(), if !accept_tasks.is_empty() => {}
                    maybe_msg = control_ws.next() => {
                        match maybe_msg {
                            Some(Ok(Message::Text(text))) => {
                                idle_sleep
                                    .as_mut()
                                    .reset(TokioInstant::now() + timings.idle_timeout);
                                let msg = serde_json::from_str::<RelayServerMsg>(&text);
                                if let Ok(RelayServerMsg::Error { code }) = msg {
                                    if code == "replaced" {
                                        replaced_flag.store(true, Ordering::Release);
                                        tracing::warn!(
                                            "relay mailbox registration replaced by a newer listener"
                                        );
                                    }
                                    break;
                                }
                                if let Ok(RelayServerMsg::Incoming { conn_id, init_frame }) = msg
                                {
                                    let Ok(permit) = Arc::clone(&ctl_accept_sem).try_acquire_owned() else {
                                        tracing::warn!("relay listener dropping incoming dial at accept cap");
                                        continue;
                                    };
                                    let relay_url_c = ctl_url.clone();
                                    let exp_host_c = ctl_host.clone();
                                    let key_c = Arc::clone(&ctl_key);
                                    let auth_c = Arc::clone(&ctl_auth);
                                    let pub_c = ctl_pub.clone();
                                    let tx_c = ctl_accepted_tx.clone();
                                    accept_tasks.spawn(async move {
                                        let _permit = permit;
                                        if let Ok(stream) = accept_one_stream(
                                            &relay_url_c,
                                            exp_host_c.as_deref(),
                                            &key_c,
                                            &pub_c,
                                            &conn_id,
                                            init_frame.as_deref(),
                                            &auth_c,
                                            write_timeout,
                                        )
                                        .await
                                        {
                                            let _ = timeout(CONTROL_TIMEOUT, tx_c.send(stream)).await;
                                        }
                                    });
                                }
                            }
                            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                                idle_sleep
                                    .as_mut()
                                    .reset(TokioInstant::now() + timings.idle_timeout);
                            }
                            None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                            Some(Ok(_)) => {}
                        }
                    }
                }
            }
            let _ = timeout(write_timeout, control_ws.close(None)).await;
            // Without a registration no stream can arrive: stop the standby pool so it does not
            // park sockets for whoever holds the mailbox now, and let `accept` end once every
            // in-flight accept has been delivered.
            pool_stop.send_replace(true);
            drop(ctl_accepted_tx);
            if shut_down {
                accept_tasks.abort_all();
            }
            while accept_tasks.join_next().await.is_some() {}
        });

        // Until bind returns, dropping this guard (bind cancelled) stops the control task.
        let mut bind_guard = ControlTaskGuard {
            shutdown_tx: Arc::clone(&shutdown_tx),
            control_task: Some(control_task),
        };

        let standby_pool = if server_standby && !*shutdown_tx.borrow() {
            let (pool_handle, sb_ready_rxs) = spawn_v1_standby_pool(
                relay_url.clone(),
                expected_host.clone(),
                Arc::clone(&signing_key),
                pub_b64.clone(),
                Arc::clone(&accept_sem),
                accepted_tx.clone(),
                Arc::clone(&active_standby_sockets),
                Arc::clone(&auth),
                write_timeout,
                shutdown_tx.subscribe(),
            );
            await_standby_ready_with_deadline(sb_ready_rxs, CONTROL_TIMEOUT).await;
            Some(pool_handle)
        } else {
            None
        };
        drop(accepted_tx);

        Ok(Self {
            accepted_rx,
            endpoint,
            mailbox_pub_b64,
            active_standby_sockets,
            replaced,
            standby_pool,
            shutdown_tx,
            control_task: bind_guard.control_task.take(),
        })
    }

    /// Returns the base64url Ed25519 mailbox public key registered on the relay.
    #[must_use]
    pub fn mailbox_pub_b64(&self) -> &str {
        &self.mailbox_pub_b64
    }

    /// Returns the number of currently registered standby acceptor sockets.
    #[must_use]
    pub fn active_standby_socket_count(&self) -> usize {
        self.active_standby_sockets.load(Ordering::Acquire)
    }

    /// Reports whether the relay ended this registration because a newer listener registered the
    /// same mailbox key (error code `replaced`), as opposed to a transport drop or expiry.
    ///
    /// Once [`PathListener::accept`] has returned [`RuntimeError::Closed`], a `true` result means
    /// another listener now owns the mailbox and re-registering would displace it in turn.
    #[must_use]
    pub fn was_replaced(&self) -> bool {
        self.replaced.load(Ordering::Acquire)
    }
}

/// Stops a [`RelayListener`] control task unless bind completed and took it over.
struct ControlTaskGuard {
    shutdown_tx: Arc<watch::Sender<bool>>,
    control_task: Option<JoinHandle<()>>,
}

impl Drop for ControlTaskGuard {
    fn drop(&mut self) {
        if let Some(task) = self.control_task.take() {
            self.shutdown_tx.send_replace(true);
            task.abort();
        }
    }
}

impl Drop for RelayListener {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        drop(self.standby_pool.take());
        if let Some(handle) = self.control_task.take() {
            handle.abort();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_v1_standby_pool(
    relay_url: String,
    expected_host: Option<String>,
    signing_key: Arc<SigningKey>,
    pub_b64: String,
    accept_sem: Arc<Semaphore>,
    accepted_tx: mpsc::Sender<RelayStream>,
    active_standby: Arc<AtomicUsize>,
    auth: Arc<RelayClientAuth>,
    write_timeout: Duration,
    shutdown_rx: watch::Receiver<bool>,
) -> (
    StandbyPoolHandle,
    Vec<oneshot::Receiver<Result<(), RuntimeError>>>,
) {
    spawn_standby_pool_supervisor(
        STANDBY_POOL_SIZE,
        shutdown_rx,
        move |ready_tx, consumed_tx, slot_shutdown| {
            let url_c = relay_url.clone();
            let host_c = expected_host.clone();
            let key_c = Arc::clone(&signing_key);
            let pub_c = pub_b64.clone();
            let sem_c = Arc::clone(&accept_sem);
            let tx_c = accepted_tx.clone();
            let active_c = Arc::clone(&active_standby);
            let auth_c = Arc::clone(&auth);
            Box::pin(run_v1_standby_slot(
                url_c,
                host_c,
                key_c,
                pub_c,
                sem_c,
                tx_c,
                active_c,
                auth_c,
                write_timeout,
                ready_tx,
                consumed_tx,
                slot_shutdown,
            ))
        },
    )
}

#[allow(clippy::too_many_arguments)]
async fn run_v1_standby_slot(
    relay_url: String,
    expected_host: Option<String>,
    signing_key: Arc<SigningKey>,
    pub_b64: String,
    accept_sem: Arc<Semaphore>,
    accepted_tx: mpsc::Sender<RelayStream>,
    active_standby: Arc<AtomicUsize>,
    auth: Arc<RelayClientAuth>,
    write_timeout: Duration,
    mut ready_tx: Option<oneshot::Sender<Result<(), RuntimeError>>>,
    consumed_tx: oneshot::Sender<()>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> StandbySlotOutcome {
    if *shutdown_rx.borrow() {
        return StandbySlotOutcome::Shutdown;
    }
    let (mut ws, challenge_host, nonce, auth_required, _fast_open, server_standby) =
        match connect_and_verify_challenge(
            &relay_url,
            expected_host.as_deref(),
            ws_control_config(),
        )
        .await
        {
            Ok(v) => v,
            Err(err) => {
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(Err(err));
                }
                return StandbySlotOutcome::Retry;
            }
        };
    if !server_standby {
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(Ok(()));
        }
        let _ = timeout(write_timeout, ws.close(None)).await;
        return StandbySlotOutcome::Unsupported;
    }

    let (derived_pub, sig_b64) = sign_relay_register(&signing_key, &challenge_host, &nonce);
    if derived_pub != pub_b64 {
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(Err(RuntimeError::Protocol(
                "standby signing key mismatch".to_owned(),
            )));
        }
        return StandbySlotOutcome::Unsupported;
    }
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let sb_auth = match build_relay_auth_proof(
        &auth,
        auth_required.as_deref(),
        "register",
        &challenge_host,
        &nonce,
        &pub_bytes,
    ) {
        Ok(p) => p,
        Err(err) => {
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Err(err));
            }
            return StandbySlotOutcome::Unsupported;
        }
    };
    if let Err(err) = send_control_msg(
        &mut ws,
        &RelayClientMsg::Standby {
            pub_key: pub_b64.clone(),
            sig: sig_b64,
            auth: sb_auth,
        },
        write_timeout,
    )
    .await
    {
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(Err(err));
        }
        return StandbySlotOutcome::Retry;
    }

    match recv_control_msg(&mut ws).await {
        Ok(RelayServerMsg::StandbyReady) => {}
        Ok(RelayServerMsg::Error { code }) => {
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Err(RuntimeError::Protocol(format!(
                    "relay standby rejected: {code}"
                ))));
            }
            return StandbySlotOutcome::Retry;
        }
        Ok(other) => {
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Err(RuntimeError::Protocol(format!(
                    "unexpected relay standby response: {other:?}"
                ))));
            }
            return StandbySlotOutcome::Retry;
        }
        Err(err) => {
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Err(err));
            }
            return StandbySlotOutcome::Retry;
        }
    }

    let active_guard = ActiveStandbyGuard::enter(&active_standby);
    if let Some(tx) = ready_tx.take() {
        let _ = tx.send(Ok(()));
    }

    let idle_sleep = tokio::time::sleep(CONTROL_IDLE_TIMEOUT);
    tokio::pin!(idle_sleep);
    let ping_sleep = tokio::time::sleep(jittered_ping_delay());
    tokio::pin!(ping_sleep);

    loop {
        if *shutdown_rx.borrow() {
            let _ = timeout(write_timeout, ws.close(None)).await;
            return StandbySlotOutcome::Shutdown;
        }
        tokio::select! {
            _ = shutdown_rx.changed() => {
                let _ = timeout(write_timeout, ws.close(None)).await;
                return StandbySlotOutcome::Shutdown;
            }
            () = &mut idle_sleep => {
                let _ = timeout(write_timeout, ws.close(None)).await;
                return StandbySlotOutcome::Retry;
            }
            () = &mut ping_sleep => {
                ping_sleep
                    .as_mut()
                    .reset(TokioInstant::now() + jittered_ping_delay());
                if !timeout(write_timeout, ws.send(Message::Ping(Vec::new().into())))
                    .await
                    .is_ok_and(|res| res.is_ok())
                {
                    let _ = timeout(write_timeout, ws.close(None)).await;
                    return StandbySlotOutcome::Retry;
                }
            }
            maybe_msg = ws.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(text))) => {
                        let Ok(RelayServerMsg::Incoming { conn_id: _, init_frame }) =
                            serde_json::from_str::<RelayServerMsg>(&text)
                        else {
                            let _ = timeout(write_timeout, ws.close(None)).await;
                            return StandbySlotOutcome::Retry;
                        };
                        drop(active_guard);

                        let Ok(init_bytes) = decode_incoming_init_frame(init_frame.as_deref()) else {
                            let _ = timeout(write_timeout, ws.close(None)).await;
                            return StandbySlotOutcome::Retry;
                        };
                        let Ok(permit) = Arc::clone(&accept_sem).try_acquire_owned() else {
                            let _ = timeout(write_timeout, ws.close(None)).await;
                            return StandbySlotOutcome::Retry;
                        };
                        let _ = consumed_tx.send(());
                        let stream = RelayStream::with_initial_bytes(ws, write_timeout, init_bytes);
                        let _ = timeout(CONTROL_TIMEOUT, accepted_tx.send(stream)).await;
                        drop(permit);
                        return StandbySlotOutcome::Consumed;
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        idle_sleep
                            .as_mut()
                            .reset(TokioInstant::now() + CONTROL_IDLE_TIMEOUT);
                        ping_sleep
                            .as_mut()
                            .reset(TokioInstant::now() + jittered_ping_delay());
                    }
                    _ => return StandbySlotOutcome::Retry,
                }
            }
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

#[allow(clippy::too_many_arguments)]
async fn accept_one_stream(
    relay_url: &str,
    expected_host: Option<&str>,
    signing_key: &SigningKey,
    pub_b64: &str,
    conn_id_b64: &str,
    init_frame: Option<&str>,
    auth: &RelayClientAuth,
    write_timeout: Duration,
) -> Result<RelayStream, RuntimeError> {
    let conn_id_bytes = b64url_decode_array::<16>(conn_id_b64)?;
    let init_bytes = decode_incoming_init_frame(init_frame)?;
    let (mut ws, host, nonce, auth_required, _, _) =
        connect_and_verify_challenge(relay_url, expected_host, client_ws_config()).await?;
    let sig_b64 = sign_relay_accept(signing_key, &host, &nonce, &conn_id_bytes);
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let acc_auth = build_relay_auth_proof(
        auth,
        auth_required.as_deref(),
        "accept",
        &host,
        &nonce,
        &pub_bytes,
    )?;
    send_control_msg(
        &mut ws,
        &RelayClientMsg::Accept {
            pub_key: pub_b64.to_owned(),
            conn_id: conn_id_b64.to_owned(),
            sig: sig_b64,
            auth: acc_auth,
        },
        write_timeout,
    )
    .await?;

    match recv_control_msg(&mut ws).await? {
        RelayServerMsg::Ready { conn_id } if conn_id == conn_id_b64 => Ok(
            RelayStream::with_initial_bytes(ws, write_timeout, init_bytes),
        ),
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
    allow_insecure_ws: bool,
    auth: RelayClientAuth,
    /// No admission material may be presented (none configured, or withheld by the origin
    /// gate): a relay demanding dial auth fails fast with `relay_auth_unconfigured`.
    auth_withheld: bool,
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
            allow_insecure_ws: false,
            auth: RelayClientAuth::None,
            auth_withheld: false,
        }
    }

    /// Explicitly permits cleartext `ws://` outside loopback hosts.
    #[must_use]
    pub fn with_allow_insecure_ws(mut self, allow: bool) -> Self {
        self.allow_insecure_ws = allow;
        self
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

    /// Attaches stateless admission credentials for relays requiring dial auth.
    #[must_use]
    pub fn with_auth(mut self, auth: RelayClientAuth) -> Self {
        self.auth = auth;
        self
    }

    /// Connects through `relay_url` to `target_signing_pub`.
    pub async fn connect(
        &self,
        relay_url: &str,
        target_signing_pub: &[u8; 32],
    ) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.connect_with_init(relay_url, target_signing_pub, None)
            .await
            .map(|(stream, _)| stream)
    }

    /// Connects through `relay_url` to `target_signing_pub`, optionally attaching `init_frame`
    /// inside `Dial` when the relay advertises `fast_open`. Returns `(stream, fast_open_sent)`.
    pub async fn connect_with_init(
        &self,
        relay_url: &str,
        target_signing_pub: &[u8; 32],
        init_frame: Option<&[u8]>,
    ) -> Result<(Box<dyn PathStream>, bool), RuntimeError> {
        let parsed = super::validate_ws_url(relay_url, self.allow_insecure_ws)?;
        let (mut ws, host, nonce, auth_required, server_fast_open, _server_standby) =
            connect_and_verify_challenge(
                parsed.as_str(),
                self.expected_host.as_deref(),
                client_ws_config(),
            )
            .await?;
        if self.auth_withheld
            && auth_required
                .as_deref()
                .is_some_and(|reqs| reqs.iter().any(|r| r == "dial"))
        {
            return Err(RuntimeError::Protocol(format!(
                "relay_auth_unconfigured: relay '{host}' requires admission credentials and its \
                 origin is not in relay_auth_origins"
            )));
        }
        let conn_id_bytes = random_bytes::<16>()?;
        let conn_id_b64 = b64url_encode(&conn_id_bytes);
        let target_b64 = b64url_encode(target_signing_pub);
        let dial_auth = build_relay_auth_proof(
            &self.auth,
            auth_required.as_deref(),
            "dial",
            &host,
            &nonce,
            target_signing_pub,
        )?;
        let (init_b64, fast_open_sent) = encode_fast_open_init_frame(init_frame, server_fast_open)?;
        send_control_msg(
            &mut ws,
            &RelayClientMsg::Dial {
                target_pub: target_b64,
                conn_id: conn_id_b64.clone(),
                auth: dial_auth,
                init_frame: init_b64,
            },
            self.write_timeout,
        )
        .await?;

        match recv_control_msg(&mut ws).await? {
            RelayServerMsg::Ready { conn_id } if conn_id == conn_id_b64 => Ok((
                Box::new(
                    RelayStream::new(ws, self.write_timeout).with_fast_open_sent(fast_open_sent),
                ),
                fast_open_sent,
            )),
            RelayServerMsg::Error { code } if code == "offline" => {
                Err(RuntimeError::RelayOffline(RelayOffline::V1Dial))
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

    fn supports_fast_open(&self) -> bool {
        true
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.dial_with_init(endpoint, None)
            .await
            .map(|(stream, _)| stream)
    }

    async fn dial_with_init(
        &self,
        endpoint: &str,
        init_frame: Option<&[u8]>,
    ) -> Result<(Box<dyn PathStream>, bool), RuntimeError> {
        let (url, target_b64) = endpoint.split_once('#').ok_or_else(|| {
            RuntimeError::Protocol(format!(
                "relay endpoint must include #<b64url_signing_pub>: {}",
                redact_hint(endpoint)
            ))
        })?;
        let target_pub = b64url_decode_array::<32>(target_b64)?;
        self.connect_with_init(url, &target_pub, init_frame).await
    }
}

/// Admission material for a pairing or Day-2 relay dial to `dial_url`.
///
/// Returns `auth` only when the URL's origin `(scheme, host, port)` is byte-equal to one of
/// `origins` ([`origin_allowed`]) or `operator_endpoint` is set (the explicit operator endpoint
/// of this call). Origins learned from a pairing URI, a stored `signed` or `committed` route or
/// an announcement get [`RelayClientAuth::None`].
#[must_use]
pub fn gate_relay_auth<S: AsRef<str>>(
    auth: &RelayClientAuth,
    dial_url: &str,
    origins: &[S],
    operator_endpoint: bool,
) -> RelayClientAuth {
    if operator_endpoint || origin_allowed(dial_url, origins) {
        auth.clone()
    } else {
        RelayClientAuth::None
    }
}

/// Relay adapter for pairing and Day-2 candidates: dials a fragment-free `/v1/relay` hint to a
/// target mailbox key that never comes from the hint, and attaches admission material only
/// through [`gate_relay_auth`] on the dialed URL.
///
/// A hint that carries `#` is rejected. When no admission material may be presented and the
/// relay demands dial authentication, the dial fails with `relay_auth_unconfigured`.
#[derive(Debug, Clone)]
pub struct RelayHintDialer {
    target_key: [u8; 32],
    auth: RelayClientAuth,
    origins: Vec<String>,
    operator_endpoint: bool,
    expected_host: Option<String>,
    write_timeout: Duration,
}

impl RelayHintDialer {
    /// Adapter dialing the mailbox of `target_key` (the Ed25519 component of the host key).
    #[must_use]
    pub fn new(target_key: [u8; 32]) -> Self {
        Self {
            target_key,
            auth: RelayClientAuth::None,
            origins: Vec::new(),
            operator_endpoint: false,
            expected_host: None,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }

    /// Configured admission material and the origins allowed to receive it.
    #[must_use]
    pub fn with_admission(mut self, auth: RelayClientAuth, origins: Vec<String>) -> Self {
        self.auth = auth;
        self.origins = origins;
        self
    }

    /// Marks the dial target as the explicit operator endpoint of this call.
    #[must_use]
    pub fn with_operator_endpoint(mut self, operator: bool) -> Self {
        self.operator_endpoint = operator;
        self
    }

    /// Requires the server `Challenge.host` field to match `host`.
    #[must_use]
    pub fn with_expected_host(mut self, host: Option<String>) -> Self {
        self.expected_host = host;
        self
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// `true` when a dial to `dial_url` would carry admission material.
    #[must_use]
    pub fn attaches_credentials(&self, dial_url: &str) -> bool {
        !matches!(self.gated_auth(dial_url), RelayClientAuth::None)
    }

    fn gated_auth(&self, dial_url: &str) -> RelayClientAuth {
        gate_relay_auth(&self.auth, dial_url, &self.origins, self.operator_endpoint)
    }

    fn build_inner_dialer(&self, endpoint: &str) -> Result<RelayDialer, RuntimeError> {
        if endpoint.contains('#') {
            return Err(RuntimeError::Protocol(format!(
                "invalid: relay hint must not carry a fragment: {}",
                redact_hint(endpoint)
            )));
        }
        let auth = self.gated_auth(endpoint);
        let mut dialer = RelayDialer::new().with_write_timeout(self.write_timeout);
        dialer.auth_withheld = matches!(auth, RelayClientAuth::None);
        dialer.auth = auth;
        if let Some(host) = &self.expected_host {
            dialer = dialer.with_expected_host(host.clone());
        }
        Ok(dialer)
    }
}

#[async_trait]
impl PathDialer for RelayHintDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Relay
    }

    fn supports_fast_open(&self) -> bool {
        true
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.build_inner_dialer(endpoint)?
            .connect(endpoint, &self.target_key)
            .await
    }

    async fn dial_with_init(
        &self,
        endpoint: &str,
        init_frame: Option<&[u8]>,
    ) -> Result<(Box<dyn PathStream>, bool), RuntimeError> {
        self.build_inner_dialer(endpoint)?
            .connect_with_init(endpoint, &self.target_key, init_frame)
            .await
    }
}

/// Embedded in-process [`tendril_relay`] server backing zero-dependency relay fallback.
#[derive(Debug)]
pub struct EmbeddedRelay {
    handle: RelayHandle,
    host: String,
}

impl EmbeddedRelay {
    /// Starts an embedded relay configured with `config`.
    pub async fn start(config: RelayConfig) -> Result<Self, RuntimeError> {
        let host = config.host.clone();
        let server = RelayServer::bind(config)
            .await
            .map_err(|err| RuntimeError::Protocol(err.to_string()))?;
        let handle = server.spawn();
        Ok(Self { handle, host })
    }

    /// Binds an embedded relay on `127.0.0.1:0` expecting `host` in challenge messages.
    pub async fn bind_local(host: impl Into<String>) -> Result<Self, RuntimeError> {
        let config = RelayConfig {
            host: host.into(),
            ..RelayConfig::default()
        };
        Self::start(config).await
    }

    /// Returns the bound local socket address of the embedded relay.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.handle.local_addr()
    }

    /// Returns the `ws://.../v1/relay` URL served by this embedded relay.
    #[must_use]
    pub fn ws_url(&self) -> String {
        self.handle.ws_url()
    }

    /// Returns the `ws://.../v2/relay` URL served by this embedded relay.
    #[must_use]
    pub fn ws_v2_url(&self) -> String {
        self.handle.ws_v2_url()
    }

    /// Returns the configured expected host identifier advertised by challenges.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Gracefully stops the embedded relay task.
    pub async fn shutdown(self) -> Result<(), RuntimeError> {
        self.handle
            .stop()
            .await
            .map_err(|err| RuntimeError::Protocol(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replaced_listener_returns_closed_and_stops_its_standby_pool() {
        let relay = EmbeddedRelay::bind_local("127.0.0.1").await.expect("relay");
        let key = SigningKey::from_bytes(&[0x5A; 32]);
        let mut old = RelayListener::bind(relay.ws_url(), None, key.clone(), DEFAULT_WRITE_TIMEOUT)
            .await
            .expect("bind old listener");
        assert!(old.active_standby_socket_count() > 0);

        let mut new = RelayListener::bind(relay.ws_url(), None, key, DEFAULT_WRITE_TIMEOUT)
            .await
            .expect("bind displacing listener");
        let ended = timeout(Duration::from_secs(5), old.accept())
            .await
            .expect("replaced listener kept waiting for streams");
        assert!(matches!(ended, Err(RuntimeError::Closed)));
        assert!(old.was_replaced());
        assert!(!new.was_replaced());
        // `Closed` means every task that could hand over a stream has ended, the standby slots
        // included, so none of them can park on the displacing registration any more.
        assert_eq!(old.active_standby_socket_count(), 0);

        let dialer = RelayDialer::new().with_allow_insecure_ws(true);
        let _stream = dialer
            .dial(&new.local_endpoint())
            .await
            .expect("dial displacing listener");
        timeout(Duration::from_secs(5), new.accept())
            .await
            .expect("displacing listener accepts in time")
            .expect("displacing listener stream");
        relay.shutdown().await.expect("stop relay");
    }

    #[tokio::test]
    async fn listener_closes_without_replacement_when_its_ticket_expires() {
        use std::sync::atomic::AtomicU64;

        use tendril_core::relay_auth::{RELAY_TICKET_CLOCK_SKEW_SECS, RelayAuthRole};
        use tendril_relay::RelayAuthScope;

        let now = 1_760_000_000;
        let clock = Arc::new(AtomicU64::new(now));
        let read = Arc::clone(&clock);
        let issuer = SigningKey::from_bytes(&[0x5B; 32]);
        let relay = EmbeddedRelay::start(RelayConfig {
            host: "127.0.0.1".to_owned(),
            trusted_issuers: vec![issuer.verifying_key().to_bytes()],
            auth_scope: RelayAuthScope::RegisterOnly,
            clock: Some(Arc::new(move || read.load(Ordering::Acquire))),
            ..RelayConfig::default()
        })
        .await
        .expect("relay");
        let key = SigningKey::from_bytes(&[0x5C; 32]);
        let ticket = tendril_core::relay_auth::mint_relay_ticket(
            &issuer,
            "127.0.0.1",
            RelayAuthRole::Register,
            &b64url_encode(&key.verifying_key().to_bytes()),
            now - 10,
            70,
        )
        .expect("ticket");
        let deadline = ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1;
        let mut listener = RelayListener::bind_with_auth(
            relay.ws_url(),
            None,
            key,
            DEFAULT_WRITE_TIMEOUT,
            RelayClientAuth::Ticket(ticket),
        )
        .await
        .expect("bind listener");

        clock.store(deadline, Ordering::Release);
        let ended = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("expired listener kept waiting for streams");
        assert!(matches!(ended, Err(RuntimeError::Closed)));
        assert!(!listener.was_replaced());
        relay.shutdown().await.expect("stop relay");
    }

    #[tokio::test]
    async fn silent_relay_ends_the_listener_after_the_idle_timeout() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let url = format!("ws://{}/v1/relay", tcp.local_addr().expect("addr"));
        let (ping_tx, ping_rx) = oneshot::channel::<()>();
        let (silence_tx, mut silence_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            // Skip stray non-WebSocket connections to the loopback port.
            let mut ws = loop {
                let Ok((stream, _)) = tcp.accept().await else {
                    return;
                };
                if let Ok(ws) = accept_async(stream).await {
                    break ws;
                }
            };
            let challenge = RelayServerMsg::Challenge {
                nonce: b64url_encode(&[0x5D; 32]),
                host: "127.0.0.1".to_owned(),
                max_frame: MAX_RELAY_FRAME_LEN,
                auth_required: None,
                fast_open: None,
                standby: None,
            };
            let text = serde_json::to_string(&challenge).expect("json");
            ws.send(Message::Text(text.into()))
                .await
                .expect("challenge");
            let Some(Ok(Message::Text(msg))) = ws.next().await else {
                return;
            };
            let Ok(RelayClientMsg::Register { pub_key, .. }) = serde_json::from_str(&msg) else {
                return;
            };
            let reply =
                serde_json::to_string(&RelayServerMsg::Registered { pub_key }).expect("json");
            ws.send(Message::Text(reply.into()))
                .await
                .expect("registered");
            // Reading answers each ping with a pong, which keeps the listener alive.
            let mut ping_tx = Some(ping_tx);
            loop {
                tokio::select! {
                    _ = &mut silence_rx => break,
                    frame = ws.next() => match frame {
                        Some(Ok(Message::Ping(_))) => {
                            if let Some(tx) = ping_tx.take() {
                                let _ = tx.send(());
                            }
                        }
                        Some(Ok(_)) => {}
                        _ => return,
                    },
                }
            }
            // Then hold the socket without reading, so pings go unanswered.
            std::future::pending::<()>().await;
            drop(ws);
        });

        let timings = ControlTimings {
            idle_timeout: Duration::from_millis(300),
            ping_delay: || Duration::from_millis(100),
        };
        let mut listener = RelayListener::bind_with_timings(
            url,
            None,
            SigningKey::from_bytes(&[0x5E; 32]),
            DEFAULT_WRITE_TIMEOUT,
            RelayClientAuth::None,
            timings,
        )
        .await
        .expect("bind listener");
        timeout(Duration::from_secs(5), ping_rx)
            .await
            .expect("listener pings its control socket")
            .expect("mock relay saw a ping");
        assert!(
            timeout(Duration::from_secs(1), listener.accept())
                .await
                .is_err(),
            "answered pings keep the listener open past its idle timeout"
        );
        silence_tx.send(()).expect("silence the mock relay");
        let ended = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("listener on a silent relay kept waiting");
        assert!(matches!(ended, Err(RuntimeError::Closed)));
        assert!(!listener.was_replaced());
    }

    #[tokio::test]
    async fn cancelled_bind_closes_its_control_socket() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let url = format!("ws://{}/v1/relay", tcp.local_addr().expect("addr"));
        let (control_closed_tx, control_closed_rx) = oneshot::channel::<()>();
        let control_closed_tx = Arc::new(std::sync::Mutex::new(Some(control_closed_tx)));
        tokio::spawn(async move {
            while let Ok((stream, _)) = tcp.accept().await {
                let closed_tx = Arc::clone(&control_closed_tx);
                tokio::spawn(async move {
                    let Ok(mut ws) = accept_async(stream).await else {
                        return;
                    };
                    let challenge = RelayServerMsg::Challenge {
                        nonce: b64url_encode(&[0x5F; 32]),
                        host: "127.0.0.1".to_owned(),
                        max_frame: MAX_RELAY_FRAME_LEN,
                        auth_required: None,
                        fast_open: None,
                        standby: Some(true),
                    };
                    let text = serde_json::to_string(&challenge).expect("json");
                    ws.send(Message::Text(text.into()))
                        .await
                        .expect("challenge");
                    let Some(Ok(Message::Text(msg))) = ws.next().await else {
                        return;
                    };
                    match serde_json::from_str::<RelayClientMsg>(&msg) {
                        Ok(RelayClientMsg::Register { pub_key, .. }) => {
                            let reply =
                                serde_json::to_string(&RelayServerMsg::Registered { pub_key })
                                    .expect("json");
                            ws.send(Message::Text(reply.into()))
                                .await
                                .expect("registered");
                            while let Some(Ok(_)) = ws.next().await {}
                            let tx = closed_tx.lock().expect("mock lock").take();
                            if let Some(tx) = tx {
                                let _ = tx.send(());
                            }
                        }
                        // Standby requests never get an answer, so bind waits on them.
                        _ => std::future::pending::<()>().await,
                    }
                });
            }
        });

        let bind = RelayListener::bind(
            url,
            None,
            SigningKey::from_bytes(&[0x60; 32]),
            DEFAULT_WRITE_TIMEOUT,
        );
        assert!(
            timeout(Duration::from_millis(500), bind).await.is_err(),
            "bind waits for standby readiness"
        );
        timeout(Duration::from_secs(5), control_closed_rx)
            .await
            .expect("cancelled bind left its control socket open")
            .expect("mock relay saw the control socket close");
    }
}
