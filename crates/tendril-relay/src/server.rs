//! Stateless async WebSocket relay server implementing `spec/relay-v1.md`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{b64url_decode_array, b64url_encode, random_bytes};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::protocol::{
    MAX_RELAY_FRAME_LEN, RELAY_PATH, RelayClientMsg, RelayServerMsg, verify_relay_accept,
    verify_relay_register,
};
use crate::rate_limit::IpTokenLimiter;

/// Configuration for [`RelayServer`].
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub listen_addr: SocketAddr,
    pub host: String,
    pub max_pending_per_mailbox: usize,
    pub max_active_per_ip: usize,
    pub max_active_per_mailbox: usize,
    pub max_tracked_ips: usize,
    pub ip_burst_capacity: u32,
    pub ip_refill_per_sec: u32,
    pub accept_timeout: Duration,
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            host: "localhost".to_owned(),
            max_pending_per_mailbox: 8,
            max_active_per_ip: 64,
            max_active_per_mailbox: 64,
            max_tracked_ips: 4096,
            ip_burst_capacity: 60,
            ip_refill_per_sec: 20,
            accept_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(300),
            write_timeout: Duration::from_secs(1),
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
}

/// Handle to a background [`RelayServer`] instance.
#[derive(Debug)]
pub struct RelayHandle {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl RelayHandle {
    /// Returns the local socket address the relay is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns a `ws://` URL pointing at the canonical `/v1/relay` path.
    #[must_use]
    pub fn ws_url(&self) -> String {
        format!("ws://{}{RELAY_PATH}", self.addr)
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

#[derive(Clone)]
struct MailboxEntry {
    reg_id: u64,
    incoming_tx: mpsc::Sender<String>,
}

struct PendingDial {
    dial_id: u64,
    target_pub: [u8; 32],
    match_tx: oneshot::Sender<AcceptorTransfer>,
}

struct AcceptorTransfer {
    ws: WebSocketStream<TcpStream>,
    _ip_guard: IpConnGuard,
    _stream_guard: MailboxStreamGuard,
}

struct RelayTables {
    next_id: u64,
    mailboxes: HashMap<[u8; 32], MailboxEntry>,
    pending: HashMap<[u8; 16], PendingDial>,
    pending_counts: HashMap<[u8; 32], usize>,
    active_per_mailbox: HashMap<[u8; 32], usize>,
}

impl RelayTables {
    fn new() -> Self {
        Self {
            next_id: 1,
            mailboxes: HashMap::new(),
            pending: HashMap::new(),
            pending_counts: HashMap::new(),
            active_per_mailbox: HashMap::new(),
        }
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
            active_per_ip: Mutex::new(HashMap::new()),
            tables: Mutex::new(RelayTables::new()),
        }
    }

    fn try_acquire_ip(self: &Arc<Self>, ip: IpAddr) -> Option<IpConnGuard> {
        {
            let mut limiter = self.limiter.lock().expect("limiter mutex poisoned");
            if !limiter.allow(ip, Instant::now()) {
                return None;
            }
        }
        let mut active = self
            .active_per_ip
            .lock()
            .expect("active_per_ip mutex poisoned");
        let count = active.entry(ip).or_insert(0);
        if *count >= self.config.max_active_per_ip {
            return None;
        }
        *count += 1;
        Some(IpConnGuard {
            state: Arc::clone(self),
            ip,
        })
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
}

impl RelayServer {
    /// Binds a TCP listener using `config`.
    pub async fn bind(config: RelayConfig) -> Result<Self, RelayError> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(RelayState::new(config));
        Ok(Self {
            listener,
            addr,
            state,
        })
    }

    /// Returns the local socket address bound by this relay.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns a `ws://` URL pointing at `/v1/relay`.
    #[must_use]
    pub fn ws_url(&self) -> String {
        format!("ws://{}{RELAY_PATH}", self.addr)
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
                            let Some(ip_guard) = self.state.try_acquire_ip(peer_addr.ip()) else {
                                tracing::debug!(ip = %peer_addr.ip(), "rejected relay connection by rate/ip cap");
                                drop(stream);
                                continue;
                            };
                            let state = Arc::clone(&self.state);
                            tokio::spawn(async move {
                                handle_connection(stream, ip_guard, state).await;
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
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = self.serve_until(shutdown_rx).await;
        });
        RelayHandle {
            addr,
            shutdown_tx: Some(shutdown_tx),
            task: Some(task),
        }
    }
}

async fn send_json(
    ws: &mut WebSocketStream<TcpStream>,
    msg: &RelayServerMsg,
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
    ws: &mut WebSocketStream<TcpStream>,
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

#[allow(clippy::result_large_err)]
fn validate_relay_path(req: &Request, resp: Response) -> Result<Response, ErrorResponse> {
    if req.uri().path() != RELAY_PATH {
        let mut err = ErrorResponse::new(Some("not found".to_owned()));
        *err.status_mut() = StatusCode::NOT_FOUND;
        return Err(err);
    }
    Ok(resp)
}

async fn handle_connection(stream: TcpStream, ip_guard: IpConnGuard, state: Arc<RelayState>) {
    let _ = stream.set_nodelay(true);
    let ws_config = WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_RELAY_FRAME_LEN * 2)
        .max_message_size(Some(MAX_RELAY_FRAME_LEN))
        .max_frame_size(Some(MAX_RELAY_FRAME_LEN));

    let Ok(Ok(mut ws)) = timeout(
        state.config.accept_timeout,
        accept_hdr_async_with_config(stream, validate_relay_path, Some(ws_config)),
    )
    .await
    else {
        return;
    };

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
            handle_register(ws, ip_guard, state, &nonce, pub_key, sig).await;
        }
        RelayClientMsg::Dial {
            target_pub,
            conn_id,
        } => {
            handle_dial(ws, ip_guard, state, target_pub, conn_id).await;
        }
        RelayClientMsg::Accept {
            pub_key,
            conn_id,
            sig,
        } => {
            handle_accept(ws, ip_guard, state, &nonce, pub_key, conn_id, sig).await;
        }
    }
}

async fn handle_register(
    mut ws: WebSocketStream<TcpStream>,
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
    let reg_id = {
        let mut tables = state.tables.lock().expect("tables mutex poisoned");
        let reg_id = tables.alloc_id();
        tables.mailboxes.insert(
            mailbox_pub,
            MailboxEntry {
                reg_id,
                incoming_tx,
            },
        );
        reg_id
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
    mut ws: WebSocketStream<TcpStream>,
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
    drop(acceptor._ip_guard);
    drop(acceptor._stream_guard);
}

async fn handle_accept(
    mut ws: WebSocketStream<TcpStream>,
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
        let mut tables = state.tables.lock().expect("tables mutex poisoned");
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
        _ip_guard: ip_guard,
        _stream_guard: stream_guard,
    });
}

async fn bridge_streams(
    dialer_ws: WebSocketStream<TcpStream>,
    acceptor_ws: WebSocketStream<TcpStream>,
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
                    if data.len() > MAX_RELAY_FRAME_LEN {
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
                    if data.len() > MAX_RELAY_FRAME_LEN {
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
