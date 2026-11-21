//! Untrusted `/v2/relay` WebSocket path provider speaking `spec/relay-v2.md`.
//!
//! Enforces canonical challenge-host verification (`VerifiedRelayHost`), opens
//! separate control WebSocket connections per active epoch mailbox in
//! `derive_epoch_mailbox_window` so the relay cannot correlate consecutive epochs
//! across a shared socket, and validates + deduplicates `incoming` dial tokens
//! with `verify_and_record_v2_relay_dial` before opening an accept data socket.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{b64url_decode_array, b64url_encode, random_bytes};
use tendril_core::policy::ProviderId;
use tendril_core::v2::{
    DerivedMailbox, RelayDialReplayCache, RelayEpochWindow, VerifiedRelayHost,
    derive_epoch_mailbox, derive_epoch_mailbox_window, epoch_for_unix, sign_v2_relay_accept,
    sign_v2_relay_dial, sign_v2_relay_register, verify_and_record_v2_relay_dial,
};
use tendril_relay::protocol::{MAX_RELAY_FRAME_LEN, RelayV2ClientMsg, RelayV2ServerMsg};
use tendril_relay::server::ClientWsStream;
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, timeout};
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::relay::RelayStream;
use super::{ensure_rustls_ring_provider, ws_binary_config};
use crate::error::RuntimeError;
use crate::provider::{DEFAULT_WRITE_TIMEOUT, PathDialer, PathListener, PathStream};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_PING_INTERVAL: Duration = Duration::from_secs(30);
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_CONCURRENT_ACCEPTS: usize = 16;
const EPOCH_ROTATE_POLL_INTERVAL: Duration = Duration::from_secs(30);
const BACKOFF_INITIAL: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
const STABLE_UPTIME_RESET: Duration = Duration::from_secs(5);

fn jittered_backoff(backoff: Duration) -> Duration {
    let base_ms = u64::try_from(backoff.as_millis()).unwrap_or(5_000).max(1);
    let max_jitter = (base_ms / 4).max(1);
    let rand_u64 = u64::from(u32::from_le_bytes(random_bytes::<4>().unwrap_or([0; 4])));
    Duration::from_millis(base_ms.saturating_add(rand_u64 % max_jitter))
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn recv_v2_control_msg(ws: &mut ClientWsStream) -> Result<RelayV2ServerMsg, RuntimeError> {
    while let Some(item) = timeout(CONTROL_TIMEOUT, ws.next())
        .await
        .map_err(|_| RuntimeError::Timeout("v2 relay control read timed out"))?
    {
        match item {
            Ok(Message::Text(text)) => {
                let msg = serde_json::from_str::<RelayV2ServerMsg>(&text).map_err(|err| {
                    RuntimeError::Protocol(format!("invalid v2 relay control json: {err}"))
                })?;
                return Ok(msg);
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            Ok(Message::Close(_)) => return Err(RuntimeError::Closed),
            Ok(other) => {
                return Err(RuntimeError::Protocol(format!(
                    "unexpected v2 relay control frame: {other:?}"
                )));
            }
            Err(err) => return Err(RuntimeError::Protocol(err.to_string())),
        }
    }
    Err(RuntimeError::Closed)
}

async fn send_v2_control_msg(
    ws: &mut ClientWsStream,
    msg: &RelayV2ClientMsg,
    write_timeout: Duration,
) -> Result<(), RuntimeError> {
    let text = serde_json::to_string(msg).map_err(|err| {
        RuntimeError::Protocol(format!("serialize v2 relay control failed: {err}"))
    })?;
    match timeout(write_timeout, ws.send(Message::Text(text.into()))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(RuntimeError::Protocol(err.to_string())),
        Err(_) => Err(RuntimeError::Timeout("v2 relay control write timed out")),
    }
}

fn extract_expected_host(
    parsed_url: &url::Url,
    expected_host: Option<&str>,
) -> Result<String, RuntimeError> {
    if let Some(h) = expected_host.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(h.to_owned());
    }
    parsed_url
        .host_str()
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| RuntimeError::Protocol("v2 relay URL is missing host".to_owned()))
}

async fn connect_and_verify_v2_challenge(
    relay_url: &str,
    expected_host: &str,
) -> Result<(ClientWsStream, VerifiedRelayHost, [u8; 32], u64), RuntimeError> {
    ensure_rustls_ring_provider();
    let (mut ws, _) = timeout(
        CONTROL_TIMEOUT,
        connect_async_with_config(relay_url, Some(ws_binary_config()), false),
    )
    .await
    .map_err(|_| RuntimeError::Timeout("v2 relay websocket connect timed out"))?
    .map_err(|err| RuntimeError::Protocol(format!("v2 relay websocket connect failed: {err}")))?;

    let RelayV2ServerMsg::Challenge {
        nonce,
        host,
        epoch,
        max_frame,
    } = recv_v2_control_msg(&mut ws).await?
    else {
        return Err(RuntimeError::Protocol(
            "expected v2 relay challenge frame".to_owned(),
        ));
    };
    if max_frame < MAX_RELAY_FRAME_LEN {
        return Err(RuntimeError::Protocol(format!(
            "v2 relay max_frame {max_frame} below required {MAX_RELAY_FRAME_LEN}"
        )));
    }
    let verified_host = VerifiedRelayHost::from_challenge(expected_host, &host)?;
    let nonce_bytes = b64url_decode_array::<32>(&nonce)?;
    Ok((ws, verified_host, nonce_bytes, epoch))
}

/// Configuration for [`RelayV2Listener`].
#[derive(Debug, Clone)]
pub struct RelayV2ListenerConfig {
    pub expected_host: Option<String>,
    pub write_timeout: Duration,
    pub allow_insecure_ws: bool,
    pub replay_cache: Option<Arc<Mutex<RelayDialReplayCache>>>,
    pub unix_secs: Option<u64>,
}

impl Default for RelayV2ListenerConfig {
    fn default() -> Self {
        Self {
            expected_host: None,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            allow_insecure_ws: false,
            replay_cache: None,
            unix_secs: None,
        }
    }
}

struct EpochSocketHandle {
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl EpochSocketHandle {
    fn stop(self) {
        drop(self);
    }
}

impl Drop for EpochSocketHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        self.task.abort();
    }
}

struct BindCleanupGuard {
    shutdown_tx: watch::Sender<bool>,
    epoch_tasks: Arc<Mutex<HashMap<u64, EpochSocketHandle>>>,
    armed: bool,
}

impl Drop for BindCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.shutdown_tx.send(true);
            let mut guard = self
                .epoch_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.clear();
        }
    }
}

/// Listener managing isolated per-epoch `/v2/relay` control WebSockets and accepting
/// authenticated, replay-checked relayed streams.
pub struct RelayV2Listener {
    accepted_rx: mpsc::Receiver<RelayStream>,
    relay_url: String,
    window: Arc<Mutex<RelayEpochWindow>>,
    replay_cache: Arc<Mutex<RelayDialReplayCache>>,
    active_control_sockets: Arc<AtomicUsize>,
    epoch_tasks: Arc<Mutex<HashMap<u64, EpochSocketHandle>>>,
    shutdown_tx: watch::Sender<bool>,
    manager_task: Option<JoinHandle<()>>,
}

impl RelayV2Listener {
    /// Connects to `relay_url`, derives the active epoch mailbox window from `mailbox_secret`,
    /// opens one independent control WebSocket per epoch mailbox, and starts accepting streams.
    pub async fn bind(
        relay_url: impl Into<String>,
        expected_host: Option<String>,
        mailbox_secret: [u8; 32],
        write_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        let config = RelayV2ListenerConfig {
            expected_host,
            write_timeout,
            ..RelayV2ListenerConfig::default()
        };
        Self::bind_with_config(relay_url, mailbox_secret, config).await
    }

    /// Connects to `relay_url` using explicit [`RelayV2ListenerConfig`].
    pub async fn bind_with_config(
        relay_url: impl Into<String>,
        mailbox_secret: [u8; 32],
        config: RelayV2ListenerConfig,
    ) -> Result<Self, RuntimeError> {
        let secret = Zeroizing::new(mailbox_secret);
        let parsed = super::validate_ws_url(&relay_url.into(), config.allow_insecure_ws)?;
        let required_host = extract_expected_host(&parsed, config.expected_host.as_deref())?;
        let relay_url = parsed.as_str().to_owned();

        let now_unix = config.unix_secs.unwrap_or_else(current_unix_secs);
        let initial_window = derive_epoch_mailbox_window(&secret, now_unix);
        let center_epoch = initial_window.center_epoch;
        let window = Arc::new(Mutex::new(initial_window.clone()));
        let replay_cache = config
            .replay_cache
            .unwrap_or_else(|| Arc::new(Mutex::new(RelayDialReplayCache::new())));
        let active_control_sockets = Arc::new(AtomicUsize::new(0));
        let (accepted_tx, accepted_rx) = mpsc::channel(32);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let accept_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let epoch_tasks = Arc::new(Mutex::new(HashMap::<u64, EpochSocketHandle>::new()));
        let mut bind_guard = BindCleanupGuard {
            shutdown_tx: shutdown_tx.clone(),
            epoch_tasks: Arc::clone(&epoch_tasks),
            armed: true,
        };

        let mut ready_waiters = Vec::new();
        for mailbox in initial_window.mailboxes() {
            let mailbox_owned = mailbox.clone();
            let epoch = mailbox_owned.epoch;
            let (ready_tx, ready_rx) = oneshot::channel();
            let handle = spawn_epoch_control_task(
                relay_url.clone(),
                required_host.clone(),
                mailbox_owned,
                Arc::clone(&window),
                Arc::clone(&replay_cache),
                Arc::clone(&accept_sem),
                accepted_tx.clone(),
                Arc::clone(&active_control_sockets),
                config.write_timeout,
                Some(ready_tx),
            );
            epoch_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(epoch, handle);
            ready_waiters.push((epoch, ready_rx));
        }

        let mut center_ok = false;
        let mut any_ok = false;
        let mut first_err: Option<RuntimeError> = None;
        let mut challenge_err: Option<RuntimeError> = None;
        for (epoch, rx) in ready_waiters {
            match rx.await {
                Ok(Ok(())) => {
                    any_ok = true;
                    if epoch == center_epoch {
                        center_ok = true;
                    }
                }
                Ok(Err(err)) => {
                    if matches!(err, RuntimeError::Core(_)) && challenge_err.is_none() {
                        challenge_err = Some(err);
                    } else if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
                Err(_) => {
                    if first_err.is_none() {
                        first_err = Some(RuntimeError::Closed);
                    }
                }
            }
        }

        if let Some(err) = challenge_err {
            return Err(err);
        }
        if !any_ok || (!center_ok && first_err.is_some()) {
            return Err(first_err.unwrap_or(RuntimeError::Closed));
        }

        let pinned_unix = config.unix_secs;
        let write_timeout = config.write_timeout;
        let window_c = Arc::clone(&window);
        let cache_c = Arc::clone(&replay_cache);
        let sockets_c = Arc::clone(&active_control_sockets);
        let tasks_c = Arc::clone(&epoch_tasks);
        let url_c = relay_url.clone();
        let mut shut_rx = shutdown_rx;
        let manager_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(EPOCH_ROTATE_POLL_INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut active_center = center_epoch;
            loop {
                tokio::select! {
                    _ = shut_rx.changed() => {
                        tasks_c
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clear();
                        break;
                    }
                    _ = interval.tick() => {
                        let now = pinned_unix.unwrap_or_else(current_unix_secs);
                        let new_center = epoch_for_unix(now);
                        if new_center != active_center {
                            let new_win = derive_epoch_mailbox_window(&secret, now);
                            let keep_epochs: Vec<u64> =
                                new_win.mailboxes().into_iter().map(|m| m.epoch).collect();
                            {
                                let mut guard = window_c
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                *guard = new_win;
                            }
                            let mut removed = Vec::new();
                            {
                                let mut guard = tasks_c
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                let to_remove: Vec<u64> = guard
                                    .keys()
                                    .copied()
                                    .filter(|ep| !keep_epochs.contains(ep))
                                    .collect();
                                for ep in to_remove {
                                    if let Some(h) = guard.remove(&ep) {
                                        removed.push(h);
                                    }
                                }
                            }
                            for h in removed {
                                h.stop();
                            }
                            active_center = new_center;
                        }

                        let active_epochs: Vec<DerivedMailbox> = {
                            let guard = window_c
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            guard.mailboxes().into_iter().cloned().collect()
                        };
                        for mb in active_epochs {
                            let needs_spawn = {
                                let guard = tasks_c
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                guard.get(&mb.epoch).is_none_or(|h| h.task.is_finished())
                            };
                            if needs_spawn {
                                let epoch = mb.epoch;
                                let handle = spawn_epoch_control_task(
                                    url_c.clone(),
                                    required_host.clone(),
                                    mb,
                                    Arc::clone(&window_c),
                                    Arc::clone(&cache_c),
                                    Arc::clone(&accept_sem),
                                    accepted_tx.clone(),
                                    Arc::clone(&sockets_c),
                                    write_timeout,
                                    None,
                                );
                                let old = tasks_c
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .insert(epoch, handle);
                                drop(old);
                            }
                        }
                    }
                }
            }
        });

        bind_guard.armed = false;
        Ok(Self {
            accepted_rx,
            relay_url,
            window,
            replay_cache,
            active_control_sockets,
            epoch_tasks,
            shutdown_tx,
            manager_task: Some(manager_task),
        })
    }

    /// Returns the base64url current center epoch `mailbox_id`.
    #[must_use]
    pub fn current_mailbox_id_b64(&self) -> String {
        self.window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current
            .mailbox_id_b64url()
    }

    /// Returns a snapshot of the active sliding epoch mailbox window.
    #[must_use]
    pub fn epoch_window(&self) -> RelayEpochWindow {
        self.window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Returns the number of currently active separate per-epoch control sockets.
    #[must_use]
    pub fn active_control_socket_count(&self) -> usize {
        self.active_control_sockets.load(Ordering::Acquire)
    }

    /// Returns the shared [`RelayDialReplayCache`] guarding `incoming` dial notifications.
    #[must_use]
    pub fn replay_cache(&self) -> Arc<Mutex<RelayDialReplayCache>> {
        Arc::clone(&self.replay_cache)
    }
}

impl Drop for RelayV2Listener {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.manager_task.take() {
            task.abort();
        }
        let mut guard = self
            .epoch_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.clear();
    }
}

#[async_trait]
impl PathListener for RelayV2Listener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = self.accepted_rx.recv().await.ok_or(RuntimeError::Closed)?;
        Ok(Box::new(stream))
    }

    fn local_endpoint(&self) -> String {
        format!("{}#{}", self.relay_url, self.current_mailbox_id_b64())
    }
}

struct ActiveSocketGuard(Arc<AtomicUsize>);

impl Drop for ActiveSocketGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_epoch_control_task(
    relay_url: String,
    expected_host: String,
    mailbox: DerivedMailbox,
    window: Arc<Mutex<RelayEpochWindow>>,
    replay_cache: Arc<Mutex<RelayDialReplayCache>>,
    accept_sem: Arc<Semaphore>,
    accepted_tx: mpsc::Sender<RelayStream>,
    active_sockets: Arc<AtomicUsize>,
    write_timeout: Duration,
    ready_tx: Option<oneshot::Sender<Result<(), RuntimeError>>>,
) -> EpochSocketHandle {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut ready_tx = ready_tx;
        let mut backoff = BACKOFF_INITIAL;
        let mut accept_tasks: JoinSet<()> = JoinSet::new();

        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            let (mut control_ws, verified_host, nonce, _srv_epoch) =
                match connect_and_verify_v2_challenge(&relay_url, &expected_host).await {
                    Ok(v) => v,
                    Err(err) => {
                        let is_core_err = matches!(err, RuntimeError::Core(_));
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(Err(err));
                            break;
                        }
                        if is_core_err {
                            break;
                        }
                        tokio::select! {
                            _ = shutdown_rx.changed() => break,
                            () = tokio::time::sleep(jittered_backoff(backoff)) => {}
                        }
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                        continue;
                    }
                };
            let sig = match sign_v2_relay_register(&mailbox, verified_host.as_str(), &nonce) {
                Ok(s) => s,
                Err(err) => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(err.into()));
                    }
                    break;
                }
            };
            let mailbox_b64 = mailbox.mailbox_id_b64url();
            if let Err(err) = send_v2_control_msg(
                &mut control_ws,
                &RelayV2ClientMsg::Register {
                    mailbox_id: mailbox_b64.clone(),
                    epoch: mailbox.epoch,
                    sig: b64url_encode(&sig),
                },
                write_timeout,
            )
            .await
            {
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(Err(err));
                    break;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    () = tokio::time::sleep(jittered_backoff(backoff)) => {}
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }

            match recv_v2_control_msg(&mut control_ws).await {
                Ok(RelayV2ServerMsg::Registered { mailbox_id, epoch })
                    if mailbox_id == mailbox_b64 && epoch == mailbox.epoch => {}
                Ok(RelayV2ServerMsg::Error { code }) => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(RuntimeError::Protocol(format!(
                            "v2 relay register rejected: {code}"
                        ))));
                        break;
                    }
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        () = tokio::time::sleep(jittered_backoff(backoff)) => {}
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
                Ok(other) => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(RuntimeError::Protocol(format!(
                            "unexpected v2 relay register response: {other:?}"
                        ))));
                        break;
                    }
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        () = tokio::time::sleep(jittered_backoff(backoff)) => {}
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
                Err(err) => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(err));
                        break;
                    }
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        () = tokio::time::sleep(jittered_backoff(backoff)) => {}
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
            }

            let connected_at = TokioInstant::now();
            active_sockets.fetch_add(1, Ordering::AcqRel);
            let _socket_guard = ActiveSocketGuard(Arc::clone(&active_sockets));
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Ok(()));
            }

            let idle_sleep = tokio::time::sleep(CONTROL_IDLE_TIMEOUT);
            tokio::pin!(idle_sleep);
            let mut ping_interval = tokio::time::interval_at(
                TokioInstant::now() + CONTROL_PING_INTERVAL,
                CONTROL_PING_INTERVAL,
            );
            ping_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let disconnected = loop {
                if *shutdown_rx.borrow() {
                    let _ = timeout(write_timeout, control_ws.close(None)).await;
                    break false;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        let _ = timeout(write_timeout, control_ws.close(None)).await;
                        break false;
                    }
                    () = &mut idle_sleep => {
                        let _ = timeout(write_timeout, control_ws.close(None)).await;
                        break true;
                    }
                    _ = ping_interval.tick() => {
                        if !timeout(
                            write_timeout,
                            control_ws.send(Message::Ping(Vec::new().into())),
                        )
                        .await
                        .is_ok_and(|res| res.is_ok())
                        {
                            let _ = timeout(write_timeout, control_ws.close(None)).await;
                            break true;
                        }
                    }
                    Some(_) = accept_tasks.join_next(), if !accept_tasks.is_empty() => {}
                    maybe_msg = control_ws.next() => {
                        match maybe_msg {
                            Some(Ok(Message::Text(text))) => {
                                idle_sleep
                                    .as_mut()
                                    .reset(TokioInstant::now() + CONTROL_IDLE_TIMEOUT);
                                if let Ok(RelayV2ServerMsg::Incoming {
                                    mailbox_id: inc_mailbox_b64,
                                    epoch: inc_epoch,
                                    conn_id,
                                    dial_nonce,
                                    dial_token,
                                }) = serde_json::from_str::<RelayV2ServerMsg>(&text)
                                {
                                    let (
                                        Ok(inc_mailbox_bytes),
                                        Ok(conn_id_bytes),
                                        Ok(dial_nonce_bytes),
                                        Ok(dial_token_bytes),
                                    ) = (
                                        b64url_decode_array::<32>(&inc_mailbox_b64),
                                        b64url_decode_array::<16>(&conn_id),
                                        b64url_decode_array::<32>(&dial_nonce),
                                        b64url_decode_array::<32>(&dial_token),
                                    ) else {
                                        continue;
                                    };
                                    if inc_mailbox_bytes != mailbox.mailbox_id || inc_epoch != mailbox.epoch {
                                        continue;
                                    }

                                    let matched_mailbox = {
                                        let mut cache = replay_cache
                                            .lock()
                                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                                        let win = window
                                            .lock()
                                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                                        verify_and_record_v2_relay_dial(
                                            &mut cache,
                                            &win,
                                            &verified_host,
                                            inc_epoch,
                                            &dial_nonce_bytes,
                                            &conn_id_bytes,
                                            &dial_token_bytes,
                                        )
                                        .ok()
                                        .cloned()
                                    };
                                    let Some(matched_mailbox) = matched_mailbox else {
                                        continue;
                                    };

                                    let Ok(permit) = Arc::clone(&accept_sem).try_acquire_owned() else {
                                        continue;
                                    };
                                    let url_c = relay_url.clone();
                                    let host_c = expected_host.clone();
                                    let tx_c = accepted_tx.clone();
                                    accept_tasks.spawn(async move {
                                        let _permit = permit;
                                        if let Ok(stream) = accept_one_v2_stream(
                                            &url_c,
                                            &host_c,
                                            &matched_mailbox,
                                            &conn_id,
                                            &conn_id_bytes,
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
                                    .reset(TokioInstant::now() + CONTROL_IDLE_TIMEOUT);
                            }
                            None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break true,
                            Some(Ok(_)) => {}
                        }
                    }
                }
            };
            drop(_socket_guard);
            if !disconnected || *shutdown_rx.borrow() {
                break;
            }
            if connected_at.elapsed() >= STABLE_UPTIME_RESET {
                backoff = BACKOFF_INITIAL;
            }
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                () = tokio::time::sleep(jittered_backoff(backoff)) => {}
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
        accept_tasks.abort_all();
    });
    EpochSocketHandle { shutdown_tx, task }
}

async fn accept_one_v2_stream(
    relay_url: &str,
    expected_host: &str,
    mailbox: &DerivedMailbox,
    conn_id_b64: &str,
    conn_id_bytes: &[u8; 16],
    write_timeout: Duration,
) -> Result<RelayStream, RuntimeError> {
    let (mut ws, verified_host, nonce, _srv_epoch) =
        connect_and_verify_v2_challenge(relay_url, expected_host).await?;
    let sig = sign_v2_relay_accept(mailbox, verified_host.as_str(), &nonce, conn_id_bytes)?;
    send_v2_control_msg(
        &mut ws,
        &RelayV2ClientMsg::Accept {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            conn_id: conn_id_b64.to_owned(),
            sig: b64url_encode(&sig),
        },
        write_timeout,
    )
    .await?;

    match recv_v2_control_msg(&mut ws).await? {
        RelayV2ServerMsg::Ready { conn_id } if conn_id == conn_id_b64 => {
            Ok(RelayStream::new(ws, write_timeout))
        }
        RelayV2ServerMsg::Error { code } => Err(RuntimeError::Protocol(format!(
            "v2 relay accept rejected: {code}"
        ))),
        other => Err(RuntimeError::Protocol(format!(
            "unexpected v2 relay accept response: {other:?}"
        ))),
    }
}

/// Dialer connecting through a Tendril `/v2/relay` endpoint using blinded epoch
/// `mailbox_id`s and authenticated HMAC-SHA256 `dial_token`s.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RelayV2Dialer {
    mailbox_secret: [u8; 32],
    #[zeroize(skip)]
    expected_host: Option<String>,
    #[zeroize(skip)]
    write_timeout: Duration,
    #[zeroize(skip)]
    allow_insecure_ws: bool,
    #[zeroize(skip)]
    unix_secs: Option<u64>,
}

impl std::fmt::Debug for RelayV2Dialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayV2Dialer")
            .field("expected_host", &self.expected_host)
            .field("allow_insecure_ws", &self.allow_insecure_ws)
            .field("mailbox_secret", &"<redacted>")
            .finish()
    }
}

impl RelayV2Dialer {
    /// Constructs a [`RelayV2Dialer`] bound to the peer's 32-byte `mailbox_secret`.
    #[must_use]
    pub fn new(mailbox_secret: [u8; 32]) -> Self {
        Self {
            mailbox_secret,
            expected_host: None,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            allow_insecure_ws: false,
            unix_secs: None,
        }
    }

    /// Explicitly permits cleartext `ws://` outside loopback hosts.
    #[must_use]
    pub fn with_allow_insecure_ws(mut self, allow: bool) -> Self {
        self.allow_insecure_ws = allow;
        self
    }

    /// Requires the server `Challenge.host` field to match `host` after canonicalization.
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

    /// Pins the dialer clock to `unix_secs` for deterministic epoch testing.
    #[must_use]
    pub fn with_unix_secs(mut self, unix_secs: u64) -> Self {
        self.unix_secs = Some(unix_secs);
        self
    }

    /// Connects through `relay_url` for the current epoch derived from clock.
    pub async fn connect(&self, relay_url: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let epoch = epoch_for_unix(self.unix_secs.unwrap_or_else(current_unix_secs));
        self.connect_for_epoch(relay_url, epoch).await
    }

    /// Connects through `relay_url` targeting an explicit epoch `epoch`.
    pub async fn connect_for_epoch(
        &self,
        relay_url: &str,
        epoch: u64,
    ) -> Result<Box<dyn PathStream>, RuntimeError> {
        let parsed = super::validate_ws_url(relay_url, self.allow_insecure_ws)?;
        let required_host = extract_expected_host(&parsed, self.expected_host.as_deref())?;
        let (mut ws, verified_host, nonce, _srv_epoch) =
            connect_and_verify_v2_challenge(parsed.as_str(), &required_host).await?;

        let mailbox = derive_epoch_mailbox(&self.mailbox_secret, epoch);
        let conn_id = random_bytes::<16>()?;
        let conn_id_b64 = b64url_encode(&conn_id);
        let dial_token = sign_v2_relay_dial(&mailbox, verified_host.as_str(), &nonce, &conn_id)?;

        send_v2_control_msg(
            &mut ws,
            &RelayV2ClientMsg::Dial {
                target_mailbox_id: mailbox.mailbox_id_b64url(),
                epoch,
                conn_id: conn_id_b64.clone(),
                dial_token: b64url_encode(&dial_token),
            },
            self.write_timeout,
        )
        .await?;

        match recv_v2_control_msg(&mut ws).await? {
            RelayV2ServerMsg::Ready { conn_id } if conn_id == conn_id_b64 => {
                Ok(Box::new(RelayStream::new(ws, self.write_timeout)))
            }
            RelayV2ServerMsg::Error { code } => Err(RuntimeError::Protocol(format!(
                "v2 relay dial rejected: {code}"
            ))),
            other => Err(RuntimeError::Protocol(format!(
                "unexpected v2 relay dial response: {other:?}"
            ))),
        }
    }
}

#[async_trait]
impl PathDialer for RelayV2Dialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Relay
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let url = endpoint.split_once('#').map_or(endpoint, |(u, _)| u);
        self.connect(url).await
    }
}
