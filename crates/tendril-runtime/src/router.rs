//! Intent-based inbound connection routing for multi-listener endpoints.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tendril_core::PREAMBLE_LEN;
use tendril_core::wire::{Intent, Preamble, WIRE_VERSION, WIRE_VERSION_V2};
use tokio::runtime::Handle;
use tokio::sync::{Notify, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, sleep, timeout, timeout_at};

use crate::driver::DEFAULT_PRE_AUTH_TIMEOUT;
use crate::error::RuntimeError;
use crate::provider::{PathListener, PathStream, PrefixedPathStream, peek_exact};
use crate::rate_limit::{HalfOpenGuard, PreAuthConfig, PreAuthRateLimiter, RefusalState};

const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(20);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Pre-authenticated inbound stream paired with its bounded half-open guard.
pub type RoutedInbound = (Box<dyn PathStream>, HalfOpenGuard);

struct QueuedInbound {
    item: RoutedInbound,
    expires_at: TokioInstant,
}

struct QueueState {
    closed: bool,
    cap: usize,
    items: VecDeque<QueuedInbound>,
}

impl QueueState {
    fn sweep_expired(&mut self, now: TokioInstant) {
        while let Some(front) = self.items.front() {
            if front.expires_at <= now {
                self.items.pop_front();
            } else {
                break;
            }
        }
    }
}

struct QueueInner {
    state: StdMutex<QueueState>,
    notify: Notify,
}

/// Shared receiver handle for one routed inbound intent stream.
#[derive(Clone)]
pub struct InboundQueue(Arc<QueueInner>);

impl InboundQueue {
    fn new(cap: usize) -> Self {
        Self(Arc::new(QueueInner {
            state: StdMutex::new(QueueState {
                closed: false,
                cap: cap.max(1),
                items: VecDeque::new(),
            }),
            notify: Notify::new(),
        }))
    }

    fn try_push(&self, item: RoutedInbound, expires_at: TokioInstant) -> bool {
        let pushed = {
            let mut st = self.0.state.lock().expect("inbound queue mutex poisoned");
            if st.closed {
                false
            } else {
                st.sweep_expired(TokioInstant::now());
                if st.items.len() >= st.cap {
                    false
                } else {
                    st.items.push_back(QueuedInbound { item, expires_at });
                    true
                }
            }
        };
        if pushed {
            self.0.notify.notify_waiters();
        }
        pushed
    }

    fn sweep(&self, now: TokioInstant) {
        let mut st = self.0.state.lock().expect("inbound queue mutex poisoned");
        st.sweep_expired(now);
    }

    fn clear_items(&self) {
        let mut st = self.0.state.lock().expect("inbound queue mutex poisoned");
        st.items.clear();
    }

    fn close(&self) {
        let mut st = self.0.state.lock().expect("inbound queue mutex poisoned");
        st.closed = true;
        st.items.clear();
        drop(st);
        self.0.notify.notify_waiters();
    }
}

/// Peeks each accepted stream's cleartext preamble and dispatches `Intent::Pair`
/// and `Intent::Session` handshakes onto independent bounded queues with isolated
/// half-open budgets and automatic expiration.
pub struct InboundRouter {
    refusal: RefusalState,
    rate_limiter: PreAuthRateLimiter,
    pair_limiter: PreAuthRateLimiter,
    session_limiter: PreAuthRateLimiter,
    v2_pair_limiter: PreAuthRateLimiter,
    v2_session_limiter: PreAuthRateLimiter,
    pair_enabled: Arc<AtomicBool>,
    v2_pair_enabled: Arc<AtomicBool>,
    queue_ttl: Duration,
    shutdown_tx: watch::Sender<bool>,
    pair_queue: InboundQueue,
    session_queue: InboundQueue,
    v2_pair_queue: InboundQueue,
    v2_session_queue: InboundQueue,
    sweeper_started: AtomicBool,
    listener_tasks: StdMutex<Vec<AbortHandle>>,
}

impl InboundRouter {
    /// Creates a new router backed by `PreAuthConfig::default()` or a custom `config`.
    #[must_use]
    pub fn with_config(config: PreAuthConfig) -> Self {
        Self::with_config_and_ttl(config, DEFAULT_PRE_AUTH_TIMEOUT)
    }

    /// Creates a new router with explicit `queue_ttl` expiration for unaccepted streams.
    #[must_use]
    pub fn with_config_and_ttl(config: PreAuthConfig, queue_ttl: Duration) -> Self {
        let queue_cap = config.max_half_open.clamp(16, 128);
        let refusal = RefusalState::new();
        let limiter = |config: PreAuthConfig| {
            PreAuthRateLimiter::new(config).with_refusal_state(refusal.clone())
        };
        let pair_limiter = limiter(config.clone());
        let session_limiter = limiter(config.clone());
        let v2_pair_limiter = limiter(config.clone());
        let v2_session_limiter = limiter(config.clone());
        let rate_limiter = limiter(config);
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            refusal,
            rate_limiter,
            pair_limiter,
            session_limiter,
            v2_pair_limiter,
            v2_session_limiter,
            pair_enabled: Arc::new(AtomicBool::new(true)),
            v2_pair_enabled: Arc::new(AtomicBool::new(true)),
            queue_ttl: queue_ttl.max(Duration::from_millis(10)),
            shutdown_tx,
            pair_queue: InboundQueue::new(queue_cap),
            session_queue: InboundQueue::new(queue_cap),
            v2_pair_queue: InboundQueue::new(queue_cap),
            v2_session_queue: InboundQueue::new(queue_cap),
            sweeper_started: AtomicBool::new(false),
            listener_tasks: StdMutex::new(Vec::new()),
        }
    }

    /// Creates a new router with default pre-authentication rate-limit bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PreAuthConfig::default())
    }

    /// Returns the endpoint-wide refusal state every limiter of this router carries. Hand it to
    /// [`crate::V2ResponderState::with_refusal_state`] so Wire v1 and Wire v2 share one limiter.
    #[must_use]
    pub fn refusal_state(&self) -> &RefusalState {
        &self.refusal
    }

    /// Returns the shared pre-authentication rate limiter guarding preamble peeks and peer checks.
    #[must_use]
    pub fn rate_limiter(&self) -> &PreAuthRateLimiter {
        &self.rate_limiter
    }

    /// Returns the isolated half-open rate limiter dedicated to queued v1 `Intent::Pair` streams.
    #[must_use]
    pub fn pair_rate_limiter(&self) -> &PreAuthRateLimiter {
        &self.pair_limiter
    }

    /// Returns the isolated half-open rate limiter dedicated to queued v1 `Intent::Session` streams.
    #[must_use]
    pub fn session_rate_limiter(&self) -> &PreAuthRateLimiter {
        &self.session_limiter
    }

    /// Returns the isolated half-open rate limiter dedicated to queued v2 `Intent::Pair` streams.
    #[must_use]
    pub fn v2_pair_rate_limiter(&self) -> &PreAuthRateLimiter {
        &self.v2_pair_limiter
    }

    /// Returns the isolated half-open rate limiter dedicated to queued v2 `Intent::Session` streams.
    #[must_use]
    pub fn v2_session_rate_limiter(&self) -> &PreAuthRateLimiter {
        &self.v2_session_limiter
    }

    /// Enables or disables acceptance of both v1 and v2 `Intent::Pair` connections at the router boundary.
    pub fn set_pair_enabled(&self, enabled: bool) {
        self.pair_enabled.store(enabled, Ordering::Release);
        self.v2_pair_enabled.store(enabled, Ordering::Release);
        if !enabled {
            self.pair_queue.clear_items();
            self.v2_pair_queue.clear_items();
        }
    }

    /// Reports whether v1 `Intent::Pair` connections are currently accepted by the router.
    #[must_use]
    pub fn is_pair_enabled(&self) -> bool {
        self.pair_enabled.load(Ordering::Acquire)
    }

    /// Enables or disables acceptance of v2 `Intent::Pair` connections at the router boundary.
    pub fn set_v2_pair_enabled(&self, enabled: bool) {
        self.v2_pair_enabled.store(enabled, Ordering::Release);
        if !enabled {
            self.v2_pair_queue.clear_items();
        }
    }

    /// Reports whether v2 `Intent::Pair` connections are currently accepted by the router.
    #[must_use]
    pub fn is_v2_pair_enabled(&self) -> bool {
        self.v2_pair_enabled.load(Ordering::Acquire)
    }

    fn register_background_task(&self, join: JoinHandle<()>) {
        let mut tasks = self
            .listener_tasks
            .lock()
            .expect("listener_tasks mutex poisoned");
        if *self.shutdown_tx.borrow() {
            drop(tasks);
            join.abort();
            return;
        }
        tasks.push(join.abort_handle());
    }

    fn ensure_sweeper(&self, handle: &Handle) {
        if self.sweeper_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let pair_q = self.pair_queue.clone();
        let sess_q = self.session_queue.clone();
        let v2_pair_q = self.v2_pair_queue.clone();
        let v2_sess_q = self.v2_session_queue.clone();
        let mut shut = self.shutdown_tx.subscribe();
        if *shut.borrow() {
            return;
        }
        let tick_every =
            (self.queue_ttl / 2).clamp(Duration::from_millis(20), Duration::from_secs(1));
        let join = handle.spawn(async move {
            let mut interval = tokio::time::interval(tick_every);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                if *shut.borrow() {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = shut.changed() => break,
                    _ = interval.tick() => {
                        let now = TokioInstant::now();
                        pair_q.sweep(now);
                        sess_q.sweep(now);
                        v2_pair_q.sweep(now);
                        v2_sess_q.sweep(now);
                    }
                }
            }
        });
        self.register_background_task(join);
    }

    /// Spawns an accept loop on `handle` routing inbound connections from `listener`.
    pub fn spawn_listener(&self, handle: &Handle, mut listener: Box<dyn PathListener>) {
        if *self.shutdown_tx.borrow() {
            return;
        }
        self.ensure_sweeper(handle);

        let peek_limiter = self.rate_limiter.clone();
        let pair_limiter = self.pair_limiter.clone();
        let session_limiter = self.session_limiter.clone();
        let v2_pair_limiter = self.v2_pair_limiter.clone();
        let v2_session_limiter = self.v2_session_limiter.clone();
        let pair_enabled = Arc::clone(&self.pair_enabled);
        let v2_pair_enabled = Arc::clone(&self.v2_pair_enabled);
        let pair_q = self.pair_queue.clone();
        let sess_q = self.session_queue.clone();
        let v2_pair_q = self.v2_pair_queue.clone();
        let v2_sess_q = self.v2_session_queue.clone();
        let queue_ttl = self.queue_ttl;
        let shutdown_tx = self.shutdown_tx.clone();
        let mut shut = shutdown_tx.subscribe();
        if *shut.borrow() {
            return;
        }
        let handle_clone = handle.clone();
        let join = handle.spawn(async move {
            let mut backoff = ACCEPT_BACKOFF_MIN;
            loop {
                if *shut.borrow() {
                    break;
                }
                let mut stream = tokio::select! {
                    biased;
                    _ = shut.changed() => break,
                    res = listener.accept() => match res {
                        Ok(s) => {
                            backoff = ACCEPT_BACKOFF_MIN;
                            s
                        }
                        Err(RuntimeError::Closed) => break,
                        Err(err) => {
                            tracing::warn!(error = %err, "inbound accept failed, retrying");
                            tokio::select! {
                                biased;
                                _ = shut.changed() => break,
                                () = sleep(backoff) => {}
                            }
                            backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                            continue;
                        }
                    },
                };
                let provider = stream.provider_id();
                let peer_ip = stream.peer_ip();
                let peer_transport_id = stream.peer_transport_id();
                let Ok(peek_guard) = peek_limiter.try_acquire_for_stream(
                    provider,
                    peer_ip,
                    peer_transport_id.as_deref(),
                ) else {
                    continue;
                };
                let p_lim = pair_limiter.clone();
                let s_lim = session_limiter.clone();
                let v2_p_lim = v2_pair_limiter.clone();
                let v2_s_lim = v2_session_limiter.clone();
                let p_enabled = Arc::clone(&pair_enabled);
                let v2_p_enabled = Arc::clone(&v2_pair_enabled);
                let p_q = pair_q.clone();
                let s_q = sess_q.clone();
                let v2_p_q = v2_pair_q.clone();
                let v2_s_q = v2_sess_q.clone();
                let mut conn_shut = shutdown_tx.subscribe();
                handle_clone.spawn(async move {
                    if *conn_shut.borrow() {
                        return;
                    }
                    let peeked = tokio::select! {
                        biased;
                        _ = conn_shut.changed() => return,
                        res = timeout(DEFAULT_PRE_AUTH_TIMEOUT, peek_exact(stream.as_mut(), PREAMBLE_LEN)) => {
                            match res {
                                Ok(Ok(bytes)) => bytes,
                                Ok(Err(_)) | Err(_) => return,
                            }
                        }
                    };
                    let Ok(preamble) = Preamble::decode(&peeked[..PREAMBLE_LEN]) else {
                        return;
                    };
                    drop(peek_guard);
                    let wrapped: Box<dyn PathStream> =
                        Box::new(PrefixedPathStream::new(stream, peeked));
                    let expires_at = TokioInstant::now() + queue_ttl;
                    match (preamble.version, preamble.intent) {
                        (WIRE_VERSION, Intent::Pair) => {
                            if !p_enabled.load(Ordering::Acquire) {
                                return;
                            }
                            let Ok(guard) = p_lim.try_acquire_half_open_for_stream(provider, peer_ip, peer_transport_id.as_deref()) else {
                                return;
                            };
                            let _ = p_q.try_push((wrapped, guard), expires_at);
                        }
                        (WIRE_VERSION, Intent::Session) => {
                            let Ok(guard) = s_lim.try_acquire_half_open_for_stream(provider, peer_ip, peer_transport_id.as_deref()) else {
                                return;
                            };
                            let _ = s_q.try_push((wrapped, guard), expires_at);
                        }
                        (WIRE_VERSION_V2, Intent::Pair) => {
                            if !v2_p_enabled.load(Ordering::Acquire) {
                                return;
                            }
                            let Ok(guard) = v2_p_lim.try_acquire_half_open_for_stream(provider, peer_ip, peer_transport_id.as_deref())
                            else {
                                return;
                            };
                            let _ = v2_p_q.try_push((wrapped, guard), expires_at);
                        }
                        (WIRE_VERSION_V2, Intent::Session) => {
                            let Ok(guard) = v2_s_lim.try_acquire_half_open_for_stream(provider, peer_ip, peer_transport_id.as_deref())
                            else {
                                return;
                            };
                            let _ = v2_s_q.try_push((wrapped, guard), expires_at);
                        }
                        _ => {}
                    }
                });
            }
        });

        self.register_background_task(join);
    }

    /// Waits up to `wait` for the next inbound v1 `Intent::Pair` stream.
    ///
    /// Returns `Ok(Some(..))` on arrival, `Ok(None)` when closed, or `Err(())` on timeout.
    pub async fn recv_pair(&self, wait: Duration) -> Result<Option<RoutedInbound>, ()> {
        recv_routed(&self.pair_queue, wait).await
    }

    /// Waits up to `wait` for the next inbound v1 `Intent::Session` stream.
    ///
    /// Returns `Ok(Some(..))` on arrival, `Ok(None)` when closed, or `Err(())` on timeout.
    pub async fn recv_session(&self, wait: Duration) -> Result<Option<RoutedInbound>, ()> {
        recv_routed(&self.session_queue, wait).await
    }

    /// Waits up to `wait` for the next inbound v2 `Intent::Pair` stream.
    ///
    /// Returns `Ok(Some(..))` on arrival, `Ok(None)` when closed, or `Err(())` on timeout.
    pub async fn recv_v2_pair(&self, wait: Duration) -> Result<Option<RoutedInbound>, ()> {
        recv_routed(&self.v2_pair_queue, wait).await
    }

    /// Waits up to `wait` for the next inbound v2 `Intent::Session` stream.
    ///
    /// Returns `Ok(Some(..))` on arrival, `Ok(None)` when closed, or `Err(())` on timeout.
    pub async fn recv_v2_session(&self, wait: Duration) -> Result<Option<RoutedInbound>, ()> {
        recv_routed(&self.v2_session_queue, wait).await
    }

    /// Returns shared v1 queue handles suitable for detached worker futures.
    #[must_use]
    pub fn split_queues(&self) -> (InboundQueue, InboundQueue) {
        (self.pair_queue.clone(), self.session_queue.clone())
    }

    /// Returns shared v2 queue handles suitable for detached worker futures.
    #[must_use]
    pub fn split_v2_queues(&self) -> (InboundQueue, InboundQueue) {
        (self.v2_pair_queue.clone(), self.v2_session_queue.clone())
    }

    /// Aborts all spawned listeners and closes inbound queues so blocked waiters wake immediately.
    pub fn close(&self) {
        let _ = self.shutdown_tx.send(true);
        self.refusal.shutdown();
        self.pair_queue.close();
        self.session_queue.close();
        self.v2_pair_queue.close();
        self.v2_session_queue.close();
        if let Ok(mut tasks) = self.listener_tasks.lock() {
            for h in tasks.drain(..) {
                h.abort();
            }
        }
    }
}

impl Default for InboundRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for InboundRouter {
    fn drop(&mut self) {
        self.close();
    }
}

/// Receives from a routed queue handle using non-blocking pop when `wait` is zero.
pub async fn recv_routed(
    queue: &InboundQueue,
    wait: Duration,
) -> Result<Option<RoutedInbound>, ()> {
    if wait.is_zero() {
        let mut st = queue.0.state.lock().expect("inbound queue mutex poisoned");
        st.sweep_expired(TokioInstant::now());
        if let Some(q) = st.items.pop_front() {
            return Ok(Some(q.item));
        }
        return if st.closed { Ok(None) } else { Err(()) };
    }

    let deadline = TokioInstant::now() + wait;
    loop {
        let notified = queue.0.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let mut st = queue.0.state.lock().expect("inbound queue mutex poisoned");
            st.sweep_expired(TokioInstant::now());
            if let Some(q) = st.items.pop_front() {
                return Ok(Some(q.item));
            }
            if st.closed {
                return Ok(None);
            }
        }
        if timeout_at(deadline, notified).await.is_err() {
            let mut st = queue.0.state.lock().expect("inbound queue mutex poisoned");
            st.sweep_expired(TokioInstant::now());
            if let Some(q) = st.items.pop_front() {
                return Ok(Some(q.item));
            }
            return if st.closed { Ok(None) } else { Err(()) };
        }
    }
}
