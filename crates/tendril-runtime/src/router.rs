//! Intent-based inbound connection routing for multi-listener endpoints.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tendril_core::PREAMBLE_LEN;
use tendril_core::wire::{Intent, Preamble};
use tokio::runtime::Handle;
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use tokio::task::AbortHandle;
use tokio::time::timeout;

use crate::driver::DEFAULT_PRE_AUTH_TIMEOUT;
use crate::provider::{PathListener, PathStream, PrefixedPathStream, peek_exact};
use crate::rate_limit::{HalfOpenGuard, PreAuthConfig, PreAuthRateLimiter};

/// Pre-authenticated inbound stream paired with its bounded half-open guard.
pub type RoutedInbound = (Box<dyn PathStream>, HalfOpenGuard);

/// Shared receiver handle for one routed inbound intent stream.
pub type InboundQueue = Arc<AsyncMutex<mpsc::Receiver<RoutedInbound>>>;

/// Peeks each accepted stream's cleartext preamble and dispatches `Intent::Pair`
/// and `Intent::Session` handshakes onto independent bounded queues.
pub struct InboundRouter {
    rate_limiter: PreAuthRateLimiter,
    shutdown_tx: watch::Sender<bool>,
    pair_tx: StdMutex<Option<mpsc::Sender<RoutedInbound>>>,
    pair_rx: InboundQueue,
    session_tx: StdMutex<Option<mpsc::Sender<RoutedInbound>>>,
    session_rx: InboundQueue,
    listener_tasks: StdMutex<Vec<AbortHandle>>,
}

impl InboundRouter {
    /// Creates a new router backed by `PreAuthConfig::default()` or a custom `config`.
    #[must_use]
    pub fn with_config(config: PreAuthConfig) -> Self {
        let queue_cap = config.max_half_open.clamp(16, 128);
        let (pair_tx, pair_rx) = mpsc::channel(queue_cap);
        let (session_tx, session_rx) = mpsc::channel(queue_cap);
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            rate_limiter: PreAuthRateLimiter::new(config),
            shutdown_tx,
            pair_tx: StdMutex::new(Some(pair_tx)),
            pair_rx: Arc::new(AsyncMutex::new(pair_rx)),
            session_tx: StdMutex::new(Some(session_tx)),
            session_rx: Arc::new(AsyncMutex::new(session_rx)),
            listener_tasks: StdMutex::new(Vec::new()),
        }
    }

    /// Creates a new router with default pre-authentication rate-limit bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PreAuthConfig::default())
    }

    /// Returns the shared pre-authentication rate limiter guarding accepted streams.
    #[must_use]
    pub fn rate_limiter(&self) -> &PreAuthRateLimiter {
        &self.rate_limiter
    }

    /// Spawns an accept loop on `handle` routing inbound connections from `listener`.
    pub fn spawn_listener(&self, handle: &Handle, mut listener: Box<dyn PathListener>) {
        if *self.shutdown_tx.borrow() {
            return;
        }
        let Some(pair_tx) = self.pair_tx.lock().expect("pair_tx mutex poisoned").clone() else {
            return;
        };
        let Some(session_tx) = self
            .session_tx
            .lock()
            .expect("session_tx mutex poisoned")
            .clone()
        else {
            return;
        };

        let limiter = self.rate_limiter.clone();
        let shutdown_tx = self.shutdown_tx.clone();
        let handle_clone = handle.clone();
        let join = handle.spawn(async move {
            let mut shut = shutdown_tx.subscribe();
            loop {
                let mut stream = tokio::select! {
                    biased;
                    _ = shut.changed() => break,
                    res = listener.accept() => match res {
                        Ok(s) => s,
                        Err(_) => break,
                    },
                };
                let Ok(guard) = limiter.try_acquire(stream.peer_ip()) else {
                    continue;
                };
                let p_tx = pair_tx.clone();
                let s_tx = session_tx.clone();
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
                    let wrapped: Box<dyn PathStream> =
                        Box::new(PrefixedPathStream::new(stream, peeked));
                    let tx = match preamble.intent {
                        Intent::Pair => p_tx,
                        Intent::Session => s_tx,
                    };
                    tokio::select! {
                        biased;
                        _ = conn_shut.changed() => {}
                        _ = tx.send((wrapped, guard)) => {}
                    }
                });
            }
        });

        if *self.shutdown_tx.borrow() {
            join.abort();
            return;
        }
        self.listener_tasks
            .lock()
            .expect("listener_tasks mutex poisoned")
            .push(join.abort_handle());
    }

    /// Waits up to `wait` for the next inbound `Intent::Pair` stream.
    ///
    /// Returns `Ok(Some(..))` on arrival, `Ok(None)` when closed, or `Err(())` on timeout.
    pub async fn recv_pair(&self, wait: Duration) -> Result<Option<RoutedInbound>, ()> {
        recv_routed(&self.pair_rx, wait).await
    }

    /// Waits up to `wait` for the next inbound `Intent::Session` stream.
    ///
    /// Returns `Ok(Some(..))` on arrival, `Ok(None)` when closed, or `Err(())` on timeout.
    pub async fn recv_session(&self, wait: Duration) -> Result<Option<RoutedInbound>, ()> {
        recv_routed(&self.session_rx, wait).await
    }

    /// Returns shared queue handles suitable for detached worker futures.
    #[must_use]
    pub fn split_queues(&self) -> (InboundQueue, InboundQueue) {
        (Arc::clone(&self.pair_rx), Arc::clone(&self.session_rx))
    }

    /// Aborts all spawned listeners and closes inbound queues so blocked waiters wake immediately.
    pub fn close(&self) {
        let _ = self.shutdown_tx.send(true);
        *self.pair_tx.lock().expect("pair_tx mutex poisoned") = None;
        *self.session_tx.lock().expect("session_tx mutex poisoned") = None;
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

/// Receives from a routed queue mutex using non-blocking `try_recv` when `wait` is zero.
pub async fn recv_routed(
    rx_mutex: &AsyncMutex<mpsc::Receiver<RoutedInbound>>,
    wait: Duration,
) -> Result<Option<RoutedInbound>, ()> {
    if wait.is_zero() {
        let Ok(mut rx) = rx_mutex.try_lock() else {
            return Err(());
        };
        return match rx.try_recv() {
            Ok(item) => Ok(Some(item)),
            Err(mpsc::error::TryRecvError::Disconnected) => Ok(None),
            Err(mpsc::error::TryRecvError::Empty) => Err(()),
        };
    }
    let mut rx = rx_mutex.lock().await;
    match timeout(wait, rx.recv()).await {
        Ok(Some(item)) => Ok(Some(item)),
        Ok(None) => Ok(None),
        Err(_) => Err(()),
    }
}
