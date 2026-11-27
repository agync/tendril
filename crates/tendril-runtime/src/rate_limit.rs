//! Pre-authentication LRU token buckets and bounded half-open handshake guard.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tendril_core::policy::ProviderId;
use tendril_core::{RefusalLimiter, RefusalReplayCache};
use tendril_relay::normalize_rate_limit_ip;
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::error::RuntimeError;
use crate::provider::PathStream;

/// Configuration bounds for [`PreAuthRateLimiter`].
#[derive(Debug, Clone)]
pub struct PreAuthConfig {
    pub max_entries: usize,
    pub max_half_open: usize,
    pub untrusted_max_half_open: usize,
    pub ip_burst: u32,
    pub ip_refill_per_sec: u32,
    pub peer_burst: u32,
    pub peer_refill_per_sec: u32,
    pub unattributed_burst: u32,
    pub unattributed_refill_per_sec: u32,
    pub max_half_open_per_key: usize,
}

impl Default for PreAuthConfig {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_half_open: 32,
            untrusted_max_half_open: 16,
            ip_burst: 24,
            ip_refill_per_sec: 8,
            peer_burst: 16,
            peer_refill_per_sec: 4,
            unattributed_burst: 16,
            unattributed_refill_per_sec: 4,
            max_half_open_per_key: 8,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seq: u64,
}

#[derive(Debug)]
struct LruBuckets<K> {
    max_entries: usize,
    capacity: f64,
    refill_per_sec: f64,
    next_seq: u64,
    buckets: HashMap<K, Bucket>,
    order: BTreeMap<(u64, K), ()>,
    eviction_overflow: Bucket,
}

impl<K: Eq + Hash + Clone + Ord> LruBuckets<K> {
    fn new(max_entries: usize, capacity: u32, refill_per_sec: u32) -> Self {
        let cap = f64::from(capacity.max(1));
        Self {
            max_entries: max_entries.max(1),
            capacity: cap,
            refill_per_sec: f64::from(refill_per_sec.max(1)),
            next_seq: 0,
            buckets: HashMap::new(),
            order: BTreeMap::new(),
            eviction_overflow: Bucket {
                tokens: cap,
                last_refill: Instant::now(),
                last_seq: 0,
            },
        }
    }

    fn allow(&mut self, key: K, now: Instant) -> bool {
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;

        if let Some(bucket) = self.buckets.get_mut(&key) {
            self.order.remove(&(bucket.last_seq, key.clone()));
            let elapsed = now
                .saturating_duration_since(bucket.last_refill)
                .as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            bucket.last_refill = now;
            bucket.last_seq = seq;
            self.order.insert((seq, key), ());
            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return true;
            }
            return false;
        }

        let under_eviction_pressure = self.buckets.len() >= self.max_entries;
        if under_eviction_pressure {
            let elapsed = now
                .saturating_duration_since(self.eviction_overflow.last_refill)
                .as_secs_f64();
            self.eviction_overflow.tokens =
                (self.eviction_overflow.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.eviction_overflow.last_refill = now;
            if self.eviction_overflow.tokens < 1.0 {
                return false;
            }
            self.eviction_overflow.tokens -= 1.0;
        }

        while self.buckets.len() >= self.max_entries {
            if let Some(((_, oldest_key), _)) = self.order.pop_first() {
                self.buckets.remove(&oldest_key);
            } else {
                break;
            }
        }

        let initial_tokens = if under_eviction_pressure {
            0.0
        } else {
            self.capacity - 1.0
        };
        self.buckets.insert(
            key.clone(),
            Bucket {
                tokens: initial_tokens,
                last_refill: now,
                last_seq: seq,
            },
        );
        self.order.insert((seq, key), ());
        true
    }
}

#[derive(Debug, Clone)]
enum HalfOpenKey {
    Peer(String),
    Ip(IpAddr),
    Unattributed,
}

impl HalfOpenKey {
    fn label(&self) -> String {
        match self {
            Self::Peer(p) => format!("peer:{p}"),
            Self::Ip(ip) => format!("ip:{}", normalize_rate_limit_ip(*ip)),
            Self::Unattributed => "unattributed".to_owned(),
        }
    }
}

/// How long a refused Wire v1 connection is read and discarded after its half-close
/// (`spec/wire-v1.md` Section 5.4.4, `REFUSAL_LINGER`).
pub const REFUSAL_LINGER: Duration = Duration::from_millis(250);

/// Maximum refused connections draining at once; a refusal that finds the bound reached closes
/// its connection immediately.
pub const MAX_REFUSAL_DRAINS: usize = 8;

/// One refusal that was actually sent to a peer (`spec/wire-v1.md` Section 5.4.2).
///
/// It is built only after the refusal limiter allowed the refusal and its frame was written, so
/// a flood of refusal-eligible attempts yields at most one record per peer per window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalAudit {
    /// Canonical `device_id` of the refused peer.
    pub peer_id: String,
    /// The refusal close code that was sent (`4001` or `4004`).
    pub code: u16,
}

type AuditSink = Arc<dyn Fn(&RefusalAudit) + Send + Sync>;

struct RefusalInner {
    limiter: Mutex<RefusalLimiter>,
    replay: Mutex<RefusalReplayCache>,
    drains: Arc<Semaphore>,
    max_drains: usize,
    audit: Option<AuditSink>,
    shutdown: watch::Sender<bool>,
}

/// Endpoint-wide state of authenticated refusal: the per-peer [`RefusalLimiter`], the
/// [`RefusalReplayCache`] of refused Wire v2 `msg1` nonces, the bound on connections draining
/// after a refusal, and the audit sink.
///
/// One value serves every ordinary listener of an endpoint, Wire v1 and Wire v2 alike, so the
/// limiter keys a peer once whichever wire it uses. Clones share the state.
#[derive(Clone)]
pub struct RefusalState {
    inner: Arc<RefusalInner>,
}

impl std::fmt::Debug for RefusalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefusalState")
            .field("drains_in_flight", &self.drains_in_flight())
            .finish_non_exhaustive()
    }
}

impl Default for RefusalState {
    fn default() -> Self {
        Self::new()
    }
}

impl RefusalState {
    /// Creates state that audits through `tracing` only.
    #[must_use]
    pub fn new() -> Self {
        Self::build(MAX_REFUSAL_DRAINS, None)
    }

    /// Creates state that also hands every sent refusal to `sink`.
    ///
    /// The sink runs on the accepting task: keep it cheap and never block in it.
    #[must_use]
    pub fn with_audit_sink(sink: impl Fn(&RefusalAudit) + Send + Sync + 'static) -> Self {
        Self::build(MAX_REFUSAL_DRAINS, Some(Arc::new(sink)))
    }

    /// Creates state that lets at most `max_drains` refused connections drain at once.
    #[must_use]
    pub fn with_max_drains(max_drains: usize) -> Self {
        Self::build(max_drains, None)
    }

    fn build(max_drains: usize, audit: Option<AuditSink>) -> Self {
        Self {
            inner: Arc::new(RefusalInner {
                limiter: Mutex::new(RefusalLimiter::new()),
                replay: Mutex::new(RefusalReplayCache::new()),
                drains: Arc::new(Semaphore::new(max_drains)),
                max_drains,
                audit,
                shutdown: watch::channel(false).0,
            }),
        }
    }

    /// Locks the per-peer refusal limiter.
    pub(crate) fn limiter(&self) -> MutexGuard<'_, RefusalLimiter> {
        self.inner
            .limiter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Locks the refused-`msg1` replay cache and the limiter together, in that order.
    pub(crate) fn caches(
        &self,
    ) -> (
        MutexGuard<'_, RefusalReplayCache>,
        MutexGuard<'_, RefusalLimiter>,
    ) {
        let replay = self
            .inner
            .replay
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        (replay, self.limiter())
    }

    /// Returns the number of refused connections draining now.
    #[must_use]
    pub fn drains_in_flight(&self) -> usize {
        self.inner
            .max_drains
            .saturating_sub(self.inner.drains.available_permits())
    }

    /// Records that a refusal with `code` was sent to `peer_id`.
    pub(crate) fn record(&self, peer_id: &str, code: u16) {
        tracing::info!(event = "session_refused", peer_id, code, "refusal sent");
        if let Some(sink) = &self.inner.audit {
            sink(&RefusalAudit {
                peer_id: peer_id.to_owned(),
                code,
            });
        }
    }

    /// Ends every refused connection that is draining and closes later ones at once. Called when
    /// the endpoint closes, so no detached drain outlives it.
    pub fn shutdown(&self) {
        self.inner.shutdown.send_replace(true);
    }

    /// Returns `true` once [`Self::shutdown`] ran.
    #[must_use]
    pub fn is_shut_down(&self) -> bool {
        *self.inner.shutdown.borrow()
    }

    /// Runs the refusal close sequence on `stream` after its refusal frame was written
    /// (`spec/wire-v1.md` Section 5.4.4, steps 2 and 3), without blocking the caller.
    ///
    /// A task half-closes the write side, then reads and discards inbound bytes until end of
    /// stream or [`REFUSAL_LINGER`], so unread inbound data cannot reset the connection and
    /// discard the frame. At most [`MAX_REFUSAL_DRAINS`] tasks run; past that, outside a Tokio
    /// runtime, or after [`Self::shutdown`], the stream is dropped at once.
    pub(crate) fn linger(&self, mut stream: Box<dyn PathStream>) {
        let Ok(runtime) = Handle::try_current() else {
            return;
        };
        let mut shutdown = self.inner.shutdown.subscribe();
        if *shutdown.borrow() {
            return;
        }
        let Ok(permit) = Arc::clone(&self.inner.drains).try_acquire_owned() else {
            return;
        };
        runtime.spawn(async move {
            let _permit = permit;
            let drain = async {
                let _ = stream.shutdown_write().await;
                let mut buf = vec![0u8; 1024];
                let _ = timeout(REFUSAL_LINGER, async {
                    loop {
                        match stream.recv_chunk(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                })
                .await;
            };
            tokio::select! {
                () = drain => {}
                _ = shutdown.wait_for(|down| *down) => {}
            }
            let _ = stream.close().await;
        });
    }
}

/// Thread-safe pre-authentication rate limiter guarding listener `accept` paths.
///
/// It also carries the endpoint's [`RefusalState`], so a Wire v1 `accept` that is given this
/// limiter is an ordinary listener that may refuse a known revoked or pending peer. Build one
/// [`RefusalState`] per endpoint and install it on every limiter with
/// [`Self::with_refusal_state`].
#[derive(Debug, Clone)]
pub struct PreAuthRateLimiter {
    inner: Arc<PreAuthInner>,
    refusal: RefusalState,
}

#[derive(Debug)]
struct PreAuthInner {
    max_half_open: usize,
    untrusted_max_half_open: usize,
    max_half_open_per_key: usize,
    active_half_open: AtomicUsize,
    untrusted_active_half_open: AtomicUsize,
    ip_buckets: Mutex<LruBuckets<IpAddr>>,
    peer_buckets: Mutex<LruBuckets<String>>,
    unattributed_bucket: Mutex<LruBuckets<()>>,
    active_per_key: Mutex<HashMap<String, usize>>,
}

/// RAII token holding one half-open pre-authentication handshake slot.
#[derive(Debug)]
pub struct HalfOpenGuard {
    inner: Arc<PreAuthInner>,
    is_untrusted: bool,
    tracked_key: Option<String>,
}

impl Drop for HalfOpenGuard {
    fn drop(&mut self) {
        if let Some(ref key) = self.tracked_key {
            let mut per_key = self
                .inner
                .active_per_key
                .lock()
                .expect("active_per_key mutex poisoned");
            if let Some(count) = per_key.get_mut(key) {
                if *count <= 1 {
                    per_key.remove(key);
                } else {
                    *count -= 1;
                }
            }
        }
        if self.is_untrusted {
            self.inner
                .untrusted_active_half_open
                .fetch_sub(1, Ordering::AcqRel);
        } else {
            self.inner.active_half_open.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn is_untrusted_provider(provider: ProviderId) -> bool {
    matches!(provider, ProviderId::Relay | ProviderId::Broker)
}

impl PreAuthRateLimiter {
    /// Creates a new pre-authentication rate limiter with `config`.
    #[must_use]
    pub fn new(config: PreAuthConfig) -> Self {
        Self {
            refusal: RefusalState::new(),
            inner: Arc::new(PreAuthInner {
                max_half_open: config.max_half_open.max(1),
                untrusted_max_half_open: config.untrusted_max_half_open.max(1),
                max_half_open_per_key: config.max_half_open_per_key.max(1),
                active_half_open: AtomicUsize::new(0),
                untrusted_active_half_open: AtomicUsize::new(0),
                ip_buckets: Mutex::new(LruBuckets::new(
                    config.max_entries,
                    config.ip_burst,
                    config.ip_refill_per_sec,
                )),
                peer_buckets: Mutex::new(LruBuckets::new(
                    config.max_entries,
                    config.peer_burst,
                    config.peer_refill_per_sec,
                )),
                unattributed_bucket: Mutex::new(LruBuckets::new(
                    1,
                    config.unattributed_burst,
                    config.unattributed_refill_per_sec,
                )),
                active_per_key: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Returns this limiter with `refusal` as its endpoint-wide refusal state.
    #[must_use]
    pub fn with_refusal_state(mut self, refusal: RefusalState) -> Self {
        self.refusal = refusal;
        self
    }

    /// Returns the refusal state shared with the listeners that use this limiter.
    #[must_use]
    pub fn refusal_state(&self) -> &RefusalState {
        &self.refusal
    }

    /// Consumes a token for `ip` (if present) and acquires one bounded half-open slot.
    pub fn try_acquire(&self, ip: Option<IpAddr>) -> Result<HalfOpenGuard, RuntimeError> {
        self.try_acquire_for_peer(ip, None)
    }

    /// Consumes a peer token when `peer_transport_id` is present, else an IP token, then acquires a half-open slot.
    pub fn try_acquire_for_peer(
        &self,
        ip: Option<IpAddr>,
        peer_transport_id: Option<&str>,
    ) -> Result<HalfOpenGuard, RuntimeError> {
        let key = if let Some(pid) = peer_transport_id {
            Some(HalfOpenKey::Peer(pid.to_owned()))
        } else {
            ip.map(HalfOpenKey::Ip)
        };
        self.try_acquire_slot(false, key)
    }

    /// Enforces partitioned half-open quotas and normalized per-key/unattributed buckets for `provider`.
    pub fn try_acquire_for_stream(
        &self,
        provider: ProviderId,
        ip: Option<IpAddr>,
        peer_transport_id: Option<&str>,
    ) -> Result<HalfOpenGuard, RuntimeError> {
        let is_untrusted = is_untrusted_provider(provider);
        let key = if let Some(pid) = peer_transport_id {
            Some(HalfOpenKey::Peer(pid.to_owned()))
        } else if let Some(addr) = ip {
            Some(HalfOpenKey::Ip(addr))
        } else if is_untrusted {
            Some(HalfOpenKey::Unattributed)
        } else {
            None
        };
        self.try_acquire_slot(is_untrusted, key)
    }

    /// Acquires one bounded half-open handshake slot enforcing the per-key, per-provider, and
    /// global caps for the stream's peer identity, source IP, or unattributed bucket.
    pub fn try_acquire_half_open_for_stream(
        &self,
        provider: ProviderId,
        ip: Option<IpAddr>,
        peer_transport_id: Option<&str>,
    ) -> Result<HalfOpenGuard, RuntimeError> {
        self.try_acquire_for_stream(provider, ip, peer_transport_id)
    }

    /// Acquires one bounded half-open handshake slot in the default (trusted) partition.
    pub fn try_acquire_half_open(&self) -> Result<HalfOpenGuard, RuntimeError> {
        self.try_acquire_slot(false, None)
    }

    /// Acquires one bounded half-open handshake slot partitioned by `provider`.
    pub fn try_acquire_half_open_for_provider(
        &self,
        provider: ProviderId,
    ) -> Result<HalfOpenGuard, RuntimeError> {
        self.try_acquire_slot(is_untrusted_provider(provider), None)
    }

    fn try_acquire_slot(
        &self,
        is_untrusted: bool,
        key: Option<HalfOpenKey>,
    ) -> Result<HalfOpenGuard, RuntimeError> {
        let now = Instant::now();
        match key.as_ref() {
            Some(HalfOpenKey::Peer(pid)) => self.check_peer(pid)?,
            Some(HalfOpenKey::Ip(addr)) => {
                let norm = normalize_rate_limit_ip(*addr);
                let mut ips = self
                    .inner
                    .ip_buckets
                    .lock()
                    .expect("ip buckets mutex poisoned");
                if !ips.allow(norm, now) {
                    return Err(RuntimeError::RateLimited("ip pre-auth rate limit"));
                }
            }
            Some(HalfOpenKey::Unattributed) => {
                let mut unattr = self
                    .inner
                    .unattributed_bucket
                    .lock()
                    .expect("unattributed bucket mutex poisoned");
                if !unattr.allow((), now) {
                    return Err(RuntimeError::RateLimited(
                        "unattributed pre-auth rate limit",
                    ));
                }
            }
            None => {}
        }

        let (counter, limit) = if is_untrusted {
            (
                &self.inner.untrusted_active_half_open,
                self.inner.untrusted_max_half_open,
            )
        } else {
            (&self.inner.active_half_open, self.inner.max_half_open)
        };

        loop {
            let cur = counter.load(Ordering::Acquire);
            if cur >= limit {
                return Err(RuntimeError::RateLimited("half-open handshake cap reached"));
            }
            if counter
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        let mut guard = HalfOpenGuard {
            inner: Arc::clone(&self.inner),
            is_untrusted,
            tracked_key: None,
        };

        if let Some(k) = key {
            let label = k.label();
            let mut per_key = self
                .inner
                .active_per_key
                .lock()
                .expect("active_per_key mutex poisoned");
            let count = per_key.entry(label.clone()).or_insert(0);
            if *count >= self.inner.max_half_open_per_key {
                return Err(RuntimeError::RateLimited("per-key half-open cap reached"));
            }
            *count += 1;
            guard.tracked_key = Some(label);
        }

        Ok(guard)
    }

    /// Checks and consumes one pre-auth token keyed by a peer identifier or public key.
    pub fn check_peer(&self, peer_key: &str) -> Result<(), RuntimeError> {
        let mut peers = self
            .inner
            .peer_buckets
            .lock()
            .expect("peer buckets mutex poisoned");
        if !peers.allow(peer_key.to_owned(), Instant::now()) {
            return Err(RuntimeError::RateLimited("peer pre-auth rate limit"));
        }
        Ok(())
    }

    /// Returns the number of currently active half-open pre-auth guards in the trusted partition.
    #[must_use]
    pub fn active_half_open(&self) -> usize {
        self.inner.active_half_open.load(Ordering::Acquire)
    }

    /// Returns the number of currently active half-open pre-auth guards in the untrusted partition.
    #[must_use]
    pub fn untrusted_active_half_open(&self) -> usize {
        self.inner
            .untrusted_active_half_open
            .load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod refusal_tests {
    use std::sync::atomic::AtomicBool;

    use async_trait::async_trait;

    use super::*;
    use crate::provider::{PathReader, PathWriter};

    /// A stream that never reads anything and records what the refusal sequence did to it.
    struct Idle {
        half_closed: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for Idle {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl PathStream for Idle {
        fn provider_id(&self) -> ProviderId {
            ProviderId::Direct
        }

        fn peer_ip(&self) -> Option<std::net::IpAddr> {
            None
        }

        async fn send_chunk(&mut self, _bytes: &[u8]) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn recv_chunk(&mut self, _buf: &mut [u8]) -> Result<usize, RuntimeError> {
            std::future::pending().await
        }

        async fn close(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn shutdown_write(&mut self) -> Result<(), RuntimeError> {
            self.half_closed.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
            unreachable!("a refused stream is never split")
        }
    }

    fn idle() -> (Box<dyn PathStream>, Arc<AtomicBool>, Arc<AtomicBool>) {
        let half_closed = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let stream = Box::new(Idle {
            half_closed: Arc::clone(&half_closed),
            dropped: Arc::clone(&dropped),
        });
        (stream, half_closed, dropped)
    }

    #[tokio::test]
    async fn linger_half_closes_then_drains_until_the_linger_bound() {
        let state = RefusalState::new();
        let (stream, half_closed, dropped) = idle();
        state.linger(stream);
        assert_eq!(state.drains_in_flight(), 1);
        tokio::time::sleep(REFUSAL_LINGER / 5).await;
        assert!(half_closed.load(Ordering::SeqCst), "write side half-closed");
        assert!(!dropped.load(Ordering::SeqCst), "still draining");
        tokio::time::sleep(REFUSAL_LINGER * 2).await;
        assert!(dropped.load(Ordering::SeqCst), "closed at the linger bound");
        assert_eq!(state.drains_in_flight(), 0);
    }

    #[tokio::test]
    async fn linger_past_the_drain_bound_closes_immediately() {
        let state = RefusalState::with_max_drains(1);
        let (first, _, first_dropped) = idle();
        let (second, second_half_closed, second_dropped) = idle();
        state.linger(first);
        state.linger(second);
        assert!(
            second_dropped.load(Ordering::SeqCst),
            "a refusal past the bound drops its stream at once"
        );
        assert!(!second_half_closed.load(Ordering::SeqCst));
        assert!(!first_dropped.load(Ordering::SeqCst));
        assert_eq!(state.drains_in_flight(), 1);
    }

    #[tokio::test]
    async fn shutdown_ends_a_draining_stream_promptly() {
        let state = RefusalState::new();
        let (stream, _, dropped) = idle();
        state.linger(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!dropped.load(Ordering::SeqCst));
        state.shutdown();
        tokio::time::sleep(REFUSAL_LINGER / 5).await;
        assert!(
            dropped.load(Ordering::SeqCst),
            "closed by shutdown, not the bound"
        );
        assert_eq!(state.drains_in_flight(), 0);
        let (late, _, late_dropped) = idle();
        state.linger(late);
        assert!(
            late_dropped.load(Ordering::SeqCst),
            "no drain after shutdown"
        );
    }

    #[test]
    fn linger_outside_a_runtime_drops_the_stream() {
        let state = RefusalState::new();
        let (stream, _, dropped) = idle();
        state.linger(stream);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn record_reaches_the_audit_sink() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let state = RefusalState::with_audit_sink(move |ev| sink.lock().unwrap().push(ev.clone()));
        state.record("dev-a", 4004);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            [RefusalAudit {
                peer_id: "dev-a".into(),
                code: 4004
            }]
        );
    }
}
