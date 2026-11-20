//! Pre-authentication LRU token buckets and bounded half-open handshake guard.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tendril_core::policy::ProviderId;
use tendril_relay::normalize_rate_limit_ip;

use crate::error::RuntimeError;

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

/// Thread-safe pre-authentication rate limiter guarding listener `accept` paths.
#[derive(Debug, Clone)]
pub struct PreAuthRateLimiter {
    inner: Arc<PreAuthInner>,
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
