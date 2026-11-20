//! Pre-authentication LRU token buckets and bounded half-open handshake guard.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::error::RuntimeError;

/// Configuration bounds for [`PreAuthRateLimiter`].
#[derive(Debug, Clone)]
pub struct PreAuthConfig {
    pub max_entries: usize,
    pub max_half_open: usize,
    pub ip_burst: u32,
    pub ip_refill_per_sec: u32,
    pub peer_burst: u32,
    pub peer_refill_per_sec: u32,
}

impl Default for PreAuthConfig {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_half_open: 32,
            ip_burst: 24,
            ip_refill_per_sec: 8,
            peer_burst: 16,
            peer_refill_per_sec: 4,
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
}

impl<K: Eq + Hash + Clone + Ord> LruBuckets<K> {
    fn new(max_entries: usize, capacity: u32, refill_per_sec: u32) -> Self {
        Self {
            max_entries: max_entries.max(1),
            capacity: f64::from(capacity.max(1)),
            refill_per_sec: f64::from(refill_per_sec.max(1)),
            next_seq: 0,
            buckets: HashMap::new(),
            order: BTreeMap::new(),
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

        while self.buckets.len() >= self.max_entries {
            if let Some(((_, oldest_key), _)) = self.order.pop_first() {
                self.buckets.remove(&oldest_key);
            } else {
                break;
            }
        }

        self.buckets.insert(
            key.clone(),
            Bucket {
                tokens: self.capacity - 1.0,
                last_refill: now,
                last_seq: seq,
            },
        );
        self.order.insert((seq, key), ());
        true
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
    active_half_open: AtomicUsize,
    ip_buckets: Mutex<LruBuckets<IpAddr>>,
    peer_buckets: Mutex<LruBuckets<String>>,
}

/// RAII token holding one half-open pre-authentication handshake slot.
#[derive(Debug)]
pub struct HalfOpenGuard {
    inner: Arc<PreAuthInner>,
}

impl Drop for HalfOpenGuard {
    fn drop(&mut self) {
        self.inner.active_half_open.fetch_sub(1, Ordering::AcqRel);
    }
}

impl PreAuthRateLimiter {
    /// Creates a new pre-authentication rate limiter with `config`.
    #[must_use]
    pub fn new(config: PreAuthConfig) -> Self {
        Self {
            inner: Arc::new(PreAuthInner {
                max_half_open: config.max_half_open.max(1),
                active_half_open: AtomicUsize::new(0),
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
        if let Some(pid) = peer_transport_id {
            self.check_peer(pid)?;
        } else if let Some(addr) = ip {
            let mut ips = self
                .inner
                .ip_buckets
                .lock()
                .expect("ip buckets mutex poisoned");
            if !ips.allow(addr, Instant::now()) {
                return Err(RuntimeError::RateLimited("ip pre-auth rate limit"));
            }
        }

        self.try_acquire_half_open()
    }

    /// Acquires one bounded half-open handshake slot without consuming IP or peer rate tokens.
    pub fn try_acquire_half_open(&self) -> Result<HalfOpenGuard, RuntimeError> {
        loop {
            let cur = self.inner.active_half_open.load(Ordering::Acquire);
            if cur >= self.inner.max_half_open {
                return Err(RuntimeError::RateLimited("half-open handshake cap reached"));
            }
            if self
                .inner
                .active_half_open
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(HalfOpenGuard {
                    inner: Arc::clone(&self.inner),
                });
            }
        }
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

    /// Returns the number of currently active half-open pre-auth guards.
    #[must_use]
    pub fn active_half_open(&self) -> usize {
        self.inner.active_half_open.load(Ordering::Acquire)
    }
}
