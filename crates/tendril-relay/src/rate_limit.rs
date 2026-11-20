//! LRU-bounded per-IP token bucket for stateless relay abuse defense.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seq: u64,
}

/// Bounded LRU token bucket table keyed by remote IP address.
#[derive(Debug)]
pub struct IpTokenLimiter {
    max_entries: usize,
    capacity: f64,
    refill_per_sec: f64,
    next_seq: u64,
    buckets: HashMap<IpAddr, Bucket>,
    order: BTreeMap<(u64, IpAddr), ()>,
}

impl IpTokenLimiter {
    /// Constructs a new bounded limiter.
    #[must_use]
    pub fn new(max_entries: usize, capacity: u32, refill_per_sec: u32) -> Self {
        Self {
            max_entries: max_entries.max(1),
            capacity: f64::from(capacity.max(1)),
            refill_per_sec: f64::from(refill_per_sec.max(1)),
            next_seq: 0,
            buckets: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    /// Consumes one token for `ip` at `now`, returning `true` when permitted.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;

        if let Some(bucket) = self.buckets.get_mut(&ip) {
            self.order.remove(&(bucket.last_seq, ip));
            let elapsed = now
                .saturating_duration_since(bucket.last_refill)
                .as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            bucket.last_refill = now;
            bucket.last_seq = seq;
            self.order.insert((seq, ip), ());
            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return true;
            }
            return false;
        }

        while self.buckets.len() >= self.max_entries {
            if let Some(((oldest_seq, oldest_ip), _)) = self.order.pop_first() {
                let _ = oldest_seq;
                self.buckets.remove(&oldest_ip);
            } else {
                break;
            }
        }

        self.buckets.insert(
            ip,
            Bucket {
                tokens: self.capacity - 1.0,
                last_refill: now,
                last_seq: seq,
            },
        );
        self.order.insert((seq, ip), ());
        true
    }
}
