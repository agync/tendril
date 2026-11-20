//! LRU-bounded per-IP token bucket for stateless relay abuse defense.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

/// Canonicalizes an IP address for rate-limiting keys (unwraps IPv4-mapped IPv6 addresses
/// and masks IPv6 addresses to `/64` prefixes so single-allocation `/64` rotations share a bucket).
#[must_use]
pub fn normalize_rate_limit_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return IpAddr::V4(mapped);
            }
            let seg = v6.segments();
            IpAddr::V6(Ipv6Addr::new(seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0))
        }
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seq: u64,
}

/// Bounded LRU token bucket table keyed by normalized remote IP/prefix.
#[derive(Debug)]
pub struct IpTokenLimiter {
    max_entries: usize,
    capacity: f64,
    refill_per_sec: f64,
    next_seq: u64,
    buckets: HashMap<IpAddr, Bucket>,
    order: BTreeMap<(u64, IpAddr), ()>,
    eviction_overflow: Bucket,
}

impl IpTokenLimiter {
    /// Constructs a new bounded limiter.
    #[must_use]
    pub fn new(max_entries: usize, capacity: u32, refill_per_sec: u32) -> Self {
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

    /// Consumes one token for `ip` (normalized to IPv4 or IPv6 `/64`) at `now`, returning `true`
    /// when permitted.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let key = normalize_rate_limit_ip(ip);
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;

        if let Some(bucket) = self.buckets.get_mut(&key) {
            self.order.remove(&(bucket.last_seq, key));
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
            if let Some((_, oldest_ip)) = self.order.pop_first().map(|(k, _)| k) {
                self.buckets.remove(&oldest_ip);
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
            key,
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
