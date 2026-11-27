//! Building blocks for authenticated refusal of a known but revoked or pending peer.
//!
//! These types are pure and Sans-I/O: the caller passes the current time in Unix seconds.
//! They bound what an unauthenticated flood of refusal-eligible attempts can cost a
//! responder (`spec/wire-v1.md` Section 5.4.2, `spec/wire-v2.md` Section 3.1.3.2).
//!
//! A responder decision runs in a fixed order so a replayed or over-capacity attempt never
//! charges the limiter: read-only cache check ([`RefusalReplayCache::can_accept`]), then
//! [`RefusalLimiter::allow`], then [`RefusalReplayCache::insert`].

use std::collections::{BTreeMap, BTreeSet};

use crate::v2::V2_RENDEZVOUS_MAX_SKEW_SECS;

/// Minimum spacing between two refusals sent to one peer `device_id`, in seconds.
pub const REFUSAL_LIMIT_WINDOW_SECS: u64 = 10;

/// Maximum peers a [`RefusalLimiter`] tracks; the least recently used peer is evicted first.
pub const MAX_REFUSAL_LIMITER_PEERS: usize = 256;

/// Maximum live nonces a [`RefusalReplayCache`] holds.
pub const MAX_REFUSAL_REPLAY_ENTRIES: usize = 256;

/// Whether a responder may send a refusal to a known revoked or pending peer.
///
/// This is a construction parameter of the accept path, never roster content
/// (`spec/wire-v1.md` Section 5.4.3). There is deliberately no `Default`: group listeners
/// must choose [`RefusalMode::Off`] explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalMode {
    /// An ordinary session listener: refusals may be sent.
    Enabled,
    /// A group listener, pool or mailbox: refusals are never sent.
    Off,
}

impl RefusalMode {
    /// Returns `true` when refusals may be sent.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Debug, Clone, Copy)]
struct LimiterSlot {
    last_allowed: u64,
    tick: u64,
}

/// Per-peer refusal limiter: at most one refusal per peer per [`REFUSAL_LIMIT_WINDOW_SECS`].
///
/// Tracks at most [`MAX_REFUSAL_LIMITER_PEERS`] peers and evicts the least recently used.
/// Any call to [`RefusalLimiter::allow`] for a tracked peer, allowed or not, counts as use.
/// A denial does not extend the window.
#[derive(Debug, Default)]
pub struct RefusalLimiter {
    slots: BTreeMap<String, LimiterSlot>,
    clock: u64,
}

impl RefusalLimiter {
    /// Creates an empty limiter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of tracked peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Returns `true` when no peer is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Returns `true` and records the refusal when `peer` may be refused at `now_unix`.
    ///
    /// A clock that moved backwards relative to the last refusal counts as an elapsed
    /// window, so a clock step cannot silence a peer for long.
    pub fn allow(&mut self, peer: &str, now_unix: u64) -> bool {
        self.clock = self.clock.wrapping_add(1);
        let tick = self.clock;
        if let Some(slot) = self.slots.get_mut(peer) {
            slot.tick = tick;
            let elapsed = now_unix
                .checked_sub(slot.last_allowed)
                .is_none_or(|d| d >= REFUSAL_LIMIT_WINDOW_SECS);
            if elapsed {
                slot.last_allowed = now_unix;
            }
            return elapsed;
        }
        if self.slots.len() >= MAX_REFUSAL_LIMITER_PEERS {
            let lru = self
                .slots
                .iter()
                .min_by_key(|(_, slot)| slot.tick)
                .map(|(peer, _)| peer.clone());
            if let Some(lru) = lru {
                self.slots.remove(&lru);
            }
        }
        self.slots.insert(
            peer.to_owned(),
            LimiterSlot {
                last_allowed: now_unix,
                tick,
            },
        );
        true
    }
}

/// Bounded replay cache for `rendezvous_nonce` values of refused `msg1` attempts.
///
/// Separate from the shared genuine replay cache so refusals never consume its capacity
/// (`spec/wire-v2.md` Section 3.1.3.2). Entries stay live for the `msg1` skew window
/// ([`V2_RENDEZVOUS_MAX_SKEW_SECS`]). [`contains`](Self::contains) and
/// [`can_accept`](Self::can_accept) are read-only; only [`insert`](Self::insert) mutates, and
/// it fails closed rather than evicting a live entry.
#[derive(Debug, Default)]
pub struct RefusalReplayCache {
    seen: BTreeSet<[u8; 16]>,
    by_expiry: BTreeSet<(u64, [u8; 16])>,
}

impl RefusalReplayCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of stored entries, including expired ones not yet pruned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_expiry.len()
    }

    /// Returns `true` when no entry is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_expiry.is_empty()
    }

    fn cutoff(now_unix: u64) -> u64 {
        now_unix.saturating_sub(V2_RENDEZVOUS_MAX_SKEW_SECS)
    }

    fn live_len(&self, now_unix: u64) -> usize {
        self.by_expiry
            .range((Self::cutoff(now_unix), [0u8; 16])..)
            .count()
    }

    /// Returns `true` when `nonce` is stored and still live at `now_unix`. Read-only.
    #[must_use]
    pub fn contains(&self, nonce: &[u8; 16], now_unix: u64) -> bool {
        let cutoff = Self::cutoff(now_unix);
        self.seen.contains(nonce)
            && self
                .by_expiry
                .range((cutoff, [0u8; 16])..)
                .any(|(_, n)| n == nonce)
    }

    /// Returns `true` when `nonce` is not live and a live slot is free. Read-only.
    #[must_use]
    pub fn can_accept(&self, nonce: &[u8; 16], now_unix: u64) -> bool {
        !self.contains(nonce, now_unix) && self.live_len(now_unix) < MAX_REFUSAL_REPLAY_ENTRIES
    }

    /// Records `nonce` with its `msg1` timestamp `ts_unix`.
    ///
    /// Prunes expired entries first. Returns `false` and changes nothing further when the
    /// nonce is already live or the cache holds [`MAX_REFUSAL_REPLAY_ENTRIES`] live entries.
    pub fn insert(&mut self, nonce: [u8; 16], ts_unix: u64, now_unix: u64) -> bool {
        let cutoff = Self::cutoff(now_unix);
        while let Some(&(ts, old)) = self.by_expiry.first() {
            if ts >= cutoff {
                break;
            }
            self.by_expiry.pop_first();
            self.seen.remove(&old);
        }
        if self.seen.contains(&nonce) || self.by_expiry.len() >= MAX_REFUSAL_REPLAY_ENTRIES {
            return false;
        }
        self.seen.insert(nonce);
        self.by_expiry.insert((ts_unix, nonce));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE_A: [u8; 16] = [0xA1; 16];

    fn nonce(n: u16) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..2].copy_from_slice(&n.to_be_bytes());
        out
    }

    #[test]
    fn limiter_allows_first_then_denies_inside_window() {
        let mut l = RefusalLimiter::new();
        assert!(l.allow("peer-a", 1_000));
        assert!(!l.allow("peer-a", 1_000));
        assert!(!l.allow("peer-a", 1_009));
        assert!(l.allow("peer-a", 1_010));
        assert!(!l.allow("peer-a", 1_019));
        assert!(l.allow("peer-a", 1_020));
    }

    #[test]
    fn limiter_denial_does_not_extend_window() {
        let mut l = RefusalLimiter::new();
        assert!(l.allow("p", 100));
        for t in 101..110 {
            assert!(!l.allow("p", t));
        }
        assert!(l.allow("p", 110));
    }

    #[test]
    fn limiter_tracks_peers_independently() {
        let mut l = RefusalLimiter::new();
        assert!(l.allow("a", 50));
        assert!(l.allow("b", 50));
        assert!(!l.allow("a", 51));
        assert!(!l.allow("b", 51));
    }

    #[test]
    fn limiter_backwards_clock_allows_and_resets() {
        let mut l = RefusalLimiter::new();
        assert!(l.allow("p", 5_000));
        assert!(l.allow("p", 4_000));
        assert!(!l.allow("p", 4_005));
    }

    #[test]
    fn limiter_capacity_is_bounded_and_evicts_lru() {
        let mut l = RefusalLimiter::new();
        for i in 0..MAX_REFUSAL_LIMITER_PEERS {
            assert!(l.allow(&format!("p{i}"), 100));
        }
        assert_eq!(l.len(), MAX_REFUSAL_LIMITER_PEERS);
        // Touch p0 (denied, still inside window) so p1 becomes least recently used.
        assert!(!l.allow("p0", 101));
        assert!(l.allow("new", 102));
        assert_eq!(l.len(), MAX_REFUSAL_LIMITER_PEERS);
        // p0 survived and is still limited; p1 was evicted and is allowed again.
        assert!(!l.allow("p0", 103));
        assert!(l.allow("p1", 103));
        assert_eq!(l.len(), MAX_REFUSAL_LIMITER_PEERS);
    }

    #[test]
    fn limiter_new_is_empty() {
        let l = RefusalLimiter::new();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
    }

    #[test]
    fn replay_cache_insert_then_contains() {
        let mut c = RefusalReplayCache::new();
        assert!(c.is_empty());
        assert!(!c.contains(&NONCE_A, 1_000));
        assert!(c.can_accept(&NONCE_A, 1_000));
        assert!(c.insert(NONCE_A, 1_000, 1_000));
        assert_eq!(c.len(), 1);
        assert!(c.contains(&NONCE_A, 1_000));
        assert!(!c.can_accept(&NONCE_A, 1_000));
        assert!(!c.insert(NONCE_A, 1_000, 1_000));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn replay_cache_checks_do_not_mutate() {
        let mut c = RefusalReplayCache::new();
        assert!(c.insert(NONCE_A, 1_000, 1_000));
        let before = c.len();
        // Far in the future the entry is expired: read-only checks must not prune it.
        assert!(!c.contains(&NONCE_A, 10_000));
        assert!(c.can_accept(&NONCE_A, 10_000));
        assert_eq!(c.len(), before);
    }

    #[test]
    fn replay_cache_expiry_boundary() {
        let mut c = RefusalReplayCache::new();
        assert!(c.insert(NONCE_A, 1_000, 1_000));
        // Live while ts >= now - 300.
        assert!(c.contains(&NONCE_A, 1_300));
        assert!(!c.contains(&NONCE_A, 1_301));
        assert!(!c.can_accept(&NONCE_A, 1_300));
        assert!(c.can_accept(&NONCE_A, 1_301));
    }

    #[test]
    fn replay_cache_insert_prunes_expired_and_reuses_nonce() {
        let mut c = RefusalReplayCache::new();
        assert!(c.insert(NONCE_A, 1_000, 1_000));
        assert!(c.insert(nonce(1), 1_400, 1_400));
        assert_eq!(c.len(), 1);
        assert!(c.insert(NONCE_A, 1_400, 1_400));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn replay_cache_full_rejects_without_mutating() {
        let mut c = RefusalReplayCache::new();
        for i in 0..MAX_REFUSAL_REPLAY_ENTRIES {
            assert!(c.insert(nonce(i as u16), 1_000, 1_000));
        }
        assert_eq!(c.len(), MAX_REFUSAL_REPLAY_ENTRIES);
        let extra = nonce(60_000);
        assert!(!c.can_accept(&extra, 1_000));
        assert!(!c.insert(extra, 1_000, 1_000));
        assert_eq!(c.len(), MAX_REFUSAL_REPLAY_ENTRIES);
        assert!(!c.contains(&extra, 1_000));
        // Live entries are never evicted to make room.
        assert!(c.contains(&nonce(0), 1_000));
    }

    #[test]
    fn replay_cache_full_of_expired_accepts_again() {
        let mut c = RefusalReplayCache::new();
        for i in 0..MAX_REFUSAL_REPLAY_ENTRIES {
            assert!(c.insert(nonce(i as u16), 1_000, 1_000));
        }
        let extra = nonce(60_000);
        assert!(!c.can_accept(&extra, 1_300));
        assert!(c.can_accept(&extra, 1_301));
        assert!(c.insert(extra, 1_301, 1_301));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn replay_cache_check_limiter_insert_order_does_not_charge_on_replay() {
        let mut cache = RefusalReplayCache::new();
        let mut limiter = RefusalLimiter::new();
        let admit = |cache: &mut RefusalReplayCache, limiter: &mut RefusalLimiter, n, t| {
            cache.can_accept(&n, t) && limiter.allow("peer", t) && cache.insert(n, t, t)
        };
        assert!(admit(&mut cache, &mut limiter, NONCE_A, 1_000));
        // Replay fails at the read-only check, so the limiter window is not renewed.
        // At the window boundary a limiter-first order would renew the window to 1010.
        assert!(!admit(&mut cache, &mut limiter, NONCE_A, 1_010));
        // A new nonce at 1015 is admitted only if the replay did not charge the limiter.
        assert!(admit(&mut cache, &mut limiter, nonce(2), 1_015));
    }

    #[test]
    fn mode_reports_enabled() {
        assert!(RefusalMode::Enabled.is_enabled());
        assert!(!RefusalMode::Off.is_enabled());
    }
}
