//! Deterministic path ranking, Happy Eyeballs dialing, no-flap pinning, and failover policy.

use core::net::{IpAddr, SocketAddr};
use std::collections::{BTreeSet, VecDeque};

/// Transport rung identifier ordered from lowest latency/trust-dependency to fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderId {
    Local = 0,
    Direct = 1,
    Overlay = 2,
    P2p = 3,
    Relay = 4,
    Broker = 5,
}

impl ProviderId {
    /// Returns the numeric priority rank (`0` = highest preference).
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

/// Candidate dial endpoint evaluated by [`PathPlanner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateEndpoint {
    pub id: usize,
    pub provider: ProviderId,
    pub addr: String,
    pub is_numeric_host: bool,
}

impl CandidateEndpoint {
    /// Creates a candidate endpoint, inferring [`Self::is_numeric_host`] cleanly from `addr`.
    #[must_use]
    pub fn new(id: usize, provider: ProviderId, addr: impl Into<String>) -> Self {
        let addr = addr.into();
        let is_numeric_host = is_numeric_host_addr(&addr);
        Self {
            id,
            provider,
            addr,
            is_numeric_host,
        }
    }
}

/// Reports whether `addr` targets a literal IP address rather than a hostname needing DNS lookup.
#[must_use]
pub fn is_numeric_host_addr(addr: &str) -> bool {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return false;
    }
    let after_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return false;
    }
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = &authority[1..end];
            let suffix = &authority[end + 1..];
            let valid_suffix = suffix.is_empty()
                || (suffix.starts_with(':')
                    && suffix.len() > 1
                    && suffix[1..].bytes().all(|b| b.is_ascii_digit()));
            return valid_suffix && host.parse::<IpAddr>().is_ok();
        }
        return false;
    }
    if authority.parse::<IpAddr>().is_ok() || authority.parse::<SocketAddr>().is_ok() {
        return true;
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return host.parse::<IpAddr>().is_ok();
    }
    false
}

/// Timing constants controlling Happy Eyeballs dial stagger, fall-up probes, and pin dwell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPolicyConfig {
    pub happy_eyeballs_stagger_ms: u64,
    pub fall_up_probe_interval_ms: u64,
    pub min_pin_dwell_ms: u64,
    pub p2p_cold_delay_ms: u64,
}

impl Default for PathPolicyConfig {
    fn default() -> Self {
        Self {
            happy_eyeballs_stagger_ms: 250,
            fall_up_probe_interval_ms: 30_000,
            min_pin_dwell_ms: 10_000,
            p2p_cold_delay_ms: 500,
        }
    }
}

/// Actions emitted by [`PathPlanner`] for the runtime transport driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannerAction {
    DialCandidate(CandidateEndpoint),
    CancelCandidate(usize),
    ActivatePath(CandidateEndpoint),
    ProbeBetterPath(CandidateEndpoint),
    CloseActivePath { id: usize, reason: String },
    AllCandidatesExhausted,
}

/// Pure Sans-I/O connection path planner implementing Happy Eyeballs, no-flap pin, and fall-up.
#[derive(Debug)]
pub struct PathPlanner {
    config: PathPolicyConfig,
    candidates: Vec<CandidateEndpoint>,
    next_dial_idx: usize,
    next_dial_ready_ms: Option<u64>,
    first_non_p2p_start_ms: Option<u64>,
    in_flight: BTreeSet<usize>,
    failed: BTreeSet<usize>,
    active: Option<CandidateEndpoint>,
    pin_since_ms: u64,
    last_fall_up_probe_ms: u64,
    started: bool,
    pending: VecDeque<PlannerAction>,
}

impl PathPlanner {
    /// Constructs a planner, sorting `candidates` by `(provider.rank(), !is_numeric_host, id)`.
    #[must_use]
    pub fn new(config: PathPolicyConfig, mut candidates: Vec<CandidateEndpoint>) -> Self {
        candidates.sort_by_key(|c| (c.provider.rank(), !c.is_numeric_host, c.id));
        Self {
            config,
            candidates,
            next_dial_idx: 0,
            next_dial_ready_ms: None,
            first_non_p2p_start_ms: None,
            in_flight: BTreeSet::new(),
            failed: BTreeSet::new(),
            active: None,
            pin_since_ms: 0,
            last_fall_up_probe_ms: 0,
            started: false,
            pending: VecDeque::new(),
        }
    }

    /// Returns the sorted candidate slice.
    #[must_use]
    pub fn candidates(&self) -> &[CandidateEndpoint] {
        &self.candidates
    }

    /// Returns the currently pinned active endpoint, if any.
    #[must_use]
    pub const fn active_candidate(&self) -> Option<&CandidateEndpoint> {
        self.active.as_ref()
    }

    /// Begins dialing the highest-priority candidate at `now_ms`.
    pub fn start(&mut self, now_ms: u64) {
        self.started = true;
        self.next_dial_idx = 0;
        self.next_dial_ready_ms = Some(now_ms);
        self.tick(now_ms);
    }

    /// Advances timers for Happy Eyeballs stagger or fall-up probing against a lower-ranked path.
    pub fn tick(&mut self, now_ms: u64) {
        if !self.started {
            return;
        }
        if self.candidates.is_empty() {
            if self.active.is_none() {
                self.pending
                    .push_back(PlannerAction::AllCandidatesExhausted);
            }
            return;
        }

        if let Some(active) = &self.active {
            let active_rank = sort_key(active);
            if now_ms.saturating_sub(self.pin_since_ms) >= self.config.min_pin_dwell_ms
                && now_ms.saturating_sub(self.last_fall_up_probe_ms)
                    >= self.config.fall_up_probe_interval_ms
            {
                let mut launched = false;
                for cand in &self.candidates {
                    if sort_key(cand) < active_rank && !self.in_flight.contains(&cand.id) {
                        self.in_flight.insert(cand.id);
                        self.pending
                            .push_back(PlannerAction::ProbeBetterPath(cand.clone()));
                        launched = true;
                        break;
                    }
                }
                if launched {
                    self.last_fall_up_probe_ms = now_ms;
                }
            }
            return;
        }

        self.advance_dial_wave(now_ms);
    }

    /// Notifies the planner that dialing `id` succeeded at `now_ms`.
    pub fn on_dial_succeeded(&mut self, id: usize, now_ms: u64) {
        self.in_flight.remove(&id);
        self.failed.remove(&id);
        let Some(cand) = self.candidates.iter().find(|c| c.id == id).cloned() else {
            return;
        };

        if let Some(cur) = self.active.clone() {
            if cand.id == cur.id {
                return;
            }
            let better = sort_key(&cand) < sort_key(&cur);
            let dwell_ok = now_ms.saturating_sub(self.pin_since_ms) >= self.config.min_pin_dwell_ms;
            if better && dwell_ok {
                self.cancel_other_in_flight(id);
                self.pending.push_back(PlannerAction::CloseActivePath {
                    id: cur.id,
                    reason: "fall-up to higher-priority path".to_string(),
                });
                self.active = Some(cand.clone());
                self.pin_since_ms = now_ms;
                self.last_fall_up_probe_ms = now_ms;
                self.pending.push_back(PlannerAction::ActivatePath(cand));
            } else {
                self.pending.push_back(PlannerAction::CancelCandidate(id));
            }
            return;
        }

        self.cancel_other_in_flight(id);
        self.active = Some(cand.clone());
        self.pin_since_ms = now_ms;
        self.last_fall_up_probe_ms = now_ms;
        self.pending.push_back(PlannerAction::ActivatePath(cand));
    }

    /// Notifies the planner that dialing `id` failed, accelerating the next candidate when idle.
    pub fn on_dial_failed(&mut self, id: usize, _reason: &str, now_ms: u64) {
        self.in_flight.remove(&id);
        if self.active.is_some() {
            return;
        }
        self.failed.insert(id);
        if self.in_flight.is_empty() {
            self.next_dial_ready_ms = Some(now_ms);
            self.advance_dial_wave(now_ms);
        }
    }

    /// Handles a fault on the active path (`close-on-fault`), tearing it down and starting failover.
    pub fn on_active_fault(&mut self, id: usize, reason: &str, now_ms: u64) {
        let Some(cur) = &self.active else {
            return;
        };
        if cur.id != id {
            return;
        }
        self.active = None;
        self.failed.insert(id);
        self.pending.push_back(PlannerAction::CloseActivePath {
            id,
            reason: reason.to_string(),
        });
        self.next_dial_idx = 0;
        self.next_dial_ready_ms = Some(now_ms);
        self.first_non_p2p_start_ms = None;
        self.advance_dial_wave(now_ms);
    }

    /// Drains all queued planner actions in FIFO order.
    pub fn drain_actions(&mut self) -> Vec<PlannerAction> {
        self.pending.drain(..).collect()
    }

    fn advance_dial_wave(&mut self, now_ms: u64) {
        while self.next_dial_idx < self.candidates.len() {
            let cand = self.candidates[self.next_dial_idx].clone();
            if self.failed.contains(&cand.id) || self.in_flight.contains(&cand.id) {
                self.next_dial_idx += 1;
                continue;
            }
            if cand.provider == ProviderId::P2p
                && let Some(first_ms) = self.first_non_p2p_start_ms
            {
                let p2p_ready = first_ms.saturating_add(self.config.p2p_cold_delay_ms);
                if now_ms < p2p_ready {
                    self.next_dial_ready_ms = Some(p2p_ready);
                    return;
                }
            }
            let Some(ready_ms) = self.next_dial_ready_ms else {
                return;
            };
            if now_ms < ready_ms {
                return;
            }
            if cand.provider != ProviderId::P2p && self.first_non_p2p_start_ms.is_none() {
                self.first_non_p2p_start_ms = Some(now_ms);
            }
            self.in_flight.insert(cand.id);
            self.next_dial_idx += 1;
            self.next_dial_ready_ms =
                Some(now_ms.saturating_add(self.config.happy_eyeballs_stagger_ms));
            self.pending.push_back(PlannerAction::DialCandidate(cand));
            return;
        }

        if self.in_flight.is_empty() && self.active.is_none() {
            self.pending
                .push_back(PlannerAction::AllCandidatesExhausted);
        }
    }

    fn cancel_other_in_flight(&mut self, winner_id: usize) {
        let to_cancel: Vec<usize> = self
            .in_flight
            .iter()
            .copied()
            .filter(|id| *id != winner_id)
            .collect();
        for other in to_cancel {
            self.in_flight.remove(&other);
            self.pending
                .push_back(PlannerAction::CancelCandidate(other));
        }
    }
}

fn sort_key(c: &CandidateEndpoint) -> (u8, bool, usize) {
    (c.provider.rank(), !c.is_numeric_host, c.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_by_provider_rung_then_numeric_host_priority() {
        let cands = vec![
            CandidateEndpoint::new(1, ProviderId::Relay, "wss://relay.example/v1/relay"),
            CandidateEndpoint::new(2, ProviderId::Direct, "host.local:7000"),
            CandidateEndpoint::new(3, ProviderId::Direct, "192.168.1.20:7000"),
            CandidateEndpoint::new(4, ProviderId::Direct, "[fe80::1]:7000"),
            CandidateEndpoint::new(5, ProviderId::Local, "/run/tendril.sock"),
        ];
        let planner = PathPlanner::new(PathPolicyConfig::default(), cands);
        let ids: Vec<usize> = planner.candidates().iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![5, 3, 4, 2, 1]);
        assert!(!is_numeric_host_addr("[::1]garbage"));
        assert!(!is_numeric_host_addr("[::1]:abc"));
        assert!(is_numeric_host_addr("[::1]:7000"));
        assert!(is_numeric_host_addr("[::1]"));
    }

    #[test]
    fn stagger_p2p_cold_delay_pin_dwell_fall_up_and_close_on_fault() {
        let cands = vec![
            CandidateEndpoint::new(1, ProviderId::Direct, "192.168.1.10:7000"),
            CandidateEndpoint::new(2, ProviderId::P2p, "node-p2p"),
            CandidateEndpoint::new(3, ProviderId::Relay, "wss://198.51.100.10/v1/relay"),
        ];
        let mut planner = PathPlanner::new(PathPolicyConfig::default(), cands);
        planner.start(0);
        let a0 = planner.drain_actions();
        assert!(matches!(&a0[..], [PlannerAction::DialCandidate(c)] if c.id == 1));

        // Direct fails at t = 100 -> advances to P2p which honors 500ms cold delay from t = 0.
        planner.on_dial_failed(1, "refused", 100);
        assert!(planner.drain_actions().is_empty());

        planner.tick(500);
        let a_p2p = planner.drain_actions();
        assert!(matches!(&a_p2p[..], [PlannerAction::DialCandidate(c)] if c.id == 2));

        // P2p fails at t = 550 -> immediately dials Relay.
        planner.on_dial_failed(2, "timeout", 550);
        let a_rel = planner.drain_actions();
        assert!(matches!(&a_rel[..], [PlannerAction::DialCandidate(c)] if c.id == 3));

        planner.on_dial_succeeded(3, 600);
        let act_rel = planner.drain_actions();
        assert!(matches!(&act_rel[..], [PlannerAction::ActivatePath(c)] if c.id == 3));
        assert_eq!(planner.active_candidate().unwrap().id, 3);

        // Before min_pin_dwell_ms (10_000 ms), no fall-up probes start.
        planner.tick(9_000);
        assert!(planner.drain_actions().is_empty());

        // After fall_up_probe_interval_ms (30_000 ms), probes highest-priority Direct candidate.
        planner.tick(31_000);
        let probe = planner.drain_actions();
        assert!(matches!(&probe[..], [PlannerAction::ProbeBetterPath(c)] if c.id == 1));

        // Direct probe succeeds -> closes Relay and switches active path to Direct.
        planner.on_dial_succeeded(1, 31_050);
        let switch = planner.drain_actions();
        assert!(matches!(
            &switch[..],
            [
                PlannerAction::CloseActivePath { id: 3, .. },
                PlannerAction::ActivatePath(c)
            ] if c.id == 1
        ));
        assert_eq!(planner.active_candidate().unwrap().id, 1);

        // Fault on active Direct closes Direct and fails over to Relay (skipping failed P2p/Direct).
        planner.on_active_fault(1, "eof", 32_000);
        let failover = planner.drain_actions();
        assert!(matches!(
            &failover[..],
            [
                PlannerAction::CloseActivePath { id: 1, .. },
                PlannerAction::DialCandidate(c)
            ] if c.id == 3
        ));
    }
}
