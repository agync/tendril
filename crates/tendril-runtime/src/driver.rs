//! Async drivers binding `tendril-core` pairing, session, and path planning state machines
//! to concrete [`PathStream`] and [`PathDialer`] transports.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tendril_core::error::CoreError;
use tendril_core::grants::{AuditEvent, Grant, RevocationList};
use tendril_core::identity::{EndpointIdentity, RotationRecord};
use tendril_core::pairing::{
    PairAction, PairOutcome, PairingInitiator, PairingManager, PairingPathKind, PairingResponder,
    PinnedHost,
};
use tendril_core::policy::{
    CandidateEndpoint, PathPlanner, PathPolicyConfig, PlannerAction, ProviderId,
};
use tendril_core::roster::Roster;
use tendril_core::session::{RekeyDirection, SessionAction, SessionMachine};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio::time::{Instant as TokioInstant, sleep, timeout, timeout_at};

use crate::error::RuntimeError;
use crate::provider::{MAX_OUTER_FRAME_LEN, PathDialer, PathStream};
use crate::rate_limit::{HalfOpenGuard, PreAuthRateLimiter};

/// Default pre-authentication handshake deadline guarding responder paths (`10 s`).
pub const DEFAULT_PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Maps an inbound [`ProviderId`] to its spec-mandated [`PairingPathKind`] policy.
#[must_use]
pub const fn pairing_path_kind_for_provider(provider: ProviderId) -> PairingPathKind {
    match provider {
        ProviderId::Local | ProviderId::Direct => PairingPathKind::Lan,
        ProviderId::Overlay | ProviderId::P2p | ProviderId::Relay | ProviderId::Broker => {
            PairingPathKind::Remote
        }
    }
}

/// Semantic events emitted by an established [`SessionDriver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    AppData(Vec<u8>),
    GrantUpdated(Grant),
    RevocationUpdated { issuer: String, seq: u64 },
    Rekeyed { direction: RekeyDirection },
    PongReceived(u64),
    Audit(AuditEvent),
    Closed { code: u16, reason: String },
}

/// Completed outcome from an async pairing exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairDriveResult {
    pub outcome: PairOutcome,
    pub sas: Option<String>,
}

async fn write_protocol_bytes(
    stream: &mut dyn PathStream,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
        stream.send_chunk(chunk).await?;
    }
    Ok(())
}

/// Drives a pairing initiator handshake to completion over `stream`.
pub async fn drive_pair_initiator(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    pinned_host: Option<PinnedHost>,
) -> Result<PairDriveResult, RuntimeError> {
    let mut machine =
        PairingInitiator::new(identity, device_name, device_kind, code, pinned_host, None)?;
    let mut observed_sas = None;
    let init_actions = machine.start()?;
    if let Some(outcome) = dispatch_pair_actions(stream, init_actions, &mut observed_sas).await? {
        return Ok(PairDriveResult {
            outcome,
            sas: observed_sas,
        });
    }

    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
    loop {
        let n = stream.recv_chunk(&mut buf).await?;
        if n == 0 {
            return Err(RuntimeError::Closed);
        }
        let actions = machine.feed_bytes(&buf[..n])?;
        if let Some(outcome) = dispatch_pair_actions(stream, actions, &mut observed_sas).await? {
            return Ok(PairDriveResult {
                outcome,
                sas: observed_sas,
            });
        }
    }
}

/// Drives a pairing responder handshake to completion over `stream`, updating `roster`.
pub async fn drive_pair_responder(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Mutex<PairingManager>,
    roster: &Mutex<Roster>,
    path_kind: PairingPathKind,
    now_unix: u64,
    rate_limiter: Option<&PreAuthRateLimiter>,
) -> Result<PairDriveResult, RuntimeError> {
    drive_pair_responder_with_options(
        stream,
        identity,
        manager,
        roster,
        path_kind,
        now_unix,
        rate_limiter,
        None,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
}

/// Drives a pairing responder handshake with an optional caller-held [`HalfOpenGuard`]
/// and an explicit overall pre-auth handshake deadline.
#[allow(clippy::too_many_arguments)]
pub async fn drive_pair_responder_with_options(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Mutex<PairingManager>,
    roster: &Mutex<Roster>,
    path_kind: PairingPathKind,
    now_unix: u64,
    rate_limiter: Option<&PreAuthRateLimiter>,
    existing_guard: Option<HalfOpenGuard>,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let _half_open = match existing_guard {
        Some(g) => Some(g),
        None => rate_limiter
            .map(|rl| {
                rl.try_acquire_for_peer(stream.peer_ip(), stream.peer_transport_id().as_deref())
            })
            .transpose()?,
    };
    let mut machine = PairingResponder::new(identity, path_kind, None)?;
    let mut observed_sas = None;
    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
    let deadline = TokioInstant::now() + handshake_timeout;

    loop {
        let n = match timeout_at(deadline, stream.recv_chunk(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                let _ = stream.close().await;
                return Err(RuntimeError::Timeout(
                    "pre-auth pairing handshake timed out",
                ));
            }
        };
        if n == 0 {
            return Err(RuntimeError::Closed);
        }
        let actions = {
            let mut mgr = manager.lock().expect("pairing manager mutex poisoned");
            let mut rst = roster.lock().expect("roster mutex poisoned");
            machine.feed_bytes(&buf[..n], now_unix, &mut mgr, &mut rst)?
        };
        if let Some(outcome) = dispatch_pair_actions(stream, actions, &mut observed_sas).await? {
            return Ok(PairDriveResult {
                outcome,
                sas: observed_sas,
            });
        }
    }
}

async fn dispatch_pair_actions(
    stream: &mut dyn PathStream,
    actions: Vec<PairAction>,
    observed_sas: &mut Option<String>,
) -> Result<Option<PairOutcome>, RuntimeError> {
    let mut completed = None;
    let mut should_close = false;
    for action in actions {
        match action {
            PairAction::WriteBytes(bytes) => {
                write_protocol_bytes(stream, &bytes).await?;
            }
            PairAction::SasReady { pairing_sas, .. } => {
                *observed_sas = Some(pairing_sas);
            }
            PairAction::Completed(outcome) => {
                completed = Some(outcome);
            }
            PairAction::CloseTransport(_) => {
                should_close = true;
            }
        }
    }
    if should_close {
        let _ = stream.close().await;
    }
    Ok(completed)
}

/// Async transport driver owning one authenticated [`SessionMachine`] and its [`PathStream`].
pub struct SessionDriver {
    stream: Box<dyn PathStream>,
    machine: SessionMachine,
    recv_buf: Vec<u8>,
    pending_events: VecDeque<SessionEvent>,
    started_at: Instant,
    _half_open: Option<HalfOpenGuard>,
}

enum RosterRef<'a> {
    Direct(&'a mut Roster),
    Locked(&'a Mutex<Roster>),
}

impl SessionDriver {
    /// Initiates and completes a Noise XX session handshake over `stream`.
    pub async fn connect(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        roster: &mut Roster,
        now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        let crl_seq = roster.crl(target_host_id).map(|c| c.seq);
        Self::connect_with_roster(
            stream,
            local_identity,
            target_host_id,
            initial_grant,
            crl_seq,
            RosterRef::Direct(roster),
            now_unix,
        )
        .await
    }

    /// Initiates and completes a Noise XX session handshake using a mutex-guarded roster
    /// without holding the lock across `.await`.
    pub async fn connect_locked(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        roster: &Mutex<Roster>,
        now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        let crl_seq = roster
            .lock()
            .expect("roster mutex poisoned")
            .crl(target_host_id)
            .map(|c| c.seq);
        Self::connect_with_roster(
            stream,
            local_identity,
            target_host_id,
            initial_grant,
            crl_seq,
            RosterRef::Locked(roster),
            now_unix,
        )
        .await
    }

    async fn connect_with_roster(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        crl_seq: Option<u64>,
        mut roster: RosterRef<'_>,
        now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        let mut machine = SessionMachine::new_initiator(
            local_identity,
            target_host_id,
            initial_grant,
            crl_seq,
            None,
        )?;
        let start_actions = machine.start()?;
        let mut driver = Self {
            stream,
            machine,
            recv_buf: vec![0u8; MAX_OUTER_FRAME_LEN],
            pending_events: VecDeque::new(),
            started_at: Instant::now(),
            _half_open: None,
        };
        driver.apply_actions(start_actions).await?;
        driver
            .drive_until_established(now_unix, &mut roster, None, Some(DEFAULT_PRE_AUTH_TIMEOUT))
            .await?;
        Ok(driver)
    }

    /// Accepts and authenticates an inbound Noise XX session handshake over `stream`.
    pub async fn accept(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &mut Roster,
        now_unix: u64,
        rate_limiter: Option<&PreAuthRateLimiter>,
    ) -> Result<Self, RuntimeError> {
        Self::accept_with_options(
            stream,
            local_identity,
            roster,
            now_unix,
            rate_limiter,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
    }

    /// Accepts an inbound Noise XX session handshake with an optional caller-held [`HalfOpenGuard`]
    /// and an explicit overall pre-auth handshake deadline.
    pub async fn accept_with_options(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &mut Roster,
        now_unix: u64,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        Self::accept_with_roster(
            stream,
            local_identity,
            RosterRef::Direct(roster),
            now_unix,
            rate_limiter,
            existing_guard,
            handshake_timeout,
        )
        .await
    }

    /// Accepts an inbound Noise XX session handshake using a mutex-guarded roster
    /// without holding the lock across `.await`.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_locked(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &Mutex<Roster>,
        now_unix: u64,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        Self::accept_with_roster(
            stream,
            local_identity,
            RosterRef::Locked(roster),
            now_unix,
            rate_limiter,
            existing_guard,
            handshake_timeout,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn accept_with_roster(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        mut roster: RosterRef<'_>,
        now_unix: u64,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        let half_open = match existing_guard {
            Some(g) => Some(g),
            None => rate_limiter
                .map(|rl| {
                    rl.try_acquire_for_peer(stream.peer_ip(), stream.peer_transport_id().as_deref())
                })
                .transpose()?,
        };
        let machine = SessionMachine::new_responder(local_identity, None)?;
        let mut driver = Self {
            stream,
            machine,
            recv_buf: vec![0u8; MAX_OUTER_FRAME_LEN],
            pending_events: VecDeque::new(),
            started_at: Instant::now(),
            _half_open: half_open,
        };
        driver
            .drive_until_established(now_unix, &mut roster, rate_limiter, Some(handshake_timeout))
            .await?;
        Ok(driver)
    }

    /// Sends encrypted `0x01 DATA`.
    pub async fn send_data(&mut self, payload: &[u8]) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self.machine.send_data(payload, now_ms)?;
        self.apply_actions(actions).await
    }

    /// Sends encrypted `0x02 GRANT`.
    pub async fn send_grant(&mut self, grant: &Grant) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self.machine.send_grant(grant, now_ms)?;
        self.apply_actions(actions).await
    }

    /// Sends encrypted `0x03 REVOCATION`.
    pub async fn send_revocation(&mut self, crl: &RevocationList) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self.machine.send_revocation(crl, now_ms)?;
        self.apply_actions(actions).await
    }

    /// Sends encrypted `0x04 REKEY`.
    pub async fn send_rekey(&mut self) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self.machine.send_rekey(now_ms)?;
        self.apply_actions(actions).await
    }

    /// Sends encrypted `0x05 PING`.
    pub async fn send_ping(&mut self, cookie: u64) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self.machine.send_ping(cookie, now_ms)?;
        self.apply_actions(actions).await
    }

    /// Sends encrypted `0x07 CLOSE` and closes the underlying transport stream.
    pub async fn send_close(&mut self, code: u16, reason: &str) -> Result<(), RuntimeError> {
        let actions = self.machine.send_close(code, reason)?;
        self.apply_actions(actions).await?;
        let _ = self.stream.close().await;
        Ok(())
    }

    /// Advances rekey/grant expiration checks against `roster`.
    pub async fn tick(&mut self, now_unix: u64, roster: &Roster) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        match self.machine.tick(now_unix, now_ms, roster) {
            Ok(actions) => self.apply_actions(actions).await,
            Err(err) => {
                let _ = self.stream.close().await;
                Err(err.into())
            }
        }
    }

    /// Evaluates default-deny capability authorization and produces a structured audit event.
    pub fn authorize(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        self.machine.authorize(requested_cap, now_unix, roster)
    }

    /// Returns the authenticated peer device ID once established.
    #[must_use]
    pub fn peer_device_id(&self) -> Option<&str> {
        self.machine.peer_device_id()
    }

    /// Returns the CRL sequence advertised by the peer in `SessionHello`, if any.
    #[must_use]
    pub const fn peer_crl_seq(&self) -> Option<u64> {
        self.machine.peer_crl_seq()
    }

    /// Returns the currently verified capability grant attached to the session, if any.
    #[must_use]
    pub const fn active_grant(&self) -> Option<&Grant> {
        self.machine.active_grant()
    }

    /// Returns the verified host rotation chain applied during handshake, if any.
    #[must_use]
    pub fn applied_rotation(&self) -> &[RotationRecord] {
        self.machine.applied_rotation()
    }

    /// Returns the provider ID backing the active stream.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.stream.provider_id()
    }

    /// Returns the next semantic event, reading and decrypting transport frames as needed.
    pub async fn next_event(
        &mut self,
        now_unix: u64,
        roster: &mut Roster,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        self.next_event_with_roster(now_unix, RosterRef::Direct(roster))
            .await
    }

    /// Returns the next semantic event using a mutex-guarded roster without holding the lock
    /// across `.await`.
    pub async fn next_event_locked(
        &mut self,
        now_unix: u64,
        roster: &Mutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        self.next_event_with_roster(now_unix, RosterRef::Locked(roster))
            .await
    }

    /// Returns the next semantic event, polling inbound frames at `poll_interval` and calling
    /// `refresh_roster` before evaluating `tick` or feeding incoming frames.
    pub async fn next_event_with_refresh<F>(
        &mut self,
        roster: &mut Roster,
        poll_interval: Duration,
        mut refresh_roster: F,
    ) -> Result<Option<SessionEvent>, RuntimeError>
    where
        F: FnMut(&mut Roster) -> Result<bool, RuntimeError>,
    {
        loop {
            if !self.pending_events.is_empty() {
                let now_unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if refresh_roster(roster)? {
                    self.tick(now_unix, roster).await?;
                }
                if let Some(ev) = self.pending_events.pop_front() {
                    return Ok(Some(ev));
                }
            }
            if self.machine.is_closed() {
                return Ok(None);
            }
            let recv_res = timeout(poll_interval, self.stream.recv_chunk(&mut self.recv_buf)).await;
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let now_ms = self.elapsed_ms();
            match recv_res {
                Ok(Ok(0)) => return Ok(None),
                Ok(Err(err)) => return Err(err),
                Ok(Ok(n)) => {
                    if refresh_roster(roster)? {
                        self.tick(now_unix, roster).await?;
                    }
                    let chunk = self.recv_buf[..n].to_vec();
                    let mut roster_ref = RosterRef::Direct(roster);
                    let actions =
                        self.feed_with_roster(&chunk, now_unix, now_ms, &mut roster_ref)?;
                    self.apply_actions(actions).await?;
                }
                Err(_) => {
                    let _ = refresh_roster(roster)?;
                    self.tick(now_unix, roster).await?;
                }
            }
        }
    }

    async fn next_event_with_roster(
        &mut self,
        now_unix: u64,
        mut roster: RosterRef<'_>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        loop {
            if let Some(ev) = self.pending_events.pop_front() {
                return Ok(Some(ev));
            }
            if self.machine.is_closed() {
                return Ok(None);
            }
            let n = self.stream.recv_chunk(&mut self.recv_buf).await?;
            if n == 0 {
                return Ok(None);
            }
            let now_ms = self.elapsed_ms();
            let chunk = self.recv_buf[..n].to_vec();
            let actions = self.feed_with_roster(&chunk, now_unix, now_ms, &mut roster)?;
            self.apply_actions(actions).await?;
        }
    }

    async fn drive_until_established(
        &mut self,
        now_unix: u64,
        roster: &mut RosterRef<'_>,
        rate_limiter: Option<&PreAuthRateLimiter>,
        handshake_timeout: Option<Duration>,
    ) -> Result<(), RuntimeError> {
        let deadline = handshake_timeout.map(|d| TokioInstant::now() + d);
        while !self.machine.is_established() {
            if self.machine.is_closed() {
                return Err(RuntimeError::Closed);
            }
            let n = match deadline {
                Some(dl) => {
                    match timeout_at(dl, self.stream.recv_chunk(&mut self.recv_buf)).await {
                        Ok(res) => res?,
                        Err(_) => {
                            let _ = self.stream.close().await;
                            return Err(RuntimeError::Timeout(
                                "pre-auth session handshake timed out",
                            ));
                        }
                    }
                }
                None => self.stream.recv_chunk(&mut self.recv_buf).await?,
            };
            if n == 0 {
                return Err(RuntimeError::Closed);
            }
            let now_ms = self.elapsed_ms();
            let chunk = self.recv_buf[..n].to_vec();
            let actions = self.feed_with_roster(&chunk, now_unix, now_ms, roster)?;
            self.apply_actions(actions).await?;
        }

        self._half_open.take();
        if let Some(rl) = rate_limiter
            && let Some(peer_id) = self.machine.peer_device_id()
        {
            rl.check_peer(peer_id)?;
        }
        Ok(())
    }

    fn feed_with_roster(
        &mut self,
        chunk: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut RosterRef<'_>,
    ) -> Result<Vec<SessionAction>, RuntimeError> {
        let actions = match roster {
            RosterRef::Direct(r) => self.machine.feed_bytes(chunk, now_unix, now_ms, r)?,
            RosterRef::Locked(m) => {
                let mut guard = m.lock().expect("roster mutex poisoned");
                self.machine
                    .feed_bytes(chunk, now_unix, now_ms, &mut guard)?
            }
        };
        Ok(actions)
    }

    async fn apply_actions(&mut self, actions: Vec<SessionAction>) -> Result<(), RuntimeError> {
        for action in actions {
            match action {
                SessionAction::WriteBytes(bytes) => {
                    write_protocol_bytes(self.stream.as_mut(), &bytes).await?;
                }
                SessionAction::Established { .. } => {}
                SessionAction::AppData(data) => {
                    self.pending_events.push_back(SessionEvent::AppData(data));
                }
                SessionAction::GrantUpdated(grant) => {
                    self.pending_events
                        .push_back(SessionEvent::GrantUpdated(grant));
                }
                SessionAction::RevocationUpdated { issuer, seq } => {
                    self.pending_events
                        .push_back(SessionEvent::RevocationUpdated { issuer, seq });
                }
                SessionAction::Rekeyed { direction } => {
                    self.pending_events
                        .push_back(SessionEvent::Rekeyed { direction });
                }
                SessionAction::PongReceived(cookie) => {
                    self.pending_events
                        .push_back(SessionEvent::PongReceived(cookie));
                }
                SessionAction::Audit(ev) => {
                    self.pending_events.push_back(SessionEvent::Audit(ev));
                }
                SessionAction::CloseTransport { code, reason } => {
                    self.pending_events
                        .push_back(SessionEvent::Closed { code, reason });
                    let _ = self.stream.close().await;
                }
            }
        }
        Ok(())
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Drives [`PathPlanner`] concurrently across provider dialers using Happy Eyeballs rules,
/// canceling all losing attempts once a candidate activates.
pub async fn dial_with_policy(
    dialers: &[Arc<dyn PathDialer>],
    policy_config: PathPolicyConfig,
    candidates: Vec<CandidateEndpoint>,
) -> Result<(CandidateEndpoint, Box<dyn PathStream>), RuntimeError> {
    let dialer_map: HashMap<ProviderId, Arc<dyn PathDialer>> = dialers
        .iter()
        .map(|d| (d.provider_id(), Arc::clone(d)))
        .collect();

    let mut planner = PathPlanner::new(policy_config, candidates);
    let started = Instant::now();
    planner.start(0);

    struct AbortOnDrop(AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let (result_tx, mut result_rx) =
        mpsc::channel::<(usize, Result<Box<dyn PathStream>, RuntimeError>)>(32);
    let mut in_flight_handles: HashMap<usize, AbortOnDrop> = HashMap::new();
    let mut succeeded_streams: HashMap<usize, Box<dyn PathStream>> = HashMap::new();

    loop {
        for action in planner.drain_actions() {
            match action {
                PlannerAction::DialCandidate(cand) => {
                    let Some(dialer) = dialer_map.get(&cand.provider).cloned() else {
                        let now_ms =
                            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                        planner.on_dial_failed(cand.id, "missing dialer", now_ms);
                        continue;
                    };
                    let tx = result_tx.clone();
                    let id = cand.id;
                    let endpoint = cand.addr;
                    let handle = tokio::spawn(async move {
                        let res = dialer.dial(&endpoint).await;
                        let _ = tx.send((id, res)).await;
                    });
                    in_flight_handles.insert(cand.id, AbortOnDrop(handle.abort_handle()));
                }
                PlannerAction::CancelCandidate(id) | PlannerAction::CloseActivePath { id, .. } => {
                    in_flight_handles.remove(&id);
                    succeeded_streams.remove(&id);
                }
                PlannerAction::ActivatePath(cand) => {
                    if let Some(stream) = succeeded_streams.remove(&cand.id) {
                        in_flight_handles.clear();
                        return Ok((cand, stream));
                    }
                }
                PlannerAction::ProbeBetterPath(_) => {}
                PlannerAction::AllCandidatesExhausted => {
                    in_flight_handles.clear();
                    return Err(RuntimeError::Policy("all candidates exhausted"));
                }
            }
        }

        tokio::select! {
            maybe_res = result_rx.recv() => {
                let Some((id, res)) = maybe_res else {
                    in_flight_handles.clear();
                    return Err(RuntimeError::Policy("dialer channel closed"));
                };
                in_flight_handles.remove(&id);
                let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                match res {
                    Ok(stream) => {
                        succeeded_streams.insert(id, stream);
                        planner.on_dial_succeeded(id, now_ms);
                    }
                    Err(err) => {
                        planner.on_dial_failed(id, &err.to_string(), now_ms);
                    }
                }
            }
            _ = sleep(Duration::from_millis(25)) => {
                let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                planner.tick(now_ms);
            }
        }
    }
}
