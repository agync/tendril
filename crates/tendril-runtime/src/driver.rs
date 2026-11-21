//! Async drivers binding `tendril-core` pairing, session, and path planning state machines
//! to concrete [`PathStream`] and [`PathDialer`] transports.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tendril_core::error::CoreError;
use tendril_core::grants::{AuditEvent, Grant, RevocationList};
use tendril_core::identity::{EndpointIdentity, RotationRecord};
use tendril_core::pairing::{
    EnrollmentPolicy, PairAction, PairOutcome, PairingInitiator, PairingManager, PairingPathKind,
    PairingResponder, PinnedHost,
};
use tendril_core::policy::{
    CandidateEndpoint, PathPlanner, PathPolicyConfig, PlannerAction, ProviderId,
};
use tendril_core::roster::Roster;
use tendril_core::session::{RekeyDirection, SessionAction, SessionMachine};
use tendril_core::wire::{Intent, Preamble};
use tendril_core::{MAX_FRAME_LEN, PREAMBLE_LEN};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::AbortHandle;
use tokio::time::{Instant as TokioInstant, sleep, timeout, timeout_at};

use crate::error::RuntimeError;
use crate::provider::{MAX_OUTER_FRAME_LEN, PathDialer, PathReader, PathStream, PathWriter};
use crate::rate_limit::{HalfOpenGuard, PreAuthRateLimiter};
use crate::store::StateStore;

pub(crate) fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) async fn write_protocol_chunks(
    writer: &mut dyn PathWriter,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
        writer.send_chunk(chunk).await?;
    }
    Ok(())
}

fn push_non_write_action(
    pending_events: &mut VecDeque<SessionEvent>,
    action: SessionAction,
) -> (bool, bool) {
    match action {
        SessionAction::WriteBytes(_) | SessionAction::Established { .. } => (false, false),
        SessionAction::AppData(data) => {
            pending_events.push_back(SessionEvent::AppData(data));
            (true, false)
        }
        SessionAction::GrantUpdated(grant) => {
            pending_events.push_back(SessionEvent::GrantUpdated(grant));
            (true, false)
        }
        SessionAction::RevocationUpdated { issuer, seq } => {
            pending_events.push_back(SessionEvent::RevocationUpdated { issuer, seq });
            (true, false)
        }
        SessionAction::Rekeyed { direction } => {
            pending_events.push_back(SessionEvent::Rekeyed { direction });
            (true, false)
        }
        SessionAction::PongReceived(cookie) => {
            pending_events.push_back(SessionEvent::PongReceived(cookie));
            (true, false)
        }
        SessionAction::Audit(ev) => {
            pending_events.push_back(SessionEvent::Audit(ev));
            (true, false)
        }
        SessionAction::CloseTransport { code, reason } => {
            pending_events.push_back(SessionEvent::Closed { code, reason });
            (true, true)
        }
    }
}

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

pub(crate) async fn write_protocol_bytes(
    stream: &mut dyn PathStream,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
        stream.send_chunk(chunk).await?;
    }
    Ok(())
}

/// Resolves the highest persisted `min_wire_version` floor matching `pin` in `roster`.
#[must_use]
pub fn pinned_pairing_floor(roster: &Roster, pin: &PinnedHost) -> u8 {
    let static_floor = roster.pairing_floor(&pin.static_pub);
    let host_floor = pin
        .host_id
        .as_deref()
        .and_then(|id| roster.get(id))
        .map_or(tendril_core::WIRE_VERSION, |e| e.min_wire_version);
    static_floor.max(host_floor)
}

/// Drives a pairing initiator handshake to completion over `stream` within `DEFAULT_PRE_AUTH_TIMEOUT`.
#[deprecated(note = "use _with_store or _with_floor to enforce Wire v2 anti-downgrade")]
#[allow(deprecated)]
pub async fn drive_pair_initiator(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    pinned_host: Option<PinnedHost>,
) -> Result<PairDriveResult, RuntimeError> {
    drive_pair_initiator_with_timeout(
        stream,
        identity,
        device_name,
        device_kind,
        code,
        pinned_host,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
}

/// Drives a pairing initiator handshake to completion over `stream` within `handshake_timeout`.
#[deprecated(note = "use _with_store or _with_floor to enforce Wire v2 anti-downgrade")]
pub async fn drive_pair_initiator_with_timeout(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    pinned_host: Option<PinnedHost>,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let machine =
        PairingInitiator::new(identity, device_name, device_kind, code, pinned_host, None)?;
    drive_pairing_initiator_machine(stream, machine, handshake_timeout).await
}

/// Drives a v1 pairing initiator enforcing an explicit `min_wire_version` anti-downgrade floor.
#[allow(clippy::too_many_arguments)]
pub async fn drive_pair_initiator_with_floor(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    pinned_host: Option<PinnedHost>,
    min_wire_version: u8,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let machine = PairingInitiator::new_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        code,
        pinned_host,
        min_wire_version,
        None,
    )?;
    drive_pairing_initiator_machine(stream, machine, handshake_timeout).await
}

/// Drives a v1 pairing initiator while enforcing any persisted `min_wire_version` floor from `store`.
#[allow(clippy::too_many_arguments)]
pub async fn drive_pair_initiator_with_store(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    pinned_host: Option<PinnedHost>,
    store: &StateStore,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let roster = store.load_roster()?;
    let floor = pinned_host
        .as_ref()
        .map_or(tendril_core::WIRE_VERSION, |pin| {
            pinned_pairing_floor(&roster, pin)
        });
    let machine = PairingInitiator::new_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        code,
        pinned_host,
        floor,
        None,
    )?
    .with_roster_floors(&roster);
    drive_pairing_initiator_machine(stream, machine, handshake_timeout).await
}

/// Drives an autonomous M2M enrollment initiator handshake to completion over `stream`
/// within `DEFAULT_PRE_AUTH_TIMEOUT`, requiring a pinned host identity.
#[deprecated(note = "use _with_store or _with_floor to enforce Wire v2 anti-downgrade")]
#[allow(deprecated)]
pub async fn drive_m2m_enroll_initiator(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    enrollment_token: Grant,
    pinned_host: PinnedHost,
) -> Result<PairDriveResult, RuntimeError> {
    drive_m2m_enroll_initiator_with_timeout(
        stream,
        identity,
        device_name,
        device_kind,
        enrollment_token,
        pinned_host,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
}

/// Drives an autonomous M2M enrollment initiator handshake to completion over `stream`
/// within `handshake_timeout`, requiring a pinned host identity.
#[deprecated(note = "use _with_store or _with_floor to enforce Wire v2 anti-downgrade")]
pub async fn drive_m2m_enroll_initiator_with_timeout(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    enrollment_token: Grant,
    pinned_host: PinnedHost,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let machine = PairingInitiator::new_m2m(
        identity,
        device_name,
        device_kind,
        enrollment_token,
        pinned_host,
        None,
    )?;
    drive_pairing_initiator_machine(stream, machine, handshake_timeout).await
}

/// Drives a v1 M2M enrollment initiator enforcing an explicit `min_wire_version` floor.
#[allow(clippy::too_many_arguments)]
pub async fn drive_m2m_enroll_initiator_with_floor(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    enrollment_token: Grant,
    pinned_host: PinnedHost,
    min_wire_version: u8,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let machine = PairingInitiator::new_m2m_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        enrollment_token,
        pinned_host,
        min_wire_version,
        None,
    )?;
    drive_pairing_initiator_machine(stream, machine, handshake_timeout).await
}

/// Drives a v1 M2M enrollment initiator while enforcing any persisted `min_wire_version` floor from `store`.
#[allow(clippy::too_many_arguments)]
pub async fn drive_m2m_enroll_initiator_with_store(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    enrollment_token: Grant,
    pinned_host: PinnedHost,
    store: &StateStore,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let roster = store.load_roster()?;
    let floor = pinned_pairing_floor(&roster, &pinned_host);
    drive_m2m_enroll_initiator_with_floor(
        stream,
        identity,
        device_name,
        device_kind,
        enrollment_token,
        pinned_host,
        floor,
        handshake_timeout,
    )
    .await
}

async fn drive_pairing_initiator_machine(
    stream: &mut dyn PathStream,
    mut machine: PairingInitiator,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let mut observed_sas = None;
    let deadline = TokioInstant::now() + handshake_timeout;
    let init_actions = machine.start()?;
    match timeout_at(
        deadline,
        dispatch_pair_actions(stream, init_actions, &mut observed_sas),
    )
    .await
    {
        Ok(Ok(Some(outcome))) => {
            return Ok(PairDriveResult {
                outcome,
                sas: observed_sas,
            });
        }
        Ok(Ok(None)) => {}
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            let _ = stream.close().await;
            return Err(RuntimeError::Timeout(
                "pre-auth pairing handshake timed out",
            ));
        }
    }

    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
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
        let actions = machine.feed_bytes(&buf[..n])?;
        match timeout_at(
            deadline,
            dispatch_pair_actions(stream, actions, &mut observed_sas),
        )
        .await
        {
            Ok(Ok(Some(outcome))) => {
                return Ok(PairDriveResult {
                    outcome,
                    sas: observed_sas,
                });
            }
            Ok(Ok(None)) => {}
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                let _ = stream.close().await;
                return Err(RuntimeError::Timeout(
                    "pre-auth pairing handshake timed out",
                ));
            }
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
/// and an explicit overall pre-auth handshake deadline (M2M enrollment disabled).
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
    drive_pair_responder_with_policy(
        stream,
        identity,
        manager,
        roster,
        path_kind,
        now_unix,
        EnrollmentPolicy::default(),
        rate_limiter,
        existing_guard,
        handshake_timeout,
    )
    .await
}

/// Drives a pairing responder handshake using an explicit [`EnrollmentPolicy`], updating `roster`.
#[allow(clippy::too_many_arguments)]
pub async fn drive_pair_responder_with_policy(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Mutex<PairingManager>,
    roster: &Mutex<Roster>,
    path_kind: PairingPathKind,
    now_unix: u64,
    enrollment_policy: EnrollmentPolicy,
    rate_limiter: Option<&PreAuthRateLimiter>,
    existing_guard: Option<HalfOpenGuard>,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    drive_pair_responder_inner(
        stream,
        identity,
        manager,
        ResponderRosterBackend::InMemory {
            roster,
            store: None,
        },
        path_kind,
        now_unix,
        enrollment_policy,
        rate_limiter,
        existing_guard,
        handshake_timeout,
    )
    .await
}

/// Drives a pairing responder handshake updating `roster` and persisting atomically to `store`
/// before transmitting `PairResponse`.
#[allow(clippy::too_many_arguments)]
pub async fn drive_pair_responder_with_policy_and_store(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Mutex<PairingManager>,
    roster: &Mutex<Roster>,
    store: Option<&StateStore>,
    path_kind: PairingPathKind,
    now_unix: u64,
    enrollment_policy: EnrollmentPolicy,
    rate_limiter: Option<&PreAuthRateLimiter>,
    existing_guard: Option<HalfOpenGuard>,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    drive_pair_responder_inner(
        stream,
        identity,
        manager,
        ResponderRosterBackend::InMemory { roster, store },
        path_kind,
        now_unix,
        enrollment_policy,
        rate_limiter,
        existing_guard,
        handshake_timeout,
    )
    .await
}

/// Drives a pairing responder backed directly by [`StateStore`] (`tendril-cli` / concurrent host),
/// executing `msg3` claim verification and nonce burn atomically under `store_lock` and `.roster.lock`
/// before transmitting `PairResponse`.
#[allow(clippy::too_many_arguments)]
pub async fn drive_pair_responder_with_store(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Mutex<PairingManager>,
    store: &StateStore,
    store_lock: &AsyncMutex<()>,
    path_kind: PairingPathKind,
    now_unix: u64,
    enrollment_policy: EnrollmentPolicy,
    rate_limiter: Option<&PreAuthRateLimiter>,
    existing_guard: Option<HalfOpenGuard>,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    drive_pair_responder_inner(
        stream,
        identity,
        manager,
        ResponderRosterBackend::DiskStore { store, store_lock },
        path_kind,
        now_unix,
        enrollment_policy,
        rate_limiter,
        existing_guard,
        handshake_timeout,
    )
    .await
}

enum ResponderRosterBackend<'a> {
    InMemory {
        roster: &'a Mutex<Roster>,
        store: Option<&'a StateStore>,
    },
    DiskStore {
        store: &'a StateStore,
        store_lock: &'a AsyncMutex<()>,
    },
}

pub(crate) fn has_complete_outer_frame(buf: &[u8]) -> Result<bool, RuntimeError> {
    if buf.len() < 2 {
        return Ok(false);
    }
    let body_len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if body_len > MAX_FRAME_LEN {
        return Err(CoreError::FrameTooLarge {
            len: body_len,
            max: MAX_FRAME_LEN,
        }
        .into());
    }
    Ok(buf.len() >= 2 + body_len)
}

#[allow(clippy::too_many_arguments)]
async fn drive_pair_responder_inner(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Mutex<PairingManager>,
    backend: ResponderRosterBackend<'_>,
    path_kind: PairingPathKind,
    now_unix: u64,
    enrollment_policy: EnrollmentPolicy,
    rate_limiter: Option<&PreAuthRateLimiter>,
    existing_guard: Option<HalfOpenGuard>,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let _half_open = match existing_guard {
        Some(g) => Some(g),
        None => rate_limiter
            .map(|rl| {
                rl.try_acquire_for_stream(
                    stream.provider_id(),
                    stream.peer_ip(),
                    stream.peer_transport_id().as_deref(),
                )
            })
            .transpose()?,
    };
    let mut machine =
        PairingResponder::with_enrollment_policy(identity, path_kind, None, enrollment_policy)?;
    let mut observed_sas = None;
    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
    let mut pre_claim_buf = Vec::new();
    let mut pending_claim_bytes = Vec::new();
    let deadline = TokioInstant::now() + handshake_timeout;

    loop {
        if !machine.is_awaiting_claim() || !has_complete_outer_frame(&pending_claim_bytes)? {
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
            if !machine.is_awaiting_claim() {
                pre_claim_buf.extend_from_slice(&buf[..n]);
                if pre_claim_buf.len() > PREAMBLE_LEN + MAX_OUTER_FRAME_LEN {
                    return Err(CoreError::BufferOverflow {
                        len: pre_claim_buf.len(),
                        max: PREAMBLE_LEN + MAX_OUTER_FRAME_LEN,
                    }
                    .into());
                }
            } else {
                pending_claim_bytes.extend_from_slice(&buf[..n]);
                if pending_claim_bytes.len() > MAX_OUTER_FRAME_LEN {
                    return Err(CoreError::BufferOverflow {
                        len: pending_claim_bytes.len(),
                        max: MAX_OUTER_FRAME_LEN,
                    }
                    .into());
                }
            }
        }

        let actions = if !machine.is_awaiting_claim() {
            if pre_claim_buf.len() < PREAMBLE_LEN {
                continue;
            }
            let preamble = Preamble::decode(&pre_claim_buf[..PREAMBLE_LEN])?;
            if preamble.intent != Intent::Pair {
                return Err(CoreError::ProtocolViolation("expected pair preamble intent").into());
            }
            // Feed only the preamble + msg1 frame before entering AwaitMsg3 so coalesced msg3
            // bytes can never execute against an empty roster.
            let after_pre = &pre_claim_buf[PREAMBLE_LEN..];
            if !has_complete_outer_frame(after_pre)? {
                continue;
            }
            let body1_len = usize::from(u16::from_be_bytes([after_pre[0], after_pre[1]]));
            let split_at = PREAMBLE_LEN + 2 + body1_len;
            let trailing = pre_claim_buf.split_off(split_at);
            pending_claim_bytes.extend_from_slice(&trailing);
            let msg1_bytes = std::mem::take(&mut pre_claim_buf);

            let mut mgr = manager.lock().expect("pairing manager mutex poisoned");
            let mut empty_roster = Roster::new();
            machine.feed_bytes(&msg1_bytes, now_unix, &mut mgr, &mut empty_roster)?
        } else {
            if !has_complete_outer_frame(&pending_claim_bytes)? {
                continue;
            }
            let claim_bytes = std::mem::take(&mut pending_claim_bytes);
            match &backend {
                ResponderRosterBackend::InMemory { roster, store } => {
                    let mut mgr = manager.lock().expect("pairing manager mutex poisoned");
                    let mut rst = roster.lock().expect("roster mutex poisoned");
                    let actions = machine.feed_bytes(&claim_bytes, now_unix, &mut mgr, &mut rst)?;
                    if let Some(s) = store
                        && actions
                            .iter()
                            .any(|a| matches!(a, PairAction::Completed(_)))
                    {
                        s.save_roster(&rst)?;
                    }
                    actions
                }
                ResponderRosterBackend::DiskStore { store, store_lock } => {
                    let _guard = store_lock.lock().await;
                    store.update_roster(|rst| {
                        let mut mgr = manager.lock().expect("pairing manager mutex poisoned");
                        machine
                            .feed_bytes(&claim_bytes, now_unix, &mut mgr, rst)
                            .map_err(Into::into)
                    })?
                }
            }
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

    /// Concurrently races candidate paths under Happy Eyeballs rules and activates the first path
    /// that completes a full authenticated Noise XX handshake (`HostHello` verified before aborting
    /// competing candidates).
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_policy(
        dialers: &[Arc<dyn PathDialer>],
        policy_config: PathPolicyConfig,
        candidates: Vec<CandidateEndpoint>,
        local_identity: Arc<EndpointIdentity>,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        roster: &mut Roster,
        now_unix: u64,
    ) -> Result<(CandidateEndpoint, Self), RuntimeError> {
        struct RosterSyncGuard<'a> {
            dst: &'a mut Roster,
            shared: Arc<Mutex<Roster>>,
        }
        impl Drop for RosterSyncGuard<'_> {
            fn drop(&mut self) {
                *self.dst = self.shared.lock().expect("roster mutex poisoned").clone();
            }
        }

        let shared_roster = Arc::new(Mutex::new(roster.clone()));
        let _sync_guard = RosterSyncGuard {
            dst: roster,
            shared: Arc::clone(&shared_roster),
        };
        let target_owned = target_host_id.to_owned();
        dial_with_policy_verified(dialers, policy_config, candidates, move |_cand, stream| {
            let id_c = Arc::clone(&local_identity);
            let target_c = target_owned.clone();
            let grant_c = initial_grant.clone();
            let roster_c = Arc::clone(&shared_roster);
            async move {
                Self::connect_locked(stream, &id_c, &target_c, grant_c, &roster_c, now_unix).await
            }
        })
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
                    rl.try_acquire_for_stream(
                        stream.provider_id(),
                        stream.peer_ip(),
                        stream.peer_transport_id().as_deref(),
                    )
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

    /// Converts this established [`SessionDriver`] into a full-duplex [`ConcurrentSession`].
    #[must_use]
    pub fn into_concurrent(self) -> ConcurrentSession {
        let provider_id = self.stream.provider_id();
        let is_closed = self.machine.is_closed();
        let (reader, writer) = self.stream.into_split();
        let (shutdown_tx, _) = tokio::sync::watch::channel(is_closed);
        ConcurrentSession {
            machine: Mutex::new(self.machine),
            reader: tokio::sync::Mutex::new(SessionReadHalf {
                reader,
                recv_buf: self.recv_buf,
            }),
            writer: tokio::sync::Mutex::new(writer),
            pending_events: Mutex::new(self.pending_events),
            event_notify: tokio::sync::Notify::new(),
            shutdown_tx,
            started_at: self.started_at,
            provider_id,
            _half_open: self._half_open,
        }
    }

    /// Returns the next semantic event, reading and decrypting transport frames as needed.
    pub async fn next_event(
        &mut self,
        now_unix: u64,
        roster: &mut Roster,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        let call_start = Instant::now();
        self.next_event_with_roster(RosterRef::Direct(roster), move || {
            now_unix.saturating_add(call_start.elapsed().as_secs())
        })
        .await
    }

    /// Returns the next semantic event using wall-clock time sampled when each frame arrives.
    pub async fn next_event_now(
        &mut self,
        roster: &mut Roster,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        self.next_event_with_roster(RosterRef::Direct(roster), current_unix_secs)
            .await
    }

    /// Returns the next semantic event using a mutex-guarded roster without holding the lock
    /// across `.await`.
    pub async fn next_event_locked(
        &mut self,
        now_unix: u64,
        roster: &Mutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        let call_start = Instant::now();
        self.next_event_with_roster(RosterRef::Locked(roster), move || {
            now_unix.saturating_add(call_start.elapsed().as_secs())
        })
        .await
    }

    /// Returns the next semantic event using a mutex-guarded roster and wall-clock time sampled
    /// when each frame arrives.
    pub async fn next_event_locked_now(
        &mut self,
        roster: &Mutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        self.next_event_with_roster(RosterRef::Locked(roster), current_unix_secs)
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
                let now_unix = current_unix_secs();
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
            let now_unix = current_unix_secs();
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
        mut roster: RosterRef<'_>,
        mut now_fn: impl FnMut() -> u64,
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
            let now_unix = now_fn();
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
        let mut should_close = false;
        for action in actions {
            if let SessionAction::WriteBytes(bytes) = action {
                write_protocol_bytes(self.stream.as_mut(), &bytes).await?;
            } else {
                let (_, close_transport) = push_non_write_action(&mut self.pending_events, action);
                if close_transport {
                    should_close = true;
                }
            }
        }
        if should_close {
            let _ = self.stream.close().await;
        }
        Ok(())
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

struct SessionReadHalf {
    reader: Box<dyn PathReader>,
    recv_buf: Vec<u8>,
}

/// Full-duplex concurrent driver for one established [`SessionMachine`].
///
/// Locks follow a strict total order: `reader` -> `writer` -> `machine` -> `roster` ->
/// `pending_events`. Neither `machine`, `roster`, nor `pending_events` is held across `.await`.
pub struct ConcurrentSession {
    machine: Mutex<SessionMachine>,
    reader: tokio::sync::Mutex<SessionReadHalf>,
    writer: tokio::sync::Mutex<Box<dyn PathWriter>>,
    pending_events: Mutex<VecDeque<SessionEvent>>,
    event_notify: tokio::sync::Notify,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    started_at: Instant,
    provider_id: ProviderId,
    _half_open: Option<HalfOpenGuard>,
}

impl ConcurrentSession {
    /// Signals any parked `next_event_*` callers to exit immediately with `Ok(None)`.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.event_notify.notify_waiters();
    }

    /// Evaluates default-deny capability authorization without waiting on session I/O.
    pub fn authorize(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        let machine = self.machine.lock().expect("session machine mutex poisoned");
        machine.authorize(requested_cap, now_unix, roster)
    }

    /// Evaluates default-deny capability authorization against a shared roster lock while
    /// maintaining `machine -> roster` lock order with `next_event_*`.
    pub fn authorize_locked(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &Mutex<Roster>,
    ) -> (Result<(), CoreError>, AuditEvent) {
        let machine = self.machine.lock().expect("session machine mutex poisoned");
        let roster_guard = roster.lock().expect("roster mutex poisoned");
        machine.authorize(requested_cap, now_unix, &roster_guard)
    }

    /// Returns the authenticated peer device ID if established.
    #[must_use]
    pub fn peer_device_id(&self) -> Option<String> {
        self.machine
            .lock()
            .expect("session machine mutex poisoned")
            .peer_device_id()
            .map(ToOwned::to_owned)
    }

    /// Returns the provider ID backing the active stream.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Sends encrypted `0x01 DATA` concurrently with inbound polling.
    pub async fn send_data(&self, payload: &[u8]) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_data(payload, now_ms))
            .await
    }

    /// Sends encrypted `0x02 GRANT` concurrently with inbound polling.
    pub async fn send_grant(&self, grant: &Grant) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_grant(grant, now_ms))
            .await
    }

    /// Sends encrypted `0x03 REVOCATION` concurrently with inbound polling.
    pub async fn send_revocation(&self, crl: &RevocationList) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_revocation(crl, now_ms))
            .await
    }

    /// Sends encrypted `0x04 REKEY` concurrently with inbound polling.
    pub async fn send_rekey(&self) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_rekey(now_ms))
            .await
    }

    /// Sends encrypted `0x05 PING` concurrently with inbound polling.
    pub async fn send_ping(&self, cookie: u64) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_ping(cookie, now_ms))
            .await
    }

    /// Sends encrypted `0x07 CLOSE` and shuts down the transport writer.
    pub async fn send_close(&self, code: u16, reason: &str) -> Result<(), RuntimeError> {
        let mut writer = self.writer.lock().await;
        let close_res = {
            let mut machine = self.machine.lock().expect("session machine mutex poisoned");
            (machine.send_close(code, reason), machine.is_closed())
        };
        let actions = match close_res {
            (Ok(actions), _) => actions,
            (Err(err), closed) => {
                if closed {
                    let _ = writer.close().await;
                    self.event_notify.notify_waiters();
                }
                return Err(err.into());
            }
        };
        let res = self.dispatch_actions_locked(&mut writer, actions).await;
        let _ = writer.close().await;
        self.event_notify.notify_waiters();
        res
    }

    /// Advances timer and grant checks against `roster`.
    pub async fn tick(&self, now_unix: u64, roster: &Roster) -> Result<(), RuntimeError> {
        let mut writer = self.writer.lock().await;
        let tick_res = {
            let now_ms = self.elapsed_ms();
            let mut machine = self.machine.lock().expect("session machine mutex poisoned");
            machine.tick(now_unix, now_ms, roster)
        };
        match tick_res {
            Ok(actions) => self.dispatch_actions_locked(&mut writer, actions).await,
            Err(err) => {
                let _ = writer.close().await;
                self.event_notify.notify_waiters();
                Err(err.into())
            }
        }
    }

    /// Advances timer and grant checks against a shared roster lock while preserving
    /// `writer -> machine -> roster` lock order.
    pub async fn tick_locked(
        &self,
        now_unix: u64,
        roster: &Mutex<Roster>,
    ) -> Result<(), RuntimeError> {
        let mut writer = self.writer.lock().await;
        let tick_res = {
            let now_ms = self.elapsed_ms();
            let mut machine = self.machine.lock().expect("session machine mutex poisoned");
            let roster_guard = roster.lock().expect("roster mutex poisoned");
            machine.tick(now_unix, now_ms, &roster_guard)
        };
        match tick_res {
            Ok(actions) => self.dispatch_actions_locked(&mut writer, actions).await,
            Err(err) => {
                let _ = writer.close().await;
                self.event_notify.notify_waiters();
                Err(err.into())
            }
        }
    }

    /// Waits for the next semantic event using fresh wall-clock `now_unix` on frame arrival,
    /// without blocking outbound sends or authorization checks while awaiting bytes.
    pub async fn next_event_locked_now(
        &self,
        roster: &Mutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        self.next_event_with_clock(roster, current_unix_secs).await
    }

    /// Waits for the next semantic event using an explicit clock callback sampled on frame arrival.
    pub async fn next_event_with_clock(
        &self,
        roster: &Mutex<Roster>,
        mut now_fn: impl FnMut() -> u64,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        let mut read_half = self.reader.lock().await;
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        loop {
            let notified = self.event_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if *shutdown_rx.borrow() {
                return Ok(None);
            }
            if let Some(ev) = self.pop_pending_event() {
                return Ok(Some(ev));
            }
            if self
                .machine
                .lock()
                .expect("session machine mutex poisoned")
                .is_closed()
            {
                return Ok(None);
            }

            let read_half_ref = &mut *read_half;
            let n = tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    return Ok(None);
                }
                _ = &mut notified => continue,
                res = read_half_ref.reader.recv_chunk(&mut read_half_ref.recv_buf) => res?,
            };
            if n == 0 {
                return Ok(None);
            }

            let now_unix = now_fn();
            let now_ms = self.elapsed_ms();
            let mut writer = self.writer.lock().await;
            let feed_res = {
                let mut machine = self.machine.lock().expect("session machine mutex poisoned");
                let mut roster_guard = roster.lock().expect("roster mutex poisoned");
                machine.feed_bytes(
                    &read_half_ref.recv_buf[..n],
                    now_unix,
                    now_ms,
                    &mut roster_guard,
                )
            };
            match feed_res {
                Ok(actions) => {
                    self.dispatch_actions_locked(&mut writer, actions).await?;
                }
                Err(err) => {
                    let _ = writer.close().await;
                    self.event_notify.notify_waiters();
                    return Err(err.into());
                }
            }
        }
    }

    async fn run_write_op<F>(&self, op: F) -> Result<(), RuntimeError>
    where
        F: FnOnce(&mut SessionMachine, u64) -> Result<Vec<SessionAction>, CoreError>,
    {
        let mut writer = self.writer.lock().await;
        let actions = {
            let now_ms = self.elapsed_ms();
            let mut machine = self.machine.lock().expect("session machine mutex poisoned");
            op(&mut machine, now_ms)?
        };
        self.dispatch_actions_locked(&mut writer, actions).await
    }

    async fn dispatch_actions_locked(
        &self,
        writer: &mut Box<dyn PathWriter>,
        actions: Vec<SessionAction>,
    ) -> Result<(), RuntimeError> {
        let mut new_events = VecDeque::new();
        let mut should_close = false;
        for action in actions {
            if let SessionAction::WriteBytes(bytes) = action {
                write_protocol_chunks(writer.as_mut(), &bytes).await?;
            } else {
                let (_, close_transport) = push_non_write_action(&mut new_events, action);
                if close_transport {
                    should_close = true;
                }
            }
        }
        let notify = !new_events.is_empty();
        if notify {
            let mut q = self
                .pending_events
                .lock()
                .expect("pending_events mutex poisoned");
            q.extend(new_events);
        }
        if notify || should_close {
            self.event_notify.notify_waiters();
        }
        if should_close {
            let _ = writer.close().await;
        }
        Ok(())
    }

    fn pop_pending_event(&self) -> Option<SessionEvent> {
        self.pending_events
            .lock()
            .expect("pending_events mutex poisoned")
            .pop_front()
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
    dial_with_policy_verified(
        dialers,
        policy_config,
        candidates,
        |_cand, stream| async move { Ok(stream) },
    )
    .await
}

/// Drives [`PathPlanner`] concurrently across provider dialers and gates path activation on an
/// asynchronous caller verifier (`verify`), keeping competing candidates alive until verification
/// succeeds.
pub async fn dial_with_policy_verified<T, F, Fut>(
    dialers: &[Arc<dyn PathDialer>],
    policy_config: PathPolicyConfig,
    candidates: Vec<CandidateEndpoint>,
    verify: F,
) -> Result<(CandidateEndpoint, T), RuntimeError>
where
    T: Send + 'static,
    F: Fn(CandidateEndpoint, Box<dyn PathStream>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, RuntimeError>> + Send + 'static,
{
    let dialer_map: HashMap<ProviderId, Arc<dyn PathDialer>> = dialers
        .iter()
        .map(|d| (d.provider_id(), Arc::clone(d)))
        .collect();

    let verifier = Arc::new(verify);
    let mut planner = PathPlanner::new(policy_config, candidates);
    let started = Instant::now();
    planner.start(0);

    struct AbortOnDrop(AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let (result_tx, mut result_rx) = mpsc::channel::<(usize, Result<T, RuntimeError>)>(32);
    let mut in_flight_handles: HashMap<usize, AbortOnDrop> = HashMap::new();
    let mut verified_values: HashMap<usize, T> = HashMap::new();

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
                    let endpoint = cand.addr.clone();
                    let verify_c = Arc::clone(&verifier);
                    let handle = tokio::spawn(async move {
                        let res = match dialer.dial(&endpoint).await {
                            Ok(stream) => verify_c(cand, stream).await,
                            Err(err) => Err(err),
                        };
                        let _ = tx.send((id, res)).await;
                    });
                    in_flight_handles.insert(id, AbortOnDrop(handle.abort_handle()));
                }
                PlannerAction::CancelCandidate(id) | PlannerAction::CloseActivePath { id, .. } => {
                    in_flight_handles.remove(&id);
                    verified_values.remove(&id);
                }
                PlannerAction::ActivatePath(cand) => {
                    if let Some(value) = verified_values.remove(&cand.id) {
                        in_flight_handles.clear();
                        return Ok((cand, value));
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
                    Ok(value) => {
                        verified_values.insert(id, value);
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
