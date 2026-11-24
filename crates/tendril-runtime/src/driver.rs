//! Async drivers binding `tendril-core` pairing, session, and path planning state machines
//! to concrete [`PathStream`] and [`PathDialer`] transports.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tendril_core::crypto::HybridSigningPublicKey;
use tendril_core::error::CoreError;
use tendril_core::grants::{AuditEvent, Grant, RevocationList};
use tendril_core::group::{GroupManifest, GroupRendezvousFrame, GroupSeq, V2GroupSecrets};
use tendril_core::identity::{EndpointIdentity, RotationRecord};
use tendril_core::pairing::{
    EnrollmentPolicy, PairAction, PairOutcome, PairingCodeKind, PairingInitiator, PairingManager,
    PairingPathKind, PairingResponder, PairingUri, PersistOpts, PersistPlan, PinnedHost,
    RouteCheck, RoutePolicy, UnsignedReason, VerifiedRouteStatement, is_v2_relay_hint,
    persistable_routes,
};
use tendril_core::policy::{
    CandidateEndpoint, PathPlanner, PathPolicyConfig, PlannerAction, ProviderId,
};
use tendril_core::roster::{PeerState, PinSnapshot, Roster, StoredRoute};
use tendril_core::routes::RouteSet;
use tendril_core::session::{
    RekeyDirection, RouteExpectation, SessionAction, SessionMachine, check_peer_allows_wire_v1,
};
use tendril_core::wire::{Intent, Preamble};
use tendril_core::{MAX_FRAME_LEN, PREAMBLE_LEN};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::AbortHandle;
use tokio::time::{Instant as TokioInstant, sleep, timeout, timeout_at};

use crate::announce::{RosterAccess, RouteSetLimiter, RouteSetSink, ingest_route_sets, unix_ms};
use crate::error::{RelayOffline, RuntimeError};
use crate::provider::{MAX_OUTER_FRAME_LEN, PathDialer, PathReader, PathStream, PathWriter};
use crate::providers::egress::{EgressKind, HintSource, HostResolver, SkipReason, SkippedHint};
use crate::providers::hints::{
    CandidateSet, DialWire, HintDialers, HintInput, HintTarget, MultiDialOptions, RelayV2Gate,
    build_pairing_candidates, normalize_operator_endpoint, session_hint_inputs,
};
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
        SessionAction::GroupManifestReceived(manifest) => {
            pending_events.push_back(SessionEvent::GroupManifestReceived(manifest));
            (true, false)
        }
        SessionAction::GroupRendezvousReceived(frame) => {
            pending_events.push_back(SessionEvent::GroupRendezvousReceived(frame));
            (true, false)
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
    RevocationUpdated {
        issuer: String,
        seq: u64,
    },
    Rekeyed {
        direction: RekeyDirection,
    },
    PongReceived(u64),
    Audit(AuditEvent),
    /// Received `0x0A` manifest: parsed but neither verified nor ingested.
    GroupManifestReceived(Box<GroupManifest>),
    /// Received `0x0B` rendezvous frame: neither authorized nor ingested.
    GroupRendezvousReceived(GroupRendezvousFrame),
    Closed {
        code: u16,
        reason: String,
    },
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
                    // The roster file lock comes before the manager (`crate::announce`).
                    let mut claim = |persist: Option<&StateStore>| {
                        let mut mgr = manager.lock().expect("pairing manager mutex poisoned");
                        let mut rst = roster.lock().expect("roster mutex poisoned");
                        let actions =
                            machine.feed_bytes(&claim_bytes, now_unix, &mut mgr, &mut rst)?;
                        if let Some(s) = persist
                            && actions
                                .iter()
                                .any(|a| matches!(a, PairAction::Completed(_)))
                        {
                            s.save_roster_unlocked(&rst)?;
                        }
                        Ok::<_, RuntimeError>(actions)
                    };
                    match store {
                        Some(s) => s.with_roster_lock(|s| claim(Some(s)))?,
                        None => claim(None)?,
                    }
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
    route_ingest: IngestSlot,
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
            Vec::new(),
        )
        .await
    }

    /// Initiates a session to a group sibling using a mutex-guarded roster, advertising `groups`
    /// in the initiator `SessionHello` so the sibling can gossip a newer manifest.
    pub async fn connect_group_member(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        roster: &Mutex<Roster>,
        groups: Vec<GroupSeq>,
        now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        Self::connect_with_roster(
            stream,
            local_identity,
            target_host_id,
            None,
            None,
            RosterRef::Locked(roster),
            now_unix,
            groups,
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
            Vec::new(),
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
        check_peer_allows_wire_v1(roster, target_host_id)?;
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

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_roster(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        crl_seq: Option<u64>,
        mut roster: RosterRef<'_>,
        now_unix: u64,
        groups: Vec<GroupSeq>,
    ) -> Result<Self, RuntimeError> {
        match &roster {
            RosterRef::Direct(r) => check_peer_allows_wire_v1(r, target_host_id)?,
            RosterRef::Locked(m) => check_peer_allows_wire_v1(
                &m.lock().expect("roster mutex poisoned"),
                target_host_id,
            )?,
        }
        let mut machine = SessionMachine::new_initiator(
            local_identity,
            target_host_id,
            initial_grant,
            crl_seq,
            None,
        )?;
        machine.set_local_groups(groups)?;
        let start_actions = machine.start()?;
        let mut driver = Self {
            stream,
            machine,
            recv_buf: vec![0u8; MAX_OUTER_FRAME_LEN],
            pending_events: VecDeque::new(),
            started_at: Instant::now(),
            _half_open: None,
            route_ingest: IngestSlot::default(),
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
            route_ingest: IngestSlot::default(),
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

    /// Sends encrypted `0x0A GROUP_MANIFEST`.
    pub async fn send_group_manifest(
        &mut self,
        manifest: &GroupManifest,
    ) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self.machine.send_group_manifest(manifest, now_ms)?;
        self.apply_actions(actions).await
    }

    /// Sends encrypted `0x0B GROUP_RENDEZVOUS` carrying `secrets` for `group_id`.
    pub async fn send_group_rendezvous(
        &mut self,
        secrets: &V2GroupSecrets,
        group_id: &str,
    ) -> Result<(), RuntimeError> {
        let frame = secrets.to_rendezvous_frame(group_id)?;
        let now_ms = self.elapsed_ms();
        let actions = self.machine.send_group_rendezvous(&frame[..], now_ms)?;
        self.apply_actions(actions).await
    }

    /// Returns the group gossip summary the initiator advertised in `SessionHello`, if any.
    #[must_use]
    pub fn peer_groups(&self) -> Option<&[GroupSeq]> {
        self.machine.peer_groups()
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

    /// Returns the authenticated peer Noise static key once established.
    #[must_use]
    pub const fn peer_static_pub(&self) -> Option<&[u8; 32]> {
        self.machine.peer_static_pub()
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
            route_ingest: self.route_ingest,
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
                    let actions = self
                        .feed_with_roster(&chunk, now_unix, now_ms, &mut roster_ref)
                        .await?;
                    let applied = self.apply_actions(actions).await;
                    self.drain_route_sets().await;
                    applied?;
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
            let actions = self
                .feed_with_roster(&chunk, now_unix, now_ms, &mut roster)
                .await?;
            let applied = self.apply_actions(actions).await;
            self.drain_route_sets().await;
            applied?;
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
            let actions = self
                .feed_with_roster(&chunk, now_unix, now_ms, roster)
                .await?;
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

    /// Feeds `chunk` and hands the CRLs it left in the roster to the client ingest
    /// ([`fed_crls`]). A failed feed persists them before its error is returned.
    async fn feed_with_roster(
        &mut self,
        chunk: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut RosterRef<'_>,
    ) -> Result<Vec<SessionAction>, RuntimeError> {
        let peer = self.machine.peer_device_id().map(ToOwned::to_owned);
        let (res, crls) = match roster {
            RosterRef::Direct(r) => {
                let res = self.machine.feed_bytes(chunk, now_unix, now_ms, r);
                let crls = fed_crls(res.as_deref().ok(), peer.as_deref(), r);
                (res, crls)
            }
            RosterRef::Locked(m) => {
                let mut guard = m.lock().expect("roster mutex poisoned");
                let res = self.machine.feed_bytes(chunk, now_unix, now_ms, &mut guard);
                let crls = fed_crls(res.as_deref().ok(), peer.as_deref(), &guard);
                (res, crls)
            }
        };
        self.route_ingest.note_crls(crls);
        if res.is_err() {
            self.route_ingest.run(Vec::new()).await;
        }
        Ok(res?)
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

    /// Hands the `0x0C` route sets this initiator session received to the client ingest.
    async fn drain_route_sets(&mut self) {
        let sets = self.machine.take_route_sets();
        self.route_ingest.run(sets).await;
    }

    /// Routes every `0x0C` route set this initiator session receives to
    /// [`crate::announce::ingest_route_sets`] for its peer under `policy`. Sets arrive only when
    /// the session sent `SessionHello.route_seq`; they never reach the event stream.
    pub fn set_route_ingest(&mut self, access: RosterAccess, policy: RoutePolicy) {
        let peer = self
            .machine
            .peer_device_id()
            .map(ToOwned::to_owned)
            .unwrap_or_default();
        self.route_ingest
            .set(RouteIngest::new(access, peer, policy));
    }

    /// The `route_seq` the client sent in `SessionHello` (responder sessions).
    #[must_use]
    pub const fn peer_route_seq(&self) -> Option<u64> {
        self.machine.peer_route_seq()
    }

    /// Sends one `0x0C ROUTE_SET` payload (responder, to a client that sent `route_seq`).
    pub async fn send_route_set(&mut self, payload: &[u8]) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self.machine.send_route_set(payload, now_ms)?;
        self.apply_actions(actions).await
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
/// The client route ingest ([`IngestSlot`]) is never taken while `machine` or `roster` is held;
/// its blocking task takes the ingest, then the roster file lock, then the in-memory roster.
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
    route_ingest: IngestSlot,
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

    /// Sends encrypted `0x0A GROUP_MANIFEST` concurrently with inbound polling.
    pub async fn send_group_manifest(&self, manifest: &GroupManifest) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_group_manifest(manifest, now_ms))
            .await
    }

    /// Sends encrypted `0x0B GROUP_RENDEZVOUS` carrying `secrets` for `group_id`.
    pub async fn send_group_rendezvous(
        &self,
        secrets: &V2GroupSecrets,
        group_id: &str,
    ) -> Result<(), RuntimeError> {
        let frame = secrets.to_rendezvous_frame(group_id)?;
        self.run_write_op(|machine, now_ms| machine.send_group_rendezvous(&frame[..], now_ms))
            .await
    }

    /// Like [`Self::send_data`], but evaluates `authority` while holding the writer lock and
    /// before sealing; an `Err` aborts the write and leaves the session untouched.
    pub async fn send_data_authorized(
        &self,
        payload: &[u8],
        authority: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.run_authorized_write_op(authority, |machine, now_ms| {
            machine.send_data(payload, now_ms)
        })
        .await
    }

    /// Like [`Self::send_group_manifest`], with `authority` evaluated as in
    /// [`Self::send_data_authorized`].
    pub async fn send_group_manifest_authorized(
        &self,
        manifest: &GroupManifest,
        authority: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.run_authorized_write_op(authority, |machine, now_ms| {
            machine.send_group_manifest(manifest, now_ms)
        })
        .await
    }

    /// Like [`Self::send_group_rendezvous`], with `authority` evaluated as in
    /// [`Self::send_data_authorized`].
    pub async fn send_group_rendezvous_authorized(
        &self,
        secrets: &V2GroupSecrets,
        group_id: &str,
        authority: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let frame = secrets.to_rendezvous_frame(group_id)?;
        self.run_authorized_write_op(authority, |machine, now_ms| {
            machine.send_group_rendezvous(&frame[..], now_ms)
        })
        .await
    }

    /// Returns the group gossip summary the initiator advertised in `SessionHello`, if any.
    #[must_use]
    pub fn peer_groups(&self) -> Option<Vec<GroupSeq>> {
        self.machine
            .lock()
            .expect("session machine mutex poisoned")
            .peer_groups()
            .map(<[GroupSeq]>::to_vec)
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
            let (feed_res, route_sets, crls) = {
                let mut machine = self.machine.lock().expect("session machine mutex poisoned");
                let mut roster_guard = roster.lock().expect("roster mutex poisoned");
                let res = machine.feed_bytes(
                    &read_half_ref.recv_buf[..n],
                    now_unix,
                    now_ms,
                    &mut roster_guard,
                );
                let crls = fed_crls(res.as_deref().ok(), machine.peer_device_id(), &roster_guard);
                (res, machine.take_route_sets(), crls)
            };
            // Taken only after the machine and roster mutexes are released (lock order).
            self.route_ingest.note_crls(crls);
            match feed_res {
                Ok(actions) => {
                    let dispatched = self.dispatch_actions_locked(&mut writer, actions).await;
                    drop(writer);
                    self.route_ingest.run(route_sets).await;
                    dispatched?;
                }
                Err(err) => {
                    let _ = writer.close().await;
                    drop(writer);
                    self.event_notify.notify_waiters();
                    self.route_ingest.run(Vec::new()).await;
                    return Err(err.into());
                }
            }
        }
    }

    async fn run_write_op<F>(&self, op: F) -> Result<(), RuntimeError>
    where
        F: FnOnce(&mut SessionMachine, u64) -> Result<Vec<SessionAction>, CoreError>,
    {
        self.run_authorized_write_op(|| Ok(()), op).await
    }

    async fn run_authorized_write_op<A, F>(&self, authority: A, op: F) -> Result<(), RuntimeError>
    where
        A: FnOnce() -> Result<(), RuntimeError>,
        F: FnOnce(&mut SessionMachine, u64) -> Result<Vec<SessionAction>, CoreError>,
    {
        let mut writer = self.writer.lock().await;
        authority()?;
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

    /// The `route_seq` the client sent in `SessionHello` (responder sessions).
    #[must_use]
    pub fn peer_route_seq(&self) -> Option<u64> {
        self.machine
            .lock()
            .expect("session machine mutex poisoned")
            .peer_route_seq()
    }

    /// Routes received `0x0C` route sets to the client ingest; see
    /// [`SessionDriver::set_route_ingest`].
    pub fn set_route_ingest(&self, access: RosterAccess, policy: RoutePolicy) {
        let peer = self.peer_device_id().unwrap_or_default();
        self.route_ingest
            .set(RouteIngest::new(access, peer, policy));
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
    let verify = Arc::new(verify);
    let race = race_verified(dialers, policy_config, candidates, move |cand, stream| {
        let verify = Arc::clone(&verify);
        async move { verify(cand, stream).await.map_err(CandidateError::retry) }
    })
    .await;
    match race.outcome {
        Ok(won) => Ok(won),
        Err(RaceEnd::Fatal(err)) => Err(err),
        Err(RaceEnd::Exhausted) => Err(RuntimeError::Policy("all candidates exhausted")),
        Err(RaceEnd::ChannelClosed) => Err(RuntimeError::Policy("dialer channel closed")),
    }
}

/// Failure of one raced candidate. A `fatal` failure ends the whole race.
pub(crate) struct CandidateError {
    pub(crate) error: RuntimeError,
    pub(crate) fatal: bool,
}

impl CandidateError {
    pub(crate) const fn retry(error: RuntimeError) -> Self {
        Self {
            error,
            fatal: false,
        }
    }

    pub(crate) const fn fatal(error: RuntimeError) -> Self {
        Self { error, fatal: true }
    }
}

impl From<RuntimeError> for CandidateError {
    fn from(error: RuntimeError) -> Self {
        Self::retry(error)
    }
}

impl From<CoreError> for CandidateError {
    fn from(error: CoreError) -> Self {
        Self::retry(error.into())
    }
}

pub(crate) enum RaceEnd {
    Fatal(RuntimeError),
    Exhausted,
    ChannelClosed,
}

/// Result of [`race_verified`]: the winner or why the race ended, and every candidate that
/// failed before that, with its typed error.
pub(crate) struct Race<T> {
    pub(crate) outcome: Result<(CandidateEndpoint, T), RaceEnd>,
    pub(crate) failures: Vec<(CandidateEndpoint, RuntimeError)>,
}

/// The Happy Eyeballs race behind [`dial_with_policy_verified`], keeping each failed candidate's
/// typed error and ending at once on a fatal verifier failure (every in-flight candidate is
/// aborted).
pub(crate) async fn race_verified<T, F, Fut>(
    dialers: &[Arc<dyn PathDialer>],
    policy_config: PathPolicyConfig,
    candidates: Vec<CandidateEndpoint>,
    verify: F,
) -> Race<T>
where
    T: Send + 'static,
    F: Fn(CandidateEndpoint, Box<dyn PathStream>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, CandidateError>> + Send + 'static,
{
    let dialer_map: HashMap<ProviderId, Arc<dyn PathDialer>> = dialers
        .iter()
        .map(|d| (d.provider_id(), Arc::clone(d)))
        .collect();
    let by_id: HashMap<usize, CandidateEndpoint> =
        candidates.iter().map(|c| (c.id, c.clone())).collect();

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

    let (result_tx, mut result_rx) = mpsc::channel::<(usize, Result<T, CandidateError>)>(32);
    let mut in_flight_handles: HashMap<usize, AbortOnDrop> = HashMap::new();
    let mut verified_values: HashMap<usize, T> = HashMap::new();
    let mut failures: Vec<(CandidateEndpoint, RuntimeError)> = Vec::new();
    let end = |outcome, failures| Race { outcome, failures };

    loop {
        for action in planner.drain_actions() {
            match action {
                PlannerAction::DialCandidate(cand) => {
                    let Some(dialer) = dialer_map.get(&cand.provider).cloned() else {
                        let now_ms =
                            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                        planner.on_dial_failed(cand.id, "missing dialer", now_ms);
                        failures.push((cand, RuntimeError::Protocol("missing dialer".to_owned())));
                        continue;
                    };
                    let tx = result_tx.clone();
                    let id = cand.id;
                    let endpoint = cand.addr.clone();
                    let verify_c = Arc::clone(&verifier);
                    let handle = tokio::spawn(async move {
                        let res = match dialer.dial(&endpoint).await {
                            Ok(stream) => verify_c(cand, stream).await,
                            Err(err) => Err(CandidateError::retry(err)),
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
                        return end(Ok((cand, value)), failures);
                    }
                }
                PlannerAction::ProbeBetterPath(_) => {}
                PlannerAction::AllCandidatesExhausted => {
                    in_flight_handles.clear();
                    return end(Err(RaceEnd::Exhausted), failures);
                }
            }
        }

        tokio::select! {
            maybe_res = result_rx.recv() => {
                let Some((id, res)) = maybe_res else {
                    in_flight_handles.clear();
                    return end(Err(RaceEnd::ChannelClosed), failures);
                };
                in_flight_handles.remove(&id);
                let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                match res {
                    Ok(value) => {
                        verified_values.insert(id, value);
                        planner.on_dial_succeeded(id, now_ms);
                    }
                    Err(CandidateError { error, fatal: true }) => {
                        in_flight_handles.clear();
                        return end(Err(RaceEnd::Fatal(error)), failures);
                    }
                    Err(CandidateError { error, fatal: false }) => {
                        planner.on_dial_failed(id, &error.to_string(), now_ms);
                        if let Some(cand) = by_id.get(&id) {
                            failures.push((cand.clone(), error));
                        }
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

/// One raced candidate that failed, with the hint it was built from and its typed error.
#[derive(Debug)]
pub struct CandidateFailure {
    /// The original hint (the candidate's address).
    pub hint: String,
    pub provider: ProviderId,
    pub error: RuntimeError,
}

/// Why a policy pairing attempt or a Day-2 connect failed.
///
/// `error` is the most severe candidate error (`RotationForkDetected` > `PeerRevoked` >
/// `VersionDowngrade` > `HostKeyUnverified` > `InvalidPairingUri` > transport errors) or the
/// error that ended the attempt. `committed` is `true` once any `msg3` byte may have been written
/// (the code may be spent and no other rung was tried). For a Day-2
/// connect it is `true` when a candidate established a session and the attempt failed after
/// that (the final authorization check or its store transaction).
#[derive(Debug)]
pub struct AttemptError {
    pub error: RuntimeError,
    pub committed: bool,
    /// Hints that were never dialed, and candidates whose dial-time egress check refused them.
    pub skipped: Vec<SkippedHint>,
    pub failures: Vec<CandidateFailure>,
}

impl AttemptError {
    fn new(error: impl Into<RuntimeError>) -> Self {
        Self {
            error: error.into(),
            committed: false,
            skipped: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn with_skipped(mut self, skipped: Vec<SkippedHint>) -> Self {
        self.skipped = skipped;
        self
    }

    /// `true` for an uncommitted transport miss a wake retry may fix: the ending error and every
    /// candidate failure are `Io`, `Timeout` or `Closed`. Never for a committed attempt, a core
    /// or policy refusal, relay admission or offline errors, egress refusals, storage errors or
    /// an attempt without dialable routes.
    #[must_use]
    pub fn is_transient_precommit(&self) -> bool {
        const fn transient(err: &RuntimeError) -> bool {
            matches!(
                err,
                RuntimeError::Io(_) | RuntimeError::Timeout(_) | RuntimeError::Closed
            )
        }
        !self.committed
            && transient(&self.error)
            && self.failures.iter().all(|f| transient(&f.error))
    }

    /// `true` for an uncommitted miss a wake may fix: [`Self::is_transient_precommit`], or an
    /// uncommitted attempt whose error and every candidate failure are `Io`, `Timeout`,
    /// `Closed` or a typed relay `offline` refusal ([`RuntimeError::RelayOffline`]). Relay
    /// errors are matched by variant, never by message text.
    #[must_use]
    pub fn is_wakeable_miss(&self) -> bool {
        const fn wakeable(err: &RuntimeError) -> bool {
            matches!(
                err,
                RuntimeError::Io(_)
                    | RuntimeError::Timeout(_)
                    | RuntimeError::Closed
                    | RuntimeError::RelayOffline(_)
            )
        }
        self.is_transient_precommit()
            || (!self.committed
                && wakeable(&self.error)
                && self.failures.iter().all(|f| wakeable(&f.error)))
    }
}

impl std::fmt::Display for AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for AttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<RuntimeError> for AttemptError {
    fn from(error: RuntimeError) -> Self {
        Self::new(error)
    }
}

impl From<CoreError> for AttemptError {
    fn from(error: CoreError) -> Self {
        Self::new(error)
    }
}

impl From<AttemptError> for RuntimeError {
    fn from(err: AttemptError) -> Self {
        err.error
    }
}

/// Severity rank of a candidate error (higher wins).
const fn error_severity(err: &RuntimeError) -> u8 {
    match err {
        RuntimeError::Core(CoreError::RotationForkDetected { .. }) => 6,
        RuntimeError::Core(CoreError::PeerRevoked(_)) => 5,
        RuntimeError::Core(CoreError::VersionDowngrade { .. }) => 4,
        RuntimeError::Core(CoreError::HostKeyUnverified) => 3,
        RuntimeError::Core(CoreError::InvalidPairingUri(_)) => 2,
        _ => 1,
    }
}

/// Splits race failures into typed per-candidate failures and dial-time egress skips.
pub(crate) fn collect_failures(
    raw: Vec<(CandidateEndpoint, RuntimeError)>,
    skipped: &mut Vec<SkippedHint>,
) -> Vec<CandidateFailure> {
    raw.into_iter()
        .map(|(cand, error)| {
            if let Some(reason) = error.skip_reason() {
                skipped.push(SkippedHint::new(cand.addr.clone(), reason));
            }
            CandidateFailure {
                hint: cand.addr,
                provider: cand.provider,
                error,
            }
        })
        .collect()
}

/// Builds the error of an exhausted race from the most severe candidate failure (the earliest
/// among equals), or `fallback` when no candidate failed.
fn exhausted_error(
    failures: Vec<CandidateFailure>,
    skipped: Vec<SkippedHint>,
    fallback: RuntimeError,
) -> AttemptError {
    let error = failures
        .iter()
        .enumerate()
        .max_by_key(|(i, f)| (error_severity(&f.error), std::cmp::Reverse(*i)))
        .map_or(fallback, |(_, f)| clone_runtime_error(&f.error));
    AttemptError {
        error,
        committed: false,
        skipped,
        failures,
    }
}

/// A best-effort copy of `err` for the per-candidate report (I/O errors keep kind and text).
fn clone_runtime_error(err: &RuntimeError) -> RuntimeError {
    match err {
        RuntimeError::Core(e) => RuntimeError::Core(e.clone()),
        RuntimeError::Io(e) => RuntimeError::Io(std::io::Error::new(e.kind(), e.to_string())),
        RuntimeError::Timeout(m) => RuntimeError::Timeout(m),
        RuntimeError::FrameTooLarge { size, max } => RuntimeError::FrameTooLarge {
            size: *size,
            max: *max,
        },
        RuntimeError::RateLimited(m) => RuntimeError::RateLimited(m),
        RuntimeError::Closed => RuntimeError::Closed,
        RuntimeError::Protocol(m) => RuntimeError::Protocol(m.clone()),
        RuntimeError::Policy(m) => RuntimeError::Policy(m),
        RuntimeError::Storage(m) => RuntimeError::Storage(m.clone()),
        RuntimeError::Egress { reason, detail } => RuntimeError::Egress {
            reason: *reason,
            detail: detail.clone(),
        },
        RuntimeError::RelayOffline(kind) => RuntimeError::RelayOffline(*kind),
    }
}

/// Client ingest of the `0x0C` route sets one initiator session receives. Route sets never reach the application event stream.
///
/// CRLs the session accepted (`RevocationUpdated`) are persisted through the same roster handle
/// before any route write, so reloading the latest roster for a route write never drops them.
pub(crate) struct RouteIngest {
    access: RosterAccess,
    peer_id: String,
    policy: RoutePolicy,
    limiter: RouteSetLimiter,
    pending_crls: Vec<(String, RevocationList)>,
}

/// The CRLs one session feed left in `roster` for the client ingest: each one an accepted feed
/// (`actions`) reports, or after a failed feed (`None`) the one `peer` issued. The core ingests
/// a CRL before it fails the session on one that revokes the peer or this device.
pub(crate) fn fed_crls(
    actions: Option<&[SessionAction]>,
    peer: Option<&str>,
    roster: &Roster,
) -> Vec<(String, RevocationList)> {
    let held = |issuer: &str| {
        roster
            .crl(issuer)
            .map(|crl| (issuer.to_owned(), crl.clone()))
    };
    match actions {
        Some(actions) => actions
            .iter()
            .filter_map(|a| match a {
                SessionAction::RevocationUpdated { issuer, .. } => held(issuer),
                _ => None,
            })
            .collect(),
        None => peer.and_then(held).into_iter().collect(),
    }
}

/// The client route ingest of one session, shared with the blocking task that runs it.
///
/// [`Self::run`] persists through the roster file lock and file I/O, so it runs on the
/// blocking pool. Callers never take the slot while holding a session machine or in-memory
/// roster mutex; the blocking task holds it while it takes the roster file lock and then the
/// in-memory roster (module docs of [`crate::announce`]). A cancelled caller leaves the task
/// to finish on its own.
#[derive(Clone, Default)]
pub(crate) struct IngestSlot(Arc<Mutex<Option<RouteIngest>>>);

impl IngestSlot {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<RouteIngest>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn set(&self, ingest: RouteIngest) {
        *self.lock() = Some(ingest);
    }

    /// Queues CRLs for persistence on the next [`Self::run`]; a no-op without an ingest.
    pub(crate) fn note_crls(&self, crls: Vec<(String, RevocationList)>) {
        if crls.is_empty() {
            return;
        }
        if let Some(ingest) = self.lock().as_mut() {
            ingest.pending_crls.extend(crls);
        }
    }

    /// Persists queued CRLs, then ingests `sets` ([`RouteIngest::ingest`]) on the blocking pool.
    pub(crate) async fn run(&self, sets: Vec<RouteSet>) {
        match self.lock().as_ref() {
            Some(ingest) if !sets.is_empty() || !ingest.pending_crls.is_empty() => {}
            _ => return,
        }
        let slot = self.clone();
        let task = tokio::task::spawn_blocking(move || {
            if let Some(ingest) = slot.lock().as_mut() {
                ingest.ingest(sets);
            }
        });
        if let Err(err) = task.await {
            tracing::warn!(%err, "route ingest task failed");
        }
    }
}

impl RouteIngest {
    pub(crate) fn new(access: RosterAccess, peer_id: String, policy: RoutePolicy) -> Self {
        Self {
            access,
            peer_id,
            policy,
            limiter: RouteSetLimiter::new(),
            pending_crls: Vec::new(),
        }
    }

    /// Persists pending CRL evidence, then ingests `sets`. When the evidence cannot be
    /// persisted the sets are dropped (the host's next announcement carries them again).
    pub(crate) fn ingest(&mut self, sets: Vec<RouteSet>) {
        if !self.pending_crls.is_empty() {
            let crls = std::mem::take(&mut self.pending_crls);
            if let Err(err) = self.access.update_if_changed(|roster| {
                let merged = roster.merge_crl_evidence(&crls);
                Ok(((), merged > 0))
            }) {
                tracing::warn!(peer = %self.peer_id, %err, "revocation evidence not persisted");
                // Keep the evidence for the next run; the sets are dropped.
                let newer = std::mem::replace(&mut self.pending_crls, crls);
                self.pending_crls.extend(newer);
                return;
            }
        }
        if sets.is_empty() {
            return;
        }
        if let Err(err) = ingest_route_sets(
            &self.access,
            &self.peer_id,
            sets,
            self.policy,
            &mut self.limiter,
            unix_ms(),
        ) {
            tracing::warn!(peer = %self.peer_id, %err, "route set ingest failed");
        }
    }
}

/// Inputs of [`drive_pair_initiator_with_policy`] and
/// [`crate::v2_driver::drive_v2_pair_initiator_with_policy`].
#[derive(Clone)]
pub struct PairPolicyOptions {
    pub device_name: String,
    pub device_kind: String,
    /// The effective code: the URI code, or an override typed by the user.
    pub code: String,
    /// The scanned pairing URI; its pin, `rp` and route statement apply.
    pub uri: Option<PairingUri>,
    /// Endpoint typed by the local operator: dialed alone and persisted as `operator`.
    pub operator_endpoint: Option<String>,
    /// Host pin for a pairing without a URI.
    pub pinned_host: Option<PinnedHost>,
    /// Display name for the roster entry (default: the URI host name, else the host id).
    pub host_name: Option<String>,
    pub persist: PersistOpts,
    pub dialers: Arc<HintDialers>,
    pub relay_auth_origins: Vec<String>,
    /// Resolver for the egress check (default: the system resolver).
    pub resolver: Option<Arc<dyn HostResolver>>,
    pub policy_config: PathPolicyConfig,
    /// Per-candidate handshake budget from dial to `PairResponse` (Wire v1).
    pub handshake_timeout: Duration,
}

impl std::fmt::Debug for PairPolicyOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairPolicyOptions")
            .field("device_name", &self.device_name)
            .field("code", &"<redacted>")
            .field("uri", &self.uri.as_ref().map(|u| &u.endpoints))
            .field("operator_endpoint", &self.operator_endpoint)
            .field("persist", &self.persist)
            .finish_non_exhaustive()
    }
}

impl PairPolicyOptions {
    /// Options for pairing with `code` through `dialers`, default policy and timeouts.
    #[must_use]
    pub fn new(
        device_name: impl Into<String>,
        device_kind: impl Into<String>,
        code: impl Into<String>,
        dialers: Arc<HintDialers>,
    ) -> Self {
        Self {
            device_name: device_name.into(),
            device_kind: device_kind.into(),
            code: code.into(),
            uri: None,
            operator_endpoint: None,
            pinned_host: None,
            host_name: None,
            persist: PersistOpts::default(),
            dialers,
            relay_auth_origins: Vec::new(),
            resolver: None,
            policy_config: PathPolicyConfig::default(),
            handshake_timeout: DEFAULT_PRE_AUTH_TIMEOUT,
        }
    }
}

/// Successful policy pairing (Wire v1: `D = PairDriveResult`).
#[derive(Debug, Clone)]
pub struct PairPolicyResult<D = PairDriveResult> {
    pub drive: D,
    /// The winning candidate; `addr` is its original hint.
    pub route: CandidateEndpoint,
    pub winner_source: HintSource,
    /// Always `true` on success: `msg3` was written.
    pub committed: bool,
    pub route_check: RouteCheck,
    /// Routes the pairing wrote (empty when nothing was persisted).
    pub routes_persisted: Vec<StoredRoute>,
    /// `unsigned_uri`, `route_key_rotated` or `stale_route_seq` when routes were not written.
    pub routes_reason: Option<&'static str>,
    pub skipped: Vec<SkippedHint>,
}

/// Shared pre-dial work of both pairing drivers.
pub(crate) struct PairingPlan {
    pub(crate) set: CandidateSet,
    pub(crate) pinned: Option<PinnedHost>,
    pub(crate) floor: u8,
    pub(crate) roster: Roster,
    pub(crate) persist: PersistOpts,
    pub(crate) operator_relay_key: Option<[u8; 32]>,
}

pub(crate) async fn plan_pairing(
    store: &RosterAccess,
    opts: &PairPolicyOptions,
    wire: DialWire,
) -> Result<PairingPlan, AttemptError> {
    opts.persist.validate()?;
    let kind = PairingCodeKind::from_code(&opts.code)?;
    let operator = opts
        .operator_endpoint
        .as_deref()
        .map(normalize_operator_endpoint)
        .transpose()?;
    if operator
        .as_ref()
        .is_some_and(|op| is_v2_relay_hint(&op.hint))
    {
        return Err(CoreError::InvalidPairingUri(
            "/v2/relay is not used for pairing; pair over another route, then use dial --relay-v2"
                .into(),
        )
        .into());
    }
    let operator_relay_key = operator.as_ref().and_then(|op| op.relay_key);
    let uri_rp = opts.uri.as_ref().and_then(|u| u.relay_pub);
    if let (Some(a), Some(b)) = (operator_relay_key, uri_rp)
        && a != b
    {
        return Err(CoreError::InvalidPairingUri(
            "operator relay key does not match the URI rp".into(),
        )
        .into());
    }
    let hints: Vec<HintInput> = match (&operator, &opts.uri) {
        (Some(op), _) => vec![HintInput::new(&op.hint, HintSource::Operator)],
        (None, Some(uri)) => uri
            .endpoints
            .iter()
            .map(|h| HintInput::new(h, HintSource::Uri))
            .collect(),
        (None, None) => {
            return Err(CoreError::InvalidPairingUri("no pairing endpoint".into()).into());
        }
    };
    let pinned = opts
        .uri
        .as_ref()
        .map(PairingUri::to_pinned_host)
        .or_else(|| opts.pinned_host.clone());
    let roster = store.load()?;
    let floor = pinned.as_ref().map_or(tendril_core::WIRE_VERSION, |pin| {
        pinned_pairing_floor(&roster, pin)
    });
    if wire == DialWire::V1 && floor > tendril_core::WIRE_VERSION {
        return Err(CoreError::VersionDowngrade {
            peer_min: floor,
            negotiated: tendril_core::WIRE_VERSION,
        }
        .into());
    }
    let mut ctx = opts
        .dialers
        .egress_context(EgressKind::Pairing(kind), opts.relay_auth_origins.clone());
    if let Some(resolver) = &opts.resolver {
        ctx = ctx.with_resolver(Arc::clone(resolver));
    }
    let target = HintTarget::pairing(operator_relay_key.or(uri_rp));
    let multi = MultiDialOptions::new(Arc::clone(&opts.dialers), wire);
    let set = build_pairing_candidates(&hints, &target, &ctx, &multi).await?;
    if set.is_empty() {
        let skipped = set.skipped;
        let error = if kind == PairingCodeKind::Lan2Group
            && !skipped.is_empty()
            && skipped
                .iter()
                .all(|s| s.reason == SkipReason::LanCodeRemoteHint)
        {
            CoreError::PairingPathDisallowed("LAN code on a remote path").into()
        } else {
            RuntimeError::Protocol("no dialable pairing endpoint".to_owned())
        };
        return Err(AttemptError::new(error).with_skipped(skipped));
    }
    let mut persist = opts.persist.clone();
    persist.operator_endpoint = operator.map(|op| op.hint);
    Ok(PairingPlan {
        set,
        pinned,
        floor,
        roster,
        persist,
        operator_relay_key,
    })
}

/// The `rp`, operator relay key and route statement checks of one verified candidate. `Invalid` is fatal for the whole attempt.
pub(crate) fn check_candidate_routes(
    uri: Option<&PairingUri>,
    operator_relay_key: Option<&[u8; 32]>,
    signing_pub: &HybridSigningPublicKey,
) -> Result<RouteCheck, CandidateError> {
    if let Some(uri) = uri {
        uri.check_relay_pub(signing_pub)?;
    }
    if operator_relay_key.is_some_and(|k| k != signing_pub.ed25519_bytes()) {
        return Err(CoreError::HostKeyUnverified.into());
    }
    let check = uri.map_or(RouteCheck::Unsigned(UnsignedReason::Absent), |u| {
        u.verify_route_statement(signing_pub)
    });
    if matches!(check, RouteCheck::Invalid) {
        return Err(CandidateError::fatal(
            CoreError::InvalidPairingUri("route statement does not verify".into()).into(),
        ));
    }
    Ok(check)
}

/// The persistence plan of a successful pairing: the winner's original hint counts only when it
/// is not the explicit operator endpoint.
pub(crate) fn pairing_persist_plan(
    check: &RouteCheck,
    code: &str,
    set: &CandidateSet,
    winner: &CandidateEndpoint,
    persist: &PersistOpts,
) -> (PersistPlan, HintSource) {
    let source = set
        .info(winner.id)
        .map_or(HintSource::Uri, |info| info.source);
    let original = (source != HintSource::Operator)
        .then(|| set.original_hint(winner.id))
        .flatten();
    (persistable_routes(check, code, original, persist), source)
}

/// Wraps a post-commit failure: the attempt is over and the code may be spent.
pub(crate) fn committed_error(
    error: impl Into<RuntimeError>,
    skipped: Vec<SkippedHint>,
    failures: Vec<CandidateFailure>,
) -> AttemptError {
    AttemptError {
        error: error.into(),
        committed: true,
        skipped,
        failures,
    }
}

/// A Wire v1 candidate that verified `HostHello`, the `rp` and the route statement and waits for
/// the single commit.
struct PendingCommit {
    stream: Box<dyn PathStream>,
    machine: PairingInitiator,
    deadline: TokioInstant,
    sas: Option<String>,
    route_check: RouteCheck,
}

/// Feeds `stream` into `machine` until it awaits the commit (`until_commit`) or completes.
async fn run_pair_machine(
    stream: &mut dyn PathStream,
    machine: &mut PairingInitiator,
    deadline: TokioInstant,
    sas: &mut Option<String>,
    until_commit: bool,
) -> Result<Option<PairOutcome>, RuntimeError> {
    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
    loop {
        if until_commit && machine.is_awaiting_commit() {
            return Ok(None);
        }
        let n = match timeout_at(deadline, stream.recv_chunk(&mut buf)).await {
            Ok(res) => res?,
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
        match timeout_at(deadline, dispatch_pair_actions(stream, actions, sas)).await {
            Ok(Ok(Some(outcome))) => return Ok(Some(outcome)),
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

/// Races the hints of a pairing URI (or one explicit operator endpoint) over Wire v1 and
/// commits on the first candidate that verifies.
///
/// Before any dial the effective code is classified (`PairingCodeInvalid`) and every hint
/// passes the egress layer. Each candidate writes `msg1` with a deferred claim and reads `msg2`;
/// the host pin, `rp` and route statement are checked before any `msg3` exists, and an invalid
/// statement ends the whole attempt. The first verified candidate wins, the others are aborted,
/// and the attempt becomes irrevocable immediately before its `msg3` write: after that no other
/// candidate is tried and failures carry `committed: true`. On success the routes the persist
/// options allow are merged into the latest roster under the store lock.
pub async fn drive_pair_initiator_with_policy(
    identity: Arc<EndpointIdentity>,
    store: &RosterAccess,
    opts: PairPolicyOptions,
) -> Result<PairPolicyResult, AttemptError> {
    let plan = plan_pairing(store, &opts, DialWire::V1).await?;
    let PairingPlan {
        set,
        pinned,
        floor,
        roster,
        persist,
        operator_relay_key,
    } = plan;
    let mut skipped = set.skipped.clone();
    let roster = Arc::new(roster);
    let uri = opts.uri.clone().map(Arc::new);
    let code = opts.code.clone();
    let (name, kind, budget) = (
        opts.device_name.clone(),
        opts.device_kind.clone(),
        opts.handshake_timeout,
    );
    let race = race_verified(
        &set.dialers,
        opts.policy_config,
        set.candidates.clone(),
        move |_cand, mut stream| {
            let identity = Arc::clone(&identity);
            let roster = Arc::clone(&roster);
            let uri = uri.clone();
            let (code, name, kind, pinned) =
                (code.clone(), name.clone(), kind.clone(), pinned.clone());
            async move {
                let deadline = TokioInstant::now() + budget;
                let mut machine = PairingInitiator::new_with_min_wire_version(
                    &identity, name, kind, code, pinned, floor, None,
                )?
                .with_roster_floors(&roster)
                .with_deferred_claim();
                let mut sas = None;
                let start = machine.start()?;
                match timeout_at(
                    deadline,
                    dispatch_pair_actions(stream.as_mut(), start, &mut sas),
                )
                .await
                {
                    Ok(res) => {
                        res?;
                    }
                    Err(_) => {
                        return Err(
                            RuntimeError::Timeout("pre-auth pairing handshake timed out").into(),
                        );
                    }
                }
                if let Some(outcome) =
                    run_pair_machine(stream.as_mut(), &mut machine, deadline, &mut sas, true)
                        .await?
                {
                    return Err(RuntimeError::Protocol(format!(
                        "pairing completed before commit: {outcome:?}"
                    ))
                    .into());
                }
                let host = machine
                    .verified_host()
                    .ok_or(CoreError::HostKeyUnverified)?;
                let route_check = check_candidate_routes(
                    uri.as_deref(),
                    operator_relay_key.as_ref(),
                    &host.signing_pub,
                )?;
                Ok(PendingCommit {
                    stream,
                    machine,
                    deadline,
                    sas,
                    route_check,
                })
            }
        },
    )
    .await;
    let failures = collect_failures(race.failures, &mut skipped);
    let (route, pending) = match race.outcome {
        Ok(won) => won,
        Err(RaceEnd::Fatal(err)) => {
            return Err(AttemptError {
                error: err,
                committed: false,
                skipped,
                failures,
            });
        }
        Err(_) => {
            return Err(exhausted_error(
                failures,
                skipped,
                RuntimeError::Policy("all candidates exhausted"),
            ));
        }
    };
    let PendingCommit {
        mut stream,
        mut machine,
        deadline,
        mut sas,
        route_check,
    } = pending;

    let claim = match machine.commit_claim() {
        Ok(actions) => actions,
        Err(err) => {
            let _ = stream.close().await;
            return Err(AttemptError {
                error: err.into(),
                committed: false,
                skipped,
                failures,
            });
        }
    };
    // `timeout_at` polls the write before its timer, so an expired budget is checked here,
    // before any `msg3` byte exists: the attempt is still uncommitted.
    if TokioInstant::now() >= deadline {
        drop(claim);
        let _ = stream.close().await;
        return Err(AttemptError {
            error: RuntimeError::Timeout("pre-auth pairing handshake timed out"),
            committed: false,
            skipped,
            failures,
        });
    }
    // Irrevocable from here: the claim write may deliver any prefix of `msg3`.
    let committed = async {
        match timeout_at(
            deadline,
            dispatch_pair_actions(stream.as_mut(), claim, &mut sas),
        )
        .await
        {
            Ok(Ok(Some(outcome))) => return Ok(outcome),
            Ok(Ok(None)) => {}
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err(RuntimeError::Timeout(
                    "pre-auth pairing handshake timed out",
                ));
            }
        }
        run_pair_machine(stream.as_mut(), &mut machine, deadline, &mut sas, false)
            .await?
            .ok_or(RuntimeError::Closed)
    }
    .await;
    let _ = stream.close().await;
    let outcome = match committed {
        Ok(outcome) => outcome,
        Err(err) => return Err(committed_error(err, skipped, failures)),
    };

    let (plan, winner_source) =
        pairing_persist_plan(&route_check, &opts.code, &set, &route, &persist);
    let mut routes_persisted = Vec::new();
    let mut routes_reason = plan.reason;
    if let PairOutcome::InitiatorPending {
        host_id,
        host_static_pub,
        host_signing_pub,
        host_rotation_seq,
        pairing_sas,
        host_pin_verified,
        ..
    } = &outcome
    {
        let name = opts
            .host_name
            .clone()
            .or_else(|| opts.uri.as_ref().map(|u| u.host_name.clone()))
            .unwrap_or_else(|| host_id.clone());
        let merged = store.update(|roster| {
            let res = if *host_pin_verified {
                roster.insert_pinned_host_with_plan(
                    host_id.clone(),
                    name,
                    *host_static_pub,
                    Some(host_signing_pub.clone()),
                    *host_rotation_seq,
                    &plan,
                )
            } else {
                roster.record_pending_host_with_plan(
                    host_id.clone(),
                    name,
                    *host_static_pub,
                    host_signing_pub.clone(),
                    *host_rotation_seq,
                    pairing_sas.clone(),
                    &plan,
                )
            };
            res.map_err(Into::into)
        });
        match merged {
            Ok(merge) => {
                routes_persisted = merge.persisted;
                routes_reason = merge.reason;
            }
            Err(err) => return Err(committed_error(err, skipped, failures)),
        }
    }
    Ok(PairPolicyResult {
        drive: PairDriveResult { outcome, sas },
        route,
        winner_source,
        committed: true,
        route_check,
        routes_persisted,
        routes_reason,
        skipped,
    })
}

/// Responder sessions carry host route announcements: the payload is sealed by the session
/// machine and written through the session writer. Core errors pass through unchanged, so
/// `FrameTooLarge`, `UnknownInnerFrameType` and `NotReady("peer did not negotiate route sets")`
/// leave the session open.
#[async_trait]
impl RouteSetSink for ConcurrentSession {
    fn peer_id(&self) -> String {
        self.peer_device_id().unwrap_or_default()
    }

    async fn send_route_set(&self, payload: &[u8]) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_route_set(payload, now_ms))
            .await
    }
}

/// Options of a Day-2 connect.
#[derive(Clone)]
pub struct ConnectOpts {
    pub grant: Option<Grant>,
    /// A fresh pairing URI of this peer, exactly as scanned. Its code is never sent; its `k` and
    /// `sh` (and `rp`, `rs`) are checked before session `msg3` on every candidate.
    pub recovery_uri: Option<String>,
    /// Explicit approval: apply the recovery URI's routes even when its `rq` is not newer.
    pub replace_routes: bool,
    pub policy: RoutePolicy,
    /// Endpoint typed by the local operator: replaces the stored routes for this connect.
    pub operator_endpoint: Option<String>,
    pub dialers: Arc<HintDialers>,
    pub relay_auth_origins: Vec<String>,
    /// Resolver for the egress check (default: the system resolver).
    pub resolver: Option<Arc<dyn HostResolver>>,
    pub policy_config: PathPolicyConfig,
}

impl std::fmt::Debug for ConnectOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectOpts")
            .field("recovery_uri", &self.recovery_uri.is_some())
            .field("replace_routes", &self.replace_routes)
            .field("policy", &self.policy)
            .field("operator_endpoint", &self.operator_endpoint)
            .finish_non_exhaustive()
    }
}

impl ConnectOpts {
    /// Endpoint-free connect over the stored routes with the default policy.
    #[must_use]
    pub fn new(dialers: Arc<HintDialers>) -> Self {
        Self {
            grant: None,
            recovery_uri: None,
            replace_routes: false,
            policy: RoutePolicy::default(),
            operator_endpoint: None,
            dialers,
            relay_auth_origins: Vec::new(),
            resolver: None,
            policy_config: PathPolicyConfig::default(),
        }
    }
}

/// What a connect did with the routes of a verified recovery URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryRoutes {
    /// `rq` was newer under `allSigned`: the `signed` routes were replaced.
    Replaced,
    /// Explicit approval replaced the `signed` routes.
    Approved,
    /// Routes unchanged: `stale_route_seq`, `route_policy` or `invalid_routes`.
    Unchanged(&'static str),
}

/// A Day-2 session with the candidate it won on and what else happened.
#[derive(Debug)]
pub struct ConnectResult<S> {
    pub route: CandidateEndpoint,
    pub session: S,
    pub skipped: Vec<SkippedHint>,
    pub failures: Vec<CandidateFailure>,
    /// Set when a recovery URI carried a verified route statement.
    pub recovery_routes: Option<RecoveryRoutes>,
}

/// Pre-dial work of a Day-2 connect under the store lock.
pub(crate) struct ConnectPlan {
    pub(crate) set: CandidateSet,
    pub(crate) roster: Roster,
    pub(crate) snapshot: PinSnapshot,
    pub(crate) expectation: Option<RouteExpectation>,
    pub(crate) route_seq: Option<u64>,
    pub(crate) crl_seq: Option<u64>,
}

const DAY2_RECOVERY_GUIDANCE: &str = "advertise a configured relay as a stable route, or scan a \
                                      fresh signed pairing URI and apply it or connect with it as \
                                      a recovery URI";

pub(crate) async fn plan_connect(
    store: &RosterAccess,
    target: &str,
    opts: &ConnectOpts,
    wire: DialWire,
) -> Result<ConnectPlan, AttemptError> {
    let roster = store.load()?;
    let entry = roster
        .get(target)
        .ok_or_else(|| CoreError::PeerNotFound(target.to_owned()))?;
    // Pre-dial gate: nothing is dialed for a peer the final check would refuse anyway.
    match entry.state {
        PeerState::Pending => return Err(CoreError::PeerPending(target.to_owned()).into()),
        PeerState::Revoked => return Err(CoreError::PeerRevoked(target.to_owned()).into()),
        PeerState::Active if roster.crl_revokes_entry(entry) => {
            return Err(CoreError::PeerRevoked(target.to_owned()).into());
        }
        PeerState::Active => {}
    }
    if wire == DialWire::V2 && entry.v2_secrets.is_none() {
        return Err(CoreError::IncompletePin(target.to_owned()).into());
    }
    if wire == DialWire::V1 {
        check_peer_allows_wire_v1(&roster, target)?;
    }
    let snapshot = roster.pin_snapshot(target)?;
    let operator = opts
        .operator_endpoint
        .as_deref()
        .map(normalize_operator_endpoint)
        .transpose()?;
    let operator_key = operator.as_ref().and_then(|op| op.relay_key);
    let expectation = if opts.recovery_uri.is_some() || operator_key.is_some() {
        Some(RouteExpectation::for_connect(
            target,
            opts.recovery_uri.as_deref(),
            operator_key,
            None,
        )?)
    } else {
        None
    };
    let recovery = expectation
        .as_ref()
        .and_then(RouteExpectation::recovery_uri);
    let hints = session_hint_inputs(entry, recovery, operator.as_ref());
    let relay_key = expectation
        .as_ref()
        .and_then(RouteExpectation::relay_pub)
        .copied()
        .unwrap_or(*snapshot.signing_pub().ed25519_bytes());
    let gate = (wire == DialWire::V2).then(|| RelayV2Gate::authorize(&roster, target));
    let hint_target = HintTarget::session(target, Some(relay_key), gate);
    let mut ctx = opts
        .dialers
        .egress_context(EgressKind::Session, opts.relay_auth_origins.clone());
    if let Some(resolver) = &opts.resolver {
        ctx = ctx.with_resolver(Arc::clone(resolver));
    }
    let multi = MultiDialOptions::new(Arc::clone(&opts.dialers), wire);
    let set = build_pairing_candidates(&hints, &hint_target, &ctx, &multi).await?;
    if set.is_empty() {
        let mut msg = format!("no dialable stored routes for {target}");
        if !entry.relay_hints.is_empty() {
            msg.push_str(
                "; legacy relay hints are never dialed automatically: re-pair, apply a fresh \
                 signed pairing URI, or connect with an explicit endpoint",
            );
        }
        msg.push_str("; ");
        msg.push_str(DAY2_RECOVERY_GUIDANCE);
        return Err(AttemptError::new(RuntimeError::Protocol(msg)).with_skipped(set.skipped));
    }
    let route_seq = entry.hello_route_seq(opts.policy);
    let crl_seq = roster.crl(target).map(|c| c.seq);
    Ok(ConnectPlan {
        set,
        roster,
        snapshot,
        expectation,
        route_seq,
        crl_seq,
    })
}

/// Authenticated evidence every Day-2 candidate collected, whatever its outcome.
#[derive(Debug, Default)]
pub(crate) struct ConnectEvidence {
    records: Vec<RotationRecord>,
    crls: Vec<(String, RevocationList)>,
}

pub(crate) type SharedEvidence = Arc<Mutex<ConnectEvidence>>;

/// Records a candidate's presented rotation and any CRL its roster clone accepted.
pub(crate) fn record_evidence(
    evidence: &SharedEvidence,
    presented: &[RotationRecord],
    clone: &Roster,
    target: &str,
    crl_seq_before: Option<u64>,
) {
    let mut ev = evidence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for record in presented {
        if !ev.records.contains(record) {
            ev.records.push(record.clone());
        }
    }
    if let Some(crl) = clone.crl(target)
        && crl_seq_before.is_none_or(|seq| crl.seq > seq)
    {
        ev.crls.push((target.to_owned(), crl.clone()));
    }
}

/// The keys and statement a Day-2 winner authenticated.
pub(crate) struct WinnerFacts {
    pub(crate) static_pub: [u8; 32],
    pub(crate) signing_pub: HybridSigningPublicKey,
    pub(crate) applied_rotation: Vec<RotationRecord>,
    pub(crate) recovery: Option<VerifiedRouteStatement>,
    pub(crate) wire: u8,
}

fn apply_recovery_routes(
    roster: &mut Roster,
    target: &str,
    statement: &VerifiedRouteStatement,
    policy: RoutePolicy,
    replace_routes: bool,
) -> RecoveryRoutes {
    let res = (|| {
        if policy == RoutePolicy::AllSigned && roster.replace_signed_routes(target, statement)? {
            return Ok(RecoveryRoutes::Replaced);
        }
        if replace_routes {
            roster.replace_routes_approved(target, statement)?;
            return Ok(RecoveryRoutes::Approved);
        }
        Ok::<_, CoreError>(RecoveryRoutes::Unchanged(
            if policy == RoutePolicy::AllSigned {
                "stale_route_seq"
            } else {
                "route_policy"
            },
        ))
    })();
    res.unwrap_or_else(|err| {
        tracing::warn!(peer = target, %err, "recovery routes not applied");
        RecoveryRoutes::Unchanged("invalid_routes")
    })
}

/// Reconciles the evidence of a Day-2 connect and, for a winner, runs the final authorization
/// check, all in one roster transaction against the latest roster.
///
/// Evidence (CRLs, a fork revocation) is persisted whatever the outcome. The inner result is the
/// error that ends the connect, or the recovery route outcome of an authorized winner.
pub(crate) fn finalize_connect(
    store: &RosterAccess,
    target: &str,
    snapshot: &PinSnapshot,
    evidence: &SharedEvidence,
    winner: Option<&WinnerFacts>,
    policy: RoutePolicy,
    replace_routes: bool,
) -> Result<Result<Option<RecoveryRoutes>, RuntimeError>, RuntimeError> {
    let (records, crls) = {
        let ev = evidence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (ev.records.clone(), ev.crls.clone())
    };
    store.update(|roster| {
        roster.merge_crl_evidence(&crls);
        if let Err(err) = roster.reconcile_rotation_evidence(target, snapshot, &records) {
            return Ok(Err(err.into()));
        }
        let Some(w) = winner else {
            return Ok(Ok(None));
        };
        if !w.applied_rotation.is_empty()
            && let Err(err) = roster.apply_verified_rotation(
                target,
                &w.applied_rotation,
                &w.static_pub,
                &w.signing_pub,
            )
        {
            return Ok(Err(err.into()));
        }
        if let Err(err) =
            roster.check_established_session(target, &w.static_pub, &w.signing_pub, w.wire)
        {
            return Ok(Err(err.into()));
        }
        if w.wire >= tendril_core::wire::WIRE_VERSION_V2
            && roster.get(target).is_some_and(|e| e.v2_secrets.is_some())
        {
            roster.set_peer_min_wire_version(target, tendril_core::wire::WIRE_VERSION_V2)?;
        }
        let recovery = w
            .recovery
            .as_ref()
            .map(|s| apply_recovery_routes(roster, target, s, policy, replace_routes));
        Ok(Ok(recovery))
    })
}

/// Classifies a Day-2 candidate failure. An invalid recovery route statement is reported only
/// after the candidate's `k` and `sh` matched the presented host keys, so every candidate would
/// get the same answer: it ends the connect and is never masked by another candidate's error.
pub(crate) fn day2_candidate_error(error: RuntimeError) -> CandidateError {
    if matches!(error, RuntimeError::Core(CoreError::InvalidPairingUri(_))) {
        CandidateError::fatal(error)
    } else {
        CandidateError::retry(error)
    }
}

/// The exhaustion error of a Day-2 connect: a relay-only peer whose mailbox is offline under the
/// pinned key gets the typed rotation message, else the most severe candidate error.
pub(crate) fn connect_exhausted(
    failures: Vec<CandidateFailure>,
    skipped: Vec<SkippedHint>,
    recovery_given: bool,
) -> AttemptError {
    let relay_offline = !recovery_given
        && !failures.is_empty()
        && failures
            .iter()
            .all(|f| f.provider == ProviderId::Relay && f.error.is_relay_offline());
    let mut err = exhausted_error(
        failures,
        skipped,
        RuntimeError::Policy("all candidates exhausted"),
    );
    if relay_offline {
        err.error = RuntimeError::RelayOffline(RelayOffline::PinnedKey);
    }
    err
}

impl SessionDriver {
    /// The endpoint-free Day-2 connect, Wire v1.
    ///
    /// Loads the latest roster, snapshots the pin and builds every candidate first: the entry's
    /// stored routes (never legacy `relay_hints`) and the hints of a signed recovery URI, or only
    /// an explicit operator endpoint; all pass the egress layer. Each candidate verifies
    /// `HostHello` against its own clone of the snapshot roster, with the route expectation of a
    /// recovery URI or operator relay key, and sends `route_seq` under `opts.policy`. Every
    /// candidate's presented rotation records are reconciled against the snapshot under the
    /// store lock on win or exhaustion; a fork revokes the peer. The winner then passes
    /// `check_established_session` on the latest roster before it is returned, and only then
    /// are a verified recovery URI's routes applied. Received route sets are ingested.
    pub async fn connect_with_policy_and_store(
        identity: Arc<EndpointIdentity>,
        target: &str,
        store: &RosterAccess,
        opts: ConnectOpts,
    ) -> Result<ConnectResult<Self>, AttemptError> {
        let plan = plan_connect(store, target, &opts, DialWire::V1).await?;
        let ConnectPlan {
            set,
            roster,
            snapshot,
            expectation,
            route_seq,
            crl_seq,
        } = plan;
        let mut skipped = set.skipped.clone();
        let evidence = SharedEvidence::default();
        let roster = Arc::new(roster);
        let target_owned = target.to_owned();
        let grant = opts.grant.clone();
        let ev = Arc::clone(&evidence);
        let race = race_verified(
            &set.dialers,
            opts.policy_config,
            set.candidates.clone(),
            move |_cand, stream| {
                let identity = Arc::clone(&identity);
                let roster = (*roster).clone();
                let (target, grant, expectation) =
                    (target_owned.clone(), grant.clone(), expectation.clone());
                let ev = Arc::clone(&ev);
                async move {
                    Self::day2_candidate(
                        stream,
                        &identity,
                        &target,
                        grant,
                        crl_seq,
                        expectation,
                        route_seq,
                        roster,
                        &ev,
                    )
                    .await
                    .map_err(day2_candidate_error)
                }
            },
        )
        .await;
        let failures = collect_failures(race.failures, &mut skipped);
        let (route, (mut driver, clone)) = match race.outcome {
            Ok(won) => won,
            Err(end) => {
                if let Err(err) | Ok(Err(err)) = finalize_connect(
                    store,
                    target,
                    &snapshot,
                    &evidence,
                    None,
                    opts.policy,
                    opts.replace_routes,
                ) {
                    return Err(AttemptError {
                        error: err,
                        committed: false,
                        skipped,
                        failures,
                    });
                }
                return Err(match end {
                    RaceEnd::Fatal(err) => AttemptError {
                        error: err,
                        committed: false,
                        skipped,
                        failures,
                    },
                    _ => connect_exhausted(failures, skipped, opts.recovery_uri.is_some()),
                });
            }
        };
        let facts = WinnerFacts {
            static_pub: driver.peer_static_pub().copied().unwrap_or_default(),
            signing_pub: match clone.get(target).and_then(|e| e.signing_pub.clone()) {
                Some(key) => key,
                None => {
                    let _ = driver.stream.close().await;
                    return Err(committed_error(
                        CoreError::IncompletePin(target.to_owned()),
                        skipped,
                        failures,
                    ));
                }
            },
            applied_rotation: driver.applied_rotation().to_vec(),
            recovery: driver.machine.verified_recovery_statement().cloned(),
            wire: tendril_core::WIRE_VERSION,
        };
        let recovery_routes = match finalize_connect(
            store,
            target,
            &snapshot,
            &evidence,
            Some(&facts),
            opts.policy,
            opts.replace_routes,
        ) {
            Ok(Ok(recovery)) => recovery,
            Ok(Err(err)) | Err(err) => {
                let _ = driver.stream.close().await;
                return Err(committed_error(err, skipped, failures));
            }
        };
        // Route sets arrive only when `route_seq` was sent; CRLs the session accepts reach
        // `store` either way.
        driver.set_route_ingest(store.clone(), opts.policy);
        Ok(ConnectResult {
            route,
            session: driver,
            skipped,
            failures,
            recovery_routes,
        })
    }

    /// One Day-2 candidate: a session handshake verified against `roster` (this candidate's own
    /// clone of the snapshot roster). The presented rotation is recorded whatever the outcome.
    #[allow(clippy::too_many_arguments)]
    async fn day2_candidate(
        stream: Box<dyn PathStream>,
        identity: &EndpointIdentity,
        target: &str,
        grant: Option<Grant>,
        crl_seq: Option<u64>,
        expectation: Option<RouteExpectation>,
        route_seq: Option<u64>,
        mut roster: Roster,
        evidence: &SharedEvidence,
    ) -> Result<(Self, Roster), RuntimeError> {
        let mut machine = SessionMachine::new_initiator(identity, target, grant, crl_seq, None)?;
        if let Some(expectation) = expectation {
            machine = machine.with_route_expectation(expectation)?;
        }
        let mut machine = machine.with_route_seq(route_seq)?;
        let start_actions = machine.start()?;
        let mut driver = Self {
            stream,
            machine,
            recv_buf: vec![0u8; MAX_OUTER_FRAME_LEN],
            pending_events: VecDeque::new(),
            started_at: Instant::now(),
            _half_open: None,
            route_ingest: IngestSlot::default(),
        };
        let deadline = TokioInstant::now() + DEFAULT_PRE_AUTH_TIMEOUT;
        let now_unix = current_unix_secs();
        // Evidence is recorded right after each feed, so a candidate aborted once another wins
        // still contributes the `HostHello` it verified.
        let res = async {
            driver.apply_actions(start_actions).await?;
            while !driver.machine.is_established() {
                if driver.machine.is_closed() {
                    return Err(RuntimeError::Closed);
                }
                let n = match timeout_at(deadline, driver.stream.recv_chunk(&mut driver.recv_buf))
                    .await
                {
                    Ok(res) => res?,
                    Err(_) => {
                        return Err(RuntimeError::Timeout(
                            "pre-auth session handshake timed out",
                        ));
                    }
                };
                if n == 0 {
                    return Err(RuntimeError::Closed);
                }
                let now_ms = driver.elapsed_ms();
                let chunk = driver.recv_buf[..n].to_vec();
                let fed = driver
                    .machine
                    .feed_bytes(&chunk, now_unix, now_ms, &mut roster);
                record_evidence(
                    evidence,
                    driver.machine.presented_rotation(),
                    &roster,
                    target,
                    crl_seq,
                );
                driver.apply_actions(fed?).await?;
            }
            Ok(())
        }
        .await;
        if let Err(err) = res {
            let _ = driver.stream.close().await;
            return Err(err);
        }
        Ok((driver, roster))
    }
}

#[cfg(test)]
mod tests {
    use tendril_core::crypto::{SigningKeypair, StaticKeypair};
    use tendril_core::grants::{RevocationListUnsigned, sign_crl};

    use super::*;

    fn identity(tag: u8) -> EndpointIdentity {
        EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([tag; 32]),
            SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
        )
    }

    #[test]
    fn finalize_persists_crl_evidence_with_a_fork_revocation() {
        let base = identity(0x21);
        let fork = |tag: u8| {
            base.clone()
                .rotate(
                    StaticKeypair::from_scalar([tag; 32]),
                    SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
                    1,
                )
                .expect("rotate")
        };
        let (a, b) = (fork(0x31), fork(0x41));
        let id = base.host_id().to_owned();
        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                id.clone(),
                "Studio".into(),
                *base.static_key().public_bytes(),
                Some(base.signing_key().public_key().clone()),
                0,
                Vec::new(),
            )
            .expect("pin");
        let snapshot = roster.pin_snapshot(&id).expect("snapshot");
        let store = RosterAccess::memory(roster);
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: id.clone(),
                seq: 4,
                revoked_devices: vec!["other-device".to_owned()],
                revoked_nonces: vec![],
                ts: "2026-11-22T00:00:00Z".to_owned(),
            },
            base.signing_key(),
        )
        .expect("crl");
        let evidence = SharedEvidence::default();
        {
            let mut ev = evidence.lock().unwrap();
            ev.records = vec![a, b];
            ev.crls = vec![(id.clone(), crl)];
        }

        let res = finalize_connect(
            &store,
            &id,
            &snapshot,
            &evidence,
            None,
            RoutePolicy::AllSigned,
            false,
        )
        .expect("one transaction");
        assert!(
            matches!(
                res,
                Err(RuntimeError::Core(CoreError::RotationForkDetected { .. }))
            ),
            "{res:?}"
        );
        let after = store.load().expect("roster");
        assert_eq!(after.get(&id).expect("entry").state, PeerState::Revoked);
        assert_eq!(after.crl(&id).map(|c| c.seq), Some(4), "CRL merged");
    }

    #[test]
    fn route_ingest_keeps_crl_evidence_when_the_store_fails() {
        let id = identity(0x51);
        let dir = tempfile::tempdir().expect("dir");
        let root = dir.path().join("state");
        let store = StateStore::open_or_create(&root).expect("store");
        let access = RosterAccess::from_store(Arc::new(store)).expect("access");
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: id.host_id().to_owned(),
                seq: 2,
                revoked_devices: vec!["other-device".to_owned()],
                revoked_nonces: vec![],
                ts: "2026-11-22T00:00:00Z".to_owned(),
            },
            id.signing_key(),
        )
        .expect("crl");
        let mut ingest = RouteIngest::new(access, "peer".into(), RoutePolicy::AllSigned);
        ingest.pending_crls.push((id.host_id().to_owned(), crl));
        std::fs::remove_dir_all(&root).expect("remove state dir");
        ingest.ingest(Vec::new());
        assert_eq!(
            ingest.pending_crls.len(),
            1,
            "evidence kept for the next run"
        );
    }
}
