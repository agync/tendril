//! Async drivers binding `tendril-core` pairing, session, and path planning state machines
//! to concrete [`PathStream`] and [`PathDialer`] transports.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
#[cfg(feature = "webrtc")]
use tendril_core::UPGRADE_CAP_WEBRTC_V1;
use tendril_core::crypto::HybridSigningPublicKey;
use tendril_core::error::CoreError;
use tendril_core::grants::{AuditEvent, Grant, RevocationList};
use tendril_core::group::{GroupManifest, GroupRendezvousFrame, GroupSeq, V2GroupSecrets};
use tendril_core::identity::{EndpointIdentity, RotationRecord};
use tendril_core::pairing::{
    EnrollmentPolicy, EnrollmentRouteReject, EnrollmentRoutes, PairAction, PairOutcome,
    PairRouteBinding, PairRouteVerdict, PairingCodeKind, PairingInitiator, PairingManager,
    PairingPathKind, PairingResponder, PairingUri, PersistOpts, PersistPlan, PinnedHost,
    RouteCheck, RoutePolicy, VerifiedHost, VerifiedRouteStatement, is_v2_relay_hint,
    persistable_routes,
};
use tendril_core::policy::{
    CandidateEndpoint, PathPlanner, PathPolicyConfig, PlannerAction, ProviderId,
};
use tendril_core::roster::{
    PeerState, PinSnapshot, Roster, RouteSetIgnored, RouteSetOutcome, RouteSource, StoredRoute,
};
use tendril_core::routes::RouteSet;
use tendril_core::session::{
    RekeyDirection, RouteExpectation, SessionAction, SessionCloseCode, SessionMachine,
    check_peer_allows_wire_v1,
};
use tendril_core::wire::{Intent, PathUpgradeMsg, Preamble};
use tendril_core::{MAX_FRAME_LEN, PREAMBLE_LEN};
use tendril_core::{RefusalMode, RefusalReason};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::AbortHandle;
use tokio::time::{Instant as TokioInstant, timeout, timeout_at};

use crate::announce::{RosterAccess, RouteSetLimiter, RouteSetSink, ingest_route_sets, unix_ms};
use crate::error::{RelayOffline, RuntimeError};
use crate::power::{IdleActivity, PowerProfile};
use crate::provider::{MAX_OUTER_FRAME_LEN, PathDialer, PathReader, PathStream, PathWriter};
use crate::providers::egress::{
    EgressKind, HintSource, HostResolver, LocalReachability, SkipReason, SkippedHint,
};
use crate::providers::hints::{
    CandidateSet, DialWire, HintDialers, HintInput, HintTarget, MultiDialOptions, RelayV2Gate,
    build_pairing_candidates, normalize_operator_endpoint, normalize_peer_routes,
    session_hint_inputs,
};
#[cfg(feature = "webrtc")]
use crate::providers::webrtc::WebRtcUpgradeHandle;
use crate::rate_limit::{HalfOpenGuard, PreAuthRateLimiter, RefusalState};
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
        // The accept path writes the frame and ends the connection before it applies a batch
        // that carries this, and an established session never emits it. Kept as a close so no
        // refusal can leave a session open.
        SessionAction::Refused { code, .. } => {
            pending_events.push_back(SessionEvent::Closed {
                code,
                reason: String::new(),
            });
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
        SessionAction::PathUpgradeReceived(msg) => {
            pending_events.push_back(SessionEvent::PathUpgrade(msg));
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
    /// Received `0x0D PATH_UPGRADE` signaling message.
    PathUpgrade(PathUpgradeMsg),
    Closed {
        code: u16,
        reason: String,
    },
}

pub(crate) const fn is_application_event(event: &SessionEvent) -> bool {
    matches!(
        event,
        SessionEvent::AppData(_)
            | SessionEvent::GrantUpdated(_)
            | SessionEvent::RevocationUpdated { .. }
            | SessionEvent::GroupManifestReceived(_)
            | SessionEvent::GroupRendezvousReceived(_)
    )
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

/// Resolves the highest persisted `min_wire_version` floor matching `pin`: every entry and
/// unconfirmed host claim holding its static key ([`Roster::pairing_floor`]), and a confirmed
/// entry under its label.
#[must_use]
pub fn pinned_pairing_floor(roster: &Roster, pin: &PinnedHost) -> u8 {
    let static_floor = roster.pairing_floor(&pin.static_pub);
    let host_floor = pin
        .host_id
        .as_deref()
        .and_then(|id| roster.get(id))
        .filter(|e| confirmed_entry(roster, e))
        .map_or(tendril_core::WIRE_VERSION, |e| e.min_wire_version);
    static_floor.max(host_floor)
}

/// An entry an enrolment pin may rely on: `Active` and not revoked by a stored CRL.
fn confirmed_entry(roster: &Roster, entry: &tendril_core::roster::RosterEntry) -> bool {
    entry.state == PeerState::Active && !roster.crl_revokes_entry(entry)
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
    let mut machine =
        PairingInitiator::new(identity, device_name, device_kind, code, pinned_host, None)?;
    drive_pairing_initiator_machine(stream, &mut machine, handshake_timeout).await
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
    let mut machine = PairingInitiator::new_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        code,
        pinned_host,
        min_wire_version,
        None,
    )?;
    drive_pairing_initiator_machine(stream, &mut machine, handshake_timeout).await
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
    let mut machine = PairingInitiator::new_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        code,
        pinned_host,
        floor,
        None,
    )?
    .with_roster_floors(&roster);
    drive_pairing_initiator_machine(stream, &mut machine, handshake_timeout).await
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
    let mut machine = PairingInitiator::new_m2m(
        identity,
        device_name,
        device_kind,
        enrollment_token,
        pinned_host,
        None,
    )?;
    drive_pairing_initiator_machine(stream, &mut machine, handshake_timeout).await
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
    let mut machine = PairingInitiator::new_m2m_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        enrollment_token,
        pinned_host,
        min_wire_version,
        None,
    )?;
    drive_pairing_initiator_machine(stream, &mut machine, handshake_timeout).await
}

/// Drives a v1 M2M enrollment initiator while enforcing any persisted `min_wire_version` floor
/// from `store`, then pins the host in `store`.
///
/// [`drive_m2m_enroll_initiator_with_routes`] with [`RoutePolicy::None`] and no operator
/// endpoint: no route set is requested (the claim carries no `route_seq`, so older hosts accept
/// it) and no route is stored. Callers that want Day-2 routes use
/// [`drive_m2m_enroll_initiator_with_routes`] with their route policy and endpoint.
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
    let opts = M2mEnrollOptions {
        operator_endpoint: None,
        policy: RoutePolicy::None,
        handshake_timeout,
    };
    let res = drive_m2m_enroll_initiator_with_routes(
        stream,
        identity,
        device_name,
        device_kind,
        enrollment_token,
        pinned_host,
        store,
        opts,
    )
    .await?;
    for warning in &res.route_warnings {
        tracing::warn!(reason = warning.as_str(), %warning, "m2m enrolment route not stored");
    }
    Ok(res.drive)
}

/// Options of [`drive_m2m_enroll_initiator_with_routes`].
#[derive(Debug, Clone)]
pub struct M2mEnrollOptions {
    /// The endpoint the operator dialed for this enrolment, exactly as typed. Unless `policy` is
    /// [`RoutePolicy::None`] it is stored, after operator normalization, as the host's
    /// `committed` route on every successful enrolment, replacing any earlier one. Never pass
    /// a hint-derived or redirected endpoint.
    pub operator_endpoint: Option<String>,
    /// Route policy. The host's route set is requested only under [`RoutePolicy::AllSigned`];
    /// [`RoutePolicy::None`] stores no route at all.
    pub policy: RoutePolicy,
    /// Budget for the whole pre-auth handshake, from `msg1` to `PairResponse`.
    pub handshake_timeout: Duration,
}

impl Default for M2mEnrollOptions {
    fn default() -> Self {
        Self {
            operator_endpoint: None,
            policy: RoutePolicy::default(),
            handshake_timeout: DEFAULT_PRE_AUTH_TIMEOUT,
        }
    }
}

/// A route of a successful M2M enrolment that was not stored. The enrolment stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollRouteWarning {
    /// `PairResponse.route_set` failed verification and was dropped.
    RouteSetRejected(EnrollmentRouteReject),
    /// The verified set was not applied (`spec/pairing-v1.md` Section 6.11.3).
    RouteSetIgnored(RouteSetIgnored),
    /// The roster refused the verified set's routes.
    RouteSetRefused(String),
    /// The operator endpoint was not stored as the `committed` route.
    OperatorEndpointRefused(String),
}

impl EnrollRouteWarning {
    /// Snake-case reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RouteSetRejected(r) => r.as_str(),
            Self::RouteSetIgnored(r) => r.as_str(),
            Self::RouteSetRefused(_) => "route_set_refused",
            Self::OperatorEndpointRefused(_) => "operator_endpoint_refused",
        }
    }
}

impl std::fmt::Display for EnrollRouteWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RouteSetRejected(r) => write!(f, "route set rejected: {}", r.as_str()),
            Self::RouteSetIgnored(r) => write!(f, "route set ignored: {}", r.as_str()),
            Self::RouteSetRefused(detail) => write!(f, "route set refused: {detail}"),
            Self::OperatorEndpointRefused(detail) => {
                write!(f, "operator endpoint not stored: {detail}")
            }
        }
    }
}

/// A completed M2M enrolment and the routes it stored.
#[derive(Debug, Clone)]
pub struct M2mEnrollResult {
    /// The handshake outcome: `InitiatorEnrolled`, or `Rejected` with the host's error code.
    pub drive: PairDriveResult,
    /// The reply's route set result; `None` when it was not requested.
    pub route_set: Option<EnrollmentRoutes>,
    /// Routes this enrolment wrote for the host, `signed` first.
    pub routes_persisted: Vec<StoredRoute>,
    /// Routes that were not stored, with the reason; the enrolment succeeded regardless.
    pub route_warnings: Vec<EnrollRouteWarning>,
}

/// Drives a v1 M2M enrollment initiator with `store`'s `min_wire_version` floor and, on success,
/// pins the host as `Active` and stores its Day-2 routes in one roster transaction
/// (`spec/pairing-v1.md` Section 7.5).
///
/// Before any byte is sent, the pin is checked against the stored roster (a revoked key or
/// label, or keys that differ from an entry at the same or an older rotation), and a pin older
/// than the stored entry is replaced by the stored keys. The claim is deferred: the host `msg2`
/// authenticated is dry-run through the pin write before `msg3`, so a local conflict never
/// spends the token. Under [`RoutePolicy::AllSigned`] the claim requests the
/// host's route set; a set verified against the host keys checked at `msg2` is applied by the
/// route announcement acceptance rules as `signed`. Unless the policy is [`RoutePolicy::None`],
/// `opts.operator_endpoint` is stored as the `committed` route, replacing any earlier one.
/// Route failures never fail the enrolment: they are returned as warnings and the pin is still
/// written. A pin conflict found after the handshake is an error.
#[allow(clippy::too_many_arguments)]
pub async fn drive_m2m_enroll_initiator_with_routes(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    enrollment_token: Grant,
    pinned_host: PinnedHost,
    store: &StateStore,
    opts: M2mEnrollOptions,
) -> Result<M2mEnrollResult, RuntimeError> {
    let roster = store.load_roster()?;
    check_enrollment_pin(&roster, &pinned_host)?;
    let floor = pinned_pairing_floor(&roster, &pinned_host);
    let request = (opts.policy == RoutePolicy::AllSigned).then(|| {
        pinned_entry(&roster, &pinned_host)
            .and_then(|e| e.hello_route_seq(opts.policy))
            .unwrap_or(0)
    });
    let pinned_host = stricter_stored_pin(&roster, pinned_host);
    drop(roster);
    let mut machine = PairingInitiator::new_m2m_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        enrollment_token,
        pinned_host,
        floor,
        None,
    )?
    .with_deferred_claim();
    if let Some(route_seq) = request {
        machine = machine.with_enrollment_routes(route_seq)?;
    }
    let drive =
        drive_enrollment_machine(stream, &mut machine, store, opts.handshake_timeout).await?;
    let route_set = machine.enrollment_routes().cloned();
    let PairOutcome::InitiatorEnrolled {
        host_id,
        host_static_pub,
        host_signing_pub,
        host_rotation_seq,
        ..
    } = &drive.outcome
    else {
        return Ok(M2mEnrollResult {
            drive,
            route_set,
            routes_persisted: Vec::new(),
            route_warnings: Vec::new(),
        });
    };
    let now = current_unix_secs();
    let (routes_persisted, route_warnings) = store.update_roster(|roster| {
        let name = roster
            .get(host_id)
            .map_or_else(|| host_id.clone(), |e| e.name.clone());
        roster.insert_pinned_host(
            host_id.clone(),
            name,
            *host_static_pub,
            Some(host_signing_pub.clone()),
            *host_rotation_seq,
            Vec::new(),
        )?;
        Ok(store_enrollment_routes(
            roster,
            host_id,
            route_set.as_ref(),
            opts.operator_endpoint.as_deref(),
            opts.policy,
            now,
        ))
    })?;
    Ok(M2mEnrollResult {
        drive,
        route_set,
        routes_persisted,
        route_warnings,
    })
}

/// Drives a deferred-claim M2M machine: after `msg2` verifies and before any `msg3` byte, the
/// host the handshake actually authenticated is dry-run through the pin write on the latest
/// roster, so a conflict (revoked label, keys or Ed25519 half, CRL, another key under the same
/// `host_id`) ends the attempt with the token unspent.
async fn drive_enrollment_machine(
    stream: &mut dyn PathStream,
    machine: &mut PairingInitiator,
    store: &StateStore,
    handshake_timeout: Duration,
) -> Result<PairDriveResult, RuntimeError> {
    let deadline = TokioInstant::now() + handshake_timeout;
    let mut sas = None;
    let start = machine.start()?;
    match timeout_at(deadline, dispatch_pair_actions(stream, start, &mut sas)).await {
        Ok(res) => {
            res?;
        }
        Err(_) => {
            let _ = stream.close().await;
            return Err(RuntimeError::Timeout(
                "pre-auth pairing handshake timed out",
            ));
        }
    }
    if let Some(outcome) = run_pair_machine(stream, machine, deadline, &mut sas, true).await? {
        return Ok(PairDriveResult { outcome, sas });
    }
    let host = machine
        .verified_host()
        .ok_or(CoreError::HostKeyUnverified)?;
    if let Err(err) = check_enrolled_host(&store.load_roster()?, &host) {
        let _ = stream.close().await;
        return Err(err);
    }
    let claim = machine.commit_claim()?;
    let outcome = match timeout_at(deadline, dispatch_pair_actions(stream, claim, &mut sas)).await {
        Ok(Ok(Some(outcome))) => outcome,
        Ok(Ok(None)) => run_pair_machine(stream, machine, deadline, &mut sas, false)
            .await?
            .ok_or(RuntimeError::Closed)?,
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            let _ = stream.close().await;
            return Err(RuntimeError::Timeout(
                "pre-auth pairing handshake timed out",
            ));
        }
    };
    Ok(PairDriveResult { outcome, sas })
}

/// Dry-runs the post-enrolment pin write for the host `msg2` authenticated.
fn check_enrolled_host(roster: &Roster, host: &VerifiedHost) -> Result<(), RuntimeError> {
    let mut staged = roster.clone();
    let name = staged
        .get(&host.host_id)
        .map_or_else(|| host.host_id.clone(), |e| e.name.clone());
    staged.insert_pinned_host(
        host.host_id.clone(),
        name,
        host.static_pub,
        Some(host.signing_pub.clone()),
        host.rotation_seq,
        Vec::new(),
    )?;
    Ok(())
}

/// The stored entry's keys as the pin when the roster already holds the pinned host at a newer
/// rotation: an older pin would accept a key the host has rotated away from.
fn stricter_stored_pin(roster: &Roster, pin: PinnedHost) -> PinnedHost {
    match pinned_entry(roster, &pin) {
        Some(entry) if entry.rotation_seq > pin.rotation_seq => match &entry.signing_pub {
            Some(signing) => PinnedHost::with_full_key(
                pin.host_id.clone(),
                entry.static_pub,
                signing.clone(),
                entry.rotation_seq,
            ),
            None => pin,
        },
        _ => pin,
    }
}

/// The confirmed stored entry a pin names: by `host_id`, else the entry holding its static key.
/// Unconfirmed and CRL-revoked entries never shape a pin.
fn pinned_entry<'a>(
    roster: &'a Roster,
    pin: &PinnedHost,
) -> Option<&'a tendril_core::roster::RosterEntry> {
    match &pin.host_id {
        Some(id) => roster.get(id).filter(|e| confirmed_entry(roster, e)),
        None => roster
            .entries()
            .map(|(_, e)| e)
            .find(|e| e.static_pub == pin.static_pub && confirmed_entry(roster, e)),
    }
}

/// Refuses, before the handshake, a pin that the post-enrolment pin write is certain to refuse:
/// a revoked entry, CRL or trust anchor sharing its label or keys, or a stored entry at the same
/// or an older rotation whose keys differ. A pin older than the stored entry is replaced by the
/// stored keys ([`stricter_stored_pin`]), and the host `msg2` authenticates is checked again
/// before `msg3` ([`check_enrolled_host`]).
fn check_enrollment_pin(roster: &Roster, pin: &PinnedHost) -> Result<(), RuntimeError> {
    let label = pin
        .host_id
        .clone()
        .unwrap_or_else(|| tendril_core::crypto::device_id(&pin.static_pub));
    let shares_key = |entry: &tendril_core::roster::RosterEntry| {
        entry.static_pub == pin.static_pub
            || entry
                .signing_pub
                .as_ref()
                .is_some_and(|s| pin.signing_pin.matches(s))
    };
    let revoked = roster
        .entries()
        .any(|(id, e)| e.state == PeerState::Revoked && (*id == label || shares_key(e)))
        || roster.crl_revokes_identity(&label, &pin.static_pub)
        || roster.trust_anchors().any(|(_, a)| {
            a.state == tendril_core::roster::AnchorState::Revoked
                && pin.signing_pin.matches(&a.signing_pub)
        });
    if revoked {
        return Err(CoreError::PeerRevoked(label).into());
    }
    if let Some(entry) = pinned_entry(roster, pin)
        && pin.rotation_seq >= entry.rotation_seq
    {
        let same_keys = entry.static_pub == pin.static_pub
            && entry
                .signing_pub
                .as_ref()
                .is_none_or(|s| pin.signing_pin.matches(s));
        if !same_keys {
            return Err(CoreError::ProtocolViolation(
                "cannot overwrite pinned host keys; rotate or revoke existing pin first",
            )
            .into());
        }
    }
    Ok(())
}

/// Applies an enrolment's routes to the freshly pinned `host_id`. Each step runs on a staged
/// copy, so a refused step leaves the roster as the previous step wrote it.
fn store_enrollment_routes(
    roster: &mut Roster,
    host_id: &str,
    route_set: Option<&EnrollmentRoutes>,
    operator_endpoint: Option<&str>,
    policy: RoutePolicy,
    now_unix: u64,
) -> (Vec<StoredRoute>, Vec<EnrollRouteWarning>) {
    let mut persisted = Vec::new();
    let mut warnings = Vec::new();
    match route_set {
        Some(EnrollmentRoutes::Verified(_)) if policy != RoutePolicy::AllSigned => {}
        Some(EnrollmentRoutes::Verified(set)) => {
            let mut staged = roster.clone();
            match staged.apply_route_announcement(host_id, set, now_unix) {
                Ok(RouteSetOutcome::Applied { .. }) => {
                    *roster = staged;
                    persisted.extend(set.routes.iter().map(|hint| StoredRoute {
                        hint: hint.clone(),
                        source: RouteSource::Signed,
                    }));
                }
                Ok(RouteSetOutcome::Ignored(reason)) => {
                    warnings.push(EnrollRouteWarning::RouteSetIgnored(reason));
                }
                Err(err) => warnings.push(EnrollRouteWarning::RouteSetRefused(err.to_string())),
            }
        }
        Some(EnrollmentRoutes::Rejected(reason)) => {
            warnings.push(EnrollRouteWarning::RouteSetRejected(*reason));
        }
        Some(EnrollmentRoutes::Absent) | None => {}
    }
    if policy != RoutePolicy::None
        && let Some(raw) = operator_endpoint
    {
        match store_committed_endpoint(roster, host_id, raw) {
            Ok(hint) => persisted.push(StoredRoute {
                hint,
                source: RouteSource::Committed,
            }),
            Err(err) => {
                warnings.push(EnrollRouteWarning::OperatorEndpointRefused(err.to_string()));
            }
        }
    }
    (persisted, warnings)
}

/// Stores the enrolment's operator endpoint as the `committed` route of `host_id`, replacing
/// any earlier one, after the checks an operator route gets plus two Day-2 requirements: a
/// `URL#key` must name the pinned host's Ed25519 key, and a `direct:` hint must be an IP literal.
fn store_committed_endpoint(
    roster: &mut Roster,
    host_id: &str,
    raw: &str,
) -> Result<String, RuntimeError> {
    let op = normalize_peer_routes(&[raw.to_owned()])?
        .pop()
        .ok_or_else(|| RuntimeError::Protocol("no operator endpoint".to_owned()))?;
    if let Some(key) = op.relay_key {
        let matches = roster
            .get(host_id)
            .and_then(|e| e.signing_pub.as_ref())
            .is_some_and(|s| *s.ed25519_bytes() == key);
        if !matches {
            return Err(CoreError::InvalidPairingUri(
                "relay key does not match the pinned host key".into(),
            )
            .into());
        }
    }
    if let Some(target) = op.hint.strip_prefix("direct:")
        && target.parse::<std::net::SocketAddr>().is_err()
    {
        return Err(CoreError::InvalidPairingUri(
            "direct endpoint must be an IP literal to be dialed on Day 2".into(),
        )
        .into());
    }
    let mut plan = PersistPlan::default();
    plan.committed = Some(op.hint.clone());
    let mut staged = roster.clone();
    staged.merge_pair_plan(host_id, &plan)?;
    *roster = staged;
    Ok(op.hint)
}

async fn drive_pairing_initiator_machine(
    stream: &mut dyn PathStream,
    machine: &mut PairingInitiator,
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
    crate::store::ensure_valid_local_host_id(identity)?;
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
    activity: IdleActivity,
    /// `true` for a session this side dialed: only an initiator maps a refusal close code.
    initiator: bool,
    /// The endpoint's refusal state on a refusal-enabled responder.
    refusal: Option<RefusalState>,
    /// A refusal the responder machine sent, held until the accept path ends the connection.
    refused: Option<(String, u16)>,
    #[cfg(feature = "webrtc")]
    webrtc_upgrade_handle: Option<WebRtcUpgradeHandle>,
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
        Self::connect_with_upgrade_caps(
            stream,
            local_identity,
            target_host_id,
            initial_grant,
            roster,
            now_unix,
            Vec::new(),
        )
        .await
    }

    /// Initiates a Noise XX session handshake advertising `upgrade_caps` in `SessionHello.upgrade`.
    pub async fn connect_with_upgrade_caps(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        roster: &mut Roster,
        now_unix: u64,
        upgrade_caps: Vec<String>,
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
            upgrade_caps,
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
            Vec::new(),
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
        Self::connect_locked_with_upgrade_caps(
            stream,
            local_identity,
            target_host_id,
            initial_grant,
            roster,
            now_unix,
            Vec::new(),
        )
        .await
    }

    /// Initiates a Noise XX session handshake with a mutex-guarded roster advertising `upgrade_caps`.
    pub async fn connect_locked_with_upgrade_caps(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        roster: &Mutex<Roster>,
        now_unix: u64,
        upgrade_caps: Vec<String>,
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
            upgrade_caps,
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
        dial_with_policy_candidates(dialers, policy_config, candidates, move |cand, dialer| {
            let id_c = Arc::clone(&local_identity);
            let target_c = target_owned.clone();
            let grant_c = initial_grant.clone();
            let roster_c = Arc::clone(&shared_roster);
            async move {
                let crl_seq = roster_c
                    .lock()
                    .expect("roster mutex poisoned")
                    .crl(&target_c)
                    .map(|c| c.seq);
                Self::connect_with_source(
                    StreamSource::Dial {
                        dialer: &*dialer,
                        addr: &cand.addr,
                    },
                    &id_c,
                    &target_c,
                    grant_c,
                    crl_seq,
                    RosterRef::Locked(&roster_c),
                    now_unix,
                    Vec::new(),
                    Vec::new(),
                )
                .await
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
        roster: RosterRef<'_>,
        now_unix: u64,
        groups: Vec<GroupSeq>,
        upgrade_caps: Vec<String>,
    ) -> Result<Self, RuntimeError> {
        Self::connect_with_source(
            StreamSource::Stream(stream),
            local_identity,
            target_host_id,
            initial_grant,
            crl_seq,
            roster,
            now_unix,
            groups,
            upgrade_caps,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_source(
        source: StreamSource<'_>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        crl_seq: Option<u64>,
        mut roster: RosterRef<'_>,
        now_unix: u64,
        groups: Vec<GroupSeq>,
        upgrade_caps: Vec<String>,
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
        let upgrade_caps = if source.provider_id() == ProviderId::P2p {
            Vec::new()
        } else {
            upgrade_caps
        };
        let mut machine = machine.with_upgrade_caps(upgrade_caps)?;
        let start_actions = machine.start()?;
        let init_bytes = match start_actions.as_slice() {
            [SessionAction::WriteBytes(bytes)] if !bytes.is_empty() => Some(bytes.as_slice()),
            _ => None,
        };
        let (stream, fast_open_sent) = dial_source_with_init(source, init_bytes).await?;
        let mut driver = Self {
            stream,
            machine,
            recv_buf: vec![0u8; MAX_OUTER_FRAME_LEN],
            pending_events: VecDeque::new(),
            started_at: Instant::now(),
            _half_open: None,
            route_ingest: IngestSlot::default(),
            activity: IdleActivity::default(),
            initiator: true,
            refusal: None,
            refused: None,
            #[cfg(feature = "webrtc")]
            webrtc_upgrade_handle: None,
        };
        if !fast_open_sent {
            driver.apply_actions(start_actions).await?;
        }
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
        Self::accept_with_upgrade_caps(
            stream,
            local_identity,
            roster,
            now_unix,
            rate_limiter,
            existing_guard,
            handshake_timeout,
            Vec::new(),
        )
        .await
    }

    /// Accepts an inbound Noise XX session handshake advertising `upgrade_caps` in `HostHello.upgrade`.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_with_upgrade_caps(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &mut Roster,
        now_unix: u64,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
        upgrade_caps: Vec<String>,
    ) -> Result<Self, RuntimeError> {
        Self::accept_with_roster(
            stream,
            local_identity,
            RosterRef::Direct(roster),
            now_unix,
            rate_limiter,
            existing_guard,
            handshake_timeout,
            upgrade_caps,
            rate_limiter.map(|rl| rl.refusal_state().clone()),
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
        Self::accept_locked_with_upgrade_caps(
            stream,
            local_identity,
            roster,
            now_unix,
            rate_limiter,
            existing_guard,
            handshake_timeout,
            Vec::new(),
        )
        .await
    }

    /// Accepts an inbound Noise XX session handshake with a mutex-guarded roster and `upgrade_caps`.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_locked_with_upgrade_caps(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &Mutex<Roster>,
        now_unix: u64,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
        upgrade_caps: Vec<String>,
    ) -> Result<Self, RuntimeError> {
        Self::accept_with_roster(
            stream,
            local_identity,
            RosterRef::Locked(roster),
            now_unix,
            rate_limiter,
            existing_guard,
            handshake_timeout,
            upgrade_caps,
            rate_limiter.map(|rl| rl.refusal_state().clone()),
        )
        .await
    }

    /// Accepts an inbound Noise XX session handshake with a mutex-guarded roster and an explicit
    /// refusal listener mode.
    ///
    /// `refusal` is the endpoint's [`RefusalState`] for a listener that may refuse a known
    /// revoked or pending peer (`spec/wire-v1.md` Section 5.4.3), or `None` for a listener that
    /// never does: a group pool, a standalone group listener or a group mailbox. The other
    /// `accept*` constructors take the state from `rate_limiter`, and refuse only when one is
    /// given.
    ///
    /// A refused peer gets one `0x07 CLOSE` frame, its half-open slot is released at once, and
    /// the connection drains in the background; this call then fails with
    /// [`CoreError::PeerRevoked`] or [`CoreError::PeerPending`], so the accept loop continues.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_locked_with_refusal(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &Mutex<Roster>,
        now_unix: u64,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
        upgrade_caps: Vec<String>,
        refusal: Option<&RefusalState>,
    ) -> Result<Self, RuntimeError> {
        Self::accept_with_roster(
            stream,
            local_identity,
            RosterRef::Locked(roster),
            now_unix,
            rate_limiter,
            existing_guard,
            handshake_timeout,
            upgrade_caps,
            refusal.cloned(),
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
        upgrade_caps: Vec<String>,
        refusal: Option<RefusalState>,
    ) -> Result<Self, RuntimeError> {
        crate::store::ensure_valid_local_host_id(local_identity)?;
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
        let upgrade_caps = if stream.provider_id() == ProviderId::P2p {
            Vec::new()
        } else {
            upgrade_caps
        };
        let mode = if refusal.is_some() {
            RefusalMode::Enabled
        } else {
            RefusalMode::Off
        };
        let machine = SessionMachine::new_responder_with_refusal(local_identity, None, mode)?
            .with_upgrade_caps(upgrade_caps)?;
        let mut driver = Self {
            stream,
            machine,
            recv_buf: vec![0u8; MAX_OUTER_FRAME_LEN],
            pending_events: VecDeque::new(),
            started_at: Instant::now(),
            _half_open: half_open,
            route_ingest: IngestSlot::default(),
            activity: IdleActivity::default(),
            initiator: false,
            refusal,
            refused: None,
            #[cfg(feature = "webrtc")]
            webrtc_upgrade_handle: None,
        };
        let established = driver
            .drive_until_established(now_unix, &mut roster, rate_limiter, Some(handshake_timeout))
            .await;
        match established {
            Ok(()) => Ok(driver),
            Err(err) => match driver.refused.take() {
                Some((peer, code)) => Err(driver.finish_refusal(peer, code)),
                None => Err(err),
            },
        }
    }

    /// Ends a connection the responder machine refused: the `CLOSE` frame is already written, the
    /// half-open slot is released, and the stream half-closes and drains in the background so
    /// the accept loop never waits on it (`spec/wire-v1.md` Section 5.4.4). Returns the accept
    /// error.
    fn finish_refusal(self, peer: String, code: u16) -> RuntimeError {
        let Self {
            stream,
            refusal,
            _half_open,
            ..
        } = self;
        drop(_half_open);
        if let Some(refusal) = refusal {
            refusal.record(&peer, code);
            refusal.linger(stream);
        }
        let err = if code == SessionCloseCode::PEER_PENDING {
            CoreError::PeerPending(peer)
        } else {
            CoreError::PeerRevoked(peer)
        };
        RuntimeError::Core(err)
    }

    /// Sends encrypted `0x01 DATA`.
    pub async fn send_data(&mut self, payload: &[u8]) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self
            .machine
            .send_data(payload, now_ms)
            .map_err(|err| self.core_error(err))?;
        self.apply_actions(actions).await?;
        self.activity.touch();
        Ok(())
    }

    /// Sends encrypted `0x02 GRANT`.
    pub async fn send_grant(&mut self, grant: &Grant) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self
            .machine
            .send_grant(grant, now_ms)
            .map_err(|err| self.core_error(err))?;
        self.apply_actions(actions).await?;
        self.activity.touch();
        Ok(())
    }

    /// Sends encrypted `0x03 REVOCATION`.
    pub async fn send_revocation(&mut self, crl: &RevocationList) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self
            .machine
            .send_revocation(crl, now_ms)
            .map_err(|err| self.core_error(err))?;
        self.apply_actions(actions).await?;
        self.activity.touch();
        Ok(())
    }

    /// Sends encrypted `0x0A GROUP_MANIFEST`.
    pub async fn send_group_manifest(
        &mut self,
        manifest: &GroupManifest,
    ) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self
            .machine
            .send_group_manifest(manifest, now_ms)
            .map_err(|err| self.core_error(err))?;
        self.apply_actions(actions).await?;
        self.activity.touch();
        Ok(())
    }

    /// Sends encrypted `0x0B GROUP_RENDEZVOUS` carrying `secrets` for `group_id`.
    pub async fn send_group_rendezvous(
        &mut self,
        secrets: &V2GroupSecrets,
        group_id: &str,
    ) -> Result<(), RuntimeError> {
        let frame = secrets.to_rendezvous_frame(group_id)?;
        let now_ms = self.elapsed_ms();
        let actions = self
            .machine
            .send_group_rendezvous(&frame[..], now_ms)
            .map_err(|err| self.core_error(err))?;
        self.apply_actions(actions).await?;
        self.activity.touch();
        Ok(())
    }

    /// Returns the group gossip summary the initiator advertised in `SessionHello`, if any.
    #[must_use]
    pub fn peer_groups(&self) -> Option<&[GroupSeq]> {
        self.machine.peer_groups()
    }

    /// Sends encrypted `0x04 REKEY`.
    pub async fn send_rekey(&mut self) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self
            .machine
            .send_rekey(now_ms)
            .map_err(|err| self.core_error(err))?;
        self.apply_actions(actions).await
    }

    /// Sends encrypted `0x05 PING`.
    pub async fn send_ping(&mut self, cookie: u64) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self
            .machine
            .send_ping(cookie, now_ms)
            .map_err(|err| self.core_error(err))?;
        self.apply_actions(actions).await
    }

    /// Sends encrypted `0x07 CLOSE` and closes the underlying transport stream.
    pub async fn send_close(&mut self, code: u16, reason: &str) -> Result<(), RuntimeError> {
        let actions = self
            .machine
            .send_close(code, reason)
            .map_err(|err| self.core_error(err))?;
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

    /// Returns the negotiated in-band path upgrade capabilities for this session.
    #[must_use]
    pub fn negotiated_upgrade_caps(&self) -> &[String] {
        self.machine.negotiated_upgrade_caps()
    }

    /// Returns the peer's advertised upgrade capabilities from handshake hello.
    #[must_use]
    pub fn peer_upgrade_caps(&self) -> &[String] {
        self.machine.peer_upgrade_caps()
    }

    /// Sends encrypted `0x0D PATH_UPGRADE` signaling after enforcing role, cap, and `upgrade_id` rules.
    pub async fn send_path_upgrade(&mut self, msg: &PathUpgradeMsg) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let actions = self
            .machine
            .send_path_upgrade(msg, now_ms)
            .map_err(|err| self.core_error(err))?;
        self.apply_actions(actions).await
    }

    /// Attaches a host-side [`WebRtcUpgradeHandle`] so inbound `webrtc/v1` offers are answered automatically.
    #[cfg(feature = "webrtc")]
    #[must_use]
    pub fn with_webrtc_upgrade_handle(mut self, handle: WebRtcUpgradeHandle) -> Self {
        self.webrtc_upgrade_handle = Some(handle);
        self
    }

    /// Sets or clears the host-side [`WebRtcUpgradeHandle`] on an established [`SessionDriver`].
    #[cfg(feature = "webrtc")]
    pub fn set_webrtc_upgrade_handle(&mut self, handle: Option<WebRtcUpgradeHandle>) {
        self.webrtc_upgrade_handle = handle;
    }

    #[cfg(feature = "webrtc")]
    async fn maybe_auto_respond_offer(&mut self, upgrade_id: u64, protocol: &str, sdp: &str) {
        let Some(ref handle) = self.webrtc_upgrade_handle else {
            return;
        };
        if protocol != UPGRADE_CAP_WEBRTC_V1 {
            return;
        }
        let reply = match handle.accept_offer(sdp).await {
            Ok(answer_sdp) => PathUpgradeMsg::Answer {
                upgrade_id,
                protocol: protocol.to_owned(),
                sdp: answer_sdp,
            },
            Err(err) => PathUpgradeMsg::Reject {
                upgrade_id,
                reason: webrtc_reject_reason(&err),
            },
        };
        if let Err(err) = self.send_path_upgrade(&reply).await {
            tracing::debug!(error = %err, "failed to send auto WebRTC path upgrade reply");
        }
    }

    /// Returns the provider ID backing the active stream.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.stream.provider_id()
    }

    /// Sets an opt-in application-data idle timeout for this session. Keepalives (`Ping`/`Pong`,
    /// rekey) do not extend the deadline.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.activity = IdleActivity::new(timeout);
        self
    }

    /// Converts this established [`SessionDriver`] into a full-duplex [`ConcurrentSession`].
    #[must_use]
    pub fn into_concurrent(self) -> ConcurrentSession {
        let provider_id = self.stream.provider_id();
        let is_closed = self.machine.is_closed();
        let negotiated_upgrade_caps = self.machine.negotiated_upgrade_caps().to_vec();
        let peer_upgrade_caps = self.machine.peer_upgrade_caps().to_vec();
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
            activity: self.activity,
            initiator: self.initiator,
            negotiated_upgrade_caps,
            peer_upgrade_caps,
            #[cfg(feature = "webrtc")]
            webrtc_upgrade_handle: Mutex::new(self.webrtc_upgrade_handle),
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
                    #[cfg(feature = "webrtc")]
                    if let SessionEvent::PathUpgrade(PathUpgradeMsg::Offer {
                        upgrade_id,
                        ref protocol,
                        ref sdp,
                    }) = ev
                    {
                        self.maybe_auto_respond_offer(upgrade_id, protocol, sdp)
                            .await;
                    }
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
                if is_application_event(&ev) {
                    self.activity.touch();
                }
                #[cfg(feature = "webrtc")]
                if let SessionEvent::PathUpgrade(PathUpgradeMsg::Offer {
                    upgrade_id,
                    ref protocol,
                    ref sdp,
                }) = ev
                {
                    self.maybe_auto_respond_offer(upgrade_id, protocol, sdp)
                        .await;
                }
                return Ok(Some(ev));
            }
            if self.machine.is_closed() {
                return Ok(None);
            }
            let idle_dl = self.activity.deadline();
            let n = tokio::select! {
                biased;
                () = async {
                    match idle_dl {
                        Some(dl) => tokio::time::sleep_until(dl).await,
                        None => std::future::pending().await,
                    }
                } => {
                    if self.activity.deadline().is_some_and(|dl| TokioInstant::now() >= dl) {
                        let _ = self.send_close(1000, "idle_timeout").await;
                        return Ok(None);
                    }
                    continue;
                }
                res = self.stream.recv_chunk(&mut self.recv_buf) => res?,
            };
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
            if let Some(refused) = self.write_refusal(&actions, deadline).await? {
                // The accept path ends the connection; it reads `refused`.
                self.refused = Some(refused);
                self._half_open.take();
                return Err(RuntimeError::Closed);
            }
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
        let refusal = self
            .refusal
            .clone()
            .filter(|_| !self.machine.is_established());
        let machine = &mut self.machine;
        let feed = |machine: &mut SessionMachine, roster: &mut Roster| match &refusal {
            Some(refusal) => machine.feed_bytes_with_limiter(
                chunk,
                now_unix,
                now_ms,
                roster,
                &mut refusal.limiter(),
            ),
            None => machine.feed_bytes(chunk, now_unix, now_ms, roster),
        };
        let (res, crls) = match roster {
            RosterRef::Direct(r) => {
                let res = feed(machine, r);
                let crls = fed_crls(res.as_deref().ok(), peer.as_deref(), r);
                (res, crls)
            }
            RosterRef::Locked(m) => {
                let mut guard = m.lock().expect("roster mutex poisoned");
                let res = feed(machine, &mut guard);
                let crls = fed_crls(res.as_deref().ok(), peer.as_deref(), &guard);
                (res, crls)
            }
        };
        self.route_ingest.note_crls(crls);
        if res.is_err() {
            self.route_ingest.run(Vec::new()).await;
        }
        res.map_err(|err| self.core_error(err))
    }

    /// Wraps a core error of this session: an initiator keeps a peer close as
    /// [`RuntimeError::InitiatorClosed`] so a refusal close is classifiable
    /// ([`RuntimeError::refusal`]); a responder keeps the plain error.
    fn core_error(&self, err: CoreError) -> RuntimeError {
        if self.initiator {
            RuntimeError::from_initiator_core(err)
        } else {
            RuntimeError::Core(err)
        }
    }

    /// When `actions` carry a refusal, writes its frame and returns the refused peer and code.
    /// The frame is the only write such a batch holds; nothing else of it is applied.
    async fn write_refusal(
        &mut self,
        actions: &[SessionAction],
        deadline: Option<TokioInstant>,
    ) -> Result<Option<(String, u16)>, RuntimeError> {
        let Some((peer, code)) = actions.iter().find_map(|action| match action {
            SessionAction::Refused {
                peer_device_id,
                code,
            } => Some((peer_device_id.clone(), *code)),
            _ => None,
        }) else {
            return Ok(None);
        };
        let write = async {
            for action in actions {
                if let SessionAction::WriteBytes(bytes) = action {
                    write_protocol_bytes(self.stream.as_mut(), bytes).await?;
                }
            }
            Ok::<(), RuntimeError>(())
        };
        // The half-open slot is still held: a stalled peer must not outlive the handshake bound.
        let written = match deadline {
            Some(dl) => timeout_at(dl, write).await.ok(),
            None => Some(write.await),
        };
        match written {
            Some(res) => res?,
            None => {
                let _ = self.stream.close().await;
                return Err(RuntimeError::Timeout(
                    "pre-auth session handshake timed out",
                ));
            }
        }
        Ok(Some((peer, code)))
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
        let actions = self
            .machine
            .send_route_set(payload, now_ms)
            .map_err(|err| self.core_error(err))?;
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
    activity: IdleActivity,
    initiator: bool,
    negotiated_upgrade_caps: Vec<String>,
    peer_upgrade_caps: Vec<String>,
    #[cfg(feature = "webrtc")]
    webrtc_upgrade_handle: Mutex<Option<WebRtcUpgradeHandle>>,
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
            .await?;
        self.activity.touch();
        Ok(())
    }

    /// Sends encrypted `0x02 GRANT` concurrently with inbound polling.
    pub async fn send_grant(&self, grant: &Grant) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_grant(grant, now_ms))
            .await?;
        self.activity.touch();
        Ok(())
    }

    /// Sends encrypted `0x03 REVOCATION` concurrently with inbound polling.
    pub async fn send_revocation(&self, crl: &RevocationList) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_revocation(crl, now_ms))
            .await?;
        self.activity.touch();
        Ok(())
    }

    /// Sends encrypted `0x0A GROUP_MANIFEST` concurrently with inbound polling.
    pub async fn send_group_manifest(&self, manifest: &GroupManifest) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_group_manifest(manifest, now_ms))
            .await?;
        self.activity.touch();
        Ok(())
    }

    /// Sends encrypted `0x0B GROUP_RENDEZVOUS` carrying `secrets` for `group_id`.
    pub async fn send_group_rendezvous(
        &self,
        secrets: &V2GroupSecrets,
        group_id: &str,
    ) -> Result<(), RuntimeError> {
        let frame = secrets.to_rendezvous_frame(group_id)?;
        self.run_write_op(|machine, now_ms| machine.send_group_rendezvous(&frame[..], now_ms))
            .await?;
        self.activity.touch();
        Ok(())
    }

    /// Returns the negotiated in-band path upgrade capabilities for this session.
    #[must_use]
    pub fn negotiated_upgrade_caps(&self) -> &[String] {
        &self.negotiated_upgrade_caps
    }

    /// Returns the peer's advertised upgrade capabilities from handshake hello.
    #[must_use]
    pub fn peer_upgrade_caps(&self) -> &[String] {
        &self.peer_upgrade_caps
    }

    /// Sends encrypted `0x0D PATH_UPGRADE` signaling concurrently with inbound polling.
    pub async fn send_path_upgrade(&self, msg: &PathUpgradeMsg) -> Result<(), RuntimeError> {
        self.run_write_op(|machine, now_ms| machine.send_path_upgrade(msg, now_ms))
            .await
    }

    /// Sets or clears the host-side [`WebRtcUpgradeHandle`] on an established [`ConcurrentSession`].
    #[cfg(feature = "webrtc")]
    pub fn set_webrtc_upgrade_handle(&self, handle: Option<WebRtcUpgradeHandle>) {
        *self
            .webrtc_upgrade_handle
            .lock()
            .expect("webrtc handle mutex poisoned") = handle;
    }

    #[cfg(feature = "webrtc")]
    async fn maybe_auto_respond_offer(&self, upgrade_id: u64, protocol: &str, sdp: &str) {
        let handle = {
            self.webrtc_upgrade_handle
                .lock()
                .expect("webrtc handle mutex poisoned")
                .clone()
        };
        let Some(handle) = handle else {
            return;
        };
        if protocol != UPGRADE_CAP_WEBRTC_V1 {
            return;
        }
        let reply = match handle.accept_offer(sdp).await {
            Ok(answer_sdp) => PathUpgradeMsg::Answer {
                upgrade_id,
                protocol: protocol.to_owned(),
                sdp: answer_sdp,
            },
            Err(err) => PathUpgradeMsg::Reject {
                upgrade_id,
                reason: webrtc_reject_reason(&err),
            },
        };
        if let Err(err) = self.send_path_upgrade(&reply).await {
            tracing::debug!(error = %err, "failed to send auto WebRTC path upgrade reply");
        }
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
                return Err(self.core_error(err));
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
                if is_application_event(&ev) {
                    self.activity.touch();
                }
                #[cfg(feature = "webrtc")]
                if let SessionEvent::PathUpgrade(PathUpgradeMsg::Offer {
                    upgrade_id,
                    ref protocol,
                    ref sdp,
                }) = ev
                {
                    self.maybe_auto_respond_offer(upgrade_id, protocol, sdp)
                        .await;
                }
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
            let idle_dl = self.activity.deadline();
            let n = tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    return Ok(None);
                }
                _ = &mut notified => continue,
                () = async {
                    match idle_dl {
                        Some(dl) => tokio::time::sleep_until(dl).await,
                        None => std::future::pending().await,
                    }
                } => {
                    if self.activity.deadline().is_some_and(|dl| TokioInstant::now() >= dl) {
                        let _ = self.send_close(1000, "idle_timeout").await;
                        return Ok(None);
                    }
                    continue;
                }
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
                    return Err(self.core_error(err));
                }
            }
        }
    }

    /// See [`SessionDriver::core_error`].
    fn core_error(&self, err: CoreError) -> RuntimeError {
        if self.initiator {
            RuntimeError::from_initiator_core(err)
        } else {
            RuntimeError::Core(err)
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
            op(&mut machine, now_ms).map_err(|err| self.core_error(err))?
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

pub(crate) enum StreamSource<'a> {
    Stream(Box<dyn PathStream>),
    Dial {
        dialer: &'a dyn PathDialer,
        addr: &'a str,
    },
}

impl StreamSource<'_> {
    pub(crate) fn provider_id(&self) -> ProviderId {
        match self {
            Self::Stream(stream) => stream.provider_id(),
            Self::Dial { dialer, .. } => dialer.provider_id(),
        }
    }
}

#[cfg(feature = "webrtc")]
pub(crate) fn webrtc_reject_reason(err: &RuntimeError) -> String {
    if matches!(err, RuntimeError::CapacityExceeded(_)) {
        "capacity_exceeded".to_owned()
    } else {
        "webrtc_offer_failed".to_owned()
    }
}

pub(crate) async fn dial_source_with_init(
    source: StreamSource<'_>,
    init_bytes: Option<&[u8]>,
) -> Result<(Box<dyn PathStream>, bool), RuntimeError> {
    match source {
        StreamSource::Stream(stream) => Ok((stream, false)),
        StreamSource::Dial { dialer, addr } => match init_bytes {
            Some(bytes) if dialer.supports_fast_open() => {
                dialer.dial_with_init(addr, Some(bytes)).await
            }
            _ => Ok((dialer.dial(addr).await?, false)),
        },
    }
}

pub(crate) async fn dial_with_policy_candidates<T, F, Fut>(
    dialers: &[Arc<dyn PathDialer>],
    policy_config: PathPolicyConfig,
    candidates: Vec<CandidateEndpoint>,
    drive: F,
) -> Result<(CandidateEndpoint, T), RuntimeError>
where
    T: Send + 'static,
    F: Fn(CandidateEndpoint, Arc<dyn PathDialer>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, RuntimeError>> + Send + 'static,
{
    let drive = Arc::new(drive);
    let race = race_candidates(dialers, policy_config, candidates, move |cand, dialer| {
        let drive = Arc::clone(&drive);
        async move { drive(cand, dialer).await.map_err(CandidateError::retry) }
    })
    .await;
    match race.outcome {
        Ok(won) => Ok(won),
        Err(RaceEnd::Fatal(err)) => Err(err),
        Err(RaceEnd::Exhausted) => Err(RuntimeError::Policy("all candidates exhausted")),
        Err(RaceEnd::ChannelClosed) => Err(RuntimeError::Policy("dialer channel closed")),
    }
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
    dial_with_policy_candidates(dialers, policy_config, candidates, move |cand, dialer| {
        let verify = Arc::clone(&verify);
        async move {
            let stream = dialer.dial(&cand.addr).await?;
            verify(cand, stream).await
        }
    })
    .await
}

/// `true` for an error that ends a race whatever the candidate's own `fatal` flag says: a
/// `Revoked` or `Pending` refusal. A reserved admission code (`Other`) may be transient, so it
/// never cancels a healthy candidate.
fn ends_race(error: &RuntimeError) -> bool {
    matches!(
        error.refusal(),
        Some(RefusalReason::Revoked | RefusalReason::Pending)
    )
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

/// Result of [`race_candidates`]: the winner or why the race ended, and every candidate that
/// failed before that, with its typed error.
pub(crate) struct Race<T> {
    pub(crate) outcome: Result<(CandidateEndpoint, T), RaceEnd>,
    pub(crate) failures: Vec<(CandidateEndpoint, RuntimeError)>,
}

/// Happy Eyeballs candidate racer passing the selected [`PathDialer`] directly so callers can
/// prepare 0-RTT fast-open frames before dialing.
pub(crate) async fn race_candidates<T, F, Fut>(
    dialers: &[Arc<dyn PathDialer>],
    policy_config: PathPolicyConfig,
    candidates: Vec<CandidateEndpoint>,
    drive: F,
) -> Race<T>
where
    T: Send + 'static,
    F: Fn(CandidateEndpoint, Arc<dyn PathDialer>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, CandidateError>> + Send + 'static,
{
    let dialer_map: HashMap<ProviderId, Arc<dyn PathDialer>> = dialers
        .iter()
        .map(|d| (d.provider_id(), Arc::clone(d)))
        .collect();
    let by_id: HashMap<usize, CandidateEndpoint> =
        candidates.iter().map(|c| (c.id, c.clone())).collect();

    let driver = Arc::new(drive);
    let mut planner = PathPlanner::new(policy_config, candidates);
    let started = TokioInstant::now();
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
                    let drive_c = Arc::clone(&driver);
                    let handle = tokio::spawn(async move {
                        let res = drive_c(cand, dialer).await;
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

        let next_dl = planner.next_deadline_ms();
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
                    Err(CandidateError { error, fatal })
                        if fatal || ends_race(&error) =>
                    {
                        in_flight_handles.clear();
                        return end(Err(RaceEnd::Fatal(error)), failures);
                    }
                    Err(CandidateError { error, .. }) => {
                        planner.on_dial_failed(id, &error.to_string(), now_ms);
                        if let Some(cand) = by_id.get(&id) {
                            failures.push((cand.clone(), error));
                        }
                    }
                }
            }
            () = async {
                match next_dl {
                    Some(dl) => tokio::time::sleep_until(started + Duration::from_millis(dl)).await,
                    None => std::future::pending().await,
                }
            } => {
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
/// authenticated refusal > `VersionDowngrade` > `HostKeyUnverified` > `InvalidPairingUri` > transport errors) or the
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
    /// or policy refusal (including an authenticated peer refusal), relay admission or offline errors, egress refusals, storage errors or
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
        RuntimeError::Core(CoreError::RotationForkDetected { .. }) => 7,
        RuntimeError::Core(CoreError::PeerRevoked(_)) => 6,
        _ if err.refusal().is_some() => 5,
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
        RuntimeError::InitiatorClosed { code, reason } => RuntimeError::InitiatorClosed {
            code: *code,
            reason: reason.clone(),
        },
        RuntimeError::CapacityExceeded(m) => RuntimeError::CapacityExceeded(m),
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
    /// Host pin. Without `uri` it is the pin; with `uri` it must name the same host as the
    /// URI pin, the stricter of the two is used, and a disagreement is `InvalidPairingUri`
    /// before any dial.
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
    pub(crate) binding: PairRouteBinding,
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
    if operator
        .as_ref()
        .is_some_and(|op| tendril_core::pairing::is_v2_p2p_hint(&op.hint))
    {
        return Err(CoreError::InvalidPairingUri(
            "iroh://v2 is not used for pairing; pair over another route, then use dial --wire-v2"
                .into(),
        )
        .into());
    }
    let operator_relay_key = operator.as_ref().and_then(|op| op.relay_key);
    let uri_rp = opts.uri.as_ref().and_then(|u| u.relay_pub);
    let binding = PairRouteBinding::new(opts.uri.clone(), operator_relay_key)?;
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
    let pinned = match (&opts.uri, &opts.pinned_host) {
        (Some(uri), Some(pin)) => Some(uri.merge_pin(pin)?),
        (Some(uri), None) => Some(uri.to_pinned_host()),
        (None, pin) => pin.clone(),
    };
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
        binding,
    })
}

/// The route check of one candidate from the machine's pre-`msg3` verdict. An invalid route
/// statement is fatal for the whole attempt, every other refusal moves on to the next candidate.
pub(crate) fn committable_route_check(
    verdict: Option<&PairRouteVerdict>,
) -> Result<RouteCheck, CandidateError> {
    let verdict = verdict.ok_or(CoreError::HostKeyUnverified)?;
    match verdict.committable() {
        Ok(check) => Ok(check.clone()),
        Err(err @ CoreError::InvalidPairingUri(_)) => Err(CandidateError::fatal(err.into())),
        Err(err) => Err(err.into()),
    }
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
        binding,
    } = plan;
    let mut skipped = set.skipped.clone();
    let roster = Arc::new(roster);
    let code = opts.code.clone();
    let (name, kind, budget) = (
        opts.device_name.clone(),
        opts.device_kind.clone(),
        opts.handshake_timeout,
    );
    let race = race_candidates(
        &set.dialers,
        opts.policy_config,
        set.candidates.clone(),
        move |cand, dialer| {
            let identity = Arc::clone(&identity);
            let roster = Arc::clone(&roster);
            let binding = binding.clone();
            let (code, name, kind, pinned) =
                (code.clone(), name.clone(), kind.clone(), pinned.clone());
            async move {
                let mut machine = PairingInitiator::new_with_min_wire_version(
                    &identity, name, kind, code, pinned, floor, None,
                )?
                .with_roster_floors(&roster)
                .with_route_binding(binding)
                .with_deferred_claim();
                let mut sas = None;
                let start = machine.start()?;
                let init_bytes = match start.as_slice() {
                    [PairAction::WriteBytes(bytes)] if !bytes.is_empty() => Some(bytes.as_slice()),
                    _ => None,
                };
                let (mut stream, fast_open_sent) = dial_source_with_init(
                    StreamSource::Dial {
                        dialer: &*dialer,
                        addr: &cand.addr,
                    },
                    init_bytes,
                )
                .await?;
                let deadline = TokioInstant::now() + budget;
                if !fast_open_sent {
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
                            return Err(RuntimeError::Timeout(
                                "pre-auth pairing handshake timed out",
                            )
                            .into());
                        }
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
                let route_check = committable_route_check(machine.route_verdict())?;
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
    /// Cached last-known-good candidate hint to prioritize ahead of other rungs (never outranks
    /// an operator override).
    pub preferred_hint: Option<String>,
    /// Optional local IPv4/IPv6 reachability used to filter unreachable candidates before dialing.
    pub reachability: Option<LocalReachability>,
    /// Power profile controlling ladder concurrency (`max_in_flight`) and Wire v2 keepalives.
    pub power_profile: PowerProfile,
    /// Opt-in application-data idle timeout for the connected session.
    pub idle_timeout: Option<Duration>,
}

impl std::fmt::Debug for ConnectOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectOpts")
            .field("recovery_uri", &self.recovery_uri.is_some())
            .field("replace_routes", &self.replace_routes)
            .field("policy", &self.policy)
            .field("operator_endpoint", &self.operator_endpoint)
            .field("preferred_hint", &self.preferred_hint)
            .field("reachability", &self.reachability)
            .field("power_profile", &self.power_profile)
            .field("idle_timeout", &self.idle_timeout)
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
            preferred_hint: None,
            reachability: None,
            power_profile: PowerProfile::Standard,
            idle_timeout: None,
        }
    }

    /// Prioritizes `hint` as a last-known-good route within the path planner.
    #[must_use]
    pub fn with_preferred_hint(mut self, hint: impl Into<String>) -> Self {
        self.preferred_hint = Some(hint.into());
        self
    }

    /// Sets local interface IPv4/IPv6 reachability used to skip unreachable address families.
    #[must_use]
    pub const fn with_reachability(mut self, reachability: LocalReachability) -> Self {
        self.reachability = Some(reachability);
        self
    }

    /// Applies `power_profile` to the path planner and Wire v2 session keepalives.
    #[must_use]
    pub fn with_power_profile(mut self, power_profile: PowerProfile) -> Self {
        self.power_profile = power_profile;
        self.policy_config = power_profile.path_policy();
        self
    }

    pub(crate) fn effective_policy_config(&self) -> PathPolicyConfig {
        if self.power_profile != PowerProfile::Standard
            && self.policy_config == PathPolicyConfig::default()
        {
            self.power_profile.path_policy()
        } else {
            self.policy_config
        }
    }

    /// Sets an opt-in application-data idle timeout on the resulting session.
    #[must_use]
    pub const fn with_idle_timeout(mut self, idle_timeout: Option<Duration>) -> Self {
        self.idle_timeout = idle_timeout;
        self
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
        .ok_or_else(|| roster.missing_peer_error(target))?;
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
    if let Some(reachability) = opts.reachability {
        ctx = ctx.with_reachability(reachability);
    }
    let multi = MultiDialOptions::new(Arc::clone(&opts.dialers), wire);
    let mut set = build_pairing_candidates(&hints, &hint_target, &ctx, &multi).await?;
    if let Some(preferred) = opts.preferred_hint.as_deref() {
        for cand in &mut set.candidates {
            if cand.addr == preferred {
                cand.preferred = true;
            }
        }
    }
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
        let race = race_candidates(
            &set.dialers,
            opts.effective_policy_config(),
            set.candidates.clone(),
            move |cand, dialer| {
                let identity = Arc::clone(&identity);
                let roster = (*roster).clone();
                let (target, grant, expectation) =
                    (target_owned.clone(), grant.clone(), expectation.clone());
                let ev = Arc::clone(&ev);
                async move {
                    Self::day2_candidate(
                        StreamSource::Dial {
                            dialer: &*dialer,
                            addr: &cand.addr,
                        },
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
        driver.activity = IdleActivity::new(opts.idle_timeout);
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
        source: StreamSource<'_>,
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
        let init_bytes = match start_actions.as_slice() {
            [SessionAction::WriteBytes(bytes)] if !bytes.is_empty() => Some(bytes.as_slice()),
            _ => None,
        };
        let (stream, fast_open_sent) = dial_source_with_init(source, init_bytes).await?;
        let mut driver = Self {
            stream,
            machine,
            recv_buf: vec![0u8; MAX_OUTER_FRAME_LEN],
            pending_events: VecDeque::new(),
            started_at: Instant::now(),
            _half_open: None,
            route_ingest: IngestSlot::default(),
            activity: IdleActivity::default(),
            initiator: true,
            refusal: None,
            refused: None,
            #[cfg(feature = "webrtc")]
            webrtc_upgrade_handle: None,
        };
        let deadline = TokioInstant::now() + DEFAULT_PRE_AUTH_TIMEOUT;
        let now_unix = current_unix_secs();
        // Evidence is recorded right after each feed, so a candidate aborted once another wins
        // still contributes the `HostHello` it verified.
        let res = async {
            if !fast_open_sent {
                driver.apply_actions(start_actions).await?;
            }
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
    use tokio::time::sleep;

    use super::*;

    fn identity(tag: u8) -> EndpointIdentity {
        EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([tag; 32]),
            SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
        )
    }

    const NOW: u64 = 1_795_564_800;

    fn refused(reason: tendril_core::RefusalReason) -> RuntimeError {
        RuntimeError::Core(CoreError::PeerRefused { reason })
    }

    #[test]
    fn severity_ranks_a_refusal_between_revoked_and_downgrade() {
        use tendril_core::RefusalReason;
        let ranked = [
            RuntimeError::Core(CoreError::RotationForkDetected { seq: 1 }),
            RuntimeError::Core(CoreError::PeerRevoked("h".into())),
            refused(RefusalReason::Revoked),
            RuntimeError::Core(CoreError::VersionDowngrade {
                peer_min: 2,
                negotiated: 1,
            }),
            RuntimeError::Core(CoreError::HostKeyUnverified),
            RuntimeError::Core(CoreError::InvalidPairingUri("u".into())),
            RuntimeError::Closed,
        ];
        let levels: Vec<u8> = ranked.iter().map(error_severity).collect();
        assert_eq!(levels, [7, 6, 5, 4, 3, 2, 1]);
        for reason in [RefusalReason::Pending, RefusalReason::Revoked] {
            assert_eq!(error_severity(&refused(reason)), 5);
        }
        let initiator = RuntimeError::from_initiator_core(CoreError::SessionClosed {
            code: 4001,
            reason: String::new(),
        });
        assert_eq!(error_severity(&initiator), 5);
    }

    #[test]
    fn exhausted_error_prefers_the_most_severe_failure() {
        use tendril_core::RefusalReason;
        let failure = |error| CandidateFailure {
            hint: "h".into(),
            provider: ProviderId::Direct,
            error,
        };
        let err = exhausted_error(
            vec![
                failure(RuntimeError::Core(CoreError::VersionDowngrade {
                    peer_min: 2,
                    negotiated: 1,
                })),
                failure(RuntimeError::Core(CoreError::HostKeyUnverified)),
                failure(RuntimeError::Closed),
            ],
            Vec::new(),
            RuntimeError::Closed,
        );
        assert!(matches!(
            err.error,
            RuntimeError::Core(CoreError::VersionDowngrade { .. })
        ));
        assert_eq!(error_severity(&refused(RefusalReason::Pending)), 5);
    }

    #[test]
    fn a_refusal_is_never_transient_or_wakeable() {
        use tendril_core::RefusalReason;
        let attempt = |error, failures| AttemptError {
            error,
            committed: false,
            skipped: Vec::new(),
            failures,
        };
        let failure = |error| CandidateFailure {
            hint: "h".into(),
            provider: ProviderId::Direct,
            error,
        };
        let initiator = || {
            RuntimeError::from_initiator_core(CoreError::SessionClosed {
                code: 4004,
                reason: String::new(),
            })
        };
        for error in [refused(RefusalReason::Revoked), initiator()] {
            let miss = attempt(error, Vec::new());
            assert!(!miss.is_transient_precommit());
            assert!(!miss.is_wakeable_miss());
        }
        let io = || RuntimeError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        for refusal in [refused(RefusalReason::Pending), initiator()] {
            let mixed = attempt(io(), vec![failure(io()), failure(refusal)]);
            assert!(!mixed.is_transient_precommit(), "a refusal candidate");
            assert!(!mixed.is_wakeable_miss(), "a refusal candidate");
        }
        assert!(attempt(io(), vec![failure(io())]).is_wakeable_miss());
    }

    struct NoDial;

    #[async_trait]
    impl PathDialer for NoDial {
        fn provider_id(&self) -> ProviderId {
            ProviderId::Direct
        }

        async fn dial(&self, _endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
            Err(RuntimeError::Closed)
        }
    }

    struct SetFlagOnDrop(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for SetFlagOnDrop {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Races three fake candidates: the first fails plainly, the second fails with `second`
    /// after 400 ms, the third wins after 1.5 s. Returns the race, how many candidates were
    /// dialed and whether the third was dropped before it finished.
    async fn race_with_second_failure(second: RuntimeError) -> (Race<()>, usize, bool) {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(NoDial)];
        let candidates: Vec<CandidateEndpoint> = (0..3)
            .map(|id| {
                CandidateEndpoint::new(id, ProviderId::Direct, format!("127.0.0.1:{}", 9000 + id))
            })
            .collect();
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let second = Arc::new(Mutex::new(Some(second)));
        let drive = {
            let started = Arc::clone(&started);
            let dropped = Arc::clone(&dropped);
            let finished = Arc::clone(&finished);
            move |cand: CandidateEndpoint, _dialer: Arc<dyn PathDialer>| {
                let started = Arc::clone(&started);
                let dropped = Arc::clone(&dropped);
                let finished = Arc::clone(&finished);
                let second = Arc::clone(&second);
                async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    match cand.id {
                        0 => Err(CandidateError::retry(RuntimeError::Closed)),
                        1 => {
                            sleep(Duration::from_millis(400)).await;
                            let error = second.lock().unwrap().take().unwrap();
                            Err(CandidateError::retry(error))
                        }
                        _ => {
                            let _guard = SetFlagOnDrop(dropped);
                            sleep(Duration::from_millis(1500)).await;
                            finished.store(true, Ordering::SeqCst);
                            Ok(())
                        }
                    }
                }
            }
        };
        let config = PathPolicyConfig {
            happy_eyeballs_stagger_ms: 20,
            ..PathPolicyConfig::default()
        };
        let race = race_candidates(&dialers, config, candidates, drive).await;
        tokio::task::yield_now().await;
        let cancelled = dropped.load(Ordering::SeqCst) && !finished.load(Ordering::SeqCst);
        (race, started.load(Ordering::SeqCst), cancelled)
    }

    #[tokio::test(start_paused = true)]
    async fn race_ends_on_the_first_refusal_and_cancels_the_rest() {
        use tendril_core::RefusalReason;

        let initiator = || {
            RuntimeError::from_initiator_core(CoreError::SessionClosed {
                code: 4004,
                reason: String::new(),
            })
        };
        for (second, expected) in [
            (refused(RefusalReason::Revoked), RefusalReason::Revoked),
            (refused(RefusalReason::Pending), RefusalReason::Pending),
            (initiator(), RefusalReason::Pending),
        ] {
            let (race, started, cancelled) = race_with_second_failure(second).await;
            match race.outcome {
                Err(RaceEnd::Fatal(err)) => assert_eq!(err.refusal(), Some(expected)),
                Err(RaceEnd::Exhausted) => panic!("the race ran on past a refusal"),
                Err(RaceEnd::ChannelClosed) => panic!("channel closed"),
                Ok(_) => panic!("a candidate won"),
            }
            assert_eq!(started, 3, "all candidates were dialed");
            assert!(cancelled, "the pending candidate was cancelled");
            assert_eq!(race.failures.len(), 1, "only the plain failure is reported");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn race_ignores_a_responder_close_and_an_admission_refusal() {
        use tendril_core::{AdmissionRefusalCode, RefusalReason};

        let other = AdmissionRefusalCode::new(4450).unwrap();
        for second in [
            RuntimeError::Core(CoreError::SessionClosed {
                code: 4001,
                reason: String::new(),
            }),
            refused(RefusalReason::Other(other)),
            RuntimeError::from_initiator_core(CoreError::SessionClosed {
                code: 4450,
                reason: String::new(),
            }),
        ] {
            let text = second.to_string();
            let (race, started, cancelled) = race_with_second_failure(second).await;
            assert!(race.outcome.is_ok(), "{text}: the healthy candidate won");
            assert_eq!(started, 3);
            assert!(
                !cancelled,
                "{text}: the healthy candidate was not cancelled"
            );
            assert_eq!(race.failures.len(), 2, "{text}: both failures are reported");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn race_keeps_going_past_a_plain_failure() {
        let dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(NoDial)];
        let candidates: Vec<CandidateEndpoint> = (0..2)
            .map(|id| {
                CandidateEndpoint::new(id, ProviderId::Direct, format!("127.0.0.1:{}", 9000 + id))
            })
            .collect();
        let drive = |cand: CandidateEndpoint, _dialer: Arc<dyn PathDialer>| async move {
            if cand.id == 0 {
                Err(CandidateError::retry(RuntimeError::Closed))
            } else {
                Ok(7_u8)
            }
        };
        let race = race_candidates(&dialers, PathPolicyConfig::default(), candidates, drive).await;
        assert!(matches!(race.outcome, Ok((_, 7))));
    }

    /// A client roster with `host` pinned as `Active`.
    fn pinned_roster(host: &EndpointIdentity) -> Roster {
        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                host.host_id().to_owned(),
                "Studio".into(),
                *host.static_key().public_bytes(),
                Some(host.signing_key().public_key().clone()),
                0,
                Vec::new(),
            )
            .unwrap();
        roster
    }

    fn verified(host: &EndpointIdentity, seq: u64, issued_at: u64) -> EnrollmentRoutes {
        EnrollmentRoutes::Verified(
            RouteSet::sign(
                host,
                seq,
                issued_at,
                vec!["direct:192.168.1.20:9100".into()],
            )
            .unwrap(),
        )
    }

    fn sourced(roster: &Roster, host: &EndpointIdentity, source: RouteSource) -> Vec<String> {
        roster
            .get(host.host_id())
            .unwrap()
            .routes_from(source)
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn rejected_or_ignored_sets_still_store_the_operator_endpoint() {
        let host = identity(0x31);
        let endpoint = "10.0.0.8:7000";
        let cases = [
            (
                EnrollmentRoutes::Rejected(EnrollmentRouteReject::BadSignature),
                EnrollRouteWarning::RouteSetRejected(EnrollmentRouteReject::BadSignature),
            ),
            (
                verified(&host, 3, NOW + 2 * 86_400),
                EnrollRouteWarning::RouteSetIgnored(RouteSetIgnored::FutureIssuedAt),
            ),
        ];
        for (set, warning) in cases {
            let mut roster = pinned_roster(&host);
            let (persisted, warnings) = store_enrollment_routes(
                &mut roster,
                host.host_id(),
                Some(&set),
                Some(endpoint),
                RoutePolicy::AllSigned,
                NOW,
            );
            assert_eq!(warnings, vec![warning]);
            assert_eq!(persisted.len(), 1);
            assert!(sourced(&roster, &host, RouteSource::Signed).is_empty());
            assert_eq!(
                sourced(&roster, &host, RouteSource::Committed),
                vec!["direct:10.0.0.8:7000"]
            );
        }
    }

    #[test]
    fn re_enrolment_with_route_meta_keeps_newer_signed_routes() {
        let host = identity(0x32);
        let mut roster = pinned_roster(&host);
        store_enrollment_routes(
            &mut roster,
            host.host_id(),
            Some(&verified(&host, 5, NOW)),
            None,
            RoutePolicy::AllSigned,
            NOW,
        );
        let signed = sourced(&roster, &host, RouteSource::Signed);
        let (persisted, warnings) = store_enrollment_routes(
            &mut roster,
            host.host_id(),
            Some(&verified(&host, 4, NOW)),
            Some("10.0.0.9:7000"),
            RoutePolicy::AllSigned,
            NOW,
        );
        assert_eq!(
            warnings,
            vec![EnrollRouteWarning::RouteSetIgnored(
                RouteSetIgnored::StaleSeq
            )]
        );
        assert_eq!(persisted.len(), 1);
        assert_eq!(sourced(&roster, &host, RouteSource::Signed), signed);
        let meta = roster.get(host.host_id()).unwrap().route_meta.unwrap();
        assert_eq!(meta.seq, 5);
    }

    #[test]
    fn operator_endpoint_checks_before_it_is_stored() {
        let host = identity(0x33);
        let other = identity(0x34);
        let key = |id: &EndpointIdentity| {
            tendril_core::crypto::b64url_encode(id.signing_key().public_key().ed25519_bytes())
        };
        let refused = [
            format!("wss://relay.example.com/v1/relay#{}", key(&other)),
            "direct:relay.example.com:7000".to_owned(),
            "direct:169.254.169.254:80".to_owned(),
            "/run/tendril/host.sock".to_owned(),
        ];
        for raw in &refused {
            let mut roster = pinned_roster(&host);
            let before = serde_json::to_value(&roster).unwrap();
            let (persisted, warnings) = store_enrollment_routes(
                &mut roster,
                host.host_id(),
                None,
                Some(raw),
                RoutePolicy::AllSigned,
                NOW,
            );
            assert!(persisted.is_empty(), "{raw}");
            assert!(
                matches!(
                    warnings.as_slice(),
                    [EnrollRouteWarning::OperatorEndpointRefused(_)]
                ),
                "{raw}: {warnings:?}"
            );
            assert_eq!(serde_json::to_value(&roster).unwrap(), before, "{raw}");
        }

        let mut roster = pinned_roster(&host);
        let own = format!("wss://relay.example.com/v1/relay#{}", key(&host));
        let (persisted, warnings) = store_enrollment_routes(
            &mut roster,
            host.host_id(),
            None,
            Some(&own),
            RoutePolicy::CommittedOnly,
            NOW,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(persisted[0].hint, "wss://relay.example.com/v1/relay");

        let (persisted, warnings) = store_enrollment_routes(
            &mut roster,
            host.host_id(),
            Some(&verified(&host, 1, NOW)),
            Some("10.0.0.8:7000"),
            RoutePolicy::None,
            NOW,
        );
        assert!(persisted.is_empty() && warnings.is_empty());
    }

    #[test]
    fn local_pin_conflicts_are_found_before_the_handshake() {
        let host = identity(0x35);
        let other = identity(0x36);
        let pin = PinnedHost::with_hash(
            Some(host.host_id().to_owned()),
            *host.static_key().public_bytes(),
            host.signing_key().signing_pub_hash(),
            0,
        );
        assert!(check_enrollment_pin(&Roster::new(), &pin).is_ok());
        assert!(check_enrollment_pin(&pinned_roster(&host), &pin).is_ok());

        // Same label, other keys at the same rotation.
        let mut clash = Roster::new();
        clash
            .insert_pinned_host(
                host.host_id().to_owned(),
                "Studio".into(),
                *other.static_key().public_bytes(),
                Some(other.signing_key().public_key().clone()),
                0,
                Vec::new(),
            )
            .unwrap();
        assert!(matches!(
            check_enrollment_pin(&clash, &pin),
            Err(RuntimeError::Core(CoreError::ProtocolViolation(_)))
        ));
        // A stored entry at a newer rotation: the chain from the older pin may reach it.
        let mut older_pin = pin.clone();
        older_pin.static_pub = *other.static_key().public_bytes();
        let mut newer = pinned_roster(&host);
        newer
            .insert_pinned_host(
                host.host_id().to_owned(),
                "Studio".into(),
                *host.static_key().public_bytes(),
                Some(host.signing_key().public_key().clone()),
                2,
                Vec::new(),
            )
            .unwrap();
        assert!(check_enrollment_pin(&newer, &older_pin).is_ok());

        // Revoked label, or a revoked entry holding the key under another label.
        let mut revoked = pinned_roster(&host);
        revoked.revoke_peer(host.host_id()).unwrap();
        assert!(matches!(
            check_enrollment_pin(&revoked, &pin),
            Err(RuntimeError::Core(CoreError::PeerRevoked(_)))
        ));
        let mut unscoped = pin.clone();
        unscoped.host_id = None;
        assert!(matches!(
            check_enrollment_pin(&revoked, &unscoped),
            Err(RuntimeError::Core(CoreError::PeerRevoked(_)))
        ));
    }

    #[test]
    fn unconfirmed_entries_never_shape_an_enrolment_pin() {
        let host = identity(0x38);
        let label = host.host_id().to_owned();
        let static_pub = *host.static_key().public_bytes();
        let other_signing = identity(0x39).signing_key().public_key().clone();
        let scoped = PinnedHost::with_hash(
            Some(label.clone()),
            static_pub,
            host.signing_key().signing_pub_hash(),
            0,
        );
        let mut unscoped = scoped.clone();
        unscoped.host_id = None;
        let genuine = VerifiedHost {
            host_id: label.clone(),
            static_pub,
            signing_pub: host.signing_key().public_key().clone(),
            rotation_seq: 0,
        };

        // An unconfirmed host claim for the same key at a far newer rotation.
        let mut claimed = Roster::new();
        claimed
            .record_pending_host(
                label.clone(),
                "Studio".into(),
                static_pub,
                other_signing.clone(),
                1000,
                "sas".into(),
                Vec::new(),
            )
            .unwrap();
        // An unconfirmed responder-side entry for the same key, stored with the same values.
        let mut peer = Roster::new();
        peer.record_pending_pair(
            static_pub,
            Some(other_signing),
            "Peer".into(),
            "cli".into(),
            "sas".into(),
        )
        .unwrap();
        let mut json = serde_json::to_value(&peer).unwrap();
        json["entries"][&label]["rotation_seq"] = 1000.into();
        json["entries"][&label]["min_wire_version"] = 2.into();
        let peer: Roster = serde_json::from_value(json).unwrap();

        for roster in [&claimed, &peer] {
            for pin in [&scoped, &unscoped] {
                assert_eq!(&stricter_stored_pin(roster, pin.clone()), pin);
                assert!(check_enrollment_pin(roster, pin).is_ok());
                assert_eq!(
                    pinned_pairing_floor(roster, pin),
                    roster.pairing_floor(&static_pub)
                );
            }
            check_enrolled_host(roster, &genuine).unwrap();
        }
    }

    #[test]
    fn unscoped_pins_find_the_entry_by_static_key() {
        let host = identity(0x37);
        let mut roster = pinned_roster(&host);
        store_enrollment_routes(
            &mut roster,
            host.host_id(),
            Some(&verified(&host, 7, NOW)),
            None,
            RoutePolicy::AllSigned,
            NOW,
        );
        let unscoped = PinnedHost::with_hash(
            None,
            *host.static_key().public_bytes(),
            host.signing_key().signing_pub_hash(),
            0,
        );
        let entry = pinned_entry(&roster, &unscoped).expect("entry by static key");
        assert_eq!(entry.hello_route_seq(RoutePolicy::AllSigned), Some(7));
    }

    #[test]
    fn enrol_route_warnings_display_their_detail() {
        let w = EnrollRouteWarning::OperatorEndpointRefused("invalid endpoint".into());
        assert_eq!(
            w.to_string(),
            "operator endpoint not stored: invalid endpoint"
        );
        assert_eq!(w.as_str(), "operator_endpoint_refused");
        let w = EnrollRouteWarning::RouteSetRejected(EnrollmentRouteReject::KeyMismatch);
        assert_eq!(w.to_string(), "route set rejected: key_mismatch");
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

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_ignores_pong_and_extends_on_app_data() {
        let host_id = identity(0x61);
        let cli_id = identity(0x62);
        let mut host_roster = Roster::new();
        host_roster
            .insert_pinned_host(
                cli_id.device_id(),
                "cli".to_owned(),
                *cli_id.static_key().public_bytes(),
                Some(cli_id.signing_key().public_key().clone()),
                0,
                vec![],
            )
            .expect("host add client");
        let mut cli_roster = Roster::new();
        cli_roster
            .insert_pinned_host(
                host_id.host_id().to_owned(),
                "host".to_owned(),
                *host_id.static_key().public_bytes(),
                Some(host_id.signing_key().public_key().clone()),
                0,
                vec![],
            )
            .expect("cli pin host");

        let (a, b) = tokio::io::duplex(64 * 1024);
        let sa = Box::new(crate::provider::IoPathStream::new(
            ProviderId::Direct,
            None,
            Duration::from_secs(1),
            a,
        ));
        let sb = Box::new(crate::provider::IoPathStream::new(
            ProviderId::Direct,
            None,
            Duration::from_secs(1),
            b,
        ));
        let (cli_res, host_res) = tokio::join!(
            SessionDriver::connect(sa, &cli_id, host_id.host_id(), None, &mut cli_roster, NOW),
            SessionDriver::accept(sb, &host_id, &mut host_roster, NOW, None),
        );
        let cli = cli_res
            .expect("client handshake")
            .with_idle_timeout(Some(Duration::from_secs(30)))
            .into_concurrent();
        let cli_roster = Mutex::new(cli_roster);
        let host = host_res.expect("host handshake").into_concurrent();
        let host_roster = Arc::new(Mutex::new(host_roster));
        let host_drain_roster = Arc::clone(&host_roster);
        let host_drain = tokio::spawn(async move {
            while let Ok(Some(_)) = host.next_event_with_clock(&host_drain_roster, || NOW).await {}
        });

        tokio::time::advance(Duration::from_secs(20)).await;
        cli.send_ping(42).await.expect("send ping");
        let ev = cli
            .next_event_with_clock(&cli_roster, || NOW + 20)
            .await
            .expect("pong event")
            .expect("some event");
        assert!(matches!(ev, SessionEvent::PongReceived(42)));

        // Advance past the original 30 s idle timeout: send_ping and Pong did NOT extend it.
        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(
            cli.next_event_with_clock(&cli_roster, || NOW + 31)
                .await
                .expect("idle close cleanly"),
            None
        );
        host_drain.abort();

        // Application data extends the deadline past 30 s.
        let (a2, b2) = tokio::io::duplex(64 * 1024);
        let sa2 = Box::new(crate::provider::IoPathStream::new(
            ProviderId::Direct,
            None,
            Duration::from_secs(1),
            a2,
        ));
        let sb2 = Box::new(crate::provider::IoPathStream::new(
            ProviderId::Direct,
            None,
            Duration::from_secs(1),
            b2,
        ));
        let mut host_roster2 = Roster::new();
        host_roster2
            .insert_pinned_host(
                cli_id.device_id(),
                "cli".to_owned(),
                *cli_id.static_key().public_bytes(),
                Some(cli_id.signing_key().public_key().clone()),
                0,
                vec![],
            )
            .expect("host2 add client");
        let mut cli_roster2 = Roster::new();
        cli_roster2
            .insert_pinned_host(
                host_id.host_id().to_owned(),
                "host".to_owned(),
                *host_id.static_key().public_bytes(),
                Some(host_id.signing_key().public_key().clone()),
                0,
                vec![],
            )
            .expect("cli2 pin host");
        let (cli2_res, host2_res) = tokio::join!(
            SessionDriver::connect(sa2, &cli_id, host_id.host_id(), None, &mut cli_roster2, NOW),
            SessionDriver::accept(sb2, &host_id, &mut host_roster2, NOW, None),
        );
        let mut cli2 = cli2_res.expect("client2 handshake");
        let host2 = host2_res
            .expect("host2 handshake")
            .with_idle_timeout(Some(Duration::from_secs(30)))
            .into_concurrent();
        let host_roster2 = Mutex::new(host_roster2);

        tokio::time::advance(Duration::from_secs(20)).await;
        cli2.send_data(b"hello").await.expect("send data");
        let ev2 = host2
            .next_event_with_clock(&host_roster2, || NOW + 20)
            .await
            .expect("data event")
            .expect("some event");
        assert!(matches!(ev2, SessionEvent::AppData(ref d) if d == b"hello"));

        // At t = 35s (only 15s since AppData), session is STILL alive.
        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(
            timeout(
                Duration::from_millis(10),
                host2.next_event_with_clock(&host_roster2, || NOW + 35),
            )
            .await
            .is_err()
        );

        // At t = 51s (>30s after AppData), idle timeout closes the session.
        tokio::time::advance(Duration::from_secs(16)).await;
        assert_eq!(
            host2
                .next_event_with_clock(&host_roster2, || NOW + 51)
                .await
                .expect("idle close cleanly"),
            None
        );
    }

    #[test]
    fn connect_opts_low_power_profile_updates_effective_policy_config() {
        let dialers = Arc::new(HintDialers::new(
            crate::providers::hints::HintDialerConfig::default(),
        ));
        let builder_opts =
            ConnectOpts::new(Arc::clone(&dialers)).with_power_profile(PowerProfile::LowPower);
        assert_eq!(
            builder_opts.effective_policy_config(),
            PathPolicyConfig::low_power()
        );

        let mut direct_opts = ConnectOpts::new(dialers);
        direct_opts.power_profile = PowerProfile::LowPower;
        assert_eq!(
            direct_opts.effective_policy_config(),
            PathPolicyConfig::low_power()
        );
    }
}
