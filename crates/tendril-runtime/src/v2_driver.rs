//! Async Wire v2 (`0x02`) handshake, PAKE pairing, padded session, and `WakeProvider` drivers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::HybridSigningPublicKey;
use tendril_core::error::CoreError;
use tendril_core::grants::{
    AuditEvent, Grant, RevocationList, authorize_grant, authorize_path_capability,
    verify_grant_with_chain,
};
use tendril_core::group::{GroupManifest, GroupSeq, V2GroupSecrets, decode_group_rendezvous_frame};
use tendril_core::identity::{EndpointIdentity, RotationRecord};
use tendril_core::pairing::{
    PairRouteBinding, PairingManager, PairingPathKind, RouteCheck, RoutePolicy,
    VerifiedRouteStatement,
};
use tendril_core::policy::{CandidateEndpoint, PathPlanner, PathPolicyConfig, ProviderId};
use tendril_core::roster::{PeerState, Roster, V2PeerSecrets};
use tendril_core::routes::RouteSet;
use tendril_core::session::{MAX_QUEUED_ROUTE_SETS, RekeyDirection, RouteExpectation};
use tendril_core::v2::{
    PaddingPolicy, PakeArgon2Params, RekeyStatus, RekeyThresholds, RendezvousReplayCache,
    ScheduleJitterPolicy, SealedSession, V2InnerFrame, V2PairAction, V2PairOutcome,
    V2PakePairInitiator, V2PakePairResponder, V2PinnedHost, V2SessionAction, V2SessionInitiator,
    V2SessionResponder,
};
use tendril_core::wire::{
    FLAG_PAKE_PAIR, InnerFrameType, Intent, PREAMBLE_FLAG_NONE, PathUpgradeMsg, PathUpgradeState,
    Preamble, ResumableFrameReader, WIRE_VERSION_V2, encode_frame,
};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::{Instant as TokioInstant, sleep, timeout, timeout_at};
use zeroize::Zeroizing;

use crate::announce::{RosterAccess, RouteSetSink};
use crate::driver::{
    AttemptError, CandidateError, CandidateFailure, ConnectOpts, ConnectPlan, ConnectResult,
    DEFAULT_PRE_AUTH_TIMEOUT, IngestSlot, PairPolicyOptions, PairPolicyResult, PairingPlan,
    RaceEnd, RouteIngest, SessionEvent, SharedEvidence, StreamSource, WinnerFacts,
    collect_failures, committable_route_check, committed_error, connect_exhausted,
    current_unix_secs, day2_candidate_error, dial_source_with_init, dial_with_policy_candidates,
    finalize_connect, has_complete_outer_frame, pairing_persist_plan, plan_connect, plan_pairing,
    race_candidates, record_evidence, write_protocol_bytes, write_protocol_chunks,
};
use crate::error::RuntimeError;
use crate::provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathReader, PathStream, PathWriter,
    recv_tendril_frame,
};
use crate::providers::egress::SkippedHint;
use crate::providers::hints::DialWire;
#[cfg(feature = "webrtc")]
use crate::providers::webrtc::WebRtcUpgradeHandle;
use crate::rate_limit::{HalfOpenGuard, PreAuthRateLimiter};
use crate::store::StateStore;
use crate::wake::{DEFAULT_WAKE_TIMEOUT, WakeOutcome, WakeProvider, WakeSecret, WakeTarget};

/// Default maximum concurrent 19 MiB Argon2id derivations on a v2 PAKE responder (`4`).
pub const DEFAULT_ARGON2_CONCURRENCY: usize = 4;

/// Maximum bounded wait for an Argon2id permit before failing closed (`250 ms`).
pub const DEFAULT_ARGON2_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(250);

/// Configuration for [`V2ResponderState`].
#[derive(Debug, Clone)]
pub struct V2ResponderConfig {
    pub max_concurrent_argon2: usize,
    pub argon2_acquire_timeout: Duration,
    pub pre_auth_timeout: Duration,
    pub padding: PaddingPolicy,
    pub jitter: ScheduleJitterPolicy,
    pub upgrade_caps: Vec<String>,
    #[cfg(feature = "webrtc")]
    pub webrtc_upgrade_handle: Option<WebRtcUpgradeHandle>,
}

impl Default for V2ResponderConfig {
    fn default() -> Self {
        Self {
            max_concurrent_argon2: DEFAULT_ARGON2_CONCURRENCY,
            argon2_acquire_timeout: DEFAULT_ARGON2_ACQUIRE_TIMEOUT,
            pre_auth_timeout: DEFAULT_PRE_AUTH_TIMEOUT,
            padding: PaddingPolicy::v2_default(),
            jitter: ScheduleJitterPolicy::default(),
            upgrade_caps: Vec::new(),
            #[cfg(feature = "webrtc")]
            webrtc_upgrade_handle: None,
        }
    }
}

/// Host-wide shared state across inbound Wire v2 connections.
///
/// Shares a single [`RendezvousReplayCache`] across all concurrent inbound session
/// handshakes (closing the cross-connection replay oracle) and bounds concurrent
/// `19 MiB` Argon2id PAKE derivations with a [`Semaphore`].
#[derive(Debug, Clone)]
pub struct V2ResponderState {
    replay_cache: Arc<Mutex<RendezvousReplayCache>>,
    argon2_semaphore: Arc<Semaphore>,
    config: V2ResponderConfig,
}

impl Default for V2ResponderState {
    fn default() -> Self {
        Self::new()
    }
}

impl V2ResponderState {
    /// Creates shared responder state with [`V2ResponderConfig::default()`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(V2ResponderConfig::default())
    }

    /// Creates shared responder state with explicit `config`.
    #[must_use]
    pub fn with_config(config: V2ResponderConfig) -> Self {
        let permits = config.max_concurrent_argon2.max(1);
        Self {
            replay_cache: Arc::new(Mutex::new(RendezvousReplayCache::new())),
            argon2_semaphore: Arc::new(Semaphore::new(permits)),
            config,
        }
    }

    /// Returns the shared [`RendezvousReplayCache`] guarding all inbound v2 session handshakes.
    #[must_use]
    pub fn replay_cache(&self) -> Arc<Mutex<RendezvousReplayCache>> {
        Arc::clone(&self.replay_cache)
    }

    /// Returns the bounded [`Semaphore`] gating concurrent Argon2id PAKE derivations.
    #[must_use]
    pub fn argon2_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.argon2_semaphore)
    }

    /// Returns the configured WebRTC upgrade handle, if any.
    #[cfg(feature = "webrtc")]
    #[must_use]
    pub fn webrtc_upgrade_handle(&self) -> Option<&crate::providers::webrtc::WebRtcUpgradeHandle> {
        self.config.webrtc_upgrade_handle.as_ref()
    }

    /// Returns a clone of this responder state with `handle` configured for WebRTC upgrades,
    /// preserving the shared replay cache and Argon2id semaphore.
    #[cfg(feature = "webrtc")]
    #[must_use]
    pub fn with_webrtc_upgrade_handle(
        &self,
        handle: crate::providers::webrtc::WebRtcUpgradeHandle,
    ) -> Self {
        let mut config = self.config.clone();
        config.webrtc_upgrade_handle = Some(handle);
        Self {
            replay_cache: Arc::clone(&self.replay_cache),
            argon2_semaphore: Arc::clone(&self.argon2_semaphore),
            config,
        }
    }

    /// Returns the active [`V2ResponderConfig`].
    #[must_use]
    pub fn config(&self) -> &V2ResponderConfig {
        &self.config
    }

    /// Returns the number of currently available Argon2id concurrency permits.
    #[must_use]
    pub fn available_argon2_permits(&self) -> usize {
        self.argon2_semaphore.available_permits()
    }
}

/// Default process-wide bound on concurrent initiator Argon2id derivations (`2`).
pub const DEFAULT_INITIATOR_ARGON2_PERMITS: usize = 2;

static INITIATOR_ARGON2: OnceLock<Arc<Semaphore>> = OnceLock::new();
static INITIATOR_ARGON2_ACTIVE: AtomicUsize = AtomicUsize::new(0);
static INITIATOR_ARGON2_PEAK: AtomicUsize = AtomicUsize::new(0);

/// Sets the process-wide bound on concurrent Wire v2 initiator Argon2id derivations.
///
/// The first call (or first derivation, which installs [`DEFAULT_INITIATOR_ARGON2_PERMITS`])
/// wins; returns `false` when the bound was already set. "Process-wide" means per loaded copy of
/// `tendril-runtime`.
pub fn set_initiator_argon2_permits(permits: usize) -> bool {
    INITIATOR_ARGON2
        .set(Arc::new(Semaphore::new(permits.max(1))))
        .is_ok()
}

fn initiator_argon2() -> Arc<Semaphore> {
    Arc::clone(
        INITIATOR_ARGON2.get_or_init(|| Arc::new(Semaphore::new(DEFAULT_INITIATOR_ARGON2_PERMITS))),
    )
}

/// Highest number of initiator Argon2id derivations that ran at once in this process.
#[must_use]
pub fn initiator_argon2_peak() -> usize {
    INITIATOR_ARGON2_PEAK.load(Ordering::SeqCst)
}

/// Free initiator Argon2id permits right now (the configured bound minus running or reserved
/// derivations).
#[must_use]
pub fn initiator_argon2_available() -> usize {
    initiator_argon2().available_permits()
}

/// Waits at most `wait` for a process-wide initiator Argon2id permit. The wait is its own budget:
/// it never counts as derivation time, and dropping the future while queued takes nothing.
async fn acquire_initiator_argon2(wait: Duration) -> Result<OwnedSemaphorePermit, RuntimeError> {
    match timeout(wait, initiator_argon2().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(RuntimeError::Protocol(
            "argon2id permit pool closed".to_owned(),
        )),
        Err(_) => Err(RuntimeError::Timeout("argon2id permit wait timed out")),
    }
}

/// One running derivation in `active` (and the high-water mark `peak`), counted until drop,
/// so a derivation that panics never leaves the count raised.
struct ActiveCount<'a>(&'a AtomicUsize);

impl<'a> ActiveCount<'a> {
    fn enter(active: &'a AtomicUsize, peak: &AtomicUsize) -> Self {
        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(now, Ordering::SeqCst);
        Self(active)
    }
}

impl Drop for ActiveCount<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Runs the initiator's blocking `start()` derivation under `permit`. The permit is moved into
/// the blocking closure, so a cancelled attempt holds it until the derivation ends.
async fn start_v2_pake_initiator(
    machine: V2PakePairInitiator,
    permit: OwnedSemaphorePermit,
) -> Result<(V2PakePairInitiator, Vec<V2PairAction>), RuntimeError> {
    let res = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _active = ActiveCount::enter(&INITIATOR_ARGON2_ACTIVE, &INITIATOR_ARGON2_PEAK);
        let mut m = machine;
        let actions = m.start();
        actions.map(|a| (m, a))
    })
    .await
    .map_err(|err| RuntimeError::Protocol(format!("argon2id start task failed: {err}")))?;
    Ok(res?)
}

/// Completed outcome from an async Wire v2 PAKE pairing exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2PairDriveResult {
    pub outcome: V2PairOutcome,
    pub sas: Option<String>,
}

macro_rules! await_deadline {
    ($deadline:expr, $stream:expr, $msg:expr, $fut:expr) => {{
        match timeout_at($deadline, $fut).await {
            Ok(res) => res?,
            Err(_) => {
                let _ = $stream.close().await;
                return Err(RuntimeError::Timeout($msg));
            }
        }
    }};
}

/// Drives a Wire v2 (`0x02`, `flags = 0x01`) hybrid PAKE + `ML-KEM-768` pairing initiator
/// over `stream` within `DEFAULT_PRE_AUTH_TIMEOUT`.
pub async fn drive_v2_pake_pair_initiator(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    pinned_host: Option<V2PinnedHost>,
) -> Result<V2PairDriveResult, RuntimeError> {
    drive_v2_pake_pair_initiator_with_timeout(
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

/// Drives a Wire v2 PAKE pairing initiator over `stream` within `handshake_timeout`.
///
/// The derivation runs under the process-wide initiator permit; the wait for it is bounded by
/// `handshake_timeout` too, as a separate budget before the handshake budget starts.
pub async fn drive_v2_pake_pair_initiator_with_timeout(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    pinned_host: Option<V2PinnedHost>,
    handshake_timeout: Duration,
) -> Result<V2PairDriveResult, RuntimeError> {
    let machine = V2PakePairInitiator::new(
        identity,
        device_name,
        device_kind,
        code,
        pinned_host,
        PakeArgon2Params::production(),
    )?;
    let permit = acquire_initiator_argon2(handshake_timeout).await?;
    let deadline = TokioInstant::now() + handshake_timeout;
    let (mut machine, init_actions) = start_v2_pake_initiator(machine, permit).await?;

    let mut observed_sas = None;
    if let Some(outcome) = await_deadline!(
        deadline,
        stream,
        "pre-auth v2 pairing handshake timed out",
        dispatch_v2_pair_actions(stream, init_actions, &mut observed_sas)
    ) {
        return Ok(V2PairDriveResult {
            outcome,
            sas: observed_sas,
        });
    }

    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
    loop {
        let n = await_deadline!(
            deadline,
            stream,
            "pre-auth v2 pairing handshake timed out",
            stream.recv_chunk(&mut buf)
        );
        if n == 0 {
            return Err(RuntimeError::Closed);
        }
        let actions = machine.feed_bytes(&buf[..n])?;
        if let Some(outcome) = await_deadline!(
            deadline,
            stream,
            "pre-auth v2 pairing handshake timed out",
            dispatch_v2_pair_actions(stream, actions, &mut observed_sas)
        ) {
            return Ok(V2PairDriveResult {
                outcome,
                sas: observed_sas,
            });
        }
    }
}

/// Drives a Wire v2 PAKE pairing initiator and atomically persists `InitiatorPending`
/// (with `min_wire_version >= 2` and `v2_secrets`) via [`StateStore::update_roster`].
#[allow(clippy::too_many_arguments)]
pub async fn drive_v2_pake_pair_initiator_with_store(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    pinned_host: Option<V2PinnedHost>,
    host_name: String,
    relay_hints: Vec<String>,
    store: &StateStore,
    handshake_timeout: Duration,
) -> Result<V2PairDriveResult, RuntimeError> {
    let res = drive_v2_pake_pair_initiator_with_timeout(
        stream,
        identity,
        device_name,
        device_kind,
        code,
        pinned_host,
        handshake_timeout,
    )
    .await?;
    if matches!(res.outcome, V2PairOutcome::InitiatorPending { .. }) {
        store.update_roster(|rst| {
            rst.apply_v2_pair_initiator_outcome(&res.outcome, host_name, relay_hints)?;
            Ok(())
        })?;
    }
    Ok(res)
}

/// Drives a Wire v2 (`0x02`, `flags = 0x01`) PAKE pairing responder over `stream`,
/// bounding Argon2id concurrency via `state` (executing Argon2id on `spawn_blocking`)
/// and updating `roster`.
///
/// Production untrusted listeners should supply a [`PreAuthRateLimiter`] to prevent
/// unauthenticated peers from saturating PAKE permits.
#[allow(clippy::too_many_arguments)]
pub async fn drive_v2_pake_pair_responder(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Arc<Mutex<PairingManager>>,
    roster: &Mutex<Roster>,
    path_kind: PairingPathKind,
    now_unix: u64,
    state: &V2ResponderState,
    rate_limiter: Option<&PreAuthRateLimiter>,
) -> Result<V2PairDriveResult, RuntimeError> {
    drive_v2_pake_pair_responder_with_options(
        stream,
        identity,
        manager,
        roster,
        path_kind,
        now_unix,
        state,
        rate_limiter,
        None,
        state.config.pre_auth_timeout,
    )
    .await
}

/// Drives a Wire v2 PAKE pairing responder with an optional caller-held [`HalfOpenGuard`]
/// and explicit pre-auth timeout.
#[allow(clippy::too_many_arguments)]
pub async fn drive_v2_pake_pair_responder_with_options(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Arc<Mutex<PairingManager>>,
    roster: &Mutex<Roster>,
    path_kind: PairingPathKind,
    now_unix: u64,
    state: &V2ResponderState,
    rate_limiter: Option<&PreAuthRateLimiter>,
    existing_guard: Option<HalfOpenGuard>,
    handshake_timeout: Duration,
) -> Result<V2PairDriveResult, RuntimeError> {
    drive_v2_pake_pair_responder_inner(
        stream,
        identity,
        manager,
        V2ResponderRosterBackend::InMemory { roster },
        path_kind,
        now_unix,
        state,
        rate_limiter,
        existing_guard,
        handshake_timeout,
    )
    .await
}

/// Drives a Wire v2 PAKE pairing responder backed directly by [`StateStore`], executing `msg3`
/// claim verification, code burn, and `min_wire_version = 2` persistence atomically before
/// transmitting `PairResponse`.
#[allow(clippy::too_many_arguments)]
pub async fn drive_v2_pake_pair_responder_with_store(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Arc<Mutex<PairingManager>>,
    store: &StateStore,
    store_lock: &AsyncMutex<()>,
    path_kind: PairingPathKind,
    now_unix: u64,
    state: &V2ResponderState,
    rate_limiter: Option<&PreAuthRateLimiter>,
    existing_guard: Option<HalfOpenGuard>,
    handshake_timeout: Duration,
) -> Result<V2PairDriveResult, RuntimeError> {
    drive_v2_pake_pair_responder_inner(
        stream,
        identity,
        manager,
        V2ResponderRosterBackend::DiskStore { store, store_lock },
        path_kind,
        now_unix,
        state,
        rate_limiter,
        existing_guard,
        handshake_timeout,
    )
    .await
}

enum V2ResponderRosterBackend<'a> {
    InMemory {
        roster: &'a Mutex<Roster>,
    },
    DiskStore {
        store: &'a StateStore,
        store_lock: &'a AsyncMutex<()>,
    },
}

#[allow(clippy::too_many_arguments)]
async fn drive_v2_pake_pair_responder_inner(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    manager: &Arc<Mutex<PairingManager>>,
    backend: V2ResponderRosterBackend<'_>,
    path_kind: PairingPathKind,
    now_unix: u64,
    state: &V2ResponderState,
    rate_limiter: Option<&PreAuthRateLimiter>,
    existing_guard: Option<HalfOpenGuard>,
    handshake_timeout: Duration,
) -> Result<V2PairDriveResult, RuntimeError> {
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

    let mut machine = Some(V2PakePairResponder::new(
        identity,
        path_kind,
        PakeArgon2Params::production(),
    )?);
    let mut observed_sas = None;
    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
    let mut pre_claim_buf = Vec::new();
    let mut pending_claim_bytes = Vec::new();
    let mut awaiting_msg3 = false;
    let deadline = TokioInstant::now() + handshake_timeout;

    loop {
        if !awaiting_msg3 || !has_complete_outer_frame(&pending_claim_bytes)? {
            let n = await_deadline!(
                deadline,
                stream,
                "pre-auth v2 pairing handshake timed out",
                stream.recv_chunk(&mut buf)
            );
            if n == 0 {
                return Err(RuntimeError::Closed);
            }
            if !awaiting_msg3 {
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

        let actions = if !awaiting_msg3 {
            if pre_claim_buf.len() < PREAMBLE_LEN {
                continue;
            }
            let preamble = Preamble::decode(&pre_claim_buf[..PREAMBLE_LEN])?;
            if preamble.version != WIRE_VERSION_V2 {
                return Err(CoreError::UnsupportedVersion(preamble.version).into());
            }
            if preamble.intent != Intent::Pair || preamble.flags != FLAG_PAKE_PAIR {
                return Err(CoreError::ProtocolViolation("expected v2 PAKE pair preamble").into());
            }
            let after_pre = &pre_claim_buf[PREAMBLE_LEN..];
            if !has_complete_outer_frame(after_pre)? {
                continue;
            }
            let body1_len = usize::from(u16::from_be_bytes([after_pre[0], after_pre[1]]));
            let split_at = PREAMBLE_LEN + 2 + body1_len;
            let trailing = pre_claim_buf.split_off(split_at);
            pending_claim_bytes.extend_from_slice(&trailing);
            let msg1_bytes = std::mem::take(&mut pre_claim_buf);

            let mut m = machine
                .take()
                .ok_or_else(|| RuntimeError::Protocol("v2 PAKE responder state missing".into()))?;
            let work = m
                .parse_pake_msg1_header(&msg1_bytes)?
                .ok_or_else(|| RuntimeError::Protocol("v2 PAKE msg1 frame incomplete".into()))?;
            let (msg1_cache_ok, allowed_codes) = {
                let mut mgr = manager
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    mgr.is_pake_msg1_allowed(work.salt(), work.candidate_mac(), now_unix),
                    mgr.allowed_live_codes(work.path(), now_unix),
                )
            };

            // Bound concurrent 19 MiB Argon2id derivations with no PairingManager lock held.
            let acquire_wait = state.config.argon2_acquire_timeout;
            let permit = if acquire_wait.is_zero() {
                match Arc::clone(&state.argon2_semaphore).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = stream.close().await;
                        return Err(RuntimeError::RateLimited(
                            "argon2 concurrency limit saturated",
                        ));
                    }
                }
            } else {
                match timeout(
                    acquire_wait,
                    Arc::clone(&state.argon2_semaphore).acquire_owned(),
                )
                .await
                {
                    Ok(Ok(p)) => p,
                    Ok(Err(_)) => return Err(RuntimeError::Closed),
                    Err(_) => {
                        let _ = stream.close().await;
                        return Err(RuntimeError::RateLimited(
                            "argon2 concurrency limit saturated",
                        ));
                    }
                }
            };

            let (work, matched) = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let matched =
                    V2PakePairResponder::evaluate_pake_msg1(&work, &allowed_codes, msg1_cache_ok)?;
                Ok::<_, CoreError>((work, matched))
            })
            .await
            .map_err(|err| {
                RuntimeError::Protocol(format!("argon2id responder task failed: {err}"))
            })??;
            let recorded = {
                let mut mgr = manager
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                matched.is_some()
                    && mgr.commit_pake_msg1(*work.salt(), *work.candidate_mac(), now_unix)
            };
            let actions = m.finish_pake_msg1(work, matched, recorded)?;
            machine = Some(m);
            awaiting_msg3 = true;
            actions
        } else {
            if !has_complete_outer_frame(&pending_claim_bytes)? {
                continue;
            }
            let claim_bytes = std::mem::take(&mut pending_claim_bytes);
            match &backend {
                V2ResponderRosterBackend::InMemory { roster } => {
                    let m = machine.as_mut().ok_or_else(|| {
                        RuntimeError::Protocol("v2 PAKE responder state missing".into())
                    })?;
                    let mut mgr = manager
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let mut rst = roster
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    m.feed_bytes(&claim_bytes, now_unix, &mut mgr, &mut rst)?
                }
                V2ResponderRosterBackend::DiskStore { store, store_lock } => {
                    let _guard = store_lock.lock().await;
                    let mut m = machine.take().ok_or_else(|| {
                        RuntimeError::Protocol("v2 PAKE responder state missing".into())
                    })?;
                    let store_c: StateStore = (**store).clone();
                    let mgr_c = Arc::clone(manager);
                    let blocking_res = tokio::task::spawn_blocking(move || {
                        let actions = store_c.update_roster(|rst| {
                            let mut mgr = mgr_c
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            m.feed_bytes(&claim_bytes, now_unix, &mut mgr, rst)
                                .map_err(Into::into)
                        })?;
                        Ok::<_, RuntimeError>((m, actions))
                    })
                    .await
                    .map_err(|err| {
                        RuntimeError::Protocol(format!("v2 PAKE store task failed: {err}"))
                    })?;
                    let (returned_m, actions) = blocking_res?;
                    machine = Some(returned_m);
                    actions
                }
            }
        };

        if let Some(outcome) = await_deadline!(
            deadline,
            stream,
            "pre-auth v2 pairing handshake timed out",
            dispatch_v2_pair_actions(stream, actions, &mut observed_sas)
        ) {
            return Ok(V2PairDriveResult {
                outcome,
                sas: observed_sas,
            });
        }
    }
}

async fn dispatch_v2_pair_actions(
    stream: &mut dyn PathStream,
    actions: Vec<V2PairAction>,
    observed_sas: &mut Option<String>,
) -> Result<Option<V2PairOutcome>, RuntimeError> {
    let mut completed = None;
    let mut should_close = false;
    for action in actions {
        match action {
            V2PairAction::WriteBytes(bytes) => {
                write_protocol_bytes(stream, &bytes).await?;
            }
            V2PairAction::SasReady { pairing_sas, .. } => {
                *observed_sas = Some(pairing_sas);
            }
            V2PairAction::Completed(outcome) => {
                if observed_sas.is_none() {
                    match &outcome {
                        V2PairOutcome::InitiatorPending { pairing_sas, .. }
                        | V2PairOutcome::ResponderPending { pairing_sas, .. } => {
                            *observed_sas = Some(pairing_sas.clone());
                        }
                        V2PairOutcome::Rejected { .. } => {}
                    }
                }
                completed = Some(outcome);
            }
            V2PairAction::CloseTransport(_) => {
                should_close = true;
            }
        }
    }
    if should_close {
        let _ = stream.close().await;
    }
    Ok(completed)
}

#[derive(Clone)]
enum SessionRole {
    Initiator {
        local_device_id: String,
        target_host_id: String,
    },
    Responder {
        local_host_id: String,
        local_signing_pub: HybridSigningPublicKey,
        peer_device_id: String,
        peer_static_pub: [u8; 32],
    },
}

struct V2TransportCore {
    sealed: SealedSession,
    role: SessionRole,
    active_grant: Option<Grant>,
    closed: bool,
    /// A frame unsealed by [`V2SessionDriver::stage_commit_frame`], handled first by the next read.
    staged: Option<V2InnerFrame>,
    /// Initiator: `SessionHello.route_seq` was sent, so `0x0C` frames are decoded and queued.
    route_seq_sent: bool,
    /// Responder: the client's `SessionHello.route_seq`.
    peer_route_seq: Option<u64>,
    /// Decoded, not yet verified route sets (at most [`MAX_QUEUED_ROUTE_SETS`]).
    route_sets: Vec<RouteSet>,
    negotiated_upgrade_caps: Vec<String>,
    peer_upgrade_caps: Vec<String>,
    upgrade_state: PathUpgradeState,
}

/// Outcome of [`V2SessionDriver::stage_commit_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StagedCommit {
    /// An authenticated frame other than `0x07 CLOSE` arrived and is staged.
    Commit,
    /// The peer sent `0x07 CLOSE` or ended the stream.
    Close,
}

impl V2TransportCore {
    fn peer_device_id(&self) -> &str {
        match &self.role {
            SessionRole::Initiator { target_host_id, .. } => target_host_id,
            SessionRole::Responder { peer_device_id, .. } => peer_device_id,
        }
    }

    fn lookup_issuer_key(
        &self,
        roster: &Roster,
        issuer_id: &str,
    ) -> Option<HybridSigningPublicKey> {
        match &self.role {
            SessionRole::Initiator { .. } => roster.lookup_active_signing_key(issuer_id),
            SessionRole::Responder {
                local_host_id,
                local_signing_pub,
                ..
            } => {
                if issuer_id == local_host_id {
                    Some(local_signing_pub.clone())
                } else {
                    roster.lookup_active_signing_key(issuer_id)
                }
            }
        }
    }

    fn verify_peer_and_active_grant(
        &self,
        now_unix: u64,
        roster: &Roster,
    ) -> Result<(), CoreError> {
        match &self.role {
            SessionRole::Initiator {
                local_device_id,
                target_host_id,
            } => {
                let entry = roster
                    .get(target_host_id)
                    .ok_or_else(|| CoreError::PeerNotFound(target_host_id.clone()))?;
                match entry.state {
                    PeerState::Pending => {
                        return Err(CoreError::PeerPending(target_host_id.clone()));
                    }
                    PeerState::Revoked => {
                        return Err(CoreError::PeerRevoked(target_host_id.clone()));
                    }
                    PeerState::Active => {
                        entry.require_complete_pin()?;
                    }
                }
                let crl = roster.crl(target_host_id);
                if let Some(list) = crl
                    && list
                        .revoked_devices
                        .iter()
                        .any(|d| d == local_device_id || d == target_host_id)
                {
                    return Err(CoreError::PeerRevoked(local_device_id.clone()));
                }
                if let Some(ref grant) = self.active_grant {
                    verify_grant_with_chain(
                        grant,
                        local_device_id,
                        target_host_id,
                        now_unix,
                        crl,
                        |issuer| roster.lookup_active_signing_key(issuer),
                    )?;
                }
                Ok(())
            }
            SessionRole::Responder {
                local_host_id,
                peer_device_id,
                peer_static_pub,
                ..
            } => {
                roster.lookup_active_by_static(peer_static_pub)?;
                let crl = roster.crl(local_host_id);
                if let Some(list) = crl
                    && list.revoked_devices.iter().any(|d| d == peer_device_id)
                {
                    return Err(CoreError::PeerRevoked(peer_device_id.clone()));
                }
                if let Some(ref grant) = self.active_grant {
                    verify_grant_with_chain(
                        grant,
                        peer_device_id,
                        local_host_id,
                        now_unix,
                        crl,
                        |issuer| self.lookup_issuer_key(roster, issuer),
                    )?;
                }
                Ok(())
            }
        }
    }

    fn authorize_inner(
        &self,
        action_or_cap: &str,
        raw_path: Option<&str>,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        let (subject, root_id) = match &self.role {
            SessionRole::Initiator {
                local_device_id,
                target_host_id,
            } => (local_device_id.as_str(), target_host_id.as_str()),
            SessionRole::Responder {
                local_host_id,
                peer_device_id,
                ..
            } => (peer_device_id.as_str(), local_host_id.as_str()),
        };
        let audit_cap = match raw_path {
            Some(path) => format!("{action_or_cap}:{path}"),
            None => action_or_cap.to_string(),
        };
        let deny = |err: CoreError| -> (Result<(), CoreError>, AuditEvent) {
            (
                Err(err.clone()),
                AuditEvent {
                    ts: now_unix,
                    subject: subject.to_owned(),
                    cap: audit_cap.clone(),
                    grant_nonce: self.active_grant.as_ref().map(|g| g.nonce.clone()),
                    allow: false,
                    reason: err.to_string(),
                },
            )
        };
        if self.closed {
            return deny(CoreError::NotReady("v2 session closed"));
        }
        if let Err(err) = self.verify_peer_and_active_grant(now_unix, roster) {
            return deny(err);
        }
        let crl = roster.crl(root_id);
        match raw_path {
            Some(path) => authorize_path_capability(
                self.active_grant.as_ref(),
                subject,
                root_id,
                action_or_cap,
                path,
                now_unix,
                crl,
                |issuer| self.lookup_issuer_key(roster, issuer),
            ),
            None => authorize_grant(
                self.active_grant.as_ref(),
                subject,
                root_id,
                action_or_cap,
                now_unix,
                crl,
                |issuer| self.lookup_issuer_key(roster, issuer),
            ),
        }
    }

    fn seal_frame(
        &mut self,
        kind: InnerFrameType,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), CoreError> {
        if self.closed {
            return Err(CoreError::NotReady("v2 session closed"));
        }
        let (rekey_ct, outcome) = self.sealed.seal_auto_rekey(kind, payload, now_ms)?;
        let mut writes = Vec::with_capacity(2);
        let rekeyed = if let Some(ct) = rekey_ct {
            writes.push(encode_frame(&ct)?);
            true
        } else {
            false
        };
        writes.push(encode_frame(&outcome.ciphertext)?);
        Ok((writes, rekeyed))
    }

    /// Seals a `0x0C ROUTE_SET` payload for a client that sent `route_seq`. Fails without state
    /// change with `NotReady("peer did not negotiate route sets")`, `FrameTooLarge` (no padding
    /// bucket fits) or `UnknownInnerFrameType` (padding disabled).
    fn seal_route_set(
        &mut self,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), CoreError> {
        if self.closed {
            return Err(CoreError::NotReady("v2 session closed"));
        }
        if !matches!(self.role, SessionRole::Responder { .. }) {
            return Err(CoreError::NotReady("only a responder sends route sets"));
        }
        if self.peer_route_seq.is_none() {
            return Err(CoreError::NotReady("peer did not negotiate route sets"));
        }
        RouteSet::decode(payload)?;
        self.seal_frame(InnerFrameType::RouteSet, payload, now_ms)
    }

    fn seal_path_upgrade(
        &mut self,
        msg: &PathUpgradeMsg,
        now_ms: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), CoreError> {
        if self.closed {
            return Err(CoreError::NotReady("v2 session closed"));
        }
        let payload = self.upgrade_state.prepare_send(msg)?;
        let out = self.seal_frame(InnerFrameType::PathUpgrade, &payload, now_ms)?;
        self.upgrade_state.commit_send(msg);
        Ok(out)
    }

    fn seal_dummy_cover(
        &mut self,
        bucket: usize,
        now_ms: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), CoreError> {
        if self.closed {
            return Err(CoreError::NotReady("v2 session closed"));
        }
        let (rekey_ct, outcome) = self.sealed.seal_dummy_cover_auto_rekey(bucket, now_ms)?;
        let mut writes = Vec::with_capacity(2);
        let rekeyed = if let Some(ct) = rekey_ct {
            writes.push(encode_frame(&ct)?);
            true
        } else {
            false
        };
        writes.push(encode_frame(&outcome.ciphertext)?);
        Ok((writes, rekeyed))
    }

    fn seal_rekey(&mut self, now_ms: u64) -> Result<Vec<u8>, CoreError> {
        if self.closed {
            return Err(CoreError::NotReady("v2 session closed"));
        }
        let ct = self.sealed.seal_rekey(now_ms)?;
        encode_frame(&ct)
    }

    fn seal_close(&mut self, code: u16, reason: &str, now_ms: u64) -> Result<Vec<u8>, CoreError> {
        if self.closed {
            return Err(CoreError::NotReady("v2 session closed"));
        }
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        let outcome = self.sealed.seal(InnerFrameType::Close, &payload, now_ms)?;
        self.closed = true;
        encode_frame(&outcome.ciphertext)
    }

    fn tick(
        &mut self,
        now_unix: u64,
        now_ms: u64,
        roster: &Roster,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        if self.closed {
            return Ok(None);
        }
        if let Err(err) = self.verify_peer_and_active_grant(now_unix, roster) {
            self.closed = true;
            return Err(err);
        }
        if self.sealed.rekey_status(now_ms) == RekeyStatus::RekeyDue {
            let ct = self.sealed.seal_rekey(now_ms)?;
            return Ok(Some(encode_frame(&ct)?));
        }
        Ok(None)
    }

    fn handle_wire_body(
        &mut self,
        body: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
    ) -> Result<WireHandleOutcome, CoreError> {
        if self.closed {
            return Ok(WireHandleOutcome {
                events: Vec::new(),
                writes: Vec::new(),
                should_close: true,
                ingested_crl: None,
                post_verify_err: None,
            });
        }
        let decoded = self.sealed.unseal(body)?;
        self.handle_decoded(decoded, now_unix, now_ms, roster)
    }

    fn handle_decoded(
        &mut self,
        decoded: V2InnerFrame,
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
    ) -> Result<WireHandleOutcome, CoreError> {
        let mut events = Vec::new();
        let mut writes = Vec::new();
        let mut should_close = false;
        match decoded {
            V2InnerFrame::DummyCover { .. } => {}
            V2InnerFrame::Frame { kind, mut payload } => match kind {
                InnerFrameType::Data => {
                    events.push(SessionEvent::AppData(std::mem::take(&mut *payload)));
                }
                InnerFrameType::Grant => {
                    let grant: Grant = serde_json::from_slice(&payload)
                        .map_err(|err| CoreError::Json(err.to_string()))?;
                    let (subject, root_id) = match &self.role {
                        SessionRole::Initiator {
                            local_device_id,
                            target_host_id,
                        } => (local_device_id.as_str(), target_host_id.as_str()),
                        SessionRole::Responder {
                            local_host_id,
                            peer_device_id,
                            ..
                        } => (peer_device_id.as_str(), local_host_id.as_str()),
                    };
                    verify_grant_with_chain(
                        &grant,
                        subject,
                        root_id,
                        now_unix,
                        roster.crl(root_id),
                        |issuer| self.lookup_issuer_key(roster, issuer),
                    )?;
                    self.active_grant = Some(grant.clone());
                    events.push(SessionEvent::GrantUpdated(grant));
                }
                InnerFrameType::Revocation => {
                    let crl: RevocationList = serde_json::from_slice(&payload)
                        .map_err(|err| CoreError::Json(err.to_string()))?;
                    let root_id = match &self.role {
                        SessionRole::Initiator { target_host_id, .. } => target_host_id.clone(),
                        SessionRole::Responder { local_host_id, .. } => local_host_id.clone(),
                    };
                    let root_pub = self
                        .lookup_issuer_key(roster, &root_id)
                        .ok_or_else(|| CoreError::IncompletePin(root_id.clone()))?;
                    let seq = crl.seq;
                    roster.ingest_crl(crl.clone(), &root_id, &root_pub)?;
                    events.push(SessionEvent::RevocationUpdated {
                        issuer: root_id.clone(),
                        seq,
                    });
                    let post_verify_err = self.verify_peer_and_active_grant(now_unix, roster).err();
                    if post_verify_err.is_some() {
                        self.closed = true;
                        should_close = true;
                    }
                    return Ok(WireHandleOutcome {
                        events,
                        writes,
                        should_close,
                        ingested_crl: Some((crl, root_id, root_pub)),
                        post_verify_err,
                    });
                }
                InnerFrameType::Rekey => {
                    if let Err(err) = self.verify_peer_and_active_grant(now_unix, roster) {
                        self.closed = true;
                        return Err(err);
                    }
                    events.push(SessionEvent::Rekeyed {
                        direction: RekeyDirection::Incoming,
                    });
                }
                InnerFrameType::Ping => {
                    if payload.len() != 8 {
                        return Err(CoreError::InvalidInnerFramePayload("PING must be 8 bytes"));
                    }
                    let (mut pong_writes, rekeyed) =
                        self.seal_frame(InnerFrameType::Pong, &payload, now_ms)?;
                    writes.append(&mut pong_writes);
                    if rekeyed {
                        events.push(SessionEvent::Rekeyed {
                            direction: RekeyDirection::Outgoing,
                        });
                    }
                }
                InnerFrameType::Pong => {
                    let cookie: [u8; 8] = payload
                        .as_slice()
                        .try_into()
                        .map_err(|_| CoreError::InvalidInnerFramePayload("PONG must be 8 bytes"))?;
                    events.push(SessionEvent::PongReceived(u64::from_be_bytes(cookie)));
                }
                InnerFrameType::Close => {
                    let code = u16::from_be_bytes([payload[0], payload[1]]);
                    let reason = String::from_utf8(payload[2..].to_vec()).map_err(|_| {
                        CoreError::InvalidInnerFramePayload("CLOSE reason must be UTF-8")
                    })?;
                    self.closed = true;
                    should_close = true;
                    events.push(SessionEvent::Closed { code, reason });
                }
                InnerFrameType::GroupManifest => {
                    let manifest = GroupManifest::from_wire_bytes(&payload)?;
                    events.push(SessionEvent::GroupManifestReceived(Box::new(manifest)));
                }
                InnerFrameType::GroupRendezvous => {
                    let frame = decode_group_rendezvous_frame(&payload)?;
                    events.push(SessionEvent::GroupRendezvousReceived(frame));
                }
                InnerFrameType::RouteSet => match self.role {
                    SessionRole::Responder { .. } => {
                        return Err(CoreError::InvalidInnerFramePayload(
                            "route set from initiator",
                        ));
                    }
                    SessionRole::Initiator { .. } => {
                        if self.route_seq_sent {
                            let set = RouteSet::decode(&payload)?;
                            if self.route_sets.len() >= MAX_QUEUED_ROUTE_SETS {
                                self.route_sets.remove(0);
                            }
                            self.route_sets.push(set);
                        }
                    }
                },
                InnerFrameType::PathUpgrade => {
                    let msg = self.upgrade_state.receive(&payload)?;
                    events.push(SessionEvent::PathUpgrade(msg));
                }
                InnerFrameType::Padding | InnerFrameType::Padded => {
                    return Err(CoreError::UnknownInnerFrameType(kind as u8));
                }
            },
        }
        Ok(WireHandleOutcome {
            events,
            writes,
            should_close,
            ingested_crl: None,
            post_verify_err: None,
        })
    }
}

struct WireHandleOutcome {
    events: Vec<SessionEvent>,
    writes: Vec<Vec<u8>>,
    should_close: bool,
    ingested_crl: Option<(RevocationList, String, HybridSigningPublicKey)>,
    post_verify_err: Option<CoreError>,
}

async fn write_protocol_bytes_timed(
    stream: &mut dyn PathStream,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    match timeout(DEFAULT_WRITE_TIMEOUT, write_protocol_bytes(stream, bytes)).await {
        Ok(res) => res,
        Err(_) => Err(RuntimeError::Timeout("v2 stream write timed out")),
    }
}

async fn write_protocol_chunks_timed(
    writer: &mut dyn PathWriter,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    match timeout(DEFAULT_WRITE_TIMEOUT, write_protocol_chunks(writer, bytes)).await {
        Ok(res) => res,
        Err(_) => Err(RuntimeError::Timeout("v2 writer chunk timed out")),
    }
}

async fn persist_ingested_crl_if_stored(
    store: Option<&StateStore>,
    ingested: Option<(RevocationList, String, HybridSigningPublicKey)>,
) -> Result<(), RuntimeError> {
    let Some(s) = store.cloned() else {
        return Ok(());
    };
    let Some((crl, root_id, root_pub)) = ingested else {
        return Ok(());
    };
    tokio::task::spawn_blocking(move || {
        s.update_roster(|rst| match rst.ingest_crl(crl, &root_id, &root_pub) {
            Ok(()) | Err(CoreError::CrlStaleSeq { .. }) => Ok(()),
            Err(err) => Err(err.into()),
        })
    })
    .await
    .map_err(|err| RuntimeError::Storage(format!("CRL persist task failed: {err}")))??;
    Ok(())
}

/// Drives a Wire v2 (`0x02`) pseudonymous reconnect session initiator to `Established`.
pub async fn drive_v2_session_initiator(
    stream: Box<dyn PathStream>,
    local_identity: &EndpointIdentity,
    target_host_id: &str,
    initial_grant: Option<Grant>,
    roster: &mut Roster,
    now_unix: u64,
) -> Result<V2SessionDriver, RuntimeError> {
    V2SessionDriver::connect(
        stream,
        local_identity,
        target_host_id,
        initial_grant,
        roster,
        now_unix,
    )
    .await
}

/// Drives a Wire v2 (`0x02`) pseudonymous reconnect session responder to `Established`,
/// enforcing the shared [`RendezvousReplayCache`] in `state`.
pub async fn drive_v2_session_responder(
    stream: Box<dyn PathStream>,
    local_identity: &EndpointIdentity,
    roster: &mut Roster,
    now_unix: u64,
    state: &V2ResponderState,
    rate_limiter: Option<&PreAuthRateLimiter>,
) -> Result<V2SessionDriver, RuntimeError> {
    V2SessionDriver::accept(
        stream,
        local_identity,
        roster,
        now_unix,
        state,
        rate_limiter,
    )
    .await
}

fn extract_v2_reconnect_secret(
    roster: &Roster,
    target_host_id: &str,
) -> Result<Zeroizing<[u8; 32]>, RuntimeError> {
    let entry = roster
        .get(target_host_id)
        .ok_or_else(|| CoreError::PeerNotFound(target_host_id.to_owned()))?;
    match entry.state {
        PeerState::Pending => return Err(CoreError::PeerPending(target_host_id.to_owned()).into()),
        PeerState::Revoked => return Err(CoreError::PeerRevoked(target_host_id.to_owned()).into()),
        PeerState::Active => {}
    }
    let secrets = entry
        .v2_secrets
        .as_ref()
        .ok_or_else(|| CoreError::IncompletePin(target_host_id.to_owned()))?;
    Ok(Zeroizing::new(*secrets.reconnect_secret()))
}

fn persist_v2_session_secrets_post_establish(
    roster: &mut Roster,
    peer_id: &str,
) -> Result<(), RuntimeError> {
    let has_secrets = roster
        .get(peer_id)
        .and_then(|e| e.v2_secrets.as_ref())
        .is_some();
    if has_secrets {
        // Retain pairing-derived (reconnect_secret, mailbox_secret) across reconnects and
        // concurrent sessions so dropped/corrupted msg3 cannot desynchronize the peer pair.
        roster.set_peer_min_wire_version(peer_id, WIRE_VERSION_V2)?;
        Ok(())
    } else {
        Err(CoreError::IncompletePin(peer_id.to_owned()).into())
    }
}

/// Async transport driver owning one established Wire v2 (`0x02`) [`SealedSession`]
/// and its [`PathStream`].
pub struct V2SessionDriver {
    stream: Box<dyn PathStream>,
    core: V2TransportCore,
    frame_reader: ResumableFrameReader,
    pending_events: VecDeque<SessionEvent>,
    started_at: Instant,
    peer_static_pub: [u8; 32],
    peer_crl_seq: Option<u64>,
    peer_groups: Option<Vec<GroupSeq>>,
    applied_rotation: Vec<RotationRecord>,
    exported_secrets: Option<V2PeerSecrets>,
    matched_rendezvous: Option<Zeroizing<[u8; 32]>>,
    jitter: ScheduleJitterPolicy,
    store: Option<StateStore>,
    _half_open: Option<HalfOpenGuard>,
    verified_recovery: Option<Box<VerifiedRouteStatement>>,
    route_ingest: IngestSlot,
    #[cfg(feature = "webrtc")]
    webrtc_upgrade_handle: Option<WebRtcUpgradeHandle>,
}

/// Persists a peer revocation observed while a v2 connect failed, before the error surfaces.
///
/// Only a rotation fork or a fresh transition into [`PeerState::Revoked`] is written, so
/// repeated rejected reconnects to an already revoked peer never rewrite the roster.
async fn persist_failed_connect_revocation(
    store: &StateStore,
    store_lock: &AsyncMutex<()>,
    target_host_id: &str,
    err: &RuntimeError,
    was_revoked: bool,
    working_roster: &Roster,
) {
    let fork = matches!(
        err,
        RuntimeError::Core(CoreError::RotationForkDetected { .. })
    );
    let fresh = !was_revoked
        && working_roster
            .get(target_host_id)
            .is_some_and(|entry| entry.state == PeerState::Revoked);
    if !fork && !fresh {
        return;
    }
    let target_owned = target_host_id.to_owned();
    let store_c = store.clone();
    let _guard = store_lock.lock().await;
    let persisted = tokio::task::spawn_blocking(move || {
        store_c.update_roster(|rst| match rst.revoke_peer(&target_owned) {
            Ok(()) | Err(CoreError::PeerNotFound(_)) => Ok(()),
            Err(e) => Err(e.into()),
        })
    })
    .await;
    if !matches!(persisted, Ok(Ok(()))) {
        tracing::warn!("failed to persist v2 peer revocation after connect error");
    }
}

enum V2RosterRef<'a> {
    Direct(&'a mut Roster),
    Locked(&'a Mutex<Roster>),
}

impl V2SessionDriver {
    /// Initiates and completes a Wire v2 (`0x02`) session handshake using the peer's
    /// persisted `v2_secrets.reconnect_secret` from `roster`.
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

    /// Initiates a Wire v2 (`0x02`) session handshake advertising `upgrade_caps` in `SessionHello.upgrade`.
    pub async fn connect_with_upgrade_caps(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        roster: &mut Roster,
        now_unix: u64,
        upgrade_caps: Vec<String>,
    ) -> Result<Self, RuntimeError> {
        let reconnect_secret = extract_v2_reconnect_secret(roster, target_host_id)?;
        let crl_seq = roster.crl(target_host_id).map(|c| c.seq);
        Self::connect_with_roster_ref(
            stream,
            local_identity,
            target_host_id,
            reconnect_secret,
            initial_grant,
            crl_seq,
            PaddingPolicy::v2_default(),
            V2RosterRef::Direct(roster),
            now_unix,
            Vec::new(),
            V2RouteInit::default(),
            upgrade_caps,
        )
        .await
    }

    /// Initiates and completes a Wire v2 session handshake with an explicit `reconnect_secret`
    /// and [`PaddingPolicy`].
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_secret(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        reconnect_secret: [u8; 32],
        initial_grant: Option<Grant>,
        padding: PaddingPolicy,
        roster: &mut Roster,
        now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        let crl_seq = roster.crl(target_host_id).map(|c| c.seq);
        Self::connect_with_roster_ref(
            stream,
            local_identity,
            target_host_id,
            Zeroizing::new(reconnect_secret),
            initial_grant,
            crl_seq,
            padding,
            V2RosterRef::Direct(roster),
            now_unix,
            Vec::new(),
            V2RouteInit::default(),
            Vec::new(),
        )
        .await
    }

    /// Initiates and completes a Wire v2 session handshake using a mutex-guarded roster
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

    /// Initiates a Wire v2 session handshake with a mutex-guarded roster advertising `upgrade_caps`.
    pub async fn connect_locked_with_upgrade_caps(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        roster: &Mutex<Roster>,
        now_unix: u64,
        upgrade_caps: Vec<String>,
    ) -> Result<Self, RuntimeError> {
        let (reconnect_secret, crl_seq) = {
            let guard = roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                extract_v2_reconnect_secret(&guard, target_host_id)?,
                guard.crl(target_host_id).map(|c| c.seq),
            )
        };
        Self::connect_with_roster_ref(
            stream,
            local_identity,
            target_host_id,
            reconnect_secret,
            initial_grant,
            crl_seq,
            PaddingPolicy::v2_default(),
            V2RosterRef::Locked(roster),
            now_unix,
            Vec::new(),
            V2RouteInit::default(),
            upgrade_caps,
        )
        .await
    }

    /// Initiates a Wire v2 session to a group sibling using `reconnect_secret` (the persisted
    /// pairwise secret or the group `pair_bootstrap`) and a mutex-guarded roster, advertising
    /// `groups` in the initiator `SessionHello`.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_group_member(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        reconnect_secret: [u8; 32],
        padding: PaddingPolicy,
        roster: &Mutex<Roster>,
        groups: Vec<GroupSeq>,
        now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        Self::connect_with_roster_ref(
            stream,
            local_identity,
            target_host_id,
            Zeroizing::new(reconnect_secret),
            None,
            None,
            padding,
            V2RosterRef::Locked(roster),
            now_unix,
            groups,
            V2RouteInit::default(),
            Vec::new(),
        )
        .await
    }

    /// Initiates and completes a Wire v2 session backed by [`StateStore`], persisting
    /// any applied rotations and exported v2 secrets ONLY after `Established`.
    pub async fn connect_with_store(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        initial_grant: Option<Grant>,
        store: &StateStore,
        store_lock: &AsyncMutex<()>,
        now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        let mut working_roster = {
            let _guard = store_lock.lock().await;
            let store_c = store.clone();
            tokio::task::spawn_blocking(move || store_c.load_roster())
                .await
                .map_err(|err| RuntimeError::Storage(format!("v2 load roster failed: {err}")))??
        };
        let was_revoked = working_roster
            .get(target_host_id)
            .is_some_and(|entry| entry.state == PeerState::Revoked);
        let mut driver = match Self::connect(
            stream,
            local_identity,
            target_host_id,
            initial_grant,
            &mut working_roster,
            now_unix,
        )
        .await
        {
            Ok(driver) => driver,
            Err(err) => {
                persist_failed_connect_revocation(
                    store,
                    store_lock,
                    target_host_id,
                    &err,
                    was_revoked,
                    &working_roster,
                )
                .await;
                return Err(err);
            }
        };
        let applied_rotation = driver.applied_rotation().to_vec();
        let peer_static = *driver.peer_static_pub();
        let has_exported = driver.exported_v2_secrets().is_some();
        let target_owned = target_host_id.to_owned();
        let store_c = store.clone();
        {
            let _guard = store_lock.lock().await;
            tokio::task::spawn_blocking(move || {
                store_c.update_roster_persisting_revocations(|rst| {
                    if !applied_rotation.is_empty() {
                        let presented_signing = working_roster
                            .get(&target_owned)
                            .and_then(|e| e.signing_pub.clone())
                            .ok_or_else(|| CoreError::IncompletePin(target_owned.clone()))?;
                        rst.apply_verified_rotation(
                            &target_owned,
                            &applied_rotation,
                            &peer_static,
                            &presented_signing,
                        )?;
                    }
                    if has_exported {
                        persist_v2_session_secrets_post_establish(rst, &target_owned)?;
                    }
                    Ok(())
                })
            })
            .await
            .map_err(|err| RuntimeError::Storage(format!("v2 update roster failed: {err}")))??;
        }
        driver.store = Some(store.clone());
        Ok(driver)
    }

    /// Concurrently races candidate paths under Happy Eyeballs rules and activates the
    /// first candidate that completes an authenticated Wire v2 handshake.
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
                *self.dst = self
                    .shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
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
                let (reconnect_secret, crl_seq) = {
                    let guard = roster_c
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (
                        extract_v2_reconnect_secret(&guard, &target_c)?,
                        guard.crl(&target_c).map(|c| c.seq),
                    )
                };
                Self::connect_with_source(
                    StreamSource::Dial {
                        dialer: &*dialer,
                        addr: &cand.addr,
                    },
                    &id_c,
                    &target_c,
                    reconnect_secret,
                    grant_c,
                    crl_seq,
                    PaddingPolicy::v2_default(),
                    V2RosterRef::Locked(&roster_c),
                    now_unix,
                    Vec::new(),
                    V2RouteInit::default(),
                    Vec::new(),
                )
                .await
            }
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_roster_ref(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        reconnect_secret: Zeroizing<[u8; 32]>,
        initial_grant: Option<Grant>,
        crl_seq: Option<u64>,
        padding: PaddingPolicy,
        roster: V2RosterRef<'_>,
        now_unix: u64,
        groups: Vec<GroupSeq>,
        route: V2RouteInit,
        upgrade_caps: Vec<String>,
    ) -> Result<Self, RuntimeError> {
        Self::connect_with_source(
            StreamSource::Stream(stream),
            local_identity,
            target_host_id,
            reconnect_secret,
            initial_grant,
            crl_seq,
            padding,
            roster,
            now_unix,
            groups,
            route,
            upgrade_caps,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_source(
        source: StreamSource<'_>,
        local_identity: &EndpointIdentity,
        target_host_id: &str,
        reconnect_secret: Zeroizing<[u8; 32]>,
        initial_grant: Option<Grant>,
        crl_seq: Option<u64>,
        padding: PaddingPolicy,
        mut roster: V2RosterRef<'_>,
        now_unix: u64,
        groups: Vec<GroupSeq>,
        route: V2RouteInit,
        upgrade_caps: Vec<String>,
    ) -> Result<Self, RuntimeError> {
        let started_at = Instant::now();
        let mut machine = V2SessionInitiator::new(
            local_identity,
            target_host_id,
            *reconnect_secret,
            initial_grant.clone(),
            crl_seq,
        )?
        .with_padding_policy(padding);
        if let Some(expectation) = route.expectation {
            machine = machine.with_route_expectation(expectation)?;
        }
        let upgrade_caps = if source.provider_id() == ProviderId::P2p {
            Vec::new()
        } else {
            upgrade_caps
        };
        let mut machine = machine
            .with_route_seq(route.route_seq)?
            .with_upgrade_caps(upgrade_caps)?;
        machine.set_local_groups(groups)?;
        let start_actions = machine.start(now_unix)?;
        let init_bytes = match start_actions.as_slice() {
            [V2SessionAction::WriteBytes(bytes)] if !bytes.is_empty() => Some(bytes.as_slice()),
            _ => None,
        };
        let (mut stream, fast_open_sent) = dial_source_with_init(source, init_bytes).await?;
        let deadline = TokioInstant::now() + DEFAULT_PRE_AUTH_TIMEOUT;
        let mut frame_reader = ResumableFrameReader::new();
        let mut peer_static_pub = None;
        // A failed handshake closes the stream gracefully before the error is returned.
        let handshake = async {
            if !fast_open_sent {
                for action in start_actions {
                    if let V2SessionAction::WriteBytes(bytes) = action {
                        await_deadline!(
                            deadline,
                            stream,
                            "pre-auth v2 session handshake timed out",
                            write_protocol_bytes_timed(stream.as_mut(), &bytes)
                        );
                    }
                }
            }

            while !machine.is_established() {
                if machine.is_closed() {
                    return Err(RuntimeError::Closed);
                }
                let body = await_deadline!(
                    deadline,
                    stream,
                    "pre-auth v2 session handshake timed out",
                    recv_tendril_frame(stream.as_mut(), &mut frame_reader)
                );
                let framed = encode_frame(&body)?;
                let now_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
                let fed = match &mut roster {
                    V2RosterRef::Direct(r) => {
                        let fed = machine.feed_bytes(&framed, now_unix, now_ms, r);
                        if let Some((evidence, crl_before)) = &route.evidence {
                            record_evidence(
                                evidence,
                                machine.presented_rotation(),
                                r,
                                target_host_id,
                                *crl_before,
                            );
                        }
                        fed
                    }
                    V2RosterRef::Locked(m) => {
                        let mut guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        let fed = machine.feed_bytes(&framed, now_unix, now_ms, &mut guard);
                        if let Some((evidence, crl_before)) = &route.evidence {
                            record_evidence(
                                evidence,
                                machine.presented_rotation(),
                                &guard,
                                target_host_id,
                                *crl_before,
                            );
                        }
                        fed
                    }
                };
                for action in fed? {
                    match action {
                        V2SessionAction::WriteBytes(bytes) => {
                            await_deadline!(
                                deadline,
                                stream,
                                "pre-auth v2 session handshake timed out",
                                write_protocol_bytes_timed(stream.as_mut(), &bytes)
                            );
                        }
                        V2SessionAction::Established {
                            peer_static_pub: p_pub,
                            ..
                        } => {
                            peer_static_pub = Some(p_pub);
                        }
                        _ => {}
                    }
                }
            }
            Ok::<(), RuntimeError>(())
        }
        .await;
        if let Err(err) = handshake {
            let _ = stream.close().await;
            return Err(err);
        }

        let applied_rotation = machine.applied_rotation().to_vec();
        let active_grant = machine.active_grant().cloned();
        let exported_secrets = machine.exported_v2_secrets().cloned();
        let verified_recovery = machine.verified_recovery_statement().cloned().map(Box::new);
        let negotiated_upgrade_caps = machine.negotiated_upgrade_caps().to_vec();
        let peer_upgrade_caps = machine.peer_upgrade_caps().to_vec();
        let mut upgrade_state = PathUpgradeState::new(true);
        upgrade_state.set_negotiated(negotiated_upgrade_caps.clone());
        let sealed = machine.into_sealed_session()?;
        let peer_static = peer_static_pub.ok_or(RuntimeError::Protocol(
            "missing peer static key after v2 establish".to_owned(),
        ))?;

        Ok(Self {
            stream,
            core: V2TransportCore {
                sealed,
                role: SessionRole::Initiator {
                    local_device_id: local_identity.device_id(),
                    target_host_id: target_host_id.to_owned(),
                },
                active_grant,
                closed: false,
                staged: None,
                route_seq_sent: route.route_seq.is_some(),
                peer_route_seq: None,
                route_sets: Vec::new(),
                negotiated_upgrade_caps,
                peer_upgrade_caps,
                upgrade_state,
            },
            frame_reader,
            pending_events: VecDeque::new(),
            started_at,
            peer_static_pub: peer_static,
            peer_crl_seq: None,
            peer_groups: None,
            applied_rotation,
            exported_secrets,
            matched_rendezvous: None,
            jitter: ScheduleJitterPolicy::default(),
            store: None,
            _half_open: None,
            verified_recovery,
            route_ingest: IngestSlot::default(),
            #[cfg(feature = "webrtc")]
            webrtc_upgrade_handle: None,
        })
    }

    /// Accepts and authenticates an inbound Wire v2 (`0x02`) session handshake over `stream`,
    /// enforcing the host's shared [`RendezvousReplayCache`] in `state`.
    pub async fn accept(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &mut Roster,
        now_unix: u64,
        state: &V2ResponderState,
        rate_limiter: Option<&PreAuthRateLimiter>,
    ) -> Result<Self, RuntimeError> {
        Self::accept_with_options(
            stream,
            local_identity,
            roster,
            now_unix,
            state,
            rate_limiter,
            None,
            state.config.pre_auth_timeout,
        )
        .await
    }

    /// Accepts an inbound Wire v2 session handshake with an optional caller-held [`HalfOpenGuard`]
    /// and explicit pre-auth timeout.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_with_options(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &mut Roster,
        now_unix: u64,
        state: &V2ResponderState,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        Self::accept_inner(
            stream,
            local_identity,
            V2AcceptBackend::InMemory(V2RosterRef::Direct(roster)),
            now_unix,
            state,
            rate_limiter,
            existing_guard,
            handshake_timeout,
        )
        .await
    }

    /// Accepts an inbound Wire v2 session handshake using a mutex-guarded roster without
    /// holding the lock across `.await`.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_locked(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        roster: &Mutex<Roster>,
        now_unix: u64,
        state: &V2ResponderState,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        Self::accept_inner(
            stream,
            local_identity,
            V2AcceptBackend::InMemory(V2RosterRef::Locked(roster)),
            now_unix,
            state,
            rate_limiter,
            existing_guard,
            handshake_timeout,
        )
        .await
    }

    /// Accepts an inbound Wire v2 session handshake backed by [`StateStore`], persisting
    /// exported v2 secrets ONLY after `Established` (`msg3` verified against an `Active` peer).
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_with_store(
        stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        store: &StateStore,
        store_lock: &AsyncMutex<()>,
        now_unix: u64,
        state: &V2ResponderState,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        Self::accept_inner(
            stream,
            local_identity,
            V2AcceptBackend::DiskStore { store, store_lock },
            now_unix,
            state,
            rate_limiter,
            existing_guard,
            handshake_timeout,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn accept_inner(
        mut stream: Box<dyn PathStream>,
        local_identity: &EndpointIdentity,
        mut backend: V2AcceptBackend<'_>,
        now_unix: u64,
        state: &V2ResponderState,
        rate_limiter: Option<&PreAuthRateLimiter>,
        existing_guard: Option<HalfOpenGuard>,
        handshake_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        let mut half_open = match existing_guard {
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

        let started_at = Instant::now();
        #[allow(unused_mut)]
        let mut upgrade_caps = if stream.provider_id() == ProviderId::P2p {
            Vec::new()
        } else {
            state.config.upgrade_caps.clone()
        };
        #[cfg(feature = "webrtc")]
        let webrtc_upgrade_handle = if stream.provider_id() == ProviderId::P2p {
            None
        } else {
            if state.config.webrtc_upgrade_handle.is_some()
                && !upgrade_caps
                    .iter()
                    .any(|c| c == tendril_core::UPGRADE_CAP_WEBRTC_V1)
                && upgrade_caps.len() < tendril_core::MAX_UPGRADE_CAPS
            {
                upgrade_caps.push(tendril_core::UPGRADE_CAP_WEBRTC_V1.to_owned());
            }
            state.config.webrtc_upgrade_handle.clone()
        };
        let mut machine = V2SessionResponder::new(local_identity)?
            .with_padding_policy(state.config.padding.clone())
            .with_upgrade_caps(upgrade_caps)?;
        let mut frame_reader = ResumableFrameReader::with_preamble();
        let mut recv_buf = vec![0u8; MAX_OUTER_FRAME_LEN];
        let deadline = TokioInstant::now() + handshake_timeout;

        // 1. Read exact 6-byte v2 session preamble + msg1 frame.
        let preamble = loop {
            if let Some(p) = frame_reader.take_preamble()? {
                break p;
            }
            let n = await_deadline!(
                deadline,
                stream,
                "pre-auth v2 session handshake timed out",
                stream.recv_chunk(&mut recv_buf)
            );
            if n == 0 {
                return Err(RuntimeError::Closed);
            }
            frame_reader.push(&recv_buf[..n])?;
        };
        if preamble.version != WIRE_VERSION_V2 {
            return Err(CoreError::UnsupportedVersion(preamble.version).into());
        }
        if preamble.intent != Intent::Session || preamble.flags != PREAMBLE_FLAG_NONE {
            return Err(CoreError::ProtocolViolation("expected v2 session preamble").into());
        }

        let msg1_body = await_deadline!(
            deadline,
            stream,
            "pre-auth v2 session handshake timed out",
            recv_tendril_frame(stream.as_mut(), &mut frame_reader)
        );
        let msg1_frame = encode_frame(&msg1_body)?;
        let mut msg1_wire = Vec::with_capacity(PREAMBLE_LEN + msg1_frame.len());
        msg1_wire.extend_from_slice(&preamble.encode());
        msg1_wire.extend_from_slice(&msg1_frame);

        let disk_store = match &backend {
            V2AcceptBackend::DiskStore { store, .. } => Some((*store).clone()),
            V2AcceptBackend::InMemory(_) => None,
        };
        let now_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Never persist anything on msg1/msg2!
        let msg1_actions = match &mut backend {
            V2AcceptBackend::InMemory(V2RosterRef::Direct(r)) => {
                let mut cache = state
                    .replay_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                machine.feed_bytes_with_replay_cache(&msg1_wire, now_unix, now_ms, r, &mut cache)?
            }
            V2AcceptBackend::InMemory(V2RosterRef::Locked(m)) => {
                let mut rst = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut cache = state
                    .replay_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                machine.feed_bytes_with_replay_cache(
                    &msg1_wire, now_unix, now_ms, &mut rst, &mut cache,
                )?
            }
            V2AcceptBackend::DiskStore { store, store_lock } => {
                let mut rst = {
                    let _guard = store_lock.lock().await;
                    let store_c = (*store).clone();
                    tokio::task::spawn_blocking(move || store_c.load_roster())
                        .await
                        .map_err(|err| {
                            RuntimeError::Storage(format!("v2 load roster failed: {err}"))
                        })??
                };
                let mut cache = state
                    .replay_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                machine.feed_bytes_with_replay_cache(
                    &msg1_wire, now_unix, now_ms, &mut rst, &mut cache,
                )?
            }
        };
        for action in msg1_actions {
            if let V2SessionAction::WriteBytes(bytes) = action {
                await_deadline!(
                    deadline,
                    stream,
                    "pre-auth v2 session handshake timed out",
                    write_protocol_bytes_timed(stream.as_mut(), &bytes)
                );
            }
        }

        // 2. Read msg3 frame and verify against roster / StateStore.
        let msg3_body = await_deadline!(
            deadline,
            stream,
            "pre-auth v2 session handshake timed out",
            recv_tendril_frame(stream.as_mut(), &mut frame_reader)
        );
        let msg3_frame = encode_frame(&msg3_body)?;
        let now_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);

        let msg3_actions = match &mut backend {
            V2AcceptBackend::InMemory(V2RosterRef::Direct(r)) => {
                let mut cache = state
                    .replay_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                machine.feed_bytes_with_replay_cache(
                    &msg3_frame,
                    now_unix,
                    now_ms,
                    r,
                    &mut cache,
                )?
            }
            V2AcceptBackend::InMemory(V2RosterRef::Locked(m)) => {
                let mut rst = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut cache = state
                    .replay_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                machine.feed_bytes_with_replay_cache(
                    &msg3_frame,
                    now_unix,
                    now_ms,
                    &mut rst,
                    &mut cache,
                )?
            }
            V2AcceptBackend::DiskStore { store, store_lock } => {
                let _guard = store_lock.lock().await;
                let store_c = (*store).clone();
                let cache_arc = Arc::clone(&state.replay_cache);
                let mut m_owned = machine;
                let (m_back, actions) = tokio::task::spawn_blocking(move || {
                    store_c
                        .update_roster_persisting_revocations(|rst| {
                            let mut cache = cache_arc
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let actions = m_owned.feed_bytes_with_replay_cache(
                                &msg3_frame,
                                now_unix,
                                now_ms,
                                rst,
                                &mut cache,
                            )?;
                            if m_owned.is_established()
                                && let Some(peer_id) = m_owned.peer_device_id()
                            {
                                persist_v2_session_secrets_post_establish(rst, peer_id)?;
                            }
                            Ok(actions)
                        })
                        .map(|actions| (m_owned, actions))
                })
                .await
                .map_err(|err| {
                    RuntimeError::Storage(format!("v2 accept store task failed: {err}"))
                })??;
                machine = m_back;
                actions
            }
        };

        let mut peer_static_pub = None;
        for action in msg3_actions {
            match action {
                V2SessionAction::WriteBytes(bytes) => {
                    await_deadline!(
                        deadline,
                        stream,
                        "pre-auth v2 session handshake timed out",
                        write_protocol_bytes_timed(stream.as_mut(), &bytes)
                    );
                }
                V2SessionAction::Established {
                    peer_static_pub: p_pub,
                    ..
                } => {
                    peer_static_pub = Some(p_pub);
                }
                _ => {}
            }
        }

        if !machine.is_established() {
            return Err(RuntimeError::Closed);
        }

        half_open.take();
        if let Some(rl) = rate_limiter
            && let Some(peer_id) = machine.peer_device_id()
        {
            rl.check_peer(peer_id)?;
        }

        let peer_device_id = machine
            .peer_device_id()
            .ok_or_else(|| RuntimeError::Protocol("missing peer_device_id".to_owned()))?
            .to_owned();
        let peer_static = peer_static_pub.ok_or_else(|| {
            RuntimeError::Protocol("missing peer static key after v2 establish".to_owned())
        })?;
        let peer_crl_seq = machine.peer_crl_seq();
        let peer_route_seq = machine.peer_route_seq();
        let peer_groups = machine.peer_groups().map(<[GroupSeq]>::to_vec);
        let active_grant = machine.active_grant().cloned();
        let exported_secrets = machine.exported_v2_secrets().cloned();
        let matched_rendezvous = machine
            .matched_rendezvous_secret()
            .map(|s| Zeroizing::new(*s));
        let negotiated_upgrade_caps = machine.negotiated_upgrade_caps().to_vec();
        let peer_upgrade_caps = machine.peer_upgrade_caps().to_vec();
        let mut upgrade_state = PathUpgradeState::new(false);
        upgrade_state.set_negotiated(negotiated_upgrade_caps.clone());
        let sealed = machine.into_sealed_session()?;

        Ok(Self {
            stream,
            core: V2TransportCore {
                sealed,
                role: SessionRole::Responder {
                    local_host_id: local_identity.host_id().to_owned(),
                    local_signing_pub: local_identity.signing_key().public_key().clone(),
                    peer_device_id,
                    peer_static_pub: peer_static,
                },
                active_grant,
                closed: false,
                staged: None,
                route_seq_sent: false,
                peer_route_seq,
                route_sets: Vec::new(),
                negotiated_upgrade_caps,
                peer_upgrade_caps,
                upgrade_state,
            },
            frame_reader,
            pending_events: VecDeque::new(),
            started_at,
            peer_static_pub: peer_static,
            peer_crl_seq,
            peer_groups,
            applied_rotation: Vec::new(),
            exported_secrets,
            matched_rendezvous,
            jitter: state.config.jitter,
            store: disk_store,
            _half_open: half_open,
            verified_recovery: None,
            route_ingest: IngestSlot::default(),
            #[cfg(feature = "webrtc")]
            webrtc_upgrade_handle,
        })
    }

    async fn write_wire_frames(&mut self, writes: &[Vec<u8>]) -> Result<(), RuntimeError> {
        for w in writes {
            if let Err(err) = write_protocol_bytes_timed(self.stream.as_mut(), w).await {
                self.core.closed = true;
                let _ = self.stream.close().await;
                return Err(err);
            }
        }
        Ok(())
    }

    /// Sends encrypted, bucket-padded `0x01 DATA` (`0x09 PADDED` when padding is enabled).
    pub async fn send_data(&mut self, payload: &[u8]) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) = self
            .core
            .seal_frame(InnerFrameType::Data, payload, now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }

    /// Sends encrypted, bucket-padded `0x0A GROUP_MANIFEST`.
    pub async fn send_group_manifest(
        &mut self,
        manifest: &GroupManifest,
    ) -> Result<(), RuntimeError> {
        let json = manifest.to_wire_bytes()?;
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) =
            self.core
                .seal_frame(InnerFrameType::GroupManifest, &json, now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }

    /// Sends encrypted, bucket-padded `0x0B GROUP_RENDEZVOUS` carrying `secrets` for `group_id`.
    pub async fn send_group_rendezvous(
        &mut self,
        secrets: &V2GroupSecrets,
        group_id: &str,
    ) -> Result<(), RuntimeError> {
        let frame = secrets.to_rendezvous_frame(group_id)?;
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) =
            self.core
                .seal_frame(InnerFrameType::GroupRendezvous, &frame[..], now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }

    /// Returns the group gossip summary the initiator advertised in `SessionHello`, if any.
    #[must_use]
    pub fn peer_groups(&self) -> Option<&[GroupSeq]> {
        self.peer_groups.as_deref()
    }

    /// Sends encrypted, bucket-padded `0x02 GRANT`.
    pub async fn send_grant(&mut self, grant: &Grant) -> Result<(), RuntimeError> {
        let json = Zeroizing::new(
            serde_json::to_vec(grant).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) = self.core.seal_frame(InnerFrameType::Grant, &json, now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }

    /// Sends encrypted, bucket-padded `0x03 REVOCATION`.
    pub async fn send_revocation(&mut self, crl: &RevocationList) -> Result<(), RuntimeError> {
        let json = Zeroizing::new(
            serde_json::to_vec(crl).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) = self
            .core
            .seal_frame(InnerFrameType::Revocation, &json, now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }

    /// Sends encrypted `0x04 REKEY` and rotates the outgoing cipher key + jittered thresholds.
    pub async fn send_rekey(&mut self) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let wire = self.core.seal_rekey(now_ms)?;
        self.write_wire_frames(std::slice::from_ref(&wire)).await?;
        self.pending_events.push_back(SessionEvent::Rekeyed {
            direction: RekeyDirection::Outgoing,
        });
        Ok(())
    }

    /// Sends encrypted, bucket-padded `0x05 PING`.
    pub async fn send_ping(&mut self, cookie: u64) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) =
            self.core
                .seal_frame(InnerFrameType::Ping, &cookie.to_be_bytes(), now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }

    /// Sends a pure `0x08 PADDING` cover frame sized to `bucket`.
    pub async fn send_dummy_cover(&mut self, bucket: usize) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) = self.core.seal_dummy_cover(bucket, now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }

    /// Sends encrypted `0x07 CLOSE` and closes the underlying transport stream.
    pub async fn send_close(&mut self, code: u16, reason: &str) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let wire = self.core.seal_close(code, reason, now_ms)?;
        let res = self.write_wire_frames(std::slice::from_ref(&wire)).await;
        let _ = self.stream.close().await;
        res
    }

    /// Advances rekey/grant expiration checks against `roster`.
    pub async fn tick(&mut self, now_unix: u64, roster: &Roster) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        match self.core.tick(now_unix, now_ms, roster) {
            Ok(Some(wire)) => {
                self.write_wire_frames(std::slice::from_ref(&wire)).await?;
                self.pending_events.push_back(SessionEvent::Rekeyed {
                    direction: RekeyDirection::Outgoing,
                });
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(err) => {
                let _ = self.stream.close().await;
                Err(err.into())
            }
        }
    }

    /// Samples the next CSPRNG-jittered keepalive delay from [`ScheduleJitterPolicy`].
    pub fn next_keepalive_delay(&self) -> Result<Duration, RuntimeError> {
        let ms = self.jitter.next_ping_delay_ms()?;
        Ok(Duration::from_millis(ms))
    }

    /// Evaluates default-deny capability authorization and produces a structured audit event.
    pub fn authorize(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        self.core
            .authorize_inner(requested_cap, None, now_unix, roster)
    }

    /// Authorizes path-scoped `action` on `raw_path` after strict canonicalization.
    pub fn authorize_path(
        &self,
        action: &str,
        raw_path: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        self.core
            .authorize_inner(action, Some(raw_path), now_unix, roster)
    }

    /// Returns the authenticated peer device ID.
    #[must_use]
    pub fn peer_device_id(&self) -> &str {
        self.core.peer_device_id()
    }

    /// Returns the authenticated peer's static X25519 public key.
    #[must_use]
    pub const fn peer_static_pub(&self) -> &[u8; 32] {
        &self.peer_static_pub
    }

    /// Returns the CRL sequence advertised by the peer in `SessionHello`, if any.
    #[must_use]
    pub const fn peer_crl_seq(&self) -> Option<u64> {
        self.peer_crl_seq
    }

    /// Returns the currently verified capability grant attached to the session, if any.
    #[must_use]
    pub const fn active_grant(&self) -> Option<&Grant> {
        self.core.active_grant.as_ref()
    }

    /// Returns the verified host rotation chain applied during handshake, if any.
    #[must_use]
    pub fn applied_rotation(&self) -> &[RotationRecord] {
        &self.applied_rotation
    }

    /// Returns the newly exported v2 `(reconnect_secret, mailbox_secret)` derived at establish.
    #[must_use]
    pub const fn exported_v2_secrets(&self) -> Option<&V2PeerSecrets> {
        self.exported_secrets.as_ref()
    }

    /// Returns the reconnect secret that admitted an accepted session's `msg1` (responder only).
    #[must_use]
    pub fn matched_rendezvous_secret(&self) -> Option<&[u8; 32]> {
        self.matched_rendezvous.as_deref()
    }

    /// Persists CRLs ingested during this session to `store`, as a store-backed accept does.
    pub fn attach_store(&mut self, store: StateStore) {
        self.store = Some(store);
    }

    /// Returns the active jittered [`RekeyThresholds`] for the current cipher epoch.
    #[must_use]
    pub const fn rekey_thresholds(&self) -> RekeyThresholds {
        self.core.sealed.rekey_thresholds()
    }

    /// Returns the number of frames sealed in the current outgoing cipher epoch.
    #[must_use]
    pub const fn frames_sent(&self) -> u64 {
        self.core.sealed.frames_sent()
    }

    /// Returns the current outgoing AEAD nonce counter.
    #[must_use]
    pub const fn tx_nonce(&self) -> u64 {
        self.core.sealed.tx_nonce()
    }

    /// Returns the current incoming AEAD nonce counter.
    #[must_use]
    pub const fn rx_nonce(&self) -> u64 {
        self.core.sealed.rx_nonce()
    }

    /// Returns the provider ID backing the active stream.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.stream.provider_id()
    }

    /// Returns the path-upgrade capabilities negotiated with the peer.
    #[must_use]
    pub fn negotiated_upgrade_caps(&self) -> &[String] {
        &self.core.negotiated_upgrade_caps
    }

    /// Returns the raw path-upgrade capabilities advertised by the peer in hello.
    #[must_use]
    pub fn peer_upgrade_caps(&self) -> &[String] {
        &self.core.peer_upgrade_caps
    }

    /// Sends one encrypted `0x0D PATH_UPGRADE` frame wrapped inside `0x09 PADDED`.
    pub async fn send_path_upgrade(&mut self, msg: &PathUpgradeMsg) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) = self.core.seal_path_upgrade(msg, now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }

    /// Attaches a host-side [`WebRtcUpgradeHandle`] that auto-answers matching in-band offers.
    #[cfg(feature = "webrtc")]
    #[must_use]
    pub fn with_webrtc_upgrade_handle(mut self, handle: WebRtcUpgradeHandle) -> Self {
        self.webrtc_upgrade_handle = Some(handle);
        self
    }

    /// Sets or clears the host-side [`WebRtcUpgradeHandle`] on an established [`V2SessionDriver`].
    #[cfg(feature = "webrtc")]
    pub fn set_webrtc_upgrade_handle(&mut self, handle: Option<WebRtcUpgradeHandle>) {
        self.webrtc_upgrade_handle = handle;
    }

    #[cfg(feature = "webrtc")]
    async fn maybe_auto_respond_offer(&mut self, upgrade_id: u64, protocol: &str, sdp: &str) {
        let Some(ref handle) = self.webrtc_upgrade_handle else {
            return;
        };
        if protocol != tendril_core::UPGRADE_CAP_WEBRTC_V1 {
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
                reason: crate::driver::webrtc_reject_reason(&err),
            },
        };
        if let Err(err) = self.send_path_upgrade(&reply).await {
            tracing::debug!(error = %err, "failed to send auto WebRTC path upgrade reply");
        }
    }

    /// Returns the next semantic event, reading and decrypting padded/cover transport frames.
    pub async fn next_event(
        &mut self,
        now_unix: u64,
        roster: &mut Roster,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        let call_start = Instant::now();
        self.next_event_with_roster(V2RosterRef::Direct(roster), move || {
            now_unix.saturating_add(call_start.elapsed().as_secs())
        })
        .await
    }

    /// Returns the next semantic event using wall-clock time sampled when each frame arrives.
    pub async fn next_event_now(
        &mut self,
        roster: &mut Roster,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        self.next_event_with_roster(V2RosterRef::Direct(roster), current_unix_secs)
            .await
    }

    /// Returns the next semantic event using a mutex-guarded roster without holding the lock across `.await`.
    pub async fn next_event_locked(
        &mut self,
        now_unix: u64,
        roster: &Mutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        let call_start = Instant::now();
        self.next_event_with_roster(V2RosterRef::Locked(roster), move || {
            now_unix.saturating_add(call_start.elapsed().as_secs())
        })
        .await
    }

    /// Returns the next semantic event using a mutex-guarded roster and wall-clock time.
    pub async fn next_event_locked_now(
        &mut self,
        roster: &Mutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        self.next_event_with_roster(V2RosterRef::Locked(roster), current_unix_secs)
            .await
    }

    /// Reads and unseals the first transport frame after `Established` without acting on it.
    ///
    /// Nothing is written and no roster or store is touched. A frame other than `0x07 CLOSE` is
    /// staged and handled first by the next `next_event_*` call (also after
    /// [`Self::into_concurrent`]); CLOSE or EOF returns [`StagedCommit::Close`]. Any error marks
    /// the session closed.
    pub(crate) async fn stage_commit_frame(&mut self) -> Result<StagedCommit, RuntimeError> {
        let res = self.read_commit_frame().await;
        if !matches!(res, Ok(StagedCommit::Commit)) {
            self.core.closed = true;
        }
        res
    }

    async fn read_commit_frame(&mut self) -> Result<StagedCommit, RuntimeError> {
        let mut recv_buf = vec![0u8; MAX_OUTER_FRAME_LEN];
        let body = loop {
            if let Some(b) = self.frame_reader.next_frame()? {
                break b;
            }
            let n = self.stream.recv_chunk(&mut recv_buf).await?;
            if n == 0 {
                return Ok(StagedCommit::Close);
            }
            self.frame_reader.push(&recv_buf[..n])?;
        };
        match self.core.sealed.unseal(&body)? {
            V2InnerFrame::Frame {
                kind: InnerFrameType::Close,
                ..
            } => Ok(StagedCommit::Close),
            frame => {
                self.core.staged = Some(frame);
                Ok(StagedCommit::Commit)
            }
        }
    }

    async fn next_event_with_roster(
        &mut self,
        mut roster: V2RosterRef<'_>,
        mut now_fn: impl FnMut() -> u64,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        let mut recv_buf = vec![0u8; MAX_OUTER_FRAME_LEN];
        loop {
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
            if self.core.closed {
                return Ok(None);
            }
            let staged = self.core.staged.take();
            let body = if staged.is_some() {
                Vec::new()
            } else if let Some(b) = self.frame_reader.next_frame()? {
                b
            } else {
                let n = self.stream.recv_chunk(&mut recv_buf).await?;
                if n == 0 {
                    return Ok(None);
                }
                self.frame_reader.push(&recv_buf[..n])?;
                continue;
            };
            let now_unix = now_fn();
            let now_ms = self.elapsed_ms();
            let core = &mut self.core;
            let handle = |r: &mut Roster| match staged {
                Some(frame) => core.handle_decoded(frame, now_unix, now_ms, r),
                None => core.handle_wire_body(&body, now_unix, now_ms, r),
            };
            let res = match &mut roster {
                V2RosterRef::Direct(r) => handle(r),
                V2RosterRef::Locked(m) => {
                    let mut guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    handle(&mut guard)
                }
            };
            match res {
                Ok(WireHandleOutcome {
                    events,
                    writes,
                    should_close,
                    ingested_crl,
                    post_verify_err,
                }) => {
                    if post_verify_err.is_none() {
                        self.pending_events.extend(events);
                    }
                    if let Some((crl, issuer, _)) = ingested_crl.as_ref() {
                        self.route_ingest
                            .note_crls(vec![(issuer.clone(), crl.clone())]);
                    }
                    if let Err(err) =
                        persist_ingested_crl_if_stored(self.store.as_ref(), ingested_crl).await
                    {
                        self.core.closed = true;
                        let _ = self.stream.close().await;
                        self.route_ingest.run(Vec::new()).await;
                        return Err(err);
                    }
                    if let Err(err) = self.write_wire_frames(&writes).await {
                        self.route_ingest.run(Vec::new()).await;
                        return Err(err);
                    }
                    if let Some(err) = post_verify_err {
                        self.core.closed = true;
                        let _ = self.stream.close().await;
                        // A CRL that revoked the peer or this device is persisted before the
                        // session ends.
                        self.route_ingest.run(Vec::new()).await;
                        return Err(err.into());
                    }
                    if should_close {
                        let _ = self.stream.close().await;
                    }
                    let sets = std::mem::take(&mut self.core.route_sets);
                    self.route_ingest.run(sets).await;
                }
                Err(err) => {
                    self.core.closed = true;
                    let _ = self.stream.close().await;
                    self.route_ingest.run(Vec::new()).await;
                    return Err(err.into());
                }
            }
        }
    }

    /// Converts this established [`V2SessionDriver`] into a full-duplex [`ConcurrentV2Session`].
    #[must_use]
    pub fn into_concurrent(self) -> ConcurrentV2Session {
        let provider_id = self.stream.provider_id();
        let is_closed = self.core.closed;
        let peer_device_id = self.core.peer_device_id().to_owned();
        let negotiated_upgrade_caps = self.core.negotiated_upgrade_caps.clone();
        let peer_upgrade_caps = self.core.peer_upgrade_caps.clone();
        let (reader, writer) = self.stream.into_split();
        let (shutdown_tx, _) = watch::channel(is_closed);
        ConcurrentV2Session {
            core: Mutex::new(self.core),
            reader: AsyncMutex::new(V2SessionReadHalf {
                reader,
                frame_reader: self.frame_reader,
                recv_buf: vec![0u8; MAX_OUTER_FRAME_LEN],
            }),
            writer: AsyncMutex::new(writer),
            pending_events: Mutex::new(self.pending_events),
            event_notify: Notify::new(),
            shutdown_tx,
            started_at: self.started_at,
            provider_id,
            peer_device_id,
            peer_groups: self.peer_groups,
            exported_secrets: self.exported_secrets,
            jitter: self.jitter,
            store: self.store,
            _half_open: self._half_open,
            route_ingest: self.route_ingest,
            negotiated_upgrade_caps,
            peer_upgrade_caps,
            #[cfg(feature = "webrtc")]
            webrtc_upgrade_handle: Mutex::new(self.webrtc_upgrade_handle),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Routes every `0x0C` route set this initiator session receives to
    /// [`crate::announce::ingest_route_sets`] for its peer under `policy`. Sets arrive only when
    /// the session sent `SessionHello.route_seq`; they never reach the event stream.
    pub fn set_route_ingest(&mut self, access: RosterAccess, policy: RoutePolicy) {
        let peer = self.core.peer_device_id().to_owned();
        self.route_ingest
            .set(RouteIngest::new(access, peer, policy));
    }

    /// The `route_seq` the client sent in `SessionHello` (responder sessions).
    #[must_use]
    pub const fn peer_route_seq(&self) -> Option<u64> {
        self.core.peer_route_seq
    }

    /// Sends one `0x0C ROUTE_SET` payload inside `0x09 PADDED` (responder, to a client that sent
    /// `route_seq`). Core errors are returned unchanged and leave the session open when they mean
    /// the frame cannot be sent (`FrameTooLarge`, `UnknownInnerFrameType`, not negotiated).
    pub async fn send_route_set(&mut self, payload: &[u8]) -> Result<(), RuntimeError> {
        let now_ms = self.elapsed_ms();
        let (writes, rekeyed) = self.core.seal_route_set(payload, now_ms)?;
        self.write_wire_frames(&writes).await?;
        if rekeyed {
            self.pending_events.push_back(SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }
        Ok(())
    }
}

enum V2AcceptBackend<'a> {
    InMemory(V2RosterRef<'a>),
    DiskStore {
        store: &'a StateStore,
        store_lock: &'a AsyncMutex<()>,
    },
}

struct V2SessionReadHalf {
    reader: Box<dyn PathReader>,
    frame_reader: ResumableFrameReader,
    recv_buf: Vec<u8>,
}

/// Full-duplex concurrent driver for one established Wire v2 (`0x02`) [`SealedSession`].
///
/// Locks follow a strict total order: `reader` -> `writer` -> `core` -> `roster` ->
/// `pending_events`. Neither `core`, `roster`, nor `pending_events` is held across `.await`.
/// The client route ingest is never taken while `core` or `roster` is held (see
/// `driver::IngestSlot`).
pub struct ConcurrentV2Session {
    core: Mutex<V2TransportCore>,
    reader: AsyncMutex<V2SessionReadHalf>,
    writer: AsyncMutex<Box<dyn PathWriter>>,
    pending_events: Mutex<VecDeque<SessionEvent>>,
    event_notify: Notify,
    shutdown_tx: watch::Sender<bool>,
    started_at: Instant,
    provider_id: ProviderId,
    peer_device_id: String,
    peer_groups: Option<Vec<GroupSeq>>,
    exported_secrets: Option<V2PeerSecrets>,
    jitter: ScheduleJitterPolicy,
    store: Option<StateStore>,
    _half_open: Option<HalfOpenGuard>,
    route_ingest: IngestSlot,
    negotiated_upgrade_caps: Vec<String>,
    peer_upgrade_caps: Vec<String>,
    #[cfg(feature = "webrtc")]
    webrtc_upgrade_handle: Mutex<Option<WebRtcUpgradeHandle>>,
}

impl ConcurrentV2Session {
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
        let core = self
            .core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        core.authorize_inner(requested_cap, None, now_unix, roster)
    }

    /// Evaluates default-deny capability authorization against a shared roster lock while
    /// maintaining `core -> roster` lock order.
    pub fn authorize_locked(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &Mutex<Roster>,
    ) -> (Result<(), CoreError>, AuditEvent) {
        let core = self
            .core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let roster_guard = roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        core.authorize_inner(requested_cap, None, now_unix, &roster_guard)
    }

    /// Returns the authenticated peer device ID.
    #[must_use]
    pub fn peer_device_id(&self) -> &str {
        &self.peer_device_id
    }

    /// Returns the provider ID backing the active stream.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Returns the path-upgrade capabilities negotiated with the peer.
    #[must_use]
    pub fn negotiated_upgrade_caps(&self) -> &[String] {
        &self.negotiated_upgrade_caps
    }

    /// Returns the raw path-upgrade capabilities advertised by the peer in hello.
    #[must_use]
    pub fn peer_upgrade_caps(&self) -> &[String] {
        &self.peer_upgrade_caps
    }

    /// Sets or clears the host-side [`WebRtcUpgradeHandle`] on an established [`ConcurrentV2Session`].
    #[cfg(feature = "webrtc")]
    pub fn set_webrtc_upgrade_handle(&self, handle: Option<WebRtcUpgradeHandle>) {
        *self
            .webrtc_upgrade_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = handle;
    }

    /// Sends one encrypted `0x0D PATH_UPGRADE` frame concurrently with inbound polling.
    pub async fn send_path_upgrade(&self, msg: &PathUpgradeMsg) -> Result<(), RuntimeError> {
        self.run_write_op(|core, now_ms| core.seal_path_upgrade(msg, now_ms))
            .await
    }

    #[cfg(feature = "webrtc")]
    async fn maybe_auto_respond_offer(&self, upgrade_id: u64, protocol: &str, sdp: &str) {
        let handle = {
            self.webrtc_upgrade_handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        let Some(handle) = handle else {
            return;
        };
        if protocol != tendril_core::UPGRADE_CAP_WEBRTC_V1 {
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
                reason: crate::driver::webrtc_reject_reason(&err),
            },
        };
        if let Err(err) = self.send_path_upgrade(&reply).await {
            tracing::debug!(error = %err, "failed to send auto WebRTC path upgrade reply");
        }
    }

    /// Returns the exported v2 `(reconnect_secret, mailbox_secret)` derived at establish.
    #[must_use]
    pub const fn exported_v2_secrets(&self) -> Option<&V2PeerSecrets> {
        self.exported_secrets.as_ref()
    }

    /// Returns the group gossip summary the initiator advertised in `SessionHello`, if any.
    #[must_use]
    pub fn peer_groups(&self) -> Option<&[GroupSeq]> {
        self.peer_groups.as_deref()
    }

    /// Samples the next CSPRNG-jittered keepalive delay from [`ScheduleJitterPolicy`].
    pub fn next_keepalive_delay(&self) -> Result<Duration, RuntimeError> {
        let ms = self.jitter.next_ping_delay_ms()?;
        Ok(Duration::from_millis(ms))
    }

    /// Sends encrypted, bucket-padded `0x0A GROUP_MANIFEST` concurrently with inbound polling.
    pub async fn send_group_manifest(&self, manifest: &GroupManifest) -> Result<(), RuntimeError> {
        let json = manifest.to_wire_bytes()?;
        self.run_write_op(|core, now_ms| {
            core.seal_frame(InnerFrameType::GroupManifest, &json, now_ms)
        })
        .await
    }

    /// Sends encrypted, bucket-padded `0x0B GROUP_RENDEZVOUS` carrying `secrets` for `group_id`.
    pub async fn send_group_rendezvous(
        &self,
        secrets: &V2GroupSecrets,
        group_id: &str,
    ) -> Result<(), RuntimeError> {
        let frame = secrets.to_rendezvous_frame(group_id)?;
        self.run_write_op(|core, now_ms| {
            core.seal_frame(InnerFrameType::GroupRendezvous, &frame[..], now_ms)
        })
        .await
    }

    /// Sends encrypted, bucket-padded `0x01 DATA` concurrently with inbound polling.
    pub async fn send_data(&self, payload: &[u8]) -> Result<(), RuntimeError> {
        self.run_write_op(|core, now_ms| core.seal_frame(InnerFrameType::Data, payload, now_ms))
            .await
    }

    /// Like [`Self::send_data`], but evaluates `authority` while holding the writer lock and
    /// before sealing; an `Err` aborts the write and leaves the session untouched.
    pub async fn send_data_authorized(
        &self,
        payload: &[u8],
        authority: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.run_authorized_write_op(authority, |core, now_ms| {
            core.seal_frame(InnerFrameType::Data, payload, now_ms)
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
        let json = manifest.to_wire_bytes()?;
        self.run_authorized_write_op(authority, |core, now_ms| {
            core.seal_frame(InnerFrameType::GroupManifest, &json, now_ms)
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
        self.run_authorized_write_op(authority, |core, now_ms| {
            core.seal_frame(InnerFrameType::GroupRendezvous, &frame[..], now_ms)
        })
        .await
    }

    /// Sends encrypted, bucket-padded `0x02 GRANT`.
    pub async fn send_grant(&self, grant: &Grant) -> Result<(), RuntimeError> {
        let json = Zeroizing::new(
            serde_json::to_vec(grant).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        self.run_write_op(|core, now_ms| core.seal_frame(InnerFrameType::Grant, &json, now_ms))
            .await
    }

    /// Sends encrypted, bucket-padded `0x03 REVOCATION`.
    pub async fn send_revocation(&self, crl: &RevocationList) -> Result<(), RuntimeError> {
        let json = Zeroizing::new(
            serde_json::to_vec(crl).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        self.run_write_op(|core, now_ms| core.seal_frame(InnerFrameType::Revocation, &json, now_ms))
            .await
    }

    /// Sends encrypted `0x04 REKEY` and rotates outgoing cipher keys.
    pub async fn send_rekey(&self) -> Result<(), RuntimeError> {
        self.run_write_op(|core, now_ms| Ok((vec![core.seal_rekey(now_ms)?], true)))
            .await
    }

    /// Sends encrypted, bucket-padded `0x05 PING`.
    pub async fn send_ping(&self, cookie: u64) -> Result<(), RuntimeError> {
        self.run_write_op(|core, now_ms| {
            core.seal_frame(InnerFrameType::Ping, &cookie.to_be_bytes(), now_ms)
        })
        .await
    }

    /// Sends a pure `0x08 PADDING` cover frame sized to `bucket`.
    pub async fn send_dummy_cover(&self, bucket: usize) -> Result<(), RuntimeError> {
        self.run_write_op(|core, now_ms| core.seal_dummy_cover(bucket, now_ms))
            .await
    }

    /// Sends encrypted `0x07 CLOSE` and shuts down the transport writer.
    pub async fn send_close(&self, code: u16, reason: &str) -> Result<(), RuntimeError> {
        let mut writer = self.writer.lock().await;
        let wire = {
            let now_ms = self.elapsed_ms();
            let mut core = self
                .core
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            core.seal_close(code, reason, now_ms)?
        };
        let res = write_protocol_chunks_timed(writer.as_mut(), &wire).await;
        if res.is_err() {
            self.core
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .closed = true;
        }
        let _ = writer.close().await;
        self.event_notify.notify_waiters();
        res
    }

    /// Advances timer and grant checks against a shared roster lock while preserving
    /// `writer -> core -> roster` lock order.
    pub async fn tick_locked(
        &self,
        now_unix: u64,
        roster: &Mutex<Roster>,
    ) -> Result<(), RuntimeError> {
        let mut writer = self.writer.lock().await;
        let tick_res = {
            let now_ms = self.elapsed_ms();
            let mut core = self
                .core
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let roster_guard = roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            core.tick(now_unix, now_ms, &roster_guard)
        };
        match tick_res {
            Ok(Some(wire)) => {
                if let Err(err) = write_protocol_chunks_timed(writer.as_mut(), &wire).await {
                    self.core
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .closed = true;
                    let _ = writer.close().await;
                    self.event_notify.notify_waiters();
                    return Err(err);
                }
                self.push_pending_events(vec![SessionEvent::Rekeyed {
                    direction: RekeyDirection::Outgoing,
                }]);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(err) => {
                let _ = writer.close().await;
                self.event_notify.notify_waiters();
                Err(err.into())
            }
        }
    }

    /// Waits for the next semantic event using wall-clock time on frame arrival.
    pub async fn next_event_locked_now(
        &self,
        roster: &Mutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        self.next_event_with_clock(roster, current_unix_secs).await
    }

    /// Waits for the next semantic event using an explicit clock callback on frame arrival.
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
            let staged = {
                let mut core = self
                    .core
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if core.closed {
                    return Ok(None);
                }
                core.staged.take()
            };

            let body = if staged.is_some() {
                Vec::new()
            } else if let Some(b) = read_half.frame_reader.next_frame()? {
                b
            } else {
                let read_half_ref = &mut *read_half;
                let n = tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => return Ok(None),
                    _ = &mut notified => continue,
                    res = read_half_ref.reader.recv_chunk(&mut read_half_ref.recv_buf) => res?,
                };
                if n == 0 {
                    return Ok(None);
                }
                read_half_ref
                    .frame_reader
                    .push(&read_half_ref.recv_buf[..n])?;
                continue;
            };

            let now_unix = now_fn();
            let now_ms = self.elapsed_ms();
            let (feed_res, route_sets) = {
                let mut core = self
                    .core
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut roster_guard = roster
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let res = match staged {
                    Some(frame) => core.handle_decoded(frame, now_unix, now_ms, &mut roster_guard),
                    None => core.handle_wire_body(&body, now_unix, now_ms, &mut roster_guard),
                };
                (res, std::mem::take(&mut core.route_sets))
            };
            match feed_res {
                Ok(WireHandleOutcome {
                    events,
                    writes,
                    should_close,
                    ingested_crl,
                    post_verify_err,
                }) => {
                    if let Some((crl, issuer, _)) = ingested_crl.as_ref() {
                        self.route_ingest
                            .note_crls(vec![(issuer.clone(), crl.clone())]);
                    }
                    if let Err(err) =
                        persist_ingested_crl_if_stored(self.store.as_ref(), ingested_crl).await
                    {
                        self.core
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .closed = true;
                        let mut writer = self.writer.lock().await;
                        let _ = writer.close().await;
                        drop(writer);
                        self.event_notify.notify_waiters();
                        self.route_ingest.run(Vec::new()).await;
                        return Err(err);
                    }
                    if !writes.is_empty() || should_close || post_verify_err.is_some() {
                        let mut writer = self.writer.lock().await;
                        for w in writes {
                            if let Err(err) = write_protocol_chunks_timed(writer.as_mut(), &w).await
                            {
                                self.core
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .closed = true;
                                let _ = writer.close().await;
                                drop(writer);
                                self.event_notify.notify_waiters();
                                self.route_ingest.run(Vec::new()).await;
                                return Err(err);
                            }
                        }
                        if post_verify_err.is_some() || should_close {
                            self.core
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .closed = true;
                            let _ = writer.close().await;
                            self.event_notify.notify_waiters();
                        }
                    }
                    if let Some(err) = post_verify_err {
                        // A CRL that revoked the peer or this device is persisted before the
                        // session ends.
                        self.route_ingest.run(Vec::new()).await;
                        return Err(err.into());
                    }
                    self.push_pending_events(events);
                    self.route_ingest.run(route_sets).await;
                }
                Err(err) => {
                    self.core
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .closed = true;
                    let mut writer = self.writer.lock().await;
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
        F: FnOnce(&mut V2TransportCore, u64) -> Result<(Vec<Vec<u8>>, bool), CoreError>,
    {
        self.run_authorized_write_op(|| Ok(()), op).await
    }

    async fn run_authorized_write_op<A, F>(&self, authority: A, op: F) -> Result<(), RuntimeError>
    where
        A: FnOnce() -> Result<(), RuntimeError>,
        F: FnOnce(&mut V2TransportCore, u64) -> Result<(Vec<Vec<u8>>, bool), CoreError>,
    {
        let mut writer = self.writer.lock().await;
        authority()?;
        let (writes, rekeyed) = {
            let now_ms = self.elapsed_ms();
            let mut core = self
                .core
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            op(&mut core, now_ms)?
        };
        for w in writes {
            if let Err(err) = write_protocol_chunks_timed(writer.as_mut(), &w).await {
                self.core
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .closed = true;
                let _ = writer.close().await;
                self.event_notify.notify_waiters();
                return Err(err);
            }
        }
        if rekeyed {
            self.push_pending_events(vec![SessionEvent::Rekeyed {
                direction: RekeyDirection::Outgoing,
            }]);
        }
        Ok(())
    }

    fn push_pending_events(&self, events: Vec<SessionEvent>) {
        if events.is_empty() {
            return;
        }
        {
            let mut q = self
                .pending_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            q.extend(events);
        }
        self.event_notify.notify_waiters();
    }

    fn pop_pending_event(&self) -> Option<SessionEvent> {
        self.pending_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
    }

    /// The `route_seq` the client sent in `SessionHello` (responder sessions).
    #[must_use]
    pub fn peer_route_seq(&self) -> Option<u64> {
        self.core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .peer_route_seq
    }

    /// Routes received `0x0C` route sets to the client ingest; see
    /// [`V2SessionDriver::set_route_ingest`].
    pub fn set_route_ingest(&self, access: RosterAccess, policy: RoutePolicy) {
        self.route_ingest.set(RouteIngest::new(
            access,
            self.peer_device_id.clone(),
            policy,
        ));
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Optional opaque push wake-hint parameters used before/around `/v2/relay` dialing.
#[derive(Clone)]
pub struct WakeDialOptions {
    pub provider: Arc<dyn WakeProvider>,
    pub target: WakeTarget,
    pub secret: WakeSecret,
    pub retry_delay: Duration,
    pub max_attempts: usize,
    pub wake_timeout: Duration,
    pub pre_wake: bool,
}

impl WakeDialOptions {
    /// Constructs [`WakeDialOptions`] with sensible retry defaults (`100 ms` x `10` attempts).
    #[must_use]
    pub fn new(provider: Arc<dyn WakeProvider>, target: WakeTarget, secret: WakeSecret) -> Self {
        Self {
            provider,
            target,
            secret,
            retry_delay: Duration::from_millis(100),
            max_attempts: 10,
            wake_timeout: DEFAULT_WAKE_TIMEOUT,
            pre_wake: false,
        }
    }

    /// Sends the best-effort epoch-blinded wake hint proactively before the initial dial attempt.
    #[must_use]
    pub fn with_pre_wake(mut self, pre_wake: bool) -> Self {
        self.pre_wake = pre_wake;
        self
    }

    /// Sets the delay between dial retries after dispatching a wake hint.
    #[must_use]
    pub fn with_retry_delay(mut self, retry_delay: Duration) -> Self {
        self.retry_delay = retry_delay;
        self
    }

    /// Sets the maximum number of dial retries after a wake hint.
    #[must_use]
    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    /// Sets the maximum time to wait for the best-effort [`WakeProvider`] hook before retrying.
    #[must_use]
    pub fn with_wake_timeout(mut self, wake_timeout: Duration) -> Self {
        self.wake_timeout = wake_timeout;
        self
    }
}

/// Dials `endpoint` via `dialer`, dispatching a best-effort epoch-blinded [`WakeTag`](crate::wake::WakeTag)
/// via [`WakeProvider::notify_best_effort`] proactively (`pre_wake = true`) or when an initial dial
/// misses (`"offline"`), then retrying until the sleeping peer registers or `max_attempts` exhausts.
pub async fn wake_and_dial_v2(
    dialer: &dyn PathDialer,
    endpoint: &str,
    wake: &WakeDialOptions,
    now_unix: u64,
) -> Result<(Box<dyn PathStream>, Option<WakeOutcome>), RuntimeError> {
    let tag = wake.secret.derive_tag(now_unix);
    let wake_outcome = if wake.pre_wake {
        Some(
            timeout(
                wake.wake_timeout,
                wake.provider
                    .notify_best_effort(&wake.target, &tag, now_unix),
            )
            .await
            .unwrap_or(WakeOutcome::Skipped),
        )
    } else {
        match dialer.dial(endpoint).await {
            Ok(stream) => return Ok((stream, None)),
            Err(_first_err) => Some(
                timeout(
                    wake.wake_timeout,
                    wake.provider
                        .notify_best_effort(&wake.target, &tag, now_unix),
                )
                .await
                .unwrap_or(WakeOutcome::Skipped),
            ),
        }
    };

    let attempts = wake.max_attempts.max(1);
    let mut last_err = None;
    for attempt in 0..attempts {
        match dialer.dial(endpoint).await {
            Ok(stream) => return Ok((stream, wake_outcome)),
            Err(err) => {
                last_err = Some(err);
                if attempt + 1 < attempts {
                    sleep(wake.retry_delay).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or(RuntimeError::Closed))
}

/// Dials `endpoint` with [`wake_and_dial_v2`] and establishes an authenticated [`V2SessionDriver`].
#[allow(clippy::too_many_arguments)]
pub async fn wake_and_connect_v2_session(
    dialer: &dyn PathDialer,
    endpoint: &str,
    wake: &WakeDialOptions,
    local_identity: &EndpointIdentity,
    target_host_id: &str,
    initial_grant: Option<Grant>,
    roster: &mut Roster,
    now_unix: u64,
) -> Result<(V2SessionDriver, Option<WakeOutcome>), RuntimeError> {
    let (stream, outcome) = wake_and_dial_v2(dialer, endpoint, wake, now_unix).await?;
    let driver = V2SessionDriver::connect(
        stream,
        local_identity,
        target_host_id,
        initial_grant,
        roster,
        now_unix,
    )
    .await?;
    Ok((driver, outcome))
}

#[cfg(test)]
mod tests {
    use tendril_core::crypto::{SigningKeypair, StaticKeypair};

    use super::*;

    #[test]
    fn active_derivation_count_drops_on_panic() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let res = std::panic::catch_unwind(|| {
            let _outer = ActiveCount::enter(&active, &peak);
            let _inner = ActiveCount::enter(&active, &peak);
            panic!("derivation failed");
        });
        assert!(res.is_err());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    fn seed_store() -> (tempfile::TempDir, StateStore, Roster) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = StateStore::open_or_create(dir.path()).expect("store");
        store
            .update_roster(|rst| {
                rst.insert_pinned_host(
                    "host".to_owned(),
                    "Host".to_owned(),
                    *StaticKeypair::from_scalar([0x31; 32]).public_bytes(),
                    Some(SigningKeypair::from_seed([0x32; 32]).public_key().clone()),
                    0,
                    vec![],
                )?;
                Ok(())
            })
            .expect("seed");
        let loaded = store.load_roster().expect("load");
        (dir, store, loaded)
    }

    #[tokio::test]
    async fn connect_fork_error_persists_revocation_before_returning() {
        let (_dir, store, mut working) = seed_store();
        working.revoke_peer("host").expect("revoke");
        let lock = AsyncMutex::new(());
        let fork = RuntimeError::Core(CoreError::RotationForkDetected { seq: 1 });
        persist_failed_connect_revocation(&store, &lock, "host", &fork, false, &working).await;
        assert_eq!(
            store.load_roster().unwrap().get("host").unwrap().state,
            PeerState::Revoked
        );
    }

    #[tokio::test]
    async fn already_revoked_peer_does_not_rewrite_the_roster() {
        let (_dir, store, mut working) = seed_store();
        working.revoke_peer("host").expect("revoke");
        let lock = AsyncMutex::new(());
        let err = RuntimeError::Core(CoreError::PeerRevoked("host".to_owned()));
        persist_failed_connect_revocation(&store, &lock, "host", &err, true, &working).await;
        assert_eq!(
            store.load_roster().unwrap().get("host").unwrap().state,
            PeerState::Active,
            "a rejected reconnect to a known-revoked peer must not touch the on-disk roster"
        );
        let io = RuntimeError::Closed;
        let active = store.load_roster().unwrap();
        persist_failed_connect_revocation(&store, &lock, "host", &io, false, &active).await;
        assert_eq!(
            store.load_roster().unwrap().get("host").unwrap().state,
            PeerState::Active
        );
    }
}

/// Responder sessions carry host route announcements, sealed inside `0x09 PADDED`. Core errors
/// pass through unchanged, so `FrameTooLarge`, `UnknownInnerFrameType` and `NotReady("peer did
/// not negotiate route sets")` leave the session open.
#[async_trait]
impl RouteSetSink for ConcurrentV2Session {
    fn peer_id(&self) -> String {
        self.peer_device_id.clone()
    }

    async fn send_route_set(&self, payload: &[u8]) -> Result<(), RuntimeError> {
        self.run_write_op(|core, now_ms| core.seal_route_set(payload, now_ms))
            .await
    }
}

/// Route options of one Wire v2 session initiator.
#[derive(Default)]
struct V2RouteInit {
    expectation: Option<RouteExpectation>,
    route_seq: Option<u64>,
    /// Day-2 evidence sink and the CRL sequence the snapshot held.
    evidence: Option<(SharedEvidence, Option<u64>)>,
}

/// Wire v2 pairing rung budget for `Local`, `Direct` and `Overlay` candidates (transport plus
/// `msg1`/`msg2`; the initiator Argon2id time comes on top).
pub const V2_RUNG_BUDGET_NEAR: Duration = Duration::from_millis(2_000);
/// Wire v2 pairing rung budget for `P2p`, `Relay` and `Broker` candidates.
pub const V2_RUNG_BUDGET_FAR: Duration = Duration::from_millis(4_000);

const fn v2_rung_budget(provider: ProviderId) -> Duration {
    match provider {
        ProviderId::Local | ProviderId::Direct | ProviderId::Overlay => V2_RUNG_BUDGET_NEAR,
        ProviderId::P2p | ProviderId::Relay | ProviderId::Broker => V2_RUNG_BUDGET_FAR,
    }
}

/// A rung that verified the sealed `HostHello`, `rp` and route statement.
struct V2PendingCommit {
    stream: Box<dyn PathStream>,
    machine: V2PakePairInitiator,
    sas: Option<String>,
    route_check: RouteCheck,
}

/// Runs one rung up to the deferred claim: permit, dial, derive, `msg1`, then `msg2` until the
/// machine awaits the commit.
///
/// The permit is taken before the dial, so a queued rung holds no connection. The wait for it
/// is bounded by its own budget (the rung budget again), and the rung deadline (transport plus
/// `msg1`/`msg2`) starts after it and excludes the derivation time.
#[allow(clippy::too_many_arguments)]
async fn v2_pairing_rung(
    dialer: &Arc<dyn PathDialer>,
    cand: &CandidateEndpoint,
    identity: &EndpointIdentity,
    opts: &PairPolicyOptions,
    pinned: Option<V2PinnedHost>,
    binding: PairRouteBinding,
) -> Result<V2PendingCommit, CandidateError> {
    let budget = v2_rung_budget(cand.provider);
    let permit = acquire_initiator_argon2(budget).await?;
    let machine = V2PakePairInitiator::new(
        identity,
        opts.device_name.clone(),
        opts.device_kind.clone(),
        opts.code.clone(),
        pinned,
        PakeArgon2Params::production(),
    )
    .map_err(|err| CandidateError::fatal(err.into()))?
    .with_route_binding(binding)
    .with_deferred_claim();
    let (deadline, mut stream, mut machine, init_actions, fast_open_sent) =
        if dialer.supports_fast_open() {
            let (machine, init_actions) = start_v2_pake_initiator(machine, permit).await?;
            let init_bytes = match init_actions.as_slice() {
                [V2PairAction::WriteBytes(bytes)] if !bytes.is_empty() => Some(bytes.as_slice()),
                _ => None,
            };
            let deadline = TokioInstant::now() + budget;
            let (stream, fast_open_sent) =
                match timeout_at(deadline, dialer.dial_with_init(&cand.addr, init_bytes)).await {
                    Ok(res) => res?,
                    Err(_) => {
                        return Err(RuntimeError::Timeout("v2 pairing rung dial timed out").into());
                    }
                };
            (deadline, stream, machine, init_actions, fast_open_sent)
        } else {
            let mut deadline = TokioInstant::now() + budget;
            let mut stream = match timeout_at(deadline, dialer.dial(&cand.addr)).await {
                Ok(res) => res?,
                Err(_) => {
                    return Err(RuntimeError::Timeout("v2 pairing rung dial timed out").into());
                }
            };
            let kdf_started = TokioInstant::now();
            let (machine, init_actions) = match start_v2_pake_initiator(machine, permit).await {
                Ok(started) => started,
                Err(err) => {
                    let _ = stream.close().await;
                    return Err(err.into());
                }
            };
            deadline += kdf_started.elapsed();
            (deadline, stream, machine, init_actions, false)
        };
    let mut sas = None;
    let res = async {
        if !fast_open_sent
            && let Some(outcome) = await_deadline!(
                deadline,
                stream,
                "v2 pairing rung timed out",
                dispatch_v2_pair_actions(stream.as_mut(), init_actions, &mut sas)
            )
        {
            return Err(RuntimeError::Protocol(format!(
                "v2 pairing completed before commit: {outcome:?}"
            )));
        }
        let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
        while !machine.is_awaiting_commit() {
            let n = await_deadline!(
                deadline,
                stream,
                "v2 pairing rung timed out",
                stream.recv_chunk(&mut buf)
            );
            if n == 0 {
                return Err(RuntimeError::Closed);
            }
            let actions = machine.feed_bytes(&buf[..n])?;
            if let Some(outcome) = await_deadline!(
                deadline,
                stream,
                "v2 pairing rung timed out",
                dispatch_v2_pair_actions(stream.as_mut(), actions, &mut sas)
            ) {
                return Err(RuntimeError::Protocol(format!(
                    "v2 pairing completed before commit: {outcome:?}"
                )));
            }
        }
        Ok(())
    }
    .await;
    if let Err(err) = res {
        let _ = stream.close().await;
        return Err(err.into());
    }
    let route_check = match committable_route_check(machine.route_verdict()) {
        Ok(check) => check,
        Err(err) => {
            let _ = stream.close().await;
            return Err(err);
        }
    };
    Ok(V2PendingCommit {
        stream,
        machine,
        sas,
        route_check,
    })
}

/// Wire v2 PAKE pairing over the hints of a pairing URI (or one explicit operator endpoint),
/// one rung at a time.
///
/// Every rung that receives `msg1` receives `init_mac`, an offline code-guess oracle, so rungs
/// are tried sequentially in path-planner order with a per-rung budget
/// ([`V2_RUNG_BUDGET_NEAR`], [`V2_RUNG_BUDGET_FAR`]) plus the initiator Argon2id time, each with
/// a fresh `channel_salt` and ephemeral key, every derivation under the process-wide permit
/// ([`set_initiator_argon2_permits`]). Before commit any failure advances to the next rung,
/// except an invalid route statement, which ends the attempt. The commit is irrevocable as in
/// [`crate::driver::drive_pair_initiator_with_policy`]; persistence merges the plan into the
/// latest roster with `apply_v2_pair_initiator_outcome_with_plan`.
pub async fn drive_v2_pair_initiator_with_policy(
    identity: Arc<EndpointIdentity>,
    store: &RosterAccess,
    opts: PairPolicyOptions,
) -> Result<PairPolicyResult<V2PairDriveResult>, AttemptError> {
    let plan = plan_pairing(store, &opts, DialWire::V2).await?;
    let PairingPlan {
        set,
        pinned,
        floor,
        persist,
        binding,
        ..
    } = plan;
    let v2_pin = pinned
        .map(|pin| V2PinnedHost::new(pin, floor.max(tendril_core::WIRE_VERSION)))
        .transpose()?;
    let mut skipped = set.skipped.clone();
    let ordered = PathPlanner::new(opts.policy_config, set.candidates.clone())
        .candidates()
        .to_vec();
    let mut raw_failures: Vec<(CandidateEndpoint, RuntimeError)> = Vec::new();
    let mut won = None;
    for cand in ordered {
        let Some(dialer) = set.dialer_for(cand.provider) else {
            raw_failures.push((cand, RuntimeError::Protocol("missing dialer".to_owned())));
            continue;
        };
        match v2_pairing_rung(
            &dialer,
            &cand,
            &identity,
            &opts,
            v2_pin.clone(),
            binding.clone(),
        )
        .await
        {
            Ok(pending) => {
                won = Some((cand, pending));
                break;
            }
            Err(CandidateError { error, fatal: true }) => {
                let failures = collect_failures(raw_failures, &mut skipped);
                return Err(AttemptError {
                    error,
                    committed: false,
                    skipped,
                    failures,
                });
            }
            Err(CandidateError { error, .. }) => raw_failures.push((cand, error)),
        }
    }
    let failures = collect_failures(raw_failures, &mut skipped);
    let Some((route, pending)) = won else {
        return Err(exhausted(failures, skipped));
    };
    let V2PendingCommit {
        mut stream,
        mut machine,
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
    // Irrevocable from here: the claim write may deliver any prefix of `msg3`.
    let deadline = TokioInstant::now() + opts.handshake_timeout;
    let committed = async {
        if let Some(outcome) = await_deadline!(
            deadline,
            stream,
            "pre-auth v2 pairing handshake timed out",
            dispatch_v2_pair_actions(stream.as_mut(), claim, &mut sas)
        ) {
            return Ok(outcome);
        }
        let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
        loop {
            let n = await_deadline!(
                deadline,
                stream,
                "pre-auth v2 pairing handshake timed out",
                stream.recv_chunk(&mut buf)
            );
            if n == 0 {
                return Err(RuntimeError::Closed);
            }
            let actions = machine.feed_bytes(&buf[..n])?;
            if let Some(outcome) = await_deadline!(
                deadline,
                stream,
                "pre-auth v2 pairing handshake timed out",
                dispatch_v2_pair_actions(stream.as_mut(), actions, &mut sas)
            ) {
                return Ok(outcome);
            }
        }
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
    if let V2PairOutcome::InitiatorPending { host_id, .. } = &outcome {
        let name = opts
            .host_name
            .clone()
            .or_else(|| opts.uri.as_ref().map(|u| u.host_name.clone()))
            .unwrap_or_else(|| host_id.clone());
        match store.update(|roster| {
            roster
                .apply_v2_pair_initiator_outcome_with_plan(&outcome, name, &plan)
                .map_err(Into::into)
        }) {
            Ok((_, merge)) => {
                routes_persisted = merge.persisted;
                routes_reason = merge.reason;
            }
            Err(err) => return Err(committed_error(err, skipped, failures)),
        }
    }
    Ok(PairPolicyResult {
        drive: V2PairDriveResult { outcome, sas },
        route,
        winner_source,
        committed: true,
        route_check,
        routes_persisted,
        routes_reason,
        skipped,
    })
}

fn exhausted(failures: Vec<CandidateFailure>, skipped: Vec<SkippedHint>) -> AttemptError {
    connect_exhausted(failures, skipped, true)
}

impl V2SessionDriver {
    /// The endpoint-free Day-2 connect, Wire v2.
    ///
    /// As [`crate::driver::SessionDriver::connect_with_policy_and_store`], with the stored
    /// `/v2/relay` gate: a `/v2/relay` route is a candidate only for this entry's `operator` or
    /// `signed` routes while the entry is `Active`, not CRL-revoked and holds `v2_secrets`. The
    /// winner's Wire v2 floor and retained secrets are persisted with the final check.
    pub async fn connect_with_policy_and_store(
        identity: Arc<EndpointIdentity>,
        target: &str,
        store: &RosterAccess,
        opts: ConnectOpts,
    ) -> Result<ConnectResult<Self>, AttemptError> {
        let plan = plan_connect(store, target, &opts, DialWire::V2).await?;
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
            opts.policy_config,
            set.candidates.clone(),
            move |cand, dialer| {
                let identity = Arc::clone(&identity);
                let mut roster = (*roster).clone();
                let (target, grant, expectation) =
                    (target_owned.clone(), grant.clone(), expectation.clone());
                let ev = Arc::clone(&ev);
                async move {
                    let res = async {
                        let secret = extract_v2_reconnect_secret(&roster, &target)?;
                        let driver = Self::connect_with_source(
                            StreamSource::Dial {
                                dialer: &*dialer,
                                addr: &cand.addr,
                            },
                            &identity,
                            &target,
                            secret,
                            grant,
                            crl_seq,
                            PaddingPolicy::v2_default(),
                            V2RosterRef::Direct(&mut roster),
                            current_unix_secs(),
                            Vec::new(),
                            V2RouteInit {
                                expectation,
                                route_seq,
                                evidence: Some((Arc::clone(&ev), crl_seq)),
                            },
                            Vec::new(),
                        )
                        .await?;
                        Ok::<_, RuntimeError>(driver)
                    }
                    .await;
                    res.map(|driver| (driver, roster))
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
        let Some(signing_pub) = clone.get(target).and_then(|e| e.signing_pub.clone()) else {
            let _ = driver.stream.close().await;
            return Err(committed_error(
                CoreError::IncompletePin(target.to_owned()),
                skipped,
                failures,
            ));
        };
        let facts = WinnerFacts {
            static_pub: driver.peer_static_pub,
            signing_pub,
            applied_rotation: driver.applied_rotation.clone(),
            recovery: driver.verified_recovery.take().map(|s| *s),
            wire: WIRE_VERSION_V2,
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
                driver.core.closed = true;
                let _ = driver.stream.close().await;
                return Err(committed_error(err, skipped, failures));
            }
        };
        driver.store = store.store().map(|s| (**s).clone());
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
}
