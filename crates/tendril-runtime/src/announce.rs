//! Signed route announcements.
//!
//! A host owns one [`RouteAnnouncer`]. [`RouteAnnouncer::publish`] is the only caller of
//! `Roster::bump_local_routes`: it recomputes the announced set `C(seq)`, persists a changed
//! set under the store lock before anything is signed, and schedules the signed set to every
//! live session whose client opted in with `SessionHello.route_seq` and has not yet been sent
//! (or reported) that sequence. Pairing URI issuance goes through the same path.
//!
//! A client hands every decoded `0x0C` set to [`ingest_route_sets`], which applies the client
//! rate limit and `Roster::apply_route_announcement` under the store lock.
//!
//! Times are Unix milliseconds (`now_ms`) so tests can drive the rate limits with a manual
//! clock; the roster receives whole seconds.
//!
//! # Lock order
//!
//! Every host path takes these locks in this order and never the reverse:
//!
//! 1. the endpoint's async store lock (surfaces and store-backed responders), if any;
//! 2. the roster file lock (`.roster.lock`, `flock`; [`StateStore`] transactions);
//! 3. the pairing manager mutex;
//! 4. an in-memory roster mutex ([`RosterAccess::roster`], a responder's roster).
//!
//! A pairing claim holds the file lock while it burns a code under the manager.
//! [`RouteAnnouncer::issue_pairing_uri`] therefore publishes (store I/O) before it takes the
//! manager, and holds the manager only for the in-memory issuance. Callers must not hold the
//! manager, or an in-memory roster mutex, across any announcer or [`RosterAccess`] call.
//!
//! A client session's route ingest slot sits before item 2: its blocking task holds the slot
//! while it takes the file lock and then the in-memory roster, and a session never takes the
//! slot while it holds its machine or roster mutex.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::Serialize;
use tendril_core::error::CoreError;
use tendril_core::grants::RevocationList;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    DroppedHint, IssueOptions, IssuedPairingUri, LocalRouteState, PairingManager, RoutePolicy,
};
use tendril_core::roster::{PeerState, Roster, RouteSetIgnored, RouteSetOutcome};
use tendril_core::routes::RouteSet;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::advertise::{
    AdvertiseInputs, ListAddrSource, LocalAddrSource, NativeAddrSource, NetworkSnapshot,
};
use crate::error::RuntimeError;
use crate::store::StateStore;

/// Host: a change waits this long before it is sent, coalescing later changes.
pub const HOST_ROUTE_SET_DEBOUNCE_MS: u64 = 2_000;
/// Host: at most one `0x0C` per session per interval after the first.
pub const HOST_ROUTE_SET_INTERVAL_MS: u64 = 30_000;
/// Client: at most one `0x0C` processed per session per interval.
pub const CLIENT_ROUTE_SET_INTERVAL_MS: u64 = 10_000;
/// A snapshot with zero networks is applied only after it persists this long.
pub const EMPTY_SNAPSHOT_DEBOUNCE_MS: u64 = 30_000;
/// Re-enumeration period for `advertise: auto` SDK and FFI hosts.
pub const DEFAULT_ROUTE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

const MAX_ANNOUNCE_EVENTS: usize = 256;

fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Current Unix time in milliseconds.
#[must_use]
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The outcome of the last route set a client processed for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LastRouteSet {
    /// `applied` or a `route_set_ignored` reason.
    pub outcome: &'static str,
    pub seq: u64,
}

/// Store-or-memory roster handle (state directory, sealed or store-less) shared by the
/// announcer, client ingest and the route setter.
///
/// With a store, every update runs against the latest on-disk roster under its advisory lock
/// and refreshes the in-memory copy. Without one, the in-memory roster is the only state.
#[derive(Clone)]
pub struct RosterAccess {
    store: Option<Arc<StateStore>>,
    roster: Arc<StdMutex<Roster>>,
    route_status: Arc<StdMutex<BTreeMap<String, LastRouteSet>>>,
}

impl std::fmt::Debug for RosterAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RosterAccess")
            .field("store", &self.store.as_ref().map(|s| s.dir().to_path_buf()))
            .finish_non_exhaustive()
    }
}

impl RosterAccess {
    /// Wraps an endpoint's store (if any) and its in-memory roster.
    #[must_use]
    pub fn new(store: Option<Arc<StateStore>>, roster: Arc<StdMutex<Roster>>) -> Self {
        Self {
            store,
            roster,
            route_status: Arc::default(),
        }
    }

    /// A store-backed handle seeded with the store's current roster.
    pub fn from_store(store: Arc<StateStore>) -> Result<Self, RuntimeError> {
        let roster = store.load_roster()?;
        Ok(Self::new(Some(store), Arc::new(StdMutex::new(roster))))
    }

    /// A store-less handle; updates stay in memory.
    #[must_use]
    pub fn memory(roster: Roster) -> Self {
        Self::new(None, Arc::new(StdMutex::new(roster)))
    }

    #[must_use]
    pub fn store(&self) -> Option<&Arc<StateStore>> {
        self.store.as_ref()
    }

    /// The in-memory roster (the only copy for a store-less handle).
    #[must_use]
    pub fn roster(&self) -> &Arc<StdMutex<Roster>> {
        &self.roster
    }

    /// The latest roster: loaded from the store, else a copy of the in-memory one. CRLs the
    /// in-memory copy holds that the store lacks (accepted by a session, not yet persisted) are
    /// merged into the loaded roster, so a reload never drops revocation state.
    pub fn load(&self) -> Result<Roster, RuntimeError> {
        match &self.store {
            Some(store) => {
                let mut roster = store.load_roster()?;
                roster.merge_crl_evidence(&held_crls(&lock(&self.roster)));
                Ok(roster)
            }
            None => Ok(lock(&self.roster).clone()),
        }
    }

    /// Runs `f` as one roster transaction; nothing is written when `f` fails.
    ///
    /// With a store, the transaction runs on the latest on-disk roster, which then replaces the
    /// in-memory copy. CRLs the in-memory copy holds that the store lacks (accepted by a session
    /// but not yet persisted) are merged in first, so the reload never drops revocation state.
    ///
    /// The in-memory mutex is taken after the roster file lock (module docs, lock order) and is
    /// not held while `f` runs. CRLs a session accepted into memory meanwhile are merged into
    /// the committed copy, so replacing the in-memory roster never drops them either.
    pub fn update<T, F>(&self, f: F) -> Result<T, RuntimeError>
    where
        F: FnOnce(&mut Roster) -> Result<T, RuntimeError>,
    {
        match &self.store {
            Some(store) => store.with_roster_lock(|store| {
                let mut roster = store.load_roster_unlocked()?;
                roster.merge_crl_evidence(&held_crls(&lock(&self.roster)));
                let out = f(&mut roster)?;
                store.save_roster_unlocked(&roster)?;
                let mut guard = lock(&self.roster);
                roster.merge_crl_evidence(&held_crls(&guard));
                *guard = roster;
                Ok(out)
            }),
            None => {
                let mut guard = lock(&self.roster);
                let mut working = guard.clone();
                let out = f(&mut working)?;
                *guard = working;
                Ok(out)
            }
        }
    }

    /// Like [`Self::update`], but nothing is written when `f` returns `(out, false)`.
    pub fn update_if_changed<T, F>(&self, f: F) -> Result<T, RuntimeError>
    where
        F: FnOnce(&mut Roster) -> Result<(T, bool), RuntimeError>,
    {
        let mut unchanged = None;
        let written = self.update(|roster| {
            let (out, changed) = f(roster)?;
            if changed {
                Ok(Some(out))
            } else {
                unchanged = Some(out);
                // Aborts the transaction so neither the store nor the memory copy is written.
                Err(RuntimeError::Storage("unchanged".into()))
            }
        });
        if let Some(out) = unchanged {
            return Ok(out);
        }
        written?.ok_or_else(|| RuntimeError::Storage("roster update lost its result".into()))
    }

    /// The last route set outcome [`ingest_route_sets`] recorded for `peer_id`.
    #[must_use]
    pub fn last_route_set(&self, peer_id: &str) -> Option<LastRouteSet> {
        lock(&self.route_status).get(peer_id).copied()
    }

    fn record_route_set(&self, peer_id: &str, last: LastRouteSet) {
        lock(&self.route_status).insert(peer_id.to_owned(), last);
    }
}

/// Every CRL `roster` holds, keyed by issuer (paired peers and trust anchors).
fn held_crls(roster: &Roster) -> Vec<(String, RevocationList)> {
    roster
        .entries()
        .map(|(id, _)| id)
        .chain(roster.trust_anchors().map(|(id, _)| id))
        .filter_map(|id| roster.crl(id).map(|crl| (id.clone(), crl.clone())))
        .collect()
}

/// The write half of a live responder session whose client sent `SessionHello.route_seq`.
///
/// Implementations seal the payload with the session machine's `send_route_set` and write it
/// through the session writer. A core `FrameTooLarge` (no Wire v2 padding bucket fits),
/// `UnknownInnerFrameType` (padding disabled) or `NotReady("peer did not negotiate route
/// sets")` must be returned as `RuntimeError::Core` with the session left open; the announcer
/// records it and never retries that sequence. Any other error, including `NotReady` from a
/// session that is closed or no longer in transport mode, drops the session from the
/// announcer.
#[async_trait]
pub trait RouteSetSink: Send + Sync {
    /// Roster key of the authenticated client.
    fn peer_id(&self) -> String;

    /// Seals and writes one `0x0C` payload.
    async fn send_route_set(&self, payload: &[u8]) -> Result<(), RuntimeError>;
}

/// Where auto advertising takes interface addresses from.
#[derive(Clone)]
pub enum AddressSource {
    /// Native enumeration (`netdev`, feature `auto-advertise`); a `None` refresh re-enumerates.
    Native,
    /// Snapshots passed to [`RouteAnnouncer::refresh`] (Android); a `None` refresh reuses the
    /// retained snapshot and never enumerates natively.
    Snapshot,
    /// An injected source, queried like [`Self::Native`].
    Custom(Arc<dyn LocalAddrSource + Send + Sync>),
}

impl AddressSource {
    /// `Snapshot` on Android, else `Native`.
    #[must_use]
    pub const fn platform_default() -> Self {
        if cfg!(target_os = "android") {
            Self::Snapshot
        } else {
            Self::Native
        }
    }
}

impl std::fmt::Debug for AddressSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Native => "Native",
            Self::Snapshot => "Snapshot",
            Self::Custom(_) => "Custom",
        })
    }
}

/// What the announcer did for one session, kept for diagnostics and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnounceEvent {
    Sent {
        peer_id: String,
        seq: u64,
    },
    /// `route_set_unsendable{reason}`: `bucket_too_small`, `padding_disabled` or
    /// `not_negotiated`. The session stays open.
    Unsendable {
        peer_id: String,
        seq: u64,
        reason: &'static str,
    },
    /// The peer was no longer `Active` (or CRL-revoked) just before sealing.
    PeerInactive {
        peer_id: String,
        seq: u64,
    },
    /// The write failed; the session is dropped from the announcer.
    SendFailed {
        peer_id: String,
        seq: u64,
    },
    /// `route_seq_exhausted`: a changed set could not be published at `seq = 2^53-1`.
    SeqExhausted,
}

/// Result of [`RouteAnnouncer::refresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshOutcome {
    pub state: LocalRouteState,
    /// `true` when this call published a new sequence.
    pub changed: bool,
}

impl RefreshOutcome {
    #[must_use]
    pub const fn route_seq(&self) -> u64 {
        self.state.seq()
    }
}

/// A sequence and its encoded `0x0C` payload.
type SignedPayload = (u64, Arc<[u8]>);

struct SignedSet {
    seq: u64,
    static_pub: [u8; 32],
    sh: [u8; 32],
    payload: Arc<[u8]>,
}

struct SessionSlot {
    id: u64,
    sink: Weak<dyn RouteSetSink>,
    peer_id: String,
    last_seq: u64,
    pending_since_ms: Option<u64>,
    last_sent_ms: Option<u64>,
}

impl SessionSlot {
    fn due_at(&self) -> Option<u64> {
        let pending = self.pending_since_ms?;
        let debounced = pending.saturating_add(HOST_ROUTE_SET_DEBOUNCE_MS);
        let spaced = self
            .last_sent_ms
            .map_or(0, |t| t.saturating_add(HOST_ROUTE_SET_INTERVAL_MS));
        Some(debounced.max(spaced))
    }
}

struct AnnouncerState {
    identity: EndpointIdentity,
    inputs: AdvertiseInputs,
    source: AddressSource,
    snapshot: Option<NetworkSnapshot>,
    empty_since_ms: Option<u64>,
    current: Option<LocalRouteState>,
    dropped: Vec<DroppedHint>,
    signed: Option<SignedSet>,
    sessions: Vec<SessionSlot>,
    next_session_id: u64,
    events: VecDeque<AnnounceEvent>,
}

impl AnnouncerState {
    fn event(&mut self, event: AnnounceEvent) {
        if self.events.len() >= MAX_ANNOUNCE_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Applies an empty snapshot once it has persisted for [`EMPTY_SNAPSHOT_DEBOUNCE_MS`]
    /// so no publication after the debounce reuses a lost network's addresses.
    fn apply_matured_empty(&mut self, now_ms: u64) {
        if self
            .empty_since_ms
            .is_some_and(|t| now_ms >= t.saturating_add(EMPTY_SNAPSHOT_DEBOUNCE_MS))
        {
            self.snapshot = Some(NetworkSnapshot::default());
            self.empty_since_ms = None;
        }
    }

    fn mark_pending(&mut self, seq: u64, now_ms: u64) {
        self.sessions.retain(|s| s.sink.strong_count() > 0);
        for slot in &mut self.sessions {
            if slot.last_seq < seq && slot.pending_since_ms.is_none() {
                slot.pending_since_ms = Some(now_ms);
            }
        }
    }

    /// The signed `0x0C` payload for the current set, re-signed when `seq` or the identity
    /// keys changed.
    fn payload(&mut self) -> Result<Option<SignedPayload>, CoreError> {
        let Some(state) = self.current.as_ref() else {
            return Ok(None);
        };
        let static_pub = *self.identity.static_key().public_bytes();
        let sh = self.identity.signing_key().signing_pub_hash();
        let fresh = self
            .signed
            .as_ref()
            .is_some_and(|s| s.seq == state.seq() && s.static_pub == static_pub && s.sh == sh);
        if !fresh {
            let set = RouteSet::sign(
                &self.identity,
                state.seq(),
                state.issued_at(),
                state.routes().to_vec(),
            )?;
            self.signed = Some(SignedSet {
                seq: state.seq(),
                static_pub,
                sh,
                payload: set.encode().into(),
            });
        }
        Ok(self
            .signed
            .as_ref()
            .map(|s| (s.seq, Arc::clone(&s.payload))))
    }
}

/// Owned by each hosting endpoint; keeps paired clients' `signed` routes current.
pub struct RouteAnnouncer {
    store: RosterAccess,
    state: StdMutex<AnnouncerState>,
    wake: Arc<Notify>,
    /// `true` while a [`Self::spawn`] timer task is alive.
    timer_running: Arc<AtomicBool>,
}

/// Clears [`RouteAnnouncer::timer_running`] when the timer task ends or is aborted.
struct TimerGuard(Arc<AtomicBool>);

impl Drop for TimerGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// One publication: the state, whether it bumped `seq`, and the identity and announced-set
/// drops it was computed with.
struct Published {
    state: LocalRouteState,
    changed: bool,
    identity: EndpointIdentity,
    dropped: Vec<DroppedHint>,
}

impl std::fmt::Debug for RouteAnnouncer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteAnnouncer")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl Drop for RouteAnnouncer {
    fn drop(&mut self) {
        self.wake.notify_waiters();
    }
}

struct Delivery {
    id: u64,
    sink: Arc<dyn RouteSetSink>,
    peer_id: String,
    seq: u64,
    payload: Arc<[u8]>,
}

impl RouteAnnouncer {
    #[must_use]
    pub fn new(
        identity: EndpointIdentity,
        store: RosterAccess,
        inputs: AdvertiseInputs,
        source: AddressSource,
    ) -> Self {
        Self {
            store,
            state: StdMutex::new(AnnouncerState {
                identity,
                inputs,
                source,
                snapshot: None,
                empty_since_ms: None,
                current: None,
                dropped: Vec::new(),
                signed: None,
                sessions: Vec::new(),
                next_session_id: 0,
                events: VecDeque::new(),
            }),
            wake: Arc::new(Notify::new()),
            timer_running: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub const fn roster_access(&self) -> &RosterAccess {
        &self.store
    }

    /// Replaces the host identity (after a key rotation); the next send is re-signed.
    pub fn set_identity(&self, identity: EndpointIdentity) {
        lock(&self.state).identity = identity;
    }

    /// Replaces the advertising inputs; call [`Self::publish`] afterwards.
    pub fn set_inputs(&self, inputs: AdvertiseInputs) {
        lock(&self.state).inputs = inputs;
    }

    #[must_use]
    pub fn inputs(&self) -> AdvertiseInputs {
        lock(&self.state).inputs.clone()
    }

    /// The announced set's drops from the last publish.
    #[must_use]
    pub fn last_dropped(&self) -> Vec<DroppedHint> {
        lock(&self.state).dropped.clone()
    }

    /// Drains the recorded announcer events.
    pub fn take_events(&self) -> Vec<AnnounceEvent> {
        lock(&self.state).events.drain(..).collect()
    }

    /// The endpoints the announced set is built from at `now_ms`.
    fn current_endpoints(&self, now_ms: u64) -> (EndpointIdentity, Vec<String>) {
        let (identity, inputs, source, snapshot) = {
            let mut st = lock(&self.state);
            st.apply_matured_empty(now_ms);
            (
                st.identity.clone(),
                st.inputs.clone(),
                st.source.clone(),
                st.snapshot.clone(),
            )
        };
        let endpoints = match source {
            AddressSource::Native => inputs.endpoints(&NativeAddrSource),
            AddressSource::Custom(src) => inputs.endpoints(src.as_ref()),
            AddressSource::Snapshot => inputs.endpoints(&ListAddrSource::from_snapshot(
                &snapshot.unwrap_or_default(),
            )),
        };
        (identity, endpoints)
    }

    /// Recomputes the announced set, publishes it through `bump_local_routes` (persisted
    /// before anything is signed or sent) and schedules the signed set to every registered
    /// session that has not been sent or reported the returned `seq`.
    ///
    /// A snapshot with zero networks that has persisted for [`EMPTY_SNAPSHOT_DEBOUNCE_MS`] is
    /// applied first, whichever call publishes.
    pub fn publish(&self, now_ms: u64) -> Result<LocalRouteState, RuntimeError> {
        self.publish_inner(now_ms).map(|p| p.state)
    }

    fn publish_inner(&self, now_ms: u64) -> Result<Published, RuntimeError> {
        let (identity, endpoints) = self.current_endpoints(now_ms);
        let announced = PairingManager::announced_route_set(&identity, &endpoints);
        let digest = LocalRouteState::digest_of(announced.routes());
        let unchanged = self
            .store
            .load()?
            .local_routes()
            .filter(|s| *s.digest() == digest)
            .cloned();
        let bumped = match unchanged {
            Some(state) => Ok((state, false)),
            None => self.store.update(|roster| {
                let before = roster.local_routes().map(LocalRouteState::seq);
                let state = roster.bump_local_routes(&announced, now_ms / 1000)?;
                let changed = before != Some(state.seq());
                Ok((state, changed))
            }),
        };
        let mut st = lock(&self.state);
        let (state, changed) = match bumped {
            Ok(v) => v,
            Err(err) => {
                if matches!(
                    err,
                    RuntimeError::Core(CoreError::ProtocolViolation("route sequence exhausted"))
                ) {
                    tracing::warn!("route_seq_exhausted");
                    st.event(AnnounceEvent::SeqExhausted);
                }
                return Err(err);
            }
        };
        let dropped = announced.dropped().to_vec();
        if st.current.as_ref().is_none_or(|c| c.seq() <= state.seq()) {
            st.current = Some(state.clone());
            st.dropped.clone_from(&dropped);
        }
        st.payload()?;
        st.mark_pending(state.seq(), now_ms);
        drop(st);
        self.wake.notify_waiters();
        Ok(Published {
            state,
            changed,
            identity,
            dropped,
        })
    }

    /// Applies a network snapshot, then publishes.
    ///
    /// `Some(snapshot)` switches the announcer to snapshot addressing and retains it. A
    /// snapshot with zero networks replaces a non-empty one only once it has persisted for
    /// [`EMPTY_SNAPSHOT_DEBOUNCE_MS`]. `None` re-enumerates a native or custom source, or
    /// reuses the retained snapshot; the publish applies a confirmed empty one after the
    /// debounce.
    pub fn refresh(
        &self,
        now_ms: u64,
        snapshot: Option<NetworkSnapshot>,
    ) -> Result<RefreshOutcome, RuntimeError> {
        if let Some(snap) = snapshot {
            let mut st = lock(&self.state);
            st.apply_matured_empty(now_ms);
            st.source = AddressSource::Snapshot;
            let had_networks = st.snapshot.as_ref().is_some_and(|s| !s.networks.is_empty());
            if !snap.networks.is_empty() || !had_networks {
                st.snapshot = Some(snap);
                st.empty_since_ms = None;
            } else if st.empty_since_ms.is_none() {
                st.empty_since_ms = Some(now_ms);
            }
        }
        let Published { state, changed, .. } = self.publish_inner(now_ms)?;
        Ok(RefreshOutcome { state, changed })
    }

    /// Publishes, then issues a pairing URI from the returned `C(seq)`. The result's `dropped`
    /// lists the announced set's drops followed by the builder's.
    ///
    /// The state, identity and drops come from one publication. When a changed set cannot be
    /// published because the sequence is exhausted, an unsigned issuance (`sign_routes: false`)
    /// falls back to the stored set and the last successful publication's drops; a signed one
    /// fails.
    ///
    /// `manager` is locked only after the publish, for the in-memory issuance: a pairing claim
    /// holds the roster file lock while it takes the manager (module docs, lock order). The
    /// caller must not hold `manager`.
    pub fn issue_pairing_uri(
        &self,
        manager: &StdMutex<PairingManager>,
        host_name: &str,
        opts: IssueOptions,
        now_ms: u64,
    ) -> Result<IssuedPairingUri, RuntimeError> {
        let (state, identity, mut dropped) = match self.publish_inner(now_ms) {
            Ok(p) => (p.state, p.identity, p.dropped),
            Err(RuntimeError::Core(CoreError::ProtocolViolation(msg)))
                if !opts.sign_routes && msg == "route sequence exhausted" =>
            {
                let stored = self
                    .store
                    .load()?
                    .local_routes()
                    .cloned()
                    .ok_or(CoreError::ProtocolViolation(msg))?;
                let st = lock(&self.state);
                (stored, st.identity.clone(), st.dropped.clone())
            }
            Err(err) => return Err(err),
        };
        let mut issued =
            lock(manager).issue_pairing_uri(&identity, host_name, &state, opts, now_ms / 1000)?;
        dropped.append(&mut issued.dropped);
        issued.dropped = dropped;
        Ok(issued)
    }

    /// Registers a responder session once it is `Established`. Call it before any other
    /// host-initiated frame: when the client sent `route_seq` and the host's current `seq` is
    /// higher, the signed set is sent here as the first host-initiated frame. A session whose
    /// client sent no `route_seq` is never registered and never receives `0x0C`.
    ///
    /// Fails with the sink's error when that first send fails ([`AnnounceEvent::SendFailed`]):
    /// the session missed its initial route set and the caller closes it. An unsendable set
    /// or a peer that is no longer `Active` is recorded and returns `Ok`.
    pub async fn on_session_established(
        &self,
        session: &Arc<dyn RouteSetSink>,
        peer_route_seq: Option<u64>,
        now_ms: u64,
    ) -> Result<(), RuntimeError> {
        let Some(peer_seq) = peer_route_seq else {
            return Ok(());
        };
        let stored = if lock(&self.state).current.is_none() {
            self.store.load()?.local_routes().cloned()
        } else {
            None
        };
        let delivery = {
            let mut st = lock(&self.state);
            if st.current.is_none() {
                st.current = stored;
            }
            let id = st.next_session_id;
            st.next_session_id += 1;
            let peer_id = session.peer_id();
            let mut slot = SessionSlot {
                id,
                sink: Arc::downgrade(session),
                peer_id: peer_id.clone(),
                last_seq: peer_seq,
                pending_since_ms: None,
                last_sent_ms: None,
            };
            let delivery = match st.payload()? {
                Some((seq, payload)) if seq > peer_seq => {
                    slot.last_seq = seq;
                    slot.last_sent_ms = Some(now_ms);
                    Some(Delivery {
                        id,
                        sink: Arc::clone(session),
                        peer_id,
                        seq,
                        payload,
                    })
                }
                _ => None,
            };
            st.sessions.push(slot);
            delivery
        };
        match delivery {
            Some(d) => self.deliver(d).await,
            None => Ok(()),
        }
    }

    /// Sends the current set to every session whose debounce and interval have elapsed.
    pub async fn flush(&self, now_ms: u64) {
        let due: Vec<Delivery> = {
            let mut st = lock(&self.state);
            st.sessions.retain(|s| s.sink.strong_count() > 0);
            let Ok(Some((seq, payload))) = st.payload() else {
                return;
            };
            st.sessions
                .iter_mut()
                .filter(|s| s.last_seq < seq && s.due_at().is_some_and(|t| now_ms >= t))
                .filter_map(|slot| {
                    let sink = slot.sink.upgrade()?;
                    slot.last_seq = seq;
                    slot.pending_since_ms = None;
                    slot.last_sent_ms = Some(now_ms);
                    Some(Delivery {
                        id: slot.id,
                        sink,
                        peer_id: slot.peer_id.clone(),
                        seq,
                        payload: Arc::clone(&payload),
                    })
                })
                .collect()
        };
        for d in due {
            // A failed send is recorded and drops the session; the timer carries on.
            let _ = self.deliver(d).await;
        }
    }

    /// Re-checks that the peer is `Active` immediately before sealing, then writes. Returns the
    /// write error of a [`AnnounceEvent::SendFailed`] delivery.
    async fn deliver(&self, d: Delivery) -> Result<(), RuntimeError> {
        let mut failed = None;
        let active = self.store.load().is_ok_and(|roster| {
            roster.get(&d.peer_id).is_some_and(|entry| {
                entry.state == PeerState::Active && !roster.crl_revokes_entry(entry)
            })
        });
        let event = if !active {
            AnnounceEvent::PeerInactive {
                peer_id: d.peer_id,
                seq: d.seq,
            }
        } else {
            match d.sink.send_route_set(&d.payload).await {
                Ok(()) => AnnounceEvent::Sent {
                    peer_id: d.peer_id,
                    seq: d.seq,
                },
                Err(RuntimeError::Core(err)) if unsendable_reason(&err).is_some() => {
                    let reason = unsendable_reason(&err).unwrap_or_default();
                    tracing::warn!(peer = %d.peer_id, seq = d.seq, reason, "route_set_unsendable");
                    AnnounceEvent::Unsendable {
                        peer_id: d.peer_id,
                        seq: d.seq,
                        reason,
                    }
                }
                Err(err) => {
                    tracing::debug!(peer = %d.peer_id, seq = d.seq, %err, "route set send failed");
                    lock(&self.state).sessions.retain(|s| s.id != d.id);
                    failed = Some(err);
                    AnnounceEvent::SendFailed {
                        peer_id: d.peer_id,
                        seq: d.seq,
                    }
                }
            }
        };
        lock(&self.state).event(event);
        failed.map_or(Ok(()), Err)
    }

    /// The earliest time a scheduled send or a pending empty snapshot becomes due.
    #[must_use]
    pub fn next_deadline_ms(&self) -> Option<u64> {
        let st = lock(&self.state);
        let current = st.current.as_ref().map(LocalRouteState::seq);
        let sends = st
            .sessions
            .iter()
            .filter(|s| current.is_some_and(|seq| s.last_seq < seq))
            .filter_map(SessionSlot::due_at);
        let empty = st
            .empty_since_ms
            .map(|t| t.saturating_add(EMPTY_SNAPSHOT_DEBOUNCE_MS));
        sends.chain(empty).min()
    }

    fn empty_deadline_ms(&self) -> Option<u64> {
        lock(&self.state)
            .empty_since_ms
            .map(|t| t.saturating_add(EMPTY_SNAPSHOT_DEBOUNCE_MS))
    }

    /// Runs the announcer's timers on the current Tokio runtime: scheduled sends, the empty
    /// snapshot debounce and, with `refresh_every`, periodic [`Self::refresh`] with `None`.
    /// The task ends once the announcer is dropped. One timer task runs at a time: while it is
    /// alive (not finished or aborted), another call returns an already finished handle.
    pub fn spawn(self: &Arc<Self>, refresh_every: Option<Duration>) -> JoinHandle<()> {
        if self.timer_running.swap(true, Ordering::AcqRel) {
            tracing::debug!("route announcer timer already running");
            return tokio::spawn(async {});
        }
        let guard = TimerGuard(Arc::clone(&self.timer_running));
        let weak = Arc::downgrade(self);
        let wake = Arc::clone(&self.wake);
        let every_ms = refresh_every.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        tokio::spawn(async move {
            let _guard = guard;
            let mut next_refresh = every_ms.map(|e| unix_ms().saturating_add(e));
            loop {
                // Registered before the state is read: `notify_waiters` from a publish or from
                // the announcer's drop after this point wakes it.
                let notified = wake.notified();
                let Some(this) = weak.upgrade() else {
                    return;
                };
                let now = unix_ms();
                let empty_due = this.empty_deadline_ms().is_some_and(|t| now >= t);
                if empty_due || next_refresh.is_some_and(|t| now >= t) {
                    if let Err(err) = this.refresh(now, None) {
                        tracing::warn!(%err, "route refresh failed");
                    }
                    next_refresh = every_ms.map(|e| now.saturating_add(e));
                }
                this.flush(now).await;
                let deadline = this
                    .next_deadline_ms()
                    .into_iter()
                    .chain(next_refresh)
                    .min();
                drop(this);
                match deadline {
                    Some(t) => {
                        let wait = Duration::from_millis(t.saturating_sub(unix_ms()));
                        tokio::select! {
                            () = tokio::time::sleep(wait) => {}
                            () = notified => {}
                        }
                    }
                    None => notified.await,
                }
            }
        })
    }
}

/// The core `NotReady` message of a session whose client did not send `route_seq`.
const NOT_NEGOTIATED: &str = "peer did not negotiate route sets";

/// Send errors that leave the session open. `NotReady` counts only when it means "not
/// negotiated"; a closed or not yet established session reports `NotReady` too and is evicted.
fn unsendable_reason(err: &CoreError) -> Option<&'static str> {
    match err {
        CoreError::FrameTooLarge { .. } => Some("bucket_too_small"),
        CoreError::UnknownInnerFrameType(_) => Some("padding_disabled"),
        CoreError::NotReady(msg) if *msg == NOT_NEGOTIATED => Some("not_negotiated"),
        _ => None,
    }
}

/// Client rate limit: at most one route set processed per [`CLIENT_ROUTE_SET_INTERVAL_MS`].
/// Keep one per session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteSetLimiter {
    last_processed_ms: Option<u64>,
}

impl RouteSetLimiter {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_processed_ms: None,
        }
    }

    fn admit(&mut self, now_ms: u64) -> bool {
        let open = self
            .last_processed_ms
            .is_none_or(|t| now_ms >= t.saturating_add(CLIENT_ROUTE_SET_INTERVAL_MS));
        if open {
            self.last_processed_ms = Some(now_ms);
        }
        open
    }
}

/// Why a route set was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestIgnored {
    /// Dropped by the client rate limit before signature verification.
    RateLimited,
    /// Rejected by `Roster::apply_route_announcement`.
    Rejected(RouteSetIgnored),
}

impl IngestIgnored {
    /// Snake-case reason recorded as `route_set_ignored{reason}`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::Rejected(r) => r.as_str(),
        }
    }
}

/// What [`ingest_route_sets`] did with one route set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    Applied {
        seq: u64,
        added: Vec<String>,
        removed: Vec<String>,
    },
    Ignored {
        seq: u64,
        reason: IngestIgnored,
    },
}

impl IngestOutcome {
    fn last(&self) -> LastRouteSet {
        match self {
            Self::Applied { seq, .. } => LastRouteSet {
                outcome: "applied",
                seq: *seq,
            },
            Self::Ignored { seq, reason } => LastRouteSet {
                outcome: reason.as_str(),
                seq: *seq,
            },
        }
    }
}

/// Client ingest of the route sets an initiator session decoded (`take_route_sets()`).
///
/// Everything is dropped, unrecorded, unless `policy` is `AllSigned`. Otherwise at most one set
/// per [`CLIENT_ROUTE_SET_INTERVAL_MS`] is processed (the newest in `sets`; the rest are
/// `rate_limited` before verification), through `Roster::apply_route_announcement` under the
/// store lock. Each outcome is logged and recorded as the peer's last route set. Semantic
/// rejections never fail the call or the session.
pub fn ingest_route_sets(
    store: &RosterAccess,
    peer_id: &str,
    sets: Vec<RouteSet>,
    policy: RoutePolicy,
    limiter: &mut RouteSetLimiter,
    now_ms: u64,
) -> Result<Vec<IngestOutcome>, RuntimeError> {
    if policy != RoutePolicy::AllSigned || sets.is_empty() {
        return Ok(Vec::new());
    }
    let before = *limiter;
    let admitted = limiter.admit(now_ms);
    let last = sets.len() - 1;
    let mut outcomes = Vec::with_capacity(sets.len());
    for (i, set) in sets.into_iter().enumerate() {
        let seq = set.seq;
        let outcome = if admitted && i == last {
            // Ignored outcomes change nothing, so only an applied set is written. A failed
            // transaction did not process the set and gives the rate-limit window back.
            let applied = store.update_if_changed(|roster| {
                let out = roster.apply_route_announcement(peer_id, &set, now_ms / 1000)?;
                let changed = matches!(out, RouteSetOutcome::Applied { .. });
                Ok((out, changed))
            });
            let applied = match applied {
                Ok(out) => out,
                Err(err) => {
                    *limiter = before;
                    return Err(err);
                }
            };
            match applied {
                RouteSetOutcome::Applied { added, removed } => IngestOutcome::Applied {
                    seq,
                    added,
                    removed,
                },
                RouteSetOutcome::Ignored(r) => IngestOutcome::Ignored {
                    seq,
                    reason: IngestIgnored::Rejected(r),
                },
            }
        } else {
            IngestOutcome::Ignored {
                seq,
                reason: IngestIgnored::RateLimited,
            }
        };
        match &outcome {
            IngestOutcome::Applied { .. } => {
                tracing::info!(peer = peer_id, seq, "route_set_applied")
            }
            IngestOutcome::Ignored { reason, .. } => {
                tracing::info!(
                    peer = peer_id,
                    seq,
                    reason = reason.as_str(),
                    "route_set_ignored"
                );
            }
        }
        store.record_route_set(peer_id, outcome.last());
        outcomes.push(outcome);
    }
    Ok(outcomes)
}
