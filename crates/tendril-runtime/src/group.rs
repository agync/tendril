//! Lazy pairwise mesh orchestration for small peer groups (`GroupPool`, `GroupHub`).
//!
//! A pool dials siblings named only by a signed [`GroupManifest`], reuses healthy sessions,
//! fans payloads out with bounded concurrency and per-peer isolation, and merges inbound
//! application data and manifest gossip into one event stream. Every trust decision is made by
//! `tendril-core`: the pool only builds in-memory, group-scoped rosters from the stored manifest
//! and routes frames to [`GroupBook`]. Siblings never enter the persisted trust roster.
//!
//! Lock order: driver writer lock, then a pool's state mutex. The state mutex may be held while
//! `groups.json` or `roster.json` is read or written, one file at a time: store file locks are
//! never nested, and the root CRL is read and released before the group book lock is taken.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;

use serde::Serialize;
use subtle::ConstantTimeEq;
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::{HybridSigningPublicKey, b64url_decode_array, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::grants::{AuditEvent, Capability, RevocationList};
use tendril_core::group as core_group;
use tendril_core::group::{
    GroupBook, GroupIngestOutcome, GroupManifest, GroupMember, GroupRendezvousFrame, GroupSeq,
    V2GroupSecrets, derive_group_mailbox_secret, is_active_member, root_device_in,
};
pub use tendril_core::group::{MAX_GROUPS_PER_SIGNER, MAX_LOCAL_GROUPS, MAX_STORED_GROUPS};
use tendril_core::identity::EndpointIdentity;
use tendril_core::policy::{CandidateEndpoint, PathPolicyConfig, ProviderId};
use tendril_core::roster::{PeerState, Roster, RosterEntry, V2PeerSecrets};
use tendril_core::v2::{MAX_PADDED_PAYLOAD_LEN, PaddingPolicy};
use tendril_core::wire::{Intent, Preamble};
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore, mpsc};
use tokio::task::AbortHandle;
use tokio::time::{Instant, timeout};
use zeroize::Zeroizing;

use crate::driver::{
    ConcurrentSession, DEFAULT_PRE_AUTH_TIMEOUT, SessionDriver, SessionEvent, current_unix_secs,
    dial_with_policy_verified,
};
use crate::error::RuntimeError;
use crate::provider::{
    DEFAULT_WRITE_TIMEOUT, PathDialer, PathListener, PathStream, PrefixedPathStream, peek_exact,
};
use crate::rate_limit::{HalfOpenGuard, PreAuthConfig, PreAuthRateLimiter};
use crate::store::{RosterStamp, StateStore};
use crate::v2_driver::{ConcurrentV2Session, StagedCommit, V2ResponderState, V2SessionDriver};
use crate::wake::{DEFAULT_WAKE_TIMEOUT, WakeProvider, WakeSecret, WakeTarget};

/// Maximum concurrent sibling dials started by one pool.
pub const MAX_CONCURRENT_GROUP_DIALS: usize = 8;

/// Default per-peer dial budget.
pub const DEFAULT_GROUP_DIAL_BUDGET: Duration = Duration::from_secs(5);

const EVENT_QUEUE_CAP: usize = 1024;
const CONTROL_EVENT_RESERVE: usize = 64;
const CLOSE_GRACE: Duration = Duration::from_secs(1);
const BOOK_WATCH_INTERVAL: Duration = Duration::from_millis(250);

/// Idle limit of an ordinary admin control session accepted by a pool: it closes when no
/// group control frame arrives for this long.
pub const ADMIN_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Concurrent admin control sessions one pool serves; further ones are refused.
pub const MAX_ADMIN_SESSIONS: usize = 4;

/// Wait for the initiator's first transport frame on an inbound session admitted under the
/// group `pair_bootstrap`; the session is dropped without persisting when none arrives.
pub const BOOTSTRAP_COMMIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Uncommitted inbound bootstrap sessions one pool holds (one first-contact path per sibling);
/// further ones are refused.
pub const MAX_PENDING_BOOTSTRAP_COMMITS: usize = 32;

/// Uncommitted inbound bootstrap sessions one pool holds from one authenticated peer; a
/// further one from that peer is refused, so one member cannot hold the pool-wide slots.
pub const MAX_PENDING_BOOTSTRAP_COMMITS_PER_PEER: usize = 2;

/// Per-peer outcome of one [`GroupPool::broadcast`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BroadcastReport {
    /// Peers whose session accepted the frame.
    pub delivered: Vec<String>,
    /// Peers that could not be reached within the dial budget.
    pub offline: Vec<String>,
    /// Peers whose session failed, timed out, or was refused, with the error text.
    pub failed: Vec<(String, String)>,
}

/// Unified inbound event surfaced by [`GroupPool::poll_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEvent {
    /// Application data from an authorized sender.
    AppData {
        sender_device_id: String,
        payload: Vec<u8>,
    },
    /// A newer manifest was stored.
    ManifestUpdated { seq: u64 },
    /// A device appeared in the stored manifest.
    MemberJoined { device_id: String },
    /// A device was revoked and its session slot closed.
    MemberRevoked { device_id: String },
    /// A denied or dropped inbound action (for example data from a sender without `group.send`).
    Audit(AuditEvent),
}

/// Dial, timeout, admission, and path settings for a [`GroupPool`].
#[derive(Clone)]
pub struct GroupPoolConfig {
    pub dialers: Vec<Arc<dyn PathDialer>>,
    pub policy: PathPolicyConfig,
    pub write_timeout: Duration,
    pub dial_budget: Duration,
    pub max_concurrent_dials: usize,
    pub padding: PaddingPolicy,
    pub pre_auth: PreAuthConfig,
    pub wake_targets: HashMap<String, (WakeTarget, WakeSecret)>,
}

impl GroupPoolConfig {
    /// Creates a config dialing through `dialers` with the documented defaults.
    #[must_use]
    pub fn new(dialers: Vec<Arc<dyn PathDialer>>) -> Self {
        Self {
            dialers,
            policy: PathPolicyConfig::default(),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            dial_budget: DEFAULT_GROUP_DIAL_BUDGET,
            max_concurrent_dials: MAX_CONCURRENT_GROUP_DIALS,
            padding: PaddingPolicy::v2_default(),
            pre_auth: PreAuthConfig::default(),
            wake_targets: HashMap::new(),
        }
    }

    /// Overrides the per-peer write timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Overrides the per-peer dial budget.
    #[must_use]
    pub fn with_dial_budget(mut self, dial_budget: Duration) -> Self {
        self.dial_budget = dial_budget;
        self
    }

    /// Registers the wake target and secret used to nudge `device_id` when it is offline.
    #[must_use]
    pub fn with_wake_target(
        mut self,
        device_id: impl Into<String>,
        target: WakeTarget,
        secret: WakeSecret,
    ) -> Self {
        self.wake_targets.insert(device_id.into(), (target, secret));
        self
    }
}

enum LinkIo {
    V1(ConcurrentSession),
    V2(ConcurrentV2Session),
}

struct Link {
    id: u64,
    peer_id: String,
    peer_static: [u8; 32],
    initiator_id: String,
    io: LinkIo,
    roster: Arc<Mutex<Roster>>,
    peer_groups: Option<Vec<GroupSeq>>,
    closed: AtomicBool,
    cancel: Notify,
}

impl Link {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancel.notify_waiters();
        match &self.io {
            LinkIo::V1(s) => s.shutdown(),
            LinkIo::V2(s) => s.shutdown(),
        }
    }

    async fn cancelled(&self) {
        let notified = self.cancel.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_closed() {
            return;
        }
        notified.await;
    }

    fn close_transport(self: &Arc<Self>) {
        self.shutdown();
        let link = Arc::clone(self);
        tokio::spawn(async move {
            let _ = timeout(CLOSE_GRACE, async {
                match &link.io {
                    LinkIo::V1(s) => s.send_close(1000, "group member closed").await,
                    LinkIo::V2(s) => s.send_close(1000, "group member closed").await,
                }
            })
            .await;
        });
    }

    async fn next_event(&self) -> Result<Option<SessionEvent>, RuntimeError> {
        match &self.io {
            LinkIo::V1(s) => s.next_event_locked_now(&self.roster).await,
            LinkIo::V2(s) => s.next_event_locked_now(&self.roster).await,
        }
    }

    async fn send_data(&self, payload: &[u8], auth: &WriteAuthority) -> Result<(), RuntimeError> {
        let verify = || auth.verify();
        match &self.io {
            LinkIo::V1(s) => s.send_data_authorized(payload, verify).await,
            LinkIo::V2(s) => s.send_data_authorized(payload, verify).await,
        }
    }

    async fn send_manifest(
        &self,
        manifest: &GroupManifest,
        auth: &WriteAuthority,
    ) -> Result<(), RuntimeError> {
        self.io
            .send_manifest_authorized(manifest, || auth.verify())
            .await
    }

    async fn send_rendezvous(
        &self,
        secrets: &V2GroupSecrets,
        group_id: &str,
        auth: &WriteAuthority,
    ) -> Result<(), RuntimeError> {
        self.io
            .send_rendezvous_authorized(secrets, group_id, || auth.verify())
            .await
    }
}

impl LinkIo {
    async fn send_manifest_authorized(
        &self,
        manifest: &GroupManifest,
        verify: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_group_manifest_authorized(manifest, verify).await,
            Self::V2(s) => s.send_group_manifest_authorized(manifest, verify).await,
        }
    }

    async fn send_rendezvous_authorized(
        &self,
        secrets: &V2GroupSecrets,
        group_id: &str,
        verify: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => {
                s.send_group_rendezvous_authorized(secrets, group_id, verify)
                    .await
            }
            Self::V2(s) => {
                s.send_group_rendezvous_authorized(secrets, group_id, verify)
                    .await
            }
        }
    }

    /// Sends `0x05 PING` and reads until the matching pong, the peer's close, or an error.
    ///
    /// The peer answers the ping only after it has read every earlier frame, so a pong
    /// acknowledges the control frames written before it. Waiting for it also keeps the
    /// transport open until the peer is done, so closing never discards unread frames.
    async fn acknowledged(&self, cookie: u64, roster: &Mutex<Roster>) -> bool {
        let sent = match self {
            Self::V1(s) => s.send_ping(cookie).await,
            Self::V2(s) => s.send_ping(cookie).await,
        };
        if sent.is_err() {
            return false;
        }
        loop {
            let event = match self {
                Self::V1(s) => s.next_event_locked_now(roster).await,
                Self::V2(s) => s.next_event_locked_now(roster).await,
            };
            match event {
                Ok(Some(SessionEvent::PongReceived(got))) if got == cookie => return true,
                Ok(Some(SessionEvent::Closed { .. }) | None) | Err(_) => return false,
                Ok(Some(_)) => {}
            }
        }
    }

    /// Sends a graceful close within [`CLOSE_GRACE`], then shuts the session down.
    async fn finish(&self, reason: &str) {
        let _ = timeout(CLOSE_GRACE, async {
            match self {
                Self::V1(s) => s.send_close(1000, reason).await,
                Self::V2(s) => s.send_close(1000, reason).await,
            }
        })
        .await;
        match self {
            Self::V1(s) => s.shutdown(),
            Self::V2(s) => s.shutdown(),
        }
    }
}

/// Recipient and sender authority check evaluated against the pool's current book and CRL.
type AuthorityCheck =
    dyn Fn(&GroupBook, Option<&RevocationList>, &str) -> Result<(), RuntimeError> + Send + Sync;

/// Authority for one write, re-evaluated under the driver writer lock right before sealing.
///
/// Evaluation refreshes the pool state first (so a manifest or CRL change written by anyone
/// is seen, and the revocation sweep runs), then requires the link to still own its slot and
/// `check` to pass for the link's peer.
#[derive(Clone)]
struct WriteAuthority {
    inner: Arc<Inner>,
    link: Arc<Link>,
    check: Arc<AuthorityCheck>,
    denied: Arc<AtomicBool>,
}

impl WriteAuthority {
    fn new(inner: &Arc<Inner>, link: &Arc<Link>, check: Arc<AuthorityCheck>) -> Self {
        Self {
            inner: Arc::clone(inner),
            link: Arc::clone(link),
            check,
            denied: Arc::new(AtomicBool::new(false)),
        }
    }

    fn verify(&self) -> Result<(), RuntimeError> {
        let res = self.inner.write_authority(&self.link, &*self.check);
        if res.is_err() {
            self.denied.store(true, Ordering::Release);
        }
        res
    }

    fn with_check(&self, check: Arc<AuthorityCheck>) -> Self {
        Self {
            check,
            ..self.clone()
        }
    }

    fn was_denied(&self) -> bool {
        self.denied.load(Ordering::Acquire)
    }
}

/// The recipient is an active member, not revoked by the root CRL, and so is the local device.
fn recipient_ok(
    book: &GroupBook,
    group_id: &str,
    crl: Option<&RevocationList>,
    local_id: &str,
    peer: &str,
) -> Result<(), RuntimeError> {
    let manifest = book
        .manifest(group_id)
        .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()))?;
    if !is_active_member(manifest, local_id) || crl_revokes(crl, local_id) {
        return Err(CoreError::GroupMemberRevoked(local_id.to_owned()).into());
    }
    if !is_active_member(manifest, peer) || crl_revokes(crl, peer) {
        return Err(CoreError::GroupMemberRevoked(peer.to_owned()).into());
    }
    Ok(())
}

fn recipient_check(group_id: &str, local_id: &str) -> Arc<AuthorityCheck> {
    let (gid, local) = (group_id.to_owned(), local_id.to_owned());
    Arc::new(move |book, crl, peer| recipient_ok(book, &gid, crl, &local, peer))
}

/// [`recipient_ok`] plus live admin authority of the local device, for `0x0B` writes.
fn admin_check(group_id: &str, local_id: &str) -> Arc<AuthorityCheck> {
    let (gid, local) = (group_id.to_owned(), local_id.to_owned());
    Arc::new(move |book, crl, peer| {
        recipient_ok(book, &gid, crl, &local, peer)?;
        if book.is_group_admin(&gid, &local, current_unix_secs(), crl) {
            Ok(())
        } else {
            Err(CoreError::GroupUnauthorized("local device is not a group admin".to_owned()).into())
        }
    })
}

fn crl_revokes(crl: Option<&RevocationList>, device_id: &str) -> bool {
    crl.is_some_and(|c| c.revoked_devices.iter().any(|d| d == device_id))
}

/// Returns the persisted roster entry that admits `accepted` as an ordinary session: an
/// `Active`, CRL-clean entry with the authenticated static key, a wire floor the session meets,
/// and, on Wire v2, the entry's own reconnect secret as the admitting rendezvous secret.
fn ordinary_entry<'r>(roster: &'r Roster, accepted: &Accepted) -> Option<&'r RosterEntry> {
    roster.get(&accepted.peer_id).filter(|e| {
        e.state == PeerState::Active
            && e.static_pub == accepted.peer_static
            && e.min_wire_version <= accepted.wire()
            && !roster.crl_revokes_entry(e)
            && match &accepted.matched {
                None => true,
                Some(m) => e
                    .v2_secrets
                    .as_ref()
                    .is_some_and(|s| bool::from(s.reconnect_secret().ct_eq(&**m))),
            }
    })
}

/// An ordinary paired session target for an admin push: the roster key, a roster narrowed to
/// that entry, and the wire version its persisted floor and secrets select.
struct OrdinaryTarget {
    host_id: String,
    roster: Roster,
    wire: u8,
}

/// Resolves `member` to an `Active`, CRL-clean ordinary roster entry with a complete pin whose
/// static key equals the manifest pin. Wire v2 is used when the entry holds v2 secrets, Wire v1
/// when its floor allows it; otherwise the member has no usable ordinary session.
fn ordinary_target(roster: &Roster, member: &GroupMember) -> Option<OrdinaryTarget> {
    let static_pub = b64url_decode_array::<32>(&member.static_pub).ok()?;
    let (host_id, entry) = roster.entries().find(|(_, e)| {
        e.device_id == member.device_id
            && e.state == PeerState::Active
            && e.static_pub == static_pub
            && e.require_complete_pin().is_ok()
            && !roster.crl_revokes_entry(e)
    })?;
    let wire = if entry.v2_secrets.is_some() {
        2
    } else if entry.min_wire_version < 2 {
        1
    } else {
        return None;
    };
    let host_id = host_id.clone();
    let mut narrowed = roster.clone();
    narrowed.retain_active(|key, _| key == host_id);
    Some(OrdinaryTarget {
        host_id,
        roster: narrowed,
        wire,
    })
}

/// Narrows the persisted roster to the ordinary entries of `group_id`'s live admins that a
/// session over `wire` can authenticate: root or co-admin per the stored manifest, CRL-clean,
/// static key and signing key equal to the manifest pins (so a merged sibling pin is never
/// verified against a different key), and a persisted floor `<= wire`.
fn admin_roster(
    persisted: &Roster,
    book: &GroupBook,
    group_id: &str,
    crl: Option<&RevocationList>,
    wire: u8,
    now: u64,
) -> Roster {
    let mut roster = persisted.clone();
    let Some(manifest) = book.manifest(group_id) else {
        roster.retain_active(|_, _| false);
        return roster;
    };
    roster.retain_active(|_, e| {
        let pinned = manifest.members.iter().any(|m| {
            m.device_id == e.device_id
                && b64url_decode_array::<32>(&m.static_pub).ok() == Some(e.static_pub)
                && e.signing_pub
                    .as_ref()
                    .is_some_and(|k| b64url_encode(&k.sha256_hash()) == m.signing_pub_hash)
        });
        pinned
            && e.min_wire_version <= wire
            && !crl_revokes(crl, &e.device_id)
            && book.is_group_admin(group_id, &e.device_id, now, crl)
    });
    roster
}

/// Which group secret admitted a Wire v2 sibling session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretKind {
    Pairwise,
    Bootstrap,
}

enum AcceptedIo {
    V1(SessionDriver),
    V2(V2SessionDriver),
}

/// One authenticated session not yet bound to a pool slot.
struct Accepted {
    io: AcceptedIo,
    peer_id: String,
    peer_static: [u8; 32],
    peer_groups: Option<Vec<GroupSeq>>,
    exported: Option<V2PeerSecrets>,
    matched: Option<Zeroizing<[u8; 32]>>,
}

impl Accepted {
    const fn wire(&self) -> u8 {
        match self.io {
            AcceptedIo::V1(_) => 1,
            AcceptedIo::V2(_) => 2,
        }
    }

    fn close(self) {
        let io = self.io;
        tokio::spawn(async move {
            let _ = timeout(CLOSE_GRACE, async {
                match io {
                    AcceptedIo::V1(mut s) => s.send_close(1000, "group session refused").await,
                    AcceptedIo::V2(mut s) => s.send_close(1000, "group session refused").await,
                }
            })
            .await;
        });
    }
}

/// One of [`MAX_PENDING_BOOTSTRAP_COMMITS_PER_PEER`] pending-commit slots of a peer, released
/// on drop.
struct PeerPendingSlot {
    counts: Arc<Mutex<HashMap<String, usize>>>,
    peer: String,
}

impl PeerPendingSlot {
    fn take(counts: &Arc<Mutex<HashMap<String, usize>>>, peer: &str) -> Option<Self> {
        let mut map = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let held = map.entry(peer.to_owned()).or_insert(0);
        if *held >= MAX_PENDING_BOOTSTRAP_COMMITS_PER_PEER {
            return None;
        }
        *held += 1;
        Some(Self {
            counts: Arc::clone(counts),
            peer: peer.to_owned(),
        })
    }
}

impl Drop for PeerPendingSlot {
    fn drop(&mut self) {
        let mut map = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(held) = map.get_mut(&self.peer) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                map.remove(&self.peer);
            }
        }
    }
}

/// Everything needed to admit or dial one active sibling, derived from the stored book.
struct MemberPin {
    device_id: String,
    name: String,
    static_pub: [u8; 32],
    signing_hash: [u8; 32],
    floor: u8,
    pairwise: Option<V2PeerSecrets>,
    bootstrap: Option<V2PeerSecrets>,
}

/// One sibling pin placed in an accepting roster.
struct PinRecord {
    static_pub: [u8; 32],
    floor: u8,
    secrets: Vec<(SecretKind, Zeroizing<[u8; 32]>)>,
}

/// Sibling pins placed in an accepting roster, indexed by `(group_id, device_id)`; tells which
/// group a session may belong to and which group secret admitted it.
#[derive(Default)]
struct PinIndex {
    pins: HashMap<(String, String), PinRecord>,
}

impl PinIndex {
    fn record(&mut self, group_id: &str, pin: &MemberPin) {
        let secrets = [
            (SecretKind::Pairwise, pin.pairwise.as_ref()),
            (SecretKind::Bootstrap, pin.bootstrap.as_ref()),
        ]
        .into_iter()
        .filter_map(|(kind, s)| Some((kind, Zeroizing::new(*s?.reconnect_secret()))))
        .collect();
        self.pins.insert(
            (group_id.to_owned(), pin.device_id.clone()),
            PinRecord {
                static_pub: pin.static_pub,
                floor: pin.floor,
                secrets,
            },
        );
    }

    /// Returns which secret of `peer`'s pin in `group_id` equals `matched`, if any.
    fn classify(&self, group_id: &str, peer: &str, matched: &[u8; 32]) -> Option<SecretKind> {
        let record = self.pins.get(&(group_id.to_owned(), peer.to_owned()))?;
        let mut found = None;
        for (kind, secret) in &record.secrets {
            if bool::from(secret.ct_eq(matched)) {
                found = Some(*kind);
            }
        }
        found
    }

    /// Decides whether a session authenticated as `peer` with `peer_static` over `wire` (and,
    /// on Wire v2, admitted under `matched`) belongs to `group_id`. `Some` carries the secret
    /// kind for Wire v2 and `None` inside it for Wire v1.
    fn route(
        &self,
        group_id: &str,
        peer: &str,
        peer_static: &[u8; 32],
        wire: u8,
        matched: Option<&[u8; 32]>,
    ) -> Option<Option<SecretKind>> {
        let record = self.pins.get(&(group_id.to_owned(), peer.to_owned()))?;
        if !bool::from(record.static_pub.ct_eq(peer_static)) {
            return None;
        }
        match (wire, matched) {
            (1, None) if record.floor < 2 => Some(None),
            (2, Some(m)) if record.floor >= 2 => self.classify(group_id, peer, m).map(Some),
            _ => None,
        }
    }
}

/// Adds `pin` to `roster` atomically: either every step succeeds or `roster` is unchanged.
///
/// An existing `Active` entry with the same static key only gains the pin's v2 secrets as
/// rendezvous alternates; any other existing entry is a conflict and the member is skipped. A
/// new entry is first built in a single-entry scratch roster, and a failure while publishing it
/// removes the partial entry, so the caller's roster is never cloned per pin.
fn add_pin(roster: &mut Roster, pin: &MemberPin) -> Result<(), RuntimeError> {
    let id = pin.device_id.as_str();
    if let Some(existing) = roster.get(id) {
        if existing.state != PeerState::Active || existing.static_pub != pin.static_pub {
            return Err(CoreError::PeerRevoked(id.to_owned()).into());
        }
        for secrets in [&pin.pairwise, &pin.bootstrap].into_iter().flatten() {
            roster.add_rendezvous_alternate(id, secrets.clone())?;
        }
        return Ok(());
    }
    build_pin_entry(&mut Roster::new(), pin)?;
    if let Err(err) = build_pin_entry(roster, pin) {
        roster.retain_active(|key, _| key != id);
        return Err(err);
    }
    Ok(())
}

fn build_pin_entry(roster: &mut Roster, pin: &MemberPin) -> Result<(), RuntimeError> {
    let id = pin.device_id.as_str();
    roster.insert_pinned_host(
        id.to_owned(),
        pin.name.clone(),
        pin.static_pub,
        None,
        0,
        Vec::new(),
    )?;
    roster.pin_signing_hash(id, pin.signing_hash)?;
    if pin.floor >= 2 {
        let (primary, alternate) = match (&pin.pairwise, &pin.bootstrap) {
            (Some(p), b) => (p.clone(), b.clone()),
            (None, Some(b)) => (b.clone(), None),
            (None, None) => {
                return Err(CoreError::IncompletePin(id.to_owned()).into());
            }
        };
        roster.upgrade_peer_to_v2(id, primary)?;
        if let Some(alt) = alternate {
            roster.add_rendezvous_alternate(id, alt)?;
        }
    }
    Ok(())
}

enum DialError {
    Offline(String),
    Failed(String),
}

/// The stored book and founding-root CRL as one coherent authority view, plus live slots.
///
/// Both files are tracked by stamp; on any change every slot is re-checked against the new view
/// in the same critical section.
struct PoolState {
    book: GroupBook,
    stamp: Option<RosterStamp>,
    crl: Option<RevocationList>,
    roster_stamp: Option<RosterStamp>,
    slots: HashMap<String, Arc<Link>>,
}

#[cfg(test)]
type TestHook = Mutex<Option<Box<dyn FnOnce() + Send>>>;

/// Test-only interleave points, fired synchronously and at most once each.
#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    after_pairwise_persist: TestHook,
    before_write: TestHook,
    staged_inbound: TestGate,
    committed_inbound: TestGate,
    inbound_done: TestGate,
    commit_timeout: Mutex<Option<Duration>>,
}

/// Test-only async interleave point: `(reached, release)`, used at most once.
#[cfg(test)]
type TestGate = Mutex<
    Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
>;

#[cfg(test)]
async fn fire_gate(gate: &TestGate) {
    let armed = gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some((reached, release)) = armed {
        let _ = reached.send(());
        let _ = release.await;
    }
}

#[cfg(test)]
fn fire(hook: &TestHook) {
    let f = hook
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(f) = f {
        f();
    }
}

struct Inner {
    store: GatedStore,
    identity: Arc<EndpointIdentity>,
    local_id: String,
    group_id: String,
    root_id: String,
    root_pub: HybridSigningPublicKey,
    cfg: GroupPoolConfig,
    wake: Option<Arc<dyn WakeProvider>>,
    state: Mutex<PoolState>,
    peer_locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    dial_sem: Semaphore,
    next_link_id: AtomicU64,
    events_tx: mpsc::Sender<GroupEvent>,
    events_rx: AsyncMutex<mpsc::Receiver<GroupEvent>>,
    v2_state: V2ResponderState,
    admission: PreAuthRateLimiter,
    admin_sessions: Arc<Semaphore>,
    pending_commits: Arc<Semaphore>,
    pending_by_peer: Arc<Mutex<HashMap<String, usize>>>,
    closed: AtomicBool,
    close_notify: tokio::sync::Notify,
    watcher_started: AtomicBool,
    tasks: Mutex<Vec<AbortHandle>>,
    #[cfg(test)]
    hooks: TestHooks,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for link in state.slots.values() {
            link.shutdown();
        }
        for task in self
            .tasks
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
    }
}

/// A pool's view of the state store, shut by [`GatedStore::close`].
///
/// Pool tasks reach the store through `spawn_blocking`, which an aborted task cannot cancel.
/// Every access holds the shared side of the gate for its whole duration (lock-file creation
/// included) and fails with [`RuntimeError::Closed`] once the gate is shut. [`GatedStore::close`]
/// takes the exclusive side, so it returns only after every in-flight access finished, and no
/// pool access touches the state directory after it returns.
#[derive(Clone)]
struct GatedStore {
    store: StateStore,
    shut: Arc<RwLock<bool>>,
}

impl GatedStore {
    fn new(store: StateStore) -> Self {
        Self {
            store,
            shut: Arc::new(RwLock::new(false)),
        }
    }

    fn close(&self) {
        *self
            .shut
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    }

    fn run<T>(
        &self,
        f: impl FnOnce(&StateStore) -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let shut = self
            .shut
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *shut {
            return Err(RuntimeError::Closed);
        }
        f(&self.store)
    }

    fn groups_stamp(&self) -> Result<Option<RosterStamp>, RuntimeError> {
        self.run(StateStore::groups_stamp)
    }

    fn roster_stamp(&self) -> Result<Option<RosterStamp>, RuntimeError> {
        self.run(StateStore::roster_stamp)
    }

    fn load_roster(&self) -> Result<Roster, RuntimeError> {
        self.run(StateStore::load_roster)
    }

    fn load_group_book(&self) -> Result<GroupBook, RuntimeError> {
        self.run(StateStore::load_group_book)
    }

    fn update_group_book<T, F>(&self, f: F) -> Result<T, RuntimeError>
    where
        F: FnOnce(&mut GroupBook) -> Result<T, RuntimeError>,
    {
        self.run(|store| store.update_group_book(f))
    }
}

/// Lazy full-mesh connection pool for one group, driven by the stored signed manifest.
#[derive(Clone)]
pub struct GroupPool {
    inner: Arc<Inner>,
}

impl GroupPool {
    /// Opens a pool for `group_id` using the manifest already stored in `store`.
    ///
    /// Fails closed when the group is unknown, the local device is not an active member, the
    /// group is not among the first [`MAX_LOCAL_GROUPS`] local member groups, or the identity
    /// `host_id` differs from its `device_id` (sibling sessions address peers by `device_id`).
    pub fn open(
        store: StateStore,
        identity: Arc<EndpointIdentity>,
        group_id: &str,
        config: GroupPoolConfig,
        wake: Option<Arc<dyn WakeProvider>>,
    ) -> Result<Self, RuntimeError> {
        let local_id = identity.device_id();
        require_group_identity(&identity)?;
        let stamp = store.groups_stamp()?;
        let book = store.load_group_book()?;
        let manifest = book
            .manifest(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()))?;
        if !is_active_member(manifest, &local_id) {
            return Err(CoreError::GroupUnauthorized(format!(
                "{local_id} is not an active member of {group_id}"
            ))
            .into());
        }
        if !local_member_groups(&book, &local_id)
            .iter()
            .any(|g| g == group_id)
        {
            return Err(CoreError::GroupUnauthorized(format!(
                "more than {MAX_LOCAL_GROUPS} local groups"
            ))
            .into());
        }
        let root_id = root_device_of(&book, manifest)
            .ok_or_else(|| CoreError::GroupUnauthorized("founding root missing".to_owned()))?;
        let root_pub = book
            .root_signing_pub(group_id)
            .cloned()
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()))?;
        let (roster, roster_stamp) = store.load_roster_with_stamp()?;
        let crl = core_group::root_crl(&roster, &root_id, &root_pub, Some(&local_id))?;
        drop(roster);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE_CAP);
        let v2_state = V2ResponderState::with_config(crate::v2_driver::V2ResponderConfig {
            padding: config.padding.clone(),
            ..crate::v2_driver::V2ResponderConfig::default()
        });
        let dials = config
            .max_concurrent_dials
            .clamp(1, MAX_CONCURRENT_GROUP_DIALS);
        let pool = Self {
            inner: Arc::new(Inner {
                store: GatedStore::new(store),
                identity,
                local_id,
                group_id: group_id.to_owned(),
                root_id,
                root_pub,
                dial_sem: Semaphore::new(dials),
                admission: PreAuthRateLimiter::new(config.pre_auth.clone()),
                admin_sessions: Arc::new(Semaphore::new(MAX_ADMIN_SESSIONS)),
                pending_commits: Arc::new(Semaphore::new(MAX_PENDING_BOOTSTRAP_COMMITS)),
                pending_by_peer: Arc::new(Mutex::new(HashMap::new())),
                cfg: config,
                wake,
                state: Mutex::new(PoolState {
                    book,
                    stamp,
                    crl,
                    roster_stamp,
                    slots: HashMap::new(),
                }),
                peer_locks: Mutex::new(HashMap::new()),
                next_link_id: AtomicU64::new(1),
                events_tx,
                events_rx: AsyncMutex::new(events_rx),
                v2_state,
                closed: AtomicBool::new(false),
                close_notify: tokio::sync::Notify::new(),
                watcher_started: AtomicBool::new(false),
                tasks: Mutex::new(Vec::new()),
                #[cfg(test)]
                hooks: TestHooks::default(),
            }),
        };
        pool.ensure_book_watcher();
        Ok(pool)
    }

    /// Applies book and root CRL changes written outside this pool (another process, a manifest
    /// ingested over an ordinary session, or a CRL ingested into the roster) promptly:
    /// membership events and the revocation sweep.
    ///
    /// A pool opened outside a Tokio runtime starts the watcher on its first runtime-bound call
    /// (`serve`, `accept`, `broadcast`, `sync`, `ingest_manifest`, `poll_event`, or an inbound
    /// session routed by a hub). The watcher starts at most once.
    fn ensure_book_watcher(&self) {
        if self.inner.watcher_started.load(Ordering::Acquire) || self.is_closed() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.inner.watcher_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(&self.inner);
        let task = runtime.spawn(async move {
            let mut tick = tokio::time::interval(BOOK_WATCH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                if inner.closed.load(Ordering::Acquire) {
                    return;
                }
                let mut st = inner.lock_state();
                if let Err(err) = inner.refresh_locked(&mut st) {
                    tracing::debug!(error = %err, "group book refresh failed");
                }
            }
        });
        self.inner.track(task.abort_handle());
    }

    /// Returns the group id this pool serves.
    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.inner.group_id
    }

    /// Reports whether [`Self::close`] was called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// Returns a copy of the stored manifest.
    pub fn manifest(&self) -> Result<GroupManifest, RuntimeError> {
        let (book, _) = self.inner.view()?;
        book.manifest(&self.inner.group_id)
            .cloned()
            .ok_or_else(|| CoreError::GroupNotFound(self.inner.group_id.clone()).into())
    }

    /// Returns the device ids with a live session slot.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .inner
            .lock_state()
            .slots
            .iter()
            .filter(|(_, l)| !l.is_closed())
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Fans `payload` out to every active non-self member holding `group.recv:<group_id>`.
    ///
    /// The local member must hold `cap` (default `group.send:<group_id>`). Healthy sessions are
    /// reused; missing ones are dialed concurrently (bounded by
    /// [`MAX_CONCURRENT_GROUP_DIALS`]). A failing peer is isolated into `offline` or `failed`.
    /// Sender and recipient authority are re-checked right before each write, and a revocation
    /// cancels queued and in-flight writes to the revoked peer.
    pub async fn broadcast(
        &self,
        cap: Option<&str>,
        payload: &[u8],
    ) -> Result<BroadcastReport, RuntimeError> {
        self.inner.ensure_open()?;
        self.ensure_book_watcher();
        if payload.len() > MAX_PADDED_PAYLOAD_LEN {
            return Err(RuntimeError::FrameTooLarge {
                size: payload.len(),
                max: MAX_PADDED_PAYLOAD_LEN,
            });
        }
        let gid = self.inner.group_id.clone();
        let send_cap = match cap {
            Some(raw) => Capability::parse(raw)?,
            None => Capability::parse(&format!("group.send:{gid}"))?,
        };
        let recv_cap = Capability::parse(&format!("group.recv:{gid}"))?;
        let now = current_unix_secs();
        let (book, crl) = self.inner.view()?;
        book.authorize_group(&gid, &self.inner.local_id, &send_cap, now, crl.as_ref())?;
        let manifest = book
            .manifest(&gid)
            .ok_or_else(|| CoreError::GroupNotFound(gid.clone()))?;
        let targets: Vec<GroupMember> = manifest
            .members
            .iter()
            .filter(|m| m.device_id != self.inner.local_id)
            .filter(|m| {
                book.authorize_group(&gid, &m.device_id, &recv_cap, now, crl.as_ref())
                    .is_ok()
            })
            .cloned()
            .collect();
        let local_id = self.inner.local_id.clone();
        let check: Arc<AuthorityCheck> = Arc::new(move |book, crl, peer| {
            let now = current_unix_secs();
            book.authorize_group(&gid, &local_id, &send_cap, now, crl)?;
            book.authorize_group(&gid, peer, &recv_cap, now, crl)?;
            Ok(())
        });
        let results = futures_util::future::join_all(targets.into_iter().map(|member| {
            let inner = Arc::clone(&self.inner);
            let check = Arc::clone(&check);
            async move {
                let outcome = inner
                    .deliver(&member, check, |link, auth| async move {
                        link.send_data(payload, &auth).await
                    })
                    .await;
                (member.device_id, outcome)
            }
        }))
        .await;
        let report = into_report(results);
        for peer in &report.offline {
            self.inner.nudge(peer).await;
        }
        Ok(report)
    }

    /// Pushes the stored manifest (and, when the local device is an admin, the current
    /// rendezvous key) to every active member not revoked by the root CRL.
    ///
    /// A member with a live pool link receives the frames on it. A member without one that is
    /// an `Active`, CRL-clean ordinarily paired peer with the manifest's static key receives them
    /// over a fresh ordinary session (persisted secrets and floor), which carries only these
    /// control frames and then closes: this is how a Wire v2 member that holds the manifest but
    /// not the current key is onboarded. Any other member is dialed as a sibling.
    ///
    /// Each frame is written only if, under the writer lock, the recipient is still an active,
    /// CRL-clean member (and, for the key, the local device is still an admin). An ordinary
    /// session counts as delivered only once the member answers a ping sent after the frames,
    /// which it does after reading them. A member driven through a host binding answers only
    /// while the host polls that session, so the host must keep polling until the session
    /// closes; the wait is bounded (10 s at least, longer when the dial or write budget is).
    pub async fn sync(&self) -> Result<BroadcastReport, RuntimeError> {
        self.inner.ensure_open()?;
        self.ensure_book_watcher();
        let gid = self.inner.group_id.clone();
        let local_id = self.inner.local_id.clone();
        let now = current_unix_secs();
        let (book, crl) = self.inner.view()?;
        let manifest = book
            .manifest(&gid)
            .cloned()
            .ok_or_else(|| CoreError::GroupNotFound(gid.clone()))?;
        let admin_secrets = book
            .is_group_admin(&gid, &local_id, now, crl.as_ref())
            .then(|| book.secrets(&gid).cloned())
            .flatten()
            .filter(|s| s.seq() == manifest.seq);
        let targets: Vec<GroupMember> = manifest
            .members
            .iter()
            .filter(|m| m.device_id != local_id)
            .filter(|m| recipient_ok(&book, &gid, crl.as_ref(), &local_id, &m.device_id).is_ok())
            .cloned()
            .collect();
        let roster = self.inner.store.load_roster()?;
        let recipient = recipient_check(&gid, &local_id);
        let admin = admin_check(&gid, &local_id);
        let results = futures_util::future::join_all(targets.into_iter().map(|member| {
            let inner = Arc::clone(&self.inner);
            let manifest = manifest.clone();
            let admin_secrets = admin_secrets.clone();
            let gid = gid.clone();
            let recipient = Arc::clone(&recipient);
            let admin = Arc::clone(&admin);
            let ordinary = inner
                .healthy_link(&member.device_id)
                .is_none()
                .then(|| ordinary_target(&roster, &member))
                .flatten();
            async move {
                let outcome = match ordinary {
                    Some(target) => {
                        inner
                            .deliver_control(
                                &member,
                                target,
                                &manifest,
                                admin_secrets.as_ref(),
                                recipient,
                                admin,
                            )
                            .await
                    }
                    None => {
                        inner
                            .deliver(&member, recipient, |link, auth| async move {
                                link.send_manifest(&manifest, &auth).await?;
                                if let Some(secrets) = &admin_secrets {
                                    let auth = auth.with_check(admin);
                                    link.send_rendezvous(secrets, &gid, &auth).await?;
                                }
                                Ok(())
                            })
                            .await
                    }
                };
                (member.device_id, outcome)
            }
        }))
        .await;
        Ok(into_report(results))
    }

    /// Verifies and ingests `manifest` as an explicit administrative push, then sweeps sessions
    /// of any newly revoked member.
    pub async fn ingest_manifest(
        &self,
        manifest: &GroupManifest,
    ) -> Result<GroupIngestOutcome, RuntimeError> {
        self.inner.ensure_open()?;
        self.ensure_book_watcher();
        self.inner.apply_manifest(manifest, true).await
    }

    /// Waits up to `wait` for the next inbound event.
    pub async fn poll_event(&self, wait: Duration) -> Option<GroupEvent> {
        self.ensure_book_watcher();
        let inner = &self.inner;
        let next = async {
            let mut rx = inner.events_rx.lock().await;
            loop {
                let closed = inner.close_notify.notified();
                tokio::pin!(closed);
                closed.as_mut().enable();
                if let Ok(event) = rx.try_recv() {
                    return Some(event);
                }
                if inner.closed.load(Ordering::Acquire) {
                    return None;
                }
                tokio::select! {
                    event = rx.recv() => return event,
                    () = &mut closed => {}
                }
            }
        };
        tokio::select! {
            biased;
            event = next => event,
            () = tokio::time::sleep(wait) => None,
        }
    }

    /// Checks whether `peer_id` currently holds `cap` in the stored manifest and is not revoked
    /// by the root CRL.
    pub fn authorize_peer(&self, peer_id: &str, cap: &str) -> Result<(), RuntimeError> {
        let cap = Capability::parse(cap)?;
        let (book, crl) = self.inner.view()?;
        book.authorize_group(
            &self.inner.group_id,
            peer_id,
            &cap,
            current_unix_secs(),
            crl.as_ref(),
        )?;
        Ok(())
    }

    /// Accepts one inbound stream through this pool's pre-auth admission limiter.
    ///
    /// A sibling session (the initiator advertises exactly this group, and the peer is an
    /// active member authenticated against the stored manifest alone) is installed. Any other
    /// session is admitted only as an ordinary admin control session from this group's root or
    /// live co-admin, authenticated against its persisted ordinary roster entry and floor; it
    /// is served in the background, ingests only this group's `0x0A` and `0x0B`, never
    /// delivers application data, and closes on peer close or after
    /// [`ADMIN_SESSION_IDLE_TIMEOUT`] without a control frame. Everything else is refused.
    ///
    /// Returns the authenticated peer `device_id`.
    pub async fn accept(&self, stream: Box<dyn PathStream>) -> Result<String, RuntimeError> {
        self.inner.ensure_open()?;
        self.ensure_book_watcher();
        let guard = self.inner.admission.try_acquire_for_stream(
            stream.provider_id(),
            stream.peer_ip(),
            stream.peer_transport_id().as_deref(),
        )?;
        Arc::clone(&self.inner).accept_stream(stream, guard).await
    }

    /// Spawns an accept loop over `listener`. Each stream must obtain a pre-auth admission slot
    /// before a handshake task is spawned for it.
    pub fn serve(&self, mut listener: Box<dyn PathListener>) {
        self.ensure_book_watcher();
        let weak: Weak<Inner> = Arc::downgrade(&self.inner);
        let handle = tokio::spawn(async move {
            loop {
                let mut stream = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if weak.strong_count() == 0 {
                            return;
                        }
                        continue;
                    }
                };
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                if inner.closed.load(Ordering::Acquire) {
                    return;
                }
                let guard = match inner.admission.try_acquire_for_stream(
                    stream.provider_id(),
                    stream.peer_ip(),
                    stream.peer_transport_id().as_deref(),
                ) {
                    Ok(g) => g,
                    Err(err) => {
                        tracing::debug!(error = %err, "group inbound session not admitted");
                        let _ = stream.close().await;
                        continue;
                    }
                };
                let task = tokio::spawn(async move {
                    if let Err(err) = Arc::clone(&inner).accept_stream(stream, guard).await {
                        tracing::debug!(error = %err, "group inbound session refused");
                    }
                });
                if let Some(inner) = weak.upgrade() {
                    inner.track(task.abort_handle());
                }
            }
        });
        self.inner.track(handle.abort_handle());
    }

    /// Closes every live session slot while keeping the pool open for later dials and accepts.
    pub fn disconnect_all(&self) {
        let links: Vec<Arc<Link>> = self
            .inner
            .lock_state()
            .slots
            .drain()
            .map(|(_, l)| l)
            .collect();
        for link in links {
            link.close_transport();
        }
    }

    /// Closes every session slot and stops accepting; further operations fail.
    ///
    /// Returns only after every in-flight state store access of this pool finished, and the pool
    /// touches the state directory no more afterwards.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.close_notify.notify_waiters();
        self.disconnect_all();
        for task in self
            .inner
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
        self.inner.store.close();
    }
}

fn into_report(results: Vec<(String, Delivery)>) -> BroadcastReport {
    let mut report = BroadcastReport::default();
    for (peer, outcome) in results {
        match outcome {
            Delivery::Delivered => report.delivered.push(peer),
            Delivery::Offline => report.offline.push(peer),
            Delivery::Failed(err) => report.failed.push((peer, err)),
        }
    }
    report.delivered.sort();
    report.offline.sort();
    report.failed.sort();
    report
}

enum Delivery {
    Delivered,
    Offline,
    Failed(String),
}

/// An inbound session authenticated by [`GroupHub::accept`].
pub enum InboundSession {
    /// A sibling session installed in the pool for `group_id`.
    Group {
        group_id: String,
        peer_device_id: String,
    },
    /// An ordinary Wire v1 session from an `Active` paired peer, with the persisted roster and
    /// stamp it was admitted against.
    OrdinaryV1 {
        session: SessionDriver,
        roster: Roster,
        stamp: Option<RosterStamp>,
    },
    /// An ordinary Wire v2 session from an `Active` paired peer, already store-backed.
    OrdinaryV2 { session: V2SessionDriver },
}

/// Inbound dispatcher for every local group plus ordinary paired sessions on one listener.
///
/// Each handshake authenticates against one snapshot: the persisted roster and group book are
/// read once, and the persisted roster is extended in memory with the group-scoped sibling pins
/// of every open pool whose wire floor matches the session's wire version (on Wire v1, persisted
/// entries with a Wire v2 floor are left out). A session is installed in a pool only when the
/// initiator advertises exactly that one local group in `SessionHello.groups`, the peer is an
/// active pinned member of it with the pinned static key, and (on Wire v2) it was admitted under
/// that member's pairwise or bootstrap secret for that group; the pool then re-checks it. Every
/// other session is ordinary and is returned only when the peer is an `Active` entry of the
/// persisted roster with the same static key, a persisted wire floor the session meets, and (on
/// Wire v2) that entry's own secret, so siblings never pass as ordinary peers and a gossip
/// summary never diverts an ordinary peer.
pub struct GroupHub {
    store: StateStore,
    identity: Arc<EndpointIdentity>,
    config: GroupPoolConfig,
    wake: Option<Arc<dyn WakeProvider>>,
    pools: Mutex<BTreeMap<String, GroupPool>>,
}

impl GroupHub {
    /// Creates a hub; pools are opened by [`Self::sync`].
    #[must_use]
    pub fn new(
        store: StateStore,
        identity: Arc<EndpointIdentity>,
        config: GroupPoolConfig,
        wake: Option<Arc<dyn WakeProvider>>,
    ) -> Self {
        Self {
            store,
            identity,
            config,
            wake,
            pools: Mutex::new(BTreeMap::new()),
        }
    }

    /// Opens a pool for every stored group the local device is an active member of (at most
    /// [`MAX_LOCAL_GROUPS`]) and closes pools for groups it left. Returns only the newly opened
    /// pools.
    pub fn sync(&self) -> Result<Vec<GroupPool>, RuntimeError> {
        let book = self.store.load_group_book()?;
        let local_id = self.identity.device_id();
        let wanted = local_member_groups(&book, &local_id);
        let mut pools = self
            .pools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stale: Vec<String> = pools
            .keys()
            .filter(|id| !wanted.contains(id))
            .cloned()
            .collect();
        for id in stale {
            if let Some(pool) = pools.remove(&id) {
                pool.close();
            }
        }
        let mut opened = Vec::new();
        for id in wanted {
            if pools.contains_key(&id) {
                continue;
            }
            match GroupPool::open(
                self.store.clone(),
                Arc::clone(&self.identity),
                &id,
                self.config.clone(),
                self.wake.clone(),
            ) {
                Ok(pool) => {
                    opened.push(pool.clone());
                    pools.insert(id, pool);
                }
                Err(err) => tracing::debug!(group = %id, error = %err, "group pool not opened"),
            }
        }
        Ok(opened)
    }

    /// Returns the open pools.
    #[must_use]
    pub fn pools(&self) -> Vec<GroupPool> {
        self.pools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Returns the open pool for `group_id`.
    #[must_use]
    pub fn pool(&self, group_id: &str) -> Option<GroupPool> {
        self.pools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(group_id)
            .cloned()
    }

    /// Authenticates one inbound session stream and routes it (see the type docs).
    ///
    /// `rate_limiter` and `guard` are the caller's pre-auth limiter and the half-open slot it
    /// already holds for this stream; failed handshakes are charged to the limiter.
    pub async fn accept(
        &self,
        mut stream: Box<dyn PathStream>,
        v2_state: &V2ResponderState,
        rate_limiter: Option<&PreAuthRateLimiter>,
        guard: Option<HalfOpenGuard>,
    ) -> Result<InboundSession, RuntimeError> {
        let peeked = timeout(
            DEFAULT_PRE_AUTH_TIMEOUT,
            peek_exact(stream.as_mut(), PREAMBLE_LEN),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("session preamble read timed out"))??;
        let preamble = Preamble::decode(&peeked[..PREAMBLE_LEN])?;
        if preamble.intent != Intent::Session {
            return Err(RuntimeError::Protocol(
                "inbound dispatch accepts session intents only".to_owned(),
            ));
        }
        let stream: Box<dyn PathStream> = Box::new(PrefixedPathStream::new(stream, peeked));
        let wire = if preamble.version >= 2 { 2 } else { 1 };
        let now = current_unix_secs();
        let store = self.store.clone();
        let (mut combined, book) =
            blocking(move || Ok((store.load_roster()?, store.load_group_book()?))).await?;
        let local_id = self.identity.device_id();
        let mut index = PinIndex::default();
        let pools: Vec<GroupPool> = self
            .pools()
            .into_iter()
            .filter(|p| !p.is_closed())
            .collect();
        // Root CRLs are resolved from the full persisted roster before the wire floor narrows it.
        let crls: Vec<_> = pools
            .iter()
            .map(|pool| {
                core_group::root_crl(
                    &combined,
                    &pool.inner.root_id,
                    &pool.inner.root_pub,
                    Some(&local_id),
                )
            })
            .collect();
        if wire < 2 {
            combined.retain_active(|_, e| e.min_wire_version < 2);
        }
        for (pool, crl) in pools.iter().zip(crls) {
            let gid = pool.group_id();
            let floor_wire = book
                .manifest(gid)
                .map(|m| if m.min_wire_version >= 2 { 2 } else { 1 });
            if floor_wire != Some(wire) {
                continue;
            }
            let crl = match crl {
                Ok(crl) => crl,
                Err(err) => {
                    tracing::debug!(group = %gid, error = %err, "group pins skipped");
                    continue;
                }
            };
            let pins = match group_pins(&book, gid, &local_id, crl.as_ref(), now) {
                Ok(pins) => pins,
                Err(err) => {
                    tracing::debug!(group = %gid, error = %err, "group pins skipped");
                    continue;
                }
            };
            for pin in pins {
                match add_pin(&mut combined, &pin) {
                    Ok(()) => index.record(gid, &pin),
                    Err(err) => {
                        tracing::debug!(peer = %pin.device_id, error = %err, "group member skipped");
                    }
                }
            }
        }
        drop(book);
        let accepted = accept_handshake(
            stream,
            &self.identity,
            combined,
            preamble.version,
            v2_state,
            rate_limiter,
            guard,
        )
        .await?;

        let routed = match accepted.peer_groups.as_deref() {
            Some([only]) => pools.iter().find(|p| p.group_id() == only.group_id),
            _ => None,
        }
        .and_then(|pool| {
            let kind = index.route(
                pool.group_id(),
                &accepted.peer_id,
                &accepted.peer_static,
                accepted.wire(),
                accepted.matched.as_deref(),
            )?;
            Some((pool, kind))
        });
        if let Some((pool, kind)) = routed {
            let peer = accepted.peer_id.clone();
            pool.ensure_book_watcher();
            if let Err(err) = pool.inner.ensure_open() {
                accepted.close();
                return Err(err);
            }
            pool.inner.install_inbound(accepted, kind).await?;
            return Ok(InboundSession::Group {
                group_id: pool.group_id().to_owned(),
                peer_device_id: peer,
            });
        }
        self.admit_ordinary(accepted).await
    }

    async fn admit_ordinary(&self, accepted: Accepted) -> Result<InboundSession, RuntimeError> {
        let store = self.store.clone();
        let (roster, stamp) = blocking(move || store.load_roster_with_stamp()).await?;
        if ordinary_entry(&roster, &accepted).is_none() {
            let peer = accepted.peer_id.clone();
            accepted.close();
            return Err(CoreError::PeerNotFound(peer).into());
        }
        match accepted.io {
            AcceptedIo::V1(session) => Ok(InboundSession::OrdinaryV1 {
                session,
                roster,
                stamp,
            }),
            AcceptedIo::V2(mut session) => {
                let store = self.store.clone();
                let peer = accepted.peer_id.clone();
                let persisted = blocking(move || {
                    store.update_roster(|r| {
                        r.set_peer_min_wire_version(&peer, 2)?;
                        Ok(())
                    })
                })
                .await;
                if let Err(err) = persisted {
                    let _ = session.send_close(1000, "roster error").await;
                    return Err(err);
                }
                session.attach_store(self.store.clone());
                Ok(InboundSession::OrdinaryV2 { session })
            }
        }
    }

    /// Closes every pool.
    pub fn close(&self) {
        let pools = std::mem::take(
            &mut *self
                .pools
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for pool in pools.into_values() {
            pool.close();
        }
    }
}

async fn accept_handshake(
    stream: Box<dyn PathStream>,
    identity: &EndpointIdentity,
    roster: Roster,
    version: u8,
    v2_state: &V2ResponderState,
    rate_limiter: Option<&PreAuthRateLimiter>,
    guard: Option<HalfOpenGuard>,
) -> Result<Accepted, RuntimeError> {
    let now = current_unix_secs();
    let roster = Mutex::new(roster);
    if version >= 2 {
        let driver = V2SessionDriver::accept_locked(
            stream,
            identity,
            &roster,
            now,
            v2_state,
            rate_limiter,
            guard,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await?;
        let matched = driver
            .matched_rendezvous_secret()
            .map(|s| Zeroizing::new(*s))
            .ok_or_else(|| RuntimeError::Protocol("missing v2 rendezvous match".to_owned()))?;
        Ok(Accepted {
            peer_id: driver.peer_device_id().to_owned(),
            peer_static: *driver.peer_static_pub(),
            peer_groups: driver.peer_groups().map(<[GroupSeq]>::to_vec),
            exported: driver.exported_v2_secrets().cloned(),
            matched: Some(matched),
            io: AcceptedIo::V2(driver),
        })
    } else {
        let driver = SessionDriver::accept_locked(
            stream,
            identity,
            &roster,
            now,
            rate_limiter,
            guard,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await?;
        let peer_id = driver
            .peer_device_id()
            .ok_or_else(|| RuntimeError::Protocol("missing peer device id".to_owned()))?
            .to_owned();
        let peer_static = *driver
            .peer_static_pub()
            .ok_or_else(|| RuntimeError::Protocol("missing peer static key".to_owned()))?;
        Ok(Accepted {
            peer_id,
            peer_static,
            peer_groups: driver.peer_groups().map(<[GroupSeq]>::to_vec),
            exported: None,
            matched: None,
            io: AcceptedIo::V1(driver),
        })
    }
}

/// Verifies and ingests a `0x0A` manifest pushed by the authenticated peer `sender_device_id`
/// over an ordinary session, outside any pool.
///
/// A known group follows the normal ingest rules. An unknown group is pinned only when the
/// sender is the manifest's `signer_device_id`, is an `Active` ordinarily paired peer whose
/// pinned signing key equals the manifest signing key (`root_signing_pub` for the root, else
/// `signer_signing_pub`), `local_device_id` is an active member, the local group caps
/// ([`check_group_capacity`]) leave room, and fewer than [`MAX_GROUPS_PER_SIGNER`] stored records
/// are attributed to that peer; the count and the pin share one group book write. Roster read
/// failures fail closed.
pub fn ingest_pushed_manifest(
    store: &StateStore,
    local_device_id: &str,
    sender_device_id: &str,
    manifest: &GroupManifest,
) -> Result<GroupIngestOutcome, RuntimeError> {
    let now = current_unix_secs();
    let roster = store.load_roster()?;
    let book = store.load_group_book()?;
    let known = book.manifest(&manifest.group_id).is_some();
    let pinned_by = if known {
        None
    } else {
        Some(core_group::check_first_contact(
            &roster,
            local_device_id,
            sender_device_id,
            manifest,
        )?)
    };
    let root = match (
        book.manifest(&manifest.group_id),
        book.root_signing_pub(&manifest.group_id),
    ) {
        (Some(stored), Some(root_pub)) => {
            root_device_of(&book, stored).map(|id| (id, root_pub.clone()))
        }
        _ => HybridSigningPublicKey::from_b64url(&manifest.root_signing_pub)
            .ok()
            .and_then(|root_pub| Some((root_device_in(manifest, &root_pub)?, root_pub))),
    };
    let crl = match root {
        Some((root_id, root_pub)) => {
            core_group::root_crl(&roster, &root_id, &root_pub, Some(local_device_id))?
        }
        None => None,
    };
    store.update_group_book(|book| {
        if known && book.manifest(&manifest.group_id).is_none() {
            return Err(CoreError::GroupNotFound(manifest.group_id.clone()).into());
        }
        check_group_capacity(book, local_device_id, &manifest.group_id)?;
        let outcome = match &pinned_by {
            Some(handles) => {
                book.ingest_first_contact_manifest(manifest, now, crl.as_ref(), handles)?
            }
            None => book.ingest_group_manifest(manifest, now, crl.as_ref())?,
        };
        drop_secrets_if_left(book, local_device_id, &manifest.group_id);
        Ok(outcome)
    })
}

/// Drops the rendezvous and pairwise secrets of `group_id` once `local_device_id` is neither an
/// active member nor the root, keeping the manifest for seq and fork checks.
pub(crate) fn drop_secrets_if_left(book: &mut GroupBook, local_device_id: &str, group_id: &str) {
    core_group::drop_secrets_if_left(book, local_device_id, group_id);
}

/// Refuses an identity whose `host_id` differs from its `device_id`: group sessions address
/// siblings by `device_id`.
pub(crate) fn require_group_identity(identity: &EndpointIdentity) -> Result<(), RuntimeError> {
    if identity.host_id() == identity.device_id() {
        return Ok(());
    }
    Err(CoreError::GroupUnauthorized(
        "group operations require host_id to equal device_id".to_owned(),
    )
    .into())
}

/// Ingests a `0x0B` frame received from `sender_device_id` into `store`.
///
/// Refuses when `local_device_id` is neither an active member nor the root of the stored group,
/// so a removed device never regains rendezvous secrets. The root CRL is read and released
/// before the group book lock is taken; a roster read failure fails closed. A group that is not
/// stored when the CRL is resolved is refused before the write, so a group pinned meanwhile is
/// never written without its CRL.
pub fn ingest_pushed_rendezvous(
    store: &StateStore,
    local_device_id: &str,
    sender_device_id: &str,
    frame: &GroupRendezvousFrame,
) -> Result<(), RuntimeError> {
    let now = current_unix_secs();
    let book = store.load_group_book()?;
    let Some(manifest) = book.manifest(&frame.group_id) else {
        return Err(CoreError::GroupNotFound(frame.group_id.clone()).into());
    };
    let (root_id, root_pub) = root_device_of(&book, manifest)
        .zip(book.root_signing_pub(&frame.group_id).cloned())
        .ok_or_else(|| CoreError::GroupUnauthorized("founding root missing".to_owned()))?;
    let crl = core_group::root_crl(
        &store.load_roster()?,
        &root_id,
        &root_pub,
        Some(local_device_id),
    )?;
    store.update_group_book(|book| {
        core_group::check_rendezvous_local_membership(book, local_device_id, &frame.group_id)?;
        book.ingest_group_rendezvous_frame(sender_device_id, frame, now, crl.as_ref())
            .map_err(Into::into)
    })
}

/// Which group control frame a [`GroupFrameOutcome`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupFrameKind {
    /// A `0x0A` manifest.
    Manifest,
    /// A `0x0B` rendezvous key.
    Rendezvous,
}

/// Redacted result of [`handle_session_group_frame`]. It never carries key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupFrameOutcome {
    pub kind: GroupFrameKind,
    pub group_id: String,
    /// The stored `seq` after an ingested manifest, otherwise the `seq` the frame carried.
    pub seq: u64,
    pub ingested: bool,
    /// Why the frame was refused, when it was.
    pub error: Option<String>,
}

/// Ingests a group control frame received on an ordinary session from the authenticated peer
/// `sender_device_id`, and returns `None` for any other event.
///
/// A `0x0A` goes through [`ingest_pushed_manifest`] and a `0x0B` through
/// [`ingest_pushed_rendezvous`], so first-contact pinning, admin authority (R8), and the
/// removed-device refusal apply unchanged. Hosts and bindings call this for every
/// [`SessionEvent`] of an ordinary session; the rendezvous key stays inside the runtime.
pub fn handle_session_group_frame(
    store: &StateStore,
    local_device_id: &str,
    sender_device_id: &str,
    event: &SessionEvent,
) -> Option<GroupFrameOutcome> {
    let (kind, group_id, seq, result) = match event {
        SessionEvent::GroupManifestReceived(manifest) => {
            let res = ingest_pushed_manifest(store, local_device_id, sender_device_id, manifest);
            let seq = res.as_ref().map_or(manifest.seq, |o| o.seq);
            (
                GroupFrameKind::Manifest,
                manifest.group_id.clone(),
                seq,
                res.map(|_| ()),
            )
        }
        SessionEvent::GroupRendezvousReceived(frame) => (
            GroupFrameKind::Rendezvous,
            frame.group_id.clone(),
            frame.seq,
            ingest_pushed_rendezvous(store, local_device_id, sender_device_id, frame),
        ),
        _ => return None,
    };
    Some(GroupFrameOutcome {
        kind,
        group_id,
        seq,
        ingested: result.is_ok(),
        error: result.err().map(|e| e.to_string()),
    })
}

fn root_device_of(book: &GroupBook, manifest: &GroupManifest) -> Option<String> {
    book.root_device_id(&manifest.group_id)
}

fn member_static(manifest: &GroupManifest, device_id: &str) -> Option<[u8; 32]> {
    manifest
        .members
        .iter()
        .find(|m| m.device_id == device_id)
        .and_then(|m| b64url_decode_array::<32>(&m.static_pub).ok())
}

fn candidates_from_hints(hints: &[String]) -> Vec<CandidateEndpoint> {
    hints
        .iter()
        .enumerate()
        .filter_map(|(id, hint)| {
            let (provider, addr) = classify_hint(hint)?;
            Some(CandidateEndpoint::new(id, provider, addr))
        })
        .collect()
}

fn classify_hint(hint: &str) -> Option<(ProviderId, String)> {
    if let Some(rest) = hint.strip_prefix("direct:") {
        return Some((ProviderId::Direct, rest.to_owned()));
    }
    if let Some(rest) = hint.strip_prefix("relay:") {
        return Some((ProviderId::Relay, rest.to_owned()));
    }
    if hint.starts_with("wss://") || hint.starts_with("ws://") {
        return Some((ProviderId::Relay, hint.to_owned()));
    }
    if hint.starts_with("broker+") {
        return Some((ProviderId::Broker, hint.to_owned()));
    }
    if hint.starts_with("overlay://") {
        return Some((ProviderId::Overlay, hint.to_owned()));
    }
    let iroh = hint.strip_prefix("p2p:").unwrap_or(hint);
    if iroh.starts_with("iroh://") {
        return Some((ProviderId::P2p, iroh.to_owned()));
    }
    if let Some(rest) = hint
        .strip_prefix("local:")
        .or_else(|| hint.strip_prefix("unix://"))
    {
        return Some((ProviderId::Local, rest.to_owned()));
    }
    None
}

async fn blocking<T, F>(f: F) -> Result<T, RuntimeError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, RuntimeError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| RuntimeError::Storage(format!("blocking task failed: {err}")))?
}

/// Sorted ids of the groups `local_id` is an active member of, capped at [`MAX_LOCAL_GROUPS`].
fn local_member_groups(book: &GroupBook, local_id: &str) -> Vec<String> {
    let mut ids: Vec<String> = book
        .group_ids()
        .into_iter()
        .filter(|id| {
            book.manifest(id)
                .is_some_and(|m| is_active_member(m, local_id))
        })
        .collect();
    ids.sort();
    ids.truncate(MAX_LOCAL_GROUPS);
    ids
}

/// Refuses to store `group_id` when it is new and `local_device_id` already holds
/// [`MAX_LOCAL_GROUPS`] groups or [`MAX_STORED_GROUPS`] records exist; see
/// [`tendril_core::group::check_group_capacity`].
pub fn check_group_capacity(
    book: &GroupBook,
    local_device_id: &str,
    group_id: &str,
) -> Result<(), RuntimeError> {
    core_group::check_group_capacity(book, local_device_id, group_id).map_err(Into::into)
}

/// Pins for every active, CRL-clean sibling of `group_id`; a member whose pin cannot be built is
/// skipped.
fn group_pins(
    book: &GroupBook,
    group_id: &str,
    local_id: &str,
    crl: Option<&RevocationList>,
    now: u64,
) -> Result<Vec<MemberPin>, RuntimeError> {
    let manifest = book
        .manifest(group_id)
        .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()))?;
    if !is_active_member(manifest, local_id) || crl_revokes(crl, local_id) {
        return Err(CoreError::GroupMemberRevoked(local_id.to_owned()).into());
    }
    let mut pins = Vec::new();
    for member in &manifest.members {
        let id = member.device_id.as_str();
        if id == local_id || !is_active_member(manifest, id) || crl_revokes(crl, id) {
            continue;
        }
        match member_pin(book, manifest, local_id, member, now) {
            Ok(pin) => pins.push(pin),
            Err(err) => {
                tracing::debug!(peer = %id, error = %err, "group member skipped");
            }
        }
    }
    Ok(pins)
}

fn member_pin(
    book: &GroupBook,
    manifest: &GroupManifest,
    local_id: &str,
    member: &GroupMember,
    now: u64,
) -> Result<MemberPin, RuntimeError> {
    let floor = manifest.min_wire_version;
    let gid = manifest.group_id.as_str();
    let (bootstrap, pairwise) = if floor >= 2 {
        (
            bootstrap_secrets(book, gid, local_id, &member.device_id, now).ok(),
            book.pairwise_secrets(gid, &member.device_id).cloned(),
        )
    } else {
        (None, None)
    };
    Ok(MemberPin {
        device_id: member.device_id.clone(),
        name: member.name.clone(),
        static_pub: b64url_decode_array::<32>(&member.static_pub)?,
        signing_hash: b64url_decode_array::<32>(&member.signing_pub_hash)?,
        floor,
        pairwise,
        bootstrap,
    })
}

fn bootstrap_secrets(
    book: &GroupBook,
    group_id: &str,
    local_id: &str,
    peer: &str,
    now: u64,
) -> Result<V2PeerSecrets, RuntimeError> {
    let reconnect = book.pair_bootstrap(group_id, local_id, peer, now)?;
    let secrets = book
        .secrets(group_id)
        .ok_or_else(|| CoreError::GroupUnauthorized("no rendezvous key".to_owned()))?;
    let mailbox = derive_group_mailbox_secret(secrets.group_rendezvous_key(), secrets.seq(), peer);
    Ok(V2PeerSecrets::new(*reconnect, *mailbox))
}

impl Inner {
    fn ensure_open(&self) -> Result<(), RuntimeError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::Closed);
        }
        Ok(())
    }

    fn lock_state(&self) -> MutexGuard<'_, PoolState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn track(&self, handle: AbortHandle) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|t| !t.is_finished());
        tasks.push(handle);
    }

    /// Reloads the book and the founding-root CRL when either file changed, emitting membership
    /// events and closing every slot that is no longer an active, CRL-clean member with the
    /// manifest-pinned static key.
    ///
    /// Each stamp is taken before its load, so a write racing the load forces another reload. A
    /// failed load leaves the state untouched and is returned, so callers fail closed and the
    /// next call retries. An unresolvable root CRL ([`core_group::root_crl`]) also closes every
    /// slot before it is returned; the roster stamp stays put, so later calls keep failing closed
    /// until it resolves.
    fn refresh_locked(&self, st: &mut PoolState) -> Result<(), RuntimeError> {
        let stamp = self.store.groups_stamp()?;
        let roster_stamp = self.store.roster_stamp()?;
        let crl = if roster_stamp == st.roster_stamp {
            None
        } else {
            let roster = self.store.load_roster()?;
            match core_group::root_crl(&roster, &self.root_id, &self.root_pub, Some(&self.local_id))
            {
                Ok(crl) => Some(crl),
                Err(err) => {
                    for (_, link) in std::mem::take(&mut st.slots) {
                        link.close_transport();
                    }
                    return Err(err.into());
                }
            }
        };
        let book = if stamp == st.stamp {
            None
        } else {
            Some(self.store.load_group_book()?)
        };
        if crl.is_none() && book.is_none() {
            return Ok(());
        }
        if let Some(crl) = crl {
            st.crl = crl;
            st.roster_stamp = roster_stamp;
        }
        if let Some(book) = book {
            let previous = st.book.manifest(&self.group_id).cloned();
            st.book = book;
            st.stamp = stamp;
            if let Some(current) = st.book.manifest(&self.group_id) {
                self.emit_diff(previous.as_ref(), current);
            }
        }
        self.sweep_locked(st);
        Ok(())
    }

    fn emit_diff(&self, previous: Option<&GroupManifest>, current: &GroupManifest) {
        let Some(previous) = previous else {
            return;
        };
        if previous.seq == current.seq {
            return;
        }
        self.emit_control(GroupEvent::ManifestUpdated { seq: current.seq });
        for member in &current.members {
            if !previous
                .members
                .iter()
                .any(|m| m.device_id == member.device_id)
            {
                self.emit_control(GroupEvent::MemberJoined {
                    device_id: member.device_id.clone(),
                });
            }
        }
        for id in &current.revoked_members {
            if !previous.revoked_members.contains(id) {
                self.emit_control(GroupEvent::MemberRevoked {
                    device_id: id.clone(),
                });
            }
        }
    }

    fn sweep_locked(&self, st: &mut PoolState) {
        let doomed: Vec<String> = st
            .slots
            .iter()
            .filter(|(id, link)| self.admit_locked(st, id, &link.peer_static).is_err())
            .map(|(id, _)| id.clone())
            .collect();
        for id in doomed {
            if let Some(link) = st.slots.remove(&id) {
                link.close_transport();
            }
        }
    }

    /// Checks `peer` against the current view: both ends active members, neither revoked by the
    /// root CRL, and `peer_static` equal to the manifest pin.
    fn admit_locked(
        &self,
        st: &PoolState,
        peer: &str,
        peer_static: &[u8; 32],
    ) -> Result<(), RuntimeError> {
        recipient_ok(
            &st.book,
            &self.group_id,
            st.crl.as_ref(),
            &self.local_id,
            peer,
        )?;
        let manifest = st
            .book
            .manifest(&self.group_id)
            .ok_or_else(|| CoreError::GroupNotFound(self.group_id.clone()))?;
        if member_static(manifest, peer) != Some(*peer_static) {
            return Err(CoreError::HostKeyUnverified.into());
        }
        Ok(())
    }

    /// [`Self::admit_locked`] plus the wire floor and, on Wire v2, a recognized group secret.
    /// A session admitted under the bootstrap secret also needs `matched` to still be the
    /// current-`seq` `pair_bootstrap` for `peer`.
    fn admit_session_locked(
        &self,
        st: &PoolState,
        peer: &str,
        peer_static: &[u8; 32],
        wire: u8,
        kind: Option<SecretKind>,
        matched: Option<&[u8; 32]>,
    ) -> Result<(), RuntimeError> {
        self.admit_locked(st, peer, peer_static)?;
        let floor = st
            .book
            .manifest(&self.group_id)
            .map_or(1, |m| m.min_wire_version);
        match wire {
            1 if floor >= 2 => {
                return Err(CoreError::VersionDowngrade {
                    peer_min: floor,
                    negotiated: 1,
                }
                .into());
            }
            2 if kind.is_none() => return Err(CoreError::HostKeyUnverified.into()),
            _ => {}
        }
        if kind == Some(SecretKind::Bootstrap) {
            let current = bootstrap_secrets(
                &st.book,
                &self.group_id,
                &self.local_id,
                peer,
                current_unix_secs(),
            )
            .ok();
            let fresh = current
                .zip(matched)
                .is_some_and(|(c, m)| bool::from(c.reconnect_secret().ct_eq(m)));
            if !fresh {
                return Err(
                    CoreError::GroupUnauthorized("stale bootstrap secret".to_owned()).into(),
                );
            }
        }
        Ok(())
    }

    /// Returns the current book and founding-root CRL as one coherent view.
    fn view(&self) -> Result<(GroupBook, Option<RevocationList>), RuntimeError> {
        let mut st = self.lock_state();
        self.refresh_locked(&mut st)?;
        Ok((st.book.clone(), st.crl.clone()))
    }

    /// Returns the current founding-root CRL.
    fn root_crl(&self) -> Result<Option<RevocationList>, RuntimeError> {
        let mut st = self.lock_state();
        self.refresh_locked(&mut st)?;
        Ok(st.crl.clone())
    }

    /// Write-boundary authority: evaluated under the driver writer lock, after a refresh, so a
    /// manifest or CRL change that landed while the write was queued invalidates it.
    fn write_authority(&self, link: &Link, check: &AuthorityCheck) -> Result<(), RuntimeError> {
        let mut st = self.lock_state();
        self.refresh_locked(&mut st)?;
        let current =
            !link.is_closed() && st.slots.get(&link.peer_id).is_some_and(|l| l.id == link.id);
        if !current {
            return Err(RuntimeError::Closed);
        }
        check(&st.book, st.crl.as_ref(), &link.peer_id)
    }

    fn emit_control(&self, event: GroupEvent) {
        if self.events_tx.try_send(event).is_err() {
            tracing::warn!("group event queue full; dropping control event");
        }
    }

    /// Enqueues application data without blocking, keeping room for control events. A full
    /// queue drops the data and records an `Audit` event instead.
    fn emit_data(&self, sender: &str, payload: Vec<u8>) {
        if self.events_tx.capacity() > CONTROL_EVENT_RESERVE {
            let _ = self.events_tx.try_send(GroupEvent::AppData {
                sender_device_id: sender.to_owned(),
                payload,
            });
            return;
        }
        let ev = self.audit(
            sender,
            &format!("group.send:{}", self.group_id),
            "event queue full; app data dropped".to_owned(),
        );
        self.emit_control(ev);
    }

    fn peer_lock(&self, peer: &str) -> Arc<AsyncMutex<()>> {
        let mut locks = self
            .peer_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            locks
                .entry(peer.to_owned())
                .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
        )
    }

    fn healthy_link(&self, peer: &str) -> Option<Arc<Link>> {
        self.lock_state()
            .slots
            .get(peer)
            .filter(|l| !l.is_closed())
            .cloned()
    }

    fn remove_slot(&self, link: &Arc<Link>) {
        link.closed.store(true, Ordering::Release);
        link.cancel.notify_waiters();
        let mut st = self.lock_state();
        if st.slots.get(&link.peer_id).is_some_and(|l| l.id == link.id) {
            st.slots.remove(&link.peer_id);
        }
    }

    async fn nudge(&self, peer: &str) {
        let (Some(provider), Some((target, secret))) =
            (&self.wake, self.cfg.wake_targets.get(peer))
        else {
            return;
        };
        let now = current_unix_secs();
        let tag = secret.derive_tag(now);
        let _ = timeout(
            DEFAULT_WAKE_TIMEOUT,
            provider.notify_best_effort(target, &tag, now),
        )
        .await;
    }

    async fn apply_manifest(
        &self,
        manifest: &GroupManifest,
        pushed: bool,
    ) -> Result<GroupIngestOutcome, RuntimeError> {
        if manifest.group_id != self.group_id {
            return Err(CoreError::GroupNotFound(manifest.group_id.clone()).into());
        }
        let now = current_unix_secs();
        let crl = self.root_crl()?;
        let store = self.store.clone();
        let m = manifest.clone();
        let local_id = self.local_id.clone();
        let outcome = blocking(move || {
            store.update_group_book(|book| {
                check_group_capacity(book, &local_id, &m.group_id)?;
                let outcome = if pushed {
                    book.ingest_group_manifest(&m, now, crl.as_ref())
                } else {
                    book.ingest_gossiped_manifest(&m, now, crl.as_ref())
                }?;
                drop_secrets_if_left(book, &local_id, &m.group_id);
                Ok(outcome)
            })
        })
        .await?;
        let mut st = self.lock_state();
        self.refresh_locked(&mut st)?;
        Ok(outcome)
    }

    fn audit(&self, subject: &str, cap: &str, reason: String) -> GroupEvent {
        GroupEvent::Audit(AuditEvent {
            ts: current_unix_secs(),
            subject: subject.to_owned(),
            cap: cap.to_owned(),
            grant_nonce: None,
            allow: false,
            reason,
        })
    }

    /// Writes through `op` to `member`'s link (dialed if missing), isolating failures.
    ///
    /// `check` is evaluated once before the write and again by every frame `op` sends, under the
    /// driver writer lock right before sealing. A refused check fails only this delivery and
    /// leaves the link up; a transport failure or timeout drops the link.
    async fn deliver<F, Fut>(
        self: &Arc<Self>,
        member: &GroupMember,
        check: Arc<AuthorityCheck>,
        op: F,
    ) -> Delivery
    where
        F: FnOnce(Arc<Link>, WriteAuthority) -> Fut,
        Fut: std::future::Future<Output = Result<(), RuntimeError>>,
    {
        let link = match self.link_for(member).await {
            Ok(link) => link,
            Err(DialError::Offline(reason)) => {
                tracing::debug!(peer = %member.device_id, %reason, "group member offline");
                return Delivery::Offline;
            }
            Err(DialError::Failed(err)) => return Delivery::Failed(err),
        };
        let auth = WriteAuthority::new(self, &link, check);
        match auth.verify() {
            Ok(()) => {}
            Err(RuntimeError::Closed) => return Delivery::Failed("session closed".to_owned()),
            Err(err) => return Delivery::Failed(err.to_string()),
        }
        #[cfg(test)]
        fire(&self.hooks.before_write);
        let write = timeout(self.cfg.write_timeout, op(Arc::clone(&link), auth.clone()));
        let res = tokio::select! {
            biased;
            () = link.cancelled() => return Delivery::Failed("session closed".to_owned()),
            res = write => res,
        };
        match res {
            Ok(Ok(())) => Delivery::Delivered,
            Ok(Err(RuntimeError::Closed)) if auth.was_denied() => {
                Delivery::Failed("session closed".to_owned())
            }
            Ok(Err(err)) if auth.was_denied() => Delivery::Failed(err.to_string()),
            Ok(Err(err)) => {
                self.remove_slot(&link);
                link.close_transport();
                Delivery::Failed(err.to_string())
            }
            Err(_) => {
                self.remove_slot(&link);
                link.close_transport();
                Delivery::Failed("write timed out".to_owned())
            }
        }
    }

    /// Write-boundary authority for a frame on an ordinary admin control session: the pool is
    /// open and `check` passes for `peer` against a refreshed view. Evaluated under the session
    /// writer lock right before sealing, as [`Self::write_authority`] is for pool links.
    fn control_authority(&self, peer: &str, check: &AuthorityCheck) -> Result<(), RuntimeError> {
        self.ensure_open()?;
        let mut st = self.lock_state();
        self.refresh_locked(&mut st)?;
        check(&st.book, st.crl.as_ref(), peer)
    }

    /// Delivers `manifest`, and `secrets` when given, to `member` over a fresh ordinary paired
    /// session that carries only these control frames and then closes.
    ///
    /// `recipient` (and `admin` for the key) is checked before dialing and again by each frame
    /// under the writer lock right before sealing. Dial failures report the member offline.
    async fn deliver_control(
        self: &Arc<Self>,
        member: &GroupMember,
        target: OrdinaryTarget,
        manifest: &GroupManifest,
        secrets: Option<&V2GroupSecrets>,
        recipient: Arc<AuthorityCheck>,
        admin: Arc<AuthorityCheck>,
    ) -> Delivery {
        let peer = member.device_id.as_str();
        if let Err(err) = self.control_authority(peer, &*recipient) {
            return Delivery::Failed(err.to_string());
        }
        let candidates = candidates_from_hints(&member.endpoints);
        if candidates.is_empty() {
            return Delivery::Offline;
        }
        let (io, roster) = {
            let Ok(_permit) = self.dial_sem.acquire().await else {
                return Delivery::Failed("pool closed".to_owned());
            };
            match self.dial_ordinary(target, candidates).await {
                Ok(dialed) => dialed,
                Err(err) => {
                    tracing::debug!(%peer, error = %err, "group member unreachable for an admin push");
                    return Delivery::Offline;
                }
            }
        };
        #[cfg(test)]
        fire(&self.hooks.before_write);
        let write = timeout(self.cfg.write_timeout, async {
            io.send_manifest_authorized(manifest, || self.control_authority(peer, &*recipient))
                .await?;
            if let Some(secrets) = secrets {
                io.send_rendezvous_authorized(secrets, &self.group_id, || {
                    self.control_authority(peer, &*admin)
                })
                .await?;
            }
            Ok::<(), RuntimeError>(())
        })
        .await;
        match write {
            Ok(Ok(())) => {
                let cookie = self.next_link_id.fetch_add(1, Ordering::Relaxed);
                let acked = timeout(self.control_ack_timeout(), io.acknowledged(cookie, &roster))
                    .await
                    .unwrap_or(false);
                io.finish("group sync complete").await;
                if acked {
                    Delivery::Delivered
                } else {
                    Delivery::Failed("admin push not acknowledged".to_owned())
                }
            }
            Ok(Err(err)) => {
                tokio::spawn(async move { io.finish("group sync refused").await });
                Delivery::Failed(err.to_string())
            }
            Err(_) => {
                tokio::spawn(async move { io.finish("group sync timed out").await });
                Delivery::Failed("write timed out".to_owned())
            }
        }
    }

    /// Bound on waiting for a member to answer the ping that follows an admin push.
    ///
    /// A member that is a binding host answers only when it polls the session, and polling
    /// runs the store writes of each group frame first, so the wait must outlast a loaded host.
    /// It is at least [`ADMIN_SESSION_IDLE_TIMEOUT`] and never below the configured dial or
    /// write budget; it is always finite.
    fn control_ack_timeout(&self) -> Duration {
        ADMIN_SESSION_IDLE_TIMEOUT
            .max(self.cfg.dial_budget)
            .max(self.cfg.write_timeout)
    }

    /// Opens an ordinary session to `target` over the member's manifest endpoints within the
    /// dial budget, authenticated against the narrowed persisted roster entry.
    async fn dial_ordinary(
        &self,
        target: OrdinaryTarget,
        candidates: Vec<CandidateEndpoint>,
    ) -> Result<(LinkIo, Arc<Mutex<Roster>>), RuntimeError> {
        let OrdinaryTarget {
            host_id,
            roster,
            wire,
        } = target;
        let roster = Arc::new(Mutex::new(roster));
        let session_roster = Arc::clone(&roster);
        let identity = Arc::clone(&self.identity);
        let (_, io) = timeout(
            self.cfg.dial_budget,
            dial_with_policy_verified(
                &self.cfg.dialers,
                self.cfg.policy,
                candidates,
                move |_cand, stream| {
                    let identity = Arc::clone(&identity);
                    let host_id = host_id.clone();
                    let roster = Arc::clone(&roster);
                    async move {
                        let now = current_unix_secs();
                        if wire >= 2 {
                            V2SessionDriver::connect_locked(
                                stream, &identity, &host_id, None, &roster, now,
                            )
                            .await
                            .map(AcceptedIo::V2)
                        } else {
                            SessionDriver::connect_locked(
                                stream, &identity, &host_id, None, &roster, now,
                            )
                            .await
                            .map(AcceptedIo::V1)
                        }
                    }
                },
            ),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("admin push dial budget exceeded"))??;
        let io = match io {
            AcceptedIo::V1(d) => LinkIo::V1(d.into_concurrent()),
            AcceptedIo::V2(d) => LinkIo::V2(d.into_concurrent()),
        };
        Ok((io, session_roster))
    }

    async fn link_for(self: &Arc<Self>, member: &GroupMember) -> Result<Arc<Link>, DialError> {
        if let Some(link) = self.healthy_link(&member.device_id) {
            return Ok(link);
        }
        let lock = self.peer_lock(&member.device_id);
        let _guard = lock.lock().await;
        if let Some(link) = self.healthy_link(&member.device_id) {
            return Ok(link);
        }
        let _permit = self
            .dial_sem
            .acquire()
            .await
            .map_err(|_| DialError::Failed("pool closed".to_owned()))?;
        self.dial(&member.device_id).await
    }

    /// Dials `peer`. On Wire v2 the stored pairwise secret is tried first and, when that
    /// handshake fails, the current-`seq` bootstrap once; both share one dial budget.
    async fn dial(self: &Arc<Self>, peer: &str) -> Result<Arc<Link>, DialError> {
        let failed = |e: RuntimeError| DialError::Failed(e.to_string());
        let now = current_unix_secs();
        let (book, crl) = self.view().map_err(failed)?;
        recipient_ok(&book, &self.group_id, crl.as_ref(), &self.local_id, peer).map_err(failed)?;
        let manifest = book
            .manifest(&self.group_id)
            .ok_or_else(|| DialError::Failed("group not found".to_owned()))?;
        let member = manifest
            .members
            .iter()
            .find(|m| m.device_id == peer)
            .cloned()
            .ok_or_else(|| DialError::Failed("not a member".to_owned()))?;
        let pin = member_pin(&book, manifest, &self.local_id, &member, now).map_err(failed)?;
        let candidates = candidates_from_hints(&member.endpoints);
        if candidates.is_empty() {
            return Err(DialError::Offline("no usable endpoint".to_owned()));
        }
        let groups = vec![GroupSeq {
            group_id: self.group_id.clone(),
            seq: manifest.seq,
        }];
        let attempts: Vec<Option<(SecretKind, V2PeerSecrets)>> = if pin.floor >= 2 {
            let attempts: Vec<_> = [
                pin.pairwise.clone().map(|s| (SecretKind::Pairwise, s)),
                pin.bootstrap.clone().map(|s| (SecretKind::Bootstrap, s)),
            ]
            .into_iter()
            .flatten()
            .map(Some)
            .collect();
            if attempts.is_empty() {
                return Err(DialError::Failed("no v2 secret".to_owned()));
            }
            attempts
        } else {
            vec![None]
        };
        let deadline = Instant::now() + self.cfg.dial_budget;
        let mut last = "dial budget exceeded".to_owned();
        for attempt in attempts {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let attempt_pin = MemberPin {
                device_id: pin.device_id.clone(),
                name: pin.name.clone(),
                static_pub: pin.static_pub,
                signing_hash: pin.signing_hash,
                floor: pin.floor,
                pairwise: attempt.as_ref().map(|(_, s)| s.clone()),
                bootstrap: None,
            };
            let kind = attempt.as_ref().map(|(k, _)| *k);
            match self
                .dial_once(&attempt_pin, candidates.clone(), groups.clone(), left)
                .await
            {
                Ok(accepted) => {
                    return self
                        .install(accepted, self.local_id.clone(), kind)
                        .map_err(failed);
                }
                Err(err) => last = err.to_string(),
            }
        }
        Err(DialError::Offline(last))
    }

    async fn dial_once(
        self: &Arc<Self>,
        pin: &MemberPin,
        candidates: Vec<CandidateEndpoint>,
        groups: Vec<GroupSeq>,
        budget: Duration,
    ) -> Result<Accepted, RuntimeError> {
        let mut roster = Roster::new();
        add_pin(&mut roster, pin)?;
        let secret = pin.pairwise.as_ref().map(|s| *s.reconnect_secret());
        let roster = Arc::new(Mutex::new(roster));
        let identity = Arc::clone(&self.identity);
        let target = pin.device_id.clone();
        let padding = self.cfg.padding.clone();
        let dialed = timeout(
            budget,
            dial_with_policy_verified(
                &self.cfg.dialers,
                self.cfg.policy,
                candidates,
                move |_cand, stream| {
                    let identity = Arc::clone(&identity);
                    let target = target.clone();
                    let roster = Arc::clone(&roster);
                    let groups = groups.clone();
                    let padding = padding.clone();
                    async move {
                        let now = current_unix_secs();
                        if let Some(secret) = secret {
                            let driver = V2SessionDriver::connect_group_member(
                                stream, &identity, &target, secret, padding, &roster, groups, now,
                            )
                            .await?;
                            Ok(Accepted {
                                peer_id: target,
                                peer_static: *driver.peer_static_pub(),
                                peer_groups: None,
                                exported: driver.exported_v2_secrets().cloned(),
                                matched: Some(Zeroizing::new(secret)),
                                io: AcceptedIo::V2(driver),
                            })
                        } else {
                            let driver = SessionDriver::connect_group_member(
                                stream, &identity, &target, &roster, groups, now,
                            )
                            .await?;
                            let peer_static = *driver.peer_static_pub().ok_or_else(|| {
                                RuntimeError::Protocol("missing peer static key".to_owned())
                            })?;
                            Ok(Accepted {
                                peer_id: target,
                                peer_static,
                                peer_groups: None,
                                exported: None,
                                matched: None,
                                io: AcceptedIo::V1(driver),
                            })
                        }
                    }
                },
            ),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("group dial budget exceeded"))??;
        Ok(dialed.1)
    }

    /// Installs an inbound sibling session. One admitted under the bootstrap secret on Wire v2
    /// is held unpublished, unpersisted, and silent until the initiator's first transport frame
    /// authenticates and is not `0x07 CLOSE` (the commit); the staged frame is then handled by
    /// the link's normal read path. CLOSE, EOF, an error, pool close, or
    /// [`BOOTSTRAP_COMMIT_TIMEOUT`] drop it without persisting. At most
    /// [`MAX_PENDING_BOOTSTRAP_COMMITS_PER_PEER`] sessions of one peer and
    /// [`MAX_PENDING_BOOTSTRAP_COMMITS`] in all wait at once; a session over either cap is
    /// refused.
    async fn install_inbound(
        self: &Arc<Self>,
        mut accepted: Accepted,
        kind: Option<SecretKind>,
    ) -> Result<Arc<Link>, RuntimeError> {
        let peer = accepted.peer_id.clone();
        if kind != Some(SecretKind::Bootstrap) || accepted.wire() != 2 {
            return self.install(accepted, peer, kind);
        }
        let Some(peer_slot) = PeerPendingSlot::take(&self.pending_by_peer, &peer) else {
            accepted.close();
            return Err(RuntimeError::RateLimited(
                "pending bootstrap commit cap per peer",
            ));
        };
        let Ok(permit) = Arc::clone(&self.pending_commits).try_acquire_owned() else {
            accepted.close();
            return Err(RuntimeError::RateLimited("pending bootstrap commit cap"));
        };
        let closed = self.close_notify.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        if self.closed.load(Ordering::Acquire) {
            accepted.close();
            return Err(RuntimeError::Closed);
        }
        #[cfg(test)]
        fire_gate(&self.hooks.staged_inbound).await;
        let AcceptedIo::V2(driver) = &mut accepted.io else {
            unreachable!("wire checked above");
        };
        let staged = tokio::select! {
            biased;
            () = &mut closed => Err(RuntimeError::Closed),
            res = timeout(self.commit_timeout(), driver.stage_commit_frame()) => match res {
                Ok(Ok(StagedCommit::Commit)) => Ok(()),
                Ok(Ok(StagedCommit::Close)) => Err(RuntimeError::Closed),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(RuntimeError::Timeout("bootstrap commit frame timed out")),
            },
        };
        if let Err(err) = staged {
            accepted.close();
            return Err(err);
        }
        #[cfg(test)]
        fire_gate(&self.hooks.committed_inbound).await;
        let installed = self.install(accepted, peer, kind);
        drop(permit);
        drop(peer_slot);
        #[cfg(test)]
        fire_gate(&self.hooks.inbound_done).await;
        installed
    }

    fn commit_timeout(&self) -> Duration {
        #[cfg(test)]
        if let Some(wait) = *self
            .hooks
            .commit_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return wait;
        }
        BOOTSTRAP_COMMIT_TIMEOUT
    }

    /// Publishes an authenticated session in its slot inside the one critical section that also
    /// runs the revocation sweep.
    ///
    /// Membership, the manifest static pin, the wire floor, and the root CRL are checked against
    /// the current view. Of two live links to one peer, both ends keep the one whose initiator
    /// has the smaller `device_id`. A Wire v2 link admitted under the bootstrap secret persists
    /// its exported pairwise secrets, and only when it survives; the view is then refreshed and
    /// the link checked again before it is published, so a revocation, rotation, or CRL entry
    /// that landed around the persistence step is never missed. Any failure drops the link (and
    /// the secrets it persisted) and is returned.
    ///
    /// The open check runs under the state lock that is held through persistence and slot
    /// publication; close sets `closed` before it takes that lock to drain the slots, so a
    /// session either lands before the drain or persists and publishes nothing.
    fn install(
        self: &Arc<Self>,
        accepted: Accepted,
        initiator_id: String,
        kind: Option<SecretKind>,
    ) -> Result<Arc<Link>, RuntimeError> {
        let now = current_unix_secs();
        let mut st = self.lock_state();
        let verdict = self
            .refresh_locked(&mut st)
            .and_then(|()| {
                self.admit_session_locked(
                    &st,
                    &accepted.peer_id,
                    &accepted.peer_static,
                    accepted.wire(),
                    kind,
                    accepted.matched.as_deref(),
                )
            })
            .and_then(|()| self.ensure_open());
        if let Err(err) = verdict {
            drop(st);
            accepted.close();
            return Err(err);
        }
        let wire = accepted.wire();
        let link_roster = st
            .book
            .manifest(&self.group_id)
            .and_then(|m| {
                let member = m.members.iter().find(|x| x.device_id == accepted.peer_id)?;
                member_pin(&st.book, m, &self.local_id, member, now).ok()
            })
            .map(|pin| {
                let mut roster = Roster::new();
                let _ = add_pin(&mut roster, &pin);
                roster
            })
            .unwrap_or_default();
        let Accepted {
            io,
            peer_id,
            peer_static,
            peer_groups,
            exported,
            matched,
            ..
        } = accepted;
        let link = Arc::new(Link {
            id: self.next_link_id.fetch_add(1, Ordering::Relaxed),
            peer_id,
            peer_static,
            initiator_id,
            io: match io {
                AcceptedIo::V1(d) => LinkIo::V1(d.into_concurrent()),
                AcceptedIo::V2(d) => LinkIo::V2(d.into_concurrent()),
            },
            roster: Arc::new(Mutex::new(link_roster)),
            peer_groups,
            closed: AtomicBool::new(false),
            cancel: Notify::new(),
        });
        if let Some(old) = st.slots.get(&link.peer_id).filter(|l| !l.is_closed()) {
            if old.initiator_id < link.initiator_id {
                let old = Arc::clone(old);
                drop(st);
                link.close_transport();
                return Ok(old);
            }
            old.close_transport();
        }
        if kind == Some(SecretKind::Bootstrap)
            && let Some(secrets) = exported
        {
            let persisted = self.store.update_group_book(|book| {
                book.set_pairwise_secrets(&self.group_id, &link.peer_id, secrets.clone())
                    .map_err(Into::into)
            });
            #[cfg(test)]
            fire(&self.hooks.after_pairwise_persist);
            let verdict = persisted.and_then(|()| {
                self.refresh_locked(&mut st)?;
                self.admit_session_locked(
                    &st,
                    &link.peer_id,
                    &link.peer_static,
                    wire,
                    kind,
                    matched.as_deref(),
                )
            });
            if let Err(err) = verdict {
                st.slots.remove(&link.peer_id);
                let cleanup = self.store.update_group_book(|book| {
                    if book.pairwise_secrets(&self.group_id, &link.peer_id) == Some(&secrets) {
                        book.remove_pairwise_secrets(&self.group_id, &link.peer_id);
                    }
                    Ok(())
                });
                if let Err(cleanup) = cleanup {
                    tracing::warn!(error = %cleanup, "refused sibling pairwise secrets not removed");
                }
                drop(st);
                link.close_transport();
                return Err(err);
            }
        }
        st.slots.insert(link.peer_id.clone(), Arc::clone(&link));
        drop(st);
        let weak = Arc::downgrade(self);
        let reader = Arc::clone(&link);
        let handle = tokio::spawn(async move {
            run_link(weak, reader).await;
        });
        self.track(handle.abort_handle());
        let inner = Arc::clone(self);
        let pushed = Arc::clone(&link);
        let initiator = link.initiator_id == self.local_id;
        let push = tokio::spawn(async move {
            inner.initial_push(&pushed, initiator).await;
        });
        self.track(push.abort_handle());
        Ok(link)
    }

    /// Pushes the stored manifest (initiator, or responder with a newer `seq`) and, for an
    /// admin, the current rendezvous key. Each frame re-checks the recipient (and admin
    /// authority for the key) under the writer lock right before sealing.
    async fn initial_push(self: &Arc<Self>, link: &Arc<Link>, initiator: bool) {
        let Ok((book, crl)) = self.view() else {
            self.remove_slot(link);
            link.close_transport();
            return;
        };
        let Some(manifest) = book.manifest(&self.group_id).cloned() else {
            return;
        };
        let peer_seq = link
            .peer_groups
            .as_ref()
            .and_then(|g| g.iter().find(|s| s.group_id == self.group_id))
            .map_or(0, |s| s.seq);
        let send_manifest = initiator || manifest.seq > peer_seq;
        let now = current_unix_secs();
        let secrets = book
            .is_group_admin(&self.group_id, &self.local_id, now, crl.as_ref())
            .then(|| book.secrets(&self.group_id).cloned())
            .flatten()
            .filter(|s| s.seq() == manifest.seq);
        let recipient =
            WriteAuthority::new(self, link, recipient_check(&self.group_id, &self.local_id));
        let admin = recipient.with_check(admin_check(&self.group_id, &self.local_id));
        let push = timeout(self.cfg.write_timeout, async {
            if send_manifest {
                link.send_manifest(&manifest, &recipient).await?;
            }
            if let Some(secrets) = &secrets {
                link.send_rendezvous(secrets, &self.group_id, &admin)
                    .await?;
            }
            Ok::<(), RuntimeError>(())
        });
        let res = tokio::select! {
            biased;
            () = link.cancelled() => return,
            res = push => res,
        };
        match res {
            Ok(Ok(())) => {}
            Ok(Err(_)) if recipient.was_denied() => {}
            _ => {
                self.remove_slot(link);
                link.close_transport();
            }
        }
    }

    async fn accept_stream(
        self: Arc<Self>,
        mut stream: Box<dyn PathStream>,
        guard: HalfOpenGuard,
    ) -> Result<String, RuntimeError> {
        let peeked = timeout(
            DEFAULT_PRE_AUTH_TIMEOUT,
            peek_exact(stream.as_mut(), PREAMBLE_LEN),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("group preamble read timed out"))??;
        let preamble = Preamble::decode(&peeked[..PREAMBLE_LEN])?;
        if preamble.intent != Intent::Session {
            return Err(RuntimeError::Protocol(
                "group pool accepts session intents only".to_owned(),
            ));
        }
        let now = current_unix_secs();
        let (book, crl) = self.view()?;
        let floor = book
            .manifest(&self.group_id)
            .map_or(1, |m| m.min_wire_version);
        let wire = if preamble.version >= 2 { 2 } else { 1 };
        let group_wire = if floor >= 2 { 2 } else { 1 };
        let pins = group_pins(&book, &self.group_id, &self.local_id, crl.as_ref(), now)?;
        let store = self.store.clone();
        let persisted = blocking(move || store.load_roster()).await?;
        let mut roster = admin_roster(&persisted, &book, &self.group_id, crl.as_ref(), wire, now);
        drop((persisted, book));
        if wire < group_wire && !roster.entries().any(|(_, e)| e.state == PeerState::Active) {
            return Err(CoreError::VersionDowngrade {
                peer_min: floor,
                negotiated: preamble.version,
            }
            .into());
        }
        let stream: Box<dyn PathStream> = Box::new(PrefixedPathStream::new(stream, peeked));
        let mut index = PinIndex::default();
        if wire == group_wire {
            for pin in pins {
                match add_pin(&mut roster, &pin) {
                    Ok(()) => index.record(&self.group_id, &pin),
                    Err(err) => {
                        tracing::debug!(peer = %pin.device_id, error = %err, "group member skipped");
                    }
                }
            }
        }
        let accepted = accept_handshake(
            stream,
            &self.identity,
            roster,
            preamble.version,
            &self.v2_state,
            Some(&self.admission),
            Some(guard),
        )
        .await?;
        let grouped = matches!(
            accepted.peer_groups.as_deref(),
            Some([only]) if only.group_id == self.group_id
        );
        let routed = grouped
            .then(|| {
                index.route(
                    &self.group_id,
                    &accepted.peer_id,
                    &accepted.peer_static,
                    accepted.wire(),
                    accepted.matched.as_deref(),
                )
            })
            .flatten();
        if let Some(kind) = routed {
            let peer = accepted.peer_id.clone();
            self.install_inbound(accepted, kind).await?;
            return Ok(peer);
        }
        self.admit_admin_session(accepted).await
    }

    /// Admits a session that is not a sibling route as an ordinary admin control session: the
    /// peer is an ordinarily paired `Active` entry ([`ordinary_entry`]) and, against a refreshed
    /// view, the root or the live co-admin of this group with the manifest's static key, both
    /// ends CRL-clean and the local device an active member. The session is then served by
    /// [`Self::run_admin_session`]. Returns the admin's `device_id`; anything else is closed.
    async fn admit_admin_session(
        self: Arc<Self>,
        accepted: Accepted,
    ) -> Result<String, RuntimeError> {
        let store = self.store.clone();
        let persisted = match blocking(move || store.load_roster()).await {
            Ok(roster) => roster,
            Err(err) => {
                accepted.close();
                return Err(err);
            }
        };
        let verdict = self
            .admin_verdict(&persisted, &accepted)
            .and_then(|device| {
                Arc::clone(&self.admin_sessions)
                    .try_acquire_owned()
                    .map(|permit| (device, permit))
                    .map_err(|_| RuntimeError::RateLimited("too many admin control sessions"))
            });
        let (device, permit) = match verdict {
            Ok(admitted) => admitted,
            Err(err) => {
                accepted.close();
                return Err(err);
            }
        };
        let inner = Arc::clone(&self);
        let sender = device.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            inner
                .run_admin_session(accepted.io, sender, persisted)
                .await;
        });
        self.track(task.abort_handle());
        Ok(device)
    }

    fn admin_verdict(
        &self,
        persisted: &Roster,
        accepted: &Accepted,
    ) -> Result<String, RuntimeError> {
        let device = ordinary_entry(persisted, accepted)
            .map(|e| e.device_id.clone())
            .ok_or(CoreError::HostKeyUnverified)?;
        let mut st = self.lock_state();
        self.refresh_locked(&mut st)?;
        let crl = st.crl.as_ref();
        let manifest = st
            .book
            .manifest(&self.group_id)
            .ok_or_else(|| CoreError::GroupNotFound(self.group_id.clone()))?;
        if !is_active_member(manifest, &self.local_id) || crl_revokes(crl, &self.local_id) {
            return Err(CoreError::GroupMemberRevoked(self.local_id.clone()).into());
        }
        let admin = !crl_revokes(crl, &device)
            && member_static(manifest, &device) == Some(accepted.peer_static)
            && st
                .book
                .is_group_admin(&self.group_id, &device, current_unix_secs(), crl);
        if !admin {
            return Err(CoreError::GroupUnauthorized(format!(
                "{device} is not an admin of {}",
                self.group_id
            ))
            .into());
        }
        Ok(device)
    }

    /// Serves one admin control session: `0x0A` and `0x0B` for this group go through
    /// [`handle_session_group_frame`], application data and frames for other groups are dropped
    /// with an `Audit` event, and the session closes when the peer closes, the pool closes, or
    /// no control frame arrives for [`ADMIN_SESSION_IDLE_TIMEOUT`].
    async fn run_admin_session(
        self: Arc<Self>,
        mut io: AcceptedIo,
        sender: String,
        roster: Roster,
    ) {
        let roster = Mutex::new(roster);
        let mut idle_since = Instant::now();
        loop {
            let left = ADMIN_SESSION_IDLE_TIMEOUT.saturating_sub(idle_since.elapsed());
            if left.is_zero() || self.closed.load(Ordering::Acquire) {
                break;
            }
            let next = async {
                match &mut io {
                    AcceptedIo::V1(s) => s.next_event_locked_now(&roster).await,
                    AcceptedIo::V2(s) => s.next_event_locked_now(&roster).await,
                }
            };
            let Ok(Ok(Some(event))) = timeout(left, next).await else {
                break;
            };
            let control = match &event {
                SessionEvent::GroupManifestReceived(m) => Some(m.group_id == self.group_id),
                SessionEvent::GroupRendezvousReceived(f) => Some(f.group_id == self.group_id),
                _ => None,
            };
            match (control, event) {
                (Some(true), event) => {
                    idle_since = Instant::now();
                    self.apply_control_frame(&sender, event).await;
                }
                (Some(false), _) => {
                    let ev = self.audit(
                        &sender,
                        "group.manifest",
                        "control frame for another group dropped".to_owned(),
                    );
                    self.emit_control(ev);
                }
                (None, SessionEvent::AppData(_)) => {
                    let ev = self.audit(
                        &sender,
                        &format!("group.send:{}", self.group_id),
                        "app data on an admin control session dropped".to_owned(),
                    );
                    self.emit_control(ev);
                }
                (None, SessionEvent::Closed { .. }) => break,
                (None, _) => {}
            }
        }
        let _ = timeout(CLOSE_GRACE, async {
            match &mut io {
                AcceptedIo::V1(s) => s.send_close(1000, "admin session closed").await,
                AcceptedIo::V2(s) => s.send_close(1000, "admin session closed").await,
            }
        })
        .await;
    }

    async fn apply_control_frame(&self, sender: &str, event: SessionEvent) {
        let store = self.store.clone();
        let local = self.local_id.clone();
        let from = sender.to_owned();
        let outcome = blocking(move || {
            store.run(|s| Ok(handle_session_group_frame(s, &local, &from, &event)))
        })
        .await;
        {
            let mut st = self.lock_state();
            if let Err(err) = self.refresh_locked(&mut st) {
                tracing::debug!(error = %err, "group book refresh failed");
            }
        }
        let (cap, reason) = match outcome {
            Ok(Some(o)) if o.ingested => return,
            Ok(Some(o)) => (
                match o.kind {
                    GroupFrameKind::Manifest => "group.manifest",
                    GroupFrameKind::Rendezvous => "group.rendezvous",
                },
                o.error.unwrap_or_default(),
            ),
            Ok(None) => return,
            Err(err) => ("group.manifest", err.to_string()),
        };
        let ev = self.audit(sender, cap, reason);
        self.emit_control(ev);
    }

    async fn handle_event(self: &Arc<Self>, link: &Arc<Link>, event: SessionEvent) -> bool {
        match event {
            SessionEvent::AppData(payload) => {
                let cap_text = format!("group.send:{}", self.group_id);
                let mut st = self.lock_state();
                let verdict = self.refresh_locked(&mut st).and_then(|()| {
                    let cap = Capability::parse(&cap_text)?;
                    st.book.authorize_group(
                        &self.group_id,
                        &link.peer_id,
                        &cap,
                        current_unix_secs(),
                        st.crl.as_ref(),
                    )?;
                    Ok(())
                });
                let current = !link.is_closed()
                    && st.slots.get(&link.peer_id).is_some_and(|l| l.id == link.id);
                match verdict {
                    Ok(()) if current => self.emit_data(&link.peer_id, payload),
                    Ok(()) => {}
                    Err(err) => {
                        let ev = self.audit(&link.peer_id, &cap_text, err.to_string());
                        self.emit_control(ev);
                    }
                }
                drop(st);
                !link.is_closed()
            }
            SessionEvent::GroupManifestReceived(manifest) => {
                match self.apply_manifest(&manifest, false).await {
                    Ok(_)
                    | Err(RuntimeError::Core(
                        CoreError::GroupSeqRollback { .. } | CoreError::GroupNotFound(_),
                    )) => {}
                    Err(err) => {
                        let ev = self.audit(&link.peer_id, "group.manifest", err.to_string());
                        self.emit_control(ev);
                    }
                }
                !link.is_closed()
            }
            SessionEvent::GroupRendezvousReceived(frame) => {
                let res = if frame.group_id == self.group_id {
                    self.apply_rendezvous(&link.peer_id, frame).await
                } else {
                    Err(CoreError::GroupNotFound(frame.group_id.clone()).into())
                };
                if let Err(err) = res {
                    let ev = self.audit(&link.peer_id, "group.rendezvous", err.to_string());
                    self.emit_control(ev);
                }
                !link.is_closed()
            }
            SessionEvent::Closed { .. } => false,
            _ => !link.is_closed(),
        }
    }

    async fn apply_rendezvous(
        &self,
        sender: &str,
        frame: GroupRendezvousFrame,
    ) -> Result<(), RuntimeError> {
        let crl = self.root_crl()?;
        let store = self.store.clone();
        let sender = sender.to_owned();
        let now = current_unix_secs();
        blocking(move || {
            store.update_group_book(|book| {
                book.ingest_group_rendezvous_frame(&sender, &frame, now, crl.as_ref())
                    .map_err(Into::into)
            })
        })
        .await?;
        let mut st = self.lock_state();
        self.refresh_locked(&mut st)?;
        Ok(())
    }
}

async fn run_link(weak: Weak<Inner>, link: Arc<Link>) {
    loop {
        let event = match link.next_event().await {
            Ok(Some(ev)) => ev,
            Ok(None) | Err(_) => break,
        };
        let Some(inner) = weak.upgrade() else {
            break;
        };
        if link.is_closed() || !inner.handle_event(&link, event).await {
            break;
        }
    }
    if let Some(inner) = weak.upgrade() {
        inner.remove_slot(&link);
    } else {
        link.closed.store(true, Ordering::Release);
    }
}

mod admin;
pub use admin::{
    default_group_caps, group_add_member, group_create, group_forget, group_ingest_manifest,
    group_remove_member, normalize_endpoint_hint,
};

#[cfg(test)]
mod tests;
