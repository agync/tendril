//! Peer roster state machine, pin verification, minting, rotation, and CRL tracking.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{
    HybridSigningPublicKey, b64url_decode_array, b64url_encode, device_id, has_control_chars,
    is_valid_x25519_public_key,
};
use crate::error::CoreError;
use crate::grants::{
    Capability, Grant, GrantUnsigned, RevocationList, RevocationListUnsigned, sign_crl, sign_grant,
    verify_crl_signature,
};
use crate::identity::{
    EndpointIdentity, RotationRecord, format_rfc3339_utc, is_valid_host_id, verify_rotation_chain,
};
use crate::identity::{detect_rotation_fork, verify_rotation_record};
use crate::pairing::{
    AnnouncedRouteSet, LocalRouteState, MAX_PAIRING_ENDPOINT_HINT_LEN, PersistPlan, RoutePolicy,
    VerifiedRouteStatement, announce_rank, is_ipc_hint, is_v2_relay_hint,
    is_valid_pairing_endpoint_hint, provider_of_valid_hint,
};
use crate::policy::ProviderId;
use crate::routes::{MAX_ROUTE_SEQ, RouteSet};
use crate::wire::{WIRE_VERSION, WIRE_VERSION_V2};

fn default_min_wire_version() -> u8 {
    WIRE_VERSION
}

fn deserialize_min_wire_version<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let v = u8::deserialize(deserializer)?;
    if v != WIRE_VERSION && v != WIRE_VERSION_V2 {
        return Err(serde::de::Error::custom(format!(
            "unsupported min_wire_version {v}; expected 1 or 2"
        )));
    }
    Ok(v)
}

/// Zeroizing, debug-redacted v2 shared secrets persisted per paired peer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct V2PeerSecrets {
    reconnect_secret: [u8; 32],
    mailbox_secret: [u8; 32],
}

impl V2PeerSecrets {
    /// Constructs a [`V2PeerSecrets`] pair from 32-byte reconnect and mailbox secrets.
    #[must_use]
    pub const fn new(reconnect_secret: [u8; 32], mailbox_secret: [u8; 32]) -> Self {
        Self {
            reconnect_secret,
            mailbox_secret,
        }
    }

    /// Returns the 32-byte pseudonymous reconnect secret.
    #[must_use]
    pub const fn reconnect_secret(&self) -> &[u8; 32] {
        &self.reconnect_secret
    }

    /// Returns the 32-byte blinded relay mailbox secret.
    #[must_use]
    pub const fn mailbox_secret(&self) -> &[u8; 32] {
        &self.mailbox_secret
    }
}

impl PartialEq for V2PeerSecrets {
    fn eq(&self, other: &Self) -> bool {
        bool::from(
            self.reconnect_secret.ct_eq(&other.reconnect_secret)
                & self.mailbox_secret.ct_eq(&other.mailbox_secret),
        )
    }
}

impl Eq for V2PeerSecrets {}

impl fmt::Debug for V2PeerSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2PeerSecrets")
            .field("reconnect_secret", &"<redacted>")
            .field("mailbox_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct V2PeerSecretsSerde {
    reconnect_secret: String,
    mailbox_secret: String,
}

impl Serialize for V2PeerSecrets {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let repr = V2PeerSecretsSerde {
            reconnect_secret: b64url_encode(&self.reconnect_secret),
            mailbox_secret: b64url_encode(&self.mailbox_secret),
        };
        repr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for V2PeerSecrets {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = V2PeerSecretsSerde::deserialize(deserializer)?;
        let reconnect_secret = Zeroizing::new(
            b64url_decode_array::<32>(&repr.reconnect_secret).map_err(serde::de::Error::custom)?,
        );
        let mailbox_secret = Zeroizing::new(
            b64url_decode_array::<32>(&repr.mailbox_secret).map_err(serde::de::Error::custom)?,
        );
        Ok(Self {
            reconnect_secret: *reconnect_secret,
            mailbox_secret: *mailbox_secret,
        })
    }
}

/// Lifecycle state of a peer entry on a Tendril endpoint roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    Pending,
    Active,
    Revoked,
}

/// Persistent trust state for one paired peer or pinned host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    pub device_id: String,
    pub name: String,
    pub kind: String,
    pub static_pub: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_pub: Option<HybridSigningPublicKey>,
    pub rotation_seq: u64,
    pub state: PeerState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pairing_sas: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_hints: Vec<String>,
    #[serde(
        default = "default_min_wire_version",
        deserialize_with = "deserialize_min_wire_version"
    )]
    pub min_wire_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2_secrets: Option<V2PeerSecrets>,
    /// Day-2 routes, unique per `(hint, source)`. Legacy `relay_hints` are never dialed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<StoredRoute>,
    /// Freshness of the `signed` routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_meta: Option<RouteMeta>,
    /// The `signed` hints an explicit approval wrote; only these are protected from
    /// equal-sequence displacement while `route_meta.origin` is `Approved`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    approved_signed: Vec<String>,
}

impl RosterEntry {
    /// Confirms this entry pins a valid full-order X25519 static public key.
    pub fn require_static_pin(&self) -> Result<[u8; 32], CoreError> {
        if !is_valid_x25519_public_key(&self.static_pub) {
            return Err(CoreError::IncompletePin(self.device_id.clone()));
        }
        Ok(self.static_pub)
    }

    /// Confirms both X25519 `static_pub` and hybrid `signing_pub` pins are present and valid.
    pub fn require_complete_pin(&self) -> Result<([u8; 32], HybridSigningPublicKey), CoreError> {
        let static_pub = self.require_static_pin()?;
        let Some(signing_pub) = self.signing_pub.clone() else {
            return Err(CoreError::IncompletePin(self.device_id.clone()));
        };
        Ok((static_pub, signing_pub))
    }
}

impl RosterEntry {
    /// Hints of the stored routes from `source`, in stored order.
    pub fn routes_from(&self, source: RouteSource) -> impl Iterator<Item = &str> {
        self.routes
            .iter()
            .filter(move |r| r.source == source)
            .map(|r| r.hint.as_str())
    }

    /// The `SessionHello.route_seq` a client sends to this host under `policy`.
    ///
    /// `None` unless the policy is `AllSigned` and the entry holds `route_meta`. The stored
    /// sequence for `Session` and `Approved` metadata, `0` for metadata from a URI.
    #[must_use]
    pub fn hello_route_seq(&self, policy: RoutePolicy) -> Option<u64> {
        if policy != RoutePolicy::AllSigned {
            return None;
        }
        self.route_meta.map(|m| match m.origin {
            RouteOrigin::Session | RouteOrigin::Approved => m.seq,
            RouteOrigin::Uri => 0,
        })
    }

    fn hints_from(&self, source: RouteSource) -> Vec<String> {
        self.routes_from(source).map(str::to_owned).collect()
    }

    /// The explicitly approved `signed` hints protected at an equal sequence.
    #[must_use]
    pub fn approved_signed_routes(&self) -> &[String] {
        &self.approved_signed
    }

    /// Replaces the `signed` routes with a set that was not explicitly approved.
    fn replace_signed_unapproved(&mut self, hints: Vec<String>) {
        self.approved_signed.clear();
        self.replace_source(RouteSource::Signed, hints);
    }

    fn replace_source(&mut self, source: RouteSource, hints: Vec<String>) {
        self.routes.retain(|r| r.source != source);
        for hint in hints {
            if !self.has_route(&hint, source) {
                self.routes.push(StoredRoute { hint, source });
            }
        }
    }

    fn has_route(&self, hint: &str, source: RouteSource) -> bool {
        self.routes
            .iter()
            .any(|r| r.source == source && r.hint == hint)
    }
}

/// Who authorized a stored route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    /// Typed by the local operator or developer.
    Operator,
    /// Listed in a verified host route statement or route set, including the route set of an
    /// M2M enrolment reply.
    Signed,
    /// The route that carried an unsigned pairing commit, kept on opt-in, or the explicit
    /// operator endpoint that carried an M2M enrolment.
    Committed,
}

impl RouteSource {
    /// Snake-case spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Signed => "signed",
            Self::Committed => "committed",
        }
    }

    const fn cap(self) -> usize {
        match self {
            Self::Operator => MAX_OPERATOR_ROUTES,
            Self::Signed => MAX_SIGNED_ROUTES,
            Self::Committed => MAX_COMMITTED_ROUTES,
        }
    }
}

/// One persisted Day-2 route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRoute {
    pub hint: String,
    pub source: RouteSource,
}

/// Where the current `signed` routes came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteOrigin {
    /// A signed pairing URI.
    Uri,
    /// A `0x0C ROUTE_SET` announcement.
    Session,
    /// An explicitly approved stale or equal-sequence URI.
    Approved,
}

/// High-water mark of the `signed` routes. `seq` never decreases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMeta {
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    pub origin: RouteOrigin,
}

/// Maximum `operator` routes per peer.
pub const MAX_OPERATOR_ROUTES: usize = 6;
/// Maximum `signed` routes per peer.
pub const MAX_SIGNED_ROUTES: usize = 6;
/// Maximum `committed` routes per peer.
pub const MAX_COMMITTED_ROUTES: usize = 1;
/// Maximum stored routes per peer across all sources.
pub const MAX_STORED_ROUTES: usize = MAX_OPERATOR_ROUTES + MAX_SIGNED_ROUTES + MAX_COMMITTED_ROUTES;

/// A normalized operator endpoint for [`Roster::set_routes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorEndpoint {
    /// Normalized hint, persisted as an `operator` route.
    pub hint: String,
    /// Ed25519 relay mailbox key from a `URL#key` input; checked against the pin, never stored.
    pub relay_key: Option<[u8; 32]>,
}

/// Result of [`Roster::merge_pair_plan`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairMergeOutcome {
    /// Plan routes stored after the merge.
    pub persisted: Vec<StoredRoute>,
    /// `stale_route_seq` when the plan's `rq` was below the high-water mark, else the plan's
    /// own reason.
    pub reason: Option<&'static str>,
}

/// Why [`Roster::apply_route_announcement`] ignored a route set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSetIgnored {
    PeerInactive,
    KeyMismatch,
    BadSignature,
    FutureIssuedAt,
    StaleSeq,
}

impl RouteSetIgnored {
    /// Snake-case reason recorded as `route_set_ignored{reason}`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerInactive => "peer_inactive",
            Self::KeyMismatch => "key_mismatch",
            Self::BadSignature => "bad_signature",
            Self::FutureIssuedAt => "future_issued_at",
            Self::StaleSeq => "stale_seq",
        }
    }
}

/// Result of [`Roster::apply_route_announcement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteSetOutcome {
    /// The set replaced the `signed` routes.
    Applied {
        added: Vec<String>,
        removed: Vec<String>,
    },
    Ignored(RouteSetIgnored),
}

/// Largest accepted `issued_at` lead over the local clock (clock-skew bound, not replay).
pub const MAX_ROUTE_SET_FUTURE_SECS: u64 = 86_400;

/// The pinned keys of one entry when a Day-2 connect started, taken by [`Roster::pin_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinSnapshot {
    peer_id: String,
    static_pub: [u8; 32],
    signing_pub: HybridSigningPublicKey,
    rotation_seq: u64,
    min_wire_version: u8,
    route_meta: Option<RouteMeta>,
}

impl PinSnapshot {
    /// The roster key this snapshot was taken of.
    #[must_use]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    #[must_use]
    pub const fn static_pub(&self) -> &[u8; 32] {
        &self.static_pub
    }

    #[must_use]
    pub const fn signing_pub(&self) -> &HybridSigningPublicKey {
        &self.signing_pub
    }

    #[must_use]
    pub const fn rotation_seq(&self) -> u64 {
        self.rotation_seq
    }

    #[must_use]
    pub const fn min_wire_version(&self) -> u8 {
        self.min_wire_version
    }

    #[must_use]
    pub const fn route_meta(&self) -> Option<RouteMeta> {
        self.route_meta
    }
}

fn invalid_route(msg: &str) -> CoreError {
    CoreError::InvalidPairingUri(msg.to_owned())
}

/// Validation of one route for `entry`.
fn validate_route(hint: &str, source: RouteSource, entry: &RosterEntry) -> Result<(), CoreError> {
    if hint.len() > MAX_PAIRING_ENDPOINT_HINT_LEN
        || hint.contains('#')
        || !is_valid_pairing_endpoint_hint(hint)
    {
        return Err(invalid_route("invalid route hint"));
    }
    if is_ipc_hint(hint) && source != RouteSource::Operator {
        return Err(invalid_route("IPC routes are operator-only"));
    }
    if is_v2_relay_hint(hint) {
        match source {
            RouteSource::Committed => {
                return Err(invalid_route("/v2/relay cannot be a committed route"));
            }
            RouteSource::Operator if entry.v2_secrets.is_none() => {
                return Err(invalid_route(
                    "/v2/relay route needs a Wire v2 pairing with this peer",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validates, deduplicates and caps a full replacement list for one source.
fn checked_source_list(
    hints: impl IntoIterator<Item = String>,
    source: RouteSource,
    entry: &RosterEntry,
) -> Result<Vec<String>, CoreError> {
    let mut out: Vec<String> = Vec::new();
    for hint in hints {
        validate_route(&hint, source, entry)?;
        if !out.contains(&hint) {
            out.push(hint);
        }
    }
    if out.len() > source.cap() {
        return Err(CoreError::InvalidPairingUri(format!(
            "at most {} {} routes",
            source.cap(),
            source.as_str()
        )));
    }
    Ok(out)
}

/// Applies the route caps to an equal-sequence union: `protected` routes are always kept, then the
/// best-ranked of `others` while two per provider and six in total allow.
fn cap_signed_union(protected: Vec<String>, others: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut per_provider: BTreeMap<ProviderId, usize> = BTreeMap::new();
    for hint in protected {
        if out.len() < MAX_SIGNED_ROUTES && !out.contains(&hint) {
            *per_provider
                .entry(provider_of_valid_hint(&hint))
                .or_default() += 1;
            out.push(hint);
        }
    }
    let mut ranked: Vec<(usize, String)> = others.into_iter().enumerate().collect();
    ranked.sort_by_key(|(i, h)| (announce_rank(h), *i));
    for (_, hint) in ranked {
        if out.len() >= MAX_SIGNED_ROUTES {
            break;
        }
        if out.contains(&hint) {
            continue;
        }
        let count = per_provider
            .entry(provider_of_valid_hint(&hint))
            .or_default();
        if *count >= MAX_ANNOUNCED_PER_PROVIDER {
            continue;
        }
        *count += 1;
        out.push(hint);
    }
    out
}

const MAX_ANNOUNCED_PER_PROVIDER: usize = crate::pairing::MAX_ANNOUNCED_HINTS_PER_PROVIDER;

fn signing_keys_share_identity(a: &HybridSigningPublicKey, b: &HybridSigningPublicKey) -> bool {
    a == b || a.ed25519_bytes() == b.ed25519_bytes()
}

/// Hard cap on tracked active burned M2M enrollment nonces in [`Roster`].
pub const MAX_BURNED_ENROLLMENT_NONCES: usize = 16_384;

/// Lifecycle state of an external M2M trust anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnchorState {
    Active,
    Revoked,
}

/// Trusted hybrid root signer authorized to issue M2M enrollment tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchor {
    pub anchor_id: String,
    pub signing_pub: HybridSigningPublicKey,
    pub state: AnchorState,
}

/// Most unconfirmed host claims a roster holds; a new claim evicts the oldest.
pub const MAX_PENDING_HOSTS: usize = 64;

/// Where a host record lives: an entry under its key, or an unconfirmed claim by index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostSlot {
    Entry(String),
    Pending(usize),
}

/// The stored form of a [`Roster`]; loading it normalizes unconfirmed host entries.
#[derive(Deserialize)]
struct StoredRoster {
    entries: BTreeMap<String, RosterEntry>,
    crls: BTreeMap<String, RevocationList>,
    #[serde(default)]
    trust_anchors: BTreeMap<String, TrustAnchor>,
    #[serde(default)]
    burned_enrollment_nonces: BTreeMap<String, u64>,
    #[serde(default, deserialize_with = "crate::pairing::deserialize_local_routes")]
    local_routes: Option<Box<LocalRouteState>>,
    #[serde(default)]
    pending_hosts: Vec<RosterEntry>,
}

impl From<StoredRoster> for Roster {
    /// Moves every `Pending` entry stored under a key other than `device_id(static_pub)` into the
    /// pending host store under that label, then admits each stored claim that is `Pending`, has
    /// a valid `host_id` and static key, and holds no revoked label or key. `Active` and `Revoked`
    /// entries, and `Pending` entries under their own `device_id`, keep their keys and are never
    /// overwritten.
    fn from(stored: StoredRoster) -> Self {
        let mut roster = Self {
            entries: stored.entries,
            crls: stored.crls,
            trust_anchors: stored.trust_anchors,
            burned_enrollment_nonces: stored.burned_enrollment_nonces,
            local_routes: stored.local_routes,
            ..Self::default()
        };
        let legacy: Vec<String> = roster
            .entries
            .iter()
            .filter(|(key, e)| e.state == PeerState::Pending && **key != device_id(&e.static_pub))
            .map(|(key, _)| key.clone())
            .collect();
        let mut claims = Vec::with_capacity(legacy.len() + stored.pending_hosts.len());
        for label in legacy {
            if let Some(mut entry) = roster.entries.remove(&label) {
                entry.device_id = label;
                claims.push(entry);
            }
        }
        claims.extend(stored.pending_hosts);
        for entry in claims {
            if entry.state == PeerState::Pending
                && is_valid_host_id(&entry.device_id)
                && is_valid_x25519_public_key(&entry.static_pub)
                && !roster.revoked_key_conflict(
                    "",
                    &entry.device_id,
                    &entry.static_pub,
                    entry.signing_pub.as_ref(),
                )
            {
                roster.push_pending_host(entry);
            }
        }
        roster
    }
}

/// Authoritative in-memory peer roster, trust anchors, burn log, and verified CRL store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(from = "StoredRoster")]
pub struct Roster {
    entries: BTreeMap<String, RosterEntry>,
    crls: BTreeMap<String, RevocationList>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    trust_anchors: BTreeMap<String, TrustAnchor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    burned_enrollment_nonces: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_routes: Option<Box<LocalRouteState>>,
    /// Unconfirmed host claims from unpinned pairings, oldest first, each labelled by the
    /// `host_id` it names (its `device_id` field) and unique per `(device_id(static_pub),
    /// host_id)`. They hold no label until `pair.confirm` moves one into `entries`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_hosts: Vec<RosterEntry>,
    #[serde(skip)]
    signing_hash_pins: BTreeMap<String, [u8; 32]>,
    #[serde(skip)]
    rendezvous_alternates: BTreeMap<String, Vec<V2PeerSecrets>>,
}

impl Roster {
    /// Creates an empty default-deny roster.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins `peer_id` to the SHA-256 hash of its hybrid signing key for this in-memory roster only.
    ///
    /// Initiator handshakes resolve the full key from `HostHello` through
    /// [`Self::resolve_signing_pin`]. The pin is never serialized.
    pub fn pin_signing_hash(&mut self, peer_id: &str, hash: [u8; 32]) -> Result<(), CoreError> {
        let entry = self
            .entries
            .get(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if let Some(signing) = &entry.signing_pub
            && !bool::from(signing.sha256_hash().ct_eq(&hash))
        {
            return Err(CoreError::HostKeyUnverified);
        }
        self.signing_hash_pins.insert(peer_id.to_string(), hash);
        Ok(())
    }

    /// Reports whether `peer_id` carries an in-memory signing hash pin (a manifest-pinned sibling).
    ///
    /// Handshakes to such a peer accept exactly the pinned Noise static and signing key: a
    /// `HostHello` rotation chain never advances the pin.
    #[must_use]
    pub fn is_manifest_pinned(&self, peer_id: &str) -> bool {
        self.signing_hash_pins.contains_key(peer_id)
    }

    /// Registers an extra in-memory Wire v2 rendezvous secret under which a responder accepts
    /// `msg1` from `peer_id`, in addition to the entry's own `v2_secrets`. Never serialized.
    pub fn add_rendezvous_alternate(
        &mut self,
        peer_id: &str,
        secrets: V2PeerSecrets,
    ) -> Result<(), CoreError> {
        if !self.entries.contains_key(peer_id) {
            return Err(CoreError::PeerNotFound(peer_id.to_string()));
        }
        self.rendezvous_alternates
            .entry(peer_id.to_string())
            .or_default()
            .push(secrets);
        Ok(())
    }

    /// Drops every `Active` entry for which `keep(key, entry)` returns `false`, with its
    /// in-memory signing hash pin and rendezvous alternates. `Pending` and `Revoked` entries are
    /// always kept, so this only narrows trust and never undoes a revocation.
    pub fn retain_active(&mut self, mut keep: impl FnMut(&str, &RosterEntry) -> bool) {
        let dropped: Vec<String> = self
            .entries
            .iter()
            .filter(|(k, e)| e.state == PeerState::Active && !keep(k, e))
            .map(|(k, _)| k.clone())
            .collect();
        for key in dropped {
            self.entries.remove(&key);
            self.signing_hash_pins.remove(&key);
            self.rendezvous_alternates.remove(&key);
        }
    }

    /// Returns the in-memory alternate rendezvous secrets registered for `peer_id`.
    #[must_use]
    pub fn rendezvous_alternates(&self, peer_id: &str) -> &[V2PeerSecrets] {
        self.rendezvous_alternates
            .get(peer_id)
            .map_or(&[], Vec::as_slice)
    }

    /// Completes a hash-only signing pin for `peer_id` from the key presented in `HostHello`.
    ///
    /// A no-op when the entry already carries a full signing key or has no hash pin. A presented
    /// key that does not hash to the pin is [`CoreError::HostKeyUnverified`].
    pub fn resolve_signing_pin(
        &mut self,
        peer_id: &str,
        presented: &HybridSigningPublicKey,
    ) -> Result<(), CoreError> {
        let Some(entry) = self.entries.get_mut(peer_id) else {
            return Ok(());
        };
        if entry.signing_pub.is_some() {
            return Ok(());
        }
        let Some(hash) = self.signing_hash_pins.get(peer_id) else {
            return Ok(());
        };
        if !bool::from(presented.sha256_hash().ct_eq(hash)) {
            return Err(CoreError::HostKeyUnverified);
        }
        entry.signing_pub = Some(presented.clone());
        Ok(())
    }

    /// The host's published announced route set, if any.
    #[must_use]
    pub fn local_routes(&self) -> Option<&LocalRouteState> {
        self.local_routes.as_deref()
    }

    /// Publishes `set` as the host's announced route set `C(seq)`.
    ///
    /// An unchanged set returns the stored state. A changed (or first) set takes the next
    /// sequence (first value `1`) and `issued_at = now_unix`. The caller persists the roster
    /// before signing or sending anything. A changed set at `seq = 2^53-1` fails with
    /// `ProtocolViolation("route sequence exhausted")` and changes nothing.
    pub fn bump_local_routes(
        &mut self,
        set: &AnnouncedRouteSet,
        now_unix: u64,
    ) -> Result<LocalRouteState, CoreError> {
        let digest = LocalRouteState::digest_of(set.routes());
        let next_seq = match &self.local_routes {
            Some(state) if *state.digest() == digest => return Ok(LocalRouteState::clone(state)),
            Some(state) if state.seq() >= MAX_ROUTE_SEQ => {
                return Err(CoreError::ProtocolViolation("route sequence exhausted"));
            }
            Some(state) => state.seq() + 1,
            None => 1,
        };
        let state = LocalRouteState::new(next_seq, now_unix, set.routes().to_vec());
        self.local_routes = Some(Box::new(state.clone()));
        Ok(state)
    }

    /// Looks up an entry by roster key (`host_id` or `device_id`).
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&RosterEntry> {
        self.entries.get(id)
    }

    /// Returns the entry under `id`, else the one unconfirmed host entry naming `id` as its
    /// `host_id`. For operator display only: trust and routing lookups use [`Self::get`].
    #[must_use]
    pub fn get_or_pending_host(&self, id: &str) -> Option<&RosterEntry> {
        self.get(id)
            .or_else(|| match self.pending_host_claims(id).as_slice() {
                [only] => self.pending_hosts.get(*only),
                _ => None,
            })
    }

    /// Iterates over the unconfirmed host claims, oldest first. Each entry's `device_id` is the
    /// `host_id` it names.
    pub fn pending_hosts(&self) -> impl Iterator<Item = &RosterEntry> {
        self.pending_hosts.iter()
    }

    /// The error for a session or lookup target with no entry of its own: `PeerPending` while an
    /// unconfirmed host entry names it, else `PeerNotFound`.
    #[must_use]
    pub fn missing_peer_error(&self, id: &str) -> CoreError {
        if self.pending_host_claims(id).is_empty() {
            CoreError::PeerNotFound(id.to_string())
        } else {
            CoreError::PeerPending(id.to_string())
        }
    }

    /// Iterates over all entries ordered by key.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &RosterEntry)> {
        self.entries.iter()
    }

    /// Returns the highest verified [`RevocationList`] persisted for `issuer`.
    #[must_use]
    pub fn crl(&self, issuer: &str) -> Option<&RevocationList> {
        self.crls.get(issuer)
    }

    /// Returns `true` if any ingested CRL revokes `id`, matching either the supplied roster key or
    /// device identifier and the canonical `device_id` derived from `static_pub`.
    #[must_use]
    pub fn crl_revokes_identity(&self, id: &str, static_pub: &[u8; 32]) -> bool {
        self.crl_revokes_id(id) || self.crl_revokes_id(&device_id(static_pub))
    }

    /// Returns `true` if any ingested CRL lists exactly `id` in `revoked_devices`.
    #[must_use]
    pub fn crl_revokes_id(&self, id: &str) -> bool {
        self.crls
            .values()
            .any(|crl| crl.revoked_devices.iter().any(|d| d == id))
    }

    /// Returns `true` if any ingested CRL revokes `entry` by its stored `device_id` or by the
    /// canonical `device_id` derived from its `static_pub`.
    #[must_use]
    pub fn crl_revokes_entry(&self, entry: &RosterEntry) -> bool {
        self.crl_revokes_identity(&entry.device_id, &entry.static_pub)
    }

    fn revoked_key_conflict(
        &self,
        skip_key: &str,
        id: &str,
        static_pub: &[u8; 32],
        signing_pub: Option<&HybridSigningPublicKey>,
    ) -> bool {
        self.crl_revokes_identity(id, static_pub)
            || self.entries.iter().any(|(k, other)| {
                k != skip_key
                    && other.state == PeerState::Revoked
                    && (other.static_pub == *static_pub
                        || other.device_id == id
                        || matches!(
                            (signing_pub, &other.signing_pub),
                            (Some(a), Some(b)) if signing_keys_share_identity(a, b)
                        ))
            })
            || signing_pub.is_some_and(|sig| {
                self.trust_anchors.values().any(|a| {
                    a.state == AnchorState::Revoked
                        && signing_keys_share_identity(&a.signing_pub, sig)
                })
            })
    }

    /// Inserts or updates a verified client-side `Active` pin for a remote host before session connect.
    ///
    /// Refuses an invalid `host_id` ([`is_valid_host_id`]), a `Revoked` entry, and an `Active`
    /// entry whose `static_pub`, `signing_pub`, or `rotation_seq` conflicts with the supplied
    /// pin, and never retains grants across differing keys. An unconfirmed `Pending` entry under
    /// the label is promoted when its keys match and replaced otherwise; its rotation is not
    /// enforced. Drops the unconfirmed host claims naming `host_id`.
    pub fn insert_pinned_host(
        &mut self,
        host_id: String,
        name: String,
        static_pub: [u8; 32],
        signing_pub: Option<HybridSigningPublicKey>,
        rotation_seq: u64,
        relay_hints: Vec<String>,
    ) -> Result<&RosterEntry, CoreError> {
        if host_id.is_empty() || !is_valid_x25519_public_key(&static_pub) {
            return Err(CoreError::IncompletePin(host_id));
        }
        if !is_valid_host_id(&host_id) {
            return Err(CoreError::ProtocolViolation("invalid host_id"));
        }
        if self.revoked_key_conflict(&host_id, &host_id, &static_pub, signing_pub.as_ref()) {
            return Err(CoreError::PeerRevoked(host_id));
        }
        let claim_floor = self
            .pending_hosts
            .iter()
            .filter(|e| e.static_pub == static_pub)
            .map(|e| e.min_wire_version)
            .fold(WIRE_VERSION, u8::max);
        if let Some(existing) = self.entries.get_mut(&host_id) {
            let signing_conflict = match (&existing.signing_pub, &signing_pub) {
                (Some(prev), Some(next)) => prev != next,
                (Some(_), None) => true,
                _ => false,
            };
            let same_keys = existing.static_pub == static_pub && !signing_conflict;
            match existing.state {
                PeerState::Revoked => return Err(CoreError::PeerRevoked(host_id)),
                PeerState::Active if !same_keys || rotation_seq < existing.rotation_seq => {
                    return Err(CoreError::ProtocolViolation(
                        "cannot overwrite pinned host keys; rotate or revoke existing pin first",
                    ));
                }
                PeerState::Pending if !same_keys => {
                    self.entries.remove(&host_id);
                }
                PeerState::Active | PeerState::Pending => {
                    existing.rotation_seq = if existing.state == PeerState::Active {
                        existing.rotation_seq.max(rotation_seq)
                    } else {
                        rotation_seq
                    };
                    existing.name = name;
                    if existing.signing_pub.is_none() {
                        existing.signing_pub = signing_pub;
                    }
                    existing.state = PeerState::Active;
                    existing.min_wire_version = existing.min_wire_version.max(claim_floor);
                    if !relay_hints.is_empty() {
                        existing.relay_hints = relay_hints;
                    }
                    self.drop_pending_host_claims(&host_id);
                    return Ok(&self.entries[&host_id]);
                }
            }
        }

        let entry = RosterEntry {
            device_id: host_id.clone(),
            name,
            kind: "host".to_string(),
            static_pub,
            signing_pub,
            rotation_seq,
            state: PeerState::Active,
            last_pairing_sas: None,
            grants: Vec::new(),
            relay_hints,
            min_wire_version: claim_floor,
            v2_secrets: None,
            routes: Vec::new(),
            route_meta: None,
            approved_signed: Vec::new(),
        };
        self.drop_pending_host_claims(&host_id);
        self.entries.insert(host_id.clone(), entry);
        Ok(&self.entries[&host_id])
    }

    /// Records an unpinned host from manual pairing as an unconfirmed claim awaiting SAS
    /// confirmation.
    ///
    /// The `host_id` from `HostHello` is unauthenticated until confirmed, so the claim goes to the
    /// pending host store, never `entries`: it holds no label, and [`Self::confirm_peer`] with the
    /// `host_id` and its SAS moves it there. A later claim for the same `(static_pub, host_id)`
    /// replaces it, and past [`MAX_PENDING_HOSTS`] the oldest claim is evicted. Refuses an invalid
    /// `host_id`, a revoked label or keys, and a label held by an `Active` entry with distinct
    /// keys; an `Active` entry with the same keys is updated in place instead.
    #[allow(clippy::too_many_arguments)]
    pub fn record_pending_host(
        &mut self,
        host_id: String,
        name: String,
        static_pub: [u8; 32],
        signing_pub: HybridSigningPublicKey,
        rotation_seq: u64,
        pairing_sas: String,
        relay_hints: Vec<String>,
    ) -> Result<&RosterEntry, CoreError> {
        match self.record_pending_host_slot(
            host_id,
            name,
            static_pub,
            signing_pub,
            rotation_seq,
            pairing_sas,
            relay_hints,
        )? {
            HostSlot::Entry(id) => Ok(&self.entries[&id]),
            HostSlot::Pending(i) => Ok(&self.pending_hosts[i]),
        }
    }

    /// [`Self::record_pending_host`], returning where the host was written.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_pending_host_slot(
        &mut self,
        host_id: String,
        name: String,
        static_pub: [u8; 32],
        signing_pub: HybridSigningPublicKey,
        rotation_seq: u64,
        pairing_sas: String,
        relay_hints: Vec<String>,
    ) -> Result<HostSlot, CoreError> {
        if host_id.is_empty() || !is_valid_x25519_public_key(&static_pub) {
            return Err(CoreError::IncompletePin(host_id));
        }
        if !is_valid_host_id(&host_id) {
            return Err(CoreError::ProtocolViolation("invalid host_id"));
        }
        if self.revoked_key_conflict(&host_id, &host_id, &static_pub, Some(&signing_pub)) {
            return Err(CoreError::PeerRevoked(host_id));
        }
        if let Some(existing) = self.entries.get_mut(&host_id) {
            match existing.state {
                PeerState::Revoked => return Err(CoreError::PeerRevoked(host_id)),
                PeerState::Active => {
                    let signing_conflict = existing
                        .signing_pub
                        .as_ref()
                        .is_some_and(|prev| prev != &signing_pub);
                    if existing.static_pub != static_pub
                        || signing_conflict
                        || rotation_seq < existing.rotation_seq
                    {
                        return Err(CoreError::ProtocolViolation(
                            "host_id collision with distinct pinned keys",
                        ));
                    }
                    existing.name = name;
                    existing.signing_pub = Some(signing_pub);
                    existing.rotation_seq = existing.rotation_seq.max(rotation_seq);
                    existing.last_pairing_sas = Some(pairing_sas);
                    if !relay_hints.is_empty() {
                        existing.relay_hints = relay_hints;
                    }
                    return Ok(HostSlot::Entry(host_id));
                }
                PeerState::Pending => {}
            }
        }
        self.push_pending_host(RosterEntry {
            device_id: host_id,
            name,
            kind: "host".to_string(),
            static_pub,
            signing_pub: Some(signing_pub),
            rotation_seq,
            state: PeerState::Pending,
            last_pairing_sas: Some(pairing_sas),
            grants: Vec::new(),
            relay_hints,
            min_wire_version: WIRE_VERSION,
            v2_secrets: None,
            routes: Vec::new(),
            route_meta: None,
            approved_signed: Vec::new(),
        });
        Ok(HostSlot::Pending(self.pending_hosts.len() - 1))
    }

    /// Appends `claim`, replacing any claim for the same `(static_pub, host_id)` and evicting the
    /// oldest claims past [`MAX_PENDING_HOSTS`].
    fn push_pending_host(&mut self, claim: RosterEntry) {
        self.pending_hosts
            .retain(|e| e.device_id != claim.device_id || e.static_pub != claim.static_pub);
        self.pending_hosts.push(claim);
        let excess = self.pending_hosts.len().saturating_sub(MAX_PENDING_HOSTS);
        self.pending_hosts.drain(..excess);
    }

    /// Runs `f` against the host at `slot` under the label it names, so roster operations that
    /// address an entry by key also apply to an unconfirmed claim.
    pub(crate) fn with_host_slot<R>(
        &mut self,
        slot: &HostSlot,
        f: impl FnOnce(&mut Self, &str) -> Result<R, CoreError>,
    ) -> Result<R, CoreError> {
        let i = match slot {
            HostSlot::Entry(id) => return f(self, id),
            HostSlot::Pending(i) => *i,
        };
        let claim = self
            .pending_hosts
            .get(i)
            .cloned()
            .ok_or(CoreError::NotReady("pending host claim missing"))?;
        let label = claim.device_id.clone();
        let mut scratch = Self {
            crls: self.crls.clone(),
            ..Self::default()
        };
        scratch.entries.insert(label.clone(), claim);
        let out = f(&mut scratch, &label)?;
        self.pending_hosts[i] = scratch
            .entries
            .remove(&label)
            .ok_or(CoreError::NotReady("pending host claim missing"))?;
        Ok(out)
    }

    /// Indexes of the unconfirmed host claims naming `host_id`.
    fn pending_host_claims(&self, host_id: &str) -> Vec<usize> {
        self.pending_hosts
            .iter()
            .enumerate()
            .filter(|(_, e)| e.device_id == host_id)
            .map(|(i, _)| i)
            .collect()
    }

    /// Drops the unconfirmed host claims naming `host_id`.
    fn drop_pending_host_claims(&mut self, host_id: &str) {
        self.pending_hosts.retain(|e| e.device_id != host_id);
    }

    /// Resolves an operator-supplied id. An `Active` or `Revoked` entry under `id` wins;
    /// otherwise the candidates are a `Pending` entry under `id` and the claims naming it, and
    /// exactly one (with `sas`, exactly one recording that SAS) must remain.
    fn resolve_peer(&self, id: &str, sas: Option<&str>) -> Result<HostSlot, CoreError> {
        let mut candidates = Vec::new();
        match self.entries.get(id) {
            Some(e) if e.state != PeerState::Pending => return Ok(HostSlot::Entry(id.to_string())),
            Some(_) => candidates.push(HostSlot::Entry(id.to_string())),
            None => {}
        }
        candidates.extend(
            self.pending_host_claims(id)
                .into_iter()
                .map(HostSlot::Pending),
        );
        if candidates.is_empty() {
            return Err(CoreError::PeerNotFound(id.to_string()));
        }
        let total = candidates.len();
        if let Some(sas) = sas {
            candidates
                .retain(|slot| self.slot_entry(slot).last_pairing_sas.as_deref() == Some(sas));
        }
        match candidates.len() {
            1 => Ok(candidates.remove(0)),
            0 if total > 0 => Err(CoreError::ProtocolViolation("pairing SAS mismatch")),
            _ => Err(CoreError::ProtocolViolation(
                "several unconfirmed entries name this id",
            )),
        }
    }

    fn slot_entry(&self, slot: &HostSlot) -> &RosterEntry {
        match slot {
            HostSlot::Entry(id) => &self.entries[id],
            HostSlot::Pending(i) => &self.pending_hosts[*i],
        }
    }

    /// Drops every unconfirmed host claim naming `host_id` and nothing else: no roster entry is
    /// touched or removed, whatever its state, and nothing is revoked. Fails with
    /// [`CoreError::PeerNotFound`] when no claim names `host_id`.
    pub fn remove_pending_host_claims(&mut self, host_id: &str) -> Result<(), CoreError> {
        if self.pending_host_claims(host_id).is_empty() {
            return Err(CoreError::PeerNotFound(host_id.to_string()));
        }
        self.drop_pending_host_claims(host_id);
        Ok(())
    }

    /// The unconfirmed host claims, oldest first, as the JSON array every binding lists:
    /// `host_id` is the unauthenticated label a claim names and `device_id` the id derived from
    /// its static key in the handshake (the only id a claim revocation matches).
    #[must_use]
    pub fn pending_hosts_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.pending_hosts
                .iter()
                .map(|claim| {
                    serde_json::json!({
                        "host_id": claim.device_id,
                        "device_id": device_id(&claim.static_pub),
                        "name": claim.name,
                        "static_pub": b64url_encode(&claim.static_pub),
                        "signing_pub_hash": claim
                            .signing_pub
                            .as_ref()
                            .map(|k| b64url_encode(&k.sha256_hash())),
                        "rotation_seq": claim.rotation_seq,
                        "min_wire_version": claim.min_wire_version,
                        "pairing_sas": claim.last_pairing_sas,
                    })
                })
                .collect(),
        )
    }

    /// Removes a `Pending` (unconfirmed) peer or host entry and every unconfirmed host claim
    /// naming `peer_id`, refusing to drop `Active` or `Revoked` entries. Nothing is revoked.
    pub fn remove_pending_peer(&mut self, peer_id: &str) -> Result<(), CoreError> {
        let claims = self.pending_host_claims(peer_id).len();
        self.drop_pending_host_claims(peer_id);
        match self.entries.get(peer_id).map(|e| e.state) {
            Some(PeerState::Pending) => {
                self.entries.remove(peer_id);
                Ok(())
            }
            _ if claims > 0 => Ok(()),
            None => Err(CoreError::PeerNotFound(peer_id.to_string())),
            Some(PeerState::Revoked) => Err(CoreError::PeerRevoked(peer_id.to_string())),
            Some(PeerState::Active) => Err(CoreError::ProtocolViolation(
                "cannot remove active peer; revoke instead",
            )),
        }
    }

    /// Records a newly paired device in `Pending` state after verifying `code_mac`.
    ///
    /// Never promotes a `Pending` peer to `Active` and never un-revokes a `Revoked` peer.
    /// A `signing_pub` claimed for an existing entry follows the pinning rules of
    /// `spec/pairing-v1.md` Section 4.1: it fills a keyless entry and returns an `Active` one to
    /// `Pending` until [`Self::confirm_peer`] with the new SAS. A key differing from one pinned by
    /// any entry with the same static key, or a keyless claim for a `Pending` entry holding a key,
    /// fails with [`CoreError::ProtocolViolation`] before any field changes.
    pub fn record_pending_pair(
        &mut self,
        static_pub: [u8; 32],
        signing_pub: Option<HybridSigningPublicKey>,
        name: String,
        kind: String,
        pairing_sas: String,
    ) -> Result<&RosterEntry, CoreError> {
        if !is_valid_x25519_public_key(&static_pub) {
            return Err(CoreError::IncompletePin(
                "invalid or low-order static_pub".to_string(),
            ));
        }
        let id = device_id(&static_pub);
        if self.revoked_key_conflict(&id, &id, &static_pub, signing_pub.as_ref()) {
            return Err(CoreError::PeerRevoked(id));
        }
        if let Some(existing) = self.entries.get(&id)
            && existing.state == PeerState::Revoked
            && existing.static_pub == static_pub
        {
            return Err(CoreError::PeerRevoked(id));
        }
        if let Some(claimed) = signing_pub.as_ref()
            && self.entries.values().chain(&self.pending_hosts).any(|e| {
                e.state != PeerState::Revoked
                    && e.static_pub == static_pub
                    && e.signing_pub
                        .as_ref()
                        .is_some_and(|pinned| pinned != claimed)
            })
        {
            return Err(CoreError::ProtocolViolation(
                "cannot replace pinned signing key; rotate or revoke",
            ));
        }
        if let Some(existing) = self.entries.get_mut(&id) {
            if existing.static_pub != static_pub {
                return Err(CoreError::ProtocolViolation(
                    "device_id collision with distinct static key",
                ));
            }
            let enrich = match (&existing.signing_pub, &signing_pub) {
                (Some(_), None) if existing.state == PeerState::Pending => {
                    return Err(CoreError::ProtocolViolation(
                        "keyless claim cannot supersede an unconfirmed signing key",
                    ));
                }
                (None, Some(_)) => true,
                _ => false,
            };
            existing.name = name;
            existing.kind = kind;
            existing.last_pairing_sas = Some(pairing_sas);
            if enrich {
                existing.signing_pub = signing_pub;
                existing.state = PeerState::Pending;
            }
            return Ok(&self.entries[&id]);
        }

        let entry = RosterEntry {
            device_id: id.clone(),
            name,
            kind,
            static_pub,
            signing_pub,
            rotation_seq: 0,
            state: PeerState::Pending,
            last_pairing_sas: Some(pairing_sas),
            grants: Vec::new(),
            relay_hints: Vec::new(),
            min_wire_version: WIRE_VERSION,
            v2_secrets: None,
            routes: Vec::new(),
            route_meta: None,
            approved_signed: Vec::new(),
        };
        self.entries.insert(id.clone(), entry);
        Ok(&self.entries[&id])
    }

    fn confirm_peer_inner(
        &mut self,
        peer_id: &str,
        expected_sas: Option<&str>,
        allow_skip_sas: bool,
    ) -> Result<&RosterEntry, CoreError> {
        let slot = self.resolve_peer(peer_id, expected_sas)?;
        let entry = self.slot_entry(&slot);
        let label = match &slot {
            HostSlot::Entry(key) => key.clone(),
            HostSlot::Pending(_) => entry.device_id.clone(),
        };
        if entry.state == PeerState::Revoked {
            return Err(CoreError::PeerRevoked(label));
        }
        entry.require_static_pin()?;
        if !allow_skip_sas && entry.last_pairing_sas.is_some() && expected_sas.is_none() {
            return Err(CoreError::ProtocolViolation(
                "pairing SAS confirmation required",
            ));
        }
        if let Some(sas) = expected_sas
            && entry.last_pairing_sas.as_deref() != Some(sas)
        {
            return Err(CoreError::ProtocolViolation("pairing SAS mismatch"));
        }
        let skip_key = match &slot {
            HostSlot::Entry(key) => key.as_str(),
            HostSlot::Pending(_) => "",
        };
        if self.revoked_key_conflict(
            skip_key,
            &entry.device_id,
            &entry.static_pub,
            entry.signing_pub.as_ref(),
        ) || self.crl_revokes_identity(&label, &entry.static_pub)
        {
            return Err(CoreError::PeerRevoked(label));
        }

        match slot {
            HostSlot::Entry(_) => {
                if let Some(entry) = self.entries.get_mut(&label) {
                    entry.state = PeerState::Active;
                }
            }
            HostSlot::Pending(i) => {
                let static_pub = self.pending_hosts[i].static_pub;
                match self.entries.get(&label) {
                    Some(e) if e.state == PeerState::Revoked => {
                        return Err(CoreError::PeerRevoked(label));
                    }
                    Some(e) if e.state == PeerState::Active || e.static_pub != static_pub => {
                        return Err(CoreError::ProtocolViolation(
                            "host_id collision with distinct pinned keys",
                        ));
                    }
                    _ => {}
                }
                let mut entry = self.pending_hosts.remove(i);
                entry.state = PeerState::Active;
                if let Some(replaced) = self.entries.remove(&label)
                    && replaced.signing_pub == entry.signing_pub
                {
                    entry.grants = replaced.grants;
                }
                self.entries.insert(label.clone(), entry);
            }
        }
        self.drop_pending_host_claims(&label);
        Ok(&self.entries[&label])
    }

    /// Confirms a `Pending` peer (`pair.confirm`) and moves it to `Active` with zero
    /// non-session capabilities (default deny).
    ///
    /// Whenever a live pairing SAS is recorded on the peer entry, `expected_sas` MUST be
    /// `Some(...)` and match; omitting `expected_sas` fails closed. Use
    /// [`Self::confirm_peer_without_sas`] only for explicit out-of-band fingerprint approval.
    pub fn confirm_peer(
        &mut self,
        peer_id: &str,
        expected_sas: Option<&str>,
    ) -> Result<&RosterEntry, CoreError> {
        self.confirm_peer_inner(peer_id, expected_sas, false)
    }

    /// Confirms a `Pending` peer explicitly bypassing live SAS verification (for example after
    /// out-of-band fingerprint verification).
    pub fn confirm_peer_without_sas(&mut self, peer_id: &str) -> Result<&RosterEntry, CoreError> {
        self.confirm_peer_inner(peer_id, None, true)
    }

    /// Mints a signed [`Grant`] (`pair.mint`) for an already `Active` peer on this roster.
    pub fn mint_grant(
        &mut self,
        issuer: &EndpointIdentity,
        subject_device_id: &str,
        caps: Vec<String>,
        not_before_unix: u64,
        not_after_unix: u64,
        nonce: [u8; 16],
    ) -> Result<Grant, CoreError> {
        let entry = self
            .entries
            .get_mut(subject_device_id)
            .ok_or_else(|| CoreError::PeerNotFound(subject_device_id.to_string()))?;
        match entry.state {
            PeerState::Pending => {
                return Err(CoreError::PeerPending(subject_device_id.to_string()));
            }
            PeerState::Revoked => {
                return Err(CoreError::PeerRevoked(subject_device_id.to_string()));
            }
            PeerState::Active => {}
        }
        entry.require_static_pin()?;

        if not_before_unix >= not_after_unix {
            return Err(CoreError::InvalidTimestamp(
                "not_before must be strictly earlier than not_after".to_string(),
            ));
        }
        for cap in &caps {
            Capability::parse(cap)?;
        }

        let grant = sign_grant(
            GrantUnsigned {
                v: 1,
                issuer: issuer.host_id().to_string(),
                subject: subject_device_id.to_string(),
                caps,
                not_before: format_rfc3339_utc(not_before_unix)?,
                not_after: format_rfc3339_utc(not_after_unix)?,
                nonce: b64url_encode(&nonce),
                delegated_from: Vec::new(),
                uses: None,
                machine: None,
            },
            issuer.signing_key(),
        )?;
        entry.grants.push(grant.clone());
        Ok(grant)
    }

    /// Updates cached `relay_hints` for an existing non-revoked peer without modifying cryptographic pins or grants.
    pub fn update_relay_hints(
        &mut self,
        peer_id: &str,
        relay_hints: Vec<String>,
    ) -> Result<&RosterEntry, CoreError> {
        let entry = self
            .entries
            .get_mut(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if entry.state == PeerState::Revoked {
            return Err(CoreError::PeerRevoked(peer_id.to_string()));
        }
        entry.relay_hints = relay_hints;
        Ok(&self.entries[peer_id])
    }

    fn revoke_siblings_by_keys(
        &mut self,
        revoked_static: [u8; 32],
        revoked_signing: Option<&HybridSigningPublicKey>,
    ) {
        for other in self.entries.values_mut() {
            let shares_static = revoked_static != [0u8; 32] && other.static_pub == revoked_static;
            let shares_signing = revoked_signing.is_some_and(|r| {
                other
                    .signing_pub
                    .as_ref()
                    .is_some_and(|o| signing_keys_share_identity(r, o))
            });
            if shares_static || shares_signing {
                other.state = PeerState::Revoked;
                other.grants.clear();
                other.v2_secrets = None;
            }
        }
        self.pending_hosts.retain(|claim| {
            let shares_static = revoked_static != [0u8; 32] && claim.static_pub == revoked_static;
            let shares_signing = revoked_signing.is_some_and(|r| {
                claim
                    .signing_pub
                    .as_ref()
                    .is_some_and(|o| signing_keys_share_identity(r, o))
            });
            !(shares_static || shares_signing)
        });
        if let Some(sig) = revoked_signing {
            for anchor in self.trust_anchors.values_mut() {
                if signing_keys_share_identity(&anchor.signing_pub, sig) {
                    anchor.state = AnchorState::Revoked;
                }
            }
        }
    }

    /// Marks `peer_id` (and any sibling entry sharing its cryptographic keys) as `Revoked`
    /// and clears any stored grants and v2 secrets.
    ///
    /// An `Active` or `Revoked` entry under `peer_id` is revoked directly. Otherwise `peer_id`
    /// first names the unconfirmed host claims whose handshake-authenticated
    /// `device_id(static_pub)` equals it ([`Self::revoke_pending_host`]); only when none does is
    /// it resolved as in [`Self::confirm_peer`], against a `Pending` entry under it and the claims
    /// naming it as their `host_id`. Revoking a claim drops it and revokes its keys, never the
    /// `host_id` it named or an entry holding other keys. Unconfirmed claims sharing the revoked
    /// keys are dropped.
    pub fn revoke_peer(&mut self, peer_id: &str) -> Result<(), CoreError> {
        if self
            .entries
            .get(peer_id)
            .is_some_and(|e| e.state != PeerState::Pending)
        {
            return self.revoke_entry(peer_id);
        }
        if self
            .pending_hosts
            .iter()
            .any(|e| device_id(&e.static_pub) == peer_id)
        {
            return self.revoke_pending_host(peer_id);
        }
        match self.resolve_peer(peer_id, None)? {
            HostSlot::Entry(key) => self.revoke_entry(&key),
            HostSlot::Pending(i) => {
                let claim = self.pending_hosts.remove(i);
                self.revoke_claim_keys(claim);
                Ok(())
            }
        }
    }

    /// Revokes the keys of every unconfirmed host claim whose `device_id(static_pub)` equals
    /// `static_device_id`, matching only that handshake-authenticated id, never a claimed
    /// `host_id`, and never revoking an entry that holds other keys or any label.
    pub fn revoke_pending_host(&mut self, static_device_id: &str) -> Result<(), CoreError> {
        let mut removed = Vec::new();
        self.pending_hosts.retain(|e| {
            let hit = device_id(&e.static_pub) == static_device_id;
            if hit {
                removed.push(e.clone());
            }
            !hit
        });
        if removed.is_empty() {
            return Err(CoreError::PeerNotFound(static_device_id.to_string()));
        }
        for claim in removed {
            self.revoke_claim_keys(claim);
        }
        Ok(())
    }

    fn revoke_entry(&mut self, key: &str) -> Result<(), CoreError> {
        let (revoked_static, revoked_signing) = {
            let entry = self
                .entries
                .get_mut(key)
                .ok_or_else(|| CoreError::PeerNotFound(key.to_string()))?;
            entry.state = PeerState::Revoked;
            entry.grants.clear();
            entry.v2_secrets = None;
            (entry.static_pub, entry.signing_pub.clone())
        };
        self.revoke_siblings_by_keys(revoked_static, revoked_signing.as_ref());
        Ok(())
    }

    /// Records the keys of a dropped claim as `Revoked`. The entry under
    /// `device_id(static_pub)` carries them only when it holds the same static key and no other
    /// signing key (a missing one is filled from the claim); otherwise a revoked record is kept
    /// under a key no `host_id` can take, so no label and no entry holding other keys is revoked.
    fn revoke_claim_keys(&mut self, mut claim: RosterEntry) {
        let own = device_id(&claim.static_pub);
        match self.entries.get_mut(&own) {
            Some(entry)
                if entry.static_pub == claim.static_pub
                    && (entry.signing_pub.is_none() || entry.signing_pub == claim.signing_pub) =>
            {
                if entry.signing_pub.is_none() {
                    entry.signing_pub.clone_from(&claim.signing_pub);
                }
                entry.state = PeerState::Revoked;
                entry.grants.clear();
                entry.v2_secrets = None;
            }
            _ => {
                let signing = claim.signing_pub.as_ref().map_or_else(
                    || "none".to_string(),
                    |k| hex::encode(&k.sha256_hash()[..8]),
                );
                let key = format!("{own}#revoked-{signing}");
                claim.device_id.clone_from(&key);
                claim.state = PeerState::Revoked;
                claim.grants.clear();
                claim.v2_secrets = None;
                claim.last_pairing_sas = None;
                self.entries.insert(key, claim.clone());
            }
        }
        self.revoke_siblings_by_keys(claim.static_pub, claim.signing_pub.as_ref());
    }

    /// Raises the minimum wire protocol version required for `peer_id` (anti-downgrade floor).
    ///
    /// Refuses decreasing `min_wire_version` below the already-persisted floor and rejects
    /// revoked or unknown peers.
    pub fn set_peer_min_wire_version(
        &mut self,
        peer_id: &str,
        min_wire_version: u8,
    ) -> Result<(), CoreError> {
        if min_wire_version != WIRE_VERSION && min_wire_version != WIRE_VERSION_V2 {
            return Err(CoreError::UnsupportedVersion(min_wire_version));
        }
        let entry = self
            .entries
            .get_mut(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if entry.state == PeerState::Revoked {
            return Err(CoreError::PeerRevoked(peer_id.to_string()));
        }
        if min_wire_version < entry.min_wire_version {
            return Err(CoreError::VersionDowngrade {
                peer_min: entry.min_wire_version,
                negotiated: min_wire_version,
            });
        }
        entry.min_wire_version = min_wire_version;
        Ok(())
    }

    /// Returns the persisted anti-downgrade wire version floor (`1` or `2`) for `static_pub`.
    #[must_use]
    pub fn pairing_floor(&self, static_pub: &[u8; 32]) -> u8 {
        self.entries
            .values()
            .chain(&self.pending_hosts)
            .filter(|e| &e.static_pub == static_pub)
            .map(|e| e.min_wire_version)
            .max()
            .unwrap_or(WIRE_VERSION)
    }

    /// Enforces `peer_id`'s persisted `min_wire_version` floor against `negotiated_version`.
    ///
    /// Fails closed with [`CoreError::PeerNotFound`] if `peer_id` is absent from the roster.
    pub fn enforce_min_wire_version(
        &self,
        peer_id: &str,
        negotiated_version: u8,
    ) -> Result<(), CoreError> {
        let entry = self
            .entries
            .get(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if entry.min_wire_version > negotiated_version {
            return Err(CoreError::VersionDowngrade {
                peer_min: entry.min_wire_version,
                negotiated: negotiated_version,
            });
        }
        Ok(())
    }

    /// Stores zeroizing v2 reconnect and blinded mailbox secrets on a non-revoked peer entry.
    pub fn set_peer_v2_secrets(
        &mut self,
        peer_id: &str,
        secrets: V2PeerSecrets,
    ) -> Result<(), CoreError> {
        let entry = self
            .entries
            .get_mut(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if entry.state == PeerState::Revoked {
            return Err(CoreError::PeerRevoked(peer_id.to_string()));
        }
        entry.v2_secrets = Some(secrets);
        Ok(())
    }

    /// Upgrades a non-revoked peer to Wire v2 (`min_wire_version >= 2`) and stores its v2 secrets.
    pub fn upgrade_peer_to_v2(
        &mut self,
        peer_id: &str,
        secrets: V2PeerSecrets,
    ) -> Result<(), CoreError> {
        let entry = self
            .entries
            .get_mut(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if entry.state == PeerState::Revoked {
            return Err(CoreError::PeerRevoked(peer_id.to_string()));
        }
        entry.min_wire_version = entry.min_wire_version.max(WIRE_VERSION_V2);
        entry.v2_secrets = Some(secrets);
        Ok(())
    }

    /// Verifies `HostHello.rotation` against `peer_id`'s pinned keys and advances pins on success.
    ///
    /// A confirmed trust-root rotation fork immediately transitions the entry to `Revoked` and
    /// clears its grants before returning [`CoreError::RotationForkDetected`].
    pub fn apply_verified_rotation(
        &mut self,
        peer_id: &str,
        chain: &[RotationRecord],
        presented_static: &[u8; 32],
        presented_signing: &HybridSigningPublicKey,
    ) -> Result<u64, CoreError> {
        let (pinned_static, pinned_signing, pinned_seq) = {
            let entry = self
                .entries
                .get(peer_id)
                .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
            match entry.state {
                PeerState::Pending => return Err(CoreError::PeerPending(peer_id.to_string())),
                PeerState::Revoked => return Err(CoreError::PeerRevoked(peer_id.to_string())),
                PeerState::Active => {}
            }
            let (stat, sig) = entry.require_complete_pin()?;
            (stat, sig, entry.rotation_seq)
        };

        match verify_rotation_chain(
            &pinned_signing,
            &pinned_static,
            pinned_seq,
            chain,
            presented_static,
            presented_signing,
        ) {
            Ok(new_seq) => {
                if new_seq > pinned_seq {
                    if self.revoked_key_conflict(
                        peer_id,
                        peer_id,
                        presented_static,
                        Some(presented_signing),
                    ) {
                        return Err(CoreError::PeerRevoked(peer_id.to_string()));
                    }
                    let entry = self
                        .entries
                        .get_mut(peer_id)
                        .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
                    entry.static_pub = *presented_static;
                    entry.signing_pub = Some(presented_signing.clone());
                    entry.rotation_seq = new_seq;
                }
                Ok(new_seq)
            }
            Err(err @ CoreError::RotationForkDetected { .. }) => {
                let keys = self.entries.get_mut(peer_id).map(|entry| {
                    entry.state = PeerState::Revoked;
                    entry.grants.clear();
                    entry.v2_secrets = None;
                    (entry.static_pub, entry.signing_pub.clone())
                });
                if let Some((revoked_static, revoked_signing)) = keys {
                    self.revoke_siblings_by_keys(revoked_static, revoked_signing.as_ref());
                }
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    /// Validates a signed [`RevocationList`], enforces monotonic `seq`, updates revoked peers, and
    /// persists the latest CRL for `expected_issuer`.
    pub fn ingest_crl(
        &mut self,
        crl: RevocationList,
        expected_issuer: &str,
        issuer_signing_pub: &HybridSigningPublicKey,
    ) -> Result<(), CoreError> {
        if crl.v != 1 {
            return Err(CoreError::CrlUnsupportedVersion(crl.v));
        }
        if crl.issuer != expected_issuer {
            return Err(CoreError::CrlIssuerMismatch {
                expected: expected_issuer.to_string(),
                got: crl.issuer,
            });
        }
        verify_crl_signature(&crl, issuer_signing_pub)?;

        if let Some(existing) = self.crls.get(expected_issuer) {
            if existing == &crl {
                return Ok(());
            }
            if crl.seq <= existing.seq {
                return Err(CoreError::CrlStaleSeq {
                    current: existing.seq,
                    got: crl.seq,
                });
            }
        }

        let mut revoked_keys = Vec::new();
        for revoked_id in &crl.revoked_devices {
            for (key, entry) in &mut self.entries {
                if key == revoked_id
                    || &entry.device_id == revoked_id
                    || &device_id(&entry.static_pub) == revoked_id
                {
                    entry.state = PeerState::Revoked;
                    entry.grants.clear();
                    entry.v2_secrets = None;
                    revoked_keys.push((entry.static_pub, entry.signing_pub.clone()));
                }
            }
            if let Some(anchor) = self.trust_anchors.get_mut(revoked_id) {
                anchor.state = AnchorState::Revoked;
                revoked_keys.push(([0u8; 32], Some(anchor.signing_pub.clone())));
            }
        }
        for (revoked_static, revoked_signing) in revoked_keys {
            self.revoke_siblings_by_keys(revoked_static, revoked_signing.as_ref());
        }

        self.crls.insert(expected_issuer.to_string(), crl);
        Ok(())
    }

    /// Finds an active peer matching `static_pub`, rejecting unknown, pending, or revoked peers.
    pub fn lookup_active_by_static(
        &self,
        static_pub: &[u8; 32],
    ) -> Result<&RosterEntry, CoreError> {
        if !is_valid_x25519_public_key(static_pub) {
            return Err(CoreError::IncompletePin(
                "invalid or low-order static_pub".to_string(),
            ));
        }
        let mut active: Option<&RosterEntry> = None;
        let mut pending: Option<&RosterEntry> = None;
        for entry in self
            .entries
            .values()
            .filter(|e| e.static_pub == *static_pub)
        {
            match entry.state {
                PeerState::Revoked => return Err(CoreError::PeerRevoked(entry.device_id.clone())),
                PeerState::Pending => pending = Some(entry),
                PeerState::Active => active = Some(entry),
            }
        }
        if let Some(entry) = active {
            entry.require_static_pin()?;
            if self.crl_revokes_entry(entry) {
                return Err(CoreError::PeerRevoked(entry.device_id.clone()));
            }
            if let Some(ref sig) = entry.signing_pub
                && self.entries.values().any(|other| {
                    other.state == PeerState::Revoked
                        && other
                            .signing_pub
                            .as_ref()
                            .is_some_and(|o| signing_keys_share_identity(sig, o))
                })
            {
                return Err(CoreError::PeerRevoked(entry.device_id.clone()));
            }
            return Ok(entry);
        }
        if let Some(entry) = pending {
            return Err(CoreError::PeerPending(entry.device_id.clone()));
        }
        Err(CoreError::PeerNotFound(device_id(static_pub)))
    }

    /// Returns the pinned hybrid signing public key of an `Active` peer for grant verification,
    /// enforcing revocation precedence across sibling entries and ingested CRLs.
    #[must_use]
    pub fn lookup_active_signing_key(&self, issuer_id: &str) -> Option<HybridSigningPublicKey> {
        if self.entries.iter().any(|(k, e)| {
            (k == issuer_id || e.device_id == issuer_id) && e.state == PeerState::Revoked
        }) {
            return None;
        }
        let entry = self
            .entries
            .get(issuer_id)
            .filter(|e| e.state == PeerState::Active)
            .or_else(|| {
                self.entries
                    .values()
                    .find(|e| e.device_id == issuer_id && e.state == PeerState::Active)
            })?;
        let sig_pub = entry.signing_pub.clone()?;
        let cand_derived_id = device_id(&entry.static_pub);

        let sibling_revoked = self.entries.values().any(|other| {
            other.state == PeerState::Revoked
                && (other.device_id == issuer_id
                    || other.device_id == entry.device_id
                    || other.device_id == cand_derived_id
                    || other.static_pub == entry.static_pub
                    || other
                        .signing_pub
                        .as_ref()
                        .is_some_and(|o| signing_keys_share_identity(&sig_pub, o)))
        }) || self.trust_anchors.values().any(|a| {
            a.state == AnchorState::Revoked && signing_keys_share_identity(&a.signing_pub, &sig_pub)
        });
        if sibling_revoked {
            return None;
        }

        let crl_revoked = self.crls.values().any(|crl| {
            crl.revoked_devices
                .iter()
                .any(|d| d == issuer_id || d == &entry.device_id || d == &cand_derived_id)
        });
        if crl_revoked {
            return None;
        }

        Some(sig_pub)
    }

    /// Registers an active external hybrid trust anchor for autonomous M2M enrollment.
    ///
    /// Fails closed if `anchor_id` is empty/malformed, `signing_pub` is invalid, any sibling
    /// sharing `signing_pub` (or `anchor_id`) is revoked, or an existing entry pins a differing key.
    pub fn add_trust_anchor(
        &mut self,
        anchor_id: String,
        signing_pub: HybridSigningPublicKey,
    ) -> Result<&TrustAnchor, CoreError> {
        if anchor_id.is_empty() || anchor_id == "*" || has_control_chars(&anchor_id) {
            return Err(CoreError::IncompletePin(anchor_id));
        }

        let sibling_revoked = self.trust_anchors.values().any(|a| {
            a.state == AnchorState::Revoked
                && (a.anchor_id == anchor_id
                    || signing_keys_share_identity(&a.signing_pub, &signing_pub))
        }) || self.entries.values().any(|e| {
            e.state == PeerState::Revoked
                && (e.device_id == anchor_id
                    || e.signing_pub
                        .as_ref()
                        .is_some_and(|s| signing_keys_share_identity(s, &signing_pub)))
        }) || self
            .crls
            .values()
            .any(|c| c.revoked_devices.iter().any(|d| d == &anchor_id));
        if sibling_revoked {
            return Err(CoreError::PeerRevoked(anchor_id));
        }

        if let Some(existing) = self.trust_anchors.get(&anchor_id) {
            if existing.signing_pub != signing_pub {
                return Err(CoreError::ProtocolViolation("trust anchor key conflict"));
            }
            return Ok(&self.trust_anchors[&anchor_id]);
        }

        self.trust_anchors.insert(
            anchor_id.clone(),
            TrustAnchor {
                anchor_id: anchor_id.clone(),
                signing_pub,
                state: AnchorState::Active,
            },
        );
        Ok(&self.trust_anchors[&anchor_id])
    }

    /// Marks `anchor_id` (and any sibling anchors or peers sharing its `signing_pub`) as `Revoked`.
    pub fn revoke_trust_anchor(&mut self, anchor_id: &str) -> Result<(), CoreError> {
        let revoked_pub = {
            let anchor = self
                .trust_anchors
                .get_mut(anchor_id)
                .ok_or_else(|| CoreError::PeerNotFound(anchor_id.to_string()))?;
            anchor.state = AnchorState::Revoked;
            anchor.signing_pub.clone()
        };
        self.revoke_siblings_by_keys([0u8; 32], Some(&revoked_pub));
        Ok(())
    }

    /// Returns a trust anchor record by identifier.
    #[must_use]
    pub fn trust_anchor(&self, anchor_id: &str) -> Option<&TrustAnchor> {
        self.trust_anchors.get(anchor_id)
    }

    /// Iterates over all trust anchors ordered by `anchor_id`.
    pub fn trust_anchors(&self) -> impl Iterator<Item = (&String, &TrustAnchor)> {
        self.trust_anchors.iter()
    }

    /// Returns the hybrid signing public key of an active trust anchor, enforcing sibling and
    /// CRL revocation checks.
    #[must_use]
    pub fn lookup_active_anchor_key(&self, anchor_id: &str) -> Option<HybridSigningPublicKey> {
        let anchor = self.trust_anchors.get(anchor_id)?;
        if anchor.state != AnchorState::Active {
            return None;
        }
        let sibling_anchor_revoked = self.trust_anchors.values().any(|other| {
            other.state == AnchorState::Revoked
                && signing_keys_share_identity(&other.signing_pub, &anchor.signing_pub)
        });
        if sibling_anchor_revoked {
            return None;
        }
        let peer_revoked = self.entries.values().any(|other| {
            other.state == PeerState::Revoked
                && (other.device_id == anchor_id
                    || other
                        .signing_pub
                        .as_ref()
                        .is_some_and(|s| signing_keys_share_identity(s, &anchor.signing_pub)))
        });
        if peer_revoked {
            return None;
        }
        let crl_revoked = self
            .crls
            .values()
            .any(|crl| crl.revoked_devices.iter().any(|d| d == anchor_id));
        if crl_revoked {
            return None;
        }
        Some(anchor.signing_pub.clone())
    }

    /// Returns `true` if `nonce` has already been burned in an M2M enrollment claim.
    #[must_use]
    pub fn is_enrollment_nonce_burned(&self, nonce: &str) -> bool {
        self.burned_enrollment_nonces.contains_key(nonce)
    }

    /// Returns the count of tracked burned enrollment nonces.
    #[must_use]
    pub fn burned_enrollment_nonce_count(&self) -> usize {
        self.burned_enrollment_nonces.len()
    }

    /// Prunes expired burned enrollment nonces (`not_after <= now_unix`) and returns how many
    /// entries were removed.
    pub fn prune_expired_enrollment_nonces(&mut self, now_unix: u64) -> usize {
        let before = self.burned_enrollment_nonces.len();
        self.burned_enrollment_nonces
            .retain(|_, &mut not_after| not_after > now_unix);
        before.saturating_sub(self.burned_enrollment_nonces.len())
    }

    /// Atomically checks and burns a single-use M2M enrollment token `nonce`, pruning expired
    /// entries first and enforcing [`MAX_BURNED_ENROLLMENT_NONCES`].
    pub fn burn_enrollment_nonce(
        &mut self,
        nonce: &str,
        not_after_unix: u64,
        now_unix: u64,
    ) -> Result<(), CoreError> {
        if nonce.is_empty() {
            return Err(CoreError::EnrollmentTokenInvalid(
                "empty enrollment nonce".to_string(),
            ));
        }
        if self.burned_enrollment_nonces.contains_key(nonce) {
            return Err(CoreError::EnrollmentTokenReplayed);
        }
        self.prune_expired_enrollment_nonces(now_unix);
        if self.burned_enrollment_nonces.len() >= MAX_BURNED_ENROLLMENT_NONCES {
            return Err(CoreError::EnrollmentBurnLogFull);
        }
        self.burned_enrollment_nonces
            .insert(nonce.to_string(), not_after_unix);
        Ok(())
    }

    /// Records a newly verified M2M peer directly in `Active` state with zero application grants
    /// (`pair.mint` remains a separate step).
    ///
    /// Fails closed if `static_pub`, `signing_pub`, or any revoked sibling/CRL indicates
    /// revocation, or if an existing entry has conflicting keys.
    pub fn record_enrolled_machine(
        &mut self,
        static_pub: [u8; 32],
        signing_pub: HybridSigningPublicKey,
        name: String,
        kind: String,
    ) -> Result<&RosterEntry, CoreError> {
        if !is_valid_x25519_public_key(&static_pub) {
            return Err(CoreError::IncompletePin(
                "invalid or low-order static_pub".to_string(),
            ));
        }
        if name.is_empty()
            || kind.is_empty()
            || has_control_chars(&name)
            || has_control_chars(&kind)
        {
            return Err(CoreError::ProtocolViolation(
                "invalid device metadata in enrollment",
            ));
        }

        let id = device_id(&static_pub);
        let sibling_or_crl_revoked = self.entries.values().any(|other| {
            other.state == PeerState::Revoked
                && (other.device_id == id
                    || other.static_pub == static_pub
                    || other
                        .signing_pub
                        .as_ref()
                        .is_some_and(|s| signing_keys_share_identity(s, &signing_pub)))
        }) || self.trust_anchors.values().any(|a| {
            a.state == AnchorState::Revoked
                && signing_keys_share_identity(&a.signing_pub, &signing_pub)
        }) || self
            .crls
            .values()
            .any(|c| c.revoked_devices.iter().any(|d| d == &id));
        if sibling_or_crl_revoked {
            return Err(CoreError::PeerRevoked(id));
        }

        if let Some(existing) = self.entries.get_mut(&id) {
            if existing.static_pub != static_pub {
                return Err(CoreError::ProtocolViolation(
                    "device_id collision with distinct static key",
                ));
            }
            if existing.state == PeerState::Revoked {
                return Err(CoreError::PeerRevoked(id));
            }
            if let Some(ref prev_sig) = existing.signing_pub
                && prev_sig != &signing_pub
            {
                return Err(CoreError::ProtocolViolation(
                    "signing_pub mismatch on existing peer",
                ));
            }
            existing.name = name;
            existing.kind = kind;
            existing.signing_pub = Some(signing_pub);
            existing.state = PeerState::Active;
            existing.last_pairing_sas = None;
            self.drop_pending_host_claims(&id);
            return Ok(&self.entries[&id]);
        }

        let entry = RosterEntry {
            device_id: id.clone(),
            name,
            kind,
            static_pub,
            signing_pub: Some(signing_pub),
            rotation_seq: 0,
            state: PeerState::Active,
            last_pairing_sas: None,
            grants: Vec::new(),
            relay_hints: Vec::new(),
            min_wire_version: WIRE_VERSION,
            v2_secrets: None,
            routes: Vec::new(),
            route_meta: None,
            approved_signed: Vec::new(),
        };
        self.drop_pending_host_claims(&id);
        self.entries.insert(id.clone(), entry);
        Ok(&self.entries[&id])
    }

    fn mint_crl_update(
        &mut self,
        issuer: &EndpointIdentity,
        extra_nonce: Option<&str>,
        now_unix: u64,
    ) -> Result<RevocationList, CoreError> {
        let issuer_id = issuer.host_id().to_string();
        let existing = self.crls.get(&issuer_id);
        let seq = existing.map_or(1, |c| c.seq.saturating_add(1));
        let revoked_devices = existing.map_or_else(Vec::new, |c| c.revoked_devices.clone());
        let mut revoked_nonces = existing.map_or_else(Vec::new, |c| c.revoked_nonces.clone());
        if let Some(nonce) = extra_nonce
            && !revoked_nonces.iter().any(|n| n == nonce)
        {
            revoked_nonces.push(nonce.to_string());
        }
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: issuer_id.clone(),
                seq,
                revoked_devices,
                revoked_nonces,
                ts: format_rfc3339_utc(now_unix)?,
            },
            issuer.signing_key(),
        )?;
        self.ingest_crl(crl.clone(), &issuer_id, issuer.signing_key().public_key())?;
        Ok(crl)
    }

    /// Mints and ingests a monotonic signed [`RevocationList`] adding `nonce` to `revoked_nonces`.
    pub fn revoke_nonce(
        &mut self,
        issuer: &EndpointIdentity,
        nonce: &str,
        now_unix: u64,
    ) -> Result<RevocationList, CoreError> {
        if nonce.is_empty() {
            return Err(CoreError::EnrollmentTokenInvalid(
                "empty nonce to revoke".to_string(),
            ));
        }
        self.mint_crl_update(issuer, Some(nonce), now_unix)
    }

    /// Re-signs any existing self-issued CRL under `issuer`'s current signing key after key rotation.
    pub fn resign_crl(
        &mut self,
        issuer: &EndpointIdentity,
        now_unix: u64,
    ) -> Result<Option<RevocationList>, CoreError> {
        if !self.crls.contains_key(issuer.host_id()) {
            return Ok(None);
        }
        self.mint_crl_update(issuer, None, now_unix).map(Some)
    }
}

/// Day-2 routes, route metadata and session authorization.
impl Roster {
    fn entry_mut(&mut self, peer_id: &str) -> Result<&mut RosterEntry, CoreError> {
        self.entries
            .get_mut(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))
    }

    fn require_active(&self, peer_id: &str) -> Result<&RosterEntry, CoreError> {
        let entry = self
            .entries
            .get(peer_id)
            .ok_or_else(|| self.missing_peer_error(peer_id))?;
        match entry.state {
            PeerState::Pending => Err(CoreError::PeerPending(peer_id.to_string())),
            PeerState::Revoked => Err(CoreError::PeerRevoked(peer_id.to_string())),
            PeerState::Active if self.crl_revokes_entry(entry) => {
                Err(CoreError::PeerRevoked(peer_id.to_string()))
            }
            PeerState::Active => Ok(entry),
        }
    }

    /// `SHA-256` of the entry's pinned signing key, or its in-memory hash pin.
    fn pinned_signing_hash(&self, peer_id: &str, entry: &RosterEntry) -> Option<[u8; 32]> {
        entry
            .signing_pub
            .as_ref()
            .map(HybridSigningPublicKey::sha256_hash)
            .or_else(|| self.signing_hash_pins.get(peer_id).copied())
    }

    /// Fails with `HostKeyUnverified` unless `(k, sh)` name the entry's pinned keys.
    fn check_signed_keys(
        &self,
        peer_id: &str,
        entry: &RosterEntry,
        k: &[u8; 32],
        sh: &[u8; 32],
    ) -> Result<(), CoreError> {
        let pinned = self
            .pinned_signing_hash(peer_id, entry)
            .ok_or(CoreError::HostKeyUnverified)?;
        if entry.static_pub != *k || !bool::from(pinned.ct_eq(sh)) {
            return Err(CoreError::HostKeyUnverified);
        }
        Ok(())
    }

    /// Takes a [`PinSnapshot`] of a complete pin of an `Active` entry no CRL revokes, for a Day-2
    /// connect.
    pub fn pin_snapshot(&self, peer_id: &str) -> Result<PinSnapshot, CoreError> {
        let entry = self
            .entries
            .get(peer_id)
            .ok_or_else(|| self.missing_peer_error(peer_id))?;
        match entry.state {
            PeerState::Pending => return Err(CoreError::PeerPending(peer_id.to_string())),
            PeerState::Revoked => return Err(CoreError::PeerRevoked(peer_id.to_string())),
            PeerState::Active if self.crl_revokes_entry(entry) => {
                return Err(CoreError::PeerRevoked(peer_id.to_string()));
            }
            PeerState::Active => {}
        }
        let (static_pub, signing_pub) = entry.require_complete_pin()?;
        Ok(PinSnapshot {
            peer_id: peer_id.to_owned(),
            static_pub,
            signing_pub,
            rotation_seq: entry.rotation_seq,
            min_wire_version: entry.min_wire_version,
            route_meta: entry.route_meta,
        })
    }

    /// [`Self::insert_pinned_host`] followed by [`Self::merge_pair_plan`] as one transaction:
    /// on any error the roster is unchanged.
    pub fn insert_pinned_host_with_plan(
        &mut self,
        host_id: String,
        name: String,
        static_pub: [u8; 32],
        signing_pub: Option<HybridSigningPublicKey>,
        rotation_seq: u64,
        plan: &PersistPlan,
    ) -> Result<PairMergeOutcome, CoreError> {
        let mut staged = self.clone();
        staged.insert_pinned_host(
            host_id.clone(),
            name,
            static_pub,
            signing_pub,
            rotation_seq,
            Vec::new(),
        )?;
        let outcome = staged.merge_pair_plan(&host_id, plan)?;
        *self = staged;
        Ok(outcome)
    }

    /// [`Self::record_pending_host`] followed by [`Self::merge_pair_plan`] as one transaction:
    /// on any error the roster is unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn record_pending_host_with_plan(
        &mut self,
        host_id: String,
        name: String,
        static_pub: [u8; 32],
        signing_pub: HybridSigningPublicKey,
        rotation_seq: u64,
        pairing_sas: String,
        plan: &PersistPlan,
    ) -> Result<PairMergeOutcome, CoreError> {
        let mut staged = self.clone();
        let slot = staged.record_pending_host_slot(
            host_id,
            name,
            static_pub,
            signing_pub,
            rotation_seq,
            pairing_sas,
            Vec::new(),
        )?;
        let outcome = staged.with_host_slot(&slot, |r, id| r.merge_pair_plan(id, plan))?;
        *self = staged;
        Ok(outcome)
    }

    /// Merges a pairing's [`PersistPlan`] into the latest entry under the route high-water rule.
    ///
    /// `signed` routes are replaced when the plan's `rq` is above `route_meta.seq` (or there is
    /// no meta), unioned and capped at an equal `rq` (only the routes an explicit approval wrote
    /// are always kept; routes later equal-sequence merges added compete by rank), and kept with
    /// reason `stale_route_seq` below it. `committed` is replaced only by a
    /// plan `committed`; `operator` is added, never removed. `route_meta.seq` never decreases.
    /// Every plan route is validated first; on error nothing changes.
    pub fn merge_pair_plan(
        &mut self,
        peer_id: &str,
        plan: &PersistPlan,
    ) -> Result<PairMergeOutcome, CoreError> {
        let entry = self
            .entries
            .get(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if entry.state == PeerState::Revoked || self.crl_revokes_entry(entry) {
            return Err(CoreError::PeerRevoked(peer_id.to_string()));
        }
        let plan_signed =
            checked_source_list(plan.signed().iter().cloned(), RouteSource::Signed, entry)?;
        if let Some(rq) = plan.route_seq() {
            if !(1..=MAX_ROUTE_SEQ).contains(&rq) {
                return Err(invalid_route("route sequence out of range"));
            }
            let (k, sh) = plan
                .signed_host_keys()
                .ok_or(CoreError::HostKeyUnverified)?;
            self.check_signed_keys(peer_id, entry, k, sh)?;
        }
        let committed = checked_source_list(plan.committed.clone(), RouteSource::Committed, entry)?;
        let operator = checked_source_list(plan.operator.clone(), RouteSource::Operator, entry)?;
        if let Some(op) = operator.first()
            && !entry.has_route(op, RouteSource::Operator)
            && entry.routes_from(RouteSource::Operator).count() >= MAX_OPERATOR_ROUTES
        {
            return Err(invalid_route("at most 6 operator routes"));
        }

        let entry = self.entry_mut(peer_id)?;
        let mut reason = plan.reason;
        if let Some(rq) = plan.route_seq() {
            match entry.route_meta {
                Some(m) if rq < m.seq => reason = Some("stale_route_seq"),
                Some(m) if rq == m.seq => {
                    let approved = m.origin == RouteOrigin::Approved;
                    let (protected, mut others): (Vec<String>, Vec<String>) = entry
                        .hints_from(RouteSource::Signed)
                        .into_iter()
                        .partition(|h| approved && entry.approved_signed.contains(h));
                    others.extend(plan_signed);
                    let merged = cap_signed_union(protected, others);
                    entry.replace_source(RouteSource::Signed, merged);
                }
                _ => {
                    entry.replace_signed_unapproved(plan_signed);
                    entry.route_meta = Some(RouteMeta {
                        seq: rq,
                        issued_at: None,
                        origin: RouteOrigin::Uri,
                    });
                }
            }
        }
        if !committed.is_empty() {
            entry.replace_source(RouteSource::Committed, committed);
        }
        for hint in operator {
            if !entry.has_route(&hint, RouteSource::Operator) {
                entry.routes.push(StoredRoute {
                    hint,
                    source: RouteSource::Operator,
                });
            }
        }

        let planned = plan
            .signed()
            .iter()
            .map(|h| (h, RouteSource::Signed))
            .chain(plan.committed.iter().map(|h| (h, RouteSource::Committed)))
            .chain(plan.operator.iter().map(|h| (h, RouteSource::Operator)));
        let persisted = planned
            .filter(|(h, src)| entry.has_route(h, *src))
            .map(|(h, source)| StoredRoute {
                hint: h.clone(),
                source,
            })
            .collect();
        Ok(PairMergeOutcome { persisted, reason })
    }

    /// Replaces the `operator` routes of an `Active` peer with already-normalized endpoints.
    ///
    /// A `relay_key` must equal the Ed25519 component of this entry's pinned signing key, checked
    /// on the same pin this call writes under. A non-empty list also removes the `committed`
    /// record: the operator's routes supersede the route a past commit carried, so a stale
    /// enrolment endpoint never sticks. `signed` routes and `route_meta` are untouched. Returns
    /// the entry's full route list.
    pub fn set_routes(
        &mut self,
        peer_id: &str,
        endpoints: Vec<OperatorEndpoint>,
    ) -> Result<&[StoredRoute], CoreError> {
        let entry = self.require_active(peer_id)?;
        for ep in &endpoints {
            if let Some(key) = &ep.relay_key {
                let matches = entry
                    .signing_pub
                    .as_ref()
                    .is_some_and(|s| bool::from(s.ed25519_bytes().ct_eq(key)));
                if !matches {
                    return Err(invalid_route(
                        "relay key does not match the pinned host key",
                    ));
                }
            }
        }
        let hints = checked_source_list(
            endpoints.into_iter().map(|ep| ep.hint),
            RouteSource::Operator,
            entry,
        )?;
        let entry = self.entry_mut(peer_id)?;
        if !hints.is_empty() {
            entry.routes.retain(|r| r.source != RouteSource::Committed);
        }
        entry.replace_source(RouteSource::Operator, hints);
        Ok(&entry.routes)
    }

    /// Removes the routes of one source, or all routes. `route_meta` is kept so stale
    /// announcements stay rejected.
    pub fn clear_routes(
        &mut self,
        peer_id: &str,
        source: Option<RouteSource>,
    ) -> Result<(), CoreError> {
        let entry = self.entry_mut(peer_id)?;
        entry
            .routes
            .retain(|r| source.is_some_and(|s| r.source != s));
        if source.is_none_or(|s| s == RouteSource::Signed) {
            entry.approved_signed.clear();
        }
        Ok(())
    }

    fn statement_signed_list(
        &self,
        peer_id: &str,
        statement: &VerifiedRouteStatement,
    ) -> Result<Vec<String>, CoreError> {
        let entry = self.require_active(peer_id)?;
        self.check_signed_keys(peer_id, entry, statement.host_static_pub(), statement.sh())?;
        checked_source_list(
            statement
                .hints()
                .iter()
                .filter(|h| !is_ipc_hint(h))
                .cloned(),
            RouteSource::Signed,
            entry,
        )
    }

    /// Applies a fresh signed URI's routes: requires `rq > route_meta.seq` (or no meta), then
    /// replaces the `signed` routes and sets `route_meta = {rq, None, Uri}`.
    ///
    /// The statement must name this entry's pinned keys (`HostKeyUnverified`). Returns `false`
    /// without change when `rq` is not newer.
    pub fn replace_signed_routes(
        &mut self,
        peer_id: &str,
        statement: &VerifiedRouteStatement,
    ) -> Result<bool, CoreError> {
        let hints = self.statement_signed_list(peer_id, statement)?;
        let entry = self.entry_mut(peer_id)?;
        let rq = statement.route_seq();
        if entry.route_meta.is_some_and(|m| rq <= m.seq) {
            return Ok(false);
        }
        entry.replace_signed_unapproved(hints);
        entry.route_meta = Some(RouteMeta {
            seq: rq,
            issued_at: None,
            origin: RouteOrigin::Uri,
        });
        Ok(true)
    }

    /// Explicitly approved replacement: replaces the `signed` routes whatever the sequence and
    /// sets `route_meta = {max(stored, rq), None, Approved}`, so equal-sequence sets cannot
    /// undo it.
    pub fn replace_routes_approved(
        &mut self,
        peer_id: &str,
        statement: &VerifiedRouteStatement,
    ) -> Result<(), CoreError> {
        let hints = self.statement_signed_list(peer_id, statement)?;
        let entry = self.entry_mut(peer_id)?;
        let seq = entry
            .route_meta
            .map_or(0, |m| m.seq)
            .max(statement.route_seq());
        entry.replace_source(RouteSource::Signed, hints.clone());
        entry.approved_signed = hints;
        entry.route_meta = Some(RouteMeta {
            seq,
            issued_at: None,
            origin: RouteOrigin::Approved,
        });
        Ok(())
    }

    /// Ingests CRLs a candidate roster clone accepted, verifying each against the issuer key
    /// this roster holds: an active paired peer's or an active trust anchor's. Unverifiable,
    /// stale or unknown-issuer lists are skipped. Returns the number ingested.
    pub fn merge_crl_evidence(&mut self, crls: &[(String, RevocationList)]) -> usize {
        let mut ingested = 0;
        for (issuer, crl) in crls {
            let Some(key) = self
                .lookup_active_signing_key(issuer)
                .or_else(|| self.lookup_active_anchor_key(issuer))
            else {
                continue;
            };
            if self.ingest_crl(crl.clone(), issuer, &key).is_ok() {
                ingested += 1;
            }
        }
        ingested
    }

    /// Client acceptance of a host route set, in order: active
    /// peer, key binding, signature, issue time, sequence, then an atomic replacement of the
    /// `signed` routes. `operator` and `committed` routes are never touched.
    pub fn apply_route_announcement(
        &mut self,
        peer_id: &str,
        set: &RouteSet,
        now_unix: u64,
    ) -> Result<RouteSetOutcome, CoreError> {
        let ignored = |r| Ok(RouteSetOutcome::Ignored(r));
        let Ok(entry) = self.require_active(peer_id) else {
            return ignored(RouteSetIgnored::PeerInactive);
        };
        let Some(signing_pub) = entry.signing_pub.as_ref() else {
            return ignored(RouteSetIgnored::KeyMismatch);
        };
        if set.static_pub != entry.static_pub
            || !bool::from(signing_pub.sha256_hash().ct_eq(&set.sh))
        {
            return ignored(RouteSetIgnored::KeyMismatch);
        }
        if set.verify(signing_pub).is_err() {
            return ignored(RouteSetIgnored::BadSignature);
        }
        if set.issued_at > now_unix.saturating_add(MAX_ROUTE_SET_FUTURE_SECS) {
            return ignored(RouteSetIgnored::FutureIssuedAt);
        }
        if let Some(m) = entry.route_meta
            && !(set.seq > m.seq || (set.seq == m.seq && m.origin == RouteOrigin::Uri))
        {
            return ignored(RouteSetIgnored::StaleSeq);
        }
        let hints = checked_source_list(set.routes.iter().cloned(), RouteSource::Signed, entry)?;
        let entry = self.entry_mut(peer_id)?;
        let before = entry.hints_from(RouteSource::Signed);
        let added = hints
            .iter()
            .filter(|h| !before.contains(h))
            .cloned()
            .collect();
        let removed = before
            .iter()
            .filter(|h| !hints.contains(h))
            .cloned()
            .collect();
        entry.replace_signed_unapproved(hints);
        entry.route_meta = Some(RouteMeta {
            seq: set.seq,
            issued_at: Some(set.issued_at),
            origin: RouteOrigin::Session,
        });
        Ok(RouteSetOutcome::Applied { added, removed })
    }

    /// Final authorization of an established session (shared by native and WASM): the entry
    /// exists, is `Active` and not CRL-revoked, its wire floor allows `negotiated_wire`, and the
    /// session's keys equal the pin.
    pub fn check_established_session(
        &self,
        peer_id: &str,
        static_pub: &[u8; 32],
        signing_pub: &HybridSigningPublicKey,
        negotiated_wire: u8,
    ) -> Result<(), CoreError> {
        let entry = self.require_active(peer_id)?;
        if entry.min_wire_version > negotiated_wire {
            return Err(CoreError::VersionDowngrade {
                peer_min: entry.min_wire_version,
                negotiated: negotiated_wire,
            });
        }
        let signing_matches = entry.signing_pub.as_ref() == Some(signing_pub);
        if !bool::from(entry.static_pub.ct_eq(static_pub)) || !signing_matches {
            return Err(CoreError::HostKeyUnverified);
        }
        Ok(())
    }

    /// Reconciles rotation records every Day-2 candidate was shown against the pin the connect
    /// started from.
    ///
    /// Keeps records that verify individually and are reachable from `original`'s signing key at
    /// `seq > original.rotation_seq`, then runs fork detection over them. A fork revokes the
    /// entry and its siblings as [`Self::apply_verified_rotation`] does and returns
    /// `RotationForkDetected`. A snapshot taken of another roster key fails with
    /// `HostKeyUnverified` before any change.
    pub fn reconcile_rotation_evidence(
        &mut self,
        peer_id: &str,
        original: &PinSnapshot,
        records: &[RotationRecord],
    ) -> Result<(), CoreError> {
        if !self.entries.contains_key(peer_id) {
            return Err(CoreError::PeerNotFound(peer_id.to_string()));
        }
        if original.peer_id != peer_id {
            return Err(CoreError::HostKeyUnverified);
        }
        let verified: Vec<(&RotationRecord, _)> = records
            .iter()
            .filter_map(|r| verify_rotation_record(r).ok().map(|v| (r, v)))
            .filter(|(_, v)| v.seq > original.rotation_seq)
            .collect();
        let mut trusted = vec![original.signing_pub.clone()];
        loop {
            let before = trusted.len();
            for (_, v) in &verified {
                if trusted.contains(&v.prev_signing_pub) && !trusted.contains(&v.new_signing_pub) {
                    trusted.push(v.new_signing_pub.clone());
                }
            }
            if trusted.len() == before {
                break;
            }
        }
        let reachable: Vec<RotationRecord> = verified
            .iter()
            .filter(|(_, v)| trusted.contains(&v.prev_signing_pub))
            .map(|(r, _)| (*r).clone())
            .collect();
        match detect_rotation_fork(&reachable) {
            Err(err @ CoreError::RotationForkDetected { .. }) => {
                let entry = self.entry_mut(peer_id)?;
                entry.state = PeerState::Revoked;
                entry.grants.clear();
                entry.v2_secrets = None;
                let current = (entry.static_pub, entry.signing_pub.clone());
                self.revoke_siblings_by_keys(current.0, current.1.as_ref());
                self.revoke_siblings_by_keys(original.static_pub, Some(&original.signing_pub));
                Err(err)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_pending_pair_key_rules() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let st = *StaticKeypair::from_scalar([0x61u8; 32]).public_bytes();
        let id = device_id(&st);
        let key = SigningKeypair::from_seed([0x62u8; 32]).public_key().clone();
        let other = SigningKeypair::from_seed([0x63u8; 32]).public_key().clone();
        let rec = |r: &mut Roster, k: Option<HybridSigningPublicKey>, sas: &str| {
            r.record_pending_pair(st, k, "Peer".into(), "cli".into(), sas.into())
                .map(|e| (e.state, e.signing_pub.clone()))
        };

        // New entry with a key.
        let mut fresh = Roster::new();
        assert_eq!(
            rec(&mut fresh, Some(key.clone()), "s1"),
            Ok((PeerState::Pending, Some(key.clone())))
        );

        // Pending keyless: key set, stays Pending.
        let mut pending = Roster::new();
        rec(&mut pending, None, "s1").unwrap();
        assert_eq!(
            rec(&mut pending, Some(key.clone()), "s2"),
            Ok((PeerState::Pending, Some(key.clone())))
        );

        // Pending keyed: a keyless claim cannot move the SAS that guards the unconfirmed key.
        let before = serde_json::to_value(&pending).unwrap();
        assert_eq!(
            rec(&mut pending, None, "s3"),
            Err(CoreError::ProtocolViolation(
                "keyless claim cannot supersede an unconfirmed signing key"
            ))
        );
        assert_eq!(serde_json::to_value(&pending).unwrap(), before);
        assert!(pending.confirm_peer(&id, Some("s3")).is_err());
        assert_eq!(pending.lookup_active_signing_key(&id), None);
        pending.confirm_peer(&id, Some("s2")).unwrap();
        assert_eq!(pending.lookup_active_signing_key(&id), Some(key.clone()));

        // Active keyless: enrichment returns it to Pending until the new SAS is confirmed.
        let host = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x64u8; 32]),
            SigningKeypair::from_seed([0x65u8; 32]),
        );
        let mut active = Roster::new();
        rec(&mut active, None, "s1").unwrap();
        active.confirm_peer(&id, Some("s1")).unwrap();
        let grant = active
            .mint_grant(&host, &id, vec!["file.read:*".into()], 10, 20, [1u8; 16])
            .unwrap();
        assert_eq!(active.lookup_active_signing_key(&id), None);
        assert_eq!(
            rec(&mut active, Some(key.clone()), "s2"),
            Ok((PeerState::Pending, Some(key.clone())))
        );
        assert_eq!(active.get(&id).unwrap().grants, vec![grant.clone()]);
        assert_eq!(active.lookup_active_signing_key(&id), None);
        assert!(active.confirm_peer(&id, Some("s1")).is_err());
        active.confirm_peer(&id, Some("s2")).unwrap();
        assert_eq!(active.lookup_active_signing_key(&id), Some(key.clone()));
        assert_eq!(active.get(&id).unwrap().grants, vec![grant]);

        // Equal key keeps state.
        assert_eq!(
            rec(&mut active, Some(key.clone()), "s3"),
            Ok((PeerState::Active, Some(key.clone())))
        );
        assert_eq!(active.lookup_active_signing_key(&id), Some(key.clone()));
        // Keyless claim on a keyed entry keeps the pin and state.
        assert_eq!(
            rec(&mut active, None, "s4"),
            Ok((PeerState::Active, Some(key.clone())))
        );

        // Differing key is refused with no mutation.
        let before = serde_json::to_value(&active).unwrap();
        assert_eq!(
            rec(&mut active, Some(other.clone()), "s5"),
            Err(CoreError::ProtocolViolation(
                "cannot replace pinned signing key; rotate or revoke"
            ))
        );
        assert_eq!(serde_json::to_value(&active).unwrap(), before);
        assert_eq!(active.lookup_active_signing_key(&id), Some(key.clone()));

        // An entry with the same static key under another label (a `host_id`, or a label kept
        // across rotation) pins its key too.
        let mut labelled = Roster::new();
        labelled
            .insert_pinned_host(
                "stable-host-id".into(),
                "Host".into(),
                st,
                Some(key.clone()),
                0,
                Vec::new(),
            )
            .unwrap();
        let before = serde_json::to_value(&labelled).unwrap();
        assert_eq!(
            rec(&mut labelled, Some(other.clone()), "s1"),
            Err(CoreError::ProtocolViolation(
                "cannot replace pinned signing key; rotate or revoke"
            ))
        );
        assert_eq!(serde_json::to_value(&labelled).unwrap(), before);

        // Revoked stays revoked, with either key.
        active.revoke_peer(&id).unwrap();
        assert_eq!(
            rec(&mut active, Some(key.clone()), "s6"),
            Err(CoreError::PeerRevoked(id.clone()))
        );
        let before = serde_json::to_value(&active).unwrap();
        assert_eq!(
            rec(&mut active, Some(other.clone()), "s7"),
            Err(CoreError::PeerRevoked(id.clone()))
        );
        assert_eq!(serde_json::to_value(&active).unwrap(), before);
        assert_eq!(active.get(&id).unwrap().state, PeerState::Revoked);

        // A key that shares identity with a revoked sibling entry or anchor is revoked.
        let sibling_st = *StaticKeypair::from_scalar([0x66u8; 32]).public_bytes();
        let mut sibling = Roster::new();
        sibling
            .record_pending_pair(
                sibling_st,
                Some(key.clone()),
                "S".into(),
                "cli".into(),
                "x".into(),
            )
            .unwrap();
        sibling.revoke_peer(&device_id(&sibling_st)).unwrap();
        assert_eq!(
            rec(&mut sibling, Some(key.clone()), "s1"),
            Err(CoreError::PeerRevoked(id.clone()))
        );
        assert!(sibling.get(&id).is_none());
        let mut anchored = Roster::new();
        anchored
            .add_trust_anchor("anchor".into(), other.clone())
            .unwrap();
        anchored.revoke_trust_anchor("anchor").unwrap();
        assert_eq!(
            rec(&mut anchored, Some(other), "s1"),
            Err(CoreError::PeerRevoked(id.clone()))
        );
        assert!(anchored.get(&id).is_none());
    }

    #[test]
    fn revoked_duplicate_static_pub_takes_precedence_and_blocks_session_lookup() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let mut roster = Roster::new();
        let pub_k = *StaticKeypair::from_scalar([0x33u8; 32]).public_bytes();
        let sig_k = SigningKeypair::from_seed([0x44u8; 32]).public_key().clone();
        roster
            .insert_pinned_host(
                "aa_revoked_host".to_string(),
                "Revoked".to_string(),
                pub_k,
                Some(sig_k.clone()),
                0,
                vec![],
            )
            .unwrap();
        roster.revoke_peer("aa_revoked_host").unwrap();

        assert!(matches!(
            roster.insert_pinned_host(
                "zz_active_host".to_string(),
                "Active".to_string(),
                pub_k,
                Some(sig_k),
                0,
                vec![],
            ),
            Err(CoreError::PeerRevoked(_))
        ));
        assert!(roster.get("zz_active_host").is_none());

        // A tampered or legacy serialized roster can still carry an Active duplicate beside the
        // Revoked entry, so lookups must keep revocation precedence.
        let mut tampered = serde_json::to_value(&roster).unwrap();
        let mut dup = serde_json::to_value(roster.get("aa_revoked_host").unwrap()).unwrap();
        dup["device_id"] = "zz_active_host".into();
        dup["state"] = "active".into();
        tampered["entries"]["zz_active_host"] = dup;
        let tampered: Roster = serde_json::from_value(tampered).unwrap();
        assert_eq!(
            tampered.get("zz_active_host").unwrap().state,
            PeerState::Active
        );
        assert!(matches!(
            tampered.lookup_active_by_static(&pub_k),
            Err(CoreError::PeerRevoked(_))
        ));
        assert_eq!(tampered.lookup_active_signing_key("zz_active_host"), None);
    }

    #[test]
    fn retain_active_drops_only_active_entries_and_their_pins() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let mut roster = Roster::new();
        for (key, n) in [("active", 0x41), ("revoked", 0x42)] {
            roster
                .insert_pinned_host(
                    key.to_string(),
                    key.to_string(),
                    *StaticKeypair::from_scalar([n; 32]).public_bytes(),
                    None,
                    0,
                    vec![],
                )
                .unwrap();
            roster
                .pin_signing_hash(
                    key,
                    SigningKeypair::from_seed([n; 32])
                        .public_key()
                        .sha256_hash(),
                )
                .unwrap();
            roster
                .add_rendezvous_alternate(key, V2PeerSecrets::new([n; 32], [n; 32]))
                .unwrap();
        }
        roster.revoke_peer("revoked").unwrap();
        roster.retain_active(|_, _| false);
        assert!(roster.get("active").is_none());
        assert!(!roster.is_manifest_pinned("active"));
        assert!(roster.rendezvous_alternates("active").is_empty());
        assert_eq!(roster.get("revoked").unwrap().state, PeerState::Revoked);
    }

    #[test]
    fn sec01_rotation_onto_crl_revoked_identity_is_refused() {
        use crate::crypto::{SigningKeypair, StaticKeypair};
        use crate::grants::{RevocationListUnsigned, sign_crl};
        use crate::identity::sign_rotation;

        let root_sk = SigningKeypair::from_seed([0x11; 32]);
        let old_static = *StaticKeypair::from_scalar([0x21; 32]).public_bytes();
        let old_sk = SigningKeypair::from_seed([0x22; 32]);
        let next_static = *StaticKeypair::from_scalar([0x31; 32]).public_bytes();
        let next_sig = SigningKeypair::from_seed([0x32; 32]).public_key().clone();

        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                "rotating-host".into(),
                "Host".into(),
                old_static,
                Some(old_sk.public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: "root-id".into(),
                seq: 1,
                revoked_devices: vec![device_id(&next_static)],
                revoked_nonces: vec![],
                ts: "2026-11-20T00:00:00Z".into(),
            },
            &root_sk,
        )
        .unwrap();
        roster
            .ingest_crl(crl, "root-id", root_sk.public_key())
            .unwrap();

        let rec = sign_rotation(1, &old_sk, &next_sig, &next_static, 1_795_133_000).unwrap();
        assert!(matches!(
            roster.apply_verified_rotation("rotating-host", &[rec], &next_static, &next_sig),
            Err(CoreError::PeerRevoked(_))
        ));
        let entry = roster.get("rotating-host").unwrap();
        assert_eq!(entry.static_pub, old_static);
        assert_eq!(entry.rotation_seq, 0);
    }

    #[test]
    fn update_relay_hints_preserves_pins_and_rejects_revoked_or_missing() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let mut roster = Roster::new();
        let pub_k = *StaticKeypair::from_scalar([0x55u8; 32]).public_bytes();
        let sig_k = SigningKeypair::from_seed([0x66u8; 32]).public_key().clone();
        roster
            .insert_pinned_host(
                "host-a".to_string(),
                "Host A".to_string(),
                pub_k,
                Some(sig_k.clone()),
                3,
                vec!["wss://relay1.example/v1/relay".to_string()],
            )
            .unwrap();

        let updated = roster
            .update_relay_hints("host-a", vec!["wss://relay2.example/v1/relay".to_string()])
            .unwrap();
        assert_eq!(updated.static_pub, pub_k);
        assert_eq!(updated.signing_pub, Some(sig_k));
        assert_eq!(updated.rotation_seq, 3);
        assert_eq!(
            updated.relay_hints,
            vec!["wss://relay2.example/v1/relay".to_string()]
        );

        assert!(matches!(
            roster.update_relay_hints("missing", vec![]),
            Err(CoreError::PeerNotFound(_))
        ));
        roster.revoke_peer("host-a").unwrap();
        assert!(matches!(
            roster.update_relay_hints("host-a", vec![]),
            Err(CoreError::PeerRevoked(_))
        ));
    }

    #[test]
    fn sec01_insert_and_pending_host_refuse_overwrite_and_gate_on_confirm() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let mut roster = Roster::new();
        let k1 = *StaticKeypair::from_scalar([0x21; 32]).public_bytes();
        let s1 = SigningKeypair::from_seed([0x22; 32]).public_key().clone();
        let k2 = *StaticKeypair::from_scalar([0x23; 32]).public_bytes();
        let s2 = SigningKeypair::from_seed([0x24; 32]).public_key().clone();

        roster
            .insert_pinned_host(
                "host-x".into(),
                "Host X".into(),
                k1,
                Some(s1.clone()),
                0,
                vec![],
            )
            .unwrap();
        assert!(matches!(
            roster.insert_pinned_host(
                "host-x".into(),
                "Evil".into(),
                k2,
                Some(s2.clone()),
                0,
                vec![]
            ),
            Err(CoreError::ProtocolViolation(_))
        ));
        assert!(matches!(
            roster.record_pending_host(
                "host-x".into(),
                "Evil".into(),
                k2,
                s2.clone(),
                0,
                "evil sas1".into(),
                vec![],
            ),
            Err(CoreError::ProtocolViolation(_))
        ));
        assert_eq!(roster.get("host-x").unwrap().static_pub, k1);

        // Fresh unpinned manual host enters Pending and requires matching SAS confirm_peer.
        let pend = roster
            .record_pending_host(
                "host-y".into(),
                "Host Y".into(),
                k1,
                s1,
                0,
                "abcd 1234 efgh 5678".into(),
                vec![],
            )
            .unwrap();
        assert_eq!(pend.state, PeerState::Pending);
        assert!(matches!(
            roster.confirm_peer("host-y", Some("wrong sas")),
            Err(CoreError::ProtocolViolation(_))
        ));
        assert!(matches!(
            roster.remove_pending_peer("host-x"),
            Err(CoreError::ProtocolViolation(_))
        ));
        roster
            .confirm_peer("host-y", Some("abcd 1234 efgh 5678"))
            .unwrap();
        assert_eq!(roster.get("host-y").unwrap().state, PeerState::Active);

        // Unconfirmed pending host can be cleanly discarded via remove_pending_peer.
        roster
            .record_pending_host(
                "host-z".into(),
                "Host Z".into(),
                k2,
                s2,
                0,
                "bad sas".into(),
                vec![],
            )
            .unwrap();
        roster.remove_pending_peer("host-z").unwrap();
        assert!(roster.get("host-z").is_none());
    }

    #[test]
    fn rejects_weak_ed25519_keys_across_roster_pins() {
        use crate::crypto::{HYBRID_SIGNING_PUB_LEN, SigningKeypair, StaticKeypair};

        let valid = SigningKeypair::from_seed([0x29; 32]);
        let mut zero_hybrid = vec![0u8; HYBRID_SIGNING_PUB_LEN];
        zero_hybrid[32..].copy_from_slice(valid.public_key().mldsa65_bytes());
        assert_eq!(
            HybridSigningPublicKey::from_bytes(&zero_hybrid),
            Err(CoreError::InvalidSignature)
        );

        let mut weak_hybrid = zero_hybrid;
        weak_hybrid[0] = 1;
        assert_eq!(
            HybridSigningPublicKey::from_bytes(&weak_hybrid),
            Err(CoreError::InvalidSignature)
        );
        assert_eq!(
            HybridSigningPublicKey::from_bytes(&valid.public_bytes()[..32]),
            Err(CoreError::InvalidLength {
                expected: HYBRID_SIGNING_PUB_LEN,
                actual: 32
            })
        );

        // Revocation propagates across entries sharing the same 32-byte Ed25519 relay prefix.
        let same_ed_diff_pq = SigningKeypair::from_seeds(*valid.seed_bytes(), [0x99u8; 32]);
        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                "host-a".into(),
                "Host A".into(),
                *StaticKeypair::from_scalar([0x21; 32]).public_bytes(),
                Some(valid.public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        roster.revoke_peer("host-a").unwrap();
        assert!(matches!(
            roster.record_enrolled_machine(
                *StaticKeypair::from_scalar([0x22; 32]).public_bytes(),
                same_ed_diff_pq.public_key().clone(),
                "Sibling".into(),
                "cli".into(),
            ),
            Err(CoreError::PeerRevoked(_))
        ));
    }

    #[test]
    fn crl_and_rotation_fork_propagate_revocation_to_sibling_entries() {
        use crate::crypto::{SigningKeypair, StaticKeypair};
        use crate::grants::{RevocationListUnsigned, sign_crl};
        use crate::identity::sign_rotation;

        let root_sk = SigningKeypair::from_seed([0x11; 32]);
        let root_pub = root_sk.public_key().clone();

        let alias_static = *StaticKeypair::from_scalar([0x22; 32]).public_bytes();
        let alias_sk = SigningKeypair::from_seed([0x23; 32]);
        let alias_sig = alias_sk.public_key().clone();

        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                "alias-a".into(),
                "Alias A".into(),
                alias_static,
                Some(alias_sig.clone()),
                0,
                vec![],
            )
            .unwrap();
        roster
            .insert_pinned_host(
                "alias-b".into(),
                "Alias B".into(),
                alias_static,
                Some(alias_sig),
                0,
                vec![],
            )
            .unwrap();

        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: "root-id".into(),
                seq: 1,
                revoked_devices: vec!["alias-a".into()],
                revoked_nonces: vec![],
                ts: "2026-11-20T00:00:00Z".into(),
            },
            &root_sk,
        )
        .unwrap();
        roster.ingest_crl(crl, "root-id", &root_pub).unwrap();
        assert_eq!(roster.get("alias-a").unwrap().state, PeerState::Revoked);
        assert_eq!(roster.get("alias-b").unwrap().state, PeerState::Revoked);

        let fork_static = *StaticKeypair::from_scalar([0x31; 32]).public_bytes();
        let fork_sk = SigningKeypair::from_seed([0x32; 32]);
        let fork_pub = fork_sk.public_key().clone();
        roster
            .insert_pinned_host(
                "fork-a".into(),
                "Fork A".into(),
                fork_static,
                Some(fork_pub.clone()),
                0,
                vec![],
            )
            .unwrap();
        roster
            .insert_pinned_host(
                "fork-b".into(),
                "Fork B".into(),
                fork_static,
                Some(fork_pub),
                0,
                vec![],
            )
            .unwrap();

        let next_stat_1 = *StaticKeypair::from_scalar([0x41; 32]).public_bytes();
        let next_sig_1 = SigningKeypair::from_seed([0x42; 32]).public_key().clone();
        let next_stat_2 = *StaticKeypair::from_scalar([0x51; 32]).public_bytes();
        let next_sig_2 = SigningKeypair::from_seed([0x52; 32]).public_key().clone();
        let rec1 = sign_rotation(1, &fork_sk, &next_sig_1, &next_stat_1, 1_795_133_000).unwrap();
        let rec2 = sign_rotation(1, &fork_sk, &next_sig_2, &next_stat_2, 1_795_133_001).unwrap();

        let fork_res =
            roster.apply_verified_rotation("fork-a", &[rec1, rec2], &next_stat_1, &next_sig_1);
        assert!(matches!(
            fork_res,
            Err(CoreError::RotationForkDetected { seq: 1 })
        ));
        assert_eq!(roster.get("fork-a").unwrap().state, PeerState::Revoked);
        assert_eq!(roster.get("fork-b").unwrap().state, PeerState::Revoked);
    }

    fn host_keys(seed: u8) -> ([u8; 32], HybridSigningPublicKey) {
        use crate::crypto::{SigningKeypair, StaticKeypair};
        (
            *StaticKeypair::from_scalar([seed; 32]).public_bytes(),
            SigningKeypair::from_seed([seed.wrapping_add(1); 32])
                .public_key()
                .clone(),
        )
    }

    #[test]
    fn unconfirmed_host_claim_does_not_block_pairing_with_the_real_host() {
        let (real_st, real_sig) = host_keys(0x71);
        let (other_st, other_sig) = host_keys(0x73);

        let mut base = Roster::new();
        base.record_pending_host(
            "host-x".into(),
            "Host X".into(),
            other_st,
            other_sig,
            0,
            "other sas".into(),
            vec![],
        )
        .unwrap();

        // A later unpinned pairing with the real host records and confirms under its host_id.
        let mut unpinned = base.clone();
        unpinned
            .record_pending_host(
                "host-x".into(),
                "Host X".into(),
                real_st,
                real_sig.clone(),
                0,
                "real sas".into(),
                vec![],
            )
            .unwrap();
        assert!(matches!(
            unpinned.confirm_peer("host-x", Some("wrong sas")),
            Err(CoreError::ProtocolViolation(_))
        ));
        let confirmed = unpinned.confirm_peer("host-x", Some("real sas")).unwrap();
        assert_eq!(confirmed.state, PeerState::Active);
        assert_eq!(confirmed.static_pub, real_st);
        assert_eq!(confirmed.device_id, "host-x");
        assert_eq!(unpinned.get("host-x").unwrap().static_pub, real_st);

        // A later pinned pairing with the real host pins it directly.
        let mut pinned = base;
        pinned
            .insert_pinned_host(
                "host-x".into(),
                "Host X".into(),
                real_st,
                Some(real_sig),
                0,
                vec![],
            )
            .unwrap();
        let entry = pinned.get("host-x").unwrap();
        assert_eq!(
            (entry.state, entry.static_pub),
            (PeerState::Active, real_st)
        );
    }

    #[test]
    fn rejecting_an_unconfirmed_host_claim_never_revokes_its_host_id() {
        let (real_st, real_sig) = host_keys(0x75);
        let (other_st, other_sig) = host_keys(0x77);
        let claim = |r: &mut Roster| {
            r.record_pending_host(
                "host-x".into(),
                "Host X".into(),
                other_st,
                other_sig.clone(),
                0,
                "other sas".into(),
                vec![],
            )
            .map(|_| ())
        };

        // Revoking the claim revokes its keys, not the host_id it named.
        let mut revoked = Roster::new();
        claim(&mut revoked).unwrap();
        revoked.revoke_peer("host-x").unwrap();
        assert!(matches!(
            revoked.record_pending_host(
                "host-y".into(),
                "Host Y".into(),
                other_st,
                other_sig.clone(),
                0,
                "again".into(),
                vec![],
            ),
            Err(CoreError::PeerRevoked(_))
        ));
        revoked
            .insert_pinned_host(
                "host-x".into(),
                "Host X".into(),
                real_st,
                Some(real_sig.clone()),
                0,
                vec![],
            )
            .unwrap();
        assert_eq!(revoked.get("host-x").unwrap().state, PeerState::Active);

        // Removing the claim leaves no trace.
        let mut removed = Roster::new();
        claim(&mut removed).unwrap();
        removed.remove_pending_peer("host-x").unwrap();
        assert_eq!(removed.entries().count(), 0);
        removed
            .record_pending_host(
                "host-x".into(),
                "Host X".into(),
                real_st,
                real_sig,
                0,
                "real sas".into(),
                vec![],
            )
            .unwrap();
        removed.confirm_peer("host-x", Some("real sas")).unwrap();
        assert_eq!(removed.get("host-x").unwrap().static_pub, real_st);
    }

    #[test]
    fn removing_host_claims_never_touches_entries() {
        let claimed = host_keys(0x3d);
        let inbound = host_keys(0x3f);
        let label = device_id(&inbound.0);
        let mut roster = Roster::new();
        roster
            .record_pending_pair(
                inbound.0,
                Some(inbound.1.clone()),
                "Inbound".into(),
                "cli".into(),
                "sas".into(),
            )
            .unwrap();
        // A hostile host names the id of a real inbound device.
        record_claim(&mut roster, &label, &claimed, "sas c").unwrap();
        assert_eq!(roster.pending_hosts().count(), 1);

        roster.remove_pending_host_claims(&label).unwrap();
        assert_eq!(roster.pending_hosts().count(), 0);
        assert_eq!(
            roster.get(&label).map(|e| e.state),
            Some(PeerState::Pending),
            "the inbound device survives"
        );
        assert_eq!(
            roster.remove_pending_host_claims(&label),
            Err(CoreError::PeerNotFound(label.clone()))
        );

        // An active or revoked entry is no claim: not found, and untouched.
        let active = host_keys(0x41);
        roster
            .insert_pinned_host(
                "act".into(),
                "A".into(),
                active.0,
                Some(active.1),
                0,
                vec![],
            )
            .unwrap();
        assert_eq!(
            roster.remove_pending_host_claims("act"),
            Err(CoreError::PeerNotFound("act".into()))
        );
        roster.revoke_peer("act").unwrap();
        assert_eq!(
            roster.remove_pending_host_claims("act"),
            Err(CoreError::PeerNotFound("act".into()))
        );
        assert_eq!(roster.get("act").map(|e| e.state), Some(PeerState::Revoked));
    }

    #[test]
    fn a_claim_coexisting_with_a_rotated_active_entry_is_removed_alone() {
        use crate::crypto::{SigningKeypair, StaticKeypair};
        use crate::identity::sign_rotation;

        let k0 = *StaticKeypair::from_scalar([0xF1; 32]).public_bytes();
        let s0 = SigningKeypair::from_seed([0xF2; 32]);
        let k1 = *StaticKeypair::from_scalar([0xF3; 32]).public_bytes();
        let s1 = SigningKeypair::from_seed([0xF4; 32]);
        let mut active = Roster::new();
        active
            .insert_pinned_host(
                "act".into(),
                "Active".into(),
                k0,
                Some(s0.public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        let rec = sign_rotation(1, &s0, s1.public_key(), &k1, 1_795_133_000).unwrap();
        active
            .apply_verified_rotation("act", &[rec], &k1, s1.public_key())
            .unwrap();
        let mut claimed = Roster::new();
        record_claim(&mut claimed, "act", &host_keys(0xF5), "sas").unwrap();
        let claims = serde_json::to_value(&claimed).unwrap()["pending_hosts"].clone();

        // A stored roster holding both: the claim never replaces the active entry.
        let mut roster = reload(&active, |j| j["pending_hosts"] = claims);
        assert_eq!(roster.pending_hosts().count(), 1);
        assert_eq!(roster.get("act").unwrap().state, PeerState::Active);

        roster.remove_pending_host_claims("act").unwrap();
        assert_eq!(roster.pending_hosts().count(), 0);
        let kept = roster.get("act").unwrap();
        assert_eq!((kept.state, kept.static_pub), (PeerState::Active, k1));
        assert_eq!(kept.rotation_seq, 1);
    }

    #[test]
    fn host_claims_wait_outside_entries_and_confirm_by_sas() {
        let real = host_keys(0x79);
        let other = host_keys(0x7b);
        let mut roster = Roster::new();
        record_claim(&mut roster, "named", &real, "sas n").unwrap();
        record_claim(&mut roster, "named", &other, "sas o").unwrap();
        assert_eq!(roster.entries().count(), 0);
        assert_eq!(roster.pending_hosts().count(), 2);
        assert!(roster.get("named").is_none());
        assert!(roster.get_or_pending_host("named").is_none());
        assert_eq!(
            roster.missing_peer_error("named"),
            CoreError::PeerPending("named".into())
        );

        // A repeat claim from the same key replaces its earlier one.
        record_claim(&mut roster, "named", &real, "sas n2").unwrap();
        assert_eq!(roster.pending_hosts().count(), 2);
        assert!(matches!(
            roster.confirm_peer("named", Some("sas n")),
            Err(CoreError::ProtocolViolation(_))
        ));

        let promoted = roster.confirm_peer("named", Some("sas n2")).unwrap();
        assert_eq!(
            (promoted.state, promoted.static_pub),
            (PeerState::Active, real.0)
        );
        assert_eq!(promoted.device_id, "named");
        assert_eq!(roster.pending_hosts().count(), 0);

        // The pending store survives a reload.
        let mut stored = Roster::new();
        record_claim(&mut stored, "named", &other, "sas o").unwrap();
        let loaded = reload(&stored, |_| {});
        assert_eq!(loaded.pending_hosts().count(), 1);
        assert_eq!(
            loaded.get_or_pending_host("named").unwrap().static_pub,
            other.0
        );
    }

    fn record_claim(
        r: &mut Roster,
        host_id: &str,
        keys: &([u8; 32], HybridSigningPublicKey),
        sas: &str,
    ) -> Result<(), CoreError> {
        r.record_pending_host(
            host_id.into(),
            "Host".into(),
            keys.0,
            keys.1.clone(),
            0,
            sas.into(),
            vec![],
        )
        .map(|_| ())
    }

    /// `roster` as stored JSON with `edit` applied, loaded back.
    fn reload(roster: &Roster, edit: impl FnOnce(&mut serde_json::Value)) -> Roster {
        let mut json = serde_json::to_value(roster).unwrap();
        edit(&mut json);
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn default_host_id_claims_are_held_like_any_other() {
        let real = host_keys(0x81);
        let other = host_keys(0x83);
        let label = device_id(&real.0);
        let mut base = Roster::new();
        record_claim(&mut base, &label, &real, "real sas").unwrap();
        record_claim(&mut base, &label, &other, "other sas").unwrap();
        let other_id = device_id(&other.0);

        let mut ambiguous = base.clone();
        assert!(matches!(
            ambiguous.confirm_peer_without_sas(&label),
            Err(CoreError::ProtocolViolation(_))
        ));
        // Revoking by the id derived from a static key reaches only that key's claim.
        ambiguous.revoke_peer(&label).unwrap();
        let left: Vec<_> = ambiguous.pending_hosts().map(|e| e.static_pub).collect();
        assert_eq!(left, vec![other.0]);

        let mut removed = base.clone();
        removed.remove_pending_peer(&label).unwrap();
        assert!(removed.get_or_pending_host(&label).is_none());
        assert_eq!(
            removed.missing_peer_error(&label),
            CoreError::PeerNotFound(label.clone())
        );

        let mut confirmed = base.clone();
        confirmed.confirm_peer(&label, Some("real sas")).unwrap();
        assert_eq!(confirmed.get(&label).unwrap().state, PeerState::Active);
        assert!(
            !serde_json::to_string(&confirmed)
                .unwrap()
                .contains(&other_id)
        );

        let mut enrolled = base;
        enrolled
            .record_enrolled_machine(real.0, real.1.clone(), "Host".into(), "host".into())
            .unwrap();
        assert!(
            !serde_json::to_string(&enrolled)
                .unwrap()
                .contains(&other_id)
        );
    }

    #[test]
    fn host_ids_are_hash_free_and_bounded() {
        let keys = host_keys(0x85);
        let longest = "h".repeat(256);
        for bad in ["a#b".to_string(), "h".repeat(257)] {
            let mut r = Roster::new();
            assert!(record_claim(&mut r, &bad, &keys, "sas").is_err(), "{bad}");
            assert!(
                r.insert_pinned_host(
                    bad.clone(),
                    "H".into(),
                    keys.0,
                    Some(keys.1.clone()),
                    0,
                    vec![]
                )
                .is_err(),
                "{bad}"
            );
        }
        let mut r = Roster::new();
        record_claim(&mut r, &longest, &keys, "sas").unwrap();
        r.confirm_peer(&longest, Some("sas")).unwrap();
    }

    #[test]
    fn pin_snapshot_requires_an_active_unrevoked_pin() {
        use crate::crypto::SigningKeypair;
        use crate::grants::{RevocationListUnsigned, sign_crl};

        let peer = host_keys(0x87);
        let id = device_id(&peer.0);
        let mut pending = Roster::new();
        pending
            .record_pending_pair(
                peer.0,
                Some(peer.1.clone()),
                "P".into(),
                "cli".into(),
                "s".into(),
            )
            .unwrap();
        assert_eq!(
            pending.pin_snapshot(&id),
            Err(CoreError::PeerPending(id.clone()))
        );

        let root = SigningKeypair::from_seed([0x89; 32]);
        let mut revoked = Roster::new();
        revoked
            .insert_pinned_host(
                "h".into(),
                "H".into(),
                peer.0,
                Some(peer.1.clone()),
                0,
                vec![],
            )
            .unwrap();
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: "root".into(),
                seq: 1,
                revoked_devices: vec!["h".into()],
                revoked_nonces: vec![],
                ts: "2026-11-20T00:00:00Z".into(),
            },
            &root,
        )
        .unwrap();
        revoked.ingest_crl(crl, "root", root.public_key()).unwrap();
        let crl_only = reload(&revoked, |j| j["entries"]["h"]["state"] = "active".into());
        assert_eq!(crl_only.get("h").unwrap().state, PeerState::Active);
        assert_eq!(
            crl_only.pin_snapshot("h"),
            Err(CoreError::PeerRevoked("h".into()))
        );
    }

    #[test]
    fn stored_pending_host_entries_are_normalized_on_load() {
        let named = host_keys(0x8b);
        let default = host_keys(0x8d);
        let active = host_keys(0x8f);
        let default_id = device_id(&default.0);
        let mut seed = Roster::new();
        for (label, keys) in [
            ("named", &named),
            (default_id.as_str(), &default),
            ("bad", &named),
        ] {
            seed.insert_pinned_host(
                label.into(),
                "H".into(),
                keys.0,
                Some(keys.1.clone()),
                0,
                vec![],
            )
            .unwrap();
        }
        seed.insert_pinned_host(
            "kept".into(),
            "K".into(),
            active.0,
            Some(active.1.clone()),
            0,
            vec![],
        )
        .unwrap();
        let loaded = reload(&seed, |j| {
            let entries = j["entries"].as_object_mut().unwrap();
            for label in ["named", default_id.as_str(), "bad"] {
                entries[label]["state"] = "pending".into();
                entries[label]["last_pairing_sas"] = "sas".into();
            }
            let bad = entries.remove("bad").unwrap();
            entries.insert("bad#x".into(), bad);
        });
        assert!(loaded.get("named").is_none());
        assert_eq!(
            loaded.get_or_pending_host("named").unwrap().state,
            PeerState::Pending
        );
        // A Pending entry under its own device_id holds no foreign label and stays put.
        assert_eq!(loaded.get(&default_id).unwrap().state, PeerState::Pending);
        assert!(loaded.get("bad#x").is_none());
        assert!(loaded.get_or_pending_host("bad#x").is_none());
        assert_eq!(loaded.get("kept").unwrap().state, PeerState::Active);
        let mut confirmed = loaded;
        confirmed.confirm_peer("named", Some("sas")).unwrap();
        assert_eq!(confirmed.get("named").unwrap().static_pub, named.0);
    }

    #[test]
    fn pending_host_claims_are_capped_oldest_first() {
        use crate::crypto::StaticKeypair;

        let sig = host_keys(0x91).1;
        let mut r = Roster::new();
        for i in 0..=64u8 {
            let st = *StaticKeypair::from_scalar([i.wrapping_add(0x10); 32]).public_bytes();
            record_claim(&mut r, &format!("h{i}"), &(st, sig.clone()), "sas").unwrap();
        }
        assert!(r.get_or_pending_host("h0").is_none());
        assert!(r.get_or_pending_host("h1").is_some());
        assert!(r.get_or_pending_host("h64").is_some());
    }

    #[test]
    fn revoking_a_claim_never_revokes_an_entry_holding_other_keys() {
        use crate::crypto::{SigningKeypair, StaticKeypair};
        use crate::identity::sign_rotation;

        let k0 = *StaticKeypair::from_scalar([0xA1; 32]).public_bytes();
        let s0 = SigningKeypair::from_seed([0xA2; 32]);
        let k1 = *StaticKeypair::from_scalar([0xA3; 32]).public_bytes();
        let s1 = SigningKeypair::from_seed([0xA4; 32]);
        let label = device_id(&k0);
        let other_sig = host_keys(0xA5).1;

        // The genuine host rotated from k0 to k1 and keeps its label.
        let mut rotated = Roster::new();
        rotated
            .insert_pinned_host(
                label.clone(),
                "Studio".into(),
                k0,
                Some(s0.public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        let rec = sign_rotation(1, &s0, s1.public_key(), &k1, 1_795_133_000).unwrap();
        rotated
            .apply_verified_rotation(&label, &[rec], &k1, s1.public_key())
            .unwrap();
        record_claim(&mut rotated, "studio", &(k0, other_sig.clone()), "sas").unwrap();
        rotated.revoke_peer("studio").unwrap();
        let genuine = rotated.get(&label).unwrap();
        assert_eq!((genuine.state, genuine.static_pub), (PeerState::Active, k1));
        assert_eq!(
            record_claim(&mut rotated, "x", &(k0, host_keys(0xA7).1), "s"),
            Err(CoreError::PeerRevoked("x".into()))
        );
        assert_eq!(
            record_claim(
                &mut rotated,
                "y",
                &(host_keys(0xA9).0, other_sig.clone()),
                "s"
            ),
            Err(CoreError::PeerRevoked("y".into()))
        );
        rotated
            .insert_pinned_host(
                label.clone(),
                "Studio".into(),
                k1,
                Some(s1.public_key().clone()),
                1,
                vec![],
            )
            .unwrap();

        // A keyless entry for the claim's static key takes the claim's signing key when revoked.
        let peer = host_keys(0xB1);
        let mut keyless = Roster::new();
        keyless
            .record_pending_pair(peer.0, None, "P".into(), "cli".into(), "p".into())
            .unwrap();
        record_claim(&mut keyless, "studio", &(peer.0, other_sig.clone()), "sas").unwrap();
        keyless.revoke_peer("studio").unwrap();
        assert_eq!(
            record_claim(&mut keyless, "z", &(host_keys(0xB3).0, other_sig), "s"),
            Err(CoreError::PeerRevoked("z".into()))
        );
    }

    #[test]
    fn migration_keeps_own_label_entries_and_drops_revoked_claims() {
        let client = host_keys(0xB5);
        let gone = host_keys(0xB7);
        let mut roster = Roster::new();
        roster
            .record_pending_pair(
                client.0,
                Some(client.1.clone()),
                "C".into(),
                "host".into(),
                "s".into(),
            )
            .unwrap();
        roster
            .insert_pinned_host(
                "gone".into(),
                "G".into(),
                gone.0,
                Some(gone.1.clone()),
                0,
                vec![],
            )
            .unwrap();
        roster.revoke_peer("gone").unwrap();
        let mut claims = Roster::new();
        record_claim(&mut claims, "other", &gone, "s").unwrap();
        let claim = serde_json::to_value(&claims).unwrap()["pending_hosts"][0].clone();
        let loaded = reload(&roster, |j| j["pending_hosts"] = serde_json::json!([claim]));
        assert_eq!(
            loaded.get(&device_id(&client.0)).unwrap().state,
            PeerState::Pending
        );
        assert!(loaded.get_or_pending_host("other").is_none());
    }

    #[test]
    fn responder_pairing_respects_a_claimed_signing_key() {
        let host = host_keys(0xB9);
        let mut roster = Roster::new();
        record_claim(&mut roster, "studio", &host, "s").unwrap();
        assert!(matches!(
            roster.record_pending_pair(
                host.0,
                Some(host_keys(0xBB).1),
                "P".into(),
                "cli".into(),
                "p".into()
            ),
            Err(CoreError::ProtocolViolation(_))
        ));
    }

    #[test]
    fn a_claim_is_revocable_by_its_device_id() {
        let real = host_keys(0xC1);
        let other = host_keys(0xC3);
        let mut roster = Roster::new();
        record_claim(&mut roster, "studio", &real, "real").unwrap();
        record_claim(&mut roster, "studio", &other, "other").unwrap();
        roster.revoke_peer(&device_id(&other.0)).unwrap();
        assert_eq!(
            record_claim(&mut roster, "q", &(other.0, host_keys(0xC5).1), "s"),
            Err(CoreError::PeerRevoked("q".into()))
        );
        assert_eq!(
            roster.get_or_pending_host("studio").unwrap().static_pub,
            real.0
        );
        roster.confirm_peer("studio", Some("real")).unwrap();
        assert_eq!(roster.get("studio").unwrap().state, PeerState::Active);
    }

    #[test]
    fn claims_carry_their_wire_floor_by_static_key() {
        let host = host_keys(0xC7);
        let mut roster = Roster::new();
        let slot = roster
            .record_pending_host_slot(
                "studio".into(),
                "S".into(),
                host.0,
                host.1.clone(),
                0,
                "s".into(),
                vec![],
            )
            .unwrap();
        roster
            .with_host_slot(&slot, |r, id| {
                r.upgrade_peer_to_v2(id, V2PeerSecrets::new([1; 32], [2; 32]))
            })
            .unwrap();
        assert_eq!(roster.pairing_floor(&host.0), WIRE_VERSION_V2);
        let pinned = roster
            .insert_pinned_host("other".into(), "O".into(), host.0, Some(host.1), 0, vec![])
            .unwrap();
        assert_eq!(pinned.min_wire_version, WIRE_VERSION_V2);
    }

    #[test]
    fn revoking_by_device_id_never_follows_a_claimed_label() {
        let k2 = host_keys(0xD1);
        let k3 = host_keys(0xD3);
        let k4 = host_keys(0xD5);
        let id2 = device_id(&k2.0);

        // Other keys claim the label equal to k2's device id: k2 is still revocable by it.
        let mut cycle = Roster::new();
        record_claim(&mut cycle, "studio", &k2, "a").unwrap();
        record_claim(&mut cycle, &id2, &k3, "b").unwrap();
        record_claim(&mut cycle, &id2, &k4, "c").unwrap();
        cycle.revoke_peer(&id2).unwrap();
        assert_eq!(
            record_claim(&mut cycle, "q", &(k2.0, host_keys(0xD7).1), "s"),
            Err(CoreError::PeerRevoked("q".into()))
        );
        assert_eq!(cycle.pending_hosts().count(), 2);

        // A single decoy claiming that label is not what gets revoked.
        let mut decoy = Roster::new();
        record_claim(&mut decoy, "studio", &k2, "a").unwrap();
        record_claim(&mut decoy, &id2, &k3, "b").unwrap();
        decoy.revoke_peer(&id2).unwrap();
        let left: Vec<_> = decoy.pending_hosts().map(|e| e.static_pub).collect();
        assert_eq!(left, vec![k3.0]);
    }

    #[test]
    fn revoke_pending_host_touches_only_claims_of_that_key() {
        use crate::crypto::{SigningKeypair, StaticKeypair};
        use crate::identity::sign_rotation;

        let k0 = *StaticKeypair::from_scalar([0xE1; 32]).public_bytes();
        let s0 = SigningKeypair::from_seed([0xE2; 32]);
        let k1 = *StaticKeypair::from_scalar([0xE3; 32]).public_bytes();
        let s1 = SigningKeypair::from_seed([0xE4; 32]);
        let label = device_id(&k0);
        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                label.clone(),
                "Studio".into(),
                k0,
                Some(s0.public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        let rec = sign_rotation(1, &s0, s1.public_key(), &k1, 1_795_133_000).unwrap();
        roster
            .apply_verified_rotation(&label, &[rec], &k1, s1.public_key())
            .unwrap();
        let other_sig = host_keys(0xE5).1;
        record_claim(&mut roster, "studio", &(k0, other_sig.clone()), "s").unwrap();

        roster.revoke_pending_host(&label).unwrap();
        let genuine = roster.get(&label).unwrap();
        assert_eq!((genuine.state, genuine.static_pub), (PeerState::Active, k1));
        assert_eq!(roster.pending_hosts().count(), 0);
        assert_eq!(
            record_claim(&mut roster, "x", &(k0, host_keys(0xE7).1), "s"),
            Err(CoreError::PeerRevoked("x".into()))
        );
        assert_eq!(
            roster.revoke_pending_host(&label),
            Err(CoreError::PeerNotFound(label.clone()))
        );
    }
}
