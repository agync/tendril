//! Sans-I/O Noise XX session state machine with grant enforcement, auto-rekey, and CRL checks.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::{
    HybridSigningPublicKey, device_id, has_control_chars, is_valid_x25519_public_key,
};
use crate::error::CoreError;
use crate::grants::{
    AuditEvent, Grant, RevocationList, authorize_grant, authorize_path_capability,
    verify_grant_with_chain,
};
use crate::group::{
    GroupManifest, GroupRendezvousFrame, GroupSeq, decode_group_rendezvous_frame,
    validate_group_seqs,
};
use crate::identity::{EndpointIdentity, RotationRecord};
use crate::noise::{NoiseHfsHandshake, NoiseHfsHandshakeBuilder, NoiseTransport};
use crate::pairing::{PairingUri, RouteCheck, VerifiedRouteStatement};
use crate::roster::{PeerState, Roster};
use crate::routes::{MAX_ROUTE_SEQ, RouteSet};
use crate::wire::{
    HostHello, InnerFrameType, Intent, PathUpgradeMsg, PathUpgradeState, Preamble,
    ResumableFrameReader, SessionHello, WIRE_VERSION, decode_inner_frame, encode_frame,
    encode_inner_frame, validate_upgrade_caps,
};

/// Maximum encrypted transport frames sent before triggering automatic `0x04 REKEY` (`2^20`).
pub const REKEY_MAX_FRAMES: u64 = 1_048_576;

/// Maximum elapsed session duration in milliseconds before triggering automatic `0x04 REKEY` (`15m`).
pub const REKEY_MAX_AGE_MS: u64 = 15 * 60 * 1_000;

/// Maximum decoded `0x0C ROUTE_SET` frames queued per session; older entries are dropped.
pub const MAX_QUEUED_ROUTE_SETS: usize = 4;

/// Canonical `0x07 CLOSE` reason codes.
pub struct SessionCloseCode;

impl SessionCloseCode {
    pub const NORMAL: u16 = 1000;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const POLICY_VIOLATION: u16 = 1008;
    /// Refusal: the responder knows the peer and it is revoked (`spec/wire-v1.md` Section 5.4.1).
    pub const PEER_REVOKED: u16 = 4001;
    /// Alias of [`Self::PEER_REVOKED`], kept for existing callers.
    pub const REVOKED: u16 = Self::PEER_REVOKED;
    /// Reserved, never a refusal.
    pub const GRANT_EXPIRED: u16 = 4002;
    /// Reserved, never a refusal.
    pub const KEY_UNVERIFIED: u16 = 4003;
    /// Refusal: the responder knows the peer and it is still pending confirmation.
    pub const PEER_PENDING: u16 = 4004;
}

/// Direction of a completed Noise `CipherState::rekey()` transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyDirection {
    Outgoing,
    Incoming,
}

/// Role played by a [`SessionMachine`] endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

/// Outbound bytes and protocol events produced by [`SessionMachine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAction {
    WriteBytes(Vec<u8>),
    Established {
        peer_device_id: String,
        peer_static_pub: [u8; 32],
        final_handshake_hash: [u8; 32],
    },
    AppData(Vec<u8>),
    GrantUpdated(Grant),
    RevocationUpdated {
        issuer: String,
        seq: u64,
    },
    /// Received `0x0A` manifest, parsed but not verified or ingested.
    GroupManifestReceived(Box<GroupManifest>),
    /// Received `0x0B` rendezvous frame, not yet authorized or ingested.
    GroupRendezvousReceived(GroupRendezvousFrame),
    /// Received `0x0D PATH_UPGRADE` signaling frame after directional and capability checks.
    PathUpgradeReceived(PathUpgradeMsg),
    Rekeyed {
        direction: RekeyDirection,
    },
    PongReceived(u64),
    Audit(AuditEvent),
    CloseTransport {
        code: u16,
        reason: String,
    },
}

/// What a Day-2 connect expects of the host it reaches, checked before session `msg3`.
///
/// Built only by [`RouteExpectation::for_connect`]. After `HostHello` verifies against the pin
/// and before the rotation is applied or `msg3` is written, the session initiator checks that
/// `relay_pub` names the presented signing key, that the recovery URI's `k` and `sh` name the
/// presented keys (signed or not), and that its route statement, if any, verifies.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RouteExpectation {
    relay_pub: Option<[u8; 32]>,
    recovery_uri: Option<PairingUri>,
}

impl fmt::Debug for RouteExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteExpectation")
            .field("relay_pub", &self.relay_pub)
            .field("recovery_uri", &self.recovery_uri)
            .finish()
    }
}

impl RouteExpectation {
    /// Builds the expectation for a connect to `target_peer_id`.
    ///
    /// Parses `recovery_uri` and rejects it when its `id` names another host. The relay key is
    /// the one agreed by `operator_relay_key` (an operator `URL#key`), `uri_rp` and the recovery
    /// URI's `rp`; any two that differ are rejected.
    pub fn for_connect(
        target_peer_id: &str,
        recovery_uri: Option<&str>,
        operator_relay_key: Option<[u8; 32]>,
        uri_rp: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        let recovery_uri = recovery_uri.map(PairingUri::parse).transpose()?;
        if let Some(id) = recovery_uri.as_ref().and_then(|u| u.host_id.as_deref())
            && id != target_peer_id
        {
            return Err(CoreError::InvalidPairingUri(
                "recovery URI is for a different host".into(),
            ));
        }
        let mut relay_pub = None;
        let keys = [
            operator_relay_key,
            uri_rp,
            recovery_uri.as_ref().and_then(|u| u.relay_pub),
        ];
        for key in keys.into_iter().flatten() {
            match relay_pub {
                Some(prev) if prev != key => {
                    return Err(CoreError::InvalidPairingUri(
                        "operator relay key does not match the URI rp".into(),
                    ));
                }
                _ => relay_pub = Some(key),
            }
        }
        Ok(Self {
            relay_pub,
            recovery_uri,
        })
    }

    /// The expected Ed25519 relay mailbox key.
    #[must_use]
    pub const fn relay_pub(&self) -> Option<&[u8; 32]> {
        self.relay_pub.as_ref()
    }

    /// The parsed recovery URI, if any.
    #[must_use]
    pub const fn recovery_uri(&self) -> Option<&PairingUri> {
        self.recovery_uri.as_ref()
    }

    fn check(
        &self,
        presented_static: &[u8; 32],
        presented_signing: &HybridSigningPublicKey,
    ) -> Result<Option<VerifiedRouteStatement>, CoreError> {
        if self
            .relay_pub
            .is_some_and(|rp| rp != *presented_signing.ed25519_bytes())
        {
            return Err(CoreError::HostKeyUnverified);
        }
        let Some(uri) = &self.recovery_uri else {
            return Ok(None);
        };
        if uri.host_static_pub != *presented_static
            || uri.host_signing_pub_hash != presented_signing.sha256_hash()
        {
            return Err(CoreError::HostKeyUnverified);
        }
        match uri.verify_route_statement_for_session(presented_signing) {
            RouteCheck::Verified(statement) => Ok(Some(statement)),
            RouteCheck::Unsigned(_) => Ok(None),
            RouteCheck::Invalid => Err(CoreError::InvalidPairingUri(
                "route statement does not verify".into(),
            )),
        }
    }
}

/// Result of [`verify_session_host`].
pub(crate) struct VerifiedSessionHost {
    pub(crate) rotation_applied: bool,
    pub(crate) recovery_statement: Option<VerifiedRouteStatement>,
}

/// Verifies a session `HostHello` against `target_id`'s pin, then `expectation`.
///
/// With an expectation the pin is verified on a staged roster, so a failed expectation leaves
/// `roster` unchanged; a failed pin check keeps its evidence (resolved hash pin, fork
/// revocation) as without an expectation.
pub(crate) fn verify_session_host(
    roster: &mut Roster,
    target_id: &str,
    rotation: &[RotationRecord],
    peer_static: &[u8; 32],
    host_signing_pub: &HybridSigningPublicKey,
    negotiated_wire: u8,
    expectation: Option<&RouteExpectation>,
) -> Result<VerifiedSessionHost, CoreError> {
    let Some(expectation) = expectation else {
        let rotation_applied = verify_host_pin(
            roster,
            target_id,
            rotation,
            peer_static,
            host_signing_pub,
            negotiated_wire,
        )?;
        return Ok(VerifiedSessionHost {
            rotation_applied,
            recovery_statement: None,
        });
    };
    let mut staged = roster.clone();
    let rotation_applied = match verify_host_pin(
        &mut staged,
        target_id,
        rotation,
        peer_static,
        host_signing_pub,
        negotiated_wire,
    ) {
        Ok(applied) => applied,
        Err(err) => {
            *roster = staged;
            return Err(err);
        }
    };
    let recovery_statement = expectation.check(peer_static, host_signing_pub)?;
    *roster = staged;
    Ok(VerifiedSessionHost {
        rotation_applied,
        recovery_statement,
    })
}

/// Checks `target_id`'s pin against the presented keys and applies a verified rotation.
///
/// Returns `true` when a non-empty rotation chain was applied.
fn verify_host_pin(
    roster: &mut Roster,
    target_id: &str,
    rotation: &[RotationRecord],
    peer_static: &[u8; 32],
    host_signing_pub: &HybridSigningPublicKey,
    negotiated_wire: u8,
) -> Result<bool, CoreError> {
    roster.resolve_signing_pin(target_id, host_signing_pub)?;
    let (pinned_static, pinned_signing) = match roster.get(target_id) {
        Some(entry) => {
            if entry.min_wire_version > negotiated_wire {
                return Err(CoreError::VersionDowngrade {
                    peer_min: entry.min_wire_version,
                    negotiated: negotiated_wire,
                });
            }
            match entry.state {
                PeerState::Pending => {
                    return Err(CoreError::PeerPending(target_id.to_string()));
                }
                PeerState::Revoked => {
                    return Err(CoreError::PeerRevoked(target_id.to_string()));
                }
                PeerState::Active => {
                    if roster.crl_revokes_entry(entry) {
                        return Err(CoreError::PeerRevoked(target_id.to_string()));
                    }
                    entry.require_complete_pin()?
                }
            }
        }
        None => {
            return Err(match roster.missing_peer_error(target_id) {
                CoreError::PeerNotFound(_) => CoreError::HostKeyUnverified,
                pending => pending,
            });
        }
    };

    if roster.is_manifest_pinned(target_id) {
        if *peer_static != pinned_static || *host_signing_pub != pinned_signing {
            return Err(CoreError::HostKeyUnverified);
        }
        return Ok(false);
    }
    if rotation.is_empty() && *peer_static == pinned_static && *host_signing_pub != pinned_signing {
        return Err(CoreError::HostKeyUnverified);
    }
    match roster.apply_verified_rotation(target_id, rotation, peer_static, host_signing_pub) {
        Ok(_) => Ok(!rotation.is_empty()),
        Err(
            err @ (CoreError::RotationForkDetected { .. }
            | CoreError::IncompletePin(_)
            | CoreError::PeerPending(_)
            | CoreError::PeerRevoked(_)),
        ) => Err(err),
        Err(_) => Err(CoreError::HostKeyUnverified),
    }
}

/// Rejects a `SessionHello.route_seq` above `2^53 - 1`.
pub(crate) fn check_route_seq(route_seq: Option<u64>) -> Result<(), CoreError> {
    if route_seq.is_some_and(|seq| seq > MAX_ROUTE_SEQ) {
        return Err(CoreError::ProtocolViolation(
            "route_seq must be at most 2^53 - 1",
        ));
    }
    Ok(())
}

/// Checks that a responder may send `payload` as `0x0C`: the initiator negotiated route sets and
/// the payload is a well-formed route set.
pub(crate) fn check_route_set_send(
    peer_route_seq: Option<u64>,
    payload: &[u8],
) -> Result<(), CoreError> {
    if peer_route_seq.is_none() {
        return Err(CoreError::NotReady("peer did not negotiate route sets"));
    }
    RouteSet::decode(payload).map(|_| ())
}

/// Receive pipeline steps 2 to 5 for one decrypted `0x0C` payload: a responder closes, an
/// initiator that did not negotiate route sets drops it unparsed, otherwise it is decoded
/// (structural errors close) and queued.
pub(crate) fn receive_route_set(
    role: SessionRole,
    negotiated: bool,
    payload: &[u8],
    queue: &mut Vec<RouteSet>,
) -> Result<(), CoreError> {
    if role == SessionRole::Responder {
        return Err(CoreError::InvalidInnerFramePayload(
            "route set from initiator",
        ));
    }
    if !negotiated {
        return Ok(());
    }
    let set = RouteSet::decode(payload)?;
    if queue.len() >= MAX_QUEUED_ROUTE_SETS {
        queue.remove(0);
    }
    queue.push(set);
    Ok(())
}

enum SessionPhase {
    Init(Box<NoiseHfsHandshake>),
    AwaitMsg2(Box<NoiseHfsHandshake>),
    AwaitPreamble(Box<NoiseHfsHandshake>),
    AwaitMsg1(Box<NoiseHfsHandshake>),
    AwaitMsg3(Box<NoiseHfsHandshake>),
    Transport(Box<NoiseTransport>),
    Closed,
}

/// Pure Sans-I/O `intent = session` protocol driver (`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`).
pub struct SessionMachine {
    role: SessionRole,
    phase: SessionPhase,
    reader: ResumableFrameReader,
    local_host_id: String,
    local_device_id: String,
    local_signing_pub: HybridSigningPublicKey,
    local_rotation_chain: Vec<RotationRecord>,
    applied_rotation: Vec<RotationRecord>,
    target_host_id: Option<String>,
    initial_grant: Option<Grant>,
    initial_crl_seq: Option<u64>,
    initial_groups: Option<Vec<GroupSeq>>,
    peer_crl_seq: Option<u64>,
    peer_groups: Option<Vec<GroupSeq>>,
    peer_device_id: Option<String>,
    peer_static_pub: Option<[u8; 32]>,
    active_grant: Option<Grant>,
    frames_sent: u64,
    last_rekey_outgoing_ms: u64,
    rekey_max_frames: u64,
    rekey_max_age_ms: u64,
    route_expectation: Option<Box<RouteExpectation>>,
    local_route_seq: Option<u64>,
    peer_route_seq: Option<u64>,
    presented_rotation: Vec<RotationRecord>,
    verified_recovery: Option<Box<VerifiedRouteStatement>>,
    route_sets: Vec<RouteSet>,
    local_upgrade_caps: Vec<String>,
    peer_upgrade_caps: Vec<String>,
    upgrade_state: PathUpgradeState,
}

impl fmt::Debug for SessionMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionMachine")
            .field("role", &self.role)
            .field("established", &self.is_established())
            .field("closed", &self.is_closed())
            .field("peer_device_id", &self.peer_device_id)
            .finish()
    }
}

impl SessionMachine {
    /// Creates an initiator session targeting `target_host_id`.
    pub fn new_initiator(
        local_identity: &EndpointIdentity,
        target_host_id: impl Into<String>,
        initial_grant: Option<Grant>,
        crl_seq: Option<u64>,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        let hs = build_handshake(true, local_identity, fixed_ephemeral)?;
        Ok(Self {
            role: SessionRole::Initiator,
            phase: SessionPhase::Init(Box::new(hs)),
            reader: ResumableFrameReader::new(),
            local_host_id: local_identity.host_id().to_string(),
            local_device_id: local_identity.device_id(),
            local_signing_pub: local_identity.signing_key().public_key().clone(),
            local_rotation_chain: local_identity.rotation_chain().to_vec(),
            applied_rotation: Vec::new(),
            target_host_id: Some(target_host_id.into()),
            initial_grant: initial_grant.clone(),
            initial_crl_seq: crl_seq,
            initial_groups: None,
            peer_crl_seq: None,
            peer_groups: None,
            peer_device_id: None,
            peer_static_pub: None,
            active_grant: initial_grant,
            frames_sent: 0,
            last_rekey_outgoing_ms: 0,
            rekey_max_frames: REKEY_MAX_FRAMES,
            rekey_max_age_ms: REKEY_MAX_AGE_MS,
            route_expectation: None,
            local_route_seq: None,
            peer_route_seq: None,
            presented_rotation: Vec::new(),
            verified_recovery: None,
            route_sets: Vec::new(),
            local_upgrade_caps: Vec::new(),
            peer_upgrade_caps: Vec::new(),
            upgrade_state: PathUpgradeState::new(true),
        })
    }

    /// Creates an initiator after verifying `roster` does not pin `target_host_id` to a
    /// `min_wire_version` above Wire v1, so no v1 preamble or `msg1` is ever emitted to such a peer.
    pub fn new_initiator_with_roster(
        local_identity: &EndpointIdentity,
        target_host_id: impl Into<String>,
        initial_grant: Option<Grant>,
        crl_seq: Option<u64>,
        fixed_ephemeral: Option<[u8; 32]>,
        roster: &Roster,
    ) -> Result<Self, CoreError> {
        let target_host_id = target_host_id.into();
        check_peer_allows_wire_v1(roster, &target_host_id)?;
        Self::new_initiator(
            local_identity,
            target_host_id,
            initial_grant,
            crl_seq,
            fixed_ephemeral,
        )
    }

    /// Creates a responder session listening for an inbound initiator preamble.
    pub fn new_responder(
        local_identity: &EndpointIdentity,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        let hs = build_handshake(false, local_identity, fixed_ephemeral)?;
        Ok(Self {
            role: SessionRole::Responder,
            phase: SessionPhase::AwaitPreamble(Box::new(hs)),
            reader: ResumableFrameReader::with_preamble(),
            local_host_id: local_identity.host_id().to_string(),
            local_device_id: local_identity.device_id(),
            local_signing_pub: local_identity.signing_key().public_key().clone(),
            local_rotation_chain: local_identity.rotation_chain().to_vec(),
            applied_rotation: Vec::new(),
            target_host_id: None,
            initial_grant: None,
            initial_crl_seq: None,
            initial_groups: None,
            peer_crl_seq: None,
            peer_groups: None,
            peer_device_id: None,
            peer_static_pub: None,
            active_grant: None,
            frames_sent: 0,
            last_rekey_outgoing_ms: 0,
            rekey_max_frames: REKEY_MAX_FRAMES,
            rekey_max_age_ms: REKEY_MAX_AGE_MS,
            route_expectation: None,
            local_route_seq: None,
            peer_route_seq: None,
            presented_rotation: Vec::new(),
            verified_recovery: None,
            route_sets: Vec::new(),
            local_upgrade_caps: Vec::new(),
            peer_upgrade_caps: Vec::new(),
            upgrade_state: PathUpgradeState::new(false),
        })
    }

    /// Configures advertised upgrade capabilities before handshake start (`HostHello` / `SessionHello`).
    pub fn with_upgrade_caps(mut self, caps: Vec<String>) -> Result<Self, CoreError> {
        if !matches!(
            self.phase,
            SessionPhase::Init(_) | SessionPhase::AwaitPreamble(_)
        ) {
            return Err(CoreError::NotReady(
                "upgrade capabilities must be set before handshake starts",
            ));
        }
        validate_upgrade_caps(&caps)?;
        self.local_upgrade_caps = caps;
        Ok(self)
    }

    /// Returns the negotiated path upgrade capabilities for this session.
    #[must_use]
    pub fn negotiated_upgrade_caps(&self) -> &[String] {
        self.upgrade_state.negotiated_caps()
    }

    /// Returns the raw upgrade capabilities advertised by the peer during handshake.
    #[must_use]
    pub fn peer_upgrade_caps(&self) -> &[String] {
        &self.peer_upgrade_caps
    }

    /// Sends an encrypted `0x0D PATH_UPGRADE` frame enforcing directional, capability, and offer limits.
    pub fn send_path_upgrade(
        &mut self,
        msg: &PathUpgradeMsg,
        now_ms: u64,
    ) -> Result<Vec<SessionAction>, CoreError> {
        if !self.is_established() {
            return Err(CoreError::NotReady("session not in transport mode"));
        }
        let payload = self.upgrade_state.prepare_send(msg)?;
        let actions = self.send_inner(InnerFrameType::PathUpgrade, &payload, now_ms)?;
        self.upgrade_state.commit_send(msg);
        Ok(actions)
    }

    /// Sets the route expectation checked against `HostHello` before `msg3` (initiator, before
    /// [`Self::start`]).
    pub fn with_route_expectation(
        mut self,
        expectation: RouteExpectation,
    ) -> Result<Self, CoreError> {
        self.require_unstarted_initiator()?;
        self.route_expectation = Some(Box::new(expectation));
        Ok(self)
    }

    /// Sets `SessionHello.route_seq` (initiator, before [`Self::start`]). `Some` opts in to
    /// `0x0C ROUTE_SET` frames; `None` keeps the pre-route-set behaviour.
    pub fn with_route_seq(mut self, route_seq: Option<u64>) -> Result<Self, CoreError> {
        self.require_unstarted_initiator()?;
        check_route_seq(route_seq)?;
        self.local_route_seq = route_seq;
        Ok(self)
    }

    fn require_unstarted_initiator(&self) -> Result<(), CoreError> {
        if self.role != SessionRole::Initiator || !matches!(self.phase, SessionPhase::Init(_)) {
            return Err(CoreError::NotReady(
                "route options are set on an initiator before start()",
            ));
        }
        Ok(())
    }

    /// Returns the `route_seq` the initiator sent in `SessionHello` (responder, after `msg3`).
    #[must_use]
    pub const fn peer_route_seq(&self) -> Option<u64> {
        self.peer_route_seq
    }

    /// Returns the `HostHello.rotation` records the host presented, kept on every outcome.
    #[must_use]
    pub fn presented_rotation(&self) -> &[RotationRecord] {
        &self.presented_rotation
    }

    /// Returns the recovery URI's route statement verified under the presented host key.
    #[must_use]
    pub fn verified_recovery_statement(&self) -> Option<&VerifiedRouteStatement> {
        self.verified_recovery.as_deref()
    }

    /// Drains the decoded, not yet verified `0x0C` route sets received so far.
    pub fn take_route_sets(&mut self) -> Vec<RouteSet> {
        std::mem::take(&mut self.route_sets)
    }

    /// Sends a `0x0C ROUTE_SET` payload (responder only, to an initiator that sent
    /// `SessionHello.route_seq`). The payload must decode as a [`RouteSet`].
    pub fn send_route_set(
        &mut self,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<SessionAction>, CoreError> {
        if self.role != SessionRole::Responder {
            return Err(CoreError::NotReady("only a responder sends route sets"));
        }
        check_route_set_send(self.peer_route_seq, payload)?;
        self.send_inner(InnerFrameType::RouteSet, payload, now_ms)
    }

    /// Overrides the automatic rekey thresholds (`frames`, `age_ms`).
    pub fn set_rekey_thresholds(&mut self, max_frames: u64, max_age_ms: u64) {
        self.rekey_max_frames = max_frames.max(1);
        self.rekey_max_age_ms = max_age_ms.max(1);
    }

    /// Sets the gossip summary advertised in the initiator `SessionHello` (before `msg3`).
    pub fn set_local_groups(&mut self, groups: Vec<GroupSeq>) -> Result<(), CoreError> {
        validate_group_seqs(&groups)?;
        self.initial_groups = (!groups.is_empty()).then_some(groups);
        Ok(())
    }

    /// Returns the group gossip summary advertised by the initiator in `SessionHello`, if any.
    #[must_use]
    pub fn peer_groups(&self) -> Option<&[GroupSeq]> {
        self.peer_groups.as_deref()
    }

    /// Returns true once the Noise XX handshake has entered transport mode.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.phase, SessionPhase::Transport(_))
    }

    /// Returns true once the session has closed cleanly or aborted due to error.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.phase, SessionPhase::Closed)
    }

    /// Returns the authenticated peer identifier once established.
    #[must_use]
    pub fn peer_device_id(&self) -> Option<&str> {
        self.peer_device_id.as_deref()
    }

    /// Returns the authenticated peer Noise static key once established.
    #[must_use]
    pub const fn peer_static_pub(&self) -> Option<&[u8; 32]> {
        self.peer_static_pub.as_ref()
    }

    /// Returns the `crl_seq` advertised by the initiator in `SessionHello`, if any.
    #[must_use]
    pub const fn peer_crl_seq(&self) -> Option<u64> {
        self.peer_crl_seq
    }

    /// Returns the currently verified capability grant associated with this session, if any.
    #[must_use]
    pub const fn active_grant(&self) -> Option<&Grant> {
        self.active_grant.as_ref()
    }

    /// Returns the verified host rotation chain applied during handshake, if any.
    #[must_use]
    pub fn applied_rotation(&self) -> &[RotationRecord] {
        &self.applied_rotation
    }

    /// Emits the initial 6-byte `Intent::Session` preamble + empty Noise `msg1` (initiator only).
    pub fn start(&mut self) -> Result<Vec<SessionAction>, CoreError> {
        if self.role != SessionRole::Initiator {
            return Err(CoreError::NotReady("only initiator calls start()"));
        }
        let prev = std::mem::replace(&mut self.phase, SessionPhase::Closed);
        let SessionPhase::Init(mut hs) = prev else {
            return Err(CoreError::NotReady("initiator already started"));
        };
        let msg1 = hs.write_message_vec(&[])?;
        let frame = encode_frame(&msg1)?;
        let preamble = Preamble::v1(Intent::Session).encode();
        let mut wire_bytes = Vec::with_capacity(preamble.len() + frame.len());
        wire_bytes.extend_from_slice(&preamble);
        wire_bytes.extend_from_slice(&frame);
        self.phase = SessionPhase::AwaitMsg2(hs);
        Ok(vec![SessionAction::WriteBytes(wire_bytes)])
    }

    /// Feeds raw transport bytes into the session state machine under explicit virtual time.
    pub fn feed_bytes(
        &mut self,
        chunk: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
    ) -> Result<Vec<SessionAction>, CoreError> {
        if self.is_closed() {
            return Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "session is closed".to_string(),
            });
        }
        if let Err(err) = self.reader.push(chunk) {
            self.phase = SessionPhase::Closed;
            return Err(err);
        }

        let mut actions = Vec::new();
        if matches!(self.phase, SessionPhase::AwaitPreamble(_)) {
            match self.reader.take_preamble() {
                Ok(Some(preamble)) => {
                    if preamble.version != WIRE_VERSION {
                        self.phase = SessionPhase::Closed;
                        return Err(CoreError::UnsupportedVersion(preamble.version));
                    }
                    if preamble.intent != Intent::Session {
                        self.phase = SessionPhase::Closed;
                        return Err(CoreError::ProtocolViolation(
                            "expected session preamble intent",
                        ));
                    }
                    let prev = std::mem::replace(&mut self.phase, SessionPhase::Closed);
                    if let SessionPhase::AwaitPreamble(hs) = prev {
                        self.phase = SessionPhase::AwaitMsg1(hs);
                    }
                }
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = SessionPhase::Closed;
                    return Err(err);
                }
            }
        }

        loop {
            let body = match self.reader.next_frame() {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = SessionPhase::Closed;
                    return Err(err);
                }
            };

            if let Err(err) = self.handle_frame(&body, now_unix, now_ms, roster, &mut actions) {
                self.phase = SessionPhase::Closed;
                return Err(err);
            }
            if self.is_closed() {
                return Ok(actions);
            }
        }
    }

    /// Sends an encrypted `0x01 DATA` payload, automatically triggering `0x04 REKEY` when due.
    pub fn send_data(
        &mut self,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<SessionAction>, CoreError> {
        self.send_inner(InnerFrameType::Data, payload, now_ms)
    }

    /// Sends an encrypted `0x02 GRANT` payload to refresh or present a signed grant.
    pub fn send_grant(
        &mut self,
        grant: &Grant,
        now_ms: u64,
    ) -> Result<Vec<SessionAction>, CoreError> {
        let json = Zeroizing::new(
            serde_json::to_vec(grant).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        self.send_inner(InnerFrameType::Grant, &json, now_ms)
    }

    /// Sends an encrypted `0x03 REVOCATION` CRL update.
    pub fn send_revocation(
        &mut self,
        crl: &RevocationList,
        now_ms: u64,
    ) -> Result<Vec<SessionAction>, CoreError> {
        let json = Zeroizing::new(
            serde_json::to_vec(crl).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        self.send_inner(InnerFrameType::Revocation, &json, now_ms)
    }

    /// Sends an encrypted `0x0A GROUP_MANIFEST` frame.
    pub fn send_group_manifest(
        &mut self,
        manifest: &GroupManifest,
        now_ms: u64,
    ) -> Result<Vec<SessionAction>, CoreError> {
        let json = manifest.to_wire_bytes()?;
        self.send_inner(InnerFrameType::GroupManifest, &json, now_ms)
    }

    /// Sends an encrypted `0x0B GROUP_RENDEZVOUS` frame carrying exactly 60 bytes.
    pub fn send_group_rendezvous(
        &mut self,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<SessionAction>, CoreError> {
        self.send_inner(InnerFrameType::GroupRendezvous, payload, now_ms)
    }

    /// Explicitly initiates a Noise `0x04 REKEY` transition on the outgoing cipher state.
    pub fn send_rekey(&mut self, now_ms: u64) -> Result<Vec<SessionAction>, CoreError> {
        let SessionPhase::Transport(ref mut tx) = self.phase else {
            return Err(CoreError::NotReady("session not in transport mode"));
        };
        let frame = encrypt_inner(tx, InnerFrameType::Rekey, &[])?;
        tx.rekey_outgoing()?;
        self.frames_sent = 0;
        self.last_rekey_outgoing_ms = now_ms;
        Ok(vec![
            SessionAction::WriteBytes(frame),
            SessionAction::Rekeyed {
                direction: RekeyDirection::Outgoing,
            },
        ])
    }

    /// Sends an encrypted `0x05 PING` liveness probe with an 8-byte cookie.
    pub fn send_ping(&mut self, cookie: u64, now_ms: u64) -> Result<Vec<SessionAction>, CoreError> {
        self.send_inner(InnerFrameType::Ping, &cookie.to_be_bytes(), now_ms)
    }

    /// Sends an encrypted `0x07 CLOSE` frame and transitions to terminal closed state.
    pub fn send_close(&mut self, code: u16, reason: &str) -> Result<Vec<SessionAction>, CoreError> {
        if !matches!(self.phase, SessionPhase::Transport(_)) {
            return Err(CoreError::NotReady("session not in transport mode"));
        }
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        let inner = Zeroizing::new(encode_inner_frame(InnerFrameType::Close, &payload)?);
        let prev = std::mem::replace(&mut self.phase, SessionPhase::Closed);
        let SessionPhase::Transport(mut tx) = prev else {
            unreachable!("validated transport phase above");
        };
        let frame = encrypt_encoded_inner(&mut tx, &inner)?;
        Ok(vec![
            SessionAction::WriteBytes(frame),
            SessionAction::CloseTransport {
                code,
                reason: reason.to_string(),
            },
        ])
    }

    /// Advances virtual timers: fails closed if the peer/grant became invalid or triggers `0x04 REKEY`
    /// when `REKEY_MAX_AGE_MS` elapses.
    pub fn tick(
        &mut self,
        now_unix: u64,
        now_ms: u64,
        roster: &Roster,
    ) -> Result<Vec<SessionAction>, CoreError> {
        if !self.is_established() {
            return Ok(Vec::new());
        }
        if let Err(err) = self.verify_peer_and_active_grant(now_unix, roster) {
            self.phase = SessionPhase::Closed;
            return Err(err);
        }
        if now_ms.saturating_sub(self.last_rekey_outgoing_ms) >= self.rekey_max_age_ms {
            return self.send_rekey(now_ms);
        }
        Ok(Vec::new())
    }

    /// Authorizes `requested_cap` against the verified session grant, roster state, and active CRL
    /// (default-deny), returning both the typed result and a structured [`AuditEvent`].
    pub fn authorize(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        self.authorize_inner(requested_cap, None, now_unix, roster)
    }

    /// Authorizes path-scoped `action` on `raw_path` after strictly canonicalizing `raw_path`
    /// and enforcing segment-boundary wildcards (default-deny).
    pub fn authorize_path(
        &self,
        action: &str,
        raw_path: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        self.authorize_inner(action, Some(raw_path), now_unix, roster)
    }

    fn authorize_inner(
        &self,
        action_or_cap: &str,
        raw_path: Option<&str>,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        let peer_subj = self.peer_device_id.as_deref().unwrap_or("");
        let audit_subj = self.incoming_grant_subject().unwrap_or(peer_subj);
        let audit_cap = match raw_path {
            Some(path) => format!("{action_or_cap}:{path}"),
            None => action_or_cap.to_string(),
        };
        let deny = |err: CoreError| -> (Result<(), CoreError>, AuditEvent) {
            (
                Err(err.clone()),
                AuditEvent {
                    ts: now_unix,
                    subject: audit_subj.to_string(),
                    cap: audit_cap.clone(),
                    grant_nonce: self.active_grant.as_ref().map(|g| g.nonce.clone()),
                    allow: false,
                    reason: err.to_string(),
                },
            )
        };
        if !self.is_established() {
            return deny(CoreError::NotReady("session not established"));
        }
        if let Err(err) = self.ensure_peer_active_in_roster(roster) {
            return deny(err);
        }
        let Ok(root_id) = self.authoritative_root_id() else {
            return (
                Err(CoreError::NotReady("missing authoritative root")),
                AuditEvent {
                    ts: now_unix,
                    subject: audit_subj.to_string(),
                    cap: audit_cap,
                    grant_nonce: None,
                    allow: false,
                    reason: CoreError::NotReady("missing authoritative root").to_string(),
                },
            );
        };
        let crl = roster.crl(root_id);
        match raw_path {
            Some(path) => authorize_path_capability(
                self.active_grant.as_ref(),
                audit_subj,
                root_id,
                action_or_cap,
                path,
                now_unix,
                crl,
                |issuer| self.lookup_issuer_key(roster, issuer),
            ),
            None => authorize_grant(
                self.active_grant.as_ref(),
                audit_subj,
                root_id,
                action_or_cap,
                now_unix,
                crl,
                |issuer| self.lookup_issuer_key(roster, issuer),
            ),
        }
    }

    fn send_inner(
        &mut self,
        kind: InnerFrameType,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<SessionAction>, CoreError> {
        let mut actions = Vec::new();
        if self.is_closed() {
            return Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "session closed".to_string(),
            });
        }
        if !matches!(self.phase, SessionPhase::Transport(_)) {
            return Err(CoreError::NotReady("session not in transport mode"));
        }
        // Validate and encode the requested frame BEFORE mutating outgoing rekey state.
        let inner = Zeroizing::new(encode_inner_frame(kind, payload)?);
        let SessionPhase::Transport(ref mut tx) = self.phase else {
            return Err(CoreError::NotReady("session not in transport mode"));
        };
        if self.frames_sent >= self.rekey_max_frames
            || now_ms.saturating_sub(self.last_rekey_outgoing_ms) >= self.rekey_max_age_ms
        {
            let rekey_frame = encrypt_inner(tx, InnerFrameType::Rekey, &[])?;
            tx.rekey_outgoing()?;
            self.frames_sent = 0;
            self.last_rekey_outgoing_ms = now_ms;
            actions.push(SessionAction::WriteBytes(rekey_frame));
            actions.push(SessionAction::Rekeyed {
                direction: RekeyDirection::Outgoing,
            });
        }

        let SessionPhase::Transport(ref mut tx) = self.phase else {
            return Err(CoreError::NotReady("session not in transport mode"));
        };
        let frame = encrypt_encoded_inner(tx, &inner)?;
        self.frames_sent = self.frames_sent.saturating_add(1);
        actions.push(SessionAction::WriteBytes(frame));
        Ok(actions)
    }

    fn handle_frame(
        &mut self,
        body: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
        actions: &mut Vec<SessionAction>,
    ) -> Result<(), CoreError> {
        let phase = std::mem::replace(&mut self.phase, SessionPhase::Closed);
        match phase {
            SessionPhase::AwaitMsg2(mut hs) => {
                let pt = hs.read_message_vec(body)?;
                let host_hello: HostHello =
                    serde_json::from_slice(&pt).map_err(|err| CoreError::Json(err.to_string()))?;
                if host_hello.proto_version != 1 {
                    return Err(CoreError::UnsupportedVersion(host_hello.proto_version));
                }
                if host_hello.host_id.is_empty() || has_control_chars(&host_hello.host_id) {
                    return Err(CoreError::ProtocolViolation("invalid host_id in HostHello"));
                }
                self.presented_rotation.clone_from(&host_hello.rotation);
                let host_signing_pub = HybridSigningPublicKey::from_b64url(&host_hello.signing_pub)
                    .map_err(|_| {
                        CoreError::ProtocolViolation("invalid signing_pub in HostHello")
                    })?;

                let target_id = self
                    .target_host_id
                    .as_deref()
                    .ok_or(CoreError::HostKeyUnverified)?;
                if host_hello.host_id != target_id {
                    return Err(CoreError::HostKeyUnverified);
                }

                let peer_static: [u8; 32] =
                    *hs.get_remote_static().ok_or(CoreError::HostKeyUnverified)?;
                if !is_valid_x25519_public_key(&peer_static) {
                    return Err(CoreError::HostKeyUnverified);
                }

                let verified = verify_session_host(
                    roster,
                    target_id,
                    &host_hello.rotation,
                    &peer_static,
                    &host_signing_pub,
                    WIRE_VERSION,
                    self.route_expectation.as_deref(),
                )?;
                if verified.rotation_applied {
                    self.applied_rotation = host_hello.rotation;
                }
                self.verified_recovery = verified.recovery_statement.map(Box::new);

                let negotiated_upgrade: Vec<String> = self
                    .local_upgrade_caps
                    .iter()
                    .filter(|c| host_hello.upgrade.contains(c))
                    .cloned()
                    .collect();
                self.peer_upgrade_caps = host_hello.upgrade;
                self.upgrade_state
                    .set_negotiated(negotiated_upgrade.clone());

                let hello = SessionHello {
                    device_id: self.local_device_id.clone(),
                    grant: self.initial_grant.clone(),
                    crl_seq: self.initial_crl_seq,
                    groups: self.initial_groups.clone(),
                    route_seq: self.local_route_seq,
                    upgrade: negotiated_upgrade,
                };
                let hello_json = Zeroizing::new(
                    serde_json::to_vec(&hello).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let msg3 = hs.write_message_vec(&hello_json)?;
                let final_hash = *hs.get_handshake_hash();
                let tx = hs.into_transport_mode()?;

                self.peer_device_id = Some(target_id.to_string());
                self.peer_static_pub = Some(peer_static);
                self.last_rekey_outgoing_ms = now_ms;
                self.phase = SessionPhase::Transport(Box::new(tx));

                actions.push(SessionAction::WriteBytes(encode_frame(&msg3)?));
                actions.push(SessionAction::Established {
                    peer_device_id: target_id.to_string(),
                    peer_static_pub: peer_static,
                    final_handshake_hash: final_hash,
                });
                Ok(())
            }
            SessionPhase::AwaitMsg1(mut hs) => {
                let pt = hs.read_message_vec(body)?;
                if !pt.is_empty() {
                    return Err(CoreError::ProtocolViolation(
                        "msg1 must carry empty payload",
                    ));
                }
                let hello = HostHello {
                    host_id: self.local_host_id.clone(),
                    proto_version: 1,
                    signing_pub: self.local_signing_pub.to_b64url(),
                    rotation: self.local_rotation_chain.clone(),
                    upgrade: self.local_upgrade_caps.clone(),
                };
                let hello_json = Zeroizing::new(
                    serde_json::to_vec(&hello).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let msg2 = hs.write_message_vec(&hello_json)?;
                actions.push(SessionAction::WriteBytes(encode_frame(&msg2)?));
                self.phase = SessionPhase::AwaitMsg3(hs);
                Ok(())
            }
            SessionPhase::AwaitMsg3(mut hs) => {
                let pt = hs.read_message_vec(body)?;
                let peer_static: [u8; 32] = *hs.get_remote_static().ok_or(
                    CoreError::ProtocolViolation("missing initiator static key in msg3"),
                )?;
                if !is_valid_x25519_public_key(&peer_static) {
                    return Err(CoreError::ProtocolViolation(
                        "invalid or low-order initiator static key",
                    ));
                }
                let hello: SessionHello =
                    serde_json::from_slice(&pt).map_err(|err| CoreError::Json(err.to_string()))?;
                if hello.device_id != device_id(&peer_static) {
                    return Err(CoreError::ProtocolViolation(
                        "SessionHello device_id does not match static key",
                    ));
                }
                if hello
                    .upgrade
                    .iter()
                    .any(|c| !self.local_upgrade_caps.contains(c))
                {
                    return Err(CoreError::ProtocolViolation(
                        "unoffered upgrade capability in session hello",
                    ));
                }

                let peer_entry = roster.lookup_active_by_static(&peer_static)?;
                if peer_entry.min_wire_version > WIRE_VERSION {
                    return Err(CoreError::VersionDowngrade {
                        peer_min: peer_entry.min_wire_version,
                        negotiated: WIRE_VERSION,
                    });
                }
                let canonical_peer_id = peer_entry.device_id.clone();
                let crl = roster.crl(&self.local_host_id);
                if roster.crl_revokes_entry(peer_entry) || roster.crl_revokes_id(&canonical_peer_id)
                {
                    return Err(CoreError::PeerRevoked(canonical_peer_id));
                }

                if let Some(ref grant) = hello.grant {
                    verify_grant_with_chain(
                        grant,
                        &canonical_peer_id,
                        &self.local_host_id,
                        now_unix,
                        crl,
                        |issuer| self.lookup_issuer_key(roster, issuer),
                    )?;
                    self.active_grant = Some(grant.clone());
                }

                let final_hash = *hs.get_handshake_hash();
                let tx = hs.into_transport_mode()?;

                self.peer_crl_seq = hello.crl_seq;
                self.peer_groups = hello.groups;
                self.peer_route_seq = hello.route_seq;
                self.peer_upgrade_caps = hello.upgrade.clone();
                self.upgrade_state.set_negotiated(hello.upgrade);
                self.peer_device_id = Some(canonical_peer_id.clone());
                self.peer_static_pub = Some(peer_static);
                self.last_rekey_outgoing_ms = now_ms;
                self.phase = SessionPhase::Transport(Box::new(tx));

                actions.push(SessionAction::Established {
                    peer_device_id: canonical_peer_id,
                    peer_static_pub: peer_static,
                    final_handshake_hash: final_hash,
                });
                Ok(())
            }
            SessionPhase::Transport(mut tx) => {
                let pt = Zeroizing::new(tx.read_message_vec(body)?);
                let (kind, payload) = decode_inner_frame(&pt)?;
                self.phase = SessionPhase::Transport(tx);

                match kind {
                    InnerFrameType::Data => actions.push(SessionAction::AppData(payload.to_vec())),
                    InnerFrameType::Grant => {
                        let grant: Grant = serde_json::from_slice(payload)
                            .map_err(|err| CoreError::Json(err.to_string()))?;
                        let root_id = self.authoritative_root_id()?.to_string();
                        let subject = self.incoming_grant_subject()?.to_string();
                        verify_grant_with_chain(
                            &grant,
                            &subject,
                            &root_id,
                            now_unix,
                            roster.crl(&root_id),
                            |issuer| self.lookup_issuer_key(roster, issuer),
                        )?;
                        self.active_grant = Some(grant.clone());
                        actions.push(SessionAction::GrantUpdated(grant));
                    }
                    InnerFrameType::Revocation => {
                        let crl: RevocationList = serde_json::from_slice(payload)
                            .map_err(|err| CoreError::Json(err.to_string()))?;
                        let root_id = self.authoritative_root_id()?.to_string();
                        let root_pub = self
                            .lookup_issuer_key(roster, &root_id)
                            .ok_or_else(|| CoreError::IncompletePin(root_id.clone()))?;
                        let seq = crl.seq;
                        roster.ingest_crl(crl, &root_id, &root_pub)?;
                        actions.push(SessionAction::RevocationUpdated {
                            issuer: root_id,
                            seq,
                        });
                        self.verify_peer_and_active_grant(now_unix, roster)?;
                    }
                    InnerFrameType::GroupManifest => {
                        let manifest = GroupManifest::from_wire_bytes(payload)?;
                        actions.push(SessionAction::GroupManifestReceived(Box::new(manifest)));
                    }
                    InnerFrameType::GroupRendezvous => {
                        let frame = decode_group_rendezvous_frame(payload)?;
                        actions.push(SessionAction::GroupRendezvousReceived(frame));
                    }
                    InnerFrameType::Rekey => {
                        if let SessionPhase::Transport(ref mut tx_mut) = self.phase {
                            tx_mut.rekey_incoming()?;
                        }
                        self.verify_peer_and_active_grant(now_unix, roster)?;
                        actions.push(SessionAction::Rekeyed {
                            direction: RekeyDirection::Incoming,
                        });
                    }
                    InnerFrameType::Ping => {
                        let cookie: [u8; 8] = payload.try_into().map_err(|_| {
                            CoreError::InvalidInnerFramePayload("PING must be 8 bytes")
                        })?;
                        let mut reply = self.send_inner(InnerFrameType::Pong, &cookie, now_ms)?;
                        actions.append(&mut reply);
                    }
                    InnerFrameType::Pong => {
                        let cookie: [u8; 8] = payload.try_into().map_err(|_| {
                            CoreError::InvalidInnerFramePayload("PONG must be 8 bytes")
                        })?;
                        actions.push(SessionAction::PongReceived(u64::from_be_bytes(cookie)));
                    }
                    InnerFrameType::Close => {
                        let code = u16::from_be_bytes([payload[0], payload[1]]);
                        let reason = String::from_utf8(payload[2..].to_vec()).map_err(|_| {
                            CoreError::InvalidInnerFramePayload("CLOSE reason must be UTF-8")
                        })?;
                        self.phase = SessionPhase::Closed;
                        actions.push(SessionAction::CloseTransport { code, reason });
                    }
                    InnerFrameType::RouteSet => receive_route_set(
                        self.role,
                        self.local_route_seq.is_some(),
                        payload,
                        &mut self.route_sets,
                    )?,
                    InnerFrameType::PathUpgrade => {
                        let msg = self.upgrade_state.receive(payload)?;
                        actions.push(SessionAction::PathUpgradeReceived(msg));
                    }
                    InnerFrameType::Padding | InnerFrameType::Padded => {
                        return Err(CoreError::UnknownInnerFrameType(kind as u8));
                    }
                }
                Ok(())
            }
            SessionPhase::Init(_) => Err(CoreError::NotReady("initiator must call start() first")),
            SessionPhase::AwaitPreamble(_) => Err(CoreError::NotReady("session preamble missing")),
            SessionPhase::Closed => Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "session closed".to_string(),
            }),
        }
    }

    fn verify_peer_and_active_grant(
        &mut self,
        now_unix: u64,
        roster: &Roster,
    ) -> Result<(), CoreError> {
        self.ensure_peer_active_in_roster(roster)?;
        let root_id = self.authoritative_root_id()?.to_string();
        let crl = roster.crl(&root_id);
        let local_revoked = crl.is_some_and(|list| {
            list.revoked_devices
                .iter()
                .any(|d| d == &self.local_device_id)
        });
        if local_revoked
            || self
                .peer_device_id
                .as_deref()
                .is_some_and(|peer| roster.crl_revokes_id(peer))
        {
            return Err(CoreError::PeerRevoked(
                self.peer_device_id
                    .clone()
                    .unwrap_or_else(|| self.local_device_id.clone()),
            ));
        }
        if let Some(ref grant) = self.active_grant {
            let subject = self.incoming_grant_subject()?.to_string();
            verify_grant_with_chain(grant, &subject, &root_id, now_unix, crl, |issuer| {
                self.lookup_issuer_key(roster, issuer)
            })?;
        }
        Ok(())
    }

    fn ensure_peer_active_in_roster(&self, roster: &Roster) -> Result<(), CoreError> {
        match self.role {
            SessionRole::Responder => {
                let peer_static = self
                    .peer_static_pub
                    .ok_or(CoreError::NotReady("peer static missing"))?;
                roster.lookup_active_by_static(&peer_static)?;
                Ok(())
            }
            SessionRole::Initiator => {
                let host_id = self
                    .target_host_id
                    .as_deref()
                    .ok_or(CoreError::NotReady("target host missing"))?;
                let entry = roster
                    .get(host_id)
                    .ok_or_else(|| roster.missing_peer_error(host_id))?;
                match entry.state {
                    PeerState::Pending => Err(CoreError::PeerPending(host_id.to_string())),
                    PeerState::Revoked => Err(CoreError::PeerRevoked(host_id.to_string())),
                    PeerState::Active => {
                        if roster.crl_revokes_entry(entry) {
                            return Err(CoreError::PeerRevoked(host_id.to_string()));
                        }
                        entry.require_complete_pin()?;
                        Ok(())
                    }
                }
            }
        }
    }

    fn authoritative_root_id(&self) -> Result<&str, CoreError> {
        match self.role {
            SessionRole::Responder => Ok(&self.local_host_id),
            SessionRole::Initiator => self
                .target_host_id
                .as_deref()
                .ok_or(CoreError::NotReady("missing target host")),
        }
    }

    fn incoming_grant_subject(&self) -> Result<&str, CoreError> {
        match self.role {
            SessionRole::Responder => self
                .peer_device_id
                .as_deref()
                .ok_or(CoreError::NotReady("missing peer device_id")),
            SessionRole::Initiator => Ok(&self.local_device_id),
        }
    }

    fn lookup_issuer_key(
        &self,
        roster: &Roster,
        issuer_id: &str,
    ) -> Option<HybridSigningPublicKey> {
        if self.role == SessionRole::Responder && issuer_id == self.local_host_id {
            Some(self.local_signing_pub.clone())
        } else {
            roster.lookup_active_signing_key(issuer_id)
        }
    }
}

/// Fails closed with [`CoreError::VersionDowngrade`] when `roster` pins `target_host_id` to a
/// `min_wire_version` above Wire v1, before any v1 bytes are emitted.
pub fn check_peer_allows_wire_v1(roster: &Roster, target_host_id: &str) -> Result<(), CoreError> {
    if let Some(entry) = roster.get(target_host_id) {
        let floor = entry
            .min_wire_version
            .max(roster.pairing_floor(&entry.static_pub));
        if floor > WIRE_VERSION {
            return Err(CoreError::VersionDowngrade {
                peer_min: floor,
                negotiated: WIRE_VERSION,
            });
        }
    }
    Ok(())
}

fn build_handshake(
    initiator: bool,
    identity: &EndpointIdentity,
    fixed_ephemeral: Option<[u8; 32]>,
) -> Result<NoiseHfsHandshake, CoreError> {
    let preamble = Preamble::v1(Intent::Session).encode();
    let mut builder = NoiseHfsHandshakeBuilder::new()
        .local_private_key(identity.static_key().secret_bytes())
        .prologue(&preamble);
    if let Some(eph) = fixed_ephemeral {
        builder = builder.fixed_ephemeral_for_testing_only(eph);
    }
    if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
}

fn encrypt_encoded_inner(tx: &mut NoiseTransport, inner: &[u8]) -> Result<Vec<u8>, CoreError> {
    let ct = tx.write_message_vec(inner)?;
    encode_frame(&ct)
}

fn encrypt_inner(
    tx: &mut NoiseTransport,
    kind: InnerFrameType,
    payload: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let inner = Zeroizing::new(encode_inner_frame(kind, payload)?);
    encrypt_encoded_inner(tx, &inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SigningKeypair, StaticKeypair};

    #[test]
    fn close_code_registry_matches_spec() {
        assert_eq!(SessionCloseCode::PEER_REVOKED, 4001);
        assert_eq!(SessionCloseCode::PEER_PENDING, 4004);
        assert_eq!(SessionCloseCode::REVOKED, SessionCloseCode::PEER_REVOKED);
        assert_eq!(SessionCloseCode::GRANT_EXPIRED, 4002);
        assert_eq!(SessionCloseCode::KEY_UNVERIFIED, 4003);
    }

    fn established_pair() -> (SessionMachine, SessionMachine) {
        established_pair_with(None)
    }

    fn established_pair_with(route_seq: Option<u64>) -> (SessionMachine, SessionMachine) {
        let host = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x51; 32]),
            SigningKeypair::from_seed([0x52; 32]),
        );
        let cli = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x53; 32]),
            SigningKeypair::from_seed([0x54; 32]),
        );
        let mut host_roster = Roster::new();
        host_roster
            .record_pending_pair(
                *cli.static_key().public_bytes(),
                None,
                "Cli".to_string(),
                "cli".to_string(),
                "abcd".to_string(),
            )
            .unwrap();
        host_roster
            .confirm_peer(&cli.device_id(), Some("abcd"))
            .unwrap();

        let mut cli_roster = Roster::new();
        cli_roster
            .insert_pinned_host(
                host.host_id().to_string(),
                "Host".to_string(),
                *host.static_key().public_bytes(),
                Some(host.signing_key().public_key().clone()),
                0,
                vec![],
            )
            .unwrap();

        let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, Some(7), None)
            .unwrap()
            .with_route_seq(route_seq)
            .unwrap();
        let mut resp = SessionMachine::new_responder(&host, None).unwrap();

        let mut m1 = Vec::new();
        for a in init.start().unwrap() {
            if let SessionAction::WriteBytes(b) = a {
                m1.extend_from_slice(&b);
            }
        }
        let mut m2 = Vec::new();
        for a in resp
            .feed_bytes(&m1, 1_795_564_800, 1, &mut host_roster)
            .unwrap()
        {
            if let SessionAction::WriteBytes(b) = a {
                m2.extend_from_slice(&b);
            }
        }
        let mut m3 = Vec::new();
        for a in init
            .feed_bytes(&m2, 1_795_564_800, 2, &mut cli_roster)
            .unwrap()
        {
            if let SessionAction::WriteBytes(b) = a {
                m3.extend_from_slice(&b);
            }
        }
        resp.feed_bytes(&m3, 1_795_564_800, 3, &mut host_roster)
            .unwrap();
        (init, resp)
    }

    fn host_identity() -> EndpointIdentity {
        EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x51; 32]),
            SigningKeypair::from_seed([0x52; 32]),
        )
    }

    fn route_set_payload(seq: u64) -> Vec<u8> {
        RouteSet::sign(
            &host_identity(),
            seq,
            1_795_564_800,
            vec!["direct:192.168.1.20:9100".into()],
        )
        .unwrap()
        .encode()
    }

    fn malformed_route_sets() -> [Vec<u8>; 2] {
        let mut trailing = route_set_payload(1);
        trailing.push(0);
        [vec![0; crate::routes::MIN_ROUTE_SET_PAYLOAD - 1], trailing]
    }

    /// Encrypts a raw inner frame from `m`, bypassing the send-side checks.
    fn raw_frame(m: &mut SessionMachine, kind: InnerFrameType, payload: &[u8]) -> Vec<u8> {
        let SessionPhase::Transport(ref mut tx) = m.phase else {
            panic!("not established");
        };
        encrypt_inner(tx, kind, payload).unwrap()
    }

    fn feed(m: &mut SessionMachine, bytes: &[u8]) -> Result<Vec<SessionAction>, CoreError> {
        m.feed_bytes(bytes, 1_795_564_800, 10, &mut Roster::new())
    }

    #[test]
    fn route_set_negotiation_send_and_queue() {
        let (mut init, mut resp) = established_pair_with(Some(3));
        assert_eq!(resp.peer_route_seq(), Some(3));
        for seq in 1..=5 {
            let mut wire = Vec::new();
            for a in resp.send_route_set(&route_set_payload(seq), 10).unwrap() {
                if let SessionAction::WriteBytes(b) = a {
                    wire.extend_from_slice(&b);
                }
            }
            assert_eq!(feed(&mut init, &wire), Ok(vec![]));
        }
        let seqs: Vec<u64> = init.take_route_sets().iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![2, 3, 4, 5]);
        assert!(init.take_route_sets().is_empty());
        assert!(init.is_established());
        assert!(matches!(
            init.send_route_set(&route_set_payload(1), 10),
            Err(CoreError::NotReady(_))
        ));
        assert_eq!(
            resp.send_route_set(&[0; 8], 10),
            Err(CoreError::InvalidInnerFramePayload("route set"))
        );
        assert!(resp.is_established());

        let (_init, mut plain_resp) = established_pair();
        assert_eq!(plain_resp.peer_route_seq(), None);
        assert!(matches!(
            plain_resp.send_route_set(&route_set_payload(1), 10),
            Err(CoreError::NotReady(_))
        ));
    }

    #[test]
    fn negotiated_malformed_route_set_closes() {
        for payload in malformed_route_sets() {
            let (mut init, mut resp) = established_pair_with(Some(0));
            let wire = raw_frame(&mut resp, InnerFrameType::RouteSet, &payload);
            assert_eq!(
                feed(&mut init, &wire),
                Err(CoreError::InvalidInnerFramePayload("route set"))
            );
            assert!(init.is_closed());
        }
    }

    #[test]
    fn unnegotiated_initiator_drops_route_sets_unparsed() {
        let (mut init, mut resp) = established_pair();
        let [short, trailing] = malformed_route_sets();
        for payload in [route_set_payload(1), short, trailing] {
            let wire = raw_frame(&mut resp, InnerFrameType::RouteSet, &payload);
            assert_eq!(feed(&mut init, &wire), Ok(vec![]));
            assert!(init.is_established());
        }
        assert!(init.take_route_sets().is_empty());
        let wire = raw_frame(&mut resp, InnerFrameType::Data, b"open");
        assert_eq!(
            feed(&mut init, &wire),
            Ok(vec![SessionAction::AppData(b"open".to_vec())])
        );
    }

    #[test]
    fn responder_closes_on_route_set() {
        let [short, _] = malformed_route_sets();
        for payload in [route_set_payload(1), short] {
            let (mut init, mut resp) = established_pair_with(Some(0));
            let wire = raw_frame(&mut init, InnerFrameType::RouteSet, &payload);
            assert_eq!(
                feed(&mut resp, &wire),
                Err(CoreError::InvalidInnerFramePayload(
                    "route set from initiator"
                ))
            );
            assert!(resp.is_closed());
        }
    }

    #[test]
    fn responder_records_peer_crl_seq_from_session_hello() {
        let (_init, resp) = established_pair();
        assert_eq!(resp.peer_crl_seq(), Some(7));
    }

    #[test]
    fn send_close_rejects_oversized_reason_without_closing_session() {
        let (mut init, _resp) = established_pair();
        let oversized = "x".repeat(crate::wire::MAX_APP_DATA_LEN);
        assert!(matches!(
            init.send_close(1000, &oversized),
            Err(CoreError::FrameTooLarge { .. })
        ));
        assert!(init.is_established());
        assert!(!init.is_closed());
        let actions = init.send_close(1000, "ok").expect("subsequent valid close");
        assert!(init.is_closed());
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, SessionAction::WriteBytes(_)))
        );
    }

    #[test]
    fn priv04_preflight_rejects_v2_floor_before_any_v1_bytes() {
        use crate::wire::WIRE_VERSION_V2;

        let host = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x61; 32]),
            SigningKeypair::from_seed([0x62; 32]),
        )
        .with_host_id("host-floor");
        let cli = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x63; 32]),
            SigningKeypair::from_seed([0x64; 32]),
        );
        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                "host-floor".to_string(),
                "Host".to_string(),
                *host.static_key().public_bytes(),
                Some(host.signing_key().public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        assert_eq!(check_peer_allows_wire_v1(&roster, "host-floor"), Ok(()));
        assert_eq!(check_peer_allows_wire_v1(&roster, "unknown-host"), Ok(()));
        assert!(
            SessionMachine::new_initiator_with_roster(
                &cli,
                "host-floor",
                None,
                None,
                None,
                &roster
            )
            .is_ok()
        );

        roster
            .set_peer_min_wire_version("host-floor", WIRE_VERSION_V2)
            .unwrap();
        let expected = CoreError::VersionDowngrade {
            peer_min: WIRE_VERSION_V2,
            negotiated: WIRE_VERSION,
        };
        assert_eq!(
            check_peer_allows_wire_v1(&roster, "host-floor"),
            Err(expected.clone())
        );
        assert_eq!(
            SessionMachine::new_initiator_with_roster(
                &cli,
                "host-floor",
                None,
                None,
                None,
                &roster
            )
            .err(),
            Some(expected.clone())
        );

        // A sibling alias pinning the same static key inherits the stricter floor.
        roster
            .insert_pinned_host(
                "host-floor-alias".to_string(),
                "Alias".to_string(),
                *host.static_key().public_bytes(),
                Some(host.signing_key().public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        assert_eq!(
            check_peer_allows_wire_v1(&roster, "host-floor-alias"),
            Err(expected)
        );
    }
}
