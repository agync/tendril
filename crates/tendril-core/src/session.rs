//! Sans-I/O Noise XX session state machine with grant enforcement, auto-rekey, and CRL checks.

use std::fmt;

use snow::params::NoiseParams;
use snow::{HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::crypto::{
    b64url_decode_array, device_id, has_control_chars, is_valid_x25519_public_key,
    new_noise_builder,
};
use crate::error::CoreError;
use crate::grants::{
    AuditEvent, Grant, RevocationList, authorize_grant, authorize_path_capability,
    verify_grant_with_chain,
};
use crate::identity::{EndpointIdentity, RotationRecord};
use crate::roster::{PeerState, Roster};
use crate::wire::{
    HostHello, InnerFrameType, Intent, MAX_FRAME_LEN, NOISE_PATTERN, Preamble,
    ResumableFrameReader, SessionHello, decode_inner_frame, encode_frame, encode_inner_frame,
};

/// Maximum encrypted transport frames sent before triggering automatic `0x04 REKEY` (`2^20`).
pub const REKEY_MAX_FRAMES: u64 = 1_048_576;

/// Maximum elapsed session duration in milliseconds before triggering automatic `0x04 REKEY` (`15m`).
pub const REKEY_MAX_AGE_MS: u64 = 15 * 60 * 1_000;

/// Canonical `0x07 CLOSE` reason codes.
pub struct SessionCloseCode;

impl SessionCloseCode {
    pub const NORMAL: u16 = 1000;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const POLICY_VIOLATION: u16 = 1008;
    pub const REVOKED: u16 = 4001;
    pub const GRANT_EXPIRED: u16 = 4002;
    pub const KEY_UNVERIFIED: u16 = 4003;
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

enum SessionPhase {
    Init(Box<HandshakeState>),
    AwaitMsg2(Box<HandshakeState>),
    AwaitPreamble(Box<HandshakeState>),
    AwaitMsg1(Box<HandshakeState>),
    AwaitMsg3(Box<HandshakeState>),
    Transport(Box<TransportState>),
    Closed,
}

/// Pure Sans-I/O `intent = session` protocol driver (`Noise_XX_25519_ChaChaPoly_SHA256`).
pub struct SessionMachine {
    role: SessionRole,
    phase: SessionPhase,
    reader: ResumableFrameReader,
    local_host_id: String,
    local_device_id: String,
    local_signing_pub: [u8; 32],
    local_rotation_chain: Vec<RotationRecord>,
    applied_rotation: Vec<RotationRecord>,
    target_host_id: Option<String>,
    initial_grant: Option<Grant>,
    initial_crl_seq: Option<u64>,
    peer_crl_seq: Option<u64>,
    peer_device_id: Option<String>,
    peer_static_pub: Option<[u8; 32]>,
    active_grant: Option<Grant>,
    frames_sent: u64,
    last_rekey_outgoing_ms: u64,
    rekey_max_frames: u64,
    rekey_max_age_ms: u64,
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
            local_signing_pub: *local_identity.signing_key().public_bytes(),
            local_rotation_chain: local_identity.rotation_chain().to_vec(),
            applied_rotation: Vec::new(),
            target_host_id: Some(target_host_id.into()),
            initial_grant: initial_grant.clone(),
            initial_crl_seq: crl_seq,
            peer_crl_seq: None,
            peer_device_id: None,
            peer_static_pub: None,
            active_grant: initial_grant,
            frames_sent: 0,
            last_rekey_outgoing_ms: 0,
            rekey_max_frames: REKEY_MAX_FRAMES,
            rekey_max_age_ms: REKEY_MAX_AGE_MS,
        })
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
            local_signing_pub: *local_identity.signing_key().public_bytes(),
            local_rotation_chain: local_identity.rotation_chain().to_vec(),
            applied_rotation: Vec::new(),
            target_host_id: None,
            initial_grant: None,
            initial_crl_seq: None,
            peer_crl_seq: None,
            peer_device_id: None,
            peer_static_pub: None,
            active_grant: None,
            frames_sent: 0,
            last_rekey_outgoing_ms: 0,
            rekey_max_frames: REKEY_MAX_FRAMES,
            rekey_max_age_ms: REKEY_MAX_AGE_MS,
        })
    }

    /// Overrides the automatic rekey thresholds (`frames`, `age_ms`).
    pub fn set_rekey_thresholds(&mut self, max_frames: u64, max_age_ms: u64) {
        self.rekey_max_frames = max_frames.max(1);
        self.rekey_max_age_ms = max_age_ms.max(1);
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
        let mut msg1 = vec![0u8; MAX_FRAME_LEN];
        let n = hs
            .write_message(&[], &mut msg1)
            .map_err(|err| CoreError::Noise(format!("{err}")))?;
        let frame = encode_frame(&msg1[..n])?;
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

    /// Explicitly initiates a Noise `0x04 REKEY` transition on the outgoing cipher state.
    pub fn send_rekey(&mut self, now_ms: u64) -> Result<Vec<SessionAction>, CoreError> {
        let SessionPhase::Transport(ref mut tx) = self.phase else {
            return Err(CoreError::NotReady("session not in transport mode"));
        };
        let frame = encrypt_inner(tx, InnerFrameType::Rekey, &[])?;
        tx.rekey_outgoing();
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
        let prev = std::mem::replace(&mut self.phase, SessionPhase::Closed);
        let SessionPhase::Transport(mut tx) = prev else {
            return Err(CoreError::NotReady("session not in transport mode"));
        };
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        let frame = encrypt_inner(&mut tx, InnerFrameType::Close, &payload)?;
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
            tx.rekey_outgoing();
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
                let mut pt = Zeroizing::new(vec![0u8; MAX_FRAME_LEN]);
                let n = hs
                    .read_message(body, &mut pt)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let host_hello: HostHello = serde_json::from_slice(&pt[..n])
                    .map_err(|err| CoreError::Json(err.to_string()))?;
                if host_hello.proto_version != 1 {
                    return Err(CoreError::UnsupportedVersion(host_hello.proto_version));
                }
                if host_hello.host_id.is_empty() || has_control_chars(&host_hello.host_id) {
                    return Err(CoreError::ProtocolViolation("invalid host_id in HostHello"));
                }

                let target_id = self
                    .target_host_id
                    .as_deref()
                    .ok_or(CoreError::HostKeyUnverified)?;
                if host_hello.host_id != target_id {
                    return Err(CoreError::HostKeyUnverified);
                }

                let peer_static: [u8; 32] = hs
                    .get_remote_static()
                    .ok_or(CoreError::HostKeyUnverified)?
                    .try_into()
                    .map_err(|_| CoreError::HostKeyUnverified)?;
                if !is_valid_x25519_public_key(&peer_static) {
                    return Err(CoreError::HostKeyUnverified);
                }

                let (_, pinned_signing) = match roster.get(target_id) {
                    Some(entry) => match entry.state {
                        PeerState::Pending => {
                            return Err(CoreError::PeerPending(target_id.to_string()));
                        }
                        PeerState::Revoked => {
                            return Err(CoreError::PeerRevoked(target_id.to_string()));
                        }
                        PeerState::Active => entry.require_complete_pin()?,
                    },
                    None => return Err(CoreError::HostKeyUnverified),
                };

                let presented_signing = if host_hello.rotation.is_empty() {
                    pinned_signing
                } else {
                    let last = host_hello
                        .rotation
                        .last()
                        .ok_or(CoreError::HostKeyUnverified)?;
                    b64url_decode_array(&last.new_signing_pub)
                        .map_err(|_| CoreError::HostKeyUnverified)?
                };

                match roster.apply_verified_rotation(
                    target_id,
                    &host_hello.rotation,
                    &peer_static,
                    &presented_signing,
                ) {
                    Ok(_) => {
                        if !host_hello.rotation.is_empty() {
                            self.applied_rotation = host_hello.rotation;
                        }
                    }
                    Err(
                        err @ (CoreError::RotationForkDetected { .. }
                        | CoreError::IncompletePin(_)
                        | CoreError::PeerPending(_)
                        | CoreError::PeerRevoked(_)),
                    ) => return Err(err),
                    Err(_) => return Err(CoreError::HostKeyUnverified),
                }

                let hello = SessionHello {
                    device_id: self.local_device_id.clone(),
                    grant: self.initial_grant.clone(),
                    crl_seq: self.initial_crl_seq,
                };
                let hello_json = Zeroizing::new(
                    serde_json::to_vec(&hello).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let mut msg3 = vec![0u8; MAX_FRAME_LEN];
                let n3 = hs
                    .write_message(&hello_json, &mut msg3)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let final_hash: [u8; 32] = hs
                    .get_handshake_hash()
                    .try_into()
                    .map_err(|_| CoreError::Noise("unexpected handshake hash length".into()))?;
                let tx = hs
                    .into_transport_mode()
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;

                self.peer_device_id = Some(target_id.to_string());
                self.peer_static_pub = Some(peer_static);
                self.last_rekey_outgoing_ms = now_ms;
                self.phase = SessionPhase::Transport(Box::new(tx));

                actions.push(SessionAction::WriteBytes(encode_frame(&msg3[..n3])?));
                actions.push(SessionAction::Established {
                    peer_device_id: target_id.to_string(),
                    peer_static_pub: peer_static,
                    final_handshake_hash: final_hash,
                });
                Ok(())
            }
            SessionPhase::AwaitMsg1(mut hs) => {
                let mut pt = Zeroizing::new(vec![0u8; MAX_FRAME_LEN]);
                let n = hs
                    .read_message(body, &mut pt)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                if n != 0 {
                    return Err(CoreError::ProtocolViolation(
                        "msg1 must carry empty payload",
                    ));
                }
                let hello = HostHello {
                    host_id: self.local_host_id.clone(),
                    proto_version: 1,
                    rotation: self.local_rotation_chain.clone(),
                };
                let hello_json = Zeroizing::new(
                    serde_json::to_vec(&hello).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let mut msg2 = vec![0u8; MAX_FRAME_LEN];
                let n2 = hs
                    .write_message(&hello_json, &mut msg2)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                actions.push(SessionAction::WriteBytes(encode_frame(&msg2[..n2])?));
                self.phase = SessionPhase::AwaitMsg3(hs);
                Ok(())
            }
            SessionPhase::AwaitMsg3(mut hs) => {
                let mut pt = Zeroizing::new(vec![0u8; MAX_FRAME_LEN]);
                let n = hs
                    .read_message(body, &mut pt)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let peer_static: [u8; 32] = hs
                    .get_remote_static()
                    .ok_or(CoreError::ProtocolViolation(
                        "missing initiator static key in msg3",
                    ))?
                    .try_into()
                    .map_err(|_| CoreError::ProtocolViolation("invalid initiator static length"))?;
                if !is_valid_x25519_public_key(&peer_static) {
                    return Err(CoreError::ProtocolViolation(
                        "invalid or low-order initiator static key",
                    ));
                }
                let hello: SessionHello = serde_json::from_slice(&pt[..n])
                    .map_err(|err| CoreError::Json(err.to_string()))?;
                if hello.device_id != device_id(&peer_static) {
                    return Err(CoreError::ProtocolViolation(
                        "SessionHello device_id does not match static key",
                    ));
                }

                let canonical_peer_id = roster
                    .lookup_active_by_static(&peer_static)?
                    .device_id
                    .clone();
                let crl = roster.crl(&self.local_host_id);
                if let Some(list) = crl
                    && list.revoked_devices.iter().any(|d| d == &canonical_peer_id)
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

                let final_hash: [u8; 32] = hs
                    .get_handshake_hash()
                    .try_into()
                    .map_err(|_| CoreError::Noise("unexpected handshake hash length".into()))?;
                let tx = hs
                    .into_transport_mode()
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;

                self.peer_crl_seq = hello.crl_seq;
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
                let mut pt = Zeroizing::new(vec![0u8; MAX_FRAME_LEN]);
                let n = tx
                    .read_message(body, &mut pt)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let (kind, payload) = decode_inner_frame(&pt[..n])?;
                let payload_owned = Zeroizing::new(payload.to_vec());
                self.phase = SessionPhase::Transport(tx);

                match kind {
                    InnerFrameType::Data => actions.push(SessionAction::AppData(payload.to_vec())),
                    InnerFrameType::Grant => {
                        let grant: Grant = serde_json::from_slice(&payload_owned)
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
                        let crl: RevocationList = serde_json::from_slice(&payload_owned)
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
                    InnerFrameType::Rekey => {
                        if let SessionPhase::Transport(ref mut tx_mut) = self.phase {
                            tx_mut.rekey_incoming();
                        }
                        self.verify_peer_and_active_grant(now_unix, roster)?;
                        actions.push(SessionAction::Rekeyed {
                            direction: RekeyDirection::Incoming,
                        });
                    }
                    InnerFrameType::Ping => {
                        let cookie: [u8; 8] =
                            payload_owned.as_slice().try_into().map_err(|_| {
                                CoreError::InvalidInnerFramePayload("PING must be 8 bytes")
                            })?;
                        let mut reply = self.send_inner(InnerFrameType::Pong, &cookie, now_ms)?;
                        actions.append(&mut reply);
                    }
                    InnerFrameType::Pong => {
                        let cookie: [u8; 8] =
                            payload_owned.as_slice().try_into().map_err(|_| {
                                CoreError::InvalidInnerFramePayload("PONG must be 8 bytes")
                            })?;
                        actions.push(SessionAction::PongReceived(u64::from_be_bytes(cookie)));
                    }
                    InnerFrameType::Close => {
                        let code = u16::from_be_bytes([payload_owned[0], payload_owned[1]]);
                        let reason =
                            String::from_utf8(payload_owned[2..].to_vec()).map_err(|_| {
                                CoreError::InvalidInnerFramePayload("CLOSE reason must be UTF-8")
                            })?;
                        self.phase = SessionPhase::Closed;
                        actions.push(SessionAction::CloseTransport { code, reason });
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
        if let Some(list) = crl
            && list.revoked_devices.iter().any(|d| {
                d == &self.local_device_id || Some(d.as_str()) == self.peer_device_id.as_deref()
            })
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
                    .ok_or_else(|| CoreError::PeerNotFound(host_id.to_string()))?;
                match entry.state {
                    PeerState::Pending => Err(CoreError::PeerPending(host_id.to_string())),
                    PeerState::Revoked => Err(CoreError::PeerRevoked(host_id.to_string())),
                    PeerState::Active => {
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

    fn lookup_issuer_key(&self, roster: &Roster, issuer_id: &str) -> Option<[u8; 32]> {
        if self.role == SessionRole::Responder && issuer_id == self.local_host_id {
            Some(self.local_signing_pub)
        } else {
            roster.lookup_active_signing_key(issuer_id)
        }
    }
}

fn build_handshake(
    initiator: bool,
    identity: &EndpointIdentity,
    fixed_ephemeral: Option<[u8; 32]>,
) -> Result<HandshakeState, CoreError> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|err| CoreError::Noise(format!("{err}")))?;
    let preamble = Preamble::v1(Intent::Session).encode();
    let mut builder = new_noise_builder(params)
        .local_private_key(identity.static_key().secret_bytes())
        .map_err(|err| CoreError::Noise(format!("{err}")))?
        .prologue(&preamble)
        .map_err(|err| CoreError::Noise(format!("{err}")))?;
    if let Some(ref eph) = fixed_ephemeral {
        builder = builder.fixed_ephemeral_key_for_testing_only(eph);
    }
    if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(|err| CoreError::Noise(format!("{err}")))
}

fn encrypt_encoded_inner(tx: &mut TransportState, inner: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut out_ct = vec![0u8; MAX_FRAME_LEN];
    let n = tx
        .write_message(inner, &mut out_ct)
        .map_err(|err| CoreError::Noise(format!("{err}")))?;
    encode_frame(&out_ct[..n])
}

fn encrypt_inner(
    tx: &mut TransportState,
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
    fn responder_records_peer_crl_seq_from_session_hello() {
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
        host_roster.confirm_peer(&cli.device_id(), None).unwrap();

        let mut cli_roster = Roster::new();
        cli_roster
            .insert_pinned_host(
                host.host_id().to_string(),
                "Host".to_string(),
                *host.static_key().public_bytes(),
                Some(*host.signing_key().public_bytes()),
                0,
                vec![],
            )
            .unwrap();

        let mut init =
            SessionMachine::new_initiator(&cli, host.host_id(), None, Some(7), None).unwrap();
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
        assert_eq!(resp.peer_crl_seq(), Some(7));
    }
}
