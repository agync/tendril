//! Wire constants, preamble encoding, outer framing, and handshake payloads.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::error::CoreError;
use crate::grants::Grant;
use crate::group::{
    GROUP_RENDEZVOUS_FRAME_LEN, GroupSeq, MAX_GROUP_MANIFEST_LEN, validate_group_seqs,
};
use crate::identity::RotationRecord;
use crate::routes::MAX_ROUTE_SEQ;

/// Fixed Noise protocol pattern for Tendril v1 and v2.
pub const NOISE_PATTERN: &str = "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256";

/// Three-byte ASCII magic opening every Tendril preamble.
pub const PREAMBLE_MAGIC: [u8; 3] = *b"TND";

/// Exact byte length of the cleartext preamble (and standard Noise prologue).
pub const PREAMBLE_LEN: usize = 6;

/// Wire protocol version v1 encoded in the cleartext preamble.
pub const WIRE_VERSION: u8 = 0x01;

/// Wire protocol version v2 (privacy profile) encoded in the cleartext preamble.
pub const WIRE_VERSION_V2: u8 = 0x02;

/// Reserved byte in the v1 preamble; must always be zero.
pub const PREAMBLE_RESERVED: u8 = 0x00;

/// Default v2 preamble flags byte (standard v2 session or standard v2 pairing).
pub const PREAMBLE_FLAG_NONE: u8 = 0x00;

/// Wire v2 pairing preamble flag enabling hybrid PAKE + ML-KEM-768 pairing (`intent == 0x02` only).
pub const FLAG_PAKE_PAIR: u8 = 0x01;

/// Length in bytes of the Noise ChaChaPoly AEAD authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Maximum length in bytes of a single outer framed body (`65535 - 16`).
pub const MAX_FRAME_LEN: usize = 65_519;

/// Maximum decrypted plaintext bytes inside a single transport AEAD frame.
pub const MAX_TRANSPORT_PLAINTEXT: usize = MAX_FRAME_LEN - AEAD_TAG_LEN;

/// Maximum application bytes carried inside a `0x01 DATA` inner frame.
pub const MAX_APP_DATA_LEN: usize = MAX_TRANSPORT_PLAINTEXT - 1;

/// Maximum total bytes queued inside [`ResumableFrameReader`] before rejecting unbounded buffering.
pub const MAX_READ_BUFFER_LEN: usize = 4 * (2 + MAX_FRAME_LEN);

/// Upgrade capability string for in-band WebRTC DataChannel direct path upgrade.
pub const UPGRADE_CAP_WEBRTC_V1: &str = "webrtc/v1";

/// Maximum number of upgrade capability strings advertised in `HostHello` / `SessionHello`.
pub const MAX_UPGRADE_CAPS: usize = 4;

/// Maximum byte length of a single upgrade capability identifier.
pub const MAX_UPGRADE_CAP_LEN: usize = 32;

/// Maximum encoded JSON byte length of a `0x0D PATH_UPGRADE` inner frame payload.
pub const MAX_PATH_UPGRADE_LEN: usize = 16_384;

/// Maximum number of `0x0D PATH_UPGRADE` offers permitted within a single Tendril session.
pub const MAX_PATH_UPGRADE_OFFERS_PER_SESSION: usize = 4;

/// Ordered SCTP DataChannel label negotiated during `webrtc/v1` upgrades.
pub const WEBRTC_DATACHANNEL_LABEL: &str = "tendril/v1";

/// Handshake intent carried in the 6-byte cleartext preamble.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Intent {
    /// Authenticated session for application data and capability enforcement.
    Session = 0x01,
    /// Pairing ceremony proving possession of a single-use pairing code.
    Pair = 0x02,
}

impl TryFrom<u8> for Intent {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Session),
            0x02 => Ok(Self::Pair),
            other => Err(CoreError::UnknownIntent(other)),
        }
    }
}

/// Parsed 6-byte cleartext preamble (and verbatim Noise prologue for v1 and standard v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preamble {
    pub version: u8,
    pub intent: Intent,
    pub flags: u8,
}

impl Preamble {
    /// Constructs a v1 preamble for `intent`.
    #[must_use]
    pub const fn v1(intent: Intent) -> Self {
        Self {
            version: WIRE_VERSION,
            intent,
            flags: PREAMBLE_RESERVED,
        }
    }

    /// Constructs a v2 preamble for `intent` and `flags`.
    #[must_use]
    pub const fn v2(intent: Intent, flags: u8) -> Self {
        Self {
            version: WIRE_VERSION_V2,
            intent,
            flags,
        }
    }

    /// Constructs a v2 PAKE pairing preamble (`version = 0x02`, `intent = Pair`, `flags = 0x01`).
    #[must_use]
    pub const fn v2_pake_pair() -> Self {
        Self {
            version: WIRE_VERSION_V2,
            intent: Intent::Pair,
            flags: FLAG_PAKE_PAIR,
        }
    }

    /// Encodes the preamble as its exact 6 wire bytes.
    #[must_use]
    pub const fn encode(self) -> [u8; PREAMBLE_LEN] {
        [
            PREAMBLE_MAGIC[0],
            PREAMBLE_MAGIC[1],
            PREAMBLE_MAGIC[2],
            self.version,
            self.intent as u8,
            self.flags,
        ]
    }

    /// Strictly decodes and validates a 6-byte cleartext preamble (v1 and v2).
    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != PREAMBLE_LEN {
            return Err(CoreError::InvalidPreambleLength {
                expected: PREAMBLE_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..3] != PREAMBLE_MAGIC {
            return Err(CoreError::BadPreambleMagic);
        }
        let version = bytes[3];
        let intent_raw = bytes[4];
        let flags = bytes[5];
        match version {
            WIRE_VERSION => {
                let intent = Intent::try_from(intent_raw)?;
                if flags != PREAMBLE_RESERVED {
                    return Err(CoreError::NonZeroReserved(flags));
                }
                Ok(Self {
                    version,
                    intent,
                    flags,
                })
            }
            WIRE_VERSION_V2 => {
                let intent = Intent::try_from(intent_raw)?;
                let allowed = match intent {
                    Intent::Session => flags == PREAMBLE_FLAG_NONE,
                    Intent::Pair => flags == PREAMBLE_FLAG_NONE || flags == FLAG_PAKE_PAIR,
                };
                if !allowed {
                    return Err(CoreError::InvalidPreambleFlags {
                        intent: intent_raw,
                        flags,
                    });
                }
                Ok(Self {
                    version,
                    intent,
                    flags,
                })
            }
            other => Err(CoreError::UnsupportedVersion(other)),
        }
    }
}

/// Encodes `body` as `uint16_be len || body`, enforcing [`MAX_FRAME_LEN`].
pub fn encode_frame(body: &[u8]) -> Result<Vec<u8>, CoreError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(CoreError::FrameTooLarge {
            len: body.len(),
            max: MAX_FRAME_LEN,
        });
    }
    let len = u16::try_from(body.len()).map_err(|_| CoreError::FrameTooLarge {
        len: body.len(),
        max: MAX_FRAME_LEN,
    })?;
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Decodes one `uint16_be len || body` frame from `bytes`, returning `(body, total_consumed)`.
pub fn decode_frame(bytes: &[u8]) -> Result<(&[u8], usize), CoreError> {
    if bytes.len() < 2 {
        return Err(CoreError::TruncatedFrame {
            expected: 2,
            actual: bytes.len(),
        });
    }
    let len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    if len > MAX_FRAME_LEN {
        return Err(CoreError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    let total = 2 + len;
    if bytes.len() < total {
        return Err(CoreError::TruncatedFrame {
            expected: total,
            actual: bytes.len(),
        });
    }
    Ok((&bytes[2..total], total))
}

/// Inner encrypted frame type inside Noise transport mode for `intent = session`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InnerFrameType {
    Data = 0x01,
    Grant = 0x02,
    Revocation = 0x03,
    Rekey = 0x04,
    Ping = 0x05,
    Pong = 0x06,
    Close = 0x07,
    /// Wire v2 pure cover traffic frame (`0x08`), zero-filled and silently discarded after AEAD decrypt.
    Padding = 0x08,
    /// Wire v2 bucketed padded envelope (`0x09`) wrapping one `0x01..=0x07`, `0x0A` or `0x0B` inner frame.
    Padded = 0x09,
    /// Signed `GroupManifest` push or gossip (`0x0A`), compact JSON of at most 32768 bytes.
    GroupManifest = 0x0A,
    /// Group rendezvous key delivery (`0x0B`), exactly 60 bytes.
    GroupRendezvous = 0x0B,
    /// Host-signed route set (`0x0C`), responder to initiator only; decoded by `routes::RouteSet`.
    RouteSet = 0x0C,
    /// In-band direct path upgrade signaling (`0x0D`); `0x09 PADDED`-only on Wire v2.
    PathUpgrade = 0x0D,
}

impl TryFrom<u8> for InnerFrameType {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Grant),
            0x03 => Ok(Self::Revocation),
            0x04 => Ok(Self::Rekey),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::Close),
            0x08 => Ok(Self::Padding),
            0x09 => Ok(Self::Padded),
            0x0A => Ok(Self::GroupManifest),
            0x0B => Ok(Self::GroupRendezvous),
            0x0C => Ok(Self::RouteSet),
            0x0D => Ok(Self::PathUpgrade),
            other => Err(CoreError::UnknownInnerFrameType(other)),
        }
    }
}

/// Encodes one inner encrypted transport frame (`type || payload`), validating per-type payload rules.
pub fn encode_inner_frame(kind: InnerFrameType, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
    validate_inner_payload(kind, payload)?;
    let total = 1 + payload.len();
    if total > MAX_TRANSPORT_PLAINTEXT {
        return Err(CoreError::FrameTooLarge {
            len: total,
            max: MAX_TRANSPORT_PLAINTEXT,
        });
    }
    let mut out = Vec::with_capacity(total);
    out.push(kind as u8);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes and validates one inner encrypted transport frame from decrypted plaintext.
pub fn decode_inner_frame(plaintext: &[u8]) -> Result<(InnerFrameType, &[u8]), CoreError> {
    if plaintext.len() > MAX_TRANSPORT_PLAINTEXT {
        return Err(CoreError::FrameTooLarge {
            len: plaintext.len(),
            max: MAX_TRANSPORT_PLAINTEXT,
        });
    }
    let (&tag, payload) = plaintext.split_first().ok_or(CoreError::EmptyInnerFrame)?;
    let kind = InnerFrameType::try_from(tag)?;
    validate_inner_payload(kind, payload)?;
    Ok((kind, payload))
}

pub(crate) fn validate_inner_payload(
    kind: InnerFrameType,
    payload: &[u8],
) -> Result<(), CoreError> {
    match kind {
        InnerFrameType::Data
        | InnerFrameType::Grant
        | InnerFrameType::Revocation
        | InnerFrameType::RouteSet => {
            if payload.len() > MAX_APP_DATA_LEN {
                return Err(CoreError::FrameTooLarge {
                    len: 1 + payload.len(),
                    max: MAX_TRANSPORT_PLAINTEXT,
                });
            }
        }
        InnerFrameType::GroupManifest => {
            if payload.len() > MAX_GROUP_MANIFEST_LEN {
                return Err(CoreError::GroupManifestTooLarge {
                    len: payload.len(),
                    max: MAX_GROUP_MANIFEST_LEN,
                });
            }
        }
        InnerFrameType::GroupRendezvous if payload.len() != GROUP_RENDEZVOUS_FRAME_LEN => {
            return Err(CoreError::InvalidInnerFramePayload(
                "GROUP_RENDEZVOUS payload must be exactly 60 bytes",
            ));
        }
        InnerFrameType::Rekey if !payload.is_empty() => {
            return Err(CoreError::InvalidInnerFramePayload(
                "REKEY frame payload must be empty",
            ));
        }
        InnerFrameType::Ping | InnerFrameType::Pong if payload.len() != 8 => {
            return Err(CoreError::InvalidInnerFramePayload(
                "PING/PONG payload must be exactly 8 bytes",
            ));
        }
        InnerFrameType::Close if payload.len() < 2 => {
            return Err(CoreError::InvalidInnerFramePayload(
                "CLOSE payload must include 2-byte reason code",
            ));
        }
        InnerFrameType::Close if payload.len() > MAX_APP_DATA_LEN => {
            return Err(CoreError::FrameTooLarge {
                len: 1 + payload.len(),
                max: MAX_TRANSPORT_PLAINTEXT,
            });
        }
        InnerFrameType::Padding => {
            if payload.len() > MAX_APP_DATA_LEN {
                return Err(CoreError::FrameTooLarge {
                    len: 1 + payload.len(),
                    max: MAX_TRANSPORT_PLAINTEXT,
                });
            }
            let mut nonzero = 0u8;
            for &b in payload {
                nonzero |= b;
            }
            if !bool::from(nonzero.ct_eq(&0u8)) {
                return Err(CoreError::InvalidInnerFramePayload(
                    "PADDING cover frame must contain only zero bytes",
                ));
            }
        }
        InnerFrameType::Padded => {
            if payload.len() > MAX_APP_DATA_LEN {
                return Err(CoreError::FrameTooLarge {
                    len: 1 + payload.len(),
                    max: MAX_TRANSPORT_PLAINTEXT,
                });
            }
            let mut full = Vec::with_capacity(1 + payload.len());
            full.push(InnerFrameType::Padded as u8);
            full.extend_from_slice(payload);
            crate::v2::unpad_inner_frame(&full)?;
        }
        InnerFrameType::PathUpgrade => {
            if payload.len() > MAX_PATH_UPGRADE_LEN {
                return Err(CoreError::FrameTooLarge {
                    len: payload.len(),
                    max: MAX_PATH_UPGRADE_LEN,
                });
            }
            PathUpgradeMsg::decode(payload)?;
        }
        InnerFrameType::GroupRendezvous
        | InnerFrameType::Rekey
        | InnerFrameType::Ping
        | InnerFrameType::Pong
        | InnerFrameType::Close => {}
    }
    Ok(())
}

/// Encrypted `msg2` payload (`responder -> initiator`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHello {
    pub host_id: String,
    pub proto_version: u8,
    pub signing_pub: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotation: Vec<RotationRecord>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_upgrade_caps"
    )]
    pub upgrade: Vec<String>,
}

/// Encrypted `msg3` payload for `intent = session` (`initiator -> responder`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHello {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_seq: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "groups_is_unset",
        deserialize_with = "deserialize_groups"
    )]
    pub groups: Option<Vec<GroupSeq>>,
    /// Initiator opt-in to `0x0C ROUTE_SET`: the last host route sequence it applied (`0..=2^53-1`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_route_seq"
    )]
    pub route_seq: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_upgrade_caps"
    )]
    pub upgrade: Vec<String>,
}

fn validate_single_upgrade_cap(cap: &str) -> Result<(), CoreError> {
    if cap.is_empty()
        || cap.len() > MAX_UPGRADE_CAP_LEN
        || !cap.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'/' | b'-')
        })
    {
        return Err(CoreError::InvalidInnerFramePayload(
            "upgrade capability must be 1..=32 bytes matching [a-z0-9._/-]",
        ));
    }
    Ok(())
}

/// Validates a list of upgrade capability identifiers for `HostHello` / `SessionHello`.
pub fn validate_upgrade_caps(caps: &[String]) -> Result<(), CoreError> {
    if caps.len() > MAX_UPGRADE_CAPS {
        return Err(CoreError::InvalidInnerFramePayload(
            "too many upgrade capabilities",
        ));
    }
    for (i, cap) in caps.iter().enumerate() {
        validate_single_upgrade_cap(cap)?;
        if caps[..i].iter().any(|prev| prev == cap) {
            return Err(CoreError::InvalidInnerFramePayload(
                "duplicate upgrade capability",
            ));
        }
    }
    Ok(())
}

fn deserialize_upgrade_caps<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let items = Vec::<String>::deserialize(deserializer)?;
    if items.is_empty() {
        return Err(serde::de::Error::custom(
            "empty upgrade array must be omitted",
        ));
    }
    validate_upgrade_caps(&items).map_err(serde::de::Error::custom)?;
    Ok(items)
}

/// Payload carried inside encrypted `0x0D PATH_UPGRADE` signaling frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathUpgradeMsg {
    Offer {
        upgrade_id: u64,
        protocol: String,
        sdp: String,
    },
    Answer {
        upgrade_id: u64,
        protocol: String,
        sdp: String,
    },
    Reject {
        upgrade_id: u64,
        reason: String,
    },
}

const MAX_PATH_UPGRADE_SDP_LEN: usize = 15_360;
const MAX_PATH_UPGRADE_REJECT_REASON_LEN: usize = 256;

impl PathUpgradeMsg {
    fn validate_fields(&self) -> Result<(), CoreError> {
        match self {
            Self::Offer {
                upgrade_id,
                protocol,
                sdp,
            }
            | Self::Answer {
                upgrade_id,
                protocol,
                sdp,
            } => {
                if *upgrade_id == 0 || *upgrade_id > MAX_ROUTE_SEQ {
                    return Err(CoreError::InvalidInnerFramePayload(
                        "upgrade_id must be 1..=2^53 - 1",
                    ));
                }
                validate_single_upgrade_cap(protocol)?;
                if sdp.is_empty()
                    || sdp.len() > MAX_PATH_UPGRADE_SDP_LEN
                    || sdp.as_bytes().contains(&0)
                {
                    return Err(CoreError::InvalidInnerFramePayload(
                        "path upgrade SDP must be 1..=15360 bytes with no NUL bytes",
                    ));
                }
            }
            Self::Reject { upgrade_id, reason } => {
                if *upgrade_id == 0 || *upgrade_id > MAX_ROUTE_SEQ {
                    return Err(CoreError::InvalidInnerFramePayload(
                        "upgrade_id must be 1..=2^53 - 1",
                    ));
                }
                if reason.is_empty()
                    || reason.len() > MAX_PATH_UPGRADE_REJECT_REASON_LEN
                    || reason.bytes().any(|b| b.is_ascii_control())
                {
                    return Err(CoreError::InvalidInnerFramePayload(
                        "path upgrade reject reason must be 1..=256 bytes without control chars",
                    ));
                }
            }
        }
        Ok(())
    }

    fn serialize_checked(&self) -> Result<Vec<u8>, CoreError> {
        self.validate_fields()?;
        let bytes = serde_json::to_vec(self).map_err(|err| CoreError::Json(err.to_string()))?;
        if bytes.is_empty() {
            return Err(CoreError::InvalidInnerFramePayload(
                "PATH_UPGRADE payload cannot be empty",
            ));
        }
        if bytes.len() > MAX_PATH_UPGRADE_LEN {
            return Err(CoreError::FrameTooLarge {
                len: bytes.len(),
                max: MAX_PATH_UPGRADE_LEN,
            });
        }
        Ok(bytes)
    }

    /// Validates field lengths, character sets, `upgrade_id` bounds, and encoded JSON size.
    pub fn validate(&self) -> Result<(), CoreError> {
        self.serialize_checked().map(|_| ())
    }

    /// Validates and serializes the signaling message to compact JSON.
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        self.serialize_checked()
    }

    /// Decodes and validates a `0x0D PATH_UPGRADE` JSON payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.is_empty() {
            return Err(CoreError::InvalidInnerFramePayload(
                "PATH_UPGRADE payload cannot be empty",
            ));
        }
        if bytes.len() > MAX_PATH_UPGRADE_LEN {
            return Err(CoreError::FrameTooLarge {
                len: bytes.len(),
                max: MAX_PATH_UPGRADE_LEN,
            });
        }
        let msg: Self = serde_json::from_slice(bytes)
            .map_err(|_| CoreError::InvalidInnerFramePayload("invalid PATH_UPGRADE JSON"))?;
        msg.validate_fields()?;
        Ok(msg)
    }
}

/// Shared session state machine tracker enforcing directional, capability, and `upgrade_id` rules
/// for `0x0D PATH_UPGRADE`.
#[derive(Debug, Clone)]
pub struct PathUpgradeState {
    is_initiator: bool,
    negotiated_caps: Vec<String>,
    pending_upgrade_ids: Vec<(u64, String)>,
    seen_upgrade_ids: Vec<u64>,
    total_offers: usize,
}

impl PathUpgradeState {
    /// Creates an empty tracker for initiator or responder role.
    #[must_use]
    pub const fn new(is_initiator: bool) -> Self {
        Self {
            is_initiator,
            negotiated_caps: Vec::new(),
            pending_upgrade_ids: Vec::new(),
            seen_upgrade_ids: Vec::new(),
            total_offers: 0,
        }
    }

    /// Records the intersection of negotiated upgrade capabilities once the handshake completes.
    pub fn set_negotiated(&mut self, caps: Vec<String>) {
        self.negotiated_caps = caps;
    }

    /// Returns the negotiated upgrade capabilities for the active session.
    #[must_use]
    pub fn negotiated_caps(&self) -> &[String] {
        &self.negotiated_caps
    }

    /// Validates an outbound `0x0D PATH_UPGRADE` message before sealing without mutating state.
    pub fn prepare_send(&self, msg: &PathUpgradeMsg) -> Result<Vec<u8>, CoreError> {
        let encoded = msg.serialize_checked()?;
        if self.is_initiator {
            let PathUpgradeMsg::Offer {
                upgrade_id,
                protocol,
                ..
            } = msg
            else {
                return Err(CoreError::NotReady(
                    "initiator may only send path upgrade offers",
                ));
            };
            if !self.negotiated_caps.iter().any(|c| c == protocol) {
                return Err(CoreError::NotReady("upgrade protocol not negotiated"));
            }
            if self.total_offers >= MAX_PATH_UPGRADE_OFFERS_PER_SESSION {
                return Err(CoreError::NotReady(
                    "maximum path upgrade offers per session exceeded",
                ));
            }
            if self.seen_upgrade_ids.contains(upgrade_id) {
                return Err(CoreError::NotReady("duplicate path upgrade_id"));
            }
        } else {
            match msg {
                PathUpgradeMsg::Offer { .. } => {
                    return Err(CoreError::NotReady(
                        "responder may only send path upgrade answers or rejections",
                    ));
                }
                PathUpgradeMsg::Answer {
                    upgrade_id,
                    protocol,
                    ..
                } => {
                    if !self.negotiated_caps.iter().any(|c| c == protocol) {
                        return Err(CoreError::NotReady("upgrade protocol not negotiated"));
                    }
                    if !self
                        .pending_upgrade_ids
                        .iter()
                        .any(|(id, p)| id == upgrade_id && p == protocol)
                    {
                        return Err(CoreError::NotReady(
                            "unknown, already answered, or protocol-mismatched path upgrade_id",
                        ));
                    }
                }
                PathUpgradeMsg::Reject { upgrade_id, .. } => {
                    if !self
                        .pending_upgrade_ids
                        .iter()
                        .any(|(id, _)| id == upgrade_id)
                    {
                        return Err(CoreError::NotReady(
                            "unknown or already answered path upgrade_id",
                        ));
                    }
                }
            }
        }
        Ok(encoded)
    }

    /// Commits a previously validated outbound `0x0D PATH_UPGRADE` after sealing succeeds.
    pub fn commit_send(&mut self, msg: &PathUpgradeMsg) {
        if self.is_initiator {
            if let PathUpgradeMsg::Offer {
                upgrade_id,
                protocol,
                ..
            } = msg
            {
                self.seen_upgrade_ids.push(*upgrade_id);
                self.pending_upgrade_ids
                    .push((*upgrade_id, protocol.clone()));
                self.total_offers += 1;
            }
        } else {
            let id = match msg {
                PathUpgradeMsg::Answer { upgrade_id, .. }
                | PathUpgradeMsg::Reject { upgrade_id, .. } => *upgrade_id,
                PathUpgradeMsg::Offer { .. } => return,
            };
            self.pending_upgrade_ids
                .retain(|(pending_id, _)| *pending_id != id);
        }
    }

    /// Validates and records an inbound `0x0D PATH_UPGRADE` frame payload, failing closed on any violation.
    pub fn receive(&mut self, payload: &[u8]) -> Result<PathUpgradeMsg, CoreError> {
        let msg = PathUpgradeMsg::decode(payload)?;
        if self.negotiated_caps.is_empty() {
            return Err(CoreError::ProtocolViolation(
                "unsolicited path upgrade frame without negotiated capabilities",
            ));
        }
        if self.is_initiator {
            match &msg {
                PathUpgradeMsg::Offer { .. } => {
                    return Err(CoreError::ProtocolViolation(
                        "initiator received path upgrade offer",
                    ));
                }
                PathUpgradeMsg::Answer {
                    upgrade_id,
                    protocol,
                    ..
                } => {
                    if !self.negotiated_caps.iter().any(|c| c == protocol) {
                        return Err(CoreError::ProtocolViolation(
                            "unnegotiated protocol in path upgrade answer",
                        ));
                    }
                    let Some(pos) = self
                        .pending_upgrade_ids
                        .iter()
                        .position(|(id, p)| id == upgrade_id && p == protocol)
                    else {
                        return Err(CoreError::ProtocolViolation(
                            "unknown, replayed, or protocol-mismatched upgrade_id in path upgrade answer",
                        ));
                    };
                    self.pending_upgrade_ids.swap_remove(pos);
                }
                PathUpgradeMsg::Reject { upgrade_id, .. } => {
                    let Some(pos) = self
                        .pending_upgrade_ids
                        .iter()
                        .position(|(id, _)| id == upgrade_id)
                    else {
                        return Err(CoreError::ProtocolViolation(
                            "unknown or replayed upgrade_id in path upgrade reject",
                        ));
                    };
                    self.pending_upgrade_ids.swap_remove(pos);
                }
            }
        } else {
            let PathUpgradeMsg::Offer {
                upgrade_id,
                protocol,
                ..
            } = &msg
            else {
                return Err(CoreError::ProtocolViolation(
                    "responder received non-offer path upgrade frame",
                ));
            };
            if !self.negotiated_caps.iter().any(|c| c == protocol) {
                return Err(CoreError::ProtocolViolation(
                    "unnegotiated protocol in path upgrade offer",
                ));
            }
            if self.total_offers >= MAX_PATH_UPGRADE_OFFERS_PER_SESSION {
                return Err(CoreError::ProtocolViolation(
                    "too many path upgrade offers in session",
                ));
            }
            if self.seen_upgrade_ids.contains(upgrade_id) {
                return Err(CoreError::ProtocolViolation(
                    "duplicate upgrade_id in path upgrade offer",
                ));
            }
            self.seen_upgrade_ids.push(*upgrade_id);
            self.pending_upgrade_ids
                .push((*upgrade_id, protocol.clone()));
            self.total_offers += 1;
        }
        Ok(msg)
    }
}

fn groups_is_unset(groups: &Option<Vec<GroupSeq>>) -> bool {
    groups.as_ref().is_none_or(Vec::is_empty)
}

fn deserialize_route_seq<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let seq = u64::deserialize(deserializer)?;
    if seq > MAX_ROUTE_SEQ {
        return Err(serde::de::Error::custom(
            "route_seq must be at most 2^53 - 1",
        ));
    }
    Ok(Some(seq))
}

fn deserialize_groups<'de, D>(deserializer: D) -> Result<Option<Vec<GroupSeq>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let items = Vec::<GroupSeq>::deserialize(deserializer)?;
    if items.is_empty() {
        return Err(serde::de::Error::custom(
            "empty groups array must be omitted from SessionHello",
        ));
    }
    validate_group_seqs(&items).map_err(serde::de::Error::custom)?;
    Ok(Some(items))
}

/// Encrypted `msg3` payload for `intent = pair` (`initiator -> responder`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairClaim {
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_pub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enroll_proof: Option<String>,
}

/// Encrypted post-handshake response frame for `intent = pair` (`responder -> initiator`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum PairResponse {
    Success {
        device_id: String,
        status: String,
        host_signing_pub: String,
    },
    Error {
        error: String,
    },
}

/// Incremental, bounded decoder for Tendril preambles and `uint16_be len || body` frames.
#[derive(Debug, Default)]
pub struct ResumableFrameReader {
    buf: Vec<u8>,
    offset: usize,
    expect_preamble: bool,
    preamble: Option<Preamble>,
}

impl ResumableFrameReader {
    /// Creates a reader expecting length-prefixed frames immediately (initiator side).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a reader expecting a 6-byte cleartext [`Preamble`] before any frames (responder side).
    #[must_use]
    pub fn with_preamble() -> Self {
        Self {
            buf: Vec::new(),
            offset: 0,
            expect_preamble: true,
            preamble: None,
        }
    }

    /// Returns the decoded preamble once [`Self::take_preamble`] has succeeded.
    #[must_use]
    pub const fn preamble(&self) -> Option<Preamble> {
        self.preamble
    }

    /// Appends received transport bytes, enforcing [`MAX_READ_BUFFER_LEN`] before allocation.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), CoreError> {
        if self.offset > 0 {
            let unread = self.buf.len() - self.offset;
            if unread == 0 {
                self.buf.clear();
                self.offset = 0;
            } else if self.offset >= 4096
                || self.buf.len().saturating_add(chunk.len()) > MAX_READ_BUFFER_LEN
            {
                self.buf.copy_within(self.offset.., 0);
                self.buf.truncate(unread);
                self.offset = 0;
            }
        }

        let unread = self.buf.len() - self.offset;
        let Some(total) = unread.checked_add(chunk.len()) else {
            return Err(CoreError::BufferOverflow {
                len: usize::MAX,
                max: MAX_READ_BUFFER_LEN,
            });
        };
        if total > MAX_READ_BUFFER_LEN {
            return Err(CoreError::BufferOverflow {
                len: total,
                max: MAX_READ_BUFFER_LEN,
            });
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// Consumes and validates the initial 6-byte [`Preamble`] once all 6 bytes have arrived.
    pub fn take_preamble(&mut self) -> Result<Option<Preamble>, CoreError> {
        if !self.expect_preamble {
            return Ok(self.preamble);
        }
        let unread = &self.buf[self.offset..];
        if unread.len() < PREAMBLE_LEN {
            return Ok(None);
        }
        let decoded = Preamble::decode(&unread[..PREAMBLE_LEN])?;
        self.offset += PREAMBLE_LEN;
        self.expect_preamble = false;
        self.preamble = Some(decoded);
        if self.offset >= self.buf.len() {
            self.buf.clear();
            self.offset = 0;
        }
        Ok(Some(decoded))
    }

    /// Decodes the next complete outer frame, immediately rejecting declared lengths above
    /// [`MAX_FRAME_LEN`] before buffering the payload.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, CoreError> {
        if self.expect_preamble {
            return Err(CoreError::ProtocolViolation(
                "preamble must be decoded before reading frames",
            ));
        }
        let unread = &self.buf[self.offset..];
        if unread.len() < 2 {
            return Ok(None);
        }
        let len = usize::from(u16::from_be_bytes([unread[0], unread[1]]));
        if len > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len,
                max: MAX_FRAME_LEN,
            });
        }
        let total = 2 + len;
        if unread.len() < total {
            return Ok(None);
        }
        let body = unread[2..total].to_vec();
        self.offset += total;
        if self.offset >= self.buf.len() {
            self.buf.clear();
            self.offset = 0;
        } else if self.offset >= 4096 {
            let rem = self.buf.len() - self.offset;
            self.buf.copy_within(self.offset.., 0);
            self.buf.truncate(rem);
            self.offset = 0;
        }
        Ok(Some(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_decode_validates_all_fields() {
        let sess = Preamble::v1(Intent::Session).encode();
        assert_eq!(
            Preamble::decode(&sess).unwrap(),
            Preamble::v1(Intent::Session)
        );

        let pair = Preamble::v1(Intent::Pair).encode();
        assert_eq!(Preamble::decode(&pair).unwrap(), Preamble::v1(Intent::Pair));

        assert_eq!(
            Preamble::decode(&sess[..5]),
            Err(CoreError::InvalidPreambleLength {
                expected: PREAMBLE_LEN,
                actual: 5
            })
        );
        assert_eq!(
            Preamble::decode(b"BAD\x01\x01\x00"),
            Err(CoreError::BadPreambleMagic)
        );
        assert_eq!(
            Preamble::decode(b"TND\x03\x01\x00"),
            Err(CoreError::UnsupportedVersion(0x03))
        );
        assert_eq!(
            Preamble::decode(b"TND\x02\x01\x00"),
            Ok(Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE))
        );
        assert_eq!(
            Preamble::decode(b"TND\x02\x02\x01"),
            Ok(Preamble::v2_pake_pair())
        );
        assert_eq!(
            Preamble::decode(b"TND\x02\x01\x01"),
            Err(CoreError::InvalidPreambleFlags {
                intent: 0x01,
                flags: 0x01
            })
        );
        assert_eq!(
            Preamble::decode(b"TND\x02\x02\x02"),
            Err(CoreError::InvalidPreambleFlags {
                intent: 0x02,
                flags: 0x02
            })
        );
        assert_eq!(
            Preamble::decode(b"TND\x01\x03\x00"),
            Err(CoreError::UnknownIntent(0x03))
        );
        assert_eq!(
            Preamble::decode(b"TND\x01\x01\x01"),
            Err(CoreError::NonZeroReserved(0x01))
        );
    }

    #[test]
    fn outer_frame_bounds_and_truncation() {
        let empty = encode_frame(&[]).unwrap();
        assert_eq!(empty, [0x00, 0x00]);
        assert_eq!(decode_frame(&empty).unwrap(), ([].as_slice(), 2));

        let max_body = vec![0xAA; MAX_FRAME_LEN];
        let max_framed = encode_frame(&max_body).unwrap();
        let (decoded, consumed) = decode_frame(&max_framed).unwrap();
        assert_eq!(decoded.len(), MAX_FRAME_LEN);
        assert_eq!(consumed, 2 + MAX_FRAME_LEN);

        let oversized = vec![0xBB; MAX_FRAME_LEN + 1];
        assert_eq!(
            encode_frame(&oversized),
            Err(CoreError::FrameTooLarge {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            })
        );

        assert_eq!(
            decode_frame(&[0x00]),
            Err(CoreError::TruncatedFrame {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            decode_frame(&[0x00, 0x05, 0x01, 0x02]),
            Err(CoreError::TruncatedFrame {
                expected: 7,
                actual: 4
            })
        );
        // Header length ceiling must be rejected before expecting the remaining payload bytes.
        let too_large_header = ((MAX_FRAME_LEN + 1) as u16).to_be_bytes();
        assert_eq!(
            decode_frame(&too_large_header),
            Err(CoreError::FrameTooLarge {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            })
        );
    }

    #[test]
    fn inner_frame_validation_and_close_ceiling() {
        assert_eq!(decode_inner_frame(&[]), Err(CoreError::EmptyInnerFrame));
        assert_eq!(
            decode_inner_frame(&[0x7F]),
            Err(CoreError::UnknownInnerFrameType(0x7F))
        );

        let max_data = vec![0x11; MAX_APP_DATA_LEN];
        let enc_data = encode_inner_frame(InnerFrameType::Data, &max_data).unwrap();
        assert_eq!(enc_data.len(), MAX_TRANSPORT_PLAINTEXT);
        assert_eq!(
            decode_inner_frame(&enc_data).unwrap(),
            (InnerFrameType::Data, max_data.as_slice())
        );

        let too_big_data = vec![0x11; MAX_APP_DATA_LEN + 1];
        assert_eq!(
            encode_inner_frame(InnerFrameType::Data, &too_big_data),
            Err(CoreError::FrameTooLarge {
                len: MAX_TRANSPORT_PLAINTEXT + 1,
                max: MAX_TRANSPORT_PLAINTEXT
            })
        );

        assert!(matches!(
            encode_inner_frame(InnerFrameType::Rekey, &[0x01]),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));
        assert!(matches!(
            encode_inner_frame(InnerFrameType::Ping, &[0u8; 7]),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));
        assert!(matches!(
            decode_inner_frame(&[InnerFrameType::Pong as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));
        assert!(matches!(
            encode_inner_frame(InnerFrameType::Close, &[0x00]),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));

        let mut oversized_close_raw =
            vec![InnerFrameType::Close as u8; MAX_TRANSPORT_PLAINTEXT + 1];
        oversized_close_raw[1] = 0x00;
        oversized_close_raw[2] = 0x01;
        assert_eq!(
            decode_inner_frame(&oversized_close_raw),
            Err(CoreError::FrameTooLarge {
                len: MAX_TRANSPORT_PLAINTEXT + 1,
                max: MAX_TRANSPORT_PLAINTEXT
            })
        );
    }

    #[test]
    fn resumable_reader_handles_single_byte_splits_coalesced_frames_and_bounds() {
        let mut reader = ResumableFrameReader::with_preamble();
        assert_eq!(
            reader.next_frame(),
            Err(CoreError::ProtocolViolation(
                "preamble must be decoded before reading frames"
            ))
        );

        let mut stream = Preamble::v1(Intent::Session).encode().to_vec();
        stream.extend_from_slice(&encode_frame(&[]).unwrap());
        stream.extend_from_slice(&encode_frame(b"alpha").unwrap());
        stream.extend_from_slice(&encode_frame(b"beta").unwrap());

        let mut preamble = None;
        let mut frames = Vec::new();
        for b in &stream {
            reader.push(std::slice::from_ref(b)).unwrap();
            if preamble.is_none() {
                preamble = reader.take_preamble().unwrap();
                if preamble.is_none() {
                    continue;
                }
            }
            while let Some(frame) = reader.next_frame().unwrap() {
                frames.push(frame);
            }
        }

        assert_eq!(preamble, Some(Preamble::v1(Intent::Session)));
        assert_eq!(
            frames,
            vec![Vec::new(), b"alpha".to_vec(), b"beta".to_vec()]
        );

        // Two oversized length header bytes must fail immediately before payload arrives.
        let mut hdr_reader = ResumableFrameReader::new();
        hdr_reader
            .push(&((MAX_FRAME_LEN + 1) as u16).to_be_bytes())
            .unwrap();
        assert_eq!(
            hdr_reader.next_frame(),
            Err(CoreError::FrameTooLarge {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            })
        );

        // Buffer overflow must trigger cleanly before unbounded allocation.
        let mut overflow_reader = ResumableFrameReader::new();
        overflow_reader
            .push(&vec![0u8; MAX_READ_BUFFER_LEN])
            .unwrap();
        assert_eq!(
            overflow_reader.push(&[0x01]),
            Err(CoreError::BufferOverflow {
                len: MAX_READ_BUFFER_LEN + 1,
                max: MAX_READ_BUFFER_LEN
            })
        );
    }

    #[test]
    fn route_set_tag_applies_only_the_generic_bound() {
        assert_eq!(
            InnerFrameType::try_from(0x0C).unwrap(),
            InnerFrameType::RouteSet
        );
        assert_eq!(
            InnerFrameType::try_from(0x0D).unwrap(),
            InnerFrameType::PathUpgrade
        );
        assert_eq!(
            InnerFrameType::try_from(0x0E),
            Err(CoreError::UnknownInnerFrameType(0x0E))
        );
        for len in [0usize, 1, 3_454, 5_004, MAX_APP_DATA_LEN] {
            let payload = vec![0xA5; len];
            let enc = encode_inner_frame(InnerFrameType::RouteSet, &payload).unwrap();
            let (kind, body) = decode_inner_frame(&enc).unwrap();
            assert_eq!(kind, InnerFrameType::RouteSet);
            assert_eq!(body.len(), len);
        }
        assert_eq!(
            encode_inner_frame(InnerFrameType::RouteSet, &vec![0; MAX_APP_DATA_LEN + 1]),
            Err(CoreError::FrameTooLarge {
                len: MAX_TRANSPORT_PLAINTEXT + 1,
                max: MAX_TRANSPORT_PLAINTEXT
            })
        );
    }

    #[test]
    fn session_hello_route_seq_field_rules() {
        let base = SessionHello {
            device_id: "dev_0123456789abcdef".to_string(),
            grant: None,
            crl_seq: None,
            groups: None,
            route_seq: None,
            upgrade: Vec::new(),
        };
        let json = serde_json::to_string(&base).unwrap();
        assert!(!json.contains("route_seq"));
        assert_eq!(serde_json::from_str::<SessionHello>(&json).unwrap(), base);

        for seq in [0, 7, MAX_ROUTE_SEQ] {
            let with = SessionHello {
                route_seq: Some(seq),
                ..base.clone()
            };
            let text = serde_json::to_string(&with).unwrap();
            assert!(text.contains(&format!("\"route_seq\":{seq}")));
            assert_eq!(serde_json::from_str::<SessionHello>(&text).unwrap(), with);
        }

        let parse = |seq: serde_json::Value| {
            serde_json::from_value::<SessionHello>(serde_json::json!({
                "device_id": "dev_0123456789abcdef",
                "route_seq": seq
            }))
        };
        assert!(parse(serde_json::json!(MAX_ROUTE_SEQ + 1)).is_err());
        assert!(parse(serde_json::json!(null)).is_err());
        assert!(parse(serde_json::json!(-1)).is_err());
        assert!(parse(serde_json::json!("5")).is_err());
    }
}
