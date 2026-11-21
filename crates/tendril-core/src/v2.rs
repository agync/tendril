//! Wire v2 (`0x02`) privacy profile primitives (`ADR 0003` + `Phase 7`).
//!
//! Includes:
//! - Anti-downgrade version enforcement (`min_wire_version`)
//! - Blinded 1-hour epoch relay mailbox derivation, canonical host checks, and replay guards
//! - Pseudonymous paired reconnect hiding `HostHello`, rotations, and decoy static keys
//! - Hybrid `Argon2id` PAKE + `ML-KEM-768` pairing (`flags = 0x01`)
//! - Bucketed inner frame padding (`0x09 PADDED`) and cover traffic (`0x08 PADDING`)
//! - CSPRNG-jittered keepalive and rekey scheduling (`ScheduleJitterPolicy`, `SealedSession`)

use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{
    ARGON2_KEY_LEN, HybridSigningPublicKey, StaticKeypair, b64url_encode, device_id,
    fingerprint_device, has_control_chars, hkdf_sha256_32, is_valid_ed25519_public_key,
    is_valid_x25519_public_key, normalize_code, pairing_sas, random_bytes,
};
use crate::error::CoreError;
use crate::grants::{
    AuditEvent, Grant, RevocationList, authorize_grant, authorize_path_capability,
    verify_grant_with_chain,
};
use crate::identity::{EndpointIdentity, RotationRecord, SigningKeyPin, verify_rotation_chain_pin};
use crate::noise::{MSG1_LEN, NoiseHfsHandshake, NoiseHfsHandshakeBuilder, NoiseTransport};
use crate::pairing::{PairingManager, PairingPathKind, PinnedHost};
use crate::roster::{PeerState, Roster, V2PeerSecrets};
use crate::session::{REKEY_MAX_AGE_MS, REKEY_MAX_FRAMES, RekeyDirection, SessionCloseCode};
use crate::wire::{
    AEAD_TAG_LEN, FLAG_PAKE_PAIR, HostHello, InnerFrameType, Intent, MAX_FRAME_LEN,
    MAX_TRANSPORT_PLAINTEXT, PREAMBLE_FLAG_NONE, PREAMBLE_LEN, PairClaim, PairResponse, Preamble,
    ResumableFrameReader, SessionHello, WIRE_VERSION, WIRE_VERSION_V2, decode_inner_frame,
    encode_frame, encode_inner_frame, validate_inner_payload,
};

type HmacSha256 = Hmac<Sha256>;

/// Duration in seconds of one `/v2/relay` blinded mailbox epoch (`1` hour).
pub const RELAY_V2_EPOCH_SECS: u64 = 3600;

/// Maximum bounded replay cache entries for `/v2/relay` dial tokens.
pub const MAX_RELAY_DIAL_REPLAY_ENTRIES: usize = 4096;

/// Maximum bounded replay cache entries for v2 rendezvous nonces.
pub const MAX_RENDEZVOUS_REPLAY_ENTRIES: usize = 4096;

/// Maximum allowed clock skew in seconds (`+-300 s`) for v2 `msg1` rendezvous timestamps.
pub const V2_RENDEZVOUS_MAX_SKEW_SECS: u64 = 300;

/// Fixed minimum byte length of a standard v2 `msg2` sealed `HostHello` / decoy envelope.
pub const V2_MSG2_ENVELOPE_LEN: usize = 4096;

/// Byte length of the v2 `msg1` rendezvous proof (`16 B nonce || 8 B ts_be || 32 B HMAC`).
pub const V2_RENDEZVOUS_PROOF_LEN: usize = 56;

/// Byte length of the v2 PAKE `msg1` channel salt (`16 B`).
pub const V2_PAKE_SALT_LEN: usize = 16;

/// Byte length of the v2 PAKE `msg1` payload (`16 B channel_salt || 32 B init_mac`).
pub const V2_PAKE_MSG1_PAYLOAD_LEN: usize = V2_PAKE_SALT_LEN + 32;

/// Production Argon2id memory cost in KiB (`19 MiB`) for v2 PAKE key derivation.
pub const PAKE_ARGON2_MEMORY_KIB: u32 = 19_456;

/// Production Argon2id iteration count for v2 PAKE key derivation.
pub const PAKE_ARGON2_TIME: u32 = 2;

/// Production Argon2id lane count for v2 PAKE key derivation.
pub const PAKE_ARGON2_PARALLELISM: u32 = 1;

/// Default keepalive base interval (`25` seconds) for [`ScheduleJitterPolicy`].
pub const DEFAULT_PING_INTERVAL_MS: u64 = 25_000;

/// Default keepalive jitter (`+-25%`, `2500` basis points) for [`ScheduleJitterPolicy`].
pub const DEFAULT_PING_JITTER_BPS: u16 = 2_500;

/// Default minimum rekey threshold fraction (`75%`, `7500` basis points).
pub const DEFAULT_REKEY_MIN_PCT_BPS: u16 = 7_500;

/// Hard upper bound on `RekeyThresholds::max_frames` (`2^32`) preventing Noise nonce exhaustion.
pub const MAX_REKEY_FRAMES_CEILING: u64 = 1u64 << 32;

/// Hard upper bound on `RekeyThresholds::max_age_ms` (`7` days).
pub const MAX_REKEY_AGE_MS_CEILING: u64 = 7 * 24 * 3_600 * 1_000;

/// Maximum inner payload length carried inside a `0x09 PADDED` envelope (`65503 - 4 = 65499`).
pub const MAX_PADDED_PAYLOAD_LEN: usize = MAX_TRANSPORT_PLAINTEXT - 4;

/// Standard v2 bucket sizes (in total inner plaintext bytes before AEAD tag).
pub const V2_PADDING_BUCKETS: [usize; 9] = [
    256,
    512,
    1024,
    2048,
    4096,
    8192,
    16_384,
    32_768,
    MAX_TRANSPORT_PLAINTEXT,
];

const V2_HANDSHAKE_BUCKETS: [usize; 4] = [4096, 16_384, 32_768, 63_488];
const V2_MSG3_BUCKETS: [usize; 8] = [512, 1024, 2048, 4096, 8192, 16_384, 32_768, 63_488];

const RELAY_V2_ED25519_INFO: &[u8] = b"tendril-relay-v2-ed25519";
const RELAY_V2_DIAL_AUTH_INFO: &[u8] = b"tendril-relay-v2-dial-auth";
const RELAY_V2_REG_DOMAIN: &[u8] = b"tendril-relay-reg-v2\0";
const RELAY_V2_DIAL_DOMAIN: &[u8] = b"tendril-relay-v2-dial\0";
const RELAY_V2_ACCEPT_DOMAIN: &[u8] = b"tendril-relay-accept-v2\0";

const RENDEZVOUS_DOMAIN: &[u8] = b"tendril-v2-rendezvous\0";
const HELLO_SEAL_INFO: &[u8] = b"tendril-v2-hello-seal";
const PAKE_PROLOGUE_INFO: &[u8] = b"tendril-v2-pake-prologue";
const PAKE_INIT_KEY_INFO: &[u8] = b"tendril-v2-pake-init-key";
const PAKE_HELLO_INFO: &[u8] = b"tendril-v2-pake-hello";
const PAKE_CONFIRM_INFO: &[u8] = b"tendril-v2-pake-confirm";
const PAKE_CONTEXT_INFO: &[u8] = b"tendril-v2-pake-context";
const PAKE_MSG1_MAC_DOMAIN: &[u8] = b"tendril-v2-pake-msg1\0";
const PAKE_RESP_MAC_DOMAIN: &[u8] = b"tendril-v2-pake-resp\0";
const PAKE_INIT_MAC_DOMAIN: &[u8] = b"tendril-v2-pake-init\0";

// ---------------------------------------------------------------------------
// 1. Anti-Downgrade & Atomic Roster Helpers
// ---------------------------------------------------------------------------

/// Enforces that `negotiated` meets `min_wire_version`, failing closed with [`CoreError::VersionDowngrade`].
pub fn check_wire_version(min_wire_version: u8, negotiated: u8) -> Result<(), CoreError> {
    if min_wire_version > negotiated {
        return Err(CoreError::VersionDowngrade {
            peer_min: min_wire_version,
            negotiated,
        });
    }
    Ok(())
}

/// Out-of-band pinned host record carrying an explicit `min_wire_version` anti-downgrade floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2PinnedHost {
    pub pinned: PinnedHost,
    min_wire_version: u8,
}

impl V2PinnedHost {
    /// Wraps a [`PinnedHost`] with a validated minimum required wire version (`1` or `2`).
    pub fn new(pinned: PinnedHost, min_wire_version: u8) -> Result<Self, CoreError> {
        if min_wire_version != WIRE_VERSION && min_wire_version != WIRE_VERSION_V2 {
            return Err(CoreError::UnsupportedVersion(min_wire_version));
        }
        Ok(Self {
            pinned,
            min_wire_version,
        })
    }

    /// Returns the persisted minimum wire version floor (`1` or `2`).
    #[must_use]
    pub const fn min_wire_version(&self) -> u8 {
        self.min_wire_version
    }

    /// Enforces `self.min_wire_version` against `negotiated`.
    pub fn enforce_version(&self, negotiated: u8) -> Result<(), CoreError> {
        check_wire_version(self.min_wire_version, negotiated)
    }
}

impl From<PinnedHost> for V2PinnedHost {
    fn from(pinned: PinnedHost) -> Self {
        Self {
            pinned,
            min_wire_version: WIRE_VERSION,
        }
    }
}

impl Roster {
    /// Atomically persists a verified v2 pairing initiator outcome (`Pending` or `Active` if
    /// `host_pin_verified`, with `min_wire_version >= 2` and `v2_secrets`).
    pub fn apply_v2_pair_initiator_outcome(
        &mut self,
        outcome: &V2PairOutcome,
        host_name: impl Into<String>,
        relay_hints: Vec<String>,
    ) -> Result<String, CoreError> {
        let V2PairOutcome::InitiatorPending {
            host_id,
            host_static_pub,
            host_signing_pub,
            host_rotation_seq,
            pairing_sas,
            host_pin_verified,
            v2_secrets,
            ..
        } = outcome
        else {
            return Err(CoreError::ProtocolViolation(
                "expected V2PairOutcome::InitiatorPending",
            ));
        };
        let mut staged = self.clone();
        let name = host_name.into();
        if *host_pin_verified {
            staged.insert_pinned_host(
                host_id.clone(),
                name,
                *host_static_pub,
                Some(host_signing_pub.clone()),
                *host_rotation_seq,
                relay_hints,
            )?;
        } else {
            staged.record_pending_host(
                host_id.clone(),
                name,
                *host_static_pub,
                host_signing_pub.clone(),
                *host_rotation_seq,
                pairing_sas.clone(),
                relay_hints,
            )?;
        }
        staged.upgrade_peer_to_v2(host_id, v2_secrets.clone())?;
        *self = staged;
        Ok(host_id.clone())
    }
}

// ---------------------------------------------------------------------------
// 2. Blinded Epoch Relay Mailbox Tokens
// ---------------------------------------------------------------------------

/// Computes the 1-hour `/v2/relay` epoch index for `unix_secs`.
#[must_use]
pub const fn epoch_for_unix(unix_secs: u64) -> u64 {
    unix_secs / RELAY_V2_EPOCH_SECS
}

/// Reports whether `claimed_epoch` falls within the `+-1` hour clock-skew window around `server_epoch`.
#[must_use]
pub const fn epoch_within_skew(server_epoch: u64, claimed_epoch: u64) -> bool {
    server_epoch.abs_diff(claimed_epoch) <= 1
}

/// Derives the shared 32-byte `mailbox_secret` from session/handshake secret key material `ikm`.
#[must_use]
pub fn derive_mailbox_secret(ikm: &[u8], host_static_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256_32(ikm, b"tendril-mailbox-v2", host_static_pub)
}

/// Derives the shared 32-byte `reconnect_secret` from session/handshake secret key material `ikm`.
#[must_use]
pub fn derive_reconnect_secret(ikm: &[u8], host_static_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256_32(ikm, b"tendril-reconnect-v2", host_static_pub)
}

/// Canonicalizes a relay host name (lowercase ASCII, strips trailing dot, rejects ports/paths/userinfo).
pub fn canonical_relay_host(host: &str) -> Result<String, CoreError> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty()
        || trimmed.len() > 253
        || has_control_chars(trimmed)
        || trimmed.bytes().any(|b| b.is_ascii_whitespace())
        || trimmed.contains(['/', '?', '#', '@'])
    {
        return Err(CoreError::ProtocolViolation("invalid relay host"));
    }
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let ip: Ipv6Addr = inner
            .parse()
            .map_err(|_| CoreError::ProtocolViolation("invalid IPv6 relay host"))?;
        return Ok(format!("[{ip}]"));
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return Ok(trimmed.to_ascii_lowercase());
    }
    if trimmed.contains(':')
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(CoreError::ProtocolViolation("invalid relay host"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Canonicalized relay host verified against the dialed endpoint host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelayHost(String);

impl VerifiedRelayHost {
    /// Validates and canonicalizes a dialed relay hostname (excluding port).
    pub fn new(expected_host: &str) -> Result<Self, CoreError> {
        Ok(Self(canonical_relay_host(expected_host)?))
    }

    /// Parses and verifies `challenge_host` against `expected_host` after canonicalization.
    pub fn from_challenge(expected_host: &str, challenge_host: &str) -> Result<Self, CoreError> {
        let verified = verify_v2_relay_challenge_host(expected_host, challenge_host)?;
        Ok(Self(verified))
    }

    /// Canonical lowercase ASCII host without port.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Enforces that `challenge_host` matches the expected dialed `expected_host` after canonicalization.
pub fn verify_v2_relay_challenge_host(
    expected_host: &str,
    challenge_host: &str,
) -> Result<String, CoreError> {
    let expected = canonical_relay_host(expected_host)?;
    let actual = canonical_relay_host(challenge_host)?;
    if expected != actual {
        return Err(CoreError::ProtocolViolation(
            "relay challenge host mismatch",
        ));
    }
    Ok(actual)
}

/// Bounded replay cache rejecting repeated `(epoch, dial_nonce, conn_id)` dial notifications.
///
/// Only entries strictly below `min_valid_epoch` are evicted; when the live window is at
/// capacity, additional entries fail closed (`false`) rather than evicting live entries.
#[derive(Debug, Default)]
pub struct RelayDialReplayCache {
    seen: BTreeSet<(u64, [u8; 32], [u8; 16])>,
    order: VecDeque<(u64, [u8; 32], [u8; 16])>,
}

impl RelayDialReplayCache {
    /// Creates an empty bounded dial replay cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns current number of tracked `(epoch, dial_nonce, conn_id)` entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Returns `true` if no entries are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Checks and records `(epoch, dial_nonce, conn_id)`, pruning entries older than `min_valid_epoch`.
    ///
    /// Returns `true` if fresh and recorded, or `false` on replay or when the live window is full.
    pub fn check_and_record(
        &mut self,
        epoch: u64,
        dial_nonce: &[u8; 32],
        conn_id: &[u8; 16],
        min_valid_epoch: u64,
    ) -> bool {
        while let Some(&front) = self.order.front() {
            if front.0 < min_valid_epoch {
                self.order.pop_front();
                self.seen.remove(&front);
            } else {
                break;
            }
        }
        let key = (epoch, *dial_nonce, *conn_id);
        if self.seen.contains(&key) {
            return false;
        }
        if self.order.len() >= MAX_RELAY_DIAL_REPLAY_ENTRIES {
            return false;
        }
        self.seen.insert(key);
        self.order.push_back(key);
        true
    }
}

/// Verifies a `/v2/relay` `dial_token` across `window` for `verified_host` BEFORE recording `(epoch, dial_nonce, conn_id)` in `cache`.
///
/// Unauthenticated or out-of-window notifications fail closed (`CoreError::InvalidSignature`)
/// without mutating `cache`. Replays or capacity saturation fail closed (`CoreError::ProtocolViolation`).
#[allow(clippy::too_many_arguments)]
pub fn verify_and_record_v2_relay_dial<'a>(
    cache: &mut RelayDialReplayCache,
    window: &'a RelayEpochWindow,
    verified_host: &VerifiedRelayHost,
    epoch: u64,
    dial_nonce: &[u8; 32],
    conn_id: &[u8; 16],
    dial_token: &[u8; 32],
) -> Result<&'a DerivedMailbox, CoreError> {
    let mailbox = verify_v2_relay_dial_in_window(
        window,
        epoch,
        verified_host.as_str(),
        dial_nonce,
        conn_id,
        dial_token,
    )?;
    let min_valid_epoch = window
        .mailboxes()
        .iter()
        .map(|m| m.epoch)
        .min()
        .unwrap_or(epoch);
    if !cache.check_and_record(epoch, dial_nonce, conn_id, min_valid_epoch) {
        return Err(CoreError::ProtocolViolation(
            "replayed or overflowing v2 relay dial notification",
        ));
    }
    Ok(mailbox)
}

/// Per-epoch unlinkable Ed25519 mailbox identity and dial authentication subkey.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedMailbox {
    #[zeroize(skip)]
    pub epoch: u64,
    #[zeroize(skip)]
    pub mailbox_id: [u8; 32],
    epoch_signing_seed: [u8; 32],
    dial_auth_key: [u8; 32],
}

impl DerivedMailbox {
    /// Returns the unpadded URL-safe base64 representation of `mailbox_id`.
    #[must_use]
    pub fn mailbox_id_b64url(&self) -> String {
        b64url_encode(&self.mailbox_id)
    }

    /// Constructs the ephemeral Ed25519 signing key for this epoch's mailbox.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.epoch_signing_seed)
    }

    /// Returns the 32-byte dial capability MAC key for this epoch.
    #[must_use]
    pub const fn dial_auth_key(&self) -> &[u8; 32] {
        &self.dial_auth_key
    }
}

impl fmt::Debug for DerivedMailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedMailbox")
            .field("epoch", &self.epoch)
            .field("mailbox_id", &self.mailbox_id_b64url())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// Sliding epoch window `(epoch - 1, epoch, epoch + 1)` covering clock-skew transitions.
#[derive(Debug, Clone)]
pub struct RelayEpochWindow {
    pub center_epoch: u64,
    pub prev: Option<DerivedMailbox>,
    pub current: DerivedMailbox,
    pub next: Option<DerivedMailbox>,
}

impl RelayEpochWindow {
    /// Returns all active derived mailboxes in the window in chronological order.
    #[must_use]
    pub fn mailboxes(&self) -> Vec<&DerivedMailbox> {
        let mut out = Vec::with_capacity(3);
        if let Some(ref prev) = self.prev {
            out.push(prev);
        }
        out.push(&self.current);
        if let Some(ref next) = self.next {
            out.push(next);
        }
        out
    }

    /// Looks up the derived mailbox matching `epoch`.
    #[must_use]
    pub fn find_by_epoch(&self, epoch: u64) -> Option<&DerivedMailbox> {
        self.mailboxes().into_iter().find(|m| m.epoch == epoch)
    }

    /// Looks up a derived mailbox by `mailbox_id` using constant-time byte comparison.
    #[must_use]
    pub fn find_by_mailbox_id(&self, mailbox_id: &[u8; 32]) -> Option<&DerivedMailbox> {
        let mut found: Option<&DerivedMailbox> = None;
        for m in self.mailboxes() {
            if bool::from(m.mailbox_id.ct_eq(mailbox_id)) {
                found = Some(m);
            }
        }
        found
    }
}

/// Derives the unlinkable Ed25519 mailbox identity and dial auth key for `epoch`.
#[must_use]
pub fn derive_epoch_mailbox(mailbox_secret: &[u8; 32], epoch: u64) -> DerivedMailbox {
    let salt = epoch.to_be_bytes();
    let epoch_seed = hkdf_sha256_32(mailbox_secret, &salt, RELAY_V2_ED25519_INFO);
    let dial_auth_key = hkdf_sha256_32(mailbox_secret, &salt, RELAY_V2_DIAL_AUTH_INFO);
    let sk = SigningKey::from_bytes(&epoch_seed);
    let mailbox_id = sk.verifying_key().to_bytes();
    DerivedMailbox {
        epoch,
        mailbox_id,
        epoch_signing_seed: *epoch_seed,
        dial_auth_key: *dial_auth_key,
    }
}

/// Derives the `(epoch - 1, epoch, epoch + 1)` relay mailbox window for `unix_secs`.
#[must_use]
pub fn derive_epoch_mailbox_window(mailbox_secret: &[u8; 32], unix_secs: u64) -> RelayEpochWindow {
    let center_epoch = epoch_for_unix(unix_secs);
    let prev = center_epoch
        .checked_sub(1)
        .map(|e| derive_epoch_mailbox(mailbox_secret, e));
    let current = derive_epoch_mailbox(mailbox_secret, center_epoch);
    let next = center_epoch
        .checked_add(1)
        .map(|e| derive_epoch_mailbox(mailbox_secret, e));
    RelayEpochWindow {
        center_epoch,
        prev,
        current,
        next,
    }
}

fn relay_register_bytes(relay_host: &str, challenge_nonce: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(RELAY_V2_REG_DOMAIN.len() + relay_host.len() + 32 + 8);
    out.extend_from_slice(RELAY_V2_REG_DOMAIN);
    out.extend_from_slice(relay_host.as_bytes());
    out.extend_from_slice(challenge_nonce);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

fn relay_dial_bytes(
    relay_host: &str,
    challenge_nonce: &[u8; 32],
    mailbox_id: &[u8; 32],
    conn_id: &[u8; 16],
    epoch: u64,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(RELAY_V2_DIAL_DOMAIN.len() + relay_host.len() + 32 + 32 + 16 + 8);
    out.extend_from_slice(RELAY_V2_DIAL_DOMAIN);
    out.extend_from_slice(relay_host.as_bytes());
    out.extend_from_slice(challenge_nonce);
    out.extend_from_slice(mailbox_id);
    out.extend_from_slice(conn_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

fn relay_accept_bytes(
    relay_host: &str,
    challenge_nonce: &[u8; 32],
    conn_id: &[u8; 16],
    epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(RELAY_V2_ACCEPT_DOMAIN.len() + relay_host.len() + 32 + 16 + 8);
    out.extend_from_slice(RELAY_V2_ACCEPT_DOMAIN);
    out.extend_from_slice(relay_host.as_bytes());
    out.extend_from_slice(challenge_nonce);
    out.extend_from_slice(conn_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// Signs a `/v2/relay` `register` challenge proof using the epoch Ed25519 mailbox key.
pub fn sign_v2_relay_register(
    mailbox: &DerivedMailbox,
    relay_host: &str,
    challenge_nonce: &[u8; 32],
) -> Result<[u8; 64], CoreError> {
    let host = canonical_relay_host(relay_host)?;
    let msg = relay_register_bytes(&host, challenge_nonce, mailbox.epoch);
    Ok(mailbox.signing_key().sign(&msg).to_bytes())
}

/// Verifies a `/v2/relay` `register` Ed25519 signature strictly against `mailbox_id`.
pub fn verify_v2_relay_register(
    mailbox_id: &[u8; 32],
    epoch: u64,
    relay_host: &str,
    challenge_nonce: &[u8; 32],
    sig: &[u8; 64],
) -> Result<(), CoreError> {
    let host = canonical_relay_host(relay_host)?;
    if !is_valid_ed25519_public_key(mailbox_id) {
        return Err(CoreError::InvalidSignature);
    }
    let vk = VerifyingKey::from_bytes(mailbox_id).map_err(|_| CoreError::InvalidSignature)?;
    let ed_sig = Ed25519Signature::from_bytes(sig);
    let msg = relay_register_bytes(&host, challenge_nonce, epoch);
    vk.verify_strict(&msg, &ed_sig)
        .map_err(|_| CoreError::InvalidSignature)
}

/// Computes the 32-byte `HMAC-SHA256` `dial_token` binding `relay_host`, `challenge_nonce`,
/// `mailbox_id`, `conn_id`, and `epoch`.
pub fn sign_v2_relay_dial(
    mailbox: &DerivedMailbox,
    relay_host: &str,
    challenge_nonce: &[u8; 32],
    conn_id: &[u8; 16],
) -> Result<[u8; 32], CoreError> {
    let host = canonical_relay_host(relay_host)?;
    let msg = relay_dial_bytes(
        &host,
        challenge_nonce,
        &mailbox.mailbox_id,
        conn_id,
        mailbox.epoch,
    );
    let mut mac = HmacSha256::new_from_slice(mailbox.dial_auth_key())
        .map_err(|_| CoreError::InvalidSignature)?;
    mac.update(&msg);
    Ok(mac.finalize().into_bytes().into())
}

/// Verifies a `/v2/relay` `dial_token` in constant time against `mailbox`.
pub fn verify_v2_relay_dial(
    mailbox: &DerivedMailbox,
    relay_host: &str,
    challenge_nonce: &[u8; 32],
    conn_id: &[u8; 16],
    dial_token: &[u8; 32],
) -> Result<(), CoreError> {
    let expected = sign_v2_relay_dial(mailbox, relay_host, challenge_nonce, conn_id)?;
    if !bool::from(expected.ct_eq(dial_token)) {
        return Err(CoreError::InvalidSignature);
    }
    Ok(())
}

/// Verifies an incoming `/v2/relay` `dial_token` against any epoch inside `window`.
pub fn verify_v2_relay_dial_in_window<'a>(
    window: &'a RelayEpochWindow,
    epoch: u64,
    relay_host: &str,
    challenge_nonce: &[u8; 32],
    conn_id: &[u8; 16],
    dial_token: &[u8; 32],
) -> Result<&'a DerivedMailbox, CoreError> {
    let host = canonical_relay_host(relay_host)?;
    let mut matched: Option<&'a DerivedMailbox> = None;
    for candidate in window.mailboxes() {
        let ok = verify_v2_relay_dial(candidate, &host, challenge_nonce, conn_id, dial_token)
            .is_ok()
            && candidate.epoch == epoch;
        if ok {
            matched = Some(candidate);
        }
    }
    matched.ok_or(CoreError::InvalidSignature)
}

/// Signs a `/v2/relay` `accept` proof binding `relay_host`, `challenge_nonce`, `conn_id`, and `epoch`.
pub fn sign_v2_relay_accept(
    mailbox: &DerivedMailbox,
    relay_host: &str,
    challenge_nonce: &[u8; 32],
    conn_id: &[u8; 16],
) -> Result<[u8; 64], CoreError> {
    let host = canonical_relay_host(relay_host)?;
    let msg = relay_accept_bytes(&host, challenge_nonce, conn_id, mailbox.epoch);
    Ok(mailbox.signing_key().sign(&msg).to_bytes())
}

/// Verifies a `/v2/relay` `accept` signature strictly against `mailbox_id`.
pub fn verify_v2_relay_accept(
    mailbox_id: &[u8; 32],
    epoch: u64,
    relay_host: &str,
    challenge_nonce: &[u8; 32],
    conn_id: &[u8; 16],
    sig: &[u8; 64],
) -> Result<(), CoreError> {
    let host = canonical_relay_host(relay_host)?;
    if !is_valid_ed25519_public_key(mailbox_id) {
        return Err(CoreError::InvalidSignature);
    }
    let vk = VerifyingKey::from_bytes(mailbox_id).map_err(|_| CoreError::InvalidSignature)?;
    let ed_sig = Ed25519Signature::from_bytes(sig);
    let msg = relay_accept_bytes(&host, challenge_nonce, conn_id, epoch);
    vk.verify_strict(&msg, &ed_sig)
        .map_err(|_| CoreError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// 3. Bucketed Inner Frame Padding & Cover Frames
// ---------------------------------------------------------------------------

/// Opt-in bucketed inner frame padding configuration for [`SealedSession`].
///
/// Fields are private so all instances uphold ascending, in-range bucket invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingPolicy {
    enabled: bool,
    buckets: Vec<usize>,
    require_padded_rx: bool,
}

impl Default for PaddingPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl PaddingPolicy {
    /// Legacy v1 unpadded transport framing (`enabled = false`).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            buckets: Vec::new(),
            require_padded_rx: false,
        }
    }

    /// Standard Wire v2 padding policy using [`V2_PADDING_BUCKETS`].
    #[must_use]
    pub fn v2_default() -> Self {
        Self {
            enabled: true,
            buckets: V2_PADDING_BUCKETS.to_vec(),
            require_padded_rx: false,
        }
    }

    /// Strict Wire v2 padding policy rejecting unpadded `0x01..=0x07` inbound frames.
    #[must_use]
    pub fn v2_strict() -> Self {
        Self {
            enabled: true,
            buckets: V2_PADDING_BUCKETS.to_vec(),
            require_padded_rx: true,
        }
    }

    /// Constructs a custom padding policy after validating strictly ascending bucket sizes.
    pub fn with_buckets(buckets: Vec<usize>, require_padded_rx: bool) -> Result<Self, CoreError> {
        if buckets.is_empty() {
            return Err(CoreError::InvalidInnerFramePayload(
                "padding bucket list cannot be empty",
            ));
        }
        let mut prev = 0usize;
        for &b in &buckets {
            if !(4..=MAX_TRANSPORT_PLAINTEXT).contains(&b) || b <= prev {
                return Err(CoreError::InvalidInnerFramePayload(
                    "padding buckets must be strictly increasing within 4..=65503",
                ));
            }
            prev = b;
        }
        Ok(Self {
            enabled: true,
            buckets,
            require_padded_rx,
        })
    }

    /// Reports whether outbound v2 bucketed padding is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the configured ascending bucket sizes.
    #[must_use]
    pub fn buckets(&self) -> &[usize] {
        &self.buckets
    }

    /// Reports whether inbound unpadded `0x01..=0x07` frames are rejected.
    #[must_use]
    pub const fn require_padded_rx(&self) -> bool {
        self.require_padded_rx
    }
}

/// Pads an inner `0x01..=0x07` frame into a `0x09 PADDED` envelope aligned to `policy.buckets()`.
pub fn pad_inner_frame(
    kind: InnerFrameType,
    payload: &[u8],
    policy: &PaddingPolicy,
) -> Result<Vec<u8>, CoreError> {
    if !policy.enabled {
        return Err(CoreError::InvalidInnerFramePayload(
            "pad_inner_frame requires an enabled PaddingPolicy",
        ));
    }
    if matches!(kind, InnerFrameType::Padding | InnerFrameType::Padded) {
        return Err(CoreError::InvalidInnerFramePayload(
            "cannot wrap PADDING or PADDED inside PADDED",
        ));
    }
    validate_inner_payload(kind, payload)?;
    if payload.len() > MAX_PADDED_PAYLOAD_LEN {
        return Err(CoreError::FrameTooLarge {
            len: 4 + payload.len(),
            max: MAX_TRANSPORT_PLAINTEXT,
        });
    }
    let needed = 4 + payload.len();
    let bucket = policy
        .buckets
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .ok_or(CoreError::FrameTooLarge {
            len: needed,
            max: policy
                .buckets
                .last()
                .copied()
                .unwrap_or(MAX_TRANSPORT_PLAINTEXT),
        })?;
    let real_len = u16::try_from(payload.len()).map_err(|_| CoreError::FrameTooLarge {
        len: needed,
        max: MAX_TRANSPORT_PLAINTEXT,
    })?;
    let mut out = vec![0u8; bucket];
    out[0] = InnerFrameType::Padded as u8;
    out[1] = kind as u8;
    out[2..4].copy_from_slice(&real_len.to_be_bytes());
    out[4..4 + payload.len()].copy_from_slice(payload);
    Ok(out)
}

/// Unpads a `0x09 PADDED` inner plaintext frame, validating zero padding in constant time.
pub fn unpad_inner_frame(plaintext: &[u8]) -> Result<(InnerFrameType, Vec<u8>), CoreError> {
    if plaintext.is_empty() {
        return Err(CoreError::EmptyInnerFrame);
    }
    if plaintext.len() > MAX_TRANSPORT_PLAINTEXT {
        return Err(CoreError::FrameTooLarge {
            len: plaintext.len(),
            max: MAX_TRANSPORT_PLAINTEXT,
        });
    }
    if plaintext[0] != InnerFrameType::Padded as u8 {
        return Err(CoreError::InvalidInnerFramePayload(
            "expected 0x09 PADDED frame tag",
        ));
    }
    if plaintext.len() < 4 {
        return Err(CoreError::InvalidInnerFramePayload(
            "truncated 0x09 PADDED header",
        ));
    }
    let padded_body = &plaintext[1..];
    let inner_kind = InnerFrameType::try_from(padded_body[0])?;
    if matches!(inner_kind, InnerFrameType::Padding | InnerFrameType::Padded) {
        return Err(CoreError::InvalidInnerFramePayload(
            "nested PADDED or cover frame inside PADDED is disallowed",
        ));
    }
    let real_len = usize::from(u16::from_be_bytes([padded_body[1], padded_body[2]]));
    if real_len > padded_body.len() - 3 {
        return Err(CoreError::InvalidInnerFramePayload(
            "PADDED real_payload_len exceeds frame body",
        ));
    }
    let body = &padded_body[3..];
    let mut nonzero = 0u8;
    for &b in &body[real_len..] {
        nonzero |= b;
    }
    if !bool::from(nonzero.ct_eq(&0u8)) {
        return Err(CoreError::InvalidInnerFramePayload(
            "non-zero padding byte in PADDED frame",
        ));
    }
    let payload = &body[..real_len];
    validate_inner_payload(inner_kind, payload)?;
    Ok((inner_kind, payload.to_vec()))
}

/// Encodes a pure `0x08 PADDING` cover frame of exactly `bucket_size` plaintext bytes.
pub fn encode_dummy_cover_frame(bucket_size: usize) -> Result<Vec<u8>, CoreError> {
    if bucket_size == 0 || bucket_size > MAX_TRANSPORT_PLAINTEXT {
        return Err(CoreError::InvalidInnerFramePayload(
            "cover frame bucket size out of range 1..=65503",
        ));
    }
    let mut out = vec![0u8; bucket_size];
    out[0] = InnerFrameType::Padding as u8;
    Ok(out)
}

/// Decoded inner frame from a v2 transport plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2InnerFrame {
    Frame {
        kind: InnerFrameType,
        payload: Vec<u8>,
    },
    DummyCover {
        plaintext_len: usize,
    },
}

/// Decodes a decrypted transport plaintext supporting `0x08` cover frames, `0x09` padded envelopes,
/// and optionally unpadded v1 `0x01..=0x07` frames.
pub fn decode_v2_inner_frame(
    plaintext: &[u8],
    allow_unpadded_v1: bool,
) -> Result<V2InnerFrame, CoreError> {
    if plaintext.is_empty() {
        return Err(CoreError::EmptyInnerFrame);
    }
    if plaintext.len() > MAX_TRANSPORT_PLAINTEXT {
        return Err(CoreError::FrameTooLarge {
            len: plaintext.len(),
            max: MAX_TRANSPORT_PLAINTEXT,
        });
    }
    match plaintext[0] {
        x if x == InnerFrameType::Padding as u8 => {
            let mut nonzero = 0u8;
            for &b in &plaintext[1..] {
                nonzero |= b;
            }
            if !bool::from(nonzero.ct_eq(&0u8)) {
                return Err(CoreError::InvalidInnerFramePayload(
                    "non-zero byte inside 0x08 cover frame",
                ));
            }
            Ok(V2InnerFrame::DummyCover {
                plaintext_len: plaintext.len(),
            })
        }
        x if x == InnerFrameType::Padded as u8 => {
            let (kind, payload) = unpad_inner_frame(plaintext)?;
            Ok(V2InnerFrame::Frame { kind, payload })
        }
        other => {
            if !allow_unpadded_v1 {
                return Err(CoreError::UnknownInnerFrameType(other));
            }
            let (kind, payload) = decode_inner_frame(plaintext)?;
            Ok(V2InnerFrame::Frame {
                kind,
                payload: payload.to_vec(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Jittered Keepalive & Rekey Scheduling + SealedSession
// ---------------------------------------------------------------------------

/// Per-epoch rekey frame count and age thresholds, bounded below Noise nonce exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyThresholds {
    pub max_frames: u64,
    pub max_age_ms: u64,
}

impl Default for RekeyThresholds {
    fn default() -> Self {
        Self {
            max_frames: REKEY_MAX_FRAMES,
            max_age_ms: REKEY_MAX_AGE_MS,
        }
    }
}

impl RekeyThresholds {
    /// Validates and constructs bounded [`RekeyThresholds`].
    pub fn new(max_frames: u64, max_age_ms: u64) -> Result<Self, CoreError> {
        if max_frames == 0
            || max_frames > MAX_REKEY_FRAMES_CEILING
            || max_age_ms == 0
            || max_age_ms > MAX_REKEY_AGE_MS_CEILING
        {
            return Err(CoreError::ProtocolViolation(
                "rekey thresholds out of safe bounds",
            ));
        }
        Ok(Self {
            max_frames,
            max_age_ms,
        })
    }
}

/// Bounded CSPRNG jitter policy for v2 keepalive pings and `0x04 REKEY` thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleJitterPolicy {
    pub ping_interval_ms: u64,
    pub ping_jitter_bps: u16,
    pub rekey_max_frames: u64,
    pub rekey_max_age_secs: u64,
    pub rekey_min_pct_bps: u16,
}

impl Default for ScheduleJitterPolicy {
    fn default() -> Self {
        Self {
            ping_interval_ms: DEFAULT_PING_INTERVAL_MS,
            ping_jitter_bps: DEFAULT_PING_JITTER_BPS,
            rekey_max_frames: REKEY_MAX_FRAMES,
            rekey_max_age_secs: REKEY_MAX_AGE_MS / 1_000,
            rekey_min_pct_bps: DEFAULT_REKEY_MIN_PCT_BPS,
        }
    }
}

impl ScheduleJitterPolicy {
    /// Validates and constructs a [`ScheduleJitterPolicy`].
    pub fn new(
        ping_interval_ms: u64,
        ping_jitter_bps: u16,
        rekey_max_frames: u64,
        rekey_max_age_secs: u64,
        rekey_min_pct_bps: u16,
    ) -> Result<Self, CoreError> {
        if ping_interval_ms == 0
            || rekey_max_frames == 0
            || rekey_max_frames > MAX_REKEY_FRAMES_CEILING
            || rekey_max_age_secs == 0
            || rekey_max_age_secs.saturating_mul(1_000) > MAX_REKEY_AGE_MS_CEILING
        {
            return Err(CoreError::ProtocolViolation(
                "schedule intervals and thresholds out of safe bounds",
            ));
        }
        if ping_jitter_bps > 10_000 || rekey_min_pct_bps == 0 || rekey_min_pct_bps > 10_000 {
            return Err(CoreError::ProtocolViolation(
                "basis-point jitter parameters out of bounds",
            ));
        }
        Ok(Self {
            ping_interval_ms,
            ping_jitter_bps,
            rekey_max_frames,
            rekey_max_age_secs,
            rekey_min_pct_bps,
        })
    }

    /// Returns inclusive `[min_ms, max_ms]` keepalive delay bounds.
    #[must_use]
    pub fn ping_bounds_ms(&self) -> (u64, u64) {
        let bps = u128::from(self.ping_jitter_bps.min(10_000));
        let delta = ((u128::from(self.ping_interval_ms) * bps) / 10_000) as u64;
        let min_ms = self.ping_interval_ms.saturating_sub(delta).max(1);
        let max_ms = self.ping_interval_ms.saturating_add(delta).max(min_ms);
        (min_ms, max_ms)
    }

    /// Returns inclusive `[min_frames, max_frames]` rekey frame bounds.
    #[must_use]
    pub fn rekey_frame_bounds(&self) -> (u64, u64) {
        let max_f = self.rekey_max_frames.clamp(1, MAX_REKEY_FRAMES_CEILING);
        let pct = u128::from(self.rekey_min_pct_bps.clamp(1, 10_000));
        let min_f = ((u128::from(max_f) * pct) / 10_000).max(1) as u64;
        (min_f, max_f.max(min_f))
    }

    /// Returns inclusive `[min_age_ms, max_age_ms]` rekey duration bounds.
    #[must_use]
    pub fn rekey_age_bounds_ms(&self) -> (u64, u64) {
        let max_ms = self
            .rekey_max_age_secs
            .saturating_mul(1_000)
            .clamp(1, MAX_REKEY_AGE_MS_CEILING);
        let pct = u128::from(self.rekey_min_pct_bps.clamp(1, 10_000));
        let min_ms = ((u128::from(max_ms) * pct) / 10_000).max(1) as u64;
        (min_ms, max_ms.max(min_ms))
    }

    /// Samples the next jittered keepalive ping delay in milliseconds using the platform CSPRNG.
    pub fn next_ping_delay_ms(&self) -> Result<u64, CoreError> {
        let (min_ms, max_ms) = self.ping_bounds_ms();
        sample_uniform_range(min_ms, max_ms, || {
            Ok(u64::from_le_bytes(random_bytes::<8>()?))
        })
    }

    /// Deterministically samples the next jittered keepalive ping delay from `(seed, counter)`.
    #[must_use]
    pub fn next_ping_delay_ms_from_seed(&self, seed: &[u8; 32], counter: u64) -> u64 {
        let (min_ms, max_ms) = self.ping_bounds_ms();
        sample_uniform_seeded(seed, b"tendril-v2-ping-jitter", counter, min_ms, max_ms)
    }

    /// Samples jittered per-epoch [`RekeyThresholds`] using the platform CSPRNG.
    pub fn sample_rekey_thresholds(&self) -> Result<RekeyThresholds, CoreError> {
        let (min_f, max_f) = self.rekey_frame_bounds();
        let (min_a, max_a) = self.rekey_age_bounds_ms();
        Ok(RekeyThresholds {
            max_frames: sample_uniform_range(min_f, max_f, || {
                Ok(u64::from_le_bytes(random_bytes::<8>()?))
            })?,
            max_age_ms: sample_uniform_range(min_a, max_a, || {
                Ok(u64::from_le_bytes(random_bytes::<8>()?))
            })?,
        })
    }

    /// Deterministically samples [`RekeyThresholds`] from `(seed, epoch)`.
    #[must_use]
    pub fn sample_rekey_thresholds_from_seed(
        &self,
        seed: &[u8; 32],
        epoch: u64,
    ) -> RekeyThresholds {
        let (min_f, max_f) = self.rekey_frame_bounds();
        let (min_a, max_a) = self.rekey_age_bounds_ms();
        RekeyThresholds {
            max_frames: sample_uniform_seeded(
                seed,
                b"tendril-v2-rekey-frames",
                epoch,
                min_f,
                max_f,
            ),
            max_age_ms: sample_uniform_seeded(seed, b"tendril-v2-rekey-age", epoch, min_a, max_a),
        }
    }
}

fn sample_uniform_range<F>(min: u64, max: u64, mut next_u64: F) -> Result<u64, CoreError>
where
    F: FnMut() -> Result<u64, CoreError>,
{
    if min >= max {
        return Ok(min);
    }
    let span = u128::from(max - min) + 1;
    let total = 1u128 << 64;
    let zone = total - (total % span);
    loop {
        let raw = u128::from(next_u64()?);
        if raw < zone {
            return Ok(min + (raw % span) as u64);
        }
    }
}

fn sample_uniform_seeded(seed: &[u8; 32], label: &[u8], counter: u64, min: u64, max: u64) -> u64 {
    let mut attempt = 0u64;
    sample_uniform_range(min, max, || {
        let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC-SHA256 accepts 32-byte key");
        mac.update(label);
        mac.update(&counter.to_be_bytes());
        mac.update(&attempt.to_be_bytes());
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        attempt = attempt.wrapping_add(1);
        Ok(u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")))
    })
    .expect("infallible seeded sampler")
}

/// Indicates whether the current epoch has reached its frame or age rekey boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyStatus {
    Ok,
    RekeyDue,
}

/// Ciphertext and rekey status produced by [`SealedSession::seal`] and [`SealedSession::seal_dummy_cover`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealOutcome {
    pub ciphertext: Vec<u8>,
    pub rekey_status: RekeyStatus,
}

/// Sans-I/O sealed transport wrapper supporting v1 unpadded mode and v2 bucketed padding,
/// cover frames, and jittered rekey thresholds.
pub struct SealedSession {
    transport: NoiseTransport,
    padding: PaddingPolicy,
    rekey: RekeyThresholds,
    jitter: Option<ScheduleJitterPolicy>,
    frames_sent: u64,
    last_rekey_ms: u64,
}

impl SealedSession {
    /// Creates a [`SealedSession`] with v1 defaults (no inner padding, standard fixed rekey limits).
    #[must_use]
    pub fn new(transport: NoiseTransport) -> Self {
        Self {
            transport,
            padding: PaddingPolicy::disabled(),
            rekey: RekeyThresholds::default(),
            jitter: None,
            frames_sent: 0,
            last_rekey_ms: 0,
        }
    }

    /// Creates a [`SealedSession`] configured with explicit v2 padding and rekey policies.
    ///
    /// Clamps `rekey` thresholds below [`MAX_REKEY_FRAMES_CEILING`] and [`MAX_REKEY_AGE_MS_CEILING`].
    #[must_use]
    pub fn with_v2_policies(
        transport: NoiseTransport,
        padding: PaddingPolicy,
        rekey: RekeyThresholds,
        jitter: Option<ScheduleJitterPolicy>,
        now_ms: u64,
    ) -> Self {
        Self {
            transport,
            padding,
            rekey: RekeyThresholds {
                max_frames: rekey.max_frames.clamp(1, MAX_REKEY_FRAMES_CEILING),
                max_age_ms: rekey.max_age_ms.clamp(1, MAX_REKEY_AGE_MS_CEILING),
            },
            jitter,
            frames_sent: 0,
            last_rekey_ms: now_ms,
        }
    }

    /// Returns the active [`RekeyThresholds`] for this cipher epoch.
    #[must_use]
    pub const fn rekey_thresholds(&self) -> RekeyThresholds {
        self.rekey
    }

    /// Returns the count of transport frames sealed in the current outgoing key epoch.
    #[must_use]
    pub const fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Returns the current outgoing AEAD nonce counter.
    #[must_use]
    pub const fn tx_nonce(&self) -> u64 {
        self.transport.tx_nonce()
    }

    /// Returns the current incoming AEAD nonce counter.
    #[must_use]
    pub const fn rx_nonce(&self) -> u64 {
        self.transport.rx_nonce()
    }

    /// Evaluates whether an outgoing `0x04 REKEY` is currently due at `now_ms`.
    #[must_use]
    pub fn rekey_status(&self, now_ms: u64) -> RekeyStatus {
        if self.frames_sent >= self.rekey.max_frames
            || now_ms.saturating_sub(self.last_rekey_ms) >= self.rekey.max_age_ms
        {
            RekeyStatus::RekeyDue
        } else {
            RekeyStatus::Ok
        }
    }

    /// Derives `(reconnect_secret, mailbox_secret)` bound to `host_static_pub`.
    #[must_use]
    pub fn export_v2_secrets(
        &self,
        host_static_pub: &[u8; 32],
    ) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        self.transport.export_v2_secrets(host_static_pub)
    }

    fn prepare_inner_plaintext(
        &self,
        kind: InnerFrameType,
        payload: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        if matches!(
            kind,
            InnerFrameType::Rekey | InnerFrameType::Padding | InnerFrameType::Padded
        ) {
            return Err(CoreError::InvalidInnerFramePayload(
                "use seal_rekey() or seal_dummy_cover() for Rekey/Padding frames",
            ));
        }
        if self.padding.enabled {
            Ok(Zeroizing::new(pad_inner_frame(
                kind,
                payload,
                &self.padding,
            )?))
        } else {
            Ok(Zeroizing::new(encode_inner_frame(kind, payload)?))
        }
    }

    fn prepare_dummy_plaintext(&self, bucket: usize) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        if !self.padding.enabled {
            return Err(CoreError::InvalidInnerFramePayload(
                "0x08 cover frames require an enabled PaddingPolicy",
            ));
        }
        if !self.padding.buckets.contains(&bucket) {
            return Err(CoreError::InvalidInnerFramePayload(
                "cover bucket not in PaddingPolicy buckets",
            ));
        }
        Ok(Zeroizing::new(encode_dummy_cover_frame(bucket)?))
    }

    fn seal_prepared_plaintext(
        &mut self,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<SealOutcome, CoreError> {
        if self.frames_sent >= MAX_REKEY_FRAMES_CEILING {
            return Err(CoreError::ProtocolViolation(
                "hard rekey frame ceiling reached; call seal_rekey()",
            ));
        }
        let ciphertext = self.transport.write_message_vec(plaintext)?;
        self.frames_sent = self.frames_sent.saturating_add(1);
        let rekey_status = self.rekey_status(now_ms);
        Ok(SealOutcome {
            ciphertext,
            rekey_status,
        })
    }

    /// Seals one inner frame (`0x01..=0x03`, `0x05..=0x07`), applying `PaddingPolicy` when enabled.
    ///
    /// Rejects `Rekey`, `Padding`, and `Padded` (use [`Self::seal_rekey`] and
    /// [`Self::seal_dummy_cover`]), and fails closed before mutating TX nonce or frame counters.
    pub fn seal(
        &mut self,
        kind: InnerFrameType,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<SealOutcome, CoreError> {
        let plaintext = self.prepare_inner_plaintext(kind, payload)?;
        self.seal_prepared_plaintext(&plaintext, now_ms)
    }

    /// Seals one pure `0x08 PADDING` cover frame sized to `bucket`.
    pub fn seal_dummy_cover(
        &mut self,
        bucket: usize,
        now_ms: u64,
    ) -> Result<SealOutcome, CoreError> {
        let plaintext = self.prepare_dummy_plaintext(bucket)?;
        self.seal_prepared_plaintext(&plaintext, now_ms)
    }

    /// Seals a `0x04 REKEY` frame and advances the outgoing Noise cipher key and rekey epoch.
    ///
    /// Pre-pads the `REKEY` frame and samples the next epoch's thresholds BEFORE mutating the
    /// outgoing cipher state so any failure leaves TX keys and nonces unchanged.
    pub fn seal_rekey(&mut self, now_ms: u64) -> Result<Vec<u8>, CoreError> {
        let plaintext = if self.padding.enabled {
            Zeroizing::new(pad_inner_frame(InnerFrameType::Rekey, &[], &self.padding)?)
        } else {
            Zeroizing::new(encode_inner_frame(InnerFrameType::Rekey, &[])?)
        };
        let next_thresholds = match self.jitter {
            Some(ref policy) => Some(policy.sample_rekey_thresholds()?),
            None => None,
        };
        let ciphertext = self.transport.write_message_vec(&plaintext)?;
        self.transport.rekey_outgoing()?;
        self.frames_sent = 0;
        self.last_rekey_ms = now_ms;
        if let Some(next) = next_thresholds {
            self.rekey = next;
        }
        Ok(ciphertext)
    }

    /// Atomically validates/pads `(kind, payload)`, triggers `seal_rekey()` if due, and seals the frame.
    ///
    /// If validation or padding fails, neither `seal_rekey()` nor `seal()` mutates TX state.
    pub fn seal_auto_rekey(
        &mut self,
        kind: InnerFrameType,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(Option<Vec<u8>>, SealOutcome), CoreError> {
        let plaintext = self.prepare_inner_plaintext(kind, payload)?;
        if plaintext.len().saturating_add(AEAD_TAG_LEN) > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: plaintext.len().saturating_add(AEAD_TAG_LEN),
                max: MAX_FRAME_LEN,
            });
        }
        let rekey_ct = if self.rekey_status(now_ms) == RekeyStatus::RekeyDue {
            Some(self.seal_rekey(now_ms)?)
        } else {
            None
        };
        let outcome = self.seal_prepared_plaintext(&plaintext, now_ms)?;
        Ok((rekey_ct, outcome))
    }

    /// Atomically validates `bucket`, triggers `seal_rekey()` if due, and seals a `0x08` cover frame.
    pub fn seal_dummy_cover_auto_rekey(
        &mut self,
        bucket: usize,
        now_ms: u64,
    ) -> Result<(Option<Vec<u8>>, SealOutcome), CoreError> {
        let plaintext = self.prepare_dummy_plaintext(bucket)?;
        let rekey_ct = if self.rekey_status(now_ms) == RekeyStatus::RekeyDue {
            Some(self.seal_rekey(now_ms)?)
        } else {
            None
        };
        let outcome = self.seal_prepared_plaintext(&plaintext, now_ms)?;
        Ok((rekey_ct, outcome))
    }

    /// Decrypts and decodes an incoming transport frame.
    ///
    /// In v1 mode (`!padding.is_enabled()`), rejects `0x08` and `0x09` (`UnknownInnerFrameType`).
    /// In v2 mode, handles `0x08` cover and `0x09` padded frames, and automatically calls
    /// `rekey_incoming()` on `0x04 REKEY`.
    pub fn unseal(&mut self, ciphertext: &[u8]) -> Result<V2InnerFrame, CoreError> {
        let plaintext = self.transport.read_message_vec(ciphertext)?;
        let decoded = if !self.padding.enabled {
            let (kind, payload) = decode_inner_frame(&plaintext)?;
            if matches!(kind, InnerFrameType::Padding | InnerFrameType::Padded) {
                return Err(CoreError::UnknownInnerFrameType(kind as u8));
            }
            V2InnerFrame::Frame {
                kind,
                payload: payload.to_vec(),
            }
        } else {
            decode_v2_inner_frame(&plaintext, !self.padding.require_padded_rx)?
        };
        if let V2InnerFrame::Frame {
            kind: InnerFrameType::Rekey,
            ..
        } = decoded
        {
            self.transport.rekey_incoming()?;
        }
        Ok(decoded)
    }
}

impl fmt::Debug for SealedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSession")
            .field("padding_enabled", &self.padding.enabled)
            .field("frames_sent", &self.frames_sent)
            .field("rekey", &self.rekey)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 5. Pseudonymous Paired Reconnect (`intent = 0x01`, `version = 0x02`)
// ---------------------------------------------------------------------------

/// Computes the 32-byte `HMAC-SHA256` pseudonymous rendezvous tag carried in v2 `msg1`.
#[must_use]
pub fn compute_rendezvous_mac(
    reconnect_secret: &[u8; 32],
    preamble: &[u8; PREAMBLE_LEN],
    e_i_pub: &[u8; 32],
    ekem_i_hash: &[u8; 32],
    rendezvous_nonce: &[u8; 16],
    ts_unix: u64,
) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(reconnect_secret).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(RENDEZVOUS_DOMAIN);
    mac.update(preamble);
    mac.update(e_i_pub);
    mac.update(ekem_i_hash);
    mac.update(rendezvous_nonce);
    mac.update(&ts_unix.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// Verifies a v2 `msg1` rendezvous MAC in constant time.
#[must_use]
pub fn verify_rendezvous_mac(
    reconnect_secret: &[u8; 32],
    preamble: &[u8; PREAMBLE_LEN],
    e_i_pub: &[u8; 32],
    ekem_i_hash: &[u8; 32],
    rendezvous_nonce: &[u8; 16],
    ts_unix: u64,
    candidate_mac: &[u8; 32],
) -> bool {
    let expected = compute_rendezvous_mac(
        reconnect_secret,
        preamble,
        e_i_pub,
        ekem_i_hash,
        rendezvous_nonce,
        ts_unix,
    );
    bool::from(expected.ct_eq(candidate_mac))
}

/// Bounded replay cache rejecting repeated `rendezvous_nonce` values within the skew window.
#[derive(Debug, Default)]
pub struct RendezvousReplayCache {
    seen: BTreeSet<[u8; 16]>,
    order: VecDeque<(u64, [u8; 16])>,
}

impl RendezvousReplayCache {
    /// Creates an empty bounded rendezvous replay cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn prune(&mut self, now_unix: u64) {
        let cutoff = now_unix.saturating_sub(V2_RENDEZVOUS_MAX_SKEW_SECS);
        while let Some(&(ts, nonce)) = self.order.front() {
            if ts < cutoff {
                self.order.pop_front();
                self.seen.remove(&nonce);
            } else {
                break;
            }
        }
    }

    /// Returns current number of cached nonces (including unexpired entries).
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Returns `true` if no nonces are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Checks whether `nonce` has already been seen in the active window.
    pub fn contains(&mut self, nonce: &[u8; 16], now_unix: u64) -> bool {
        self.prune(now_unix);
        self.seen.contains(nonce)
    }

    /// Returns `true` only if `nonce` is unseen and the active window has spare capacity.
    pub fn can_accept(&mut self, nonce: &[u8; 16], now_unix: u64) -> bool {
        self.prune(now_unix);
        !self.seen.contains(nonce) && self.order.len() < MAX_RENDEZVOUS_REPLAY_ENTRIES
    }

    /// Records an authenticated `nonce` at `ts_unix`, failing closed (`false`) if replayed or full.
    pub fn record(&mut self, nonce: [u8; 16], ts_unix: u64, now_unix: u64) -> bool {
        self.prune(now_unix);
        if self.seen.contains(&nonce) {
            return false;
        }
        if self.order.len() >= MAX_RENDEZVOUS_REPLAY_ENTRIES {
            return false;
        }
        self.seen.insert(nonce);
        self.order.push_back((ts_unix, nonce));
        true
    }
}

fn select_handshake_bucket(needed: usize) -> Result<usize, CoreError> {
    V2_HANDSHAKE_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .ok_or(CoreError::FrameTooLarge {
            len: needed,
            max: *V2_HANDSHAKE_BUCKETS.last().unwrap_or(&63_488),
        })
}

fn seal_v2_hello_envelope(
    reconnect_secret: &[u8; 32],
    rendezvous_nonce: &[u8; 16],
    h_pre: &[u8; 32],
    host_hello_json: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let needed = 2 + host_hello_json.len() + AEAD_TAG_LEN;
    let bucket = select_handshake_bucket(needed)?;
    let pt_len = bucket - AEAD_TAG_LEN;
    let json_len = u16::try_from(host_hello_json.len()).map_err(|_| CoreError::FrameTooLarge {
        len: needed,
        max: *V2_HANDSHAKE_BUCKETS.last().unwrap_or(&63_488),
    })?;
    let mut pt = Zeroizing::new(vec![0u8; pt_len]);
    pt[..2].copy_from_slice(&json_len.to_be_bytes());
    pt[2..2 + host_hello_json.len()].copy_from_slice(host_hello_json);

    let key = hkdf_sha256_32(reconnect_secret, rendezvous_nonce, HELLO_SEAL_INFO);
    let cipher = ChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|err| CoreError::Noise(format!("hello seal init: {err}")))?;
    let mut buf = pt.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(&[0u8; 12]), h_pre, &mut buf)
        .map_err(|_| CoreError::Noise("hello envelope seal failed".into()))?;
    Ok(buf)
}

fn unseal_v2_hello_envelope(
    reconnect_secret: &[u8; 32],
    rendezvous_nonce: &[u8; 16],
    h_pre: &[u8; 32],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    if envelope.len() < 2 + AEAD_TAG_LEN {
        return Err(CoreError::HostKeyUnverified);
    }
    let key = hkdf_sha256_32(reconnect_secret, rendezvous_nonce, HELLO_SEAL_INFO);
    let cipher = ChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|err| CoreError::Noise(format!("hello unseal init: {err}")))?;
    let mut pt = Zeroizing::new(envelope.to_vec());
    cipher
        .decrypt_in_place(Nonce::from_slice(&[0u8; 12]), h_pre, &mut *pt)
        .map_err(|_| CoreError::HostKeyUnverified)?;
    if pt.len() < 2 {
        return Err(CoreError::HostKeyUnverified);
    }
    let json_len = usize::from(u16::from_be_bytes([pt[0], pt[1]]));
    if json_len > pt.len() - 2 {
        return Err(CoreError::ProtocolViolation(
            "invalid sealed HostHello length",
        ));
    }
    let mut nonzero = 0u8;
    for &b in &pt[2 + json_len..] {
        nonzero |= b;
    }
    if !bool::from(nonzero.ct_eq(&0u8)) {
        return Err(CoreError::ProtocolViolation(
            "non-zero padding in HostHello envelope",
        ));
    }
    Ok(Zeroizing::new(pt[2..2 + json_len].to_vec()))
}

fn pad_msg3_payload(json: &[u8]) -> Result<Vec<u8>, CoreError> {
    let needed = 2 + json.len();
    let bucket = V2_MSG3_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .ok_or(CoreError::FrameTooLarge {
            len: needed,
            max: *V2_MSG3_BUCKETS.last().unwrap_or(&63_488),
        })?;
    let json_len = u16::try_from(json.len()).map_err(|_| CoreError::FrameTooLarge {
        len: needed,
        max: *V2_MSG3_BUCKETS.last().unwrap_or(&63_488),
    })?;
    let mut out = vec![0u8; bucket];
    out[..2].copy_from_slice(&json_len.to_be_bytes());
    out[2..2 + json.len()].copy_from_slice(json);
    Ok(out)
}

fn unpad_msg3_payload(padded: &[u8]) -> Result<&[u8], CoreError> {
    if padded.len() < 2 {
        return Err(CoreError::ProtocolViolation("truncated v2 msg3 payload"));
    }
    let json_len = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
    if json_len > padded.len() - 2 {
        return Err(CoreError::ProtocolViolation("invalid v2 msg3 payload len"));
    }
    let mut nonzero = 0u8;
    for &b in &padded[2 + json_len..] {
        nonzero |= b;
    }
    if !bool::from(nonzero.ct_eq(&0u8)) {
        return Err(CoreError::ProtocolViolation(
            "non-zero padding in v2 msg3 payload",
        ));
    }
    Ok(&padded[2..2 + json_len])
}

/// Outbound bytes and protocol events produced by [`V2SessionInitiator`] and [`V2SessionResponder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2SessionAction {
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

enum V2InitPhase {
    Init(Box<NoiseHfsHandshake>),
    AwaitMsg2 {
        hs: Box<NoiseHfsHandshake>,
        rendezvous_nonce: [u8; 16],
    },
    Transport(Box<SealedSession>),
    Closed,
}

/// Wire v2 (`0x02`) pseudonymous paired reconnect initiator with full grant/CRL enforcement.
pub struct V2SessionInitiator {
    phase: V2InitPhase,
    reader: ResumableFrameReader,
    #[cfg(any(test, feature = "test-utils"))]
    local_static_priv: Zeroizing<[u8; 32]>,
    local_device_id: String,
    target_host_id: String,
    reconnect_secret: Zeroizing<[u8; 32]>,
    initial_grant: Option<Grant>,
    initial_crl_seq: Option<u64>,
    active_grant: Option<Grant>,
    padding: PaddingPolicy,
    jitter: ScheduleJitterPolicy,
    applied_rotation: Vec<RotationRecord>,
    peer_static_pub: Option<[u8; 32]>,
    exported_secrets: Option<V2PeerSecrets>,
    #[cfg(any(test, feature = "test-utils"))]
    fixed_rendezvous_nonce: Option<[u8; 16]>,
}

impl fmt::Debug for V2SessionInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2SessionInitiator")
            .field("target_host_id", &self.target_host_id)
            .field("established", &self.is_established())
            .field("reconnect_secret", &"<redacted>")
            .finish()
    }
}

impl V2SessionInitiator {
    /// Creates a v2 session initiator using `reconnect_secret` for pseudonymous rendezvous.
    pub fn new(
        local_identity: &EndpointIdentity,
        target_host_id: impl Into<String>,
        reconnect_secret: [u8; 32],
        initial_grant: Option<Grant>,
        crl_seq: Option<u64>,
    ) -> Result<Self, CoreError> {
        let preamble = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
        let hs = NoiseHfsHandshakeBuilder::new()
            .local_private_key(local_identity.static_key().secret_bytes())
            .prologue(&preamble)
            .build_initiator()?;
        Ok(Self {
            phase: V2InitPhase::Init(Box::new(hs)),
            reader: ResumableFrameReader::new(),
            #[cfg(any(test, feature = "test-utils"))]
            local_static_priv: Zeroizing::new(*local_identity.static_key().secret_bytes()),
            local_device_id: local_identity.device_id(),
            target_host_id: target_host_id.into(),
            reconnect_secret: Zeroizing::new(reconnect_secret),
            initial_grant: initial_grant.clone(),
            initial_crl_seq: crl_seq,
            active_grant: initial_grant,
            padding: PaddingPolicy::v2_default(),
            jitter: ScheduleJitterPolicy::default(),
            applied_rotation: Vec::new(),
            peer_static_pub: None,
            exported_secrets: None,
            #[cfg(any(test, feature = "test-utils"))]
            fixed_rendezvous_nonce: None,
        })
    }

    /// Overrides ephemeral Noise randomness strictly in tests.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_fixed_ephemeral_for_testing_only(
        mut self,
        eph_seed: [u8; 32],
    ) -> Result<Self, CoreError> {
        let preamble = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
        let hs = NoiseHfsHandshakeBuilder::new()
            .local_private_key(&self.local_static_priv)
            .prologue(&preamble)
            .fixed_ephemeral_for_testing_only(eph_seed)
            .build_initiator()?;
        self.phase = V2InitPhase::Init(Box::new(hs));
        Ok(self)
    }

    /// Overrides the random `rendezvous_nonce` strictly in tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_rendezvous_nonce_for_testing_only(mut self, nonce: [u8; 16]) -> Self {
        self.fixed_rendezvous_nonce = Some(nonce);
        self
    }

    /// Overrides the v2 padding policy used once the session enters transport mode.
    #[must_use]
    pub fn with_padding_policy(mut self, padding: PaddingPolicy) -> Self {
        self.padding = padding;
        self
    }

    /// Returns true once the v2 handshake has completed and entered [`SealedSession`] transport mode.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.phase, V2InitPhase::Transport(_))
    }

    /// Returns true once the v2 session has closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.phase, V2InitPhase::Closed)
    }

    /// Returns the verified host rotation records applied during `msg2`.
    #[must_use]
    pub fn applied_rotation(&self) -> &[RotationRecord] {
        &self.applied_rotation
    }

    /// Returns the currently verified capability grant associated with this session, if any.
    #[must_use]
    pub const fn active_grant(&self) -> Option<&Grant> {
        self.active_grant.as_ref()
    }

    /// Returns the newly exported v2 `(reconnect_secret, mailbox_secret)` once established.
    #[must_use]
    pub const fn exported_v2_secrets(&self) -> Option<&V2PeerSecrets> {
        self.exported_secrets.as_ref()
    }

    /// Emits the 6-byte v2 preamble + `msg1` carrying the 56-byte timestamped rendezvous proof.
    pub fn start(&mut self, now_unix: u64) -> Result<Vec<V2SessionAction>, CoreError> {
        let prev = std::mem::replace(&mut self.phase, V2InitPhase::Closed);
        let V2InitPhase::Init(mut hs) = prev else {
            return Err(CoreError::NotReady("v2 initiator already started"));
        };
        let preamble = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
        #[cfg(any(test, feature = "test-utils"))]
        let rendezvous_nonce = match self.fixed_rendezvous_nonce {
            Some(n) => n,
            None => random_bytes::<16>()?,
        };
        #[cfg(not(any(test, feature = "test-utils")))]
        let rendezvous_nonce = random_bytes::<16>()?;
        let secret = &self.reconnect_secret;
        let msg1 = hs.write_msg1_with_payload(|e_pub, ek_bytes| {
            let ek_hash: [u8; 32] = Sha256::digest(ek_bytes).into();
            let mac = compute_rendezvous_mac(
                secret,
                &preamble,
                e_pub,
                &ek_hash,
                &rendezvous_nonce,
                now_unix,
            );
            let mut payload = Vec::with_capacity(V2_RENDEZVOUS_PROOF_LEN);
            payload.extend_from_slice(&rendezvous_nonce);
            payload.extend_from_slice(&now_unix.to_be_bytes());
            payload.extend_from_slice(&mac);
            Ok(payload)
        })?;
        let frame = encode_frame(&msg1)?;
        let mut wire = Vec::with_capacity(preamble.len() + frame.len());
        wire.extend_from_slice(&preamble);
        wire.extend_from_slice(&frame);
        self.phase = V2InitPhase::AwaitMsg2 {
            hs,
            rendezvous_nonce,
        };
        Ok(vec![V2SessionAction::WriteBytes(wire)])
    }

    /// Feeds inbound transport bytes into the v2 initiator state machine.
    pub fn feed_bytes(
        &mut self,
        chunk: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        if matches!(self.phase, V2InitPhase::Closed) {
            return Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "v2 session closed".to_string(),
            });
        }
        if let Err(err) = self.reader.push(chunk) {
            self.phase = V2InitPhase::Closed;
            return Err(err);
        }
        let mut actions = Vec::new();
        loop {
            let body = match self.reader.next_frame() {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = V2InitPhase::Closed;
                    return Err(err);
                }
            };
            if let Err(err) = self.handle_frame(&body, now_unix, now_ms, roster, &mut actions) {
                self.phase = V2InitPhase::Closed;
                return Err(err);
            }
            if matches!(self.phase, V2InitPhase::Closed) {
                return Ok(actions);
            }
        }
    }

    fn handle_frame(
        &mut self,
        body: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
        actions: &mut Vec<V2SessionAction>,
    ) -> Result<(), CoreError> {
        let phase = std::mem::replace(&mut self.phase, V2InitPhase::Closed);
        match phase {
            V2InitPhase::AwaitMsg2 {
                mut hs,
                rendezvous_nonce,
            } => {
                let (outer_env, h_pre) = hs.read_msg2_with_pre_payload_hash(body)?;
                let hello_json = unseal_v2_hello_envelope(
                    &self.reconnect_secret,
                    &rendezvous_nonce,
                    &h_pre,
                    &outer_env,
                )?;
                let host_hello: HostHello = serde_json::from_slice(&hello_json)
                    .map_err(|err| CoreError::Json(err.to_string()))?;
                if host_hello.proto_version != WIRE_VERSION_V2 {
                    return Err(CoreError::UnsupportedVersion(host_hello.proto_version));
                }
                if host_hello.host_id != self.target_host_id
                    || host_hello.host_id.is_empty()
                    || has_control_chars(&host_hello.host_id)
                {
                    return Err(CoreError::HostKeyUnverified);
                }
                let host_signing_pub = HybridSigningPublicKey::from_b64url(&host_hello.signing_pub)
                    .map_err(|_| CoreError::HostKeyUnverified)?;
                let peer_static: [u8; 32] =
                    *hs.get_remote_static().ok_or(CoreError::HostKeyUnverified)?;
                if !is_valid_x25519_public_key(&peer_static) {
                    return Err(CoreError::HostKeyUnverified);
                }

                let (pinned_static, pinned_signing) = match roster.get(&self.target_host_id) {
                    Some(entry) => {
                        check_wire_version(entry.min_wire_version, WIRE_VERSION_V2)?;
                        match entry.state {
                            PeerState::Pending => {
                                return Err(CoreError::PeerPending(self.target_host_id.clone()));
                            }
                            PeerState::Revoked => {
                                return Err(CoreError::PeerRevoked(self.target_host_id.clone()));
                            }
                            PeerState::Active => entry.require_complete_pin()?,
                        }
                    }
                    None => return Err(CoreError::HostKeyUnverified),
                };
                if host_hello.rotation.is_empty()
                    && peer_static == pinned_static
                    && host_signing_pub != pinned_signing
                {
                    return Err(CoreError::HostKeyUnverified);
                }
                match roster.apply_verified_rotation(
                    &self.target_host_id,
                    &host_hello.rotation,
                    &peer_static,
                    &host_signing_pub,
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
                let hello_bytes = Zeroizing::new(
                    serde_json::to_vec(&hello).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let msg3_payload = Zeroizing::new(pad_msg3_payload(&hello_bytes)?);
                let msg3 = hs.write_message_vec(&msg3_payload)?;
                let final_hash = *hs.get_handshake_hash();
                let transport = hs.into_transport_mode()?;
                let (next_reconnect, next_mailbox) = transport.export_v2_secrets(&peer_static);
                self.exported_secrets = Some(V2PeerSecrets::new(*next_reconnect, *next_mailbox));
                let thresholds = self.jitter.sample_rekey_thresholds()?;
                let sealed = SealedSession::with_v2_policies(
                    transport,
                    self.padding.clone(),
                    thresholds,
                    Some(self.jitter),
                    now_ms,
                );
                self.peer_static_pub = Some(peer_static);
                self.phase = V2InitPhase::Transport(Box::new(sealed));

                actions.push(V2SessionAction::WriteBytes(encode_frame(&msg3)?));
                actions.push(V2SessionAction::Established {
                    peer_device_id: self.target_host_id.clone(),
                    peer_static_pub: peer_static,
                    final_handshake_hash: final_hash,
                });
                Ok(())
            }
            V2InitPhase::Transport(mut sealed) => {
                let decoded = sealed.unseal(body)?;
                self.phase = V2InitPhase::Transport(sealed);
                self.handle_transport_frame(decoded, now_unix, now_ms, roster, actions)
            }
            V2InitPhase::Init(_) => Err(CoreError::NotReady("v2 initiator must call start()")),
            V2InitPhase::Closed => Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "v2 session closed".to_string(),
            }),
        }
    }

    fn handle_transport_frame(
        &mut self,
        decoded: V2InnerFrame,
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
        actions: &mut Vec<V2SessionAction>,
    ) -> Result<(), CoreError> {
        match decoded {
            V2InnerFrame::DummyCover { .. } => {}
            V2InnerFrame::Frame { kind, payload } => match kind {
                InnerFrameType::Data => actions.push(V2SessionAction::AppData(payload)),
                InnerFrameType::Grant => {
                    let grant: Grant = serde_json::from_slice(&payload)
                        .map_err(|err| CoreError::Json(err.to_string()))?;
                    let root_id = self.target_host_id.clone();
                    let subject = self.local_device_id.clone();
                    verify_grant_with_chain(
                        &grant,
                        &subject,
                        &root_id,
                        now_unix,
                        roster.crl(&root_id),
                        |issuer| roster.lookup_active_signing_key(issuer),
                    )?;
                    self.active_grant = Some(grant.clone());
                    actions.push(V2SessionAction::GrantUpdated(grant));
                }
                InnerFrameType::Revocation => {
                    let crl: RevocationList = serde_json::from_slice(&payload)
                        .map_err(|err| CoreError::Json(err.to_string()))?;
                    let root_id = self.target_host_id.clone();
                    let root_pub = roster
                        .lookup_active_signing_key(&root_id)
                        .ok_or_else(|| CoreError::IncompletePin(root_id.clone()))?;
                    let seq = crl.seq;
                    roster.ingest_crl(crl, &root_id, &root_pub)?;
                    actions.push(V2SessionAction::RevocationUpdated {
                        issuer: root_id,
                        seq,
                    });
                    self.verify_peer_and_active_grant(now_unix, roster)?;
                }
                InnerFrameType::Rekey => {
                    self.verify_peer_and_active_grant(now_unix, roster)?;
                    actions.push(V2SessionAction::Rekeyed {
                        direction: RekeyDirection::Incoming,
                    });
                }
                InnerFrameType::Ping => {
                    let cookie: [u8; 8] = payload
                        .try_into()
                        .map_err(|_| CoreError::InvalidInnerFramePayload("PING must be 8 bytes"))?;
                    let V2InitPhase::Transport(ref mut sealed) = self.phase else {
                        return Err(CoreError::NotReady("v2 session not established"));
                    };
                    let mut reply =
                        seal_transport_action(sealed, InnerFrameType::Pong, &cookie, now_ms)?;
                    actions.append(&mut reply);
                }
                InnerFrameType::Pong => {
                    let cookie: [u8; 8] = payload
                        .try_into()
                        .map_err(|_| CoreError::InvalidInnerFramePayload("PONG must be 8 bytes"))?;
                    actions.push(V2SessionAction::PongReceived(u64::from_be_bytes(cookie)));
                }
                InnerFrameType::Close => {
                    let code = u16::from_be_bytes([payload[0], payload[1]]);
                    let reason = String::from_utf8(payload[2..].to_vec()).map_err(|_| {
                        CoreError::InvalidInnerFramePayload("CLOSE reason must be UTF-8")
                    })?;
                    self.phase = V2InitPhase::Closed;
                    actions.push(V2SessionAction::CloseTransport { code, reason });
                }
                InnerFrameType::Padding | InnerFrameType::Padded => {
                    return Err(CoreError::UnknownInnerFrameType(kind as u8));
                }
            },
        }
        Ok(())
    }

    fn verify_peer_and_active_grant(
        &self,
        now_unix: u64,
        roster: &Roster,
    ) -> Result<(), CoreError> {
        let entry = roster
            .get(&self.target_host_id)
            .ok_or_else(|| CoreError::PeerNotFound(self.target_host_id.clone()))?;
        match entry.state {
            PeerState::Pending => return Err(CoreError::PeerPending(self.target_host_id.clone())),
            PeerState::Revoked => return Err(CoreError::PeerRevoked(self.target_host_id.clone())),
            PeerState::Active => {
                entry.require_complete_pin()?;
            }
        }
        let crl = roster.crl(&self.target_host_id);
        if let Some(list) = crl
            && list
                .revoked_devices
                .iter()
                .any(|d| d == &self.local_device_id || d == &self.target_host_id)
        {
            return Err(CoreError::PeerRevoked(self.local_device_id.clone()));
        }
        if let Some(ref grant) = self.active_grant {
            verify_grant_with_chain(
                grant,
                &self.local_device_id,
                &self.target_host_id,
                now_unix,
                crl,
                |issuer| roster.lookup_active_signing_key(issuer),
            )?;
        }
        Ok(())
    }

    /// Authorizes `requested_cap` against the verified session grant, roster, and active CRL (default-deny).
    pub fn authorize(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        self.authorize_inner(requested_cap, None, now_unix, roster)
    }

    /// Authorizes path-scoped `action` on `raw_path` after strict canonicalization (default-deny).
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
        let audit_cap = match raw_path {
            Some(path) => format!("{action_or_cap}:{path}"),
            None => action_or_cap.to_string(),
        };
        let deny = |err: CoreError| -> (Result<(), CoreError>, AuditEvent) {
            (
                Err(err.clone()),
                AuditEvent {
                    ts: now_unix,
                    subject: self.local_device_id.clone(),
                    cap: audit_cap.clone(),
                    grant_nonce: self.active_grant.as_ref().map(|g| g.nonce.clone()),
                    allow: false,
                    reason: err.to_string(),
                },
            )
        };
        if !self.is_established() {
            return deny(CoreError::NotReady("v2 session not established"));
        }
        if let Err(err) = self.verify_peer_and_active_grant(now_unix, roster) {
            return deny(err);
        }
        let crl = roster.crl(&self.target_host_id);
        match raw_path {
            Some(path) => authorize_path_capability(
                self.active_grant.as_ref(),
                &self.local_device_id,
                &self.target_host_id,
                action_or_cap,
                path,
                now_unix,
                crl,
                |issuer| roster.lookup_active_signing_key(issuer),
            ),
            None => authorize_grant(
                self.active_grant.as_ref(),
                &self.local_device_id,
                &self.target_host_id,
                action_or_cap,
                now_unix,
                crl,
                |issuer| roster.lookup_active_signing_key(issuer),
            ),
        }
    }

    /// Seals an application `0x01 DATA` frame under the v2 padded [`SealedSession`].
    pub fn seal_data(
        &mut self,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let V2InitPhase::Transport(ref mut sealed) = self.phase else {
            return Err(CoreError::NotReady("v2 session not established"));
        };
        seal_transport_action(sealed, InnerFrameType::Data, payload, now_ms)
    }

    /// Seals a `0x02 GRANT` update frame.
    pub fn seal_grant(
        &mut self,
        grant: &Grant,
        now_ms: u64,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let V2InitPhase::Transport(ref mut sealed) = self.phase else {
            return Err(CoreError::NotReady("v2 session not established"));
        };
        let json = Zeroizing::new(
            serde_json::to_vec(grant).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        seal_transport_action(sealed, InnerFrameType::Grant, &json, now_ms)
    }

    /// Seals a `0x03 REVOCATION` CRL update frame.
    pub fn seal_revocation(
        &mut self,
        crl: &RevocationList,
        now_ms: u64,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let V2InitPhase::Transport(ref mut sealed) = self.phase else {
            return Err(CoreError::NotReady("v2 session not established"));
        };
        let json = Zeroizing::new(
            serde_json::to_vec(crl).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        seal_transport_action(sealed, InnerFrameType::Revocation, &json, now_ms)
    }

    /// Seals a `0x08 PADDING` cover frame sized to `bucket`.
    pub fn seal_dummy_cover(
        &mut self,
        bucket: usize,
        now_ms: u64,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let V2InitPhase::Transport(ref mut sealed) = self.phase else {
            return Err(CoreError::NotReady("v2 session not established"));
        };
        seal_cover_action(sealed, bucket, now_ms)
    }

    /// Advances virtual timers: fails closed if the peer or active grant became invalid.
    pub fn tick(
        &mut self,
        now_unix: u64,
        now_ms: u64,
        roster: &Roster,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        if !self.is_established() {
            return Ok(Vec::new());
        }
        if let Err(err) = self.verify_peer_and_active_grant(now_unix, roster) {
            self.phase = V2InitPhase::Closed;
            return Err(err);
        }
        let V2InitPhase::Transport(ref mut sealed) = self.phase else {
            return Ok(Vec::new());
        };
        if sealed.rekey_status(now_ms) == RekeyStatus::RekeyDue {
            let rekey_ct = sealed.seal_rekey(now_ms)?;
            return Ok(vec![
                V2SessionAction::WriteBytes(encode_frame(&rekey_ct)?),
                V2SessionAction::Rekeyed {
                    direction: RekeyDirection::Outgoing,
                },
            ]);
        }
        Ok(Vec::new())
    }

    /// Extracts the underlying [`SealedSession`] once the handshake is established.
    pub fn into_sealed_session(mut self) -> Result<SealedSession, CoreError> {
        let prev = std::mem::replace(&mut self.phase, V2InitPhase::Closed);
        match prev {
            V2InitPhase::Transport(sealed) => Ok(*sealed),
            _ => Err(CoreError::NotReady("v2 session not established")),
        }
    }
}

enum V2RespPhase {
    AwaitPreamble,
    AwaitMsg1 {
        preamble: [u8; PREAMBLE_LEN],
    },
    AwaitMsg3 {
        hs: Box<NoiseHfsHandshake>,
        authenticated_peer: Option<(String, [u8; 32])>,
    },
    Transport(Box<SealedSession>),
    Closed,
}

/// Wire v2 (`0x02`) pseudonymous paired reconnect responder with replay protection, ephemeral decoy
/// static keys, matching bucket decoys, and full grant/CRL enforcement.
pub struct V2SessionResponder {
    phase: V2RespPhase,
    reader: ResumableFrameReader,
    local_static_priv: Zeroizing<[u8; 32]>,
    local_static_pub: [u8; 32],
    local_host_id: String,
    local_signing_pub: HybridSigningPublicKey,
    local_rotation_chain: Vec<RotationRecord>,
    padding: PaddingPolicy,
    jitter: ScheduleJitterPolicy,
    replay_cache: RendezvousReplayCache,
    peer_device_id: Option<String>,
    peer_static_pub: Option<[u8; 32]>,
    peer_crl_seq: Option<u64>,
    active_grant: Option<Grant>,
    exported_secrets: Option<V2PeerSecrets>,
    #[cfg(any(test, feature = "test-utils"))]
    fixed_ephemeral: Option<[u8; 32]>,
}

impl fmt::Debug for V2SessionResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2SessionResponder")
            .field("local_host_id", &self.local_host_id)
            .field("established", &self.is_established())
            .field("peer_device_id", &self.peer_device_id)
            .finish()
    }
}

impl V2SessionResponder {
    /// Creates a new v2 session responder bound to `local_identity`.
    pub fn new(local_identity: &EndpointIdentity) -> Result<Self, CoreError> {
        Ok(Self {
            phase: V2RespPhase::AwaitPreamble,
            reader: ResumableFrameReader::with_preamble(),
            local_static_priv: Zeroizing::new(*local_identity.static_key().secret_bytes()),
            local_static_pub: *local_identity.static_key().public_bytes(),
            local_host_id: local_identity.host_id().to_string(),
            local_signing_pub: local_identity.signing_key().public_key().clone(),
            local_rotation_chain: local_identity.rotation_chain().to_vec(),
            padding: PaddingPolicy::v2_default(),
            jitter: ScheduleJitterPolicy::default(),
            replay_cache: RendezvousReplayCache::new(),
            peer_device_id: None,
            peer_static_pub: None,
            peer_crl_seq: None,
            active_grant: None,
            exported_secrets: None,
            #[cfg(any(test, feature = "test-utils"))]
            fixed_ephemeral: None,
        })
    }

    /// Overrides ephemeral Noise randomness strictly in tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_fixed_ephemeral_for_testing_only(mut self, eph_seed: [u8; 32]) -> Self {
        self.fixed_ephemeral = Some(eph_seed);
        self
    }

    /// Overrides the v2 padding policy used once established.
    #[must_use]
    pub fn with_padding_policy(mut self, padding: PaddingPolicy) -> Self {
        self.padding = padding;
        self
    }

    /// Returns true once the v2 handshake has completed and entered transport mode.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.phase, V2RespPhase::Transport(_))
    }

    /// Returns true once the v2 session has closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.phase, V2RespPhase::Closed)
    }

    /// Returns the authenticated peer `device_id` once established.
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

    /// Returns the newly exported v2 `(reconnect_secret, mailbox_secret)` once established.
    #[must_use]
    pub const fn exported_v2_secrets(&self) -> Option<&V2PeerSecrets> {
        self.exported_secrets.as_ref()
    }

    fn build_host_hello_json(&self) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let hello = HostHello {
            host_id: self.local_host_id.clone(),
            proto_version: WIRE_VERSION_V2,
            signing_pub: self.local_signing_pub.to_b64url(),
            rotation: self.local_rotation_chain.clone(),
        };
        Ok(Zeroizing::new(
            serde_json::to_vec(&hello).map_err(|err| CoreError::Json(err.to_string()))?,
        ))
    }

    /// Feeds raw transport bytes into the v2 responder state machine using an internal replay cache.
    pub fn feed_bytes(
        &mut self,
        chunk: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let mut cache = std::mem::take(&mut self.replay_cache);
        let res = self.feed_bytes_with_replay_cache(chunk, now_unix, now_ms, roster, &mut cache);
        self.replay_cache = cache;
        res
    }

    /// Feeds raw transport bytes using a caller-owned shared [`RendezvousReplayCache`].
    pub fn feed_bytes_with_replay_cache(
        &mut self,
        chunk: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
        replay_cache: &mut RendezvousReplayCache,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        if matches!(self.phase, V2RespPhase::Closed) {
            return Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "v2 session closed".to_string(),
            });
        }
        if let Err(err) = self.reader.push(chunk) {
            self.phase = V2RespPhase::Closed;
            return Err(err);
        }
        let mut actions = Vec::new();
        if matches!(self.phase, V2RespPhase::AwaitPreamble) {
            match self.reader.take_preamble() {
                Ok(Some(preamble)) => {
                    if preamble.version != WIRE_VERSION_V2 {
                        self.phase = V2RespPhase::Closed;
                        return Err(CoreError::UnsupportedVersion(preamble.version));
                    }
                    if preamble.intent != Intent::Session || preamble.flags != PREAMBLE_FLAG_NONE {
                        self.phase = V2RespPhase::Closed;
                        return Err(CoreError::ProtocolViolation("expected v2 session preamble"));
                    }
                    self.phase = V2RespPhase::AwaitMsg1 {
                        preamble: preamble.encode(),
                    };
                }
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = V2RespPhase::Closed;
                    return Err(err);
                }
            }
        }

        loop {
            let body = match self.reader.next_frame() {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = V2RespPhase::Closed;
                    return Err(err);
                }
            };
            if let Err(err) =
                self.handle_frame(&body, now_unix, now_ms, roster, replay_cache, &mut actions)
            {
                self.phase = V2RespPhase::Closed;
                return Err(err);
            }
            if matches!(self.phase, V2RespPhase::Closed) {
                return Ok(actions);
            }
        }
    }

    fn handle_frame(
        &mut self,
        body: &[u8],
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
        replay_cache: &mut RendezvousReplayCache,
        actions: &mut Vec<V2SessionAction>,
    ) -> Result<(), CoreError> {
        let phase = std::mem::replace(&mut self.phase, V2RespPhase::Closed);
        match phase {
            V2RespPhase::AwaitMsg1 { preamble } => {
                if body.len() < MSG1_LEN {
                    return Err(CoreError::Noise("truncated XXhfs msg1".into()));
                }
                let mut re_i = [0u8; 32];
                re_i.copy_from_slice(&body[..32]);
                let ek_hash: [u8; 32] = Sha256::digest(&body[32..MSG1_LEN]).into();
                let payload = &body[MSG1_LEN..];

                let mut matched: Option<(String, [u8; 32], Zeroizing<[u8; 32]>)> = None;
                let mut r_nonce = [0u8; 16];
                let mut ts_unix = 0u64;
                let mut candidate_mac = [0u8; 32];
                let payload_valid_len = payload.len() == V2_RENDEZVOUS_PROOF_LEN;
                let dummy_key = [0u8; 32];

                if payload_valid_len {
                    r_nonce.copy_from_slice(&payload[..16]);
                    ts_unix = u64::from_be_bytes(payload[16..24].try_into().expect("8-byte ts"));
                    candidate_mac.copy_from_slice(&payload[24..56]);
                }
                let ts_fresh =
                    payload_valid_len && ts_unix.abs_diff(now_unix) <= V2_RENDEZVOUS_MAX_SKEW_SECS;
                let cache_accepts =
                    payload_valid_len && replay_cache.can_accept(&r_nonce, now_unix);

                for (_, entry) in roster.entries() {
                    let active_secret = if entry.state == PeerState::Active {
                        entry.v2_secrets.as_ref().map(|s| s.reconnect_secret())
                    } else {
                        None
                    };
                    let key_ref = active_secret.unwrap_or(&dummy_key);
                    let mac_ok = verify_rendezvous_mac(
                        key_ref,
                        &preamble,
                        &re_i,
                        &ek_hash,
                        &r_nonce,
                        ts_unix,
                        &candidate_mac,
                    );
                    if payload_valid_len
                        && active_secret.is_some()
                        && ts_fresh
                        && cache_accepts
                        && mac_ok
                    {
                        matched = Some((
                            entry.device_id.clone(),
                            entry.static_pub,
                            Zeroizing::new(*key_ref),
                        ));
                    }
                }

                let hello_json = self.build_host_hello_json()?;
                let decoy_bucket = select_handshake_bucket(2 + hello_json.len() + AEAD_TAG_LEN)?;

                let decoy_static = StaticKeypair::generate()?;
                let recorded_match = match matched {
                    Some((peer_id, peer_static, secret))
                        if replay_cache.record(r_nonce, ts_unix, now_unix) =>
                    {
                        Some((peer_id, peer_static, secret))
                    }
                    _ => None,
                };

                let hs_priv: &[u8; 32] = if recorded_match.is_some() {
                    &self.local_static_priv
                } else {
                    decoy_static.secret_bytes()
                };

                let builder = NoiseHfsHandshakeBuilder::new()
                    .local_private_key(hs_priv)
                    .prologue(&preamble);
                #[cfg(any(test, feature = "test-utils"))]
                let builder = match self.fixed_ephemeral {
                    Some(eph) => builder.fixed_ephemeral_for_testing_only(eph),
                    None => builder,
                };
                let mut hs = builder.build_responder()?;
                hs.read_message_vec(body)?;

                let (msg2, authenticated_peer) = if let Some((peer_id, peer_static, secret)) =
                    recorded_match
                {
                    let msg2 = hs.write_msg2_with_hash(|h_pre| {
                        seal_v2_hello_envelope(&secret, &r_nonce, h_pre, &hello_json)
                    })?;
                    (msg2, Some((peer_id, peer_static)))
                } else {
                    let mut decoy = vec![0u8; decoy_bucket];
                    getrandom::fill(&mut decoy).map_err(|err| CoreError::Rng(err.to_string()))?;
                    let msg2 = hs.write_message_vec(&decoy)?;
                    (msg2, None)
                };

                actions.push(V2SessionAction::WriteBytes(encode_frame(&msg2)?));
                self.phase = V2RespPhase::AwaitMsg3 {
                    hs: Box::new(hs),
                    authenticated_peer,
                };
                Ok(())
            }
            V2RespPhase::AwaitMsg3 {
                mut hs,
                authenticated_peer,
            } => {
                let pt = hs.read_message_vec(body)?;
                let Some((expected_peer_id, expected_static)) = authenticated_peer else {
                    return Err(CoreError::HostKeyUnverified);
                };
                let peer_static: [u8; 32] = *hs.get_remote_static().ok_or(
                    CoreError::ProtocolViolation("missing initiator static key in msg3"),
                )?;
                if !is_valid_x25519_public_key(&peer_static)
                    || !bool::from(peer_static.ct_eq(&expected_static))
                {
                    return Err(CoreError::HostKeyUnverified);
                }
                let json_bytes = unpad_msg3_payload(&pt)?;
                let hello: SessionHello = serde_json::from_slice(json_bytes)
                    .map_err(|err| CoreError::Json(err.to_string()))?;
                if hello.device_id != device_id(&peer_static) {
                    return Err(CoreError::ProtocolViolation(
                        "SessionHello device_id does not match static key",
                    ));
                }

                let peer_entry = roster.lookup_active_by_static(&peer_static)?;
                check_wire_version(peer_entry.min_wire_version, WIRE_VERSION_V2)?;
                let canonical_peer_id = peer_entry.device_id.clone();
                if canonical_peer_id != expected_peer_id {
                    return Err(CoreError::HostKeyUnverified);
                }

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

                let final_hash = *hs.get_handshake_hash();
                let transport = hs.into_transport_mode()?;
                let (next_reconnect, next_mailbox) =
                    transport.export_v2_secrets(&self.local_static_pub);
                self.exported_secrets = Some(V2PeerSecrets::new(*next_reconnect, *next_mailbox));
                let thresholds = self.jitter.sample_rekey_thresholds()?;
                let sealed = SealedSession::with_v2_policies(
                    transport,
                    self.padding.clone(),
                    thresholds,
                    Some(self.jitter),
                    now_ms,
                );
                self.peer_crl_seq = hello.crl_seq;
                self.peer_device_id = Some(canonical_peer_id.clone());
                self.peer_static_pub = Some(peer_static);
                self.phase = V2RespPhase::Transport(Box::new(sealed));

                actions.push(V2SessionAction::Established {
                    peer_device_id: canonical_peer_id,
                    peer_static_pub: peer_static,
                    final_handshake_hash: final_hash,
                });
                Ok(())
            }
            V2RespPhase::Transport(mut sealed) => {
                let decoded = sealed.unseal(body)?;
                self.phase = V2RespPhase::Transport(sealed);
                self.handle_transport_frame(decoded, now_unix, now_ms, roster, actions)
            }
            V2RespPhase::AwaitPreamble => Err(CoreError::NotReady("v2 session preamble missing")),
            V2RespPhase::Closed => Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "v2 session closed".to_string(),
            }),
        }
    }

    fn handle_transport_frame(
        &mut self,
        decoded: V2InnerFrame,
        now_unix: u64,
        now_ms: u64,
        roster: &mut Roster,
        actions: &mut Vec<V2SessionAction>,
    ) -> Result<(), CoreError> {
        match decoded {
            V2InnerFrame::DummyCover { .. } => {}
            V2InnerFrame::Frame { kind, payload } => match kind {
                InnerFrameType::Data => actions.push(V2SessionAction::AppData(payload)),
                InnerFrameType::Grant => {
                    let grant: Grant = serde_json::from_slice(&payload)
                        .map_err(|err| CoreError::Json(err.to_string()))?;
                    let root_id = self.local_host_id.clone();
                    let subject = self
                        .peer_device_id
                        .as_deref()
                        .ok_or(CoreError::NotReady("missing peer device_id"))?
                        .to_string();
                    verify_grant_with_chain(
                        &grant,
                        &subject,
                        &root_id,
                        now_unix,
                        roster.crl(&root_id),
                        |issuer| self.lookup_issuer_key(roster, issuer),
                    )?;
                    self.active_grant = Some(grant.clone());
                    actions.push(V2SessionAction::GrantUpdated(grant));
                }
                InnerFrameType::Revocation => {
                    let crl: RevocationList = serde_json::from_slice(&payload)
                        .map_err(|err| CoreError::Json(err.to_string()))?;
                    let root_id = self.local_host_id.clone();
                    let root_pub = self.local_signing_pub.clone();
                    let seq = crl.seq;
                    roster.ingest_crl(crl, &root_id, &root_pub)?;
                    actions.push(V2SessionAction::RevocationUpdated {
                        issuer: root_id,
                        seq,
                    });
                    self.verify_peer_and_active_grant(now_unix, roster)?;
                }
                InnerFrameType::Rekey => {
                    self.verify_peer_and_active_grant(now_unix, roster)?;
                    actions.push(V2SessionAction::Rekeyed {
                        direction: RekeyDirection::Incoming,
                    });
                }
                InnerFrameType::Ping => {
                    let cookie: [u8; 8] = payload
                        .try_into()
                        .map_err(|_| CoreError::InvalidInnerFramePayload("PING must be 8 bytes"))?;
                    let V2RespPhase::Transport(ref mut sealed) = self.phase else {
                        return Err(CoreError::NotReady("v2 session not established"));
                    };
                    let mut reply =
                        seal_transport_action(sealed, InnerFrameType::Pong, &cookie, now_ms)?;
                    actions.append(&mut reply);
                }
                InnerFrameType::Pong => {
                    let cookie: [u8; 8] = payload
                        .try_into()
                        .map_err(|_| CoreError::InvalidInnerFramePayload("PONG must be 8 bytes"))?;
                    actions.push(V2SessionAction::PongReceived(u64::from_be_bytes(cookie)));
                }
                InnerFrameType::Close => {
                    let code = u16::from_be_bytes([payload[0], payload[1]]);
                    let reason = String::from_utf8(payload[2..].to_vec()).map_err(|_| {
                        CoreError::InvalidInnerFramePayload("CLOSE reason must be UTF-8")
                    })?;
                    self.phase = V2RespPhase::Closed;
                    actions.push(V2SessionAction::CloseTransport { code, reason });
                }
                InnerFrameType::Padding | InnerFrameType::Padded => {
                    return Err(CoreError::UnknownInnerFrameType(kind as u8));
                }
            },
        }
        Ok(())
    }

    fn lookup_issuer_key(
        &self,
        roster: &Roster,
        issuer_id: &str,
    ) -> Option<HybridSigningPublicKey> {
        if issuer_id == self.local_host_id {
            Some(self.local_signing_pub.clone())
        } else {
            roster.lookup_active_signing_key(issuer_id)
        }
    }

    fn verify_peer_and_active_grant(
        &self,
        now_unix: u64,
        roster: &Roster,
    ) -> Result<(), CoreError> {
        let peer_static = self
            .peer_static_pub
            .ok_or(CoreError::NotReady("peer static missing"))?;
        roster.lookup_active_by_static(&peer_static)?;
        let crl = roster.crl(&self.local_host_id);
        let peer_id = self
            .peer_device_id
            .as_deref()
            .ok_or(CoreError::NotReady("peer device_id missing"))?;
        if let Some(list) = crl
            && list.revoked_devices.iter().any(|d| d == peer_id)
        {
            return Err(CoreError::PeerRevoked(peer_id.to_string()));
        }
        if let Some(ref grant) = self.active_grant {
            verify_grant_with_chain(
                grant,
                peer_id,
                &self.local_host_id,
                now_unix,
                crl,
                |issuer| self.lookup_issuer_key(roster, issuer),
            )?;
        }
        Ok(())
    }

    /// Authorizes `requested_cap` against the verified session grant, roster, and active CRL (default-deny).
    pub fn authorize(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (Result<(), CoreError>, AuditEvent) {
        self.authorize_inner(requested_cap, None, now_unix, roster)
    }

    /// Authorizes path-scoped `action` on `raw_path` after strict canonicalization (default-deny).
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
        let audit_subj = self.peer_device_id.as_deref().unwrap_or("");
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
            return deny(CoreError::NotReady("v2 session not established"));
        }
        if let Err(err) = self.verify_peer_and_active_grant(now_unix, roster) {
            return deny(err);
        }
        let crl = roster.crl(&self.local_host_id);
        match raw_path {
            Some(path) => authorize_path_capability(
                self.active_grant.as_ref(),
                audit_subj,
                &self.local_host_id,
                action_or_cap,
                path,
                now_unix,
                crl,
                |issuer| self.lookup_issuer_key(roster, issuer),
            ),
            None => authorize_grant(
                self.active_grant.as_ref(),
                audit_subj,
                &self.local_host_id,
                action_or_cap,
                now_unix,
                crl,
                |issuer| self.lookup_issuer_key(roster, issuer),
            ),
        }
    }

    /// Seals an application `0x01 DATA` frame under the v2 padded [`SealedSession`].
    pub fn seal_data(
        &mut self,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let V2RespPhase::Transport(ref mut sealed) = self.phase else {
            return Err(CoreError::NotReady("v2 session not established"));
        };
        seal_transport_action(sealed, InnerFrameType::Data, payload, now_ms)
    }

    /// Seals a `0x02 GRANT` update frame.
    pub fn seal_grant(
        &mut self,
        grant: &Grant,
        now_ms: u64,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let V2RespPhase::Transport(ref mut sealed) = self.phase else {
            return Err(CoreError::NotReady("v2 session not established"));
        };
        let json = Zeroizing::new(
            serde_json::to_vec(grant).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        seal_transport_action(sealed, InnerFrameType::Grant, &json, now_ms)
    }

    /// Seals a `0x03 REVOCATION` CRL update frame.
    pub fn seal_revocation(
        &mut self,
        crl: &RevocationList,
        now_ms: u64,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let V2RespPhase::Transport(ref mut sealed) = self.phase else {
            return Err(CoreError::NotReady("v2 session not established"));
        };
        let json = Zeroizing::new(
            serde_json::to_vec(crl).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        seal_transport_action(sealed, InnerFrameType::Revocation, &json, now_ms)
    }

    /// Seals a `0x08 PADDING` cover frame sized to `bucket`.
    pub fn seal_dummy_cover(
        &mut self,
        bucket: usize,
        now_ms: u64,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        let V2RespPhase::Transport(ref mut sealed) = self.phase else {
            return Err(CoreError::NotReady("v2 session not established"));
        };
        seal_cover_action(sealed, bucket, now_ms)
    }

    /// Advances virtual timers: fails closed if the peer or active grant became invalid.
    pub fn tick(
        &mut self,
        now_unix: u64,
        now_ms: u64,
        roster: &Roster,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        if !self.is_established() {
            return Ok(Vec::new());
        }
        if let Err(err) = self.verify_peer_and_active_grant(now_unix, roster) {
            self.phase = V2RespPhase::Closed;
            return Err(err);
        }
        let V2RespPhase::Transport(ref mut sealed) = self.phase else {
            return Ok(Vec::new());
        };
        if sealed.rekey_status(now_ms) == RekeyStatus::RekeyDue {
            let rekey_ct = sealed.seal_rekey(now_ms)?;
            return Ok(vec![
                V2SessionAction::WriteBytes(encode_frame(&rekey_ct)?),
                V2SessionAction::Rekeyed {
                    direction: RekeyDirection::Outgoing,
                },
            ]);
        }
        Ok(Vec::new())
    }

    /// Extracts the underlying [`SealedSession`] once established.
    pub fn into_sealed_session(mut self) -> Result<SealedSession, CoreError> {
        let prev = std::mem::replace(&mut self.phase, V2RespPhase::Closed);
        match prev {
            V2RespPhase::Transport(sealed) => Ok(*sealed),
            _ => Err(CoreError::NotReady("v2 session not established")),
        }
    }
}

fn seal_transport_action(
    sealed: &mut SealedSession,
    kind: InnerFrameType,
    payload: &[u8],
    now_ms: u64,
) -> Result<Vec<V2SessionAction>, CoreError> {
    let (rekey_ct, outcome) = sealed.seal_auto_rekey(kind, payload, now_ms)?;
    let mut actions = Vec::new();
    if let Some(ct) = rekey_ct {
        actions.push(V2SessionAction::WriteBytes(encode_frame(&ct)?));
        actions.push(V2SessionAction::Rekeyed {
            direction: RekeyDirection::Outgoing,
        });
    }
    actions.push(V2SessionAction::WriteBytes(encode_frame(
        &outcome.ciphertext,
    )?));
    Ok(actions)
}

fn seal_cover_action(
    sealed: &mut SealedSession,
    bucket: usize,
    now_ms: u64,
) -> Result<Vec<V2SessionAction>, CoreError> {
    let (rekey_ct, outcome) = sealed.seal_dummy_cover_auto_rekey(bucket, now_ms)?;
    let mut actions = Vec::new();
    if let Some(ct) = rekey_ct {
        actions.push(V2SessionAction::WriteBytes(encode_frame(&ct)?));
        actions.push(V2SessionAction::Rekeyed {
            direction: RekeyDirection::Outgoing,
        });
    }
    actions.push(V2SessionAction::WriteBytes(encode_frame(
        &outcome.ciphertext,
    )?));
    Ok(actions)
}

// ---------------------------------------------------------------------------
// 6. Hybrid Argon2id PAKE + ML-KEM-768 Pairing (`intent = 0x02, flags = 0x01`)
// ---------------------------------------------------------------------------

/// Tunable `Argon2id` parameters for v2 PAKE pairing.
///
/// Production builds enforce `memory_kib >= 19456`, `time_cost >= 2`, `parallelism >= 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PakeArgon2Params {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for PakeArgon2Params {
    fn default() -> Self {
        Self::production()
    }
}

impl PakeArgon2Params {
    /// Hardened production parameters (`m = 19456 KiB`, `t = 2`, `p = 1`).
    #[must_use]
    pub const fn production() -> Self {
        Self {
            memory_kib: PAKE_ARGON2_MEMORY_KIB,
            time_cost: PAKE_ARGON2_TIME,
            parallelism: PAKE_ARGON2_PARALLELISM,
        }
    }

    /// Lightweight parameters strictly for fast unit and integration tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn for_testing_only() -> Self {
        Self {
            memory_kib: 256,
            time_cost: 1,
            parallelism: 1,
        }
    }
}

/// Zeroizing symmetric PAKE subkeys derived from `(pairing_code, channel_salt)` via Argon2id + HKDF.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PakeKeys {
    pub pake_prologue_key: [u8; 32],
    pub pake_init_key: [u8; 32],
    pub pake_hello_key: [u8; 32],
    pub pake_confirm_key: [u8; 32],
    pub pake_context_tag: [u8; 32],
}

impl fmt::Debug for PakeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PakeKeys")
            .field("keys", &"<redacted>")
            .finish()
    }
}

fn validate_pake_params(params: PakeArgon2Params) -> Result<(), CoreError> {
    #[cfg(not(any(test, feature = "test-utils")))]
    if params.memory_kib < PAKE_ARGON2_MEMORY_KIB
        || params.time_cost < PAKE_ARGON2_TIME
        || params.parallelism < PAKE_ARGON2_PARALLELISM
    {
        return Err(CoreError::Argon2(
            "PAKE Argon2id parameters below production minimum".to_string(),
        ));
    }
    Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        Some(ARGON2_KEY_LEN),
    )
    .map_err(|err| CoreError::Argon2(err.to_string()))?;
    Ok(())
}

/// Derives PAKE subkeys from normalized `code` and 16-byte `channel_salt`.
///
/// In production builds (without `test-utils`), rejects `params` below `PAKE_ARGON2_MEMORY_KIB`,
/// `PAKE_ARGON2_TIME`, and `PAKE_ARGON2_PARALLELISM`.
pub fn derive_pake_keys(
    code: &str,
    channel_salt: &[u8; V2_PAKE_SALT_LEN],
    params: PakeArgon2Params,
) -> Result<PakeKeys, CoreError> {
    validate_pake_params(params)?;
    let normalized = Zeroizing::new(normalize_code(code));
    derive_pake_keys_from_bytes(normalized.as_bytes(), channel_salt, params)
}

fn derive_pake_keys_from_bytes(
    password_bytes: &[u8],
    channel_salt: &[u8; V2_PAKE_SALT_LEN],
    params: PakeArgon2Params,
) -> Result<PakeKeys, CoreError> {
    let argon_params = Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        Some(ARGON2_KEY_LEN),
    )
    .map_err(|err| CoreError::Argon2(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut master = Zeroizing::new([0u8; ARGON2_KEY_LEN]);
    argon2
        .hash_password_into(password_bytes, channel_salt, &mut *master)
        .map_err(|err| CoreError::Argon2(err.to_string()))?;

    let pake_prologue_key = hkdf_sha256_32(&*master, channel_salt, PAKE_PROLOGUE_INFO);
    let pake_init_key = hkdf_sha256_32(&*master, channel_salt, PAKE_INIT_KEY_INFO);
    let pake_hello_key = hkdf_sha256_32(&*master, channel_salt, PAKE_HELLO_INFO);
    let pake_confirm_key = hkdf_sha256_32(&*master, channel_salt, PAKE_CONFIRM_INFO);
    let pake_context_tag = hkdf_sha256_32(&*pake_prologue_key, channel_salt, PAKE_CONTEXT_INFO);

    Ok(PakeKeys {
        pake_prologue_key: *pake_prologue_key,
        pake_init_key: *pake_init_key,
        pake_hello_key: *pake_hello_key,
        pake_confirm_key: *pake_confirm_key,
        pake_context_tag: *pake_context_tag,
    })
}

fn pake_noise_prologue(pake_context_tag: &[u8; 32]) -> [u8; PREAMBLE_LEN + 32] {
    let pre = Preamble::v2_pake_pair().encode();
    let mut out = [0u8; PREAMBLE_LEN + 32];
    out[..PREAMBLE_LEN].copy_from_slice(&pre);
    out[PREAMBLE_LEN..].copy_from_slice(pake_context_tag);
    out
}

fn compute_pake_msg1_mac(
    pake_init_key: &[u8; 32],
    preamble: &[u8; PREAMBLE_LEN],
    e_i_pub: &[u8; 32],
    ek_hash: &[u8; 32],
    channel_salt: &[u8; V2_PAKE_SALT_LEN],
) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(pake_init_key).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(PAKE_MSG1_MAC_DOMAIN);
    mac.update(preamble);
    mac.update(e_i_pub);
    mac.update(ek_hash);
    mac.update(channel_salt);
    mac.finalize().into_bytes().into()
}

fn compute_pake_resp_mac(
    pake_confirm_key: &[u8; 32],
    h_pre: &[u8; 32],
    sealed_hello: &[u8],
) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(pake_confirm_key).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(PAKE_RESP_MAC_DOMAIN);
    mac.update(h_pre);
    mac.update(sealed_hello);
    mac.finalize().into_bytes().into()
}

fn compute_pake_init_mac(
    pake_confirm_key: &[u8; 32],
    post_msg2_hash: &[u8; 32],
    claim_json: &[u8],
) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(pake_confirm_key).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(PAKE_INIT_MAC_DOMAIN);
    mac.update(post_msg2_hash);
    mac.update(claim_json);
    mac.finalize().into_bytes().into()
}

fn seal_pake_host_hello(
    pake_hello_key: &[u8; 32],
    h_pre: &[u8; 32],
    hello_json: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = ChaCha20Poly1305::new_from_slice(pake_hello_key)
        .map_err(|err| CoreError::Noise(format!("pake hello init: {err}")))?;
    let mut buf = Vec::with_capacity(hello_json.len() + AEAD_TAG_LEN);
    buf.extend_from_slice(hello_json);
    cipher
        .encrypt_in_place(Nonce::from_slice(&[0u8; 12]), h_pre, &mut buf)
        .map_err(|_| CoreError::PairingAuthFailed)?;
    Ok(buf)
}

fn unseal_pake_host_hello(
    pake_hello_key: &[u8; 32],
    h_pre: &[u8; 32],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let cipher = ChaCha20Poly1305::new_from_slice(pake_hello_key)
        .map_err(|err| CoreError::Noise(format!("pake hello unseal init: {err}")))?;
    let mut buf = Zeroizing::new(sealed.to_vec());
    cipher
        .decrypt_in_place(Nonce::from_slice(&[0u8; 12]), h_pre, &mut *buf)
        .map_err(|_| CoreError::PairingAuthFailed)?;
    Ok(buf)
}

fn pake_msg2_bucket_for_hello_len(hello_json_len: usize) -> Result<usize, CoreError> {
    // 2 B sealed_len + hello_json_len + 16 B tag + 32 B resp_mac
    select_handshake_bucket(2 + hello_json_len + AEAD_TAG_LEN + 32)
}

/// Actions emitted by [`V2PakePairInitiator`] and [`V2PakePairResponder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2PairAction {
    WriteBytes(Vec<u8>),
    SasReady {
        pairing_sas: String,
        host_id: String,
        host_static_pub: [u8; 32],
    },
    Completed(V2PairOutcome),
    CloseTransport(String),
}

/// Terminal outcome emitted on completion of a v2 PAKE pairing handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2PairOutcome {
    InitiatorPending {
        device_id: String,
        host_id: String,
        host_static_pub: [u8; 32],
        host_signing_pub: HybridSigningPublicKey,
        host_rotation_seq: u64,
        pairing_sas: String,
        host_pin_verified: bool,
        v2_secrets: V2PeerSecrets,
    },
    ResponderPending {
        device_id: String,
        device_static_pub: [u8; 32],
        device_fingerprint: String,
        pairing_sas: String,
        name: String,
        kind: String,
        v2_secrets: V2PeerSecrets,
    },
    Rejected {
        error: String,
    },
}

enum PakeInitPhase {
    Init,
    AwaitMsg2 {
        hs: Box<NoiseHfsHandshake>,
        keys: PakeKeys,
    },
    AwaitResponse {
        transport: Box<NoiseTransport>,
        host_id: String,
        host_static_pub: [u8; 32],
        verified_host_signing_pub: HybridSigningPublicKey,
        verified_seq: Option<u64>,
        presented_rotation: Vec<RotationRecord>,
        pairing_sas: String,
        host_pin_verified: bool,
    },
    Closed,
}

/// Wire v2 (`0x02`, `flags = 0x01`) hybrid PAKE + `ML-KEM-768` pairing initiator.
pub struct V2PakePairInitiator {
    phase: PakeInitPhase,
    reader: ResumableFrameReader,
    local_static_priv: Zeroizing<[u8; 32]>,
    local_static_pub: [u8; 32],
    device_name: String,
    device_kind: String,
    code: Zeroizing<String>,
    pinned_host: Option<V2PinnedHost>,
    params: PakeArgon2Params,
    #[cfg(any(test, feature = "test-utils"))]
    fixed_ephemeral: Option<[u8; 32]>,
    #[cfg(any(test, feature = "test-utils"))]
    fixed_salt: Option<[u8; V2_PAKE_SALT_LEN]>,
}

impl fmt::Debug for V2PakePairInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2PakePairInitiator")
            .field("device_id", &device_id(&self.local_static_pub))
            .field("credentials", &"<redacted>")
            .finish()
    }
}

impl V2PakePairInitiator {
    /// Creates a new v2 PAKE pairing initiator.
    pub fn new(
        identity: &EndpointIdentity,
        device_name: impl Into<String>,
        device_kind: impl Into<String>,
        code: impl Into<String>,
        pinned_host: Option<V2PinnedHost>,
        params: PakeArgon2Params,
    ) -> Result<Self, CoreError> {
        let device_name = device_name.into();
        let device_kind = device_kind.into();
        if device_name.is_empty()
            || device_kind.is_empty()
            || has_control_chars(&device_name)
            || has_control_chars(&device_kind)
        {
            return Err(CoreError::ProtocolViolation(
                "invalid device metadata in v2 PAKE initiator",
            ));
        }
        validate_pake_params(params)?;
        if let Some(ref pin) = pinned_host {
            pin.enforce_version(WIRE_VERSION_V2)?;
            if !is_valid_x25519_public_key(&pin.pinned.static_pub) {
                return Err(CoreError::IncompletePin(
                    pin.pinned
                        .host_id
                        .clone()
                        .unwrap_or_else(|| "pinned_host".to_string()),
                ));
            }
        }
        Ok(Self {
            phase: PakeInitPhase::Init,
            reader: ResumableFrameReader::new(),
            local_static_priv: Zeroizing::new(*identity.static_key().secret_bytes()),
            local_static_pub: *identity.static_key().public_bytes(),
            device_name,
            device_kind,
            code: Zeroizing::new(code.into()),
            pinned_host,
            params,
            #[cfg(any(test, feature = "test-utils"))]
            fixed_ephemeral: None,
            #[cfg(any(test, feature = "test-utils"))]
            fixed_salt: None,
        })
    }

    /// Overrides the random 16-byte `channel_salt` strictly in tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_channel_salt_for_testing_only(mut self, salt: [u8; V2_PAKE_SALT_LEN]) -> Self {
        self.fixed_salt = Some(salt);
        self
    }

    /// Overrides ephemeral Noise randomness strictly in tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_fixed_ephemeral_for_testing_only(mut self, eph_seed: [u8; 32]) -> Self {
        self.fixed_ephemeral = Some(eph_seed);
        self
    }

    /// Emits the v2 PAKE preamble (`TND\x02\x02\x01`) + `msg1` carrying `channel_salt || init_mac`.
    pub fn start(&mut self) -> Result<Vec<V2PairAction>, CoreError> {
        let prev = std::mem::replace(&mut self.phase, PakeInitPhase::Closed);
        if !matches!(prev, PakeInitPhase::Init) {
            return Err(CoreError::NotReady("v2 PAKE initiator already started"));
        }
        #[cfg(any(test, feature = "test-utils"))]
        let salt = match self.fixed_salt {
            Some(s) => s,
            None => random_bytes::<V2_PAKE_SALT_LEN>()?,
        };
        #[cfg(not(any(test, feature = "test-utils")))]
        let salt = random_bytes::<V2_PAKE_SALT_LEN>()?;

        let keys = derive_pake_keys(&self.code, &salt, self.params)?;
        let prologue = pake_noise_prologue(&keys.pake_context_tag);
        let builder = NoiseHfsHandshakeBuilder::new()
            .local_private_key(&self.local_static_priv)
            .prologue(&prologue);
        #[cfg(any(test, feature = "test-utils"))]
        let builder = match self.fixed_ephemeral {
            Some(eph) => builder.fixed_ephemeral_for_testing_only(eph),
            None => builder,
        };
        let mut hs = builder.build_initiator()?;
        let pre = Preamble::v2_pake_pair().encode();
        let init_key = keys.pake_init_key;
        let msg1 = hs.write_msg1_with_payload(|e_i_pub, ek_bytes| {
            let ek_hash: [u8; 32] = Sha256::digest(ek_bytes).into();
            let init_mac = compute_pake_msg1_mac(&init_key, &pre, e_i_pub, &ek_hash, &salt);
            let mut out = Vec::with_capacity(V2_PAKE_MSG1_PAYLOAD_LEN);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&init_mac);
            Ok(out)
        })?;
        let frame = encode_frame(&msg1)?;
        let mut wire = Vec::with_capacity(pre.len() + frame.len());
        wire.extend_from_slice(&pre);
        wire.extend_from_slice(&frame);
        self.phase = PakeInitPhase::AwaitMsg2 {
            hs: Box::new(hs),
            keys,
        };
        Ok(vec![V2PairAction::WriteBytes(wire)])
    }

    /// Feeds inbound transport bytes into the v2 PAKE initiator state machine.
    pub fn feed_bytes(&mut self, chunk: &[u8]) -> Result<Vec<V2PairAction>, CoreError> {
        if matches!(self.phase, PakeInitPhase::Closed) {
            return Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "v2 PAKE pairing session closed".to_string(),
            });
        }
        if let Err(err) = self.reader.push(chunk) {
            self.phase = PakeInitPhase::Closed;
            return Err(err);
        }
        let mut actions = Vec::new();
        loop {
            let body = match self.reader.next_frame() {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = PakeInitPhase::Closed;
                    return Err(err);
                }
            };
            if let Err(err) = self.handle_frame(&body, &mut actions) {
                self.phase = PakeInitPhase::Closed;
                return Err(err);
            }
            if matches!(self.phase, PakeInitPhase::Closed) {
                return Ok(actions);
            }
        }
    }

    fn handle_frame(
        &mut self,
        body: &[u8],
        actions: &mut Vec<V2PairAction>,
    ) -> Result<(), CoreError> {
        let phase = std::mem::replace(&mut self.phase, PakeInitPhase::Closed);
        match phase {
            PakeInitPhase::AwaitMsg2 { mut hs, keys } => {
                let (payload, h_pre) = hs
                    .read_msg2_with_pre_payload_hash(body)
                    .map_err(|_| CoreError::PairingAuthFailed)?;
                if payload.len() < 2 + AEAD_TAG_LEN + 32 {
                    return Err(CoreError::PairingAuthFailed);
                }
                let sealed_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
                if payload.len() < 2 + sealed_len + 32 {
                    return Err(CoreError::PairingAuthFailed);
                }
                let sealed_hello = &payload[2..2 + sealed_len];
                let resp_mac: [u8; 32] = payload[2 + sealed_len..2 + sealed_len + 32]
                    .try_into()
                    .map_err(|_| CoreError::PairingAuthFailed)?;
                let mut nonzero = 0u8;
                for &b in &payload[2 + sealed_len + 32..] {
                    nonzero |= b;
                }
                if !bool::from(nonzero.ct_eq(&0u8)) {
                    return Err(CoreError::PairingAuthFailed);
                }
                let expected_mac =
                    compute_pake_resp_mac(&keys.pake_confirm_key, &h_pre, sealed_hello);
                if !bool::from(expected_mac.ct_eq(&resp_mac)) {
                    return Err(CoreError::PairingAuthFailed);
                }

                let hello_json =
                    unseal_pake_host_hello(&keys.pake_hello_key, &h_pre, sealed_hello)?;
                let host_hello: HostHello = serde_json::from_slice(&hello_json)
                    .map_err(|err| CoreError::Json(err.to_string()))?;
                if host_hello.proto_version != WIRE_VERSION_V2 {
                    return Err(CoreError::UnsupportedVersion(host_hello.proto_version));
                }
                if host_hello.host_id.is_empty() || has_control_chars(&host_hello.host_id) {
                    return Err(CoreError::ProtocolViolation("invalid host_id in HostHello"));
                }
                let host_signing_pub = HybridSigningPublicKey::from_b64url(&host_hello.signing_pub)
                    .map_err(|_| {
                        CoreError::ProtocolViolation("invalid signing_pub in HostHello")
                    })?;
                let remote_static: [u8; 32] = *hs.get_remote_static().ok_or(
                    CoreError::ProtocolViolation("missing responder static key in msg2"),
                )?;
                if !is_valid_x25519_public_key(&remote_static) {
                    return Err(CoreError::HostKeyUnverified);
                }

                let mut verified_seq = None;
                if let Some(ref v2_pin) = self.pinned_host {
                    let pin = &v2_pin.pinned;
                    if let Some(ref exp_id) = pin.host_id
                        && exp_id != &host_hello.host_id
                    {
                        return Err(CoreError::HostKeyUnverified);
                    }
                    let verify_res = if pin.rotation_seq == 0
                        && !host_hello.rotation.is_empty()
                        && host_hello.rotation[0].seq == 1
                        && remote_static == pin.static_pub
                        && pin.signing_pin.matches(&host_signing_pub)
                    {
                        let last_seq = host_hello.rotation.last().map_or(0, |r| r.seq);
                        verify_rotation_chain_pin(
                            &pin.signing_pin,
                            &pin.static_pub,
                            last_seq,
                            &host_hello.rotation,
                            &remote_static,
                            &host_signing_pub,
                        )
                    } else {
                        verify_rotation_chain_pin(
                            &pin.signing_pin,
                            &pin.static_pub,
                            pin.rotation_seq,
                            &host_hello.rotation,
                            &remote_static,
                            &host_signing_pub,
                        )
                    };
                    match verify_res {
                        Ok(seq) => verified_seq = Some(seq),
                        Err(err @ CoreError::RotationForkDetected { .. }) => return Err(err),
                        Err(_) => return Err(CoreError::HostKeyUnverified),
                    }
                }

                let h_post = *hs.get_handshake_hash();
                let sas = pairing_sas(&h_post);
                actions.push(V2PairAction::SasReady {
                    pairing_sas: sas.clone(),
                    host_id: host_hello.host_id.clone(),
                    host_static_pub: remote_static,
                });

                let claim = PairClaim {
                    name: self.device_name.clone(),
                    kind: self.device_kind.clone(),
                    code_mac: None,
                    enrollment_token: None,
                    signing_pub: None,
                    enroll_proof: None,
                };
                let claim_json = Zeroizing::new(
                    serde_json::to_vec(&claim).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let init_mac = compute_pake_init_mac(&keys.pake_confirm_key, &h_post, &claim_json);
                let mut msg3_pt = Zeroizing::new(Vec::with_capacity(32 + claim_json.len()));
                msg3_pt.extend_from_slice(&init_mac);
                msg3_pt.extend_from_slice(&claim_json);

                let msg3 = hs.write_message_vec(&msg3_pt)?;
                actions.push(V2PairAction::WriteBytes(encode_frame(&msg3)?));

                let transport = hs.into_transport_mode()?;
                self.phase = PakeInitPhase::AwaitResponse {
                    transport: Box::new(transport),
                    host_id: host_hello.host_id,
                    host_static_pub: remote_static,
                    verified_host_signing_pub: host_signing_pub,
                    verified_seq,
                    presented_rotation: host_hello.rotation,
                    pairing_sas: sas,
                    host_pin_verified: self.pinned_host.is_some(),
                };
                Ok(())
            }
            PakeInitPhase::AwaitResponse {
                mut transport,
                host_id,
                host_static_pub,
                verified_host_signing_pub,
                verified_seq,
                presented_rotation,
                pairing_sas,
                host_pin_verified,
            } => {
                let pt = transport.read_message_vec(body)?;
                let resp: PairResponse =
                    serde_json::from_slice(&pt).map_err(|err| CoreError::Json(err.to_string()))?;
                match resp {
                    PairResponse::Success {
                        device_id: resp_dev_id,
                        status,
                        host_signing_pub,
                    } => {
                        if resp_dev_id != device_id(&self.local_static_pub) || status != "pending" {
                            return Err(CoreError::ProtocolViolation(
                                "unexpected v2 pair response fields",
                            ));
                        }
                        let host_signing =
                            HybridSigningPublicKey::from_b64url(&host_signing_pub)
                                .map_err(|_| CoreError::IncompletePin(host_id.clone()))?;
                        if host_signing != verified_host_signing_pub {
                            return Err(CoreError::HostKeyUnverified);
                        }
                        let host_rotation_seq = if let Some(seq) = verified_seq {
                            seq
                        } else if let Some(first) = presented_rotation.first() {
                            let root_sig =
                                HybridSigningPublicKey::from_b64url(&first.prev_signing_pub)
                                    .map_err(|_| CoreError::HostKeyUnverified)?;
                            verify_rotation_chain_pin(
                                &SigningKeyPin::Full(root_sig),
                                &host_static_pub,
                                first.seq.saturating_sub(1),
                                &presented_rotation,
                                &host_static_pub,
                                &host_signing,
                            )
                            .map_err(|_| CoreError::HostKeyUnverified)?
                        } else {
                            0
                        };
                        let (reconnect_secret, mailbox_secret) =
                            transport.export_v2_secrets(&host_static_pub);
                        actions.push(V2PairAction::Completed(V2PairOutcome::InitiatorPending {
                            device_id: resp_dev_id,
                            host_id,
                            host_static_pub,
                            host_signing_pub: host_signing,
                            host_rotation_seq,
                            pairing_sas,
                            host_pin_verified,
                            v2_secrets: V2PeerSecrets::new(*reconnect_secret, *mailbox_secret),
                        }));
                        actions.push(V2PairAction::CloseTransport(
                            "v2 pairing complete".to_string(),
                        ));
                        self.phase = PakeInitPhase::Closed;
                        Ok(())
                    }
                    PairResponse::Error { error } => {
                        actions.push(V2PairAction::Completed(V2PairOutcome::Rejected {
                            error: error.clone(),
                        }));
                        actions.push(V2PairAction::CloseTransport(error));
                        self.phase = PakeInitPhase::Closed;
                        Ok(())
                    }
                }
            }
            PakeInitPhase::Init => Err(CoreError::NotReady("v2 PAKE initiator not started")),
            PakeInitPhase::Closed => Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "v2 PAKE pairing session closed".to_string(),
            }),
        }
    }
}

struct PakeAuthenticatedMsg1 {
    keys: PakeKeys,
    post_msg2_hash: [u8; 32],
    code: Zeroizing<String>,
}

enum PakeRespPhase {
    AwaitPreamble,
    AwaitMsg1,
    AwaitMsg3 {
        hs: Box<NoiseHfsHandshake>,
        authenticated: Option<Box<PakeAuthenticatedMsg1>>,
    },
    Closed,
}

/// Wire v2 (`0x02`, `flags = 0x01`) hybrid PAKE + `ML-KEM-768` pairing responder.
///
/// Unauthenticated or no-live-code `msg1` probes execute a CSPRNG-seeded Argon2id pass, use a
/// fresh ephemeral static keypair, emit an indistinguishable CSPRNG decoy `msg2`, and never
/// charge or leak live pairing codes.
pub struct V2PakePairResponder {
    phase: PakeRespPhase,
    reader: ResumableFrameReader,
    local_static_priv: Zeroizing<[u8; 32]>,
    local_static_pub: [u8; 32],
    host_hello: HostHello,
    host_signing_pub: HybridSigningPublicKey,
    path: PairingPathKind,
    params: PakeArgon2Params,
    #[cfg(any(test, feature = "test-utils"))]
    fixed_ephemeral: Option<[u8; 32]>,
}

impl fmt::Debug for V2PakePairResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2PakePairResponder")
            .field("host_id", &self.host_hello.host_id)
            .field("path", &self.path)
            .finish()
    }
}

impl V2PakePairResponder {
    /// Creates a new v2 PAKE pairing responder bound to `identity` and `path`.
    ///
    /// Rejects sub-production Argon2id parameters unless built with `test-utils` or unit tests.
    pub fn new(
        identity: &EndpointIdentity,
        path: PairingPathKind,
        params: PakeArgon2Params,
    ) -> Result<Self, CoreError> {
        validate_pake_params(params)?;
        Ok(Self {
            phase: PakeRespPhase::AwaitPreamble,
            reader: ResumableFrameReader::with_preamble(),
            local_static_priv: Zeroizing::new(*identity.static_key().secret_bytes()),
            local_static_pub: *identity.static_key().public_bytes(),
            host_hello: HostHello {
                host_id: identity.host_id().to_string(),
                proto_version: WIRE_VERSION_V2,
                signing_pub: identity.signing_key().public_key().to_b64url(),
                rotation: identity.rotation_chain().to_vec(),
            },
            host_signing_pub: identity.signing_key().public_key().clone(),
            path,
            params,
            #[cfg(any(test, feature = "test-utils"))]
            fixed_ephemeral: None,
        })
    }

    /// Overrides ephemeral Noise randomness strictly in tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_fixed_ephemeral_for_testing_only(mut self, eph_seed: [u8; 32]) -> Self {
        self.fixed_ephemeral = Some(eph_seed);
        self
    }

    /// Consumes inbound transport bytes, verifying PAKE proof against `manager` and recording into `roster`.
    pub fn feed_bytes(
        &mut self,
        chunk: &[u8],
        now_unix: u64,
        manager: &mut PairingManager,
        roster: &mut Roster,
    ) -> Result<Vec<V2PairAction>, CoreError> {
        if matches!(self.phase, PakeRespPhase::Closed) {
            return Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "v2 PAKE pairing session closed".to_string(),
            });
        }
        if let Err(err) = self.reader.push(chunk) {
            self.phase = PakeRespPhase::Closed;
            return Err(err);
        }
        let mut actions = Vec::new();
        if matches!(self.phase, PakeRespPhase::AwaitPreamble) {
            match self.reader.take_preamble() {
                Ok(Some(preamble)) => {
                    if preamble.version != WIRE_VERSION_V2 {
                        self.phase = PakeRespPhase::Closed;
                        return Err(CoreError::UnsupportedVersion(preamble.version));
                    }
                    if preamble.intent != Intent::Pair || preamble.flags != FLAG_PAKE_PAIR {
                        self.phase = PakeRespPhase::Closed;
                        return Err(CoreError::ProtocolViolation(
                            "expected v2 PAKE pair preamble",
                        ));
                    }
                    self.phase = PakeRespPhase::AwaitMsg1;
                }
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = PakeRespPhase::Closed;
                    return Err(err);
                }
            }
        }

        loop {
            let body = match self.reader.next_frame() {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = PakeRespPhase::Closed;
                    return Err(err);
                }
            };
            if let Err(err) = self.handle_frame(&body, now_unix, manager, roster, &mut actions) {
                self.phase = PakeRespPhase::Closed;
                return Err(err);
            }
            if matches!(self.phase, PakeRespPhase::Closed) {
                return Ok(actions);
            }
        }
    }

    fn handle_frame(
        &mut self,
        body: &[u8],
        now_unix: u64,
        manager: &mut PairingManager,
        roster: &mut Roster,
        actions: &mut Vec<V2PairAction>,
    ) -> Result<(), CoreError> {
        let phase = std::mem::replace(&mut self.phase, PakeRespPhase::Closed);
        match phase {
            PakeRespPhase::AwaitMsg1 => {
                if body.len() != MSG1_LEN + V2_PAKE_MSG1_PAYLOAD_LEN {
                    return Err(CoreError::ProtocolViolation(
                        "v2 PAKE msg1 must carry 16-byte salt and 32-byte MAC",
                    ));
                }
                let mut e_i_pub = [0u8; 32];
                e_i_pub.copy_from_slice(&body[..32]);
                let ek_hash: [u8; 32] = Sha256::digest(&body[32..MSG1_LEN]).into();
                let salt: [u8; V2_PAKE_SALT_LEN] = body[MSG1_LEN..MSG1_LEN + V2_PAKE_SALT_LEN]
                    .try_into()
                    .map_err(|_| CoreError::ProtocolViolation("invalid PAKE salt length"))?;
                let candidate_mac: [u8; 32] = body
                    [MSG1_LEN + V2_PAKE_SALT_LEN..MSG1_LEN + V2_PAKE_MSG1_PAYLOAD_LEN]
                    .try_into()
                    .map_err(|_| CoreError::ProtocolViolation("invalid PAKE msg1 MAC length"))?;

                let pre = Preamble::v2_pake_pair().encode();
                let msg1_cache_ok = manager.can_accept_pake_msg1(&salt, &candidate_mac, now_unix);
                let live_codes = manager.live_codes(now_unix);
                let mut matched: Option<(PakeKeys, Zeroizing<String>)> = None;
                if live_codes.is_empty() {
                    let dummy_secret = Zeroizing::new(random_bytes::<32>()?);
                    let _ = derive_pake_keys_from_bytes(&*dummy_secret, &salt, self.params)?;
                } else {
                    for (code, _) in live_codes {
                        let candidate_keys = derive_pake_keys(&code, &salt, self.params)?;
                        let expected_mac = compute_pake_msg1_mac(
                            &candidate_keys.pake_init_key,
                            &pre,
                            &e_i_pub,
                            &ek_hash,
                            &salt,
                        );
                        if bool::from(expected_mac.ct_eq(&candidate_mac))
                            && msg1_cache_ok
                            && matched.is_none()
                        {
                            matched = Some((candidate_keys, code));
                        }
                    }
                }

                let authenticated_match = match matched {
                    Some((keys, code))
                        if manager.record_pake_msg1(salt, candidate_mac, now_unix) =>
                    {
                        Some((keys, code))
                    }
                    _ => None,
                };

                let hello_json = Zeroizing::new(
                    serde_json::to_vec(&self.host_hello)
                        .map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let msg2_bucket = pake_msg2_bucket_for_hello_len(hello_json.len())?;

                if let Some((keys, code)) = authenticated_match {
                    let prologue = pake_noise_prologue(&keys.pake_context_tag);
                    let builder = NoiseHfsHandshakeBuilder::new()
                        .local_private_key(&self.local_static_priv)
                        .prologue(&prologue);
                    #[cfg(any(test, feature = "test-utils"))]
                    let builder = match self.fixed_ephemeral {
                        Some(eph) => builder.fixed_ephemeral_for_testing_only(eph),
                        None => builder,
                    };
                    let mut hs = builder.build_responder()?;
                    hs.read_message_vec(body)?;

                    let pake_hello_key = Zeroizing::new(keys.pake_hello_key);
                    let pake_confirm_key = Zeroizing::new(keys.pake_confirm_key);
                    let msg2 = hs.write_msg2_with_hash(|h_pre| {
                        let sealed_hello =
                            seal_pake_host_hello(&pake_hello_key, h_pre, &hello_json)?;
                        let sealed_len = u16::try_from(sealed_hello.len()).map_err(|_| {
                            CoreError::FrameTooLarge {
                                len: sealed_hello.len(),
                                max: MAX_FRAME_LEN,
                            }
                        })?;
                        let resp_mac =
                            compute_pake_resp_mac(&pake_confirm_key, h_pre, &sealed_hello);
                        let mut out = vec![0u8; msg2_bucket];
                        out[..2].copy_from_slice(&sealed_len.to_be_bytes());
                        out[2..2 + sealed_hello.len()].copy_from_slice(&sealed_hello);
                        out[2 + sealed_hello.len()..2 + sealed_hello.len() + 32]
                            .copy_from_slice(&resp_mac);
                        Ok(out)
                    })?;
                    let post_msg2_hash = *hs.get_handshake_hash();
                    actions.push(V2PairAction::WriteBytes(encode_frame(&msg2)?));
                    self.phase = PakeRespPhase::AwaitMsg3 {
                        hs: Box::new(hs),
                        authenticated: Some(Box::new(PakeAuthenticatedMsg1 {
                            keys,
                            post_msg2_hash,
                            code,
                        })),
                    };
                } else {
                    let decoy_static = StaticKeypair::generate()?;
                    let decoy_tag = Zeroizing::new(random_bytes::<32>()?);
                    let prologue = pake_noise_prologue(&decoy_tag);
                    let builder = NoiseHfsHandshakeBuilder::new()
                        .local_private_key(decoy_static.secret_bytes())
                        .prologue(&prologue);
                    #[cfg(any(test, feature = "test-utils"))]
                    let builder = match self.fixed_ephemeral {
                        Some(eph) => builder.fixed_ephemeral_for_testing_only(eph),
                        None => builder,
                    };
                    let mut hs = builder.build_responder()?;
                    hs.read_message_vec(body)?;
                    let mut decoy_payload = vec![0u8; msg2_bucket];
                    getrandom::fill(&mut decoy_payload)
                        .map_err(|err| CoreError::Rng(err.to_string()))?;
                    let msg2 = hs.write_message_vec(&decoy_payload)?;
                    actions.push(V2PairAction::WriteBytes(encode_frame(&msg2)?));
                    self.phase = PakeRespPhase::AwaitMsg3 {
                        hs: Box::new(hs),
                        authenticated: None,
                    };
                }
                Ok(())
            }
            PakeRespPhase::AwaitMsg3 {
                mut hs,
                authenticated,
            } => {
                let Some(auth_box) = authenticated else {
                    // Unauthenticated probe: do NOT charge live pairing codes.
                    let _ = hs.read_message_vec(body);
                    return Err(CoreError::PairingAuthFailed);
                };
                let PakeAuthenticatedMsg1 {
                    keys,
                    post_msg2_hash,
                    code: code_str,
                } = *auth_box;
                // Do not burn/charge live pairing codes on msg3 failures: an attacker
                // cannot reach msg3 without a fresh valid msg1 (`can_accept_pake_msg1`),
                // and legitimate retries require a fresh msg1 salt.
                let pt = hs
                    .read_message_vec(body)
                    .map_err(|_| CoreError::PairingAuthFailed)?;
                if pt.len() < 32 {
                    return Err(CoreError::PairingAuthFailed);
                }
                let init_mac: [u8; 32] = pt[..32]
                    .try_into()
                    .map_err(|_| CoreError::PairingAuthFailed)?;
                let claim_json = &pt[32..];
                let expected_mac =
                    compute_pake_init_mac(&keys.pake_confirm_key, &post_msg2_hash, claim_json);
                if !bool::from(expected_mac.ct_eq(&init_mac)) {
                    return Err(CoreError::PairingAuthFailed);
                }

                let peer_static: [u8; 32] = *hs.get_remote_static().ok_or(
                    CoreError::ProtocolViolation("missing initiator static key in msg3"),
                )?;
                if !is_valid_x25519_public_key(&peer_static) {
                    return Err(CoreError::ProtocolViolation(
                        "invalid or low-order initiator static key",
                    ));
                }
                let mut transport = hs.into_transport_mode()?;

                let claim: PairClaim = match serde_json::from_slice(claim_json) {
                    Ok(c) => c,
                    Err(_) => {
                        return write_v2_pair_error(&mut transport, "protocol_error", actions);
                    }
                };
                if claim.name.is_empty()
                    || claim.kind.is_empty()
                    || claim.name.len() > 256
                    || claim.kind.len() > 64
                    || has_control_chars(&claim.name)
                    || has_control_chars(&claim.kind)
                {
                    return write_v2_pair_error(&mut transport, "protocol_error", actions);
                }

                if let Err(err) = manager.burn_pake_code(&code_str, self.path, now_unix) {
                    return write_v2_pair_error(&mut transport, err.pair_error_code(), actions);
                }

                let sas = pairing_sas(&post_msg2_hash);
                let (reconnect_secret, mailbox_secret) =
                    transport.export_v2_secrets(&self.local_static_pub);
                let v2_secrets = V2PeerSecrets::new(*reconnect_secret, *mailbox_secret);
                let peer_id = match apply_responder_v2_record(
                    roster,
                    peer_static,
                    &claim.name,
                    &claim.kind,
                    &sas,
                    &v2_secrets,
                ) {
                    Ok(id) => id,
                    Err(err) => {
                        return write_v2_pair_error(&mut transport, err.pair_error_code(), actions);
                    }
                };

                let resp = PairResponse::Success {
                    device_id: peer_id.clone(),
                    status: "pending".to_string(),
                    host_signing_pub: self.host_signing_pub.to_b64url(),
                };
                let json = Zeroizing::new(
                    serde_json::to_vec(&resp).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let ct = transport.write_message_vec(&json)?;
                actions.push(V2PairAction::WriteBytes(encode_frame(&ct)?));
                actions.push(V2PairAction::Completed(V2PairOutcome::ResponderPending {
                    device_id: peer_id,
                    device_static_pub: peer_static,
                    device_fingerprint: fingerprint_device(&peer_static),
                    pairing_sas: sas,
                    name: claim.name,
                    kind: claim.kind,
                    v2_secrets,
                }));
                actions.push(V2PairAction::CloseTransport(
                    "v2 pairing response sent".to_string(),
                ));
                Ok(())
            }
            PakeRespPhase::AwaitPreamble => {
                Err(CoreError::NotReady("v2 PAKE pairing preamble missing"))
            }
            PakeRespPhase::Closed => Err(CoreError::SessionClosed {
                code: SessionCloseCode::NORMAL,
                reason: "v2 PAKE pairing session closed".to_string(),
            }),
        }
    }
}

fn apply_responder_v2_record(
    roster: &mut Roster,
    peer_static: [u8; 32],
    name: &str,
    kind: &str,
    sas: &str,
    v2_secrets: &V2PeerSecrets,
) -> Result<String, CoreError> {
    let mut staged = roster.clone();
    let peer_id = staged
        .record_pending_pair(
            peer_static,
            None,
            name.to_string(),
            kind.to_string(),
            sas.to_string(),
        )?
        .device_id
        .clone();
    staged.upgrade_peer_to_v2(&peer_id, v2_secrets.clone())?;
    *roster = staged;
    Ok(peer_id)
}

fn write_v2_pair_error(
    transport: &mut NoiseTransport,
    code: &str,
    actions: &mut Vec<V2PairAction>,
) -> Result<(), CoreError> {
    let resp = PairResponse::Error {
        error: code.to_string(),
    };
    let json =
        Zeroizing::new(serde_json::to_vec(&resp).map_err(|err| CoreError::Json(err.to_string()))?);
    let ct = transport.write_message_vec(&json)?;
    actions.push(V2PairAction::WriteBytes(encode_frame(&ct)?));
    actions.push(V2PairAction::Completed(V2PairOutcome::Rejected {
        error: code.to_string(),
    }));
    actions.push(V2PairAction::CloseTransport(code.to_string()));
    Ok(())
}
