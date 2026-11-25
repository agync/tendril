//! Pairing code management, URI codec, and Sans-I/O pairing state machines.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{
    CODE_ALPHABET, HYBRID_SIGNING_HASH_LEN, HybridSigningPublicKey, SigningKeypair, b64url_decode,
    b64url_decode_array, b64url_encode, compute_code_mac, device_id, fingerprint_device,
    has_control_chars, is_valid_ed25519_public_key, is_valid_x25519_public_key, pairing_sas,
    random_bytes, verify_code_mac,
};
use crate::error::CoreError;
use crate::grants::{
    Capability, Grant, GrantUnsigned, MAX_CLOCK_SKEW_SECS, MAX_DELEGATION_DEPTH, parse_caps,
    sign_grant, sign_grant_deterministic, verify_enrollment_grant_chain,
};
use crate::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, format_rfc3339_utc, parse_rfc3339_utc,
    verify_rotation_chain_pin,
};
use crate::noise::{NoiseHfsHandshake, NoiseHfsHandshakeBuilder, NoiseTransport};
use crate::policy::{ProviderId, is_numeric_host_addr};
use crate::roster::{AnchorState, Roster};
use crate::routes::MAX_ROUTE_SEQ;
use crate::wire::{
    HostHello, Intent, PairClaim, PairResponse, Preamble, ResumableFrameReader, WIRE_VERSION,
    WIRE_VERSION_V2, encode_frame,
};

/// Default lifetime of a newly issued pairing code (`15` minutes).
pub const DEFAULT_PAIRING_TTL_SECS: u64 = 900;

/// Default maximum failed claim attempts across live pairing codes before burn.
pub const DEFAULT_MAX_PAIRING_ATTEMPTS: u32 = 5;

/// Default lifetime of an M2M enrollment token (`15` minutes).
pub const DEFAULT_ENROLLMENT_TTL_SECS: u64 = 900;

/// Hard upper bound on M2M enrollment token lifetime (`24` hours).
pub const MAX_ENROLLMENT_TTL_SECS: u64 = 86_400;

/// 18-byte domain prefix prepended to channel-binding M2M enrollment proofs.
pub const ENROLL_PROOF_DOMAIN: &[u8] = b"tendril-enroll-v1\0";

/// 20-byte domain prefix prepended to human pairing signing key proofs.
pub const PAIR_KEY_PROOF_DOMAIN: &[u8] = b"tendril-pair-key-v1\0";

/// Policy controlling autonomous Machine-to-Machine enrollment on a responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentPolicy {
    pub enabled: bool,
    pub allow_self_issued: bool,
    pub allow_wildcard_subject: bool,
    pub max_ttl_secs: u64,
}

impl Default for EnrollmentPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_self_issued: false,
            allow_wildcard_subject: false,
            max_ttl_secs: DEFAULT_ENROLLMENT_TTL_SECS,
        }
    }
}

impl EnrollmentPolicy {
    /// Returns the opt-in default M2M policy enabling self-issued and anchored tokens (`900 s` TTL).
    #[must_use]
    pub const fn enabled_default() -> Self {
        Self {
            enabled: true,
            allow_self_issued: true,
            allow_wildcard_subject: true,
            max_ttl_secs: DEFAULT_ENROLLMENT_TTL_SECS,
        }
    }
}

/// Pairing code entropy form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingCodeKind {
    /// Two 4-character groups (`TND-XXXX-XXXX`), for QR scan or verified LAN paths.
    Lan2Group,
    /// Three 4-character groups (`TND-XXXX-XXXX-XXXX`), safe for remote/relay manual entry.
    Remote3Group,
}

/// Transport context classification for a pairing claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingPathKind {
    Lan,
    Remote,
}

/// Policy configuration for [`PairingManager`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingConfig {
    pub ttl_secs: u64,
    pub max_failed_attempts: u32,
    pub allow_lan_code_over_remote: bool,
}

impl Default for PairingConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_PAIRING_TTL_SECS,
            max_failed_attempts: DEFAULT_MAX_PAIRING_ATTEMPTS,
            allow_lan_code_over_remote: false,
        }
    }
}

struct IssuedCode {
    code: Zeroizing<String>,
    kind: PairingCodeKind,
    expires_at: u64,
    failed_attempts: u32,
    burned: bool,
    expired: bool,
}

impl fmt::Debug for IssuedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCode")
            .field("kind", &self.kind)
            .field("expires_at", &self.expires_at)
            .field("failed_attempts", &self.failed_attempts)
            .field("burned", &self.burned)
            .field("expired", &self.expired)
            .field("code", &"<redacted>")
            .finish()
    }
}

/// Maximum number of concurrently live (unexpired, unburned) pairing codes per manager.
pub const MAX_LIVE_PAIRING_CODES: usize = 4;

/// Maximum bounded replay cache entries for v2 PAKE `msg1` `(salt, init_mac)` pairs.
pub const MAX_PAKE_MSG1_REPLAY_ENTRIES: usize = 1024;

/// Tracks issued pairing codes, TTL expiration, single-use burn, and constant-time retry budgets.
#[derive(Debug, Default)]
pub struct PairingManager {
    config: PairingConfig,
    codes: Vec<IssuedCode>,
    seen_pake_msg1: BTreeSet<([u8; 16], [u8; 32])>,
    seen_pake_msg1_order: VecDeque<(u64, [u8; 16], [u8; 32])>,
}

impl PairingManager {
    /// Creates a new pairing code manager with the supplied policy.
    #[must_use]
    pub fn new(config: PairingConfig) -> Self {
        Self {
            config,
            codes: Vec::new(),
            seen_pake_msg1: BTreeSet::new(),
            seen_pake_msg1_order: VecDeque::new(),
        }
    }

    /// Returns the number of currently unburned, unexpired codes.
    #[must_use]
    pub fn live_code_count(&self, now_unix: u64) -> usize {
        self.codes
            .iter()
            .filter(|c| !c.burned && !c.expired && now_unix < c.expires_at)
            .count()
    }

    /// Generates and stores a new random pairing code using the platform CSPRNG.
    pub fn issue_code(
        &mut self,
        kind: PairingCodeKind,
        now_unix: u64,
    ) -> Result<String, CoreError> {
        let mut entropy = Zeroizing::new(Vec::with_capacity(64));
        while entropy.len() < 64 {
            entropy.extend_from_slice(&random_bytes::<32>()?);
        }
        for _ in 0..8 {
            match self.issue_code_with_entropy(kind, now_unix, &entropy) {
                Ok(code) => return Ok(code),
                Err(CoreError::Rng(_)) => {
                    entropy.extend_from_slice(&random_bytes::<32>()?);
                }
                Err(err) => return Err(err),
            }
        }
        Err(CoreError::Rng(
            "failed to sample unbiased pairing code".to_string(),
        ))
    }

    /// Deterministically issues a pairing code by rejection-sampling `entropy` (`byte < 248`).
    pub fn issue_code_with_entropy(
        &mut self,
        kind: PairingCodeKind,
        now_unix: u64,
        entropy: &[u8],
    ) -> Result<String, CoreError> {
        let total_chars = match kind {
            PairingCodeKind::Lan2Group => 8,
            PairingCodeKind::Remote3Group => 12,
        };
        let mut picked = Zeroizing::new(Vec::with_capacity(total_chars));
        for &b in entropy {
            // 248 = 8 * 31 avoids modulo bias across the 31-character alphabet.
            if b < 248 {
                picked.push(CODE_ALPHABET[(b % 31) as usize]);
                if picked.len() == total_chars {
                    break;
                }
            }
        }
        if picked.len() < total_chars {
            return Err(CoreError::Rng(
                "insufficient unbiased entropy for pairing code".to_string(),
            ));
        }

        let mut code = String::from("TND");
        for chunk in picked.chunks_exact(4) {
            code.push('-');
            for &ch in chunk {
                code.push(ch as char);
            }
        }

        for c in &mut self.codes {
            if !c.burned && now_unix >= c.expires_at {
                c.expired = true;
            }
        }
        let live_count = self
            .codes
            .iter()
            .filter(|c| !c.burned && !c.expired)
            .count();
        if live_count >= MAX_LIVE_PAIRING_CODES {
            return Err(CoreError::ProtocolViolation("too many live pairing codes"));
        }
        if self.codes.len() >= 64 {
            let mut live = Vec::new();
            let mut dead = Vec::new();
            for c in self.codes.drain(..) {
                if !c.burned && !c.expired {
                    live.push(c);
                } else {
                    dead.push(c);
                }
            }
            let keep_dead_from = dead.len().saturating_sub(8);
            self.codes.extend(dead.into_iter().skip(keep_dead_from));
            self.codes.extend(live);
        }

        let expires_at = now_unix.saturating_add(self.config.ttl_secs);
        self.codes.push(IssuedCode {
            code: Zeroizing::new(code.clone()),
            kind,
            expires_at,
            failed_attempts: 0,
            burned: false,
            expired: false,
        });
        Ok(code)
    }

    /// Verifies a `PairClaim.code_mac` against all live codes in constant time.
    ///
    /// Burns a matched code immediately (single-use) and increments failure counters on every
    /// live code on mismatch, burning codes that hit `max_failed_attempts`.
    pub fn verify_claim(
        &mut self,
        handshake_hash: &[u8; 32],
        candidate_mac: &[u8; 32],
        path: PairingPathKind,
        now_unix: u64,
    ) -> Result<(), CoreError> {
        for c in &mut self.codes {
            if !c.burned && now_unix >= c.expires_at {
                c.expired = true;
            }
        }

        let live_indices: Vec<usize> = self
            .codes
            .iter()
            .enumerate()
            .filter_map(|(i, c)| (!c.burned && !c.expired).then_some(i))
            .collect();

        if live_indices.is_empty() {
            let _ = verify_code_mac("TND-AAAA-AAAA-AAAA", handshake_hash, candidate_mac);
            return Err(CoreError::PairingCodeInvalid);
        }

        let mut matched_idx: Option<usize> = None;
        for &idx in &live_indices {
            if verify_code_mac(&self.codes[idx].code, handshake_hash, candidate_mac)?
                && matched_idx.is_none()
            {
                matched_idx = Some(idx);
            }
        }

        if let Some(idx) = matched_idx {
            let allows = self.allows_code_on_path(self.codes[idx].kind, path);
            self.codes[idx].burned = true;
            if !allows {
                return Err(CoreError::PairingPathDisallowed(
                    "2-group code disallowed on remote path",
                ));
            }
            return Ok(());
        }

        for &idx in &live_indices {
            let entry = &mut self.codes[idx];
            entry.failed_attempts = entry.failed_attempts.saturating_add(1);
            if entry.failed_attempts >= self.config.max_failed_attempts {
                entry.burned = true;
            }
        }

        Err(CoreError::PairingCodeInvalid)
    }

    /// Returns `true` when a code of `kind` may be used on `path` under this manager's policy.
    ///
    /// A [`PairingCodeKind::Lan2Group`] code is refused on [`PairingPathKind::Remote`] unless
    /// `allow_lan_code_over_remote` is set.
    #[must_use]
    pub fn allows_code_on_path(&self, kind: PairingCodeKind, path: PairingPathKind) -> bool {
        !(kind == PairingCodeKind::Lan2Group
            && path == PairingPathKind::Remote
            && !self.config.allow_lan_code_over_remote)
    }

    /// Returns clones of every live code usable on `path`, marking expired codes first.
    ///
    /// Codes disallowed on `path` are omitted so they can never match a PAKE `msg1` there.
    pub fn allowed_live_codes(
        &mut self,
        path: PairingPathKind,
        now_unix: u64,
    ) -> Vec<Zeroizing<String>> {
        for c in &mut self.codes {
            if !c.burned && now_unix >= c.expires_at {
                c.expired = true;
            }
        }
        self.codes
            .iter()
            .filter(|c| !c.burned && !c.expired && self.allows_code_on_path(c.kind, path))
            .map(|c| c.code.clone())
            .collect()
    }

    fn prune_expired_pake_msg1(&mut self, now_unix: u64) {
        while let Some(&(expires_at, salt, init_mac)) = self.seen_pake_msg1_order.front() {
            if expires_at <= now_unix {
                self.seen_pake_msg1_order.pop_front();
                self.seen_pake_msg1.remove(&(salt, init_mac));
            } else {
                break;
            }
        }
    }

    /// Returns `true` if `(salt, init_mac)` is unseen and the replay cache has capacity.
    pub fn is_pake_msg1_allowed(
        &mut self,
        salt: &[u8; 16],
        init_mac: &[u8; 32],
        now_unix: u64,
    ) -> bool {
        self.prune_expired_pake_msg1(now_unix);
        !self.seen_pake_msg1.contains(&(*salt, *init_mac))
            && self.seen_pake_msg1.len() < MAX_PAKE_MSG1_REPLAY_ENTRIES
    }

    /// Records `(salt, init_mac)` in the replay cache, returning `false` on replay or exhaustion.
    pub fn commit_pake_msg1(&mut self, salt: [u8; 16], init_mac: [u8; 32], now_unix: u64) -> bool {
        self.prune_expired_pake_msg1(now_unix);
        if self.seen_pake_msg1.contains(&(salt, init_mac))
            || self.seen_pake_msg1.len() >= MAX_PAKE_MSG1_REPLAY_ENTRIES
        {
            return false;
        }
        let expires_at = now_unix.saturating_add(self.config.ttl_secs.max(1));
        self.seen_pake_msg1.insert((salt, init_mac));
        self.seen_pake_msg1_order
            .push_back((expires_at, salt, init_mac));
        true
    }

    pub(crate) fn burn_pake_code(
        &mut self,
        code: &str,
        path: PairingPathKind,
        now_unix: u64,
    ) -> Result<(), CoreError> {
        for c in &mut self.codes {
            if !c.burned && now_unix >= c.expires_at {
                c.expired = true;
            }
        }
        let allow_lan_remote = self.config.allow_lan_code_over_remote;
        let Some(entry) = self
            .codes
            .iter_mut()
            .rev()
            .find(|c| !c.burned && !c.expired && c.code.as_str() == code)
        else {
            return Err(CoreError::PairingCodeInvalid);
        };
        entry.burned = true;
        if entry.kind == PairingCodeKind::Lan2Group
            && path == PairingPathKind::Remote
            && !allow_lan_remote
        {
            return Err(CoreError::PairingPathDisallowed(
                "2-group code disallowed on remote path",
            ));
        }
        Ok(())
    }
}

/// Maximum number of endpoint hints in any pairing URI.
pub const MAX_PAIRING_URI_ENDPOINTS: usize = 6;

/// Maximum byte length of one decoded pairing URI endpoint hint.
pub const MAX_PAIRING_ENDPOINT_HINT_LEN: usize = 256;

/// Maximum byte length of an encoded pairing URI (QR Version 26, ECC M, byte mode).
pub const MAX_PAIRING_URI_LEN: usize = 1_024;

/// Soft builder target for an encoded pairing URI (QR Version 21, ECC M, byte mode).
pub const PAIRING_URI_QR_SOFT_LEN: usize = 711;

/// Maximum hints per provider in an announced route set.
pub const MAX_ANNOUNCED_HINTS_PER_PROVIDER: usize = 2;

/// 26-byte domain prefix of the Ed25519 pairing URI route statement `rs`.
pub const PAIRING_ROUTES_DOMAIN: &[u8] = b"tendril-pairing-routes-v1\0";

const ROUTE_SIG_B64_LEN: usize = 86;
const RELAY_PUB_B64_LEN: usize = 43;
const RS_SUFFIX_LEN: usize = "&rs=".len() + ROUTE_SIG_B64_LEN;
const LAN2_PLACEHOLDER_CODE: &str = "TND-AAAA-AAAA";
const REMOTE3_PLACEHOLDER_CODE: &str = "TND-AAAA-AAAA-AAAA";

/// Byte-mode capacities of QR versions 1 to 40 at error correction level M.
const QR_BYTE_CAPACITY_M: [usize; 40] = [
    14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 251, 287, 331, 362, 412, 450, 504, 560, 624, 666,
    711, 779, 857, 911, 997, 1059, 1125, 1190, 1264, 1370, 1452, 1538, 1628, 1722, 1809, 1911,
    1989, 2099, 2213, 2331,
];

impl std::str::FromStr for PairingCodeKind {
    type Err = CoreError;

    /// Parses a code kind name: `lan` (two groups) or `remote` (three groups), any case. The
    /// error never echoes the input.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("lan") {
            Ok(Self::Lan2Group)
        } else if s.eq_ignore_ascii_case("remote") {
            Ok(Self::Remote3Group)
        } else {
            Err(CoreError::ProtocolViolation(
                "invalid pairing code kind (expected lan or remote)",
            ))
        }
    }
}

impl PairingCodeKind {
    /// Classifies an issued pairing code by its parsed group count.
    ///
    /// Accepts exactly `TND` followed by two (`Lan2Group`) or three (`Remote3Group`) groups of
    /// four `[A-Z0-9]` characters. Does not trim or change case.
    pub fn from_code(code: &str) -> Result<Self, CoreError> {
        let mut parts = code.split('-');
        if parts.next() != Some("TND") {
            return Err(CoreError::PairingCodeInvalid);
        }
        let groups: Vec<&str> = parts.collect();
        let well_formed = groups.iter().all(|g| {
            g.len() == 4
                && g.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        });
        match (groups.len(), well_formed) {
            (2, true) => Ok(Self::Lan2Group),
            (3, true) => Ok(Self::Remote3Group),
            _ => Err(CoreError::PairingCodeInvalid),
        }
    }
}

/// Classifies a valid endpoint hint by transport provider.
///
/// Fails with `InvalidPairingUri` for hints that do not pass the pairing hint grammar.
pub fn classify_endpoint_hint(ep: &str) -> Result<ProviderId, CoreError> {
    if !is_valid_pairing_endpoint_hint(ep) {
        return Err(CoreError::InvalidPairingUri("invalid endpoint hint".into()));
    }
    Ok(provider_of_valid_hint(ep))
}

pub(crate) fn provider_of_valid_hint(ep: &str) -> ProviderId {
    if is_ipc_hint(ep) {
        ProviderId::Local
    } else if ep.starts_with("direct:") {
        ProviderId::Direct
    } else if ep.starts_with("overlay://") {
        ProviderId::Overlay
    } else if ep.starts_with("iroh://") || ep.starts_with("p2p:iroh://") {
        ProviderId::P2p
    } else if ep.starts_with("broker+") {
        ProviderId::Broker
    } else if relay_url_path(ep).is_some() {
        ProviderId::Relay
    } else {
        ProviderId::Direct
    }
}

pub(crate) fn is_ipc_hint(ep: &str) -> bool {
    ep.starts_with("local:") || ep.starts_with("unix://")
}

/// Path of a relay hint (`relay:ws(s)://` or `ws(s)://`), without query or fragment.
///
/// The path is the WHATWG-normalized one a dialer sends (dot segments resolved, so
/// `/x/../v2/relay` is `/v2/relay`); a URL that does not parse keeps its raw path.
fn relay_url_path(ep: &str) -> Option<String> {
    let url = ep.strip_prefix("relay:").unwrap_or(ep);
    let rest = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))?;
    if let Ok(parsed) = url::Url::parse(url) {
        return Some(parsed.path().to_owned());
    }
    let path = rest.find(['/', '?', '#']).map_or("", |i| &rest[i..]);
    Some(path.split(['?', '#']).next().unwrap_or_default().to_owned())
}

/// Returns `true` for a `/v2/relay` mailbox relay hint, judged on the normalized path.
#[must_use]
pub fn is_v2_relay_hint(ep: &str) -> bool {
    relay_url_path(ep).as_deref() == Some("/v2/relay")
}

/// Returns `true` for a relay hint other than `/v2/relay`, which requires `rp` in a URI.
fn needs_relay_pub(ep: &str) -> bool {
    relay_url_path(ep).is_some_and(|p| p != "/v2/relay")
}

/// Host:port target of a `direct:` or bare hint.
fn direct_target(ep: &str) -> &str {
    ep.strip_prefix("direct:").unwrap_or(ep)
}

/// The IPv4 address an IPv6 form with a fixed IPv4 embedding names, as the runtime egress
/// classification reads it: IPv4-mapped `::ffff:0:0/96`, IPv4-translated `::ffff:0:0:0/96`,
/// IPv4-compatible `::/96` (except `::` and `::1`), NAT64 `64:ff9b::/96` and 6to4 `2002::/16`.
/// Every other address is returned unchanged.
fn unmapped(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };
    let s = v6.segments();
    let v4 = |hi: u16, lo: u16| {
        let [a, b] = hi.to_be_bytes();
        let [c, d] = lo.to_be_bytes();
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    };
    match s {
        [0, 0, 0, 0, 0, 0xffff, hi, lo]
        | [0, 0, 0, 0, 0xffff, 0, hi, lo]
        | [0x0064, 0xff9b, 0, 0, 0, 0, hi, lo] => v4(hi, lo),
        [0, 0, 0, 0, 0, 0, hi, lo] if hi != 0 || lo > 1 => v4(hi, lo),
        [0x2002, hi, lo, ..] => v4(hi, lo),
        _ => ip,
    }
}

fn is_lan_or_loopback_ip(ip: IpAddr) -> bool {
    match unmapped(ip) {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Returns `true` for a `direct:` IP literal in the Loopback or LAN class.
fn is_lan_direct_literal(ep: &str) -> bool {
    ep.strip_prefix("direct:")
        .and_then(|t| t.parse::<SocketAddr>().ok())
        .is_some_and(|s| is_lan_or_loopback_ip(s.ip()))
}

/// Hints a `Lan2Group` code may never be paired with: every hint but IPC and a `direct:` or bare
/// loopback or LAN IP literal.
fn is_remote_for_lan_code(ep: &str) -> bool {
    match provider_of_valid_hint(ep) {
        ProviderId::Local => false,
        ProviderId::Direct => !direct_target(ep)
            .parse::<SocketAddr>()
            .is_ok_and(|s| is_lan_or_loopback_ip(s.ip())),
        _ => true,
    }
}

/// Parses a decimal `rq` route sequence: no sign, no leading zero, `1..=2^53-1`.
fn parse_route_seq(raw: &str) -> Result<u64, CoreError> {
    let err = || CoreError::InvalidPairingUri("invalid rq parameter".into());
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) || raw.starts_with('0') {
        return Err(err());
    }
    let seq = raw.parse::<u64>().map_err(|_| err())?;
    if seq > MAX_ROUTE_SEQ {
        return Err(err());
    }
    Ok(seq)
}

fn is_b64url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

/// Splits a trailing `&rs=<86 b64url>` route statement off `uri`.
///
/// Returns the exact signed prefix and the decoded signature, or `uri` unchanged when no `rs`
/// parameter exists anywhere.
fn split_route_signature(uri: &str) -> Result<(&str, Option<[u8; 64]>), CoreError> {
    let query = uri.split_once('?').map_or("", |(_, q)| q);
    let segments: Vec<&str> = query.split('&').collect();
    let rs_count = segments
        .iter()
        .filter(|s| s.split_once('=').is_some_and(|(k, _)| k == "rs"))
        .count();
    if rs_count == 0 {
        return Ok((uri, None));
    }
    let last = segments.last().copied().unwrap_or_default();
    let Some(value) = last.strip_prefix("rs=") else {
        return Err(CoreError::InvalidPairingUri(
            "route statement rs must be the last parameter".into(),
        ));
    };
    if rs_count != 1
        || segments.len() < 2
        || value.len() != ROUTE_SIG_B64_LEN
        || !value.bytes().all(is_b64url_char)
    {
        return Err(CoreError::InvalidPairingUri(
            "malformed route statement rs".into(),
        ));
    }
    let sig = b64url_decode_array::<64>(value)
        .map_err(|_| CoreError::InvalidPairingUri("malformed route statement rs".into()))?;
    Ok((&uri[..uri.len() - RS_SUFFIX_LEN], Some(sig)))
}

/// Builds the Ed25519 route statement input `PAIRING_ROUTES_DOMAIN || uri_bytes_before_rs`.
#[must_use]
pub fn route_statement_input(uri_bytes_before_rs: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAIRING_ROUTES_DOMAIN.len() + uri_bytes_before_rs.len());
    out.extend_from_slice(PAIRING_ROUTES_DOMAIN);
    out.extend_from_slice(uri_bytes_before_rs.as_bytes());
    out
}

/// Signs `uri_bytes_before_rs` with the Ed25519 component of `identity`'s signing key.
#[must_use]
pub fn sign_route_statement(identity: &EndpointIdentity, uri_bytes_before_rs: &str) -> [u8; 64] {
    identity
        .signing_key()
        .ed25519_signing_key()
        .sign(&route_statement_input(uri_bytes_before_rs))
        .to_bytes()
}

/// Structured QR / out-of-band pairing URI (`tendril://pair?v=1&...`).
///
/// Public fields are display data. Authorization reads a signed URI only through the
/// [`VerifiedRouteStatement`] returned by [`PairingUri::verify_route_statement`].
#[derive(Clone, PartialEq, Eq)]
pub struct PairingUri {
    pub host_name: String,
    pub code: String,
    pub host_static_pub: [u8; 32],
    pub host_signing_pub_hash: [u8; HYBRID_SIGNING_HASH_LEN],
    pub endpoints: Vec<String>,
    pub host_id: Option<String>,
    pub rotation_seq: Option<u64>,
    /// Ed25519 relay mailbox key (`rp`), required iff a non-`/v2/relay` relay hint is present.
    pub relay_pub: Option<[u8; 32]>,
    route_seq: Option<u64>,
    route_sig: Option<[u8; 64]>,
    signed_prefix: Option<String>,
}

impl fmt::Debug for PairingUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingUri")
            .field("host_name", &self.host_name)
            .field("code", &"<redacted>")
            .field("host_static_pub", &self.host_static_pub)
            .field("host_signing_pub_hash", &self.host_signing_pub_hash)
            .field("endpoints", &self.endpoints)
            .field("host_id", &self.host_id)
            .field("rotation_seq", &self.rotation_seq)
            .field("relay_pub", &self.relay_pub)
            .field("route_seq", &self.route_seq)
            .field("signed", &self.route_sig.is_some())
            .finish_non_exhaustive()
    }
}

impl PairingUri {
    /// Builds an unsigned pairing URI value without `rp`.
    #[must_use]
    pub fn new(
        host_name: impl Into<String>,
        code: impl Into<String>,
        host_static_pub: [u8; 32],
        host_signing_pub_hash: [u8; HYBRID_SIGNING_HASH_LEN],
        endpoints: Vec<String>,
        host_id: Option<String>,
        rotation_seq: Option<u64>,
    ) -> Self {
        Self {
            host_name: host_name.into(),
            code: code.into(),
            host_static_pub,
            host_signing_pub_hash,
            endpoints,
            host_id,
            rotation_seq,
            relay_pub: None,
            route_seq: None,
            route_sig: None,
            signed_prefix: None,
        }
    }

    /// Converts this URI's out-of-band cryptographic hash pin into a [`PinnedHost`].
    #[must_use]
    pub fn to_pinned_host(&self) -> PinnedHost {
        PinnedHost::with_hash(
            self.host_id.clone(),
            self.host_static_pub,
            self.host_signing_pub_hash,
            self.rotation_seq.unwrap_or(0),
        )
    }

    /// Route sequence `rq` of a parsed signed URI (display only).
    #[must_use]
    pub const fn route_seq(&self) -> Option<u64> {
        self.route_seq
    }

    /// Returns `true` when this URI was parsed with a route statement `rs`.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signed_prefix.is_some()
    }

    /// Encodes this pairing payload without checks.
    ///
    /// Returns [`Self::try_encode`] output when it succeeds, else the unsigned field encoding,
    /// which may violate the URI bounds and rules.
    #[deprecated(note = "unchecked; use try_encode")]
    #[must_use]
    pub fn encode(&self) -> String {
        self.try_encode().unwrap_or_else(|_| self.encode_fields())
    }

    /// Encodes and validates this URI.
    ///
    /// Never emits `rq` or `rs` for a constructed value. A parsed signed URI is returned
    /// byte-for-byte only while every public field still equals its signed value.
    pub fn try_encode(&self) -> Result<String, CoreError> {
        if let (Some(prefix), Some(sig)) = (&self.signed_prefix, &self.route_sig) {
            let (signed, _) = Self::parse_body(prefix, true)?;
            if !signed.same_public_fields(self) {
                return Err(CoreError::InvalidPairingUri(
                    "signed pairing URI fields were modified".into(),
                ));
            }
            return Ok(format!("{prefix}&rs={}", b64url_encode(sig)));
        }
        self.validate()?;
        let out = self.encode_fields();
        if out.len() > MAX_PAIRING_URI_LEN {
            return Err(CoreError::InvalidPairingUri(
                "pairing URI exceeds 1024 bytes".into(),
            ));
        }
        Ok(out)
    }

    fn same_public_fields(&self, other: &Self) -> bool {
        self.host_name == other.host_name
            && self.code == other.code
            && self.host_static_pub == other.host_static_pub
            && self.host_signing_pub_hash == other.host_signing_pub_hash
            && self.endpoints == other.endpoints
            && self.host_id == other.host_id
            && self.rotation_seq == other.rotation_seq
            && self.relay_pub == other.relay_pub
    }

    /// Canonical field encoding in emission order: `host`, `code`, `k`, `sh`, `id`, `seq`, `rp`,
    /// `ep`.
    fn encode_fields(&self) -> String {
        let mut out = format!(
            "tendril://pair?v=1&host={}&code={}&k={}&sh={}",
            pct_encode(&self.host_name),
            pct_encode(&self.code),
            b64url_encode(&self.host_static_pub),
            b64url_encode(&self.host_signing_pub_hash),
        );
        if let Some(ref host_id) = self.host_id
            && !host_id.is_empty()
        {
            out.push_str("&id=");
            out.push_str(&pct_encode(host_id));
        }
        if let Some(seq) = self.rotation_seq {
            out.push_str(&format!("&seq={seq}"));
        }
        if let Some(rp) = self.relay_pub {
            out.push_str("&rp=");
            out.push_str(&b64url_encode(&rp));
        }
        if !self.endpoints.is_empty() {
            let joined = self
                .endpoints
                .iter()
                .map(|e| pct_encode(e))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str("&ep=");
            out.push_str(&joined);
        }
        out
    }

    /// Checks every public field against the URI rules and returns the code kind.
    fn validate(&self) -> Result<PairingCodeKind, CoreError> {
        if self.host_name.is_empty() || has_control_chars(&self.host_name) {
            return Err(CoreError::InvalidPairingUri(
                "invalid or empty host parameter".into(),
            ));
        }
        let kind = PairingCodeKind::from_code(&self.code)
            .map_err(|_| CoreError::InvalidPairingUri("invalid pairing code format".into()))?;
        if !is_valid_x25519_public_key(&self.host_static_pub) {
            return Err(CoreError::InvalidPairingUri(
                "invalid or low-order host static key".into(),
            ));
        }
        if let Some(ref id) = self.host_id
            && (id.is_empty() || has_control_chars(id))
        {
            return Err(CoreError::InvalidPairingUri("invalid id parameter".into()));
        }
        if self.endpoints.len() > MAX_PAIRING_URI_ENDPOINTS {
            return Err(CoreError::InvalidPairingUri(
                "too many endpoints in ep list".into(),
            ));
        }
        for ep in &self.endpoints {
            if ep.len() > MAX_PAIRING_ENDPOINT_HINT_LEN
                || ep.contains('#')
                || has_control_chars(ep)
                || !is_valid_pairing_endpoint_hint(ep)
            {
                return Err(CoreError::InvalidPairingUri(
                    "invalid endpoint in ep list".into(),
                ));
            }
        }
        if let Some(rp) = self.relay_pub
            && !is_valid_ed25519_public_key(&rp)
        {
            return Err(CoreError::InvalidPairingUri("invalid rp parameter".into()));
        }
        if self.endpoints.iter().any(|e| needs_relay_pub(e)) != self.relay_pub.is_some() {
            return Err(CoreError::InvalidPairingUri(
                "rp must be present exactly when a /v1/relay hint is present".into(),
            ));
        }
        if kind == PairingCodeKind::Lan2Group
            && self.endpoints.iter().any(|e| is_remote_for_lan_code(e))
        {
            return Err(CoreError::InvalidPairingUri(
                "lan 2-group code cannot be paired with remote endpoint hints".into(),
            ));
        }
        Ok(kind)
    }

    /// Parses and validates a `tendril://pair?v=1&...` URI.
    pub fn parse(uri: &str) -> Result<Self, CoreError> {
        if uri.len() > MAX_PAIRING_URI_LEN {
            return Err(CoreError::InvalidPairingUri(
                "pairing URI exceeds 1024 bytes".into(),
            ));
        }
        let (body, sig) = split_route_signature(uri)?;
        let (mut out, route_seq) = Self::parse_body(body, sig.is_some())?;
        if let Some(sig) = sig {
            out.route_seq = route_seq;
            out.route_sig = Some(sig);
            out.signed_prefix = Some(body.to_owned());
        }
        Ok(out)
    }

    /// Parses the URI without `rs`. With `signed`, `rq` must be the last parameter.
    fn parse_body(body: &str, signed: bool) -> Result<(Self, Option<u64>), CoreError> {
        let query = body
            .strip_prefix("tendril://pair?")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing tendril://pair? prefix".into()))?;
        let mut params = BTreeMap::new();
        let mut last_key = "";
        for pair in query.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| CoreError::InvalidPairingUri("malformed query pair".into()))?;
            if !matches!(
                k,
                "v" | "host" | "code" | "k" | "sh" | "id" | "seq" | "rp" | "ep" | "rq"
            ) {
                return Err(CoreError::InvalidPairingUri(
                    "unknown query parameter".into(),
                ));
            }
            if params.insert(k, v).is_some() {
                return Err(CoreError::InvalidPairingUri(
                    "duplicate query parameter".into(),
                ));
            }
            last_key = k;
        }
        let route_seq = match (params.get("rq").copied(), signed) {
            (None, false) => None,
            (Some(raw), true) if last_key == "rq" => Some(parse_route_seq(raw)?),
            (Some(_), true) => {
                return Err(CoreError::InvalidPairingUri(
                    "rq must immediately precede rs".into(),
                ));
            }
            (None, true) => {
                return Err(CoreError::InvalidPairingUri("rs requires rq".into()));
            }
            (Some(_), false) => {
                return Err(CoreError::InvalidPairingUri("rq requires rs".into()));
            }
        };
        if params.get("v").copied() != Some("1") {
            return Err(CoreError::InvalidPairingUri(
                "unsupported or missing pairing URI version".into(),
            ));
        }

        let host_raw = params
            .get("host")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing host parameter".into()))?;
        let host_name = pct_decode(host_raw)?;
        let code_raw = params
            .get("code")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing code parameter".into()))?;
        let code = pct_decode(code_raw)?;

        let k_raw = params
            .get("k")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing host static key k".into()))?;
        let host_static_pub: [u8; 32] = b64url_decode_array(k_raw)?;

        let sh_raw = params
            .get("sh")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing host signing hash sh".into()))?;
        let host_signing_pub_hash: [u8; HYBRID_SIGNING_HASH_LEN] = b64url_decode_array(sh_raw)?;

        let host_id = match params.get("id").copied() {
            None => None,
            Some(id_raw) => Some(pct_decode(id_raw)?),
        };

        let rotation_seq = match params.get("seq").copied() {
            None => None,
            Some(seq_raw) => {
                if seq_raw.is_empty() || !seq_raw.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(CoreError::InvalidPairingUri("invalid seq parameter".into()));
                }
                let seq = seq_raw
                    .parse::<u64>()
                    .map_err(|_| CoreError::InvalidPairingUri("seq parameter overflow".into()))?;
                Some(seq)
            }
        };

        let relay_pub = match params.get("rp").copied() {
            None => None,
            Some(rp_raw) => {
                if rp_raw.len() != RELAY_PUB_B64_LEN || !rp_raw.bytes().all(is_b64url_char) {
                    return Err(CoreError::InvalidPairingUri("invalid rp parameter".into()));
                }
                let rp = b64url_decode_array::<32>(rp_raw)
                    .map_err(|_| CoreError::InvalidPairingUri("invalid rp parameter".into()))?;
                Some(rp)
            }
        };

        let endpoints = match params.get("ep").copied() {
            None | Some("") => Vec::new(),
            Some(ep_raw) => {
                let mut list = Vec::new();
                for part in ep_raw.split(',') {
                    if list.len() == MAX_PAIRING_URI_ENDPOINTS {
                        return Err(CoreError::InvalidPairingUri(
                            "too many endpoints in ep list".into(),
                        ));
                    }
                    let dec = pct_decode(part)?;
                    if dec.is_empty() {
                        return Err(CoreError::InvalidPairingUri(
                            "invalid endpoint in ep list".into(),
                        ));
                    }
                    list.push(dec);
                }
                list
            }
        };

        let mut uri = Self::new(
            host_name,
            code,
            host_static_pub,
            host_signing_pub_hash,
            endpoints,
            host_id,
            rotation_seq,
        );
        uri.relay_pub = relay_pub;
        uri.validate()?;
        Ok((uri, route_seq))
    }

    /// Checks the route statement `rs` against the chain-verified host signing key.
    ///
    /// Returns `Unsigned(Absent)` without `rs`, `Unsigned(KeyRotated)` when `sh` does not hash
    /// `host_signing_pub`, `Verified` with the statement re-parsed from the signed bytes when the
    /// strict Ed25519 signature verifies, else `Invalid`.
    #[must_use]
    pub fn verify_route_statement(&self, host_signing_pub: &HybridSigningPublicKey) -> RouteCheck {
        self.check_route_statement(host_signing_pub, false)
    }

    /// Session variant of [`Self::verify_route_statement`]: a key mismatch is `Invalid`.
    #[must_use]
    pub fn verify_route_statement_for_session(
        &self,
        host_signing_pub: &HybridSigningPublicKey,
    ) -> RouteCheck {
        self.check_route_statement(host_signing_pub, true)
    }

    fn check_route_statement(&self, key: &HybridSigningPublicKey, session: bool) -> RouteCheck {
        let (Some(prefix), Some(sig)) = (&self.signed_prefix, &self.route_sig) else {
            return RouteCheck::Unsigned(UnsignedReason::Absent);
        };
        let Ok((signed, Some(route_seq))) = Self::parse_body(prefix, true) else {
            return RouteCheck::Invalid;
        };
        if !signed.same_public_fields(self) {
            return RouteCheck::Invalid;
        }
        if key.sha256_hash() != signed.host_signing_pub_hash {
            return if session {
                RouteCheck::Invalid
            } else {
                RouteCheck::Unsigned(UnsignedReason::KeyRotated)
            };
        }
        let Ok(vk) = VerifyingKey::from_bytes(key.ed25519_bytes()) else {
            return RouteCheck::Invalid;
        };
        let sig = Ed25519Signature::from_bytes(sig);
        if vk
            .verify_strict(&route_statement_input(prefix), &sig)
            .is_err()
        {
            return RouteCheck::Invalid;
        }
        RouteCheck::Verified(VerifiedRouteStatement {
            code: signed.code,
            host_static_pub: signed.host_static_pub,
            sh: signed.host_signing_pub_hash,
            host_id: signed.host_id,
            rotation_seq: signed.rotation_seq,
            relay_pub: signed.relay_pub,
            hints: signed.endpoints,
            route_seq,
        })
    }

    /// Checks that `rp`, when present, equals the Ed25519 component of `host_signing_pub`.
    pub fn check_relay_pub(
        &self,
        host_signing_pub: &HybridSigningPublicKey,
    ) -> Result<(), CoreError> {
        match self.relay_pub {
            Some(rp) if rp != *host_signing_pub.ed25519_bytes() => {
                Err(CoreError::HostKeyUnverified)
            }
            _ => Ok(()),
        }
    }
}

/// Route fields a host signed, re-parsed from the exact verified URI bytes.
///
/// Constructed only by [`PairingUri::verify_route_statement`] and its session variant.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedRouteStatement {
    code: String,
    host_static_pub: [u8; 32],
    sh: [u8; HYBRID_SIGNING_HASH_LEN],
    host_id: Option<String>,
    rotation_seq: Option<u64>,
    relay_pub: Option<[u8; 32]>,
    hints: Vec<String>,
    route_seq: u64,
}

impl VerifiedRouteStatement {
    /// Signed pairing code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Signed host Noise static key `k`.
    #[must_use]
    pub const fn host_static_pub(&self) -> &[u8; 32] {
        &self.host_static_pub
    }

    /// Signed host signing key hash `sh`.
    #[must_use]
    pub const fn sh(&self) -> &[u8; HYBRID_SIGNING_HASH_LEN] {
        &self.sh
    }

    /// Signed host identifier `id`.
    #[must_use]
    pub fn host_id(&self) -> Option<&str> {
        self.host_id.as_deref()
    }

    /// Signed host rotation sequence `seq`.
    #[must_use]
    pub const fn rotation_seq(&self) -> Option<u64> {
        self.rotation_seq
    }

    /// Signed relay mailbox key `rp`.
    #[must_use]
    pub const fn relay_pub(&self) -> Option<&[u8; 32]> {
        self.relay_pub.as_ref()
    }

    /// Signed endpoint hints in URI order.
    #[must_use]
    pub fn hints(&self) -> &[String] {
        &self.hints
    }

    /// Signed route sequence `rq`.
    #[must_use]
    pub const fn route_seq(&self) -> u64 {
        self.route_seq
    }
}

impl fmt::Debug for VerifiedRouteStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedRouteStatement")
            .field("code", &"<redacted>")
            .field("host_id", &self.host_id)
            .field("rotation_seq", &self.rotation_seq)
            .field("hints", &self.hints)
            .field("route_seq", &self.route_seq)
            .finish_non_exhaustive()
    }
}

/// Why a pairing URI carries no usable route statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsignedReason {
    /// The URI has no `rs`.
    Absent,
    /// The presented host key no longer hashes to the URI's `sh`.
    KeyRotated,
}

/// Result of checking a pairing URI route statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCheck {
    Verified(VerifiedRouteStatement),
    Unsigned(UnsignedReason),
    Invalid,
}

impl RouteCheck {
    /// Surface spelling: `verified`, `unsigned`, `route_key_rotated` or `invalid`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Verified(_) => "verified",
            Self::Unsigned(UnsignedReason::Absent) => "unsigned",
            Self::Unsigned(UnsignedReason::KeyRotated) => "route_key_rotated",
            Self::Invalid => "invalid",
        }
    }

    /// The verified statement, if any.
    #[must_use]
    pub const fn statement(&self) -> Option<&VerifiedRouteStatement> {
        match self {
            Self::Verified(s) => Some(s),
            _ => None,
        }
    }
}

/// The pairing URI and operator relay key a pairing initiator checks the verified host
/// against before `msg3` (spec 6.5 steps 2-3).
#[derive(Debug, Clone, Default)]
pub struct PairRouteBinding {
    uri: Option<PairingUri>,
    operator_relay_key: Option<[u8; 32]>,
}

impl PairRouteBinding {
    /// Binds `uri` and the operator `URL#key`. Fails with `InvalidPairingUri` when both name a
    /// relay key and the keys differ.
    pub fn new(
        uri: Option<PairingUri>,
        operator_relay_key: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        if let (Some(op), Some(rp)) = (operator_relay_key, uri.as_ref().and_then(|u| u.relay_pub))
            && op != rp
        {
            return Err(CoreError::InvalidPairingUri(
                "operator relay key does not match the URI rp".into(),
            ));
        }
        Ok(Self {
            uri,
            operator_relay_key,
        })
    }

    /// The host pin `msg2` is verified against: the bound URI's pin (`k`, `sh`, `id`, `seq`)
    /// merged with `pinned`, so a URI binding never lets an unrelated host key through. A
    /// `pinned` host that names another host is `HostKeyUnverified`.
    pub(crate) fn host_pin(
        &self,
        pinned: Option<&PinnedHost>,
    ) -> Result<Option<PinnedHost>, CoreError> {
        match (pinned, &self.uri) {
            (Some(pin), Some(uri)) => merge_uri_pin(pin, uri)
                .map(Some)
                .ok_or(CoreError::HostKeyUnverified),
            (pin, None) => Ok(pin.cloned()),
            (None, Some(uri)) => Ok(Some(uri.to_pinned_host())),
        }
    }

    /// Checks a binding set on an initiator that already holds `pinned`.
    pub(crate) fn check_pin(&self, pinned: Option<&PinnedHost>) -> Result<(), CoreError> {
        self.host_pin(pinned).map(|_| ()).map_err(|_| {
            CoreError::InvalidPairingUri("pairing URI does not match the pinned host".into())
        })
    }

    /// Binds `uri` without an operator relay key, which cannot disagree.
    pub(crate) fn from_uri(uri: &PairingUri) -> Self {
        Self {
            uri: Some(uri.clone()),
            operator_relay_key: None,
        }
    }

    /// The bound pairing URI.
    #[must_use]
    pub const fn uri(&self) -> Option<&PairingUri> {
        self.uri.as_ref()
    }

    /// Checks `rp` and the operator relay key against the Ed25519 half of `host_signing_pub`,
    /// and the route statement against the whole key.
    #[must_use]
    pub fn verdict(&self, host_signing_pub: &HybridSigningPublicKey) -> PairRouteVerdict {
        let ed = host_signing_pub.ed25519_bytes();
        let relay_pub_ok = self
            .uri
            .as_ref()
            .is_none_or(|u| u.check_relay_pub(host_signing_pub).is_ok())
            && self.operator_relay_key.is_none_or(|k| k == *ed);
        let check = self
            .uri
            .as_ref()
            .map_or(RouteCheck::Unsigned(UnsignedReason::Absent), |u| {
                u.verify_route_statement(host_signing_pub)
            });
        PairRouteVerdict {
            relay_pub_ok,
            check,
        }
    }
}

/// The stricter of `pin` and `uri`'s pin when both name the same host, else `None`.
///
/// They agree on the static key `k`; on the signing key when `pin`'s full key or hash matches
/// `sh`; on `id` when either omits it or both are equal; and on `seq` when the URI omits it or
/// both are equal. The merge keeps `pin`'s signing pin (a full key is stricter than `sh`), the
/// `id` either side names and `pin`'s `seq`.
fn merge_uri_pin(pin: &PinnedHost, uri: &PairingUri) -> Option<PinnedHost> {
    if pin.static_pub != uri.host_static_pub {
        return None;
    }
    let signing_agrees = match &pin.signing_pin {
        SigningKeyPin::Full(key) => key.sha256_hash() == uri.host_signing_pub_hash,
        SigningKeyPin::Hash(hash) => *hash == uri.host_signing_pub_hash,
    };
    if !signing_agrees {
        return None;
    }
    let host_id = match (&pin.host_id, &uri.host_id) {
        (Some(a), Some(b)) if a != b => return None,
        (a, b) => a.clone().or_else(|| b.clone()),
    };
    if uri.rotation_seq.is_some_and(|seq| seq != pin.rotation_seq) {
        return None;
    }
    Some(PinnedHost {
        host_id,
        static_pub: pin.static_pub,
        signing_pin: pin.signing_pin.clone(),
        rotation_seq: pin.rotation_seq,
    })
}

/// The pre-`msg3` route verdict of one verified host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRouteVerdict {
    relay_pub_ok: bool,
    check: RouteCheck,
}

impl PairRouteVerdict {
    /// `rp` and the operator relay key, when present, name the host's Ed25519 key.
    #[must_use]
    pub const fn relay_pub_ok(&self) -> bool {
        self.relay_pub_ok
    }

    /// The route statement result.
    #[must_use]
    pub const fn route_check(&self) -> &RouteCheck {
        &self.check
    }

    /// The route check when `msg3` may be written: `HostKeyUnverified` on a relay key mismatch
    /// (checked first), `InvalidPairingUri` on an invalid route statement.
    pub fn committable(&self) -> Result<&RouteCheck, CoreError> {
        if !self.relay_pub_ok {
            return Err(CoreError::HostKeyUnverified);
        }
        if matches!(self.check, RouteCheck::Invalid) {
            return Err(CoreError::InvalidPairingUri(
                "route statement does not verify".into(),
            ));
        }
        Ok(&self.check)
    }
}

/// Which pairing routes a client persists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePolicy {
    /// Persist every route of a verified, code-bound route statement as `signed`.
    #[default]
    AllSigned,
    /// Persist only the route that carried the commit.
    CommittedOnly,
    /// Persist no URI route.
    None,
}

impl RoutePolicy {
    /// Snake-case spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllSigned => "all_signed",
            Self::CommittedOnly => "committed_only",
            Self::None => "none",
        }
    }
}

impl std::str::FromStr for RoutePolicy {
    type Err = CoreError;

    /// Accepts the snake (`all_signed`), kebab (`all-signed`) and camel (`allSigned`) spellings.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all_signed" | "all-signed" | "allSigned" => Ok(Self::AllSigned),
            "committed_only" | "committed-only" | "committedOnly" => Ok(Self::CommittedOnly),
            "none" => Ok(Self::None),
            _ => Err(CoreError::InvalidPairingUri("unknown route policy".into())),
        }
    }
}

/// Client persistence options for one pairing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistOpts {
    /// Normalized explicit operator endpoint of this call.
    pub operator_endpoint: Option<String>,
    pub policy: RoutePolicy,
    /// Persist the committed route of an unsigned pairing (`--save-route`).
    pub save_committed: bool,
}

impl PersistOpts {
    /// Rejects `save_committed` combined with [`RoutePolicy::None`].
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.save_committed && self.policy == RoutePolicy::None {
            return Err(CoreError::InvalidPairingUri(
                "--save-route conflicts with --route-policy none".into(),
            ));
        }
        Ok(())
    }
}

/// Routes a successful pairing may write, before the roster high-water merge.
///
/// The signed portion (hints, `rq` and the host keys they were signed for) is read-only and set
/// only by [`persistable_routes`] from a [`VerifiedRouteStatement`], so a roster writer never
/// accepts a signed hint no signature covered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistPlan {
    signed: Vec<String>,
    route_seq: Option<u64>,
    signed_keys: Option<([u8; 32], [u8; HYBRID_SIGNING_HASH_LEN])>,
    /// The committed route of an unsigned (or uncovered) pairing.
    pub committed: Option<String>,
    /// The normalized explicit operator endpoint.
    pub operator: Option<String>,
    pub reason: Option<&'static str>,
}

impl PersistPlan {
    /// Hints to persist as `signed`, all covered by the verified statement.
    #[must_use]
    pub fn signed(&self) -> &[String] {
        &self.signed
    }

    /// The verified statement's `rq` when [`Self::signed`] is non-empty.
    #[must_use]
    pub const fn route_seq(&self) -> Option<u64> {
        self.route_seq
    }

    /// The host Noise static key `k` and signing key hash `sh` the signed portion was signed for.
    #[must_use]
    pub const fn signed_host_keys(&self) -> Option<&([u8; 32], [u8; HYBRID_SIGNING_HASH_LEN])> {
        self.signed_keys.as_ref()
    }

    fn set_signed(&mut self, s: &VerifiedRouteStatement, hints: Vec<String>) {
        self.signed = hints;
        self.route_seq = Some(s.route_seq());
        self.signed_keys = Some((s.host_static_pub, s.sh));
    }
}

fn committable(hint: &str) -> bool {
    !is_ipc_hint(hint) && !is_v2_relay_hint(hint)
}

/// Computes the routes a successful pairing persists.
///
/// Signed hints and `rq` come only from the [`VerifiedRouteStatement`] in `check`, and only
/// when `effective_code` equals the signed code. `winner_original_hint` is the URI hint string
/// the winning candidate was built from (`None` for an operator endpoint winner).
#[must_use]
pub fn persistable_routes(
    check: &RouteCheck,
    effective_code: &str,
    winner_original_hint: Option<&str>,
    opts: &PersistOpts,
) -> PersistPlan {
    if matches!(check, RouteCheck::Invalid) {
        return PersistPlan::default();
    }
    let mut plan = PersistPlan {
        operator: opts.operator_endpoint.clone(),
        ..PersistPlan::default()
    };
    if opts.policy == RoutePolicy::None {
        return plan;
    }
    let committed_winner = winner_original_hint
        .filter(|h| committable(h))
        .map(str::to_owned);
    match check {
        RouteCheck::Verified(s) if s.code() == effective_code => match opts.policy {
            RoutePolicy::AllSigned => {
                let hints = s
                    .hints()
                    .iter()
                    .filter(|h| !is_ipc_hint(h))
                    .cloned()
                    .collect();
                plan.set_signed(s, hints);
            }
            RoutePolicy::CommittedOnly => {
                if let Some(h) = winner_original_hint
                    && !is_ipc_hint(h)
                    && s.hints().iter().any(|x| x == h)
                {
                    plan.set_signed(s, vec![h.to_owned()]);
                }
            }
            RoutePolicy::None => {}
        },
        _ => {
            plan.reason = Some(match check {
                RouteCheck::Unsigned(UnsignedReason::KeyRotated) => "route_key_rotated",
                _ => "unsigned_uri",
            });
            if opts.policy == RoutePolicy::CommittedOnly || opts.save_committed {
                plan.committed = committed_winner;
            }
        }
    }
    plan
}

/// Why the announced set or the URI builder dropped a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropReason {
    Invalid,
    BlockedAddress,
    UnspecifiedBind,
    InsecureWs,
    Duplicate,
    ProviderCap,
    CountCap,
    SizeCap,
    LanCodeRemoteHint,
    DirectRequiresIpLiteral,
    RelayNotServed,
    IpcNotAdvertised,
}

/// One hint dropped by the announced set or the URI builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DroppedHint {
    pub hint: String,
    pub reason: DropReason,
}

impl DroppedHint {
    /// The hint in a printable form ([`crate::redact::redact_hint`]); `hint` stays raw for the
    /// operator's own tooling.
    #[must_use]
    pub fn redacted_hint(&self) -> String {
        crate::redact::redact_hint(&self.hint)
    }

    fn new(hint: impl Into<String>, reason: DropReason) -> Self {
        Self {
            hint: hint.into(),
            reason,
        }
    }
}

/// A normalized, capped announced route set, built only by
/// [`PairingManager::announced_route_set`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncedRouteSet {
    routes: Vec<String>,
    dropped: Vec<DroppedHint>,
}

impl AnnouncedRouteSet {
    /// The announced hints in builder order.
    #[must_use]
    pub fn routes(&self) -> &[String] {
        &self.routes
    }

    /// Every input hint the announced set dropped, with its reason.
    #[must_use]
    pub fn dropped(&self) -> &[DroppedHint] {
        &self.dropped
    }
}

/// The host's published announced route set `C(seq)` with its persistent sequence.
///
/// Built only by the roster's publish path (`Roster::bump_local_routes`) from an
/// [`AnnouncedRouteSet`], or loaded with a persisted roster after validation, so one `seq`
/// always names one normalized, capped set. It has no public deserializer: a caller cannot
/// build a different list at a published `seq` and hand it to issuance.
///
/// ```compile_fail
/// let state: tendril_core::pairing::LocalRouteState = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalRouteState {
    seq: u64,
    issued_at: u64,
    digest: [u8; 32],
    routes: Vec<String>,
}

#[derive(Deserialize)]
struct LocalRouteStateRepr {
    seq: u64,
    issued_at: u64,
    digest: [u8; 32],
    routes: Vec<String>,
}

/// Roster persistence only: deserializes and validates a stored `local_routes`.
pub(crate) fn deserialize_local_routes<'de, D>(
    d: D,
) -> Result<Option<Box<LocalRouteState>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<LocalRouteStateRepr>::deserialize(d)?
        .map(|repr| LocalRouteState::try_from(repr).map(Box::new))
        .transpose()
        .map_err(serde::de::Error::custom)
}

impl TryFrom<LocalRouteStateRepr> for LocalRouteState {
    type Error = String;

    fn try_from(r: LocalRouteStateRepr) -> Result<Self, Self::Error> {
        if !(1..=MAX_ROUTE_SEQ).contains(&r.seq) {
            return Err("local route sequence out of range".into());
        }
        if !is_published_route_list(&r.routes) {
            return Err("local routes are not a normalized announced set".into());
        }
        if Self::digest_of(&r.routes) != r.digest {
            return Err("local route digest mismatch".into());
        }
        Ok(Self {
            seq: r.seq,
            issued_at: r.issued_at,
            digest: r.digest,
            routes: r.routes,
        })
    }
}

/// `true` when `routes` could be the output of [`PairingManager::announced_route_set`]: each
/// hint is already normalized, unique, and the route caps hold.
fn is_published_route_list(routes: &[String]) -> bool {
    if routes.len() > MAX_PAIRING_URI_ENDPOINTS {
        return false;
    }
    let mut seen = BTreeSet::new();
    let mut per_provider: BTreeMap<ProviderId, usize> = BTreeMap::new();
    routes.iter().all(|h| {
        let count = per_provider.entry(provider_of_valid_hint(h)).or_default();
        *count += 1;
        *count <= MAX_ANNOUNCED_HINTS_PER_PROVIDER
            && seen.insert(h.as_str())
            && normalize_announced_hint(h, "").as_deref() == Ok(h.as_str())
    })
}

impl LocalRouteState {
    pub(crate) fn new(seq: u64, issued_at: u64, routes: Vec<String>) -> Self {
        Self {
            seq,
            issued_at,
            digest: Self::digest_of(&routes),
            routes,
        }
    }

    /// The persistent route sequence.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Unix seconds at which this set was first published.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// `SHA-256(count || routes)` in the route set body encoding.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The announced set `C(seq)`.
    #[must_use]
    pub fn routes(&self) -> &[String] {
        &self.routes
    }

    /// `SHA-256(count (1 B) || per route: len (2 B BE) || hint)`.
    #[must_use]
    pub fn digest_of(routes: &[String]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([u8::try_from(routes.len()).unwrap_or(u8::MAX)]);
        for r in routes {
            h.update(u16::try_from(r.len()).unwrap_or(u16::MAX).to_be_bytes());
            h.update(r.as_bytes());
        }
        h.finalize().into()
    }
}

/// Options for [`PairingManager::issue_pairing_uri`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueOptions {
    /// Explicit code kind; `None` picks `Remote3Group` whenever a remote-class hint survives.
    pub requested_kind: Option<PairingCodeKind>,
    /// Append `rq` and the route statement `rs` (default `true`).
    pub sign_routes: bool,
}

impl Default for IssueOptions {
    fn default() -> Self {
        Self {
            requested_kind: None,
            sign_routes: true,
        }
    }
}

/// A freshly issued pairing URI and its build report.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedPairingUri {
    pub uri: String,
    pub parsed: PairingUri,
    pub code_kind: PairingCodeKind,
    pub dropped: Vec<DroppedHint>,
    pub uri_len: usize,
    /// Smallest QR version (ECC M, byte mode) that holds `uri`.
    pub qr_version_m: u8,
    pub route_seq: Option<u64>,
}

impl fmt::Debug for IssuedPairingUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedPairingUri")
            .field("uri", &"<redacted>")
            .field("code_kind", &self.code_kind)
            .field("dropped", &self.dropped)
            .field("uri_len", &self.uri_len)
            .field("qr_version_m", &self.qr_version_m)
            .field("route_seq", &self.route_seq)
            .finish_non_exhaustive()
    }
}

/// Smallest QR version at ECC M in byte mode whose capacity holds `len` bytes.
#[must_use]
pub fn qr_version_m(len: usize) -> u8 {
    let idx = QR_BYTE_CAPACITY_M
        .iter()
        .position(|&cap| len <= cap)
        .unwrap_or(QR_BYTE_CAPACITY_M.len() - 1);
    u8::try_from(idx + 1).unwrap_or(40)
}

fn auto_code_kind(hints: &[String]) -> PairingCodeKind {
    if !hints.is_empty() && hints.iter().all(|h| is_lan_direct_literal(h)) {
        PairingCodeKind::Lan2Group
    } else {
        PairingCodeKind::Remote3Group
    }
}

fn is_blocked_announce_ip(ip: IpAddr) -> bool {
    let ip = unmapped(ip);
    if is_disallowed_hint_ip(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.octets()[0] == 0 || v4.octets()[0] >= 240,
        // Local-use NAT64 `64:ff9b:1::/48` (operator-chosen embedding) and site-local
        // `fec0::/10`, blocked outright as at dial time.
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) || (s[0] & 0xffc0) == 0xfec0
        }
    }
}

/// Literal IP host of a direct, overlay or URL hint.
fn hint_host_ip(ep: &str) -> Option<IpAddr> {
    if let Some(t) = ep.strip_prefix("overlay://") {
        return t.parse::<SocketAddr>().ok().map(|s| s.ip());
    }
    if let Ok(s) = direct_target(ep).parse::<SocketAddr>() {
        return Some(s.ip());
    }
    let url = ep
        .strip_prefix("relay:")
        .or_else(|| ep.strip_prefix("broker+"))
        .unwrap_or(ep);
    if let Some(ip) = normalized_url_host_ip(url) {
        return Some(ip);
    }
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = if let Some(b) = authority.strip_prefix('[') {
        b.split(']').next()?
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    host.trim_end_matches('.').parse::<IpAddr>().ok()
}

/// IP host of a `ws`, `wss`, `http` or `https` URL after the WHATWG host normalization the
/// runtime's URL parser applies, so `https://0xf0.1/` is `240.0.0.1`.
fn normalized_url_host_ip(url: &str) -> Option<IpAddr> {
    let parsed = url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "ws" | "wss" | "http" | "https") {
        return None;
    }
    match parsed.host()? {
        url::Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        url::Host::Domain(_) => None,
    }
}

fn hint_is_numeric_host(ep: &str) -> bool {
    let target = ep
        .strip_prefix("direct:")
        .or_else(|| ep.strip_prefix("relay:"))
        .or_else(|| ep.strip_prefix("broker+"))
        .or_else(|| ep.strip_prefix("p2p:"))
        .unwrap_or(ep);
    is_numeric_host_addr(target)
}

/// Drops trailing `addr=` parameters of an `iroh://` hint until it fits the hint bound.
fn trim_iroh_addrs(ep: &str) -> String {
    let (head, query) = match ep.split_once('?') {
        Some((h, q)) if ep.starts_with("iroh://") || ep.starts_with("p2p:iroh://") => (h, q),
        _ => return ep.to_owned(),
    };
    let mut params: Vec<&str> = query.split('&').collect();
    let render = |params: &[&str]| {
        if params.is_empty() {
            head.to_owned()
        } else {
            format!("{head}?{}", params.join("&"))
        }
    };
    let mut out = render(&params);
    while out.len() > MAX_PAIRING_ENDPOINT_HINT_LEN {
        let Some(pos) = params.iter().rposition(|p| p.starts_with("addr=")) else {
            break;
        };
        params.remove(pos);
        out = render(&params);
    }
    out
}

/// Order key of a valid hint: provider rank, numeric host first, then destination order:
/// LAN or loopback first for `Direct`, IPv4 first for `Overlay`, input order otherwise.
pub(crate) fn announce_rank(h: &str) -> (u8, bool, u8) {
    let provider = provider_of_valid_hint(h);
    let ip = hint_host_ip(h);
    let dest_order = match provider {
        ProviderId::Direct => u8::from(!ip.is_some_and(is_lan_or_loopback_ip)),
        ProviderId::Overlay => u8::from(ip.is_some_and(|ip| unmapped(ip).is_ipv6())),
        _ => 0,
    };
    (provider.rank(), !hint_is_numeric_host(h), dest_order)
}

/// Announce-time check of the nested `addr=` and `relay=` destinations of an `iroh://` hint.
fn iroh_destination_drop(hint: &str) -> Option<DropReason> {
    let rest = hint
        .strip_prefix("p2p:")
        .unwrap_or(hint)
        .strip_prefix("iroh://")?;
    let query = rest.split_once('?')?.1;
    for (key, value) in query.split('&').filter_map(|p| p.split_once('=')) {
        let ip = match key {
            "addr" => value.parse::<SocketAddr>().ok().map(|s| s.ip()),
            "relay" => hint_host_ip(value),
            _ => None,
        };
        if let Some(ip) = ip {
            if unmapped(ip).is_unspecified() {
                return Some(DropReason::UnspecifiedBind);
            }
            if is_blocked_announce_ip(ip) {
                return Some(DropReason::BlockedAddress);
            }
        }
    }
    None
}

/// Normalizes one listener or advertised endpoint into an announceable hint.
fn normalize_announced_hint(raw: &str, identity_ed_b64: &str) -> Result<String, DropReason> {
    if is_ipc_hint(raw) || raw.starts_with('/') {
        return Err(DropReason::IpcNotAdvertised);
    }
    let base = match raw.split_once('#') {
        None => raw,
        Some((base, frag)) => {
            if relay_url_path(base).is_none() {
                return Err(DropReason::Invalid);
            }
            if !is_v2_relay_hint(base) && frag != identity_ed_b64 {
                return Err(DropReason::RelayNotServed);
            }
            base
        }
    };
    let hint = match base.parse::<SocketAddr>() {
        Ok(sock) => format!("direct:{sock}"),
        Err(_) => trim_iroh_addrs(base),
    };
    if let Some(ip) = hint_host_ip(&hint) {
        if unmapped(ip).is_unspecified() {
            return Err(DropReason::UnspecifiedBind);
        }
        if is_blocked_announce_ip(ip) {
            return Err(DropReason::BlockedAddress);
        }
    }
    if let Some(reason) = iroh_destination_drop(&hint) {
        return Err(reason);
    }
    if is_valid_pairing_endpoint_hint(&hint)
        && hint.len() <= MAX_PAIRING_ENDPOINT_HINT_LEN
        && provider_of_valid_hint(&hint) == ProviderId::Direct
        && direct_target(&hint).parse::<SocketAddr>().is_err()
    {
        return Err(DropReason::DirectRequiresIpLiteral);
    }
    if !is_valid_pairing_endpoint_hint(&hint) {
        let insecure = hint
            .strip_prefix("relay:")
            .or_else(|| hint.strip_prefix("broker+"))
            .unwrap_or(&hint)
            .starts_with("ws://");
        if insecure {
            let secure = hint.replacen("ws://", "wss://", 1);
            if is_valid_pairing_endpoint_hint(&secure) {
                return Err(DropReason::InsecureWs);
            }
        }
        return Err(DropReason::Invalid);
    }
    if hint.len() > MAX_PAIRING_ENDPOINT_HINT_LEN || hint.contains('#') {
        return Err(DropReason::Invalid);
    }
    Ok(hint)
}

impl PairingManager {
    /// Builds the announced route set `C(seq)` from listener and advertised endpoints.
    ///
    /// Normalizes listener formats, validates, deduplicates, sorts by
    /// `(provider rank, !numeric host, destination order, input order)` (LAN-first for `Direct`,
    /// IPv4-first for `Overlay`), keeps two hints per provider, then six in total. Returns the
    /// set and every dropped hint with its reason.
    #[must_use]
    pub fn announced_route_set(
        identity: &EndpointIdentity,
        endpoints: &[String],
    ) -> AnnouncedRouteSet {
        let ed_b64 = b64url_encode(identity.signing_key().ed25519_public_bytes());
        let mut dropped = Vec::new();
        let mut seen = BTreeSet::new();
        let mut unique = Vec::new();
        for raw in endpoints {
            match normalize_announced_hint(raw, &ed_b64) {
                Ok(hint) if seen.insert(hint.clone()) => unique.push(hint),
                Ok(hint) => dropped.push(DroppedHint::new(hint, DropReason::Duplicate)),
                Err(reason) => dropped.push(DroppedHint::new(raw.clone(), reason)),
            }
        }
        let mut indexed: Vec<(usize, String)> = unique.into_iter().enumerate().collect();
        indexed.sort_by_key(|(i, h)| (announce_rank(h), *i));
        let mut per_provider: BTreeMap<ProviderId, usize> = BTreeMap::new();
        let mut set = Vec::new();
        for (_, hint) in indexed {
            let count = per_provider
                .entry(provider_of_valid_hint(&hint))
                .or_default();
            if *count >= MAX_ANNOUNCED_HINTS_PER_PROVIDER {
                dropped.push(DroppedHint::new(hint, DropReason::ProviderCap));
                continue;
            }
            *count += 1;
            if set.len() >= MAX_PAIRING_URI_ENDPOINTS {
                dropped.push(DroppedHint::new(hint, DropReason::CountCap));
            } else {
                set.push(hint);
            }
        }
        AnnouncedRouteSet {
            routes: set,
            dropped,
        }
    }

    /// Filters, size-trims, issues a code for, encodes and signs a pairing URI.
    ///
    /// Hints come only from `announced.routes` (`C(seq)`), so the URI's hints are an
    /// order-preserving subset of the announced set. Every check runs before the code is issued;
    /// a later failure removes the issued code. `dropped` lists this builder's drops only; the
    /// caller merges the announced set's drops.
    pub fn issue_pairing_uri(
        &mut self,
        identity: &EndpointIdentity,
        host_name: &str,
        announced: &LocalRouteState,
        opts: IssueOptions,
        now_unix: u64,
    ) -> Result<IssuedPairingUri, CoreError> {
        if host_name.is_empty() || has_control_chars(host_name) {
            return Err(CoreError::InvalidPairingUri(
                "invalid or empty host parameter".into(),
            ));
        }
        if opts.sign_routes && !(1..=MAX_ROUTE_SEQ).contains(&announced.seq) {
            return Err(CoreError::InvalidPairingUri(
                "route sequence out of range".into(),
            ));
        }
        let mut dropped = Vec::new();
        let mut seen = BTreeSet::new();
        let mut hints: Vec<String> = Vec::new();
        for hint in &announced.routes {
            if is_ipc_hint(hint) {
                dropped.push(DroppedHint::new(hint.clone(), DropReason::IpcNotAdvertised));
            } else if hint.len() > MAX_PAIRING_ENDPOINT_HINT_LEN
                || hint.contains('#')
                || !is_valid_pairing_endpoint_hint(hint)
            {
                dropped.push(DroppedHint::new(hint.clone(), DropReason::Invalid));
            } else if !seen.insert(hint.as_str()) {
                dropped.push(DroppedHint::new(hint.clone(), DropReason::Duplicate));
            } else if hints.len() >= MAX_PAIRING_URI_ENDPOINTS {
                dropped.push(DroppedHint::new(hint.clone(), DropReason::CountCap));
            } else {
                hints.push(hint.clone());
            }
        }

        let mut kind = match opts.requested_kind {
            Some(PairingCodeKind::Lan2Group) => {
                hints.retain(|h| {
                    let keep = is_lan_direct_literal(h);
                    if !keep {
                        dropped.push(DroppedHint::new(h.clone(), DropReason::LanCodeRemoteHint));
                    }
                    keep
                });
                PairingCodeKind::Lan2Group
            }
            Some(PairingCodeKind::Remote3Group) => PairingCodeKind::Remote3Group,
            None => auto_code_kind(&hints),
        };

        let ed_pub = *identity.signing_key().ed25519_public_bytes();
        let host_id = Some(identity.host_id().to_owned()).filter(|id| !id.is_empty());
        let build = |code: &str, hints: &[String]| {
            let mut uri = PairingUri::new(
                host_name,
                code,
                *identity.static_key().public_bytes(),
                identity.signing_key().signing_pub_hash(),
                hints.to_vec(),
                host_id.clone(),
                Some(identity.rotation_seq()),
            );
            uri.relay_pub = hints.iter().any(|h| needs_relay_pub(h)).then_some(ed_pub);
            uri
        };
        let signed_extra = if opts.sign_routes {
            "&rq=".len() + announced.seq.to_string().len() + RS_SUFFIX_LEN
        } else {
            0
        };
        loop {
            let placeholder = match kind {
                PairingCodeKind::Lan2Group => LAN2_PLACEHOLDER_CODE,
                PairingCodeKind::Remote3Group => REMOTE3_PLACEHOLDER_CODE,
            };
            let len = build(placeholder, &hints).encode_fields().len() + signed_extra;
            if len <= MAX_PAIRING_URI_LEN {
                break;
            }
            let Some(last) = hints.pop() else {
                return Err(CoreError::InvalidPairingUri("host name too long".into()));
            };
            dropped.push(DroppedHint::new(last, DropReason::SizeCap));
            if opts.requested_kind.is_none() {
                kind = auto_code_kind(&hints);
            }
        }

        let code = self.issue_code(kind, now_unix)?;
        let finish = || -> Result<IssuedPairingUri, CoreError> {
            let fields = build(&code, &hints);
            fields.validate()?;
            let base = fields.encode_fields();
            let (uri, route_seq) = if opts.sign_routes {
                let prefix = format!("{base}&rq={}", announced.seq);
                let sig = sign_route_statement(identity, &prefix);
                (
                    format!("{prefix}&rs={}", b64url_encode(&sig)),
                    Some(announced.seq),
                )
            } else {
                (base, None)
            };
            let parsed = PairingUri::parse(&uri)?;
            Ok(IssuedPairingUri {
                uri_len: uri.len(),
                qr_version_m: qr_version_m(uri.len()),
                uri,
                parsed,
                code_kind: kind,
                dropped: dropped.clone(),
                route_seq,
            })
        };
        let result = finish();
        if result.is_err() {
            self.discard_code(&code);
        }
        result
    }

    fn discard_code(&mut self, code: &str) {
        self.codes.retain(|c| c.code.as_str() != code);
    }
}

/// Link-local, unspecified, multicast or cloud metadata, judged after [`unmapped`], plus the
/// IPv6 embeddings whose IPv4 target is not fixed: local-use NAT64 `64:ff9b:1::/48` and Teredo
/// `2001::/32`.
fn is_disallowed_hint_ip(ip: IpAddr) -> bool {
    match unmapped(ip) {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified() || v4.is_multicast(),
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let is_link_local = (seg[0] & 0xffc0) == 0xfe80;
            let is_aws_metadata = v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);
            let is_local_nat64 = seg[..3] == [0x0064, 0xff9b, 0x0001];
            let is_teredo = seg[..2] == [0x2001, 0];
            is_link_local
                || is_aws_metadata
                || is_local_nat64
                || is_teredo
                || v6.is_unspecified()
                || v6.is_multicast()
        }
    }
}

fn is_loopback_authority_host(host: &str) -> bool {
    let clean = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if clean.eq_ignore_ascii_case("localhost") {
        return true;
    }
    clean.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn is_valid_url_hint(url: &str, secure_scheme: &str, loopback_scheme: &str) -> bool {
    if url
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || b.is_ascii_whitespace())
        || url.contains('#')
    {
        return false;
    }
    let (is_insecure, rest) = if let Some(r) = url.strip_prefix(secure_scheme) {
        (false, r)
    } else if let Some(r) = url.strip_prefix(loopback_scheme) {
        (true, r)
    } else {
        return false;
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (host, port_opt) = if let Some(bracket_rest) = authority.strip_prefix('[') {
        let Some((inner, after)) = bracket_rest.split_once(']') else {
            return false;
        };
        if inner.parse::<Ipv6Addr>().is_err() {
            return false;
        }
        let port_str = after.strip_prefix(':');
        if !after.is_empty() && port_str.is_none() {
            return false;
        }
        (authority.split(']').next().unwrap_or(authority), port_str)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return false;
        }
        (h, Some(p))
    } else {
        (authority, None)
    };
    if let Some(p) = port_opt
        && p.parse::<u16>().ok().filter(|&n| n > 0).is_none()
    {
        return false;
    }
    let bare_host = host.strip_prefix('[').unwrap_or(host);
    if bare_host.is_empty()
        || (!bare_host.contains(':')
            && !bare_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
    {
        return false;
    }
    if bare_host
        .trim_end_matches('.')
        .eq_ignore_ascii_case("metadata.google.internal")
    {
        return false;
    }
    if let Ok(ip) = bare_host.trim_end_matches('.').parse::<IpAddr>()
        && is_disallowed_hint_ip(ip)
    {
        return false;
    }
    if let Some(ip) = normalized_url_host_ip(url)
        && is_disallowed_hint_ip(ip)
    {
        return false;
    }
    if is_insecure && !is_loopback_authority_host(bare_host) {
        return false;
    }
    true
}

fn is_valid_host_port_hint(target: &str) -> bool {
    if target.is_empty()
        || target
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b.is_ascii_whitespace())
    {
        return false;
    }
    if let Ok(sock) = target.parse::<SocketAddr>() {
        return sock.port() > 0 && !is_disallowed_hint_ip(sock.ip());
    }
    let Some((host, port_str)) = target.rsplit_once(':') else {
        return false;
    };
    let trimmed_host = host.strip_prefix('[').unwrap_or(host).trim_end_matches('.');
    if trimmed_host.is_empty()
        || trimmed_host.eq_ignore_ascii_case("metadata.google.internal")
        || trimmed_host
            .parse::<IpAddr>()
            .is_ok_and(is_disallowed_hint_ip)
        || host.contains([':', '/', '?', '#', '@'])
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return false;
    }
    port_str.parse::<u16>().ok().filter(|&n| n > 0).is_some()
}

/// Returns `true` when `ep` passes the pairing endpoint hint grammar.
#[must_use]
pub fn is_valid_pairing_endpoint_hint(ep: &str) -> bool {
    if ep.is_empty()
        || ep
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b.is_ascii_whitespace())
        || ep.contains('@')
    {
        return false;
    }
    if let Some(ws) = ep.strip_prefix("relay:") {
        return is_valid_url_hint(ws, "wss://", "ws://");
    }
    if ep.starts_with("wss://") || ep.starts_with("ws://") {
        return is_valid_url_hint(ep, "wss://", "ws://");
    }
    if let Some(broker_ws) = ep.strip_prefix("broker+") {
        return is_valid_url_hint(broker_ws, "wss://", "ws://");
    }
    if let Some(direct) = ep.strip_prefix("direct:") {
        return is_valid_host_port_hint(direct);
    }
    if let Some(local) = ep
        .strip_prefix("local:")
        .or_else(|| ep.strip_prefix("unix://"))
    {
        return !local.is_empty() && !local.contains(['?', '#']);
    }
    if let Some(overlay) = ep.strip_prefix("overlay://") {
        return is_valid_host_port_hint(overlay);
    }
    let iroh_cand = ep.strip_prefix("p2p:").unwrap_or(ep);
    if let Some(rest) = iroh_cand.strip_prefix("iroh://") {
        if rest.contains('#') {
            return false;
        }
        let (node_id, query) = rest.split_once('?').unwrap_or((rest, ""));
        if node_id.is_empty()
            || !node_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return false;
        }
        if !query.is_empty() {
            for pair in query.split('&') {
                let Some((k, v)) = pair.split_once('=') else {
                    return false;
                };
                match k {
                    "addr" => {
                        let Ok(sock) = v.parse::<SocketAddr>() else {
                            return false;
                        };
                        if sock.port() == 0 || is_disallowed_hint_ip(sock.ip()) {
                            return false;
                        }
                    }
                    "relay" => {
                        if !is_valid_url_hint(v, "https://", "http://") {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
        }
        return true;
    }
    is_valid_host_port_hint(ep)
}

fn pct_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper((b >> 4) & 0x0F));
            out.push(hex_upper(b & 0x0F));
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

fn pct_decode(input: &str) -> Result<String, CoreError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(CoreError::InvalidPairingUri(
                    "truncated percent encoding".into(),
                ));
            }
            let hi = from_hex(bytes[i + 1])?;
            let lo = from_hex(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|err| CoreError::InvalidPairingUri(format!("invalid UTF-8: {err}")))
}

fn from_hex(b: u8) -> Result<u8, CoreError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err(CoreError::InvalidPairingUri(
            "invalid hex digit in percent encoding".into(),
        )),
    }
}

/// Optional QR-pinned host identity supplied to [`PairingInitiator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedHost {
    pub host_id: Option<String>,
    pub static_pub: [u8; 32],
    pub signing_pin: SigningKeyPin,
    pub rotation_seq: u64,
}

impl PinnedHost {
    /// Pins a host using its full 1984-byte [`HybridSigningPublicKey`].
    #[must_use]
    pub fn with_full_key(
        host_id: Option<String>,
        static_pub: [u8; 32],
        signing_pub: HybridSigningPublicKey,
        rotation_seq: u64,
    ) -> Self {
        Self {
            host_id,
            static_pub,
            signing_pin: SigningKeyPin::Full(signing_pub),
            rotation_seq,
        }
    }

    /// Pins a host using the SHA-256 hash of its 1984-byte [`HybridSigningPublicKey`].
    #[must_use]
    pub fn with_hash(
        host_id: Option<String>,
        static_pub: [u8; 32],
        signing_pub_hash: [u8; HYBRID_SIGNING_HASH_LEN],
        rotation_seq: u64,
    ) -> Self {
        Self {
            host_id,
            static_pub,
            signing_pin: SigningKeyPin::Hash(signing_pub_hash),
            rotation_seq,
        }
    }
}

/// Actions produced by [`PairingInitiator`] and [`PairingResponder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairAction {
    WriteBytes(Vec<u8>),
    SasReady {
        pairing_sas: String,
        host_id: String,
        host_static_pub: [u8; 32],
    },
    Completed(PairOutcome),
    CloseTransport(String),
}

/// Terminal outcome emitted once `PairResponse` completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairOutcome {
    InitiatorPending {
        device_id: String,
        host_id: String,
        host_static_pub: [u8; 32],
        host_signing_pub: HybridSigningPublicKey,
        host_rotation_seq: u64,
        pairing_sas: String,
        host_pin_verified: bool,
    },
    ResponderPending {
        device_id: String,
        device_static_pub: [u8; 32],
        device_fingerprint: String,
        pairing_sas: String,
        name: String,
        kind: String,
    },
    InitiatorEnrolled {
        device_id: String,
        host_id: String,
        host_static_pub: [u8; 32],
        host_signing_pub: HybridSigningPublicKey,
        host_rotation_seq: u64,
        token_nonce: String,
    },
    ResponderEnrolled {
        device_id: String,
        device_static_pub: [u8; 32],
        device_signing_pub: HybridSigningPublicKey,
        token_nonce: String,
        name: String,
        kind: String,
    },
    Rejected {
        error: String,
    },
}

/// Mints a short-lived, single-use M2M enrollment token (`Grant` with `machine = true`, `uses = 1`).
pub fn mint_enrollment_token(
    issuer: &EndpointIdentity,
    target_host_id: &str,
    subject_device_id: Option<&str>,
    not_before_unix: u64,
    ttl_secs: u64,
    nonce: [u8; 16],
) -> Result<Grant, CoreError> {
    mint_enrollment_token_impl(
        issuer,
        target_host_id,
        subject_device_id,
        not_before_unix,
        ttl_secs,
        nonce,
        false,
    )
}

/// Deterministically mints an M2M enrollment token for reproducible test vectors.
pub fn mint_enrollment_token_deterministic(
    issuer: &EndpointIdentity,
    target_host_id: &str,
    subject_device_id: Option<&str>,
    not_before_unix: u64,
    ttl_secs: u64,
    nonce: [u8; 16],
) -> Result<Grant, CoreError> {
    mint_enrollment_token_impl(
        issuer,
        target_host_id,
        subject_device_id,
        not_before_unix,
        ttl_secs,
        nonce,
        true,
    )
}

fn mint_enrollment_token_impl(
    issuer: &EndpointIdentity,
    target_host_id: &str,
    subject_device_id: Option<&str>,
    not_before_unix: u64,
    ttl_secs: u64,
    nonce: [u8; 16],
    deterministic: bool,
) -> Result<Grant, CoreError> {
    if target_host_id.is_empty()
        || target_host_id.contains('*')
        || has_control_chars(target_host_id)
    {
        return Err(CoreError::EnrollmentTokenInvalid(
            "invalid target_host_id".to_string(),
        ));
    }
    if ttl_secs == 0 || ttl_secs > MAX_ENROLLMENT_TTL_SECS {
        return Err(CoreError::EnrollmentTokenInvalid(
            "enrollment ttl out of bounds".to_string(),
        ));
    }
    let cap = format!("pair.enroll:{target_host_id}");
    Capability::parse(&cap)?;

    let subject = match subject_device_id {
        Some(subj) => {
            if subj.is_empty() || has_control_chars(subj) {
                return Err(CoreError::EnrollmentTokenInvalid(
                    "invalid enrollment subject".to_string(),
                ));
            }
            subj.to_string()
        }
        None => "*".to_string(),
    };

    let not_after_unix = not_before_unix
        .checked_add(ttl_secs)
        .ok_or_else(|| CoreError::InvalidTimestamp("enrollment timestamp overflow".to_string()))?;

    let unsigned = GrantUnsigned {
        v: 1,
        issuer: issuer.host_id().to_string(),
        subject,
        caps: vec![cap],
        not_before: format_rfc3339_utc(not_before_unix)?,
        not_after: format_rfc3339_utc(not_after_unix)?,
        nonce: b64url_encode(&nonce),
        delegated_from: Vec::new(),
        uses: Some(1),
        machine: Some(true),
    };
    if deterministic {
        sign_grant_deterministic(unsigned, issuer.signing_key())
    } else {
        sign_grant(unsigned, issuer.signing_key())
    }
}

/// Builds the canonical signature input for `PairClaim.enroll_proof`:
/// `"tendril-enroll-v1\0" (18 B) || h (32 B) || peer_static_pub (32 B) || UTF-8(token_nonce)`.
#[must_use]
pub fn enroll_proof_bytes(
    handshake_hash: &[u8; 32],
    peer_static_pub: &[u8; 32],
    token_nonce: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENROLL_PROOF_DOMAIN.len() + 32 + 32 + token_nonce.len());
    out.extend_from_slice(ENROLL_PROOF_DOMAIN);
    out.extend_from_slice(handshake_hash);
    out.extend_from_slice(peer_static_pub);
    out.extend_from_slice(token_nonce.as_bytes());
    out
}

/// Signs the M2M channel-binding proof binding `handshake_hash`, `peer_static_pub`, and `token_nonce`.
pub fn sign_enroll_proof(
    signing_key: &SigningKeypair,
    handshake_hash: &[u8; 32],
    peer_static_pub: &[u8; 32],
    token_nonce: &str,
) -> Result<Vec<u8>, CoreError> {
    let msg = enroll_proof_bytes(handshake_hash, peer_static_pub, token_nonce);
    signing_key.sign(&msg)
}

/// Deterministically signs the M2M channel-binding proof for reproducible test vectors.
pub fn sign_enroll_proof_deterministic(
    signing_key: &SigningKeypair,
    handshake_hash: &[u8; 32],
    peer_static_pub: &[u8; 32],
    token_nonce: &str,
) -> Result<Vec<u8>, CoreError> {
    let msg = enroll_proof_bytes(handshake_hash, peer_static_pub, token_nonce);
    signing_key.sign_deterministic(&msg)
}

/// Strictly verifies a channel-bound hybrid M2M `enroll_proof` signature.
pub fn verify_enroll_proof(
    signing_pub: &HybridSigningPublicKey,
    handshake_hash: &[u8; 32],
    peer_static_pub: &[u8; 32],
    token_nonce: &str,
    sig_bytes: &[u8],
) -> Result<(), CoreError> {
    let msg = enroll_proof_bytes(handshake_hash, peer_static_pub, token_nonce);
    signing_pub.verify(&msg, sig_bytes)
}

/// Builds the canonical signature input for a human `PairClaim` signing key proof:
/// `"tendril-pair-key-v1\0" (20 B) || h (32 B) || peer_static_pub (32 B)`.
#[must_use]
pub fn pair_key_proof_bytes(handshake_hash: &[u8; 32], peer_static_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAIR_KEY_PROOF_DOMAIN.len() + 32 + 32);
    out.extend_from_slice(PAIR_KEY_PROOF_DOMAIN);
    out.extend_from_slice(handshake_hash);
    out.extend_from_slice(peer_static_pub);
    out
}

/// Signs the human pairing proof that the initiator holding `peer_static_pub` owns `signing_key`.
pub fn sign_pair_key_proof(
    signing_key: &SigningKeypair,
    handshake_hash: &[u8; 32],
    peer_static_pub: &[u8; 32],
) -> Result<Vec<u8>, CoreError> {
    signing_key.sign(&pair_key_proof_bytes(handshake_hash, peer_static_pub))
}

/// Deterministically signs the human pairing key proof for reproducible test vectors.
pub fn sign_pair_key_proof_deterministic(
    signing_key: &SigningKeypair,
    handshake_hash: &[u8; 32],
    peer_static_pub: &[u8; 32],
) -> Result<Vec<u8>, CoreError> {
    signing_key.sign_deterministic(&pair_key_proof_bytes(handshake_hash, peer_static_pub))
}

/// Strictly verifies both halves of a channel-bound human pairing key proof.
pub fn verify_pair_key_proof(
    signing_pub: &HybridSigningPublicKey,
    handshake_hash: &[u8; 32],
    peer_static_pub: &[u8; 32],
    sig_bytes: &[u8],
) -> Result<(), CoreError> {
    signing_pub.verify(
        &pair_key_proof_bytes(handshake_hash, peer_static_pub),
        sig_bytes,
    )
}

/// Test-only corruptions of the human pairing signing key claim.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClaimTamper {
    /// Proof signed over a different handshake hash.
    WrongTranscript,
    /// Proof signed over a different initiator static key.
    WrongStatic,
    /// Ed25519 half of the proof corrupted.
    CorruptEd25519,
    /// ML-DSA-65 half of the proof corrupted.
    CorruptMlDsa,
    /// Proof signed by a key other than the claimed `signing_pub`.
    OtherKey,
    /// `signing_pub` sent without `enroll_proof`.
    KeyOnly,
    /// `signing_pub` that does not decode as a hybrid key.
    MalformedKey,
    /// `enroll_proof` that does not decode as `b64url`.
    MalformedProof,
    /// Neither field, as a pre-change initiator sends.
    Omit,
}

/// Builds the `(signing_pub, enroll_proof)` pair a human `PairClaim` carries.
pub(crate) fn human_key_claim(
    signing_key: &SigningKeypair,
    handshake_hash: &[u8; 32],
    local_static_pub: &[u8; 32],
    #[cfg(any(test, feature = "test-utils"))] tamper: Option<KeyClaimTamper>,
) -> Result<(Option<String>, Option<String>), CoreError> {
    let signing_pub = Some(signing_key.public_key().to_b64url());
    #[cfg(any(test, feature = "test-utils"))]
    if let Some(t) = tamper {
        return tampered_key_claim(signing_key, handshake_hash, local_static_pub, t);
    }
    let proof = sign_pair_key_proof(signing_key, handshake_hash, local_static_pub)?;
    Ok((signing_pub, Some(b64url_encode(&proof))))
}

#[cfg(any(test, feature = "test-utils"))]
fn tampered_key_claim(
    signing_key: &SigningKeypair,
    handshake_hash: &[u8; 32],
    local_static_pub: &[u8; 32],
    tamper: KeyClaimTamper,
) -> Result<(Option<String>, Option<String>), CoreError> {
    if tamper == KeyClaimTamper::Omit {
        return Ok((None, None));
    }
    let signing_pub = signing_key.public_key().to_b64url();
    let mut h = *handshake_hash;
    let mut st = *local_static_pub;
    let mut signer = signing_key.clone();
    match tamper {
        KeyClaimTamper::WrongTranscript => h[0] ^= 0x01,
        KeyClaimTamper::WrongStatic => st[0] ^= 0x01,
        KeyClaimTamper::OtherKey => signer = SigningKeypair::from_seed([0xEE; 32]),
        _ => {}
    }
    let mut proof = sign_pair_key_proof(&signer, &h, &st)?;
    match tamper {
        KeyClaimTamper::CorruptEd25519 => proof[0] ^= 0x01,
        KeyClaimTamper::CorruptMlDsa => proof[crate::crypto::ED25519_SIG_LEN + 7] ^= 0x01,
        KeyClaimTamper::KeyOnly => return Ok((Some(signing_pub), None)),
        KeyClaimTamper::MalformedKey => {
            return Ok((
                Some(b64url_encode(&[0x42; 16])),
                Some(b64url_encode(&proof)),
            ));
        }
        KeyClaimTamper::MalformedProof => {
            return Ok((Some(signing_pub), Some("*".repeat(64))));
        }
        _ => {}
    }
    Ok((Some(signing_pub), Some(b64url_encode(&proof))))
}

/// Decodes and verifies a human claim's `(signing_pub, enroll_proof)` after the code burn.
///
/// Returns the `PairResponse` error code on failure: `protocol_error` for malformed encodings,
/// `unauthorized` for a proof that does not verify.
pub(crate) fn verify_human_key_claim(
    signing_pub_b64: &str,
    proof_b64: &str,
    handshake_hash: &[u8; 32],
    peer_static_pub: &[u8; 32],
) -> Result<HybridSigningPublicKey, &'static str> {
    let key = HybridSigningPublicKey::from_b64url(signing_pub_b64).map_err(|_| "protocol_error")?;
    let proof = b64url_decode(proof_b64).map_err(|_| "protocol_error")?;
    verify_pair_key_proof(&key, handshake_hash, peer_static_pub, &proof)
        .map_err(|err| err.pair_error_code())?;
    Ok(key)
}

fn validate_enrollment_token_structure(
    token: &Grant,
    expected_host_id: Option<&str>,
    max_ttl_secs: u64,
) -> Result<(u64, u64), CoreError> {
    if token.v != 1 {
        return Err(CoreError::EnrollmentTokenInvalid(
            "unsupported enrollment token version".to_string(),
        ));
    }
    if token.machine != Some(true) || token.uses != Some(1) {
        return Err(CoreError::EnrollmentTokenInvalid(
            "enrollment token requires machine=true and uses=1".to_string(),
        ));
    }
    b64url_decode_array::<16>(&token.nonce).map_err(|_| {
        CoreError::EnrollmentTokenInvalid("enrollment nonce must be 16-byte b64url".to_string())
    })?;

    let nb = parse_rfc3339_utc(&token.not_before)?;
    let na = parse_rfc3339_utc(&token.not_after)?;
    if nb >= na || na - nb > max_ttl_secs {
        return Err(CoreError::EnrollmentTokenInvalid(
            "enrollment token validity window exceeds policy limit".to_string(),
        ));
    }

    if token.caps.is_empty() {
        return Err(CoreError::EnrollmentTokenInvalid(
            "enrollment token caps cannot be empty".to_string(),
        ));
    }
    let parsed_caps = parse_caps(&token.caps)?;
    for cap in &parsed_caps {
        if cap.namespace != "pair" || cap.verb != "enroll" {
            return Err(CoreError::EnrollmentTokenInvalid(format!(
                "disallowed capability {cap} in enrollment token"
            )));
        }
        if let Some(res) = cap.resource.as_deref()
            && (res.contains('*') || expected_host_id.is_some_and(|hid| res != hid))
        {
            return Err(CoreError::EnrollmentTokenInvalid(format!(
                "enrollment capability scope mismatch: {cap}"
            )));
        }
    }

    Ok((nb, na))
}

fn find_enrollment_root_issuer(token: &Grant) -> Result<String, CoreError> {
    let mut cur = token;
    for depth in 0..=MAX_DELEGATION_DEPTH {
        if cur.delegated_from.is_empty() {
            return Ok(cur.issuer.clone());
        }
        if cur.delegated_from.len() != 1 || depth == MAX_DELEGATION_DEPTH {
            return Err(CoreError::DelegationDenied(
                "invalid enrollment token delegation chain".to_string(),
            ));
        }
        cur = &cur.delegated_from[0];
    }
    Err(CoreError::DelegationDenied(
        "enrollment delegation depth exceeded".to_string(),
    ))
}

/// Verifies an M2M enrollment token against `policy`, trust anchors, persisted CRLs, and the
/// burned-nonce replay log, returning the token's `(not_before_unix, not_after_unix)` window.
pub fn verify_enrollment_token(
    token: &Grant,
    responder_host_id: &str,
    responder_signing_pub: &HybridSigningPublicKey,
    peer_device_id: &str,
    now_unix: u64,
    policy: &EnrollmentPolicy,
    roster: &Roster,
) -> Result<(u64, u64), CoreError> {
    if !policy.enabled {
        return Err(CoreError::EnrollmentAnchorUntrusted(
            "m2m enrollment disabled by policy".to_string(),
        ));
    }
    let max_ttl = policy.max_ttl_secs.min(MAX_ENROLLMENT_TTL_SECS);
    if max_ttl == 0 {
        return Err(CoreError::EnrollmentTokenInvalid(
            "invalid max_ttl policy".to_string(),
        ));
    }

    let (nb, na) = validate_enrollment_token_structure(token, Some(responder_host_id), max_ttl)?;
    if now_unix >= na {
        return Err(CoreError::EnrollmentTokenExpired);
    }
    if now_unix < nb.saturating_sub(MAX_CLOCK_SKEW_SECS) {
        return Err(CoreError::EnrollmentTokenInvalid(
            "enrollment token not yet valid".to_string(),
        ));
    }

    let root_issuer = find_enrollment_root_issuer(token)?;
    let self_issued = root_issuer == responder_host_id;
    let self_anchor_ok = if let Some(anchor) = roster.trust_anchor(&root_issuer) {
        anchor.state == AnchorState::Active && &anchor.signing_pub == responder_signing_pub
    } else {
        true
    };
    if self_issued {
        if !policy.allow_self_issued || !self_anchor_ok {
            return Err(CoreError::EnrollmentAnchorUntrusted(root_issuer));
        }
    } else if roster.lookup_active_anchor_key(&root_issuer).is_none() {
        return Err(CoreError::EnrollmentAnchorUntrusted(root_issuer));
    }

    let crl = roster.crl(&root_issuer);
    verify_enrollment_grant_chain(
        token,
        peer_device_id,
        policy.allow_wildcard_subject,
        &root_issuer,
        now_unix,
        crl,
        |issuer_id| {
            if issuer_id == responder_host_id && policy.allow_self_issued && self_anchor_ok {
                Some(responder_signing_pub.clone())
            } else {
                roster
                    .lookup_active_anchor_key(issuer_id)
                    .or_else(|| roster.lookup_active_signing_key(issuer_id))
            }
        },
    )?;

    if let Some(list) = crl
        && list.revoked_devices.iter().any(|d| d == peer_device_id)
    {
        return Err(CoreError::PeerRevoked(peer_device_id.to_string()));
    }

    if roster.is_enrollment_nonce_burned(&token.nonce) {
        return Err(CoreError::EnrollmentTokenReplayed);
    }

    Ok((nb, na))
}

enum InitiatorPhase {
    Init(Box<NoiseHfsHandshake>),
    AwaitMsg2(Box<NoiseHfsHandshake>),
    AwaitCommit {
        hs: Box<NoiseHfsHandshake>,
        host: VerifiedHostState,
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

enum InitiatorAuth {
    Human {
        code: Zeroizing<String>,
        signing_key: SigningKeypair,
    },
    M2m {
        token: Box<Grant>,
        signing_key: SigningKeypair,
    },
}

/// Sans-I/O pairing initiator state machine (`intent = 0x02`).
pub struct PairingInitiator {
    phase: InitiatorPhase,
    reader: ResumableFrameReader,
    auth: InitiatorAuth,
    device_name: String,
    device_kind: String,
    local_static_pub: [u8; 32],
    pinned_host: Option<PinnedHost>,
    v2_floored_static_pubs: BTreeSet<[u8; 32]>,
    v2_floored_host_ids: BTreeSet<String>,
    deferred_claim: bool,
    route_binding: PairRouteBinding,
    route_verdict: Option<PairRouteVerdict>,
    #[cfg(any(test, feature = "test-utils"))]
    key_claim_tamper: Option<KeyClaimTamper>,
}

/// Host identity a pairing initiator verified from `HostHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHost {
    pub host_id: String,
    pub static_pub: [u8; 32],
    pub signing_pub: HybridSigningPublicKey,
    /// Verified rotation sequence when pinned, else the sequence of the presented chain (`0`
    /// when the chain does not verify from its first record).
    pub rotation_seq: u64,
}

struct VerifiedHostState {
    host_id: String,
    host_static_pub: [u8; 32],
    verified_host_signing_pub: HybridSigningPublicKey,
    verified_seq: Option<u64>,
    presented_rotation: Vec<RotationRecord>,
    pairing_sas: String,
}

impl VerifiedHostState {
    fn to_verified_host(&self) -> VerifiedHost {
        VerifiedHost {
            host_id: self.host_id.clone(),
            static_pub: self.host_static_pub,
            signing_pub: self.verified_host_signing_pub.clone(),
            rotation_seq: self.verified_seq.unwrap_or_else(|| {
                presented_chain_seq(
                    &self.presented_rotation,
                    &self.host_static_pub,
                    &self.verified_host_signing_pub,
                )
                .unwrap_or(0)
            }),
        }
    }
}

/// Verifies an unpinned `HostHello.rotation` chain from its first record's previous key.
fn presented_chain_seq(
    presented_rotation: &[RotationRecord],
    host_static_pub: &[u8; 32],
    host_signing: &HybridSigningPublicKey,
) -> Result<u64, CoreError> {
    let Some(first) = presented_rotation.first() else {
        return Ok(0);
    };
    let root_sig = HybridSigningPublicKey::from_b64url(&first.prev_signing_pub)
        .map_err(|_| CoreError::HostKeyUnverified)?;
    verify_rotation_chain_pin(
        &SigningKeyPin::Full(root_sig),
        host_static_pub,
        first.seq.saturating_sub(1),
        presented_rotation,
        host_static_pub,
        host_signing,
    )
    .map_err(|_| CoreError::HostKeyUnverified)
}

impl fmt::Debug for PairingInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match &self.auth {
            InitiatorAuth::Human { .. } => "human",
            InitiatorAuth::M2m { .. } => "m2m",
        };
        f.debug_struct("PairingInitiator")
            .field("device_id", &device_id(&self.local_static_pub))
            .field("mode", &mode)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

impl PairingInitiator {
    fn build_handshake(
        identity: &EndpointIdentity,
        pinned_host: Option<&PinnedHost>,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<NoiseHfsHandshake, CoreError> {
        if let Some(pin) = pinned_host
            && !is_valid_x25519_public_key(&pin.static_pub)
        {
            return Err(CoreError::IncompletePin(
                pin.host_id
                    .clone()
                    .unwrap_or_else(|| "pinned_host".to_string()),
            ));
        }
        let preamble = Preamble::v1(Intent::Pair).encode();
        let mut builder = NoiseHfsHandshakeBuilder::new()
            .local_private_key(identity.static_key().secret_bytes())
            .prologue(&preamble);
        if let Some(eph) = fixed_ephemeral {
            builder = builder.fixed_ephemeral_for_testing_only(eph);
        }
        builder.build_initiator()
    }

    /// Creates a new human pairing initiator ready to emit the pairing preamble and `msg1`.
    pub fn new(
        identity: &EndpointIdentity,
        device_name: impl Into<String>,
        device_kind: impl Into<String>,
        code: impl Into<String>,
        pinned_host: Option<PinnedHost>,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        let hs = Self::build_handshake(identity, pinned_host.as_ref(), fixed_ephemeral)?;
        Ok(Self {
            phase: InitiatorPhase::Init(Box::new(hs)),
            reader: ResumableFrameReader::new(),
            auth: InitiatorAuth::Human {
                code: Zeroizing::new(code.into()),
                signing_key: identity.signing_key().clone(),
            },
            device_name: device_name.into(),
            device_kind: device_kind.into(),
            local_static_pub: *identity.static_key().public_bytes(),
            pinned_host,
            v2_floored_static_pubs: BTreeSet::new(),
            v2_floored_host_ids: BTreeSet::new(),
            deferred_claim: false,
            route_binding: PairRouteBinding::default(),
            route_verdict: None,
            #[cfg(any(test, feature = "test-utils"))]
            key_claim_tamper: None,
        })
    }

    /// Creates a v1 human pairing initiator enforcing `min_wire_version` anti-downgrade.
    ///
    /// Fails closed with [`CoreError::VersionDowngrade`] if `min_wire_version >= 2`.
    pub fn new_with_min_wire_version(
        identity: &EndpointIdentity,
        device_name: impl Into<String>,
        device_kind: impl Into<String>,
        code: impl Into<String>,
        pinned_host: Option<PinnedHost>,
        min_wire_version: u8,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        if min_wire_version > WIRE_VERSION {
            return Err(CoreError::VersionDowngrade {
                peer_min: min_wire_version,
                negotiated: WIRE_VERSION,
            });
        }
        Self::new(
            identity,
            device_name,
            device_kind,
            code,
            pinned_host,
            fixed_ephemeral,
        )
    }

    /// Corrupts the human signing key claim in `msg3` strictly in tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_key_claim_tamper_for_testing_only(mut self, tamper: KeyClaimTamper) -> Self {
        self.key_claim_tamper = Some(tamper);
        self
    }

    /// Defers `msg3`: a verified `msg2` emits only `SasReady` (human) and parks until
    /// [`Self::commit_claim`].
    #[must_use]
    pub fn with_deferred_claim(mut self) -> Self {
        self.deferred_claim = true;
        self
    }

    /// Binds the pairing URI and operator relay key whose `rp`, operator key and route statement
    /// checks gate `msg3`. A bound URI's host pin is enforced at `msg2`: it is the pin when none
    /// was given, and a different pinned host refuses `msg2` with `HostKeyUnverified`.
    #[must_use]
    pub fn with_route_binding(mut self, binding: PairRouteBinding) -> Self {
        self.route_binding = binding;
        self
    }

    /// Binds `uri` alone, as [`Self::with_route_binding`].
    #[must_use]
    pub fn with_pairing_uri(self, uri: &PairingUri) -> Self {
        self.with_route_binding(PairRouteBinding::from_uri(uri))
    }

    /// Replaces the route binding. Fails with `NotReady` once `msg2` was accepted, and with
    /// `InvalidPairingUri` when the URI's host pin differs from the pinned host.
    pub fn set_route_binding(&mut self, binding: PairRouteBinding) -> Result<(), CoreError> {
        if !matches!(
            self.phase,
            InitiatorPhase::Init(_) | InitiatorPhase::AwaitMsg2(_)
        ) {
            return Err(CoreError::NotReady(
                "pairing route binding is set before msg2",
            ));
        }
        binding.check_pin(self.pinned_host.as_ref())?;
        self.route_binding = binding;
        Ok(())
    }

    /// The route verdict of the verified host, from `msg2` acceptance on.
    #[must_use]
    pub const fn route_verdict(&self) -> Option<&PairRouteVerdict> {
        self.route_verdict.as_ref()
    }

    /// Returns `true` while a verified `msg2` waits for [`Self::commit_claim`].
    #[must_use]
    pub const fn is_awaiting_commit(&self) -> bool {
        matches!(self.phase, InitiatorPhase::AwaitCommit { .. })
    }

    /// The host verified from `HostHello`, once `msg2` has been accepted.
    #[must_use]
    pub fn verified_host(&self) -> Option<VerifiedHost> {
        match &self.phase {
            InitiatorPhase::AwaitCommit { host, .. } => Some(host.to_verified_host()),
            InitiatorPhase::AwaitResponse {
                host_id,
                host_static_pub,
                verified_host_signing_pub,
                verified_seq,
                presented_rotation,
                ..
            } => Some(VerifiedHost {
                host_id: host_id.clone(),
                static_pub: *host_static_pub,
                signing_pub: verified_host_signing_pub.clone(),
                rotation_seq: verified_seq.unwrap_or_else(|| {
                    presented_chain_seq(
                        presented_rotation,
                        host_static_pub,
                        verified_host_signing_pub,
                    )
                    .unwrap_or(0)
                }),
            }),
            _ => None,
        }
    }

    /// Builds and returns the `msg3` claim of a deferred initiator from this handshake's `h`.
    ///
    /// Fails with `NotReady` before a verified `msg2` or when called twice. A failed route
    /// verdict returns its error and closes the initiator without `msg3`.
    pub fn commit_claim(&mut self) -> Result<Vec<PairAction>, CoreError> {
        if !self.is_awaiting_commit() {
            return Err(CoreError::NotReady(
                "pairing initiator is not awaiting commit",
            ));
        }
        let InitiatorPhase::AwaitCommit { hs, host } =
            std::mem::replace(&mut self.phase, InitiatorPhase::Closed)
        else {
            return Err(CoreError::NotReady(
                "pairing initiator is not awaiting commit",
            ));
        };
        self.route_verdict
            .as_ref()
            .ok_or(CoreError::HostKeyUnverified)?
            .committable()?;
        let mut actions = Vec::new();
        self.write_claim(hs, host, &mut actions)?;
        Ok(actions)
    }

    fn write_claim(
        &mut self,
        mut hs: Box<NoiseHfsHandshake>,
        host: VerifiedHostState,
        actions: &mut Vec<PairAction>,
    ) -> Result<(), CoreError> {
        let h = *hs.get_handshake_hash();
        let claim = match &self.auth {
            InitiatorAuth::Human { code, signing_key } => {
                let mac = compute_code_mac(code, &h)?;
                let (signing_pub, enroll_proof) = human_key_claim(
                    signing_key,
                    &h,
                    &self.local_static_pub,
                    #[cfg(any(test, feature = "test-utils"))]
                    self.key_claim_tamper,
                )?;
                PairClaim {
                    name: self.device_name.clone(),
                    kind: self.device_kind.clone(),
                    code_mac: Some(b64url_encode(&mac)),
                    enrollment_token: None,
                    signing_pub,
                    enroll_proof,
                }
            }
            InitiatorAuth::M2m { token, signing_key } => {
                let proof =
                    sign_enroll_proof(signing_key, &h, &self.local_static_pub, &token.nonce)?;
                PairClaim {
                    name: self.device_name.clone(),
                    kind: self.device_kind.clone(),
                    code_mac: None,
                    enrollment_token: Some(token.as_ref().clone()),
                    signing_pub: Some(signing_key.public_key().to_b64url()),
                    enroll_proof: Some(b64url_encode(&proof)),
                }
            }
        };
        let claim_json = Zeroizing::new(
            serde_json::to_vec(&claim).map_err(|err| CoreError::Json(err.to_string()))?,
        );
        let msg3 = hs.write_message_vec(&claim_json)?;
        let msg3_frame = encode_frame(&msg3)?;
        actions.push(PairAction::WriteBytes(msg3_frame));

        let transport = hs.into_transport_mode()?;
        self.phase = InitiatorPhase::AwaitResponse {
            transport: Box::new(transport),
            host_id: host.host_id,
            host_static_pub: host.host_static_pub,
            verified_host_signing_pub: host.verified_host_signing_pub,
            verified_seq: host.verified_seq,
            presented_rotation: host.presented_rotation,
            pairing_sas: host.pairing_sas,
            host_pin_verified: host.verified_seq.is_some(),
        };
        Ok(())
    }

    /// Creates an autonomous M2M enrollment initiator requiring an out-of-band pinned host key.
    pub fn new_m2m(
        identity: &EndpointIdentity,
        device_name: impl Into<String>,
        device_kind: impl Into<String>,
        enrollment_token: Grant,
        pinned_host: PinnedHost,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        let device_name = device_name.into();
        let device_kind = device_kind.into();
        if device_name.is_empty()
            || device_kind.is_empty()
            || has_control_chars(&device_name)
            || has_control_chars(&device_kind)
        {
            return Err(CoreError::ProtocolViolation(
                "invalid device metadata in m2m initiator",
            ));
        }
        validate_enrollment_token_structure(
            &enrollment_token,
            pinned_host.host_id.as_deref(),
            MAX_ENROLLMENT_TTL_SECS,
        )?;
        if enrollment_token.subject != "*" && enrollment_token.subject != identity.device_id() {
            return Err(CoreError::EnrollmentTokenInvalid(
                "enrollment token subject does not match local device_id".to_string(),
            ));
        }

        let hs = Self::build_handshake(identity, Some(&pinned_host), fixed_ephemeral)?;
        Ok(Self {
            phase: InitiatorPhase::Init(Box::new(hs)),
            reader: ResumableFrameReader::new(),
            auth: InitiatorAuth::M2m {
                token: Box::new(enrollment_token),
                signing_key: identity.signing_key().clone(),
            },
            device_name,
            device_kind,
            local_static_pub: *identity.static_key().public_bytes(),
            pinned_host: Some(pinned_host),
            v2_floored_static_pubs: BTreeSet::new(),
            v2_floored_host_ids: BTreeSet::new(),
            deferred_claim: false,
            route_binding: PairRouteBinding::default(),
            route_verdict: None,
            #[cfg(any(test, feature = "test-utils"))]
            key_claim_tamper: None,
        })
    }

    /// Creates a v1 M2M pairing initiator enforcing `min_wire_version` anti-downgrade.
    ///
    /// Fails closed with [`CoreError::VersionDowngrade`] if `min_wire_version >= 2`.
    pub fn new_m2m_with_min_wire_version(
        identity: &EndpointIdentity,
        device_name: impl Into<String>,
        device_kind: impl Into<String>,
        enrollment_token: Grant,
        pinned_host: PinnedHost,
        min_wire_version: u8,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        if min_wire_version > WIRE_VERSION {
            return Err(CoreError::VersionDowngrade {
                peer_min: min_wire_version,
                negotiated: WIRE_VERSION,
            });
        }
        Self::new_m2m(
            identity,
            device_name,
            device_kind,
            enrollment_token,
            pinned_host,
            fixed_ephemeral,
        )
    }

    /// Enforces a persisted `min_wire_version` floor before emitting `PairClaim`.
    pub fn with_min_wire_version(self, min_wire_version: u8) -> Result<Self, CoreError> {
        if min_wire_version > WIRE_VERSION {
            return Err(CoreError::VersionDowngrade {
                peer_min: min_wire_version,
                negotiated: WIRE_VERSION,
            });
        }
        Ok(self)
    }

    /// Collects every peer in `roster` with `min_wire_version >= 2` so unpinned v1 pairing
    /// aborts at `msg2` before transmitting `PairClaim`.
    #[must_use]
    pub fn with_roster_floors(mut self, roster: &Roster) -> Self {
        for (id, entry) in roster.entries() {
            if entry.min_wire_version >= WIRE_VERSION_V2 {
                self.v2_floored_host_ids.insert(id.clone());
                self.v2_floored_static_pubs.insert(entry.static_pub);
            }
        }
        self
    }

    /// Emits the 6-byte `Intent::Pair` preamble concatenated with Noise `msg1`.
    pub fn start(&mut self) -> Result<Vec<PairAction>, CoreError> {
        let prev = std::mem::replace(&mut self.phase, InitiatorPhase::Closed);
        let InitiatorPhase::Init(mut hs) = prev else {
            return Err(CoreError::NotReady("pairing initiator already started"));
        };
        let msg1 = hs.write_message_vec(&[])?;
        let frame = encode_frame(&msg1)?;
        let preamble = Preamble::v1(Intent::Pair).encode();
        let mut wire_bytes = Vec::with_capacity(preamble.len() + frame.len());
        wire_bytes.extend_from_slice(&preamble);
        wire_bytes.extend_from_slice(&frame);
        self.phase = InitiatorPhase::AwaitMsg2(hs);
        Ok(vec![PairAction::WriteBytes(wire_bytes)])
    }

    /// Consumes inbound transport bytes, advancing the pairing handshake and emitting actions.
    pub fn feed_bytes(&mut self, chunk: &[u8]) -> Result<Vec<PairAction>, CoreError> {
        if matches!(self.phase, InitiatorPhase::Closed) {
            return Err(CoreError::SessionClosed {
                code: 1000,
                reason: "pairing session closed".to_string(),
            });
        }
        if let Err(err) = self.reader.push(chunk) {
            self.phase = InitiatorPhase::Closed;
            return Err(err);
        }

        let mut actions = Vec::new();
        loop {
            let body = match self.reader.next_frame() {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = InitiatorPhase::Closed;
                    return Err(err);
                }
            };

            let res = self.handle_frame(&body, &mut actions);
            if let Err(err) = res {
                self.phase = InitiatorPhase::Closed;
                return Err(err);
            }
            if matches!(self.phase, InitiatorPhase::Closed) {
                return Ok(actions);
            }
        }
    }

    fn handle_frame(
        &mut self,
        body: &[u8],
        actions: &mut Vec<PairAction>,
    ) -> Result<(), CoreError> {
        let phase = std::mem::replace(&mut self.phase, InitiatorPhase::Closed);
        match phase {
            InitiatorPhase::AwaitMsg2(mut hs) => {
                let pt = hs.read_message_vec(body)?;
                let host_hello: HostHello =
                    serde_json::from_slice(&pt).map_err(|err| CoreError::Json(err.to_string()))?;
                if host_hello.proto_version != 1 {
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

                if self.v2_floored_static_pubs.contains(&remote_static)
                    || self.v2_floored_host_ids.contains(&host_hello.host_id)
                {
                    return Err(CoreError::VersionDowngrade {
                        peer_min: WIRE_VERSION_V2,
                        negotiated: WIRE_VERSION,
                    });
                }

                let mut verified_seq = None;
                let pin = self.route_binding.host_pin(self.pinned_host.as_ref())?;
                if let Some(pin) = &pin {
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
                        Ok(seq) => {
                            verified_seq = Some(seq);
                        }
                        Err(err @ CoreError::RotationForkDetected { .. }) => return Err(err),
                        Err(_) => return Err(CoreError::HostKeyUnverified),
                    }
                }

                let h = *hs.get_handshake_hash();
                let sas = pairing_sas(&h);
                if matches!(self.auth, InitiatorAuth::Human { .. }) {
                    actions.push(PairAction::SasReady {
                        pairing_sas: sas.clone(),
                        host_id: host_hello.host_id.clone(),
                        host_static_pub: remote_static,
                    });
                }
                let host = VerifiedHostState {
                    host_id: host_hello.host_id,
                    host_static_pub: remote_static,
                    verified_host_signing_pub: host_signing_pub,
                    verified_seq,
                    presented_rotation: host_hello.rotation,
                    pairing_sas: sas,
                };
                let verdict = self.route_binding.verdict(&host.verified_host_signing_pub);
                let refusal = verdict.committable().err();
                self.route_verdict = Some(verdict);
                if self.deferred_claim {
                    self.phase = InitiatorPhase::AwaitCommit { hs, host };
                    return Ok(());
                }
                if let Some(err) = refusal {
                    return Err(err);
                }
                self.write_claim(hs, host, actions)
            }
            InitiatorPhase::AwaitResponse {
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
                        let expected_status = match &self.auth {
                            InitiatorAuth::Human { .. } => "pending",
                            InitiatorAuth::M2m { .. } => "active",
                        };
                        if resp_dev_id != device_id(&self.local_static_pub)
                            || status != expected_status
                        {
                            return Err(CoreError::ProtocolViolation(
                                "unexpected pair response fields",
                            ));
                        }
                        let host_signing =
                            HybridSigningPublicKey::from_b64url(&host_signing_pub)
                                .map_err(|_| CoreError::IncompletePin(host_id.clone()))?;
                        if host_signing != verified_host_signing_pub {
                            return Err(CoreError::HostKeyUnverified);
                        }
                        let host_rotation_seq = match verified_seq {
                            Some(seq) => seq,
                            None => presented_chain_seq(
                                &presented_rotation,
                                &host_static_pub,
                                &host_signing,
                            )?,
                        };
                        let outcome = match &self.auth {
                            InitiatorAuth::Human { .. } => PairOutcome::InitiatorPending {
                                device_id: resp_dev_id,
                                host_id,
                                host_static_pub,
                                host_signing_pub: host_signing,
                                host_rotation_seq,
                                pairing_sas,
                                host_pin_verified,
                            },
                            InitiatorAuth::M2m { token, .. } => PairOutcome::InitiatorEnrolled {
                                device_id: resp_dev_id,
                                host_id,
                                host_static_pub,
                                host_signing_pub: host_signing,
                                host_rotation_seq,
                                token_nonce: token.nonce.clone(),
                            },
                        };
                        actions.push(PairAction::Completed(outcome));
                        actions.push(PairAction::CloseTransport("pairing complete".to_string()));
                        self.phase = InitiatorPhase::Closed;
                        Ok(())
                    }
                    PairResponse::Error { error } => {
                        actions.push(PairAction::Completed(PairOutcome::Rejected {
                            error: error.clone(),
                        }));
                        actions.push(PairAction::CloseTransport(error));
                        self.phase = InitiatorPhase::Closed;
                        Ok(())
                    }
                }
            }
            InitiatorPhase::AwaitCommit { .. } => Err(CoreError::ProtocolViolation(
                "unexpected pairing frame before claim commit",
            )),
            InitiatorPhase::Init(_) => Err(CoreError::NotReady("pairing initiator not started")),
            InitiatorPhase::Closed => Err(CoreError::SessionClosed {
                code: 1000,
                reason: "pairing session closed".to_string(),
            }),
        }
    }
}

enum ResponderPhase {
    AwaitPreamble(Box<NoiseHfsHandshake>),
    AwaitMsg1(Box<NoiseHfsHandshake>),
    AwaitMsg3 {
        hs: Box<NoiseHfsHandshake>,
        post_msg2_hash: [u8; 32],
    },
    Closed,
}

/// Sans-I/O pairing responder state machine (`intent = 0x02`).
pub struct PairingResponder {
    phase: ResponderPhase,
    reader: ResumableFrameReader,
    host_hello: HostHello,
    host_signing_pub: HybridSigningPublicKey,
    path: PairingPathKind,
    enrollment_policy: EnrollmentPolicy,
}

impl fmt::Debug for PairingResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingResponder")
            .field("host_id", &self.host_hello.host_id)
            .field("path", &self.path)
            .field("m2m_enabled", &self.enrollment_policy.enabled)
            .finish()
    }
}

impl PairingResponder {
    /// Creates a new pairing responder bound to `identity` and transport classification `path`
    /// with M2M enrollment disabled by default.
    pub fn new(
        identity: &EndpointIdentity,
        path: PairingPathKind,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        Self::with_enrollment_policy(identity, path, fixed_ephemeral, EnrollmentPolicy::default())
    }

    /// Creates a pairing responder configured with an explicit [`EnrollmentPolicy`].
    pub fn with_enrollment_policy(
        identity: &EndpointIdentity,
        path: PairingPathKind,
        fixed_ephemeral: Option<[u8; 32]>,
        enrollment_policy: EnrollmentPolicy,
    ) -> Result<Self, CoreError> {
        let preamble = Preamble::v1(Intent::Pair).encode();
        let mut builder = NoiseHfsHandshakeBuilder::new()
            .local_private_key(identity.static_key().secret_bytes())
            .prologue(&preamble);
        if let Some(eph) = fixed_ephemeral {
            builder = builder.fixed_ephemeral_for_testing_only(eph);
        }
        let hs = builder.build_responder()?;

        Ok(Self {
            phase: ResponderPhase::AwaitPreamble(Box::new(hs)),
            reader: ResumableFrameReader::with_preamble(),
            host_hello: HostHello {
                host_id: identity.host_id().to_string(),
                proto_version: 1,
                signing_pub: identity.signing_key().public_key().to_b64url(),
                rotation: identity.rotation_chain().to_vec(),
            },
            host_signing_pub: identity.signing_key().public_key().clone(),
            path,
            enrollment_policy,
        })
    }

    /// Returns `true` once `msg2` has been sent and the responder is waiting for `msg3` (`PairClaim`).
    #[must_use]
    pub fn is_awaiting_claim(&self) -> bool {
        matches!(self.phase, ResponderPhase::AwaitMsg3 { .. })
    }

    /// Consumes inbound transport bytes, verifies `code_mac` against `manager`, and updates `roster`.
    pub fn feed_bytes(
        &mut self,
        chunk: &[u8],
        now_unix: u64,
        manager: &mut PairingManager,
        roster: &mut Roster,
    ) -> Result<Vec<PairAction>, CoreError> {
        if matches!(self.phase, ResponderPhase::Closed) {
            return Err(CoreError::SessionClosed {
                code: 1000,
                reason: "pairing session closed".to_string(),
            });
        }
        if let Err(err) = self.reader.push(chunk) {
            self.phase = ResponderPhase::Closed;
            return Err(err);
        }

        let mut actions = Vec::new();
        if matches!(self.phase, ResponderPhase::AwaitPreamble(_)) {
            match self.reader.take_preamble() {
                Ok(Some(preamble)) => {
                    if preamble.version != WIRE_VERSION {
                        self.phase = ResponderPhase::Closed;
                        return Err(CoreError::UnsupportedVersion(preamble.version));
                    }
                    if preamble.intent != Intent::Pair {
                        self.phase = ResponderPhase::Closed;
                        return Err(CoreError::ProtocolViolation(
                            "expected pair preamble intent",
                        ));
                    }
                    let prev = std::mem::replace(&mut self.phase, ResponderPhase::Closed);
                    if let ResponderPhase::AwaitPreamble(hs) = prev {
                        self.phase = ResponderPhase::AwaitMsg1(hs);
                    }
                }
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = ResponderPhase::Closed;
                    return Err(err);
                }
            }
        }

        loop {
            let body = match self.reader.next_frame() {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(actions),
                Err(err) => {
                    self.phase = ResponderPhase::Closed;
                    return Err(err);
                }
            };

            if let Err(err) = self.handle_frame(&body, now_unix, manager, roster, &mut actions) {
                self.phase = ResponderPhase::Closed;
                return Err(err);
            }
            if matches!(self.phase, ResponderPhase::Closed) {
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
        actions: &mut Vec<PairAction>,
    ) -> Result<(), CoreError> {
        let phase = std::mem::replace(&mut self.phase, ResponderPhase::Closed);
        match phase {
            ResponderPhase::AwaitMsg1(mut hs) => {
                let pt = hs.read_message_vec(body)?;
                if !pt.is_empty() {
                    return Err(CoreError::ProtocolViolation(
                        "msg1 must carry empty payload",
                    ));
                }

                let hello_json = Zeroizing::new(
                    serde_json::to_vec(&self.host_hello)
                        .map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let msg2 = hs.write_message_vec(&hello_json)?;
                let post_msg2_hash = *hs.get_handshake_hash();
                let frame2 = encode_frame(&msg2)?;
                actions.push(PairAction::WriteBytes(frame2));
                self.phase = ResponderPhase::AwaitMsg3 { hs, post_msg2_hash };
                Ok(())
            }
            ResponderPhase::AwaitMsg3 {
                mut hs,
                post_msg2_hash,
            } => {
                let pt = hs.read_message_vec(body)?;
                let peer_static: [u8; 32] = *hs.get_remote_static().ok_or(
                    CoreError::ProtocolViolation("missing initiator static key in msg3"),
                )?;
                if !is_valid_x25519_public_key(&peer_static) {
                    return Err(CoreError::ProtocolViolation(
                        "invalid or low-order initiator static key",
                    ));
                }
                if let Some(peer_min) = roster
                    .entries()
                    .filter(|(_, e)| {
                        e.static_pub == peer_static && e.min_wire_version > WIRE_VERSION
                    })
                    .map(|(_, e)| e.min_wire_version)
                    .max()
                {
                    return Err(CoreError::VersionDowngrade {
                        peer_min,
                        negotiated: WIRE_VERSION,
                    });
                }

                let mut transport = hs.into_transport_mode()?;

                let claim: PairClaim = match serde_json::from_slice(&pt) {
                    Ok(c) => c,
                    Err(_) => {
                        return write_pair_error(&mut transport, "protocol_error", actions);
                    }
                };
                if claim.name.is_empty()
                    || claim.kind.is_empty()
                    || claim.name.len() > 256
                    || claim.kind.len() > 64
                    || has_control_chars(&claim.name)
                    || has_control_chars(&claim.kind)
                {
                    return write_pair_error(&mut transport, "protocol_error", actions);
                }

                match (
                    claim.code_mac,
                    claim.enrollment_token,
                    claim.signing_pub,
                    claim.enroll_proof,
                ) {
                    (Some(code_mac), None, signing_pub, enroll_proof)
                        if signing_pub.is_some() == enroll_proof.is_some() =>
                    {
                        let mac_bytes: [u8; 32] = match b64url_decode_array(&code_mac) {
                            Ok(m) => m,
                            Err(_) => {
                                return write_pair_error(&mut transport, "protocol_error", actions);
                            }
                        };

                        // Verify and burn the pairing code BEFORE inspecting roster state so
                        // revoked devices cannot probe live codes without consuming them.
                        if let Err(err) =
                            manager.verify_claim(&post_msg2_hash, &mac_bytes, self.path, now_unix)
                        {
                            return write_pair_error(
                                &mut transport,
                                err.pair_error_code(),
                                actions,
                            );
                        }

                        let claimed_key = match (signing_pub, enroll_proof) {
                            (Some(key_b64), Some(proof_b64)) => match verify_human_key_claim(
                                &key_b64,
                                &proof_b64,
                                &post_msg2_hash,
                                &peer_static,
                            ) {
                                Ok(key) => Some(key),
                                Err(code) => {
                                    return write_pair_error(&mut transport, code, actions);
                                }
                            },
                            _ => None,
                        };

                        let sas = pairing_sas(&post_msg2_hash);
                        let peer_id = match roster.record_pending_pair(
                            peer_static,
                            claimed_key,
                            claim.name.clone(),
                            claim.kind.clone(),
                            sas.clone(),
                        ) {
                            Ok(entry) => entry.device_id.clone(),
                            Err(err) => {
                                return write_pair_error(
                                    &mut transport,
                                    err.pair_error_code(),
                                    actions,
                                );
                            }
                        };

                        write_pair_success(
                            &mut transport,
                            &peer_id,
                            "pending",
                            &self.host_signing_pub,
                            PairOutcome::ResponderPending {
                                device_id: peer_id.clone(),
                                device_static_pub: peer_static,
                                device_fingerprint: fingerprint_device(&peer_static),
                                pairing_sas: sas,
                                name: claim.name,
                                kind: claim.kind,
                            },
                            actions,
                        )?;
                    }
                    (None, Some(token), Some(sig_pub_b64), Some(proof_b64)) => {
                        if !self.enrollment_policy.enabled {
                            return write_pair_error(&mut transport, "unauthorized", actions);
                        }
                        let peer_signing_pub =
                            match HybridSigningPublicKey::from_b64url(&sig_pub_b64) {
                                Ok(k) => k,
                                Err(_) => {
                                    return write_pair_error(
                                        &mut transport,
                                        "protocol_error",
                                        actions,
                                    );
                                }
                            };
                        let proof_bytes = match b64url_decode(&proof_b64) {
                            Ok(p) => p,
                            Err(_) => {
                                return write_pair_error(&mut transport, "protocol_error", actions);
                            }
                        };
                        if let Err(err) = verify_enroll_proof(
                            &peer_signing_pub,
                            &post_msg2_hash,
                            &peer_static,
                            &token.nonce,
                            &proof_bytes,
                        ) {
                            return write_pair_error(
                                &mut transport,
                                err.pair_error_code(),
                                actions,
                            );
                        }

                        let peer_id = device_id(&peer_static);
                        let (_, na) = match verify_enrollment_token(
                            &token,
                            &self.host_hello.host_id,
                            &self.host_signing_pub,
                            &peer_id,
                            now_unix,
                            &self.enrollment_policy,
                            roster,
                        ) {
                            Ok(win) => win,
                            Err(err) => {
                                return write_pair_error(
                                    &mut transport,
                                    err.pair_error_code(),
                                    actions,
                                );
                            }
                        };

                        // Burn single-use nonce BEFORE inspecting/recording peer roster state so a
                        // revoked peer presenting a stolen wildcard token consumes the token.
                        if let Err(err) = roster.burn_enrollment_nonce(&token.nonce, na, now_unix) {
                            return write_pair_error(
                                &mut transport,
                                err.pair_error_code(),
                                actions,
                            );
                        }

                        let registered_id = match roster.record_enrolled_machine(
                            peer_static,
                            peer_signing_pub.clone(),
                            claim.name.clone(),
                            claim.kind.clone(),
                        ) {
                            Ok(entry) => entry.device_id.clone(),
                            Err(err) => {
                                return write_pair_error(
                                    &mut transport,
                                    err.pair_error_code(),
                                    actions,
                                );
                            }
                        };

                        write_pair_success(
                            &mut transport,
                            &registered_id,
                            "active",
                            &self.host_signing_pub,
                            PairOutcome::ResponderEnrolled {
                                device_id: registered_id.clone(),
                                device_static_pub: peer_static,
                                device_signing_pub: peer_signing_pub,
                                token_nonce: token.nonce,
                                name: claim.name,
                                kind: claim.kind,
                            },
                            actions,
                        )?;
                    }
                    _ => {
                        return write_pair_error(&mut transport, "protocol_error", actions);
                    }
                }
                self.phase = ResponderPhase::Closed;
                Ok(())
            }
            ResponderPhase::AwaitPreamble(_) => {
                Err(CoreError::NotReady("pairing preamble not received"))
            }
            ResponderPhase::Closed => Err(CoreError::SessionClosed {
                code: 1000,
                reason: "pairing session closed".to_string(),
            }),
        }
    }
}

fn write_pair_success(
    transport: &mut NoiseTransport,
    device_id: &str,
    status: &str,
    host_signing_pub: &HybridSigningPublicKey,
    outcome: PairOutcome,
    actions: &mut Vec<PairAction>,
) -> Result<(), CoreError> {
    let resp = PairResponse::Success {
        device_id: device_id.to_string(),
        status: status.to_string(),
        host_signing_pub: host_signing_pub.to_b64url(),
    };
    let resp_json =
        Zeroizing::new(serde_json::to_vec(&resp).map_err(|err| CoreError::Json(err.to_string()))?);
    let out_ct = transport.write_message_vec(&resp_json)?;
    actions.push(PairAction::WriteBytes(encode_frame(&out_ct)?));
    actions.push(PairAction::Completed(outcome));
    actions.push(PairAction::CloseTransport("pairing complete".to_string()));
    Ok(())
}

fn write_pair_error(
    transport: &mut NoiseTransport,
    error_code: &str,
    actions: &mut Vec<PairAction>,
) -> Result<(), CoreError> {
    let resp = PairResponse::Error {
        error: error_code.to_string(),
    };
    let resp_json =
        Zeroizing::new(serde_json::to_vec(&resp).map_err(|err| CoreError::Json(err.to_string()))?);
    let out_ct = transport.write_message_vec(&resp_json)?;
    actions.push(PairAction::WriteBytes(encode_frame(&out_ct)?));
    actions.push(PairAction::Completed(PairOutcome::Rejected {
        error: error_code.to_string(),
    }));
    actions.push(PairAction::CloseTransport(error_code.to_string()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_time_classification_unwraps_ipv4_embeddings() {
        let blocked = [
            "direct:[64:ff9b::a9fe:a9fe]:9000",
            "direct:[::ffff:0:a9fe:a9fe]:9000",
            "direct:[::a9fe:a9fe]:9000",
            "direct:[2002:a9fe:a9fe::1]:9000",
            "direct:[64:ff9b::f000:1]:9000",
            "direct:[64:ff9b:1::cb00:7107]:9000",
            "direct:[fec0::1]:9000",
        ];
        for hint in blocked {
            assert_eq!(
                normalize_announced_hint(hint, ""),
                Err(DropReason::BlockedAddress),
                "{hint}"
            );
        }
        for hint in [
            "direct:[64:ff9b::cb00:7107]:9000",
            "direct:[2002:cb00:7107::1]:9000",
        ] {
            assert_eq!(normalize_announced_hint(hint, ""), Ok(hint.to_owned()));
        }
        assert!(is_lan_or_loopback_ip("64:ff9b::c0a8:101".parse().unwrap()));
        assert!(is_lan_or_loopback_ip("2002:a00:1::1".parse().unwrap()));
        assert!(!is_lan_or_loopback_ip(
            "64:ff9b::cb00:7107".parse().unwrap()
        ));
        assert_eq!(
            unmapped("::".parse().unwrap()),
            "::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            unmapped("::1".parse().unwrap()),
            "::1".parse::<IpAddr>().unwrap()
        );
    }

    fn uri_with(code: &str, hints: &[&str]) -> PairingUri {
        let host = EndpointIdentity::from_keys(
            crate::crypto::StaticKeypair::from_scalar([0x11; 32]),
            crate::crypto::SigningKeypair::from_seed([0x22; 32]),
        );
        PairingUri::new(
            "Studio",
            code,
            *host.static_key().public_bytes(),
            host.signing_key().signing_pub_hash(),
            hints.iter().map(|h| (*h).to_owned()).collect(),
            None,
            None,
        )
    }

    #[test]
    fn parse_rejects_disallowed_ipv4_embeddings_in_host_port_hints() {
        for hint in [
            "direct:[64:ff9b::a9fe:a9fe]:9000",
            "direct:[2002:a9fe:a9fe::1]:9000",
            "[::ffff:0:a9fe:a9fe]:9000",
            "overlay://[64:ff9b::e000:1]:7000",
            "overlay://[::a9fe:a9fe]:1",
            "iroh://n?addr=[64:ff9b::a9fe:a9fe]:1",
            "direct:[::]:9000",
            "direct:[64:ff9b:1::cb00:7107]:9000",
            "[64:ff9b:1::1]:9000",
            "wss://[64:ff9b:1::1]/v1/relay",
            "direct:[2001:0:4136:e378:8000:63bf:3fff:fdd2]:9000",
            "[2001::1]:9000",
            "wss://[2001::1]/v1/relay",
            "overlay://[2001::1]:7000",
        ] {
            assert!(!is_valid_pairing_endpoint_hint(hint), "{hint}");
            let uri = uri_with("TND-ABCD-EFGH-JKLM", &[hint]);
            assert!(
                matches!(uri.try_encode(), Err(CoreError::InvalidPairingUri(_))),
                "{hint}"
            );
        }
        for hint in [
            "direct:[64:ff9b::cb00:7107]:9000",
            "direct:[2002:cb00:7107::1]:9000",
            "direct:[::1]:9000",
            "direct:[2001:db8::1]:9000",
            "direct:[64:ff9b:2::1]:9000",
        ] {
            assert!(is_valid_pairing_endpoint_hint(hint), "{hint}");
            let encoded = uri_with("TND-ABCD-EFGH-JKLM", &[hint]).try_encode();
            assert!(PairingUri::parse(&encoded.unwrap()).is_ok(), "{hint}");
        }
    }

    #[test]
    fn uri_pin_merge_keeps_the_stricter_pin() {
        let host = EndpointIdentity::from_keys(
            crate::crypto::StaticKeypair::from_scalar([0x11; 32]),
            crate::crypto::SigningKeypair::from_seed([0x22; 32]),
        );
        let mut uri = uri_with("TND-ABCD-EFGH-JKLM", &["direct:192.168.1.5:7000"]);
        uri.host_id = Some("host-a".into());
        uri.rotation_seq = Some(0);
        let full = PinnedHost::with_full_key(
            None,
            *host.static_key().public_bytes(),
            host.signing_key().public_key().clone(),
            2,
        );
        assert!(
            merge_uri_pin(&full, &uri).is_none(),
            "URI seq 0 against pin seq 2"
        );
        uri.rotation_seq = None;
        let merged = merge_uri_pin(&full, &uri).unwrap();
        assert_eq!(merged.host_id.as_deref(), Some("host-a"));
        assert_eq!(merged.rotation_seq, 2);
        assert!(matches!(merged.signing_pin, SigningKeyPin::Full(_)));
        let binding = PairRouteBinding::from_uri(&uri);
        assert_eq!(binding.host_pin(Some(&full)), Ok(Some(merged)));
        assert_eq!(binding.host_pin(None), Ok(Some(uri.to_pinned_host())));
        let mut other_id = full.clone();
        other_id.host_id = Some("host-b".into());
        assert_eq!(
            binding.host_pin(Some(&other_id)),
            Err(CoreError::HostKeyUnverified)
        );
    }

    #[test]
    fn lan_code_rejects_named_direct_hints() {
        for hint in [
            "direct:host.lan:7000",
            "host.lan:7000",
            "direct:8.8.8.8:7000",
        ] {
            assert!(
                matches!(
                    uri_with("TND-ABCD-EFGH", &[hint]).try_encode(),
                    Err(CoreError::InvalidPairingUri(_))
                ),
                "{hint}"
            );
        }
        for hint in ["direct:192.168.1.5:7000", "192.168.1.5:7000"] {
            let encoded = uri_with("TND-ABCD-EFGH", &[hint]).try_encode().unwrap();
            assert!(PairingUri::parse(&encoded).is_ok(), "{hint}");
        }
        let remote = uri_with("TND-ABCD-EFGH-JKLM", &["direct:host.lan:7000"]);
        assert!(PairingUri::parse(&remote.try_encode().unwrap()).is_ok());
    }

    #[test]
    fn pairing_uri_roundtrip_and_strict_rejection() {
        let host_id_keys = EndpointIdentity::from_keys(
            crate::crypto::StaticKeypair::from_scalar([0x11; 32]),
            crate::crypto::SigningKeypair::from_seed([0x22; 32]),
        );
        let mut uri = PairingUri::new(
            "Home Server & Lab",
            "TND-4F9K-22XQ-7M3P",
            *host_id_keys.static_key().public_bytes(),
            host_id_keys.signing_key().signing_pub_hash(),
            vec![
                "direct:192.168.1.10:7000".to_string(),
                "relay:wss://relay.example/v1/relay".to_string(),
            ],
            None,
            None,
        );
        uri.relay_pub = Some(*host_id_keys.signing_key().ed25519_public_bytes());
        let encoded = uri.try_encode().unwrap();
        assert!(encoded.contains("&sh="));
        assert!(!encoded.contains("&s="));
        let parsed = PairingUri::parse(&encoded).unwrap();
        assert_eq!(parsed, uri);

        assert!(matches!(
            PairingUri::parse("https://pair?v=1"),
            Err(CoreError::InvalidPairingUri(_))
        ));
        assert!(matches!(
            PairingUri::parse("tendril://pair?v=2&host=a&code=TND-AAAA-BBBB&k=AA&sh=AA"),
            Err(CoreError::InvalidPairingUri(_))
        ));
        // Legacy `s=` parameter must be rejected.
        assert!(matches!(
            PairingUri::parse(&format!(
                "tendril://pair?v=1&host=a&code=TND-AAAA-BBBB&k={}&s={}",
                b64url_encode(host_id_keys.static_key().public_bytes()),
                b64url_encode(&[0x11; 32]),
            )),
            Err(CoreError::InvalidPairingUri(_))
        ));
        assert!(matches!(
            PairingUri::parse("tendril://pair?v=1&host=a%ZZ&code=TND-AAAA-BBBB&k=AA&sh=AA"),
            Err(CoreError::InvalidPairingUri(_))
        ));
    }

    #[test]
    fn pairing_manager_rejects_expired_burned_and_lan_on_remote() {
        let mut mgr = PairingManager::new(PairingConfig {
            ttl_secs: 900,
            max_failed_attempts: 5,
            allow_lan_code_over_remote: false,
        });
        let entropy = [10u8; 32];
        let code = mgr
            .issue_code_with_entropy(PairingCodeKind::Lan2Group, 1000, &entropy)
            .unwrap();
        assert!(code.starts_with("TND-"));
        assert_eq!(code.len(), 13);

        let h = [0x42u8; 32];
        let mac = compute_code_mac(&code, &h).unwrap();

        // Wrong attempts 1..=5 return uniform PairingCodeInvalid; 5th burns the code.
        let wrong = [0x99u8; 32];
        for t in 1..=5u64 {
            assert_eq!(
                mgr.verify_claim(&h, &wrong, PairingPathKind::Lan, 1000 + t),
                Err(CoreError::PairingCodeInvalid)
            );
        }
        assert_eq!(mgr.live_code_count(1006), 0);
        // Valid claim after burn must fail uniformly.
        assert_eq!(
            mgr.verify_claim(&h, &mac, PairingPathKind::Lan, 1007),
            Err(CoreError::PairingCodeInvalid)
        );

        // Fresh manager with zero live codes also returns uniform PairingCodeInvalid.
        let mut empty_mgr = PairingManager::new(PairingConfig::default());
        assert_eq!(
            empty_mgr.verify_claim(&h, &wrong, PairingPathKind::Lan, 1000),
            Err(CoreError::PairingCodeInvalid)
        );

        // Fresh 2-group code on remote path burns and returns PairingPathDisallowed.
        let code2 = mgr
            .issue_code_with_entropy(PairingCodeKind::Lan2Group, 2000, &entropy)
            .unwrap();
        let mac2 = compute_code_mac(&code2, &h).unwrap();
        assert!(matches!(
            mgr.verify_claim(&h, &mac2, PairingPathKind::Remote, 2001),
            Err(CoreError::PairingPathDisallowed(_))
        ));
        assert_eq!(mgr.live_code_count(2001), 0);

        // TTL expiry after 900 seconds fails uniformly with PairingCodeInvalid and clears live count.
        let code3 = mgr
            .issue_code_with_entropy(PairingCodeKind::Remote3Group, 3000, &entropy)
            .unwrap();
        let mac3 = compute_code_mac(&code3, &h).unwrap();
        assert_eq!(
            mgr.verify_claim(&h, &mac3, PairingPathKind::Remote, 3900),
            Err(CoreError::PairingCodeInvalid)
        );
        assert_eq!(mgr.live_code_count(3900), 0);

        let id = EndpointIdentity::from_keys(
            crate::crypto::StaticKeypair::from_scalar([0x41; 32]),
            crate::crypto::SigningKeypair::from_seed([0x42; 32]),
        );
        assert!(matches!(
            PairingInitiator::new(
                &id,
                "Dev",
                "cli",
                "TND-AAAA-BBBB",
                Some(PinnedHost::with_hash(
                    Some("host-1".to_string()),
                    [0u8; 32],
                    [0x11; 32],
                    0,
                )),
                None,
            ),
            Err(CoreError::IncompletePin(_))
        ));
    }

    #[test]
    fn qr_hash_pin_verifies_pre_and_post_rotation_and_rejects_mismatch() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let mut host_id = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x51; 32]),
            SigningKeypair::from_seed([0x52; 32]),
        )
        .with_host_id("qr-host");
        let dev_id = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x61; 32]),
            SigningKeypair::from_seed([0x62; 32]),
        );

        let qr = PairingUri::new(
            "QR Host",
            "TND-AAAA-BBBB",
            *host_id.static_key().public_bytes(),
            host_id.signing_key().signing_pub_hash(),
            vec![],
            Some(host_id.host_id().to_string()),
            Some(0),
        );
        let parsed = PairingUri::parse(&qr.try_encode().unwrap()).unwrap();

        // Wrong signing hash pin must abort at msg2 before sending msg3.
        let mut wrong_pin = parsed.to_pinned_host();
        wrong_pin.signing_pin = SigningKeyPin::Hash([0x99; 32]);
        let mut mgr_bad = PairingManager::new(PairingConfig::default());
        mgr_bad
            .issue_code_with_entropy(PairingCodeKind::Lan2Group, 1000, &[0x11; 32])
            .unwrap();
        let mut init_bad = PairingInitiator::new(
            &dev_id,
            "Dev",
            "cli",
            "TND-AAAA-BBBB",
            Some(wrong_pin),
            None,
        )
        .unwrap();
        let mut resp_bad = PairingResponder::new(&host_id, PairingPathKind::Lan, None).unwrap();
        let m1 = match &init_bad.start().unwrap()[0] {
            PairAction::WriteBytes(b) => b.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        let mut roster_bad = Roster::new();
        let m2 = match &resp_bad
            .feed_bytes(&m1, 1000, &mut mgr_bad, &mut roster_bad)
            .unwrap()[0]
        {
            PairAction::WriteBytes(b) => b.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(init_bad.feed_bytes(&m2), Err(CoreError::HostKeyUnverified));

        // Rotate host identity and verify original `sh=` QR pin still anchors the rotation chain.
        host_id
            .rotate(
                StaticKeypair::from_scalar([0x53; 32]),
                SigningKeypair::from_seed([0x54; 32]),
                1_795_132_800,
            )
            .unwrap();

        let mut mgr = PairingManager::new(PairingConfig::default());
        let code = mgr
            .issue_code_with_entropy(PairingCodeKind::Lan2Group, 1000, &[0x22; 32])
            .unwrap();
        let mut roster = Roster::new();
        let mut init = PairingInitiator::new(
            &dev_id,
            "Dev",
            "cli",
            &code,
            Some(parsed.to_pinned_host()),
            None,
        )
        .unwrap();
        let mut resp = PairingResponder::new(&host_id, PairingPathKind::Lan, None).unwrap();

        let msg1 = match &init.start().unwrap()[0] {
            PairAction::WriteBytes(b) => b.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        let msg2 = match &resp.feed_bytes(&msg1, 1001, &mut mgr, &mut roster).unwrap()[0] {
            PairAction::WriteBytes(b) => b.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        let msg3 = init
            .feed_bytes(&msg2)
            .unwrap()
            .into_iter()
            .find_map(|a| match a {
                PairAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .unwrap();
        let msg4 = resp
            .feed_bytes(&msg3, 1002, &mut mgr, &mut roster)
            .unwrap()
            .into_iter()
            .find_map(|a| match a {
                PairAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .unwrap();
        let outcome = init
            .feed_bytes(&msg4)
            .unwrap()
            .into_iter()
            .find_map(|a| match a {
                PairAction::Completed(o) => Some(o),
                _ => None,
            })
            .unwrap();
        assert!(matches!(
            outcome,
            PairOutcome::InitiatorPending {
                host_rotation_seq: 1,
                host_pin_verified: true,
                ref host_signing_pub,
                ..
            } if host_signing_pub == host_id.signing_key().public_key()
        ));
    }

    #[test]
    fn unpinned_v1_initiator_with_roster_floors_aborts_at_msg2_before_pair_claim() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let host_id = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x71; 32]),
            SigningKeypair::from_seed([0x72; 32]),
        )
        .with_host_id("floored-v2-host");
        let dev_id = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x81; 32]),
            SigningKeypair::from_seed([0x82; 32]),
        );

        let mut client_roster = Roster::new();
        client_roster
            .insert_pinned_host(
                host_id.host_id().to_string(),
                "Floored Host".to_string(),
                *host_id.static_key().public_bytes(),
                Some(host_id.signing_key().public_key().clone()),
                host_id.rotation_seq(),
                vec![],
            )
            .unwrap();
        client_roster
            .set_peer_min_wire_version(host_id.host_id(), WIRE_VERSION_V2)
            .unwrap();

        let mut mgr = PairingManager::new(PairingConfig::default());
        let code = mgr
            .issue_code_with_entropy(PairingCodeKind::Lan2Group, 1000, &[0x33; 32])
            .unwrap();
        let mut host_roster = Roster::new();

        let mut init = PairingInitiator::new(&dev_id, "Dev", "cli", &code, None, None)
            .unwrap()
            .with_roster_floors(&client_roster);
        let mut resp = PairingResponder::new(&host_id, PairingPathKind::Lan, None).unwrap();

        let msg1 = match &init.start().unwrap()[0] {
            PairAction::WriteBytes(b) => b.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        let msg2 = match &resp
            .feed_bytes(&msg1, 1001, &mut mgr, &mut host_roster)
            .unwrap()[0]
        {
            PairAction::WriteBytes(b) => b.clone(),
            other => panic!("unexpected: {other:?}"),
        };

        let err = init.feed_bytes(&msg2).unwrap_err();
        assert_eq!(
            err,
            CoreError::VersionDowngrade {
                peer_min: WIRE_VERSION_V2,
                negotiated: WIRE_VERSION,
            }
        );
        // Responder did not burn the code because msg3 PairClaim was never sent.
        assert_eq!(mgr.live_code_count(1001), 1);
    }

    #[test]
    fn sec06_lan_code_is_filtered_from_remote_live_codes() {
        let mut mgr = PairingManager::new(PairingConfig::default());
        assert!(mgr.allows_code_on_path(PairingCodeKind::Lan2Group, PairingPathKind::Lan));
        assert!(mgr.allows_code_on_path(PairingCodeKind::Remote3Group, PairingPathKind::Lan));
        assert!(mgr.allows_code_on_path(PairingCodeKind::Remote3Group, PairingPathKind::Remote));
        assert!(!mgr.allows_code_on_path(PairingCodeKind::Lan2Group, PairingPathKind::Remote));
        let permissive = PairingManager::new(PairingConfig {
            allow_lan_code_over_remote: true,
            ..PairingConfig::default()
        });
        assert!(
            permissive.allows_code_on_path(PairingCodeKind::Lan2Group, PairingPathKind::Remote)
        );

        mgr.issue_code_with_entropy(PairingCodeKind::Lan2Group, 1000, &[0x11; 32])
            .unwrap();
        let remote = mgr
            .issue_code_with_entropy(PairingCodeKind::Remote3Group, 1000, &[0x22; 32])
            .unwrap();
        let on_remote = mgr.allowed_live_codes(PairingPathKind::Remote, 1001);
        assert_eq!(on_remote.len(), 1);
        assert_eq!(on_remote[0].as_str(), remote);
        assert_eq!(mgr.allowed_live_codes(PairingPathKind::Lan, 1001).len(), 2);
        let after_ttl = 1000 + DEFAULT_PAIRING_TTL_SECS + 1;
        assert!(
            mgr.allowed_live_codes(PairingPathKind::Lan, after_ttl)
                .is_empty()
        );
    }

    #[test]
    fn sec05_pake_msg1_cache_snapshot_and_commit_are_replay_safe() {
        let mut mgr = PairingManager::new(PairingConfig::default());
        let (salt, mac) = ([0x01; 16], [0x02; 32]);
        assert!(mgr.is_pake_msg1_allowed(&salt, &mac, 1000));
        assert!(mgr.commit_pake_msg1(salt, mac, 1000));
        assert!(!mgr.is_pake_msg1_allowed(&salt, &mac, 1001));
        assert!(!mgr.commit_pake_msg1(salt, mac, 1001));
    }

    #[test]
    fn sec13_issue_code_refuses_beyond_live_cap() {
        let mut mgr = PairingManager::new(PairingConfig::default());
        for i in 0..MAX_LIVE_PAIRING_CODES {
            let entropy = [u8::try_from(i).unwrap() + 1; 32];
            mgr.issue_code_with_entropy(PairingCodeKind::Remote3Group, 1000, &entropy)
                .unwrap();
        }
        assert_eq!(
            mgr.issue_code_with_entropy(PairingCodeKind::Lan2Group, 1000, &[0x70; 32]),
            Err(CoreError::ProtocolViolation("too many live pairing codes"))
        );
        assert_eq!(mgr.live_code_count(1000), MAX_LIVE_PAIRING_CODES);
    }

    fn v1_claim(
        init: PairingInitiator,
        host: &EndpointIdentity,
        mgr: &mut PairingManager,
        roster: &mut Roster,
    ) -> PairOutcome {
        v1_claim_burning(init, host, mgr, roster, None)
    }

    /// Runs a v1 exchange; `burn_before_msg3` makes that code unavailable once `msg2` is sent.
    fn v1_claim_burning(
        mut init: PairingInitiator,
        host: &EndpointIdentity,
        mgr: &mut PairingManager,
        roster: &mut Roster,
        burn_before_msg3: Option<&str>,
    ) -> PairOutcome {
        fn writes(actions: &[PairAction]) -> Vec<u8> {
            let mut out = Vec::new();
            for a in actions {
                if let PairAction::WriteBytes(b) = a {
                    out.extend_from_slice(b);
                }
            }
            out
        }
        let mut resp = PairingResponder::new(host, PairingPathKind::Remote, None).unwrap();
        let mut to_resp = writes(&init.start().unwrap());
        for _ in 0..4 {
            let acts = resp.feed_bytes(&to_resp, 1000, mgr, roster).unwrap();
            if let Some(outcome) = acts.iter().find_map(|a| match a {
                PairAction::Completed(o) => Some(o.clone()),
                _ => None,
            }) {
                return outcome;
            }
            to_resp = writes(&init.feed_bytes(&writes(&acts)).unwrap());
            if let Some(code) = burn_before_msg3.filter(|_| !to_resp.is_empty()) {
                mgr.burn_pake_code(code, PairingPathKind::Remote, 1000)
                    .unwrap();
            }
        }
        panic!("responder never completed");
    }

    #[test]
    fn v1_key_claim_binding_fails_closed() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let host = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x91; 32]),
            SigningKeypair::from_seed([0x92; 32]),
        );
        let dev = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0xA1; 32]),
            SigningKeypair::from_seed([0xA2; 32]),
        );
        let cases = [
            (KeyClaimTamper::WrongTranscript, "unauthorized", true),
            (KeyClaimTamper::WrongStatic, "unauthorized", true),
            (KeyClaimTamper::CorruptEd25519, "unauthorized", true),
            (KeyClaimTamper::CorruptMlDsa, "unauthorized", true),
            (KeyClaimTamper::OtherKey, "unauthorized", true),
            (KeyClaimTamper::MalformedKey, "protocol_error", true),
            (KeyClaimTamper::MalformedProof, "protocol_error", true),
            (KeyClaimTamper::KeyOnly, "protocol_error", false),
        ];
        for (tamper, code_str, burns) in cases {
            // A legacy keyless active entry: a verified key claim would demote and enrich it.
            let mut roster = Roster::new();
            roster
                .record_pending_pair(
                    *dev.static_key().public_bytes(),
                    None,
                    "Dev".into(),
                    "cli".into(),
                    "old".into(),
                )
                .unwrap();
            roster.confirm_peer(&dev.device_id(), Some("old")).unwrap();
            let before = serde_json::to_value(&roster).unwrap();

            let mut mgr = PairingManager::new(PairingConfig::default());
            let code = mgr.issue_code(PairingCodeKind::Remote3Group, 1000).unwrap();
            let init = PairingInitiator::new(&dev, "Dev", "cli", &code, None, None)
                .unwrap()
                .with_key_claim_tamper_for_testing_only(tamper);
            assert_eq!(
                v1_claim(init, &host, &mut mgr, &mut roster),
                PairOutcome::Rejected {
                    error: code_str.to_string()
                },
                "{tamper:?}"
            );
            assert_eq!(serde_json::to_value(&roster).unwrap(), before, "{tamper:?}");
            if burns {
                assert_eq!(mgr.live_code_count(1000), 0, "{tamper:?}");
                let retry = PairingInitiator::new(&dev, "Dev", "cli", &code, None, None).unwrap();
                assert_eq!(
                    v1_claim(retry, &host, &mut mgr, &mut roster),
                    PairOutcome::Rejected {
                        error: "unauthorized".to_string()
                    },
                    "{tamper:?}"
                );
                assert_eq!(serde_json::to_value(&roster).unwrap(), before, "{tamper:?}");
            } else {
                assert_eq!(mgr.live_code_count(1000), 1, "{tamper:?}");
            }
        }
    }

    #[test]
    fn v1_key_claim_code_is_burned_before_proof_is_checked() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let host = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x91; 32]),
            SigningKeypair::from_seed([0x92; 32]),
        );
        let dev = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0xA1; 32]),
            SigningKeypair::from_seed([0xA2; 32]),
        );
        for tamper in [
            KeyClaimTamper::MalformedProof,
            KeyClaimTamper::MalformedKey,
            KeyClaimTamper::CorruptEd25519,
        ] {
            let mut roster = Roster::new();
            let mut mgr = PairingManager::new(PairingConfig::default());
            let code = mgr.issue_code(PairingCodeKind::Remote3Group, 1000).unwrap();
            let init = PairingInitiator::new(&dev, "Dev", "cli", &code, None, None)
                .unwrap()
                .with_key_claim_tamper_for_testing_only(tamper);
            assert_eq!(
                v1_claim_burning(init, &host, &mut mgr, &mut roster, Some(&code)),
                PairOutcome::Rejected {
                    error: "unauthorized".to_string()
                },
                "{tamper:?}"
            );
            assert!(roster.get(&dev.device_id()).is_none(), "{tamper:?}");
        }
    }

    #[test]
    fn v1_keyless_repair_cannot_reconfirm_pending_key() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let host = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x91; 32]),
            SigningKeypair::from_seed([0x92; 32]),
        );
        let dev = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0xA1; 32]),
            SigningKeypair::from_seed([0xA2; 32]),
        );
        let mut roster = Roster::new();
        let mut mgr = PairingManager::new(PairingConfig::default());
        let code = mgr.issue_code(PairingCodeKind::Remote3Group, 1000).unwrap();
        let init = PairingInitiator::new(&dev, "Dev", "cli", &code, None, None).unwrap();
        let PairOutcome::ResponderPending { pairing_sas, .. } =
            v1_claim(init, &host, &mut mgr, &mut roster)
        else {
            panic!("keyed pairing failed");
        };
        let before = serde_json::to_value(&roster).unwrap();

        let code = mgr.issue_code(PairingCodeKind::Remote3Group, 1000).unwrap();
        let legacy = PairingInitiator::new(&dev, "Dev", "cli", &code, None, None)
            .unwrap()
            .with_key_claim_tamper_for_testing_only(KeyClaimTamper::Omit);
        assert_eq!(
            v1_claim(legacy, &host, &mut mgr, &mut roster),
            PairOutcome::Rejected {
                error: "protocol_error".to_string()
            }
        );
        assert_eq!(serde_json::to_value(&roster).unwrap(), before);
        assert_eq!(roster.lookup_active_signing_key(&dev.device_id()), None);
        roster
            .confirm_peer(&dev.device_id(), Some(&pairing_sas))
            .unwrap();
        assert_eq!(
            roster.lookup_active_signing_key(&dev.device_id()),
            Some(dev.signing_key().public_key().clone())
        );
    }
}
