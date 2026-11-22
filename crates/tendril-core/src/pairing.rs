//! Pairing code management, URI codec, and Sans-I/O pairing state machines.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use zeroize::Zeroizing;

use crate::crypto::{
    CODE_ALPHABET, HYBRID_SIGNING_HASH_LEN, HybridSigningPublicKey, SigningKeypair, b64url_decode,
    b64url_decode_array, b64url_encode, compute_code_mac, device_id, fingerprint_device,
    has_control_chars, is_valid_x25519_public_key, pairing_sas, random_bytes, verify_code_mac,
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
use crate::roster::{AnchorState, Roster};
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

/// Structured QR / out-of-band pairing URI (`tendril://pair?v=1&...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingUri {
    pub host_name: String,
    pub code: String,
    pub host_static_pub: [u8; 32],
    pub host_signing_pub_hash: [u8; HYBRID_SIGNING_HASH_LEN],
    pub endpoints: Vec<String>,
    pub host_id: Option<String>,
    pub rotation_seq: Option<u64>,
}

impl PairingUri {
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

    /// Encodes this pairing payload as a `tendril://pair?v=1&...` URI using `sh=` hash pinning.
    #[must_use]
    pub fn encode(&self) -> String {
        let ep_joined = self
            .endpoints
            .iter()
            .map(|e| pct_encode(e))
            .collect::<Vec<_>>()
            .join(",");
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
        if !ep_joined.is_empty() {
            out.push_str("&ep=");
            out.push_str(&ep_joined);
        }
        out
    }

    /// Parses and validates a `tendril://pair?v=1&...` URI.
    pub fn parse(uri: &str) -> Result<Self, CoreError> {
        let query = uri
            .strip_prefix("tendril://pair?")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing tendril://pair? prefix".into()))?;
        let mut params = BTreeMap::new();
        for pair in query.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| CoreError::InvalidPairingUri("malformed query pair".into()))?;
            if !matches!(k, "v" | "host" | "code" | "k" | "sh" | "id" | "seq" | "ep") {
                return Err(CoreError::InvalidPairingUri(format!(
                    "unknown query parameter {k}"
                )));
            }
            if params.insert(k, v).is_some() {
                return Err(CoreError::InvalidPairingUri(format!(
                    "duplicate query parameter {k}"
                )));
            }
        }
        if params.get("v").copied() != Some("1") {
            return Err(CoreError::InvalidPairingUri(
                "unsupported or missing pairing URI version".into(),
            ));
        }

        let host_raw = params
            .get("host")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing host parameter".into()))?;
        let host_name = pct_decode(host_raw)?;
        if host_name.is_empty() || has_control_chars(&host_name) {
            return Err(CoreError::InvalidPairingUri(
                "invalid or empty host parameter".into(),
            ));
        }
        let code_raw = params
            .get("code")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing code parameter".into()))?;
        let code = pct_decode(code_raw)?;
        if has_control_chars(&code) || !is_valid_pairing_code_format(&code) {
            return Err(CoreError::InvalidPairingUri(
                "invalid pairing code format".into(),
            ));
        }

        let k_raw = params
            .get("k")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing host static key k".into()))?;
        let host_static_pub: [u8; 32] = b64url_decode_array(k_raw)?;
        if !is_valid_x25519_public_key(&host_static_pub) {
            return Err(CoreError::InvalidPairingUri(
                "invalid or low-order host static key".into(),
            ));
        }

        let sh_raw = params
            .get("sh")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing host signing hash sh".into()))?;
        let host_signing_pub_hash: [u8; HYBRID_SIGNING_HASH_LEN] = b64url_decode_array(sh_raw)?;

        let host_id = match params.get("id").copied() {
            None => None,
            Some(id_raw) => {
                let dec = pct_decode(id_raw)?;
                if dec.is_empty() || has_control_chars(&dec) {
                    return Err(CoreError::InvalidPairingUri("invalid id parameter".into()));
                }
                Some(dec)
            }
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

        let endpoints = match params.get("ep").copied() {
            None | Some("") => Vec::new(),
            Some(ep_raw) => {
                let mut list = Vec::new();
                for part in ep_raw.split(',') {
                    let dec = pct_decode(part)?;
                    if dec.is_empty()
                        || has_control_chars(&dec)
                        || !is_valid_pairing_endpoint_hint(&dec)
                    {
                        return Err(CoreError::InvalidPairingUri(
                            "invalid endpoint in ep list".into(),
                        ));
                    }
                    list.push(dec);
                }
                list
            }
        };

        Ok(Self {
            host_name,
            code,
            host_static_pub,
            host_signing_pub_hash,
            endpoints,
            host_id,
            rotation_seq,
        })
    }
}

fn is_valid_pairing_code_format(code: &str) -> bool {
    let mut parts = code.split('-');
    if parts.next() != Some("TND") {
        return false;
    }
    let groups: Vec<&str> = parts.collect();
    if !matches!(groups.len(), 2 | 3) {
        return false;
    }
    groups.iter().all(|g| {
        g.len() == 4
            && g.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    })
}

fn is_disallowed_hint_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified() || v4.is_multicast(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_disallowed_hint_ip(IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            let is_link_local = (seg[0] & 0xffc0) == 0xfe80;
            let is_aws_metadata = v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);
            is_link_local || is_aws_metadata || v6.is_unspecified() || v6.is_multicast()
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

fn is_valid_pairing_endpoint_hint(ep: &str) -> bool {
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
            },
            device_name: device_name.into(),
            device_kind: device_kind.into(),
            local_static_pub: *identity.static_key().public_bytes(),
            pinned_host,
            v2_floored_static_pubs: BTreeSet::new(),
            v2_floored_host_ids: BTreeSet::new(),
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
                if let Some(pin) = &self.pinned_host {
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
                let claim = match &self.auth {
                    InitiatorAuth::Human { code } => {
                        actions.push(PairAction::SasReady {
                            pairing_sas: sas.clone(),
                            host_id: host_hello.host_id.clone(),
                            host_static_pub: remote_static,
                        });
                        let mac = compute_code_mac(code, &h)?;
                        PairClaim {
                            name: self.device_name.clone(),
                            kind: self.device_kind.clone(),
                            code_mac: Some(b64url_encode(&mac)),
                            enrollment_token: None,
                            signing_pub: None,
                            enroll_proof: None,
                        }
                    }
                    InitiatorAuth::M2m { token, signing_key } => {
                        let proof = sign_enroll_proof(
                            signing_key,
                            &h,
                            &self.local_static_pub,
                            &token.nonce,
                        )?;
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
                    (Some(code_mac), None, None, None) => {
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

                        let sas = pairing_sas(&post_msg2_hash);
                        let peer_id = match roster.record_pending_pair(
                            peer_static,
                            None,
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
    fn pairing_uri_roundtrip_and_strict_rejection() {
        let host_id_keys = EndpointIdentity::from_keys(
            crate::crypto::StaticKeypair::from_scalar([0x11; 32]),
            crate::crypto::SigningKeypair::from_seed([0x22; 32]),
        );
        let uri = PairingUri {
            host_name: "Home Server & Lab".to_string(),
            code: "TND-4F9K-22XQ".to_string(),
            host_static_pub: *host_id_keys.static_key().public_bytes(),
            host_signing_pub_hash: host_id_keys.signing_key().signing_pub_hash(),
            endpoints: vec![
                "direct:192.168.1.10:7000".to_string(),
                "relay:wss://relay.example/v1/relay".to_string(),
            ],
            host_id: None,
            rotation_seq: None,
        };
        let encoded = uri.encode();
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

        let qr = PairingUri {
            host_name: "QR Host".into(),
            code: "TND-AAAA-BBBB".into(),
            host_static_pub: *host_id.static_key().public_bytes(),
            host_signing_pub_hash: host_id.signing_key().signing_pub_hash(),
            endpoints: vec![],
            host_id: Some(host_id.host_id().to_string()),
            rotation_seq: Some(0),
        };
        let parsed = PairingUri::parse(&qr.encode()).unwrap();

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
}
