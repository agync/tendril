//! Pairing code management, URI codec, and Sans-I/O pairing state machines.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use snow::params::NoiseParams;
use snow::{HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::crypto::{
    CODE_ALPHABET, b64url_decode_array, b64url_encode, compute_code_mac, device_id,
    fingerprint_device, has_control_chars, is_valid_ed25519_public_key, is_valid_x25519_public_key,
    new_noise_builder, pairing_sas, random_bytes, verify_code_mac,
};
use crate::error::CoreError;
use crate::identity::{EndpointIdentity, RotationRecord, verify_rotation_chain};
use crate::roster::Roster;
use crate::wire::{
    HostHello, Intent, MAX_FRAME_LEN, NOISE_PATTERN, PairClaim, PairResponse, Preamble,
    ResumableFrameReader, encode_frame,
};

/// Default lifetime of a newly issued pairing code (`15` minutes).
pub const DEFAULT_PAIRING_TTL_SECS: u64 = 900;

/// Default maximum failed claim attempts across live pairing codes before burn.
pub const DEFAULT_MAX_PAIRING_ATTEMPTS: u32 = 5;

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

/// Tracks issued pairing codes, TTL expiration, single-use burn, and constant-time retry budgets.
#[derive(Debug, Default)]
pub struct PairingManager {
    config: PairingConfig,
    codes: Vec<IssuedCode>,
}

impl PairingManager {
    /// Creates a new pairing code manager with the supplied policy.
    #[must_use]
    pub fn new(config: PairingConfig) -> Self {
        Self {
            config,
            codes: Vec::new(),
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
            if self.codes.iter().any(|c| c.expired && !c.burned) {
                return Err(CoreError::PairingCodeExpired);
            }
            if self.codes.iter().any(|c| c.burned) {
                return Err(CoreError::PairingCodeBurned);
            }
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
            let entry = &mut self.codes[idx];
            entry.burned = true;
            if entry.kind == PairingCodeKind::Lan2Group
                && path == PairingPathKind::Remote
                && !self.config.allow_lan_code_over_remote
            {
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

        if live_indices.iter().all(|&i| self.codes[i].burned) {
            Err(CoreError::PairingCodeBurned)
        } else {
            Err(CoreError::PairingCodeInvalid)
        }
    }
}

/// Structured QR / out-of-band pairing URI (`tendril://pair?v=1&...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingUri {
    pub host_name: String,
    pub code: String,
    pub host_static_pub: [u8; 32],
    pub host_signing_pub: [u8; 32],
    pub endpoints: Vec<String>,
    pub host_id: Option<String>,
    pub rotation_seq: Option<u64>,
}

impl PairingUri {
    /// Converts this URI's out-of-band cryptographic pin into a [`PinnedHost`].
    #[must_use]
    pub fn to_pinned_host(&self) -> PinnedHost {
        PinnedHost {
            host_id: self.host_id.clone(),
            static_pub: self.host_static_pub,
            signing_pub: self.host_signing_pub,
            rotation_seq: self.rotation_seq.unwrap_or(0),
        }
    }

    /// Encodes this pairing payload as a `tendril://pair?v=1&...` URI.
    #[must_use]
    pub fn encode(&self) -> String {
        let ep_joined = self
            .endpoints
            .iter()
            .map(|e| pct_encode(e))
            .collect::<Vec<_>>()
            .join(",");
        let mut out = format!(
            "tendril://pair?v=1&host={}&code={}&k={}&s={}",
            pct_encode(&self.host_name),
            pct_encode(&self.code),
            b64url_encode(&self.host_static_pub),
            b64url_encode(&self.host_signing_pub),
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
            if !matches!(k, "v" | "host" | "code" | "k" | "s" | "id" | "seq" | "ep") {
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

        let s_raw = params
            .get("s")
            .ok_or_else(|| CoreError::InvalidPairingUri("missing host signing key s".into()))?;
        let host_signing_pub: [u8; 32] = b64url_decode_array(s_raw)?;
        if !is_valid_ed25519_public_key(&host_signing_pub) {
            return Err(CoreError::InvalidPairingUri(
                "invalid host signing key".into(),
            ));
        }

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
            host_signing_pub,
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
    {
        return false;
    }
    if host.is_empty()
        || host
            .trim_end_matches('.')
            .eq_ignore_ascii_case("metadata.google.internal")
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
    pub signing_pub: [u8; 32],
    pub rotation_seq: u64,
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
        host_signing_pub: [u8; 32],
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
    Rejected {
        error: String,
    },
}

enum InitiatorPhase {
    Init(Box<HandshakeState>),
    AwaitMsg2(Box<HandshakeState>),
    AwaitResponse {
        transport: Box<TransportState>,
        host_id: String,
        host_static_pub: [u8; 32],
        expected_signing_pub: Option<[u8; 32]>,
        verified_seq: Option<u64>,
        presented_rotation: Vec<RotationRecord>,
        pairing_sas: String,
        host_pin_verified: bool,
    },
    Closed,
}

/// Sans-I/O pairing initiator state machine (`intent = 0x02`).
pub struct PairingInitiator {
    phase: InitiatorPhase,
    reader: ResumableFrameReader,
    code: Zeroizing<String>,
    device_name: String,
    device_kind: String,
    local_static_pub: [u8; 32],
    pinned_host: Option<PinnedHost>,
}

impl fmt::Debug for PairingInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingInitiator")
            .field("device_id", &device_id(&self.local_static_pub))
            .field("code", &"<redacted>")
            .finish()
    }
}

impl PairingInitiator {
    /// Creates a new initiator ready to emit the pairing preamble and `msg1`.
    pub fn new(
        identity: &EndpointIdentity,
        device_name: impl Into<String>,
        device_kind: impl Into<String>,
        code: impl Into<String>,
        pinned_host: Option<PinnedHost>,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        if let Some(ref pin) = pinned_host
            && (!is_valid_x25519_public_key(&pin.static_pub)
                || !is_valid_ed25519_public_key(&pin.signing_pub))
        {
            return Err(CoreError::IncompletePin(
                pin.host_id
                    .clone()
                    .unwrap_or_else(|| "pinned_host".to_string()),
            ));
        }
        let params: NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|err| CoreError::Noise(format!("{err}")))?;
        let preamble = Preamble::v1(Intent::Pair).encode();
        let mut builder = new_noise_builder(params)
            .local_private_key(identity.static_key().secret_bytes())
            .map_err(|err| CoreError::Noise(format!("{err}")))?
            .prologue(&preamble)
            .map_err(|err| CoreError::Noise(format!("{err}")))?;
        if let Some(ref eph) = fixed_ephemeral {
            builder = builder.fixed_ephemeral_key_for_testing_only(eph);
        }
        let hs = builder
            .build_initiator()
            .map_err(|err| CoreError::Noise(format!("{err}")))?;

        Ok(Self {
            phase: InitiatorPhase::Init(Box::new(hs)),
            reader: ResumableFrameReader::new(),
            code: Zeroizing::new(code.into()),
            device_name: device_name.into(),
            device_kind: device_kind.into(),
            local_static_pub: *identity.static_key().public_bytes(),
            pinned_host,
        })
    }

    /// Emits the 6-byte `Intent::Pair` preamble concatenated with Noise `msg1`.
    pub fn start(&mut self) -> Result<Vec<PairAction>, CoreError> {
        let prev = std::mem::replace(&mut self.phase, InitiatorPhase::Closed);
        let InitiatorPhase::Init(mut hs) = prev else {
            return Err(CoreError::NotReady("pairing initiator already started"));
        };
        let mut msg1 = vec![0u8; MAX_FRAME_LEN];
        let n = hs
            .write_message(&[], &mut msg1)
            .map_err(|err| CoreError::Noise(format!("{err}")))?;
        let frame = encode_frame(&msg1[..n])?;
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
                let mut pt = Zeroizing::new(vec![0u8; MAX_FRAME_LEN]);
                let n_pt = hs
                    .read_message(body, &mut pt)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let host_hello: HostHello = serde_json::from_slice(&pt[..n_pt])
                    .map_err(|err| CoreError::Json(err.to_string()))?;
                if host_hello.proto_version != 1 {
                    return Err(CoreError::UnsupportedVersion(host_hello.proto_version));
                }
                if host_hello.host_id.is_empty() || has_control_chars(&host_hello.host_id) {
                    return Err(CoreError::ProtocolViolation("invalid host_id in HostHello"));
                }

                let remote_static: [u8; 32] = hs
                    .get_remote_static()
                    .ok_or(CoreError::ProtocolViolation(
                        "missing responder static key in msg2",
                    ))?
                    .try_into()
                    .map_err(|_| CoreError::ProtocolViolation("invalid responder static length"))?;
                if !is_valid_x25519_public_key(&remote_static) {
                    return Err(CoreError::HostKeyUnverified);
                }

                let mut expected_signing_pub = None;
                let mut verified_seq = None;
                if let Some(pin) = &self.pinned_host {
                    if let Some(ref exp_id) = pin.host_id
                        && exp_id != &host_hello.host_id
                    {
                        return Err(CoreError::HostKeyUnverified);
                    }
                    let presented_signing = if host_hello.rotation.is_empty() {
                        pin.signing_pub
                    } else {
                        let last = host_hello
                            .rotation
                            .last()
                            .ok_or(CoreError::HostKeyUnverified)?;
                        b64url_decode_array(&last.new_signing_pub)
                            .map_err(|_| CoreError::HostKeyUnverified)?
                    };
                    let verify_res = if pin.rotation_seq == 0
                        && !host_hello.rotation.is_empty()
                        && host_hello.rotation[0].seq == 1
                        && remote_static == pin.static_pub
                        && presented_signing == pin.signing_pub
                    {
                        let last_seq = host_hello.rotation.last().map_or(0, |r| r.seq);
                        verify_rotation_chain(
                            &pin.signing_pub,
                            &pin.static_pub,
                            last_seq,
                            &host_hello.rotation,
                            &remote_static,
                            &presented_signing,
                        )
                    } else {
                        verify_rotation_chain(
                            &pin.signing_pub,
                            &pin.static_pub,
                            pin.rotation_seq,
                            &host_hello.rotation,
                            &remote_static,
                            &presented_signing,
                        )
                    };
                    match verify_res {
                        Ok(seq) => {
                            expected_signing_pub = Some(presented_signing);
                            verified_seq = Some(seq);
                        }
                        Err(err @ CoreError::RotationForkDetected { .. }) => return Err(err),
                        Err(_) => return Err(CoreError::HostKeyUnverified),
                    }
                }

                let h: [u8; 32] = hs
                    .get_handshake_hash()
                    .try_into()
                    .map_err(|_| CoreError::Noise("unexpected handshake hash length".into()))?;
                let sas = pairing_sas(&h);
                actions.push(PairAction::SasReady {
                    pairing_sas: sas.clone(),
                    host_id: host_hello.host_id.clone(),
                    host_static_pub: remote_static,
                });

                let mac = compute_code_mac(&self.code, &h)?;
                let claim = PairClaim {
                    name: self.device_name.clone(),
                    kind: self.device_kind.clone(),
                    code_mac: b64url_encode(&mac),
                };
                let claim_json = Zeroizing::new(
                    serde_json::to_vec(&claim).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let mut msg3 = vec![0u8; MAX_FRAME_LEN];
                let n3 = hs
                    .write_message(&claim_json, &mut msg3)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let msg3_frame = encode_frame(&msg3[..n3])?;
                actions.push(PairAction::WriteBytes(msg3_frame));

                let transport = hs
                    .into_transport_mode()
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                self.phase = InitiatorPhase::AwaitResponse {
                    transport: Box::new(transport),
                    host_id: host_hello.host_id,
                    host_static_pub: remote_static,
                    expected_signing_pub,
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
                expected_signing_pub,
                verified_seq,
                presented_rotation,
                pairing_sas,
                host_pin_verified,
            } => {
                let mut pt = Zeroizing::new(vec![0u8; MAX_FRAME_LEN]);
                let n = transport
                    .read_message(body, &mut pt)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let resp: PairResponse = serde_json::from_slice(&pt[..n])
                    .map_err(|err| CoreError::Json(err.to_string()))?;
                match resp {
                    PairResponse::Success {
                        device_id: resp_dev_id,
                        status,
                        host_signing_pub,
                    } => {
                        if resp_dev_id != device_id(&self.local_static_pub) || status != "pending" {
                            return Err(CoreError::ProtocolViolation(
                                "unexpected pair response fields",
                            ));
                        }
                        let host_signing: [u8; 32] = b64url_decode_array(&host_signing_pub)?;
                        if !is_valid_ed25519_public_key(&host_signing) {
                            return Err(CoreError::IncompletePin(host_id));
                        }
                        if let Some(expected) = expected_signing_pub
                            && expected != host_signing
                        {
                            return Err(CoreError::HostKeyUnverified);
                        }
                        let host_rotation_seq = if let Some(seq) = verified_seq {
                            seq
                        } else if let Some(first) = presented_rotation.first() {
                            let root_sig: [u8; 32] = b64url_decode_array(&first.prev_signing_pub)
                                .map_err(|_| CoreError::HostKeyUnverified)?;
                            verify_rotation_chain(
                                &root_sig,
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
                        actions.push(PairAction::Completed(PairOutcome::InitiatorPending {
                            device_id: resp_dev_id,
                            host_id,
                            host_static_pub,
                            host_signing_pub: host_signing,
                            host_rotation_seq,
                            pairing_sas,
                            host_pin_verified,
                        }));
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
    AwaitPreamble(Box<HandshakeState>),
    AwaitMsg1(Box<HandshakeState>),
    AwaitMsg3 {
        hs: Box<HandshakeState>,
        post_msg2_hash: [u8; 32],
    },
    Closed,
}

/// Sans-I/O pairing responder state machine (`intent = 0x02`).
pub struct PairingResponder {
    phase: ResponderPhase,
    reader: ResumableFrameReader,
    host_hello: HostHello,
    host_signing_pub: [u8; 32],
    path: PairingPathKind,
}

impl fmt::Debug for PairingResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingResponder")
            .field("host_id", &self.host_hello.host_id)
            .field("path", &self.path)
            .finish()
    }
}

impl PairingResponder {
    /// Creates a new pairing responder bound to `identity` and transport classification `path`.
    pub fn new(
        identity: &EndpointIdentity,
        path: PairingPathKind,
        fixed_ephemeral: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        let params: NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|err| CoreError::Noise(format!("{err}")))?;
        let preamble = Preamble::v1(Intent::Pair).encode();
        let mut builder = new_noise_builder(params)
            .local_private_key(identity.static_key().secret_bytes())
            .map_err(|err| CoreError::Noise(format!("{err}")))?
            .prologue(&preamble)
            .map_err(|err| CoreError::Noise(format!("{err}")))?;
        if let Some(ref eph) = fixed_ephemeral {
            builder = builder.fixed_ephemeral_key_for_testing_only(eph);
        }
        let hs = builder
            .build_responder()
            .map_err(|err| CoreError::Noise(format!("{err}")))?;

        Ok(Self {
            phase: ResponderPhase::AwaitPreamble(Box::new(hs)),
            reader: ResumableFrameReader::with_preamble(),
            host_hello: HostHello {
                host_id: identity.host_id().to_string(),
                proto_version: 1,
                rotation: identity.rotation_chain().to_vec(),
            },
            host_signing_pub: *identity.signing_key().public_bytes(),
            path,
        })
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
                let mut pt = Zeroizing::new(vec![0u8; MAX_FRAME_LEN]);
                let n = hs
                    .read_message(body, &mut pt)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                if n != 0 {
                    return Err(CoreError::ProtocolViolation(
                        "msg1 must carry empty payload",
                    ));
                }

                let hello_json = Zeroizing::new(
                    serde_json::to_vec(&self.host_hello)
                        .map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let mut msg2 = vec![0u8; MAX_FRAME_LEN];
                let n2 = hs
                    .write_message(&hello_json, &mut msg2)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let post_msg2_hash: [u8; 32] = hs
                    .get_handshake_hash()
                    .try_into()
                    .map_err(|_| CoreError::Noise("unexpected handshake hash length".into()))?;
                let frame2 = encode_frame(&msg2[..n2])?;
                actions.push(PairAction::WriteBytes(frame2));
                self.phase = ResponderPhase::AwaitMsg3 { hs, post_msg2_hash };
                Ok(())
            }
            ResponderPhase::AwaitMsg3 {
                mut hs,
                post_msg2_hash,
            } => {
                let mut pt = Zeroizing::new(vec![0u8; MAX_FRAME_LEN]);
                let n_pt = hs
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

                let mut transport = hs
                    .into_transport_mode()
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;

                let claim: PairClaim = match serde_json::from_slice(&pt[..n_pt]) {
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

                let mac_bytes: [u8; 32] = match b64url_decode_array(&claim.code_mac) {
                    Ok(m) => m,
                    Err(_) => {
                        return write_pair_error(&mut transport, "protocol_error", actions);
                    }
                };

                // Verify and burn the pairing code BEFORE inspecting roster state so revoked
                // devices cannot probe live codes without consuming them.
                if let Err(err) =
                    manager.verify_claim(&post_msg2_hash, &mac_bytes, self.path, now_unix)
                {
                    return write_pair_error(&mut transport, err.pair_error_code(), actions);
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
                        return write_pair_error(&mut transport, err.pair_error_code(), actions);
                    }
                };

                let resp = PairResponse::Success {
                    device_id: peer_id.clone(),
                    status: "pending".to_string(),
                    host_signing_pub: b64url_encode(&self.host_signing_pub),
                };
                let resp_json = Zeroizing::new(
                    serde_json::to_vec(&resp).map_err(|err| CoreError::Json(err.to_string()))?,
                );
                let mut out_ct = vec![0u8; MAX_FRAME_LEN];
                let n_ct = transport
                    .write_message(&resp_json, &mut out_ct)
                    .map_err(|err| CoreError::Noise(format!("{err}")))?;
                let resp_frame = encode_frame(&out_ct[..n_ct])?;
                actions.push(PairAction::WriteBytes(resp_frame));
                actions.push(PairAction::Completed(PairOutcome::ResponderPending {
                    device_id: peer_id,
                    device_static_pub: peer_static,
                    device_fingerprint: fingerprint_device(&peer_static),
                    pairing_sas: sas,
                    name: claim.name,
                    kind: claim.kind,
                }));
                actions.push(PairAction::CloseTransport("pairing complete".to_string()));
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

fn write_pair_error(
    transport: &mut TransportState,
    error_code: &str,
    actions: &mut Vec<PairAction>,
) -> Result<(), CoreError> {
    let resp = PairResponse::Error {
        error: error_code.to_string(),
    };
    let resp_json =
        Zeroizing::new(serde_json::to_vec(&resp).map_err(|err| CoreError::Json(err.to_string()))?);
    let mut out_ct = vec![0u8; MAX_FRAME_LEN];
    let n_ct = transport
        .write_message(&resp_json, &mut out_ct)
        .map_err(|err| CoreError::Noise(format!("{err}")))?;
    actions.push(PairAction::WriteBytes(encode_frame(&out_ct[..n_ct])?));
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
            host_signing_pub: *host_id_keys.signing_key().public_bytes(),
            endpoints: vec![
                "direct:192.168.1.10:7000".to_string(),
                "relay:wss://relay.example/v1/relay".to_string(),
            ],
            host_id: None,
            rotation_seq: None,
        };
        let encoded = uri.encode();
        let parsed = PairingUri::parse(&encoded).unwrap();
        assert_eq!(parsed, uri);

        assert!(matches!(
            PairingUri::parse("https://pair?v=1"),
            Err(CoreError::InvalidPairingUri(_))
        ));
        assert!(matches!(
            PairingUri::parse("tendril://pair?v=2&host=a&code=b&k=AA&s=AA"),
            Err(CoreError::InvalidPairingUri(_))
        ));
        assert!(matches!(
            PairingUri::parse("tendril://pair?v=1&host=a%ZZ&code=b&k=AA&s=AA"),
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

        // Wrong attempts 1..=4 keep code alive, 5th burns it.
        let wrong = [0x99u8; 32];
        for _ in 0..4 {
            assert_eq!(
                mgr.verify_claim(&h, &wrong, PairingPathKind::Lan, 1001),
                Err(CoreError::PairingCodeInvalid)
            );
        }
        assert_eq!(
            mgr.verify_claim(&h, &wrong, PairingPathKind::Lan, 1002),
            Err(CoreError::PairingCodeBurned)
        );
        assert_eq!(mgr.live_code_count(1002), 0);
        // Valid claim after burn must fail.
        assert_eq!(
            mgr.verify_claim(&h, &mac, PairingPathKind::Lan, 1003),
            Err(CoreError::PairingCodeBurned)
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

        // TTL expiry after 900 seconds.
        let code3 = mgr
            .issue_code_with_entropy(PairingCodeKind::Remote3Group, 3000, &entropy)
            .unwrap();
        let mac3 = compute_code_mac(&code3, &h).unwrap();
        assert_eq!(
            mgr.verify_claim(&h, &mac3, PairingPathKind::Remote, 3900),
            Err(CoreError::PairingCodeExpired)
        );

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
                Some(PinnedHost {
                    host_id: Some("host-1".to_string()),
                    static_pub: [0u8; 32],
                    signing_pub: [0x11; 32],
                    rotation_seq: 0,
                }),
                None,
            ),
            Err(CoreError::IncompletePin(_))
        ));
    }
}
