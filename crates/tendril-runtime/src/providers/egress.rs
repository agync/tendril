//! Dial-time egress policy for pairing URI hints and stored routes (`spec/pairing-v1.md`).
//!
//! Every check is enforced through the connect that uses it: `direct:` takes IP literals only,
//! `overlay://` is resolved once here and dialed as a checked literal, the WebSocket family
//! (`ws(s)://`, relays, brokers) is checked inside the single lookup of the dialer through an
//! [`AddrPolicy`] without rewriting the URL, and `iroh://` hints are reduced to the relay map
//! of the lookup-free hint dialer.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tendril_core::pairing::{PairingCodeKind, PairingPathKind, classify_endpoint_hint};
use tendril_core::policy::ProviderId;
use tendril_core::roster::RouteSource;
use tokio::time::timeout;

#[cfg(feature = "p2p-iroh")]
use super::p2p::{P2pRelayMode, filter_p2p_hint};
use crate::error::RuntimeError;
use crate::provider::{PathDialer, PathStream};
use crate::redact::{redact_host, redact_text};

/// Bound on one host lookup; a timeout rejects the hint.
pub const EGRESS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Destination class of one canonical address (IPv6 forms with a fixed IPv4 embedding are
/// classified by the embedded address: mapped, translated, compatible, NAT64 `64:ff9b::/96`
/// and 6to4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestClass {
    /// Never dialed: unspecified, multicast, broadcast, link-local, `0.0.0.0/8`,
    /// `240.0.0.0/4`, cloud metadata, site-local `fec0::/10` and local-use NAT64
    /// `64:ff9b:1::/48`.
    Blocked,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918, IPv6 ULA `fc00::/7`.
    Lan,
    /// RFC 6598 `100.64.0.0/10`.
    Overlay,
    /// Anything else.
    Public,
}

/// The IPv4 address an IPv6 form embeds, so a destination is classified by the IPv4 address a
/// translator or tunnel would reach. Each prefix below has a fixed embedding:
///
/// - IPv4-mapped `::ffff:0:0/96` and IPv4-translated `::ffff:0:0:0/96` (RFC 4291, RFC 2765);
/// - IPv4-compatible `::/96` (deprecated, RFC 4291) except `::` and `::1`;
/// - NAT64 well-known `64:ff9b::/96` (RFC 6052): DNS64 networks synthesize these for every
///   IPv4-only name, so the embedded address is classified rather than the prefix blocked;
/// - 6to4 `2002::/16` (RFC 3056, deprecated by RFC 7526): bits 16..48 name the IPv4 relay
///   endpoint, so a 6to4 address of a public host stays usable.
///
/// The local-use NAT64 prefix `64:ff9b:1::/48` (RFC 8215) has an operator-chosen RFC 6052
/// prefix length, so its embedded IPv4 address cannot be located; [`classify_destination`]
/// blocks that prefix outright.
fn canonical(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };
    let s = v6.segments();
    let tail = || {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    };
    match s {
        [0, 0, 0, 0, 0, 0xffff, _, _]
        | [0, 0, 0, 0, 0xffff, 0, _, _]
        | [0x0064, 0xff9b, 0, 0, 0, 0, _, _] => tail(),
        [0, 0, 0, 0, 0, 0, hi, lo] if hi != 0 || lo > 1 => tail(),
        [0x2002, hi, lo, ..] => {
            let [a, b] = hi.to_be_bytes();
            let [c, d] = lo.to_be_bytes();
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        }
        _ => ip,
    }
}

/// Classifies `ip` into its [`DestClass`].
#[must_use]
pub fn classify_destination(ip: IpAddr) -> DestClass {
    let ip = canonical(ip);
    if super::is_metadata_or_link_local_ip(ip) {
        return DestClass::Blocked;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_multicast() || v4.is_broadcast() || o[0] == 0 || o[0] >= 240 {
                DestClass::Blocked
            } else if v4.is_loopback() {
                DestClass::Loopback
            } else if v4.is_private() {
                DestClass::Lan
            } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
                DestClass::Overlay
            } else {
                DestClass::Public
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let nat64_local = s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001;
            let site_local = (s[0] & 0xffc0) == 0xfec0;
            let teredo = s[0] == 0x2001 && s[1] == 0;
            if v6.is_multicast() || nat64_local || site_local || teredo {
                DestClass::Blocked
            } else if v6.is_loopback() {
                DestClass::Loopback
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                DestClass::Lan
            } else {
                DestClass::Public
            }
        }
    }
}

/// Path class for the `Lan2Group` code guard: `Lan` only when the provider is `Local` or
/// `Direct` and every checked destination is Loopback or LAN.
#[must_use]
pub fn path_class(provider: ProviderId, destinations: &[IpAddr]) -> PairingPathKind {
    let lan_provider = matches!(provider, ProviderId::Local | ProviderId::Direct);
    let lan_dests = destinations.iter().all(|ip| {
        matches!(
            classify_destination(*ip),
            DestClass::Loopback | DestClass::Lan
        )
    });
    if lan_provider && lan_dests {
        PairingPathKind::Lan
    } else {
        PairingPathKind::Remote
    }
}

/// Why a hint was not dialed. Serialized in `snake_case`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Malformed hint, or a hint carrying a fragment.
    Invalid,
    /// A literal or resolved address is in the always-blocked set.
    BlockedAddress,
    /// A `direct:` hint names a host instead of an IP literal.
    DirectRequiresIpLiteral,
    /// A `local:` or `unix://` hint that did not come from the local operator.
    IpcFromUri,
    /// An `iroh://` hint with no usable relay in the configured map and no usable `addr=`.
    IrohRelayNotConfigured,
    /// A `Lan2Group` code on a `Remote` path.
    LanCodeRemoteHint,
    /// Lookup failed, timed out, or returned zero addresses.
    Unresolved,
    /// An `iroh://` hint while the `p2p-iroh` feature is disabled.
    P2pFeatureDisabled,
    /// A `/v2/relay` hint that did not pass the stored-route gate.
    RelayV2NotAuthorized,
    /// A `/v2/relay` hint on a Wire v1 driver.
    WireV1NoRelayV2,
    /// A `wt://` hint while the `webtransport` feature is disabled.
    #[serde(rename = "webtransport_feature_disabled")]
    WebtransportFeatureDisabled,
}

impl SkipReason {
    /// Snake-case spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::BlockedAddress => "blocked_address",
            Self::DirectRequiresIpLiteral => "direct_requires_ip_literal",
            Self::IpcFromUri => "ipc_from_uri",
            Self::IrohRelayNotConfigured => "iroh_relay_not_configured",
            Self::LanCodeRemoteHint => "lan_code_remote_hint",
            Self::Unresolved => "unresolved",
            Self::P2pFeatureDisabled => "p2p_feature_disabled",
            Self::RelayV2NotAuthorized => "relay_v2_not_authorized",
            Self::WireV1NoRelayV2 => "wire_v1_no_relay_v2",
            Self::WebtransportFeatureDisabled => "webtransport_feature_disabled",
        }
    }
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A hint that was reported and never dialed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedHint {
    pub hint: String,
    pub reason: SkipReason,
}

impl SkippedHint {
    #[must_use]
    pub fn new(hint: impl Into<String>, reason: SkipReason) -> Self {
        Self {
            hint: hint.into(),
            reason,
        }
    }
}

/// Where a hint came from; decides its egress treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintSource {
    /// A pairing or recovery URI hint.
    Uri,
    /// A stored route, by its strongest source.
    Stored(RouteSource),
    /// Typed by the local operator or developer.
    Operator,
}

impl HintSource {
    /// `true` for operator input, which gets only the always-blocked set and the code guard.
    #[must_use]
    pub const fn is_operator(self) -> bool {
        matches!(self, Self::Operator | Self::Stored(RouteSource::Operator))
    }
}

/// What the dial is for: pairing with the effective code's kind, or a Day-2 session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressKind {
    Pairing(PairingCodeKind),
    Session,
}

/// Host name resolver used by the egress layer and the WebSocket dialers.
#[async_trait]
pub trait HostResolver: Send + Sync {
    /// Resolves `host` (never an IP literal) with `port`.
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, RuntimeError>;
}

/// The system resolver (`tokio::net::lookup_host`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

static SYSTEM_LOOKUPS: AtomicUsize = AtomicUsize::new(0);

impl SystemResolver {
    /// Process-wide number of lookups made through the system resolver, for diagnostics and
    /// for witnesses that a dial made no lookup outside its policy's resolver.
    #[must_use]
    pub fn lookups() -> usize {
        SYSTEM_LOOKUPS.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl HostResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
        SYSTEM_LOOKUPS.fetch_add(1, Ordering::Relaxed);
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// Address check applied to every answer of the single lookup made by a WebSocket-family dial.
pub trait AddrPolicy: Send + Sync + fmt::Debug {
    /// Accepts or rejects one resolved address.
    fn check(&self, ip: IpAddr) -> Result<(), SkipReason>;

    /// Resolver used for host names.
    fn resolver(&self) -> &dyn HostResolver {
        &SystemResolver
    }
}

/// Policy of dials outside the egress layer: rejects cloud metadata, link-local and
/// unspecified addresses.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultAddrPolicy;

impl AddrPolicy for DefaultAddrPolicy {
    fn check(&self, ip: IpAddr) -> Result<(), SkipReason> {
        if super::is_metadata_or_link_local_ip(ip) {
            Err(SkipReason::BlockedAddress)
        } else {
            Ok(())
        }
    }
}

/// Egress policy for hints: rejects the always-blocked set ([`DestClass::Blocked`]).
#[derive(Clone)]
pub struct EgressAddrPolicy {
    resolver: Arc<dyn HostResolver>,
}

impl EgressAddrPolicy {
    #[must_use]
    pub fn new(resolver: Arc<dyn HostResolver>) -> Self {
        Self { resolver }
    }
}

impl Default for EgressAddrPolicy {
    fn default() -> Self {
        Self::new(Arc::new(SystemResolver))
    }
}

impl fmt::Debug for EgressAddrPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EgressAddrPolicy")
    }
}

impl AddrPolicy for EgressAddrPolicy {
    fn check(&self, ip: IpAddr) -> Result<(), SkipReason> {
        if classify_destination(ip) == DestClass::Blocked {
            Err(SkipReason::BlockedAddress)
        } else {
            Ok(())
        }
    }

    fn resolver(&self) -> &dyn HostResolver {
        &*self.resolver
    }
}

fn egress_err(reason: SkipReason, detail: impl Into<String>) -> RuntimeError {
    RuntimeError::Egress {
        reason,
        detail: detail.into(),
    }
}

fn bare_host(host: &str) -> &str {
    let trimmed = host.trim();
    trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed)
        .trim_end_matches('.')
}

/// Resolves `host` once (IP literals without a lookup) and checks every answer with `policy`.
///
/// Any lookup error, a lookup timeout, zero answers or one rejected answer fails the whole host
/// with [`RuntimeError::Egress`], whose [`RuntimeError::skip_reason`] is the hint-level reason.
pub(crate) async fn resolve_checked(
    host: &str,
    port: u16,
    policy: &dyn AddrPolicy,
) -> Result<Vec<SocketAddr>, RuntimeError> {
    let bare = bare_host(host);
    if bare.is_empty() {
        return Err(egress_err(SkipReason::Invalid, "URL is missing a host"));
    }
    let shown = redact_host(bare);
    let addrs = if let Ok(ip) = bare.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        if bare.eq_ignore_ascii_case("metadata.google.internal") {
            return Err(egress_err(
                SkipReason::BlockedAddress,
                "cloud metadata hostname is not permitted",
            ));
        }
        match timeout(EGRESS_LOOKUP_TIMEOUT, policy.resolver().resolve(bare, port)).await {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(err)) => {
                return Err(egress_err(
                    SkipReason::Unresolved,
                    format!(
                        "lookup of '{shown}' failed: {}",
                        redact_text(&err.to_string().replace(bare, &shown))
                    ),
                ));
            }
            Err(_) => {
                return Err(egress_err(
                    SkipReason::Unresolved,
                    format!("lookup of '{shown}' timed out"),
                ));
            }
        }
    };
    if addrs.is_empty() {
        return Err(egress_err(
            SkipReason::Unresolved,
            format!("host '{shown}' resolved to zero addresses"),
        ));
    }
    let addrs: Vec<SocketAddr> = addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr.ip(), port))
        .collect();
    for addr in &addrs {
        if let Err(reason) = policy.check(addr.ip()) {
            return Err(egress_err(
                reason,
                format!("resolved address '{}' is not permitted", addr.ip()),
            ));
        }
    }
    Ok(addrs)
}

tokio::task_local! {
    static WS_ADDR_POLICY: Arc<dyn AddrPolicy>;
}

/// Runs `fut` with `policy` as the address policy of every WebSocket-family connect it makes
/// on this task (relay, `/v2/relay` and broker dialers).
pub async fn with_addr_policy<F: Future>(policy: Arc<dyn AddrPolicy>, fut: F) -> F::Output {
    WS_ADDR_POLICY.scope(policy, fut).await
}

pub(crate) fn scoped_addr_policy() -> Option<Arc<dyn AddrPolicy>> {
    WS_ADDR_POLICY.try_with(Arc::clone).ok()
}

/// A [`PathDialer`] that dials through `inner` under an [`AddrPolicy`], so the WebSocket
/// connect of `inner` checks its single lookup with that policy.
pub struct EgressDialer {
    inner: Arc<dyn PathDialer>,
    policy: Arc<dyn AddrPolicy>,
}

impl EgressDialer {
    #[must_use]
    pub fn new(inner: Arc<dyn PathDialer>, policy: Arc<dyn AddrPolicy>) -> Self {
        Self { inner, policy }
    }
}

#[async_trait]
impl PathDialer for EgressDialer {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn supports_fast_open(&self) -> bool {
        self.inner.supports_fast_open()
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        with_addr_policy(Arc::clone(&self.policy), self.inner.dial(endpoint)).await
    }

    async fn dial_with_init(
        &self,
        endpoint: &str,
        init_frame: Option<&[u8]>,
    ) -> Result<(Box<dyn PathStream>, bool), RuntimeError> {
        with_addr_policy(
            Arc::clone(&self.policy),
            self.inner.dial_with_init(endpoint, init_frame),
        )
        .await
    }
}

/// Inputs of the egress check for one attempt.
#[derive(Clone)]
pub struct EgressContext {
    /// Effective code kind for pairing, or `Session`.
    pub kind: EgressKind,
    /// Origins allowed to receive relay admission material.
    pub relay_auth_origins: Vec<String>,
    /// Configured Iroh relay mode of the hint dialer ([`P2pRelayMode::N0Public`] by default).
    #[cfg(feature = "p2p-iroh")]
    pub iroh_relay_mode: P2pRelayMode,
    /// Resolver for `overlay://` and WebSocket host names.
    pub resolver: Arc<dyn HostResolver>,
}

impl fmt::Debug for EgressContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("EgressContext");
        d.field("kind", &self.kind)
            .field("relay_auth_origins", &self.relay_auth_origins);
        #[cfg(feature = "p2p-iroh")]
        d.field("iroh_relay_mode", &self.iroh_relay_mode);
        d.finish_non_exhaustive()
    }
}

impl EgressContext {
    /// Context with the system resolver, no relay origins and the default n0 public Iroh relays.
    #[must_use]
    pub fn new(kind: EgressKind) -> Self {
        Self {
            kind,
            relay_auth_origins: Vec::new(),
            #[cfg(feature = "p2p-iroh")]
            iroh_relay_mode: P2pRelayMode::default(),
            resolver: Arc::new(SystemResolver),
        }
    }

    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    #[must_use]
    pub fn with_relay_auth_origins(mut self, origins: Vec<String>) -> Self {
        self.relay_auth_origins = origins;
        self
    }

    #[cfg(feature = "p2p-iroh")]
    #[must_use]
    pub fn with_iroh_relay_mode(mut self, mode: P2pRelayMode) -> Self {
        self.iroh_relay_mode = mode;
        self
    }

    /// The [`AddrPolicy`] for WebSocket-family dials of this context.
    #[must_use]
    pub fn addr_policy(&self) -> Arc<dyn AddrPolicy> {
        Arc::new(EgressAddrPolicy::new(Arc::clone(&self.resolver)))
    }
}

/// A hint that passed the egress check, with what the dialer must use.
#[derive(Debug, Clone)]
pub struct CheckedHint {
    /// The original hint string.
    pub hint: String,
    pub provider: ProviderId,
    /// What to pass to the provider's dialer: a checked literal for `direct:` and
    /// `overlay://` (a comma-separated list of every checked address, in resolver order, that
    /// the overlay dialer tries in turn), the unchanged URL for the WebSocket family, a filtered `iroh://` string
    /// for the hint dialer, or a socket path for operator IPC.
    pub dial_endpoint: String,
    pub path_class: PairingPathKind,
    /// Addresses checked before the dial (empty when the check happens inside the connect).
    pub destinations: Vec<IpAddr>,
    /// Set for the WebSocket family: wrap the dialer in an [`EgressDialer`] with it.
    pub addr_policy: Option<Arc<dyn AddrPolicy>>,
    /// `true` when the dial must use the lookup-free hint `P2pDialer`.
    pub p2p_hint_dialer: bool,
    /// Hint `relay=` URLs dropped because they are not in the configured relay map.
    pub dropped_relays: Vec<String>,
    /// Relay host names of an operator `iroh://` endpoint with the addresses resolved and
    /// checked for them; the operator dialer answers these names from this list only.
    pub relay_pins: Vec<(String, Vec<IpAddr>)>,
}

#[cfg(feature = "webtransport")]
struct PinnedHostResolver {
    host: String,
    addrs: Vec<SocketAddr>,
}

#[cfg(feature = "webtransport")]
#[async_trait]
impl HostResolver for PinnedHostResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
        if bare_host(host).eq_ignore_ascii_case(&self.host) {
            Ok(self
                .addrs
                .iter()
                .map(|a| SocketAddr::new(a.ip(), port))
                .collect())
        } else {
            Err(egress_err(
                SkipReason::Unresolved,
                "unpinned host lookup rejected",
            ))
        }
    }
}

fn split_host_port(target: &str) -> Option<(&str, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

fn ws_url_of(stripped: &str) -> &str {
    stripped.strip_prefix("broker+").unwrap_or(stripped)
}

/// `true` when a literal host of the nested Iroh relay URL `raw` is in the always-blocked set.
#[cfg(feature = "p2p-iroh")]
fn relay_literal_blocked(raw: &str) -> bool {
    match url::Url::parse(raw)
        .ok()
        .and_then(|u| u.host().map(|h| h.to_owned()))
    {
        Some(url::Host::Ipv4(v4)) => classify_destination(IpAddr::V4(v4)) == DestClass::Blocked,
        Some(url::Host::Ipv6(v6)) => classify_destination(IpAddr::V6(v6)) == DestClass::Blocked,
        Some(url::Host::Domain(d)) => d
            .trim_end_matches('.')
            .eq_ignore_ascii_case("metadata.google.internal"),
        None => false,
    }
}

/// Applies the always-blocked set to the nested destinations of an operator `iroh://` endpoint:
/// `addr=` literals and literal `relay=` hosts in the set are removed, every other parameter is
/// kept verbatim for the operator dialer. Fails with [`SkipReason::BlockedAddress`] when only
/// blocked destinations were given.
#[cfg(feature = "p2p-iroh")]
fn strip_blocked_iroh_destinations(endpoint: &str) -> Result<String, SkipReason> {
    let Some((base, query)) = endpoint.split_once('?') else {
        return Ok(endpoint.to_owned());
    };
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = false;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let blocked = match pair.split_once('=') {
            Some(("addr", val)) => val
                .parse::<SocketAddr>()
                .is_ok_and(|sock| classify_destination(sock.ip()) == DestClass::Blocked),
            Some(("relay", val)) => relay_literal_blocked(val),
            _ => false,
        };
        if blocked {
            removed = true;
        } else {
            kept.push(pair);
        }
    }
    if !removed {
        return Ok(endpoint.to_owned());
    }
    let destinations = kept
        .iter()
        .filter(|p| p.starts_with("addr=") || p.starts_with("relay="))
        .count();
    if destinations == 0 {
        return Err(SkipReason::BlockedAddress);
    }
    Ok(format!("{base}?{}", kept.join("&")))
}

/// Resolves every `relay=` host name of an operator `iroh://` endpoint once and checks every
/// answer against the always-blocked set. A relay whose lookup fails or returns a blocked
/// address is removed; the others are kept verbatim with their checked addresses as pins.
/// Fails when relays were removed and no `addr=` or `relay=` destination remains.
#[cfg(feature = "p2p-iroh")]
async fn pin_iroh_relay_hosts(
    endpoint: &str,
    resolver: &Arc<dyn HostResolver>,
) -> Result<(String, Vec<(String, Vec<IpAddr>)>), SkipReason> {
    let Some((base, query)) = endpoint.split_once('?') else {
        return Ok((endpoint.to_owned(), Vec::new()));
    };
    let policy = EgressAddrPolicy::new(Arc::clone(resolver));
    let mut kept: Vec<&str> = Vec::new();
    let mut pins: Vec<(String, Vec<IpAddr>)> = Vec::new();
    let mut refused: Option<SkipReason> = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let domain = pair
            .strip_prefix("relay=")
            .and_then(|raw| url::Url::parse(raw).ok())
            .and_then(|url| match (url.host(), url.port_or_known_default()) {
                (Some(url::Host::Domain(d)), Some(port)) => Some((bare_host(d).to_owned(), port)),
                _ => None,
            });
        let Some((host, port)) = domain else {
            kept.push(pair);
            continue;
        };
        match resolve_checked(&host, port, &policy).await {
            Ok(addrs) => {
                let key = host.to_ascii_lowercase();
                if !pins.iter().any(|(h, _)| *h == key) {
                    pins.push((key, addrs.iter().map(SocketAddr::ip).collect()));
                }
                kept.push(pair);
            }
            Err(err) => {
                let reason = err.skip_reason().unwrap_or(SkipReason::Unresolved);
                if refused != Some(SkipReason::BlockedAddress) {
                    refused = Some(reason);
                }
            }
        }
    }
    let Some(reason) = refused else {
        return Ok((endpoint.to_owned(), pins));
    };
    let destinations = kept
        .iter()
        .filter(|p| p.starts_with("addr=") || p.starts_with("relay="))
        .count();
    if destinations == 0 {
        return Err(reason);
    }
    Ok((format!("{base}?{}", kept.join("&")), pins))
}

/// Applies the egress policy to one hint, without dialing.
///
/// URI hints and `signed` or `committed` stored routes get every rule; operator input (explicit,
/// or a stored `operator` route) gets the always-blocked set and the code guard only. Operator
/// IPC and operator `iroh://` endpoints keep their current dialers; the blocked set still removes
/// their blocked `addr=` and literal `relay=` destinations, and each `relay=` host name is
/// resolved once here and dialed only at its checked addresses ([`CheckedHint::relay_pins`]).
/// On rejection the [`SkippedHint`] carries the original hint.
pub async fn check_hint(
    hint: &str,
    source: HintSource,
    ctx: &EgressContext,
) -> Result<CheckedHint, SkippedHint> {
    let skip = |reason| SkippedHint::new(hint, reason);
    if hint.contains('#') {
        return Err(skip(SkipReason::Invalid));
    }
    let provider = classify_endpoint_hint(hint).map_err(|_| skip(SkipReason::Invalid))?;
    if ctx.kind == EgressKind::Pairing(PairingCodeKind::Lan2Group)
        && !matches!(provider, ProviderId::Local | ProviderId::Direct)
    {
        return Err(skip(SkipReason::LanCodeRemoteHint));
    }
    let mut checked = CheckedHint {
        hint: hint.to_owned(),
        provider,
        dial_endpoint: String::new(),
        path_class: PairingPathKind::Remote,
        destinations: Vec::new(),
        addr_policy: None,
        p2p_hint_dialer: false,
        dropped_relays: Vec::new(),
        relay_pins: Vec::new(),
    };
    match provider {
        ProviderId::Local => {
            if !source.is_operator() {
                return Err(skip(SkipReason::IpcFromUri));
            }
            let path = hint
                .strip_prefix("local:")
                .or_else(|| hint.strip_prefix("unix://"))
                .unwrap_or(hint);
            checked.dial_endpoint = path.to_owned();
        }
        ProviderId::Direct if hint.starts_with("wt://") => {
            let rest = &hint["wt://".len()..];
            let parsed = url::Url::parse(&format!("https://{rest}"))
                .map_err(|_| skip(SkipReason::Invalid))?;
            let host = parsed
                .host_str()
                .map(bare_host)
                .filter(|h| !h.is_empty())
                .ok_or_else(|| skip(SkipReason::Invalid))?;
            let authority = rest.split(['/', '?']).next().unwrap_or_default();
            let port = authority
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .filter(|&p| p > 0)
                .ok_or_else(|| skip(SkipReason::Invalid))?;
            if host.eq_ignore_ascii_case("metadata.google.internal")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| classify_destination(ip) == DestClass::Blocked)
            {
                return Err(skip(SkipReason::BlockedAddress));
            }
            #[cfg(not(feature = "webtransport"))]
            {
                let _ = port;
                if ctx.kind == EgressKind::Pairing(PairingCodeKind::Lan2Group) {
                    let is_lan_literal = host.parse::<IpAddr>().is_ok_and(|ip| {
                        matches!(
                            classify_destination(ip),
                            DestClass::Loopback | DestClass::Lan
                        )
                    });
                    if !is_lan_literal {
                        return Err(skip(SkipReason::LanCodeRemoteHint));
                    }
                }
                return Err(skip(SkipReason::WebtransportFeatureDisabled));
            }
            #[cfg(feature = "webtransport")]
            {
                let policy = EgressAddrPolicy::new(Arc::clone(&ctx.resolver));
                let addrs = resolve_checked(host, port, &policy)
                    .await
                    .map_err(|err| skip(err.skip_reason().unwrap_or(SkipReason::Unresolved)))?;
                checked.dial_endpoint = hint.to_owned();
                checked.destinations = addrs.iter().map(SocketAddr::ip).collect();
                if host.parse::<IpAddr>().is_err() {
                    let pinned = Arc::new(PinnedHostResolver {
                        host: host.to_owned(),
                        addrs,
                    });
                    checked.addr_policy = Some(Arc::new(EgressAddrPolicy::new(pinned)));
                }
            }
        }
        ProviderId::Direct => {
            let target = hint.strip_prefix("direct:").unwrap_or(hint);
            let sock = target.parse::<SocketAddr>().map_err(|_| {
                if split_host_port(target).is_some() {
                    skip(SkipReason::DirectRequiresIpLiteral)
                } else {
                    skip(SkipReason::Invalid)
                }
            })?;
            if classify_destination(sock.ip()) == DestClass::Blocked {
                return Err(skip(SkipReason::BlockedAddress));
            }
            checked.dial_endpoint = sock.to_string();
            checked.destinations = vec![sock.ip()];
        }
        ProviderId::Overlay => {
            let target = hint.strip_prefix("overlay://").unwrap_or(hint);
            let (host, port) = split_host_port(target).ok_or_else(|| skip(SkipReason::Invalid))?;
            let policy = EgressAddrPolicy::new(Arc::clone(&ctx.resolver));
            let addrs = resolve_checked(host, port, &policy)
                .await
                .map_err(|err| skip(err.skip_reason().unwrap_or(SkipReason::Unresolved)))?;
            let joined: Vec<String> = addrs.iter().map(SocketAddr::to_string).collect();
            checked.dial_endpoint = format!("overlay://{}", joined.join(","));
            checked.destinations = addrs.iter().map(SocketAddr::ip).collect();
        }
        ProviderId::Relay | ProviderId::Broker => {
            let stripped = hint.strip_prefix("relay:").unwrap_or(hint);
            let url =
                url::Url::parse(ws_url_of(stripped)).map_err(|_| skip(SkipReason::Invalid))?;
            let host = url
                .host_str()
                .map(bare_host)
                .filter(|h| !h.is_empty())
                .ok_or_else(|| skip(SkipReason::Invalid))?;
            if host.eq_ignore_ascii_case("metadata.google.internal")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| classify_destination(ip) == DestClass::Blocked)
            {
                return Err(skip(SkipReason::BlockedAddress));
            }
            checked.dial_endpoint = stripped.to_owned();
            checked.addr_policy = Some(ctx.addr_policy());
        }
        ProviderId::P2p => {
            let stripped = hint.strip_prefix("p2p:").unwrap_or(hint);
            #[cfg(feature = "p2p-iroh")]
            {
                if source.is_operator() {
                    let literal_checked =
                        strip_blocked_iroh_destinations(stripped).map_err(skip)?;
                    let (endpoint, pins) = pin_iroh_relay_hosts(&literal_checked, &ctx.resolver)
                        .await
                        .map_err(skip)?;
                    checked.dial_endpoint = endpoint;
                    checked.relay_pins = pins;
                } else {
                    let filtered = filter_p2p_hint(stripped, &ctx.iroh_relay_mode).map_err(skip)?;
                    checked.dial_endpoint = filtered.endpoint;
                    checked.dropped_relays = filtered.dropped_relays;
                    checked.p2p_hint_dialer = true;
                }
            }
            #[cfg(not(feature = "p2p-iroh"))]
            {
                let _ = stripped;
                return Err(skip(SkipReason::P2pFeatureDisabled));
            }
        }
    }
    checked.path_class = path_class(provider, &checked.destinations);
    if ctx.kind == EgressKind::Pairing(PairingCodeKind::Lan2Group)
        && checked.path_class != PairingPathKind::Lan
    {
        return Err(skip(SkipReason::LanCodeRemoteHint));
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct EchoingResolver(Vec<SocketAddr>);

    #[async_trait]
    impl HostResolver for EchoingResolver {
        async fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
            if self.0.is_empty() && host.contains("fail") {
                return Err(RuntimeError::Protocol(format!("no such host {host}")));
            }
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn egress_errors_never_echo_a_raw_host() {
        for (host, answers) in [
            ("fail;tok=s3cret", Vec::new()),
            ("empty(s3cret)", Vec::new()),
        ] {
            let policy = EgressAddrPolicy::new(Arc::new(EchoingResolver(answers)));
            let err = resolve_checked(host, 443, &policy)
                .await
                .expect_err(host)
                .to_string();
            assert!(!err.contains("s3cret"), "{err}");
        }
    }

    #[test]
    fn destination_classes_follow_the_spec_table() {
        let cases: &[(&str, DestClass)] = &[
            ("0.0.0.0", DestClass::Blocked),
            ("0.1.2.3", DestClass::Blocked),
            ("224.0.0.1", DestClass::Blocked),
            ("255.255.255.255", DestClass::Blocked),
            ("240.0.0.1", DestClass::Blocked),
            ("169.254.169.254", DestClass::Blocked),
            ("::", DestClass::Blocked),
            ("ff02::1", DestClass::Blocked),
            ("fe80::1", DestClass::Blocked),
            ("fd00:ec2::254", DestClass::Blocked),
            ("::ffff:169.254.1.1", DestClass::Blocked),
            ("127.0.0.1", DestClass::Loopback),
            ("127.9.9.9", DestClass::Loopback),
            ("::1", DestClass::Loopback),
            ("::ffff:127.0.0.1", DestClass::Loopback),
            ("10.1.2.3", DestClass::Lan),
            ("172.16.0.1", DestClass::Lan),
            ("192.168.1.20", DestClass::Lan),
            ("fd34::9", DestClass::Lan),
            ("100.64.0.1", DestClass::Overlay),
            ("100.127.255.254", DestClass::Overlay),
            ("100.128.0.1", DestClass::Public),
            ("203.0.113.7", DestClass::Public),
            ("2001:db8::1", DestClass::Public),
            ("2001:4860::1", DestClass::Public),
            ("2001:1::1", DestClass::Public),
            // Teredo 2001::/32 embeds an unverifiable IPv4 address: blocked outright.
            ("2001::1", DestClass::Blocked),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", DestClass::Blocked),
            // IPv6 forms with a fixed IPv4 embedding take the embedded address's class.
            ("64:ff9b::a9fe:a9fe", DestClass::Blocked),
            ("64:ff9b::f000:1", DestClass::Blocked),
            ("64:ff9b::7f00:1", DestClass::Loopback),
            ("64:ff9b::c0a8:101", DestClass::Lan),
            ("64:ff9b::cb00:7107", DestClass::Public),
            ("::ffff:0:a9fe:a9fe", DestClass::Blocked),
            ("::a9fe:a9fe", DestClass::Blocked),
            ("::7f00:1", DestClass::Loopback),
            ("::2", DestClass::Blocked),
            ("2002:a9fe:a9fe::1", DestClass::Blocked),
            ("2002:a00:1::1", DestClass::Lan),
            ("2002:cb00:7107::1", DestClass::Public),
            // Local-use NAT64 (unknown embedding) and deprecated site-local: blocked outright.
            ("64:ff9b:1::cb00:7107", DestClass::Blocked),
            ("fec0::1", DestClass::Blocked),
            ("feff::1", DestClass::Blocked),
        ];
        for (raw, want) in cases {
            let ip: IpAddr = raw.parse().expect("ip");
            assert_eq!(classify_destination(ip), *want, "{raw}");
        }
    }

    #[test]
    fn path_class_needs_lan_provider_and_lan_destinations() {
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let lo = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(path_class(ProviderId::Direct, &[lan]), PairingPathKind::Lan);
        assert_eq!(path_class(ProviderId::Direct, &[lo]), PairingPathKind::Lan);
        assert_eq!(path_class(ProviderId::Local, &[]), PairingPathKind::Lan);
        assert_eq!(
            path_class(ProviderId::Direct, &[lan, public]),
            PairingPathKind::Remote
        );
        assert_eq!(
            path_class(ProviderId::Overlay, &[lan]),
            PairingPathKind::Remote
        );
        assert_eq!(
            path_class(ProviderId::Relay, &[lo]),
            PairingPathKind::Remote
        );
    }

    #[test]
    fn skip_reasons_serialize_in_snake_case() {
        let json = serde_json::to_string(&SkippedHint::new(
            "direct:host:1",
            SkipReason::DirectRequiresIpLiteral,
        ))
        .expect("json");
        assert_eq!(
            json,
            r#"{"hint":"direct:host:1","reason":"direct_requires_ip_literal"}"#
        );
        assert_eq!(
            serde_json::to_string(&SkipReason::IrohRelayNotConfigured).expect("json"),
            r#""iroh_relay_not_configured""#
        );
    }

    #[cfg(feature = "p2p-iroh")]
    struct FixedResolver {
        answers: Vec<(&'static str, IpAddr)>,
        lookups: AtomicUsize,
    }

    #[cfg(feature = "p2p-iroh")]
    #[async_trait]
    impl HostResolver for FixedResolver {
        async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            let found: Vec<SocketAddr> = self
                .answers
                .iter()
                .filter(|(h, _)| *h == host)
                .map(|(_, ip)| SocketAddr::new(*ip, port))
                .collect();
            if found.is_empty() {
                Err(RuntimeError::Protocol(format!("no such host {host}")))
            } else {
                Ok(found)
            }
        }
    }

    #[cfg(feature = "p2p-iroh")]
    #[tokio::test]
    async fn operator_iroh_relay_hosts_are_resolved_once_and_screened() {
        let good = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let resolver = Arc::new(FixedResolver {
            answers: vec![
                ("good.example", good),
                (
                    "evil.example",
                    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
                ),
                ("mixed.example", good),
                ("mixed.example", IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))),
            ],
            lookups: AtomicUsize::new(0),
        });
        let ctx = EgressContext::new(EgressKind::Session)
            .with_resolver(Arc::clone(&resolver) as Arc<dyn HostResolver>);
        let node = iroh::SecretKey::from_bytes(&[9; 32]).public();

        let hint = format!(
            "iroh://{node}?relay=https://good.example/&relay=https://evil.example/\
             &relay=https://mixed.example/"
        );
        for source in [
            HintSource::Operator,
            HintSource::Stored(RouteSource::Operator),
        ] {
            let checked = check_hint(&hint, source, &ctx)
                .await
                .expect("good relay kept");
            assert_eq!(
                checked.dial_endpoint,
                format!("iroh://{node}?relay=https://good.example/")
            );
            assert_eq!(
                checked.relay_pins,
                vec![("good.example".to_owned(), vec![good])]
            );
        }
        assert_eq!(
            resolver.lookups.load(Ordering::SeqCst),
            6,
            "one lookup per host"
        );

        let only_blocked = format!("iroh://{node}?relay=https://evil.example/");
        let skipped = check_hint(&only_blocked, HintSource::Operator, &ctx)
            .await
            .expect_err("every relay is blocked");
        assert_eq!(skipped.reason, SkipReason::BlockedAddress);
        let unresolved = format!("iroh://{node}?relay=https://missing.example/");
        let skipped = check_hint(&unresolved, HintSource::Operator, &ctx)
            .await
            .expect_err("no checked answer");
        assert_eq!(skipped.reason, SkipReason::Unresolved);
        // A node id alone keeps the operator dialer's own discovery.
        let bare = format!("iroh://{node}");
        assert!(
            check_hint(&bare, HintSource::Operator, &ctx)
                .await
                .expect("bare node id")
                .relay_pins
                .is_empty()
        );
    }
}
