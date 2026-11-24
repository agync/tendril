//! Iroh QUIC P2P path provider (`p2p`, zero-config hole-punching + public relay fallback).

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig as IrohRelayConfig, RelayMap, RelayMode,
    RelayUrl, SecretKey, TransportAddr,
};
use tendril_core::crypto::random_bytes;
use tendril_core::policy::ProviderId;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::egress::{DestClass, SkipReason, classify_destination};
use crate::error::RuntimeError;
use crate::provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathReader, PathStream,
    PathWriter,
};
use crate::redact::{redact_hint, redact_host, redact_text, redact_url_str};

/// ALPN registered on iroh endpoints carrying Tendril `Intent::Pair` and `Intent::Session`.
pub const TENDRIL_P2P_ALPN: &[u8] = b"tendril/p2p/v1";

/// Maximum number of custom `iroh-relay` URLs accepted in [`P2pRelayMode::CustomMany`].
pub const MAX_P2P_CUSTOM_RELAYS: usize = 8;

const MAX_P2P_RELAY_AUTH_BYTES: usize = 4_096;

const P2P_STREAM_MAGIC: u8 = 0x54;
const P2P_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_DNS_TIMEOUT: Duration = Duration::from_secs(3);
const P2P_ACCEPT_BI_TIMEOUT: Duration = Duration::from_secs(3);
const P2P_MAGIC_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_ACCEPTS: usize = 64;
const MAX_CONCURRENT_ACCEPTS_PER_PEER: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum IncomingSourceKey {
    Ip(IpAddr),
    Peer(EndpointId),
    Other,
}

fn normalize_incoming_source(addr: &iroh::endpoint::IncomingAddr) -> IncomingSourceKey {
    match addr {
        iroh::endpoint::IncomingAddr::Ip(sock) => {
            let ip = match sock.ip() {
                IpAddr::V4(v4) => IpAddr::V4(v4),
                IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) => IpAddr::V4(v4),
                    None => {
                        let seg = v6.segments();
                        IpAddr::V6(std::net::Ipv6Addr::new(
                            seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0,
                        ))
                    }
                },
            };
            IncomingSourceKey::Ip(ip)
        }
        iroh::endpoint::IncomingAddr::Relay { endpoint_id, .. } => {
            IncomingSourceKey::Peer(*endpoint_id)
        }
        _ => IncomingSourceKey::Other,
    }
}

struct PeerAcceptGuard<K: Eq + std::hash::Hash> {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<K, usize>>>,
    key: K,
}

impl<K: Eq + std::hash::Hash + Clone> PeerAcceptGuard<K> {
    fn try_acquire(
        counts: Arc<std::sync::Mutex<std::collections::HashMap<K, usize>>>,
        key: K,
        limit: usize,
    ) -> Option<Self> {
        let mut map = counts.lock().unwrap_or_else(|err| err.into_inner());
        let entry = map.entry(key.clone()).or_insert(0);
        if *entry >= limit {
            return None;
        }
        *entry += 1;
        drop(map);
        Some(Self { counts, key })
    }
}

impl<K: Eq + std::hash::Hash> Drop for PeerAcceptGuard<K> {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(count) = map.get_mut(&self.key) {
            if *count <= 1 {
                map.remove(&self.key);
            } else {
                *count -= 1;
            }
        }
    }
}

/// Authentication credentials attached to managed `iroh-relay` connections.
#[derive(Clone)]
pub enum P2pRelayAuth {
    /// Static or pre-minted bearer token attached to `iroh::RelayMap::with_auth_token`.
    BearerToken(Zeroizing<String>),
    /// Managed `iroh-services` API secret used to derive an endpoint-scoped `RelayCap::Use` RCAN token.
    #[cfg(feature = "p2p-iroh-services")]
    IrohServicesSecret(Zeroizing<String>),
}

impl fmt::Debug for P2pRelayAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.write_str("P2pRelayAuth::BearerToken(<redacted>)"),
            #[cfg(feature = "p2p-iroh-services")]
            Self::IrohServicesSecret(_) => {
                f.write_str("P2pRelayAuth::IrohServicesSecret(<redacted>)")
            }
        }
    }
}

/// Relay strategy used when constructing [`P2pListener`] and [`P2pDialer`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum P2pRelayMode {
    /// Zero-setup public relays (`RelayMode::Default`).
    #[default]
    Default,
    /// Single self-hosted or regional `iroh-relay` URL (`https://...` or loopback `http://...`).
    Custom(String),
    /// Multi-region custom `iroh-relay` URL list (`2..=8` URLs).
    CustomMany(Vec<String>),
    /// Direct UDP socket addresses only (no relay server).
    Disabled,
}

/// Privacy and discovery options controlling `iroh` P2P endpoint construction.
#[derive(Debug, Clone)]
pub struct P2pOptions {
    pub relay_mode: P2pRelayMode,
    pub publish_pkarr: bool,
    pub resolve_pkarr: bool,
    pub advertise_direct_addrs: bool,
    pub allow_private_addrs: bool,
    pub relay_auth: Option<P2pRelayAuth>,
    /// `true` when `relay_mode` was derived from an untrusted peer URI rather than supplied by
    /// the caller, so its relays never count as operator-trusted.
    pub(crate) uri_derived_relays: bool,
    /// `true` for the lookup-free hint dialer: no address lookup service is installed whatever
    /// `publish_pkarr` or `resolve_pkarr` say, and every dial is filtered to the relay map.
    pub(crate) hint_dialer: bool,
    /// Relay host names answered only from these already checked addresses (operator
    /// endpoints); other names resolve with blocked answers removed.
    pub(crate) dns_pins: Vec<(String, Vec<IpAddr>)>,
}

impl Default for P2pOptions {
    fn default() -> Self {
        Self::for_listener(P2pRelayMode::Default)
    }
}

impl P2pOptions {
    /// Default privacy-preserving options for a listening [`P2pListener`].
    ///
    /// - [`P2pRelayMode::Default`]: publishes and resolves via `n0` Pkarr/DNS; omits direct `?addr=` hints.
    /// - [`P2pRelayMode::Custom`] / [`P2pRelayMode::CustomMany`]: disables `n0` Pkarr/DNS (`presets::Minimal`) and omits direct `?addr=` hints.
    /// - [`P2pRelayMode::Disabled`]: disables `n0` Pkarr/DNS and advertises local `?addr=` hints.
    #[must_use]
    pub fn for_listener(relay_mode: P2pRelayMode) -> Self {
        let is_default = matches!(relay_mode, P2pRelayMode::Default);
        let is_disabled = matches!(relay_mode, P2pRelayMode::Disabled);
        Self {
            relay_mode,
            publish_pkarr: is_default,
            resolve_pkarr: is_default,
            advertise_direct_addrs: is_disabled,
            allow_private_addrs: is_disabled,
            relay_auth: None,
            uri_derived_relays: false,
            hint_dialer: false,
            dns_pins: Vec::new(),
        }
    }

    /// Default privacy-preserving options for a dialing [`P2pDialer`].
    ///
    /// Never enables `PkarrPublisher` so ephemeral client identities are never published.
    #[must_use]
    pub fn for_dialer(relay_mode: P2pRelayMode) -> Self {
        let is_default = matches!(relay_mode, P2pRelayMode::Default);
        let is_disabled = matches!(relay_mode, P2pRelayMode::Disabled);
        Self {
            relay_mode,
            publish_pkarr: false,
            resolve_pkarr: is_default,
            advertise_direct_addrs: false,
            allow_private_addrs: is_disabled,
            relay_auth: None,
            uri_derived_relays: false,
            hint_dialer: false,
            dns_pins: Vec::new(),
        }
    }

    /// Options for the lookup-free dialer used for pairing URI hints and stored routes.
    ///
    /// `configured_mode` is the operator's relay mode; `None` means [`P2pRelayMode::Default`].
    /// The endpoint never installs `PkarrResolver`, `DnsAddressLookup`, or any other address
    /// lookup service, even if `resolve_pkarr` is later set, and each dial keeps only `relay=`
    /// URLs from this relay map and `addr=` literals outside the always-blocked set (see
    /// [`filter_p2p_hint`]). Hint relays never become a custom relay map.
    #[must_use]
    pub fn for_hint_dialer(configured_mode: Option<P2pRelayMode>) -> Self {
        let mut opts = Self::for_dialer(configured_mode.unwrap_or_default())
            .with_resolve_pkarr(false)
            .with_allow_private_addrs(true);
        opts.hint_dialer = true;
        opts
    }

    /// Options for the shared dialer of a group pool, or `None` when none may be built.
    ///
    /// A shared dialer cannot derive per-peer `?relay=` URLs, so it exists only when `relay_mode`
    /// is set explicitly or `local` (`TENDRIL_P2P_LOCAL=1`) selects [`P2pRelayMode::Disabled`].
    /// Other p2p settings never imply a relay mode, so an endpoint that configured only Pkarr,
    /// private-address, or relay-auth settings never falls back to the public `n0` relays.
    #[must_use]
    pub fn for_group_dialer(
        relay_mode: Option<P2pRelayMode>,
        local: bool,
        resolve_pkarr: Option<bool>,
        allow_private_addrs: Option<bool>,
        relay_auth: Option<P2pRelayAuth>,
    ) -> Option<Self> {
        let mode = match relay_mode {
            Some(mode) => mode,
            None if local => P2pRelayMode::Disabled,
            None => return None,
        };
        let mut opts = Self::for_dialer(mode);
        if let Some(resolve) = resolve_pkarr {
            opts = opts.with_resolve_pkarr(resolve);
        }
        if allow_private_addrs == Some(true) {
            opts = opts.with_allow_private_addrs(true);
        }
        Some(opts.with_relay_auth(relay_auth))
    }

    /// Derives dialer options for dialing `endpoint`.
    ///
    /// When `explicit_mode` is `None` or [`P2pRelayMode::Default`] and the URI carries validated
    /// `?relay=` URLs, those relays become [`P2pRelayMode::Custom`] / [`P2pRelayMode::CustomMany`]
    /// so the dialer never contacts `n0` public relays or Pkarr/DNS for that peer. Any other
    /// explicit mode is kept as given.
    pub fn for_endpoint(
        endpoint: &str,
        explicit_mode: Option<P2pRelayMode>,
        allow_private_addrs: bool,
    ) -> Result<Self, RuntimeError> {
        if let Some(mode) = explicit_mode
            && !matches!(mode, P2pRelayMode::Default)
        {
            let is_disabled = matches!(mode, P2pRelayMode::Disabled);
            return Ok(
                Self::for_dialer(mode).with_allow_private_addrs(allow_private_addrs || is_disabled)
            );
        }
        let urls = extract_p2p_relay_urls_from_endpoint(endpoint, allow_private_addrs)?;
        if urls.is_empty() {
            return Ok(Self::for_dialer(P2pRelayMode::Default)
                .with_allow_private_addrs(allow_private_addrs));
        }
        let mut opts = Self::for_dialer(parse_p2p_relay_modes(&urls)?)
            .with_allow_private_addrs(allow_private_addrs);
        opts.uri_derived_relays = true;
        Ok(opts)
    }

    /// Answers these relay host names only from the given, already checked addresses.
    #[must_use]
    pub(crate) fn with_dns_pins(mut self, pins: Vec<(String, Vec<IpAddr>)>) -> Self {
        self.dns_pins = pins;
        self
    }

    /// Enables or disables publishing this endpoint to `n0` Pkarr/DNS.
    #[must_use]
    pub fn with_publish_pkarr(mut self, publish: bool) -> Self {
        self.publish_pkarr = publish;
        self
    }

    /// Enables or disables resolving peer endpoints via `n0` Pkarr/DNS.
    #[must_use]
    pub fn with_resolve_pkarr(mut self, resolve: bool) -> Self {
        self.resolve_pkarr = resolve;
        self
    }

    /// Controls whether [`P2pListener`] serializes non-metadata `?addr=` direct socket hints.
    #[must_use]
    pub fn with_advertise_direct_addrs(mut self, advertise: bool) -> Self {
        self.advertise_direct_addrs = advertise;
        self
    }

    /// Controls whether [`P2pDialer`] accepts private/loopback `?addr=` hints.
    #[must_use]
    pub fn with_allow_private_addrs(mut self, allow: bool) -> Self {
        self.allow_private_addrs = allow;
        self
    }

    /// Attaches relay authentication credentials for managed `iroh-relay` servers.
    #[must_use]
    pub fn with_relay_auth(mut self, auth: Option<P2pRelayAuth>) -> Self {
        self.relay_auth = auth;
        self
    }
}

struct EndpointGuard {
    endpoint: Endpoint,
    closed: AtomicBool,
}

impl EndpointGuard {
    fn new(endpoint: Endpoint) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            closed: AtomicBool::new(false),
        })
    }

    async fn close_now(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.endpoint.close().await;
        }
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let ep = self.endpoint.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    ep.close().await;
                });
            }
        }
    }
}

/// Parses an optional P2P relay mode selector (`"default"`, `"disabled"`/`"local"`, or `http(s)://...`).
pub fn parse_p2p_relay_mode(mode: Option<&str>) -> Result<P2pRelayMode, RuntimeError> {
    if mode.is_some_and(|raw| raw.chars().any(char::is_control)) {
        return Err(RuntimeError::Protocol(
            "iroh relay URL contains control characters".into(),
        ));
    }
    match mode.map(str::trim) {
        None | Some("" | "default") => Ok(P2pRelayMode::Default),
        Some("disabled" | "local") => Ok(P2pRelayMode::Disabled),
        Some(url) if url.starts_with("https://") || url.starts_with("http://") => {
            let validated = super::validate_iroh_relay_url(url)?;
            let canonical = validated.as_str().to_owned();
            let _ = RelayUrl::from_str(&canonical).map_err(|err| {
                RuntimeError::Protocol(format!(
                    "invalid iroh relay URL {}: {err}",
                    redact_url_str(url)
                ))
            })?;
            Ok(P2pRelayMode::Custom(canonical))
        }
        Some(other) => Err(RuntimeError::Protocol(format!(
            "invalid p2p relay mode {} (expected default, disabled, local, or relay URL)",
            redact_hint(other)
        ))),
    }
}

/// Parses one or more custom `iroh-relay` URLs (`1..=8`) into [`P2pRelayMode::Custom`] or
/// [`P2pRelayMode::CustomMany`].
pub fn parse_p2p_relay_modes(urls: &[String]) -> Result<P2pRelayMode, RuntimeError> {
    if urls.is_empty() || urls.len() > MAX_P2P_CUSTOM_RELAYS {
        return Err(RuntimeError::Protocol(format!(
            "custom p2p relay list must contain 1..={MAX_P2P_CUSTOM_RELAYS} URLs"
        )));
    }
    let mut validated_urls = Vec::with_capacity(urls.len());
    for raw in urls {
        let validated = super::validate_iroh_relay_url(raw)?;
        let canonical = validated.as_str().to_owned();
        let _ = RelayUrl::from_str(&canonical).map_err(|err| {
            RuntimeError::Protocol(format!(
                "invalid iroh relay URL {}: {err}",
                redact_url_str(raw)
            ))
        })?;
        validated_urls.push(canonical);
    }
    if validated_urls.len() == 1 {
        Ok(P2pRelayMode::Custom(
            validated_urls.into_iter().next().expect("len == 1"),
        ))
    } else {
        Ok(P2pRelayMode::CustomMany(validated_urls))
    }
}

fn validate_p2p_auth_str(raw: &str, label: &str) -> Result<(), RuntimeError> {
    if raw.is_empty() || raw.len() > MAX_P2P_RELAY_AUTH_BYTES {
        return Err(RuntimeError::Protocol(format!(
            "{label} must be 1..={MAX_P2P_RELAY_AUTH_BYTES} bytes"
        )));
    }
    if raw.chars().any(char::is_control) {
        return Err(RuntimeError::Protocol(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

fn validate_p2p_options(options: &P2pOptions) -> Result<(), RuntimeError> {
    if let Some(auth) = &options.relay_auth {
        if matches!(options.relay_mode, P2pRelayMode::Disabled) {
            return Err(RuntimeError::Protocol(
                "relay_auth is invalid when relay_mode is Disabled".into(),
            ));
        }
        if matches!(options.relay_mode, P2pRelayMode::Default) {
            return Err(RuntimeError::Protocol(
                "relay_auth requires an explicit custom relay and is never sent to public relays"
                    .into(),
            ));
        }
        if options.uri_derived_relays {
            return Err(RuntimeError::Protocol(
                "relay_auth is never sent to relays taken from a peer URI".into(),
            ));
        }
        match auth {
            P2pRelayAuth::BearerToken(tok) => {
                validate_p2p_auth_str(tok, "p2p relay bearer token")?;
            }
            #[cfg(feature = "p2p-iroh-services")]
            P2pRelayAuth::IrohServicesSecret(sec) => {
                validate_p2p_auth_str(sec, "iroh-services secret")?;
            }
        }
    }
    Ok(())
}

fn build_custom_relay_map(urls: &[String]) -> Result<RelayMap, RuntimeError> {
    if urls.is_empty() || urls.len() > MAX_P2P_CUSTOM_RELAYS {
        return Err(RuntimeError::Protocol(format!(
            "custom p2p relay list must contain 1..={MAX_P2P_CUSTOM_RELAYS} URLs"
        )));
    }
    let mut configs = Vec::with_capacity(urls.len());
    for raw in urls {
        let validated = super::validate_iroh_relay_url(raw)?;
        let url = RelayUrl::from_str(validated.as_str()).map_err(|err| {
            RuntimeError::Protocol(format!(
                "invalid iroh relay URL {}: {err}",
                redact_url_str(raw)
            ))
        })?;
        let cfg = if validated.scheme() == "http" {
            IrohRelayConfig::new(url, None)
        } else {
            IrohRelayConfig::from(url)
        };
        configs.push(cfg);
    }
    Ok(RelayMap::from_iter(configs))
}

fn resolve_p2p_auth_token(
    auth: Option<&P2pRelayAuth>,
    #[cfg_attr(not(feature = "p2p-iroh-services"), allow(unused_variables))]
    endpoint_pub: EndpointId,
) -> Result<Option<Zeroizing<String>>, RuntimeError> {
    let Some(auth) = auth else {
        return Ok(None);
    };
    match auth {
        P2pRelayAuth::BearerToken(tok) => Ok(Some(tok.clone())),
        #[cfg(feature = "p2p-iroh-services")]
        P2pRelayAuth::IrohServicesSecret(sec) => {
            let api_secret =
                iroh_services::api_secret::ApiSecret::from_str(sec.trim()).map_err(|err| {
                    RuntimeError::Protocol(format!("invalid iroh-services API secret: {err}"))
                })?;
            let rcan = iroh_services::caps::create_api_token_from_secret_key(
                api_secret.secret,
                endpoint_pub,
                Duration::from_secs(30 * 24 * 3600),
                iroh_services::caps::Caps::relay_use(),
            );
            let encoded = data_encoding::BASE32_NOPAD
                .encode(&rcan.encode())
                .to_ascii_lowercase();
            Ok(Some(Zeroizing::new(encoded)))
        }
    }
}

async fn build_iroh_endpoint(
    options: &P2pOptions,
    alpns: Vec<Vec<u8>>,
    secret_seed: Option<Zeroizing<[u8; 32]>>,
) -> Result<Endpoint, RuntimeError> {
    validate_p2p_options(options)?;
    let relay_urls = configured_relay_urls(&options.relay_mode);
    let trusted: &[String] = if options.uri_derived_relays {
        &[]
    } else {
        &relay_urls
    };
    check_relay_hosts_pinned(
        &relay_urls,
        options.allow_private_addrs,
        trusted,
        &options.dns_pins,
    )
    .await?;

    let seed = match secret_seed {
        Some(s) => s,
        None => Zeroizing::new(random_bytes::<32>()?),
    };
    let secret_key = SecretKey::from_bytes(&seed);
    let auth_token = resolve_p2p_auth_token(options.relay_auth.as_ref(), secret_key.public())?;

    let relay_mode = match &options.relay_mode {
        P2pRelayMode::Default => RelayMode::Default,
        P2pRelayMode::Custom(url_str) => {
            let mut map = build_custom_relay_map(std::slice::from_ref(url_str))?;
            if let Some(tok) = auth_token.as_ref() {
                map = map.with_auth_token(tok.as_str());
            }
            RelayMode::Custom(map)
        }
        P2pRelayMode::CustomMany(urls) => {
            let mut map = build_custom_relay_map(urls)?;
            if let Some(tok) = auth_token.as_ref() {
                map = map.with_auth_token(tok.as_str());
            }
            RelayMode::Custom(map)
        }
        P2pRelayMode::Disabled => RelayMode::Disabled,
    };

    let mut builder = Endpoint::builder(presets::Minimal)
        .relay_mode(relay_mode)
        .secret_key(secret_key);
    if !options.dns_pins.is_empty() {
        builder = builder.dns_resolver(iroh::dns::DnsResolver::custom(PinnedDnsResolver {
            pins: options.dns_pins.clone(),
            inner: iroh::dns::DnsResolver::new(),
        }));
    }
    if options.publish_pkarr && !options.hint_dialer {
        builder = builder.address_lookup(iroh::address_lookup::PkarrPublisher::n0_dns());
    }
    if options.resolve_pkarr && !options.hint_dialer {
        builder = builder.address_lookup(iroh::address_lookup::PkarrResolver::n0_dns());
        builder = builder.address_lookup(iroh::address_lookup::DnsAddressLookup::n0_dns());
    }
    if !alpns.is_empty() {
        builder = builder.alpns(alpns);
    }
    builder
        .bind()
        .await
        .map_err(|err| RuntimeError::Protocol(format!("iroh endpoint bind failed: {err}")))
}

/// Formats an [`EndpointAddr`] without direct `?addr=` IP hints (`iroh://<endpoint_id>[?relay=...]`).
#[must_use]
pub fn format_p2p_endpoint(addr: &EndpointAddr) -> String {
    format_p2p_endpoint_with_addrs(addr, false)
}

/// Formats an [`EndpointAddr`] as `iroh://<endpoint_id>[?addr=...&relay=...]`, omitting `?addr=`
/// hints unless `include_addrs` is `true` and unconditionally skipping link-local/metadata IPs.
#[must_use]
pub fn format_p2p_endpoint_with_addrs(addr: &EndpointAddr, include_addrs: bool) -> String {
    let mut query = Vec::new();
    if include_addrs {
        for sock in addr.ip_addrs() {
            if !super::is_metadata_or_link_local_ip(sock.ip()) {
                query.push(format!("addr={sock}"));
            }
        }
    }
    for relay in addr.relay_urls() {
        query.push(format!("relay={relay}"));
    }
    if query.is_empty() {
        format!("iroh://{}", addr.id)
    } else {
        format!("iroh://{}?{}", addr.id, query.join("&"))
    }
}

/// Parses an `iroh://<endpoint_id>[?addr=...&relay=...]` endpoint string into [`EndpointAddr`].
pub fn parse_p2p_endpoint(endpoint: &str) -> Result<EndpointAddr, RuntimeError> {
    parse_p2p_endpoint_filtered(endpoint, true)
}

/// Parses an `iroh://...` endpoint URI while always stripping metadata/link-local IPs
/// and optionally stripping private/loopback/reserved `?addr=` hints.
pub fn parse_p2p_endpoint_filtered(
    endpoint: &str,
    allow_private_addrs: bool,
) -> Result<EndpointAddr, RuntimeError> {
    parse_p2p_endpoint_trusting(endpoint, allow_private_addrs, &[])
}

/// Returns the validated `?relay=` URLs of an `iroh://` or `p2p:iroh://` endpoint string.
///
/// Metadata and link-local relay hosts always fail closed; loopback, private, CGNAT, and ULA
/// relay hosts also fail closed unless `allow_private_addrs`.
pub fn extract_p2p_relay_urls_from_endpoint(
    endpoint: &str,
    allow_private_addrs: bool,
) -> Result<Vec<String>, RuntimeError> {
    let endpoint = endpoint.strip_prefix("p2p:").unwrap_or(endpoint);
    let addr = parse_p2p_endpoint_filtered(endpoint, allow_private_addrs)?;
    Ok(addr.relay_urls().map(ToString::to_string).collect())
}

fn reject_private_relay_host(validated: &url::Url) -> Result<(), RuntimeError> {
    let host = validated.host_str().unwrap_or_default();
    let bare = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    let private = super::is_loopback_host(bare)
        || bare
            .parse::<IpAddr>()
            .is_ok_and(super::is_private_or_reserved_ip);
    if private {
        return Err(RuntimeError::Protocol(format!(
            "private or loopback relay host '{}' requires allow_private_addrs",
            redact_host(bare)
        )));
    }
    Ok(())
}

fn parse_p2p_endpoint_trusting(
    endpoint: &str,
    allow_private_addrs: bool,
    trusted_relays: &[String],
) -> Result<EndpointAddr, RuntimeError> {
    if endpoint.chars().any(char::is_control) {
        return Err(RuntimeError::Protocol(
            "iroh endpoint contains control characters".into(),
        ));
    }
    let raw = endpoint.strip_prefix("iroh://").unwrap_or(endpoint);
    let (id_part, query_part) = raw.split_once('?').unwrap_or((raw, ""));
    let id = EndpointId::from_str(id_part)
        .map_err(|err| RuntimeError::Protocol(format!("invalid iroh endpoint id: {err}")))?;

    let mut addrs = Vec::new();
    if !query_part.is_empty() {
        for pair in query_part.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, val) = pair
                .split_once('=')
                .ok_or_else(|| RuntimeError::Protocol("invalid iroh query param".to_owned()))?;
            match key {
                "addr" => {
                    let sock: SocketAddr = val.parse().map_err(|err| {
                        RuntimeError::Protocol(format!("invalid iroh socket addr: {err}"))
                    })?;
                    if super::is_metadata_or_link_local_ip(sock.ip())
                        || (!allow_private_addrs && super::is_private_or_reserved_ip(sock.ip()))
                    {
                        continue;
                    }
                    addrs.push(TransportAddr::Ip(sock));
                }
                "relay" => {
                    let validated = super::validate_iroh_relay_url(val)?;
                    if !allow_private_addrs
                        && !trusted_relays.iter().any(|t| t == validated.as_str())
                    {
                        reject_private_relay_host(&validated)?;
                    }
                    let url = RelayUrl::from_str(validated.as_str()).map_err(|err| {
                        RuntimeError::Protocol(format!(
                            "invalid iroh relay URL {}: {err}",
                            redact_url_str(val)
                        ))
                    })?;
                    addrs.push(TransportAddr::Relay(url));
                }
                _ => {
                    return Err(RuntimeError::Protocol(
                        "unknown iroh endpoint query parameter".to_owned(),
                    ));
                }
            }
        }
    }
    Ok(EndpointAddr::from_parts(id, addrs))
}

/// An `iroh://` hint reduced to what the lookup-free hint dialer may contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pHintAddr {
    /// Filtered endpoint string (`iroh://<id>[?addr=...&relay=...]`).
    pub endpoint: String,
    /// Hint `relay=` URLs dropped because they are not in the configured relay map.
    pub dropped_relays: Vec<String>,
}

/// Returns the URLs of the relay map an endpoint built with `mode` uses.
fn relay_map_urls(mode: &P2pRelayMode) -> Result<Vec<RelayUrl>, RuntimeError> {
    let map = match mode {
        P2pRelayMode::Default => RelayMode::Default.relay_map(),
        P2pRelayMode::Custom(url) => build_custom_relay_map(std::slice::from_ref(url))?,
        P2pRelayMode::CustomMany(urls) => build_custom_relay_map(urls)?,
        P2pRelayMode::Disabled => return Ok(Vec::new()),
    };
    Ok(map.urls::<Vec<_>>())
}

fn filter_hint_addr(
    hint: &str,
    relay_map: &[RelayUrl],
) -> Result<(EndpointAddr, Vec<String>), SkipReason> {
    let raw = hint.strip_prefix("p2p:").unwrap_or(hint);
    if raw.chars().any(char::is_control) || raw.contains('#') {
        return Err(SkipReason::Invalid);
    }
    let rest = raw.strip_prefix("iroh://").ok_or(SkipReason::Invalid)?;
    let (id_part, query) = rest.split_once('?').unwrap_or((rest, ""));
    let id = EndpointId::from_str(id_part).map_err(|_| SkipReason::Invalid)?;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    let mut relays: Vec<RelayUrl> = Vec::new();
    let mut dropped = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, val) = pair.split_once('=').ok_or(SkipReason::Invalid)?;
        match key {
            "addr" => {
                let sock: SocketAddr = val.parse().map_err(|_| SkipReason::Invalid)?;
                if classify_destination(sock.ip()) != DestClass::Blocked && !addrs.contains(&sock) {
                    addrs.push(sock);
                }
            }
            "relay" => {
                let url = RelayUrl::from_str(val).map_err(|_| SkipReason::Invalid)?;
                if relay_map.contains(&url) {
                    if !relays.contains(&url) {
                        relays.push(url);
                    }
                } else {
                    dropped.push(val.to_owned());
                }
            }
            _ => return Err(SkipReason::Invalid),
        }
    }
    if relays.is_empty() {
        relays = relay_map.to_vec();
    }
    if relays.is_empty() && addrs.is_empty() {
        return Err(SkipReason::IrohRelayNotConfigured);
    }
    let parts = addrs
        .into_iter()
        .map(TransportAddr::Ip)
        .chain(relays.into_iter().map(TransportAddr::Relay));
    Ok((EndpointAddr::from_parts(id, parts), dropped))
}

/// Filters an `iroh://` (or `p2p:iroh://`) hint for the lookup-free hint dialer of `relay_mode`.
///
/// Keeps `relay=` URLs that are members of the relay map of `relay_mode` and `addr=` literals
/// outside the always-blocked set. If no hint relay is in the map, every relay in the map is
/// used. Fails with [`SkipReason::IrohRelayNotConfigured`] when the map is empty and no `addr=`
/// survives, and with [`SkipReason::Invalid`] on a malformed hint.
pub fn filter_p2p_hint(hint: &str, relay_mode: &P2pRelayMode) -> Result<P2pHintAddr, SkipReason> {
    let map = relay_map_urls(relay_mode).map_err(|_| SkipReason::IrohRelayNotConfigured)?;
    let (addr, dropped_relays) = filter_hint_addr(hint, &map)?;
    Ok(P2pHintAddr {
        endpoint: format_p2p_endpoint_with_addrs(&addr, true),
        dropped_relays,
    })
}

struct P2pConnDropper {
    guard: StdMutex<Option<Arc<EndpointGuard>>>,
    conn: StdMutex<Option<Connection>>,
}

impl P2pConnDropper {
    fn new(guard: Arc<EndpointGuard>, conn: Connection) -> Self {
        Self {
            guard: StdMutex::new(Some(guard)),
            conn: StdMutex::new(Some(conn)),
        }
    }

    async fn close_now(&self) {
        let conn = self.conn.lock().expect("p2p conn mutex poisoned").take();
        drop(conn);
        let guard = self.guard.lock().expect("p2p guard mutex poisoned").take();
        if let Some(g_arc) = guard
            && let Ok(g) = Arc::try_unwrap(g_arc)
        {
            g.close_now().await;
        }
    }
}

impl Drop for P2pConnDropper {
    fn drop(&mut self) {
        let conn = self.conn.get_mut().expect("p2p conn mutex poisoned").take();
        let guard = self
            .guard
            .get_mut()
            .expect("p2p guard mutex poisoned")
            .take();
        if let (Some(conn), Some(guard)) = (conn, guard)
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                // Keep QUIC connection open briefly so flushed stream frames and FIN deliver.
                let _ = timeout(Duration::from_millis(250), conn.closed()).await;
                drop(conn);
                drop(guard);
            });
        }
    }
}

struct P2pFinishSend(SendStream);

impl Drop for P2pFinishSend {
    fn drop(&mut self) {
        let _ = self.0.finish();
    }
}

/// Bidirectional QUIC stream over an `iroh` P2P connection implementing [`PathStream`].
pub struct P2pStream {
    conn_drop: Arc<P2pConnDropper>,
    peer_ip: Option<IpAddr>,
    peer_transport_id: String,
    send: P2pFinishSend,
    recv: RecvStream,
    write_timeout: Duration,
}

impl P2pStream {
    fn new(
        guard: Arc<EndpointGuard>,
        conn: Connection,
        send: SendStream,
        recv: RecvStream,
        write_timeout: Duration,
    ) -> Self {
        let peer_transport_id = conn.remote_id().to_string();
        Self {
            conn_drop: Arc::new(P2pConnDropper::new(guard, conn)),
            peer_ip: None,
            peer_transport_id,
            send: P2pFinishSend(send),
            recv,
            write_timeout,
        }
    }
}

async fn p2p_send_chunk(
    send: &mut SendStream,
    write_timeout: Duration,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    if bytes.len() > MAX_OUTER_FRAME_LEN {
        return Err(RuntimeError::FrameTooLarge {
            size: bytes.len(),
            max: MAX_OUTER_FRAME_LEN,
        });
    }
    match timeout(write_timeout, send.write_all(bytes)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(RuntimeError::Protocol(err.to_string())),
        Err(_) => Err(RuntimeError::Timeout("p2p stream write timed out")),
    }
}

async fn p2p_recv_chunk(recv: &mut RecvStream, buf: &mut [u8]) -> Result<usize, RuntimeError> {
    if buf.is_empty() {
        return Ok(0);
    }
    match recv.read(buf).await {
        Ok(Some(n)) => Ok(n),
        Ok(None) => Ok(0),
        Err(err) => Err(RuntimeError::Protocol(err.to_string())),
    }
}

async fn p2p_close_write(send: &mut SendStream, conn_drop: &P2pConnDropper) {
    let _ = send.finish();
    let _ = timeout(Duration::from_millis(50), send.stopped()).await;
    conn_drop.close_now().await;
}

struct P2pReadHalf {
    recv: RecvStream,
    _conn_drop: Arc<P2pConnDropper>,
}

struct P2pWriteHalf {
    send: P2pFinishSend,
    write_timeout: Duration,
    conn_drop: Arc<P2pConnDropper>,
}

#[async_trait]
impl PathReader for P2pReadHalf {
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        p2p_recv_chunk(&mut self.recv, buf).await
    }
}

#[async_trait]
impl PathWriter for P2pWriteHalf {
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        p2p_send_chunk(&mut self.send.0, self.write_timeout, bytes).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        p2p_close_write(&mut self.send.0, &self.conn_drop).await;
        Ok(())
    }
}

#[async_trait]
impl PathStream for P2pStream {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    fn peer_transport_id(&self) -> Option<String> {
        Some(self.peer_transport_id.clone())
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        p2p_send_chunk(&mut self.send.0, self.write_timeout, bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        p2p_recv_chunk(&mut self.recv, buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        p2p_close_write(&mut self.send.0, &self.conn_drop).await;
        Ok(())
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        let this = *self;
        (
            Box::new(P2pReadHalf {
                recv: this.recv,
                _conn_drop: Arc::clone(&this.conn_drop),
            }),
            Box::new(P2pWriteHalf {
                send: this.send,
                write_timeout: this.write_timeout,
                conn_drop: this.conn_drop,
            }),
        )
    }
}

/// Listener accepting QUIC peer connections via `iroh` (`p2p`).
pub struct P2pListener {
    guard: Arc<EndpointGuard>,
    local_ep: String,
    advertise_direct_addrs: bool,
    accepted_rx: mpsc::Receiver<P2pStream>,
    accept_task: JoinHandle<()>,
    write_timeout: Duration,
}

impl P2pListener {
    /// Binds a new `iroh` P2P endpoint listener under `relay_mode` with a fresh ephemeral key.
    pub async fn bind(relay_mode: P2pRelayMode) -> Result<Self, RuntimeError> {
        Self::bind_with_options(P2pOptions::for_listener(relay_mode), None).await
    }

    /// Binds a new `iroh` P2P endpoint listener under `relay_mode` with a deterministic secret seed.
    pub async fn bind_with_secret(
        relay_mode: P2pRelayMode,
        secret_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, RuntimeError> {
        Self::bind_with_options(P2pOptions::for_listener(relay_mode), Some(secret_seed)).await
    }

    /// Binds a new `iroh` P2P endpoint listener with explicit privacy and lookup options.
    pub async fn bind_with_options(
        options: P2pOptions,
        secret_seed: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, RuntimeError> {
        let endpoint =
            build_iroh_endpoint(&options, vec![TENDRIL_P2P_ALPN.to_vec()], secret_seed).await?;
        if !matches!(options.relay_mode, P2pRelayMode::Disabled) {
            let _ = timeout(Duration::from_secs(3), endpoint.online()).await;
        }
        let advertise_direct_addrs = options.advertise_direct_addrs;
        let local_ep = format_p2p_endpoint_with_addrs(&endpoint.addr(), advertise_direct_addrs);
        let write_timeout = DEFAULT_WRITE_TIMEOUT;
        let guard = EndpointGuard::new(endpoint);
        let (accepted_tx, accepted_rx) = mpsc::channel(32);
        let incoming_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let pre_accepts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        let peer_accepts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let guard_clone = Arc::clone(&guard);

        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = guard_clone.endpoint.accept().await {
                let source_key = normalize_incoming_source(&incoming.remote_addr());
                let Some(pre_guard) = PeerAcceptGuard::try_acquire(
                    Arc::clone(&pre_accepts),
                    source_key,
                    MAX_CONCURRENT_ACCEPTS_PER_PEER,
                ) else {
                    incoming.ignore();
                    continue;
                };
                let Ok(pre_permit) = Arc::clone(&incoming_sem).try_acquire_owned() else {
                    drop(pre_guard);
                    incoming.ignore();
                    continue;
                };
                let tx_c = accepted_tx.clone();
                let stream_guard = Arc::clone(&guard_clone);
                let peer_counts = Arc::clone(&peer_accepts);
                let post_sem = Arc::clone(&sem);
                tokio::spawn(async move {
                    let conn_res = timeout(P2P_CONNECT_TIMEOUT, incoming).await;
                    drop(pre_permit);
                    drop(pre_guard);
                    let Ok(Ok(conn)) = conn_res else {
                        return;
                    };
                    let Ok(_permit) = post_sem.try_acquire_owned() else {
                        conn.close(0u32.into(), b"rate_limited");
                        return;
                    };
                    let Some(_peer_guard) = PeerAcceptGuard::try_acquire(
                        peer_counts,
                        conn.remote_id(),
                        MAX_CONCURRENT_ACCEPTS_PER_PEER,
                    ) else {
                        conn.close(0u32.into(), b"rate_limited");
                        return;
                    };
                    let Ok(Ok((send, mut recv))) =
                        timeout(P2P_ACCEPT_BI_TIMEOUT, conn.accept_bi()).await
                    else {
                        return;
                    };
                    let mut magic = [0u8; 1];
                    if let Ok(Ok(())) =
                        timeout(P2P_MAGIC_TIMEOUT, recv.read_exact(&mut magic)).await
                        && magic[0] == P2P_STREAM_MAGIC
                    {
                        let stream = P2pStream::new(stream_guard, conn, send, recv, write_timeout);
                        let _ = timeout(P2P_ACCEPT_BI_TIMEOUT, tx_c.send(stream)).await;
                    }
                });
            }
        });

        Ok(Self {
            guard,
            local_ep,
            advertise_direct_addrs,
            accepted_rx,
            accept_task,
            write_timeout,
        })
    }

    /// Returns the underlying `iroh` endpoint identifier.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.guard.endpoint.id()
    }

    /// Returns a fresh serialized `iroh://...` address snapshot (useful once relays finish homing).
    #[must_use]
    pub fn current_endpoint(&self) -> String {
        format_p2p_endpoint_with_addrs(&self.guard.endpoint.addr(), self.advertise_direct_addrs)
    }

    /// Returns the configured per-write timeout.
    #[must_use]
    pub fn write_timeout(&self) -> Duration {
        self.write_timeout
    }
}

impl Drop for P2pListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

#[async_trait]
impl PathListener for P2pListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = self.accepted_rx.recv().await.ok_or(RuntimeError::Closed)?;
        Ok(Box::new(stream))
    }

    fn local_endpoint(&self) -> String {
        let current = format_p2p_endpoint_with_addrs(
            &self.guard.endpoint.addr(),
            self.advertise_direct_addrs,
        );
        if current == format!("iroh://{}", self.guard.endpoint.id()) {
            self.local_ep.clone()
        } else {
            current
        }
    }
}

/// Dialer opening authenticated Tendril byte streams over `iroh` (`iroh://...`).
pub struct P2pDialer {
    guard: Arc<EndpointGuard>,
    write_timeout: Duration,
    allow_private_addrs: bool,
    trusted_relays: Vec<String>,
    /// Relay map of a lookup-free hint dialer; `None` for every other dialer.
    hint_relay_map: Option<Vec<RelayUrl>>,
    /// Relay host names answered from their checked addresses ([`P2pOptions::with_dns_pins`]),
    /// at bind and on every dial.
    dns_pins: Vec<(String, Vec<IpAddr>)>,
}

fn configured_relay_urls(mode: &P2pRelayMode) -> Vec<String> {
    let raw: &[String] = match mode {
        P2pRelayMode::Custom(url) => std::slice::from_ref(url),
        P2pRelayMode::CustomMany(urls) => urls,
        P2pRelayMode::Default | P2pRelayMode::Disabled => &[],
    };
    raw.iter()
        .filter_map(|u| super::validate_iroh_relay_url(u).ok())
        .map(|u| u.as_str().to_owned())
        .collect()
}

/// Resolves each relay URL host and rejects metadata and link-local addresses always, and
/// private, loopback, or reserved addresses unless `allow_private_addrs` or the URL is trusted.
/// A host named in `pins` is answered from its checked addresses without a lookup.
///
/// Fails closed on a lookup error, a lookup timeout, or zero resolved addresses. For a host
/// without a DNS pin the resolved addresses cannot be pinned into `iroh`, so a resolver that
/// answers differently on the second lookup remains an accepted residual limit; a pinned host
/// is answered from its pin by this check and by `iroh`.
async fn check_relay_hosts_pinned(
    relay_urls: &[String],
    allow_private_addrs: bool,
    trusted_relays: &[String],
    pins: &[(String, Vec<IpAddr>)],
) -> Result<(), RuntimeError> {
    for raw in relay_urls {
        let parsed = url::Url::parse(raw)
            .map_err(|err| RuntimeError::Protocol(format!("invalid iroh relay URL: {err}")))?;
        let trusted = trusted_relays.iter().any(|t| t == parsed.as_str());
        let host = parsed
            .host_str()
            .ok_or_else(|| RuntimeError::Protocol("iroh relay URL is missing a host".into()))?;
        let bare = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.');
        if bare.is_empty() {
            return Err(RuntimeError::Protocol(
                "iroh relay URL is missing a host".into(),
            ));
        }
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| RuntimeError::Protocol("iroh relay URL is missing a port".into()))?;
        let shown = redact_host(bare);
        let pinned = pinned_addrs(pins, bare)
            .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
        let resolved: Vec<SocketAddr> = if let Some(addrs) = pinned {
            addrs
        } else {
            match timeout(RELAY_DNS_TIMEOUT, tokio::net::lookup_host((bare, port))).await {
                Ok(Ok(iter)) => iter.collect(),
                Ok(Err(err)) => {
                    return Err(RuntimeError::Protocol(format!(
                        "iroh relay host '{shown}' failed to resolve: {}",
                        redact_text(&err.to_string().replace(bare, &shown))
                    )));
                }
                Err(_) => {
                    return Err(RuntimeError::Timeout(
                        "iroh relay host resolution timed out",
                    ));
                }
            }
        };
        if resolved.is_empty() {
            return Err(RuntimeError::Protocol(format!(
                "iroh relay host '{shown}' resolved to zero addresses"
            )));
        }
        for sock in resolved {
            let ip = sock.ip();
            if super::is_metadata_or_link_local_ip(ip)
                || (!allow_private_addrs && !trusted && super::is_private_or_reserved_ip(ip))
            {
                return Err(RuntimeError::Protocol(format!(
                    "iroh relay host '{shown}' resolved to forbidden address '{ip}'"
                )));
            }
        }
    }
    Ok(())
}

fn pinned_addrs<'a>(pins: &'a [(String, Vec<IpAddr>)], host: &str) -> Option<&'a [IpAddr]> {
    let host = host.trim_end_matches('.');
    pins.iter()
        .find(|(h, _)| h.eq_ignore_ascii_case(host))
        .map(|(_, ips)| ips.as_slice())
}

type DnsAnswer<T> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<iroh::dns::BoxIter<T>, iroh::dns::DnsError>>
            + Send
            + 'static,
    >,
>;

const PINNED_DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Iroh DNS for an operator endpoint: pinned relay host names answer from the addresses the
/// egress layer checked (one lookup per dial), other names resolve through the default
/// resolver with always-blocked answers removed.
#[derive(Debug)]
struct PinnedDnsResolver {
    pins: Vec<(String, Vec<IpAddr>)>,
    inner: iroh::dns::DnsResolver,
}

impl PinnedDnsResolver {
    fn answer<T: Send + 'static>(
        &self,
        host: String,
        pick: fn(IpAddr) -> Option<T>,
        v6: bool,
    ) -> DnsAnswer<T> {
        if let Some(ips) = pinned_addrs(&self.pins, &host) {
            let out: Vec<T> = ips.iter().copied().filter_map(pick).collect();
            return Box::pin(async move { Ok(Box::new(out.into_iter()) as iroh::dns::BoxIter<T>) });
        }
        let inner = self.inner.clone();
        Box::pin(async move {
            let ips: Vec<IpAddr> = if v6 {
                inner
                    .lookup_ipv6(host, PINNED_DNS_LOOKUP_TIMEOUT)
                    .await?
                    .collect()
            } else {
                inner
                    .lookup_ipv4(host, PINNED_DNS_LOOKUP_TIMEOUT)
                    .await?
                    .collect()
            };
            let out: Vec<T> = ips
                .into_iter()
                .filter(|ip| classify_destination(*ip) != DestClass::Blocked)
                .filter_map(pick)
                .collect();
            Ok(Box::new(out.into_iter()) as iroh::dns::BoxIter<T>)
        })
    }
}

impl iroh::dns::Resolver for PinnedDnsResolver {
    fn lookup_ipv4(&self, host: String) -> DnsAnswer<std::net::Ipv4Addr> {
        self.answer(
            host,
            |ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            },
            false,
        )
    }

    fn lookup_ipv6(&self, host: String) -> DnsAnswer<std::net::Ipv6Addr> {
        self.answer(
            host,
            |ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => None,
            },
            true,
        )
    }

    fn lookup_txt(&self, host: String) -> DnsAnswer<iroh::dns::TxtRecordData> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let records: Vec<_> = inner
                .lookup_txt(host, PINNED_DNS_LOOKUP_TIMEOUT)
                .await?
                .collect();
            Ok(Box::new(records.into_iter()) as iroh::dns::BoxIter<_>)
        })
    }

    fn clear_cache(&self) {
        self.inner.clear_cache();
    }

    fn reset(&self) -> Box<dyn iroh::dns::Resolver> {
        self.inner.reset();
        Box::new(Self {
            pins: self.pins.clone(),
            inner: self.inner.clone(),
        })
    }
}

impl P2pDialer {
    /// Binds a client endpoint for dialing `endpoint`, deriving custom relays from its `?relay=`
    /// URLs per [`P2pOptions::for_endpoint`].
    pub async fn bind_for_endpoint(
        endpoint: &str,
        explicit_mode: Option<P2pRelayMode>,
        allow_private_addrs: bool,
    ) -> Result<Self, RuntimeError> {
        Self::bind_with_options(P2pOptions::for_endpoint(
            endpoint,
            explicit_mode,
            allow_private_addrs,
        )?)
        .await
    }

    /// Binds the lookup-free hint dialer for URI hints and stored routes
    /// ([`P2pOptions::for_hint_dialer`]).
    pub async fn bind_hint_dialer(
        configured_mode: Option<P2pRelayMode>,
    ) -> Result<Self, RuntimeError> {
        Self::bind_with_options(P2pOptions::for_hint_dialer(configured_mode)).await
    }

    /// Binds a client `iroh` endpoint configured with `relay_mode`.
    pub async fn bind(relay_mode: P2pRelayMode) -> Result<Self, RuntimeError> {
        Self::bind_with_options(P2pOptions::for_dialer(relay_mode)).await
    }

    /// Binds a client `iroh` endpoint with explicit privacy and lookup options.
    pub async fn bind_with_options(options: P2pOptions) -> Result<Self, RuntimeError> {
        let allow_private_addrs = options.allow_private_addrs;
        let trusted_relays = if options.uri_derived_relays {
            Vec::new()
        } else {
            configured_relay_urls(&options.relay_mode)
        };
        let hint_relay_map = if options.hint_dialer {
            Some(relay_map_urls(&options.relay_mode)?)
        } else {
            None
        };
        let endpoint = build_iroh_endpoint(&options, Vec::new(), None).await?;
        Ok(Self {
            guard: EndpointGuard::new(endpoint),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            allow_private_addrs,
            trusted_relays,
            hint_relay_map,
            dns_pins: options.dns_pins,
        })
    }

    /// Returns `true` for a dialer built with [`P2pOptions::for_hint_dialer`].
    #[must_use]
    pub fn is_hint_dialer(&self) -> bool {
        self.hint_relay_map.is_some()
    }

    /// Returns `true` when the endpoint has any address lookup service installed.
    #[must_use]
    pub fn uses_address_lookup(&self) -> bool {
        self.guard
            .endpoint
            .address_lookup()
            .is_ok_and(|services| !services.is_empty())
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Allows dialing private/loopback `?addr=` hints on relayed P2P connections.
    #[must_use]
    pub fn with_allow_private_addrs(mut self, allow: bool) -> Self {
        self.allow_private_addrs = allow;
        self
    }

    /// Gracefully closes the client endpoint handle when no active streams still hold it.
    pub async fn close(self) {
        if let Ok(guard) = Arc::try_unwrap(self.guard) {
            guard.close_now().await;
        }
    }
}

#[async_trait]
impl PathDialer for P2pDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let addr = if let Some(map) = &self.hint_relay_map {
            filter_hint_addr(endpoint, map)
                .map_err(|reason| {
                    RuntimeError::Protocol(format!("iroh hint is not dialable: {reason}"))
                })?
                .0
        } else {
            let addr = parse_p2p_endpoint_trusting(
                endpoint,
                self.allow_private_addrs,
                &self.trusted_relays,
            )?;
            let relay_urls: Vec<String> = addr.relay_urls().map(ToString::to_string).collect();
            check_relay_hosts_pinned(
                &relay_urls,
                self.allow_private_addrs,
                &self.trusted_relays,
                &self.dns_pins,
            )
            .await?;
            addr
        };
        let conn = timeout(
            P2P_HANDSHAKE_TIMEOUT,
            self.guard.endpoint.connect(addr, TENDRIL_P2P_ALPN),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("p2p connect timed out"))?
        .map_err(|err| RuntimeError::Protocol(format!("p2p connect failed: {err}")))?;

        let (mut send, recv) = timeout(P2P_HANDSHAKE_TIMEOUT, conn.open_bi())
            .await
            .map_err(|_| RuntimeError::Timeout("p2p open_bi timed out"))?
            .map_err(|err| RuntimeError::Protocol(format!("p2p open_bi failed: {err}")))?;

        // Write a 1-byte stream marker immediately so the peer's QUIC accept_bi() resolves.
        timeout(self.write_timeout, send.write_all(&[P2P_STREAM_MAGIC]))
            .await
            .map_err(|_| RuntimeError::Timeout("p2p stream opener write timed out"))?
            .map_err(|err| RuntimeError::Protocol(format!("p2p stream opener failed: {err}")))?;

        Ok(Box::new(P2pStream::new(
            Arc::clone(&self.guard),
            conn,
            send,
            recv,
            self.write_timeout,
        )))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    async fn check_relay_hosts_post_dns(
        relay_urls: &[String],
        allow_private_addrs: bool,
        trusted_relays: &[String],
    ) -> Result<(), RuntimeError> {
        check_relay_hosts_pinned(relay_urls, allow_private_addrs, trusted_relays, &[]).await
    }

    #[test]
    fn parse_p2p_endpoint_supports_ipv6_relay_and_rejects_unknown_params() {
        let ep_id = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        let addr_ipv6 = "[::1]:4433";
        let relay = "https://relay.example/";
        let uri = format!("iroh://{ep_id}?addr={addr_ipv6}&relay={relay}");
        let parsed = parse_p2p_endpoint(&uri).expect("parse ipv6 + relay URI");
        assert_eq!(parsed.id, ep_id);
        assert_eq!(parsed.ip_addrs().count(), 1);
        assert_eq!(parsed.relay_urls().count(), 1);

        let bare = parse_p2p_endpoint(&format!("iroh://{ep_id}")).expect("bare endpoint");
        assert_eq!(bare.id, ep_id);
        assert_eq!(bare.ip_addrs().count(), 0);

        let err = parse_p2p_endpoint(&format!("iroh://{ep_id}?unknown=1"));
        assert!(matches!(err, Err(RuntimeError::Protocol(_))));
    }

    #[test]
    fn incoming_source_key_normalizes_ipv6_prefix_and_caps_concurrent_guards() {
        let counts = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let a1 = normalize_incoming_source(&iroh::endpoint::IncomingAddr::Ip(
            "[2001:db8:1:2::10]:4433".parse().expect("sock"),
        ));
        let a2 = normalize_incoming_source(&iroh::endpoint::IncomingAddr::Ip(
            "[2001:db8:1:2:ffff::99]:5555".parse().expect("sock"),
        ));
        assert_eq!(a1, a2);

        let g1 = PeerAcceptGuard::try_acquire(Arc::clone(&counts), a1.clone(), 4).expect("1");
        let g2 = PeerAcceptGuard::try_acquire(Arc::clone(&counts), a1.clone(), 4).expect("2");
        let g3 = PeerAcceptGuard::try_acquire(Arc::clone(&counts), a1.clone(), 4).expect("3");
        let g4 = PeerAcceptGuard::try_acquire(Arc::clone(&counts), a2, 4).expect("4");
        assert!(PeerAcceptGuard::try_acquire(Arc::clone(&counts), a1.clone(), 4).is_none());
        let other = normalize_incoming_source(&iroh::endpoint::IncomingAddr::Ip(
            "192.0.2.50:4433".parse().expect("sock"),
        ));
        let g_other = PeerAcceptGuard::try_acquire(Arc::clone(&counts), other, 4).expect("other");
        drop((g1, g2, g3, g4, g_other));
        assert!(counts.lock().expect("lock").is_empty());
    }

    #[test]
    fn private_relay_hosts_fail_closed_unless_private_addrs_allowed() {
        let ep_id = iroh::SecretKey::from_bytes(&[21u8; 32]).public();
        for host in [
            "http://localhost:8080/",
            "http://127.0.0.1:8080/",
            "http://[::1]:8080/",
            "https://10.0.0.5/",
            "https://192.168.1.5/",
            "https://100.64.0.1/",
            "https://[fd00::1]/",
        ] {
            let uri = format!("iroh://{ep_id}?relay={host}");
            assert!(
                parse_p2p_endpoint_filtered(&uri, false).is_err(),
                "{host} must fail closed"
            );
            assert!(
                parse_p2p_endpoint_filtered(&uri, true).is_ok(),
                "{host} must be allowed with allow_private_addrs"
            );
        }
        let public = format!("iroh://{ep_id}?relay=https://relay.example/");
        assert!(parse_p2p_endpoint_filtered(&public, false).is_ok());
        let meta = format!("iroh://{ep_id}?relay=https://169.254.169.254/");
        assert!(parse_p2p_endpoint_filtered(&meta, true).is_err());
    }

    #[test]
    fn extract_relay_urls_and_for_endpoint_derive_custom_relays() {
        let ep_id = iroh::SecretKey::from_bytes(&[22u8; 32]).public();
        let one = format!("iroh://{ep_id}?relay=https://r1.example/");
        let urls = extract_p2p_relay_urls_from_endpoint(&one, false).expect("extract");
        assert_eq!(urls, vec!["https://r1.example/".to_owned()]);
        let prefixed = format!("p2p:iroh://{ep_id}?relay=https://r1.example/");
        assert_eq!(
            extract_p2p_relay_urls_from_endpoint(&prefixed, false).expect("prefixed"),
            urls
        );
        assert!(
            extract_p2p_relay_urls_from_endpoint(&format!("iroh://{ep_id}"), false)
                .expect("bare")
                .is_empty()
        );

        let opts = P2pOptions::for_endpoint(&one, None, false).expect("derive");
        assert_eq!(
            opts.relay_mode,
            P2pRelayMode::Custom("https://r1.example/".to_owned())
        );
        assert!(!opts.publish_pkarr && !opts.resolve_pkarr);

        let many = format!("iroh://{ep_id}?relay=https://r1.example/&relay=https://r2.example/");
        let opts = P2pOptions::for_endpoint(&many, Some(P2pRelayMode::Default), false)
            .expect("derive many");
        assert!(matches!(opts.relay_mode, P2pRelayMode::CustomMany(ref u) if u.len() == 2));
        assert!(!opts.resolve_pkarr);

        let disabled = P2pOptions::for_endpoint(&one, Some(P2pRelayMode::Disabled), false)
            .expect("explicit disabled");
        assert_eq!(disabled.relay_mode, P2pRelayMode::Disabled);

        let bare = P2pOptions::for_endpoint(&format!("iroh://{ep_id}"), None, false)
            .expect("bare default");
        assert_eq!(bare.relay_mode, P2pRelayMode::Default);
        assert!(bare.resolve_pkarr);

        let private = format!("iroh://{ep_id}?relay=http://127.0.0.1:9/");
        assert!(P2pOptions::for_endpoint(&private, None, false).is_err());
        assert!(P2pOptions::for_endpoint(&private, None, true).is_ok());
    }

    #[tokio::test]
    async fn relay_auth_is_refused_for_default_public_relays() {
        let opts = P2pOptions::for_dialer(P2pRelayMode::Default).with_relay_auth(Some(
            P2pRelayAuth::BearerToken(Zeroizing::new("tok".to_owned())),
        ));
        assert!(matches!(
            P2pDialer::bind_with_options(opts).await,
            Err(RuntimeError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn dial_rejects_private_relay_hint_before_connecting() {
        let dialer = P2pDialer::bind_with_options(
            P2pOptions::for_dialer(P2pRelayMode::Disabled).with_allow_private_addrs(false),
        )
        .await
        .expect("bind");
        let ep_id = iroh::SecretKey::from_bytes(&[23u8; 32]).public();
        let err = dialer
            .dial(&format!("iroh://{ep_id}?relay=https://10.0.0.5/"))
            .await
            .err()
            .expect("private relay hint must be rejected");
        assert!(
            matches!(&err, RuntimeError::Protocol(m) if m.contains("allow_private_addrs")),
            "{err:?}"
        );
        dialer.close().await;
    }

    #[tokio::test]
    async fn post_dns_relay_check_blocks_forbidden_resolved_addresses() {
        let loopback = vec!["https://localhost/".to_owned()];
        assert!(
            check_relay_hosts_post_dns(&loopback, false, &[])
                .await
                .is_err()
        );
        assert!(
            check_relay_hosts_post_dns(&loopback, true, &[])
                .await
                .is_ok()
        );
        assert!(
            check_relay_hosts_post_dns(&loopback, false, &loopback)
                .await
                .is_ok()
        );
        let metadata = vec!["https://169.254.169.254/".to_owned()];
        assert!(
            check_relay_hosts_post_dns(&metadata, true, &metadata)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn uri_derived_relays_are_never_trusted_and_are_checked_before_bind() {
        let ep_id = iroh::SecretKey::from_bytes(&[25u8; 32]).public();
        let uri = format!("iroh://{ep_id}?relay=http://127.0.0.1:9/");
        let derived = P2pDialer::bind_with_options(
            P2pOptions::for_endpoint(&uri, None, true).expect("derive"),
        )
        .await
        .expect("bind derived");
        assert!(derived.trusted_relays.is_empty());
        derived.close().await;

        let explicit = P2pDialer::bind_with_options(P2pOptions::for_dialer(P2pRelayMode::Custom(
            "http://127.0.0.1:9/".to_owned(),
        )))
        .await
        .expect("explicit loopback relay stays permitted");
        assert_eq!(
            explicit.trusted_relays,
            vec!["http://127.0.0.1:9/".to_owned()]
        );
        explicit.close().await;

        let mut forged =
            P2pOptions::for_dialer(P2pRelayMode::Custom("http://127.0.0.1:9/".to_owned()));
        forged.uri_derived_relays = true;
        assert!(matches!(
            P2pDialer::bind_with_options(forged).await,
            Err(RuntimeError::Protocol(_))
        ));
    }

    #[test]
    fn for_group_dialer_requires_an_explicit_relay_mode() {
        let auth = Some(P2pRelayAuth::BearerToken("tok".to_owned().into()));
        assert!(
            P2pOptions::for_group_dialer(None, false, Some(true), Some(true), auth.clone())
                .is_none()
        );
        let local = P2pOptions::for_group_dialer(None, true, None, None, None).expect("local");
        assert!(matches!(local.relay_mode, P2pRelayMode::Disabled));
        assert!(local.allow_private_addrs && !local.resolve_pkarr);
        let custom = P2pOptions::for_group_dialer(
            Some(P2pRelayMode::Custom("https://relay.example/".to_owned())),
            false,
            Some(true),
            None,
            auth,
        )
        .expect("custom");
        assert!(matches!(custom.relay_mode, P2pRelayMode::Custom(_)));
        assert!(custom.resolve_pkarr && custom.relay_auth.is_some());
        assert!(!custom.publish_pkarr && !custom.allow_private_addrs);
    }

    #[test]
    fn for_endpoint_keeps_explicit_local_relays_despite_uri_hints() {
        let ep_id = iroh::SecretKey::from_bytes(&[26u8; 32]).public();
        let uri = format!("iroh://{ep_id}?relay=http://127.0.0.1:3340/");
        let custom = P2pOptions::for_endpoint(
            &uri,
            Some(P2pRelayMode::Custom("http://127.0.0.1:3340/".to_owned())),
            false,
        )
        .expect("explicit loopback relay");
        assert!(matches!(custom.relay_mode, P2pRelayMode::Custom(_)));
        assert!(!custom.uri_derived_relays);
        let local = P2pOptions::for_endpoint(&uri, Some(P2pRelayMode::Disabled), false)
            .expect("local mode");
        assert!(local.allow_private_addrs);
        assert!(P2pOptions::for_endpoint(&uri, None, false).is_err());
    }

    /// A dial whose relay host is pinned must pass the relay check without a system lookup
    /// (`.invalid` never resolves), then wait on the connect: no relay listens there.
    pub(crate) async fn assert_pinned_dial_skips_lookup(
        dial: impl std::future::Future<Output = Result<Box<dyn PathStream>, RuntimeError>>,
    ) {
        match timeout(Duration::from_secs(3), dial).await {
            Err(_) => {}
            Ok(Err(err)) => assert!(!err.to_string().contains("resolve"), "{err}"),
            Ok(Ok(_)) => panic!("no relay listens on the pinned address"),
        }
    }

    pub(crate) const PINNED_RELAY: &str = "pinned-relay.invalid";

    #[tokio::test]
    async fn dial_answers_pinned_relay_hosts_without_a_lookup() {
        let ep_id = iroh::SecretKey::from_bytes(&[29u8; 32]).public();
        let uri = format!("iroh://{ep_id}?relay=https://{PINNED_RELAY}/");
        let opts = P2pOptions::for_endpoint(&uri, None, true)
            .expect("derive")
            .with_dns_pins(vec![(
                PINNED_RELAY.to_owned(),
                vec![IpAddr::from([127, 0, 0, 1])],
            )]);
        let dialer = P2pDialer::bind_with_options(opts).await.expect("bind");
        assert_pinned_dial_skips_lookup(dialer.dial(&uri)).await;
        dialer.close().await;
    }

    #[tokio::test]
    async fn relay_host_errors_never_echo_a_raw_host() {
        let unresolvable = vec!["https://x;tok=s3cret.invalid/".to_owned()];
        let pinned_bad = vec!["https://p;s3cret/".to_owned()];
        let pins = [("p;s3cret".to_owned(), vec![IpAddr::from([10, 0, 0, 1])])];
        let errs = [
            check_relay_hosts_post_dns(&unresolvable, true, &[]).await,
            check_relay_hosts_pinned(&pinned_bad, false, &[], &pins).await,
            reject_private_relay_host(
                &url::Url::parse("https://x;s3cret.localhost/").expect("url"),
            ),
        ];
        for err in errs {
            let text = err.expect_err("refused").to_string();
            assert!(!text.contains("s3cret"), "{text}");
        }
    }

    #[tokio::test]
    async fn post_dns_relay_check_fails_closed_on_unresolvable_or_empty_hosts() {
        let unresolvable = vec!["https://relay-host.invalid/".to_owned()];
        assert!(
            check_relay_hosts_post_dns(&unresolvable, true, &unresolvable)
                .await
                .is_err()
        );
        let dotted = vec!["https://./".to_owned()];
        assert!(matches!(
            check_relay_hosts_post_dns(&dotted, true, &dotted).await,
            Err(RuntimeError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn relay_auth_is_refused_for_uri_derived_relays() {
        let ep_id = iroh::SecretKey::from_bytes(&[27u8; 32]).public();
        let uri = format!("iroh://{ep_id}?relay=http://127.0.0.1:9/");
        let opts = P2pOptions::for_endpoint(&uri, None, true)
            .expect("derive")
            .with_relay_auth(Some(P2pRelayAuth::BearerToken(Zeroizing::new(
                "tok".to_owned(),
            ))));
        assert!(matches!(
            P2pDialer::bind_with_options(opts).await,
            Err(RuntimeError::Protocol(m)) if m.contains("peer URI")
        ));
    }

    #[tokio::test]
    async fn pinned_dns_answers_pinned_relays_only_from_checked_addresses() {
        let pinned = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));
        let resolver = iroh::dns::DnsResolver::custom(PinnedDnsResolver {
            pins: vec![("relay.example".to_owned(), vec![pinned])],
            inner: iroh::dns::DnsResolver::new(),
        });
        let v4: Vec<IpAddr> = resolver
            .lookup_ipv4("Relay.Example.", Duration::from_secs(1))
            .await
            .expect("pinned")
            .collect();
        assert_eq!(v4, vec![pinned]);
        let v6: Vec<IpAddr> = resolver
            .lookup_ipv6("relay.example", Duration::from_secs(1))
            .await
            .expect("pinned")
            .collect();
        assert!(v6.is_empty());
        assert_eq!(
            pinned_addrs(
                &[("relay.example".to_owned(), vec![pinned])],
                "other.example"
            ),
            None
        );
    }
}
