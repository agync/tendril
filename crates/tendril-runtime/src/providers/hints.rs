//! Candidate builder for pairing URI hints, stored routes and operator endpoints, the peer route
//! setter, and offline application of signed pairing URIs (`spec/pairing-v1.md`).
//!
//! Every hint passes the egress layer ([`check_hint`]) before it becomes a candidate. Each
//! candidate's address is its original hint string, so the driver knows which hint won; the
//! per-provider dialers of a [`CandidateSet`] map it to the checked dial target.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use subtle::ConstantTimeEq;
use tendril_core::crypto::b64url_decode_array;
use tendril_core::error::CoreError;
use tendril_core::pairing::{
    PairingPathKind, PairingUri, RouteCheck, RoutePolicy, VerifiedRouteStatement,
    classify_endpoint_hint, is_v2_relay_hint, is_valid_pairing_endpoint_hint,
};
use tendril_core::policy::{CandidateEndpoint, ProviderId, is_numeric_host_addr};
use tendril_core::roster::{
    OperatorEndpoint, PeerState, Roster, RosterEntry, RouteMeta, RouteSource, StoredRoute,
};
use zeroize::Zeroizing;

use super::egress::{
    DestClass, EgressContext, EgressDialer, EgressKind, HintSource, SkipReason, SkippedHint,
    check_hint, classify_destination,
};
#[cfg(feature = "p2p-iroh")]
use super::p2p::{P2pDialer, P2pOptions, P2pRelayAuth, P2pRelayMode};
use super::relay::{RelayHintDialer, gate_relay_auth};
use super::relay_v2::MailboxSecretSource;
use super::{
    BrokerDialer, DirectDialer, LocalDialer, OverlayDialer, RelayClientAuth, RelayV2Dialer,
};
use crate::announce::{LastRouteSet, RosterAccess};
use crate::error::RuntimeError;
use crate::provider::{PathDialer, PathStream};
use crate::redact::redact_hint;

/// Most `operator` routes [`set_peer_routes`] accepts in one call.
pub const MAX_OPERATOR_ROUTE_INPUTS: usize = 6;

fn invalid(msg: impl Into<String>) -> RuntimeError {
    RuntimeError::Core(CoreError::InvalidPairingUri(msg.into()))
}

/// One hint offered to [`build_pairing_candidates`] with the source that decides its egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintInput {
    pub hint: String,
    pub source: HintSource,
}

impl HintInput {
    #[must_use]
    pub fn new(hint: impl Into<String>, source: HintSource) -> Self {
        Self {
            hint: hint.into(),
            source,
        }
    }
}

/// Strength order of hint sources: explicit operator input, stored `operator`, `signed`,
/// `committed`, then URI hints. Lower is stronger.
const fn source_rank(source: HintSource) -> u8 {
    match source {
        HintSource::Operator => 0,
        HintSource::Stored(RouteSource::Operator) => 1,
        HintSource::Stored(RouteSource::Signed) => 2,
        HintSource::Stored(RouteSource::Committed) => 3,
        HintSource::Uri => 4,
    }
}

/// The stored routes of `entry`, one input per hint with its strongest source
/// (`operator` > `signed` > `committed`), in first-stored order.
///
/// Legacy `relay_hints` are never read.
#[must_use]
pub fn stored_route_inputs(entry: &RosterEntry) -> Vec<HintInput> {
    let mut out: Vec<HintInput> = Vec::new();
    for route in &entry.routes {
        push_strongest(
            &mut out,
            HintInput::new(&route.hint, HintSource::Stored(route.source)),
        );
    }
    out
}

/// Day-2 candidate inputs: the entry's stored routes, then the non-IPC hints
/// of a recovery URI that carries `rs` and are not already stored. An explicit operator endpoint
/// replaces both. Legacy `relay_hints` are never read.
#[must_use]
pub fn session_hint_inputs(
    entry: &RosterEntry,
    recovery_uri: Option<&PairingUri>,
    operator_endpoint: Option<&OperatorEndpoint>,
) -> Vec<HintInput> {
    if let Some(op) = operator_endpoint {
        return vec![HintInput::new(&op.hint, HintSource::Operator)];
    }
    let mut out = stored_route_inputs(entry);
    if let Some(uri) = recovery_uri.filter(|u| u.is_signed()) {
        for hint in &uri.endpoints {
            if hint.starts_with("local:") || hint.starts_with("unix://") {
                continue;
            }
            push_strongest(&mut out, HintInput::new(hint, HintSource::Uri));
        }
    }
    out
}

fn push_strongest(out: &mut Vec<HintInput>, input: HintInput) {
    if let Some(existing) = out.iter_mut().find(|i| i.hint == input.hint) {
        if source_rank(input.source) < source_rank(existing.source) {
            existing.source = input.source;
        }
    } else {
        out.push(input);
    }
}

/// The gate for stored `/v2/relay` routes, evaluated under the store lock on
/// the latest roster for the entry being connected.
///
/// It records the entry's `operator` and `signed` `/v2/relay` routes and, only when the entry is
/// `Active`, not CRL-revoked and holds `v2_secrets`, its mailbox secret. The secret is released
/// only inside the dial of a Wire v2 session candidate that passed every check in
/// [`build_pairing_candidates`], after the relay connect (with its address check) and challenge
/// succeed and the relay did not demand withheld credentials; [`Self::releases`] counts those
/// releases.
pub struct RelayV2Gate {
    peer_id: String,
    authorized: Vec<String>,
    secret: Option<Zeroizing<[u8; 32]>>,
    releases: AtomicUsize,
}

impl fmt::Debug for RelayV2Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayV2Gate")
            .field("peer_id", &self.peer_id)
            .field("authorized", &self.authorized)
            .field("has_secret", &self.secret.is_some())
            .field("releases", &self.releases())
            .finish()
    }
}

impl RelayV2Gate {
    /// Evaluates the gate for the roster entry keyed `peer_id` (never looked up by a URI `id`
    /// or a hint).
    #[must_use]
    pub fn authorize(roster: &Roster, peer_id: &str) -> Self {
        let mut gate = Self {
            peer_id: peer_id.to_owned(),
            authorized: Vec::new(),
            secret: None,
            releases: AtomicUsize::new(0),
        };
        let Some(entry) = roster.get(peer_id) else {
            return gate;
        };
        gate.authorized = entry
            .routes
            .iter()
            .filter(|r| matches!(r.source, RouteSource::Operator | RouteSource::Signed))
            .filter(|r| is_v2_relay_hint(&r.hint))
            .map(|r| r.hint.clone())
            .collect();
        if entry.state == PeerState::Active && !roster.crl_revokes_entry(entry) {
            gate.secret = entry
                .v2_secrets
                .as_ref()
                .map(|s| Zeroizing::new(*s.mailbox_secret()));
        }
        gate
    }

    /// Roster key of the entry this gate was evaluated for.
    #[must_use]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Number of times the mailbox secret was released to a dialer.
    #[must_use]
    pub fn releases(&self) -> usize {
        self.releases.load(Ordering::SeqCst)
    }

    fn admits(&self, hint: &str, source: HintSource) -> bool {
        self.secret.is_some()
            && (source == HintSource::Operator || self.authorized.iter().any(|h| h == hint))
    }

    fn release(&self) -> Option<Zeroizing<[u8; 32]>> {
        let secret = Zeroizing::new(**self.secret.as_ref()?);
        self.releases.fetch_add(1, Ordering::SeqCst);
        Some(secret)
    }
}

/// Who the candidates dial: the `/v1/relay` mailbox key, the target roster entry, and the
/// `/v2/relay` gate of that entry.
#[derive(Debug, Default)]
pub struct HintTarget {
    relay_key: Option<[u8; 32]>,
    peer_id: Option<String>,
    relay_v2: Option<Arc<RelayV2Gate>>,
}

impl HintTarget {
    /// A pairing target: `relay_key` is the URI `rp` or the operator `URL#key`.
    #[must_use]
    pub fn pairing(relay_key: Option<[u8; 32]>) -> Self {
        Self {
            relay_key,
            ..Self::default()
        }
    }

    /// A Day-2 target: the entry keyed `peer_id`, the `/v1/relay` key (recovery `rp`, operator
    /// `URL#key`, else the Ed25519 component of the pinned signing key) and the entry's
    /// `/v2/relay` gate. A gate evaluated for another entry admits nothing.
    #[must_use]
    pub fn session(
        peer_id: impl Into<String>,
        relay_key: Option<[u8; 32]>,
        relay_v2: Option<RelayV2Gate>,
    ) -> Self {
        Self {
            relay_key,
            peer_id: Some(peer_id.into()),
            relay_v2: relay_v2.map(Arc::new),
        }
    }

    #[must_use]
    pub const fn relay_key(&self) -> Option<&[u8; 32]> {
        self.relay_key.as_ref()
    }

    #[must_use]
    pub fn peer_id(&self) -> Option<&str> {
        self.peer_id.as_deref()
    }

    /// The `/v2/relay` gate, if one was evaluated.
    #[must_use]
    pub fn relay_v2_gate(&self) -> Option<&RelayV2Gate> {
        self.relay_v2.as_deref()
    }

    fn gate(&self) -> Option<&Arc<RelayV2Gate>> {
        let gate = self.relay_v2.as_ref()?;
        (self.peer_id.as_deref() == Some(gate.peer_id())).then_some(gate)
    }
}

/// Wire version of the driver the candidates are built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialWire {
    V1,
    V2,
}

/// Configuration of the shared pairing and Day-2 dialer set.
#[derive(Clone, Default)]
pub struct HintDialerConfig {
    /// Relay admission material, attached only through the origin gate.
    pub relay_auth: RelayClientAuth,
    /// Expected relay challenge host for explicit operator relay endpoints only.
    pub relay_expected_host: Option<String>,
    /// Configured Iroh relay mode; `None` means the default relays.
    #[cfg(feature = "p2p-iroh")]
    pub p2p_relay_mode: Option<P2pRelayMode>,
    /// Iroh relay credentials, attached by Iroh to relays of the configured map only.
    #[cfg(feature = "p2p-iroh")]
    pub p2p_relay_auth: Option<P2pRelayAuth>,
    /// Allow private `?addr=` hints on explicit operator `iroh://` endpoints.
    #[cfg(feature = "p2p-iroh")]
    pub p2p_allow_private_addrs: bool,
    /// Pkarr lookup override for explicit operator `iroh://` endpoints and stored `operator`
    /// routes only (`None` keeps the per-endpoint default). URI and stored hint dials never
    /// look up addresses whatever this says.
    #[cfg(feature = "p2p-iroh")]
    pub p2p_pkarr: Option<bool>,
}

impl fmt::Debug for HintDialerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("HintDialerConfig");
        d.field("relay_auth", &self.relay_auth)
            .field("relay_expected_host", &self.relay_expected_host);
        #[cfg(feature = "p2p-iroh")]
        d.field("p2p_relay_mode", &self.p2p_relay_mode)
            .field("p2p_relay_auth", &self.p2p_relay_auth)
            .field("p2p_allow_private_addrs", &self.p2p_allow_private_addrs)
            .field("p2p_pkarr", &self.p2p_pkarr);
        d.finish()
    }
}

/// The one dialer set behind pairing and Day-2 connects on every native surface.
///
/// URI hints and `signed` or `committed` routes dial `iroh://` through the lookup-free hint
/// dialer ([`P2pOptions::for_hint_dialer`]), bound on first use. Explicit operator `iroh://`
/// endpoints and stored `operator` routes keep today's per-endpoint options
/// ([`P2pOptions::for_endpoint`]). Group dialers are built elsewhere.
pub struct HintDialers {
    config: HintDialerConfig,
    direct: Arc<dyn PathDialer>,
    local: Arc<dyn PathDialer>,
    overlay: Arc<dyn PathDialer>,
    broker: Arc<dyn PathDialer>,
    #[cfg(feature = "p2p-iroh")]
    p2p_hint: Arc<LazyHintP2pDialer>,
    #[cfg(feature = "p2p-iroh")]
    p2p_operator: Arc<OperatorP2pDialer>,
}

impl fmt::Debug for HintDialers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HintDialers")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl HintDialers {
    /// Builds the dialer set. No socket is bound until a candidate dials.
    #[must_use]
    pub fn new(config: HintDialerConfig) -> Self {
        #[cfg(feature = "p2p-iroh")]
        let p2p_hint = Arc::new(LazyHintP2pDialer {
            options: P2pOptions::for_hint_dialer(config.p2p_relay_mode.clone())
                .with_relay_auth(config.p2p_relay_auth.clone()),
            dialer: tokio::sync::OnceCell::new(),
        });
        #[cfg(feature = "p2p-iroh")]
        let p2p_operator = Arc::new(OperatorP2pDialer {
            relay_mode: config.p2p_relay_mode.clone(),
            relay_auth: config.p2p_relay_auth.clone(),
            allow_private_addrs: config.p2p_allow_private_addrs,
            pkarr: config.p2p_pkarr,
            dns_pins: Vec::new(),
        });
        Self {
            config,
            direct: Arc::new(DirectDialer::new()),
            local: Arc::new(LocalDialer::new()),
            overlay: Arc::new(OverlayDialer::new()),
            broker: Arc::new(BrokerDialer::new()),
            #[cfg(feature = "p2p-iroh")]
            p2p_hint,
            #[cfg(feature = "p2p-iroh")]
            p2p_operator,
        }
    }

    #[must_use]
    pub const fn config(&self) -> &HintDialerConfig {
        &self.config
    }

    /// Replaces the base dialer of `dialer.provider_id()` (`Direct`, `Local`, `Overlay` or
    /// `Broker`) with `dialer`, for custom transports and dial spies. Egress checks still run
    /// first, so the dialer receives only checked targets. Other providers are unchanged.
    #[must_use]
    pub fn with_provider_dialer(mut self, dialer: Arc<dyn PathDialer>) -> Self {
        match dialer.provider_id() {
            ProviderId::Direct => self.direct = dialer,
            ProviderId::Local => self.local = dialer,
            ProviderId::Overlay => self.overlay = dialer,
            ProviderId::Broker => self.broker = dialer,
            ProviderId::Relay | ProviderId::P2p => {}
        }
        self
    }

    /// The Iroh options an explicit operator `endpoint` is dialed with (relay mode, private
    /// addresses, relay credentials and the Pkarr override of this set).
    #[cfg(feature = "p2p-iroh")]
    pub fn operator_p2p_options(&self, endpoint: &str) -> Result<P2pOptions, RuntimeError> {
        self.p2p_operator.options(endpoint)
    }

    /// An [`EgressContext`] for `kind` consistent with this set's Iroh relay mode.
    #[must_use]
    pub fn egress_context(
        &self,
        kind: EgressKind,
        relay_auth_origins: Vec<String>,
    ) -> EgressContext {
        let ctx = EgressContext::new(kind).with_relay_auth_origins(relay_auth_origins);
        #[cfg(feature = "p2p-iroh")]
        let ctx = ctx.with_iroh_relay_mode(self.config.p2p_relay_mode.clone());
        ctx
    }

    /// The lookup-free hint dialer, binding it on first use.
    #[cfg(feature = "p2p-iroh")]
    pub async fn p2p_hint_dialer(&self) -> Result<Arc<P2pDialer>, RuntimeError> {
        self.p2p_hint.get().await
    }
}

#[cfg(feature = "p2p-iroh")]
struct LazyHintP2pDialer {
    options: P2pOptions,
    dialer: tokio::sync::OnceCell<Arc<P2pDialer>>,
}

#[cfg(feature = "p2p-iroh")]
impl LazyHintP2pDialer {
    async fn get(&self) -> Result<Arc<P2pDialer>, RuntimeError> {
        self.dialer
            .get_or_try_init(|| async {
                P2pDialer::bind_with_options(self.options.clone())
                    .await
                    .map(Arc::new)
            })
            .await
            .cloned()
    }
}

#[cfg(feature = "p2p-iroh")]
#[async_trait]
impl PathDialer for LazyHintP2pDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.get().await?.dial(endpoint).await
    }
}

/// Explicit operator `iroh://` endpoints: one dialer per dial with today's options, the Pkarr
/// override, and the relay host names the egress check resolved pinned to their checked
/// addresses.
#[cfg(feature = "p2p-iroh")]
#[derive(Clone)]
struct OperatorP2pDialer {
    relay_mode: Option<P2pRelayMode>,
    relay_auth: Option<P2pRelayAuth>,
    allow_private_addrs: bool,
    pkarr: Option<bool>,
    dns_pins: Vec<(String, Vec<IpAddr>)>,
}

#[cfg(feature = "p2p-iroh")]
impl OperatorP2pDialer {
    fn options(&self, endpoint: &str) -> Result<P2pOptions, RuntimeError> {
        let mut opts =
            P2pOptions::for_endpoint(endpoint, self.relay_mode.clone(), self.allow_private_addrs)?
                .with_relay_auth(self.relay_auth.clone())
                .with_dns_pins(self.dns_pins.clone());
        if let Some(pkarr) = self.pkarr {
            opts = opts.with_resolve_pkarr(pkarr);
        }
        Ok(opts)
    }
}

#[cfg(feature = "p2p-iroh")]
#[async_trait]
impl PathDialer for OperatorP2pDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let opts = self.options(endpoint)?;
        let dialer = P2pDialer::bind_with_options(opts).await?;
        match dialer.dial(endpoint).await {
            Ok(stream) => Ok(stream),
            Err(err) => {
                dialer.close().await;
                Err(err)
            }
        }
    }
}

/// Dialer set and wire version for one candidate build.
#[derive(Debug, Clone)]
pub struct MultiDialOptions {
    pub dialers: Arc<HintDialers>,
    pub wire: DialWire,
}

impl MultiDialOptions {
    #[must_use]
    pub fn new(dialers: Arc<HintDialers>, wire: DialWire) -> Self {
        Self { dialers, wire }
    }
}

/// What one candidate was built from.
#[derive(Debug, Clone)]
pub struct CandidateInfo {
    /// The original hint string (also the candidate's `addr`).
    pub hint: String,
    pub source: HintSource,
    pub provider: ProviderId,
    /// Path class for the `Lan2Group` code guard.
    pub path_class: PairingPathKind,
    /// The checked target the provider dialer receives.
    pub dial_endpoint: String,
    /// `true` when a `/v1/relay` dial to this candidate carries admission material.
    pub relay_credentials: bool,
}

/// Checked candidates, their per-provider dialers, and every hint that will not be dialed.
pub struct CandidateSet {
    /// One dialer per provider, for [`crate::dial_with_policy_verified`].
    pub dialers: Vec<Arc<dyn PathDialer>>,
    /// Candidates; `addr` is the original hint and `id` indexes [`Self::info`].
    pub candidates: Vec<CandidateEndpoint>,
    /// Hints reported and never dialed, with their reasons.
    pub skipped: Vec<SkippedHint>,
    info: Vec<CandidateInfo>,
}

impl fmt::Debug for CandidateSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateSet")
            .field("candidates", &self.info)
            .field("skipped", &self.skipped)
            .finish_non_exhaustive()
    }
}

impl CandidateSet {
    /// What candidate `id` was built from.
    #[must_use]
    pub fn info(&self, id: usize) -> Option<&CandidateInfo> {
        self.info.get(id)
    }

    /// The original hint of candidate `id` (the winner's hint for persistence).
    #[must_use]
    pub fn original_hint(&self, id: usize) -> Option<&str> {
        self.info.get(id).map(|i| i.hint.as_str())
    }

    /// The dialer serving `provider`.
    #[must_use]
    pub fn dialer_for(&self, provider: ProviderId) -> Option<Arc<dyn PathDialer>> {
        self.dialers
            .iter()
            .find(|d| d.provider_id() == provider)
            .cloned()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

/// Dialer and checked dial target per original hint.
type HintRoutes = HashMap<String, (Arc<dyn PathDialer>, String)>;

/// Per-provider dialer that maps a candidate's original hint to its checked target and dialer.
struct RoutedDialer {
    provider: ProviderId,
    routes: HintRoutes,
}

#[async_trait]
impl PathDialer for RoutedDialer {
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn supports_fast_open(&self) -> bool {
        self.routes
            .values()
            .any(|(dialer, _)| dialer.supports_fast_open())
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let (dialer, target) = self.routes.get(endpoint).ok_or_else(|| {
            RuntimeError::Protocol(format!(
                "no checked candidate for {}",
                redact_hint(endpoint)
            ))
        })?;
        dialer.dial(target).await
    }

    async fn dial_with_init(
        &self,
        endpoint: &str,
        init_frame: Option<&[u8]>,
    ) -> Result<(Box<dyn PathStream>, bool), RuntimeError> {
        let (dialer, target) = self.routes.get(endpoint).ok_or_else(|| {
            RuntimeError::Protocol(format!(
                "no checked candidate for {}",
                redact_hint(endpoint)
            ))
        })?;
        dialer.dial_with_init(target, init_frame).await
    }
}

/// Builds the candidates for one pairing attempt or Day-2 connect.
///
/// Inputs are deduplicated by hint with the strongest source winning. `/v2/relay` is dropped
/// for pairing (`relay_v2_not_authorized`) and Wire v1 (`wire_v1_no_relay_v2`); on a Wire v2
/// session it needs the target's [`RelayV2Gate`]. Every other hint passes [`check_hint`];
/// `/v1/relay` hints dial through [`RelayHintDialer`] to [`HintTarget::relay_key`] with the
/// origin gate. Fails only when the sole candidates were `iroh://` hints and the `p2p-iroh`
/// feature is disabled; an empty set is returned otherwise and the caller reports it.
pub async fn build_pairing_candidates(
    hints: &[HintInput],
    target: &HintTarget,
    ctx: &EgressContext,
    opts: &MultiDialOptions,
) -> Result<CandidateSet, RuntimeError> {
    let mut inputs: Vec<HintInput> = Vec::new();
    for input in hints {
        push_strongest(&mut inputs, input.clone());
    }
    let pairing = matches!(ctx.kind, EgressKind::Pairing(_));
    let set = &opts.dialers;
    let mut routes: HashMap<ProviderId, HintRoutes> = HashMap::new();
    let mut candidates = Vec::new();
    let mut info = Vec::new();
    let mut skipped = Vec::new();

    for input in &inputs {
        let hint = input.hint.as_str();
        let v2_relay = is_v2_relay_hint(hint);
        if v2_relay {
            let reason = if pairing {
                Some(SkipReason::RelayV2NotAuthorized)
            } else if opts.wire == DialWire::V1 {
                Some(SkipReason::WireV1NoRelayV2)
            } else if !target.gate().is_some_and(|g| g.admits(hint, input.source)) {
                Some(SkipReason::RelayV2NotAuthorized)
            } else {
                None
            };
            if let Some(reason) = reason {
                skipped.push(SkippedHint::new(hint, reason));
                continue;
            }
        }
        let checked = match check_hint(hint, input.source, ctx).await {
            Ok(checked) => checked,
            Err(skip) => {
                skipped.push(skip);
                continue;
            }
        };
        for relay in &checked.dropped_relays {
            skipped.push(SkippedHint::new(relay, SkipReason::IrohRelayNotConfigured));
        }
        let operator_call = input.source == HintSource::Operator;
        let mut relay_credentials = false;
        let dialer: Arc<dyn PathDialer> = match checked.provider {
            ProviderId::Local => Arc::clone(&set.local),
            ProviderId::Direct => Arc::clone(&set.direct),
            ProviderId::Overlay => Arc::clone(&set.overlay),
            ProviderId::Broker => Arc::clone(&set.broker),
            ProviderId::Relay if v2_relay => {
                let auth = gate_relay_auth(
                    &set.config.relay_auth,
                    &checked.dial_endpoint,
                    &ctx.relay_auth_origins,
                    operator_call,
                );
                relay_credentials = !matches!(auth, RelayClientAuth::None);
                let Some(gate) = target.gate().map(Arc::clone) else {
                    skipped.push(SkippedHint::new(hint, SkipReason::RelayV2NotAuthorized));
                    continue;
                };
                let source: MailboxSecretSource = Arc::new(move || gate.release());
                let mut dialer = RelayV2Dialer::gated(source)
                    .with_auth_withheld(!relay_credentials)
                    .with_auth(auth);
                if operator_call && let Some(host) = &set.config.relay_expected_host {
                    dialer = dialer.with_expected_host(host.clone());
                }
                Arc::new(dialer)
            }
            ProviderId::Relay => {
                let Some(key) = target.relay_key() else {
                    skipped.push(SkippedHint::new(hint, SkipReason::Invalid));
                    continue;
                };
                let adapter = RelayHintDialer::new(*key)
                    .with_admission(
                        set.config.relay_auth.clone(),
                        ctx.relay_auth_origins.clone(),
                    )
                    .with_operator_endpoint(operator_call)
                    .with_expected_host(
                        operator_call
                            .then(|| set.config.relay_expected_host.clone())
                            .flatten(),
                    );
                relay_credentials = adapter.attaches_credentials(&checked.dial_endpoint);
                Arc::new(adapter)
            }
            ProviderId::P2p => {
                #[cfg(feature = "p2p-iroh")]
                {
                    if checked.p2p_hint_dialer {
                        Arc::clone(&set.p2p_hint) as Arc<dyn PathDialer>
                    } else if checked.relay_pins.is_empty() {
                        Arc::clone(&set.p2p_operator) as Arc<dyn PathDialer>
                    } else {
                        Arc::new(OperatorP2pDialer {
                            dns_pins: checked.relay_pins.clone(),
                            ..(*set.p2p_operator).clone()
                        })
                    }
                }
                #[cfg(not(feature = "p2p-iroh"))]
                {
                    skipped.push(SkippedHint::new(hint, SkipReason::P2pFeatureDisabled));
                    continue;
                }
            }
        };
        let dialer: Arc<dyn PathDialer> = match &checked.addr_policy {
            Some(policy) => Arc::new(EgressDialer::new(dialer, Arc::clone(policy))),
            None => dialer,
        };
        let id = candidates.len();
        candidates.push(CandidateEndpoint {
            id,
            provider: checked.provider,
            addr: hint.to_owned(),
            is_numeric_host: is_numeric_host_addr(&checked.dial_endpoint)
                || !checked.destinations.is_empty(),
        });
        routes
            .entry(checked.provider)
            .or_default()
            .insert(hint.to_owned(), (dialer, checked.dial_endpoint.clone()));
        info.push(CandidateInfo {
            hint: hint.to_owned(),
            source: input.source,
            provider: checked.provider,
            path_class: checked.path_class,
            dial_endpoint: checked.dial_endpoint,
            relay_credentials,
        });
    }

    if candidates.is_empty()
        && !skipped.is_empty()
        && skipped
            .iter()
            .all(|s| s.reason == SkipReason::P2pFeatureDisabled)
    {
        return Err(RuntimeError::Protocol(
            "p2p-iroh feature is not enabled in tendril-runtime".to_owned(),
        ));
    }

    let mut providers: Vec<ProviderId> = routes.keys().copied().collect();
    providers.sort();
    let dialers = providers
        .into_iter()
        .map(|provider| {
            let routes = routes.remove(&provider).unwrap_or_default();
            Arc::new(RoutedDialer { provider, routes }) as Arc<dyn PathDialer>
        })
        .collect();
    Ok(CandidateSet {
        dialers,
        candidates,
        skipped,
        info,
    })
}

fn has_known_prefix(raw: &str) -> bool {
    [
        "local:",
        "unix://",
        "direct:",
        "overlay://",
        "iroh://",
        "p2p:",
        "relay:",
        "ws://",
        "wss://",
        "broker+",
    ]
    .iter()
    .any(|p| raw.starts_with(p))
}

fn is_ws_url(raw: &str) -> bool {
    let url = raw.strip_prefix("relay:").unwrap_or(raw);
    url.starts_with("ws://") || url.starts_with("wss://")
}

/// Normalizes an endpoint typed by the local operator or developer.
///
/// Never called on URI hints, stored routes or announcements. `/abs/path` becomes
/// `local:/abs/path`; a relay `URL#<43-char key>` loses its fragment and yields `relay_key`
/// (a valid Ed25519 point); a `/v2/relay#<mailbox_id>` loses its fragment; a bare `host:port`
/// becomes `direct:host:port`; any other `#` fails with `fragment not allowed`. The result
/// must pass the pairing hint grammar.
pub fn normalize_operator_endpoint(raw: &str) -> Result<OperatorEndpoint, RuntimeError> {
    let (hint, relay_key) = match raw.split_once('#') {
        Some((base, fragment)) if is_ws_url(base) => {
            if is_v2_relay_hint(base) {
                (base.to_owned(), None)
            } else {
                let key = b64url_decode_array::<32>(fragment)
                    .ok()
                    .filter(|k| fragment.len() == 43 && VerifyingKey::from_bytes(k).is_ok())
                    .ok_or_else(|| invalid("invalid relay key in endpoint fragment"))?;
                (base.to_owned(), Some(key))
            }
        }
        Some(_) => return Err(invalid("fragment not allowed")),
        None if raw.starts_with('/') => (format!("local:{raw}"), None),
        None if has_known_prefix(raw) => (raw.to_owned(), None),
        None => (format!("direct:{raw}"), None),
    };
    if !is_valid_pairing_endpoint_hint(&hint) {
        return Err(invalid(format!("invalid endpoint {}", redact_hint(raw))));
    }
    Ok(OperatorEndpoint { hint, relay_key })
}

fn ip_blocked(ip: IpAddr) -> bool {
    classify_destination(ip) == DestClass::Blocked
}

fn url_host_blocked(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    match url.host() {
        Some(url::Host::Ipv4(v4)) => ip_blocked(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => ip_blocked(IpAddr::V6(v6)),
        Some(url::Host::Domain(d)) => d
            .trim_end_matches('.')
            .eq_ignore_ascii_case("metadata.google.internal"),
        None => false,
    }
}

fn host_port_blocked(target: &str) -> bool {
    if let Ok(sock) = target.parse::<SocketAddr>() {
        return ip_blocked(sock.ip());
    }
    target.rsplit_once(':').is_some_and(|(host, _)| {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        bare.parse::<IpAddr>().is_ok_and(ip_blocked)
    })
}

fn url_has_host(raw: &str) -> bool {
    url::Url::parse(raw).is_ok_and(|u| u.host_str().is_some_and(|h| !h.is_empty()))
}

/// `true` when a nested Iroh `relay=` URL is one the operator Iroh dialer accepts.
fn iroh_relay_url_ok(raw: &str) -> bool {
    #[cfg(feature = "p2p-iroh")]
    {
        super::validate_iroh_relay_url(raw).is_ok()
    }
    #[cfg(not(feature = "p2p-iroh"))]
    {
        url_has_host(raw) && (raw.starts_with("https://") || raw.starts_with("http://"))
    }
}

/// `true` when every URL `hint` carries parses (WHATWG) with a host: the WebSocket URL of a
/// relay or broker hint and each nested `relay=` of an `iroh://` hint, which must also pass the
/// Iroh relay URL checks of the operator dialer. The core grammar is textual and admits URLs such
/// as `https://999.0.0.1/` that no dialer can use.
fn hint_urls_parse(hint: &str) -> bool {
    let Ok(provider) = classify_endpoint_hint(hint) else {
        return false;
    };
    match provider {
        ProviderId::Relay => url_has_host(hint.strip_prefix("relay:").unwrap_or(hint)),
        ProviderId::Broker => url_has_host(hint.strip_prefix("broker+").unwrap_or(hint)),
        ProviderId::P2p => {
            let query = hint.split_once('?').map_or("", |(_, q)| q);
            query.split('&').all(|pair| match pair.split_once('=') {
                Some(("relay", v)) => iroh_relay_url_ok(v),
                _ => true,
            })
        }
        ProviderId::Local | ProviderId::Direct | ProviderId::Overlay => true,
    }
}

/// `true` when a literal host of `hint` is in the always-blocked set (no DNS).
#[must_use]
pub fn hint_has_blocked_literal(hint: &str) -> bool {
    let Ok(provider) = classify_endpoint_hint(hint) else {
        return false;
    };
    match provider {
        ProviderId::Local => false,
        ProviderId::Direct => host_port_blocked(hint.strip_prefix("direct:").unwrap_or(hint)),
        ProviderId::Overlay => host_port_blocked(hint.strip_prefix("overlay://").unwrap_or(hint)),
        ProviderId::Relay => url_host_blocked(hint.strip_prefix("relay:").unwrap_or(hint)),
        ProviderId::Broker => url_host_blocked(hint.strip_prefix("broker+").unwrap_or(hint)),
        ProviderId::P2p => {
            let query = hint.split_once('?').map_or("", |(_, q)| q);
            query.split('&').any(|pair| match pair.split_once('=') {
                Some(("addr", v)) => v.parse::<SocketAddr>().is_ok_and(|s| ip_blocked(s.ip())),
                Some(("relay", v)) => url_host_blocked(v),
                _ => false,
            })
        }
    }
}

/// Route view of one peer. `L` is the surface's record of the last route announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRoutes<L> {
    pub routes: Vec<StoredRoute>,
    pub route_meta: Option<RouteMeta>,
    /// The last route set outcome, as supplied to [`peer_routes`].
    pub last_route_set: Option<L>,
}

/// Normalizes and checks operator route input for [`set_peer_routes`] without touching a roster:
/// at most six entries, each through [`normalize_operator_endpoint`], every carried URL
/// (including nested Iroh `relay=` URLs) parseable with a host, and no always-blocked literal.
/// One bad entry fails the whole batch. Callers may run it before taking the store lock.
pub fn normalize_peer_routes(raw: &[String]) -> Result<Vec<OperatorEndpoint>, RuntimeError> {
    if raw.len() > MAX_OPERATOR_ROUTE_INPUTS {
        return Err(invalid(format!(
            "at most {MAX_OPERATOR_ROUTE_INPUTS} operator routes"
        )));
    }
    let endpoints = raw
        .iter()
        .map(|r| normalize_operator_endpoint(r))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(ep) = endpoints.iter().find(|ep| !hint_urls_parse(&ep.hint)) {
        return Err(invalid(format!(
            "invalid URL in endpoint {}",
            redact_hint(&ep.hint)
        )));
    }
    if let Some(ep) = endpoints
        .iter()
        .find(|ep| hint_has_blocked_literal(&ep.hint))
    {
        return Err(invalid(format!(
            "blocked_address: {}",
            redact_hint(&ep.hint)
        )));
    }
    Ok(endpoints)
}

/// Replaces the peer's `operator` routes on `roster`, which the caller loads and
/// persists under the store lock.
///
/// Every entry is checked by [`normalize_peer_routes`] before anything is written; an empty list
/// clears the `operator` routes. [`Roster::set_routes`] then checks the peer, the `URL#key`
/// against this roster's pin, validation and caps, and replaces the list atomically. Returns
/// the entry's full route list.
pub fn set_peer_routes(
    roster: &mut Roster,
    peer_id: &str,
    raw: &[String],
) -> Result<Vec<StoredRoute>, RuntimeError> {
    let endpoints = normalize_peer_routes(raw)?;
    Ok(roster.set_routes(peer_id, endpoints)?.to_vec())
}

/// Routes and route metadata of `peer_id`, with the caller's `last_route_set` record.
pub fn peer_routes<L>(
    roster: &Roster,
    peer_id: &str,
    last_route_set: Option<L>,
) -> Result<PeerRoutes<L>, RuntimeError> {
    let entry = roster
        .get(peer_id)
        .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_owned()))?;
    Ok(PeerRoutes {
        routes: entry.routes.clone(),
        route_meta: entry.route_meta,
        last_route_set,
    })
}

/// Removes the peer's routes of `source`, or all routes; `route_meta` is kept.
pub fn clear_peer_routes(
    roster: &mut Roster,
    peer_id: &str,
    source: Option<RouteSource>,
) -> Result<(), RuntimeError> {
    Ok(roster.clear_routes(peer_id, source)?)
}

/// [`set_peer_routes`] as one transaction on `access` (the latest roster under the store lock
/// for a store-backed handle). Input is normalized and checked before the lock is taken.
pub fn set_peer_routes_in(
    access: &RosterAccess,
    peer_id: &str,
    raw: &[String],
) -> Result<Vec<StoredRoute>, RuntimeError> {
    let endpoints = normalize_peer_routes(raw)?;
    access.update(|roster| Ok(roster.set_routes(peer_id, endpoints)?.to_vec()))
}

/// [`peer_routes`] on the latest roster of `access`, with the last route set outcome this
/// process recorded for the peer ([`RosterAccess::last_route_set`]). That record is runtime
/// state: it is never persisted and starts empty in every process.
pub fn peer_routes_in(
    access: &RosterAccess,
    peer_id: &str,
) -> Result<PeerRoutes<LastRouteSet>, RuntimeError> {
    peer_routes(&access.load()?, peer_id, access.last_route_set(peer_id))
}

/// [`clear_peer_routes`] as one transaction on `access`.
pub fn clear_peer_routes_in(
    access: &RosterAccess,
    peer_id: &str,
    source: Option<RouteSource>,
) -> Result<(), RuntimeError> {
    access.update(|roster| clear_peer_routes(roster, peer_id, source))
}

/// Options of [`apply_signed_route_uri`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteApplyOpts {
    pub policy: RoutePolicy,
    /// Explicit approval (`--replace-routes`): replace even when `rq` is not newer.
    pub replace_routes: bool,
}

/// Result of [`apply_signed_route_uri`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteApplyResult {
    pub peer_id: String,
    /// `true` when the `signed` routes were replaced.
    pub applied: bool,
    /// `stale_route_seq` or `route_policy` when nothing changed.
    pub reason: Option<&'static str>,
    pub routes: Vec<StoredRoute>,
    pub route_meta: Option<RouteMeta>,
}

const NO_MATCHING_HOST: &str = "no paired host matches this pairing URI's keys; if the host \
                                rotated, connect with the URI as a recovery URI";

/// Applies a fresh signed pairing URI to the matching paired host offline
/// on `roster`, which the caller loads and persists under the store lock.
///
/// Finds the `Active` entry whose `static_pub` is `k` and whose signing key hashes to `sh`,
/// verifies `rs` under that key and re-checks both keys from the verified bytes, then applies
/// the `rq` rules: with `allSigned` and a newer `rq` the `signed` routes are replaced; otherwise
/// only `replace_routes` replaces them. On error `roster` is unchanged. No network and no code
/// use.
pub fn apply_signed_route_uri(
    roster: &mut Roster,
    uri: &PairingUri,
    opts: RouteApplyOpts,
) -> Result<RouteApplyResult, RuntimeError> {
    let (peer_id, statement) = matching_statement(roster, uri)?;
    let mut staged = roster.clone();
    let mut reason = None;
    let mut applied = false;
    if opts.policy == RoutePolicy::AllSigned {
        applied = staged.replace_signed_routes(&peer_id, &statement)?;
        if !applied {
            reason = Some("stale_route_seq");
        }
    } else {
        reason = Some("route_policy");
    }
    if !applied && opts.replace_routes {
        staged.replace_routes_approved(&peer_id, &statement)?;
        applied = true;
        reason = None;
    }
    let entry = staged
        .get(&peer_id)
        .ok_or_else(|| CoreError::PeerNotFound(peer_id.clone()))?;
    let result = RouteApplyResult {
        routes: entry.routes.clone(),
        route_meta: entry.route_meta,
        peer_id,
        applied,
        reason,
    };
    *roster = staged;
    Ok(result)
}

fn matching_statement(
    roster: &Roster,
    uri: &PairingUri,
) -> Result<(String, VerifiedRouteStatement), RuntimeError> {
    let (peer_id, entry) = roster
        .entries()
        .find(|(_, e)| {
            e.state == PeerState::Active
                && !roster.crl_revokes_entry(e)
                && bool::from(e.static_pub.ct_eq(&uri.host_static_pub))
                && e.signing_pub
                    .as_ref()
                    .is_some_and(|s| bool::from(s.sha256_hash().ct_eq(&uri.host_signing_pub_hash)))
        })
        .ok_or_else(|| CoreError::PeerNotFound(NO_MATCHING_HOST.to_owned()))?;
    let signing_pub = entry
        .signing_pub
        .as_ref()
        .ok_or_else(|| CoreError::PeerNotFound(NO_MATCHING_HOST.to_owned()))?;
    let statement = match uri.verify_route_statement(signing_pub) {
        RouteCheck::Verified(s) => s,
        RouteCheck::Unsigned(_) => return Err(invalid("pairing URI is not host-signed")),
        RouteCheck::Invalid => return Err(invalid("route statement does not verify")),
    };
    if *statement.host_static_pub() != entry.static_pub
        || *statement.sh() != signing_pub.sha256_hash()
    {
        return Err(RuntimeError::Core(CoreError::HostKeyUnverified));
    }
    Ok((peer_id.clone(), statement))
}

#[cfg(all(test, feature = "p2p-iroh"))]
mod tests {
    use super::*;
    use crate::providers::p2p::tests::{PINNED_RELAY, assert_pinned_dial_skips_lookup};

    #[tokio::test]
    async fn operator_iroh_dial_uses_the_egress_pins() {
        let node = iroh::SecretKey::from_bytes(&[31; 32]).public();
        let endpoint = format!("iroh://{node}?relay=https://{PINNED_RELAY}/");
        let dialer = OperatorP2pDialer {
            dns_pins: vec![(PINNED_RELAY.to_owned(), vec![IpAddr::from([127, 0, 0, 1])])],
            ..(*HintDialers::new(HintDialerConfig {
                p2p_allow_private_addrs: true,
                ..HintDialerConfig::default()
            })
            .p2p_operator)
                .clone()
        };
        assert_pinned_dial_skips_lookup(dialer.dial(&endpoint)).await;
    }

    #[test]
    fn operator_iroh_dials_honour_the_pkarr_override() {
        let node = iroh::SecretKey::from_bytes(&[9; 32]).public();
        let endpoint = format!("iroh://{node}");
        let resolves = |config: HintDialerConfig| {
            HintDialers::new(config)
                .operator_p2p_options(&endpoint)
                .expect("options")
                .resolve_pkarr
        };
        assert!(
            resolves(HintDialerConfig::default()),
            "default relays look up"
        );
        assert!(!resolves(HintDialerConfig {
            p2p_pkarr: Some(false),
            ..HintDialerConfig::default()
        }));
        let custom = Some(P2pRelayMode::Custom("https://relay.example/".into()));
        assert!(!resolves(HintDialerConfig {
            p2p_relay_mode: custom.clone(),
            ..HintDialerConfig::default()
        }));
        assert!(resolves(HintDialerConfig {
            p2p_relay_mode: custom,
            p2p_pkarr: Some(true),
            ..HintDialerConfig::default()
        }));

        // URI and stored hints keep lookup off whatever the override says.
        let dialers = HintDialers::new(HintDialerConfig {
            p2p_pkarr: Some(true),
            ..HintDialerConfig::default()
        });
        assert!(!dialers.p2p_hint.options.resolve_pkarr);
        assert!(dialers.p2p_hint.options.hint_dialer);
    }
}
