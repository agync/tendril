//! Ephemeral hourly-rotating Wire v2 P2P (`iroh://v2`) listener, probe, and dialer (`spec/wire-v2.md` Section 7).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use iroh::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use subtle::ConstantTimeEq;
use tendril_core::error::CoreError;
use tendril_core::policy::ProviderId;
use tendril_core::v2::{DerivedP2pEpoch, derive_epoch_p2p_window};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, timeout};

use zeroize::Zeroizing;

use crate::driver::current_unix_secs;
use crate::error::RuntimeError;
use crate::provider::{PathDialer, PathListener, PathStream};
use crate::providers::p2p::{
    P2P_HANDSHAKE_TIMEOUT, P2pListener, P2pOptions, P2pRelayAuth, P2pRelayMode, P2pRole, P2pStream,
    TENDRIL_P2P_ALPN, build_iroh_endpoint, check_relay_hosts_pinned, configured_relay_urls,
    parse_p2p_relay_modes, parse_v2_p2p_relays, relay_map_urls,
};
use crate::providers::relay_v2::MailboxSecretSource;
use crate::router::InboundRouter;

const P2P_V2_ROTATE_POLL_INTERVAL: Duration = Duration::from_secs(5);
const P2P_V2_PROBE_ONLINE_TIMEOUT: Duration = Duration::from_secs(3);
const P2P_V2_MULTI_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);
const P2P_V2_CHANNEL_CAP: usize = 32;

/// Clock callback used for deriving epoch windows; defaults to wall clock.
pub type P2pV2Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn wall_clock() -> P2pV2Clock {
    Arc::new(current_unix_secs)
}

fn sanitize_v2_options(mut options: P2pOptions) -> P2pOptions {
    options.publish_pkarr = false;
    options.resolve_pkarr = false;
    options.advertise_direct_addrs = false;
    options.hint_dialer = false;
    options
}

fn extract_home_relay(endpoint_str: &str) -> Option<String> {
    let (_, query) = endpoint_str.split_once('?')?;
    for pair in query.split('&') {
        if let Some(("relay", url)) = pair.split_once('=')
            && !url.is_empty()
        {
            return Some(url.to_owned());
        }
    }
    None
}

fn format_v2_advertised(
    home_relay: Option<&str>,
    options: &P2pOptions,
) -> Result<String, RuntimeError> {
    if let Some(relay) = home_relay {
        return Ok(format!("iroh://v2?relay={relay}"));
    }
    if let Some(first) = relay_map_urls(&options.relay_mode)?.into_iter().next() {
        return Ok(format!("iroh://v2?relay={first}"));
    }
    Ok("iroh://v2".to_owned())
}

/// Probes the home relay URL using a short-lived throwaway `iroh` endpoint with `Pkarr` disabled
/// and returns `"iroh://v2?relay=<home>"` (or `"iroh://v2"` when relay mode is `Disabled`).
pub async fn probe_p2p_v2_endpoint(options: P2pOptions) -> Result<String, RuntimeError> {
    let options = sanitize_v2_options(options);
    if matches!(options.relay_mode, P2pRelayMode::Disabled) {
        return Ok("iroh://v2".to_owned());
    }
    let (endpoint, _) = build_iroh_endpoint(
        &options,
        P2pRole::Listener,
        vec![TENDRIL_P2P_ALPN.to_vec()],
        None,
    )
    .await?;
    let _ = timeout(P2P_V2_PROBE_ONLINE_TIMEOUT, endpoint.online()).await;
    let home = endpoint.addr().relay_urls().next().map(ToString::to_string);
    endpoint.close().await;
    format_v2_advertised(home.as_deref(), &options)
}

struct BoundEpoch {
    endpoint_id: EndpointId,
    forward_task: Option<JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
}

impl BoundEpoch {
    async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.forward_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for BoundEpoch {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Hourly-rotating ephemeral `iroh://v2` listener (`spec/wire-v2.md` Section 7).
///
/// Binds one [`P2pListener`] per active epoch in the `+-300 s` boundary window, rotates
/// automatically as time or `secret_source` changes, and tears down immediately when
/// `secret_source` returns `None` (peer revocation or group removal).
pub struct P2pV2Listener {
    advertised: String,
    active_ids: Arc<StdMutex<BTreeMap<u64, EndpointId>>>,
    accepted_rx: mpsc::Receiver<P2pStream>,
    shutdown_tx: watch::Sender<bool>,
    manager_task: Option<JoinHandle<()>>,
}

async fn bind_epoch_listener(
    options: P2pOptions,
    derived: DerivedP2pEpoch,
    accepted_tx: mpsc::Sender<P2pStream>,
) -> Result<(BoundEpoch, Option<String>), RuntimeError> {
    let mut listener = P2pListener::bind_with_options(options, Some(derived.secret_seed())).await?;
    let endpoint_id = listener.endpoint_id();
    let local_ep = listener.local_endpoint();
    let home_relay = extract_home_relay(&local_ep);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let forward_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    listener.close_now().await;
                    return;
                }
                res = listener.accept_p2p_stream() => {
                    match res {
                        Ok(stream) => {
                            if accepted_tx.send(stream).await.is_err() {
                                listener.close_now().await;
                                return;
                            }
                        }
                        Err(_) => {
                            listener.close_now().await;
                            return;
                        }
                    }
                }
            }
        }
    });
    Ok((
        BoundEpoch {
            endpoint_id,
            forward_task: Some(forward_task),
            shutdown_tx,
        },
        home_relay,
    ))
}

impl P2pV2Listener {
    /// Binds an hourly-rotating `iroh://v2` listener driven by `secret_source`.
    pub async fn bind(
        options: P2pOptions,
        secret_source: MailboxSecretSource,
    ) -> Result<Self, RuntimeError> {
        Self::bind_with_clock_and_poll(
            options,
            secret_source,
            wall_clock(),
            P2P_V2_ROTATE_POLL_INTERVAL,
        )
        .await
    }

    /// Binds an hourly-rotating listener with an injected clock and poll interval (for tests).
    pub(crate) async fn bind_with_clock_and_poll(
        options: P2pOptions,
        secret_source: MailboxSecretSource,
        clock: P2pV2Clock,
        poll_interval: Duration,
    ) -> Result<Self, RuntimeError> {
        let options = sanitize_v2_options(options);
        let Some(initial_secret) = (secret_source)() else {
            return Err(RuntimeError::Protocol(
                "v2 p2p listener secret is not available".to_owned(),
            ));
        };
        let now = (clock)();
        let initial_window = derive_epoch_p2p_window(&initial_secret, now);
        let (accepted_tx, accepted_rx) = mpsc::channel(P2P_V2_CHANNEL_CAP);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let mut bound_epochs: HashMap<u64, BoundEpoch> = HashMap::new();
        let active_ids_map: Arc<StdMutex<BTreeMap<u64, EndpointId>>> =
            Arc::new(StdMutex::new(BTreeMap::new()));
        let mut home_relay: Option<String> = None;

        for derived in initial_window.current_first() {
            match bind_epoch_listener(options.clone(), derived.clone(), accepted_tx.clone()).await {
                Ok((bound, relay)) => {
                    if home_relay.is_none() {
                        home_relay = relay;
                    }
                    active_ids_map
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(derived.epoch, bound.endpoint_id);
                    bound_epochs.insert(derived.epoch, bound);
                }
                Err(err) => {
                    for (_, b) in bound_epochs.drain() {
                        b.shutdown().await;
                    }
                    return Err(err);
                }
            }
        }

        let advertised = format_v2_advertised(home_relay.as_deref(), &options)?;
        let active_ids_c = Arc::clone(&active_ids_map);
        let mut last_secret = initial_secret;

        let manager_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        active_ids_c
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clear();
                        for (_, b) in bound_epochs.drain() {
                            b.shutdown().await;
                        }
                        return;
                    }
                    _ = interval.tick() => {
                        let Some(cur_secret) = (secret_source)() else {
                            active_ids_c
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .clear();
                            for (_, b) in bound_epochs.drain() {
                                b.shutdown().await;
                            }
                            return;
                        };
                        let secret_rotated = !bool::from(cur_secret.ct_eq(&*last_secret));
                        if secret_rotated {
                            last_secret = cur_secret.clone();
                            active_ids_c
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .clear();
                            for (_, b) in bound_epochs.drain() {
                                b.shutdown().await;
                            }
                        }

                        let window = derive_epoch_p2p_window(&last_secret, (clock)());
                        let want_epochs: Vec<&DerivedP2pEpoch> = window.epochs();

                        // Evict out-of-window epochs immediately.
                        let obsolete: Vec<u64> = bound_epochs
                            .keys()
                            .copied()
                            .filter(|ep| !want_epochs.iter().any(|d| d.epoch == *ep))
                            .collect();
                        for ep in obsolete {
                            active_ids_c
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .remove(&ep);
                            if let Some(b) = bound_epochs.remove(&ep) {
                                b.shutdown().await;
                            }
                        }

                        // Bind missing or finished epochs.
                        for derived in want_epochs {
                            let needs_bind = match bound_epochs.get(&derived.epoch) {
                                None => true,
                                Some(b) => b
                                    .forward_task
                                    .as_ref()
                                    .is_none_or(JoinHandle::is_finished),
                            };
                            if !needs_bind {
                                continue;
                            }
                            if let Some(old) = bound_epochs.remove(&derived.epoch) {
                                old.shutdown().await;
                            }
                            match bind_epoch_listener(
                                options.clone(),
                                derived.clone(),
                                accepted_tx.clone(),
                            )
                            .await
                            {
                                Ok((bound, _)) => {
                                    active_ids_c
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .insert(derived.epoch, bound.endpoint_id);
                                    bound_epochs.insert(derived.epoch, bound);
                                }
                                Err(err) => {
                                    tracing::debug!(epoch = derived.epoch, error = %err, "iroh://v2 epoch bind failed");
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            advertised,
            active_ids: active_ids_map,
            accepted_rx,
            shutdown_tx,
            manager_task: Some(manager_task),
        })
    }

    /// Advertised sentinel route (`iroh://v2?relay=<home>` or `iroh://v2`).
    #[must_use]
    pub fn advertised_endpoint(&self) -> &str {
        &self.advertised
    }

    /// Currently active `EndpointId`s bound across the active epoch window.
    #[must_use]
    pub fn active_endpoint_ids(&self) -> Vec<EndpointId> {
        self.active_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .copied()
            .collect()
    }

    /// Closes all active epoch listeners immediately.
    pub async fn close(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.manager_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for P2pV2Listener {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

#[async_trait]
impl PathListener for P2pV2Listener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = self.accepted_rx.recv().await.ok_or(RuntimeError::Closed)?;
        Ok(Box::new(stream))
    }

    fn local_endpoint(&self) -> String {
        self.advertised.clone()
    }
}

/// Ephemeral per-dial `iroh://v2` dialer (`spec/wire-v2.md` Section 7).
///
/// Each dial derives `(current [, adjacent])` target `EndpointId`s from `secret_source`, binds a
/// fresh ephemeral client `EndpointId` with `Pkarr` disabled, tries hint `?relay=` URL(s) first,
/// and falls back across remaining configured `relay_map` URLs (and the `+-300 s` adjacent epoch)
/// on miss. The client `Endpoint` closes when the returned stream closes or on dial failure.
#[derive(Clone)]
pub struct P2pV2Dialer {
    options: P2pOptions,
    secret_source: MailboxSecretSource,
    clock: P2pV2Clock,
    is_operator: bool,
    attempt_timeout: Option<Duration>,
}

impl P2pV2Dialer {
    /// Builds an ephemeral dialer for `iroh://v2` routes.
    #[must_use]
    pub fn new(options: P2pOptions, secret_source: MailboxSecretSource) -> Self {
        Self {
            options: sanitize_v2_options(options),
            secret_source,
            clock: wall_clock(),
            is_operator: false,
            attempt_timeout: None,
        }
    }

    /// Treats `?relay=` URLs on hints as operator-specified (subject to DNS pinning) rather than
    /// requiring membership in the configured relay map.
    #[must_use]
    pub fn with_operator(mut self, is_operator: bool) -> Self {
        self.is_operator = is_operator;
        self
    }

    /// Applies pre-checked DNS pins from egress verification.
    #[must_use]
    pub(crate) fn with_dns_pins(mut self, pins: Vec<(String, Vec<std::net::IpAddr>)>) -> Self {
        self.options = self.options.with_dns_pins(pins);
        self
    }

    /// Overrides the clock used for epoch window derivation (for tests).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_clock(mut self, clock: P2pV2Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Overrides whether relay addresses on private, loopback, or LAN IPs are permitted.
    #[must_use]
    pub fn with_allow_private_addrs(mut self, allow: bool) -> Self {
        self.options = self.options.with_allow_private_addrs(allow);
        self
    }

    /// Overrides per-tier dial timeout (for tests).
    #[must_use]
    pub fn with_attempt_timeout(mut self, dur: Duration) -> Self {
        self.attempt_timeout = Some(dur);
        self
    }
}

impl std::fmt::Debug for P2pV2Dialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pV2Dialer")
            .field("is_operator", &self.is_operator)
            .field("relay_mode", &self.options.relay_mode)
            .finish_non_exhaustive()
    }
}

struct RelayTier {
    relays: Vec<RelayUrl>,
    from_configured: bool,
}

#[async_trait]
impl PathDialer for P2pV2Dialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let hint_relays = parse_v2_p2p_relays(endpoint).map_err(|reason| {
            RuntimeError::Protocol(format!("iroh://v2 hint invalid: {reason}"))
        })?;
        let configured = relay_map_urls(&self.options.relay_mode)?;

        let mut tiers: Vec<RelayTier> = Vec::new();
        let mut extra_pins: Vec<(String, Vec<std::net::IpAddr>)> = Vec::new();
        if self.is_operator {
            if !hint_relays.is_empty() {
                let raw_urls: Vec<String> = hint_relays.iter().map(ToString::to_string).collect();
                let pins: Vec<(String, Vec<std::net::IpAddr>)> = self.options.dns_pins.clone();
                let checked_hosts = check_relay_hosts_pinned(
                    &raw_urls,
                    self.options.allow_private_addrs,
                    &configured_relay_urls(&self.options.relay_mode),
                    &pins,
                )
                .await?;
                for checked in checked_hosts {
                    let key = checked.host.to_ascii_lowercase();
                    if !extra_pins.iter().any(|(h, _)| *h == key) {
                        extra_pins.push((key, checked.ips));
                    }
                }
                let all_in_configured = hint_relays.iter().all(|u| configured.contains(u));
                tiers.push(RelayTier {
                    relays: hint_relays.clone(),
                    from_configured: all_in_configured,
                });
            }
            let remaining: Vec<RelayUrl> = configured
                .iter()
                .filter(|u| !hint_relays.contains(u))
                .cloned()
                .collect();
            if !remaining.is_empty() {
                tiers.push(RelayTier {
                    relays: remaining,
                    from_configured: true,
                });
            }
        } else {
            let primary: Vec<RelayUrl> = hint_relays
                .iter()
                .filter(|u| configured.contains(u))
                .cloned()
                .collect();
            let fallback: Vec<RelayUrl> = configured
                .iter()
                .filter(|u| !primary.contains(u))
                .cloned()
                .collect();
            if !primary.is_empty() {
                tiers.push(RelayTier {
                    relays: primary,
                    from_configured: true,
                });
            }
            if !fallback.is_empty() {
                tiers.push(RelayTier {
                    relays: fallback,
                    from_configured: true,
                });
            }
        }

        if tiers.is_empty() {
            return Err(RuntimeError::Protocol(
                "iroh://v2 hint has no configured relay".to_owned(),
            ));
        }

        let Some(secret) = (self.secret_source)() else {
            return Err(RuntimeError::Core(CoreError::HostKeyUnverified));
        };
        let window = derive_epoch_p2p_window(&secret, (self.clock)());
        let epochs = window.current_first();
        let total_attempts = epochs.len() * tiers.len();
        let per_attempt = self.attempt_timeout.unwrap_or_else(|| {
            if total_attempts > 1 {
                P2P_V2_MULTI_ATTEMPT_TIMEOUT
            } else {
                P2P_HANDSHAKE_TIMEOUT
            }
        });

        let mut last_err: Option<RuntimeError> = None;
        for derived in epochs {
            let target_id = EndpointId::from_bytes(&derived.endpoint_id)
                .map_err(|err| RuntimeError::Protocol(format!("invalid derived p2p id: {err}")))?;
            for tier in &tiers {
                let tier_urls: Vec<String> = tier.relays.iter().map(ToString::to_string).collect();
                let mode = parse_p2p_relay_modes(&tier_urls)?;
                let mut opts = sanitize_v2_options(self.options.clone());
                for (host, ips) in &extra_pins {
                    if !opts.dns_pins.iter().any(|(h, _)| h == host) {
                        opts.dns_pins.push((host.clone(), ips.clone()));
                    }
                }
                opts.relay_mode = mode;
                opts.ephemeral = true;
                opts.uri_derived_relays = !tier.from_configured;
                if !tier.from_configured {
                    opts.relay_auth = None;
                }
                let dialer = match crate::providers::p2p::P2pDialer::bind_with_options(opts).await {
                    Ok(d) => d,
                    Err(err) => {
                        last_err = Some(err);
                        continue;
                    }
                };
                let addr = EndpointAddr::from_parts(
                    target_id,
                    tier.relays.iter().cloned().map(TransportAddr::Relay),
                );
                match timeout(per_attempt, dialer.connect_endpoint_addr(addr)).await {
                    Ok(Ok(stream)) => return Ok(stream),
                    Ok(Err(err)) => {
                        dialer.close().await;
                        last_err = Some(err);
                    }
                    Err(_) => {
                        dialer.close().await;
                        last_err = Some(RuntimeError::Timeout("iroh://v2 attempt timed out"));
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| RuntimeError::Protocol("iroh://v2 dial failed".to_owned())))
    }
}

struct CancelableP2pV2Listener {
    inner: P2pV2Listener,
    stop_rx: watch::Receiver<bool>,
}

#[async_trait]
impl PathListener for CancelableP2pV2Listener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        loop {
            if *self.stop_rx.borrow() {
                return Err(RuntimeError::Closed);
            }
            tokio::select! {
                _ = self.stop_rx.changed() => {
                    if *self.stop_rx.borrow() {
                        return Err(RuntimeError::Closed);
                    }
                }
                res = self.inner.accept() => return res,
            }
        }
    }

    fn local_endpoint(&self) -> String {
        self.inner.local_endpoint()
    }
}

struct DynamicSlot {
    opts: P2pOptions,
    generation: u64,
}

struct ActivePeerListener {
    generation: u64,
    advertised: String,
    secret: Zeroizing<[u8; 32]>,
    secret_cell: Arc<StdMutex<Option<Zeroizing<[u8; 32]>>>>,
    stop_tx: watch::Sender<bool>,
}

struct ExplicitPeerListener {
    peer_id: String,
    listener: ActivePeerListener,
}

#[derive(Default)]
struct P2pV2SyncInner {
    closed: bool,
    desired: HashMap<String, Zeroizing<[u8; 32]>>,
    slots: Vec<DynamicSlot>,
    listeners: HashMap<(usize, String), ActivePeerListener>,
    explicit: Vec<ExplicitPeerListener>,
}

fn take_unusable_explicit(st: &mut P2pV2SyncInner) -> Vec<ActivePeerListener> {
    let mut removed = Vec::new();
    let mut idx = 0;
    while idx < st.explicit.len() {
        let keep = st
            .desired
            .get(&st.explicit[idx].peer_id)
            .is_some_and(|want| bool::from(want.ct_eq(&*st.explicit[idx].listener.secret)));
        if keep {
            idx += 1;
        } else {
            removed.push(st.explicit.swap_remove(idx).listener);
        }
    }
    removed
}

type MissingV2Bind = (usize, u64, P2pOptions, String, Zeroizing<[u8; 32]>);

/// Plan returned by [`P2pV2RosterSync::prepare_sync`] describing missing `(slot, peer)` listeners
/// to bind on the async runtime.
pub struct P2pV2SyncPlan {
    missing: Vec<MissingV2Bind>,
    register_idx: Option<usize>,
    existing_adv: Option<String>,
}

impl P2pV2SyncPlan {
    /// Returns `true` when there are no new `(slot, peer)` listeners to bind.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty()
    }
}

fn ct_str_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn p2p_relay_auth_eq(a: Option<&P2pRelayAuth>, b: Option<&P2pRelayAuth>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(P2pRelayAuth::BearerToken(x)), Some(P2pRelayAuth::BearerToken(y))) => ct_str_eq(x, y),
        #[cfg(feature = "p2p-iroh-services")]
        (Some(P2pRelayAuth::IrohServicesSecret(x)), Some(P2pRelayAuth::IrohServicesSecret(y))) => {
            ct_str_eq(x, y)
        }
        _ => false,
    }
}

fn p2p_options_eq(a: &P2pOptions, b: &P2pOptions) -> bool {
    a.relay_mode == b.relay_mode
        && a.publish_pkarr == b.publish_pkarr
        && a.resolve_pkarr == b.resolve_pkarr
        && a.advertise_direct_addrs == b.advertise_direct_addrs
        && a.allow_private_addrs == b.allow_private_addrs
        && p2p_relay_auth_eq(a.relay_auth.as_ref(), b.relay_auth.as_ref())
        && a.port_mapping == b.port_mapping
        && a.bind_addrs == b.bind_addrs
        && a.uri_derived_relays == b.uri_derived_relays
        && a.ephemeral == b.ephemeral
        && a.hint_dialer == b.hint_dialer
        && a.dns_pins == b.dns_pins
}

fn stop_active_listeners(removed: Vec<ActivePeerListener>) {
    for entry in removed {
        *entry
            .secret_cell
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let _ = entry.stop_tx.send(true);
    }
}

/// Shared roster-synchronized manager for dynamic `iroh://v2` listeners (`peer_id = None`).
///
/// Deduplicates slots by `relay_mode`, replaces slots and rotates listeners when any `P2pOptions`
/// field changes, tears down removed or CRL-revoked peers synchronously via `secret_cell` +
/// `watch`, and spawns newly activated peers onto an [`InboundRouter`].
#[derive(Default)]
pub struct P2pV2RosterSync {
    inner: StdMutex<P2pV2SyncInner>,
}

impl P2pV2RosterSync {
    /// Creates an empty, open dynamic listener registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` after [`Self::stop_all`] has been called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
    }

    /// Returns the number of currently active listeners (dynamic `(slot, peer)` plus explicit
    /// single-peer listeners).
    #[must_use]
    pub fn active_listener_count(&self) -> usize {
        let st = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.listeners.len() + st.explicit.len()
    }

    /// Returns the number of registered dynamic listener option slots.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots
            .len()
    }

    /// Synchronously reconciles active listeners against a serialized snapshot from
    /// `read_desired`, stopping removed or superseded listeners and returning any missing
    /// `(slot, peer)` binds in [`P2pV2SyncPlan`].
    ///
    /// Acquires `self.inner` before invoking `read_desired`, so concurrent sync and revocation
    /// calls observe the final roster state in lock order (`P2pV2RosterSync` -> roster). Callers
    /// must never hold a roster lock while calling into [`P2pV2RosterSync`].
    ///
    /// Returns `Ok(None)` when no dynamic listener slot has been registered yet.
    pub fn prepare_sync_with<F>(
        &self,
        read_desired: F,
        new_dynamic_opts: Option<P2pOptions>,
    ) -> Result<Option<P2pV2SyncPlan>, RuntimeError>
    where
        F: FnOnce() -> HashMap<String, Zeroizing<[u8; 32]>>,
    {
        let (removed, missing, register_idx, existing_adv) = {
            let mut st = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if st.closed {
                return Err(RuntimeError::Closed);
            }
            let reg_idx = if let Some(opts) = new_dynamic_opts {
                if let Some(pos) = st
                    .slots
                    .iter()
                    .position(|slot| slot.opts.relay_mode == opts.relay_mode)
                {
                    if !p2p_options_eq(&st.slots[pos].opts, &opts) {
                        st.slots[pos].opts = opts;
                        st.slots[pos].generation = st.slots[pos].generation.saturating_add(1);
                    }
                    Some(pos)
                } else {
                    let pos = st.slots.len();
                    st.slots.push(DynamicSlot {
                        opts,
                        generation: 1,
                    });
                    Some(pos)
                }
            } else {
                None
            };
            if st.slots.is_empty() {
                if !st.explicit.is_empty() {
                    st.desired = read_desired();
                    let removed = take_unusable_explicit(&mut st);
                    drop(st);
                    stop_active_listeners(removed);
                }
                return Ok(None);
            }
            st.desired = read_desired();

            let drop_keys: Vec<(usize, String)> = st
                .listeners
                .iter()
                .filter(|((idx, pid), cur)| {
                    st.slots
                        .get(*idx)
                        .is_none_or(|s| s.generation != cur.generation)
                        || st
                            .desired
                            .get(pid)
                            .is_none_or(|want| !bool::from(want.ct_eq(&*cur.secret)))
                })
                .map(|(k, _)| k.clone())
                .collect();
            let mut removed = Vec::with_capacity(drop_keys.len());
            for key in drop_keys {
                if let Some(entry) = st.listeners.remove(&key) {
                    removed.push(entry);
                }
            }
            removed.extend(take_unusable_explicit(&mut st));

            let mut missing = Vec::new();
            for (idx, slot) in st.slots.iter().enumerate() {
                for (pid, sec) in &st.desired {
                    if !st.listeners.contains_key(&(idx, pid.clone())) {
                        missing.push((
                            idx,
                            slot.generation,
                            slot.opts.clone(),
                            pid.clone(),
                            sec.clone(),
                        ));
                    }
                }
            }

            let existing_adv = reg_idx.and_then(|idx| {
                let slot_gen = st.slots.get(idx)?.generation;
                st.listeners
                    .iter()
                    .find(|((i, _), l)| *i == idx && l.generation == slot_gen)
                    .map(|(_, l)| l.advertised.clone())
            });

            (removed, missing, reg_idx, existing_adv)
        };
        stop_active_listeners(removed);
        Ok(Some(P2pV2SyncPlan {
            missing,
            register_idx,
            existing_adv,
        }))
    }

    /// Synchronously reconciles active listeners against `desired`, stopping removed or superseded
    /// listeners and returning any missing `(slot, peer)` binds in [`P2pV2SyncPlan`].
    ///
    /// Returns `Ok(None)` when no dynamic listener slot has been registered yet.
    pub fn prepare_sync(
        &self,
        desired: &HashMap<String, Zeroizing<[u8; 32]>>,
        new_dynamic_opts: Option<P2pOptions>,
    ) -> Result<Option<P2pV2SyncPlan>, RuntimeError> {
        self.prepare_sync_with(|| desired.clone(), new_dynamic_opts)
    }

    /// Synchronously updates the desired set via `read_desired` and tears down any listener whose
    /// peer is missing or whose mailbox secret changed. Safe to call without a Tokio runtime handle.
    pub fn stop_unusable_with<F>(&self, read_desired: F)
    where
        F: FnOnce() -> HashMap<String, Zeroizing<[u8; 32]>>,
    {
        let removed: Vec<ActivePeerListener> = {
            let mut st = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if st.closed || (st.slots.is_empty() && st.explicit.is_empty()) {
                return;
            }
            st.desired = read_desired();
            let drop_keys: Vec<(usize, String)> = st
                .listeners
                .iter()
                .filter(|((_, pid), cur)| {
                    st.desired
                        .get(pid)
                        .is_none_or(|want| !bool::from(want.ct_eq(&*cur.secret)))
                })
                .map(|(k, _)| k.clone())
                .collect();
            let mut removed = Vec::with_capacity(drop_keys.len());
            for key in drop_keys {
                if let Some(entry) = st.listeners.remove(&key) {
                    removed.push(entry);
                }
            }
            removed.extend(take_unusable_explicit(&mut st));
            removed
        };
        stop_active_listeners(removed);
    }

    /// Synchronously tears down any listener whose peer is missing from `desired` or whose mailbox
    /// secret changed. Safe to call without a Tokio runtime handle (for example on CRL updates).
    pub fn stop_unusable(&self, desired: &HashMap<String, Zeroizing<[u8; 32]>>) {
        self.stop_unusable_with(|| desired.clone());
    }

    /// Binds all missing `(slot, peer)` listeners planned by [`Self::prepare_sync`] and spawns
    /// them on `router`.
    pub async fn bind_missing(
        &self,
        plan: P2pV2SyncPlan,
        router: &InboundRouter,
        handle: &tokio::runtime::Handle,
    ) -> Result<Option<String>, RuntimeError> {
        let mut registered_adv = plan.existing_adv;
        for (idx, generation, opts, pid, secret) in plan.missing {
            let (proceed, existing_adv) = {
                let st = self
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let still_desired = st
                    .desired
                    .get(&pid)
                    .is_some_and(|want| bool::from(want.ct_eq(&*secret)));
                let slot_ok = st
                    .slots
                    .get(idx)
                    .is_some_and(|slot| slot.generation == generation);
                if st.closed || !still_desired || !slot_ok {
                    (false, None)
                } else if let Some(existing) = st.listeners.get(&(idx, pid.clone())) {
                    (false, Some(existing.advertised.clone()))
                } else {
                    (true, None)
                }
            };
            if let Some(adv) = existing_adv
                && Some(idx) == plan.register_idx
                && registered_adv.is_none()
            {
                registered_adv = Some(adv);
            }
            if !proceed {
                continue;
            }
            let secret_cell = Arc::new(StdMutex::new(Some(secret.clone())));
            let cell_c = Arc::clone(&secret_cell);
            let secret_source = Arc::new(move || {
                cell_c
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            });
            let listener = P2pV2Listener::bind(opts, secret_source).await?;
            let adv = listener.advertised_endpoint().to_owned();
            let (stop_tx, stop_rx) = watch::channel(false);
            let cancelable = CancelableP2pV2Listener {
                inner: listener,
                stop_rx,
            };
            let should_spawn = {
                let mut st = self
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let still_desired = st
                    .desired
                    .get(&pid)
                    .is_some_and(|want| bool::from(want.ct_eq(&*secret)));
                if st.closed
                    || !still_desired
                    || st
                        .slots
                        .get(idx)
                        .is_none_or(|slot| slot.generation != generation)
                    || st.listeners.contains_key(&(idx, pid.clone()))
                {
                    false
                } else {
                    st.listeners.insert(
                        (idx, pid),
                        ActivePeerListener {
                            generation,
                            advertised: adv.clone(),
                            secret,
                            secret_cell: Arc::clone(&secret_cell),
                            stop_tx: stop_tx.clone(),
                        },
                    );
                    true
                }
            };
            if should_spawn {
                if Some(idx) == plan.register_idx && registered_adv.is_none() {
                    registered_adv = Some(adv);
                }
                router.spawn_listener(handle, Box::new(cancelable));
            } else {
                *secret_cell
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                let _ = stop_tx.send(true);
                cancelable.inner.close().await;
            }
        }
        Ok(registered_adv)
    }

    /// Reconciles active listeners against `desired` and binds any missing slots asynchronously.
    pub async fn sync_with_desired(
        &self,
        desired: &HashMap<String, Zeroizing<[u8; 32]>>,
        new_dynamic_opts: Option<P2pOptions>,
        router: &InboundRouter,
        handle: &tokio::runtime::Handle,
    ) -> Result<Option<String>, RuntimeError> {
        let Some(plan) = self.prepare_sync(desired, new_dynamic_opts)? else {
            return Ok(None);
        };
        self.bind_missing(plan, router, handle).await
    }

    /// Binds and registers an explicit single-peer `iroh://v2` listener so it tears down on peer
    /// revocation, CRL ingestion, mailbox rotation, or [`Self::stop_all`].
    pub async fn bind_explicit_with<F>(
        &self,
        peer_id: String,
        opts: P2pOptions,
        secret: Zeroizing<[u8; 32]>,
        read_desired: F,
        router: &InboundRouter,
        handle: &tokio::runtime::Handle,
    ) -> Result<String, RuntimeError>
    where
        F: FnOnce() -> HashMap<String, Zeroizing<[u8; 32]>>,
    {
        if self.is_closed() {
            return Err(RuntimeError::Closed);
        }
        let secret_cell = Arc::new(StdMutex::new(Some(secret.clone())));
        let cell_c = Arc::clone(&secret_cell);
        let secret_source = Arc::new(move || {
            cell_c
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        });
        let listener = P2pV2Listener::bind(opts, secret_source).await?;
        let adv = listener.advertised_endpoint().to_owned();
        let (stop_tx, stop_rx) = watch::channel(false);
        let cancelable = CancelableP2pV2Listener {
            inner: listener,
            stop_rx,
        };
        let reject_err = {
            let mut st = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if st.closed {
                Some(RuntimeError::Closed)
            } else {
                st.desired = read_desired();
                let usable = st
                    .desired
                    .get(&peer_id)
                    .is_some_and(|want| bool::from(want.ct_eq(&*secret)));
                if usable {
                    st.explicit.push(ExplicitPeerListener {
                        peer_id,
                        listener: ActivePeerListener {
                            generation: 0,
                            advertised: adv.clone(),
                            secret,
                            secret_cell: Arc::clone(&secret_cell),
                            stop_tx: stop_tx.clone(),
                        },
                    });
                    None
                } else {
                    Some(RuntimeError::Protocol(
                        "peer is no longer usable for iroh://v2".to_owned(),
                    ))
                }
            }
        };
        if let Some(err) = reject_err {
            *secret_cell
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            let _ = stop_tx.send(true);
            cancelable.inner.close().await;
            return Err(err);
        }
        router.spawn_listener(handle, Box::new(cancelable));
        Ok(adv)
    }

    /// Closes the sync controller and stops every active dynamic and explicit listener
    /// synchronously.
    pub fn stop_all(&self) {
        let removed: Vec<ActivePeerListener> = {
            let mut st = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.closed = true;
            st.desired.clear();
            st.slots.clear();
            let mut removed: Vec<ActivePeerListener> =
                st.listeners.drain().map(|(_, v)| v).collect();
            removed.extend(st.explicit.drain(..).map(|e| e.listener));
            removed
        };
        stop_active_listeners(removed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicU64, Ordering};
    use zeroize::Zeroizing;

    use crate::provider::{recv_tendril_frame, send_tendril_frame};
    use crate::providers::p2p::P2pBindAddrs;
    use tendril_core::wire::ResumableFrameReader;

    fn loopback_bind() -> P2pBindAddrs {
        P2pBindAddrs::Only {
            v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            v6: None,
        }
    }

    async fn spawn_relay_server() -> (iroh_relay::server::Server, String) {
        let mut relay_cfg =
            iroh_relay::server::RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        relay_cfg.key_cache_capacity = Some(1024);
        let mut server_cfg = iroh_relay::server::ServerConfig::default();
        server_cfg.relay = Some(relay_cfg);
        let srv = iroh_relay::server::Server::spawn(server_cfg)
            .await
            .expect("spawn iroh-relay server");
        let url = format!("http://{}", srv.http_addr().expect("http addr"));
        (srv, url)
    }

    fn loopback_options(relay_urls: &[String]) -> P2pOptions {
        let mode = parse_p2p_relay_modes(relay_urls).expect("relay mode");
        P2pOptions::for_v2_listener(mode)
            .with_allow_private_addrs(true)
            .with_port_mapping(false)
            .with_bind_addrs(loopback_bind())
    }

    #[test]
    fn derived_seed_matches_iroh_secret_key_public() {
        let secret = [0x42u8; 32];
        for ts in [0u64, 150, 3599, 3600, 3601, 1_700_000_000] {
            let derived = derive_epoch_p2p_window(&secret, ts).current;
            let sk = iroh::SecretKey::from_bytes(&derived.secret_seed());
            assert_eq!(sk.public().as_bytes(), &derived.endpoint_id, "ts={ts}");
        }
    }

    #[tokio::test]
    async fn probe_p2p_v2_endpoint_uses_disabled_and_home_relay() {
        let bare = probe_p2p_v2_endpoint(
            P2pOptions::for_v2_listener(P2pRelayMode::Disabled).with_port_mapping(false),
        )
        .await
        .expect("probe disabled");
        assert_eq!(bare, "iroh://v2");

        let (_srv, relay_url) = spawn_relay_server().await;
        let probed = probe_p2p_v2_endpoint(loopback_options(std::slice::from_ref(&relay_url)))
            .await
            .expect("probe relay");
        assert!(probed.starts_with("iroh://v2?relay="), "{probed}");
        assert!(!probed.contains("addr="), "{probed}");
    }

    #[tokio::test]
    async fn v2_listener_and_dialer_handshake_uses_ephemeral_client_ids() {
        let (_srv, relay_url) = spawn_relay_server().await;
        let mailbox = Zeroizing::new([0x33u8; 32]);
        let secret_src: MailboxSecretSource = {
            let m = mailbox.clone();
            Arc::new(move || Some(m.clone()))
        };
        let clock: P2pV2Clock = Arc::new(|| 7_200 + 600);
        let mut listener = P2pV2Listener::bind_with_clock_and_poll(
            loopback_options(std::slice::from_ref(&relay_url)),
            secret_src.clone(),
            Arc::clone(&clock),
            Duration::from_millis(25),
        )
        .await
        .expect("bind v2 listener");
        let advertised = listener.advertised_endpoint().to_owned();
        assert!(advertised.starts_with("iroh://v2?relay="), "{advertised}");
        assert!(!advertised.contains("addr="), "{advertised}");

        let dialer = P2pV2Dialer::new(
            P2pOptions::for_dialer(parse_p2p_relay_modes(&[relay_url]).unwrap())
                .with_allow_private_addrs(true)
                .with_bind_addrs(loopback_bind()),
            secret_src,
        )
        .with_clock(clock);

        let mut seen_client_ids = Vec::new();
        for payload in [&b"first-v2"[..], &b"second-v2"[..]] {
            let adv = advertised.clone();
            let dial_fut = dialer.dial(&adv);
            let (client_res, server_res) = timeout(Duration::from_secs(20), async {
                tokio::join!(dial_fut, listener.accept())
            })
            .await
            .expect("handshake timeout");
            let mut client = client_res.expect("client dial");
            let mut server = server_res.expect("server accept");
            if let Some(id) = server.peer_transport_id() {
                seen_client_ids.push(id);
            }
            send_tendril_frame(client.as_mut(), payload)
                .await
                .expect("send");
            let mut reader = ResumableFrameReader::new();
            assert_eq!(
                recv_tendril_frame(server.as_mut(), &mut reader)
                    .await
                    .expect("recv"),
                payload
            );
            client.close().await.expect("close client");
            server.close().await.expect("close server");
        }
        assert_eq!(seen_client_ids.len(), 2);
        assert_ne!(
            seen_client_ids[0], seen_client_ids[1],
            "each dial must allocate a fresh ephemeral client EndpointId"
        );
        listener.close().await;
    }

    #[tokio::test]
    async fn v2_boundary_overlap_rotation_and_revocation_teardown() {
        let (_srv, relay_url) = spawn_relay_server().await;
        let now_secs = Arc::new(AtomicU64::new(3_500));
        let listener_clock: P2pV2Clock = {
            let c = Arc::clone(&now_secs);
            Arc::new(move || c.load(Ordering::SeqCst))
        };
        let secret_cell = Arc::new(StdMutex::new(Some(Zeroizing::new([0x55u8; 32]))));
        let secret_src: MailboxSecretSource = {
            let cell = Arc::clone(&secret_cell);
            Arc::new(move || {
                cell.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            })
        };

        let mut listener = P2pV2Listener::bind_with_clock_and_poll(
            loopback_options(std::slice::from_ref(&relay_url)),
            secret_src.clone(),
            listener_clock,
            Duration::from_millis(20),
        )
        .await
        .expect("bind listener");
        let ep0 = derive_epoch_p2p_window(&[0x55u8; 32], 3_500).current;
        let ep1 = derive_epoch_p2p_window(&[0x55u8; 32], 3_700).current;
        assert_eq!(listener.active_endpoint_ids().len(), 2);
        let advertised = listener.advertised_endpoint().to_owned();

        // Dialer already crossed into epoch 1 (at 3700) outside its own boundary window;
        // listener still at 3500 accepts via its pre-bound epoch 1 slot.
        let future_clock: P2pV2Clock = Arc::new(|| 3_600 + 600);
        let dialer = P2pV2Dialer::new(
            P2pOptions::for_dialer(
                parse_p2p_relay_modes(std::slice::from_ref(&relay_url)).unwrap(),
            )
            .with_allow_private_addrs(true)
            .with_bind_addrs(loopback_bind()),
            secret_src.clone(),
        )
        .with_clock(future_clock);

        let (c_res, s_res) = timeout(Duration::from_secs(20), async {
            tokio::join!(dialer.dial(&advertised), listener.accept())
        })
        .await
        .expect("boundary handshake");
        c_res
            .expect("epoch 1 dial while listener at 3500")
            .close()
            .await
            .expect("close");
        s_res.expect("epoch 1 accept").close().await.expect("close");

        // Advance listener past overlap window (offset 350 in epoch 1): epoch 0 must be evicted.
        now_secs.store(3_600 + 350, Ordering::SeqCst);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let ids = listener.active_endpoint_ids();
            if ids.len() == 1 && ids[0].as_bytes() == &ep1.endpoint_id {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "expected only ep1 bound after rotation; active={ids:?}, ep0={:?}, ep1={:?}",
                ep0.endpoint_id,
                ep1.endpoint_id
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Revocation (secret_source -> None) tears down all listeners immediately.
        *secret_cell
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let rev_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !listener.active_endpoint_ids().is_empty() {
            assert!(
                tokio::time::Instant::now() < rev_deadline,
                "revocation did not clear active IDs"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(matches!(
            timeout(Duration::from_secs(2), listener.accept()).await,
            Ok(Err(RuntimeError::Closed))
        ));
    }

    #[tokio::test]
    async fn v2_tier1_miss_falls_back_to_configured_relay_map() {
        let (_srv_a, relay_a) = spawn_relay_server().await;
        let (_srv_b, relay_b) = spawn_relay_server().await;
        let mailbox = Zeroizing::new([0x77u8; 32]);
        let secret_src: MailboxSecretSource = {
            let m = mailbox.clone();
            Arc::new(move || Some(m.clone()))
        };
        let clock: P2pV2Clock = Arc::new(|| 10_800 + 600);
        // Listener only binds relay_b.
        let mut listener = P2pV2Listener::bind_with_clock_and_poll(
            loopback_options(std::slice::from_ref(&relay_b)),
            secret_src.clone(),
            Arc::clone(&clock),
            Duration::from_millis(25),
        )
        .await
        .expect("bind listener on relay_b");

        // Dialer knows both [relay_a, relay_b]; hint points at relay_a where target isn't online.
        let dialer = P2pV2Dialer::new(
            P2pOptions::for_dialer(parse_p2p_relay_modes(&[relay_a.clone(), relay_b]).unwrap())
                .with_allow_private_addrs(true)
                .with_bind_addrs(loopback_bind()),
            secret_src,
        )
        .with_clock(clock)
        .with_attempt_timeout(Duration::from_millis(900));

        let hint = format!("iroh://v2?relay={relay_a}");
        let (c_res, s_res) = timeout(Duration::from_secs(20), async {
            tokio::join!(dialer.dial(&hint), listener.accept())
        })
        .await
        .expect("fallback timeout");
        let mut client = c_res.expect("fallback to relay_b must succeed");
        let mut server = s_res.expect("listener must accept via relay_b");
        send_tendril_frame(client.as_mut(), b"via-tier2")
            .await
            .expect("send");
        let mut reader = ResumableFrameReader::new();
        assert_eq!(
            recv_tendril_frame(server.as_mut(), &mut reader)
                .await
                .expect("recv"),
            b"via-tier2"
        );
        listener.close().await;
    }

    #[tokio::test]
    async fn roster_sync_deduplicates_idempotent_calls_and_rebinds_on_option_change() {
        let opts1 = P2pOptions::for_v2_listener(P2pRelayMode::Disabled)
            .with_allow_private_addrs(true)
            .with_port_mapping(false)
            .with_bind_addrs(loopback_bind());
        let opts2 = opts1.clone().with_port_mapping(true);

        let sync = P2pV2RosterSync::new();
        let router = InboundRouter::new();
        let handle = tokio::runtime::Handle::current();
        let mut desired = HashMap::new();
        desired.insert("peer-a".to_owned(), Zeroizing::new([0x33u8; 32]));

        let adv1 = sync
            .sync_with_desired(&desired, Some(opts1.clone()), &router, &handle)
            .await
            .expect("first sync")
            .expect("adv1");
        assert_eq!(adv1, "iroh://v2");
        assert_eq!(sync.slot_count(), 1);
        assert_eq!(sync.active_listener_count(), 1);

        // Identical repeat call must not add a slot or duplicate listener.
        let adv2 = sync
            .sync_with_desired(&desired, Some(opts1), &router, &handle)
            .await
            .expect("repeat sync")
            .expect("adv2");
        assert_eq!(adv2, adv1);
        assert_eq!(sync.slot_count(), 1);
        assert_eq!(sync.active_listener_count(), 1);

        // Changing options on same relay_mode rotates generation and keeps exactly 1 listener.
        let _ = sync
            .sync_with_desired(&desired, Some(opts2), &router, &handle)
            .await
            .expect("option change sync");
        assert_eq!(sync.slot_count(), 1);
        assert_eq!(sync.active_listener_count(), 1);

        // CRL / revocation dropping the peer stops the active listener synchronously.
        sync.stop_unusable(&HashMap::new());
        assert_eq!(sync.active_listener_count(), 0);
        sync.stop_all();
        assert!(sync.is_closed());
    }

    #[tokio::test]
    async fn roster_sync_bind_missing_skips_peer_revoked_or_rotated_after_prepare_sync() {
        let opts = P2pOptions::for_v2_listener(P2pRelayMode::Disabled)
            .with_allow_private_addrs(true)
            .with_port_mapping(false)
            .with_bind_addrs(loopback_bind());

        let sync = P2pV2RosterSync::new();
        let router = InboundRouter::new();
        let handle = tokio::runtime::Handle::current();

        let mut active = HashMap::new();
        active.insert("peer-a".to_owned(), Zeroizing::new([0x41u8; 32]));

        // (a) Plan with peer-a active, revoke before bind_missing executes -> no listener spawned.
        let plan_revoked = sync
            .prepare_sync_with(|| active.clone(), Some(opts.clone()))
            .expect("prepare active")
            .expect("plan");
        assert!(!plan_revoked.is_empty());
        sync.stop_unusable_with(HashMap::new);
        assert!(
            sync.bind_missing(plan_revoked, &router, &handle)
                .await
                .expect("bind_missing after revoke")
                .is_none()
        );
        assert_eq!(sync.active_listener_count(), 0);

        // (b) Plan with secret A, rotate desired secret to B before bind_missing -> old plan skipped.
        let plan_old_secret = sync
            .prepare_sync(&active, None)
            .expect("prepare secret A")
            .expect("plan A");
        let mut rotated = HashMap::new();
        rotated.insert("peer-a".to_owned(), Zeroizing::new([0x42u8; 32]));
        sync.stop_unusable(&rotated);
        assert!(
            sync.bind_missing(plan_old_secret, &router, &handle)
                .await
                .expect("bind_missing with stale secret")
                .is_none()
        );
        assert_eq!(sync.active_listener_count(), 0);

        // Fresh prepare matching rotated secret binds normally.
        let plan_new = sync
            .prepare_sync(&rotated, Some(opts))
            .expect("prepare secret B")
            .expect("plan B");
        assert_eq!(
            sync.bind_missing(plan_new, &router, &handle)
                .await
                .expect("bind_missing rotated")
                .as_deref(),
            Some("iroh://v2")
        );
        assert_eq!(sync.active_listener_count(), 1);
        sync.stop_all();
    }

    #[tokio::test]
    async fn explicit_listener_stops_on_revocation_and_stop_all() {
        let opts = P2pOptions::for_v2_listener(P2pRelayMode::Disabled)
            .with_allow_private_addrs(true)
            .with_port_mapping(false)
            .with_bind_addrs(loopback_bind());

        let sync = P2pV2RosterSync::new();
        let router = InboundRouter::new();
        let handle = tokio::runtime::Handle::current();

        let sec_a = Zeroizing::new([0x51u8; 32]);
        let mut active = HashMap::new();
        active.insert("peer-explicit".to_owned(), sec_a.clone());

        let adv = sync
            .bind_explicit_with(
                "peer-explicit".to_owned(),
                opts.clone(),
                sec_a.clone(),
                || active.clone(),
                &router,
                &handle,
            )
            .await
            .expect("bind explicit active peer");
        assert_eq!(adv, "iroh://v2");
        assert_eq!(sync.slot_count(), 0);
        assert_eq!(sync.active_listener_count(), 1);

        // Revoking removes the explicit listener even when no dynamic slot exists.
        sync.stop_unusable_with(HashMap::new);
        assert_eq!(sync.active_listener_count(), 0);

        // If the peer became unusable right before registration, bind_explicit_with refuses it.
        let err = sync
            .bind_explicit_with(
                "peer-explicit".to_owned(),
                opts.clone(),
                sec_a.clone(),
                HashMap::new,
                &router,
                &handle,
            )
            .await
            .expect_err("stale secret rejected");
        assert!(matches!(err, RuntimeError::Protocol(_)));
        assert_eq!(sync.active_listener_count(), 0);

        // stop_all tears down an explicit listener too.
        sync.bind_explicit_with(
            "peer-explicit".to_owned(),
            opts,
            sec_a,
            || active.clone(),
            &router,
            &handle,
        )
        .await
        .expect("rebind explicit");
        assert_eq!(sync.active_listener_count(), 1);
        sync.stop_all();
        assert!(sync.is_closed());
        assert_eq!(sync.active_listener_count(), 0);
    }
}
