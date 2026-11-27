//! Python PyO3 bindings over `tendril-core` and `tendril-runtime` with GIL release.

mod route_set;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde::Deserialize;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, b64url_decode,
    b64url_decode_array, b64url_encode, compute_code_mac as core_compute_code_mac,
    device_id as core_device_id, fingerprint_device as core_fingerprint_device,
    fingerprint_host as core_fingerprint_host, pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::error::{CoreError, RefusalReason};
use tendril_core::grants::{AuditEvent, Grant, RevocationList, authorize_grant, canonical_json};
use tendril_core::group::GroupManifest;
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, is_valid_host_id, verify_rotation_chain,
};
use tendril_core::pairing::{
    EnrollmentPolicy, IssueOptions, PairAction, PairOutcome, PairingCodeKind, PairingConfig,
    PairingManager, PairingUri, PersistOpts, PinnedHost, RoutePolicy,
    mint_enrollment_token as core_mint_enrollment_token,
};
use tendril_core::policy::ProviderId;
use tendril_core::relay_auth::{RelayAuthRole, RelayAuthSecret, RelayTicket, origin_allowed};
use tendril_core::roster::{
    AnchorState, PeerState, RefusalPolicy, Roster, RouteSource, StoredRoute,
};
use tendril_core::v2::{
    V2PairOutcome, V2PinnedHost, canonical_relay_host, derive_epoch_mailbox_window,
};
use tendril_runtime::advertise::{AdvertiseInputs, AdvertiseMode, NetworkSnapshot, ServedListener};
use tendril_runtime::announce::{
    AddressSource, DEFAULT_ROUTE_REFRESH_INTERVAL, RosterAccess, RouteAnnouncer, RouteSetSink,
    unix_ms,
};
use tendril_runtime::driver::{
    AttemptError, ConnectOpts, PairPolicyOptions, PairPolicyResult,
    drive_pair_initiator_with_policy,
};
use tendril_runtime::providers::SkippedHint;
use tendril_runtime::providers::hints::{
    HintDialerConfig, HintDialers, RouteApplyOpts, apply_signed_route_uri, clear_peer_routes,
    peer_routes, set_peer_routes,
};
use tendril_runtime::redact::{redact_error, redact_hint, redact_json_error, redact_text};
use tendril_runtime::v2_driver::drive_v2_pair_initiator_with_policy;
use tendril_runtime::{
    ApnsPushMode, BroadcastReport, BrokerDialer, ConcurrentSession, ConcurrentV2Session,
    DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, GroupEvent,
    GroupFrameKind, GroupFrameOutcome, GroupPool, GroupPoolConfig, InboundRouter, LocalDialer,
    M2mEnrollOptions, MAX_OUTER_FRAME_LEN, OverlayDialer, P2pDialer, P2pListener, P2pOptions,
    P2pRelayAuth, P2pRelayMode, PathDialer, PathListener, PathStream, RelayClientAuth, RelayDialer,
    RelayListener, RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig, RuntimeError,
    SessionDriver, SessionEvent, StateStore, V2ResponderState, V2SessionDriver, WakeAdapterKind,
    WakeConfigSpec, WakeTag, WakeTransportSettings, build_wake_provider, connect_with_wake_policy,
    dial_endpoint_with_auth, drive_m2m_enroll_initiator_with_floor,
    drive_m2m_enroll_initiator_with_routes, drive_pair_initiator_with_store,
    drive_pair_responder_with_policy_and_store, drive_pair_responder_with_store,
    drive_v2_pake_pair_initiator_with_store, drive_v2_pake_pair_initiator_with_timeout,
    drive_v2_pake_pair_responder_with_options, drive_v2_pake_pair_responder_with_store,
    group_add_member as rt_group_add_member, group_create as rt_group_create,
    group_ingest_manifest as rt_group_ingest_manifest,
    group_remove_member as rt_group_remove_member, handle_session_group_frame,
    pairing_path_kind_for_provider, parse_p2p_relay_mode, parse_p2p_relay_modes,
    pinned_pairing_floor, verify_epoch_wake_tag_window,
};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn py_err(err: impl fmt::Display) -> PyErr {
    PyRuntimeError::new_err(redact_text(&err.to_string()))
}

fn value_err(err: impl fmt::Display) -> PyErr {
    PyValueError::new_err(redact_text(&err.to_string()))
}

pyo3::create_exception!(
    tendril,
    RefusedError,
    PyRuntimeError,
    "A host that knows this device refused the session over an authenticated channel.\n\n\
     `reason` is `\"revoked\"` (the host blocks this device key for good: re-pairing needs a new \
     device identity), `\"pending\"` (the host has not confirmed this device yet: retry with \
     backoff) or `\"other\"`. `close_code` is the wire close code and `code` the stable machine \
     code (`refused_revoked`, `refused_pending` or `refused`)."
);

/// Name of a refusal reason in a `RefusedError` and in the closed event.
const fn refusal_name(reason: RefusalReason) -> &'static str {
    match reason {
        RefusalReason::Revoked => "revoked",
        RefusalReason::Pending => "pending",
        RefusalReason::Other(_) => "other",
    }
}

/// A [`RefusedError`] carrying the typed `reason`, `close_code` and `code` of `reason`.
fn refused_err(reason: RefusalReason, msg: &str) -> PyErr {
    let err = RefusedError::new_err(redact_text(msg));
    Python::attach(|py| {
        let value = err.value(py);
        // A fresh exception instance has a dict, so these attributes cannot fail to set.
        let _ = value.setattr("reason", refusal_name(reason));
        let _ = value.setattr("close_code", reason.close_code());
        let _ = value.setattr("code", reason.code());
    });
    err
}

/// The error of a failed session call: a [`RefusedError`] for an authenticated refusal.
fn session_err(err: &RuntimeError) -> PyErr {
    session_err_msg(err, &err.to_string())
}

/// [`session_err`] with `msg` as the text, typed by the refusal of `err`.
fn session_err_msg(err: &RuntimeError, msg: &str) -> PyErr {
    match err.refusal() {
        Some(reason) => refused_err(reason, msg),
        None => PyRuntimeError::new_err(redact_text(msg)),
    }
}

fn rt_err(err: RuntimeError) -> PyErr {
    PyRuntimeError::new_err(redact_error(&err))
}

fn rt_value_err(err: RuntimeError) -> PyErr {
    PyValueError::new_err(redact_error(&err))
}

/// A `ValueError` naming the JSON error's category and position, never its input.
fn json_err(what: &str, err: &serde_json::Error) -> PyErr {
    PyValueError::new_err(format!("invalid {what}: {}", redact_json_error(err)))
}

fn lock_roster(roster: &StdMutex<Roster>) -> std::sync::MutexGuard<'_, Roster> {
    roster
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The roster handle live sessions share: the state directory and the in-memory roster they
/// write to, with the local signer, so the host's own CRL is kept.
///
/// Every read of the store folds the revocation state `roster` holds into the stored roster,
/// and every write persists it, under the roster file lock (`tendril_runtime::announce`).
fn session_access(
    store: Option<&Arc<StateStore>>,
    roster: &Arc<StdMutex<Roster>>,
    identity: &EndpointIdentity,
) -> RosterAccess {
    RosterAccess::new(store.cloned(), Arc::clone(roster)).with_local_signer(
        identity.host_id(),
        identity.signing_key().public_key().clone(),
    )
}

/// Mutates the roster under the `store_lock` -> roster lock order. Must run outside any Tokio
/// runtime thread.
fn update_roster_blocking<T>(
    store: Option<&Arc<StateStore>>,
    store_lock: &AsyncMutex<()>,
    roster: &Arc<StdMutex<Roster>>,
    identity: &EndpointIdentity,
    f: impl FnOnce(&mut Roster) -> Result<T, RuntimeError>,
) -> PyResult<T> {
    if let Some(store) = store {
        let _guard = store_lock.blocking_lock();
        session_access(Some(store), roster, identity)
            .update(f)
            .map_err(py_err)
    } else {
        let mut guard = lock_roster(roster);
        f(&mut guard).map_err(py_err)
    }
}

/// Commits the revocations and CRLs live sessions learned in memory to the store and reloads
/// the shared roster from the result, under the `store_lock` -> roster lock order. Nothing is
/// written when the store already holds them: no `roster.json` is created and an existing one
/// keeps its mtime. Call it before any driver reads the store and after any session event or
/// driver result that can revoke.
fn sync_roster_blocking(
    store: Option<&Arc<StateStore>>,
    store_lock: &AsyncMutex<()>,
    roster: &Arc<StdMutex<Roster>>,
    identity: &EndpointIdentity,
) -> PyResult<()> {
    if let Some(store) = store {
        let _guard = store_lock.blocking_lock();
        session_access(Some(store), roster, identity)
            .commit_held_revocations()
            .map_err(py_err)?;
    }
    Ok(())
}

/// [`sync_roster_blocking`] for async callers: the commit runs on a blocking thread.
async fn sync_roster_async(
    store: Option<&Arc<StateStore>>,
    store_lock: &AsyncMutex<()>,
    roster: &Arc<StdMutex<Roster>>,
    identity: &Arc<EndpointIdentity>,
) -> Result<(), RuntimeError> {
    if let Some(store) = store {
        let _guard = store_lock.lock().await;
        let access = session_access(Some(store), roster, identity);
        tokio::task::spawn_blocking(move || access.commit_held_revocations())
            .await
            .map_err(|e| RuntimeError::Protocol(e.to_string()))??;
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn as_32(bytes: &[u8], name: &str) -> PyResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{name} must be exactly 32 bytes")))
}

fn parse_hybrid_signing_pub(bytes: &[u8], name: &str) -> PyResult<HybridSigningPublicKey> {
    if bytes.len() != HYBRID_SIGNING_PUB_LEN {
        return Err(PyValueError::new_err(format!(
            "{name} must be exactly {HYBRID_SIGNING_PUB_LEN} bytes"
        )));
    }
    HybridSigningPublicKey::from_bytes(bytes).map_err(|e| value_err(format!("invalid {name}: {e}")))
}

fn parse_signing_pin(bytes: &[u8], name: &str) -> PyResult<SigningKeyPin> {
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        parse_hybrid_signing_pub(bytes, name).map(SigningKeyPin::Full)
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let mut hash = [0u8; HYBRID_SIGNING_HASH_LEN];
        hash.copy_from_slice(bytes);
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(PyValueError::new_err(format!(
            "{name} must be {HYBRID_SIGNING_PUB_LEN} or {HYBRID_SIGNING_HASH_LEN} bytes"
        )))
    }
}

fn parse_signing_pin_b64(encoded: &str) -> Result<SigningKeyPin, String> {
    let bytes = b64url_decode(encoded).map_err(|e| e.to_string())?;
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        HybridSigningPublicKey::from_bytes(&bytes)
            .map(SigningKeyPin::Full)
            .map_err(|e| e.to_string())
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let hash: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "invalid signing key hash length".to_owned())?;
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(format!("invalid signing pin length {}", bytes.len()))
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct TransportConfigInput {
    relay_auth_secret: Option<String>,
    #[zeroize(skip)]
    relay_ticket: Option<RelayTicket>,
    #[zeroize(skip)]
    p2p_relay_mode: Option<String>,
    #[zeroize(skip)]
    p2p_relay_urls: Option<Vec<String>>,
    #[zeroize(skip)]
    p2p_pkarr: Option<bool>,
    #[zeroize(skip)]
    p2p_advertise_direct_addrs: Option<bool>,
    #[zeroize(skip)]
    p2p_allow_private_addrs: Option<bool>,
    #[zeroize(skip)]
    p2p_port_mapping: Option<bool>,
    #[zeroize(skip)]
    p2p_bind_addrs: Option<Vec<String>>,
    p2p_relay_auth_token: Option<String>,
    p2p_api_secret: Option<String>,
    #[zeroize(skip)]
    wake_url: Option<String>,
    #[zeroize(skip)]
    wake_adapter: Option<WakeAdapterKind>,
    wake_secret_b64: Option<String>,
    wake_auth_token: Option<String>,
    #[zeroize(skip)]
    wake_pre_wake: Option<bool>,
    #[zeroize(skip)]
    wake_retry_delay_ms: Option<u64>,
    #[zeroize(skip)]
    wake_max_attempts: Option<usize>,
    #[zeroize(skip)]
    wake_timeout_ms: Option<u64>,
    #[zeroize(skip)]
    wake_coalesce_secs: Option<u64>,
    #[zeroize(skip)]
    wake_apns_mode: Option<ApnsPushMode>,
    wake_apns_topic: Option<String>,
    wake_apns_loc_key: Option<String>,
    wake_apns_team_id: Option<String>,
    wake_apns_key_id: Option<String>,
    wake_apns_p8_pem: Option<String>,
    wake_apns_client_cert_pem: Option<String>,
    wake_apns_client_key_pem: Option<String>,
    #[zeroize(skip)]
    relay_auth_origins: Option<Vec<String>>,
    #[zeroize(skip)]
    advertise: Option<String>,
    #[zeroize(skip)]
    advertised_endpoints: Option<Vec<String>>,
    #[zeroize(skip)]
    route_policy: Option<String>,
    #[zeroize(skip)]
    sign_routes: Option<bool>,
}

#[derive(Clone)]
struct EndpointTransportConfig {
    relay_auth: RelayClientAuth,
    p2p_relay_mode: Option<P2pRelayMode>,
    p2p_pkarr: Option<bool>,
    p2p_advertise_direct_addrs: Option<bool>,
    p2p_allow_private_addrs: Option<bool>,
    /// `None` keeps port mapping on.
    p2p_port_mapping: Option<bool>,
    p2p_bind_addrs: tendril_runtime::P2pBindAddrs,
    p2p_relay_auth: Option<P2pRelayAuth>,
    wake: Option<WakeTransportSettings>,
    relay_auth_origins: Vec<String>,
    advertise: AdvertiseMode,
    advertised_endpoints: Vec<String>,
    route_policy: RoutePolicy,
    sign_routes: bool,
}

impl Default for EndpointTransportConfig {
    fn default() -> Self {
        Self {
            relay_auth: RelayClientAuth::default(),
            p2p_relay_mode: None,
            p2p_pkarr: None,
            p2p_advertise_direct_addrs: None,
            p2p_allow_private_addrs: None,
            p2p_port_mapping: None,
            p2p_bind_addrs: tendril_runtime::P2pBindAddrs::AllInterfaces,
            p2p_relay_auth: None,
            wake: None,
            relay_auth_origins: Vec::new(),
            advertise: AdvertiseMode::Auto,
            advertised_endpoints: Vec::new(),
            route_policy: RoutePolicy::AllSigned,
            sign_routes: true,
        }
    }
}

impl fmt::Debug for EndpointTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointTransportConfig")
            .field("relay_auth", &self.relay_auth)
            .field("p2p_relay_mode", &self.p2p_relay_mode)
            .field("p2p_pkarr", &self.p2p_pkarr)
            .field(
                "p2p_advertise_direct_addrs",
                &self.p2p_advertise_direct_addrs,
            )
            .field("p2p_allow_private_addrs", &self.p2p_allow_private_addrs)
            .field("p2p_port_mapping", &self.p2p_port_mapping)
            .field("p2p_bind_addrs", &self.p2p_bind_addrs)
            .field("p2p_relay_auth", &self.p2p_relay_auth)
            .field("wake", &self.wake)
            .field("relay_auth_origins", &self.relay_auth_origins)
            .field("advertise", &self.advertise)
            .field("advertised_endpoints", &self.advertised_endpoints)
            .field("route_policy", &self.route_policy)
            .field("sign_routes", &self.sign_routes)
            .finish()
    }
}

impl Drop for EndpointTransportConfig {
    fn drop(&mut self) {
        self.relay_auth = RelayClientAuth::None;
        self.p2p_relay_auth = None;
        self.wake = None;
    }
}

impl EndpointTransportConfig {
    fn from_input(mut input: TransportConfigInput) -> PyResult<Self> {
        if input.relay_auth_secret.is_some() && input.relay_ticket.is_some() {
            return Err(PyValueError::new_err(
                "relay_auth_secret and relay_ticket are mutually exclusive",
            ));
        }
        if input.p2p_relay_auth_token.is_some() && input.p2p_api_secret.is_some() {
            return Err(PyValueError::new_err(
                "p2p_relay_auth_token and p2p_api_secret are mutually exclusive",
            ));
        }
        if input.p2p_relay_mode.is_some() && input.p2p_relay_urls.is_some() {
            return Err(PyValueError::new_err(
                "p2p_relay_mode and p2p_relay_urls are mutually exclusive",
            ));
        }

        let relay_auth = if let Some(sec) = input.relay_auth_secret.take().map(Zeroizing::new) {
            let trimmed = sec.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
                return Err(PyValueError::new_err("invalid relay_auth_secret"));
            }
            let parsed = RelayAuthSecret::from_bytes(trimmed.as_bytes())
                .map_err(|_| PyValueError::new_err("invalid relay_auth_secret"))?;
            RelayClientAuth::HmacSecret(parsed)
        } else if let Some(ticket) = input.relay_ticket.take() {
            canonical_relay_host(&ticket.relay_host).map_err(value_err)?;
            if ticket.issuer_pub.is_empty() || ticket.target_pub.is_empty() || ticket.sig.is_empty()
            {
                return Err(PyValueError::new_err(
                    "relay_ticket has empty required fields",
                ));
            }
            RelayClientAuth::Ticket(ticket)
        } else {
            RelayClientAuth::None
        };

        let p2p_bind_addrs = tendril_runtime::parse_p2p_bind_addrs(
            "p2p_bind_addrs",
            input.p2p_bind_addrs.as_deref().unwrap_or_default(),
        )
        .map_err(value_err)?;

        let p2p_relay_mode = if let Some(ref mode_s) = input.p2p_relay_mode {
            Some(parse_p2p_relay_mode(Some(mode_s)).map_err(value_err)?)
        } else if let Some(ref urls) = input.p2p_relay_urls {
            Some(parse_p2p_relay_modes(urls).map_err(value_err)?)
        } else {
            None
        };

        let p2p_relay_auth =
            if let Some(tok) = input.p2p_relay_auth_token.take().map(Zeroizing::new) {
                if tok.is_empty() || tok.chars().any(char::is_control) {
                    return Err(PyValueError::new_err("invalid p2p_relay_auth_token"));
                }
                Some(P2pRelayAuth::BearerToken(tok))
            } else if let Some(sec) = input.p2p_api_secret.take().map(Zeroizing::new) {
                #[cfg(feature = "p2p-iroh-services")]
                {
                    if sec.is_empty() || sec.chars().any(char::is_control) {
                        return Err(PyValueError::new_err("invalid p2p_api_secret"));
                    }
                    Some(P2pRelayAuth::IrohServicesSecret(sec))
                }
                #[cfg(not(feature = "p2p-iroh-services"))]
                {
                    let _ = sec;
                    return Err(PyRuntimeError::new_err(
                        "tendril-py built without p2p-iroh-services feature",
                    ));
                }
            } else {
                None
            };

        if p2p_relay_auth.is_some() && matches!(p2p_relay_mode, Some(P2pRelayMode::Disabled)) {
            return Err(PyValueError::new_err(
                "p2p relay auth is invalid when p2p_relay_mode is disabled",
            ));
        }

        let wake_coalesce_secs = match (input.wake_url.as_ref(), input.wake_adapter) {
            (Some(_), Some(WakeAdapterKind::ApnsH2)) => input.wake_coalesce_secs,
            (Some(_), _) => Some(input.wake_coalesce_secs.unwrap_or(0)),
            (None, _) => input.wake_coalesce_secs,
        };
        let wake_spec = WakeConfigSpec {
            wake_url: input.wake_url.take(),
            wake_adapter: input.wake_adapter.take(),
            wake_secret_b64: input.wake_secret_b64.take(),
            wake_auth_token: input.wake_auth_token.take(),
            wake_pre_wake: input.wake_pre_wake.take(),
            wake_retry_delay_ms: input.wake_retry_delay_ms.take(),
            wake_max_attempts: input.wake_max_attempts.take(),
            wake_timeout_ms: input.wake_timeout_ms.take(),
            wake_coalesce_secs,
            wake_apns_mode: input.wake_apns_mode.take(),
            wake_apns_topic: input.wake_apns_topic.take(),
            wake_apns_loc_key: input.wake_apns_loc_key.take(),
            wake_apns_team_id: input.wake_apns_team_id.take(),
            wake_apns_key_id: input.wake_apns_key_id.take(),
            wake_apns_p8_pem: input.wake_apns_p8_pem.take(),
            wake_apns_client_cert_pem: input.wake_apns_client_cert_pem.take(),
            wake_apns_client_key_pem: input.wake_apns_client_key_pem.take(),
        };
        let wake = build_wake_provider(wake_spec).map_err(rt_value_err)?;

        let relay_auth_origins = input.relay_auth_origins.take().unwrap_or_default();
        if let Some(index) = relay_auth_origins
            .iter()
            .position(|o| !origin_allowed(o, std::slice::from_ref(o)))
        {
            return Err(PyValueError::new_err(format!(
                "invalid relay_auth_origins entry #{index}: expected scheme://host[:port]"
            )));
        }
        let advertise = match input.advertise.as_deref() {
            None | Some("auto") => AdvertiseMode::Auto,
            Some("explicit") => AdvertiseMode::Explicit,
            Some(other) => {
                return Err(PyValueError::new_err(format!(
                    "invalid advertise '{other}': expected 'auto' or 'explicit'"
                )));
            }
        };
        let route_policy = input
            .route_policy
            .as_deref()
            .map(str::parse::<RoutePolicy>)
            .transpose()
            .map_err(value_err)?
            .unwrap_or_default();

        Ok(Self {
            relay_auth,
            p2p_relay_mode,
            p2p_pkarr: input.p2p_pkarr,
            p2p_advertise_direct_addrs: input.p2p_advertise_direct_addrs,
            p2p_allow_private_addrs: input.p2p_allow_private_addrs,
            p2p_port_mapping: input.p2p_port_mapping,
            p2p_bind_addrs,
            p2p_relay_auth,
            wake,
            relay_auth_origins,
            advertise,
            advertised_endpoints: input.advertised_endpoints.take().unwrap_or_default(),
            route_policy,
            sign_routes: input.sign_routes.unwrap_or(true),
        })
    }

    /// The dialer set behind policy pairing and Day-2 connects. `relay_host` is the expected
    /// relay challenge host for an explicit operator relay endpoint; for an explicit `iroh://`
    /// endpoint it also selects the Iroh relay mode when none is configured.
    fn hint_dialers(
        &self,
        relay_host: Option<&str>,
        operator_endpoint: Option<&str>,
    ) -> Result<Arc<HintDialers>, RuntimeError> {
        let host = relay_host.map(str::trim).filter(|s| !s.is_empty());
        let mut p2p_relay_mode = self.p2p_relay_mode.clone();
        if p2p_relay_mode.is_none() && operator_endpoint.is_some_and(|e| e.starts_with("iroh://")) {
            if let Some(spec) = host {
                p2p_relay_mode = Some(parse_p2p_relay_mode(Some(spec))?);
            } else if std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1") {
                p2p_relay_mode = Some(P2pRelayMode::Disabled);
            }
        }
        Ok(Arc::new(HintDialers::new(HintDialerConfig {
            relay_auth: self.relay_auth.clone(),
            relay_expected_host: host.map(ToOwned::to_owned),
            p2p_relay_mode: p2p_relay_mode.unwrap_or(P2pRelayMode::N0Public),
            p2p_relay_auth: self.p2p_relay_auth.clone(),
            p2p_allow_private_addrs: self.p2p_allow_private_addrs.unwrap_or(false),
            p2p_pkarr: self.p2p_pkarr,
            p2p_port_mapping: self.p2p_port_mapping.unwrap_or(true),
            p2p_bind_addrs: self.p2p_bind_addrs.clone(),
        })))
    }

    fn build_p2p_listener_options(
        &self,
        relay_mode_override: Option<&str>,
    ) -> Result<P2pOptions, RuntimeError> {
        let mode = match relay_mode_override.map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => parse_p2p_relay_mode(Some(raw))?,
            None => self
                .p2p_relay_mode
                .clone()
                .unwrap_or(P2pRelayMode::N0Public),
        };
        let mut opts = P2pOptions::for_listener(mode);
        if let Some(pkarr) = self.p2p_pkarr {
            opts = opts.with_publish_pkarr(pkarr).with_resolve_pkarr(pkarr);
        }
        if let Some(adv) = self.p2p_advertise_direct_addrs {
            opts = opts.with_advertise_direct_addrs(adv);
        }
        if let Some(allow_priv) = self.p2p_allow_private_addrs {
            opts = opts.with_allow_private_addrs(allow_priv);
        }
        opts = opts.with_relay_auth(self.p2p_relay_auth.clone());
        Ok(self.with_p2p_net(opts))
    }

    /// Applies `p2p_port_mapping` and `p2p_bind_addrs` to `opts`.
    fn with_p2p_net(&self, opts: P2pOptions) -> P2pOptions {
        opts.with_port_mapping(self.p2p_port_mapping.unwrap_or(true))
            .with_bind_addrs(self.p2p_bind_addrs.clone())
    }

    fn build_p2p_dialer_options(
        &self,
        endpoint: &str,
        relay_host: Option<&str>,
    ) -> Result<P2pOptions, RuntimeError> {
        let explicit_mode = if let Some(ref m) = self.p2p_relay_mode {
            Some(m.clone())
        } else if let Some(spec) = relay_host.map(str::trim).filter(|s| !s.is_empty()) {
            Some(parse_p2p_relay_mode(Some(spec))?)
        } else if std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1") {
            Some(P2pRelayMode::Disabled)
        } else {
            None
        };
        let allow_private = self.p2p_allow_private_addrs.unwrap_or(false);
        let mut opts = P2pOptions::for_endpoint(endpoint, explicit_mode, allow_private)?;
        if let Some(pkarr) = self.p2p_pkarr {
            opts = opts.with_resolve_pkarr(pkarr);
        }
        Ok(self.with_p2p_net(opts.with_relay_auth(self.p2p_relay_auth.clone())))
    }

    /// Options for the shared group `P2pDialer`, present only when a relay mode is configured
    /// explicitly (or `TENDRIL_P2P_LOCAL=1`). Other p2p settings never imply public relays.
    fn build_p2p_group_options(&self) -> Option<P2pOptions> {
        P2pOptions::for_group_dialer(
            self.p2p_relay_mode.clone(),
            std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1"),
            self.p2p_pkarr,
            self.p2p_allow_private_addrs,
            self.p2p_relay_auth.clone(),
        )
        .map(|opts| self.with_p2p_net(opts))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PyPinnedHostInput {
    host_id: Option<String>,
    #[serde(alias = "static_pub")]
    static_pub_b64: String,
    #[serde(alias = "signing_pub", alias = "signing_pin")]
    signing_pin_b64: String,
    #[serde(default)]
    rotation_seq: u64,
    #[serde(default)]
    min_wire_version: Option<u8>,
}

fn ws_path(endpoint: &str) -> &str {
    let without_frag = endpoint.split_once('#').map_or(endpoint, |(u, _)| u);
    let without_query = without_frag
        .split_once('?')
        .map_or(without_frag, |(u, _)| u);
    if let Some(rest) = without_query
        .strip_prefix("ws://")
        .or_else(|| without_query.strip_prefix("wss://"))
    {
        rest.split_once('/').map_or("", |(_, path)| path)
    } else {
        ""
    }
}

fn is_v2_relay_endpoint(endpoint: &str) -> bool {
    (endpoint.starts_with("ws://") || endpoint.starts_with("wss://"))
        && ws_path(endpoint) == "v2/relay"
}

fn lookup_v2_mailbox_secret_for_target(
    roster: &Roster,
    target_host_id: &str,
) -> PyResult<[u8; 32]> {
    let entry = roster.get(target_host_id).ok_or_else(|| {
        PyRuntimeError::new_err(format!("target '{target_host_id}' not found in roster"))
    })?;
    if entry.state == PeerState::Revoked {
        return Err(PyRuntimeError::new_err(format!(
            "target '{target_host_id}' is revoked"
        )));
    }
    entry
        .v2_secrets
        .as_ref()
        .map(|s| *s.mailbox_secret())
        .ok_or_else(|| {
            PyRuntimeError::new_err(format!(
                "target '{target_host_id}' has no v2 mailbox_secret"
            ))
        })
}

fn lookup_v2_mailbox_secret_for_pair(
    roster: &Roster,
    pinned: Option<&PinnedHost>,
    endpoint: &str,
    now_unix: u64,
) -> Result<[u8; 32], RuntimeError> {
    if let Some(pin) = pinned {
        if let Some(ref hid) = pin.host_id
            && let Some(entry) = roster.get(hid)
            && entry.state != PeerState::Revoked
            && let Some(ref secrets) = entry.v2_secrets
        {
            return Ok(*secrets.mailbox_secret());
        }
        for (_, entry) in roster.entries() {
            if entry.state != PeerState::Revoked
                && entry.static_pub == pin.static_pub
                && let Some(ref secrets) = entry.v2_secrets
            {
                return Ok(*secrets.mailbox_secret());
            }
        }
    }
    if let Some((_, frag)) = endpoint.split_once('#')
        && !frag.is_empty()
    {
        for (_, entry) in roster.entries() {
            if entry.state != PeerState::Revoked
                && let Some(ref secrets) = entry.v2_secrets
            {
                let win = derive_epoch_mailbox_window(secrets.mailbox_secret(), now_unix);
                if win
                    .mailboxes()
                    .iter()
                    .any(|mb| mb.mailbox_id_b64url() == frag)
                {
                    return Ok(*secrets.mailbox_secret());
                }
            }
        }
    }
    Err(RuntimeError::Protocol(
        "no matching v2 mailbox_secret in roster for /v2/relay endpoint".to_owned(),
    ))
}

async fn dial_endpoint_v2_with_options(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &EndpointTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathStream>, RuntimeError> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        let opts = cfg.build_p2p_dialer_options(endpoint, normalized_host)?;
        let dialer = P2pDialer::bind_with_options(opts).await?;
        return match dialer.dial(endpoint).await {
            Ok(stream) => Ok(stream),
            Err(err) => {
                dialer.close().await;
                Err(err)
            }
        };
    }
    if let Some(secret) = v2_mailbox_secret {
        let mut dialer = RelayV2Dialer::new(secret).with_auth(cfg.relay_auth.clone());
        if let Some(host) = normalized_host {
            dialer = dialer.with_expected_host(host);
        }
        return dialer.dial(endpoint).await;
    }
    dial_endpoint_with_auth(endpoint, normalized_host, cfg.relay_auth.clone()).await
}

async fn drive_v1_pair_initiator_with_roster_floors(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    roster: &Roster,
) -> Result<PairOutcome, RuntimeError> {
    let mut machine = tendril_core::pairing::PairingInitiator::new_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        code,
        None,
        tendril_core::WIRE_VERSION,
        None,
    )?
    .with_roster_floors(roster);
    timeout(DEFAULT_PRE_AUTH_TIMEOUT, async {
        let init_actions = machine.start()?;
        let mut should_close = false;
        for action in init_actions {
            match action {
                PairAction::WriteBytes(bytes) => {
                    for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
                        stream.send_chunk(chunk).await?;
                    }
                }
                PairAction::SasReady { .. } => {}
                PairAction::Completed(outcome) => return Ok(outcome),
                PairAction::CloseTransport(_) => {
                    should_close = true;
                }
            }
        }
        if should_close {
            let _ = stream.close().await;
        }
        let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
        loop {
            let n = stream.recv_chunk(&mut buf).await?;
            if n == 0 {
                return Err(RuntimeError::Closed);
            }
            let actions = machine.feed_bytes(&buf[..n])?;
            let mut completed = None;
            let mut close_now = false;
            for action in actions {
                match action {
                    PairAction::WriteBytes(bytes) => {
                        for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
                            stream.send_chunk(chunk).await?;
                        }
                    }
                    PairAction::SasReady { .. } => {}
                    PairAction::Completed(outcome) => completed = Some(outcome),
                    PairAction::CloseTransport(_) => close_now = true,
                }
            }
            if close_now {
                let _ = stream.close().await;
            }
            if let Some(outcome) = completed {
                return Ok(outcome);
            }
        }
    })
    .await
    .map_err(|_| RuntimeError::Timeout("pre-auth pairing handshake timed out"))?
}

#[pyfunction]
fn device_id(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_device_id(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn fingerprint_host(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_fingerprint_host(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn fingerprint_device(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_fingerprint_device(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn pairing_sas(handshake_hash: &[u8]) -> PyResult<String> {
    Ok(core_pairing_sas(&as_32(handshake_hash, "handshake_hash")?))
}

#[pyfunction]
fn compute_code_mac(py: Python<'_>, code: &str, handshake_hash: &[u8]) -> PyResult<Py<PyBytes>> {
    let hh = as_32(handshake_hash, "handshake_hash")?;
    let code_owned = code.to_owned();
    let mac = py
        .detach(move || core_compute_code_mac(&code_owned, &hh))
        .map_err(py_err)?;
    Ok(PyBytes::new(py, &mac).unbind())
}

#[pyfunction]
fn verify_rotation_chain_json(
    pinned_signing_b64: &str,
    pinned_static_b64: &str,
    pinned_seq: u64,
    chain_json: &str,
    cur_static_b64: &str,
    cur_signing_b64: &str,
) -> PyResult<u64> {
    let psig = HybridSigningPublicKey::from_b64url(pinned_signing_b64).map_err(value_err)?;
    let pstat = b64url_decode_array::<32>(pinned_static_b64).map_err(value_err)?;
    let cstat = b64url_decode_array::<32>(cur_static_b64).map_err(value_err)?;
    let csig = HybridSigningPublicKey::from_b64url(cur_signing_b64).map_err(value_err)?;
    let chain: Vec<RotationRecord> =
        serde_json::from_str(chain_json).map_err(|e| json_err("chain_json", &e))?;
    verify_rotation_chain(&psig, &pstat, pinned_seq, &chain, &cstat, &csig).map_err(py_err)
}

#[pyfunction]
#[pyo3(signature = (grant_json, issuer_keys_json, expected_subject, expected_root_issuer, requested_cap, now_unix_secs, crl_json=None))]
fn verify_grant_json(
    grant_json: &str,
    issuer_keys_json: &str,
    expected_subject: &str,
    expected_root_issuer: &str,
    requested_cap: &str,
    now_unix_secs: u64,
    crl_json: Option<&str>,
) -> PyResult<bool> {
    let grant: Grant = serde_json::from_str(grant_json).map_err(|e| json_err("grant_json", &e))?;
    let key_map_raw: HashMap<String, String> =
        serde_json::from_str(issuer_keys_json).map_err(|e| json_err("issuer_keys_json", &e))?;
    let mut key_map = HashMap::with_capacity(key_map_raw.len());
    for (id, b64) in key_map_raw {
        let k = HybridSigningPublicKey::from_b64url(&b64)
            .map_err(|e| value_err(format!("invalid key for {id}: {e}")))?;
        key_map.insert(id, k);
    }
    let crl: Option<RevocationList> = match crl_json {
        Some(s) if !s.is_empty() => {
            Some(serde_json::from_str(s).map_err(|e| json_err("crl_json", &e))?)
        }
        _ => None,
    };
    let (res, _) = authorize_grant(
        Some(&grant),
        expected_subject,
        expected_root_issuer,
        requested_cap,
        now_unix_secs,
        crl.as_ref(),
        |id| key_map.get(id).cloned(),
    );
    Ok(res.is_ok())
}

#[pyfunction]
fn verify_wake_tag(wake_secret: &[u8], wake_tag_b64: &str, now_unix_secs: u64) -> PyResult<bool> {
    let secret = Zeroizing::new(as_32(wake_secret, "wake_secret")?);
    let tag = WakeTag::from_b64url(wake_tag_b64).map_err(rt_value_err)?;
    Ok(verify_epoch_wake_tag_window(&secret, &tag, now_unix_secs))
}

/// Arguments of one Day-2 connect.
#[derive(Default)]
struct ConnectArgs {
    wire: u8,
    endpoint: Option<String>,
    grant: Option<Grant>,
    recovery_uri: Option<String>,
    replace_routes: bool,
    policy: Option<RoutePolicy>,
    relay_host: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConnectOptionsInput {
    wire: Option<u8>,
    grant: Option<Grant>,
    endpoint: Option<String>,
    recovery_uri: Option<String>,
    replace_routes: Option<bool>,
    route_policy: Option<String>,
    relay_host: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct IssueUriOptions {
    kind: Option<String>,
    host_name: Option<String>,
    sign_routes: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PairUriOptions {
    route_policy: Option<String>,
    save_route: Option<bool>,
    endpoint: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ApplyRouteOptions {
    replace_routes: Option<bool>,
    route_policy: Option<String>,
}

/// Parses an optional JSON options object; `None` and `""` mean all defaults.
fn parse_options<T: serde::de::DeserializeOwned + Default>(
    raw: Option<&str>,
    name: &str,
) -> PyResult<T> {
    match raw.filter(|s| !s.trim().is_empty()) {
        None => Ok(T::default()),
        Some(s) => serde_json::from_str(s).map_err(|e| json_err(name, &e)),
    }
}

fn parse_grant(grant_json: Option<&str>) -> PyResult<Option<Grant>> {
    match grant_json {
        Some(s) if !s.is_empty() => Ok(Some(
            serde_json::from_str(s).map_err(|e| json_err("grant_json", &e))?,
        )),
        _ => Ok(None),
    }
}

fn parse_route_policy(raw: Option<&str>, default: RoutePolicy) -> PyResult<RoutePolicy> {
    raw.filter(|s| !s.is_empty())
        .map_or(Ok(default), str::parse::<RoutePolicy>)
        .map_err(value_err)
}

const fn code_kind_name(kind: PairingCodeKind) -> &'static str {
    match kind {
        PairingCodeKind::Lan2Group => "lan",
        PairingCodeKind::Remote3Group => "remote",
    }
}

const fn provider_name(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::Local => "local",
        ProviderId::Direct => "direct",
        ProviderId::Overlay => "overlay",
        ProviderId::P2p => "p2p",
        ProviderId::Relay => "relay",
        ProviderId::Broker => "broker",
    }
}

fn routes_json_array(routes: &[StoredRoute]) -> serde_json::Value {
    routes
        .iter()
        .map(|r| serde_json::json!({ "hint": r.hint, "source": r.source.as_str() }))
        .collect()
}

/// One policy connect over the chosen wire.
async fn policy_connect(
    wire: u8,
    identity: &Arc<EndpointIdentity>,
    target: &str,
    access: &RosterAccess,
    opts: ConnectOpts,
) -> Result<SessionBackend, AttemptError> {
    if wire == 2 {
        V2SessionDriver::connect_with_policy_and_store(Arc::clone(identity), target, access, opts)
            .await
            .map(|r| SessionBackend::V2(Arc::new(r.session.into_concurrent())))
    } else {
        SessionDriver::connect_with_policy_and_store(Arc::clone(identity), target, access, opts)
            .await
            .map(|r| SessionBackend::V1(Arc::new(r.session.into_concurrent())))
    }
}

/// Folds an exhausted attempt into one error: the most severe cause, then the hints that were
/// never dialed and each candidate's failure. `committed` means the pairing code may be spent.
fn attempt_err(err: AttemptError) -> PyErr {
    let msg = attempt_message(&err);
    match err.error.refusal() {
        Some(reason) => refused_err(reason, &msg),
        None => py_err(msg),
    }
}

/// The text of [`attempt_err`] without its typing, for callers that have no refusal to report.
fn attempt_message(err: &AttemptError) -> String {
    use std::fmt::Write as _;
    let mut msg = redact_error(&err.error);
    if err.committed {
        msg.push_str("; committed: the pairing code may be spent");
    }
    if !err.skipped.is_empty() {
        let list: Vec<String> = err
            .skipped
            .iter()
            .map(|s| format!("{} ({})", redact_hint(&s.hint), skip_reason_name(s)))
            .collect();
        let _ = write!(msg, "; skipped: {}", list.join(", "));
    }
    if !err.failures.is_empty() {
        let list: Vec<String> = err
            .failures
            .iter()
            .map(|f| {
                format!(
                    "{} [{}]: {}",
                    redact_hint(&f.hint),
                    provider_name(f.provider),
                    redact_error(&f.error)
                )
            })
            .collect();
        let _ = write!(msg, "; candidates: {}", list.join("; "));
    }
    msg
}

fn skip_reason_name(skipped: &SkippedHint) -> String {
    serde_json::to_value(skipped.reason)
        .ok()
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

/// The identity fields of a Wire v1 pairing outcome, or the rejection text.
fn pair_outcome_json_v1(outcome: &PairOutcome) -> Result<serde_json::Value, String> {
    match outcome {
        PairOutcome::InitiatorPending {
            device_id,
            host_id,
            pairing_sas,
            host_pin_verified,
            ..
        } => Ok(serde_json::json!({
            "device_id": device_id,
            "host_id": host_id,
            "sas": pairing_sas,
            "status": if *host_pin_verified { "active" } else { "pending" },
            "host_confirmed": host_pin_verified,
        })),
        PairOutcome::Rejected { error } => Err(error.clone()),
        _ => Err("unexpected pairing outcome".to_owned()),
    }
}

/// The identity fields of a Wire v2 pairing outcome, or the rejection text.
fn pair_outcome_json_v2(outcome: &V2PairOutcome) -> Result<serde_json::Value, String> {
    match outcome {
        V2PairOutcome::InitiatorPending {
            device_id,
            host_id,
            pairing_sas,
            host_pin_verified,
            ..
        } => Ok(serde_json::json!({
            "device_id": device_id,
            "host_id": host_id,
            "sas": pairing_sas,
            "status": if *host_pin_verified { "active" } else { "pending" },
            "host_confirmed": host_pin_verified,
        })),
        V2PairOutcome::Rejected { error } => Err(error.clone()),
        V2PairOutcome::ResponderPending { .. } => Err("unexpected responder outcome".to_owned()),
    }
}

/// The route report of a policy pairing, shared by both wires.
struct PairReport {
    provider: &'static str,
    endpoint: String,
    committed: bool,
    route_check: &'static str,
    routes_persisted: Vec<StoredRoute>,
    routes_reason: Option<&'static str>,
    skipped: Vec<SkippedHint>,
}

impl PairReport {
    fn from_result<D>(res: &PairPolicyResult<D>) -> Self {
        Self {
            provider: provider_name(res.route.provider),
            endpoint: res.route.addr.clone(),
            committed: res.committed,
            route_check: res.route_check.as_str(),
            routes_persisted: res.routes_persisted.clone(),
            routes_reason: res.routes_reason,
            skipped: res.skipped.clone(),
        }
    }

    fn merge_into(self, json: &mut serde_json::Value) {
        json["provider"] = serde_json::json!(self.provider);
        json["endpoint"] = serde_json::json!(self.endpoint);
        json["committed"] = serde_json::json!(self.committed);
        json["route_check"] = serde_json::json!(self.route_check);
        json["routes_persisted"] = routes_json_array(&self.routes_persisted);
        json["routes_reason"] = serde_json::json!(self.routes_reason);
        json["skipped"] = serde_json::json!(self.skipped);
    }
}

fn refresh_m2m_flags(self_m2m: &AtomicBool, m2m: &AtomicBool, roster: &Roster) {
    let enabled = self_m2m.load(Ordering::Acquire)
        || roster
            .trust_anchors()
            .any(|(_, a)| a.state == AnchorState::Active);
    m2m.store(enabled, Ordering::Release);
}

/// What a hosting endpoint advertises and the `RouteAnnouncer` built from it (created on first
/// use: pairing URI issuance, a route refresh, or an accepted session whose client opted in).
struct AnnouncerSlot {
    rt: Arc<Runtime>,
    identity: Arc<EndpointIdentity>,
    access: RosterAccess,
    transport_cfg: Arc<StdMutex<EndpointTransportConfig>>,
    served_endpoints: StdMutex<Vec<String>>,
    served_listeners: StdMutex<Vec<ServedListener>>,
    announcer: StdMutex<AnnouncerState>,
}

/// The announcer slot's life cycle. `Closed` is terminal: closing the endpoint ends the timer
/// and nothing (an accept that raced the close, a later refresh) can start another one.
enum AnnouncerState {
    Idle,
    Running(Arc<RouteAnnouncer>, JoinHandle<()>),
    Closed,
}

impl AnnouncerSlot {
    fn inputs(&self) -> AdvertiseInputs {
        let cfg = self
            .transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AdvertiseInputs {
            mode: cfg.advertise,
            served_endpoints: self
                .served_endpoints
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            listeners: self
                .served_listeners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            advertised_endpoints: cfg.advertised_endpoints.clone(),
        }
    }

    fn existing(&self) -> Option<Arc<RouteAnnouncer>> {
        match &*self
            .announcer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            AnnouncerState::Running(announcer, _) => Some(Arc::clone(announcer)),
            AnnouncerState::Idle | AnnouncerState::Closed => None,
        }
    }

    /// The live announcer, created on first use; fails once the endpoint is closed.
    fn announcer(&self) -> PyResult<Arc<RouteAnnouncer>> {
        let mut guard = self
            .announcer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*guard {
            AnnouncerState::Running(announcer, _) => return Ok(Arc::clone(announcer)),
            AnnouncerState::Closed => {
                return Err(PyRuntimeError::new_err("endpoint is closed"));
            }
            AnnouncerState::Idle => {}
        }
        let announcer = Arc::new(RouteAnnouncer::new(
            (*self.identity).clone(),
            self.access.clone(),
            self.inputs(),
            AddressSource::platform_default(),
        ));
        let _enter = self.rt.enter();
        let timer = announcer.spawn(Some(DEFAULT_ROUTE_REFRESH_INTERVAL));
        *guard = AnnouncerState::Running(Arc::clone(&announcer), timer);
        Ok(announcer)
    }

    /// Re-reads the advertising inputs into a live announcer and publishes them.
    fn inputs_changed(&self) {
        if let Some(announcer) = self.existing() {
            announcer.set_inputs(self.inputs());
            // A failed publish (for example an exhausted sequence) surfaces on the next issuance.
            let _ = announcer.publish(unix_ms());
        }
    }

    fn record_served(&self, endpoint: &str, listener: Option<ServedListener>) {
        self.served_endpoints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(endpoint.to_owned());
        if let Some(l) = listener {
            self.served_listeners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(l);
        }
        self.inputs_changed();
    }

    /// Ends the timer for good: the slot never creates another announcer.
    fn stop(&self) {
        let previous = std::mem::replace(
            &mut *self
                .announcer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            AnnouncerState::Closed,
        );
        if let AnnouncerState::Running(_, timer) = previous {
            timer.abort();
        }
    }
}

#[pyclass(frozen)]
struct Endpoint {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    router: Arc<InboundRouter>,
    v2_state: Arc<V2ResponderState>,
    transport_cfg: Arc<StdMutex<EndpointTransportConfig>>,
    self_m2m_enabled: Arc<AtomicBool>,
    m2m_enabled: Arc<AtomicBool>,
    groups: StdMutex<Vec<Weak<GroupPool>>>,
    /// URLs bound by `serve_relay`, so a group pool never displaces their identity mailbox.
    served_v1_relays: Arc<StdMutex<Vec<String>>>,
    /// Store-or-memory roster handle shared by the policy drivers, the route setter and the
    /// announcer. With a state directory it keeps its own in-memory copy, so a driver write never
    /// replaces the roster live sessions share; `sync_roster_blocking` reloads that one.
    access: RosterAccess,
    announce: Arc<AnnouncerSlot>,
}

impl Endpoint {
    fn new_session(&self, backend: SessionBackend, initiator: bool) -> Session {
        Session {
            initiator,
            rt: Arc::clone(&self.rt),
            store: self.store.clone(),
            store_lock: Arc::clone(&self.store_lock),
            identity: Arc::clone(&self.identity),
            roster: Arc::clone(&self.roster),
            session: Arc::new(backend),
        }
    }

    /// Wraps an accepted responder session and, when the client opted in with `route_seq`,
    /// registers it with the announcer so it receives the host's signed route sets.
    ///
    /// A registration that fails (the route set cannot be loaded or signed) or an endpoint that
    /// closed meanwhile fails the accept and closes the session, so no accepted session ever
    /// skips its initial route set. A sealed route set the peer cannot take (no padding bucket
    /// fits) stays the announcer's non-fatal outcome.
    fn accepted_session(&self, py: Python<'_>, backend: SessionBackend) -> PyResult<Session> {
        if let Some(peer_seq) = backend.peer_route_seq() {
            let sink = backend.route_sink();
            let rt = Arc::clone(&self.rt);
            let announce = Arc::clone(&self.announce);
            let registered = py.detach(move || {
                let announcer = announce.announcer()?;
                rt.block_on(announcer.on_session_established(&sink, Some(peer_seq), unix_ms()))
                    .map_err(py_err)
            });
            if let Err(err) = registered {
                let rt = Arc::clone(&self.rt);
                let closing = Arc::new(backend);
                py.detach(move || {
                    // The accept already failed; a close that cannot be sent changes nothing.
                    let _ = rt.block_on(closing.send_close(1011, "route registration failed"));
                });
                return Err(err);
            }
        }
        Ok(self.new_session(backend, false))
    }

    /// Day-2 connect through the runtime policy drivers.
    fn connect_policy(
        &self,
        py: Python<'_>,
        target_host_id: &str,
        args: ConnectArgs,
    ) -> PyResult<Session> {
        let cfg = self.snapshot_transport_cfg();
        let dialers = cfg
            .hint_dialers(args.relay_host.as_deref(), args.endpoint.as_deref())
            .map_err(py_err)?;
        let mut opts = ConnectOpts::new(dialers);
        opts.grant = args.grant;
        opts.recovery_uri = args.recovery_uri;
        opts.replace_routes = args.replace_routes;
        opts.policy = args.policy.unwrap_or(cfg.route_policy);
        opts.operator_endpoint = args.endpoint;
        opts.relay_auth_origins = cfg.relay_auth_origins.clone();
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let access = self.access.clone();
        let target = target_host_id.to_owned();
        let wire = args.wire;
        // A configured wake target applies to an explicit Wire v2 endpoint, with or without a
        // recovery URI: `wake_pre_wake` decides whether the wake hint or the first connect goes first.
        let wake = (wire == 2 && opts.operator_endpoint.is_some())
            .then(|| cfg.wake.clone())
            .flatten();

        let backend = py.detach(move || {
            sync_roster_blocking(store.as_ref(), &store_lock, &roster, &identity)?;
            let res = rt.block_on(async {
                let connect = || policy_connect(wire, &identity, &target, &access, opts.clone());
                match &wake {
                    Some(w) => connect_with_wake_policy(&w.to_dial_options(), connect)
                        .await
                        .map(|(backend, _)| backend),
                    None => connect().await,
                }
            });
            let synced = sync_roster_blocking(store.as_ref(), &store_lock, &roster, &identity);
            let backend = res.map_err(attempt_err)?;
            synced?;
            Ok::<_, PyErr>(backend)
        })?;
        Ok(self.new_session(backend, true))
    }

    /// Pairing from a scanned URI through the runtime policy drivers.
    fn pair_uri_impl(
        &self,
        py: Python<'_>,
        v2: bool,
        pairing_uri: &str,
        name: Option<&str>,
        kind: Option<&str>,
        options_json: Option<&str>,
    ) -> PyResult<String> {
        let opts_in: PairUriOptions = parse_options(options_json, "options_json")?;
        let uri = PairingUri::parse(pairing_uri).map_err(value_err)?;
        let cfg = self.snapshot_transport_cfg();
        let policy = parse_route_policy(opts_in.route_policy.as_deref(), cfg.route_policy)?;
        let endpoint = opts_in.endpoint.filter(|e| !e.is_empty());
        let dialers = cfg
            .hint_dialers(None, endpoint.as_deref())
            .map_err(py_err)?;
        // An explicit empty code is rejected before any dial; it never falls back to the URI code.
        let code = opts_in.code.unwrap_or_else(|| uri.code.clone());
        let mut opts = PairPolicyOptions::new(
            name.unwrap_or("py-device"),
            kind.unwrap_or("python"),
            code,
            dialers,
        );
        opts.uri = Some(uri);
        opts.operator_endpoint = endpoint;
        opts.persist = PersistOpts {
            operator_endpoint: None,
            policy,
            save_committed: opts_in.save_route.unwrap_or(false),
        };
        opts.relay_auth_origins = cfg.relay_auth_origins.clone();
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let access = self.access.clone();

        py.detach(move || {
            sync_roster_blocking(store.as_ref(), &store_lock, &roster, &identity)?;
            let res = rt.block_on(async {
                if v2 {
                    drive_v2_pair_initiator_with_policy(Arc::clone(&identity), &access, opts)
                        .await
                        .map(|r| {
                            let outcome = pair_outcome_json_v2(&r.drive.outcome);
                            (outcome, PairReport::from_result(&r))
                        })
                } else {
                    drive_pair_initiator_with_policy(Arc::clone(&identity), &access, opts)
                        .await
                        .map(|r| {
                            let outcome = pair_outcome_json_v1(&r.drive.outcome);
                            (outcome, PairReport::from_result(&r))
                        })
                }
            });
            let synced = sync_roster_blocking(store.as_ref(), &store_lock, &roster, &identity);
            let (outcome, report) = res.map_err(|e| py_err(attempt_message(&e)))?;
            synced?;
            let mut json = outcome.map_err(py_err)?;
            if v2 {
                json["wire_version"] = serde_json::json!(2);
            }
            report.merge_into(&mut json);
            Ok(json.to_string())
        })
    }

    fn group_store(&self) -> PyResult<Arc<StateStore>> {
        self.store
            .clone()
            .ok_or_else(|| PyRuntimeError::new_err("group operations require a state_dir"))
    }

    fn snapshot_transport_cfg(&self) -> EndpointTransportConfig {
        self.transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[pymethods]
impl Endpoint {
    #[new]
    #[pyo3(signature = (state_dir=None, host_id=None))]
    fn new(py: Python<'_>, state_dir: Option<&str>, host_id: Option<&str>) -> PyResult<Self> {
        let dir_owned = state_dir.filter(|s| !s.is_empty()).map(ToOwned::to_owned);
        let host_owned = host_id.map(ToOwned::to_owned);
        py.detach(move || {
            let rt = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(py_err)?,
            );
            let (store, identity, roster) = if let Some(dir) = dir_owned {
                let store = Arc::new(StateStore::open_or_create(dir).map_err(py_err)?);
                let identity = store
                    .load_or_generate_identity(host_owned.as_deref())
                    .map_err(py_err)?;
                let roster = store.load_roster().map_err(py_err)?;
                (Some(store), identity, roster)
            } else {
                let mut identity = EndpointIdentity::generate().map_err(py_err)?;
                if let Some(h) = host_owned.as_deref()
                    && !h.is_empty()
                {
                    identity = identity.try_with_host_id(h).map_err(py_err)?;
                }
                (None, identity, Roster::new())
            };

            let has_active_anchor = roster
                .trust_anchors()
                .any(|(_, a)| a.state == AnchorState::Active);
            if !is_valid_host_id(identity.host_id()) {
                return Err(PyValueError::new_err("invalid local host_id"));
            }
            let identity = Arc::new(identity);
            let roster = Arc::new(StdMutex::new(roster));
            let access_roster = if store.is_some() {
                Arc::new(StdMutex::new(lock_roster(&roster).clone()))
            } else {
                Arc::clone(&roster)
            };
            let access = RosterAccess::new(store.clone(), access_roster).with_local_signer(
                identity.host_id(),
                identity.signing_key().public_key().clone(),
            );
            let transport_cfg = Arc::new(StdMutex::new(EndpointTransportConfig::default()));
            let announce = Arc::new(AnnouncerSlot {
                rt: Arc::clone(&rt),
                identity: Arc::clone(&identity),
                access: access.clone(),
                transport_cfg: Arc::clone(&transport_cfg),
                served_endpoints: StdMutex::new(Vec::new()),
                served_listeners: StdMutex::new(Vec::new()),
                announcer: StdMutex::new(AnnouncerState::Idle),
            });
            Ok(Self {
                rt,
                store,
                store_lock: Arc::new(AsyncMutex::new(())),
                identity,
                roster,
                pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
                router: Arc::new(InboundRouter::new()),
                v2_state: Arc::new(V2ResponderState::default()),
                transport_cfg,
                self_m2m_enabled: Arc::new(AtomicBool::new(false)),
                m2m_enabled: Arc::new(AtomicBool::new(has_active_anchor)),
                groups: StdMutex::new(Vec::new()),
                served_v1_relays: Arc::new(StdMutex::new(Vec::new())),
                access,
                announce,
            })
        })
    }

    #[pyo3(signature = (name, min_wire_version, endpoints=None))]
    fn group_create(
        &self,
        py: Python<'_>,
        name: &str,
        min_wire_version: u8,
        endpoints: Option<Vec<String>>,
    ) -> PyResult<String> {
        let store = self.group_store()?;
        let identity = Arc::clone(&self.identity);
        let name = name.to_owned();
        let endpoints = endpoints.unwrap_or_default();
        py.detach(move || {
            let manifest = rt_group_create(&store, &identity, &name, min_wire_version, endpoints)
                .map_err(py_err)?;
            manifest_json(&manifest)
        })
    }

    #[pyo3(signature = (group_id, peer_id, caps=None, endpoints=None))]
    fn group_add_member(
        &self,
        py: Python<'_>,
        group_id: &str,
        peer_id: &str,
        caps: Option<Vec<String>>,
        endpoints: Option<Vec<String>>,
    ) -> PyResult<String> {
        let store = self.group_store()?;
        let identity = Arc::clone(&self.identity);
        let group_id = group_id.to_owned();
        let peer_id = peer_id.to_owned();
        let caps = caps.unwrap_or_default();
        let endpoints = endpoints.unwrap_or_default();
        py.detach(move || {
            let manifest =
                rt_group_add_member(&store, &identity, &group_id, &peer_id, caps, endpoints)
                    .map_err(py_err)?;
            manifest_json(&manifest)
        })
    }

    fn group_remove_member(
        &self,
        py: Python<'_>,
        group_id: &str,
        peer_id: &str,
    ) -> PyResult<String> {
        let store = self.group_store()?;
        let identity = Arc::clone(&self.identity);
        let group_id = group_id.to_owned();
        let peer_id = peer_id.to_owned();
        py.detach(move || {
            let manifest =
                rt_group_remove_member(&store, &identity, &group_id, &peer_id).map_err(py_err)?;
            manifest_json(&manifest)
        })
    }

    fn group_ingest_manifest(
        &self,
        py: Python<'_>,
        manifest_json: &str,
        sender_peer_id: &str,
    ) -> PyResult<String> {
        let store = self.group_store()?;
        let local_id = self.identity.device_id();
        let manifest_json = manifest_json.to_owned();
        let sender = sender_peer_id.to_owned();
        py.detach(move || {
            rt_group_ingest_manifest(&store, &local_id, &sender, &manifest_json)
                .map(|outcome| outcome.group_id)
                .map_err(py_err)
        })
    }

    #[pyo3(signature = (group_id, listen_addr=None, relay_listen=false))]
    fn group_open(
        &self,
        py: Python<'_>,
        group_id: &str,
        listen_addr: Option<&str>,
        relay_listen: bool,
    ) -> PyResult<Group> {
        let store = self.group_store()?;
        let identity = Arc::clone(&self.identity);
        let rt = Arc::clone(&self.rt);
        let transport_cfg = self.snapshot_transport_cfg();
        let relay_auth = transport_cfg.relay_auth.clone();
        let p2p_opts = transport_cfg.build_p2p_group_options();
        let served_v1_relays = self
            .served_v1_relays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let group_id = group_id.to_owned();
        let addr: Option<SocketAddr> = listen_addr
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse()
                    .map_err(|e| value_err(format!("invalid address: {e}")))
            })
            .transpose()?;
        py.detach(move || {
            let rt_for_pool = Arc::clone(&rt);
            rt_for_pool.block_on(async move {
                let mut dialers: Vec<Arc<dyn PathDialer>> = vec![
                    Arc::new(DirectDialer::new()),
                    Arc::new(LocalDialer::new()),
                    Arc::new(RelayDialer::new().with_auth(relay_auth.clone())),
                    Arc::new(OverlayDialer::new()),
                    Arc::new(BrokerDialer::new()),
                ];
                if let Some(opts) = p2p_opts {
                    dialers.push(Arc::new(
                        P2pDialer::bind_with_options(opts).await.map_err(py_err)?,
                    ));
                }
                let config = GroupPoolConfig::new(dialers)
                    .with_relay_auth(relay_auth)
                    .with_relay_listen(relay_listen)
                    .with_served_v1_relays(served_v1_relays);
                let pool = GroupPool::open((*store).clone(), identity, &group_id, config, None)
                    .map_err(py_err)?;
                let mut local_endpoint = None;
                if let Some(addr) = addr {
                    let listener = match DirectListener::bind(addr, None).await {
                        Ok(l) => l,
                        Err(e) => {
                            pool.close();
                            return Err(py_err(e));
                        }
                    };
                    local_endpoint = Some(listener.local_endpoint());
                    pool.serve(Box::new(listener));
                }
                Ok(Group {
                    rt,
                    pool: Arc::new(pool),
                    local_endpoint,
                })
            })
        })
        .inspect(|group| {
            let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            groups.retain(|w| w.upgrade().is_some_and(|p| !p.is_closed()));
            groups.push(Arc::downgrade(&group.pool));
        })
    }

    fn info_json(&self) -> String {
        serde_json::json!({
            "host_id": self.identity.host_id(),
            "device_id": self.identity.device_id(),
            "static_pub": b64url_encode(self.identity.static_key().public_bytes()),
            "signing_pub": self.identity.signing_key().public_key().to_b64url(),
            "signing_pub_hash": b64url_encode(&self.identity.signing_key().signing_pub_hash()),
            "relay_pub": b64url_encode(self.identity.signing_key().ed25519_public_bytes()),
        })
        .to_string()
    }

    fn configure_transports_json(
        &self,
        py: Python<'_>,
        transport_config_json: &str,
    ) -> PyResult<()> {
        let input: TransportConfigInput = serde_json::from_str(transport_config_json)
            .map_err(|e| json_err("transport_config_json", &e))?;
        let parsed = EndpointTransportConfig::from_input(input)?;
        *self
            .transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = parsed;
        // Publishing waits on the state directory lock; other Python threads keep running.
        let announce = Arc::clone(&self.announce);
        py.detach(move || announce.inputs_changed());
        Ok(())
    }

    #[pyo3(signature = (relay_host, role=None, target_pub_or_wildcard=None, ttl_secs=None))]
    fn mint_relay_ticket(
        &self,
        py: Python<'_>,
        relay_host: &str,
        role: Option<&str>,
        target_pub_or_wildcard: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> PyResult<String> {
        let role_enum = match role.map(str::trim) {
            None | Some("" | "any") => RelayAuthRole::Any,
            Some("register") => RelayAuthRole::Register,
            Some("dial") => RelayAuthRole::Dial,
            Some(other) => {
                return Err(PyValueError::new_err(format!(
                    "invalid relay ticket role '{other}'"
                )));
            }
        };
        let host_s = relay_host.to_owned();
        let target_s = target_pub_or_wildcard
            .filter(|s| !s.is_empty())
            .unwrap_or("*")
            .to_owned();
        let ttl = ttl_secs.unwrap_or(300);
        let identity = Arc::clone(&self.identity);
        py.detach(move || {
            let ticket = identity
                .mint_relay_ticket(&host_s, role_enum, &target_s, now_unix(), ttl)
                .map_err(value_err)?;
            let json = Zeroizing::new(canonical_json(&ticket).map_err(py_err)?);
            Ok((*json).clone())
        })
    }

    #[pyo3(signature = (listen_addr="127.0.0.1:0"))]
    fn serve_direct(&self, py: Python<'_>, listen_addr: &str) -> PyResult<String> {
        let addr: SocketAddr = listen_addr
            .parse()
            .map_err(|e| value_err(format!("invalid address: {e}")))?;
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let announce = Arc::clone(&self.announce);
        py.detach(move || {
            let listener = rt
                .block_on(DirectListener::bind(addr, None))
                .map_err(py_err)?;
            let ep = listener.local_endpoint();
            let served = ServedListener::from_listener(listener.tcp_listener()).map_err(py_err)?;
            router.spawn_listener(rt.handle(), Box::new(listener));
            announce.record_served(&ep, Some(served));
            Ok(ep)
        })
    }

    #[pyo3(signature = (relay_url, expected_host=None))]
    fn serve_relay(
        &self,
        py: Python<'_>,
        relay_url: &str,
        expected_host: Option<&str>,
    ) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let url = relay_url.to_owned();
        let exp = expected_host.map(ToOwned::to_owned);
        let key = self.identity.signing_key().ed25519_signing_key();
        let cfg = self.snapshot_transport_cfg();
        let served = Arc::clone(&self.served_v1_relays);
        let announce = Arc::clone(&self.announce);
        py.detach(move || {
            let listener = rt
                .block_on(RelayListener::bind_with_auth(
                    url.clone(),
                    exp,
                    key,
                    DEFAULT_WRITE_TIMEOUT,
                    cfg.relay_auth.clone(),
                ))
                .map_err(py_err)?;
            let ep = listener.local_endpoint();
            router.spawn_listener(rt.handle(), Box::new(listener));
            served
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(url);
            announce.record_served(&ep, None);
            Ok(ep)
        })
    }

    #[pyo3(signature = (relay_url, expected_host=None, peer_id=None))]
    fn serve_relay_v2(
        &self,
        py: Python<'_>,
        relay_url: &str,
        expected_host: Option<&str>,
        peer_id: Option<&str>,
    ) -> PyResult<String> {
        let cfg = self.snapshot_transport_cfg();
        {
            let store = self.store.clone();
            let store_lock = Arc::clone(&self.store_lock);
            let roster = Arc::clone(&self.roster);
            let identity = Arc::clone(&self.identity);
            py.detach(move || {
                sync_roster_blocking(store.as_ref(), &store_lock, &roster, &identity)
            })?;
        }
        let secrets: Vec<[u8; 32]> = {
            let roster = lock_roster(&self.roster);
            if let Some(pid) = peer_id.filter(|s| !s.is_empty()) {
                vec![lookup_v2_mailbox_secret_for_target(&roster, pid)?]
            } else {
                let list: Vec<[u8; 32]> = roster
                    .entries()
                    .filter(|(_, e)| e.state == PeerState::Active)
                    .filter_map(|(_, e)| e.v2_secrets.as_ref().map(|s| *s.mailbox_secret()))
                    .collect();
                if list.is_empty() {
                    return Err(PyRuntimeError::new_err(
                        "no active v2 peers with mailbox_secret in roster",
                    ));
                }
                list
            }
        };

        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let url_s = relay_url.to_owned();
        let exp_host = expected_host.map(ToOwned::to_owned);
        let announce = Arc::clone(&self.announce);
        py.detach(move || {
            let mut bound_listeners = Vec::with_capacity(secrets.len());
            for secret in secrets {
                let lcfg = RelayV2ListenerConfig {
                    expected_host: exp_host.clone(),
                    write_timeout: DEFAULT_WRITE_TIMEOUT,
                    allow_insecure_ws: false,
                    replay_cache: None,
                    unix_secs: None,
                    auth: cfg.relay_auth.clone(),
                };
                let listener = rt
                    .block_on(RelayV2Listener::bind_with_config(
                        url_s.clone(),
                        secret,
                        lcfg,
                    ))
                    .map_err(py_err)?;
                bound_listeners.push(listener);
            }
            let first_ep = bound_listeners.first().map(|l| l.local_endpoint());
            for listener in bound_listeners {
                announce.record_served(&listener.local_endpoint(), None);
                router.spawn_listener(rt.handle(), Box::new(listener));
            }
            Ok(first_ep.unwrap_or(url_s))
        })
    }

    #[pyo3(signature = (relay_mode=None))]
    fn serve_p2p(&self, py: Python<'_>, relay_mode: Option<&str>) -> PyResult<String> {
        let cfg = self.snapshot_transport_cfg();
        let opts = cfg
            .build_p2p_listener_options(relay_mode)
            .map_err(value_err)?;
        let seed = self.identity.derive_p2p_identity_seed();
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let announce = Arc::clone(&self.announce);
        py.detach(move || {
            let listener = rt
                .block_on(P2pListener::bind_with_options(opts, Some(seed)))
                .map_err(py_err)?;
            let ep = listener.local_endpoint();
            router.spawn_listener(rt.handle(), Box::new(listener));
            announce.record_served(&ep, None);
            Ok(ep)
        })
    }

    #[pyo3(signature = (kind="lan"))]
    fn issue_code(&self, py: Python<'_>, kind: &str) -> PyResult<String> {
        let pk = if kind.is_empty() {
            PairingCodeKind::Lan2Group
        } else {
            kind.parse::<PairingCodeKind>().map_err(value_err)?
        };
        let mgr = Arc::clone(&self.pair_mgr);
        py.detach(move || {
            let mut guard = mgr.lock().expect("pair_mgr mutex poisoned");
            guard.issue_code(pk, now_unix()).map_err(py_err)
        })
    }

    #[pyo3(signature = (endpoint, code, relay_host=None, name="py-device", kind="python"))]
    fn pair_initiate(
        &self,
        py: Python<'_>,
        endpoint: &str,
        code: &str,
        relay_host: Option<&str>,
        name: &str,
        kind: &str,
    ) -> PyResult<String> {
        let identity_sync = Arc::clone(&self.identity);
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let cfg = self.snapshot_transport_cfg();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let code_s = code.to_owned();
        let name_s = name.to_owned();
        let kind_s = kind.to_owned();

        py.detach(move || {
            sync_roster_blocking(store.as_ref(), &store_lock, &roster_arc, &identity)?;
            let roster_snapshot = lock_roster(&roster_arc).clone();
            let v2_secret = if is_v2_relay_endpoint(&ep_s) {
                Some(
                    lookup_v2_mailbox_secret_for_pair(&roster_snapshot, None, &ep_s, now_unix())
                        .map_err(py_err)?,
                )
            } else {
                None
            };
            let store_for_pair = store.clone();
            let outcome = rt.block_on(async move {
                let mut stream =
                    dial_endpoint_v2_with_options(&ep_s, rh_s.as_deref(), &cfg, v2_secret)
                        .await
                        .map_err(py_err)?;
                let pair_res = if let Some(ref s) = store_for_pair {
                    drive_pair_initiator_with_store(
                        stream.as_mut(),
                        &identity,
                        name_s,
                        kind_s,
                        code_s,
                        None,
                        s,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                    .map(|r| r.outcome)
                } else {
                    drive_v1_pair_initiator_with_roster_floors(
                        stream.as_mut(),
                        &identity,
                        name_s,
                        kind_s,
                        code_s,
                        &roster_snapshot,
                    )
                    .await
                }
                .map_err(py_err);
                let _ = stream.close().await;
                pair_res
            })?;

            match outcome {
                PairOutcome::InitiatorPending {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    pairing_sas,
                    host_pin_verified,
                } => {
                    update_roster_blocking(
                        store.as_ref(),
                        &store_lock,
                        &roster_arc,
                        &identity_sync,
                        |roster| {
                            if host_pin_verified {
                                roster
                                    .insert_pinned_host(
                                        host_id.clone(),
                                        host_id.clone(),
                                        host_static_pub,
                                        Some(host_signing_pub),
                                        host_rotation_seq,
                                        Vec::new(),
                                    )
                                    .map(|_| ())
                            } else {
                                roster
                                    .record_pending_host(
                                        host_id.clone(),
                                        host_id.clone(),
                                        host_static_pub,
                                        host_signing_pub,
                                        host_rotation_seq,
                                        pairing_sas.clone(),
                                        Vec::new(),
                                    )
                                    .map(|_| ())
                            }
                            .map_err(RuntimeError::from)
                        },
                    )?;
                    Ok(serde_json::json!({
                        "device_id": device_id,
                        "host_id": host_id,
                        "sas": pairing_sas,
                        "status": if host_pin_verified { "active" } else { "pending" },
                        "host_confirmed": host_pin_verified,
                    })
                    .to_string())
                }
                PairOutcome::Rejected { error } => Err(py_err(error)),
                PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                    Err(PyRuntimeError::new_err("unexpected responder outcome"))
                }
                PairOutcome::InitiatorEnrolled { .. } => {
                    Err(PyRuntimeError::new_err("unexpected m2m enrollment outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn pair_accept(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let pair_mgr = Arc::clone(&self.pair_mgr);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        let wait = Duration::from_millis(timeout_ms);

        py.detach(move || {
            sync_roster_blocking(store.as_ref(), &store_lock, &roster_arc, &identity)?;
            refresh_m2m_flags(&self_m2m, &m2m, &lock_roster(&roster_arc));
            let policy = if m2m.load(Ordering::Acquire) {
                EnrollmentPolicy::enabled_default()
            } else {
                EnrollmentPolicy::default()
            };
            let roster_in = Arc::clone(&roster_arc);
            let res = rt.block_on(async move {
                let (mut stream, guard) = match router.recv_pair(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => return Err(PyRuntimeError::new_err("timed out accepting pair")),
                };

                let path_kind = pairing_path_kind_for_provider(stream.provider_id());
                // The store-backed driver reads the stored roster: commit held revocations first.
                sync_roster_async(store.as_ref(), &store_lock, &roster_in, &identity)
                    .await
                    .map_err(py_err)?;
                let driven = if let Some(ref s) = store {
                    drive_pair_responder_with_store(
                        stream.as_mut(),
                        &identity,
                        &pair_mgr,
                        s,
                        &store_lock,
                        path_kind,
                        now_unix(),
                        policy,
                        Some(router.rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                } else {
                    drive_pair_responder_with_policy_and_store(
                        stream.as_mut(),
                        &identity,
                        &pair_mgr,
                        &roster_in,
                        None,
                        path_kind,
                        now_unix(),
                        policy,
                        Some(router.rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                };
                let synced =
                    sync_roster_async(store.as_ref(), &store_lock, &roster_in, &identity).await;
                let driven = driven.map_err(py_err)?;
                synced.map_err(py_err)?;
                Ok(driven)
            })?;

            match res.outcome {
                PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => Ok(serde_json::json!({
                    "device_id": device_id,
                    "sas": pairing_sas,
                    "name": name,
                    "kind": kind,
                })
                .to_string()),
                PairOutcome::ResponderEnrolled {
                    device_id,
                    token_nonce,
                    name,
                    kind,
                    ..
                } => Ok(serde_json::json!({
                    "device_id": device_id,
                    "status": "active",
                    "token_nonce": token_nonce,
                    "name": name,
                    "kind": kind,
                })
                .to_string()),
                PairOutcome::Rejected { error } => Err(py_err(error)),
                PairOutcome::InitiatorPending { .. } | PairOutcome::InitiatorEnrolled { .. } => {
                    Err(PyRuntimeError::new_err("unexpected initiator outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (peer_id, sas=None))]
    fn confirm_peer(&self, py: Python<'_>, peer_id: &str, sas: Option<&str>) -> PyResult<()> {
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let pid = peer_id.to_owned();
        let sas_owned = sas.map(ToOwned::to_owned);
        py.detach(move || {
            update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| {
                    roster
                        .confirm_peer(&pid, sas_owned.as_deref())
                        .map(|_| ())
                        .map_err(RuntimeError::from)
                },
            )
        })
    }

    #[pyo3(signature = (peer_id, caps, ttl_secs=3600))]
    fn mint_grant(
        &self,
        py: Python<'_>,
        peer_id: &str,
        caps: Vec<String>,
        ttl_secs: u64,
    ) -> PyResult<String> {
        let roster_arc = Arc::clone(&self.roster);
        let identity = Arc::clone(&self.identity);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let pid = peer_id.to_owned();
        py.detach(move || {
            let nonce = random_bytes::<16>().map_err(py_err)?;
            let grant = update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| {
                    let now = now_unix();
                    roster
                        .mint_grant(
                            &identity,
                            &pid,
                            caps,
                            now,
                            now.saturating_add(ttl_secs),
                            nonce,
                        )
                        .map_err(RuntimeError::from)
                },
            )?;
            serde_json::to_string(&grant).map_err(py_err)
        })
    }

    /// Marks `peer_id` revoked and clears its grants. `notify=None` follows the refusal policy
    /// (a notice unless `revoked_notice_ttl_secs` is `0`), `notify=False` revokes silently and
    /// clears an earlier notice, so the peer's next connect is no longer told why.
    #[pyo3(signature = (peer_id, notify=None))]
    fn revoke_peer(&self, py: Python<'_>, peer_id: &str, notify: Option<bool>) -> PyResult<()> {
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let pid = peer_id.to_owned();
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        py.detach(move || {
            update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| {
                    roster
                        .revoke_peer_at(&pid, notify.unwrap_or(true), now_unix())
                        .map_err(RuntimeError::from)
                },
            )?;
            refresh_m2m_flags(&self_m2m, &m2m, &lock_roster(&roster_arc));
            Ok(())
        })
    }

    /// Sets the host refusal policy and persists it with the roster. `pending` refuses
    /// unconfirmed peers with `4004` (default `True`); `revoked_notice_ttl_secs` is the lifetime
    /// of a notice recorded at revocation (default 30 days) and `0` records none. Notices
    /// already recorded keep their expiry.
    #[pyo3(signature = (pending=None, revoked_notice_ttl_secs=None))]
    fn set_refusal_policy(
        &self,
        py: Python<'_>,
        pending: Option<bool>,
        revoked_notice_ttl_secs: Option<u64>,
    ) -> PyResult<()> {
        let defaults = RefusalPolicy::default();
        let policy = RefusalPolicy {
            pending: pending.unwrap_or(defaults.pending),
            revoked_notice_ttl_secs: revoked_notice_ttl_secs
                .unwrap_or(defaults.revoked_notice_ttl_secs),
        };
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        py.detach(move || {
            update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| {
                    roster.set_refusal_policy(policy);
                    Ok(())
                },
            )
        })
    }

    /// Drops the refusal notice of `peer_id`, which stays revoked: its next connect is no
    /// longer told why. Raises `RuntimeError` for an unknown peer.
    fn clear_refusal_notice(&self, py: Python<'_>, peer_id: &str) -> PyResult<()> {
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let pid = peer_id.to_owned();
        py.detach(move || {
            update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| {
                    roster
                        .clear_refusal_notice(&pid)
                        .map_err(RuntimeError::from)
                },
            )
        })
    }

    /// The unconfirmed host claims left by unpinned pairing, oldest first, as a JSON array of
    /// `{"host_id", "device_id", "name", "static_pub", "signing_pub_hash", "rotation_seq",
    /// "min_wire_version", "pairing_sas"}`. `host_id` is the unauthenticated label a claim names
    /// and `device_id` the id derived from its static key in the handshake.
    fn pending_hosts(&self, py: Python<'_>) -> PyResult<String> {
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let roster = Arc::clone(&self.roster);
        let identity = Arc::clone(&self.identity);
        py.detach(move || {
            sync_roster_blocking(store.as_ref(), &store_lock, &roster, &identity)?;
            Ok(lock_roster(&roster).pending_hosts_json().to_string())
        })
    }

    /// Drops every unconfirmed host claim naming `host_id` and revokes nothing.
    fn remove_pending_host(&self, py: Python<'_>, host_id: &str) -> PyResult<()> {
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let host = host_id.to_owned();
        py.detach(move || {
            update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| {
                    roster
                        .remove_pending_host_claims(&host)
                        .map_err(RuntimeError::from)
                },
            )
        })
    }

    /// Revokes the keys of the unconfirmed host claims whose handshake-derived `device_id`
    /// equals `device_id`; a claimed `host_id` never matches.
    fn revoke_pending_host(&self, py: Python<'_>, device_id: &str) -> PyResult<()> {
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let device = device_id.to_owned();
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        py.detach(move || {
            update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| {
                    roster
                        .revoke_pending_host(&device)
                        .map_err(RuntimeError::from)
                },
            )?;
            // Revoking a claim's keys also revokes trust anchors sharing its signing key.
            refresh_m2m_flags(&self_m2m, &m2m, &lock_roster(&roster_arc));
            Ok(())
        })
    }

    fn add_trust_anchor(
        &self,
        py: Python<'_>,
        anchor_id: &str,
        signing_pub: &[u8],
    ) -> PyResult<()> {
        let identity = Arc::clone(&self.identity);
        let key = parse_hybrid_signing_pub(signing_pub, "signing_pub")?;
        let aid = anchor_id.to_owned();
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        let router = Arc::clone(&self.router);
        py.detach(move || {
            update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| {
                    roster
                        .add_trust_anchor(aid, key)
                        .map(|_| ())
                        .map_err(RuntimeError::from)
                },
            )?;
            refresh_m2m_flags(&self_m2m, &m2m, &lock_roster(&roster_arc));
            router.set_pair_enabled(true);
            Ok(())
        })
    }

    fn revoke_trust_anchor(&self, py: Python<'_>, anchor_id: &str) -> PyResult<()> {
        let identity = Arc::clone(&self.identity);
        let aid = anchor_id.to_owned();
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        py.detach(move || {
            update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster_arc,
                &identity,
                |roster| roster.revoke_trust_anchor(&aid).map_err(RuntimeError::from),
            )?;
            refresh_m2m_flags(&self_m2m, &m2m, &lock_roster(&roster_arc));
            Ok(())
        })
    }

    #[pyo3(signature = (target_host_id, subject=None, ttl_secs=900))]
    fn mint_enrollment_token(
        &self,
        py: Python<'_>,
        target_host_id: &str,
        subject: Option<&str>,
        ttl_secs: u64,
    ) -> PyResult<String> {
        let target_s = target_host_id.to_owned();
        let subject_s = subject.map(ToOwned::to_owned);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        let router = Arc::clone(&self.router);
        py.detach(move || {
            let nonce = random_bytes::<16>().map_err(py_err)?;
            let token = core_mint_enrollment_token(
                &identity,
                &target_s,
                subject_s.as_deref(),
                now_unix(),
                ttl_secs,
                nonce,
            )
            .map_err(value_err)?;
            if target_s == identity.host_id() {
                let roster = roster_arc.lock().expect("roster mutex poisoned");
                self_m2m.store(true, Ordering::Release);
                refresh_m2m_flags(&self_m2m, &m2m, &roster);
                router.set_pair_enabled(true);
            }
            serde_json::to_string(&token).map_err(py_err)
        })
    }

    #[pyo3(signature = (endpoint, host_id, host_static_pub, host_signing_pub, token_json, relay_host=None, host_rotation_seq=0, name="py-machine", kind="machine"))]
    #[allow(clippy::too_many_arguments)]
    fn enroll_initiate(
        &self,
        py: Python<'_>,
        endpoint: &str,
        host_id: &str,
        host_static_pub: &[u8],
        host_signing_pub: &[u8],
        token_json: &str,
        relay_host: Option<&str>,
        host_rotation_seq: u64,
        name: &str,
        kind: &str,
    ) -> PyResult<String> {
        let identity_sync = Arc::clone(&self.identity);
        let static_pub = as_32(host_static_pub, "host_static_pub")?;
        let signing_pin = parse_signing_pin(host_signing_pub, "host_signing_pub")?;
        let token: Grant =
            serde_json::from_str(token_json).map_err(|e| json_err("token_json", &e))?;
        let pinned_host = PinnedHost {
            host_id: Some(host_id.to_owned()),
            static_pub,
            signing_pin,
            rotation_seq: host_rotation_seq,
        };
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let name_s = name.to_owned();
        let kind_s = kind.to_owned();

        let cfg = self.snapshot_transport_cfg();
        py.detach(move || {
            // The store-backed driver reads the on-disk roster for its pin checks: persist the
            // revocation state only this endpoint's sessions hold first, so the driver sees it.
            sync_roster_blocking(store.as_ref(), &store_lock, &roster_arc, &identity_sync)?;
            let fallback_floor = pinned_pairing_floor(&lock_roster(&roster_arc), &pinned_host);
            let store_for_enroll = store.clone();
            let route_policy = cfg.route_policy;
            let (res, routes_persisted, route_warnings) = rt.block_on(async move {
                let mut stream = dial_endpoint_v2_with_options(&ep_s, rh_s.as_deref(), &cfg, None)
                    .await
                    .map_err(py_err)?;
                let pair_res = if let Some(ref s) = store_for_enroll {
                    // With a state directory the runtime pins the host and stores its routes in
                    // one roster transaction, under this endpoint's route policy.
                    let opts = M2mEnrollOptions {
                        operator_endpoint: Some(ep_s.clone()),
                        policy: route_policy,
                        handshake_timeout: DEFAULT_PRE_AUTH_TIMEOUT,
                    };
                    drive_m2m_enroll_initiator_with_routes(
                        stream.as_mut(),
                        &identity,
                        name_s,
                        kind_s,
                        token,
                        pinned_host,
                        s,
                        opts,
                    )
                    .await
                    .map(|r| {
                        let warnings: Vec<&'static str> =
                            r.route_warnings.iter().map(|w| w.as_str()).collect();
                        (r.drive, r.routes_persisted, warnings)
                    })
                } else {
                    // A memory-only endpoint has no store to hold routes: it pins the host in
                    // memory below and requests and stores no route, whatever the route policy.
                    drive_m2m_enroll_initiator_with_floor(
                        stream.as_mut(),
                        &identity,
                        name_s,
                        kind_s,
                        token,
                        pinned_host,
                        fallback_floor,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                    .map(|drive| (drive, Vec::new(), Vec::new()))
                }
                .map_err(py_err);
                let _ = stream.close().await;
                pair_res
            })?;

            match res.outcome {
                PairOutcome::InitiatorEnrolled {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    token_nonce,
                } => {
                    if store.is_some() {
                        sync_roster_blocking(
                            store.as_ref(),
                            &store_lock,
                            &roster_arc,
                            &identity_sync,
                        )?;
                    } else {
                        update_roster_blocking(
                            store.as_ref(),
                            &store_lock,
                            &roster_arc,
                            &identity_sync,
                            |roster| {
                                roster
                                    .insert_pinned_host(
                                        host_id.clone(),
                                        host_id.clone(),
                                        host_static_pub,
                                        Some(host_signing_pub),
                                        host_rotation_seq,
                                        Vec::new(),
                                    )
                                    .map(|_| ())
                                    .map_err(RuntimeError::from)
                            },
                        )?;
                    }
                    Ok(serde_json::json!({
                        "device_id": device_id,
                        "host_id": host_id,
                        "status": "active",
                        "host_rotation_seq": host_rotation_seq,
                        "token_nonce": token_nonce,
                        "routes_persisted": routes_json_array(&routes_persisted),
                        "route_warnings": route_warnings,
                        "routes_reason": store.is_none().then_some("no_state_dir"),
                    })
                    .to_string())
                }
                PairOutcome::Rejected { error } => Err(py_err(error)),
                PairOutcome::InitiatorPending { .. } => {
                    Err(PyRuntimeError::new_err("unexpected human pending outcome"))
                }
                PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                    Err(PyRuntimeError::new_err("unexpected responder outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (endpoint, code, relay_host=None, name=None, kind=None, pinned_host_json=None))]
    #[allow(clippy::too_many_arguments)]
    fn pair_v2_initiate(
        &self,
        py: Python<'_>,
        endpoint: &str,
        code: &str,
        relay_host: Option<&str>,
        name: Option<&str>,
        kind: Option<&str>,
        pinned_host_json: Option<&str>,
    ) -> PyResult<String> {
        let identity_sync = Arc::clone(&self.identity);
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let cfg = self.snapshot_transport_cfg();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let code_s = code.to_owned();
        let device_name = name.unwrap_or("py-device").to_owned();
        let device_kind = kind.unwrap_or("python").to_owned();
        let pinned_opt = pinned_host_json
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        py.detach(move || {
            sync_roster_blocking(store.as_ref(), &store_lock, &roster_arc, &identity)?;
            let roster_snapshot = lock_roster(&roster_arc).clone();

            let v2_pinned = match pinned_opt {
                Some(raw) => {
                    let pin_in: PyPinnedHostInput =
                        serde_json::from_str(&raw).map_err(|e| json_err("pinned_host_json", &e))?;
                    let static_pub =
                        b64url_decode_array::<32>(&pin_in.static_pub_b64).map_err(value_err)?;
                    let signing_pin = parse_signing_pin_b64(&pin_in.signing_pin_b64)
                        .map_err(PyValueError::new_err)?;
                    let pinned = PinnedHost {
                        host_id: pin_in.host_id,
                        static_pub,
                        signing_pin,
                        rotation_seq: pin_in.rotation_seq,
                    };
                    let base_floor = pinned_pairing_floor(&roster_snapshot, &pinned);
                    let floor = pin_in
                        .min_wire_version
                        .map_or(base_floor, |v| base_floor.max(v));
                    Some(V2PinnedHost::new(pinned, floor).map_err(value_err)?)
                }
                None => None,
            };

            let v2_secret = if is_v2_relay_endpoint(&ep_s) {
                Some(
                    lookup_v2_mailbox_secret_for_pair(
                        &roster_snapshot,
                        v2_pinned.as_ref().map(|p| &p.pinned),
                        &ep_s,
                        now_unix(),
                    )
                    .map_err(py_err)?,
                )
            } else {
                None
            };

            let store_for_pair = store.clone();
            let pair_res = rt.block_on(async move {
                let mut stream =
                    dial_endpoint_v2_with_options(&ep_s, rh_s.as_deref(), &cfg, v2_secret)
                        .await
                        .map_err(py_err)?;
                let res = if let Some(ref s) = store_for_pair {
                    drive_v2_pake_pair_initiator_with_store(
                        stream.as_mut(),
                        &identity,
                        device_name,
                        device_kind,
                        code_s,
                        v2_pinned,
                        "paired-host".to_owned(),
                        Vec::new(),
                        s,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                } else {
                    drive_v2_pake_pair_initiator_with_timeout(
                        stream.as_mut(),
                        &identity,
                        device_name,
                        device_kind,
                        code_s,
                        v2_pinned,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                }
                .map_err(py_err);
                let _ = stream.close().await;
                res
            })?;

            match pair_res.outcome {
                V2PairOutcome::InitiatorPending {
                    ref device_id,
                    ref host_id,
                    ref pairing_sas,
                    host_pin_verified,
                    ..
                } => {
                    let dev_id = device_id.clone();
                    let h_id = host_id.clone();
                    let sas = pairing_sas.clone();
                    if store.is_some() {
                        sync_roster_blocking(
                            store.as_ref(),
                            &store_lock,
                            &roster_arc,
                            &identity_sync,
                        )?;
                    } else {
                        let mut roster = roster_arc
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        roster
                            .apply_v2_pair_initiator_outcome(
                                &pair_res.outcome,
                                h_id.clone(),
                                Vec::new(),
                            )
                            .map_err(py_err)?;
                    }
                    Ok(serde_json::json!({
                        "device_id": dev_id,
                        "host_id": h_id,
                        "sas": sas,
                        "status": if host_pin_verified { "active" } else { "pending" },
                        "host_confirmed": host_pin_verified,
                        "wire_version": 2,
                    })
                    .to_string())
                }
                V2PairOutcome::Rejected { error } => Err(py_err(error)),
                V2PairOutcome::ResponderPending { .. } => {
                    Err(PyRuntimeError::new_err("unexpected responder outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn pair_v2_accept(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let pair_mgr = Arc::clone(&self.pair_mgr);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let v2_state = Arc::clone(&self.v2_state);
        let wait = Duration::from_millis(timeout_ms);

        py.detach(move || {
            let roster_in = Arc::clone(&roster_arc);
            let store_in = store.clone();
            let res = rt.block_on(async move {
                let (mut stream, guard) = match router.recv_v2_pair(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => return Err(PyRuntimeError::new_err("timed out accepting v2 pair")),
                };
                let path_kind = pairing_path_kind_for_provider(stream.provider_id());
                // The store-backed driver reads the stored roster: commit held revocations first.
                sync_roster_async(store_in.as_ref(), &store_lock, &roster_in, &identity)
                    .await
                    .map_err(py_err)?;
                let driven = if let Some(ref s) = store_in {
                    drive_v2_pake_pair_responder_with_store(
                        stream.as_mut(),
                        &identity,
                        &pair_mgr,
                        s,
                        &store_lock,
                        path_kind,
                        now_unix(),
                        &v2_state,
                        Some(router.v2_pair_rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                } else {
                    drive_v2_pake_pair_responder_with_options(
                        stream.as_mut(),
                        &identity,
                        &pair_mgr,
                        &roster_in,
                        path_kind,
                        now_unix(),
                        &v2_state,
                        Some(router.v2_pair_rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                };
                let synced =
                    sync_roster_async(store_in.as_ref(), &store_lock, &roster_in, &identity).await;
                let driven = driven.map_err(py_err)?;
                synced.map_err(py_err)?;
                Ok(driven)
            })?;

            match res.outcome {
                V2PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => Ok(serde_json::json!({
                    "device_id": device_id,
                    "sas": pairing_sas,
                    "name": name,
                    "kind": kind,
                    "wire_version": 2,
                })
                .to_string()),
                V2PairOutcome::Rejected { error } => Err(py_err(error)),
                V2PairOutcome::InitiatorPending { .. } => {
                    Err(PyRuntimeError::new_err("unexpected initiator outcome"))
                }
            }
        })
    }

    /// Wire v1 Day-2 connect. An empty or `None` `endpoint` dials the stored routes of the target.
    /// A non-empty one is normalized and dialed alone.
    #[pyo3(signature = (endpoint, target_host_id, grant_json=None, relay_host=None))]
    fn connect(
        &self,
        py: Python<'_>,
        endpoint: Option<&str>,
        target_host_id: &str,
        grant_json: Option<&str>,
        relay_host: Option<&str>,
    ) -> PyResult<Session> {
        let args = ConnectArgs {
            wire: 1,
            endpoint: endpoint.filter(|e| !e.is_empty()).map(ToOwned::to_owned),
            grant: parse_grant(grant_json)?,
            relay_host: relay_host.map(ToOwned::to_owned),
            ..ConnectArgs::default()
        };
        self.connect_policy(py, target_host_id, args)
    }

    /// Wire v2 Day-2 connect; `endpoint` as in [`Self::connect`]. A configured wake target with an
    /// explicit endpoint wakes the host first, then connects through the same policy path.
    #[pyo3(signature = (endpoint, target_host_id, grant_json=None, relay_host=None))]
    fn connect_v2(
        &self,
        py: Python<'_>,
        endpoint: Option<&str>,
        target_host_id: &str,
        grant_json: Option<&str>,
        relay_host: Option<&str>,
    ) -> PyResult<Session> {
        let endpoint = endpoint.filter(|e| !e.is_empty());
        let args = ConnectArgs {
            wire: 2,
            endpoint: endpoint.map(ToOwned::to_owned),
            grant: parse_grant(grant_json)?,
            relay_host: relay_host.map(ToOwned::to_owned),
            ..ConnectArgs::default()
        };
        self.connect_policy(py, target_host_id, args)
    }

    /// Day-2 connect with every option in one JSON object: `wire` (`1` or `2`),
    /// `grant` (object), `endpoint`, `recovery_uri`, `replace_routes`, `route_policy` and
    /// `relay_host` (the expected relay challenge host of an explicit relay endpoint).
    fn connect_with_options(
        &self,
        py: Python<'_>,
        target_host_id: &str,
        options_json: &str,
    ) -> PyResult<Session> {
        let opts: ConnectOptionsInput = parse_options(Some(options_json), "options_json")?;
        let wire = opts.wire.unwrap_or(1);
        if wire != 1 && wire != 2 {
            return Err(PyValueError::new_err("wire must be 1 or 2"));
        }
        let policy = parse_route_policy(
            opts.route_policy.as_deref(),
            self.snapshot_transport_cfg().route_policy,
        )?;
        let args = ConnectArgs {
            wire,
            endpoint: opts.endpoint.filter(|e| !e.is_empty()),
            grant: opts.grant,
            recovery_uri: opts.recovery_uri.filter(|u| !u.is_empty()),
            replace_routes: opts.replace_routes.unwrap_or(false),
            policy: Some(policy),
            relay_host: opts.relay_host,
        };
        self.connect_policy(py, target_host_id, args)
    }

    /// Issues a pairing URI from the current announced route set.
    /// Options `{"kind": "auto"|"lan"|"remote", "host_name": str, "sign_routes": bool}`.
    #[pyo3(signature = (options_json=None))]
    fn issue_pairing_uri(&self, py: Python<'_>, options_json: Option<&str>) -> PyResult<String> {
        let opts: IssueUriOptions = parse_options(options_json, "options_json")?;
        let requested_kind = match opts.kind.as_deref() {
            None | Some("") => None,
            Some(k) if k.eq_ignore_ascii_case("auto") => None,
            Some(k) => Some(k.parse::<PairingCodeKind>().map_err(value_err)?),
        };
        let sign_routes = opts
            .sign_routes
            .unwrap_or(self.snapshot_transport_cfg().sign_routes);
        let host_name = opts
            .host_name
            .unwrap_or_else(|| self.identity.host_id().to_owned());
        let announce = Arc::clone(&self.announce);
        let mgr = Arc::clone(&self.pair_mgr);
        py.detach(move || {
            let announcer = announce.announcer()?;
            // The announcer publishes before it takes the manager (runtime lock order); this
            // call must not hold the manager.
            let issued = announcer
                .issue_pairing_uri(
                    &mgr,
                    &host_name,
                    IssueOptions {
                        requested_kind,
                        sign_routes,
                    },
                    unix_ms(),
                )
                .map_err(rt_err)?;
            let dropped: Vec<serde_json::Value> = issued
                .dropped
                .iter()
                .map(|d| serde_json::json!({ "hint": d.redacted_hint(), "reason": d.reason }))
                .collect();
            Ok(serde_json::json!({
                "uri": issued.uri,
                "code_kind": code_kind_name(issued.code_kind),
                "dropped": dropped,
                "uri_len": issued.uri_len,
                "qr_version_m": issued.qr_version_m,
                "route_seq": issued.route_seq,
            })
            .to_string())
        })
    }

    /// Pairs over Wire v1 from a scanned pairing URI: races its hints (or only
    /// `options.endpoint`) and persists the routes `options.route_policy` allows.
    /// Options `{"route_policy", "save_route", "endpoint", "code"}`.
    #[pyo3(signature = (pairing_uri, name=None, kind=None, options_json=None))]
    fn pair_uri(
        &self,
        py: Python<'_>,
        pairing_uri: &str,
        name: Option<&str>,
        kind: Option<&str>,
        options_json: Option<&str>,
    ) -> PyResult<String> {
        self.pair_uri_impl(py, false, pairing_uri, name, kind, options_json)
    }

    /// As [`Self::pair_uri`] over Wire v2 PAKE, one rung at a time.
    #[pyo3(signature = (pairing_uri, name=None, kind=None, options_json=None))]
    fn pair_v2_uri(
        &self,
        py: Python<'_>,
        pairing_uri: &str,
        name: Option<&str>,
        kind: Option<&str>,
        options_json: Option<&str>,
    ) -> PyResult<String> {
        self.pair_uri_impl(py, true, pairing_uri, name, kind, options_json)
    }

    /// Replaces the peer's `operator` routes. `routes_json` is a JSON array of endpoint strings
    /// (at most six; an empty array clears them). Returns the peer's full route list.
    fn set_peer_routes(
        &self,
        py: Python<'_>,
        peer_id: &str,
        routes_json: &str,
    ) -> PyResult<String> {
        let raw: Vec<String> = serde_json::from_str(routes_json)
            .map_err(|e| json_err("routes_json (expected an array of strings)", &e))?;
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let roster = Arc::clone(&self.roster);
        let identity = Arc::clone(&self.identity);
        let peer = peer_id.to_owned();
        py.detach(move || {
            let routes = update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster,
                &identity,
                |roster| set_peer_routes(roster, &peer, &raw),
            )?;
            Ok(routes_json_array(&routes).to_string())
        })
    }

    /// `{"routes": [{"hint", "source"}], "route_meta": {"seq", "issued_at", "origin"} | null,
    /// "last_route_set": {"outcome", "seq"} | null}` for one peer.
    fn peer_routes(&self, py: Python<'_>, peer_id: &str) -> PyResult<String> {
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let roster = Arc::clone(&self.roster);
        let identity = Arc::clone(&self.identity);
        let access = self.access.clone();
        let peer = peer_id.to_owned();
        py.detach(move || {
            sync_roster_blocking(store.as_ref(), &store_lock, &roster, &identity)?;
            let last = access.last_route_set(&peer);
            let view = peer_routes(&lock_roster(&roster), &peer, last).map_err(py_err)?;
            Ok(serde_json::json!({
                "routes": routes_json_array(&view.routes),
                "route_meta": view.route_meta.map(|m| serde_json::json!({
                    "seq": m.seq,
                    "issued_at": m.issued_at,
                    "origin": m.origin,
                })),
                "last_route_set": view.last_route_set.map(|l| serde_json::json!({
                    "outcome": l.outcome,
                    "seq": l.seq,
                })),
            })
            .to_string())
        })
    }

    /// Removes the peer's routes of `source` (`"operator"` when omitted, `"signed"`,
    /// `"committed"` or `"all"`).
    #[pyo3(signature = (peer_id, source=None))]
    fn clear_peer_routes(
        &self,
        py: Python<'_>,
        peer_id: &str,
        source: Option<&str>,
    ) -> PyResult<()> {
        let source = match source {
            None | Some("" | "operator") => Some(RouteSource::Operator),
            Some("signed") => Some(RouteSource::Signed),
            Some("committed") => Some(RouteSource::Committed),
            Some("all") => None,
            Some(other) => {
                return Err(PyValueError::new_err(format!(
                    "invalid route source '{other}'"
                )));
            }
        };
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let roster = Arc::clone(&self.roster);
        let identity = Arc::clone(&self.identity);
        let peer = peer_id.to_owned();
        py.detach(move || {
            update_roster_blocking(store.as_ref(), &store_lock, &roster, &identity, |roster| {
                clear_peer_routes(roster, &peer, source)
            })
        })
    }

    /// Applies a fresh signed pairing URI to the matching paired host offline. Options
    /// `{"replace_routes", "route_policy"}`. Returns `{"peer_id", "applied", "reason",
    /// "route_seq"}`.
    #[pyo3(signature = (pairing_uri, options_json=None))]
    fn apply_route_uri(
        &self,
        py: Python<'_>,
        pairing_uri: &str,
        options_json: Option<&str>,
    ) -> PyResult<String> {
        let opts: ApplyRouteOptions = parse_options(options_json, "options_json")?;
        let policy = parse_route_policy(
            opts.route_policy.as_deref(),
            self.snapshot_transport_cfg().route_policy,
        )?;
        let uri = PairingUri::parse(pairing_uri).map_err(value_err)?;
        let apply = RouteApplyOpts {
            policy,
            replace_routes: opts.replace_routes.unwrap_or(false),
        };
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let roster = Arc::clone(&self.roster);
        let identity = Arc::clone(&self.identity);
        py.detach(move || {
            let res = update_roster_blocking(
                store.as_ref(),
                &store_lock,
                &roster,
                &identity,
                |roster| apply_signed_route_uri(roster, &uri, apply),
            )?;
            Ok(serde_json::json!({
                "peer_id": res.peer_id,
                "applied": res.applied,
                "reason": res.reason,
                "route_seq": res.route_meta.map(|m| m.seq),
            })
            .to_string())
        })
    }

    /// Re-scans the host's addresses and publishes the announced route set. `snapshot_json` is
    /// the complete current network snapshot `{"networks": [{"id", "iface", "if_index",
    /// "transports", "addrs"}]}`; `None` re-enumerates natively (or reuses the retained
    /// snapshot after one was passed). Returns `{"route_seq", "changed"}`.
    #[pyo3(signature = (snapshot_json=None))]
    fn refresh_routes(&self, py: Python<'_>, snapshot_json: Option<&str>) -> PyResult<String> {
        let snapshot = snapshot_json
            .filter(|s| !s.is_empty())
            .map(NetworkSnapshot::from_json)
            .transpose()
            .map_err(rt_value_err)?;
        let announce = Arc::clone(&self.announce);
        py.detach(move || {
            let out = announce
                .announcer()?
                .refresh(unix_ms(), snapshot)
                .map_err(py_err)?;
            Ok(serde_json::json!({
                "route_seq": out.route_seq(),
                "changed": out.changed,
            })
            .to_string())
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn accept_session(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Session> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let wait = Duration::from_millis(timeout_ms);

        let driver = py.detach(move || {
            rt.block_on(async move {
                let (stream, guard) = match router.recv_session(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => return Err(PyRuntimeError::new_err("timed out accepting session")),
                };
                sync_roster_async(store.as_ref(), &store_lock, &roster, &identity)
                    .await
                    .map_err(py_err)?;
                let accepted = SessionDriver::accept_locked(
                    stream,
                    &identity,
                    &roster,
                    now_unix(),
                    Some(router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                .map_err(py_err);
                let persisted =
                    sync_roster_async(store.as_ref(), &store_lock, &roster, &identity).await;
                let driver = accepted?;
                persisted.map_err(py_err)?;
                Ok(driver)
            })
        })?;

        self.accepted_session(py, SessionBackend::V1(Arc::new(driver.into_concurrent())))
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn accept_v2(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Session> {
        let identity_sync = Arc::clone(&self.identity);
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let v2_state = Arc::clone(&self.v2_state);
        let wait = Duration::from_millis(timeout_ms);

        let driver = py.detach(move || {
            let roster_in = Arc::clone(&roster);
            let store_in = store.clone();
            let store_lock_in = Arc::clone(&store_lock);
            let res = rt.block_on(async move {
                let (stream, guard) = match router.recv_v2_session(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => {
                        return Err(PyRuntimeError::new_err("timed out accepting v2 session"));
                    }
                };
                // The store-backed driver reads the stored roster: commit held revocations first.
                sync_roster_async(store_in.as_ref(), &store_lock_in, &roster_in, &identity)
                    .await
                    .map_err(py_err)?;
                if let Some(ref s) = store_in {
                    V2SessionDriver::accept_with_store(
                        stream,
                        &identity,
                        s,
                        &store_lock_in,
                        now_unix(),
                        &v2_state,
                        Some(router.v2_session_rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                } else {
                    V2SessionDriver::accept_locked(
                        stream,
                        &identity,
                        &roster_in,
                        now_unix(),
                        &v2_state,
                        Some(router.v2_session_rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                }
                .map_err(py_err)
            });
            let synced = sync_roster_blocking(store.as_ref(), &store_lock, &roster, &identity_sync);
            match res {
                Ok(drv) => {
                    synced?;
                    Ok(drv)
                }
                Err(err) => Err(err),
            }
        })?;

        self.accepted_session(py, SessionBackend::V2(Arc::new(driver.into_concurrent())))
    }

    fn close(&self, py: Python<'_>) {
        let router = Arc::clone(&self.router);
        let rt = Arc::clone(&self.rt);
        let pools: Vec<Arc<GroupPool>> = self
            .groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .filter_map(|w| w.upgrade())
            .collect();
        let announce = Arc::clone(&self.announce);
        py.detach(move || {
            announce.stop();
            router.close();
            let _guard = rt.enter();
            for pool in pools {
                pool.close();
            }
        });
    }
}

enum SessionBackend {
    V1(Arc<ConcurrentSession>),
    V2(Arc<ConcurrentV2Session>),
}

impl SessionBackend {
    fn peer_device_id(&self) -> Option<String> {
        match self {
            Self::V1(s) => s.peer_device_id(),
            Self::V2(s) => Some(s.peer_device_id().to_owned()),
        }
    }

    /// The `route_seq` the client sent in `SessionHello` (responder sessions).
    fn peer_route_seq(&self) -> Option<u64> {
        match self {
            Self::V1(s) => s.peer_route_seq(),
            Self::V2(s) => s.peer_route_seq(),
        }
    }

    fn route_sink(&self) -> Arc<dyn RouteSetSink> {
        match self {
            Self::V1(s) => Arc::clone(s) as Arc<dyn RouteSetSink>,
            Self::V2(s) => Arc::clone(s) as Arc<dyn RouteSetSink>,
        }
    }

    async fn send_data(&self, payload: &[u8]) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_data(payload).await,
            Self::V2(s) => s.send_data(payload).await,
        }
    }

    async fn next_event_locked_now(
        &self,
        roster: &StdMutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        match self {
            Self::V1(s) => s.next_event_locked_now(roster).await,
            Self::V2(s) => s.next_event_locked_now(roster).await,
        }
    }

    fn authorize_locked(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &StdMutex<Roster>,
    ) -> (Result<(), CoreError>, AuditEvent) {
        match self {
            Self::V1(s) => s.authorize_locked(requested_cap, now_unix, roster),
            Self::V2(s) => s.authorize_locked(requested_cap, now_unix, roster),
        }
    }

    async fn send_rekey(&self) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_rekey().await,
            Self::V2(s) => s.send_rekey().await,
        }
    }

    async fn send_close(&self, code: u16, reason: &str) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_close(code, reason).await,
            Self::V2(s) => s.send_close(code, reason).await,
        }
    }
}

#[pyclass(frozen)]
struct Session {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    session: Arc<SessionBackend>,
    /// `true` for a session this endpoint dialed: only an initiator maps a refusal close.
    initiator: bool,
}

#[pymethods]
impl Session {
    #[getter]
    fn peer_id(&self, py: Python<'_>) -> PyResult<String> {
        let sess = Arc::clone(&self.session);
        py.detach(move || {
            sess.peer_device_id()
                .ok_or_else(|| PyRuntimeError::new_err("session peer is not authenticated"))
        })
    }

    fn send_data(&self, py: Python<'_>, payload: &[u8]) -> PyResult<()> {
        let data = payload.to_vec();
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        py.detach(move || {
            rt.block_on(async move { sess.send_data(&data).await.map_err(|e| session_err(&e)) })
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn poll_event(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let identity = Arc::clone(&self.identity);
        let wait = Duration::from_millis(timeout_ms);
        let initiator = self.initiator;

        py.detach(move || {
            rt.block_on(async move {
                match timeout(wait, sess.next_event_locked_now(&roster)).await {
                    Ok(Ok(Some(ev))) => {
                        let json = match ev {
                            SessionEvent::AppData(data) => serde_json::json!({
                                "status": "event",
                                "event": "data",
                                "data_b64": b64url_encode(&data),
                            }),
                            SessionEvent::Rekeyed { direction } => serde_json::json!({
                                "status": "event",
                                "event": "rekeyed",
                                "direction": format!("{direction:?}"),
                            }),
                            SessionEvent::GrantUpdated(g) => serde_json::json!({
                                "status": "event",
                                "event": "grant_updated",
                                "grant": g,
                            }),
                            SessionEvent::RevocationUpdated { issuer, seq } => {
                                sync_roster_async(store.as_ref(), &store_lock, &roster, &identity)
                                    .await
                                    .map_err(py_err)?;
                                serde_json::json!({
                                    "status": "event",
                                    "event": "revocation_updated",
                                    "issuer": issuer,
                                    "seq": seq,
                                })
                            }
                            SessionEvent::PongReceived(cookie) => serde_json::json!({
                                "status": "event",
                                "event": "pong",
                                "cookie": cookie,
                            }),
                            SessionEvent::Audit(audit) => serde_json::json!({
                                "status": "event",
                                "event": "audit",
                                "audit": audit,
                            }),
                            ev @ (SessionEvent::GroupManifestReceived(_)
                            | SessionEvent::GroupRendezvousReceived(_)) => {
                                group_frame_json(store.as_ref(), &identity, &sess, ev).await?
                            }
                            SessionEvent::PathUpgrade(msg) => serde_json::json!({
                                "status": "event",
                                "event": "path_upgrade",
                                "upgrade": msg,
                            }),
                            SessionEvent::Closed { code, reason } => serde_json::json!({
                                "status": "event",
                                "event": "closed",
                                "code": code,
                                "reason": reason,
                                "refusal": initiator
                                    .then(|| RefusalReason::from_close_code(code))
                                    .flatten()
                                    .map(refusal_name),
                            }),
                        };
                        Ok(json.to_string())
                    }
                    Ok(Ok(None)) => Ok(serde_json::json!({ "status": "eof" }).to_string()),
                    Ok(Err(e)) => {
                        // A failed event can leave a revocation in memory only (a fork, say).
                        match sync_roster_async(store.as_ref(), &store_lock, &roster, &identity)
                            .await
                        {
                            Ok(()) => Err(session_err(&e)),
                            Err(pe) => Err(session_err_msg(&e, &format!("{e} ({pe})"))),
                        }
                    }
                    Err(_) => Ok(serde_json::json!({ "status": "would_block" }).to_string()),
                }
            })
        })
    }

    fn authorize(&self, py: Python<'_>, requested_cap: &str) -> bool {
        let sess = Arc::clone(&self.session);
        let roster = Arc::clone(&self.roster);
        let cap = requested_cap.to_owned();
        py.detach(move || sess.authorize_locked(&cap, now_unix(), &roster).0.is_ok())
    }

    fn rekey(&self, py: Python<'_>) -> PyResult<()> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        py.detach(move || {
            rt.block_on(async move { sess.send_rekey().await.map_err(|e| session_err(&e)) })
        })
    }

    #[pyo3(signature = (code=1000, reason="normal"))]
    fn close(&self, py: Python<'_>, code: u16, reason: &str) -> PyResult<()> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        let reason_s = reason.to_owned();
        py.detach(move || {
            rt.block_on(async move {
                sess.send_close(code, &reason_s)
                    .await
                    .map_err(|e| session_err(&e))
            })
        })
    }
}

/// Hands an ordinary-session `0x0A`/`0x0B` to the runtime when the endpoint has a state store
/// and reports the redacted outcome. Store-less endpoints surface the unverified event instead.
async fn group_frame_json(
    store: Option<&Arc<StateStore>>,
    identity: &EndpointIdentity,
    session: &SessionBackend,
    ev: SessionEvent,
) -> PyResult<serde_json::Value> {
    if let Some(store) = store {
        let peer = session
            .peer_device_id()
            .ok_or_else(|| PyRuntimeError::new_err("session peer is not authenticated"))?;
        let store = Arc::clone(store);
        let local_id = identity.device_id();
        let probe = ev.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            handle_session_group_frame(&store, &local_id, &peer, &probe)
        })
        .await
        .map_err(py_err)?;
        if let Some(outcome) = outcome {
            return Ok(group_frame_outcome_json(&outcome));
        }
    }
    match &ev {
        SessionEvent::GroupManifestReceived(manifest) => Ok(serde_json::json!({
            "status": "event",
            "event": "group_manifest_unverified",
            "group_id": manifest.group_id,
            "seq": manifest.seq,
            "manifest_json": manifest_json(manifest)?,
        })),
        SessionEvent::GroupRendezvousReceived(frame) => Ok(serde_json::json!({
            "status": "event",
            "event": "group_rendezvous_unverified",
            "group_id": frame.group_id,
            "seq": frame.seq,
        })),
        _ => Err(PyRuntimeError::new_err("not a group frame event")),
    }
}

fn group_frame_outcome_json(outcome: &GroupFrameOutcome) -> serde_json::Value {
    let kind = match outcome.kind {
        GroupFrameKind::Manifest => "manifest",
        GroupFrameKind::Rendezvous => "rendezvous",
    };
    let verdict = if outcome.ingested {
        "ingested"
    } else {
        "rejected"
    };
    let mut val = serde_json::json!({
        "status": "event",
        "event": format!("group_{kind}_{verdict}"),
        "group_id": outcome.group_id,
        "seq": outcome.seq,
    });
    if let Some(error) = &outcome.error {
        val["error"] = serde_json::Value::String(error.clone());
    }
    val
}

fn manifest_json(manifest: &GroupManifest) -> PyResult<String> {
    let bytes = manifest.to_wire_bytes().map_err(py_err)?;
    String::from_utf8(bytes).map_err(py_err)
}

fn report_json(report: &BroadcastReport) -> PyResult<String> {
    serde_json::to_string(report).map_err(py_err)
}

fn group_event_json(event: &GroupEvent) -> String {
    match event {
        GroupEvent::AppData {
            sender_device_id,
            payload,
        } => serde_json::json!({
            "event": "app_data",
            "sender_device_id": sender_device_id,
            "payload_b64": b64url_encode(payload),
        }),
        GroupEvent::ManifestUpdated { seq } => serde_json::json!({
            "event": "manifest_updated",
            "seq": seq,
        }),
        GroupEvent::MemberJoined { device_id } => serde_json::json!({
            "event": "member_joined",
            "device_id": device_id,
        }),
        GroupEvent::MemberRevoked { device_id } => serde_json::json!({
            "event": "member_revoked",
            "device_id": device_id,
        }),
        GroupEvent::Audit(audit) => serde_json::json!({
            "event": "audit",
            "audit": audit,
        }),
    }
    .to_string()
}

#[pyclass(frozen)]
struct Group {
    rt: Arc<Runtime>,
    pool: Arc<GroupPool>,
    local_endpoint: Option<String>,
}

impl Group {
    fn ensure_open(&self) -> PyResult<()> {
        if self.pool.is_closed() {
            return Err(PyRuntimeError::new_err("group is closed"));
        }
        Ok(())
    }
}

#[pymethods]
impl Group {
    #[getter]
    fn group_id(&self) -> String {
        self.pool.group_id().to_owned()
    }

    #[getter]
    fn local_endpoint(&self) -> Option<String> {
        self.local_endpoint.clone()
    }

    #[pyo3(signature = (data, required_cap=None))]
    fn broadcast(
        &self,
        py: Python<'_>,
        data: &[u8],
        required_cap: Option<&str>,
    ) -> PyResult<String> {
        self.ensure_open()?;
        let payload = data.to_vec();
        let cap = required_cap
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        let rt = Arc::clone(&self.rt);
        let pool = Arc::clone(&self.pool);
        py.detach(move || {
            let report = rt
                .block_on(async move { pool.broadcast(cap.as_deref(), &payload).await })
                .map_err(py_err)?;
            report_json(&report)
        })
    }

    fn sync(&self, py: Python<'_>) -> PyResult<String> {
        self.ensure_open()?;
        let rt = Arc::clone(&self.rt);
        let pool = self.pool.clone();
        py.detach(move || {
            let report = rt
                .block_on(async move { pool.sync().await })
                .map_err(py_err)?;
            report_json(&report)
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn poll_event(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Option<String>> {
        self.ensure_open()?;
        let rt = Arc::clone(&self.rt);
        let pool = self.pool.clone();
        let wait = Duration::from_millis(timeout_ms);
        py.detach(move || {
            Ok(rt
                .block_on(async move { pool.poll_event(wait).await })
                .map(|ev| group_event_json(&ev)))
        })
    }

    fn authorize_peer(&self, py: Python<'_>, peer_id: &str, cap: &str) -> PyResult<bool> {
        self.ensure_open()?;
        let pool = self.pool.clone();
        let peer_id = peer_id.to_owned();
        let cap = cap.to_owned();
        py.detach(move || {
            pool.authorize_peer(&peer_id, &cap)
                .map(|()| true)
                .map_err(py_err)
        })
    }

    fn close(&self, py: Python<'_>) {
        let pool = self.pool.clone();
        let rt = Arc::clone(&self.rt);
        py.detach(move || {
            let _guard = rt.enter();
            pool.close();
        });
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (_exc_type=None, _exc_value=None, _traceback=None))]
    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Option<Py<PyAny>>,
        _exc_value: Option<Py<PyAny>>,
        _traceback: Option<Py<PyAny>>,
    ) {
        self.close(py);
    }
}

#[pymodule]
fn _tendril(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(device_id, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_host, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_device, m)?)?;
    m.add_function(wrap_pyfunction!(pairing_sas, m)?)?;
    m.add_function(wrap_pyfunction!(compute_code_mac, m)?)?;
    m.add_function(wrap_pyfunction!(verify_rotation_chain_json, m)?)?;
    m.add_function(wrap_pyfunction!(verify_grant_json, m)?)?;
    m.add_function(wrap_pyfunction!(route_set::verify_route_set, m)?)?;
    m.add_function(wrap_pyfunction!(verify_wake_tag, m)?)?;
    m.add_class::<Endpoint>()?;
    m.add_class::<Session>()?;
    m.add_class::<Group>()?;
    m.add("RefusedError", m.py().get_type::<RefusedError>())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASEPOINT_ID: &str = "5866666666666666666666666666666666666666666666666666666666666666";

    fn net_config(json: &str) -> EndpointTransportConfig {
        let input: TransportConfigInput = serde_json::from_str(json).expect("json");
        EndpointTransportConfig::from_input(input)
            .map_err(|_| "config rejected")
            .expect("config")
    }

    #[test]
    fn p2p_net_keys_reach_every_option_set() {
        let only = tendril_runtime::P2pBindAddrs::Only {
            v4: Some("127.0.0.1:0".parse().unwrap()),
            v6: None,
        };
        let defaults = net_config("{}");
        let opts = defaults.build_p2p_listener_options(None).unwrap();
        assert!(opts.port_mapping);
        assert_eq!(
            opts.bind_addrs,
            tendril_runtime::P2pBindAddrs::AllInterfaces
        );

        let cfg = net_config(
            r#"{"p2p_relay_mode":"disabled","p2p_port_mapping":false,
                "p2p_bind_addrs":["127.0.0.1:0"]}"#,
        );
        let endpoint = format!("iroh://{BASEPOINT_ID}");
        let sets = [
            ("listener", cfg.build_p2p_listener_options(None).unwrap()),
            (
                "dialer",
                cfg.build_p2p_dialer_options(&endpoint, None).unwrap(),
            ),
            ("group", cfg.build_p2p_group_options().unwrap()),
            (
                "hint operator",
                cfg.hint_dialers(None, Some(&endpoint))
                    .unwrap()
                    .operator_p2p_options(&endpoint)
                    .unwrap(),
            ),
        ];
        for (name, opts) in sets {
            assert!(!opts.port_mapping, "{name}");
            assert_eq!(opts.bind_addrs, only, "{name}");
        }
        let hints = cfg.hint_dialers(None, None).unwrap();
        assert!(!hints.config().p2p_port_mapping);
        assert_eq!(hints.config().p2p_bind_addrs, only);
    }

    #[test]
    fn n0_alias_selects_the_public_relays() {
        let cfg = net_config(r#"{"p2p_relay_mode":"n0"}"#);
        let opts = cfg.build_p2p_listener_options(None).unwrap();
        assert!(matches!(opts.relay_mode, P2pRelayMode::N0Public));
    }
}
