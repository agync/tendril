//! Node.js N-API native addon over `tendril-core` and `tendril-runtime`.

pub mod route_set;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::Deserialize;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, b64url_decode,
    b64url_decode_array, b64url_encode, compute_code_mac as core_compute_code_mac,
    device_id as core_device_id, fingerprint_device as core_fingerprint_device,
    fingerprint_host as core_fingerprint_host, pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::error::{CoreError, RefusalReason};
use tendril_core::grants::{Grant, RevocationList, authorize_grant, canonical_json};
use tendril_core::group::GroupManifest;
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, is_valid_host_id, verify_rotation_chain,
};
use tendril_core::pairing::{
    EnrollmentPolicy, IssueOptions, PairAction, PairOutcome, PairingCodeKind, PairingConfig,
    PairingInitiator, PairingManager, PairingUri, PersistOpts, PinnedHost, RoutePolicy,
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
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_SAFE_INTEGER_F64: f64 = 9_007_199_254_740_991.0;

fn f64_to_u64(v: f64, name: &str) -> Result<u64> {
    if !(0.0..=MAX_SAFE_INTEGER_F64).contains(&v) || v.fract() != 0.0 {
        return Err(Error::new(
            Status::InvalidArg,
            format!("{name} must be a non-negative safe integer"),
        ));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(v as u64)
}

fn f64_to_timeout_ms(v: Option<f64>, default_ms: u64) -> Result<u64> {
    let Some(raw) = v else {
        return Ok(default_ms);
    };
    let ms = f64_to_u64(raw, "timeout_ms")?;
    if ms > u64::from(u32::MAX) {
        return Err(Error::new(
            Status::InvalidArg,
            "timeout_ms exceeds u32 maximum",
        ));
    }
    Ok(ms)
}

fn f64_to_u16(v: Option<f64>, default_val: u16, name: &str) -> Result<u16> {
    let Some(raw) = v else {
        return Ok(default_val);
    };
    let n = f64_to_u64(raw, name)?;
    u16::try_from(n)
        .map_err(|_| Error::new(Status::InvalidArg, format!("{name} must be in 0..=65535")))
}

fn f64_to_u8(v: f64, name: &str) -> Result<u8> {
    let n = f64_to_u64(v, name)?;
    u8::try_from(n)
        .map_err(|_| Error::new(Status::InvalidArg, format!("{name} must be in 0..=255")))
}

fn u64_to_f64(v: u64) -> Result<f64> {
    if v > 9_007_199_254_740_991 {
        return Err(Error::new(
            Status::GenericFailure,
            "sequence exceeds JavaScript safe integer range",
        ));
    }
    #[allow(clippy::cast_precision_loss)]
    Ok(v as f64)
}

fn lock_roster(roster: &StdMutex<Roster>) -> std::sync::MutexGuard<'_, Roster> {
    roster
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Applies `f` to the latest on-disk roster and publishes the committed result to memory.
///
/// Callers must hold `store_lock`. Lock order (`tendril_runtime::announce`): store lock, roster
/// file lock, pairing manager, in-memory roster mutex. The mutex is therefore taken only inside
/// the file-lock transaction, for the pure callback, and again to publish after it; it is never
/// held while waiting for the file lock or across an `.await`.
fn commit_roster<T>(
    store: &StateStore,
    roster: &StdMutex<Roster>,
    identity: &EndpointIdentity,
    f: impl FnOnce(&mut Roster, &Roster) -> std::result::Result<T, RuntimeError>,
) -> std::result::Result<T, RuntimeError> {
    let (out, disk, _) = store.update_roster_with_state(|disk| f(disk, &lock_roster(roster)))?;
    publish_roster(&mut lock_roster(roster), disk, identity);
    Ok(out)
}

fn reload_roster(
    store: &StateStore,
    roster: &StdMutex<Roster>,
    identity: &EndpointIdentity,
) -> std::result::Result<(), RuntimeError> {
    let disk = store.load_roster()?;
    publish_roster(&mut lock_roster(roster), disk, identity);
    Ok(())
}

/// Replaces the in-memory roster with the committed disk roster while keeping any revocation
/// or CRL a live session learned in memory but has not committed yet.
fn publish_roster(mem: &mut Roster, disk: Roster, identity: &EndpointIdentity) {
    let mut next = disk;
    merge_session_state(&mut next, mem, identity);
    *mem = next;
}

/// Persists the revocations and CRLs live sessions learned in memory, under the roster file
/// lock. Nothing is written when the store already holds them: no `roster.json` is created and
/// an existing one keeps its mtime.
fn commit_session_state(
    store: &StateStore,
    roster: &StdMutex<Roster>,
    identity: &EndpointIdentity,
) -> std::result::Result<(), RuntimeError> {
    let (_, disk, _) = store.update_roster_if_changed(|disk| {
        merge_session_state(disk, &lock_roster(roster), identity);
        Ok(())
    })?;
    publish_roster(&mut lock_roster(roster), disk, identity);
    Ok(())
}

/// Folds revocations and CRLs learned in memory by a live session into the on-disk roster
/// without overwriting any other committed state.
fn merge_session_state(disk: &mut Roster, mem: &Roster, identity: &EndpointIdentity) {
    let newly_revoked: Vec<String> = mem
        .entries()
        .filter(|(id, entry)| {
            entry.state == PeerState::Revoked
                && disk
                    .get(id)
                    .is_some_and(|prev| prev.state != PeerState::Revoked)
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in &newly_revoked {
        let _ = disk.revoke_peer(id);
    }
    let mut issuers = vec![identity.host_id().to_owned()];
    issuers.extend(mem.entries().map(|(id, _)| id.clone()));
    issuers.extend(mem.trust_anchors().map(|(id, _)| id.clone()));
    for issuer in issuers {
        let Some(crl) = mem.crl(&issuer).cloned() else {
            continue;
        };
        let issuer_pub = if issuer == identity.host_id() {
            Some(identity.signing_key().public_key().clone())
        } else {
            disk.lookup_active_signing_key(&issuer)
                .or_else(|| disk.lookup_active_anchor_key(&issuer))
                .or_else(|| {
                    disk.get(&issuer)
                        .filter(|e| e.state != PeerState::Pending)
                        .and_then(|e| e.signing_pub.clone())
                })
        };
        if let Some(pk) = issuer_pub {
            let _ = disk.ingest_crl(crl, &issuer, &pk);
        }
    }
}

/// Mutates the roster under the `store_lock` -> roster lock order from a Tokio worker without
/// blocking the runtime thread on file locks.
async fn update_roster_async<T, F>(
    store: Option<&Arc<StateStore>>,
    store_lock: &AsyncMutex<()>,
    roster: &Arc<StdMutex<Roster>>,
    identity: &Arc<EndpointIdentity>,
    f: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut Roster) -> std::result::Result<T, RuntimeError> + Send + 'static,
{
    if let Some(store) = store {
        let _guard = store_lock.lock().await;
        let store = Arc::clone(store);
        let roster = Arc::clone(roster);
        let identity = Arc::clone(identity);
        tokio::task::spawn_blocking(move || {
            commit_roster(&store, &roster, &identity, |disk, _| f(disk))
        })
        .await
        .map_err(to_generic_err)?
        .map_err(to_generic_err)
    } else {
        let mut guard = lock_roster(roster);
        f(&mut guard).map_err(to_generic_err)
    }
}

async fn sync_roster_async(
    store: Option<&Arc<StateStore>>,
    store_lock: &AsyncMutex<()>,
    roster: &Arc<StdMutex<Roster>>,
    identity: &Arc<EndpointIdentity>,
) -> Result<()> {
    if let Some(store) = store {
        let _guard = store_lock.lock().await;
        let store = Arc::clone(store);
        let roster = Arc::clone(roster);
        let identity = Arc::clone(identity);
        tokio::task::spawn_blocking(move || reload_roster(&store, &roster, &identity))
            .await
            .map_err(to_generic_err)?
            .map_err(to_generic_err)?;
    }
    Ok(())
}

async fn commit_session_async(
    store: Option<&Arc<StateStore>>,
    store_lock: &AsyncMutex<()>,
    roster: &Arc<StdMutex<Roster>>,
    identity: &Arc<EndpointIdentity>,
) -> Result<()> {
    if let Some(store) = store {
        let _guard = store_lock.lock().await;
        let store = Arc::clone(store);
        let roster = Arc::clone(roster);
        let identity = Arc::clone(identity);
        tokio::task::spawn_blocking(move || commit_session_state(&store, &roster, &identity))
            .await
            .map_err(to_generic_err)?
            .map_err(to_generic_err)?;
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn as_32(bytes: &[u8], name: &str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        Error::new(
            Status::InvalidArg,
            format!("{name} must be exactly 32 bytes"),
        )
    })
}

fn parse_hybrid_signing_pub(bytes: &[u8], name: &str) -> Result<HybridSigningPublicKey> {
    if bytes.len() != HYBRID_SIGNING_PUB_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            format!("{name} must be exactly {HYBRID_SIGNING_PUB_LEN} bytes"),
        ));
    }
    HybridSigningPublicKey::from_bytes(bytes)
        .map_err(|e| to_invalid_arg(format!("invalid {name}: {e}")))
}

fn parse_signing_pin(bytes: &[u8], name: &str) -> Result<SigningKeyPin> {
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        parse_hybrid_signing_pub(bytes, name).map(SigningKeyPin::Full)
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let mut hash = [0u8; HYBRID_SIGNING_HASH_LEN];
        hash.copy_from_slice(bytes);
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(Error::new(
            Status::InvalidArg,
            format!("{name} must be {HYBRID_SIGNING_PUB_LEN} or {HYBRID_SIGNING_HASH_LEN} bytes"),
        ))
    }
}

fn to_generic_err(err: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, redact_text(&err.to_string()))
}

fn to_invalid_arg(err: impl std::fmt::Display) -> Error {
    Error::new(Status::InvalidArg, redact_text(&err.to_string()))
}

/// Name of a refusal reason in the closed event: `revoked`, `pending` or `other`.
const fn refusal_name(reason: RefusalReason) -> &'static str {
    match reason {
        RefusalReason::Revoked => "revoked",
        RefusalReason::Pending => "pending",
        RefusalReason::Other(_) => "other",
    }
}

/// The failure of a session call or connect.
///
/// An async N-API method can reject only with a napi status code, so a refusal carries its
/// stable machine code and close code in a `[tendril:CODE:CLOSE]` prefix of the message. The
/// package entry point (`index.js`) moves them to the `code` and `closeCode` properties of the
/// error and strips the prefix.
fn session_err(err: &RuntimeError, msg: String) -> Error {
    match err.refusal() {
        Some(reason) => Error::new(
            Status::GenericFailure,
            format!(
                "[tendril:{}:{}] {}",
                reason.code(),
                reason.close_code(),
                redact_text(&msg)
            ),
        ),
        None => to_generic_err(msg),
    }
}

fn rt_err(err: RuntimeError) -> Error {
    Error::new(Status::GenericFailure, redact_error(&err))
}

fn rt_invalid_arg(err: RuntimeError) -> Error {
    Error::new(Status::InvalidArg, redact_error(&err))
}

/// An `InvalidArg` error naming the JSON error's category and position, never its input.
fn json_err(what: &str, err: &serde_json::Error) -> Error {
    Error::new(
        Status::InvalidArg,
        format!("invalid {what}: {}", redact_json_error(err)),
    )
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct TransportConfigInput {
    #[serde(alias = "relayAuthSecret")]
    relay_auth_secret: Option<String>,
    #[zeroize(skip)]
    #[serde(alias = "relayTicket")]
    relay_ticket: Option<RelayTicket>,
    #[zeroize(skip)]
    #[serde(alias = "p2pRelayMode")]
    p2p_relay_mode: Option<String>,
    #[zeroize(skip)]
    #[serde(alias = "p2pRelayUrls")]
    p2p_relay_urls: Option<Vec<String>>,
    #[zeroize(skip)]
    #[serde(alias = "p2pPkarr")]
    p2p_pkarr: Option<bool>,
    #[zeroize(skip)]
    #[serde(alias = "p2pAdvertiseDirectAddrs")]
    p2p_advertise_direct_addrs: Option<bool>,
    #[zeroize(skip)]
    #[serde(alias = "p2pAllowPrivateAddrs")]
    p2p_allow_private_addrs: Option<bool>,
    #[zeroize(skip)]
    #[serde(alias = "p2pPortMapping")]
    p2p_port_mapping: Option<bool>,
    #[zeroize(skip)]
    #[serde(alias = "p2pBindAddrs")]
    p2p_bind_addrs: Option<Vec<String>>,
    #[serde(alias = "p2pRelayAuthToken")]
    p2p_relay_auth_token: Option<String>,
    #[serde(alias = "p2pApiSecret")]
    p2p_api_secret: Option<String>,
    #[zeroize(skip)]
    #[serde(alias = "wakeUrl")]
    wake_url: Option<String>,
    #[zeroize(skip)]
    #[serde(alias = "wakeAdapter")]
    wake_adapter: Option<WakeAdapterKind>,
    #[serde(alias = "wakeSecretB64")]
    wake_secret_b64: Option<String>,
    #[serde(alias = "wakeAuthToken")]
    wake_auth_token: Option<String>,
    #[zeroize(skip)]
    #[serde(alias = "wakePreWake")]
    wake_pre_wake: Option<bool>,
    #[zeroize(skip)]
    #[serde(alias = "wakeRetryDelayMs")]
    wake_retry_delay_ms: Option<u64>,
    #[zeroize(skip)]
    #[serde(alias = "wakeMaxAttempts")]
    wake_max_attempts: Option<usize>,
    #[zeroize(skip)]
    #[serde(alias = "wakeTimeoutMs")]
    wake_timeout_ms: Option<u64>,
    #[zeroize(skip)]
    #[serde(alias = "wakeCoalesceSecs")]
    wake_coalesce_secs: Option<u64>,
    #[zeroize(skip)]
    #[serde(alias = "wakeApnsMode")]
    wake_apns_mode: Option<ApnsPushMode>,
    #[serde(alias = "wakeApnsTopic")]
    wake_apns_topic: Option<String>,
    #[serde(alias = "wakeApnsLocKey")]
    wake_apns_loc_key: Option<String>,
    #[serde(alias = "wakeApnsTeamId")]
    wake_apns_team_id: Option<String>,
    #[serde(alias = "wakeApnsKeyId")]
    wake_apns_key_id: Option<String>,
    #[serde(alias = "wakeApnsP8Pem")]
    wake_apns_p8_pem: Option<String>,
    #[serde(alias = "wakeApnsClientCertPem")]
    wake_apns_client_cert_pem: Option<String>,
    #[serde(alias = "wakeApnsClientKeyPem")]
    wake_apns_client_key_pem: Option<String>,
    #[zeroize(skip)]
    #[serde(alias = "relayAuthOrigins")]
    relay_auth_origins: Option<Vec<String>>,
    #[zeroize(skip)]
    advertise: Option<String>,
    #[zeroize(skip)]
    #[serde(alias = "advertisedEndpoints")]
    advertised_endpoints: Option<Vec<String>>,
    #[zeroize(skip)]
    #[serde(alias = "routePolicy")]
    route_policy: Option<String>,
    #[zeroize(skip)]
    #[serde(alias = "signRoutes")]
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
    fn from_input(mut input: TransportConfigInput) -> Result<Self> {
        if input.relay_auth_secret.is_some() && input.relay_ticket.is_some() {
            return Err(to_invalid_arg(
                "relay_auth_secret and relay_ticket are mutually exclusive",
            ));
        }
        if input.p2p_relay_auth_token.is_some() && input.p2p_api_secret.is_some() {
            return Err(to_invalid_arg(
                "p2p_relay_auth_token and p2p_api_secret are mutually exclusive",
            ));
        }
        if input.p2p_relay_mode.is_some() && input.p2p_relay_urls.is_some() {
            return Err(to_invalid_arg(
                "p2p_relay_mode and p2p_relay_urls are mutually exclusive",
            ));
        }

        let relay_auth = if let Some(sec) = input.relay_auth_secret.take().map(Zeroizing::new) {
            let trimmed = sec.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
                return Err(to_invalid_arg("invalid relay_auth_secret"));
            }
            let parsed = RelayAuthSecret::from_bytes(trimmed.as_bytes())
                .map_err(|_| to_invalid_arg("invalid relay_auth_secret"))?;
            RelayClientAuth::HmacSecret(parsed)
        } else if let Some(ticket) = input.relay_ticket.take() {
            canonical_relay_host(&ticket.relay_host).map_err(to_invalid_arg)?;
            if ticket.issuer_pub.is_empty() || ticket.target_pub.is_empty() || ticket.sig.is_empty()
            {
                return Err(to_invalid_arg("relay_ticket has empty required fields"));
            }
            RelayClientAuth::Ticket(ticket)
        } else {
            RelayClientAuth::None
        };

        let p2p_bind_addrs = tendril_runtime::parse_p2p_bind_addrs(
            "p2p_bind_addrs",
            input.p2p_bind_addrs.as_deref().unwrap_or_default(),
        )
        .map_err(to_invalid_arg)?;

        let p2p_relay_mode = if let Some(ref mode_s) = input.p2p_relay_mode {
            Some(parse_p2p_relay_mode(Some(mode_s)).map_err(to_invalid_arg)?)
        } else if let Some(ref urls) = input.p2p_relay_urls {
            Some(parse_p2p_relay_modes(urls).map_err(to_invalid_arg)?)
        } else {
            None
        };

        let p2p_relay_auth =
            if let Some(tok) = input.p2p_relay_auth_token.take().map(Zeroizing::new) {
                if tok.is_empty() || tok.chars().any(char::is_control) {
                    return Err(to_invalid_arg("invalid p2p_relay_auth_token"));
                }
                Some(P2pRelayAuth::BearerToken(tok))
            } else if let Some(sec) = input.p2p_api_secret.take().map(Zeroizing::new) {
                #[cfg(feature = "p2p-iroh-services")]
                {
                    if sec.is_empty() || sec.chars().any(char::is_control) {
                        return Err(to_invalid_arg("invalid p2p_api_secret"));
                    }
                    Some(P2pRelayAuth::IrohServicesSecret(sec))
                }
                #[cfg(not(feature = "p2p-iroh-services"))]
                {
                    let _ = sec;
                    return Err(to_generic_err(
                        "tendril-node built without p2p-iroh-services feature",
                    ));
                }
            } else {
                None
            };

        if p2p_relay_auth.is_some() && matches!(p2p_relay_mode, Some(P2pRelayMode::Disabled)) {
            return Err(to_invalid_arg(
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
        let wake = build_wake_provider(wake_spec).map_err(to_invalid_arg)?;

        let relay_auth_origins = input.relay_auth_origins.take().unwrap_or_default();
        if let Some(index) = relay_auth_origins
            .iter()
            .position(|o| !origin_allowed(o, std::slice::from_ref(o)))
        {
            return Err(to_invalid_arg(format!(
                "invalid relay_auth_origins entry #{index}: expected scheme://host[:port]"
            )));
        }
        let advertise = match input.advertise.as_deref() {
            None | Some("auto") => AdvertiseMode::Auto,
            Some("explicit") => AdvertiseMode::Explicit,
            Some(other) => {
                return Err(to_invalid_arg(format!(
                    "invalid advertise '{other}': expected 'auto' or 'explicit'"
                )));
            }
        };
        let route_policy = input
            .route_policy
            .as_deref()
            .map(str::parse::<RoutePolicy>)
            .transpose()
            .map_err(to_invalid_arg)?
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
    ) -> std::result::Result<Arc<HintDialers>, RuntimeError> {
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
    ) -> std::result::Result<P2pOptions, RuntimeError> {
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
    ) -> std::result::Result<P2pOptions, RuntimeError> {
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
struct NodePinnedHostInput {
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

fn parse_signing_pin_b64(encoded: &str) -> std::result::Result<SigningKeyPin, String> {
    let bytes = b64url_decode(encoded).map_err(|e| e.to_string())?;
    parse_signing_pin(&bytes, "signing_pin").map_err(|e| e.reason)
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

fn lookup_v2_mailbox_secret_for_target(roster: &Roster, target_host_id: &str) -> Result<[u8; 32]> {
    let entry = roster
        .get(target_host_id)
        .ok_or_else(|| to_generic_err(format!("target '{target_host_id}' not found in roster")))?;
    if entry.state == PeerState::Revoked {
        return Err(to_generic_err(format!(
            "target '{target_host_id}' is revoked"
        )));
    }
    entry
        .v2_secrets
        .as_ref()
        .map(|s| *s.mailbox_secret())
        .ok_or_else(|| {
            to_generic_err(format!(
                "target '{target_host_id}' has no v2 mailbox_secret"
            ))
        })
}

fn lookup_v2_mailbox_secret_for_pair(
    roster: &Roster,
    pinned: Option<&PinnedHost>,
    endpoint: &str,
    now_unix: u64,
) -> Result<[u8; 32]> {
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
    Err(to_generic_err(
        "no matching v2 mailbox_secret in roster for /v2/relay endpoint",
    ))
}

async fn dial_endpoint_v2_with_options(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &EndpointTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> std::result::Result<Box<dyn PathStream>, RuntimeError> {
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
) -> std::result::Result<PairOutcome, RuntimeError> {
    let mut machine = PairingInitiator::new_with_min_wire_version(
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

#[napi]
pub fn device_id(static_pub: Buffer) -> Result<String> {
    Ok(core_device_id(&as_32(static_pub.as_ref(), "static_pub")?))
}

#[napi]
pub fn fingerprint_host(static_pub: Buffer) -> Result<String> {
    Ok(core_fingerprint_host(&as_32(
        static_pub.as_ref(),
        "static_pub",
    )?))
}

#[napi]
pub fn fingerprint_device(static_pub: Buffer) -> Result<String> {
    Ok(core_fingerprint_device(&as_32(
        static_pub.as_ref(),
        "static_pub",
    )?))
}

#[napi]
pub fn pairing_sas(handshake_hash: Buffer) -> Result<String> {
    Ok(core_pairing_sas(&as_32(
        handshake_hash.as_ref(),
        "handshake_hash",
    )?))
}

#[napi]
pub async fn compute_code_mac(code: String, handshake_hash: Buffer) -> Result<Buffer> {
    let hh = as_32(handshake_hash.as_ref(), "handshake_hash")?;
    let mac = tokio::task::spawn_blocking(move || core_compute_code_mac(&code, &hh))
        .await
        .map_err(to_generic_err)?
        .map_err(to_generic_err)?;
    Ok(Buffer::from(mac.to_vec()))
}

#[napi]
pub fn verify_rotation_chain_json(
    pinned_signing_b64: String,
    pinned_static_b64: String,
    pinned_seq: f64,
    chain_json: String,
    cur_static_b64: String,
    cur_signing_b64: String,
) -> Result<f64> {
    let pinned_seq_u64 = f64_to_u64(pinned_seq, "pinned_seq")?;
    let psig = HybridSigningPublicKey::from_b64url(&pinned_signing_b64).map_err(to_generic_err)?;
    let pstat = b64url_decode_array::<32>(&pinned_static_b64).map_err(to_generic_err)?;
    let cstat = b64url_decode_array::<32>(&cur_static_b64).map_err(to_generic_err)?;
    let csig = HybridSigningPublicKey::from_b64url(&cur_signing_b64).map_err(to_generic_err)?;
    let chain: Vec<RotationRecord> =
        serde_json::from_str(&chain_json).map_err(|e| json_err("chain_json", &e))?;
    let seq = verify_rotation_chain(&psig, &pstat, pinned_seq_u64, &chain, &cstat, &csig)
        .map_err(to_generic_err)?;
    u64_to_f64(seq)
}

#[napi]
pub fn verify_grant_json(
    grant_json: String,
    issuer_keys_json: String,
    expected_subject: String,
    expected_root_issuer: String,
    requested_cap: String,
    now_unix_secs: f64,
    crl_json: Option<String>,
) -> Result<bool> {
    let now_u64 = f64_to_u64(now_unix_secs, "now_unix_secs")?;
    let grant: Grant = serde_json::from_str(&grant_json).map_err(|e| json_err("grant_json", &e))?;
    let key_map_raw: HashMap<String, String> =
        serde_json::from_str(&issuer_keys_json).map_err(|e| json_err("issuer_keys_json", &e))?;
    let mut key_map = HashMap::with_capacity(key_map_raw.len());
    for (id, b64) in key_map_raw {
        let k = HybridSigningPublicKey::from_b64url(&b64).map_err(to_generic_err)?;
        key_map.insert(id, k);
    }
    let crl: Option<RevocationList> = match crl_json {
        Some(s) if !s.is_empty() => {
            Some(serde_json::from_str(&s).map_err(|e| json_err("crl_json", &e))?)
        }
        _ => None,
    };
    let (res, _) = authorize_grant(
        Some(&grant),
        &expected_subject,
        &expected_root_issuer,
        &requested_cap,
        now_u64,
        crl.as_ref(),
        |id| key_map.get(id).cloned(),
    );
    Ok(res.is_ok())
}

#[napi]
pub fn verify_wake_tag(
    wake_secret: Buffer,
    wake_tag_b64: String,
    now_unix_secs: f64,
) -> Result<bool> {
    let secret = Zeroizing::new(as_32(wake_secret.as_ref(), "wake_secret")?);
    let now_u64 = f64_to_u64(now_unix_secs, "now_unix_secs")?;
    let tag = WakeTag::from_b64url(&wake_tag_b64).map_err(to_invalid_arg)?;
    Ok(verify_epoch_wake_tag_window(&secret, &tag, now_u64))
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
) -> Result<T> {
    match raw.filter(|s| !s.trim().is_empty()) {
        None => Ok(T::default()),
        Some(s) => serde_json::from_str(s).map_err(|e| json_err(name, &e)),
    }
}

fn parse_grant(grant_json: Option<&str>) -> Result<Option<Grant>> {
    match grant_json {
        Some(s) if !s.is_empty() => Ok(Some(
            serde_json::from_str(s).map_err(|e| json_err("grant_json", &e))?,
        )),
        _ => Ok(None),
    }
}

fn parse_route_policy(raw: Option<&str>, default: RoutePolicy) -> Result<RoutePolicy> {
    raw.filter(|s| !s.is_empty())
        .map_or(Ok(default), str::parse::<RoutePolicy>)
        .map_err(to_invalid_arg)
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

fn skip_reason_name(skipped: &SkippedHint) -> String {
    serde_json::to_value(skipped.reason)
        .ok()
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

/// One policy connect over the chosen wire.
async fn policy_connect(
    wire: u8,
    identity: &Arc<EndpointIdentity>,
    target: &str,
    access: &RosterAccess,
    opts: ConnectOpts,
) -> std::result::Result<SessionBackend, AttemptError> {
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
fn attempt_err(err: AttemptError) -> Error {
    let msg = attempt_message(&err);
    session_err(&err.error, msg)
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

/// The identity fields of a Wire v1 pairing outcome, or the rejection text.
fn pair_outcome_json_v1(outcome: &PairOutcome) -> std::result::Result<serde_json::Value, String> {
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
fn pair_outcome_json_v2(outcome: &V2PairOutcome) -> std::result::Result<serde_json::Value, String> {
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

/// What a hosting endpoint advertises and the `RouteAnnouncer` built from it (created on first
/// use: pairing URI issuance, a route refresh, or an accepted session whose client opted in).
struct AnnouncerSlot {
    identity: Arc<EndpointIdentity>,
    access: RosterAccess,
    transport_cfg: Arc<StdMutex<EndpointTransportConfig>>,
    served_endpoints: StdMutex<Vec<String>>,
    served_listeners: StdMutex<Vec<ServedListener>>,
    announcer: StdMutex<AnnouncerState>,
    /// Publishes `configureTransportsJson` started on blocking threads and nobody awaited yet.
    pending_publishes: StdMutex<Vec<JoinHandle<()>>>,
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

    /// The live announcer, created with its 60 s timer on first use; fails once the endpoint is
    /// closed. Must run inside the Tokio runtime (every caller is an async N-API method).
    fn announcer(&self) -> Result<Arc<RouteAnnouncer>> {
        let mut guard = self
            .announcer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*guard {
            AnnouncerState::Running(announcer, _) => return Ok(Arc::clone(announcer)),
            AnnouncerState::Closed => {
                return Err(to_generic_err("endpoint is closed"));
            }
            AnnouncerState::Idle => {}
        }
        let announcer = Arc::new(RouteAnnouncer::new(
            (*self.identity).clone(),
            self.access.clone(),
            self.inputs(),
            AddressSource::platform_default(),
        ));
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

    /// Applies the current inputs to a live announcer at once, so a call that follows never
    /// publishes stale ones, and starts the publish on a blocking thread (it waits on the state
    /// directory lock, so it never runs on the JS thread). The handle is kept: the next
    /// issuance, refresh or [`Self::settle`] waits for it. A failed publish (for example an
    /// exhausted sequence) is not an error of the configuration call, as in Python; the
    /// issuance or refresh that follows publishes again and reports it.
    fn publish_detached(&self) {
        let Some(announcer) = self.existing() else {
            return;
        };
        announcer.set_inputs(self.inputs());
        let handle = within_runtime_if_available(move || {
            tokio::task::spawn_blocking(move || {
                let _ = announcer.publish(unix_ms());
            })
        });
        let mut pending = self
            .pending_publishes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|h| !h.is_finished());
        pending.push(handle);
    }

    /// Waits for every publish [`Self::publish_detached`] started.
    async fn settle(&self) {
        let pending = std::mem::take(
            &mut *self
                .pending_publishes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for handle in pending {
            let _ = handle.await;
        }
    }

    /// [`Self::inputs_changed`] on a blocking thread: publishing waits on the state directory
    /// lock, which must never park a Tokio worker.
    async fn inputs_changed_async(self: &Arc<Self>) {
        let slot = Arc::clone(self);
        let _ = tokio::task::spawn_blocking(move || slot.inputs_changed()).await;
    }

    async fn record_served(self: &Arc<Self>, endpoint: &str, listener: Option<ServedListener>) {
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
        self.inputs_changed_async().await;
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

#[napi]
pub struct Endpoint {
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    router: InboundRouter,
    v2_state: Arc<V2ResponderState>,
    transport_cfg: Arc<StdMutex<EndpointTransportConfig>>,
    self_m2m_enabled: AtomicBool,
    m2m_enabled: AtomicBool,
    groups: StdMutex<Vec<Weak<GroupPool>>>,
    /// URLs bound by `serveRelay`, so a group pool never displaces their identity mailbox.
    served_v1_relays: StdMutex<Vec<String>>,
    /// Store-or-memory roster handle shared by the policy drivers, the route setter and the
    /// announcer. With a state directory it keeps its own in-memory copy, so a driver write never
    /// replaces the roster live sessions share; `sync_roster_from_store` reloads that one.
    access: RosterAccess,
    announce: Arc<AnnouncerSlot>,
}

impl Endpoint {
    fn update_roster_sync<T>(
        &self,
        f: impl FnOnce(&mut Roster) -> std::result::Result<T, RuntimeError>,
    ) -> Result<T> {
        if let Some(store) = &self.store {
            let _guard = self.store_lock.blocking_lock();
            commit_roster(store, &self.roster, &self.identity, |disk, _| f(disk))
                .map_err(to_generic_err)
        } else {
            let mut guard = lock_roster(&self.roster);
            f(&mut guard).map_err(to_generic_err)
        }
    }

    async fn sync_roster_from_store(&self) -> Result<()> {
        sync_roster_async(
            self.store.as_ref(),
            &self.store_lock,
            &self.roster,
            &self.identity,
        )
        .await
    }

    async fn commit_session_roster(&self) -> Result<()> {
        commit_session_async(
            self.store.as_ref(),
            &self.store_lock,
            &self.roster,
            &self.identity,
        )
        .await
    }

    fn new_session(&self, backend: SessionBackend, initiator: bool) -> Session {
        Session {
            initiator,
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
    async fn accepted_session(&self, backend: SessionBackend) -> Result<Session> {
        if let Some(peer_seq) = backend.peer_route_seq() {
            let sink = backend.route_sink();
            let announce = Arc::clone(&self.announce);
            let handle = tokio::runtime::Handle::current();
            // Registration reads the roster under the state directory lock: blocking thread.
            let registered = tokio::task::spawn_blocking(move || {
                let announcer = announce.announcer()?;
                handle
                    .block_on(announcer.on_session_established(&sink, Some(peer_seq), unix_ms()))
                    .map_err(to_generic_err)
            })
            .await
            .map_err(to_generic_err)
            .and_then(|outcome| outcome);
            if let Err(err) = registered {
                // The accept already failed; a close that cannot be sent changes nothing.
                let _ = backend.send_close(1011, "route registration failed").await;
                return Err(err);
            }
        }
        Ok(self.new_session(backend, false))
    }

    /// Day-2 connect through the runtime policy drivers.
    async fn connect_policy(&self, target_host_id: &str, args: ConnectArgs) -> Result<Session> {
        let cfg = self.snapshot_transport_cfg();
        let dialers = cfg
            .hint_dialers(args.relay_host.as_deref(), args.endpoint.as_deref())
            .map_err(to_generic_err)?;
        let mut opts = ConnectOpts::new(dialers);
        opts.grant = args.grant;
        opts.recovery_uri = args.recovery_uri;
        opts.replace_routes = args.replace_routes;
        opts.policy = args.policy.unwrap_or(cfg.route_policy);
        opts.operator_endpoint = args.endpoint;
        opts.relay_auth_origins = cfg.relay_auth_origins.clone();

        // A configured wake target applies to an explicit Wire v2 endpoint, with or without a
        // recovery URI: `wake_pre_wake` decides whether the wake hint or the first connect goes first.
        let wake = (args.wire == 2 && opts.operator_endpoint.is_some())
            .then(|| cfg.wake.clone())
            .flatten();

        self.sync_roster_from_store().await?;
        let identity = Arc::clone(&self.identity);
        let access = self.access.clone();
        let target = target_host_id.to_owned();
        let wire = args.wire;
        let handle = tokio::runtime::Handle::current();
        // The drivers read and write the roster under the state directory lock: they run on a
        // blocking thread, never on a Tokio worker.
        let res = tokio::task::spawn_blocking(move || {
            handle.block_on(async move {
                let connect = || policy_connect(wire, &identity, &target, &access, opts.clone());
                match &wake {
                    Some(w) => connect_with_wake_policy(&w.to_dial_options(), connect)
                        .await
                        .map(|(backend, _)| backend),
                    None => connect().await,
                }
            })
        })
        .await
        .map_err(to_generic_err)?;
        let synced = self.sync_roster_from_store().await;
        let backend = res.map_err(attempt_err)?;
        synced?;
        Ok(self.new_session(backend, true))
    }

    /// Pairing from a scanned URI through the runtime policy drivers.
    async fn pair_uri_impl(
        &self,
        v2: bool,
        pairing_uri: &str,
        name: Option<String>,
        kind: Option<String>,
        options_json: Option<String>,
    ) -> Result<String> {
        let opts_in: PairUriOptions = parse_options(options_json.as_deref(), "options_json")?;
        let uri = PairingUri::parse(pairing_uri).map_err(to_invalid_arg)?;
        let cfg = self.snapshot_transport_cfg();
        let policy = parse_route_policy(opts_in.route_policy.as_deref(), cfg.route_policy)?;
        let endpoint = opts_in.endpoint.filter(|e| !e.is_empty());
        let dialers = cfg
            .hint_dialers(None, endpoint.as_deref())
            .map_err(to_generic_err)?;
        // An explicit empty code is rejected before any dial; it never falls back to the URI code.
        let code = opts_in.code.unwrap_or_else(|| uri.code.clone());
        let mut opts = PairPolicyOptions::new(
            name.unwrap_or_else(|| "node-device".to_owned()),
            kind.unwrap_or_else(|| "node".to_owned()),
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

        self.sync_roster_from_store().await?;
        let identity = Arc::clone(&self.identity);
        let access = self.access.clone();
        let handle = tokio::runtime::Handle::current();
        // The drivers persist routes under the state directory lock: blocking thread.
        let res = tokio::task::spawn_blocking(move || {
            handle.block_on(async move {
                if v2 {
                    drive_v2_pair_initiator_with_policy(identity, &access, opts)
                        .await
                        .map(|r| {
                            let outcome = pair_outcome_json_v2(&r.drive.outcome);
                            (outcome, PairReport::from_result(&r))
                        })
                } else {
                    drive_pair_initiator_with_policy(identity, &access, opts)
                        .await
                        .map(|r| {
                            let outcome = pair_outcome_json_v1(&r.drive.outcome);
                            (outcome, PairReport::from_result(&r))
                        })
                }
            })
        })
        .await
        .map_err(to_generic_err)?;
        let synced = self.sync_roster_from_store().await;
        let (outcome, report) = res.map_err(|e| to_generic_err(attempt_message(&e)))?;
        synced?;
        let mut json = outcome.map_err(to_generic_err)?;
        if v2 {
            json["wire_version"] = serde_json::json!(2);
        }
        report.merge_into(&mut json);
        Ok(json.to_string())
    }

    fn group_store(&self) -> Result<Arc<StateStore>> {
        self.store.clone().ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "group operations require a state_dir",
            )
        })
    }

    fn snapshot_transport_cfg(&self) -> EndpointTransportConfig {
        self.transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn refresh_m2m_enabled(&self, roster: &Roster) {
        let enabled = self.self_m2m_enabled.load(Ordering::Acquire)
            || roster
                .trust_anchors()
                .any(|(_, a)| a.state == AnchorState::Active);
        self.m2m_enabled.store(enabled, Ordering::Release);
    }

    fn spawn_listener(&self, listener: Box<dyn PathListener>) {
        self.router
            .spawn_listener(&tokio::runtime::Handle::current(), listener);
    }
}

#[napi]
impl Endpoint {
    #[napi(constructor)]
    pub fn new(state_dir: Option<String>, host_id: Option<String>) -> Result<Self> {
        let host_opt = host_id.as_deref();
        let (store, identity, roster) = if let Some(dir) = state_dir.filter(|s| !s.is_empty()) {
            let store = Arc::new(StateStore::open_or_create(dir).map_err(to_generic_err)?);
            let identity = store
                .load_or_generate_identity(host_opt)
                .map_err(to_generic_err)?;
            let roster = store.load_roster().map_err(to_generic_err)?;
            (Some(store), identity, roster)
        } else {
            let mut identity = EndpointIdentity::generate().map_err(to_generic_err)?;
            if let Some(h) = host_opt
                && !h.is_empty()
            {
                identity = identity.try_with_host_id(h).map_err(to_generic_err)?;
            }
            (None, identity, Roster::new())
        };

        let has_active_anchor = roster
            .trust_anchors()
            .any(|(_, a)| a.state == AnchorState::Active);
        if !is_valid_host_id(identity.host_id()) {
            return Err(to_generic_err("invalid local host_id"));
        }
        let identity = Arc::new(identity);
        let roster = Arc::new(StdMutex::new(roster));
        let access_roster = if store.is_some() {
            Arc::new(StdMutex::new(lock_roster(&roster).clone()))
        } else {
            Arc::clone(&roster)
        };
        let access = RosterAccess::new(store.clone(), access_roster);
        let transport_cfg = Arc::new(StdMutex::new(EndpointTransportConfig::default()));
        let announce = Arc::new(AnnouncerSlot {
            identity: Arc::clone(&identity),
            access: access.clone(),
            transport_cfg: Arc::clone(&transport_cfg),
            served_endpoints: StdMutex::new(Vec::new()),
            served_listeners: StdMutex::new(Vec::new()),
            announcer: StdMutex::new(AnnouncerState::Idle),
            pending_publishes: StdMutex::new(Vec::new()),
        });
        Ok(Self {
            store,
            store_lock: Arc::new(AsyncMutex::new(())),
            identity,
            roster,
            pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
            router: InboundRouter::new(),
            v2_state: Arc::new(V2ResponderState::new()),
            transport_cfg,
            self_m2m_enabled: AtomicBool::new(false),
            m2m_enabled: AtomicBool::new(has_active_anchor),
            groups: StdMutex::new(Vec::new()),
            served_v1_relays: StdMutex::new(Vec::new()),
            access,
            announce,
        })
    }

    #[napi]
    pub async fn group_create(
        &self,
        name: String,
        min_wire_version: f64,
        endpoints: Option<Vec<String>>,
    ) -> Result<String> {
        let store = self.group_store()?;
        let wire = f64_to_u8(min_wire_version, "min_wire_version")?;
        let manifest = rt_group_create(
            &store,
            &self.identity,
            &name,
            wire,
            endpoints.unwrap_or_default(),
        )
        .map_err(to_generic_err)?;
        manifest_json(&manifest)
    }

    #[napi]
    pub async fn group_add_member(
        &self,
        group_id: String,
        peer_id: String,
        caps: Option<Vec<String>>,
        endpoints: Option<Vec<String>>,
    ) -> Result<String> {
        let store = self.group_store()?;
        let manifest = rt_group_add_member(
            &store,
            &self.identity,
            &group_id,
            &peer_id,
            caps.unwrap_or_default(),
            endpoints.unwrap_or_default(),
        )
        .map_err(to_generic_err)?;
        manifest_json(&manifest)
    }

    #[napi]
    pub async fn group_remove_member(&self, group_id: String, peer_id: String) -> Result<String> {
        let store = self.group_store()?;
        let manifest = rt_group_remove_member(&store, &self.identity, &group_id, &peer_id)
            .map_err(to_generic_err)?;
        manifest_json(&manifest)
    }

    #[napi]
    pub async fn group_ingest_manifest(
        &self,
        manifest_json: String,
        sender_peer_id: String,
    ) -> Result<String> {
        let store = self.group_store()?;
        rt_group_ingest_manifest(
            &store,
            &self.identity.device_id(),
            &sender_peer_id,
            &manifest_json,
        )
        .map(|outcome| outcome.group_id)
        .map_err(to_generic_err)
    }

    #[napi]
    pub async fn group_open(
        &self,
        group_id: String,
        listen_addr: Option<String>,
        relay_listen: Option<bool>,
    ) -> Result<Group> {
        let store = self.group_store()?;
        let addr: Option<SocketAddr> = listen_addr
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse()
                    .map_err(|e| to_invalid_arg(format!("invalid address: {e}")))
            })
            .transpose()?;
        let transport_cfg = self.snapshot_transport_cfg();
        let mut dialers: Vec<Arc<dyn PathDialer>> = vec![
            Arc::new(DirectDialer::new()),
            Arc::new(LocalDialer::new()),
            Arc::new(RelayDialer::new().with_auth(transport_cfg.relay_auth.clone())),
            Arc::new(OverlayDialer::new()),
            Arc::new(BrokerDialer::new()),
        ];
        if let Some(opts) = transport_cfg.build_p2p_group_options() {
            let dialer = P2pDialer::bind_with_options(opts)
                .await
                .map_err(to_generic_err)?;
            dialers.push(Arc::new(dialer));
        }
        let served_v1_relays = self
            .served_v1_relays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let config = GroupPoolConfig::new(dialers)
            .with_relay_auth(transport_cfg.relay_auth.clone())
            .with_relay_listen(relay_listen.unwrap_or(false))
            .with_served_v1_relays(served_v1_relays);
        let pool = GroupPool::open(
            (*store).clone(),
            Arc::clone(&self.identity),
            &group_id,
            config,
            None,
        )
        .map_err(to_generic_err)?;
        let mut local_endpoint = None;
        if let Some(addr) = addr {
            let listener = match DirectListener::bind(addr, None).await {
                Ok(l) => l,
                Err(e) => {
                    pool.close();
                    return Err(to_generic_err(e));
                }
            };
            local_endpoint = Some(listener.local_endpoint());
            pool.serve(Box::new(listener));
        }
        let pool = Arc::new(pool);
        {
            let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
            groups.retain(|w| w.upgrade().is_some_and(|p| !p.is_closed()));
            groups.push(Arc::downgrade(&pool));
        }
        Ok(Group {
            pool,
            local_endpoint,
        })
    }

    #[napi]
    pub fn info_json(&self) -> String {
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

    #[napi]
    pub async fn serve_direct(&self, listen_addr: Option<String>) -> Result<String> {
        let addr: SocketAddr = listen_addr
            .as_deref()
            .unwrap_or("127.0.0.1:0")
            .parse()
            .map_err(|e| to_invalid_arg(format!("invalid address: {e}")))?;
        let listener = DirectListener::bind(addr, None)
            .await
            .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        let served =
            ServedListener::from_listener(listener.tcp_listener()).map_err(to_generic_err)?;
        self.spawn_listener(Box::new(listener));
        self.announce.record_served(&ep, Some(served)).await;
        Ok(ep)
    }

    #[napi]
    pub async fn serve_relay(
        &self,
        relay_url: String,
        expected_host: Option<String>,
    ) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        let key = self.identity.signing_key().ed25519_signing_key();
        let listener = RelayListener::bind_with_auth(
            relay_url.clone(),
            expected_host,
            key,
            DEFAULT_WRITE_TIMEOUT,
            cfg.relay_auth.clone(),
        )
        .await
        .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        self.served_v1_relays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(relay_url);
        self.announce.record_served(&ep, None).await;
        Ok(ep)
    }

    #[napi(js_name = "serveP2p")]
    pub async fn serve_p2p(&self, relay_mode: Option<String>) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        let opts = cfg
            .build_p2p_listener_options(relay_mode.as_deref())
            .map_err(to_invalid_arg)?;
        let seed = self.identity.derive_p2p_identity_seed();
        let listener = P2pListener::bind_with_options(opts, Some(seed))
            .await
            .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        self.announce.record_served(&ep, None).await;
        Ok(ep)
    }

    #[napi]
    pub fn issue_code(&self, kind: Option<String>) -> Result<String> {
        let pk = match kind.as_deref() {
            None | Some("") => PairingCodeKind::Lan2Group,
            Some(k) => k.parse::<PairingCodeKind>().map_err(to_invalid_arg)?,
        };
        let mut mgr = self.pair_mgr.lock().expect("pair_mgr mutex poisoned");
        mgr.issue_code(pk, now_unix()).map_err(to_generic_err)
    }

    #[napi]
    pub async fn pair_initiate(
        &self,
        endpoint: String,
        code: String,
        relay_host: Option<String>,
        name: Option<String>,
        kind: Option<String>,
    ) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        self.sync_roster_from_store().await?;
        let roster_snapshot = lock_roster(&self.roster).clone();
        let v2_secret = if is_v2_relay_endpoint(&endpoint) {
            Some(lookup_v2_mailbox_secret_for_pair(
                &roster_snapshot,
                None,
                &endpoint,
                now_unix(),
            )?)
        } else {
            None
        };
        let mut stream =
            dial_endpoint_v2_with_options(&endpoint, relay_host.as_deref(), &cfg, v2_secret)
                .await
                .map_err(to_generic_err)?;
        let device_name = name.unwrap_or_else(|| "node-device".to_owned());
        let device_kind = kind.unwrap_or_else(|| "node".to_owned());
        let outcome = if let Some(ref store) = self.store {
            drive_pair_initiator_with_store(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                None,
                store,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .map(|r| r.outcome)
        } else {
            drive_v1_pair_initiator_with_roster_floors(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                &roster_snapshot,
            )
            .await
        };
        let _ = stream.close().await;
        let outcome = outcome.map_err(to_generic_err)?;

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
                let host_id_c = host_id.clone();
                let sas_c = pairing_sas.clone();
                update_roster_async(
                    self.store.as_ref(),
                    &self.store_lock,
                    &self.roster,
                    &self.identity,
                    move |roster| {
                        if host_pin_verified {
                            roster
                                .insert_pinned_host(
                                    host_id_c.clone(),
                                    host_id_c,
                                    host_static_pub,
                                    Some(host_signing_pub),
                                    host_rotation_seq,
                                    Vec::new(),
                                )
                                .map(|_| ())
                        } else {
                            roster
                                .record_pending_host(
                                    host_id_c.clone(),
                                    host_id_c,
                                    host_static_pub,
                                    host_signing_pub,
                                    host_rotation_seq,
                                    sas_c,
                                    Vec::new(),
                                )
                                .map(|_| ())
                        }
                        .map_err(RuntimeError::from)
                    },
                )
                .await?;
                Ok(serde_json::json!({
                    "device_id": device_id,
                    "host_id": host_id,
                    "sas": pairing_sas,
                    "status": if host_pin_verified { "active" } else { "pending" },
                    "host_confirmed": host_pin_verified,
                })
                .to_string())
            }
            PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                Err(to_generic_err("unexpected responder outcome"))
            }
            PairOutcome::InitiatorEnrolled { .. } => {
                Err(to_generic_err("unexpected m2m enrollment outcome"))
            }
        }
    }

    #[napi]
    pub async fn pair_accept(&self, timeout_ms: Option<f64>) -> Result<String> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        self.sync_roster_from_store().await?;
        self.refresh_m2m_enabled(&lock_roster(&self.roster));
        let policy = if self.m2m_enabled.load(Ordering::Acquire) {
            EnrollmentPolicy::enabled_default()
        } else {
            EnrollmentPolicy::default()
        };
        let (mut stream, guard) = match self.router.recv_pair(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting pair")),
        };

        let path_kind = pairing_path_kind_for_provider(stream.provider_id());
        let driven = if let Some(ref store) = self.store {
            drive_pair_responder_with_store(
                stream.as_mut(),
                &self.identity,
                &self.pair_mgr,
                store,
                &self.store_lock,
                path_kind,
                now_unix(),
                policy,
                Some(self.router.rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        } else {
            drive_pair_responder_with_policy_and_store(
                stream.as_mut(),
                &self.identity,
                &self.pair_mgr,
                &self.roster,
                None,
                path_kind,
                now_unix(),
                policy,
                Some(self.router.rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        let synced = self.sync_roster_from_store().await;
        let res = driven.map_err(to_generic_err)?;
        synced?;

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
            PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            PairOutcome::InitiatorPending { .. } | PairOutcome::InitiatorEnrolled { .. } => {
                Err(to_generic_err("unexpected initiator outcome"))
            }
        }
    }

    #[napi]
    pub fn confirm_peer(&self, peer_id: String, sas: Option<String>) -> Result<()> {
        self.update_roster_sync(|roster| {
            roster
                .confirm_peer(&peer_id, sas.as_deref())
                .map(|_| ())
                .map_err(RuntimeError::from)
        })
    }

    #[napi]
    pub fn mint_grant(
        &self,
        peer_id: String,
        caps: Vec<String>,
        ttl_secs: Option<f64>,
    ) -> Result<String> {
        let ttl = match ttl_secs {
            Some(v) => f64_to_u64(v, "ttl_secs")?,
            None => 3600,
        };
        let nonce = random_bytes::<16>().map_err(to_generic_err)?;
        let grant = self.update_roster_sync(|roster| {
            let now = now_unix();
            roster
                .mint_grant(
                    &self.identity,
                    &peer_id,
                    caps,
                    now,
                    now.saturating_add(ttl),
                    nonce,
                )
                .map_err(RuntimeError::from)
        })?;
        serde_json::to_string(&grant).map_err(to_generic_err)
    }

    /// Marks `peerId` revoked and clears its grants. `notify` unset follows the refusal policy
    /// (a notice unless `revokedNoticeTtlSecs` is `0`); `false` revokes silently and clears an
    /// earlier notice, so the peer's next connect is no longer told why.
    #[napi]
    pub fn revoke_peer(&self, peer_id: String, notify: Option<bool>) -> Result<()> {
        let notify = notify.unwrap_or(true);
        self.update_roster_sync(|roster| {
            roster
                .revoke_peer_at(&peer_id, notify, now_unix())
                .map_err(RuntimeError::from)
        })?;
        self.refresh_m2m_enabled(&lock_roster(&self.roster));
        Ok(())
    }

    /// Sets the host refusal policy and persists it with the roster. `pending` refuses
    /// unconfirmed peers with `4004` (default `true`); `revokedNoticeTtlSecs` is the lifetime of
    /// a notice recorded at revocation (default 30 days) and `0` records none. Notices already
    /// recorded keep their expiry.
    #[napi]
    pub fn set_refusal_policy(
        &self,
        pending: Option<bool>,
        revoked_notice_ttl_secs: Option<f64>,
    ) -> Result<()> {
        let defaults = RefusalPolicy::default();
        let ttl = match revoked_notice_ttl_secs {
            None => defaults.revoked_notice_ttl_secs,
            Some(v) => f64_to_u64(v, "revokedNoticeTtlSecs")?,
        };
        let policy = RefusalPolicy {
            pending: pending.unwrap_or(defaults.pending),
            revoked_notice_ttl_secs: ttl,
        };
        self.update_roster_sync(|roster| {
            roster.set_refusal_policy(policy);
            Ok(())
        })
    }

    /// Drops the refusal notice of `peerId`, which stays revoked: its next connect is no longer
    /// told why. Throws for an unknown peer.
    #[napi]
    pub fn clear_refusal_notice(&self, peer_id: String) -> Result<()> {
        self.update_roster_sync(|roster| {
            roster
                .clear_refusal_notice(&peer_id)
                .map_err(RuntimeError::from)
        })
    }

    /// The unconfirmed host claims left by unpinned pairing, oldest first, as a JSON array of
    /// `{"host_id", "device_id", "name", "static_pub", "signing_pub_hash", "rotation_seq",
    /// "min_wire_version", "pairing_sas"}`. `host_id` is the unauthenticated label a claim names
    /// and `device_id` the id derived from its static key in the handshake.
    #[napi]
    pub async fn pending_hosts(&self) -> Result<String> {
        self.sync_roster_from_store().await?;
        Ok(lock_roster(&self.roster).pending_hosts_json().to_string())
    }

    /// Drops every unconfirmed host claim naming `host_id` and revokes nothing.
    #[napi]
    pub fn remove_pending_host(&self, host_id: String) -> Result<()> {
        self.update_roster_sync(|roster| {
            roster
                .remove_pending_host_claims(&host_id)
                .map_err(RuntimeError::from)
        })
    }

    /// Revokes the keys of the unconfirmed host claims whose handshake-derived `device_id`
    /// equals `device_id`; a claimed `host_id` never matches.
    #[napi]
    pub fn revoke_pending_host(&self, device_id: String) -> Result<()> {
        self.update_roster_sync(|roster| {
            roster
                .revoke_pending_host(&device_id)
                .map_err(RuntimeError::from)
        })?;
        // Revoking a claim's keys also revokes trust anchors sharing its signing key.
        self.refresh_m2m_enabled(&lock_roster(&self.roster));
        Ok(())
    }

    #[napi]
    pub fn add_trust_anchor(&self, anchor_id: String, signing_pub: Buffer) -> Result<()> {
        let key = parse_hybrid_signing_pub(signing_pub.as_ref(), "signing_pub")?;
        self.update_roster_sync(|roster| {
            roster
                .add_trust_anchor(anchor_id, key)
                .map(|_| ())
                .map_err(RuntimeError::from)
        })?;
        self.refresh_m2m_enabled(&lock_roster(&self.roster));
        self.router.set_pair_enabled(true);
        Ok(())
    }

    #[napi]
    pub fn revoke_trust_anchor(&self, anchor_id: String) -> Result<()> {
        self.update_roster_sync(|roster| {
            roster
                .revoke_trust_anchor(&anchor_id)
                .map_err(RuntimeError::from)
        })?;
        self.refresh_m2m_enabled(&lock_roster(&self.roster));
        Ok(())
    }

    #[napi]
    pub fn mint_enrollment_token(
        &self,
        target_host_id: String,
        subject: Option<String>,
        ttl_secs: Option<f64>,
    ) -> Result<String> {
        let ttl = match ttl_secs {
            Some(v) => f64_to_u64(v, "ttl_secs")?,
            None => 900,
        };
        let nonce = random_bytes::<16>().map_err(to_generic_err)?;
        let token = core_mint_enrollment_token(
            &self.identity,
            &target_host_id,
            subject.as_deref(),
            now_unix(),
            ttl,
            nonce,
        )
        .map_err(to_invalid_arg)?;
        if target_host_id == self.identity.host_id() {
            self.self_m2m_enabled.store(true, Ordering::Release);
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.refresh_m2m_enabled(&roster);
            self.router.set_pair_enabled(true);
        }
        serde_json::to_string(&token).map_err(to_generic_err)
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_initiate(
        &self,
        endpoint: String,
        host_id: String,
        host_static_pub: Buffer,
        host_signing_pub: Buffer,
        token_json: String,
        relay_host: Option<String>,
        host_rotation_seq: Option<f64>,
        name: Option<String>,
        kind: Option<String>,
    ) -> Result<String> {
        let static_pub = as_32(host_static_pub.as_ref(), "host_static_pub")?;
        let signing_pin = parse_signing_pin(host_signing_pub.as_ref(), "host_signing_pub")?;
        let rot_seq = match host_rotation_seq {
            Some(v) => f64_to_u64(v, "host_rotation_seq")?,
            None => 0,
        };
        let token: Grant =
            serde_json::from_str(&token_json).map_err(|e| json_err("token_json", &e))?;
        let pinned_host = PinnedHost {
            host_id: Some(host_id),
            static_pub,
            signing_pin,
            rotation_seq: rot_seq,
        };

        let cfg = self.snapshot_transport_cfg();
        // The store-backed driver reads the on-disk roster for its pin checks: persist the CRLs
        // only this endpoint's sessions hold first, so the driver sees them.
        self.commit_session_roster().await?;
        self.sync_roster_from_store().await?;
        let (fallback_floor, v2_secret) = {
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let floor = pinned_pairing_floor(&roster, &pinned_host);
            let sec = if is_v2_relay_endpoint(&endpoint) {
                Some(lookup_v2_mailbox_secret_for_pair(
                    &roster,
                    Some(&pinned_host),
                    &endpoint,
                    now_unix(),
                )?)
            } else {
                None
            };
            (floor, sec)
        };
        let mut stream =
            dial_endpoint_v2_with_options(&endpoint, relay_host.as_deref(), &cfg, v2_secret)
                .await
                .map_err(to_generic_err)?;
        let device_name = name.unwrap_or_else(|| "node-machine".to_owned());
        let device_kind = kind.unwrap_or_else(|| "machine".to_owned());
        let res = if let Some(store) = self.store.clone() {
            // With a state directory the runtime pins the host and stores its routes in one
            // roster transaction, under this endpoint's route policy. The driver takes the
            // state directory lock and does disk I/O, so it runs on a blocking thread, never on
            // a Tokio worker.
            let opts = M2mEnrollOptions {
                operator_endpoint: Some(endpoint.clone()),
                policy: cfg.route_policy,
                handshake_timeout: DEFAULT_PRE_AUTH_TIMEOUT,
            };
            let identity = Arc::clone(&self.identity);
            let handle = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                handle.block_on(async move {
                    let res = drive_m2m_enroll_initiator_with_routes(
                        stream.as_mut(),
                        &identity,
                        device_name,
                        device_kind,
                        token,
                        pinned_host,
                        &store,
                        opts,
                    )
                    .await
                    .map(|r| {
                        let warnings: Vec<&'static str> =
                            r.route_warnings.iter().map(|w| w.as_str()).collect();
                        (r.drive, r.routes_persisted, warnings)
                    });
                    let _ = stream.close().await;
                    res
                })
            })
            .await
            .map_err(to_generic_err)?
        } else {
            // A memory-only endpoint has no store to hold routes: it pins the host in memory
            // below and requests and stores no route, whatever the route policy.
            let res = drive_m2m_enroll_initiator_with_floor(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                token,
                pinned_host,
                fallback_floor,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .map(|drive| (drive, Vec::new(), Vec::new()));
            let _ = stream.close().await;
            res
        };
        let (res, routes_persisted, route_warnings) = res.map_err(to_generic_err)?;

        match res.outcome {
            PairOutcome::InitiatorEnrolled {
                device_id,
                host_id,
                host_static_pub,
                host_signing_pub,
                host_rotation_seq,
                token_nonce,
            } => {
                if self.store.is_some() {
                    self.sync_roster_from_store().await?;
                } else {
                    let host_id_c = host_id.clone();
                    update_roster_async(
                        self.store.as_ref(),
                        &self.store_lock,
                        &self.roster,
                        &self.identity,
                        move |roster| {
                            roster
                                .insert_pinned_host(
                                    host_id_c.clone(),
                                    host_id_c,
                                    host_static_pub,
                                    Some(host_signing_pub),
                                    host_rotation_seq,
                                    Vec::new(),
                                )
                                .map(|_| ())
                                .map_err(RuntimeError::from)
                        },
                    )
                    .await?;
                }
                Ok(serde_json::json!({
                    "device_id": device_id,
                    "host_id": host_id,
                    "status": "active",
                    "host_rotation_seq": host_rotation_seq,
                    "token_nonce": token_nonce,
                    "routes_persisted": routes_json_array(&routes_persisted),
                    "route_warnings": route_warnings,
                    "routes_reason": self.store.is_none().then_some("no_state_dir"),
                })
                .to_string())
            }
            PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            PairOutcome::InitiatorPending { .. } => {
                Err(to_generic_err("unexpected human pending outcome"))
            }
            PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                Err(to_generic_err("unexpected responder outcome"))
            }
        }
    }

    /// Wire v1 Day-2 connect. A missing or empty `endpoint` dials the stored routes of the target.
    /// A non-empty one is normalized and dialed alone.
    #[napi]
    pub async fn connect(
        &self,
        endpoint: Option<String>,
        target_host_id: String,
        grant_json: Option<String>,
        relay_host: Option<String>,
    ) -> Result<Session> {
        let args = ConnectArgs {
            wire: 1,
            endpoint: endpoint.filter(|e| !e.is_empty()),
            grant: parse_grant(grant_json.as_deref())?,
            relay_host,
            ..ConnectArgs::default()
        };
        self.connect_policy(&target_host_id, args).await
    }

    #[napi]
    pub async fn accept_session(&self, timeout_ms: Option<f64>) -> Result<Session> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        let (stream, guard) = match self.router.recv_session(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting session")),
        };

        self.sync_roster_from_store().await?;
        let accepted = SessionDriver::accept_locked(
            stream,
            &self.identity,
            &self.roster,
            now_unix(),
            Some(self.router.rate_limiter()),
            Some(guard),
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await;
        let persisted = self.commit_session_roster().await;
        let driver = accepted.map_err(to_generic_err)?;
        persisted?;

        self.accepted_session(SessionBackend::V1(Arc::new(driver.into_concurrent())))
            .await
    }

    #[napi(js_name = "configureTransportsJson")]
    pub fn configure_transports_json(&self, transport_config_json: String) -> Result<()> {
        let input: TransportConfigInput = serde_json::from_str(&transport_config_json)
            .map_err(|e| json_err("transport_config_json", &e))?;
        let parsed = EndpointTransportConfig::from_input(input)?;
        *self
            .transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = parsed;
        // Publishing waits on the state directory lock: it never runs on the JS thread.
        self.announce.publish_detached();
        Ok(())
    }

    #[napi(js_name = "mintRelayTicket")]
    pub fn mint_relay_ticket(
        &self,
        relay_host: String,
        role: Option<String>,
        target_pub_or_wildcard: Option<String>,
        ttl_secs: Option<f64>,
    ) -> Result<String> {
        let ttl = match ttl_secs {
            Some(v) => f64_to_u64(v, "ttl_secs")?,
            None => 3600,
        };
        let role_enum = match role.as_deref().map(str::trim) {
            None | Some("" | "any") => RelayAuthRole::Any,
            Some("register") => RelayAuthRole::Register,
            Some("dial") => RelayAuthRole::Dial,
            Some(other) => {
                return Err(to_invalid_arg(format!(
                    "invalid relay ticket role '{other}'"
                )));
            }
        };
        let target_s = target_pub_or_wildcard
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("*");
        let ticket = self
            .identity
            .mint_relay_ticket(&relay_host, role_enum, target_s, now_unix(), ttl)
            .map_err(to_invalid_arg)?;
        let json = Zeroizing::new(canonical_json(&ticket).map_err(to_generic_err)?);
        Ok(json.to_string())
    }

    #[napi(js_name = "serveRelayV2")]
    pub async fn serve_relay_v2(
        &self,
        relay_url: String,
        expected_host: Option<String>,
        peer_id: Option<String>,
    ) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        self.sync_roster_from_store().await?;
        let secrets: Vec<[u8; 32]> = {
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(pid) = peer_id.as_deref().filter(|s| !s.is_empty()) {
                vec![lookup_v2_mailbox_secret_for_target(&roster, pid)?]
            } else {
                let list: Vec<[u8; 32]> = roster
                    .entries()
                    .filter(|(_, e)| e.state == PeerState::Active)
                    .filter_map(|(_, e)| e.v2_secrets.as_ref().map(|s| *s.mailbox_secret()))
                    .collect();
                if list.is_empty() {
                    return Err(to_generic_err(
                        "no active v2 peers with mailbox_secret in roster",
                    ));
                }
                list
            }
        };

        let mut bound_listeners: Vec<RelayV2Listener> = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let lcfg = RelayV2ListenerConfig {
                expected_host: expected_host.clone(),
                write_timeout: DEFAULT_WRITE_TIMEOUT,
                allow_insecure_ws: false,
                replay_cache: None,
                unix_secs: None,
                auth: cfg.relay_auth.clone(),
            };
            let listener = RelayV2Listener::bind_with_config(&relay_url, secret, lcfg)
                .await
                .map_err(to_generic_err)?;
            bound_listeners.push(listener);
        }
        let first_ep = bound_listeners.first().map(|l| l.local_endpoint());
        for listener in bound_listeners {
            self.announce
                .record_served(&listener.local_endpoint(), None)
                .await;
            self.spawn_listener(Box::new(listener));
        }
        Ok(first_ep.unwrap_or(relay_url))
    }

    #[napi(js_name = "pairV2Initiate")]
    pub async fn pair_v2_initiate(
        &self,
        endpoint: String,
        code: String,
        relay_host: Option<String>,
        name: Option<String>,
        kind: Option<String>,
        pinned_host_json: Option<String>,
    ) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        self.sync_roster_from_store().await?;
        let roster_snapshot = lock_roster(&self.roster).clone();

        let v2_pinned = match pinned_host_json.as_deref().filter(|s| !s.is_empty()) {
            Some(raw) => {
                let pin_in: NodePinnedHostInput =
                    serde_json::from_str(raw).map_err(|e| json_err("pinned_host_json", &e))?;
                let static_pub =
                    b64url_decode_array::<32>(&pin_in.static_pub_b64).map_err(to_invalid_arg)?;
                let signing_pin =
                    parse_signing_pin_b64(&pin_in.signing_pin_b64).map_err(to_invalid_arg)?;
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
                Some(V2PinnedHost::new(pinned, floor).map_err(to_invalid_arg)?)
            }
            None => None,
        };

        let v2_secret = if is_v2_relay_endpoint(&endpoint) {
            Some(lookup_v2_mailbox_secret_for_pair(
                &roster_snapshot,
                v2_pinned.as_ref().map(|p| &p.pinned),
                &endpoint,
                now_unix(),
            )?)
        } else {
            None
        };

        let device_name = name.unwrap_or_else(|| "node-device".to_owned());
        let device_kind = kind.unwrap_or_else(|| "node".to_owned());
        let mut stream =
            dial_endpoint_v2_with_options(&endpoint, relay_host.as_deref(), &cfg, v2_secret)
                .await
                .map_err(to_generic_err)?;
        let pair_res = if let Some(ref store) = self.store {
            drive_v2_pake_pair_initiator_with_store(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                v2_pinned,
                "paired-host".to_owned(),
                Vec::new(),
                store,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        } else {
            drive_v2_pake_pair_initiator_with_timeout(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                v2_pinned,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        let _ = stream.close().await;
        let pair_res = pair_res.map_err(to_generic_err)?;

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
                if self.store.is_some() {
                    self.sync_roster_from_store().await?;
                } else {
                    let mut roster = self
                        .roster
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    roster
                        .apply_v2_pair_initiator_outcome(
                            &pair_res.outcome,
                            h_id.clone(),
                            Vec::new(),
                        )
                        .map_err(to_generic_err)?;
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
            V2PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            V2PairOutcome::ResponderPending { .. } => {
                Err(to_generic_err("unexpected responder outcome"))
            }
        }
    }

    #[napi(js_name = "pairV2Accept")]
    pub async fn pair_v2_accept(&self, timeout_ms: Option<f64>) -> Result<String> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        let (mut stream, guard) = match self.router.recv_v2_pair(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting v2 pair")),
        };
        let path_kind = pairing_path_kind_for_provider(stream.provider_id());
        let pair_res = if let Some(ref store) = self.store {
            drive_v2_pake_pair_responder_with_store(
                stream.as_mut(),
                &self.identity,
                &self.pair_mgr,
                store,
                &self.store_lock,
                path_kind,
                now_unix(),
                &self.v2_state,
                Some(self.router.v2_pair_rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        } else {
            drive_v2_pake_pair_responder_with_options(
                stream.as_mut(),
                &self.identity,
                &self.pair_mgr,
                &self.roster,
                path_kind,
                now_unix(),
                &self.v2_state,
                Some(self.router.v2_pair_rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        let synced = self.sync_roster_from_store().await;
        let pair_res = pair_res.map_err(to_generic_err)?;
        synced?;

        match pair_res.outcome {
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
            V2PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            V2PairOutcome::InitiatorPending { .. } => {
                Err(to_generic_err("unexpected initiator outcome"))
            }
        }
    }

    /// Wire v2 Day-2 connect; `endpoint` as in `connect`. A configured wake target with an
    /// explicit endpoint wakes the host first, then connects through the same policy path.
    #[napi(js_name = "connectV2")]
    pub async fn connect_v2(
        &self,
        endpoint: Option<String>,
        target_host_id: String,
        grant_json: Option<String>,
        relay_host: Option<String>,
    ) -> Result<Session> {
        let endpoint = endpoint.filter(|e| !e.is_empty());
        let grant = parse_grant(grant_json.as_deref())?;
        let args = ConnectArgs {
            wire: 2,
            endpoint,
            grant,
            relay_host,
            ..ConnectArgs::default()
        };
        self.connect_policy(&target_host_id, args).await
    }

    /// Day-2 connect with every option in one JSON object: `wire` (`1` or `2`),
    /// `grant` (object), `endpoint`, `recovery_uri`, `replace_routes`, `route_policy` and
    /// `relay_host` (the expected relay challenge host of an explicit relay endpoint).
    #[napi]
    pub async fn connect_with_options(
        &self,
        target_host_id: String,
        options_json: String,
    ) -> Result<Session> {
        let opts: ConnectOptionsInput = parse_options(Some(&options_json), "options_json")?;
        let wire = opts.wire.unwrap_or(1);
        if wire != 1 && wire != 2 {
            return Err(to_invalid_arg("wire must be 1 or 2"));
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
        self.connect_policy(&target_host_id, args).await
    }

    /// Issues a pairing URI from the current announced route set.
    /// Options `{"kind": "auto"|"lan"|"remote", "host_name": str, "sign_routes": bool}`.
    #[napi]
    pub async fn issue_pairing_uri(&self, options_json: Option<String>) -> Result<String> {
        let opts: IssueUriOptions = parse_options(options_json.as_deref(), "options_json")?;
        let requested_kind = match opts.kind.as_deref() {
            None | Some("") => None,
            Some(k) if k.eq_ignore_ascii_case("auto") => None,
            Some(k) => Some(k.parse::<PairingCodeKind>().map_err(to_invalid_arg)?),
        };
        let sign_routes = opts
            .sign_routes
            .unwrap_or(self.snapshot_transport_cfg().sign_routes);
        let host_name = opts
            .host_name
            .unwrap_or_else(|| self.identity.host_id().to_owned());
        self.announce.settle().await;
        let announcer = self.announce.announcer()?;
        let mgr = Arc::clone(&self.pair_mgr);
        // The announcer publishes before it takes the manager (runtime lock order); this call
        // must not hold the manager.
        let issued = tokio::task::spawn_blocking(move || {
            announcer.issue_pairing_uri(
                &mgr,
                &host_name,
                IssueOptions {
                    requested_kind,
                    sign_routes,
                },
                unix_ms(),
            )
        })
        .await
        .map_err(to_generic_err)?
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
    }

    /// Pairs over Wire v1 from a scanned pairing URI: races its hints (or only
    /// `options.endpoint`) and persists the routes `options.route_policy` allows.
    /// Options `{"route_policy", "save_route", "endpoint", "code"}`.
    #[napi]
    pub async fn pair_uri(
        &self,
        pairing_uri: String,
        name: Option<String>,
        kind: Option<String>,
        options_json: Option<String>,
    ) -> Result<String> {
        self.pair_uri_impl(false, &pairing_uri, name, kind, options_json)
            .await
    }

    /// As `pairUri` over Wire v2 PAKE, one rung at a time.
    #[napi(js_name = "pairV2Uri")]
    pub async fn pair_v2_uri(
        &self,
        pairing_uri: String,
        name: Option<String>,
        kind: Option<String>,
        options_json: Option<String>,
    ) -> Result<String> {
        self.pair_uri_impl(true, &pairing_uri, name, kind, options_json)
            .await
    }

    /// Replaces the peer's `operator` routes. `routes_json` is a JSON array of endpoint strings
    /// (at most six; an empty array clears them). Returns the peer's full route list.
    #[napi]
    pub async fn set_peer_routes(&self, peer_id: String, routes_json: String) -> Result<String> {
        let raw: Vec<String> = serde_json::from_str(&routes_json)
            .map_err(|e| json_err("routes_json (expected an array of strings)", &e))?;
        let routes = update_roster_async(
            self.store.as_ref(),
            &self.store_lock,
            &self.roster,
            &self.identity,
            move |roster| set_peer_routes(roster, &peer_id, &raw),
        )
        .await?;
        Ok(routes_json_array(&routes).to_string())
    }

    /// `{"routes": [{"hint", "source"}], "route_meta": {"seq", "issued_at", "origin"} | null,
    /// "last_route_set": {"outcome", "seq"} | null}` for one peer.
    #[napi]
    pub async fn peer_routes(&self, peer_id: String) -> Result<String> {
        self.sync_roster_from_store().await?;
        let last = self.access.last_route_set(&peer_id);
        let view =
            peer_routes(&lock_roster(&self.roster), &peer_id, last).map_err(to_generic_err)?;
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
    }

    /// Removes the peer's routes of `source` (`"operator"` when omitted, `"signed"`,
    /// `"committed"` or `"all"`).
    #[napi]
    pub async fn clear_peer_routes(&self, peer_id: String, source: Option<String>) -> Result<()> {
        let source = match source.as_deref() {
            None | Some("" | "operator") => Some(RouteSource::Operator),
            Some("signed") => Some(RouteSource::Signed),
            Some("committed") => Some(RouteSource::Committed),
            Some("all") => None,
            Some(other) => {
                return Err(to_invalid_arg(format!("invalid route source '{other}'")));
            }
        };
        update_roster_async(
            self.store.as_ref(),
            &self.store_lock,
            &self.roster,
            &self.identity,
            move |roster| clear_peer_routes(roster, &peer_id, source),
        )
        .await
    }

    /// Applies a fresh signed pairing URI to the matching paired host offline. Options
    /// `{"replace_routes", "route_policy"}`. Returns `{"peer_id", "applied", "reason",
    /// "route_seq"}`.
    #[napi]
    pub async fn apply_route_uri(
        &self,
        pairing_uri: String,
        options_json: Option<String>,
    ) -> Result<String> {
        let opts: ApplyRouteOptions = parse_options(options_json.as_deref(), "options_json")?;
        let policy = parse_route_policy(
            opts.route_policy.as_deref(),
            self.snapshot_transport_cfg().route_policy,
        )?;
        let uri = PairingUri::parse(&pairing_uri).map_err(to_invalid_arg)?;
        let apply = RouteApplyOpts {
            policy,
            replace_routes: opts.replace_routes.unwrap_or(false),
        };
        let res = update_roster_async(
            self.store.as_ref(),
            &self.store_lock,
            &self.roster,
            &self.identity,
            move |roster| apply_signed_route_uri(roster, &uri, apply),
        )
        .await?;
        Ok(serde_json::json!({
            "peer_id": res.peer_id,
            "applied": res.applied,
            "reason": res.reason,
            "route_seq": res.route_meta.map(|m| m.seq),
        })
        .to_string())
    }

    /// Re-scans the host's addresses and publishes the announced route set. `snapshot_json` is
    /// the complete current network snapshot `{"networks": [{"id", "iface", "if_index",
    /// "transports", "addrs"}]}`; `null` re-enumerates natively (or reuses the retained
    /// snapshot after one was passed). Returns `{"route_seq", "changed"}`.
    #[napi]
    pub async fn refresh_routes(&self, snapshot_json: Option<String>) -> Result<String> {
        let snapshot = snapshot_json
            .filter(|s| !s.is_empty())
            .map(|s| NetworkSnapshot::from_json(&s))
            .transpose()
            .map_err(rt_invalid_arg)?;
        self.announce.settle().await;
        let announcer = self.announce.announcer()?;
        let out = tokio::task::spawn_blocking(move || announcer.refresh(unix_ms(), snapshot))
            .await
            .map_err(to_generic_err)?
            .map_err(to_generic_err)?;
        Ok(serde_json::json!({
            "route_seq": out.route_seq(),
            "changed": out.changed,
        })
        .to_string())
    }

    #[napi(js_name = "acceptV2")]
    pub async fn accept_v2(&self, timeout_ms: Option<f64>) -> Result<Session> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        let (stream, guard) = match self.router.recv_v2_session(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting v2 session")),
        };
        let driver_res = if let Some(ref store) = self.store {
            V2SessionDriver::accept_with_store(
                stream,
                &self.identity,
                store,
                &self.store_lock,
                now_unix(),
                &self.v2_state,
                Some(self.router.v2_session_rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        } else {
            V2SessionDriver::accept_locked(
                stream,
                &self.identity,
                &self.roster,
                now_unix(),
                &self.v2_state,
                Some(self.router.v2_session_rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        match driver_res {
            Ok(driver) => {
                self.sync_roster_from_store().await?;
                self.accepted_session(SessionBackend::V2(Arc::new(driver.into_concurrent())))
                    .await
            }
            Err(e) => {
                let _ = self.sync_roster_from_store().await;
                Err(to_generic_err(e))
            }
        }
    }

    #[napi]
    pub fn close(&self) {
        self.announce.stop();
        self.router.close();
        let pools: Vec<Arc<GroupPool>> = self
            .groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .filter_map(|w| w.upgrade())
            .collect();
        within_runtime_if_available(|| {
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

    fn peer_device_id(&self) -> Option<String> {
        match self {
            Self::V1(s) => s.peer_device_id(),
            Self::V2(s) => Some(s.peer_device_id().to_owned()),
        }
    }

    async fn send_data(&self, payload: &[u8]) -> std::result::Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_data(payload).await,
            Self::V2(s) => s.send_data(payload).await,
        }
    }

    async fn next_event_locked_now(
        &self,
        roster: &StdMutex<Roster>,
    ) -> std::result::Result<Option<SessionEvent>, RuntimeError> {
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
    ) -> (
        std::result::Result<(), CoreError>,
        tendril_core::grants::AuditEvent,
    ) {
        match self {
            Self::V1(s) => s.authorize_locked(requested_cap, now_unix, roster),
            Self::V2(s) => s.authorize_locked(requested_cap, now_unix, roster),
        }
    }

    async fn send_rekey(&self) -> std::result::Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_rekey().await,
            Self::V2(s) => s.send_rekey().await,
        }
    }

    async fn send_close(&self, code: u16, reason: &str) -> std::result::Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_close(code, reason).await,
            Self::V2(s) => s.send_close(code, reason).await,
        }
    }
}

#[napi]
pub struct Session {
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    session: Arc<SessionBackend>,
    /// `true` for a session this endpoint dialed: only an initiator maps a refusal close.
    initiator: bool,
}

impl Session {
    /// Hands an ordinary-session `0x0A`/`0x0B` to the runtime when the endpoint has a state
    /// store and reports the redacted outcome. Store-less endpoints surface the unverified
    /// event instead.
    async fn group_frame_json(&self, ev: SessionEvent) -> Result<serde_json::Value> {
        if let Some(store) = self.store.as_ref() {
            let peer = self.session.peer_device_id().ok_or_else(|| {
                Error::new(Status::GenericFailure, "session peer is not authenticated")
            })?;
            let store = Arc::clone(store);
            let local_id = self.identity.device_id();
            let probe = ev.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                handle_session_group_frame(&store, &local_id, &peer, &probe)
            })
            .await
            .map_err(to_generic_err)?;
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
            _ => Err(Error::new(
                Status::GenericFailure,
                "not a group frame event",
            )),
        }
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

#[napi]
impl Session {
    #[napi(getter)]
    pub fn peer_id(&self) -> Result<String> {
        self.session
            .peer_device_id()
            .ok_or_else(|| Error::new(Status::GenericFailure, "session peer is not authenticated"))
    }

    #[napi]
    pub async fn send_data(&self, payload: Buffer) -> Result<()> {
        self.session
            .send_data(payload.as_ref())
            .await
            .map_err(|e| session_err(&e, e.to_string()))
    }

    #[napi]
    pub async fn poll_event(&self, timeout_ms: Option<f64>) -> Result<String> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        match timeout(wait, self.session.next_event_locked_now(&self.roster)).await {
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
                        if matches!(self.session.as_ref(), SessionBackend::V2(_)) {
                            sync_roster_async(
                                self.store.as_ref(),
                                &self.store_lock,
                                &self.roster,
                                &self.identity,
                            )
                            .await?;
                        } else {
                            commit_session_async(
                                self.store.as_ref(),
                                &self.store_lock,
                                &self.roster,
                                &self.identity,
                            )
                            .await?;
                        }
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
                        self.group_frame_json(ev).await?
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
                        "refusal": self
                            .initiator
                            .then(|| RefusalReason::from_close_code(code))
                            .flatten()
                            .map(refusal_name),
                    }),
                };
                Ok(json.to_string())
            }
            Ok(Ok(None)) => Ok(serde_json::json!({ "status": "eof" }).to_string()),
            Ok(Err(e)) => {
                if matches!(self.session.as_ref(), SessionBackend::V2(_)) {
                    let _ = sync_roster_async(
                        self.store.as_ref(),
                        &self.store_lock,
                        &self.roster,
                        &self.identity,
                    )
                    .await;
                    Err(session_err(&e, e.to_string()))
                } else if let Err(pe) = commit_session_async(
                    self.store.as_ref(),
                    &self.store_lock,
                    &self.roster,
                    &self.identity,
                )
                .await
                {
                    Err(session_err(&e, format!("{e} ({pe})")))
                } else {
                    Err(session_err(&e, e.to_string()))
                }
            }
            Err(_) => Ok(serde_json::json!({ "status": "would_block" }).to_string()),
        }
    }

    #[napi]
    pub async fn authorize(&self, requested_cap: String) -> bool {
        self.session
            .authorize_locked(&requested_cap, now_unix(), &self.roster)
            .0
            .is_ok()
    }

    #[napi]
    pub async fn rekey(&self) -> Result<()> {
        self.session
            .send_rekey()
            .await
            .map_err(|e| session_err(&e, e.to_string()))
    }

    #[napi]
    pub async fn close(&self, code: Option<f64>, reason: Option<String>) -> Result<()> {
        let close_code = f64_to_u16(code, 1000, "code")?;
        self.session
            .send_close(close_code, reason.as_deref().unwrap_or("normal"))
            .await
            .map_err(|e| session_err(&e, e.to_string()))
    }
}

fn manifest_json(manifest: &GroupManifest) -> Result<String> {
    let bytes = manifest.to_wire_bytes().map_err(to_generic_err)?;
    String::from_utf8(bytes).map_err(to_generic_err)
}

fn report_json(report: &BroadcastReport) -> Result<String> {
    serde_json::to_string(report).map_err(to_generic_err)
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

#[napi]
pub struct Group {
    pool: Arc<GroupPool>,
    local_endpoint: Option<String>,
}

impl Group {
    fn ensure_open(&self) -> Result<()> {
        if self.pool.is_closed() {
            return Err(Error::new(Status::GenericFailure, "group is closed"));
        }
        Ok(())
    }
}

#[napi]
impl Group {
    #[napi(getter)]
    pub fn group_id(&self) -> String {
        self.pool.group_id().to_owned()
    }

    #[napi(getter)]
    pub fn local_endpoint(&self) -> Option<String> {
        self.local_endpoint.clone()
    }

    #[napi]
    pub async fn broadcast(&self, data: Buffer, required_cap: Option<String>) -> Result<String> {
        self.ensure_open()?;
        let cap = required_cap.filter(|s| !s.is_empty());
        let report = self
            .pool
            .broadcast(cap.as_deref(), data.as_ref())
            .await
            .map_err(to_generic_err)?;
        report_json(&report)
    }

    #[napi]
    pub async fn sync(&self) -> Result<String> {
        self.ensure_open()?;
        let report = self.pool.sync().await.map_err(to_generic_err)?;
        report_json(&report)
    }

    #[napi]
    pub async fn poll_event(&self, timeout_ms: Option<f64>) -> Result<Option<String>> {
        self.ensure_open()?;
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        Ok(self
            .pool
            .poll_event(wait)
            .await
            .map(|ev| group_event_json(&ev)))
    }

    #[napi]
    pub fn authorize_peer(&self, peer_id: String, cap: String) -> Result<bool> {
        self.ensure_open()?;
        self.pool
            .authorize_peer(&peer_id, &cap)
            .map(|()| true)
            .map_err(to_generic_err)
    }

    #[napi]
    pub async fn close(&self) {
        self.pool.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendril_core::grants::{RevocationListUnsigned, sign_crl};

    fn attempt(error: RuntimeError, committed: bool, failures: Vec<RuntimeError>) -> AttemptError {
        AttemptError {
            error,
            committed,
            skipped: Vec::new(),
            failures: failures
                .into_iter()
                .map(|error| tendril_runtime::driver::CandidateFailure {
                    hint: "direct:127.0.0.1:9".to_owned(),
                    provider: ProviderId::Direct,
                    error,
                })
                .collect(),
        }
    }

    fn wake_config(pre_wake: bool, max_attempts: usize) -> WakeTransportSettings {
        let mut spec = WakeConfigSpec::default();
        spec.wake_url = Some("http://127.0.0.1:9/".to_owned());
        spec.wake_adapter = Some(WakeAdapterKind::Webhook);
        spec.wake_secret_b64 = Some(b64url_encode(&[7u8; 32]));
        spec.wake_pre_wake = Some(pre_wake);
        spec.wake_retry_delay_ms = Some(0);
        spec.wake_max_attempts = Some(max_attempts);
        spec.wake_timeout_ms = Some(50);
        spec.wake_coalesce_secs = Some(0);
        build_wake_provider(spec).unwrap().unwrap()
    }

    /// Runs `connect_with_wake_policy` against a connect that always fails with `attempts`'
    /// outcome and returns how many connects ran: the call site's retry decision.
    async fn connects_run(wake: &WakeTransportSettings, make: impl Fn() -> AttemptError) -> usize {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let res: std::result::Result<((), _), AttemptError> =
            connect_with_wake_policy(&wake.to_dial_options(), || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let err = make();
                async move { Err(err) }
            })
            .await;
        assert!(res.is_err());
        calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test]
    async fn wake_retries_transport_misses_and_relay_offline_only() {
        let offline = || RuntimeError::RelayOffline(tendril_runtime::RelayOffline::V2Dial);
        let io = || RuntimeError::Io(std::io::Error::other("refused"));
        let wake = wake_config(false, 3);
        // Wakeable: retried up to max_attempts after the first connect.
        assert_eq!(
            connects_run(&wake, || attempt(io(), false, vec![io()])).await,
            4
        );
        assert_eq!(
            connects_run(&wake, || attempt(RuntimeError::Closed, false, vec![])).await,
            4
        );
        assert_eq!(
            connects_run(&wake, || attempt(offline(), false, vec![offline()])).await,
            4
        );
        // Fail fast: one connect, no wake: committed, auth, policy and other refusals.
        assert_eq!(
            connects_run(&wake, || attempt(offline(), true, vec![offline()])).await,
            1
        );
        assert_eq!(
            connects_run(&wake, || attempt(
                offline(),
                false,
                vec![
                    offline(),
                    RuntimeError::Protocol("relay_auth_unconfigured: x".to_owned())
                ]
            ))
            .await,
            1
        );
        assert_eq!(
            connects_run(&wake, || attempt(
                RuntimeError::Protocol("relay dial rejected: unauthorized".to_owned()),
                false,
                vec![]
            ))
            .await,
            1
        );
        assert_eq!(
            connects_run(&wake, || attempt(
                RuntimeError::Core(tendril_core::error::CoreError::IncompletePin(
                    "x".to_owned()
                )),
                false,
                vec![]
            ))
            .await,
            1
        );
    }

    fn net_config(json: &str) -> EndpointTransportConfig {
        let input: TransportConfigInput = serde_json::from_str(json).expect("json");
        EndpointTransportConfig::from_input(input).expect("config")
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

        for raw in [
            r#"{"p2p_relay_mode":"disabled","p2p_port_mapping":false,
                "p2p_bind_addrs":["127.0.0.1:0"]}"#,
            r#"{"p2pRelayMode":"disabled","p2pPortMapping":false,
                "p2pBindAddrs":["127.0.0.1:0"]}"#,
        ] {
            let cfg = net_config(raw);
            let id = "58".to_owned() + &"66".repeat(31);
            let endpoint = format!("iroh://{id}");
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
    }

    #[test]
    fn invalid_bind_addr_is_a_config_error_naming_the_key() {
        let input: TransportConfigInput =
            serde_json::from_str(r#"{"p2p_bind_addrs":["nope"]}"#).expect("json");
        let err = EndpointTransportConfig::from_input(input).expect_err("bad");
        assert!(err.reason.contains("p2p_bind_addrs"), "{}", err.reason);
    }

    #[test]
    fn n0_alias_selects_the_public_relays() {
        let cfg = net_config(r#"{"p2p_relay_mode":"n0"}"#);
        let opts = cfg.build_p2p_listener_options(None).unwrap();
        assert!(matches!(opts.relay_mode, P2pRelayMode::N0Public));
    }

    #[test]
    fn custom_relay_uri_disables_default_relays_and_pkarr() {
        let id = "58".to_owned() + &"66".repeat(31);
        let uri = format!("iroh://{id}?relay=http://127.0.0.1:9/");
        let uri = uri.as_str();
        let mut cfg = EndpointTransportConfig::default();
        cfg.p2p_allow_private_addrs = Some(true);
        let opts = cfg.build_p2p_dialer_options(uri, None).unwrap();
        assert!(matches!(opts.relay_mode, P2pRelayMode::Custom(_)));
        assert!(!opts.resolve_pkarr);
        assert!(!opts.publish_pkarr);

        let plain = cfg
            .build_p2p_dialer_options(&format!("iroh://{id}"), None)
            .unwrap();
        assert!(matches!(plain.relay_mode, P2pRelayMode::N0Public));
        assert!(plain.resolve_pkarr);

        let mut pinned = EndpointTransportConfig::default();
        pinned.p2p_relay_mode = Some(P2pRelayMode::Disabled);
        let opts = pinned.build_p2p_dialer_options(uri, None).unwrap();
        assert!(matches!(opts.relay_mode, P2pRelayMode::Disabled));
    }

    #[test]
    fn group_dialer_needs_an_explicit_relay_mode() {
        let mut cfg = EndpointTransportConfig::default();
        cfg.p2p_pkarr = Some(true);
        cfg.p2p_advertise_direct_addrs = Some(true);
        cfg.p2p_allow_private_addrs = Some(true);
        cfg.p2p_relay_auth = Some(P2pRelayAuth::BearerToken("tok".to_owned().into()));
        assert!(cfg.build_p2p_group_options().is_none());

        cfg.p2p_relay_mode = Some(P2pRelayMode::Custom("https://relay.example/".to_owned()));
        let opts = cfg.build_p2p_group_options().expect("explicit mode");
        assert!(matches!(opts.relay_mode, P2pRelayMode::Custom(_)));
        assert!(opts.relay_auth.is_some());
    }

    #[test]
    fn dialer_options_reject_untrusted_relay_uri_without_private_opt_in() {
        let cfg = EndpointTransportConfig::default();
        assert!(
            cfg.build_p2p_dialer_options(
                &format!(
                    "iroh://{}?relay=http://127.0.0.1:9/",
                    "58".to_owned() + &"66".repeat(31)
                ),
                None
            )
            .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v1_host_rotation_persists_to_disk_and_memory() {
        use tendril_core::crypto::{SigningKeypair, StaticKeypair};

        let uniq = format!(
            "tendril-node-rot-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base_dir = std::env::temp_dir().join(uniq);
        let host_dir = base_dir.join("host");
        let cli_dir = base_dir.join("cli");
        std::fs::create_dir_all(&host_dir).unwrap();
        std::fs::create_dir_all(&cli_dir).unwrap();

        let host_ep = Endpoint::new(
            Some(host_dir.to_string_lossy().into_owned()),
            Some("rot-host".to_owned()),
        )
        .unwrap();
        let cli_ep = Endpoint::new(
            Some(cli_dir.to_string_lossy().into_owned()),
            Some("rot-cli".to_owned()),
        )
        .unwrap();

        let addr = host_ep
            .serve_direct(Some("127.0.0.1:0".to_owned()))
            .await
            .unwrap();
        let code = host_ep.issue_code(Some("lan".to_owned())).unwrap();
        let (cli_pair_raw, host_acc_raw) = tokio::join!(
            cli_ep.pair_initiate(
                addr,
                code,
                None,
                Some("rot-cli".to_owned()),
                Some("node".to_owned()),
            ),
            host_ep.pair_accept(Some(5000.0)),
        );
        let cli_pair: serde_json::Value = serde_json::from_str(&cli_pair_raw.unwrap()).unwrap();
        let host_acc: serde_json::Value = serde_json::from_str(&host_acc_raw.unwrap()).unwrap();
        let sas = cli_pair["sas"].as_str().unwrap().to_owned();
        let dev_id = host_acc["device_id"].as_str().unwrap().to_owned();

        tokio::task::block_in_place(|| {
            host_ep
                .confirm_peer(dev_id.clone(), Some(sas.clone()))
                .unwrap();
            cli_ep
                .confirm_peer("rot-host".to_owned(), Some(sas))
                .unwrap();
        });
        host_ep.close();

        let host_store = StateStore::open_or_create(&host_dir).unwrap();
        let mut host_id = host_store.load_or_generate_identity(None).unwrap();
        host_id
            .rotate(
                StaticKeypair::generate().unwrap(),
                SigningKeypair::generate().unwrap(),
                now_unix(),
            )
            .unwrap();
        let expected_static = *host_id.static_key().public_bytes();
        let expected_signing = host_id.signing_key().public_key().clone();
        let mut host_roster = host_store.load_roster().unwrap();
        let grant = host_roster
            .mint_grant(
                &host_id,
                &dev_id,
                vec!["fs.read".to_owned()],
                now_unix(),
                now_unix() + 3600,
                random_bytes::<16>().unwrap(),
            )
            .unwrap();
        let grant_json = serde_json::to_string(&grant).unwrap();
        let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let v1_ep = listener.local_endpoint();
        let accept_task = tokio::spawn(async move {
            let mut r = host_roster;
            let stream = listener.accept().await.unwrap();
            SessionDriver::accept(stream, &host_id, &mut r, now_unix(), None)
                .await
                .unwrap()
        });

        let sess = cli_ep
            .connect(Some(v1_ep), "rot-host".to_owned(), Some(grant_json), None)
            .await
            .unwrap();
        let _host_drv = accept_task.await.unwrap();
        drop(sess);

        let mem_entry = lock_roster(&cli_ep.roster)
            .get("rot-host")
            .cloned()
            .expect("rot-host in memory");
        assert_eq!(mem_entry.rotation_seq, 1);
        assert_eq!(mem_entry.static_pub, expected_static);
        assert_eq!(mem_entry.signing_pub.as_ref(), Some(&expected_signing));

        let disk_roster = StateStore::open_or_create(&cli_dir)
            .unwrap()
            .load_roster()
            .unwrap();
        let disk_entry = disk_roster.get("rot-host").expect("rot-host on disk");
        assert_eq!(disk_entry.rotation_seq, 1);
        assert_eq!(disk_entry.static_pub, expected_static);
        assert_eq!(disk_entry.signing_pub.as_ref(), Some(&expected_signing));

        cli_ep.close();
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_mid_session_crl_revocation_closes_session() {
        let uniq = format!(
            "tendril-node-crl-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base_dir = std::env::temp_dir().join(uniq);
        let host_dir = base_dir.join("host");
        let cli_dir = base_dir.join("cli");
        std::fs::create_dir_all(&host_dir).unwrap();
        std::fs::create_dir_all(&cli_dir).unwrap();

        let host_ep = Endpoint::new(
            Some(host_dir.to_string_lossy().into_owned()),
            Some("crl-host".to_owned()),
        )
        .unwrap();
        let cli_ep = Endpoint::new(
            Some(cli_dir.to_string_lossy().into_owned()),
            Some("crl-cli".to_owned()),
        )
        .unwrap();

        let addr = host_ep
            .serve_direct(Some("127.0.0.1:0".to_owned()))
            .await
            .unwrap();
        let code = host_ep.issue_code(Some("lan".to_owned())).unwrap();
        let (cli_pair_raw, host_acc_raw) = tokio::join!(
            cli_ep.pair_v2_initiate(
                addr.clone(),
                code,
                None,
                Some("crl-cli".to_owned()),
                Some("node".to_owned()),
                None,
            ),
            host_ep.pair_v2_accept(Some(5000.0)),
        );
        let cli_pair: serde_json::Value = serde_json::from_str(&cli_pair_raw.unwrap()).unwrap();
        let host_acc: serde_json::Value = serde_json::from_str(&host_acc_raw.unwrap()).unwrap();
        let sas = cli_pair["sas"].as_str().unwrap().to_owned();
        let dev_id = host_acc["device_id"].as_str().unwrap().to_owned();

        let grant_json = tokio::task::block_in_place(|| {
            host_ep
                .confirm_peer(dev_id.clone(), Some(sas.clone()))
                .unwrap();
            cli_ep
                .confirm_peer("crl-host".to_owned(), Some(sas))
                .unwrap();
            host_ep
                .mint_grant(dev_id, vec!["fs.read".to_owned()], Some(3600.0))
                .unwrap()
        });
        let grant: Grant = serde_json::from_str(&grant_json).unwrap();
        let crl_ts = grant.not_before.clone();
        let revoked_nonce = grant.nonce.clone();
        host_ep.close();

        let host_store = StateStore::open_or_create(&host_dir).unwrap();
        let host_id = host_store.load_or_generate_identity(None).unwrap();
        let mut host_roster = host_store.load_roster().unwrap();
        let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let v2_ep = listener.local_endpoint();
        let accept_handle = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            let mut drv = V2SessionDriver::accept(
                stream,
                &host_id,
                &mut host_roster,
                now_unix(),
                &Default::default(),
                None,
            )
            .await
            .unwrap();
            let crl = sign_crl(
                RevocationListUnsigned {
                    v: 1,
                    issuer: host_id.host_id().to_owned(),
                    seq: 1,
                    revoked_devices: Vec::new(),
                    revoked_nonces: vec![revoked_nonce],
                    ts: crl_ts,
                },
                host_id.signing_key(),
            )
            .unwrap();
            drv.send_revocation(&crl).await.unwrap();
            drv
        });

        let cli_sess = cli_ep
            .connect_v2(Some(v2_ep), "crl-host".to_owned(), Some(grant_json), None)
            .await
            .unwrap();
        let mut closed_or_err = false;
        for _ in 0..4 {
            match cli_sess.poll_event(Some(2000.0)).await {
                Ok(ev_raw) => {
                    let ev: serde_json::Value = serde_json::from_str(&ev_raw).unwrap();
                    if ev["event"] == "closed" || ev["status"] == "eof" {
                        closed_or_err = true;
                        break;
                    }
                }
                Err(_) => {
                    closed_or_err = true;
                    break;
                }
            }
        }
        assert!(
            closed_or_err,
            "expected mid-session CRL revocation to close or error session"
        );
        assert!(!cli_sess.authorize("fs.read".to_owned()).await);
        let _ = accept_handle.await;
        cli_ep.close();

        let reloaded_roster = StateStore::open_or_create(&cli_dir)
            .unwrap()
            .load_roster()
            .unwrap();
        let persisted_crl = reloaded_roster
            .crl("crl-host")
            .expect("persisted CRL across reload");
        assert_eq!(persisted_crl.seq, 1);
        assert_eq!(persisted_crl.revoked_nonces, vec![grant.nonce]);

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn publish_roster_keeps_anchor_signed_crl() {
        use tendril_core::crypto::SigningKeypair;
        use tendril_core::grants::{RevocationListUnsigned, sign_crl};

        let identity = EndpointIdentity::generate().unwrap();
        let anchor = SigningKeypair::generate().unwrap();
        let anchor_id = "anchor-a".to_owned();
        let mut disk = Roster::default();
        disk.add_trust_anchor(anchor_id.clone(), anchor.public_key().clone())
            .unwrap();
        let mut mem = disk.clone();
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: anchor_id.clone(),
                seq: 1,
                revoked_devices: vec!["dev-gone".to_owned()],
                revoked_nonces: Vec::new(),
                ts: "2026-01-01T00:00:00Z".to_owned(),
            },
            &anchor,
        )
        .unwrap();
        mem.ingest_crl(crl, &anchor_id, anchor.public_key())
            .unwrap();
        publish_roster(&mut mem, disk, &identity);
        assert!(mem.crl(&anchor_id).is_some(), "anchor CRL dropped on merge");
    }
}
