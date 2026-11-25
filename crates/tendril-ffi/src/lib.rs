//! Callback-free polled C ABI over `tendril-core` and `tendril-runtime`.
#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::fmt;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, b64url_decode,
    b64url_decode_array, b64url_encode, compute_code_mac, device_id, fingerprint_device,
    fingerprint_host, pairing_sas, random_bytes,
};
use tendril_core::error::CoreError;
use tendril_core::grants::{Grant, RevocationList, authorize_grant, canonical_json};
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, verify_rotation_chain,
};
use tendril_core::pairing::{
    DroppedHint, EnrollmentPolicy, IssueOptions, PairAction, PairOutcome, PairingCodeKind,
    PairingConfig, PairingInitiator, PairingManager, PairingUri, PersistOpts, PinnedHost,
    RoutePolicy, mint_enrollment_token,
};
use tendril_core::policy::{CandidateEndpoint, ProviderId};
use tendril_core::relay_auth::{RelayAuthRole, RelayAuthSecret, RelayTicket, origin_allowed};
use tendril_core::roster::{AnchorState, PeerState, Roster, RouteMeta, RouteSource, StoredRoute};
use tendril_core::v2::{
    V2PairOutcome, V2PinnedHost, canonical_relay_host, derive_epoch_mailbox_window,
};
use tendril_runtime::announce::unix_ms;
use tendril_runtime::driver::{AttemptError, ConnectOpts, PairPolicyOptions};
use tendril_runtime::providers::SkippedHint;
use tendril_runtime::providers::hints::{
    HintDialerConfig, HintDialers, RouteApplyOpts, apply_signed_route_uri, clear_peer_routes_in,
    peer_routes_in, set_peer_routes_in,
};
use tendril_runtime::redact::{redact_error, redact_hint, redact_json_error, redact_text};
use tendril_runtime::{
    AddressSource, AdvertiseInputs, AdvertiseMode, BrokerDialer, ConcurrentSession,
    ConcurrentV2Session, DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT, DirectDialer,
    DirectListener, GroupEvent, GroupFrameKind, GroupFrameOutcome, GroupHub, GroupPool,
    GroupPoolConfig, HttpWakeProvider, InboundQueue, InboundRouter, InboundSession, LastRouteSet,
    LocalDialer, MAX_OUTER_FRAME_LEN, NetworkSnapshot, OverlayDialer, PathDialer, PathListener,
    PathStream, PreAuthRateLimiter, RelayClientAuth, RelayDialer, RelayListener, RelayV2Dialer,
    RelayV2Listener, RelayV2ListenerConfig, RosterAccess, RouteAnnouncer, RouteSetSink,
    RuntimeError, ServedListener, SessionDriver, SessionEvent, StateStore, V2ResponderState,
    V2SessionDriver, WakeAdapterKind, WakeProvider, WakeSecret, WakeTarget,
    deserialize_identity_json, dial_endpoint_with_auth, drive_m2m_enroll_initiator_with_floor,
    drive_pair_responder_with_policy, drive_pair_responder_with_store,
    drive_v2_pake_pair_initiator_with_timeout, drive_v2_pake_pair_responder_with_options,
    drive_v2_pake_pair_responder_with_store, group_add_member, group_create, group_ingest_manifest,
    group_remove_member, handle_session_group_frame, pairing_path_kind_for_provider,
    pinned_pairing_floor, recv_routed, serialize_identity_json,
};
#[cfg(feature = "p2p-iroh")]
use tendril_runtime::{
    P2pDialer, P2pListener, P2pOptions, P2pRelayAuth, P2pRelayMode, parse_p2p_relay_mode,
    parse_p2p_relay_modes,
};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::time::{timeout, timeout_at};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const TENDRIL_OK: i32 = 0;
pub const TENDRIL_WOULD_BLOCK: i32 = 1;
pub const TENDRIL_EOF: i32 = 2;
pub const TENDRIL_ERR_INVALID_ARG: i32 = -1;
pub const TENDRIL_ERR_NOT_FOUND: i32 = -2;
pub const TENDRIL_ERR_CLOSED: i32 = -5;
pub const TENDRIL_ERR_PROTOCOL: i32 = -6;
pub const TENDRIL_ERR_INTERNAL: i32 = -7;

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Stores `msg` for [`tendril_last_error`] in redacted form: the shared runtime scrubber
/// ([`redact_text`]) keeps only `scheme://host[:port]` of a URL, masks pairing codes and redacts
/// a quoted value to the end of its line, so raw caller input never reaches a host app's logs.
fn set_last_error(msg: impl Into<String>) {
    let s = redact_text(&msg.into());
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = s;
    });
}

/// `invalid <name>: invalid JSON (<category>) at line L column C`. A serde message can quote a
/// field name or value (a code, a URI), so only its category and position are reported.
fn json_error(name: &str, err: &serde_json::Error) -> String {
    format!("invalid {name}: {}", redact_json_error(err))
}

fn clear_last_error() {
    LAST_ERROR.with(|cell| {
        cell.borrow_mut().clear();
    });
}

fn ffi_i32<F: FnOnce() -> i32>(f: F) -> i32 {
    clear_last_error();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(rc) => rc,
        Err(_) => {
            set_last_error("unexpected panic inside tendril-ffi");
            TENDRIL_ERR_INTERNAL
        }
    }
}

fn ffi_ptr<T, F: FnOnce() -> *mut T>(f: F) -> *mut T {
    clear_last_error();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(p) => p,
        Err(_) => {
            set_last_error("unexpected panic inside tendril-ffi");
            ptr::null_mut()
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

unsafe fn cstr_to_str<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, i32> {
    if ptr.is_null() {
        set_last_error(format!("null pointer for {name}"));
        return Err(TENDRIL_ERR_INVALID_ARG);
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|_| {
        set_last_error(format!("invalid UTF-8 in {name}"));
        TENDRIL_ERR_INVALID_ARG
    })
}

unsafe fn opt_cstr_to_str<'a>(ptr: *const c_char, name: &str) -> Result<Option<&'a str>, i32> {
    if ptr.is_null() {
        return Ok(None);
    }
    unsafe { cstr_to_str(ptr, name) }.map(Some)
}

unsafe fn read_bytes32(ptr: *const u8, name: &str) -> Result<[u8; 32], i32> {
    if ptr.is_null() {
        set_last_error(format!("null 32-byte pointer for {name}"));
        return Err(TENDRIL_ERR_INVALID_ARG);
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, 32) };
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

unsafe fn read_hybrid_signing_pub(
    ptr: *const u8,
    len: usize,
    name: &str,
) -> Result<HybridSigningPublicKey, i32> {
    if ptr.is_null() {
        set_last_error(format!("null pointer for {name}"));
        return Err(TENDRIL_ERR_INVALID_ARG);
    }
    if len != HYBRID_SIGNING_PUB_LEN {
        set_last_error(format!(
            "invalid {name} length {len}, expected {HYBRID_SIGNING_PUB_LEN}"
        ));
        return Err(TENDRIL_ERR_INVALID_ARG);
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    HybridSigningPublicKey::from_bytes(slice).map_err(|e| {
        set_last_error(format!("invalid {name}: {e}"));
        TENDRIL_ERR_INVALID_ARG
    })
}

unsafe fn read_signing_pin(ptr: *const u8, len: usize, name: &str) -> Result<SigningKeyPin, i32> {
    if ptr.is_null() {
        set_last_error(format!("null pointer for {name}"));
        return Err(TENDRIL_ERR_INVALID_ARG);
    }
    if len == HYBRID_SIGNING_PUB_LEN {
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        HybridSigningPublicKey::from_bytes(slice)
            .map(SigningKeyPin::Full)
            .map_err(|e| {
                set_last_error(format!("invalid {name}: {e}"));
                TENDRIL_ERR_INVALID_ARG
            })
    } else if len == HYBRID_SIGNING_HASH_LEN {
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        let mut hash = [0u8; HYBRID_SIGNING_HASH_LEN];
        hash.copy_from_slice(slice);
        Ok(SigningKeyPin::Hash(hash))
    } else {
        set_last_error(format!(
            "invalid {name} length {len}, expected {HYBRID_SIGNING_PUB_LEN} or {HYBRID_SIGNING_HASH_LEN}"
        ));
        Err(TENDRIL_ERR_INVALID_ARG)
    }
}

unsafe fn write_out_cstring(out: *mut *mut c_char, val: &str) -> i32 {
    if out.is_null() {
        set_last_error("null output string pointer");
        return TENDRIL_ERR_INVALID_ARG;
    }
    let Ok(cs) = CString::new(val) else {
        set_last_error("string contains interior NUL byte");
        return TENDRIL_ERR_INTERNAL;
    };
    unsafe {
        *out = cs.into_raw();
    }
    TENDRIL_OK
}

fn lock_roster(roster: &StdMutex<Roster>) -> std::sync::MutexGuard<'_, Roster> {
    roster
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Every CRL `roster` holds, keyed by issuer (paired peers and trust anchors).
fn held_crls(roster: &Roster) -> Vec<(String, RevocationList)> {
    roster
        .entries()
        .map(|(id, _)| id)
        .chain(roster.trust_anchors().map(|(id, _)| id))
        .filter_map(|id| roster.crl(id).map(|crl| (id.clone(), crl.clone())))
        .collect()
}

/// Applies `f` to the roster as one [`RosterAccess::update`] transaction; nothing is written
/// when `f` fails. With a store the caller must already hold the endpoint's `store_lock`.
///
/// Lock order (`tendril_runtime::announce` module docs): `store_lock`, then the roster file
/// lock, then the in-memory roster mutex, which is never held while `f` runs or across store
/// I/O. `f` runs on the latest on-disk roster with the CRLs only the in-memory copy holds (accepted
/// by a session, not yet persisted) merged in, and the committed roster, again with any such
/// CRLs, replaces the in-memory copy.
fn commit_roster_update<T, F>(access: &RosterAccess, f: F) -> Result<T, (i32, String)>
where
    F: FnOnce(&mut Roster) -> Result<T, (i32, String)>,
{
    let mut failure: Option<(i32, String)> = None;
    access
        .update(|roster| {
            f(roster).map_err(|e| {
                failure = Some(e);
                RuntimeError::Protocol(String::new())
            })
        })
        .map_err(|e| failure.unwrap_or((TENDRIL_ERR_INTERNAL, e.to_string())))
}

/// Reloads the on-disk roster into `roster` under `store_lock` (lock order `store_lock` then
/// `roster`) without taking an exclusive write lock or rewriting `roster.json`. CRLs only the
/// in-memory copy holds are kept (merged into the reloaded copy).
fn load_roster_from_store_locked(
    store: Option<&Arc<StateStore>>,
    store_lock: &AsyncMutex<()>,
    rt: &Runtime,
    roster: &StdMutex<Roster>,
) -> Result<(), String> {
    let Some(store) = store else {
        return Ok(());
    };
    let _store_guard = rt.block_on(store_lock.lock());
    let disk = store.load_roster().map_err(|e| e.to_string())?;
    replace_keeping_crls(&mut lock_roster(roster), disk);
    Ok(())
}

/// Replaces the in-memory roster with `disk`, keeping the CRLs only the in-memory copy holds.
fn replace_keeping_crls(memory: &mut Roster, mut disk: Roster) {
    disk.merge_crl_evidence(&held_crls(memory));
    *memory = disk;
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
    advertised_endpoints: Option<Vec<String>>,
    #[zeroize(skip)]
    relay_auth_origins: Option<Vec<String>>,
    #[zeroize(skip)]
    advertise: Option<AdvertiseMode>,
    #[zeroize(skip)]
    route_policy: Option<RoutePolicy>,
    #[zeroize(skip)]
    sign_routes: Option<bool>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct WakeTransportConfig {
    #[zeroize(skip)]
    target: WakeTarget,
    #[zeroize(skip)]
    secret: WakeSecret,
    pre_wake: bool,
    retry_delay_ms: u64,
    max_attempts: usize,
    timeout_ms: u64,
}

impl fmt::Debug for WakeTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakeTransportConfig")
            .field("target", &self.target)
            .field("secret", &"<redacted>")
            .field("pre_wake", &self.pre_wake)
            .field("retry_delay_ms", &self.retry_delay_ms)
            .field("max_attempts", &self.max_attempts)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

#[derive(Clone, Default)]
struct EndpointTransportConfig {
    relay_auth: RelayClientAuth,
    #[cfg(feature = "p2p-iroh")]
    p2p_relay_mode: Option<P2pRelayMode>,
    #[cfg(feature = "p2p-iroh")]
    p2p_pkarr: Option<bool>,
    #[cfg(feature = "p2p-iroh")]
    p2p_advertise_direct_addrs: Option<bool>,
    #[cfg(feature = "p2p-iroh")]
    p2p_allow_private_addrs: Option<bool>,
    #[cfg(feature = "p2p-iroh")]
    p2p_relay_auth: Option<P2pRelayAuth>,
    wake: Option<WakeTransportConfig>,
    /// Developer-listed hints added to the announced route set.
    advertised_endpoints: Vec<String>,
    /// Relay origins that may receive admission material.
    relay_auth_origins: Vec<String>,
    advertise: AdvertiseMode,
    route_policy: RoutePolicy,
    /// `None` means the default, signed issuance.
    sign_routes: Option<bool>,
}

impl fmt::Debug for EndpointTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("EndpointTransportConfig");
        dbg.field("relay_auth", &self.relay_auth);
        #[cfg(feature = "p2p-iroh")]
        {
            dbg.field("p2p_relay_mode", &self.p2p_relay_mode)
                .field("p2p_pkarr", &self.p2p_pkarr)
                .field(
                    "p2p_advertise_direct_addrs",
                    &self.p2p_advertise_direct_addrs,
                )
                .field("p2p_allow_private_addrs", &self.p2p_allow_private_addrs)
                .field("p2p_relay_auth", &self.p2p_relay_auth);
        }
        dbg.field("wake", &self.wake)
            .field("advertised_endpoints", &self.advertised_endpoints)
            .field("relay_auth_origins", &self.relay_auth_origins)
            .field("advertise", &self.advertise)
            .field("route_policy", &self.route_policy)
            .field("sign_routes", &self.sign_routes)
            .finish()
    }
}

impl Drop for EndpointTransportConfig {
    fn drop(&mut self) {
        self.relay_auth = RelayClientAuth::None;
        #[cfg(feature = "p2p-iroh")]
        {
            self.p2p_relay_auth = None;
        }
        self.wake = None;
    }
}

impl EndpointTransportConfig {
    fn from_input(mut input: TransportConfigInput) -> Result<Self, (i32, String)> {
        if input.relay_auth_secret.is_some() && input.relay_ticket.is_some() {
            return Err((
                TENDRIL_ERR_INVALID_ARG,
                "relay_auth_secret and relay_ticket are mutually exclusive".to_owned(),
            ));
        }
        if input.p2p_relay_auth_token.is_some() && input.p2p_api_secret.is_some() {
            return Err((
                TENDRIL_ERR_INVALID_ARG,
                "p2p_relay_auth_token and p2p_api_secret are mutually exclusive".to_owned(),
            ));
        }
        if input.p2p_relay_mode.is_some() && input.p2p_relay_urls.is_some() {
            return Err((
                TENDRIL_ERR_INVALID_ARG,
                "p2p_relay_mode and p2p_relay_urls are mutually exclusive".to_owned(),
            ));
        }

        let relay_auth = if let Some(sec) = input.relay_auth_secret.take().map(Zeroizing::new) {
            let trimmed = sec.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
                return Err((
                    TENDRIL_ERR_INVALID_ARG,
                    "invalid relay_auth_secret".to_owned(),
                ));
            }
            let parsed = RelayAuthSecret::from_bytes(trimmed.as_bytes()).map_err(|_| {
                (
                    TENDRIL_ERR_INVALID_ARG,
                    "invalid relay_auth_secret".to_owned(),
                )
            })?;
            RelayClientAuth::HmacSecret(parsed)
        } else if let Some(ticket) = input.relay_ticket.take() {
            canonical_relay_host(&ticket.relay_host)
                .map_err(|e| (TENDRIL_ERR_INVALID_ARG, e.to_string()))?;
            if ticket.issuer_pub.is_empty() || ticket.target_pub.is_empty() || ticket.sig.is_empty()
            {
                return Err((
                    TENDRIL_ERR_INVALID_ARG,
                    "relay_ticket has empty required fields".to_owned(),
                ));
            }
            RelayClientAuth::Ticket(ticket)
        } else {
            RelayClientAuth::None
        };

        #[cfg(not(feature = "p2p-iroh"))]
        {
            if input.p2p_relay_mode.is_some()
                || input.p2p_relay_urls.is_some()
                || input.p2p_relay_auth_token.is_some()
                || input.p2p_api_secret.is_some()
                || input.p2p_pkarr == Some(true)
                || input.p2p_advertise_direct_addrs == Some(true)
                || input.p2p_allow_private_addrs == Some(true)
            {
                return Err((
                    TENDRIL_ERR_PROTOCOL,
                    "tendril-ffi built without p2p-iroh feature".to_owned(),
                ));
            }
        }

        #[cfg(feature = "p2p-iroh")]
        let (p2p_relay_mode, p2p_relay_auth) = {
            let mode = if let Some(ref mode_s) = input.p2p_relay_mode {
                Some(
                    parse_p2p_relay_mode(Some(mode_s))
                        .map_err(|e| (TENDRIL_ERR_INVALID_ARG, e.to_string()))?,
                )
            } else if let Some(ref urls) = input.p2p_relay_urls {
                Some(
                    parse_p2p_relay_modes(urls)
                        .map_err(|e| (TENDRIL_ERR_INVALID_ARG, e.to_string()))?,
                )
            } else {
                None
            };

            let auth = if let Some(tok) = input.p2p_relay_auth_token.take().map(Zeroizing::new) {
                if tok.is_empty() || tok.chars().any(char::is_control) {
                    return Err((
                        TENDRIL_ERR_INVALID_ARG,
                        "invalid p2p_relay_auth_token".to_owned(),
                    ));
                }
                Some(P2pRelayAuth::BearerToken(tok))
            } else if let Some(sec) = input.p2p_api_secret.take().map(Zeroizing::new) {
                #[cfg(feature = "p2p-iroh-services")]
                {
                    if sec.is_empty() || sec.chars().any(char::is_control) {
                        return Err((TENDRIL_ERR_INVALID_ARG, "invalid p2p_api_secret".to_owned()));
                    }
                    Some(P2pRelayAuth::IrohServicesSecret(sec))
                }
                #[cfg(not(feature = "p2p-iroh-services"))]
                {
                    let _ = sec;
                    return Err((
                        TENDRIL_ERR_PROTOCOL,
                        "tendril-ffi built without p2p-iroh-services feature".to_owned(),
                    ));
                }
            } else {
                None
            };

            if auth.is_some() && matches!(mode, Some(P2pRelayMode::Disabled)) {
                return Err((
                    TENDRIL_ERR_INVALID_ARG,
                    "p2p relay auth is invalid when p2p_relay_mode is disabled".to_owned(),
                ));
            }
            (mode, auth)
        };

        let wake = if let Some(url) = input.wake_url.take() {
            let adapter = input.wake_adapter.unwrap_or(WakeAdapterKind::Webhook);
            let mut target = WakeTarget::new(adapter, &url)
                .map_err(|e| (TENDRIL_ERR_INVALID_ARG, e.to_string()))?;
            if let Some(tok) = input.wake_auth_token.take().map(Zeroizing::new) {
                target = target.with_auth_token(tok.as_str()).map_err(|_| {
                    (
                        TENDRIL_ERR_INVALID_ARG,
                        "invalid wake_auth_token".to_owned(),
                    )
                })?;
            }
            let secret_b64 = input
                .wake_secret_b64
                .take()
                .map(Zeroizing::new)
                .ok_or_else(|| {
                    (
                        TENDRIL_ERR_INVALID_ARG,
                        "wake_secret_b64 is required when wake_url is set".to_owned(),
                    )
                })?;
            let secret_bytes =
                Zeroizing::new(b64url_decode_array::<32>(secret_b64.trim()).map_err(|_| {
                    (
                        TENDRIL_ERR_INVALID_ARG,
                        "invalid wake_secret_b64".to_owned(),
                    )
                })?);
            Some(WakeTransportConfig {
                target,
                secret: WakeSecret::from_bytes(*secret_bytes),
                pre_wake: input.wake_pre_wake.unwrap_or(false),
                retry_delay_ms: input.wake_retry_delay_ms.unwrap_or(100),
                max_attempts: input.wake_max_attempts.unwrap_or(10).max(1),
                timeout_ms: input.wake_timeout_ms.unwrap_or(3_000),
            })
        } else if input.wake_adapter.is_some()
            || input.wake_secret_b64.is_some()
            || input.wake_auth_token.is_some()
            || input.wake_pre_wake.is_some()
            || input.wake_retry_delay_ms.is_some()
            || input.wake_max_attempts.is_some()
            || input.wake_timeout_ms.is_some()
        {
            return Err((
                TENDRIL_ERR_INVALID_ARG,
                "wake_* options require wake_url".to_owned(),
            ));
        } else {
            None
        };

        let relay_auth_origins = input.relay_auth_origins.take().unwrap_or_default();
        if let Some(index) = relay_auth_origins
            .iter()
            .position(|o| !origin_allowed(o, std::slice::from_ref(o)))
        {
            // The entry itself is never echoed: a pasted URL may carry credentials.
            return Err((
                TENDRIL_ERR_INVALID_ARG,
                format!(
                    "invalid relay_auth_origins entry at index {index}: expected an origin \
                     (ws, wss, http or https scheme, host and optional port)"
                ),
            ));
        }

        Ok(Self {
            advertised_endpoints: input.advertised_endpoints.take().unwrap_or_default(),
            relay_auth_origins,
            advertise: input.advertise.unwrap_or_default(),
            route_policy: input.route_policy.unwrap_or_default(),
            sign_routes: input.sign_routes,
            relay_auth,
            #[cfg(feature = "p2p-iroh")]
            p2p_relay_mode,
            #[cfg(feature = "p2p-iroh")]
            p2p_pkarr: input.p2p_pkarr,
            #[cfg(feature = "p2p-iroh")]
            p2p_advertise_direct_addrs: input.p2p_advertise_direct_addrs,
            #[cfg(feature = "p2p-iroh")]
            p2p_allow_private_addrs: input.p2p_allow_private_addrs,
            #[cfg(feature = "p2p-iroh")]
            p2p_relay_auth,
            wake,
        })
    }

    fn sign_routes(&self) -> bool {
        self.sign_routes.unwrap_or(true)
    }

    /// The runtime pairing and Day-2 dialer set. `relay_host` is the expected relay host of an
    /// explicit operator endpoint (relay challenge host, or Iroh relay mode for `iroh://`).
    fn hint_dialers(
        &self,
        operator_endpoint: Option<&str>,
        relay_host: Option<&str>,
    ) -> Result<Arc<HintDialers>, RuntimeError> {
        let relay_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
        let iroh_operator = operator_endpoint.is_some_and(|e| e.starts_with("iroh://"));
        #[cfg(not(feature = "p2p-iroh"))]
        let _ = iroh_operator;
        #[cfg(feature = "p2p-iroh")]
        let p2p_relay_mode = if let Some(ref m) = self.p2p_relay_mode {
            Some(m.clone())
        } else if let Some(spec) = relay_host.filter(|_| iroh_operator) {
            Some(parse_p2p_relay_mode(Some(spec))?)
        } else if std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1") {
            Some(P2pRelayMode::Disabled)
        } else {
            None
        };
        let config = HintDialerConfig {
            relay_auth: self.relay_auth.clone(),
            relay_expected_host: relay_host.filter(|_| !iroh_operator).map(ToOwned::to_owned),
            #[cfg(feature = "p2p-iroh")]
            p2p_relay_mode,
            #[cfg(feature = "p2p-iroh")]
            p2p_relay_auth: self.p2p_relay_auth.clone(),
            #[cfg(feature = "p2p-iroh")]
            p2p_allow_private_addrs: self.p2p_allow_private_addrs.unwrap_or(false),
            #[cfg(feature = "p2p-iroh")]
            p2p_pkarr: self.p2p_pkarr,
        };
        Ok(Arc::new(HintDialers::new(config)))
    }

    #[cfg(feature = "p2p-iroh")]
    fn build_p2p_listener_options(
        &self,
        relay_mode_override: Option<&str>,
    ) -> Result<P2pOptions, RuntimeError> {
        let mode = match relay_mode_override.map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => parse_p2p_relay_mode(Some(raw))?,
            None => self.p2p_relay_mode.clone().unwrap_or(P2pRelayMode::Default),
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
        Ok(opts)
    }

    /// Options for the shared group `P2pDialer`, present only when a relay mode is configured
    /// explicitly (or `TENDRIL_P2P_LOCAL=1`). A shared dialer cannot derive per-peer `?relay=`
    /// URLs, so an unconfigured endpoint never builds one and never falls back to public relays.
    #[cfg(feature = "p2p-iroh")]
    fn build_p2p_group_options(&self) -> Option<P2pOptions> {
        P2pOptions::for_group_dialer(
            self.p2p_relay_mode.clone(),
            std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1"),
            self.p2p_pkarr,
            self.p2p_allow_private_addrs,
            self.p2p_relay_auth.clone(),
        )
    }

    #[cfg(feature = "p2p-iroh")]
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
        let mut opts = P2pOptions::for_endpoint(
            endpoint,
            explicit_mode,
            self.p2p_allow_private_addrs.unwrap_or(false),
        )?;
        if let Some(pkarr) = self.p2p_pkarr {
            opts = opts.with_resolve_pkarr(pkarr);
        }
        opts = opts.with_relay_auth(self.p2p_relay_auth.clone());
        Ok(opts)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FfiPinnedHostInput {
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
) -> Result<[u8; 32], (i32, String)> {
    let entry = roster.get(target_host_id).ok_or_else(|| {
        (
            TENDRIL_ERR_NOT_FOUND,
            format!("target {target_host_id} not found in roster"),
        )
    })?;
    if entry.state == PeerState::Revoked {
        return Err((
            TENDRIL_ERR_PROTOCOL,
            format!("target {target_host_id} is revoked"),
        ));
    }
    entry
        .v2_secrets
        .as_ref()
        .map(|s| *s.mailbox_secret())
        .ok_or_else(|| {
            (
                TENDRIL_ERR_PROTOCOL,
                format!("target {target_host_id} has no v2 mailbox_secret"),
            )
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
        #[cfg(feature = "p2p-iroh")]
        {
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
        #[cfg(not(feature = "p2p-iroh"))]
        {
            let _ = normalized_host;
            return Err(RuntimeError::Protocol(
                "p2p-iroh feature is not enabled in tendril-ffi".to_owned(),
            ));
        }
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

/// Opaque endpoint handle owning a Tokio runtime, identity, roster, and background listeners.
pub struct TendrilEndpoint {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: EndpointIdentity,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    router: InboundRouter,
    v2_state: Arc<V2ResponderState>,
    transport_cfg: StdMutex<EndpointTransportConfig>,
    self_m2m_enabled: AtomicBool,
    m2m_enabled: AtomicBool,
    group_rt: StdMutex<Option<Arc<GroupRuntime>>>,
    /// Fired once when the group runtime is installed, so parked accepts switch to its channels.
    group_ready: tokio::sync::Notify,
    /// `/v1/relay` URLs this endpoint registered its identity mailbox on through
    /// `tendril_endpoint_serve_relay`; the group hub never registers a pool there.
    served_v1_relays: StdMutex<Vec<String>>,
    /// Roster handle shared by pairing, Day-2 connects, route ingest and the route setter; it
    /// wraps `store` and `roster` and records each peer's last route set.
    route_access: RosterAccess,
    /// Keeps paired clients' `signed` routes current.
    announcer: Arc<RouteAnnouncer>,
    /// Hosting lifecycle: running once the endpoint serves a listener, issues a pairing URI or
    /// refreshes its routes (advertising input changes then publish and the announcer timer
    /// runs), and terminally closed by `tendril_endpoint_close`. A leaf lock: never held across
    /// announcer, roster or pairing manager calls.
    hosting: StdMutex<HostingState>,
    /// Endpoint strings of every listener served through this handle, including unspecified
    /// binds (used only by auto enumeration).
    served_endpoints: StdMutex<Vec<String>>,
    /// Pairing-capable TCP listeners (`tendril_endpoint_serve_direct`) for auto enumeration.
    served_listeners: StdMutex<Vec<ServedListener>>,
}

/// Hosting lifecycle of an endpoint: `Idle -> Running -> Closed`, with `Closed` terminal.
#[derive(Debug)]
enum HostingState {
    Idle,
    /// Holds the announcer's timer task, aborted on close.
    Running(tokio::task::JoinHandle<()>),
    Closed,
}

impl TendrilEndpoint {
    fn advertise_inputs(&self) -> AdvertiseInputs {
        let cfg = self.snapshot_transport_cfg();
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

    /// Marks the endpoint as a host and starts the announcer timer (scheduled sends, the empty
    /// snapshot debounce and the periodic re-enumeration) once. A closed endpoint never hosts.
    fn start_hosting(&self) -> Result<(), (i32, String)> {
        let mut state = self
            .hosting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*state {
            HostingState::Closed => Err((TENDRIL_ERR_CLOSED, "endpoint is closed".to_owned())),
            HostingState::Running(_) => Ok(()),
            HostingState::Idle => {
                let _guard = self.rt.enter();
                let task = self
                    .announcer
                    .spawn(Some(tendril_runtime::DEFAULT_ROUTE_REFRESH_INTERVAL));
                *state = HostingState::Running(task);
                Ok(())
            }
        }
    }

    /// True while the endpoint hosts; a closed endpoint publishes nothing.
    fn is_hosting(&self) -> bool {
        matches!(
            &*self
                .hosting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            HostingState::Running(_)
        )
    }

    /// Moves the endpoint to the terminal `Closed` state and aborts the timer task, if any. The
    /// abort runs after the lock is released.
    fn stop_hosting(&self) {
        let previous = std::mem::replace(
            &mut *self
                .hosting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            HostingState::Closed,
        );
        if let HostingState::Running(task) = previous {
            task.abort();
        }
    }

    /// Hands the current advertising inputs to the announcer and, on a hosting endpoint,
    /// publishes the recomputed set. A failed publish (for example an exhausted sequence) is
    /// reported by the next issuance or refresh.
    fn sync_advertising(&self) {
        self.announcer.set_inputs(self.advertise_inputs());
        if self.is_hosting() {
            let _ = self.announcer.publish(unix_ms());
        }
    }

    /// Records a served listener for advertising, then publishes.
    fn record_served(&self, endpoint: String, listener: Option<ServedListener>) {
        {
            let mut served = self
                .served_endpoints
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !served.contains(&endpoint) {
                served.push(endpoint);
            }
        }
        if let Some(l) = listener {
            self.served_listeners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(l);
        }
        let _ = self.start_hosting();
        self.sync_advertising();
    }

    /// Registers an accepted responder session with the announcer before the caller can send
    /// anything on it, so a newer signed route set is its first host-initiated frame.
    ///
    /// On failure the session is closed and the error returned: an accept never hands out a
    /// session that skipped its initial route set.
    fn register_route_session(&self, session: &SessionBackend) -> Result<(), String> {
        let (sink, peer_route_seq) = session.route_sink();
        self.register_route_sink(&sink, peer_route_seq, || session.close_now(&self.rt))
    }

    fn register_route_sink(
        &self,
        sink: &Arc<dyn RouteSetSink>,
        peer_route_seq: Option<u64>,
        close: impl FnOnce(),
    ) -> Result<(), String> {
        match self.rt.block_on(self.announcer.on_session_established(
            sink,
            peer_route_seq,
            unix_ms(),
        )) {
            Ok(()) => Ok(()),
            Err(e) => {
                close();
                Err(format!("route announcer registration failed: {e}"))
            }
        }
    }

    /// Runs a route write on the shared roster handle (which merges unpersisted CRLs before it
    /// writes) under the endpoint's store lock, so it serializes with [`Self::mutate_roster`].
    fn route_write<T>(
        &self,
        f: impl FnOnce(&RosterAccess) -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let _store_guard = self
            .store
            .as_ref()
            .map(|_| self.rt.block_on(self.store_lock.lock()));
        f(&self.route_access)
    }

    fn mutate_roster<T, F>(&self, f: F) -> Result<T, (i32, String)>
    where
        F: FnOnce(&mut Roster) -> Result<T, (i32, String)>,
    {
        let _store_guard = self
            .store
            .as_ref()
            .map(|_| self.rt.block_on(self.store_lock.lock()));
        commit_roster_update(&self.route_access, f)
    }

    fn load_roster_from_store(&self) -> Result<(), String> {
        load_roster_from_store_locked(
            self.store.as_ref(),
            &self.store_lock,
            &self.rt,
            &self.roster,
        )
    }

    fn snapshot_transport_cfg(&self) -> EndpointTransportConfig {
        self.transport_cfg
            .lock()
            .expect("transport_cfg mutex poisoned")
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
        self.router.spawn_listener(self.rt.handle(), listener);
    }

    fn group_runtime(&self) -> Option<Arc<GroupRuntime>> {
        self.group_rt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Returns the endpoint's group runtime, creating it (hub plus inbound pumps) on first use.
    ///
    /// The hub is the serving runtime of the endpoint's identity, like `tendril serve`: its pools
    /// use the endpoint's relay auth and register their relay mailboxes (`relay_listen`). The
    /// pool book watcher does that on its own tick, so no inbound stream is needed. The
    /// identity's `/v1/relay` mailbox is left alone on every URL the app already serves with
    /// `tendril_endpoint_serve_relay` before the first group call (`served_v1_relays`).
    fn ensure_group_runtime(&self) -> Result<Arc<GroupRuntime>, (i32, String)> {
        let Some(store) = self.store.as_ref() else {
            return Err((
                TENDRIL_ERR_INVALID_ARG,
                "groups require a state directory endpoint".to_owned(),
            ));
        };
        let mut slot = self
            .group_rt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = slot.as_ref() {
            return Ok(Arc::clone(existing));
        }
        let cfg = self.snapshot_transport_cfg();
        #[allow(unused_mut)]
        let mut dialers: Vec<Arc<dyn PathDialer>> = vec![
            Arc::new(DirectDialer::new()),
            Arc::new(LocalDialer::new()),
            Arc::new(RelayDialer::new().with_auth(cfg.relay_auth.clone())),
            Arc::new(OverlayDialer::new()),
            Arc::new(BrokerDialer::new()),
        ];
        #[cfg(feature = "p2p-iroh")]
        if let Some(opts) = cfg.build_p2p_group_options() {
            let dialer = self
                .rt
                .block_on(P2pDialer::bind_with_options(opts))
                .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))?;
            dialers.push(Arc::new(dialer));
        }
        let served_v1_relays = self
            .served_v1_relays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let hub = Arc::new(GroupHub::new(
            store.as_ref().clone(),
            Arc::new(self.identity.clone()),
            GroupPoolConfig::new(dialers)
                .with_relay_auth(cfg.relay_auth.clone())
                .with_relay_listen(true)
                .with_served_v1_relays(served_v1_relays),
            None,
        ));
        {
            // Register every stored group before the pumps run, so a sibling stream that is
            // already queued is never handled by a hub with no pools.
            let _guard = self.rt.enter();
            let _ = hub.sync();
        }
        let (v1_tx, v1_rx) = mpsc::channel(GROUP_ORDINARY_QUEUE_CAP);
        let (v2_tx, v2_rx) = mpsc::channel(GROUP_ORDINARY_QUEUE_CAP);
        let (_, v1_queue) = self.router.split_queues();
        let (_, v2_queue) = self.router.split_v2_queues();
        let handle = self.rt.handle();
        let pumps = vec![
            handle
                .spawn(group_inbound_pump(
                    v1_queue,
                    self.router.session_rate_limiter().clone(),
                    Arc::clone(&hub),
                    Arc::clone(&self.v2_state),
                    v1_tx.clone(),
                    v2_tx.clone(),
                ))
                .abort_handle(),
            handle
                .spawn(group_inbound_pump(
                    v2_queue,
                    self.router.v2_session_rate_limiter().clone(),
                    Arc::clone(&hub),
                    Arc::clone(&self.v2_state),
                    v1_tx,
                    v2_tx,
                ))
                .abort_handle(),
        ];
        let runtime = Arc::new(GroupRuntime {
            rt: Arc::clone(&self.rt),
            hub,
            v1_rx: AsyncMutex::new(v1_rx),
            v2_rx: AsyncMutex::new(v2_rx),
            pumps,
        });
        *slot = Some(Arc::clone(&runtime));
        self.group_ready.notify_waiters();
        Ok(runtime)
    }
}

/// Close code sent when an accepted session cannot be registered with the route announcer.
const ROUTE_REGISTRATION_CLOSE_CODE: u16 = 1011;

const GROUP_ORDINARY_QUEUE_CAP: usize = 16;
const GROUP_PUMP_WAIT: Duration = Duration::from_secs(3600);

/// Group dispatch state shared by an endpoint once the first group is opened.
///
/// From then on the pumps own the endpoint's inbound session queues: sibling sessions are
/// installed in their pool by the hub and ordinary paired sessions are handed to
/// `tendril_session_accept` and `tendril_session_accept_v2` through the channels.
struct GroupRuntime {
    rt: Arc<Runtime>,
    hub: Arc<GroupHub>,
    v1_rx: AsyncMutex<mpsc::Receiver<SessionDriver>>,
    v2_rx: AsyncMutex<mpsc::Receiver<V2SessionDriver>>,
    pumps: Vec<tokio::task::AbortHandle>,
}

impl GroupRuntime {
    /// Closes the hub and aborts the pumps; dropping a pump aborts its in-flight handshakes.
    fn shutdown(&self) {
        let _guard = self.rt.enter();
        self.hub.close();
        for pump in &self.pumps {
            pump.abort();
        }
    }
}

impl Drop for GroupRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Locks `rx` and takes its next item; lock wait and dequeue share one deadline.
async fn recv_group_queue<T>(
    rx: &AsyncMutex<mpsc::Receiver<T>>,
    deadline: tokio::time::Instant,
) -> Result<Option<T>, tokio::time::error::Elapsed> {
    timeout_at(deadline, async { rx.lock().await.recv().await }).await
}

async fn group_inbound_pump(
    queue: InboundQueue,
    limiter: PreAuthRateLimiter,
    hub: Arc<GroupHub>,
    v2_state: Arc<V2ResponderState>,
    v1_tx: mpsc::Sender<SessionDriver>,
    v2_tx: mpsc::Sender<V2SessionDriver>,
) {
    let mut handshakes = tokio::task::JoinSet::new();
    loop {
        while handshakes.try_join_next().is_some() {}
        match recv_routed(&queue, GROUP_PUMP_WAIT).await {
            Ok(Some((stream, guard))) => {
                let hub = Arc::clone(&hub);
                let v2_state = Arc::clone(&v2_state);
                let limiter = limiter.clone();
                let v1_tx = v1_tx.clone();
                let v2_tx = v2_tx.clone();
                handshakes.spawn(async move {
                    match hub
                        .accept(stream, &v2_state, Some(&limiter), Some(guard))
                        .await
                    {
                        Ok(InboundSession::OrdinaryV1 { session, .. }) => {
                            let _ = v1_tx.try_send(session);
                        }
                        Ok(InboundSession::OrdinaryV2 { session }) => {
                            let _ = v2_tx.try_send(session);
                        }
                        Ok(InboundSession::Group { .. }) | Err(_) => {}
                    }
                });
            }
            Ok(None) => return,
            Err(()) => {}
        }
    }
}

fn build_endpoint_handle(
    store: Option<Arc<StateStore>>,
    identity: EndpointIdentity,
    roster: Roster,
) -> *mut TendrilEndpoint {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => Arc::new(rt),
        Err(e) => {
            set_last_error(format!("failed to create tokio runtime: {e}"));
            return ptr::null_mut();
        }
    };
    let has_active_anchor = roster
        .trust_anchors()
        .any(|(_, a)| a.state == AnchorState::Active);
    let roster = Arc::new(StdMutex::new(roster));
    let route_access = RosterAccess::new(store.clone(), Arc::clone(&roster));
    let announcer = Arc::new(RouteAnnouncer::new(
        identity.clone(),
        route_access.clone(),
        AdvertiseInputs::default(),
        AddressSource::platform_default(),
    ));
    Box::into_raw(Box::new(TendrilEndpoint {
        rt,
        store,
        store_lock: Arc::new(AsyncMutex::new(())),
        identity,
        roster,
        pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
        router: InboundRouter::new(),
        v2_state: Arc::new(V2ResponderState::new()),
        transport_cfg: StdMutex::new(EndpointTransportConfig::default()),
        self_m2m_enabled: AtomicBool::new(false),
        m2m_enabled: AtomicBool::new(has_active_anchor),
        group_rt: StdMutex::new(None),
        group_ready: tokio::sync::Notify::new(),
        served_v1_relays: StdMutex::new(Vec::new()),
        route_access,
        announcer,
        hosting: StdMutex::new(HostingState::Idle),
        served_endpoints: StdMutex::new(Vec::new()),
        served_listeners: StdMutex::new(Vec::new()),
    }))
}

unsafe fn write_roster_json_out(roster_arc: &StdMutex<Roster>, out_json: *mut *mut c_char) -> i32 {
    let json = {
        let guard = roster_arc.lock().expect("roster mutex poisoned");
        match serde_json::to_string(&*guard) {
            Ok(j) => Zeroizing::new(j),
            Err(e) => {
                set_last_error(format!("failed to serialize roster: {e}"));
                return TENDRIL_ERR_INTERNAL;
            }
        }
    };
    unsafe { write_out_cstring(out_json, &json) }
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
        "event": format!("group_{kind}_{verdict}"),
        "group_id": outcome.group_id,
        "seq": outcome.seq,
    });
    if let Some(error) = &outcome.error {
        val["error"] = serde_json::Value::String(error.clone());
    }
    val
}

enum SessionBackend {
    V1(Arc<ConcurrentSession>),
    V2(Arc<ConcurrentV2Session>),
}

impl SessionBackend {
    fn v1(driver: SessionDriver) -> Self {
        Self::V1(Arc::new(driver.into_concurrent()))
    }

    fn v2(driver: V2SessionDriver) -> Self {
        Self::V2(Arc::new(driver.into_concurrent()))
    }

    /// The announcer's weak write handle and the client's `SessionHello.route_seq`.
    fn route_sink(&self) -> (Arc<dyn RouteSetSink>, Option<u64>) {
        match self {
            Self::V1(s) => (Arc::clone(s) as Arc<dyn RouteSetSink>, s.peer_route_seq()),
            Self::V2(s) => (Arc::clone(s) as Arc<dyn RouteSetSink>, s.peer_route_seq()),
        }
    }

    fn shutdown(&self) {
        match self {
            Self::V1(s) => s.shutdown(),
            Self::V2(s) => s.shutdown(),
        }
    }

    /// Sends a best-effort close frame and stops the session.
    fn close_now(&self, rt: &Runtime) {
        let _ = rt.block_on(timeout(
            Duration::from_secs(2),
            self.send_close(ROUTE_REGISTRATION_CLOSE_CODE, "route registration failed"),
        ));
        self.shutdown();
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
    ) -> (Result<(), CoreError>, tendril_core::grants::AuditEvent) {
        match self {
            Self::V1(s) => s.authorize_locked(requested_cap, now_unix, roster),
            Self::V2(s) => s.authorize_locked(requested_cap, now_unix, roster),
        }
    }

    fn peer_device_id(&self) -> Option<String> {
        match self {
            Self::V1(s) => s.peer_device_id(),
            Self::V2(s) => Some(s.peer_device_id().to_owned()),
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

/// Opaque authenticated session handle sharing the endpoint's Tokio runtime and roster state.
pub struct TendrilSession {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    roster: Arc<StdMutex<Roster>>,
    /// The endpoint's roster handle over `store` and `roster`.
    route_access: RosterAccess,
    v1_root_id: Option<String>,
    v1_local_signing: Option<(String, HybridSigningPublicKey)>,
    local_device_id: String,
    session: SessionBackend,
}

impl TendrilSession {
    /// Hands an ordinary-session `0x0A`/`0x0B` to the runtime when the endpoint has a state
    /// store and reports the redacted outcome. Store-less endpoints surface the unverified
    /// event instead.
    fn group_frame_json(&self, ev: &SessionEvent) -> Result<serde_json::Value, String> {
        if let Some(store) = self.store.as_ref() {
            let peer = self
                .session
                .peer_device_id()
                .ok_or_else(|| "session peer is not authenticated".to_owned())?;
            if let Some(outcome) =
                handle_session_group_frame(store, &self.local_device_id, &peer, ev)
            {
                return Ok(group_frame_outcome_json(&outcome));
            }
        }
        match ev {
            SessionEvent::GroupManifestReceived(manifest) => {
                let bytes = manifest.to_wire_bytes().map_err(|e| e.to_string())?;
                Ok(serde_json::json!({
                    "event": "group_manifest_unverified",
                    "group_id": manifest.group_id,
                    "seq": manifest.seq,
                    "manifest_json": String::from_utf8_lossy(&bytes),
                }))
            }
            SessionEvent::GroupRendezvousReceived(frame) => Ok(serde_json::json!({
                "event": "group_rendezvous_unverified",
                "group_id": frame.group_id,
                "seq": frame.seq,
            })),
            _ => Err("not a group frame event".to_owned()),
        }
    }

    fn load_roster_from_store(&self) -> Result<(), String> {
        load_roster_from_store_locked(
            self.store.as_ref(),
            &self.store_lock,
            &self.rt,
            &self.roster,
        )
    }

    /// Persists the CRL a v1 session accepted for `issuer` when it is newer than the stored
    /// one; otherwise reloads the roster. Either way the in-memory copy keeps every CRL only it
    /// holds.
    ///
    /// Lock order: `store_lock`, then the roster file lock ([`RosterAccess::update`]), then the
    /// in-memory roster mutex, which is never held across store I/O.
    fn persist_v1_crl_if_newer(&self, issuer: &str) -> Result<(), String> {
        let Some(ref store) = self.store else {
            return Ok(());
        };
        let _store_guard = self.rt.block_on(self.store_lock.lock());
        let held = {
            let guard = lock_roster(&self.roster);
            guard.crl(issuer).cloned().map(|crl| {
                let key = guard.get(issuer).and_then(|e| e.signing_pub.clone());
                (crl, key)
            })
        };
        let disk = store.load_roster().map_err(|e| e.to_string())?;
        let Some((crl, memory_key)) = held.filter(|(crl, _)| {
            disk.crl(issuer)
                .is_none_or(|existing| crl.seq > existing.seq)
        }) else {
            replace_keeping_crls(&mut lock_roster(&self.roster), disk);
            return Ok(());
        };
        let issuer_pub = if let Some((ref local_id, ref local_pub)) = self.v1_local_signing
            && local_id == issuer
        {
            local_pub.clone()
        } else {
            disk.lookup_active_signing_key(issuer)
                .or_else(|| disk.lookup_active_anchor_key(issuer))
                .or(memory_key)
                .ok_or_else(|| format!("missing signing key for CRL issuer {issuer}"))?
        };
        self.route_access
            .update(|d| match d.ingest_crl(crl, issuer, &issuer_pub) {
                Ok(()) | Err(CoreError::CrlStaleSeq { .. }) => Ok(()),
                Err(err) => Err(err.into()),
            })
            .map_err(|e| e.to_string())
    }
}

/// Copies the last thread-local FFI error string into `buf`.
///
/// # Safety
/// `buf` must be null (to query needed length) or point to `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_last_error(buf: *mut c_char, cap: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        LAST_ERROR.with(|cell| {
            let msg = cell.borrow();
            let bytes = msg.as_bytes();
            let needed = bytes.len() + 1;
            if buf.is_null() || cap == 0 {
                return i32::try_from(needed).unwrap_or(i32::MAX);
            }
            let mut copy_len = bytes.len().min(cap - 1);
            while copy_len > 0 && !msg.is_char_boundary(copy_len) {
                copy_len -= 1;
            }
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), copy_len);
                *buf.add(copy_len) = 0;
            }
            i32::try_from(needed).unwrap_or(i32::MAX)
        })
    }))
    .unwrap_or(-1)
}

/// Frees a NUL-terminated string returned by `tendril-ffi` after zeroizing its buffer.
///
/// # Safety
/// `ptr` must be null or a pointer previously allocated by `tendril-ffi` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            let mut bytes = CString::from_raw(ptr).into_bytes();
            bytes.zeroize();
        }));
    }
}

/// Computes the `dev_<hex16>` identifier for a 32-byte X25519 public key.
///
/// # Safety
/// `static_pub_32` must point to 32 readable bytes; `out_str` must be a valid non-null out pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_device_id(
    static_pub_32: *const u8,
    out_str: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_str.is_null() {
            set_last_error("null output string pointer");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(key) = (unsafe { read_bytes32(static_pub_32, "static_pub_32") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        unsafe { write_out_cstring(out_str, &device_id(&key)) }
    })
}

/// Computes the base32 host fingerprint for a 32-byte static public key.
///
/// # Safety
/// `static_pub_32` must point to 32 readable bytes; `out_str` must be a valid non-null out pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_fingerprint_host(
    static_pub_32: *const u8,
    out_str: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_str.is_null() {
            set_last_error("null output string pointer");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(key) = (unsafe { read_bytes32(static_pub_32, "static_pub_32") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        unsafe { write_out_cstring(out_str, &fingerprint_host(&key)) }
    })
}

/// Computes the uppercase hex device fingerprint for a 32-byte static public key.
///
/// # Safety
/// `static_pub_32` must point to 32 readable bytes; `out_str` must be a valid non-null out pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_fingerprint_device(
    static_pub_32: *const u8,
    out_str: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_str.is_null() {
            set_last_error("null output string pointer");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(key) = (unsafe { read_bytes32(static_pub_32, "static_pub_32") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        unsafe { write_out_cstring(out_str, &fingerprint_device(&key)) }
    })
}

/// Derives the 4x4 pairing SAS from a 32-byte Noise handshake hash.
///
/// # Safety
/// `handshake_hash_32` must point to 32 readable bytes; `out_str` must be a valid non-null out pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_pairing_sas(
    handshake_hash_32: *const u8,
    out_str: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_str.is_null() {
            set_last_error("null output string pointer");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(hh) = (unsafe { read_bytes32(handshake_hash_32, "handshake_hash_32") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        unsafe { write_out_cstring(out_str, &pairing_sas(&hh)) }
    })
}

/// Computes the Argon2id + HMAC-SHA256 pairing proof for `code` and `handshake_hash_32`.
///
/// # Safety
/// `code` must be a valid NUL-terminated UTF-8 string; `handshake_hash_32` and `out_mac_32` must be 32-byte valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_compute_code_mac(
    code: *const c_char,
    handshake_hash_32: *const u8,
    out_mac_32: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if out_mac_32.is_null() {
            set_last_error("null out_mac_32");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(code_s) = (unsafe { cstr_to_str(code, "code") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(hh) = (unsafe { read_bytes32(handshake_hash_32, "handshake_hash_32") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        match compute_code_mac(code_s, &hh) {
            Ok(mac) => {
                unsafe {
                    ptr::copy_nonoverlapping(mac.as_ptr(), out_mac_32, 32);
                }
                TENDRIL_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                TENDRIL_ERR_PROTOCOL
            }
        }
    })
}

/// Verifies a JSON rotation record chain against pinned keys.
///
/// # Safety
/// All string arguments must be valid NUL-terminated UTF-8 C strings; `out_final_seq` may be null or writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_verify_rotation_chain_json(
    pinned_signing_b64: *const c_char,
    pinned_static_b64: *const c_char,
    pinned_seq: u64,
    chain_json: *const c_char,
    cur_static_b64: *const c_char,
    cur_signing_b64: *const c_char,
    out_final_seq: *mut u64,
) -> i32 {
    ffi_i32(|| {
        let Ok(psig_s) = (unsafe { cstr_to_str(pinned_signing_b64, "pinned_signing_b64") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(pstat_s) = (unsafe { cstr_to_str(pinned_static_b64, "pinned_static_b64") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(chain_s) = (unsafe { cstr_to_str(chain_json, "chain_json") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(cstat_s) = (unsafe { cstr_to_str(cur_static_b64, "cur_static_b64") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(csig_s) = (unsafe { cstr_to_str(cur_signing_b64, "cur_signing_b64") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };

        let Ok(psig) = HybridSigningPublicKey::from_b64url(psig_s) else {
            set_last_error("invalid pinned_signing_b64");
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(pstat) = b64url_decode_array::<32>(pstat_s) else {
            set_last_error("invalid pinned_static_b64");
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(cstat) = b64url_decode_array::<32>(cstat_s) else {
            set_last_error("invalid cur_static_b64");
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(csig) = HybridSigningPublicKey::from_b64url(csig_s) else {
            set_last_error("invalid cur_signing_b64");
            return TENDRIL_ERR_INVALID_ARG;
        };
        let chain: Vec<RotationRecord> = match serde_json::from_str(chain_s) {
            Ok(v) => v,
            Err(e) => {
                set_last_error(json_error("chain_json", &e));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };

        match verify_rotation_chain(&psig, &pstat, pinned_seq, &chain, &cstat, &csig) {
            Ok(final_seq) => {
                if !out_final_seq.is_null() {
                    unsafe {
                        *out_final_seq = final_seq;
                    }
                }
                TENDRIL_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                TENDRIL_ERR_PROTOCOL
            }
        }
    })
}

/// Evaluates a JSON capability grant and optional CRL against `requested_cap`.
///
/// # Safety
/// Non-optional string arguments must be valid NUL-terminated UTF-8 C strings; `crl_json_opt` may be null; `out_allowed` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_verify_grant_json(
    grant_json: *const c_char,
    issuer_keys_json: *const c_char,
    expected_subject: *const c_char,
    expected_root_issuer: *const c_char,
    requested_cap: *const c_char,
    now_unix: u64,
    crl_json_opt: *const c_char,
    out_allowed: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if out_allowed.is_null() {
            set_last_error("null out_allowed");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(grant_s) = (unsafe { cstr_to_str(grant_json, "grant_json") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(keys_s) = (unsafe { cstr_to_str(issuer_keys_json, "issuer_keys_json") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(subj_s) = (unsafe { cstr_to_str(expected_subject, "expected_subject") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(root_s) = (unsafe { cstr_to_str(expected_root_issuer, "expected_root_issuer") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(cap_s) = (unsafe { cstr_to_str(requested_cap, "requested_cap") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(crl_opt_s) = (unsafe { opt_cstr_to_str(crl_json_opt, "crl_json_opt") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };

        let grant: Grant = match serde_json::from_str(grant_s) {
            Ok(g) => g,
            Err(e) => {
                set_last_error(json_error("grant_json", &e));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let key_map_raw: HashMap<String, String> = match serde_json::from_str(keys_s) {
            Ok(m) => m,
            Err(e) => {
                set_last_error(json_error("issuer_keys_json", &e));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let mut key_map: HashMap<String, HybridSigningPublicKey> =
            HashMap::with_capacity(key_map_raw.len());
        for (id, b64) in key_map_raw {
            let Ok(k) = HybridSigningPublicKey::from_b64url(&b64) else {
                set_last_error(format!("invalid signing key for issuer {id}"));
                return TENDRIL_ERR_INVALID_ARG;
            };
            key_map.insert(id, k);
        }
        let crl: Option<RevocationList> = match crl_opt_s {
            Some(s) if !s.is_empty() => match serde_json::from_str(s) {
                Ok(c) => Some(c),
                Err(e) => {
                    set_last_error(json_error("crl_json_opt", &e));
                    return TENDRIL_ERR_INVALID_ARG;
                }
            },
            _ => None,
        };

        let (res, _audit) = authorize_grant(
            Some(&grant),
            subj_s,
            root_s,
            cap_s,
            now_unix,
            crl.as_ref(),
            |issuer| key_map.get(issuer).cloned(),
        );
        if let Err(ref err) = res {
            set_last_error(err.to_string());
        }
        unsafe {
            *out_allowed = u8::from(res.is_ok());
        }
        TENDRIL_OK
    })
}

/// Creates an endpoint handle backed by `state_dir` or an ephemeral in-memory store.
///
/// # Safety
/// `state_dir` and `host_id` must be null or valid NUL-terminated UTF-8 C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_new(
    state_dir: *const c_char,
    host_id: *const c_char,
) -> *mut TendrilEndpoint {
    ffi_ptr(|| {
        let Ok(dir_opt) = (unsafe { opt_cstr_to_str(state_dir, "state_dir") }) else {
            return ptr::null_mut();
        };
        let Ok(host_opt) = (unsafe { opt_cstr_to_str(host_id, "host_id") }) else {
            return ptr::null_mut();
        };

        let (store, identity, roster) = if let Some(dir) = dir_opt.filter(|d| !d.is_empty()) {
            let store = match StateStore::open_or_create(dir) {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    set_last_error(e.to_string());
                    return ptr::null_mut();
                }
            };
            let identity = match store.load_or_generate_identity(host_opt) {
                Ok(id) => id,
                Err(e) => {
                    set_last_error(e.to_string());
                    return ptr::null_mut();
                }
            };
            let roster = match store.load_roster() {
                Ok(r) => r,
                Err(e) => {
                    set_last_error(e.to_string());
                    return ptr::null_mut();
                }
            };
            (Some(store), identity, roster)
        } else {
            let mut identity = match EndpointIdentity::generate() {
                Ok(id) => id,
                Err(e) => {
                    set_last_error(e.to_string());
                    return ptr::null_mut();
                }
            };
            if let Some(h) = host_opt
                && !h.is_empty()
            {
                identity = identity.with_host_id(h);
            }
            (None, identity, Roster::new())
        };

        build_endpoint_handle(store, identity, roster)
    })
}

/// Creates an in-memory endpoint handle restored from optional sealed identity/roster JSON without
/// touching plaintext storage on disk.
///
/// # Safety
/// `identity_json_opt`, `roster_json_opt`, and `host_id_opt` must be null or valid NUL-terminated UTF-8 C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_new_from_state(
    identity_json_opt: *const c_char,
    roster_json_opt: *const c_char,
    host_id_opt: *const c_char,
) -> *mut TendrilEndpoint {
    ffi_ptr(|| {
        let Ok(id_json) = (unsafe { opt_cstr_to_str(identity_json_opt, "identity_json_opt") })
        else {
            return ptr::null_mut();
        };
        let Ok(roster_json) = (unsafe { opt_cstr_to_str(roster_json_opt, "roster_json_opt") })
        else {
            return ptr::null_mut();
        };
        let Ok(host_opt) = (unsafe { opt_cstr_to_str(host_id_opt, "host_id_opt") }) else {
            return ptr::null_mut();
        };

        let identity = match identity_from_json_or_generate(id_json, host_opt) {
            Ok(id) => id,
            Err(e) => {
                set_last_error(e);
                return ptr::null_mut();
            }
        };
        let roster = match roster_from_json(roster_json) {
            Ok(r) => r,
            Err(e) => {
                set_last_error(e);
                return ptr::null_mut();
            }
        };

        build_endpoint_handle(None, identity, roster)
    })
}

fn identity_from_json_or_generate(
    identity_json: Option<&str>,
    host_id: Option<&str>,
) -> Result<EndpointIdentity, String> {
    if let Some(raw) = identity_json.filter(|s| !s.is_empty()) {
        return deserialize_identity_json(raw).map_err(|e| e.to_string());
    }
    let mut id = EndpointIdentity::generate().map_err(|e| e.to_string())?;
    if let Some(h) = host_id
        && !h.is_empty()
    {
        id = id.with_host_id(h);
    }
    Ok(id)
}

fn roster_from_json(roster_json: Option<&str>) -> Result<Roster, String> {
    match roster_json.filter(|s| !s.is_empty()) {
        Some(raw) => serde_json::from_str(raw).map_err(|e| json_error("roster json", &e)),
        None => Ok(Roster::new()),
    }
}

/// Opens `dir` as a sealed runtime store per the sealed open rules: existing runtime state needs
/// the identity that sealed it, a generated identity writes no runtime state, and `roster_json`
/// seeds only a directory without runtime state, under the identity the caller already saved.
fn open_sealed_endpoint_state(
    dir: &str,
    identity_json: Option<&str>,
    roster_json: Option<&str>,
    host_id: Option<&str>,
) -> Result<(StateStore, EndpointIdentity, Roster), String> {
    let seed = roster_json.filter(|s| !s.is_empty());
    if identity_json.is_none_or(str::is_empty) {
        if seed.is_some() {
            return Err("a roster seed requires the saved identity".to_owned());
        }
        if StateStore::sealed_state_exists(dir).map_err(|e| e.to_string())? {
            return Err("sealed runtime state exists but no identity was supplied".to_owned());
        }
    }
    let identity = identity_from_json_or_generate(identity_json, host_id)?;
    let store = StateStore::open_sealed(dir, &identity).map_err(|e| e.to_string())?;
    if seed.is_some() {
        store
            .seed_roster_if_absent_with(|| roster_from_json(seed).map_err(RuntimeError::Storage))
            .map_err(|e| e.to_string())?;
    }
    let roster = store.load_roster().map_err(|e| e.to_string())?;
    Ok((store, identity, roster))
}

/// Creates an endpoint whose roster and group state the runtime persists itself in `state_dir`
/// (`rt-roster.sealed`, `rt-groups.sealed`), sealed under a key derived from the identity. The
/// identity stays caller-sealed: without `identity_json_opt` one is generated and nothing is
/// written, so the caller saves it and reopens with it. `roster_json_opt` needs
/// `identity_json_opt` and is parsed and written only for a directory with no runtime state.
///
/// # Safety
/// `state_dir`, `identity_json_opt`, `roster_json_opt`, and `host_id_opt` must be null or valid
/// NUL-terminated UTF-8 C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_new_sealed(
    state_dir: *const c_char,
    identity_json_opt: *const c_char,
    roster_json_opt: *const c_char,
    host_id_opt: *const c_char,
) -> *mut TendrilEndpoint {
    ffi_ptr(|| {
        let Ok(dir_opt) = (unsafe { opt_cstr_to_str(state_dir, "state_dir") }) else {
            return ptr::null_mut();
        };
        let Ok(id_json) = (unsafe { opt_cstr_to_str(identity_json_opt, "identity_json_opt") })
        else {
            return ptr::null_mut();
        };
        let Ok(roster_json) = (unsafe { opt_cstr_to_str(roster_json_opt, "roster_json_opt") })
        else {
            return ptr::null_mut();
        };
        let Ok(host_opt) = (unsafe { opt_cstr_to_str(host_id_opt, "host_id_opt") }) else {
            return ptr::null_mut();
        };
        let Some(dir) = dir_opt.filter(|d| !d.is_empty()) else {
            set_last_error("state_dir is required for a sealed endpoint");
            return ptr::null_mut();
        };
        match open_sealed_endpoint_state(dir, id_json, roster_json, host_opt) {
            Ok((store, identity, roster)) => {
                build_endpoint_handle(Some(Arc::new(store)), identity, roster)
            }
            Err(e) => {
                set_last_error(e);
                ptr::null_mut()
            }
        }
    })
}

/// Closes the endpoint's inbound router, wakes any parked `pair_accept`/`session_accept` calls and
/// stops the route announcer's refresh timer.
///
/// Safe to invoke concurrently with blocked accept calls prior to calling [`tendril_endpoint_free`].
///
/// # Safety
/// `ep` must be a valid endpoint pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_close(ep: *mut TendrilEndpoint) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let ep = unsafe { &*ep };
        ep.router.close();
        if let Some(groups) = ep.group_runtime() {
            groups.shutdown();
        }
        ep.stop_hosting();
        TENDRIL_OK
    })
}

/// Serializes the endpoint's private identity JSON for caller-managed sealed storage.
///
/// # Safety
/// `ep` must be a valid endpoint pointer and `out_json` must be non-null; free result with [`tendril_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_export_identity_json(
    ep: *const TendrilEndpoint,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let ep = unsafe { &*ep };
        let json = match serialize_identity_json(&ep.identity) {
            Ok(j) => j,
            Err(e) => {
                set_last_error(e.to_string());
                return TENDRIL_ERR_INTERNAL;
            }
        };
        unsafe { write_out_cstring(out_json, &json) }
    })
}

/// Serializes the endpoint's current roster JSON for caller-managed sealed storage.
///
/// # Safety
/// `ep` must be a valid endpoint pointer and `out_json` must be non-null; free result with [`tendril_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_export_roster_json(
    ep: *const TendrilEndpoint,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let ep = unsafe { &*ep };
        if let Err(e) = ep.load_roster_from_store() {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        unsafe { write_roster_json_out(&ep.roster, out_json) }
    })
}

/// Frees a [`TendrilEndpoint`] handle previously returned by [`tendril_endpoint_new`].
///
/// # Safety
/// `ep` must be null or an unfreed pointer returned by [`tendril_endpoint_new`], with no concurrent calls using `ep`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_free(ep: *mut TendrilEndpoint) {
    if !ep.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(ep));
        }));
    }
}

/// Serializes the endpoint's public identity metadata as JSON.
///
/// # Safety
/// `ep` must be a valid endpoint pointer and `out_json` must be a valid out pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_info_json(
    ep: *const TendrilEndpoint,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let ep = unsafe { &*ep };
        let info = serde_json::json!({
            "host_id": ep.identity.host_id(),
            "device_id": ep.identity.device_id(),
            "static_pub": b64url_encode(ep.identity.static_key().public_bytes()),
            "signing_pub": ep.identity.signing_key().public_key().to_b64url(),
            "signing_pub_hash": b64url_encode(&ep.identity.signing_key().signing_pub_hash()),
            "relay_pub": b64url_encode(ep.identity.signing_key().ed25519_public_bytes()),
        });
        unsafe { write_out_cstring(out_json, &info.to_string()) }
    })
}

/// Binds a direct TCP listener on `listen_addr` (defaulting to `127.0.0.1:0` when null).
///
/// # Safety
/// `ep` must be a valid endpoint pointer; `listen_addr` may be null or UTF-8; `out_endpoint` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_serve_direct(
    ep: *mut TendrilEndpoint,
    listen_addr: *const c_char,
    out_endpoint: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_endpoint.is_null() {
            set_last_error("null endpoint or out_endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let addr_opt = match unsafe { opt_cstr_to_str(listen_addr, "listen_addr") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let addr: SocketAddr = match addr_opt.unwrap_or("127.0.0.1:0").parse() {
            Ok(a) => a,
            Err(e) => {
                set_last_error(format!("invalid listen_addr: {e}"));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let ep = unsafe { &*ep };
        match ep.rt.block_on(DirectListener::bind(addr, None)) {
            Ok(listener) => {
                let local_ep = listener.local_endpoint();
                let served = ServedListener::from_listener(listener.tcp_listener()).ok();
                ep.spawn_listener(Box::new(listener));
                ep.record_served(local_ep.clone(), served);
                unsafe { write_out_cstring(out_endpoint, &local_ep) }
            }
            Err(e) => {
                set_last_error(e.to_string());
                TENDRIL_ERR_PROTOCOL
            }
        }
    })
}

/// Registers this endpoint's mailbox on a Tendril v1 WebSocket relay.
///
/// # Safety
/// `ep` and `relay_url` must be valid; `expected_host` may be null or UTF-8; `out_endpoint` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_serve_relay(
    ep: *mut TendrilEndpoint,
    relay_url: *const c_char,
    expected_host: *const c_char,
    out_endpoint: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_endpoint.is_null() {
            set_last_error("null endpoint or out_endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let url = match unsafe { cstr_to_str(relay_url, "relay_url") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let exp_host = match unsafe { opt_cstr_to_str(expected_host, "expected_host") } {
            Ok(v) => v.map(ToOwned::to_owned),
            Err(rc) => return rc,
        };
        let ep = unsafe { &*ep };
        let cfg = ep.snapshot_transport_cfg();
        let signing_key = ep.identity.signing_key().ed25519_signing_key();
        match ep.rt.block_on(RelayListener::bind_with_auth(
            url,
            exp_host,
            signing_key,
            DEFAULT_WRITE_TIMEOUT,
            cfg.relay_auth.clone(),
        )) {
            Ok(listener) => {
                let local_ep = listener.local_endpoint();
                ep.spawn_listener(Box::new(listener));
                ep.served_v1_relays
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(url.to_owned());
                ep.record_served(local_ep.clone(), None);
                unsafe { write_out_cstring(out_endpoint, &local_ep) }
            }
            Err(e) => {
                set_last_error(e.to_string());
                TENDRIL_ERR_PROTOCOL
            }
        }
    })
}

/// Binds an `iroh` P2P listener using this endpoint's HKDF-derived P2P identity seed.
///
/// `relay_mode_opt` may be null/`""`/`"default"`, `"disabled"`/`"local"`, or a relay `https://` URL.
///
/// # Safety
/// `ep` must be a valid endpoint pointer; `relay_mode_opt` may be null or UTF-8; `out_endpoint` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_serve_p2p(
    ep: *mut TendrilEndpoint,
    relay_mode_opt: *const c_char,
    out_endpoint: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_endpoint.is_null() {
            set_last_error("null endpoint or out_endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let mode_opt = match unsafe { opt_cstr_to_str(relay_mode_opt, "relay_mode_opt") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let ep = unsafe { &*ep };
        #[cfg(feature = "p2p-iroh")]
        {
            let cfg = ep.snapshot_transport_cfg();
            let opts = match cfg.build_p2p_listener_options(mode_opt) {
                Ok(o) => o,
                Err(e) => {
                    set_last_error(e.to_string());
                    return TENDRIL_ERR_INVALID_ARG;
                }
            };
            let seed = ep.identity.derive_p2p_identity_seed();
            match ep
                .rt
                .block_on(P2pListener::bind_with_options(opts, Some(seed)))
            {
                Ok(listener) => {
                    let local_ep = listener.local_endpoint();
                    ep.spawn_listener(Box::new(listener));
                    ep.record_served(local_ep.clone(), None);
                    unsafe { write_out_cstring(out_endpoint, &local_ep) }
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    TENDRIL_ERR_PROTOCOL
                }
            }
        }
        #[cfg(not(feature = "p2p-iroh"))]
        {
            let _ = (ep, mode_opt);
            set_last_error("tendril-ffi built without p2p-iroh feature");
            TENDRIL_ERR_PROTOCOL
        }
    })
}

/// Issues a one-time pairing code (`"lan"` or `"remote"`, defaults to `"lan"`).
///
/// # Safety
/// `ep` must be a valid endpoint pointer; `kind` may be null; `out_code` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_issue_code(
    ep: *mut TendrilEndpoint,
    kind: *const c_char,
    out_code: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_code.is_null() {
            set_last_error("null endpoint or out_code");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let kind_opt = match unsafe { opt_cstr_to_str(kind, "kind") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let pk = match kind_opt.filter(|k| !k.is_empty()).map(str::parse) {
            None => PairingCodeKind::Lan2Group,
            Some(Ok(kind)) => kind,
            Some(Err(_)) => {
                set_last_error("invalid pairing code kind: expected lan or remote");
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let ep = unsafe { &*ep };
        let issued = ep
            .pair_mgr
            .lock()
            .expect("pair_mgr mutex poisoned")
            .issue_code(pk, now_unix());
        match issued {
            Ok(code) => {
                let code = Zeroizing::new(code);
                unsafe { write_out_cstring(out_code, &code) }
            }
            Err(e) => {
                set_last_error(e.to_string());
                TENDRIL_ERR_INTERNAL
            }
        }
    })
}

/// Initiates a pairing handshake toward `endpoint` using `code`.
///
/// # Safety
/// `ep`, `endpoint`, `code`, and `out_json` must be non-null valid pointers; optional strings may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_pair_initiate(
    ep: *mut TendrilEndpoint,
    endpoint: *const c_char,
    relay_host: *const c_char,
    code: *const c_char,
    name: *const c_char,
    kind: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(endpoint_s) = (unsafe { cstr_to_str(endpoint, "endpoint") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(relay_host_s) = (unsafe { opt_cstr_to_str(relay_host, "relay_host") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(code_s) = (unsafe { cstr_to_str(code, "code") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(name_s) = (unsafe { opt_cstr_to_str(name, "name") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(kind_s) = (unsafe { opt_cstr_to_str(kind, "kind") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };

        let ep = unsafe { &*ep };
        let cfg = ep.snapshot_transport_cfg();
        if let Err(e) = ep.load_roster_from_store() {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        let roster_snapshot = lock_roster(&ep.roster).clone();
        let v2_secret = if is_v2_relay_endpoint(endpoint_s) {
            match lookup_v2_mailbox_secret_for_pair(&roster_snapshot, None, endpoint_s, now_unix())
            {
                Ok(s) => Some(s),
                Err(e) => {
                    set_last_error(e.to_string());
                    return TENDRIL_ERR_PROTOCOL;
                }
            }
        } else {
            None
        };
        let res = ep.rt.block_on(async {
            let mut stream =
                dial_endpoint_v2_with_options(endpoint_s, relay_host_s, &cfg, v2_secret)
                    .await
                    .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))?;
            let device_name = name_s.unwrap_or("ffi-device").to_owned();
            let device_kind = kind_s.unwrap_or("ffi").to_owned();
            let pair_res = drive_v1_pair_initiator_with_roster_floors(
                stream.as_mut(),
                &ep.identity,
                device_name,
                device_kind,
                code_s.to_owned(),
                &roster_snapshot,
            )
            .await
            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()));
            let _ = stream.close().await;
            pair_res
        });

        match res {
            Ok(outcome) => match outcome {
                PairOutcome::InitiatorPending {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    pairing_sas,
                    host_pin_verified,
                } => {
                    if let Err((rc, msg)) = ep.mutate_roster(|roster| {
                        let pin_res = if host_pin_verified {
                            roster.insert_pinned_host(
                                host_id.clone(),
                                host_id.clone(),
                                host_static_pub,
                                Some(host_signing_pub),
                                host_rotation_seq,
                                Vec::new(),
                            )
                        } else {
                            roster.record_pending_host(
                                host_id.clone(),
                                host_id.clone(),
                                host_static_pub,
                                host_signing_pub,
                                host_rotation_seq,
                                pairing_sas.clone(),
                                Vec::new(),
                            )
                        };
                        pin_res
                            .map(|_| ())
                            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))
                    }) {
                        set_last_error(msg);
                        return rc;
                    }
                    let out = serde_json::json!({
                        "device_id": device_id,
                        "host_id": host_id,
                        "sas": pairing_sas,
                        "status": if host_pin_verified { "active" } else { "pending" },
                        "host_confirmed": host_pin_verified,
                    });
                    unsafe { write_out_cstring(out_json, &out.to_string()) }
                }
                PairOutcome::Rejected { error } => {
                    set_last_error(error);
                    TENDRIL_ERR_PROTOCOL
                }
                PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                    set_last_error("unexpected responder outcome");
                    TENDRIL_ERR_INTERNAL
                }
                PairOutcome::InitiatorEnrolled { .. } => {
                    set_last_error("unexpected m2m enrollment outcome");
                    TENDRIL_ERR_INTERNAL
                }
            },
            Err((rc, msg)) => {
                set_last_error(msg);
                rc
            }
        }
    })
}

/// Accepts the next incoming pairing connection within `timeout_ms`.
///
/// # Safety
/// `ep` must be a valid endpoint pointer and `out_json` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_pair_accept(
    ep: *mut TendrilEndpoint,
    timeout_ms: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let ep = unsafe { &*ep };
        let wait = Duration::from_millis(timeout_ms);
        let policy = if ep.m2m_enabled.load(Ordering::Acquire) {
            EnrollmentPolicy::enabled_default()
        } else {
            EnrollmentPolicy::default()
        };
        let res = ep.rt.block_on(async {
            let (mut stream, guard) = match ep.router.recv_pair(wait).await {
                Ok(Some(pair)) => pair,
                Ok(None) => return Err((TENDRIL_ERR_CLOSED, "listener closed".to_owned())),
                Err(()) => {
                    return Err((TENDRIL_WOULD_BLOCK, "timed out accepting pair".to_owned()));
                }
            };

            let path_kind = pairing_path_kind_for_provider(stream.provider_id());
            if let Some(ref store) = ep.store {
                drive_pair_responder_with_store(
                    stream.as_mut(),
                    &ep.identity,
                    &ep.pair_mgr,
                    store,
                    &ep.store_lock,
                    path_kind,
                    now_unix(),
                    policy,
                    Some(ep.router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            } else {
                drive_pair_responder_with_policy(
                    stream.as_mut(),
                    &ep.identity,
                    &ep.pair_mgr,
                    &ep.roster,
                    path_kind,
                    now_unix(),
                    policy,
                    Some(ep.router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            }
            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))
        });
        if !matches!(res, Err((TENDRIL_WOULD_BLOCK | TENDRIL_ERR_CLOSED, _)))
            && let Err(e) = ep.load_roster_from_store()
        {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }

        match res {
            Ok(pair_res) => match pair_res.outcome {
                PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => {
                    let out = serde_json::json!({
                        "device_id": device_id,
                        "sas": pairing_sas,
                        "name": name,
                        "kind": kind,
                    });
                    unsafe { write_out_cstring(out_json, &out.to_string()) }
                }
                PairOutcome::ResponderEnrolled {
                    device_id,
                    token_nonce,
                    name,
                    kind,
                    ..
                } => {
                    let out = serde_json::json!({
                        "device_id": device_id,
                        "status": "active",
                        "token_nonce": token_nonce,
                        "name": name,
                        "kind": kind,
                    });
                    unsafe { write_out_cstring(out_json, &out.to_string()) }
                }
                PairOutcome::Rejected { error } => {
                    set_last_error(error);
                    TENDRIL_ERR_PROTOCOL
                }
                PairOutcome::InitiatorPending { .. } | PairOutcome::InitiatorEnrolled { .. } => {
                    set_last_error("unexpected initiator outcome");
                    TENDRIL_ERR_INTERNAL
                }
            },
            Err((rc, msg)) => {
                set_last_error(msg);
                rc
            }
        }
    })
}

/// Promotes a pending paired peer to `Active` (`pair.confirm`), requiring SAS verification
/// whenever a live pairing SAS was recorded (`sas` may be NULL only if no SAS was recorded).
///
/// # Safety
/// `ep` and `peer_id` must be non-null valid pointers; `sas` may be null or UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_confirm_peer(
    ep: *mut TendrilEndpoint,
    peer_id: *const c_char,
    sas: *const c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(peer_s) = (unsafe { cstr_to_str(peer_id, "peer_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(sas_opt) = (unsafe { opt_cstr_to_str(sas, "sas") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let ep = unsafe { &*ep };
        match ep.mutate_roster(|roster| {
            roster
                .confirm_peer(peer_s, sas_opt)
                .map(|_| ())
                .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))
        }) {
            Ok(()) => TENDRIL_OK,
            Err((rc, msg)) => {
                set_last_error(msg);
                rc
            }
        }
    })
}

/// Mints a signed capability grant JSON object for an active peer (`pair.mint`).
///
/// # Safety
/// `ep`, `peer_id`, `caps_json`, and `out_grant_json` must be valid non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_mint_grant(
    ep: *mut TendrilEndpoint,
    peer_id: *const c_char,
    caps_json: *const c_char,
    ttl_secs: u64,
    out_grant_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_grant_json.is_null() {
            set_last_error("null endpoint or out_grant_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(peer_s) = (unsafe { cstr_to_str(peer_id, "peer_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(caps_s) = (unsafe { cstr_to_str(caps_json, "caps_json") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let caps: Vec<String> = match serde_json::from_str(caps_s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(json_error("caps_json", &e));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let nonce = match random_bytes::<16>() {
            Ok(n) => n,
            Err(e) => {
                set_last_error(e.to_string());
                return TENDRIL_ERR_INTERNAL;
            }
        };
        let ep = unsafe { &*ep };
        let now = now_unix();
        let grant = match ep.mutate_roster(|roster| {
            roster
                .mint_grant(
                    &ep.identity,
                    peer_s,
                    caps,
                    now,
                    now.saturating_add(ttl_secs),
                    nonce,
                )
                .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))
        }) {
            Ok(g) => g,
            Err((rc, msg)) => {
                set_last_error(msg);
                return rc;
            }
        };
        let json = Zeroizing::new(serde_json::to_string(&grant).expect("serialize grant"));
        unsafe { write_out_cstring(out_grant_json, &json) }
    })
}

/// Marks `peer_id` as `Revoked` and clears its stored grants (`pair.revoke`).
///
/// # Safety
/// `ep` and `peer_id` must be valid non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_revoke_peer(
    ep: *mut TendrilEndpoint,
    peer_id: *const c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(peer_s) = (unsafe { cstr_to_str(peer_id, "peer_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let ep = unsafe { &*ep };
        if let Err((rc, msg)) = ep.mutate_roster(|roster| {
            roster
                .revoke_peer(peer_s)
                .map_err(|e| (TENDRIL_ERR_NOT_FOUND, e.to_string()))
        }) {
            set_last_error(msg);
            return rc;
        }
        ep.refresh_m2m_enabled(&lock_roster(&ep.roster));
        TENDRIL_OK
    })
}

/// Registers an active external hybrid signing trust anchor for M2M enrollment and enables M2M mode.
///
/// # Safety
/// `ep` and `anchor_id` must be valid non-null pointers and `signing_pub` must point to `signing_pub_len` bytes (`1984`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_add_trust_anchor(
    ep: *mut TendrilEndpoint,
    anchor_id: *const c_char,
    signing_pub: *const u8,
    signing_pub_len: usize,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(anchor_s) = (unsafe { cstr_to_str(anchor_id, "anchor_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(signing_pub_key) =
            (unsafe { read_hybrid_signing_pub(signing_pub, signing_pub_len, "signing_pub") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let ep = unsafe { &*ep };
        if let Err((rc, msg)) = ep.mutate_roster(|roster| {
            roster
                .add_trust_anchor(anchor_s.to_owned(), signing_pub_key)
                .map(|_| ())
                .map_err(|e| {
                    let rc = match e {
                        CoreError::IncompletePin(_) => TENDRIL_ERR_INVALID_ARG,
                        _ => TENDRIL_ERR_PROTOCOL,
                    };
                    (rc, e.to_string())
                })
        }) {
            set_last_error(msg);
            return rc;
        }
        ep.refresh_m2m_enabled(&lock_roster(&ep.roster));
        ep.router.set_pair_enabled(true);
        TENDRIL_OK
    })
}

/// Revokes an external hybrid signing trust anchor and any sibling anchors sharing its signing key.
///
/// # Safety
/// `ep` and `anchor_id` must be valid non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_revoke_trust_anchor(
    ep: *mut TendrilEndpoint,
    anchor_id: *const c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(anchor_s) = (unsafe { cstr_to_str(anchor_id, "anchor_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let ep = unsafe { &*ep };
        if let Err((rc, msg)) = ep.mutate_roster(|roster| {
            roster
                .revoke_trust_anchor(anchor_s)
                .map_err(|e| (TENDRIL_ERR_NOT_FOUND, e.to_string()))
        }) {
            set_last_error(msg);
            return rc;
        }
        ep.refresh_m2m_enabled(&lock_roster(&ep.roster));
        TENDRIL_OK
    })
}

/// Mints a short-lived single-use M2M enrollment token JSON object; enables local M2M acceptance
/// when `target_host_id` matches the local endpoint's `host_id`.
///
/// # Safety
/// `ep`, `target_host_id`, and `out_token_json` must be valid non-null pointers; `subject_opt` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_mint_enrollment_token(
    ep: *mut TendrilEndpoint,
    target_host_id: *const c_char,
    subject_opt: *const c_char,
    ttl_secs: u64,
    out_token_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_token_json.is_null() {
            set_last_error("null endpoint or out_token_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(target_s) = (unsafe { cstr_to_str(target_host_id, "target_host_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(subject_s) = (unsafe { opt_cstr_to_str(subject_opt, "subject_opt") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let nonce = match random_bytes::<16>() {
            Ok(n) => n,
            Err(e) => {
                set_last_error(e.to_string());
                return TENDRIL_ERR_INTERNAL;
            }
        };
        let ep = unsafe { &*ep };
        let token = match mint_enrollment_token(
            &ep.identity,
            target_s,
            subject_s,
            now_unix(),
            ttl_secs,
            nonce,
        ) {
            Ok(t) => t,
            Err(e) => {
                set_last_error(e.to_string());
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        if target_s == ep.identity.host_id() {
            ep.self_m2m_enabled.store(true, Ordering::Release);
            ep.refresh_m2m_enabled(&lock_roster(&ep.roster));
            ep.router.set_pair_enabled(true);
        }
        let json =
            Zeroizing::new(serde_json::to_string(&token).expect("serialize enrollment token"));
        unsafe { write_out_cstring(out_token_json, &json) }
    })
}

/// Initiates autonomous M2M enrollment toward a pinned host using `token_json`.
///
/// # Safety
/// `ep`, `endpoint`, `host_id`, `host_static_pub_32`, `host_signing_pin`, `token_json`, and
/// `out_json` must be valid non-null pointers (`host_signing_pin_len` must be `1984` or `32`);
/// optional strings may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_enroll_initiate(
    ep: *mut TendrilEndpoint,
    endpoint: *const c_char,
    relay_host_opt: *const c_char,
    host_id: *const c_char,
    host_static_pub_32: *const u8,
    host_signing_pin: *const u8,
    host_signing_pin_len: usize,
    host_rotation_seq: u64,
    token_json: *const c_char,
    name: *const c_char,
    kind: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(endpoint_s) = (unsafe { cstr_to_str(endpoint, "endpoint") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(relay_host_s) = (unsafe { opt_cstr_to_str(relay_host_opt, "relay_host_opt") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(host_id_s) = (unsafe { cstr_to_str(host_id, "host_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(static_pub) = (unsafe { read_bytes32(host_static_pub_32, "host_static_pub_32") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(signing_pin) = (unsafe {
            read_signing_pin(host_signing_pin, host_signing_pin_len, "host_signing_pin")
        }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(token_s) = (unsafe { cstr_to_str(token_json, "token_json") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(name_s) = (unsafe { opt_cstr_to_str(name, "name") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(kind_s) = (unsafe { opt_cstr_to_str(kind, "kind") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let token: Grant = match serde_json::from_str(token_s) {
            Ok(t) => t,
            Err(e) => {
                set_last_error(json_error("token_json", &e));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let pinned_host = PinnedHost {
            host_id: Some(host_id_s.to_owned()),
            static_pub,
            signing_pin,
            rotation_seq: host_rotation_seq,
        };

        let ep = unsafe { &*ep };
        let cfg = ep.snapshot_transport_cfg();
        if let Err(e) = ep.load_roster_from_store() {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        let pairing_floor = {
            let roster = lock_roster(&ep.roster);
            pinned_pairing_floor(&roster, &pinned_host)
        };
        let res = ep.rt.block_on(async {
            let mut stream = dial_endpoint_v2_with_options(endpoint_s, relay_host_s, &cfg, None)
                .await
                .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))?;
            let device_name = name_s.unwrap_or("ffi-machine").to_owned();
            let device_kind = kind_s.unwrap_or("machine").to_owned();
            let pair_res = drive_m2m_enroll_initiator_with_floor(
                stream.as_mut(),
                &ep.identity,
                device_name,
                device_kind,
                token,
                pinned_host,
                pairing_floor,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()));
            let _ = stream.close().await;
            pair_res
        });

        match res {
            Ok(pair_res) => match pair_res.outcome {
                PairOutcome::InitiatorEnrolled {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    token_nonce,
                } => {
                    if let Err((rc, msg)) = ep.mutate_roster(|roster| {
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
                            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))
                    }) {
                        set_last_error(msg);
                        return rc;
                    }
                    let out = serde_json::json!({
                        "device_id": device_id,
                        "host_id": host_id,
                        "status": "active",
                        "host_rotation_seq": host_rotation_seq,
                        "token_nonce": token_nonce,
                    });
                    unsafe { write_out_cstring(out_json, &out.to_string()) }
                }
                PairOutcome::Rejected { error } => {
                    set_last_error(error);
                    TENDRIL_ERR_PROTOCOL
                }
                PairOutcome::InitiatorPending { .. } => {
                    set_last_error("unexpected human pending outcome");
                    TENDRIL_ERR_PROTOCOL
                }
                PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                    set_last_error("unexpected responder outcome");
                    TENDRIL_ERR_INTERNAL
                }
            },
            Err((rc, msg)) => {
                set_last_error(msg);
                rc
            }
        }
    })
}

fn parse_grant_json(raw: Option<&str>, name: &str) -> Result<Option<Grant>, String> {
    match raw {
        Some(g) if !g.is_empty() => serde_json::from_str(g)
            .map(Some)
            .map_err(|e| json_error(name, &e)),
        _ => Ok(None),
    }
}

/// Inputs of a Day-2 connect through the runtime policy path.
struct ConnectRequest<'a> {
    wire: u8,
    target: &'a str,
    grant: Option<Grant>,
    /// Explicit operator endpoint; `None` connects over the stored routes.
    endpoint: Option<&'a str>,
    relay_host: Option<&'a str>,
    recovery_uri: Option<String>,
    replace_routes: bool,
    route_policy: Option<RoutePolicy>,
}

/// Runs `SessionDriver` / `V2SessionDriver::connect_with_policy_and_store` against the
/// endpoint's roster handle and wraps the winner. Route sets the session receives are ingested
/// under the effective route policy.
///
/// A Wire v2 connect to an explicit endpoint on an endpoint with a configured `WakeProvider`
/// runs the wake around the policy connect ([`connect_with_wake`]),
/// so a woken connect also negotiates `route_seq`, ingests route sets and honours a recovery
/// URI.
fn connect_session(ep: &TendrilEndpoint, req: ConnectRequest<'_>) -> *mut TendrilSession {
    let cfg = ep.snapshot_transport_cfg();
    let endpoint = req.endpoint.filter(|e| !e.is_empty());
    let dialers = match cfg.hint_dialers(endpoint, req.relay_host) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(e.to_string());
            return ptr::null_mut();
        }
    };
    let connect_once = || {
        let mut opts = ConnectOpts::new(Arc::clone(&dialers));
        opts.grant.clone_from(&req.grant);
        opts.recovery_uri.clone_from(&req.recovery_uri);
        opts.replace_routes = req.replace_routes;
        opts.policy = req.route_policy.unwrap_or(cfg.route_policy);
        opts.operator_endpoint = endpoint.map(ToOwned::to_owned);
        opts.relay_auth_origins.clone_from(&cfg.relay_auth_origins);
        policy_connect(ep, req.wire, req.target, opts)
    };
    let wake = cfg
        .wake
        .as_ref()
        .filter(|_| req.wire == 2 && endpoint.is_some());
    let res = ep.rt.block_on(async {
        match wake {
            Some(wake) => connect_with_wake(wake, connect_once).await,
            None => connect_once().await,
        }
    });
    let synced = ep.load_roster_from_store();
    match res {
        Ok(session) => {
            if let Err(e) = synced {
                set_last_error(e);
                return ptr::null_mut();
            }
            Box::into_raw(Box::new(TendrilSession {
                rt: Arc::clone(&ep.rt),
                store: ep.store.clone(),
                store_lock: Arc::clone(&ep.store_lock),
                roster: Arc::clone(&ep.roster),
                route_access: ep.route_access.clone(),
                v1_root_id: (req.wire != 2).then(|| req.target.to_owned()),
                v1_local_signing: None,
                local_device_id: ep.identity.device_id(),
                session,
            }))
        }
        Err(err) => {
            let msg = attempt_error_message(&err);
            match synced {
                Ok(()) => set_last_error(msg),
                Err(pe) => set_last_error(format!("{msg} (roster sync error: {pe})")),
            }
            ptr::null_mut()
        }
    }
}

/// One policy connect over the endpoint's roster handle.
async fn policy_connect(
    ep: &TendrilEndpoint,
    wire: u8,
    target: &str,
    opts: ConnectOpts,
) -> Result<SessionBackend, AttemptError> {
    let identity = Arc::new(ep.identity.clone());
    if wire == 2 {
        V2SessionDriver::connect_with_policy_and_store(identity, target, &ep.route_access, opts)
            .await
            .map(|r| SessionBackend::v2(r.session))
    } else {
        SessionDriver::connect_with_policy_and_store(identity, target, &ep.route_access, opts)
            .await
            .map(|r| SessionBackend::v1(r.session))
    }
}

/// The wake flow around a whole policy connect: with `pre_wake`, the
/// best-effort wake hint first; without it, one connect first and the wake hint only after a
/// miss a wake can fix ([`AttemptError::is_wakeable_miss`]). Then up to `max_attempts` connects
/// `retry_delay_ms` apart, retried only on such a miss; any other failure is final.
async fn connect_with_wake<T, F, Fut>(
    wake: &WakeTransportConfig,
    mut connect: F,
) -> Result<T, AttemptError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, AttemptError>>,
{
    let retryable = AttemptError::is_wakeable_miss;
    if !wake.pre_wake {
        match connect().await {
            Err(err) if retryable(&err) => {}
            done => return done,
        }
    }
    let now = now_unix();
    let tag = wake.secret.derive_tag(now);
    let wake_timeout = Duration::from_millis(wake.timeout_ms);
    let provider = HttpWakeProvider::new()
        .with_cooldown_secs(0)
        .with_timeout(wake_timeout);
    let _ = timeout(
        wake_timeout,
        provider.notify_best_effort(&wake.target, &tag, now),
    )
    .await;
    let attempts = wake.max_attempts.max(1);
    let mut attempt = 1;
    loop {
        match connect().await {
            Err(err) if retryable(&err) && attempt < attempts => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(wake.retry_delay_ms)).await;
            }
            done => return done,
        }
    }
}

/// Opens an authenticated Noise XX session toward `target_host_id`.
///
/// A `NULL` or empty `endpoint` connects over the peer's stored routes; a non-empty one is an explicit operator endpoint dialed alone.
///
/// # Safety
/// `ep` and `target_host_id` must be valid non-null pointers; `endpoint`, `relay_host` and
/// `grant_json` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_connect(
    ep: *mut TendrilEndpoint,
    endpoint: *const c_char,
    relay_host: *const c_char,
    target_host_id: *const c_char,
    grant_json: *const c_char,
) -> *mut TendrilSession {
    ffi_ptr(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return ptr::null_mut();
        }
        let Ok(ep_s) = (unsafe { opt_cstr_to_str(endpoint, "endpoint") }) else {
            return ptr::null_mut();
        };
        let Ok(relay_host_s) = (unsafe { opt_cstr_to_str(relay_host, "relay_host") }) else {
            return ptr::null_mut();
        };
        let Ok(target_s) = (unsafe { cstr_to_str(target_host_id, "target_host_id") }) else {
            return ptr::null_mut();
        };
        let Ok(grant_opt) = (unsafe { opt_cstr_to_str(grant_json, "grant_json") }) else {
            return ptr::null_mut();
        };
        let grant = match parse_grant_json(grant_opt, "grant_json") {
            Ok(g) => g,
            Err(e) => {
                set_last_error(e);
                return ptr::null_mut();
            }
        };
        let ep = unsafe { &*ep };
        connect_session(
            ep,
            ConnectRequest {
                wire: 1,
                target: target_s,
                grant,
                endpoint: ep_s,
                relay_host: relay_host_s,
                recovery_uri: None,
                replace_routes: false,
                route_policy: None,
            },
        )
    })
}

/// Accepts and authenticates the next inbound session stream within `timeout_ms`.
///
/// Once groups run, `timeout_ms` bounds the whole wait for a group-routed session, including
/// waiting behind another concurrent accept. A call that was parked on the router when the first
/// group opened and dequeues a stream at that moment completes that stream's handshake under the
/// pre-auth timeouts, outside `timeout_ms`.
///
/// # Safety
/// `ep` must be a valid endpoint pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_accept(
    ep: *mut TendrilEndpoint,
    timeout_ms: u64,
) -> *mut TendrilSession {
    ffi_ptr(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return ptr::null_mut();
        }
        let ep = unsafe { &*ep };
        let wait = Duration::from_millis(timeout_ms);
        let accepted = std::cell::Cell::new(false);
        let res = ep.rt.block_on(async {
            let deadline = tokio::time::Instant::now() + wait;
            let mut groups = ep.group_runtime();
            let (stream, guard) = loop {
                if let Some(groups) = groups.as_ref() {
                    // The group pumps own the router queue from here on.
                    return match recv_group_queue(&groups.v1_rx, deadline).await {
                        Ok(Some(driver)) => {
                            accepted.set(true);
                            Ok(driver)
                        }
                        Ok(None) => Err("listener closed".to_owned()),
                        Err(_) => Err("timed out accepting session".to_owned()),
                    };
                }
                let ready = ep.group_ready.notified();
                tokio::pin!(ready);
                ready.as_mut().enable();
                groups = ep.group_runtime();
                if groups.is_some() {
                    continue;
                }
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                let (stream, guard) = tokio::select! {
                    () = &mut ready => continue,
                    recv = ep.router.recv_session(left) => match recv {
                        Ok(Some(pair)) => pair,
                        Ok(None) => return Err("listener closed".to_owned()),
                        Err(()) => return Err("timed out accepting session".to_owned()),
                    },
                };
                // A group runtime created while this call was parked now owns group streams.
                let Some(rt_groups) = ep.group_runtime() else {
                    break (stream, guard);
                };
                match rt_groups
                    .hub
                    .accept(
                        stream,
                        &ep.v2_state,
                        Some(ep.router.session_rate_limiter()),
                        Some(guard),
                    )
                    .await
                {
                    Ok(InboundSession::OrdinaryV1 { session, .. }) => {
                        accepted.set(true);
                        return Ok(session);
                    }
                    Ok(_) | Err(_) => groups = Some(rt_groups),
                }
            };
            accepted.set(true);

            if let Some(ref store) = ep.store {
                let mut working_roster = {
                    let _store_guard = ep.store_lock.lock().await;
                    let store_c = store.as_ref().clone();
                    let disk = tokio::task::spawn_blocking(move || store_c.load_roster())
                        .await
                        .map_err(|e| format!("load roster task failed: {e}"))?
                        .map_err(|e| e.to_string())?;
                    let mut guard = lock_roster(&ep.roster);
                    replace_keeping_crls(&mut guard, disk);
                    guard.clone()
                };
                SessionDriver::accept_with_options(
                    stream,
                    &ep.identity,
                    &mut working_roster,
                    now_unix(),
                    Some(ep.router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            } else {
                SessionDriver::accept_locked(
                    stream,
                    &ep.identity,
                    &ep.roster,
                    now_unix(),
                    Some(ep.router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            }
            .map_err(|e| e.to_string())
        });
        let synced = if accepted.get() {
            ep.load_roster_from_store()
        } else {
            Ok(())
        };

        match res {
            Ok(driver) => {
                if let Err(e) = synced {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                let local_id = ep.identity.host_id().to_owned();
                let local_sig = ep.identity.signing_key().public_key().clone();
                let session = SessionBackend::v1(driver);
                if let Err(e) = ep.register_route_session(&session) {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                Box::into_raw(Box::new(TendrilSession {
                    rt: Arc::clone(&ep.rt),
                    store: ep.store.clone(),
                    store_lock: Arc::clone(&ep.store_lock),
                    roster: Arc::clone(&ep.roster),
                    route_access: ep.route_access.clone(),
                    v1_root_id: Some(local_id.clone()),
                    v1_local_signing: Some((local_id, local_sig)),
                    local_device_id: ep.identity.device_id(),
                    session,
                }))
            }
            Err(e) => {
                match synced {
                    Ok(()) => set_last_error(e),
                    Err(pe) => set_last_error(format!("{e} (roster persist error: {pe})")),
                }
                ptr::null_mut()
            }
        }
    })
}

/// Signals parked [`tendril_session_poll_event`] calls on `sess` to exit immediately with `TENDRIL_EOF`.
///
/// Safe to invoke concurrently prior to exclusive [`tendril_session_free`].
///
/// # Safety
/// `sess` must be a valid session pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_shutdown(sess: *mut TendrilSession) -> i32 {
    ffi_i32(|| {
        if sess.is_null() {
            set_last_error("null session");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let sess = unsafe { &*sess };
        sess.session.shutdown();
        TENDRIL_OK
    })
}

/// Serializes the session's shared roster JSON for caller-managed sealed storage.
///
/// # Safety
/// `sess` must be a valid session pointer and `out_json` must be non-null; free result with [`tendril_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_export_roster_json(
    sess: *const TendrilSession,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if sess.is_null() || out_json.is_null() {
            set_last_error("null session or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let sess = unsafe { &*sess };
        if let Err(e) = sess.load_roster_from_store() {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        unsafe { write_roster_json_out(&sess.roster, out_json) }
    })
}

/// Writes the authenticated roster peer identifier of `sess` into `out_peer_id`.
///
/// On responder sessions (`tendril_session_accept` / `tendril_session_accept_v2`) this is the
/// canonical peer `device_id` verified against the Noise static key and active roster pin. On
/// initiator sessions (`tendril_session_connect*`) this is the pinned `target_host_id`.
/// Callers must still evaluate capability grants with [`tendril_session_authorize`].
///
/// # Safety
/// `sess` must be a valid session pointer and `out_peer_id` must be non-null; free result with
/// [`tendril_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_peer_id(
    sess: *const TendrilSession,
    out_peer_id: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if !out_peer_id.is_null() {
            unsafe { *out_peer_id = ptr::null_mut() };
        }
        if sess.is_null() || out_peer_id.is_null() {
            set_last_error("null session or out_peer_id");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let sess = unsafe { &*sess };
        let Some(peer_id) = sess.session.peer_device_id() else {
            set_last_error("session peer is not authenticated");
            return TENDRIL_ERR_PROTOCOL;
        };
        unsafe { write_out_cstring(out_peer_id, &peer_id) }
    })
}

/// Frees a [`TendrilSession`] returned by `tendril_session_connect` or `tendril_session_accept`.
///
/// # Safety
/// `sess` must be null or an unfreed valid session pointer with no concurrent active calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_free(sess: *mut TendrilSession) {
    if !sess.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(sess));
        }));
    }
}

/// Sends an encrypted `0x01 DATA` payload over an established session.
///
/// # Safety
/// `sess` must be a valid session pointer; if `len > 0` and `len <= MAX_APP_DATA_LEN`, `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_send_data(
    sess: *mut TendrilSession,
    data: *const u8,
    len: usize,
) -> i32 {
    ffi_i32(|| {
        if sess.is_null() || (data.is_null() && len > 0) {
            set_last_error("invalid session or data pointer");
            return TENDRIL_ERR_INVALID_ARG;
        }
        if len > tendril_core::MAX_APP_DATA_LEN {
            set_last_error(format!(
                "payload length {len} exceeds max {}",
                tendril_core::MAX_APP_DATA_LEN
            ));
            return TENDRIL_ERR_PROTOCOL;
        }
        let slice = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }
        };
        let sess = unsafe { &*sess };
        match sess.rt.block_on(sess.session.send_data(slice)) {
            Ok(()) => TENDRIL_OK,
            Err(e) => {
                set_last_error(e.to_string());
                TENDRIL_ERR_PROTOCOL
            }
        }
    })
}

/// Polls the next decrypted session event as JSON (`0=event`, `1=would_block`, `2=eof`).
///
/// # Safety
/// `sess` must be a valid session pointer; `out_event_json` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_poll_event(
    sess: *mut TendrilSession,
    timeout_ms: u64,
    out_event_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if sess.is_null() || out_event_json.is_null() {
            set_last_error("null session or out_event_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let sess = unsafe { &*sess };
        let wait = Duration::from_millis(timeout_ms);
        let roster_ref = Arc::clone(&sess.roster);

        match sess.rt.block_on(async {
            timeout(wait, sess.session.next_event_locked_now(&roster_ref)).await
        }) {
            Ok(Ok(Some(ev))) => {
                let val = match ev {
                    SessionEvent::AppData(mut data) => {
                        let encoded = Zeroizing::new(b64url_encode(&data));
                        data.zeroize();
                        serde_json::json!({
                            "event": "data",
                            "data_b64": &*encoded,
                        })
                    }
                    SessionEvent::Rekeyed { direction } => serde_json::json!({
                        "event": "rekeyed",
                        "direction": format!("{direction:?}"),
                    }),
                    SessionEvent::GrantUpdated(g) => serde_json::json!({
                        "event": "grant_updated",
                        "grant": g,
                    }),
                    SessionEvent::RevocationUpdated { issuer, seq } => {
                        let res = if matches!(sess.session, SessionBackend::V1(_)) {
                            sess.persist_v1_crl_if_newer(&issuer)
                        } else {
                            sess.load_roster_from_store()
                        };
                        if let Err(e) = res {
                            set_last_error(e);
                            return TENDRIL_ERR_INTERNAL;
                        }
                        serde_json::json!({
                            "event": "revocation_updated",
                            "issuer": issuer,
                            "seq": seq,
                        })
                    }
                    SessionEvent::PongReceived(cookie) => serde_json::json!({
                        "event": "pong",
                        "cookie": cookie,
                    }),
                    SessionEvent::Audit(audit) => serde_json::json!({
                        "event": "audit",
                        "audit": audit,
                    }),
                    ev @ (SessionEvent::GroupManifestReceived(_)
                    | SessionEvent::GroupRendezvousReceived(_)) => {
                        match sess.group_frame_json(&ev) {
                            Ok(val) => val,
                            Err(msg) => {
                                set_last_error(msg);
                                return TENDRIL_ERR_PROTOCOL;
                            }
                        }
                    }
                    SessionEvent::Closed { code, reason } => serde_json::json!({
                        "event": "closed",
                        "code": code,
                        "reason": reason,
                    }),
                };
                let serialized = Zeroizing::new(val.to_string());
                unsafe { write_out_cstring(out_event_json, &serialized) }
            }
            Ok(Ok(None)) => TENDRIL_EOF,
            Ok(Err(e)) => {
                let sync_res = if matches!(sess.session, SessionBackend::V1(_)) {
                    if let Some(ref root_id) = sess.v1_root_id {
                        sess.persist_v1_crl_if_newer(root_id)
                    } else {
                        sess.load_roster_from_store()
                    }
                } else {
                    sess.load_roster_from_store()
                };
                match sync_res {
                    Ok(()) => set_last_error(e.to_string()),
                    Err(pe) => set_last_error(format!("{e} (roster persist error: {pe})")),
                }
                TENDRIL_ERR_PROTOCOL
            }
            Err(_) => TENDRIL_WOULD_BLOCK,
        }
    })
}

/// Evaluates default-deny capability authorization (`out_allowed = 1` when permitted).
///
/// # Safety
/// `sess`, `cap`, and `out_allowed` must be non-null valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_authorize(
    sess: *const TendrilSession,
    cap: *const c_char,
    out_allowed: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if sess.is_null() || out_allowed.is_null() {
            set_last_error("null argument");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(cap_s) = (unsafe { cstr_to_str(cap, "cap") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let sess = unsafe { &*sess };
        let (res, _audit) = sess
            .session
            .authorize_locked(cap_s, now_unix(), &sess.roster);
        unsafe {
            *out_allowed = u8::from(res.is_ok());
        }
        TENDRIL_OK
    })
}

/// Initiates a Noise `0x04 REKEY` ratchet on the outgoing session cipher state.
///
/// # Safety
/// `sess` must be a valid session pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_rekey(sess: *mut TendrilSession) -> i32 {
    ffi_i32(|| {
        if sess.is_null() {
            set_last_error("null session");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let sess = unsafe { &*sess };
        match sess.rt.block_on(sess.session.send_rekey()) {
            Ok(()) => TENDRIL_OK,
            Err(e) => {
                set_last_error(e.to_string());
                TENDRIL_ERR_PROTOCOL
            }
        }
    })
}

/// Sends an encrypted `0x07 CLOSE` frame and closes the underlying transport stream.
///
/// # Safety
/// `sess` must be a valid session pointer; `reason` may be null or UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_close(
    sess: *mut TendrilSession,
    code: u16,
    reason: *const c_char,
) -> i32 {
    ffi_i32(|| {
        if sess.is_null() {
            set_last_error("null session");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(reason_opt) = (unsafe { opt_cstr_to_str(reason, "reason") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let sess = unsafe { &*sess };
        match sess.rt.block_on(
            sess.session
                .send_close(code, reason_opt.unwrap_or("normal")),
        ) {
            Ok(()) => TENDRIL_OK,
            Err(e) => {
                set_last_error(e.to_string());
                TENDRIL_ERR_PROTOCOL
            }
        }
    })
}

/// Configures relay admission, P2P transport, and `WakeProvider` options on `ep` from JSON.
///
/// # Safety
/// `ep` and `transport_config_json` must be non-null valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_configure_transports_json(
    ep: *mut TendrilEndpoint,
    transport_config_json: *const c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(cfg_s) = (unsafe { cstr_to_str(transport_config_json, "transport_config_json") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let input: TransportConfigInput = match serde_json::from_str(cfg_s) {
            Ok(v) => v,
            Err(e) => {
                set_last_error(json_error("transport_config_json", &e));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let parsed = match EndpointTransportConfig::from_input(input) {
            Ok(cfg) => cfg,
            Err((rc, msg)) => {
                set_last_error(msg);
                return rc;
            }
        };
        let ep = unsafe { &*ep };
        *ep.transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = parsed;
        ep.sync_advertising();
        TENDRIL_OK
    })
}

/// Mints a canonical signed stateless Ed25519 [`RelayTicket`] JSON object.
///
/// # Safety
/// `ep`, `relay_host`, and `out_ticket_json` must be valid non-null pointers; `role` and
/// `target_pub_b64_or_wildcard` may be null or UTF-8. Free output with [`tendril_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_mint_relay_ticket(
    ep: *mut TendrilEndpoint,
    relay_host: *const c_char,
    role: *const c_char,
    target_pub_b64_or_wildcard: *const c_char,
    ttl_secs: u64,
    out_ticket_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_ticket_json.is_null() {
            set_last_error("null endpoint or out_ticket_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(host_s) = (unsafe { cstr_to_str(relay_host, "relay_host") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(role_opt) = (unsafe { opt_cstr_to_str(role, "role") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(target_opt) =
            (unsafe { opt_cstr_to_str(target_pub_b64_or_wildcard, "target_pub_b64_or_wildcard") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let role_enum = match role_opt.map(str::trim) {
            None | Some("" | "any") => RelayAuthRole::Any,
            Some("register") => RelayAuthRole::Register,
            Some("dial") => RelayAuthRole::Dial,
            Some(_) => {
                set_last_error("invalid relay ticket role: expected any, register or dial");
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let target_s = target_opt.filter(|s| !s.is_empty()).unwrap_or("*");
        let ep = unsafe { &*ep };
        let ticket =
            match ep
                .identity
                .mint_relay_ticket(host_s, role_enum, target_s, now_unix(), ttl_secs)
            {
                Ok(t) => t,
                Err(e) => {
                    set_last_error(e.to_string());
                    return TENDRIL_ERR_INVALID_ARG;
                }
            };
        let json = match canonical_json(&ticket) {
            Ok(j) => Zeroizing::new(j),
            Err(e) => {
                set_last_error(e.to_string());
                return TENDRIL_ERR_INTERNAL;
            }
        };
        unsafe { write_out_cstring(out_ticket_json, &json) }
    })
}

/// Registers blinded `/v2/relay` epoch mailboxes for `peer_id_opt` (or all active v2 peers when null).
///
/// # Safety
/// `ep`, `relay_url`, and `out_endpoint` must be valid non-null pointers; `expected_host` and `peer_id_opt` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_serve_relay_v2(
    ep: *mut TendrilEndpoint,
    relay_url: *const c_char,
    expected_host: *const c_char,
    peer_id_opt: *const c_char,
    out_endpoint: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_endpoint.is_null() {
            set_last_error("null endpoint or out_endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(url_s) = (unsafe { cstr_to_str(relay_url, "relay_url") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(exp_host) = (unsafe { opt_cstr_to_str(expected_host, "expected_host") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(peer_opt) = (unsafe { opt_cstr_to_str(peer_id_opt, "peer_id_opt") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let ep = unsafe { &*ep };
        let cfg = ep.snapshot_transport_cfg();
        if let Err(e) = ep.load_roster_from_store() {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        let secrets: Vec<[u8; 32]> = {
            let roster = lock_roster(&ep.roster);
            if let Some(pid) = peer_opt.filter(|s| !s.is_empty()) {
                match lookup_v2_mailbox_secret_for_target(&roster, pid) {
                    Ok(sec) => vec![sec],
                    Err((rc, msg)) => {
                        set_last_error(msg);
                        return rc;
                    }
                }
            } else {
                let list: Vec<[u8; 32]> = roster
                    .entries()
                    .filter(|(_, e)| e.state == PeerState::Active)
                    .filter_map(|(_, e)| e.v2_secrets.as_ref().map(|s| *s.mailbox_secret()))
                    .collect();
                if list.is_empty() {
                    set_last_error("no active v2 peers with mailbox_secret in roster");
                    return TENDRIL_ERR_NOT_FOUND;
                }
                list
            }
        };

        let mut bound_listeners: Vec<RelayV2Listener> = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let lcfg = RelayV2ListenerConfig {
                expected_host: exp_host.map(ToOwned::to_owned),
                write_timeout: DEFAULT_WRITE_TIMEOUT,
                allow_insecure_ws: false,
                replay_cache: None,
                unix_secs: None,
                auth: cfg.relay_auth.clone(),
            };
            match ep
                .rt
                .block_on(RelayV2Listener::bind_with_config(url_s, secret, lcfg))
            {
                Ok(listener) => bound_listeners.push(listener),
                Err(e) => {
                    set_last_error(e.to_string());
                    return TENDRIL_ERR_PROTOCOL;
                }
            }
        }
        let first_ep = bound_listeners.first().map(|l| l.local_endpoint());
        for listener in bound_listeners {
            ep.spawn_listener(Box::new(listener));
        }
        let local_ep = first_ep.unwrap_or_else(|| url_s.to_owned());
        ep.record_served(local_ep.clone(), None);
        unsafe { write_out_cstring(out_endpoint, &local_ep) }
    })
}

/// Initiates a Wire v2 hybrid `Argon2id` PAKE + `ML-KEM-768` pairing handshake toward `endpoint`.
///
/// # Safety
/// `ep`, `endpoint`, `code`, and `out_json` must be valid non-null pointers; optional strings may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_pair_v2_initiate(
    ep: *mut TendrilEndpoint,
    endpoint: *const c_char,
    relay_host_opt: *const c_char,
    code: *const c_char,
    name: *const c_char,
    kind: *const c_char,
    pinned_host_json_opt: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(endpoint_s) = (unsafe { cstr_to_str(endpoint, "endpoint") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(relay_host_s) = (unsafe { opt_cstr_to_str(relay_host_opt, "relay_host_opt") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(code_s) = (unsafe { cstr_to_str(code, "code") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(name_s) = (unsafe { opt_cstr_to_str(name, "name") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(kind_s) = (unsafe { opt_cstr_to_str(kind, "kind") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(pinned_opt) =
            (unsafe { opt_cstr_to_str(pinned_host_json_opt, "pinned_host_json_opt") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };

        let ep = unsafe { &*ep };
        let cfg = ep.snapshot_transport_cfg();
        if let Err(e) = ep.load_roster_from_store() {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        let roster_snapshot = lock_roster(&ep.roster).clone();

        let v2_pinned = match pinned_opt.filter(|s| !s.is_empty()) {
            Some(raw) => {
                let pin_in: FfiPinnedHostInput = match serde_json::from_str(raw) {
                    Ok(v) => v,
                    Err(e) => {
                        set_last_error(json_error("pinned_host_json_opt", &e));
                        return TENDRIL_ERR_INVALID_ARG;
                    }
                };
                let static_pub = match b64url_decode_array::<32>(&pin_in.static_pub_b64) {
                    Ok(k) => k,
                    Err(e) => {
                        set_last_error(e.to_string());
                        return TENDRIL_ERR_INVALID_ARG;
                    }
                };
                let signing_pin = match parse_signing_pin_b64(&pin_in.signing_pin_b64) {
                    Ok(p) => p,
                    Err(e) => {
                        set_last_error(e);
                        return TENDRIL_ERR_INVALID_ARG;
                    }
                };
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
                match V2PinnedHost::new(pinned, floor) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        set_last_error(e.to_string());
                        return TENDRIL_ERR_INVALID_ARG;
                    }
                }
            }
            None => None,
        };

        let v2_secret = if is_v2_relay_endpoint(endpoint_s) {
            match lookup_v2_mailbox_secret_for_pair(
                &roster_snapshot,
                v2_pinned.as_ref().map(|p| &p.pinned),
                endpoint_s,
                now_unix(),
            ) {
                Ok(s) => Some(s),
                Err(e) => {
                    set_last_error(e.to_string());
                    return TENDRIL_ERR_PROTOCOL;
                }
            }
        } else {
            None
        };

        let device_name = name_s.unwrap_or("ffi-device").to_owned();
        let device_kind = kind_s.unwrap_or("ffi").to_owned();
        let res = ep.rt.block_on(async {
            let mut stream =
                dial_endpoint_v2_with_options(endpoint_s, relay_host_s, &cfg, v2_secret)
                    .await
                    .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))?;
            let pair_res = drive_v2_pake_pair_initiator_with_timeout(
                stream.as_mut(),
                &ep.identity,
                device_name,
                device_kind,
                code_s.to_owned(),
                v2_pinned,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()));
            let _ = stream.close().await;
            pair_res
        });

        match res {
            Ok(pair_res) => match pair_res.outcome {
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
                    if let Err((rc, msg)) = ep.mutate_roster(|roster| {
                        roster
                            .apply_v2_pair_initiator_outcome(
                                &pair_res.outcome,
                                h_id.clone(),
                                Vec::new(),
                            )
                            .map(|_| ())
                            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))
                    }) {
                        set_last_error(msg);
                        return rc;
                    }
                    let out = serde_json::json!({
                        "device_id": dev_id,
                        "host_id": h_id,
                        "sas": sas,
                        "status": if host_pin_verified { "active" } else { "pending" },
                        "host_confirmed": host_pin_verified,
                        "wire_version": 2,
                    });
                    unsafe { write_out_cstring(out_json, &out.to_string()) }
                }
                V2PairOutcome::Rejected { error } => {
                    set_last_error(error);
                    TENDRIL_ERR_PROTOCOL
                }
                V2PairOutcome::ResponderPending { .. } => {
                    set_last_error("unexpected responder outcome");
                    TENDRIL_ERR_INTERNAL
                }
            },
            Err((rc, msg)) => {
                set_last_error(msg);
                rc
            }
        }
    })
}

/// Accepts the next incoming Wire v2 (`0x02`) PAKE pairing connection within `timeout_ms`.
///
/// # Safety
/// `ep` must be a valid endpoint pointer and `out_json` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_pair_v2_accept(
    ep: *mut TendrilEndpoint,
    timeout_ms: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let ep = unsafe { &*ep };
        let wait = Duration::from_millis(timeout_ms);
        let accepted = std::cell::Cell::new(false);
        let res = ep.rt.block_on(async {
            let (mut stream, guard) = match ep.router.recv_v2_pair(wait).await {
                Ok(Some(pair)) => pair,
                Ok(None) => return Err((TENDRIL_ERR_CLOSED, "listener closed".to_owned())),
                Err(()) => {
                    return Err((
                        TENDRIL_WOULD_BLOCK,
                        "timed out accepting v2 pair".to_owned(),
                    ));
                }
            };
            accepted.set(true);
            let path_kind = pairing_path_kind_for_provider(stream.provider_id());
            if let Some(ref store) = ep.store {
                drive_v2_pake_pair_responder_with_store(
                    stream.as_mut(),
                    &ep.identity,
                    &ep.pair_mgr,
                    store,
                    &ep.store_lock,
                    path_kind,
                    now_unix(),
                    &ep.v2_state,
                    Some(ep.router.v2_pair_rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            } else {
                drive_v2_pake_pair_responder_with_options(
                    stream.as_mut(),
                    &ep.identity,
                    &ep.pair_mgr,
                    &ep.roster,
                    path_kind,
                    now_unix(),
                    &ep.v2_state,
                    Some(ep.router.v2_pair_rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            }
            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))
        });

        if accepted.get()
            && let Err(e) = ep.load_roster_from_store()
        {
            if let Err((_, msg)) = res {
                set_last_error(format!("{msg} (roster sync error: {e})"));
            } else {
                set_last_error(e);
            }
            return TENDRIL_ERR_INTERNAL;
        }

        match res {
            Ok(pair_res) => match pair_res.outcome {
                V2PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => {
                    let out = serde_json::json!({
                        "device_id": device_id,
                        "sas": pairing_sas,
                        "name": name,
                        "kind": kind,
                        "wire_version": 2,
                    });
                    unsafe { write_out_cstring(out_json, &out.to_string()) }
                }
                V2PairOutcome::Rejected { error } => {
                    set_last_error(error);
                    TENDRIL_ERR_PROTOCOL
                }
                V2PairOutcome::InitiatorPending { .. } => {
                    set_last_error("unexpected initiator outcome");
                    TENDRIL_ERR_INTERNAL
                }
            },
            Err((rc, msg)) => {
                set_last_error(msg);
                rc
            }
        }
    })
}

/// Opens an authenticated Wire v2 (`0x02`) pseudonymous session toward `target_host_id`.
///
/// A `NULL` or empty `endpoint` connects over the peer's stored routes; a non-empty one is an explicit operator endpoint. With a configured
/// `WakeProvider` an explicit endpoint is woken first, then connected through the same policy
/// connect (route negotiation and route set ingest included).
///
/// # Safety
/// `ep` and `target_host_id` must be valid non-null pointers; `endpoint`, `relay_host_opt` and
/// `grant_json_opt` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_connect_v2(
    ep: *mut TendrilEndpoint,
    endpoint: *const c_char,
    relay_host_opt: *const c_char,
    target_host_id: *const c_char,
    grant_json_opt: *const c_char,
) -> *mut TendrilSession {
    ffi_ptr(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return ptr::null_mut();
        }
        let Ok(ep_opt) = (unsafe { opt_cstr_to_str(endpoint, "endpoint") }) else {
            return ptr::null_mut();
        };
        let Ok(relay_host_s) = (unsafe { opt_cstr_to_str(relay_host_opt, "relay_host_opt") })
        else {
            return ptr::null_mut();
        };
        let Ok(target_s) = (unsafe { cstr_to_str(target_host_id, "target_host_id") }) else {
            return ptr::null_mut();
        };
        let Ok(grant_opt) = (unsafe { opt_cstr_to_str(grant_json_opt, "grant_json_opt") }) else {
            return ptr::null_mut();
        };
        let grant = match parse_grant_json(grant_opt, "grant_json_opt") {
            Ok(g) => g,
            Err(e) => {
                set_last_error(e);
                return ptr::null_mut();
            }
        };

        let ep = unsafe { &*ep };
        connect_session(
            ep,
            ConnectRequest {
                wire: 2,
                target: target_s,
                grant,
                endpoint: ep_opt,
                relay_host: relay_host_s,
                recovery_uri: None,
                replace_routes: false,
                route_policy: None,
            },
        )
    })
}

/// Accepts and authenticates the next inbound Wire v2 (`0x02`) session stream within `timeout_ms`.
///
/// Once groups run, `timeout_ms` bounds the whole wait for a group-routed session, including
/// waiting behind another concurrent accept. A call that was parked on the router when the first
/// group opened and dequeues a stream at that moment completes that stream's handshake under the
/// pre-auth timeouts, outside `timeout_ms`.
///
/// # Safety
/// `ep` must be a valid endpoint pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_accept_v2(
    ep: *mut TendrilEndpoint,
    timeout_ms: u64,
) -> *mut TendrilSession {
    ffi_ptr(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return ptr::null_mut();
        }
        let ep = unsafe { &*ep };
        let wait = Duration::from_millis(timeout_ms);
        let accepted = std::cell::Cell::new(false);
        let res = ep.rt.block_on(async {
            let deadline = tokio::time::Instant::now() + wait;
            let mut groups = ep.group_runtime();
            let (stream, guard) = loop {
                if let Some(groups) = groups.as_ref() {
                    // The group pumps own the router queue from here on.
                    return match recv_group_queue(&groups.v2_rx, deadline).await {
                        Ok(Some(driver)) => {
                            accepted.set(true);
                            Ok(driver)
                        }
                        Ok(None) => Err("listener closed".to_owned()),
                        Err(_) => Err("timed out accepting v2 session".to_owned()),
                    };
                }
                let ready = ep.group_ready.notified();
                tokio::pin!(ready);
                ready.as_mut().enable();
                groups = ep.group_runtime();
                if groups.is_some() {
                    continue;
                }
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                let (stream, guard) = tokio::select! {
                    () = &mut ready => continue,
                    recv = ep.router.recv_v2_session(left) => match recv {
                        Ok(Some(pair)) => pair,
                        Ok(None) => return Err("listener closed".to_owned()),
                        Err(()) => return Err("timed out accepting v2 session".to_owned()),
                    },
                };
                // A group runtime created while this call was parked now owns group streams.
                let Some(rt_groups) = ep.group_runtime() else {
                    break (stream, guard);
                };
                match rt_groups
                    .hub
                    .accept(
                        stream,
                        &ep.v2_state,
                        Some(ep.router.v2_session_rate_limiter()),
                        Some(guard),
                    )
                    .await
                {
                    Ok(InboundSession::OrdinaryV2 { session }) => {
                        accepted.set(true);
                        return Ok(session);
                    }
                    Ok(_) | Err(_) => groups = Some(rt_groups),
                }
            };
            accepted.set(true);
            if let Some(ref store) = ep.store {
                V2SessionDriver::accept_with_store(
                    stream,
                    &ep.identity,
                    store,
                    &ep.store_lock,
                    now_unix(),
                    &ep.v2_state,
                    Some(ep.router.v2_session_rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            } else {
                V2SessionDriver::accept_locked(
                    stream,
                    &ep.identity,
                    &ep.roster,
                    now_unix(),
                    &ep.v2_state,
                    Some(ep.router.v2_session_rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            }
            .map_err(|e| e.to_string())
        });

        let synced = if accepted.get() {
            ep.load_roster_from_store()
        } else {
            Ok(())
        };
        match res {
            Ok(driver) => {
                if let Err(e) = synced {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                let session = SessionBackend::v2(driver);
                if let Err(e) = ep.register_route_session(&session) {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                Box::into_raw(Box::new(TendrilSession {
                    rt: Arc::clone(&ep.rt),
                    store: ep.store.clone(),
                    store_lock: Arc::clone(&ep.store_lock),
                    roster: Arc::clone(&ep.roster),
                    route_access: ep.route_access.clone(),
                    v1_root_id: None,
                    v1_local_signing: None,
                    local_device_id: ep.identity.device_id(),
                    session,
                }))
            }
            Err(e) => {
                match synced {
                    Ok(()) => set_last_error(e),
                    Err(pe) => set_last_error(format!("{e} (roster sync error: {pe})")),
                }
                ptr::null_mut()
            }
        }
    })
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

const fn code_kind_name(kind: PairingCodeKind) -> &'static str {
    match kind {
        PairingCodeKind::Lan2Group => "lan",
        PairingCodeKind::Remote3Group => "remote",
    }
}

fn routes_json(routes: &[StoredRoute]) -> serde_json::Value {
    routes
        .iter()
        .map(|r| serde_json::json!({"hint": r.hint, "source": r.source.as_str()}))
        .collect()
}

fn skipped_json(skipped: &[SkippedHint]) -> serde_json::Value {
    skipped
        .iter()
        .map(|s| serde_json::json!({"hint": s.hint, "reason": s.reason.as_str()}))
        .collect()
}

/// Dropped advertised hints, each only as [`DroppedHint::redacted_hint`]: an operator hint may
/// carry credentials or a code.
fn dropped_json(dropped: &[DroppedHint]) -> serde_json::Value {
    dropped
        .iter()
        .map(|d| serde_json::json!({"hint": d.redacted_hint(), "reason": d.reason}))
        .collect()
}

fn route_meta_json(meta: Option<RouteMeta>) -> serde_json::Value {
    meta.map_or(serde_json::Value::Null, |m| {
        serde_json::json!({
            "seq": m.seq,
            "issued_at": m.issued_at,
            "origin": m.origin,
        })
    })
}

fn last_route_set_json(last: Option<LastRouteSet>) -> serde_json::Value {
    last.map_or(
        serde_json::Value::Null,
        |l| serde_json::json!({"outcome": l.outcome, "seq": l.seq}),
    )
}

/// Result code of a runtime route or pairing error.
const fn runtime_error_code(err: &RuntimeError) -> i32 {
    match err {
        RuntimeError::Core(CoreError::PeerNotFound(_)) => TENDRIL_ERR_NOT_FOUND,
        RuntimeError::Core(CoreError::InvalidPairingUri(_) | CoreError::PairingCodeInvalid) => {
            TENDRIL_ERR_INVALID_ARG
        }
        _ => TENDRIL_ERR_PROTOCOL,
    }
}

/// The error of a failed policy pairing or connect, with whether the code may be spent, the
/// hints that were never dialed and each failed candidate. Each hint and nested error is
/// redacted before it is formatted in.
fn attempt_error_message(err: &AttemptError) -> String {
    let mut msg = redact_error(&err.error);
    if err.committed {
        msg.push_str(" (committed: the pairing code may be spent)");
    }
    if !err.skipped.is_empty() {
        let list: Vec<String> = err
            .skipped
            .iter()
            .map(|s| format!("{} ({})", redact_hint(&s.hint), s.reason.as_str()))
            .collect();
        msg.push_str("; skipped: ");
        msg.push_str(&list.join(", "));
    }
    if !err.failures.is_empty() {
        let list: Vec<String> = err
            .failures
            .iter()
            .map(|f| {
                format!(
                    "{} ({}: {})",
                    redact_hint(&f.hint),
                    provider_name(f.provider),
                    redact_error(&f.error)
                )
            })
            .collect();
        msg.push_str("; failed: ");
        msg.push_str(&list.join(", "));
    }
    msg
}

/// Parses optional options JSON (`NULL` or `""` means defaults).
fn parse_options<T: serde::de::DeserializeOwned + Default>(
    raw: Option<&str>,
    name: &str,
) -> Result<T, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(json) => serde_json::from_str(json).map_err(|e| json_error(name, &e)),
        None => Ok(T::default()),
    }
}

fn parse_pairing_uri(raw: &str) -> Result<PairingUri, String> {
    PairingUri::parse(raw.trim()).map_err(|e| format!("invalid pairing_uri: {e}"))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct IssueUriOptions {
    kind: Option<String>,
    host_name: Option<String>,
    sign_routes: Option<bool>,
}

/// Issues a single-use pairing code inside a pairing URI built from the announced route set.
///
/// `options_json_opt` is `NULL` or `{"kind": "auto"|"lan"|"remote", "host_name": str,
/// "sign_routes": bool}`. Hints come only from the announced set (served listeners,
/// `advertised_endpoints` and, with `advertise: auto`, enumerated LAN and overlay addresses).
/// `*out_json` is `{"uri", "code_kind", "dropped", "uri_len", "qr_version_m", "route_seq"}`.
///
/// # Safety
/// `ep` and `out_json` must be valid non-null pointers; `options_json_opt` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_issue_pairing_uri(
    ep: *mut TendrilEndpoint,
    options_json_opt: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(opts_raw) = (unsafe { opt_cstr_to_str(options_json_opt, "options_json_opt") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let opts: IssueUriOptions = match parse_options(opts_raw, "options_json_opt") {
            Ok(o) => o,
            Err(e) => {
                set_last_error(e);
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let requested_kind = match opts.kind.as_deref() {
            None | Some("") => None,
            Some(k) if k.eq_ignore_ascii_case("auto") => None,
            Some(k) => match k.parse::<PairingCodeKind>() {
                Ok(kind) => Some(kind),
                Err(_) => {
                    // Never echoes the input.
                    set_last_error("invalid pairing code kind: expected auto, lan or remote");
                    return TENDRIL_ERR_INVALID_ARG;
                }
            },
        };
        let ep = unsafe { &*ep };
        let cfg = ep.snapshot_transport_cfg();
        let host_name = opts
            .host_name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| ep.identity.host_id().to_owned());
        let issue = IssueOptions {
            requested_kind,
            sign_routes: opts.sign_routes.unwrap_or_else(|| cfg.sign_routes()),
        };
        if let Err((rc, msg)) = ep.start_hosting() {
            set_last_error(msg);
            return rc;
        }
        ep.announcer.set_inputs(ep.advertise_inputs());
        // The announcer publishes (roster file lock) before it takes the pairing manager, the
        // order a concurrent pairing claim uses; the manager is never held across the call.
        let issued = ep
            .announcer
            .issue_pairing_uri(&ep.pair_mgr, &host_name, issue, unix_ms());
        match issued {
            Ok(issued) => {
                let out = Zeroizing::new(
                    serde_json::json!({
                        "uri": issued.uri,
                        "code_kind": code_kind_name(issued.code_kind),
                        "dropped": dropped_json(&issued.dropped),
                        "uri_len": issued.uri_len,
                        "qr_version_m": issued.qr_version_m,
                        "route_seq": issued.route_seq,
                    })
                    .to_string(),
                );
                unsafe { write_out_cstring(out_json, &out) }
            }
            Err(e) => {
                set_last_error(e.to_string());
                runtime_error_code(&e)
            }
        }
    })
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PairUriOptions {
    route_policy: Option<RoutePolicy>,
    save_route: Option<bool>,
    endpoint: Option<String>,
    code: Option<String>,
}

/// One pairing initiator outcome, reduced to what the C result reports.
struct InitiatorResult {
    device_id: String,
    host_id: String,
    sas: String,
    host_confirmed: bool,
}

/// Shared body of [`tendril_endpoint_pair_uri`] and [`tendril_endpoint_pair_v2_uri`].
unsafe fn pair_uri_impl(
    ep: *mut TendrilEndpoint,
    wire: u8,
    pairing_uri: *const c_char,
    name_opt: *const c_char,
    device_kind_opt: *const c_char,
    options_json_opt: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    if ep.is_null() || out_json.is_null() {
        set_last_error("null endpoint or out_json");
        return TENDRIL_ERR_INVALID_ARG;
    }
    let Ok(uri_s) = (unsafe { cstr_to_str(pairing_uri, "pairing_uri") }) else {
        return TENDRIL_ERR_INVALID_ARG;
    };
    let Ok(name_s) = (unsafe { opt_cstr_to_str(name_opt, "name_opt") }) else {
        return TENDRIL_ERR_INVALID_ARG;
    };
    let Ok(kind_s) = (unsafe { opt_cstr_to_str(device_kind_opt, "device_kind_opt") }) else {
        return TENDRIL_ERR_INVALID_ARG;
    };
    let Ok(opts_raw) = (unsafe { opt_cstr_to_str(options_json_opt, "options_json_opt") }) else {
        return TENDRIL_ERR_INVALID_ARG;
    };
    let opts: PairUriOptions = match parse_options(opts_raw, "options_json_opt") {
        Ok(o) => o,
        Err(e) => {
            set_last_error(e);
            return TENDRIL_ERR_INVALID_ARG;
        }
    };
    let uri = match parse_pairing_uri(uri_s) {
        Ok(u) => u,
        Err(e) => {
            set_last_error(e);
            return TENDRIL_ERR_INVALID_ARG;
        }
    };
    // An explicit code override that is empty is malformed input, not "use the URI code".
    if opts.code.as_deref().is_some_and(|c| c.trim().is_empty()) {
        set_last_error(CoreError::PairingCodeInvalid.to_string());
        return TENDRIL_ERR_INVALID_ARG;
    }
    let ep = unsafe { &*ep };
    let cfg = ep.snapshot_transport_cfg();
    let operator = opts.endpoint.filter(|e| !e.is_empty());
    let dialers = match cfg.hint_dialers(operator.as_deref(), None) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(e.to_string());
            return TENDRIL_ERR_INVALID_ARG;
        }
    };
    let code = Zeroizing::new(opts.code.unwrap_or_else(|| uri.code.clone()));
    let mut popts = PairPolicyOptions::new(
        name_s.filter(|n| !n.is_empty()).unwrap_or("ffi-device"),
        kind_s.filter(|k| !k.is_empty()).unwrap_or("ffi"),
        code.as_str(),
        dialers,
    );
    popts.uri = Some(uri);
    popts.operator_endpoint = operator;
    popts.persist = PersistOpts {
        policy: opts.route_policy.unwrap_or(cfg.route_policy),
        save_committed: opts.save_route.unwrap_or(false),
        ..PersistOpts::default()
    };
    popts.relay_auth_origins.clone_from(&cfg.relay_auth_origins);
    let identity = Arc::new(ep.identity.clone());

    let res = if wire == 2 {
        ep.rt
            .block_on(
                tendril_runtime::v2_driver::drive_v2_pair_initiator_with_policy(
                    identity,
                    &ep.route_access,
                    popts,
                ),
            )
            .map(|r| {
                let outcome = match r.drive.outcome {
                    V2PairOutcome::InitiatorPending {
                        device_id,
                        host_id,
                        pairing_sas,
                        host_pin_verified,
                        ..
                    } => Ok(InitiatorResult {
                        device_id,
                        host_id,
                        sas: pairing_sas,
                        host_confirmed: host_pin_verified,
                    }),
                    V2PairOutcome::Rejected { error } => Err(error),
                    V2PairOutcome::ResponderPending { .. } => {
                        Err("unexpected responder outcome".to_owned())
                    }
                };
                (
                    outcome,
                    r.route,
                    r.committed,
                    r.route_check,
                    r.routes_persisted,
                    r.routes_reason,
                    r.skipped,
                )
            })
    } else {
        ep.rt
            .block_on(tendril_runtime::driver::drive_pair_initiator_with_policy(
                identity,
                &ep.route_access,
                popts,
            ))
            .map(|r| {
                let outcome = match r.drive.outcome {
                    PairOutcome::InitiatorPending {
                        device_id,
                        host_id,
                        pairing_sas,
                        host_pin_verified,
                        ..
                    } => Ok(InitiatorResult {
                        device_id,
                        host_id,
                        sas: pairing_sas,
                        host_confirmed: host_pin_verified,
                    }),
                    PairOutcome::Rejected { error } => Err(error),
                    _ => Err("unexpected pairing outcome".to_owned()),
                };
                (
                    outcome,
                    r.route,
                    r.committed,
                    r.route_check,
                    r.routes_persisted,
                    r.routes_reason,
                    r.skipped,
                )
            })
    };
    if let Err(e) = ep.load_roster_from_store() {
        set_last_error(e);
        return TENDRIL_ERR_INTERNAL;
    }
    let (outcome, route, committed, route_check, routes_persisted, routes_reason, skipped) =
        match res {
            Ok(parts) => parts,
            Err(err) => {
                set_last_error(attempt_error_message(&err));
                return runtime_error_code(&err.error);
            }
        };
    let res = match outcome {
        Ok(r) => r,
        Err(error) => {
            set_last_error(error);
            return TENDRIL_ERR_PROTOCOL;
        }
    };
    let route: CandidateEndpoint = route;
    let out = serde_json::json!({
        "device_id": res.device_id,
        "host_id": res.host_id,
        "sas": res.sas,
        "status": if res.host_confirmed { "active" } else { "pending" },
        "host_confirmed": res.host_confirmed,
        "provider": provider_name(route.provider),
        "endpoint": route.addr,
        "committed": committed,
        "route_check": route_check.as_str(),
        "routes_persisted": routes_json(&routes_persisted),
        "routes_reason": routes_reason,
        "skipped": skipped_json(&skipped),
    });
    unsafe { write_out_cstring(out_json, &out.to_string()) }
}

/// Pairs over Wire v1 with a scanned pairing URI: races its hints (or the explicit operator
/// `endpoint` option alone) and commits on the first candidate that verifies the host pin, `rp`
/// and route statement. Routes are persisted under the route policy.
///
/// `options_json_opt` is `NULL` or `{"route_policy": "all_signed"|"committed_only"|"none",
/// "save_route": bool, "endpoint": str, "code": str}`; `code` overrides the URI code. `*out_json`
/// is `{"device_id", "host_id", "sas", "status", "host_confirmed", "provider", "endpoint",
/// "committed", "route_check", "routes_persisted", "skipped"}`.
///
/// # Safety
/// `ep`, `pairing_uri` and `out_json` must be valid non-null pointers; the other strings may be
/// null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_pair_uri(
    ep: *mut TendrilEndpoint,
    pairing_uri: *const c_char,
    name_opt: *const c_char,
    device_kind_opt: *const c_char,
    options_json_opt: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| unsafe {
        pair_uri_impl(
            ep,
            1,
            pairing_uri,
            name_opt,
            device_kind_opt,
            options_json_opt,
            out_json,
        )
    })
}

/// Wire v2 PAKE pairing with a scanned pairing URI, one rung at a time.
/// Options and result as [`tendril_endpoint_pair_uri`].
///
/// # Safety
/// As [`tendril_endpoint_pair_uri`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_pair_v2_uri(
    ep: *mut TendrilEndpoint,
    pairing_uri: *const c_char,
    name_opt: *const c_char,
    device_kind_opt: *const c_char,
    options_json_opt: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| unsafe {
        pair_uri_impl(
            ep,
            2,
            pairing_uri,
            name_opt,
            device_kind_opt,
            options_json_opt,
            out_json,
        )
    })
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConnectOptionsInput {
    wire: Option<u8>,
    grant: Option<Grant>,
    endpoint: Option<String>,
    relay_host: Option<String>,
    recovery_uri: Option<String>,
    replace_routes: Option<bool>,
    route_policy: Option<RoutePolicy>,
}

/// Opens a session toward `target_host_id` with options.
///
/// `options_json` is `NULL` or `{"wire": 1|2, "grant": obj, "endpoint": str, "relay_host": str,
/// "recovery_uri": str, "replace_routes": bool, "route_policy": str}`. Without `endpoint` the
/// stored routes are dialed. `relay_host` is the expected relay host of an explicit `endpoint`
/// (the Iroh relay mode for `iroh://`), as in [`tendril_session_connect`]. `recovery_uri` is a fresh pairing URI of the peer, honoured with and without
/// `endpoint`: its keys are checked before session `msg3` on every candidate, a signed one adds
/// its hints, and its routes replace the `signed` routes when its `rq` is newer (or with
/// `replace_routes`). Its code is never sent.
///
/// # Safety
/// `ep` and `target_host_id` must be valid non-null pointers; `options_json` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_session_connect_with_options(
    ep: *mut TendrilEndpoint,
    target_host_id: *const c_char,
    options_json: *const c_char,
) -> *mut TendrilSession {
    ffi_ptr(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return ptr::null_mut();
        }
        let Ok(target_s) = (unsafe { cstr_to_str(target_host_id, "target_host_id") }) else {
            return ptr::null_mut();
        };
        let Ok(opts_raw) = (unsafe { opt_cstr_to_str(options_json, "options_json") }) else {
            return ptr::null_mut();
        };
        let opts: ConnectOptionsInput = match parse_options(opts_raw, "options_json") {
            Ok(o) => o,
            Err(e) => {
                set_last_error(e);
                return ptr::null_mut();
            }
        };
        let wire = opts.wire.unwrap_or(1);
        if wire != 1 && wire != 2 {
            set_last_error(format!("invalid wire {wire}: expected 1 or 2"));
            return ptr::null_mut();
        }
        let ep = unsafe { &*ep };
        connect_session(
            ep,
            ConnectRequest {
                wire,
                target: target_s,
                grant: opts.grant,
                endpoint: opts.endpoint.as_deref(),
                relay_host: opts.relay_host.as_deref(),
                recovery_uri: opts.recovery_uri.filter(|u| !u.is_empty()),
                replace_routes: opts.replace_routes.unwrap_or(false),
                route_policy: opts.route_policy,
            },
        )
    })
}

/// Replaces the `operator` routes of `peer_id`.
///
/// `routes_json` is a JSON array of endpoint strings, each normalized like an explicit
/// endpoint; one invalid entry rejects the whole list and nothing is written. `[]` clears the
/// `operator` routes. Returns `0`, `TENDRIL_ERR_INVALID_ARG` for a bad argument or list,
/// `TENDRIL_ERR_NOT_FOUND` for an unknown peer, or `TENDRIL_ERR_PROTOCOL` for a pending or
/// revoked one, with the last error set.
///
/// # Safety
/// `ep`, `peer_id` and `routes_json` must be valid non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_set_peer_routes(
    ep: *mut TendrilEndpoint,
    peer_id: *const c_char,
    routes_json: *const c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(peer_s) = (unsafe { cstr_to_str(peer_id, "peer_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        if routes_json.is_null() {
            set_last_error("null pointer for routes_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(raw) = (unsafe { json_string_list(routes_json, "routes_json") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let ep = unsafe { &*ep };
        match ep.route_write(|access| set_peer_routes_in(access, peer_s, &raw)) {
            Ok(_) => TENDRIL_OK,
            Err(e) => {
                set_last_error(e.to_string());
                runtime_error_code(&e)
            }
        }
    })
}

/// Writes the stored routes of `peer_id` as `{"routes": [{"hint", "source"}], "route_meta":
/// {"seq", "issued_at", "origin"} | null, "last_route_set": {"outcome", "seq"} | null}`.
///
/// # Safety
/// `ep`, `peer_id` and `out_json` must be valid non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_peer_routes(
    ep: *mut TendrilEndpoint,
    peer_id: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(peer_s) = (unsafe { cstr_to_str(peer_id, "peer_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let ep = unsafe { &*ep };
        match peer_routes_in(&ep.route_access, peer_s) {
            Ok(view) => {
                let out = serde_json::json!({
                    "routes": routes_json(&view.routes),
                    "route_meta": route_meta_json(view.route_meta),
                    "last_route_set": last_route_set_json(view.last_route_set),
                });
                unsafe { write_out_cstring(out_json, &out.to_string()) }
            }
            Err(e) => {
                set_last_error(e.to_string());
                runtime_error_code(&e)
            }
        }
    })
}

/// Removes the routes of `peer_id` from one source: `NULL` or `"operator"`, `"signed"`,
/// `"committed"`, or `"all"` for every source. `route_meta` is kept.
///
/// # Safety
/// `ep` and `peer_id` must be valid non-null pointers; `source_opt` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_clear_peer_routes(
    ep: *mut TendrilEndpoint,
    peer_id: *const c_char,
    source_opt: *const c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(peer_s) = (unsafe { cstr_to_str(peer_id, "peer_id") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(source_s) = (unsafe { opt_cstr_to_str(source_opt, "source_opt") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let source = match source_s {
            None | Some("" | "operator") => Some(RouteSource::Operator),
            Some("signed") => Some(RouteSource::Signed),
            Some("committed") => Some(RouteSource::Committed),
            Some("all") => None,
            Some(_) => {
                set_last_error("invalid route source: expected operator, signed, committed or all");
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let ep = unsafe { &*ep };
        match ep.route_write(|access| clear_peer_routes_in(access, peer_s, source)) {
            Ok(()) => TENDRIL_OK,
            Err(e) => {
                set_last_error(e.to_string());
                runtime_error_code(&e)
            }
        }
    })
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ApplyRouteOptions {
    replace_routes: Option<bool>,
    route_policy: Option<RoutePolicy>,
}

/// Applies a fresh signed pairing URI to the paired host whose keys it carries, offline. No network and no code use.
///
/// `options_json_opt` is `NULL` or `{"replace_routes": bool, "route_policy": str}`. Under
/// `all_signed` a newer `rq` replaces the `signed` routes; otherwise only `replace_routes` does.
/// `*out_json` is `{"peer_id", "applied": bool, "reason", "route_seq"}`.
///
/// # Safety
/// `ep`, `pairing_uri` and `out_json` must be valid non-null pointers; `options_json_opt` may be
/// null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_apply_route_uri(
    ep: *mut TendrilEndpoint,
    pairing_uri: *const c_char,
    options_json_opt: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() || out_json.is_null() {
            set_last_error("null endpoint or out_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(uri_s) = (unsafe { cstr_to_str(pairing_uri, "pairing_uri") }) else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let Ok(opts_raw) = (unsafe { opt_cstr_to_str(options_json_opt, "options_json_opt") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let opts: ApplyRouteOptions = match parse_options(opts_raw, "options_json_opt") {
            Ok(o) => o,
            Err(e) => {
                set_last_error(e);
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let uri = match parse_pairing_uri(uri_s) {
            Ok(u) => u,
            Err(e) => {
                set_last_error(e);
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let ep = unsafe { &*ep };
        let apply = RouteApplyOpts {
            policy: opts
                .route_policy
                .unwrap_or_else(|| ep.snapshot_transport_cfg().route_policy),
            replace_routes: opts.replace_routes.unwrap_or(false),
        };
        match ep.route_write(|access| {
            access.update(|roster| apply_signed_route_uri(roster, &uri, apply))
        }) {
            Ok(res) => {
                let out = serde_json::json!({
                    "peer_id": res.peer_id,
                    "applied": res.applied,
                    "reason": res.reason,
                    "route_seq": res.route_meta.map(|m| m.seq),
                });
                unsafe { write_out_cstring(out_json, &out.to_string()) }
            }
            Err(e) => {
                set_last_error(e.to_string());
                runtime_error_code(&e)
            }
        }
    })
}

/// Re-scans the host's routes and publishes a changed set to paired
/// clients' live sessions.
///
/// `snapshot_json_opt` is `NULL` or the complete current network snapshot, never a delta:
/// `{"networks": [{"id": str, "iface": str, "if_index": int, "transports":
/// ["wifi"|"ethernet"|"cellular"|"vpn"|"other"], "addrs": [str]}]}`. A snapshot switches the
/// endpoint to snapshot addressing and is retained; `NULL` re-enumerates natively, or reuses the
/// retained snapshot on Android. A snapshot with zero networks applies only after it persists
/// for 30 s. `*out_json` (when `out_json` is non-null) is `{"route_seq", "changed": bool}`.
///
/// # Safety
/// `ep` must be a valid non-null pointer; `snapshot_json_opt` and `out_json` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_endpoint_refresh_routes(
    ep: *mut TendrilEndpoint,
    snapshot_json_opt: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if ep.is_null() {
            set_last_error("null endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let Ok(snap_raw) = (unsafe { opt_cstr_to_str(snapshot_json_opt, "snapshot_json_opt") })
        else {
            return TENDRIL_ERR_INVALID_ARG;
        };
        let snapshot = match snap_raw.map(str::trim).filter(|s| !s.is_empty()) {
            Some(json) => match NetworkSnapshot::from_json(json) {
                Ok(s) => Some(s),
                Err(e) => {
                    set_last_error(format!("invalid snapshot_json_opt: {e}"));
                    return TENDRIL_ERR_INVALID_ARG;
                }
            },
            None => None,
        };
        let ep = unsafe { &*ep };
        if let Err((rc, msg)) = ep.start_hosting() {
            set_last_error(msg);
            return rc;
        }
        ep.announcer.set_inputs(ep.advertise_inputs());
        match ep.announcer.refresh(unix_ms(), snapshot) {
            Ok(outcome) => {
                if out_json.is_null() {
                    return TENDRIL_OK;
                }
                let out = serde_json::json!({
                    "route_seq": outcome.route_seq(),
                    "changed": outcome.changed,
                });
                unsafe { write_out_cstring(out_json, &out.to_string()) }
            }
            Err(e) => {
                set_last_error(e.to_string());
                runtime_error_code(&e)
            }
        }
    })
}

/// Opaque group handle over one endpoint-scoped [`GroupPool`], sharing the endpoint's runtime.
pub struct TendrilGroup {
    rt: Arc<Runtime>,
    pool: GroupPool,
    local_endpoint: Option<String>,
    listener: Option<HandleListener>,
    closed: AtomicBool,
    close_notify: tokio::sync::Notify,
}

/// A direct listener bound by one group handle and served by the shared pool. Closing the handle
/// stops it accepting and drops the socket, so the port can be bound again straight away.
struct HandleListener {
    slot: Arc<AsyncMutex<Option<Box<dyn PathListener>>>>,
    cancel: tokio::sync::watch::Sender<bool>,
}

/// Pool-facing half of a [`HandleListener`].
struct CancellableListener {
    slot: Arc<AsyncMutex<Option<Box<dyn PathListener>>>>,
    cancel: tokio::sync::watch::Receiver<bool>,
    endpoint: String,
}

#[async_trait::async_trait]
impl PathListener for CancellableListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        let mut slot = self.slot.lock().await;
        let Some(inner) = slot.as_mut() else {
            return std::future::pending().await;
        };
        let accepted = tokio::select! {
            res = inner.accept() => Some(res),
            _ = self.cancel.wait_for(|stopped| *stopped) => None,
        };
        if let Some(res) = accepted {
            return res;
        }
        *slot = None;
        drop(slot);
        std::future::pending().await
    }

    fn local_endpoint(&self) -> String {
        self.endpoint.clone()
    }
}

impl HandleListener {
    fn new(listener: Box<dyn PathListener>) -> (Self, CancellableListener) {
        let endpoint = listener.local_endpoint();
        let slot = Arc::new(AsyncMutex::new(Some(listener)));
        let (cancel, rx) = tokio::sync::watch::channel(false);
        (
            Self {
                slot: Arc::clone(&slot),
                cancel,
            },
            CancellableListener {
                slot,
                cancel: rx,
                endpoint,
            },
        )
    }

    /// Stops the listener and waits until its socket is released.
    async fn stop(&self) {
        let _ = self.cancel.send(true);
        *self.slot.lock().await = None;
    }
}

impl TendrilGroup {
    fn close_once(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.close_notify.notify_waiters();
            let _guard = self.rt.enter();
            self.pool.disconnect_all();
            if let Some(listener) = &self.listener {
                self.rt.block_on(listener.stop());
            }
        }
    }

    fn live(&self) -> Result<(), i32> {
        if self.closed.load(Ordering::Acquire) {
            set_last_error("group handle is closed");
            return Err(TENDRIL_ERR_CLOSED);
        }
        Ok(())
    }
}

impl Drop for TendrilGroup {
    fn drop(&mut self) {
        self.close_once();
    }
}

fn group_error_code(err: &RuntimeError) -> i32 {
    match err {
        RuntimeError::Core(CoreError::GroupNotFound(_) | CoreError::PeerNotFound(_)) => {
            TENDRIL_ERR_NOT_FOUND
        }
        RuntimeError::Closed => TENDRIL_ERR_CLOSED,
        RuntimeError::Io(_) | RuntimeError::Storage(_) => TENDRIL_ERR_INTERNAL,
        _ => TENDRIL_ERR_PROTOCOL,
    }
}

fn fail_group(err: &RuntimeError) -> i32 {
    set_last_error(err.to_string());
    group_error_code(err)
}

unsafe fn json_string_list(ptr: *const c_char, name: &str) -> Result<Vec<String>, i32> {
    let Some(raw) = (unsafe { opt_cstr_to_str(ptr, name) })? else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<String>>(raw).map_err(|e| {
        set_last_error(format!(
            "{} (expected a JSON array of strings)",
            json_error(name, &e)
        ));
        TENDRIL_ERR_INVALID_ARG
    })
}

unsafe fn group_admin_ep<'a>(
    ep: *mut TendrilEndpoint,
) -> Result<(&'a TendrilEndpoint, &'a StateStore), i32> {
    if ep.is_null() {
        set_last_error("null endpoint");
        return Err(TENDRIL_ERR_INVALID_ARG);
    }
    let ep = unsafe { &*ep };
    let Some(store) = ep.store.as_deref() else {
        set_last_error("groups require a state directory endpoint");
        return Err(TENDRIL_ERR_INVALID_ARG);
    };
    Ok((ep, store))
}

unsafe fn write_manifest_out(
    manifest: &tendril_core::group::GroupManifest,
    out: *mut *mut c_char,
) -> i32 {
    let json = match manifest.to_wire_bytes() {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => {
            set_last_error(e.to_string());
            return TENDRIL_ERR_INTERNAL;
        }
    };
    unsafe { write_out_cstring(out, &json) }
}

/// Creates a group rooted at this endpoint's identity and returns the signed manifest JSON.
///
/// `endpoints_json` is null or a JSON array of endpoint hint strings.
///
/// # Safety
/// `ep` must be a valid endpoint pointer; `name` a NUL-terminated string; `endpoints_json` null or
/// a NUL-terminated JSON string; `out_manifest_json` non-null (free with [`tendril_string_free`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_create(
    ep: *mut TendrilEndpoint,
    name: *const c_char,
    min_wire_version: u8,
    endpoints_json: *const c_char,
    out_manifest_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_manifest_json.is_null() {
            set_last_error("null out_manifest_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let (ep, store) = match unsafe { group_admin_ep(ep) } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let name = match unsafe { cstr_to_str(name, "name") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let endpoints = match unsafe { json_string_list(endpoints_json, "endpoints_json") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        match group_create(store, &ep.identity, name, min_wire_version, endpoints) {
            Ok(manifest) => unsafe { write_manifest_out(&manifest, out_manifest_json) },
            Err(e) => fail_group(&e),
        }
    })
}

/// Adds the paired peer `peer_id` to a group this endpoint roots and returns the new manifest.
///
/// `caps_json` and `endpoints_json` are null or JSON arrays of strings; empty caps grant the
/// default send and receive capabilities.
///
/// # Safety
/// `ep` must be a valid endpoint pointer; string arguments NUL-terminated (the JSON ones may be
/// null); `out_manifest_json` non-null (free with [`tendril_string_free`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_add_member(
    ep: *mut TendrilEndpoint,
    group_id: *const c_char,
    peer_id: *const c_char,
    caps_json: *const c_char,
    endpoints_json: *const c_char,
    out_manifest_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_manifest_json.is_null() {
            set_last_error("null out_manifest_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let (ep, store) = match unsafe { group_admin_ep(ep) } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let group_id = match unsafe { cstr_to_str(group_id, "group_id") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let peer_id = match unsafe { cstr_to_str(peer_id, "peer_id") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let caps = match unsafe { json_string_list(caps_json, "caps_json") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let endpoints = match unsafe { json_string_list(endpoints_json, "endpoints_json") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        match group_add_member(store, &ep.identity, group_id, peer_id, caps, endpoints) {
            Ok(manifest) => unsafe { write_manifest_out(&manifest, out_manifest_json) },
            Err(e) => fail_group(&e),
        }
    })
}

/// Revokes `peer_id` from a group this endpoint roots, rotates its keys, and returns the manifest.
///
/// # Safety
/// `ep` must be a valid endpoint pointer; string arguments NUL-terminated; `out_manifest_json`
/// non-null (free with [`tendril_string_free`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_remove_member(
    ep: *mut TendrilEndpoint,
    group_id: *const c_char,
    peer_id: *const c_char,
    out_manifest_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_manifest_json.is_null() {
            set_last_error("null out_manifest_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let (ep, store) = match unsafe { group_admin_ep(ep) } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let group_id = match unsafe { cstr_to_str(group_id, "group_id") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let peer_id = match unsafe { cstr_to_str(peer_id, "peer_id") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        match group_remove_member(store, &ep.identity, group_id, peer_id) {
            Ok(manifest) => unsafe { write_manifest_out(&manifest, out_manifest_json) },
            Err(e) => fail_group(&e),
        }
    })
}

/// Ingests a group manifest received from the authenticated peer `sender_peer_id` and returns its
/// group id. First-contact and capacity rules are enforced by the runtime.
///
/// # Safety
/// `ep` must be a valid endpoint pointer; string arguments NUL-terminated; `out_group_id` non-null
/// (free with [`tendril_string_free`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_ingest_manifest(
    ep: *mut TendrilEndpoint,
    manifest_json: *const c_char,
    sender_peer_id: *const c_char,
    out_group_id: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_group_id.is_null() {
            set_last_error("null out_group_id");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let (ep, store) = match unsafe { group_admin_ep(ep) } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let manifest = match unsafe { cstr_to_str(manifest_json, "manifest_json") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let sender = match unsafe { cstr_to_str(sender_peer_id, "sender_peer_id") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        match group_ingest_manifest(store, &ep.identity.device_id(), sender, manifest) {
            Ok(outcome) => unsafe { write_out_cstring(out_group_id, &outcome.group_id) },
            Err(e) => fail_group(&e),
        }
    })
}

/// Opens the lazy full-mesh pool for `group_id` and returns an opaque handle.
///
/// The first open on an endpoint starts group dispatch: the endpoint's inbound session streams are
/// then routed through the group hub, and ordinary sessions still reach `tendril_session_accept`
/// and `tendril_session_accept_v2`. Configure transports before the first open. The hub reads the
/// URLs served with `tendril_endpoint_serve_relay` once, at the first open, and leaves their relay
/// hosts to the app: let every such call return before the first open, or the group's mailbox
/// registration competes with a later call on a relay host named in its own entry.
///
/// `listen_addr` may be null. When set, a direct listener is bound there and served by this
/// group's pool, and [`tendril_group_local_endpoint`] reports the bound endpoint.
///
/// # Safety
/// `ep` must be a valid endpoint pointer; `group_id` NUL-terminated; `listen_addr` null or
/// NUL-terminated; `out_group` non-null. Release the handle with [`tendril_group_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_open(
    ep: *mut TendrilEndpoint,
    group_id: *const c_char,
    listen_addr: *const c_char,
    out_group: *mut *mut TendrilGroup,
) -> i32 {
    ffi_i32(|| {
        if out_group.is_null() {
            set_last_error("null out_group");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let (ep, store) = match unsafe { group_admin_ep(ep) } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let group_id = match unsafe { cstr_to_str(group_id, "group_id") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let listen = match unsafe { opt_cstr_to_str(listen_addr, "listen_addr") } {
            Ok(v) => v.filter(|a| !a.is_empty()),
            Err(rc) => return rc,
        };
        let listen: Option<SocketAddr> = match listen.map(str::parse).transpose() {
            Ok(v) => v,
            Err(e) => {
                set_last_error(format!("invalid listen_addr: {e}"));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let groups = match ep.ensure_group_runtime() {
            Ok(g) => g,
            Err((rc, msg)) => {
                set_last_error(msg);
                return rc;
            }
        };
        let _guard = ep.rt.enter();
        let _ = groups.hub.sync();
        let pool = match groups.hub.pool(group_id) {
            Some(pool) if !pool.is_closed() => pool,
            _ => {
                return match GroupPool::open(
                    store.clone(),
                    Arc::new(ep.identity.clone()),
                    group_id,
                    GroupPoolConfig::new(Vec::new()),
                    None,
                ) {
                    Ok(unregistered) => {
                        unregistered.close();
                        set_last_error("group pool is not available on this endpoint");
                        TENDRIL_ERR_CLOSED
                    }
                    Err(e) => fail_group(&e),
                };
            }
        };
        let mut local_endpoint = None;
        let mut handle_listener = None;
        if let Some(addr) = listen {
            match ep.rt.block_on(DirectListener::bind(addr, None)) {
                Ok(listener) => {
                    local_endpoint = Some(listener.local_endpoint());
                    let (handle, served) = HandleListener::new(Box::new(listener));
                    handle_listener = Some(handle);
                    pool.serve(Box::new(served));
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    return TENDRIL_ERR_PROTOCOL;
                }
            }
        }
        let handle = Box::new(TendrilGroup {
            rt: Arc::clone(&ep.rt),
            pool,
            local_endpoint,
            listener: handle_listener,
            closed: AtomicBool::new(false),
            close_notify: tokio::sync::Notify::new(),
        });
        unsafe {
            *out_group = Box::into_raw(handle);
        }
        TENDRIL_OK
    })
}

unsafe fn group_ref<'a>(group: *const TendrilGroup) -> Result<&'a TendrilGroup, i32> {
    if group.is_null() {
        set_last_error("null group");
        return Err(TENDRIL_ERR_INVALID_ARG);
    }
    let group = unsafe { &*group };
    group.live()?;
    Ok(group)
}

/// Sends `data` to every reachable member holding the receive capability and writes the
/// `BroadcastReport` JSON (`delivered`, `offline`, `failed`).
///
/// `required_cap` may be null for the group's default send capability.
///
/// # Safety
/// `group` must be a valid group pointer; `required_cap` null or NUL-terminated; if `data_len > 0`
/// `data_ptr` must point to `data_len` readable bytes; `out_report_json` non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_broadcast(
    group: *mut TendrilGroup,
    required_cap: *const c_char,
    data_ptr: *const u8,
    data_len: usize,
    out_report_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_report_json.is_null() || (data_ptr.is_null() && data_len > 0) {
            set_last_error("invalid data or out_report_json pointer");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let group = match unsafe { group_ref(group) } {
            Ok(g) => g,
            Err(rc) => return rc,
        };
        let cap = match unsafe { opt_cstr_to_str(required_cap, "required_cap") } {
            Ok(v) => v.filter(|c| !c.is_empty()),
            Err(rc) => return rc,
        };
        let data: &[u8] = if data_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data_ptr, data_len) }
        };
        match group.rt.block_on(group.pool.broadcast(cap, data)) {
            Ok(report) => match serde_json::to_string(&report) {
                Ok(json) => unsafe { write_out_cstring(out_report_json, &json) },
                Err(e) => {
                    set_last_error(format!("failed to serialize report: {e}"));
                    TENDRIL_ERR_INTERNAL
                }
            },
            Err(e) => fail_group(&e),
        }
    })
}

/// Pushes the stored manifest (and, for an admin, the rendezvous key) to every member and writes
/// the `BroadcastReport` JSON. Wire v2 groups need this so members learn the rendezvous key; the
/// runtime enforces who may push.
///
/// # Safety
/// `group` must be a valid group pointer and `out_report_json` non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_sync(
    group: *mut TendrilGroup,
    out_report_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_report_json.is_null() {
            set_last_error("null out_report_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let group = match unsafe { group_ref(group) } {
            Ok(g) => g,
            Err(rc) => return rc,
        };
        match group.rt.block_on(group.pool.sync()) {
            Ok(report) => match serde_json::to_string(&report) {
                Ok(json) => unsafe { write_out_cstring(out_report_json, &json) },
                Err(e) => {
                    set_last_error(format!("failed to serialize report: {e}"));
                    TENDRIL_ERR_INTERNAL
                }
            },
            Err(e) => fail_group(&e),
        }
    })
}

/// Writes the endpoint bound by `listen_addr` at open time, or sets `*out_endpoint` to null when
/// the group was opened without a listener.
///
/// # Safety
/// `group` must be a valid group pointer and `out_endpoint` non-null (free a non-null result with
/// [`tendril_string_free`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_local_endpoint(
    group: *const TendrilGroup,
    out_endpoint: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_endpoint.is_null() {
            set_last_error("null out_endpoint");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let group = match unsafe { group_ref(group) } {
            Ok(g) => g,
            Err(rc) => return rc,
        };
        match group.local_endpoint.as_deref() {
            Some(endpoint) => unsafe { write_out_cstring(out_endpoint, endpoint) },
            None => {
                unsafe { *out_endpoint = ptr::null_mut() };
                TENDRIL_OK
            }
        }
    })
}

fn group_event_json(event: GroupEvent) -> serde_json::Value {
    match event {
        GroupEvent::AppData {
            sender_device_id,
            mut payload,
        } => {
            let encoded = Zeroizing::new(b64url_encode(&payload));
            payload.zeroize();
            serde_json::json!({
                "event": "app_data",
                "sender_device_id": sender_device_id,
                "payload_b64": &*encoded,
            })
        }
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
}

/// Waits up to `timeout_ms` for the next group event and writes it as JSON.
///
/// Returns `TENDRIL_OK` with an event, `TENDRIL_WOULD_BLOCK` on timeout, and `TENDRIL_EOF` once the
/// pool is closed or the handle is closed (a parked call returns promptly on
/// [`tendril_group_close`]). Events are `app_data` (`payload_b64`), `manifest_updated`, `member_joined`,
/// `member_revoked`, and `audit`.
///
/// # Safety
/// `group` must be a valid group pointer and `out_event_json` non-null (free with
/// [`tendril_string_free`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_poll_event(
    group: *mut TendrilGroup,
    timeout_ms: u64,
    out_event_json: *mut *mut c_char,
) -> i32 {
    ffi_i32(|| {
        if out_event_json.is_null() {
            set_last_error("null out_event_json");
            return TENDRIL_ERR_INVALID_ARG;
        }
        let group = match unsafe { group_ref(group) } {
            Ok(g) => g,
            Err(rc) => return rc,
        };
        let wait = Duration::from_millis(timeout_ms);
        let polled = group.rt.block_on(async {
            let closed = group.close_notify.notified();
            tokio::pin!(closed);
            closed.as_mut().enable();
            if group.closed.load(Ordering::Acquire) {
                return None;
            }
            tokio::select! {
                biased;
                event = group.pool.poll_event(wait) => Some(event),
                () = &mut closed => None,
            }
        });
        match polled {
            Some(Some(event)) => {
                let json = Zeroizing::new(group_event_json(event).to_string());
                unsafe { write_out_cstring(out_event_json, &json) }
            }
            Some(None) if group.pool.is_closed() => TENDRIL_EOF,
            Some(None) => TENDRIL_WOULD_BLOCK,
            None => TENDRIL_EOF,
        }
    })
}

/// Checks whether `peer_id` currently holds `cap` in the group. Returns `TENDRIL_OK` when allowed;
/// any refusal sets the last error to the core error text.
///
/// # Safety
/// `group` must be a valid group pointer; `peer_id` and `cap` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_authorize_peer(
    group: *const TendrilGroup,
    peer_id: *const c_char,
    cap: *const c_char,
) -> i32 {
    ffi_i32(|| {
        let group = match unsafe { group_ref(group) } {
            Ok(g) => g,
            Err(rc) => return rc,
        };
        let peer_id = match unsafe { cstr_to_str(peer_id, "peer_id") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let cap = match unsafe { cstr_to_str(cap, "cap") } {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        match group.pool.authorize_peer(peer_id, cap) {
            Ok(()) => TENDRIL_OK,
            Err(e) => fail_group(&e),
        }
    })
}

/// Closes the group handle's sessions. Idempotent; later calls on the handle return
/// `TENDRIL_ERR_CLOSED` until [`tendril_group_free`] releases it.
///
/// # Safety
/// `group` must be a valid group pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_close(group: *mut TendrilGroup) -> i32 {
    ffi_i32(|| {
        if group.is_null() {
            set_last_error("null group");
            return TENDRIL_ERR_INVALID_ARG;
        }
        unsafe { &*group }.close_once();
        TENDRIL_OK
    })
}

/// Frees a group handle returned by [`tendril_group_open`]; safe after [`tendril_group_close`].
///
/// # Safety
/// `group` must be null or an unfreed pointer from [`tendril_group_open`], with no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tendril_group_free(group: *mut TendrilGroup) {
    if !group.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(group));
        }));
    }
}

#[cfg(all(test, feature = "p2p-iroh"))]
mod p2p_dialer_option_tests {
    use super::*;

    const BASEPOINT_ID: &str = "5866666666666666666666666666666666666666666666666666666666666666";

    fn bearer_cfg() -> EndpointTransportConfig {
        let mut cfg = EndpointTransportConfig::default();
        cfg.p2p_relay_auth = Some(P2pRelayAuth::BearerToken(Zeroizing::new("tok".to_owned())));
        cfg.p2p_allow_private_addrs = Some(true);
        cfg
    }

    #[test]
    fn uri_relay_disables_default_relays_and_pkarr() {
        let uri = format!("iroh://{BASEPOINT_ID}?relay=http://127.0.0.1:9/");
        let mut cfg = EndpointTransportConfig::default();
        cfg.p2p_allow_private_addrs = Some(true);
        let opts = cfg.build_p2p_dialer_options(&uri, None).expect("options");
        assert!(matches!(opts.relay_mode, P2pRelayMode::Custom(_)));
        assert!(!opts.resolve_pkarr);
        assert!(!opts.publish_pkarr);

        let plain = format!("iroh://{BASEPOINT_ID}");
        let opts = cfg.build_p2p_dialer_options(&plain, None).expect("options");
        assert!(matches!(opts.relay_mode, P2pRelayMode::Default));
        assert!(opts.resolve_pkarr);
    }

    #[test]
    fn operator_iroh_connect_honours_the_pkarr_override() {
        let endpoint = format!("iroh://{BASEPOINT_ID}");
        let resolves = |pkarr: Option<bool>| {
            let mut cfg = EndpointTransportConfig::default();
            cfg.p2p_pkarr = pkarr;
            cfg.hint_dialers(Some(&endpoint), None)
                .expect("dialers")
                .operator_p2p_options(&endpoint)
                .expect("options")
                .resolve_pkarr
        };
        assert!(resolves(None), "default relays keep the default lookup");
        assert!(!resolves(Some(false)), "p2p_pkarr false turns lookup off");
    }

    #[test]
    fn group_dialer_options_require_an_explicit_relay_mode() {
        if std::env::var("TENDRIL_P2P_LOCAL").as_deref() != Ok("1") {
            assert!(
                EndpointTransportConfig::default()
                    .build_p2p_group_options()
                    .is_none()
            );
        }
        let mut cfg = EndpointTransportConfig::default();
        cfg.p2p_relay_mode = Some(P2pRelayMode::Disabled);
        let opts = cfg.build_p2p_group_options().expect("options");
        assert!(matches!(opts.relay_mode, P2pRelayMode::Disabled));
        assert!(!opts.publish_pkarr);
    }

    #[test]
    fn explicit_operator_relay_wins_over_uri_hint() {
        let uri = format!("iroh://{BASEPOINT_ID}?relay=http://127.0.0.1:9/");
        let mut cfg = EndpointTransportConfig::default();
        cfg.p2p_allow_private_addrs = Some(true);
        let opts = cfg
            .build_p2p_dialer_options(&uri, Some("http://127.0.0.1:3340/"))
            .expect("options");
        match opts.relay_mode {
            P2pRelayMode::Custom(ref url) => assert_eq!(url, "http://127.0.0.1:3340/"),
            ref other => panic!("unexpected relay mode {other:?}"),
        }
    }

    #[test]
    fn bearer_auth_is_refused_on_untrusted_uri_relay() {
        let uri = format!("iroh://{BASEPOINT_ID}?relay=http://127.0.0.1:9/");
        let opts = bearer_cfg()
            .build_p2p_dialer_options(&uri, None)
            .expect("options");
        assert!(opts.relay_auth.is_some());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res = rt.block_on(P2pDialer::bind_with_options(opts));
        assert!(matches!(res, Err(RuntimeError::Protocol(ref m)) if m.contains("peer URI")));
    }
}

#[cfg(test)]
mod group_accept_tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::time::Instant;

    const HOLD: Duration = Duration::from_secs(10);

    /// Spawns a task that locks `rx`, signals once the guard is held, then keeps it for `hold`.
    async fn hold_lock<T: Send + 'static>(rx: &Arc<AsyncMutex<mpsc::Receiver<T>>>, hold: Duration) {
        let (held_tx, held_rx) = oneshot::channel();
        let rx = Arc::clone(rx);
        tokio::spawn(async move {
            let _guard = rx.lock().await;
            let _ = held_tx.send(());
            tokio::time::sleep(hold).await;
        });
        held_rx.await.unwrap();
    }

    async fn contended_lock_wait_honours_deadline<T: Send + 'static>() {
        let (_tx, rx) = mpsc::channel::<T>(1);
        let rx = Arc::new(AsyncMutex::new(rx));
        hold_lock(&rx, HOLD).await;
        let start = Instant::now();
        let res = recv_group_queue(&rx, start + Duration::from_millis(100)).await;
        assert!(res.is_err());
        assert_eq!(Instant::now(), start + Duration::from_millis(100));
    }

    async fn lock_released_mid_budget_keeps_original_deadline<T: Send + 'static>() {
        let (_tx, rx) = mpsc::channel::<T>(1);
        let rx = Arc::new(AsyncMutex::new(rx));
        hold_lock(&rx, Duration::from_millis(150)).await;
        let start = Instant::now();
        let res = recv_group_queue(&rx, start + Duration::from_millis(400)).await;
        assert!(res.is_err());
        assert_eq!(Instant::now(), start + Duration::from_millis(400));
    }

    #[tokio::test(start_paused = true)]
    async fn contended_lock_wait_honours_deadline_v1() {
        contended_lock_wait_honours_deadline::<SessionDriver>().await;
    }

    #[tokio::test(start_paused = true)]
    async fn contended_lock_wait_honours_deadline_v2() {
        contended_lock_wait_honours_deadline::<V2SessionDriver>().await;
    }

    #[tokio::test(start_paused = true)]
    async fn lock_released_mid_budget_keeps_original_deadline_v1() {
        lock_released_mid_budget_keeps_original_deadline::<SessionDriver>().await;
    }

    #[tokio::test(start_paused = true)]
    async fn lock_released_mid_budget_keeps_original_deadline_v2() {
        lock_released_mid_budget_keeps_original_deadline::<V2SessionDriver>().await;
    }

    #[tokio::test(start_paused = true)]
    async fn lock_released_mid_budget_delivers_queued_item() {
        let (tx, rx) = mpsc::channel::<u32>(1);
        let rx = Arc::new(AsyncMutex::new(rx));
        tx.send(7).await.unwrap();
        hold_lock(&rx, Duration::from_millis(150)).await;
        let start = Instant::now();
        let res = recv_group_queue(&rx, start + Duration::from_millis(400)).await;
        assert_eq!(res.unwrap(), Some(7));
        assert_eq!(Instant::now(), start + Duration::from_millis(150));
    }

    #[tokio::test(start_paused = true)]
    async fn uncontended_zero_budget_still_delivers_queued_item() {
        let (tx, rx) = mpsc::channel::<u32>(1);
        let rx = AsyncMutex::new(rx);
        tx.send(7).await.unwrap();
        let res = recv_group_queue(&rx, Instant::now()).await;
        assert_eq!(res.unwrap(), Some(7));
    }

    #[tokio::test(start_paused = true)]
    async fn contended_zero_budget_times_out_immediately() {
        let (_tx, rx) = mpsc::channel::<u32>(1);
        let rx = Arc::new(AsyncMutex::new(rx));
        hold_lock(&rx, HOLD).await;
        let start = Instant::now();
        let res = recv_group_queue(&rx, start).await;
        assert!(res.is_err());
        assert_eq!(Instant::now(), start);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_waiter_does_not_lose_items() {
        let (tx, rx) = mpsc::channel::<u32>(1);
        let rx = Arc::new(AsyncMutex::new(rx));
        hold_lock(&rx, Duration::from_millis(150)).await;
        let start = Instant::now();
        assert!(
            recv_group_queue(&rx, start + Duration::from_millis(100))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send(9).await.unwrap();
        let res = recv_group_queue(&rx, Instant::now() + Duration::from_millis(100)).await;
        assert_eq!(res.unwrap(), Some(9));
    }

    #[tokio::test(start_paused = true)]
    async fn closed_queue_reports_none() {
        let (tx, rx) = mpsc::channel::<u32>(1);
        let rx = AsyncMutex::new(rx);
        drop(tx);
        let res = recv_group_queue(&rx, Instant::now() + Duration::from_secs(1)).await;
        assert_eq!(res.unwrap(), None);
    }
}

#[cfg(test)]
mod route_state_tests {
    use super::*;
    use std::path::Path;
    use std::thread;
    use tendril_core::grants::{RevocationListUnsigned, sign_crl};
    use tendril_core::routes::RouteSet;
    use tendril_runtime::RelayOffline;

    fn cs(s: &str) -> CString {
        CString::new(s).expect("no interior NUL")
    }

    unsafe fn take(p: *mut c_char) -> String {
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
        unsafe { tendril_string_free(p) };
        s
    }

    fn last_err() -> String {
        LAST_ERROR.with(|c| c.borrow().clone())
    }

    struct Ep(*mut TendrilEndpoint);

    impl Ep {
        fn new(dir: &Path, host_id: Option<&str>) -> Self {
            let d = cs(dir.to_str().unwrap());
            let h = host_id.map(cs);
            let ep = unsafe {
                tendril_endpoint_new(d.as_ptr(), h.as_ref().map_or(ptr::null(), |c| c.as_ptr()))
            };
            assert!(!ep.is_null(), "{}", last_err());
            Self(ep)
        }

        fn get(&self) -> &TendrilEndpoint {
            unsafe { &*self.0 }
        }

        fn disk_crl_seq(&self, issuer: &str) -> Option<u64> {
            let store = self.get().store.as_ref().unwrap();
            store.load_roster().unwrap().crl(issuer).map(|c| c.seq)
        }

        fn memory_crl_seq(&self, issuer: &str) -> Option<u64> {
            lock_roster(&self.get().roster).crl(issuer).map(|c| c.seq)
        }
    }

    impl Drop for Ep {
        fn drop(&mut self) {
            unsafe { tendril_endpoint_free(self.0) };
        }
    }

    struct Sess(*mut TendrilSession);

    impl Drop for Sess {
        fn drop(&mut self) {
            unsafe { tendril_session_free(self.0) };
        }
    }

    fn crl(issuer: &EndpointIdentity, issuer_id: &str, seq: u64) -> RevocationList {
        sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: issuer_id.to_owned(),
                seq,
                revoked_devices: vec!["dev_other".to_owned()],
                revoked_nonces: vec![],
                ts: "2026-11-23T00:00:00Z".to_owned(),
            },
            issuer.signing_key(),
        )
        .unwrap()
    }

    struct OpenSink;

    #[async_trait::async_trait]
    impl RouteSetSink for OpenSink {
        fn peer_id(&self) -> String {
            "dev_peer".to_owned()
        }

        async fn send_route_set(&self, _payload: &[u8]) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    #[test]
    fn failed_route_registration_closes_the_session() {
        let tmp = tempfile::tempdir().unwrap();
        let ep = Ep::new(tmp.path(), None);
        // Nothing published yet, so registration reads the stored local routes: make that fail.
        std::fs::write(tmp.path().join("roster.json"), b"not a roster").unwrap();
        let sink: Arc<dyn RouteSetSink> = Arc::new(OpenSink);

        let mut closed = false;
        let err = ep
            .get()
            .register_route_sink(&sink, Some(0), || closed = true)
            .expect_err("registration must fail");
        assert!(closed, "the session is closed");
        assert!(err.contains("route announcer registration failed"), "{err}");

        // A client that negotiated no route sets needs no registration.
        ep.get()
            .register_route_sink(&sink, None, || panic!("not closed"))
            .expect("no route_seq");
    }

    #[test]
    fn ffi_route_writes_keep_unpersisted_crls() {
        let tmp = tempfile::tempdir().unwrap();
        let ep = Ep::new(tmp.path(), None);
        let host = EndpointIdentity::generate().unwrap();
        let host_id = host.host_id().to_owned();
        let host_pub = host.signing_key().public_key().clone();
        ep.get()
            .mutate_roster(|r| {
                r.insert_pinned_host(
                    host_id.clone(),
                    "Host".to_owned(),
                    *host.static_key().public_bytes(),
                    Some(host_pub.clone()),
                    0,
                    vec![],
                )
                .map(|_| ())
                .map_err(|e| (TENDRIL_ERR_INTERNAL, e.to_string()))
            })
            .unwrap();
        // A CRL a live session accepted into the shared roster that is not on disk yet.
        let accept = |seq| {
            lock_roster(&ep.get().roster)
                .ingest_crl(crl(&host, &host_id, seq), &host_id, &host_pub)
                .unwrap();
            assert_eq!(ep.disk_crl_seq(&host_id), (seq > 1).then(|| seq - 1));
        };
        let peer = cs(&host_id);

        accept(1);
        let routes = cs(r#"["127.0.0.1:7000"]"#);
        assert_eq!(
            unsafe { tendril_endpoint_set_peer_routes(ep.0, peer.as_ptr(), routes.as_ptr()) },
            TENDRIL_OK,
            "{}",
            last_err()
        );
        assert_eq!(ep.memory_crl_seq(&host_id), Some(1), "set kept the CRL");
        assert_eq!(ep.disk_crl_seq(&host_id), Some(1), "set persisted the CRL");

        accept(2);
        assert_eq!(
            unsafe { tendril_endpoint_clear_peer_routes(ep.0, peer.as_ptr(), ptr::null()) },
            TENDRIL_OK
        );
        assert_eq!(ep.memory_crl_seq(&host_id), Some(2), "clear kept the CRL");
        assert_eq!(ep.disk_crl_seq(&host_id), Some(2));

        accept(3);
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_peer_routes(ep.0, peer.as_ptr(), &raw mut out) },
            TENDRIL_OK
        );
        drop(unsafe { take(out) });
        ep.get().load_roster_from_store().unwrap();
        assert_eq!(
            ep.memory_crl_seq(&host_id),
            Some(3),
            "a reload kept the CRL"
        );
        ep.get().mutate_roster(|_| Ok(())).unwrap();
        assert_eq!(ep.disk_crl_seq(&host_id), Some(3), "any write persists it");
    }

    fn serve_direct(ep: &Ep) -> String {
        let a = cs("127.0.0.1:0");
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_serve_direct(ep.0, a.as_ptr(), &raw mut out) },
            TENDRIL_OK,
            "{}",
            last_err()
        );
        unsafe { take(out) }
    }

    /// Pairs `client` with `host` over a signed pairing URI and returns the host's grant JSON.
    fn pair(host: &Ep, client: &Ep) -> String {
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_issue_pairing_uri(host.0, ptr::null(), &raw mut out) },
            TENDRIL_OK
        );
        let issued: serde_json::Value = serde_json::from_str(&unsafe { take(out) }).unwrap();
        let host_addr = host.0 as usize;
        let acceptor = thread::spawn(move || {
            let mut out = ptr::null_mut();
            let rc = unsafe {
                tendril_endpoint_pair_accept(
                    host_addr as *mut TendrilEndpoint,
                    15_000,
                    &raw mut out,
                )
            };
            assert_eq!(rc, TENDRIL_OK, "{}", last_err());
            serde_json::from_str::<serde_json::Value>(&unsafe { take(out) }).unwrap()
        });
        let uri = cs(issued["uri"].as_str().unwrap());
        let mut out = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_uri(
                client.0,
                uri.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "{}", last_err());
        drop(unsafe { take(out) });
        let accepted = acceptor.join().unwrap();
        let device = cs(accepted["device_id"].as_str().unwrap());
        let sas = cs(accepted["sas"].as_str().unwrap());
        assert_eq!(
            unsafe { tendril_endpoint_confirm_peer(host.0, device.as_ptr(), sas.as_ptr()) },
            TENDRIL_OK
        );
        let caps = cs(r#"["fs.read"]"#);
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe {
                tendril_endpoint_mint_grant(
                    host.0,
                    device.as_ptr(),
                    caps.as_ptr(),
                    3600,
                    &raw mut out,
                )
            },
            TENDRIL_OK
        );
        unsafe { take(out) }
    }

    /// Connects `client` to `host` over its stored routes; returns (client, host) sessions.
    fn connect(host: &Ep, client: &Ep, host_id: &str, grant: &str) -> (Sess, Sess) {
        let host_addr = host.0 as usize;
        let acceptor = thread::spawn(move || {
            let sess = unsafe { tendril_session_accept(host_addr as *mut TendrilEndpoint, 10_000) };
            sess as usize
        });
        let target = cs(host_id);
        let g = cs(grant);
        let c = unsafe {
            tendril_session_connect(
                client.0,
                ptr::null(),
                ptr::null(),
                target.as_ptr(),
                g.as_ptr(),
            )
        };
        assert!(!c.is_null(), "{}", last_err());
        let h = acceptor.join().unwrap() as *mut TendrilSession;
        assert!(!h.is_null(), "host accept failed");
        (Sess(c), Sess(h))
    }

    /// Inserts a pinned peer and a trust anchor into `ep`'s roster (persisted), then accepts a
    /// CRL from each into the in-memory copy only, as a live session would. Returns their ids.
    fn hold_unpersisted_crls(ep: &Ep) -> [String; 2] {
        let peer = EndpointIdentity::generate().unwrap();
        let anchor = EndpointIdentity::generate().unwrap();
        let peer_id = peer.host_id().to_owned();
        let anchor_id = "anchor-held".to_owned();
        let peer_pub = peer.signing_key().public_key().clone();
        let anchor_pub = anchor.signing_key().public_key().clone();
        ep.get()
            .mutate_roster(|r| {
                r.insert_pinned_host(
                    peer_id.clone(),
                    "Peer".to_owned(),
                    *peer.static_key().public_bytes(),
                    Some(peer_pub.clone()),
                    0,
                    vec![],
                )
                .map_err(|e| (TENDRIL_ERR_INTERNAL, e.to_string()))?;
                r.add_trust_anchor(anchor_id.clone(), anchor_pub.clone())
                    .map(|_| ())
                    .map_err(|e| (TENDRIL_ERR_INTERNAL, e.to_string()))
            })
            .unwrap();
        let mut roster = lock_roster(&ep.get().roster);
        roster
            .ingest_crl(crl(&peer, &peer_id, 1), &peer_id, &peer_pub)
            .unwrap();
        roster
            .ingest_crl(crl(&anchor, &anchor_id, 1), &anchor_id, &anchor_pub)
            .unwrap();
        [peer_id, anchor_id]
    }

    #[test]
    fn persisting_a_session_crl_keeps_other_unpersisted_crls() {
        let tmp = tempfile::tempdir().unwrap();
        let host = Ep::new(&tmp.path().join("host"), Some("crl-keep-host"));
        let client = Ep::new(&tmp.path().join("client"), None);
        serve_direct(&host);
        let grant = pair(&host, &client);
        let host_id = host.get().identity.host_id().to_owned();
        let (c, _h) = connect(&host, &client, &host_id, &grant);
        let held = hold_unpersisted_crls(&client);
        // The v1 session accepted a newer CRL from its host that is not on disk either.
        let host_pub = host.get().identity.signing_key().public_key().clone();
        lock_roster(&client.get().roster)
            .ingest_crl(crl(&host.get().identity, &host_id, 1), &host_id, &host_pub)
            .unwrap();
        for id in held.iter().chain([&host_id]) {
            assert_eq!(client.disk_crl_seq(id), None, "{id} is held in memory only");
        }

        let sess = unsafe { &*c.0 };
        assert!(matches!(sess.session, SessionBackend::V1(_)));
        sess.persist_v1_crl_if_newer(&host_id).unwrap();

        assert_eq!(
            client.disk_crl_seq(&host_id),
            Some(1),
            "session CRL persisted"
        );
        assert_eq!(client.memory_crl_seq(&host_id), Some(1));
        for id in &held {
            assert_eq!(
                client.memory_crl_seq(id),
                Some(1),
                "{id} CRL kept in memory"
            );
            assert_eq!(
                client.disk_crl_seq(id),
                Some(1),
                "{id} CRL persisted with it"
            );
        }
    }

    fn wake_config(url: &str, pre_wake: bool) -> WakeTransportConfig {
        WakeTransportConfig {
            target: WakeTarget::new(WakeAdapterKind::Webhook, url).unwrap(),
            secret: WakeSecret::from_bytes([7; 32]),
            pre_wake,
            retry_delay_ms: 1,
            max_attempts: 3,
            timeout_ms: 2_000,
        }
    }

    /// A loopback webhook counting `POST` requests (a host service may probe new loopback
    /// listeners with `GET /`; those are not counted).
    fn wake_hits() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                if buf[..n].starts_with(b"POST ") {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.write_all(
                        b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
        });
        (format!("http://{addr}/wake"), hits)
    }

    fn miss(error: RuntimeError, committed: bool) -> AttemptError {
        let mut err = AttemptError::from(error);
        err.committed = committed;
        err
    }

    /// Runs `connect_with_wake` over a connect that always fails with `make()`; returns the
    /// number of connects and wake hints.
    fn wake_run(pre_wake: bool, make: impl Fn() -> AttemptError) -> (usize, usize) {
        let (url, hits) = wake_hits();
        let wake = wake_config(&url, pre_wake);
        let calls = std::cell::Cell::new(0);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res: Result<(), AttemptError> = rt.block_on(connect_with_wake(&wake, || {
            calls.set(calls.get() + 1);
            let err = make();
            async move { Err(err) }
        }));
        assert!(res.is_err());
        (calls.get(), hits.load(Ordering::SeqCst))
    }

    #[test]
    fn wake_retries_only_misses_a_wake_can_fix() {
        let io = || {
            miss(
                RuntimeError::Io(std::io::ErrorKind::ConnectionRefused.into()),
                false,
            )
        };
        // pre_wake=false: connect, wake on the transient miss, then max_attempts retries.
        assert_eq!(wake_run(false, io), (4, 1));
        // pre_wake=true: wake, then max_attempts connects.
        assert_eq!(wake_run(true, io), (3, 1));

        // A relay that reports the sleeping host's mailbox offline is a wakeable miss.
        for offline in [
            RelayOffline::V2Dial,
            RelayOffline::V1Dial,
            RelayOffline::PinnedKey,
        ] {
            let make = || miss(RuntimeError::RelayOffline(offline), false);
            assert_eq!(wake_run(false, make), (4, 1), "{offline:?}");
        }
        // The text alone is not a typed refusal: an untyped look-alike is final.
        let lookalike = || {
            miss(
                RuntimeError::Protocol("v2 relay dial rejected: offline".into()),
                false,
            )
        };
        assert_eq!(wake_run(false, lookalike), (1, 0), "untyped text is final");

        // A permanent protocol error, a committed attempt and a core error are final.
        let permanent = |what: &str| match what {
            "unauthorized" => miss(
                RuntimeError::Protocol("v2 relay dial rejected: unauthorized".into()),
                false,
            ),
            "committed offline" => miss(RuntimeError::RelayOffline(RelayOffline::V2Dial), true),
            "protocol" => miss(
                RuntimeError::Protocol("no dialable stored routes".into()),
                false,
            ),
            "committed" => miss(
                RuntimeError::Io(std::io::ErrorKind::BrokenPipe.into()),
                true,
            ),
            _ => miss(RuntimeError::Core(CoreError::PairingCodeInvalid), false),
        };
        for what in [
            "protocol",
            "committed",
            "core",
            "unauthorized",
            "committed offline",
        ] {
            let make = || permanent(what);
            assert_eq!(wake_run(false, make), (1, 0), "{what}: no wake, no retry");
            assert_eq!(wake_run(true, make), (1, 1), "{what}: pre-wake, no retry");
        }
    }

    #[test]
    fn attempt_error_text_survives_the_last_error_scrub_unchanged() {
        // attempt_error_message redacts each hint and nested error; set_last_error then
        // scrubs the whole message again. The second pass must change nothing.
        let mut err = miss(
            RuntimeError::Egress {
                reason: tendril_runtime::providers::SkipReason::BlockedAddress,
                detail: tendril_runtime::redact::redact_host("bad host!"),
            },
            true,
        );
        err.skipped = vec![SkippedHint::new(
            "wss://u:p@relay.example:8443/v2/relay?t=s3cret".to_owned(),
            tendril_runtime::providers::SkipReason::BlockedAddress,
        )];
        err.failures = vec![tendril_runtime::driver::CandidateFailure {
            hint: "direct:TND-ABCD-EFGH:1".to_owned(),
            provider: tendril_core::policy::ProviderId::Direct,
            error: RuntimeError::RelayOffline(RelayOffline::V2Dial),
        }];
        let msg = attempt_error_message(&err);
        assert_eq!(redact_text(&msg), msg, "double redaction changed {msg}");
        assert!(msg.contains("wss://relay.example:8443"), "{msg}");
        for leaked in ["s3cret", "ABCD", "u:p", "/v2/relay"] {
            assert!(!msg.contains(leaked), "{leaked} leaked: {msg}");
        }
    }

    #[test]
    fn crl_and_route_set_on_one_session_persist_both() {
        let tmp = tempfile::tempdir().unwrap();
        let host = Ep::new(&tmp.path().join("host"), Some("crl-host"));
        let client = Ep::new(&tmp.path().join("client"), None);
        let listen = serve_direct(&host);
        let grant = pair(&host, &client);
        let host_id = host.get().identity.host_id().to_owned();
        let seq0 = lock_roster(&client.get().roster)
            .get(&host_id)
            .and_then(|e| e.route_meta)
            .map(|m| m.seq)
            .unwrap();
        // An earlier session already delivered the host's current set, so the client sends
        // `route_seq = seq0` and the host has no initial announcement for this session. Without
        // it the initial set may be processed alone and rate-limit the set sent below.
        let current: Vec<String> = lock_roster(&client.get().roster)
            .get(&host_id)
            .unwrap()
            .routes_from(RouteSource::Signed)
            .map(str::to_owned)
            .collect();
        let earlier = RouteSet::sign(&host.get().identity, seq0, now_unix(), current).unwrap();
        client
            .get()
            .route_access
            .update(|r| Ok(r.apply_route_announcement(&host_id, &earlier, now_unix())?))
            .unwrap();
        assert_eq!(
            lock_roster(&client.get().roster)
                .get(&host_id)
                .unwrap()
                .hello_route_seq(RoutePolicy::AllSigned),
            Some(seq0)
        );
        let (c, h) = connect(&host, &client, &host_id, &grant);

        // The host sends a CRL and a newer route set back to back, before the client reads.
        let identity = &host.get().identity;
        let revocation = crl(identity, &host_id, 1);
        let routes = vec![format!("direct:{listen}"), "direct:127.0.0.1:9".to_owned()];
        let set = RouteSet::sign(identity, seq0 + 1, now_unix(), routes.clone()).unwrap();
        let SessionBackend::V1(ref hs) = unsafe { &*h.0 }.session else {
            panic!("v1 session");
        };
        host.get().rt.block_on(async {
            hs.send_revocation(&revocation).await.unwrap();
            RouteSetSink::send_route_set(hs.as_ref(), &set.encode())
                .await
                .unwrap();
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut revoked_event = false;
        loop {
            let mut out = ptr::null_mut();
            match unsafe { tendril_session_poll_event(c.0, 200, &raw mut out) } {
                TENDRIL_OK => {
                    let ev: serde_json::Value =
                        serde_json::from_str(&unsafe { take(out) }).unwrap();
                    revoked_event |= ev["event"] == "revocation_updated";
                }
                TENDRIL_WOULD_BLOCK => {}
                rc => panic!("poll failed {rc}: {}", last_err()),
            }
            let applied = client
                .get()
                .route_access
                .last_route_set(&host_id)
                .is_some_and(|l| l.seq == seq0 + 1 && l.outcome == "applied");
            if revoked_event && applied {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "CRL or route set lost"
            );
        }
        assert_eq!(client.disk_crl_seq(&host_id), Some(1), "CRL persisted");
        assert_eq!(
            client.memory_crl_seq(&host_id),
            Some(1),
            "CRL kept in memory"
        );
        let disk = client.get().store.as_ref().unwrap().load_roster().unwrap();
        let signed: Vec<_> = disk
            .get(&host_id)
            .unwrap()
            .routes
            .iter()
            .filter(|r| r.source == RouteSource::Signed)
            .map(|r| r.hint.clone())
            .collect();
        assert_eq!(signed, routes, "route set persisted");
    }

    #[test]
    fn close_stops_the_announcer_refresh_task() {
        let dir = tempfile::tempdir().unwrap();
        let ep = Ep::new(dir.path(), Some("close-host"));
        let addr = cs("127.0.0.1:0");
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_serve_direct(ep.0, addr.as_ptr(), &raw mut out) },
            TENDRIL_OK,
            "{}",
            last_err()
        );
        drop(unsafe { take(out) });
        let timer = match &*ep.get().hosting.lock().unwrap() {
            HostingState::Running(h) => h.abort_handle(),
            other => panic!("hosting must start the timer task, got {other:?}"),
        };
        assert!(!timer.is_finished(), "hosting starts the timer task");

        assert_eq!(unsafe { tendril_endpoint_close(ep.0) }, TENDRIL_OK);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !timer.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "close left the refresh task running"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            unsafe { tendril_endpoint_close(ep.0) },
            TENDRIL_OK,
            "close is idempotent"
        );
    }

    fn serve_loopback(ep: &Ep) {
        let addr = cs("127.0.0.1:0");
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_serve_direct(ep.0, addr.as_ptr(), &raw mut out) },
            TENDRIL_OK,
            "{}",
            last_err()
        );
        drop(unsafe { take(out) });
    }

    #[test]
    fn close_blocks_every_start_path() {
        let dir = tempfile::tempdir().unwrap();
        let ep = Ep::new(dir.path(), Some("closed-host"));
        assert_eq!(unsafe { tendril_endpoint_close(ep.0) }, TENDRIL_OK);
        let closed = |ep: &Ep| matches!(&*ep.get().hosting.lock().unwrap(), HostingState::Closed);
        assert!(closed(&ep), "close from Idle is terminal");

        let err = ep.get().start_hosting().unwrap_err();
        assert_eq!(err.0, TENDRIL_ERR_CLOSED);
        assert!(err.1.contains("closed"), "{}", err.1);
        assert!(closed(&ep), "start_hosting does not leave Closed");

        ep.get().record_served("127.0.0.1:1".to_owned(), None);
        assert!(closed(&ep), "record_served does not revive hosting");
        assert!(!ep.get().is_hosting());
    }

    /// One C ABI call that starts hosting: issue or refresh. Returns the code, with the output
    /// freed; any non-OK result must leave the output null.
    fn hosting_call(ep: *mut TendrilEndpoint, pick: u32) -> i32 {
        let mut out = ptr::null_mut();
        let rc = if pick.is_multiple_of(2) {
            unsafe { tendril_endpoint_issue_pairing_uri(ep, ptr::null(), &raw mut out) }
        } else {
            unsafe { tendril_endpoint_refresh_routes(ep, ptr::null(), &raw mut out) }
        };
        if rc == TENDRIL_OK {
            if !out.is_null() {
                drop(unsafe { take(out) });
            }
        } else {
            assert!(out.is_null(), "output set on error {rc}");
        }
        rc
    }

    #[test]
    fn close_racing_issue_and_refresh_leaves_no_timer() {
        use std::sync::Barrier;

        for round in 0..20_u32 {
            // Even rounds start Idle, so the Idle -> Running spawn races the close; odd rounds
            // start Running with a timer task to watch.
            let idle_start = round.is_multiple_of(2);
            let dir = tempfile::tempdir().unwrap();
            let ep = Ep::new(dir.path(), Some("race-host"));
            let timer = if idle_start {
                None
            } else {
                serve_loopback(&ep);
                match &*ep.get().hosting.lock().unwrap() {
                    HostingState::Running(h) => Some(h.abort_handle()),
                    other => panic!("serving must start hosting, got {other:?}"),
                }
            };
            let addr = ep.0 as usize;
            let barrier = Barrier::new(5);
            thread::scope(|scope| {
                let workers: Vec<_> = (0..4_u32)
                    .map(|n| {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            let ep = addr as *mut TendrilEndpoint;
                            barrier.wait();
                            if idle_start && n == 0 {
                                let a = cs("127.0.0.1:0");
                                let mut out = ptr::null_mut();
                                let rc = unsafe {
                                    tendril_endpoint_serve_direct(ep, a.as_ptr(), &raw mut out)
                                };
                                assert_eq!(rc, TENDRIL_OK, "{}", last_err());
                                if !out.is_null() {
                                    drop(unsafe { take(out) });
                                }
                            }
                            let deadline = std::time::Instant::now() + Duration::from_secs(10);
                            for i in 0.. {
                                assert!(
                                    std::time::Instant::now() < deadline,
                                    "worker never observed the close"
                                );
                                match hosting_call(ep, i + n) {
                                    TENDRIL_OK => {}
                                    TENDRIL_ERR_PROTOCOL => assert!(
                                        last_err().contains("too many live pairing codes"),
                                        "{}",
                                        last_err()
                                    ),
                                    TENDRIL_ERR_CLOSED => {
                                        assert!(last_err().contains("closed"), "{}", last_err());
                                        for j in 0..3_u32 {
                                            assert_eq!(
                                                hosting_call(ep, j + n),
                                                TENDRIL_ERR_CLOSED,
                                                "closed is terminal"
                                            );
                                        }
                                        return;
                                    }
                                    rc => panic!("unexpected rc {rc}: {}", last_err()),
                                }
                            }
                            unreachable!();
                        })
                    })
                    .collect();
                barrier.wait();
                thread::yield_now();
                assert_eq!(unsafe { tendril_endpoint_close(ep.0) }, TENDRIL_OK);
                for w in workers {
                    w.join().unwrap();
                }
            });
            assert!(
                matches!(&*ep.get().hosting.lock().unwrap(), HostingState::Closed),
                "round {round}: state must be Closed"
            );
            if let Some(timer) = timer {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !timer.is_finished() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "round {round}: timer task still running after close"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
            }
            assert_eq!(hosting_call(ep.0, 0), TENDRIL_ERR_CLOSED);
        }
    }
}
