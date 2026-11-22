//! Callback-free polled C ABI over `tendril-core` and `tendril-runtime`.
#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString, c_char};
use std::fmt;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
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
    EnrollmentPolicy, PairAction, PairOutcome, PairingCodeKind, PairingConfig, PairingInitiator,
    PairingManager, PinnedHost, mint_enrollment_token,
};
use tendril_core::relay_auth::{RelayAuthRole, RelayAuthSecret, RelayTicket};
use tendril_core::roster::{AnchorState, PeerState, Roster, RosterEntry, TrustAnchor};
use tendril_core::v2::{
    V2PairOutcome, V2PinnedHost, canonical_relay_host, derive_epoch_mailbox_window,
};
use tendril_runtime::{
    BrokerDialer, ConcurrentSession, ConcurrentV2Session, DEFAULT_PRE_AUTH_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, HttpWakeProvider, InboundRouter,
    LocalDialer, MAX_OUTER_FRAME_LEN, OverlayDialer, PathDialer, PathListener, PathStream,
    RelayClientAuth, RelayDialer, RelayListener, RelayV2Dialer, RelayV2Listener,
    RelayV2ListenerConfig, RuntimeError, SessionDriver, SessionEvent, StateStore, V2ResponderState,
    V2SessionDriver, WakeAdapterKind, WakeDialOptions, WakeSecret, WakeTarget,
    deserialize_identity_json, dial_endpoint_with_auth, drive_m2m_enroll_initiator_with_floor,
    drive_m2m_enroll_initiator_with_store, drive_pair_initiator_with_store,
    drive_pair_responder_with_policy, drive_pair_responder_with_store,
    drive_v2_pake_pair_initiator_with_store, drive_v2_pake_pair_initiator_with_timeout,
    drive_v2_pake_pair_responder_with_options, drive_v2_pake_pair_responder_with_store,
    pairing_path_kind_for_provider, pinned_pairing_floor, serialize_identity_json,
    wake_and_dial_v2,
};
#[cfg(feature = "p2p-iroh")]
use tendril_runtime::{
    P2pDialer, P2pListener, P2pOptions, P2pRelayAuth, P2pRelayMode, parse_p2p_relay_mode,
    parse_p2p_relay_modes,
};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
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

fn set_last_error(msg: impl Into<String>) {
    let s = msg.into();
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = s;
    });
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

/// Serde shape of [`Roster`] used to merge in-memory session state into the on-disk roster.
///
/// Unknown top-level fields are carried through `rest` so a merge never drops state.
#[derive(Serialize, Deserialize)]
struct RosterShadow {
    entries: BTreeMap<String, RosterEntry>,
    crls: BTreeMap<String, RevocationList>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    trust_anchors: BTreeMap<String, TrustAnchor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    burned_enrollment_nonces: BTreeMap<String, u64>,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_json::Value>,
}

/// Merges the monotonic security state of `mem` (revocations, newer CRLs, rotations, raised wire
/// floors, burned nonces) into `disk`. The disk roster stays authoritative for existence and
/// for any entry already revoked, so a stale in-memory snapshot can never resurrect a peer or
/// drop a revocation that was committed concurrently.
fn merge_roster_state(disk: &Roster, mem: &Roster) -> Result<Roster, String> {
    let disk_bytes = Zeroizing::new(serde_json::to_vec(disk).map_err(|e| e.to_string())?);
    let mem_bytes = Zeroizing::new(serde_json::to_vec(mem).map_err(|e| e.to_string())?);
    if *disk_bytes == *mem_bytes {
        return Ok(disk.clone());
    }
    let mut merged: RosterShadow =
        serde_json::from_slice(&disk_bytes).map_err(|e| e.to_string())?;
    let session: RosterShadow = serde_json::from_slice(&mem_bytes).map_err(|e| e.to_string())?;
    for (id, mem_entry) in &session.entries {
        let Some(entry) = merged.entries.get_mut(id) else {
            continue;
        };
        if entry.state == PeerState::Revoked {
            continue;
        }
        if mem_entry.state == PeerState::Revoked {
            entry.state = PeerState::Revoked;
            entry.grants.clear();
            entry.v2_secrets = None;
            continue;
        }
        if mem_entry.rotation_seq > entry.rotation_seq {
            entry.static_pub = mem_entry.static_pub;
            entry.signing_pub.clone_from(&mem_entry.signing_pub);
            entry.rotation_seq = mem_entry.rotation_seq;
        }
        entry.min_wire_version = entry.min_wire_version.max(mem_entry.min_wire_version);
    }
    for (issuer, crl) in session.crls {
        let newer = merged
            .crls
            .get(&issuer)
            .is_none_or(|existing| crl.seq > existing.seq);
        if newer {
            merged.crls.insert(issuer, crl);
        }
    }
    for (id, mem_anchor) in &session.trust_anchors {
        if mem_anchor.state == AnchorState::Revoked
            && let Some(anchor) = merged.trust_anchors.get_mut(id)
        {
            anchor.state = AnchorState::Revoked;
        }
    }
    for (nonce, expiry) in session.burned_enrollment_nonces {
        merged
            .burned_enrollment_nonces
            .entry(nonce)
            .or_insert(expiry);
    }
    let out = Zeroizing::new(serde_json::to_vec(&merged).map_err(|e| e.to_string())?);
    serde_json::from_slice(&out).map_err(|e| e.to_string())
}

/// Applies `f` to the roster. The caller must already hold `store_lock` when `store` is `Some`.
///
/// Lock order is `store_lock` then `roster`. With a store, `f` runs transactionally on the
/// latest on-disk roster after the in-memory security state is merged in, and the committed
/// roster replaces the in-memory copy before `roster` is released.
fn commit_roster_update<T, F>(
    store: Option<&Arc<StateStore>>,
    roster: &StdMutex<Roster>,
    f: F,
) -> Result<T, (i32, String)>
where
    F: FnOnce(&mut Roster) -> Result<T, (i32, String)>,
{
    let mut guard = lock_roster(roster);
    let Some(store) = store else {
        return f(&mut guard);
    };
    let mut failure: Option<(i32, String)> = None;
    let res = store.update_roster_with_state(|disk| {
        let merged = merge_roster_state(disk, &guard).map_err(RuntimeError::Storage)?;
        *disk = merged;
        f(disk).map_err(|e| {
            failure = Some(e);
            RuntimeError::Protocol(String::new())
        })
    });
    match res {
        Ok((out, committed, _stamp)) => {
            *guard = committed;
            Ok(out)
        }
        Err(e) => Err(failure.unwrap_or((TENDRIL_ERR_INTERNAL, e.to_string()))),
    }
}

/// Merges in-memory session state into the store and reloads the committed roster, serialized
/// under `store_lock` (lock order `store_lock` then `roster`). No-op without a store.
fn sync_roster_from_store_locked(
    store: Option<&Arc<StateStore>>,
    store_lock: &AsyncMutex<()>,
    rt: &Runtime,
    roster: &StdMutex<Roster>,
) -> Result<(), String> {
    let Some(store) = store else {
        return Ok(());
    };
    let _store_guard = rt.block_on(store_lock.lock());
    commit_roster_update(Some(store), roster, |_| Ok(())).map_err(|(_, msg)| msg)
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
        dbg.field("wake", &self.wake).finish()
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

        Ok(Self {
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
            format!("target '{target_host_id}' not found in roster"),
        )
    })?;
    if entry.state == PeerState::Revoked {
        return Err((
            TENDRIL_ERR_PROTOCOL,
            format!("target '{target_host_id}' is revoked"),
        ));
    }
    entry
        .v2_secrets
        .as_ref()
        .map(|s| *s.mailbox_secret())
        .ok_or_else(|| {
            (
                TENDRIL_ERR_PROTOCOL,
                format!("target '{target_host_id}' has no v2 mailbox_secret"),
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

async fn build_dialer_with_options(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &EndpointTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathDialer>, RuntimeError> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        #[cfg(feature = "p2p-iroh")]
        {
            let opts = cfg.build_p2p_dialer_options(endpoint, normalized_host)?;
            return Ok(Box::new(P2pDialer::bind_with_options(opts).await?));
        }
        #[cfg(not(feature = "p2p-iroh"))]
        {
            let _ = normalized_host;
            return Err(RuntimeError::Protocol(
                "p2p-iroh feature is not enabled in tendril-ffi".to_owned(),
            ));
        }
    }
    if endpoint.starts_with("overlay://") {
        return Ok(Box::new(OverlayDialer::new()));
    }
    if endpoint.starts_with("broker+ws://") || endpoint.starts_with("broker+wss://") {
        return Ok(Box::new(BrokerDialer::new()));
    }
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        if let Some(secret) = v2_mailbox_secret {
            let mut dialer = RelayV2Dialer::new(secret).with_auth(cfg.relay_auth.clone());
            if let Some(host) = normalized_host {
                dialer = dialer.with_expected_host(host);
            }
            return Ok(Box::new(dialer));
        }
        let mut dialer = RelayDialer::new().with_auth(cfg.relay_auth.clone());
        if let Some(host) = normalized_host {
            dialer = dialer.with_expected_host(host);
        }
        return Ok(Box::new(dialer));
    }
    if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        return Ok(Box::new(LocalDialer::new()));
    }
    Ok(Box::new(DirectDialer::new()))
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
}

impl TendrilEndpoint {
    fn mutate_roster<T, F>(&self, f: F) -> Result<T, (i32, String)>
    where
        F: FnOnce(&mut Roster) -> Result<T, (i32, String)>,
    {
        let _store_guard = self
            .store
            .as_ref()
            .map(|_| self.rt.block_on(self.store_lock.lock()));
        commit_roster_update(self.store.as_ref(), &self.roster, f)
    }

    fn sync_roster_from_store(&self) -> Result<(), String> {
        sync_roster_from_store_locked(
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
    Box::into_raw(Box::new(TendrilEndpoint {
        rt,
        store,
        store_lock: Arc::new(AsyncMutex::new(())),
        identity,
        roster: Arc::new(StdMutex::new(roster)),
        pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
        router: InboundRouter::new(),
        v2_state: Arc::new(V2ResponderState::new()),
        transport_cfg: StdMutex::new(EndpointTransportConfig::default()),
        self_m2m_enabled: AtomicBool::new(false),
        m2m_enabled: AtomicBool::new(has_active_anchor),
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

enum SessionBackend {
    V1(ConcurrentSession),
    V2(ConcurrentV2Session),
}

impl SessionBackend {
    fn shutdown(&self) {
        match self {
            Self::V1(s) => s.shutdown(),
            Self::V2(s) => s.shutdown(),
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
    ) -> (Result<(), CoreError>, tendril_core::grants::AuditEvent) {
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

/// Opaque authenticated session handle sharing the endpoint's Tokio runtime and roster state.
pub struct TendrilSession {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    roster: Arc<StdMutex<Roster>>,
    session: SessionBackend,
}

impl TendrilSession {
    fn sync_roster_from_store(&self) -> Result<(), String> {
        sync_roster_from_store_locked(
            self.store.as_ref(),
            &self.store_lock,
            &self.rt,
            &self.roster,
        )
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
                set_last_error(format!("invalid chain_json: {e}"));
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
                set_last_error(format!("invalid grant_json: {e}"));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let key_map_raw: HashMap<String, String> = match serde_json::from_str(keys_s) {
            Ok(m) => m,
            Err(e) => {
                set_last_error(format!("invalid issuer_keys_json: {e}"));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let mut key_map: HashMap<String, HybridSigningPublicKey> =
            HashMap::with_capacity(key_map_raw.len());
        for (id, b64) in key_map_raw {
            let Ok(k) = HybridSigningPublicKey::from_b64url(&b64) else {
                set_last_error(format!("invalid signing key for issuer '{id}'"));
                return TENDRIL_ERR_INVALID_ARG;
            };
            key_map.insert(id, k);
        }
        let crl: Option<RevocationList> = match crl_opt_s {
            Some(s) if !s.is_empty() => match serde_json::from_str(s) {
                Ok(c) => Some(c),
                Err(e) => {
                    set_last_error(format!("invalid crl_json_opt: {e}"));
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

        let identity = match id_json.filter(|s| !s.is_empty()) {
            Some(raw) => match deserialize_identity_json(raw) {
                Ok(id) => id,
                Err(e) => {
                    set_last_error(e.to_string());
                    return ptr::null_mut();
                }
            },
            None => {
                let mut id = match EndpointIdentity::generate() {
                    Ok(id) => id,
                    Err(e) => {
                        set_last_error(e.to_string());
                        return ptr::null_mut();
                    }
                };
                if let Some(h) = host_opt
                    && !h.is_empty()
                {
                    id = id.with_host_id(h);
                }
                id
            }
        };

        let roster = match roster_json.filter(|s| !s.is_empty()) {
            Some(raw) => match serde_json::from_str::<Roster>(raw) {
                Ok(r) => r,
                Err(e) => {
                    set_last_error(format!("invalid roster json: {e}"));
                    return ptr::null_mut();
                }
            },
            None => Roster::new(),
        };

        build_endpoint_handle(None, identity, roster)
    })
}

/// Closes the endpoint's inbound router and wakes any parked `pair_accept`/`session_accept` calls.
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
                ep.spawn_listener(Box::new(listener));
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
        let pk = match kind_opt {
            None | Some("" | "lan") => PairingCodeKind::Lan2Group,
            Some("remote") => PairingCodeKind::Remote3Group,
            Some(other) => {
                set_last_error(format!("invalid pairing code kind '{other}'"));
                return TENDRIL_ERR_INVALID_ARG;
            }
        };
        let ep = unsafe { &*ep };
        let mut mgr = ep.pair_mgr.lock().expect("pair_mgr mutex poisoned");
        match mgr.issue_code(pk, now_unix()) {
            Ok(code) => unsafe { write_out_cstring(out_code, &code) },
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
        let roster_snapshot = {
            ep.roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
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
            let pair_res = if let Some(ref store) = ep.store {
                drive_pair_initiator_with_store(
                    stream.as_mut(),
                    &ep.identity,
                    device_name,
                    device_kind,
                    code_s.to_owned(),
                    None,
                    store,
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                .map(|r| r.outcome)
            } else {
                drive_v1_pair_initiator_with_roster_floors(
                    stream.as_mut(),
                    &ep.identity,
                    device_name,
                    device_kind,
                    code_s.to_owned(),
                    &roster_snapshot,
                )
                .await
            }
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
            && let Err(e) = ep.sync_roster_from_store()
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
                set_last_error(format!("invalid caps_json: {e}"));
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
                set_last_error(format!("invalid token_json: {e}"));
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
        let fallback_floor = {
            let roster = ep
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pinned_pairing_floor(&roster, &pinned_host)
        };
        let res = ep.rt.block_on(async {
            let mut stream = dial_endpoint_v2_with_options(endpoint_s, relay_host_s, &cfg, None)
                .await
                .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))?;
            let device_name = name_s.unwrap_or("ffi-machine").to_owned();
            let device_kind = kind_s.unwrap_or("machine").to_owned();
            let pair_res = if let Some(ref store) = ep.store {
                drive_m2m_enroll_initiator_with_store(
                    stream.as_mut(),
                    &ep.identity,
                    device_name,
                    device_kind,
                    token,
                    pinned_host,
                    store,
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            } else {
                drive_m2m_enroll_initiator_with_floor(
                    stream.as_mut(),
                    &ep.identity,
                    device_name,
                    device_kind,
                    token,
                    pinned_host,
                    fallback_floor,
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            }
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

/// Opens an authenticated Noise XX session toward `target_host_id` via `endpoint`.
///
/// # Safety
/// `ep`, `endpoint`, and `target_host_id` must be valid non-null pointers; `relay_host` and `grant_json` may be null.
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
        let Ok(ep_s) = (unsafe { cstr_to_str(endpoint, "endpoint") }) else {
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
        let grant: Option<Grant> = match grant_opt {
            Some(g) if !g.is_empty() => match serde_json::from_str(g) {
                Ok(parsed) => Some(parsed),
                Err(e) => {
                    set_last_error(format!("invalid grant_json: {e}"));
                    return ptr::null_mut();
                }
            },
            _ => None,
        };

        let ep = unsafe { &*ep };
        let cfg = ep.snapshot_transport_cfg();
        if let Err(e) = ep.sync_roster_from_store() {
            set_last_error(e);
            return ptr::null_mut();
        }
        if let Err(e) =
            tendril_core::session::check_peer_allows_wire_v1(&lock_roster(&ep.roster), target_s)
        {
            set_last_error(e.to_string());
            return ptr::null_mut();
        }
        let v2_secret = if is_v2_relay_endpoint(ep_s) {
            let roster = lock_roster(&ep.roster);
            match lookup_v2_mailbox_secret_for_target(&roster, target_s) {
                Ok(s) => Some(s),
                Err((_, msg)) => {
                    set_last_error(msg);
                    return ptr::null_mut();
                }
            }
        } else {
            None
        };
        let res = ep.rt.block_on(async {
            let stream = dial_endpoint_v2_with_options(ep_s, relay_host_s, &cfg, v2_secret)
                .await
                .map_err(|e| e.to_string())?;
            SessionDriver::connect_locked(
                stream,
                &ep.identity,
                target_s,
                grant,
                &ep.roster,
                now_unix(),
            )
            .await
            .map_err(|e| e.to_string())
        });

        match res {
            Ok(driver) => {
                if let Err(e) = ep.sync_roster_from_store() {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                Box::into_raw(Box::new(TendrilSession {
                    rt: Arc::clone(&ep.rt),
                    store: ep.store.clone(),
                    store_lock: Arc::clone(&ep.store_lock),
                    roster: Arc::clone(&ep.roster),
                    session: SessionBackend::V1(driver.into_concurrent()),
                }))
            }
            Err(e) => {
                if let Err(pe) = ep.sync_roster_from_store() {
                    set_last_error(format!("{e} (roster persist error: {pe})"));
                } else {
                    set_last_error(e);
                }
                ptr::null_mut()
            }
        }
    })
}

/// Accepts and authenticates the next inbound session stream within `timeout_ms`.
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
            let (stream, guard) = match ep.router.recv_session(wait).await {
                Ok(Some(pair)) => pair,
                Ok(None) => return Err("listener closed".to_owned()),
                Err(()) => return Err("timed out accepting session".to_owned()),
            };
            accepted.set(true);

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
            .map_err(|e| e.to_string())
        });
        let synced = if accepted.get() {
            ep.sync_roster_from_store()
        } else {
            Ok(())
        };

        match res {
            Ok(driver) => {
                if let Err(e) = synced {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                Box::into_raw(Box::new(TendrilSession {
                    rt: Arc::clone(&ep.rt),
                    store: ep.store.clone(),
                    store_lock: Arc::clone(&ep.store_lock),
                    roster: Arc::clone(&ep.roster),
                    session: SessionBackend::V1(driver.into_concurrent()),
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
        unsafe { write_roster_json_out(&sess.roster, out_json) }
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
                    SessionEvent::AppData(data) => serde_json::json!({
                        "event": "data",
                        "data_b64": b64url_encode(&data),
                    }),
                    SessionEvent::Rekeyed { direction } => serde_json::json!({
                        "event": "rekeyed",
                        "direction": format!("{direction:?}"),
                    }),
                    SessionEvent::GrantUpdated(g) => serde_json::json!({
                        "event": "grant_updated",
                        "grant": g,
                    }),
                    SessionEvent::RevocationUpdated { issuer, seq } => {
                        if let Err(e) = sess.sync_roster_from_store() {
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
                    SessionEvent::Closed { code, reason } => serde_json::json!({
                        "event": "closed",
                        "code": code,
                        "reason": reason,
                    }),
                };
                unsafe { write_out_cstring(out_event_json, &val.to_string()) }
            }
            Ok(Ok(None)) => TENDRIL_EOF,
            Ok(Err(e)) => {
                match sess.sync_roster_from_store() {
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
                set_last_error(format!(
                    "invalid transport_config_json: {:?} at line {} column {}",
                    e.classify(),
                    e.line(),
                    e.column()
                ));
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
        let mut guard = ep
            .transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = parsed;
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
            Some(other) => {
                set_last_error(format!("invalid relay ticket role '{other}'"));
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
        let secrets: Vec<[u8; 32]> = {
            let roster = ep
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let roster_snapshot = {
            ep.roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };

        let v2_pinned = match pinned_opt.filter(|s| !s.is_empty()) {
            Some(raw) => {
                let pin_in: FfiPinnedHostInput = match serde_json::from_str(raw) {
                    Ok(v) => v,
                    Err(e) => {
                        set_last_error(format!(
                            "invalid pinned_host_json_opt: {:?} at line {} column {}",
                            e.classify(),
                            e.line(),
                            e.column()
                        ));
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
            let pair_res = if let Some(ref store) = ep.store {
                drive_v2_pake_pair_initiator_with_store(
                    stream.as_mut(),
                    &ep.identity,
                    device_name,
                    device_kind,
                    code_s.to_owned(),
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
                    &ep.identity,
                    device_name,
                    device_kind,
                    code_s.to_owned(),
                    v2_pinned,
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
            }
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
                    if ep.store.is_some() {
                        if let Err(e) = ep.sync_roster_from_store() {
                            set_last_error(e);
                            return TENDRIL_ERR_INTERNAL;
                        }
                    } else {
                        let mut roster = ep
                            .roster
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Err(e) = roster.apply_v2_pair_initiator_outcome(
                            &pair_res.outcome,
                            h_id.clone(),
                            Vec::new(),
                        ) {
                            set_last_error(e.to_string());
                            return TENDRIL_ERR_PROTOCOL;
                        }
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

        match res {
            Ok(pair_res) => match pair_res.outcome {
                V2PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => {
                    if let Err(e) = ep.sync_roster_from_store() {
                        set_last_error(e);
                        return TENDRIL_ERR_INTERNAL;
                    }
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

/// Opens an authenticated Wire v2 (`0x02`) pseudonymous session toward `target_host_id` via `endpoint`.
///
/// Honors configured `RelayClientAuth`, `P2pOptions`, and `WakeProvider` (`wake_and_connect_v2_session`).
///
/// # Safety
/// `ep`, `endpoint`, and `target_host_id` must be valid non-null pointers; `relay_host_opt` and
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
        let Ok(ep_s) = (unsafe { cstr_to_str(endpoint, "endpoint") }) else {
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
        let grant: Option<Grant> = match grant_opt {
            Some(g) if !g.is_empty() => match serde_json::from_str(g) {
                Ok(parsed) => Some(parsed),
                Err(e) => {
                    set_last_error(format!("invalid grant_json_opt: {e}"));
                    return ptr::null_mut();
                }
            },
            _ => None,
        };

        let ep = unsafe { &*ep };
        let cfg = ep.snapshot_transport_cfg();
        let v2_secret = if is_v2_relay_endpoint(ep_s) {
            let roster = ep
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match lookup_v2_mailbox_secret_for_target(&roster, target_s) {
                Ok(s) => Some(s),
                Err((_, msg)) => {
                    set_last_error(msg);
                    return ptr::null_mut();
                }
            }
        } else {
            None
        };

        let res: Result<V2SessionDriver, String> = ep.rt.block_on(async {
            let stream = if let Some(ref wake_cfg) = cfg.wake {
                let dialer = build_dialer_with_options(ep_s, relay_host_s, &cfg, v2_secret)
                    .await
                    .map_err(|e| e.to_string())?;
                let http_wake = Arc::new(
                    HttpWakeProvider::new()
                        .with_cooldown_secs(0)
                        .with_timeout(Duration::from_millis(wake_cfg.timeout_ms)),
                );
                let wake_opts = WakeDialOptions::new(
                    http_wake,
                    wake_cfg.target.clone(),
                    wake_cfg.secret.clone(),
                )
                .with_pre_wake(wake_cfg.pre_wake)
                .with_retry_delay(Duration::from_millis(wake_cfg.retry_delay_ms))
                .with_max_attempts(wake_cfg.max_attempts)
                .with_wake_timeout(Duration::from_millis(wake_cfg.timeout_ms));
                wake_and_dial_v2(&*dialer, ep_s, &wake_opts, now_unix())
                    .await
                    .map(|(stream, _)| stream)
                    .map_err(|e| e.to_string())?
            } else {
                dial_endpoint_v2_with_options(ep_s, relay_host_s, &cfg, v2_secret)
                    .await
                    .map_err(|e| e.to_string())?
            };
            if let Some(ref store) = ep.store {
                V2SessionDriver::connect_with_store(
                    stream,
                    &ep.identity,
                    target_s,
                    grant,
                    store,
                    &ep.store_lock,
                    now_unix(),
                )
                .await
                .map_err(|e| e.to_string())
            } else {
                V2SessionDriver::connect_locked(
                    stream,
                    &ep.identity,
                    target_s,
                    grant,
                    &ep.roster,
                    now_unix(),
                )
                .await
                .map_err(|e| e.to_string())
            }
        });

        match res {
            Ok(driver) => {
                if let Err(e) = ep.sync_roster_from_store() {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                Box::into_raw(Box::new(TendrilSession {
                    rt: Arc::clone(&ep.rt),
                    store: ep.store.clone(),
                    store_lock: Arc::clone(&ep.store_lock),
                    roster: Arc::clone(&ep.roster),
                    session: SessionBackend::V2(driver.into_concurrent()),
                }))
            }
            Err(e) => {
                match ep.sync_roster_from_store() {
                    Ok(()) => set_last_error(e),
                    Err(pe) => set_last_error(format!("{e} (roster sync error: {pe})")),
                }
                ptr::null_mut()
            }
        }
    })
}

/// Accepts and authenticates the next inbound Wire v2 (`0x02`) session stream within `timeout_ms`.
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
            let (stream, guard) = match ep.router.recv_v2_session(wait).await {
                Ok(Some(pair)) => pair,
                Ok(None) => return Err("listener closed".to_owned()),
                Err(()) => return Err("timed out accepting v2 session".to_owned()),
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
            ep.sync_roster_from_store()
        } else {
            Ok(())
        };
        match res {
            Ok(driver) => {
                if let Err(e) = synced {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                Box::into_raw(Box::new(TendrilSession {
                    rt: Arc::clone(&ep.rt),
                    store: ep.store.clone(),
                    store_lock: Arc::clone(&ep.store_lock),
                    roster: Arc::clone(&ep.roster),
                    session: SessionBackend::V2(driver.into_concurrent()),
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
