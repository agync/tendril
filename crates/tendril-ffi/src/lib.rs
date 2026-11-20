//! Callback-free polled C ABI over `tendril-core` and `tendril-runtime`.
#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tendril_core::crypto::{
    b64url_decode_array, b64url_encode, compute_code_mac, device_id, fingerprint_device,
    fingerprint_host, pairing_sas, random_bytes,
};
use tendril_core::grants::{Grant, RevocationList, authorize_grant};
use tendril_core::identity::{EndpointIdentity, RotationRecord, verify_rotation_chain};
use tendril_core::pairing::{PairOutcome, PairingCodeKind, PairingConfig, PairingManager};
use tendril_core::roster::Roster;
use tendril_runtime::{
    ConcurrentSession, DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT, DirectListener,
    InboundRouter, PathListener, RelayListener, SessionDriver, SessionEvent, StateStore,
    deserialize_identity_json, dial_endpoint, drive_pair_initiator,
    drive_pair_responder_with_options, pairing_path_kind_for_provider, serialize_identity_json,
};
#[cfg(feature = "p2p-iroh")]
use tendril_runtime::{P2pListener, parse_p2p_relay_mode};
use tokio::runtime::Runtime;
use tokio::time::timeout;
use zeroize::Zeroize;

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

fn persist_store_roster(
    store: Option<&Arc<StateStore>>,
    roster: &Arc<StdMutex<Roster>>,
) -> Result<(), String> {
    if let Some(s) = store {
        let guard = roster.lock().expect("roster mutex poisoned");
        s.save_roster(&guard).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Opaque endpoint handle owning a Tokio runtime, identity, roster, and background listeners.
pub struct TendrilEndpoint {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    identity: EndpointIdentity,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: StdMutex<PairingManager>,
    router: InboundRouter,
}

impl TendrilEndpoint {
    fn persist_roster(&self, roster: &Roster) -> Result<(), String> {
        if let Some(store) = &self.store {
            store.save_roster(roster).map_err(|e| e.to_string())?;
        }
        Ok(())
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
    Box::into_raw(Box::new(TendrilEndpoint {
        rt,
        store,
        identity,
        roster: Arc::new(StdMutex::new(roster)),
        pair_mgr: StdMutex::new(PairingManager::new(PairingConfig::default())),
        router: InboundRouter::new(),
    }))
}

unsafe fn write_roster_json_out(roster_arc: &StdMutex<Roster>, out_json: *mut *mut c_char) -> i32 {
    let json = {
        let guard = roster_arc.lock().expect("roster mutex poisoned");
        match serde_json::to_string(&*guard) {
            Ok(j) => j,
            Err(e) => {
                set_last_error(format!("failed to serialize roster: {e}"));
                return TENDRIL_ERR_INTERNAL;
            }
        }
    };
    unsafe { write_out_cstring(out_json, &json) }
}

/// Opaque authenticated session handle sharing the endpoint's Tokio runtime and roster state.
pub struct TendrilSession {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    roster: Arc<StdMutex<Roster>>,
    session: ConcurrentSession,
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

        let Ok(psig) = b64url_decode_array::<32>(psig_s) else {
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
        let Ok(csig) = b64url_decode_array::<32>(csig_s) else {
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
        let mut key_map: HashMap<String, [u8; 32]> = HashMap::with_capacity(key_map_raw.len());
        for (id, b64) in key_map_raw {
            let Ok(k) = b64url_decode_array::<32>(&b64) else {
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
            |issuer| key_map.get(issuer).copied(),
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
            "signing_pub": b64url_encode(ep.identity.signing_key().public_bytes()),
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
        let signing_key = ep.identity.signing_key().signing_key();
        match ep.rt.block_on(RelayListener::bind(
            url,
            exp_host,
            signing_key,
            DEFAULT_WRITE_TIMEOUT,
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
            let mode = match parse_p2p_relay_mode(mode_opt) {
                Ok(m) => m,
                Err(e) => {
                    set_last_error(e.to_string());
                    return TENDRIL_ERR_INVALID_ARG;
                }
            };
            let seed = ep.identity.derive_p2p_identity_seed();
            match ep.rt.block_on(P2pListener::bind_with_secret(mode, seed)) {
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
        let res = ep.rt.block_on(async {
            let mut stream = dial_endpoint(endpoint_s, relay_host_s)
                .await
                .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))?;
            let pair_res = drive_pair_initiator(
                stream.as_mut(),
                &ep.identity,
                name_s.unwrap_or("ffi-device").to_owned(),
                kind_s.unwrap_or("ffi").to_owned(),
                code_s.to_owned(),
                None,
            )
            .await
            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()));
            let _ = stream.close().await;
            pair_res
        });

        match res {
            Ok(pair_res) => match pair_res.outcome {
                PairOutcome::InitiatorPending {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    pairing_sas,
                    host_pin_verified,
                } => {
                    let mut roster = ep.roster.lock().expect("roster mutex poisoned");
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
                    if let Err(e) = pin_res {
                        set_last_error(e.to_string());
                        return TENDRIL_ERR_PROTOCOL;
                    }
                    if let Err(e) = ep.persist_roster(&roster) {
                        set_last_error(e);
                        return TENDRIL_ERR_INTERNAL;
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
                PairOutcome::ResponderPending { .. } => {
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
        let res = ep.rt.block_on(async {
            let (mut stream, guard) = match ep.router.recv_pair(wait).await {
                Ok(Some(pair)) => pair,
                Ok(None) => return Err((TENDRIL_ERR_CLOSED, "listener closed".to_owned())),
                Err(()) => {
                    return Err((TENDRIL_WOULD_BLOCK, "timed out accepting pair".to_owned()));
                }
            };

            let path_kind = pairing_path_kind_for_provider(stream.provider_id());
            drive_pair_responder_with_options(
                stream.as_mut(),
                &ep.identity,
                &ep.pair_mgr,
                &ep.roster,
                path_kind,
                now_unix(),
                Some(ep.router.rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .map_err(|e| (TENDRIL_ERR_PROTOCOL, e.to_string()))
        });

        match res {
            Ok(pair_res) => match pair_res.outcome {
                PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => {
                    let roster = ep.roster.lock().expect("roster mutex poisoned");
                    if let Err(e) = ep.persist_roster(&roster) {
                        set_last_error(e);
                        return TENDRIL_ERR_INTERNAL;
                    }
                    let out = serde_json::json!({
                        "device_id": device_id,
                        "sas": pairing_sas,
                        "name": name,
                        "kind": kind,
                    });
                    unsafe { write_out_cstring(out_json, &out.to_string()) }
                }
                PairOutcome::Rejected { error } => {
                    set_last_error(error);
                    TENDRIL_ERR_PROTOCOL
                }
                PairOutcome::InitiatorPending { .. } => {
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

/// Promotes a pending paired peer to `Active` (`pair.confirm`), optionally asserting SAS match.
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
        let mut roster = ep.roster.lock().expect("roster mutex poisoned");
        if let Err(e) = roster.confirm_peer(peer_s, sas_opt) {
            set_last_error(e.to_string());
            return TENDRIL_ERR_PROTOCOL;
        }
        if let Err(e) = ep.persist_roster(&roster) {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        TENDRIL_OK
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
        let mut roster = ep.roster.lock().expect("roster mutex poisoned");
        let now = now_unix();
        let grant = match roster.mint_grant(
            &ep.identity,
            peer_s,
            caps,
            now,
            now.saturating_add(ttl_secs),
            nonce,
        ) {
            Ok(g) => g,
            Err(e) => {
                set_last_error(e.to_string());
                return TENDRIL_ERR_PROTOCOL;
            }
        };
        if let Err(e) = ep.persist_roster(&roster) {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        let json = serde_json::to_string(&grant).expect("serialize grant");
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
        let mut roster = ep.roster.lock().expect("roster mutex poisoned");
        if let Err(e) = roster.revoke_peer(peer_s) {
            set_last_error(e.to_string());
            return TENDRIL_ERR_NOT_FOUND;
        }
        if let Err(e) = ep.persist_roster(&roster) {
            set_last_error(e);
            return TENDRIL_ERR_INTERNAL;
        }
        TENDRIL_OK
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
        let res = ep.rt.block_on(async {
            let stream = dial_endpoint(ep_s, relay_host_s)
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
                if let Err(e) = persist_store_roster(ep.store.as_ref(), &ep.roster) {
                    set_last_error(e);
                    return ptr::null_mut();
                }
                Box::into_raw(Box::new(TendrilSession {
                    rt: Arc::clone(&ep.rt),
                    store: ep.store.clone(),
                    roster: Arc::clone(&ep.roster),
                    session: driver.into_concurrent(),
                }))
            }
            Err(e) => {
                if let Err(pe) = persist_store_roster(ep.store.as_ref(), &ep.roster) {
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
        let res = ep.rt.block_on(async {
            let (stream, guard) = match ep.router.recv_session(wait).await {
                Ok(Some(pair)) => pair,
                Ok(None) => return Err("listener closed".to_owned()),
                Err(()) => return Err("timed out accepting session".to_owned()),
            };

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

        match res {
            Ok(driver) => Box::into_raw(Box::new(TendrilSession {
                rt: Arc::clone(&ep.rt),
                store: ep.store.clone(),
                roster: Arc::clone(&ep.roster),
                session: driver.into_concurrent(),
            })),
            Err(e) => {
                set_last_error(e);
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
                        if let Err(e) = persist_store_roster(sess.store.as_ref(), &sess.roster) {
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
                if let Err(pe) = persist_store_roster(sess.store.as_ref(), &sess.roster) {
                    set_last_error(format!("{e} (roster persist error: {pe})"));
                } else {
                    set_last_error(e.to_string());
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
        let roster = sess.roster.lock().expect("roster mutex poisoned");
        let (res, _audit) = sess.session.authorize(cap_s, now_unix(), &roster);
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
