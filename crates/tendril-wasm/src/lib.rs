//! Sans-I/O WebAssembly bindings exposing `tendril-core` primitives and state machines,
//! plus opt-in `p2p-iroh` browser WebSocket relay transport.

pub mod group;
#[cfg(feature = "p2p-iroh")]
pub mod p2p;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, SigningKeypair,
    StaticKeypair, b64url_decode, b64url_decode_array, b64url_encode,
    compute_code_mac as core_compute_code_mac, device_id as core_device_id,
    fingerprint_device as core_fingerprint_device, fingerprint_host as core_fingerprint_host,
    is_valid_ed25519_public_key, pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::grants::{Grant, RevocationList, authorize_grant};
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, verify_rotation_chain,
};
use tendril_core::pairing::{
    PairAction, PairOutcome, PairingCodeKind, PairingInitiator, PairingUri, PersistOpts,
    PersistPlan, PinnedHost, RouteCheck, RoutePolicy, VerifiedRouteStatement,
    classify_endpoint_hint, is_v2_relay_hint, mint_enrollment_token as core_mint_enrollment_token,
    persistable_routes,
};
use tendril_core::policy::{
    CandidateEndpoint, PathPlanner, PathPolicyConfig, PlannerAction, ProviderId, sort_key,
};
use tendril_core::relay_auth::{
    MAX_RELAY_FRAME_LEN, MAX_STANDBY_PER_MAILBOX, RELAY_HEALTH_PATH, RELAY_PATH, RELAY_V2_PATH,
    RelayAuthRole, RelayTicket, compute_relay_auth_hmac_b64 as core_compute_relay_auth_hmac_b64,
    decode_init_frame as core_decode_init_frame, mint_relay_ticket as core_mint_relay_ticket,
    origin_allowed, validate_relay_auth_secret as core_validate_relay_auth_secret,
    verify_relay_accept as core_verify_relay_accept,
    verify_relay_auth_hmac as core_verify_relay_auth_hmac,
    verify_relay_register as core_verify_relay_register,
    verify_relay_ticket as core_verify_relay_ticket,
};
use tendril_core::roster::{
    OperatorEndpoint, PairMergeOutcome, PeerState, PinSnapshot, Roster, RouteSetOutcome,
    RouteSource, StoredRoute,
};
use tendril_core::routes::RouteSet;
use tendril_core::session::{
    RouteExpectation, SessionAction, SessionMachine, check_peer_allows_wire_v1,
};
use tendril_core::v2::{
    PaddingPolicy, PakeArgon2Params, RELAY_V2_EPOCH_SECS, V2PairAction, V2PairOutcome,
    V2PakePairInitiator, V2PinnedHost, V2SessionAction, V2SessionInitiator, VerifiedRelayHost,
    canonical_relay_host as core_canonical_relay_host, derive_epoch_mailbox, epoch_for_unix,
    epoch_within_skew, sign_v2_relay_dial, verify_v2_relay_accept as core_verify_v2_relay_accept,
    verify_v2_relay_register as core_verify_v2_relay_register,
};
use tendril_core::wire::WIRE_VERSION_V2;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize as _, Zeroizing};

use group::{MAX_PENDING_RENDEZVOUS, WasmGroupBook};
use tendril_core::group::GroupRendezvousFrame;

/// Generic code of an error that is not a [`CoreError`](tendril_core::error::CoreError).
const GENERIC_ERROR_CODE: &str = "error";

/// An error crossing the JS boundary: a stable machine `code` plus the human message.
///
/// JS receives an `Error` whose `message` is the message and whose `code` property is the
/// code: the snake-case name of the [`CoreError`](tendril_core::error::CoreError) variant, or
/// [`GENERIC_ERROR_CODE`] for argument and state errors of this crate. Callers rank errors by
/// `code`, never by message text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WasmError {
    code: &'static str,
    message: String,
}

impl WasmError {
    fn generic(message: impl Into<String>) -> Self {
        Self {
            code: GENERIC_ERROR_CODE,
            message: message.into(),
        }
    }

    /// A core error behind a context prefix; the code stays the core variant's.
    fn core_in(context: impl fmt::Display, err: &tendril_core::error::CoreError) -> Self {
        Self {
            code: core_error_code(err),
            message: format!("{context}: {err}"),
        }
    }
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<tendril_core::error::CoreError> for WasmError {
    fn from(err: tendril_core::error::CoreError) -> Self {
        Self {
            code: core_error_code(&err),
            message: err.to_string(),
        }
    }
}

impl From<String> for WasmError {
    fn from(message: String) -> Self {
        Self::generic(message)
    }
}

impl From<&str> for WasmError {
    fn from(message: &str) -> Self {
        Self::generic(message)
    }
}

impl From<serde_json::Error> for WasmError {
    fn from(err: serde_json::Error) -> Self {
        Self::generic(err.to_string())
    }
}

impl From<std::str::Utf8Error> for WasmError {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::generic(err.to_string())
    }
}

/// The stable code of a core error: the snake-case variant name. The match is exhaustive, so a
/// new variant cannot ship without a code.
fn core_error_code(err: &tendril_core::error::CoreError) -> &'static str {
    use tendril_core::error::CoreError;
    match err {
        CoreError::InvalidPreambleLength { .. } => "invalid_preamble_length",
        CoreError::BadPreambleMagic => "bad_preamble_magic",
        CoreError::UnsupportedVersion(_) => "unsupported_version",
        CoreError::UnknownIntent(_) => "unknown_intent",
        CoreError::NonZeroReserved(_) => "non_zero_reserved",
        CoreError::InvalidPreambleFlags { .. } => "invalid_preamble_flags",
        CoreError::VersionDowngrade { .. } => "version_downgrade",
        CoreError::PairingAuthFailed => "pairing_auth_failed",
        CoreError::FrameTooLarge { .. } => "frame_too_large",
        CoreError::TruncatedFrame { .. } => "truncated_frame",
        CoreError::EmptyInnerFrame => "empty_inner_frame",
        CoreError::UnknownInnerFrameType(_) => "unknown_inner_frame_type",
        CoreError::InvalidInnerFramePayload(_) => "invalid_inner_frame_payload",
        CoreError::InvalidLength { .. } => "invalid_length",
        CoreError::Base64Decode(_) => "base64_decode",
        CoreError::InvalidSignature => "invalid_signature",
        CoreError::Argon2(_) => "argon2",
        CoreError::Noise(_) => "noise",
        CoreError::InvalidTimestamp(_) => "invalid_timestamp",
        CoreError::RotationEmptyChain => "rotation_empty_chain",
        CoreError::RotationRootMismatch => "rotation_root_mismatch",
        CoreError::RotationNonMonotonicSeq { .. } => "rotation_non_monotonic_seq",
        CoreError::RotationNonContiguous => "rotation_non_contiguous",
        CoreError::RotationForkDetected { .. } => "rotation_fork_detected",
        CoreError::RotationEndpointMismatch => "rotation_endpoint_mismatch",
        CoreError::HostKeyUnverified => "host_key_unverified",
        CoreError::InvalidCapability(_) => "invalid_capability",
        CoreError::CanonicalJson(_) => "canonical_json",
        CoreError::GrantDenied(_) => "grant_denied",
        CoreError::DelegationDenied(_) => "delegation_denied",
        CoreError::Rng(_) => "rng",
        CoreError::Json(_) => "json",
        CoreError::ProtocolViolation(_) => "protocol_violation",
        CoreError::PeerNotFound(_) => "peer_not_found",
        CoreError::PeerPending(_) => "peer_pending",
        CoreError::PeerRevoked(_) => "peer_revoked",
        CoreError::IncompletePin(_) => "incomplete_pin",
        CoreError::PairingCodeInvalid => "pairing_code_invalid",
        CoreError::PairingCodeExpired => "pairing_code_expired",
        CoreError::PairingCodeBurned => "pairing_code_burned",
        CoreError::PairingPathDisallowed(_) => "pairing_path_disallowed",
        CoreError::InvalidPairingUri(_) => "invalid_pairing_uri",
        CoreError::CrlUnsupportedVersion(_) => "crl_unsupported_version",
        CoreError::CrlIssuerMismatch { .. } => "crl_issuer_mismatch",
        CoreError::CrlStaleSeq { .. } => "crl_stale_seq",
        CoreError::SessionClosed { .. } => "session_closed",
        CoreError::EnrollmentTokenInvalid(_) => "enrollment_token_invalid",
        CoreError::EnrollmentTokenExpired => "enrollment_token_expired",
        CoreError::EnrollmentTokenReplayed => "enrollment_token_replayed",
        CoreError::EnrollmentAnchorUntrusted(_) => "enrollment_anchor_untrusted",
        CoreError::EnrollmentBurnLogFull => "enrollment_burn_log_full",
        CoreError::NotReady(_) => "not_ready",
        CoreError::BufferOverflow { .. } => "buffer_overflow",
        CoreError::InvalidGroupManifest(_) => "invalid_group_manifest",
        CoreError::InvalidGroupCapabilityScope(_) => "invalid_group_capability_scope",
        CoreError::GroupSeqRollback { .. } => "group_seq_rollback",
        CoreError::GroupManifestFork { .. } => "group_manifest_fork",
        CoreError::GroupMemberRevoked(_) => "group_member_revoked",
        CoreError::GroupNotFound(_) => "group_not_found",
        CoreError::GroupUnauthorized(_) => "group_unauthorized",
        CoreError::GroupManifestTooLarge { .. } => "group_manifest_too_large",
        CoreError::GroupWireDowngrade { .. } => "group_wire_downgrade",
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = Error)]
    type JsCodedError;

    #[wasm_bindgen(constructor, js_class = "Error")]
    fn new_coded_error(message: &str) -> JsCodedError;

    #[wasm_bindgen(method, setter = code, js_class = "Error")]
    fn set_code(this: &JsCodedError, code: &str);
}

fn to_js_err(err: impl Into<WasmError>) -> JsValue {
    let err = err.into();
    let js = JsCodedError::new_coded_error(&err.message);
    js.set_code(err.code);
    js.into()
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = Uint8Array)]
    type JsUint8Array;

    #[wasm_bindgen(constructor, js_class = "Uint8Array")]
    fn new_with_length(len: u32) -> JsUint8Array;

    #[wasm_bindgen(method, js_class = "Uint8Array", js_name = set)]
    fn set_bytes(this: &JsUint8Array, src: &[u8]);
}

fn copy_zeroizing_bytes_to_js(bytes: Zeroizing<Vec<u8>>) -> Result<JsValue, JsValue> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| to_js_err("serialized payload exceeds u32 length"))?;
    let arr = JsUint8Array::new_with_length(len);
    arr.set_bytes(&bytes);
    Ok(arr.into())
}

fn as_32(bytes: &[u8], name: &str) -> Result<[u8; 32], WasmError> {
    bytes
        .try_into()
        .map_err(|_| WasmError::from(format!("{name} must be exactly 32 bytes")))
}

fn parse_signing_pin_b64(encoded: &str, name: &str) -> Result<SigningKeyPin, WasmError> {
    let bytes = b64url_decode(encoded)
        .map_err(|e| WasmError::core_in(format_args!("invalid {name}"), &e))?;
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        HybridSigningPublicKey::from_bytes(&bytes)
            .map(SigningKeyPin::Full)
            .map_err(|e| WasmError::core_in(format_args!("invalid {name}"), &e))
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let hash: [u8; HYBRID_SIGNING_HASH_LEN] = bytes
            .try_into()
            .map_err(|_| WasmError::from(format!("invalid {name} hash length")))?;
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(WasmError::from(format!(
            "{name} must be {HYBRID_SIGNING_PUB_LEN} or {HYBRID_SIGNING_HASH_LEN} bytes"
        )))
    }
}

fn f64_to_u64(v: f64, name: &str) -> Result<u64, WasmError> {
    if !(0.0..=9_007_199_254_740_991.0).contains(&v) || v.fract() != 0.0 {
        return Err(WasmError::from(format!(
            "{name} must be a non-negative safe integer"
        )));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(v as u64)
}

fn f64_to_u16(v: f64, name: &str) -> Result<u16, WasmError> {
    let n = f64_to_u64(v, name)?;
    u16::try_from(n).map_err(|_| WasmError::from(format!("{name} must be within 0..=65535")))
}

#[allow(clippy::cast_precision_loss)]
fn u64_to_f64(v: u64) -> Result<f64, WasmError> {
    if v > 9_007_199_254_740_991 {
        return Err("sequence exceeds JavaScript safe integer range"
            .to_owned()
            .into());
    }
    Ok(v as f64)
}

fn manifest_wire_json(manifest: &tendril_core::group::GroupManifest) -> Result<String, WasmError> {
    let bytes = manifest.to_wire_bytes().map_err(WasmError::from)?;
    String::from_utf8(bytes).map_err(|e| WasmError::from(e.to_string()))
}

fn collect_session_writes(actions: Vec<SessionAction>) -> Vec<u8> {
    let mut out = Vec::new();
    for action in actions {
        if let SessionAction::WriteBytes(chunk) = action {
            out.extend_from_slice(&chunk);
        }
    }
    out
}

#[wasm_bindgen]
pub fn device_id(static_pub: &[u8]) -> Result<String, JsValue> {
    let key = as_32(static_pub, "static_pub").map_err(to_js_err)?;
    Ok(core_device_id(&key))
}

#[wasm_bindgen]
pub fn fingerprint_host(static_pub: &[u8]) -> Result<String, JsValue> {
    let key = as_32(static_pub, "static_pub").map_err(to_js_err)?;
    Ok(core_fingerprint_host(&key))
}

#[wasm_bindgen]
pub fn fingerprint_device(static_pub: &[u8]) -> Result<String, JsValue> {
    let key = as_32(static_pub, "static_pub").map_err(to_js_err)?;
    Ok(core_fingerprint_device(&key))
}

#[wasm_bindgen]
pub fn pairing_sas(handshake_hash: &[u8]) -> Result<String, JsValue> {
    let hh = as_32(handshake_hash, "handshake_hash").map_err(to_js_err)?;
    Ok(core_pairing_sas(&hh))
}

#[wasm_bindgen]
pub fn compute_code_mac(code: &str, handshake_hash: &[u8]) -> Result<Vec<u8>, JsValue> {
    let hh = as_32(handshake_hash, "handshake_hash").map_err(to_js_err)?;
    let mac = core_compute_code_mac(code, &hh).map_err(to_js_err)?;
    Ok(mac.to_vec())
}

#[wasm_bindgen]
pub fn compute_code_mac_bytes(
    code_utf8: &mut [u8],
    handshake_hash: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mac_res = match core::str::from_utf8(code_utf8) {
        Ok(code) => as_32(handshake_hash, "handshake_hash")
            .and_then(|hh| core_compute_code_mac(code, &hh).map_err(WasmError::from))
            .map(|mac| mac.to_vec())
            .map_err(to_js_err),
        Err(err) => Err(to_js_err(format!("invalid UTF-8 pairing code: {err}"))),
    };
    code_utf8.zeroize();
    mac_res
}

#[wasm_bindgen]
pub fn compute_relay_auth_hmac_b64(
    secret: &mut [u8],
    op: &str,
    relay_host: &str,
    nonce: &[u8],
    pub_or_target: &[u8],
) -> Result<String, JsValue> {
    let res = as_32(nonce, "nonce")
        .and_then(|nonce_arr| {
            as_32(pub_or_target, "pub_or_target").and_then(|target_arr| {
                core_compute_relay_auth_hmac_b64(secret, op, relay_host, &nonce_arr, &target_arr)
                    .map_err(WasmError::from)
            })
        })
        .map_err(to_js_err);
    secret.zeroize();
    res
}

fn derive_v2_relay_dial_inner(
    mailbox_secret: &[u8; 32],
    relay_host: &str,
    unix_secs: f64,
    dial_nonce: &[u8],
    conn_id: &[u8],
) -> Result<String, WasmError> {
    let host = VerifiedRelayHost::new(relay_host).map_err(WasmError::from)?;
    let unix = f64_to_u64(unix_secs, "unix_secs")?;
    let nonce = as_32(dial_nonce, "dial_nonce")?;
    let cid: [u8; 16] = conn_id
        .try_into()
        .map_err(|_| "conn_id must be exactly 16 bytes".to_owned())?;
    let epoch = epoch_for_unix(unix);
    let mailbox = derive_epoch_mailbox(mailbox_secret, epoch);
    let dial_token =
        sign_v2_relay_dial(&mailbox, host.as_str(), &nonce, &cid).map_err(WasmError::from)?;
    let epoch_f64 = u64_to_f64(epoch)?;
    Ok(json!({
        "mailbox_id": b64url_encode(&mailbox.mailbox_id),
        "epoch": epoch_f64,
        "dial_token": b64url_encode(&dial_token),
    })
    .to_string())
}

#[wasm_bindgen]
pub fn derive_v2_relay_dial_json(
    mailbox_secret: &[u8],
    relay_host: &str,
    unix_secs: f64,
    dial_nonce: &[u8],
    conn_id: &[u8],
) -> Result<String, JsValue> {
    let secret = Zeroizing::new(as_32(mailbox_secret, "mailbox_secret").map_err(to_js_err)?);
    derive_v2_relay_dial_inner(&secret, relay_host, unix_secs, dial_nonce, conn_id)
        .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn v2_epoch_within_skew(server_epoch: f64, claimed_epoch: f64) -> Result<bool, JsValue> {
    let srv = f64_to_u64(server_epoch, "server_epoch").map_err(to_js_err)?;
    let claimed = f64_to_u64(claimed_epoch, "claimed_epoch").map_err(to_js_err)?;
    Ok(epoch_within_skew(srv, claimed))
}

#[wasm_bindgen]
pub fn canonical_relay_host(host: &str) -> Result<String, JsValue> {
    core_canonical_relay_host(host).map_err(to_js_err)
}

fn relay_protocol_constants_json_inner() -> String {
    json!({
        "relay_path": RELAY_PATH,
        "relay_v2_path": RELAY_V2_PATH,
        "health_path": RELAY_HEALTH_PATH,
        "max_standby_per_mailbox": MAX_STANDBY_PER_MAILBOX,
        "max_relay_frame_len": MAX_RELAY_FRAME_LEN,
        "v2_epoch_secs": RELAY_V2_EPOCH_SECS,
    })
    .to_string()
}

#[wasm_bindgen]
pub fn relay_protocol_constants_json() -> String {
    relay_protocol_constants_json_inner()
}

fn v2_epoch_for_unix_inner(unix_secs: f64) -> Result<f64, WasmError> {
    let unix = f64_to_u64(unix_secs, "unix_secs")?;
    u64_to_f64(epoch_for_unix(unix)).map_err(|_| WasmError::from("epoch exceeds safe integer"))
}

#[wasm_bindgen]
pub fn v2_epoch_for_unix(unix_secs: f64) -> Result<f64, JsValue> {
    v2_epoch_for_unix_inner(unix_secs).map_err(to_js_err)
}

fn validate_relay_auth_secret_bytes_inner(secret: &mut [u8]) -> Result<(), WasmError> {
    let res = core_validate_relay_auth_secret(secret).map_err(WasmError::from);
    secret.zeroize();
    res
}

#[wasm_bindgen]
pub fn validate_relay_auth_secret_bytes(secret: &mut [u8]) -> Result<(), JsValue> {
    validate_relay_auth_secret_bytes_inner(secret).map_err(to_js_err)
}

fn decode_b64url_exact_inner(raw: &str, expected_len: usize) -> Result<Vec<u8>, WasmError> {
    let bytes = b64url_decode(raw).map_err(WasmError::from)?;
    if bytes.len() != expected_len {
        return Err(WasmError::from(
            tendril_core::error::CoreError::InvalidLength {
                expected: expected_len,
                actual: bytes.len(),
            },
        ));
    }
    Ok(bytes)
}

#[wasm_bindgen]
pub fn decode_b64url_exact(raw: &str, expected_len: usize) -> Result<Vec<u8>, JsValue> {
    decode_b64url_exact_inner(raw, expected_len).map_err(to_js_err)
}

fn validate_ed25519_pub_b64_inner(raw: &str) -> Result<Vec<u8>, WasmError> {
    let bytes = b64url_decode_array::<32>(raw).map_err(WasmError::from)?;
    if !is_valid_ed25519_public_key(&bytes) {
        return Err(WasmError::from(
            tendril_core::error::CoreError::InvalidSignature,
        ));
    }
    Ok(bytes.to_vec())
}

#[wasm_bindgen]
pub fn validate_ed25519_pub_b64(raw: &str) -> Result<Vec<u8>, JsValue> {
    validate_ed25519_pub_b64_inner(raw).map_err(to_js_err)
}

fn decode_relay_init_frame_b64_inner(
    init_frame: Option<&str>,
) -> Result<Option<Vec<u8>>, WasmError> {
    core_decode_init_frame(init_frame).map_err(|code| WasmError {
        code,
        message: code.to_owned(),
    })
}

#[wasm_bindgen]
pub fn decode_relay_init_frame_b64(init_frame: &str) -> Result<Vec<u8>, JsValue> {
    decode_relay_init_frame_b64_inner(Some(init_frame))
        .map(|opt| opt.unwrap_or_default())
        .map_err(to_js_err)
}

fn verify_relay_register_v1_inner(
    pub_b64: &str,
    sig_b64: &str,
    relay_host: &str,
    nonce: &[u8],
) -> Result<Vec<u8>, WasmError> {
    let nonce_arr = as_32(nonce, "nonce")?;
    core_verify_relay_register(pub_b64, sig_b64, relay_host, &nonce_arr)
        .map(|pk| pk.to_vec())
        .map_err(WasmError::from)
}

#[wasm_bindgen]
pub fn verify_relay_register_v1(
    pub_b64: &str,
    sig_b64: &str,
    relay_host: &str,
    nonce: &[u8],
) -> Result<Vec<u8>, JsValue> {
    verify_relay_register_v1_inner(pub_b64, sig_b64, relay_host, nonce).map_err(to_js_err)
}

fn verify_relay_accept_v1_inner(
    pub_b64: &str,
    conn_id_b64: &str,
    sig_b64: &str,
    relay_host: &str,
    nonce: &[u8],
) -> Result<Vec<u8>, WasmError> {
    let nonce_arr = as_32(nonce, "nonce")?;
    let (pk, cid) = core_verify_relay_accept(pub_b64, conn_id_b64, sig_b64, relay_host, &nonce_arr)
        .map_err(WasmError::from)?;
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&pk);
    out.extend_from_slice(&cid);
    Ok(out)
}

#[wasm_bindgen]
pub fn verify_relay_accept_v1(
    pub_b64: &str,
    conn_id_b64: &str,
    sig_b64: &str,
    relay_host: &str,
    nonce: &[u8],
) -> Result<Vec<u8>, JsValue> {
    verify_relay_accept_v1_inner(pub_b64, conn_id_b64, sig_b64, relay_host, nonce)
        .map_err(to_js_err)
}

fn verify_v2_relay_register_b64_inner(
    mailbox_id_b64: &str,
    epoch: f64,
    relay_host: &str,
    nonce: &[u8],
    sig_b64: &str,
) -> Result<Vec<u8>, WasmError> {
    let ep = f64_to_u64(epoch, "epoch")?;
    let nonce_arr = as_32(nonce, "nonce")?;
    let mailbox_id = b64url_decode_array::<32>(mailbox_id_b64).map_err(WasmError::from)?;
    let sig = b64url_decode_array::<64>(sig_b64).map_err(WasmError::from)?;
    core_verify_v2_relay_register(&mailbox_id, ep, relay_host, &nonce_arr, &sig)
        .map_err(WasmError::from)?;
    Ok(mailbox_id.to_vec())
}

#[wasm_bindgen]
pub fn verify_v2_relay_register_b64(
    mailbox_id_b64: &str,
    epoch: f64,
    relay_host: &str,
    nonce: &[u8],
    sig_b64: &str,
) -> Result<Vec<u8>, JsValue> {
    verify_v2_relay_register_b64_inner(mailbox_id_b64, epoch, relay_host, nonce, sig_b64)
        .map_err(to_js_err)
}

fn verify_v2_relay_accept_b64_inner(
    mailbox_id_b64: &str,
    epoch: f64,
    relay_host: &str,
    nonce: &[u8],
    conn_id_b64: &str,
    sig_b64: &str,
) -> Result<Vec<u8>, WasmError> {
    let ep = f64_to_u64(epoch, "epoch")?;
    let nonce_arr = as_32(nonce, "nonce")?;
    let mailbox_id = b64url_decode_array::<32>(mailbox_id_b64).map_err(WasmError::from)?;
    let conn_id = b64url_decode_array::<16>(conn_id_b64).map_err(WasmError::from)?;
    let sig = b64url_decode_array::<64>(sig_b64).map_err(WasmError::from)?;
    core_verify_v2_relay_accept(&mailbox_id, ep, relay_host, &nonce_arr, &conn_id, &sig)
        .map_err(WasmError::from)?;
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&mailbox_id);
    out.extend_from_slice(&conn_id);
    Ok(out)
}

#[wasm_bindgen]
pub fn verify_v2_relay_accept_b64(
    mailbox_id_b64: &str,
    epoch: f64,
    relay_host: &str,
    nonce: &[u8],
    conn_id_b64: &str,
    sig_b64: &str,
) -> Result<Vec<u8>, JsValue> {
    verify_v2_relay_accept_b64_inner(
        mailbox_id_b64,
        epoch,
        relay_host,
        nonce,
        conn_id_b64,
        sig_b64,
    )
    .map_err(to_js_err)
}

fn verify_relay_auth_hmac_b64_inner(
    secret: &mut [u8],
    op: &str,
    relay_host: &str,
    nonce: &[u8],
    pub_or_target: &[u8],
    candidate_mac_b64: &str,
) -> Result<(), WasmError> {
    let res = as_32(nonce, "nonce").and_then(|nonce_arr| {
        as_32(pub_or_target, "pub_or_target").and_then(|target_arr| {
            core_verify_relay_auth_hmac(
                secret,
                op,
                relay_host,
                &nonce_arr,
                &target_arr,
                candidate_mac_b64,
            )
            .map_err(WasmError::from)
        })
    });
    secret.zeroize();
    res
}

#[wasm_bindgen]
pub fn verify_relay_auth_hmac_b64(
    secret: &mut [u8],
    op: &str,
    relay_host: &str,
    nonce: &[u8],
    pub_or_target: &[u8],
    candidate_mac_b64: &str,
) -> Result<(), JsValue> {
    verify_relay_auth_hmac_b64_inner(
        secret,
        op,
        relay_host,
        nonce,
        pub_or_target,
        candidate_mac_b64,
    )
    .map_err(to_js_err)
}

fn verify_relay_ticket_json_inner(
    ticket_json: &str,
    trusted_issuers_json: &str,
    expected_relay_host: &str,
    required_op: &str,
    target_pub: &[u8],
    now_unix_secs: f64,
) -> Result<Vec<u8>, WasmError> {
    let ticket: RelayTicket = serde_json::from_str(ticket_json)?;
    let issuer_strs: Vec<String> = serde_json::from_str(trusted_issuers_json)
        .map_err(|e| WasmError::from(format!("invalid trusted_issuers_json: {e}")))?;
    let mut trusted_issuers = Vec::with_capacity(issuer_strs.len());
    for raw in &issuer_strs {
        trusted_issuers.push(b64url_decode_array::<32>(raw).map_err(WasmError::from)?);
    }
    let op = match required_op {
        "register" | "accept" => RelayAuthRole::Register,
        "dial" => RelayAuthRole::Dial,
        _ => {
            return Err(WasmError::from(
                "required_op must be register, accept, or dial",
            ));
        }
    };
    let target = as_32(target_pub, "target_pub")?;
    let now = f64_to_u64(now_unix_secs, "now_unix_secs")?;
    let issuer = core_verify_relay_ticket(
        &ticket,
        &trusted_issuers,
        expected_relay_host,
        op,
        &target,
        now,
    )
    .map_err(WasmError::from)?;
    Ok(issuer.to_vec())
}

fn validate_relay_ticket_schema_json_inner(ticket_json: &str) -> Result<(), WasmError> {
    serde_json::from_str::<RelayTicket>(ticket_json)
        .map(|_| ())
        .map_err(WasmError::from)
}

#[wasm_bindgen]
pub fn validate_relay_ticket_schema_json(ticket_json: &str) -> Result<(), JsValue> {
    validate_relay_ticket_schema_json_inner(ticket_json).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn verify_relay_ticket_json(
    ticket_json: &str,
    trusted_issuers_json: &str,
    expected_relay_host: &str,
    required_op: &str,
    target_pub: &[u8],
    now_unix_secs: f64,
) -> Result<Vec<u8>, JsValue> {
    verify_relay_ticket_json_inner(
        ticket_json,
        trusted_issuers_json,
        expected_relay_host,
        required_op,
        target_pub,
        now_unix_secs,
    )
    .map_err(to_js_err)
}

#[wasm_bindgen]
pub fn verify_rotation_chain_json(
    pinned_signing_b64: &str,
    pinned_static_b64: &str,
    pinned_seq: f64,
    chain_json: &str,
    cur_static_b64: &str,
    cur_signing_b64: &str,
) -> Result<f64, JsValue> {
    let p_seq = f64_to_u64(pinned_seq, "pinned_seq").map_err(to_js_err)?;
    let psig = HybridSigningPublicKey::from_b64url(pinned_signing_b64).map_err(to_js_err)?;
    let pstat = b64url_decode_array::<32>(pinned_static_b64).map_err(to_js_err)?;
    let cstat = b64url_decode_array::<32>(cur_static_b64).map_err(to_js_err)?;
    let csig = HybridSigningPublicKey::from_b64url(cur_signing_b64).map_err(to_js_err)?;
    let chain: Vec<RotationRecord> = serde_json::from_str(chain_json).map_err(to_js_err)?;
    let final_seq =
        verify_rotation_chain(&psig, &pstat, p_seq, &chain, &cstat, &csig).map_err(to_js_err)?;
    u64_to_f64(final_seq).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn verify_grant_json(
    grant_json: &str,
    issuer_keys_json: &str,
    expected_subject: &str,
    expected_root_issuer: &str,
    requested_cap: &str,
    now_unix: f64,
    crl_json: Option<String>,
) -> Result<bool, JsValue> {
    let now_u64 = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
    let grant: Grant = serde_json::from_str(grant_json).map_err(to_js_err)?;
    let key_map_raw: HashMap<String, String> =
        serde_json::from_str(issuer_keys_json).map_err(to_js_err)?;
    let mut key_map = HashMap::with_capacity(key_map_raw.len());
    for (id, b64) in key_map_raw {
        let k = HybridSigningPublicKey::from_b64url(&b64)
            .map_err(|e| to_js_err(WasmError::core_in(format_args!("invalid key for {id}"), &e)))?;
        key_map.insert(id, k);
    }
    let crl: Option<RevocationList> = match crl_json {
        Some(ref s) if !s.is_empty() => Some(serde_json::from_str(s).map_err(to_js_err)?),
        _ => None,
    };
    let (res, _) = authorize_grant(
        Some(&grant),
        expected_subject,
        expected_root_issuer,
        requested_cap,
        now_u64,
        crl.as_ref(),
        |id| key_map.get(id).cloned(),
    );
    Ok(res.is_ok())
}

#[wasm_bindgen]
pub fn parse_pairing_uri_json(uri: &str) -> Result<String, JsValue> {
    parse_pairing_uri_value(uri)
        .map(|v| v.to_string())
        .map_err(to_js_err)
}

fn provider_name(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::Local => "local",
        ProviderId::Direct => "direct",
        ProviderId::Overlay => "overlay",
        ProviderId::P2p => "p2p",
        ProviderId::Relay => "relay",
        ProviderId::Broker => "broker",
    }
}

fn parse_pairing_uri_value(uri: &str) -> Result<serde_json::Value, WasmError> {
    let parsed = PairingUri::parse(uri).map_err(WasmError::from)?;
    let rotation_seq = parsed.rotation_seq.map(u64_to_f64).transpose()?;
    let route_seq = parsed.route_seq().map(u64_to_f64).transpose()?;
    let providers = parsed
        .endpoints
        .iter()
        .map(|ep| {
            classify_endpoint_hint(ep)
                .map(provider_name)
                .map_err(WasmError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "host_name": parsed.host_name,
        "code": parsed.code,
        "host_static_pub_b64": b64url_encode(&parsed.host_static_pub),
        "host_signing_pub_hash_b64": b64url_encode(&parsed.host_signing_pub_hash),
        "endpoints": parsed.endpoints,
        "providers": providers,
        "host_id": parsed.host_id,
        "rotation_seq": rotation_seq,
        "relay_pub_b64": parsed.relay_pub.as_ref().map(|k| b64url_encode(k)),
        "route_seq": route_seq,
        "route_signed": parsed.is_signed(),
    }))
}

/// Classifies a pairing code by its group count: `lan2_group` or `remote3_group`.
///
/// A malformed code is an error, so callers reject it before any dial.
#[wasm_bindgen]
pub fn classify_pairing_code(code: &str) -> Result<String, JsValue> {
    classify_pairing_code_inner(code)
        .map(str::to_owned)
        .map_err(to_js_err)
}

fn classify_pairing_code_inner(code: &str) -> Result<&'static str, WasmError> {
    match PairingCodeKind::from_code(code).map_err(WasmError::from)? {
        PairingCodeKind::Lan2Group => Ok("lan2_group"),
        PairingCodeKind::Remote3Group => Ok("remote3_group"),
    }
}

/// Returns whether `dial_url` is in `origins_json` (a JSON array of origin strings), the gate
/// for attaching relay admission material (`relay_auth::origin_allowed`).
#[wasm_bindgen]
pub fn relay_auth_origin_allowed(dial_url: &str, origins_json: &str) -> Result<bool, JsValue> {
    relay_auth_origin_allowed_inner(dial_url, origins_json).map_err(to_js_err)
}

fn relay_auth_origin_allowed_inner(dial_url: &str, origins_json: &str) -> Result<bool, WasmError> {
    let origins: Vec<String> = serde_json::from_str(origins_json)
        .map_err(|e| WasmError::from(format!("invalid origins_json: {e}")))?;
    Ok(origin_allowed(dial_url, &origins))
}

#[derive(Serialize, Deserialize)]
struct PersistedWasmIdentity {
    host_id: String,
    static_secret_b64: String,
    signing_seed_b64: String,
    pq_signing_seed_b64: String,
    #[serde(default)]
    rotation_chain: Vec<RotationRecord>,
    #[serde(default)]
    rotation_seq: u64,
}

impl Drop for PersistedWasmIdentity {
    fn drop(&mut self) {
        self.static_secret_b64.zeroize();
        self.signing_seed_b64.zeroize();
        self.pq_signing_seed_b64.zeroize();
    }
}

/// Persistent client/endpoint identity held in browser storage by host JS.
#[wasm_bindgen]
pub struct WasmIdentity {
    inner: EndpointIdentity,
}

impl WasmIdentity {
    fn generate_inner(host_id: Option<&str>) -> Result<Self, WasmError> {
        let mut id = EndpointIdentity::generate().map_err(WasmError::from)?;
        if let Some(h) = host_id
            && !h.is_empty()
        {
            id = id.with_host_id(h);
        }
        Ok(Self { inner: id })
    }

    fn serialize_json(&self) -> Result<Zeroizing<String>, WasmError> {
        let doc = PersistedWasmIdentity {
            host_id: self.inner.host_id().to_owned(),
            static_secret_b64: b64url_encode(self.inner.static_key().secret_bytes()),
            signing_seed_b64: b64url_encode(self.inner.signing_key().seed_bytes()),
            pq_signing_seed_b64: b64url_encode(self.inner.signing_key().mldsa_seed_bytes()),
            rotation_chain: self.inner.rotation_chain().to_vec(),
            rotation_seq: self.inner.rotation_seq(),
        };
        serde_json::to_string(&doc)
            .map(Zeroizing::new)
            .map_err(WasmError::from)
    }

    fn serialize_json_bytes(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let doc = PersistedWasmIdentity {
            host_id: self.inner.host_id().to_owned(),
            static_secret_b64: b64url_encode(self.inner.static_key().secret_bytes()),
            signing_seed_b64: b64url_encode(self.inner.signing_key().seed_bytes()),
            pq_signing_seed_b64: b64url_encode(self.inner.signing_key().mldsa_seed_bytes()),
            rotation_chain: self.inner.rotation_chain().to_vec(),
            rotation_seq: self.inner.rotation_seq(),
        };
        serde_json::to_vec(&doc)
            .map(Zeroizing::new)
            .map_err(|e| e.to_string())
    }

    fn parse_json(json_str: &str) -> Result<Self, WasmError> {
        let doc: PersistedWasmIdentity = serde_json::from_str(json_str).map_err(WasmError::from)?;
        let static_scalar = Zeroizing::new(
            b64url_decode_array::<32>(&doc.static_secret_b64).map_err(WasmError::from)?,
        );
        let signing_seed = Zeroizing::new(
            b64url_decode_array::<32>(&doc.signing_seed_b64).map_err(WasmError::from)?,
        );
        let pq_signing_seed = Zeroizing::new(
            b64url_decode_array::<32>(&doc.pq_signing_seed_b64).map_err(WasmError::from)?,
        );
        let inner = EndpointIdentity::from_persisted(
            doc.host_id.clone(),
            StaticKeypair::from_scalar(*static_scalar),
            SigningKeypair::from_seeds(*signing_seed, *pq_signing_seed),
            doc.rotation_chain.clone(),
            doc.rotation_seq,
        )
        .map_err(WasmError::from)?;
        Ok(Self { inner })
    }

    fn info_string(&self) -> String {
        json!({
            "host_id": self.inner.host_id(),
            "device_id": self.inner.device_id(),
            "static_pub": b64url_encode(self.inner.static_key().public_bytes()),
            "signing_pub": self.inner.signing_key().public_key().to_b64url(),
            "signing_pub_hash": b64url_encode(&self.inner.signing_key().signing_pub_hash()),
            "relay_pub": b64url_encode(self.inner.signing_key().ed25519_public_bytes()),
        })
        .to_string()
    }
}

#[wasm_bindgen]
impl WasmIdentity {
    #[wasm_bindgen]
    pub fn generate(host_id: Option<String>) -> Result<WasmIdentity, JsValue> {
        Self::generate_inner(host_id.as_deref()).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn from_json(json: &str) -> Result<WasmIdentity, JsValue> {
        Self::parse_json(json).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn from_json_bytes(json_bytes: &mut [u8]) -> Result<WasmIdentity, JsValue> {
        let res = match core::str::from_utf8(json_bytes) {
            Ok(s) => Self::parse_json(s).map_err(to_js_err),
            Err(err) => Err(to_js_err(format!("invalid UTF-8 identity JSON: {err}"))),
        };
        json_bytes.zeroize();
        res
    }

    #[wasm_bindgen(unchecked_return_type = "string")]
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        let serialized = self.serialize_json().map_err(to_js_err)?;
        Ok(JsValue::from_str(&serialized))
    }

    #[wasm_bindgen(unchecked_return_type = "Uint8Array")]
    pub fn to_json_bytes(&self) -> Result<JsValue, JsValue> {
        let serialized = self.serialize_json_bytes().map_err(to_js_err)?;
        copy_zeroizing_bytes_to_js(serialized)
    }

    #[wasm_bindgen]
    pub fn info_json(&self) -> String {
        self.info_string()
    }

    #[wasm_bindgen]
    pub fn mint_enrollment_token(
        &self,
        target_host_id: &str,
        subject_opt: Option<String>,
        now_unix: f64,
        ttl_secs: f64,
    ) -> Result<String, JsValue> {
        let now_u64 = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        let ttl_u64 = f64_to_u64(ttl_secs, "ttl_secs").map_err(to_js_err)?;
        let nonce = random_bytes::<16>().map_err(to_js_err)?;
        let token = core_mint_enrollment_token(
            &self.inner,
            target_host_id,
            subject_opt.as_deref(),
            now_u64,
            ttl_u64,
            nonce,
        )
        .map_err(to_js_err)?;
        serde_json::to_string(&token).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn mint_relay_ticket_json(
        &self,
        relay_host: &str,
        role: &str,
        target_pub_or_wildcard: &str,
        now_unix: f64,
        ttl_secs: f64,
    ) -> Result<String, JsValue> {
        let parsed_role = match role {
            "register" => RelayAuthRole::Register,
            "dial" => RelayAuthRole::Dial,
            "any" => RelayAuthRole::Any,
            _ => {
                return Err(to_js_err(
                    "invalid relay auth role; expected register, dial, or any",
                ));
            }
        };
        let now_u64 = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        let ttl_u64 = f64_to_u64(ttl_secs, "ttl_secs").map_err(to_js_err)?;
        let signing_key = self.inner.signing_key().ed25519_signing_key();
        let ticket = core_mint_relay_ticket(
            &signing_key,
            relay_host,
            parsed_role,
            target_pub_or_wildcard,
            now_u64,
            ttl_u64,
        )
        .map_err(to_js_err)?;
        serde_json::to_string(&ticket).map_err(to_js_err)
    }
}

// ---------------------------------------------------------------------------
// Syntactic route checks for the browser (no resolver access)
// ---------------------------------------------------------------------------

const MAX_OPERATOR_ROUTE_INPUTS: usize = 6;
const AWS_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

fn invalid_route(msg: impl fmt::Display) -> WasmError {
    WasmError::from(tendril_core::error::CoreError::InvalidPairingUri(
        msg.to_string(),
    ))
}

/// IPv4 address a fixed IPv6 embedding stands for (mapped, translated, compatible, NAT64, 6to4).
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    let oct = v6.octets();
    let tail = Ipv4Addr::new(oct[12], oct[13], oct[14], oct[15]);
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return Some(mapped);
    }
    if seg[..4] == [0; 4] && seg[4] == 0xffff && seg[5] == 0 {
        return Some(tail);
    }
    if seg[..6] == [0; 6] && !v6.is_unspecified() && !v6.is_loopback() {
        return Some(tail);
    }
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0; 4] {
        return Some(tail);
    }
    if seg[0] == 0x2002 {
        return Some(Ipv4Addr::new(oct[2], oct[3], oct[4], oct[5]));
    }
    None
}

/// The always-blocked destination set: unspecified, multicast, broadcast, link-local,
/// `0.0.0.0/8`, `240.0.0.0/4`, site-local, local-use NAT64 and cloud metadata addresses.
fn ip_blocked(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => embedded_ipv4(v6).map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.octets()[0] == 0
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xffc0) == 0xfe80
                || (seg[0] & 0xffc0) == 0xfec0
                || v6 == AWS_METADATA_V6
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001)
        }
    }
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
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(ip_blocked)
    })
}

/// `true` when a literal host of `hint` is in the always-blocked set (no DNS).
fn hint_has_blocked_literal(hint: &str) -> bool {
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

fn url_has_host(raw: &str) -> bool {
    url::Url::parse(raw).is_ok_and(|u| u.host_str().is_some_and(|h| !h.is_empty()))
}

/// `true` when every URL `hint` carries parses (WHATWG) with a host: the WebSocket URL of a
/// relay or broker hint and each nested `relay=` of an `iroh://` hint.
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

/// A nested `relay=` URL of an operator `iroh://` endpoint. Builds with the `p2p-iroh` dialer
/// apply its relay URL validation (no userinfo, query or fragment; `http://` only on
/// loopback); other builds check the scheme and host only.
#[cfg(feature = "p2p-iroh")]
fn iroh_relay_url_ok(raw: &str) -> bool {
    p2p::validate_iroh_relay_url_wasm(raw).is_ok()
}

#[cfg(not(feature = "p2p-iroh"))]
fn iroh_relay_url_ok(raw: &str) -> bool {
    url_has_host(raw) && (raw.starts_with("https://") || raw.starts_with("http://"))
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

/// Normalizes an endpoint typed by the local operator or developer: `/abs/path` becomes
/// `local:/abs/path`, a relay `URL#<43-char key>` yields the key, a `/v2/relay#<id>` loses its
/// fragment, a bare `host:port` becomes `direct:host:port`, any other `#` fails.
fn normalize_operator_endpoint(raw: &str) -> Result<OperatorEndpoint, WasmError> {
    let (hint, relay_key) = match raw.split_once('#') {
        Some((base, fragment)) if is_ws_url(base) => {
            if is_v2_relay_hint(base) {
                (base.to_owned(), None)
            } else {
                let key = (fragment.len() == 43)
                    .then(|| b64url_decode_array::<32>(fragment).ok())
                    .flatten()
                    .filter(is_valid_ed25519_public_key)
                    .ok_or_else(|| invalid_route("invalid relay key in endpoint fragment"))?;
                (base.to_owned(), Some(key))
            }
        }
        Some(_) => return Err(invalid_route("fragment not allowed")),
        None if raw.starts_with('/') => (format!("local:{raw}"), None),
        None if has_known_prefix(raw) => (raw.to_owned(), None),
        None => (format!("direct:{raw}"), None),
    };
    if !tendril_core::pairing::is_valid_pairing_endpoint_hint(&hint) {
        return Err(invalid_route("invalid endpoint"));
    }
    Ok(OperatorEndpoint { hint, relay_key })
}

/// Normalizes and checks operator route input without touching a roster: at most six entries,
/// each normalized, every carried URL parseable with a host, and no always-blocked literal. One
/// bad entry fails the whole batch.
fn normalize_peer_routes(raw: &[String]) -> Result<Vec<OperatorEndpoint>, WasmError> {
    if raw.len() > MAX_OPERATOR_ROUTE_INPUTS {
        return Err(invalid_route(format!(
            "at most {MAX_OPERATOR_ROUTE_INPUTS} operator routes"
        )));
    }
    let endpoints = raw
        .iter()
        .map(|r| normalize_operator_endpoint(r))
        .collect::<Result<Vec<_>, _>>()?;
    if endpoints.iter().any(|ep| !hint_urls_parse(&ep.hint)) {
        return Err(invalid_route("invalid URL in endpoint"));
    }
    if endpoints
        .iter()
        .any(|ep| hint_has_blocked_literal(&ep.hint))
    {
        return Err(invalid_route("blocked_address"));
    }
    Ok(endpoints)
}

fn stored_route_json(route: &StoredRoute) -> serde_json::Value {
    json!({ "hint": route.hint, "source": route.source.as_str() })
}

/// Options of [`WasmRoster::session_candidates`].
#[derive(Deserialize, Default)]
#[serde(default)]
struct SessionCandidateOpts {
    /// A fresh pairing URI for this peer (Day-2 recovery).
    recovery_uri: Option<String>,
    /// Wire version of the connect: `1` (default) or `2`.
    wire: Option<u8>,
    /// Route policy deciding the `route_seq` to send (`allSigned` default).
    route_policy: Option<String>,
    /// `iroh://` hints are dialable (the `p2p-iroh` WASM module loaded).
    p2p: bool,
    /// Permit cleartext `ws://` and `broker+ws://` outside loopback hosts.
    #[serde(default)]
    allow_insecure_ws: bool,
}

fn source_strength(source: &str) -> u8 {
    match source {
        "operator" => 3,
        "signed" => 2,
        "committed" => 1,
        _ => 0,
    }
}

/// `true` when an `addr=` value of an `iroh://` hint is a socket address in the always-blocked set.
fn iroh_addr_blocked(value: &str) -> Result<bool, &'static str> {
    value
        .parse::<SocketAddr>()
        .map(|sock| ip_blocked(sock.ip()))
        .map_err(|_| "invalid")
}

/// The `iroh://` endpoint a browser dials for `endpoint`, mirroring the native egress rules.
///
/// Operator endpoints keep every parameter except `addr=` literals and literal `relay=` hosts
/// in the always-blocked set, and are skipped as `blocked_address` when only blocked
/// destinations were given. URI hints and `signed` or `committed` routes lose every `relay=`
/// (the browser dials through its configured relay map, as native hint dials do) and their
/// blocked `addr=` literals; a malformed or unknown parameter skips them as `invalid`.
fn filter_browser_iroh_hint(endpoint: &str, source: &str) -> Result<String, &'static str> {
    let Some((base, query)) = endpoint.split_once('?') else {
        return Ok(endpoint.to_owned());
    };
    let operator = source == "operator";
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = false;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let blocked = match pair.split_once('=') {
            Some(("addr", value)) => iroh_addr_blocked(value)?,
            Some(("relay", value)) if operator => url_host_blocked(value),
            Some(("relay", value)) => {
                url::Url::parse(value).map_err(|_| "invalid")?;
                true
            }
            _ if operator => false,
            _ => return Err("invalid"),
        };
        if blocked {
            removed = true;
        } else {
            kept.push(pair);
        }
    }
    if operator && !removed {
        return Ok(endpoint.to_owned());
    }
    if operator
        && !kept
            .iter()
            .any(|p| p.starts_with("addr=") || p.starts_with("relay="))
    {
        return Err("blocked_address");
    }
    Ok(if kept.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", kept.join("&"))
    })
}

fn split_ws_prefix(hint: &str) -> (&str, &str) {
    if let Some(rest) = hint.strip_prefix("relay:") {
        ("relay:", rest)
    } else if let Some(rest) = hint.strip_prefix("broker+") {
        ("broker+", rest)
    } else {
        ("", hint)
    }
}

fn classify_browser_hint(hint: &str, allow_insecure_ws: bool) -> Result<ProviderId, &'static str> {
    if hint.contains('#') {
        return Err("invalid");
    }
    if let Ok(provider) = classify_endpoint_hint(hint) {
        if provider != ProviderId::P2p && hint_has_blocked_literal(hint) {
            return Err("blocked_address");
        }
        return Ok(provider);
    }
    let (prefix, url) = split_ws_prefix(hint);
    if url.starts_with("wss://") || url.starts_with("ws://") {
        if url_host_blocked(url) {
            return Err("blocked_address");
        }
        if let Some(rest) = url.strip_prefix("ws://") {
            let secure = format!("{prefix}wss://{rest}");
            if let Ok(provider) = classify_endpoint_hint(&secure) {
                return if allow_insecure_ws {
                    Ok(provider)
                } else {
                    Err("insecure_ws")
                };
            }
        }
    }
    Err("invalid")
}

/// Checks one hint for a browser Day-2 dial. `Ok` carries the provider and the endpoint string
/// to dial (`relay:`, `p2p:`, and `broker+` prefixes stripped); `Err` the skip reason.
fn check_browser_hint(
    hint: &str,
    source: &str,
    wire: u8,
    opts: &SessionCandidateOpts,
    relay_v2_authorized: bool,
) -> Result<(ProviderId, String), &'static str> {
    let provider = classify_browser_hint(hint, opts.allow_insecure_ws)?;
    if provider == ProviderId::Local && source == "uri" {
        return Err("ipc_from_uri");
    }
    match provider {
        ProviderId::Relay => {
            let endpoint = hint.strip_prefix("relay:").unwrap_or(hint);
            if is_v2_relay_hint(hint) {
                if wire != 2 {
                    return Err("wire_v1_no_relay_v2");
                }
                if !relay_v2_authorized {
                    return Err("relay_v2_not_authorized");
                }
            }
            url::Url::parse(endpoint).map_err(|_| "invalid")?;
            Ok((provider, endpoint.to_owned()))
        }
        ProviderId::Broker => {
            let endpoint = hint.strip_prefix("broker+").unwrap_or(hint);
            let parsed = url::Url::parse(endpoint).map_err(|_| "invalid")?;
            if !parsed.host_str().is_some_and(|h| !h.is_empty()) {
                return Err("invalid");
            }
            Ok((provider, endpoint.to_owned()))
        }
        ProviderId::P2p => {
            if !opts.p2p {
                return Err("p2p_feature_disabled");
            }
            let endpoint = hint.strip_prefix("p2p:").unwrap_or(hint);
            Ok((provider, filter_browser_iroh_hint(endpoint, source)?))
        }
        ProviderId::Local | ProviderId::Direct | ProviderId::Overlay => Err("browser_unsupported"),
    }
}

/// The complete candidate list for a browser Day-2 connect to `peer_id`.
fn session_candidates_value(
    roster: &Roster,
    peer_id: &str,
    opts: &SessionCandidateOpts,
) -> Result<serde_json::Value, WasmError> {
    use tendril_core::error::CoreError;
    let entry = roster
        .get(peer_id)
        .ok_or_else(|| WasmError::from(CoreError::PeerNotFound(peer_id.to_owned())))?;
    match entry.state {
        PeerState::Pending => {
            return Err(WasmError::from(CoreError::PeerPending(peer_id.to_owned())));
        }
        PeerState::Revoked => {
            return Err(WasmError::from(CoreError::PeerRevoked(peer_id.to_owned())));
        }
        PeerState::Active => {}
    }
    if roster.crl_revokes_entry(entry) {
        return Err(WasmError::from(CoreError::PeerRevoked(peer_id.to_owned())));
    }
    let (_, signing_pub) = entry.require_complete_pin().map_err(WasmError::from)?;
    let wire = opts.wire.unwrap_or(1);
    if !matches!(wire, 1 | 2) {
        return Err("wire must be 1 or 2".to_owned().into());
    }
    if wire == 1 {
        check_peer_allows_wire_v1(roster, peer_id)?;
    }
    let policy = match opts.route_policy.as_deref() {
        Some(p) => p.parse::<RoutePolicy>().map_err(WasmError::from)?,
        None => RoutePolicy::default(),
    };
    let expectation =
        RouteExpectation::for_connect(peer_id, opts.recovery_uri.as_deref(), None, None)
            .map_err(WasmError::from)?;

    let mut inputs: Vec<(String, &'static str)> = Vec::new();
    for route in &entry.routes {
        let source = route.source.as_str();
        match inputs.iter_mut().find(|(h, _)| *h == route.hint) {
            Some((_, existing)) => {
                if source_strength(source) > source_strength(existing) {
                    *existing = source;
                }
            }
            None => inputs.push((route.hint.clone(), source)),
        }
    }
    if let Some(uri) = expectation.recovery_uri().filter(|u| u.is_signed()) {
        for hint in &uri.endpoints {
            let ipc = classify_endpoint_hint(hint).is_ok_and(|p| p == ProviderId::Local);
            if !ipc && !inputs.iter().any(|(h, _)| h == hint) {
                inputs.push((hint.clone(), "uri"));
            }
        }
    }

    let relay_v2_ready = entry.v2_secrets.is_some();
    let mut candidates: Vec<(CandidateEndpoint, serde_json::Value)> = Vec::new();
    let mut skipped = Vec::new();
    for (idx, (hint, source)) in inputs.iter().enumerate() {
        let authorized = relay_v2_ready
            && entry.routes.iter().any(|r| {
                r.hint == *hint && matches!(r.source, RouteSource::Operator | RouteSource::Signed)
            });
        match check_browser_hint(hint, source, wire, opts, authorized) {
            Ok((provider, endpoint)) => candidates.push((
                CandidateEndpoint::new(idx, provider, hint.as_str()),
                json!({
                    "hint": hint,
                    "endpoint": endpoint,
                    "provider": provider_name(provider),
                    "source": source,
                }),
            )),
            Err(reason) => skipped.push(json!({ "hint": hint, "reason": reason })),
        }
    }
    candidates.sort_by_key(|(ep, _)| sort_key(ep));
    let relay_key = expectation
        .relay_pub()
        .copied()
        .unwrap_or(*signing_pub.ed25519_bytes());
    let route_seq = entry.hello_route_seq(policy).map(u64_to_f64).transpose()?;
    Ok(json!({
        "peer_id": peer_id,
        "wire": wire,
        "relay_key_b64": b64url_encode(&relay_key),
        "route_seq": route_seq,
        "legacy_relay_hints": !entry.relay_hints.is_empty(),
        "candidates": candidates.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
        "skipped": skipped,
    }))
}

/// Options of [`WasmRoster::apply_signed_route_uri`].
#[derive(Deserialize, Default)]
#[serde(default)]
struct RouteApplyInput {
    route_policy: Option<String>,
    replace_routes: bool,
}

/// Applies a fresh signed pairing URI to the matching `Active` entry offline. On error `roster` is unchanged.
fn apply_signed_route_uri_value(
    roster: &mut Roster,
    uri: &str,
    opts: &RouteApplyInput,
) -> Result<serde_json::Value, WasmError> {
    use tendril_core::error::CoreError;
    const NO_MATCHING_HOST: &str = "no paired host matches this pairing URI's keys; if the host \
                                    rotated, connect with the URI as a recovery URI";
    let uri = PairingUri::parse(uri).map_err(WasmError::from)?;
    let policy = match opts.route_policy.as_deref() {
        Some(p) => p.parse::<RoutePolicy>().map_err(WasmError::from)?,
        None => RoutePolicy::default(),
    };
    let (peer_id, statement) = {
        let (peer_id, entry) = roster
            .entries()
            .find(|(_, e)| {
                e.state == PeerState::Active
                    && !roster.crl_revokes_entry(e)
                    && e.static_pub == uri.host_static_pub
                    && e.signing_pub
                        .as_ref()
                        .is_some_and(|s| s.sha256_hash() == uri.host_signing_pub_hash)
            })
            .ok_or_else(|| WasmError::from(CoreError::PeerNotFound(NO_MATCHING_HOST.to_owned())))?;
        let signing_pub = entry
            .signing_pub
            .as_ref()
            .ok_or_else(|| WasmError::from(CoreError::PeerNotFound(NO_MATCHING_HOST.to_owned())))?;
        let statement = match uri.verify_route_statement(signing_pub) {
            RouteCheck::Verified(s) => s,
            RouteCheck::Unsigned(_) => {
                return Err(invalid_route("pairing URI is not host-signed"));
            }
            RouteCheck::Invalid => return Err(invalid_route("route statement does not verify")),
        };
        if *statement.host_static_pub() != entry.static_pub
            || *statement.sh() != signing_pub.sha256_hash()
        {
            return Err(WasmError::from(CoreError::HostKeyUnverified));
        }
        (peer_id.clone(), statement)
    };
    let mut staged = roster.clone();
    let mut reason = None;
    let mut applied = false;
    if policy == RoutePolicy::AllSigned {
        applied = staged
            .replace_signed_routes(&peer_id, &statement)
            .map_err(WasmError::from)?;
        if !applied {
            reason = Some("stale_route_seq");
        }
    } else {
        reason = Some("route_policy");
    }
    if !applied && opts.replace_routes {
        staged
            .replace_routes_approved(&peer_id, &statement)
            .map_err(WasmError::from)?;
        applied = true;
        reason = None;
    }
    let updated = staged
        .get(&peer_id)
        .ok_or_else(|| WasmError::from(CoreError::PeerNotFound(peer_id.clone())))?;
    let result = json!({
        "peer_id": peer_id,
        "applied": applied,
        "reason": reason,
        "routes": updated.routes.iter().map(stored_route_json).collect::<Vec<_>>(),
        "route_meta": updated.route_meta,
    });
    *roster = staged;
    Ok(result)
}

/// Sans-I/O peer roster and verified CRL store managed by host JS storage.
#[wasm_bindgen]
pub struct WasmRoster {
    inner: Roster,
}

/// The pinned keys of one roster entry when a Day-2 connect started (opaque handle).
#[wasm_bindgen]
pub struct WasmPinSnapshot {
    inner: PinSnapshot,
}

#[wasm_bindgen]
impl WasmPinSnapshot {
    /// Roster key the snapshot was taken of.
    #[wasm_bindgen]
    #[must_use]
    pub fn peer_id(&self) -> String {
        self.inner.peer_id().to_owned()
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn rotation_seq(&self) -> f64 {
        u64_to_f64(self.inner.rotation_seq()).unwrap_or(f64::NAN)
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn min_wire_version(&self) -> u8 {
        self.inner.min_wire_version()
    }
}

#[derive(Serialize, Deserialize)]
struct CrlEvidence {
    issuer: String,
    crl: RevocationList,
}

fn parse_rotation_records(json: &str) -> Result<Vec<RotationRecord>, WasmError> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(json).map_err(|e| WasmError::from(format!("invalid records_json: {e}")))
}

impl WasmRoster {
    fn peer_entry(&self, peer_id: &str) -> Result<&tendril_core::roster::RosterEntry, WasmError> {
        self.inner
            .get(peer_id)
            .ok_or_else(|| tendril_core::error::CoreError::PeerNotFound(peer_id.to_owned()).into())
    }

    fn peer_v2_secrets(
        &self,
        peer_id: &str,
    ) -> Result<&tendril_core::roster::V2PeerSecrets, WasmError> {
        self.peer_entry(peer_id)?
            .v2_secrets
            .as_ref()
            .ok_or_else(|| {
                tendril_core::error::CoreError::NotReady("peer has no v2 secrets").into()
            })
    }

    fn pin_snapshot_inner(&self, peer_id: &str) -> Result<WasmPinSnapshot, WasmError> {
        self.inner
            .pin_snapshot(peer_id)
            .map(|inner| WasmPinSnapshot { inner })
            .map_err(WasmError::from)
    }

    fn reconcile_rotation_evidence_inner(
        &mut self,
        peer_id: &str,
        snapshot: &WasmPinSnapshot,
        records_json: &str,
    ) -> Result<(), WasmError> {
        let records = parse_rotation_records(records_json)?;
        self.inner
            .reconcile_rotation_evidence(peer_id, &snapshot.inner, &records)
            .map_err(WasmError::from)
    }

    /// Applies the rotation chain a host presented: the presented keys are the chain's final
    /// keys, which the session already matched against the keys of its handshake.
    fn apply_verified_rotation_inner(
        &mut self,
        peer_id: &str,
        records_json: &str,
    ) -> Result<f64, WasmError> {
        let records = parse_rotation_records(records_json)?;
        let (presented_static, presented_signing) = match records.last() {
            Some(last) => (
                b64url_decode_array::<32>(&last.new_static_pub).map_err(WasmError::from)?,
                HybridSigningPublicKey::from_b64url(&last.new_signing_pub)
                    .map_err(WasmError::from)?,
            ),
            None => {
                let entry = self
                    .inner
                    .get(peer_id)
                    .ok_or_else(|| tendril_core::error::CoreError::PeerNotFound(peer_id.to_owned()))
                    .map_err(WasmError::from)?;
                entry.require_complete_pin().map_err(WasmError::from)?
            }
        };
        let seq = self
            .inner
            .apply_verified_rotation(peer_id, &records, &presented_static, &presented_signing)
            .map_err(WasmError::from)?;
        u64_to_f64(seq)
    }

    fn check_established_session_inner(
        &self,
        peer_id: &str,
        static_pub_b64: &str,
        signing_pub_b64: &str,
        wire: u8,
    ) -> Result<(), WasmError> {
        let static_pub = b64url_decode_array::<32>(static_pub_b64).map_err(WasmError::from)?;
        let signing_pub =
            HybridSigningPublicKey::from_b64url(signing_pub_b64).map_err(WasmError::from)?;
        self.inner
            .check_established_session(peer_id, &static_pub, &signing_pub, wire)
            .map_err(WasmError::from)
    }

    fn session_candidates_inner(
        &self,
        peer_id: &str,
        opts_json: Option<&str>,
    ) -> Result<String, WasmError> {
        let opts: SessionCandidateOpts = match opts_json {
            Some(raw) if !raw.trim().is_empty() => serde_json::from_str(raw)
                .map_err(|e| WasmError::from(format!("invalid opts_json: {e}")))?,
            _ => SessionCandidateOpts::default(),
        };
        session_candidates_value(&self.inner, peer_id, &opts).map(|v| v.to_string())
    }

    fn merge_crl_evidence_inner(&mut self, crls_json: &str) -> Result<f64, WasmError> {
        let evidence: Vec<CrlEvidence> = if crls_json.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(crls_json)
                .map_err(|e| WasmError::from(format!("invalid crls_json: {e}")))?
        };
        let pairs: Vec<(String, RevocationList)> =
            evidence.into_iter().map(|e| (e.issuer, e.crl)).collect();
        #[allow(clippy::cast_precision_loss)]
        Ok(self.inner.merge_crl_evidence(&pairs) as f64)
    }

    fn export_crls_inner(&self) -> Vec<CrlEvidence> {
        let issuers: BTreeSet<&str> = self
            .inner
            .entries()
            .map(|(id, _)| id.as_str())
            .chain(self.inner.trust_anchors().map(|(id, _)| id.as_str()))
            .collect();
        issuers
            .into_iter()
            .filter_map(|issuer| {
                self.inner.crl(issuer).map(|crl| CrlEvidence {
                    issuer: issuer.to_owned(),
                    crl: crl.clone(),
                })
            })
            .collect()
    }

    fn apply_route_announcement_inner(
        &mut self,
        peer_id: &str,
        payload: &[u8],
        now_unix: f64,
    ) -> Result<String, WasmError> {
        let now = f64_to_u64(now_unix, "now_unix")?;
        let set = RouteSet::decode(payload).map_err(WasmError::from)?;
        let outcome = self
            .inner
            .apply_route_announcement(peer_id, &set, now)
            .map_err(WasmError::from)?;
        Ok(match outcome {
            RouteSetOutcome::Applied { added, removed } => {
                json!({ "outcome": "applied", "added": added, "removed": removed })
            }
            RouteSetOutcome::Ignored(reason) => {
                json!({ "outcome": "ignored", "reason": reason.as_str() })
            }
        }
        .to_string())
    }

    fn set_routes_inner(&mut self, peer_id: &str, routes_json: &str) -> Result<String, WasmError> {
        let raw: Vec<String> = if routes_json.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(routes_json)
                .map_err(|e| WasmError::from(format!("invalid routes_json: {e}")))?
        };
        let endpoints = normalize_peer_routes(&raw)?;
        let routes = self
            .inner
            .set_routes(peer_id, endpoints)
            .map_err(WasmError::from)?;
        Ok(serde_json::Value::Array(routes.iter().map(stored_route_json).collect()).to_string())
    }

    fn clear_routes_inner(&mut self, peer_id: &str, source: Option<&str>) -> Result<(), WasmError> {
        let source = match source {
            Some("all") => None,
            None | Some("") | Some("operator") => Some(RouteSource::Operator),
            Some("signed") => Some(RouteSource::Signed),
            Some("committed") => Some(RouteSource::Committed),
            Some(_) => return Err(invalid_route("unknown route source")),
        };
        self.inner
            .clear_routes(peer_id, source)
            .map_err(WasmError::from)
    }

    fn apply_signed_route_uri_inner(
        &mut self,
        uri: &str,
        opts_json: Option<&str>,
    ) -> Result<String, WasmError> {
        let opts: RouteApplyInput = match opts_json {
            Some(raw) if !raw.trim().is_empty() => serde_json::from_str(raw)
                .map_err(|e| WasmError::from(format!("invalid opts_json: {e}")))?,
            _ => RouteApplyInput::default(),
        };
        apply_signed_route_uri_value(&mut self.inner, uri, &opts).map(|v| v.to_string())
    }
}

#[wasm_bindgen]
impl WasmRoster {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Roster::new(),
        }
    }

    #[wasm_bindgen]
    pub fn from_json(json: &str) -> Result<WasmRoster, JsValue> {
        let inner: Roster = serde_json::from_str(json).map_err(to_js_err)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen]
    pub fn from_json_bytes(json_bytes: &mut [u8]) -> Result<WasmRoster, JsValue> {
        let res = serde_json::from_slice::<Roster>(json_bytes)
            .map(|inner| Self { inner })
            .map_err(to_js_err);
        json_bytes.zeroize();
        res
    }

    #[wasm_bindgen(unchecked_return_type = "string")]
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        let serialized = Zeroizing::new(serde_json::to_string(&self.inner).map_err(to_js_err)?);
        Ok(JsValue::from_str(&serialized))
    }

    #[wasm_bindgen(unchecked_return_type = "Uint8Array")]
    pub fn to_json_bytes(&self) -> Result<JsValue, JsValue> {
        let serialized = Zeroizing::new(serde_json::to_vec(&self.inner).map_err(to_js_err)?);
        copy_zeroizing_bytes_to_js(serialized)
    }

    #[wasm_bindgen]
    pub fn replace_from_json(&mut self, json: &str) -> Result<(), JsValue> {
        self.inner = serde_json::from_str(json).map_err(to_js_err)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn replace_from_json_bytes(&mut self, json_bytes: &mut [u8]) -> Result<(), JsValue> {
        let res = serde_json::from_slice::<Roster>(json_bytes).map_err(to_js_err);
        json_bytes.zeroize();
        self.inner = res?;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn check_allows_wire_v1(&self, target_host_id: &str) -> Result<(), JsValue> {
        check_peer_allows_wire_v1(&self.inner, target_host_id).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn insert_pinned_host(
        &mut self,
        host_id: &str,
        name: &str,
        static_pub_b64: &str,
        signing_pub_b64: Option<String>,
        rotation_seq: f64,
        relay_hints_json: Option<String>,
    ) -> Result<(), JsValue> {
        let seq = f64_to_u64(rotation_seq, "rotation_seq").map_err(to_js_err)?;
        let static_pub = b64url_decode_array::<32>(static_pub_b64).map_err(to_js_err)?;
        let signing_pub = match signing_pub_b64 {
            Some(ref s) if !s.is_empty() => {
                Some(HybridSigningPublicKey::from_b64url(s).map_err(to_js_err)?)
            }
            _ => None,
        };
        let hints: Vec<String> = match relay_hints_json {
            Some(ref s) if !s.is_empty() => serde_json::from_str(s).map_err(to_js_err)?,
            _ => Vec::new(),
        };
        self.inner
            .insert_pinned_host(
                host_id.to_owned(),
                name.to_owned(),
                static_pub,
                signing_pub,
                seq,
                hints,
            )
            .map_err(to_js_err)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn confirm_peer(
        &mut self,
        peer_id: &str,
        expected_sas: Option<String>,
    ) -> Result<(), JsValue> {
        self.inner
            .confirm_peer(peer_id, expected_sas.as_deref())
            .map_err(to_js_err)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn remove_pending_peer(&mut self, peer_id: &str) -> Result<(), JsValue> {
        self.inner.remove_pending_peer(peer_id).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn add_trust_anchor(
        &mut self,
        anchor_id: &str,
        signing_pub_b64: &str,
    ) -> Result<(), JsValue> {
        let key = HybridSigningPublicKey::from_b64url(signing_pub_b64).map_err(to_js_err)?;
        self.inner
            .add_trust_anchor(anchor_id.to_owned(), key)
            .map(|_| ())
            .map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn revoke_trust_anchor(&mut self, anchor_id: &str) -> Result<(), JsValue> {
        self.inner.revoke_trust_anchor(anchor_id).map_err(to_js_err)
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn get_peer_json(&self, peer_id: &str) -> Option<String> {
        self.inner
            .get(peer_id)
            .and_then(|entry| serde_json::to_string(entry).ok())
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn crl_seq(&self, issuer: &str) -> Option<f64> {
        self.inner
            .crl(issuer)
            .and_then(|crl| u64_to_f64(crl.seq).ok())
    }

    #[wasm_bindgen]
    pub fn pairing_floor(&self, static_pub: &[u8]) -> Result<u8, JsValue> {
        let key = as_32(static_pub, "static_pub").map_err(to_js_err)?;
        Ok(self.inner.pairing_floor(&key))
    }

    #[wasm_bindgen]
    pub fn peer_v2_summary(&self, peer_id: &str) -> Result<String, JsValue> {
        let entry = self.peer_entry(peer_id).map_err(to_js_err)?;
        Ok(json!({
            "min_wire_version": entry.min_wire_version,
            "has_v2_secrets": entry.v2_secrets.is_some(),
        })
        .to_string())
    }

    #[wasm_bindgen]
    pub fn derive_v2_relay_dial_for_peer_json(
        &self,
        peer_id: &str,
        relay_host: &str,
        unix_secs: f64,
        dial_nonce: &[u8],
        conn_id: &[u8],
    ) -> Result<String, JsValue> {
        let secrets = self.peer_v2_secrets(peer_id).map_err(to_js_err)?;
        derive_v2_relay_dial_inner(
            secrets.mailbox_secret(),
            relay_host,
            unix_secs,
            dial_nonce,
            conn_id,
        )
        .map_err(to_js_err)
    }
}

#[wasm_bindgen]
impl WasmRoster {
    /// Independent copy of this roster (a Day-2 candidate verifies against its own clone).
    #[wasm_bindgen]
    #[must_use]
    pub fn clone_roster(&self) -> WasmRoster {
        Self {
            inner: self.inner.clone(),
        }
    }

    /// Takes the pin snapshot of `peer_id` a Day-2 connect reconciles against.
    #[wasm_bindgen]
    pub fn pin_snapshot(&self, peer_id: &str) -> Result<WasmPinSnapshot, JsValue> {
        self.pin_snapshot_inner(peer_id).map_err(to_js_err)
    }

    /// Reconciles the rotation records every candidate was shown (JSON array of records)
    /// against `snapshot`; a fork revokes the entry and fails with `RotationForkDetected`.
    #[wasm_bindgen]
    pub fn reconcile_rotation_evidence(
        &mut self,
        peer_id: &str,
        snapshot: &WasmPinSnapshot,
        records_json: &str,
    ) -> Result<(), JsValue> {
        self.reconcile_rotation_evidence_inner(peer_id, snapshot, records_json)
            .map_err(to_js_err)
    }

    /// Applies the winner's presented rotation chain (JSON array of records); returns the
    /// resulting rotation sequence.
    #[wasm_bindgen]
    pub fn apply_verified_rotation_json(
        &mut self,
        peer_id: &str,
        records_json: &str,
    ) -> Result<f64, JsValue> {
        self.apply_verified_rotation_inner(peer_id, records_json)
            .map_err(to_js_err)
    }

    /// Final authorization of an established session against the stored pin and wire floor.
    #[wasm_bindgen]
    pub fn check_established_session(
        &self,
        peer_id: &str,
        static_pub_b64: &str,
        signing_pub_b64: &str,
        wire: u8,
    ) -> Result<(), JsValue> {
        self.check_established_session_inner(peer_id, static_pub_b64, signing_pub_b64, wire)
            .map_err(to_js_err)
    }

    /// Complete Day-2 candidate list for `peer_id`: stored routes plus signed recovery-URI hints
    /// after the syntactic egress, browser scheme filter and `/v2/relay` gate.
    ///
    /// `opts_json` keys: `recovery_uri`, `wire` (1 or 2), `route_policy` and `p2p`.
    /// Returns `{peer_id, wire, relay_key_b64, route_seq,
    /// legacy_relay_hints, candidates: [{hint, endpoint, provider, source}], skipped:
    /// [{hint, reason}]}` with candidates in provider order.
    #[wasm_bindgen]
    pub fn session_candidates(
        &self,
        peer_id: &str,
        opts_json: Option<String>,
    ) -> Result<String, JsValue> {
        self.session_candidates_inner(peer_id, opts_json.as_deref())
            .map_err(to_js_err)
    }

    /// Ingests CRLs candidate clones accepted (JSON array of `{issuer, crl}`); returns how many
    /// were ingested.
    #[wasm_bindgen]
    pub fn merge_crl_evidence(&mut self, crls_json: &str) -> Result<f64, JsValue> {
        self.merge_crl_evidence_inner(crls_json).map_err(to_js_err)
    }

    /// The verified CRLs this roster holds, as a JSON array of `{issuer, crl}`.
    #[wasm_bindgen]
    pub fn export_crls_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.export_crls_inner()).map_err(to_js_err)
    }

    /// Applies a `0x0C` route set payload from an authenticated peer under the route
    /// high-water rule; returns `{outcome: "applied", added, removed}` or `{outcome:
    /// "ignored", reason}`.
    #[wasm_bindgen]
    pub fn apply_route_announcement(
        &mut self,
        peer_id: &str,
        payload: &[u8],
        now_unix: f64,
    ) -> Result<String, JsValue> {
        self.apply_route_announcement_inner(peer_id, payload, now_unix)
            .map_err(to_js_err)
    }

    /// Replaces the `operator` routes of an `Active` peer. `routes_json` is a JSON array of up
    /// to six raw operator endpoints; an empty array clears them. Returns the full route list.
    #[wasm_bindgen]
    pub fn set_routes(&mut self, peer_id: &str, routes_json: &str) -> Result<String, JsValue> {
        self.set_routes_inner(peer_id, routes_json)
            .map_err(to_js_err)
    }

    /// Removes the routes of one source (`operator`, the default, `signed` or `committed`), or
    /// every route with `all`.
    #[wasm_bindgen]
    pub fn clear_routes(&mut self, peer_id: &str, source: Option<String>) -> Result<(), JsValue> {
        self.clear_routes_inner(peer_id, source.as_deref())
            .map_err(to_js_err)
    }

    /// Applies a fresh signed pairing URI offline to the matching paired host. `opts_json` keys:
    /// `route_policy`, `replace_routes`. No network and no code use.
    #[wasm_bindgen]
    pub fn apply_signed_route_uri(
        &mut self,
        uri: &str,
        opts_json: Option<String>,
    ) -> Result<String, JsValue> {
        self.apply_signed_route_uri_inner(uri, opts_json.as_deref())
            .map_err(to_js_err)
    }
}

impl Default for WasmRoster {
    fn default() -> Self {
        Self::new()
    }
}

/// Persist options of one pairing (JSON object accepted by `set_persist_options`).
#[derive(Deserialize, Default)]
#[serde(default)]
struct PersistOptionsInput {
    /// `all_signed` (default), `committed_only` or `none`; camel spellings are accepted.
    route_policy: Option<String>,
    /// The raw explicit operator endpoint of this call (normalized here).
    operator_endpoint: Option<String>,
    /// Persist the committed route of an unsigned pairing.
    save_committed: bool,
    /// The URI hint string the winning candidate was built from (`None` for an operator winner).
    winner_hint: Option<String>,
}

/// Fails pre-dial when the operator `URL#key` and the URI `rp` name different keys.
fn check_relay_keys_agree(
    operator_relay_key: Option<[u8; 32]>,
    uri_rp: Option<[u8; 32]>,
) -> Result<(), WasmError> {
    match (operator_relay_key, uri_rp) {
        (Some(op), Some(rp)) if op != rp => Err(invalid_route(
            "operator relay key does not match the URI rp",
        )),
        _ => Ok(()),
    }
}

/// Route-statement checks and the persist plan of one pairing, shared by both initiators.
struct PairRouteContext {
    code: Zeroizing<String>,
    uri: Option<PairingUri>,
    opts: PersistOpts,
    operator_relay_key: Option<[u8; 32]>,
    winner_hint: Option<String>,
    check: Option<RouteCheck>,
    relay_pub_ok: Option<bool>,
}

impl PairRouteContext {
    fn new(code: &str) -> Self {
        Self {
            code: Zeroizing::new(code.to_owned()),
            uri: None,
            opts: PersistOpts::default(),
            operator_relay_key: None,
            winner_hint: None,
            check: None,
            relay_pub_ok: None,
        }
    }

    /// Refuses the deferred claim of a verified host whose relay key does not match (checked
    /// first) or whose route statement is invalid. JS falls back on the first and
    /// stops on the second, but `msg3` is never written for either.
    fn require_committable(&self) -> Result<(), WasmError> {
        if self.relay_pub_ok == Some(false) {
            return Err(tendril_core::error::CoreError::HostKeyUnverified.into());
        }
        if matches!(self.check, Some(RouteCheck::Invalid)) {
            return Err(invalid_route("route statement does not verify"));
        }
        Ok(())
    }

    /// The roster name of the paired host: the pairing URI's host name when set, else its id.
    fn host_name(&self, host_id: &str) -> String {
        self.uri
            .as_ref()
            .map(|u| u.host_name.as_str())
            .filter(|name| !name.is_empty())
            .unwrap_or(host_id)
            .to_owned()
    }

    fn set_uri(&mut self, uri: &str) -> Result<(), WasmError> {
        let uri = PairingUri::parse(uri)?;
        check_relay_keys_agree(self.operator_relay_key, uri.relay_pub)?;
        self.uri = Some(uri);
        Ok(())
    }

    fn set_options(&mut self, json: &str) -> Result<(), WasmError> {
        let input: PersistOptionsInput = if json.trim().is_empty() {
            PersistOptionsInput::default()
        } else {
            serde_json::from_str(json)
                .map_err(|e| WasmError::from(format!("invalid persist options: {e}")))?
        };
        let policy = match input.route_policy.as_deref() {
            Some(p) => p.parse::<RoutePolicy>().map_err(WasmError::from)?,
            None => RoutePolicy::default(),
        };
        let endpoint = match input.operator_endpoint.as_deref() {
            Some(raw) if !raw.is_empty() => normalize_peer_routes(&[raw.to_owned()])?.pop(),
            _ => None,
        };
        let opts = PersistOpts {
            operator_endpoint: endpoint.as_ref().map(|e| e.hint.clone()),
            policy,
            save_committed: input.save_committed,
        };
        opts.validate().map_err(WasmError::from)?;
        let operator_relay_key = endpoint.and_then(|e| e.relay_key);
        check_relay_keys_agree(
            operator_relay_key,
            self.uri.as_ref().and_then(|u| u.relay_pub),
        )?;
        self.opts = opts;
        self.operator_relay_key = operator_relay_key;
        self.winner_hint = input.winner_hint.filter(|h| !h.is_empty());
        Ok(())
    }

    fn check_for(&self, host_signing: &HybridSigningPublicKey) -> RouteCheck {
        self.uri.as_ref().map_or(
            RouteCheck::Unsigned(tendril_core::pairing::UnsignedReason::Absent),
            |uri| uri.verify_route_statement(host_signing),
        )
    }

    /// `rp` of the URI and the operator `URL#key`, when present, name the verified host's
    /// Ed25519 key.
    fn relay_pub_ok(&self, host_signing: &HybridSigningPublicKey) -> bool {
        let uri_ok = self
            .uri
            .as_ref()
            .is_none_or(|uri| uri.check_relay_pub(host_signing).is_ok());
        let operator_ok = self
            .operator_relay_key
            .is_none_or(|key| key == *host_signing.ed25519_bytes());
        uri_ok && operator_ok
    }

    /// Records the check of the verified host and returns the host-verified report.
    fn host_verified_json(
        &mut self,
        host: &tendril_core::pairing::VerifiedHost,
    ) -> serde_json::Value {
        let check = self.check_for(&host.signing_pub);
        let route_seq = check
            .statement()
            .and_then(|s| u64_to_f64(s.route_seq()).ok());
        let relay_pub_ok = self.relay_pub_ok(&host.signing_pub);
        let report = json!({
            "host_verified": true,
            "host_id": host.host_id,
            "relay_pub_ok": relay_pub_ok,
            "route_check": check.as_str(),
            "route_seq": route_seq,
        });
        self.check = Some(check);
        self.relay_pub_ok = Some(relay_pub_ok);
        report
    }

    fn plan(&self, host_signing: &HybridSigningPublicKey) -> (PersistPlan, &'static str) {
        let check = self
            .check
            .clone()
            .unwrap_or_else(|| self.check_for(host_signing));
        let label = check.as_str();
        (
            persistable_routes(&check, &self.code, self.winner_hint.as_deref(), &self.opts),
            label,
        )
    }
}

fn annotate_outcome(outcome: &mut serde_json::Value, merge: &PairMergeOutcome, route_check: &str) {
    outcome["route_check"] = json!(route_check);
    outcome["routes"] =
        serde_json::Value::Array(merge.persisted.iter().map(stored_route_json).collect());
    outcome["routes_reason"] = json!(merge.reason);
}

/// Sans-I/O pairing initiator driving `Intent::Pair` bytes for JS transport layers.
#[wasm_bindgen]
pub struct WasmPairInitiator {
    inner: Option<PairingInitiator>,
    routes: PairRouteContext,
    started: bool,
}

impl WasmPairInitiator {
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        code: &str,
        host_static_pub_b64: Option<&str>,
        host_signing_pub_b64: Option<&str>,
        host_id: Option<&str>,
        host_rotation_seq: Option<f64>,
        roster_opt: Option<&WasmRoster>,
    ) -> Result<Self, WasmError> {
        let pinned = match (host_static_pub_b64, host_signing_pub_b64) {
            (Some(st), Some(sg)) if !st.is_empty() && !sg.is_empty() => {
                let seq = match host_rotation_seq {
                    Some(v) => f64_to_u64(v, "host_rotation_seq")?,
                    None => 0,
                };
                Some(PinnedHost {
                    host_id: host_id.filter(|h| !h.is_empty()).map(ToOwned::to_owned),
                    static_pub: b64url_decode_array::<32>(st).map_err(WasmError::from)?,
                    signing_pin: parse_signing_pin_b64(sg, "host_signing_pub_b64")?,
                    rotation_seq: seq,
                })
            }
            (None | Some(""), None | Some("")) => None,
            _ => {
                return Err(
                    "both host_static_pub_b64 and host_signing_pub_b64 must be set together"
                        .to_owned()
                        .into(),
                );
            }
        };
        let mut inner = PairingInitiator::new(
            &identity.inner,
            device_name.to_owned(),
            device_kind.to_owned(),
            code.to_owned(),
            pinned.clone(),
            None,
        )
        .map_err(WasmError::from)?;
        if let Some(roster_ref) = roster_opt {
            if let Some(ref p) = pinned {
                let floor = roster_ref.inner.pairing_floor(&p.static_pub);
                inner = inner
                    .with_min_wire_version(floor)
                    .map_err(WasmError::from)?;
            }
            inner = inner.with_roster_floors(&roster_ref.inner);
        }
        Ok(Self {
            inner: Some(inner),
            routes: PairRouteContext::new(code),
            started: false,
        })
    }

    fn machine(&mut self) -> Result<&mut PairingInitiator, WasmError> {
        self.inner
            .as_mut()
            .ok_or_else(|| WasmError::from("pairing initiator unavailable"))
    }

    fn enable_deferred_claim_inner(&mut self) -> Result<(), WasmError> {
        if self.started {
            return Err("the deferred claim is set before start()".to_owned().into());
        }
        let machine = self
            .inner
            .take()
            .ok_or_else(|| WasmError::from("pairing initiator unavailable"))?;
        self.inner = Some(machine.with_deferred_claim());
        Ok(())
    }

    fn commit_claim_inner(&mut self) -> Result<Vec<u8>, WasmError> {
        self.routes.require_committable()?;
        let actions = self.machine()?.commit_claim().map_err(WasmError::from)?;
        let mut out = Vec::new();
        for action in actions {
            if let PairAction::WriteBytes(chunk) = action {
                out.extend_from_slice(&chunk);
            }
        }
        Ok(out)
    }

    fn step_bytes(&mut self, bytes: &[u8], roster: &mut WasmRoster) -> Result<String, WasmError> {
        let actions = self.machine()?.feed_bytes(bytes).map_err(WasmError::from)?;
        let mut writes = Vec::new();
        let mut sas: Option<String> = None;
        let mut outcome_json: Option<serde_json::Value> = None;

        for action in actions {
            match action {
                PairAction::WriteBytes(chunk) => writes.extend_from_slice(&chunk),
                PairAction::SasReady { pairing_sas, .. } => {
                    sas = Some(pairing_sas);
                }
                PairAction::Completed(PairOutcome::InitiatorPending {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    pairing_sas,
                    host_pin_verified,
                }) => {
                    let (plan, route_check) = self.routes.plan(&host_signing_pub);
                    let name = self.routes.host_name(&host_id);
                    let merge = if host_pin_verified {
                        roster.inner.insert_pinned_host_with_plan(
                            host_id.clone(),
                            name,
                            host_static_pub,
                            Some(host_signing_pub),
                            host_rotation_seq,
                            &plan,
                        )
                    } else {
                        roster.inner.record_pending_host_with_plan(
                            host_id.clone(),
                            name,
                            host_static_pub,
                            host_signing_pub,
                            host_rotation_seq,
                            pairing_sas.clone(),
                            &plan,
                        )
                    }
                    .map_err(WasmError::from)?;
                    sas = Some(pairing_sas.clone());
                    let mut outcome = json!({
                        "status": "pending",
                        "device_id": device_id,
                        "host_id": host_id,
                        "sas": pairing_sas,
                        "host_confirmed": host_pin_verified,
                    });
                    annotate_outcome(&mut outcome, &merge, route_check);
                    outcome_json = Some(outcome);
                }
                PairAction::Completed(PairOutcome::InitiatorEnrolled {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    token_nonce,
                }) => {
                    let (plan, route_check) = self.routes.plan(&host_signing_pub);
                    let merge = roster
                        .inner
                        .insert_pinned_host_with_plan(
                            host_id.clone(),
                            host_id.clone(),
                            host_static_pub,
                            Some(host_signing_pub),
                            host_rotation_seq,
                            &plan,
                        )
                        .map_err(WasmError::from)?;
                    let mut outcome = json!({
                        "status": "active",
                        "device_id": device_id,
                        "host_id": host_id,
                        "host_rotation_seq": host_rotation_seq,
                        "token_nonce": token_nonce,
                    });
                    annotate_outcome(&mut outcome, &merge, route_check);
                    outcome_json = Some(outcome);
                }
                PairAction::Completed(PairOutcome::Rejected { error }) => {
                    outcome_json = Some(json!({
                        "status": "rejected",
                        "error": error,
                    }));
                }
                PairAction::Completed(PairOutcome::ResponderPending { .. })
                | PairAction::Completed(PairOutcome::ResponderEnrolled { .. }) => {
                    return Err("unexpected responder outcome".to_owned().into());
                }
                PairAction::CloseTransport(_) => {}
            }
        }

        let awaiting = self.machine()?.is_awaiting_commit();
        let host = if awaiting {
            self.machine()?.verified_host()
        } else {
            None
        };
        if let Some(host) = host {
            let mut report = self.routes.host_verified_json(&host);
            report["sas"] = json!(sas);
            report["outcome"] = serde_json::Value::Null;
            return Ok(report.to_string());
        }

        Ok(json!({
            "write_b64": b64url_encode(&writes),
            "sas": sas,
            "outcome": outcome_json,
        })
        .to_string())
    }

    #[allow(clippy::too_many_arguments)]
    fn new_m2m_inner(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        host_id: &str,
        host_static_pub_b64: &str,
        host_signing_pub_b64: &str,
        host_rotation_seq: Option<f64>,
        token_json: &str,
        roster_opt: Option<&WasmRoster>,
    ) -> Result<Self, WasmError> {
        let seq = match host_rotation_seq {
            Some(v) => f64_to_u64(v, "host_rotation_seq")?,
            None => 0,
        };
        let static_pub = b64url_decode_array::<32>(host_static_pub_b64).map_err(WasmError::from)?;
        let signing_pin = parse_signing_pin_b64(host_signing_pub_b64, "host_signing_pub_b64")?;
        let token: Grant = serde_json::from_str(token_json)
            .map_err(|e| WasmError::from(format!("invalid token_json: {e}")))?;
        let pinned = PinnedHost {
            host_id: Some(host_id.to_owned()),
            static_pub,
            signing_pin,
            rotation_seq: seq,
        };
        let mut inner = PairingInitiator::new_m2m(
            &identity.inner,
            device_name.to_owned(),
            device_kind.to_owned(),
            token,
            pinned,
            None,
        )
        .map_err(WasmError::from)?;
        if let Some(roster_ref) = roster_opt {
            let floor = roster_ref.inner.pairing_floor(&static_pub);
            inner = inner
                .with_min_wire_version(floor)
                .map_err(WasmError::from)?;
            inner = inner.with_roster_floors(&roster_ref.inner);
        }
        Ok(Self {
            inner: Some(inner),
            routes: PairRouteContext::new(""),
            started: false,
        })
    }
}

#[wasm_bindgen]
impl WasmPairInitiator {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        code: &str,
        host_static_pub_b64: Option<String>,
        host_signing_pub_b64: Option<String>,
        host_id: Option<String>,
        host_rotation_seq: Option<f64>,
    ) -> Result<WasmPairInitiator, JsValue> {
        Self::new_inner(
            identity,
            device_name,
            device_kind,
            code,
            host_static_pub_b64.as_deref(),
            host_signing_pub_b64.as_deref(),
            host_id.as_deref(),
            host_rotation_seq,
            None,
        )
        .map_err(to_js_err)
    }

    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_roster(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        code: &str,
        host_static_pub_b64: Option<String>,
        host_signing_pub_b64: Option<String>,
        host_id: Option<String>,
        host_rotation_seq: Option<f64>,
        roster: &WasmRoster,
    ) -> Result<WasmPairInitiator, JsValue> {
        Self::new_inner(
            identity,
            device_name,
            device_kind,
            code,
            host_static_pub_b64.as_deref(),
            host_signing_pub_b64.as_deref(),
            host_id.as_deref(),
            host_rotation_seq,
            Some(roster),
        )
        .map_err(to_js_err)
    }

    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn new_m2m(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        host_id: &str,
        host_static_pub_b64: &str,
        host_signing_pub_b64: &str,
        host_rotation_seq: Option<f64>,
        token_json: &str,
    ) -> Result<WasmPairInitiator, JsValue> {
        Self::new_m2m_inner(
            identity,
            device_name,
            device_kind,
            host_id,
            host_static_pub_b64,
            host_signing_pub_b64,
            host_rotation_seq,
            token_json,
            None,
        )
        .map_err(to_js_err)
    }

    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn new_m2m_with_roster(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        host_id: &str,
        host_static_pub_b64: &str,
        host_signing_pub_b64: &str,
        host_rotation_seq: Option<f64>,
        token_json: &str,
        roster: &WasmRoster,
    ) -> Result<WasmPairInitiator, JsValue> {
        Self::new_m2m_inner(
            identity,
            device_name,
            device_kind,
            host_id,
            host_static_pub_b64,
            host_signing_pub_b64,
            host_rotation_seq,
            token_json,
            Some(roster),
        )
        .map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn start(&mut self) -> Result<Vec<u8>, JsValue> {
        let actions = self
            .machine()
            .map_err(to_js_err)?
            .start()
            .map_err(to_js_err)?;
        self.started = true;
        let mut out = Vec::new();
        for action in actions {
            if let PairAction::WriteBytes(chunk) = action {
                out.extend_from_slice(&chunk);
            }
        }
        Ok(out)
    }

    /// Defers `msg3`: a verified `msg2` makes `feed_bytes` report `host_verified: true` (with
    /// `relay_pub_ok` and `route_check`, and no `write_b64`) until [`Self::commit_claim`].
    /// Valid only before `start()`.
    #[wasm_bindgen]
    pub fn enable_deferred_claim(&mut self) -> Result<(), JsValue> {
        self.enable_deferred_claim_inner().map_err(to_js_err)
    }

    /// Supplies the pairing URI whose `rp` and route statement are checked against the
    /// verified host. Valid before `msg2` is processed.
    #[wasm_bindgen]
    pub fn set_pairing_uri(&mut self, uri: &str) -> Result<(), JsValue> {
        self.routes.set_uri(uri).map_err(to_js_err)
    }

    /// Sets the route persist options: `route_policy`, `operator_endpoint`, `save_committed`
    /// and `winner_hint`, as a JSON object.
    #[wasm_bindgen]
    pub fn set_persist_options(&mut self, opts_json: &str) -> Result<(), JsValue> {
        self.routes.set_options(opts_json).map_err(to_js_err)
    }

    /// Writes `msg3` once `feed_bytes` reported `host_verified: true`. Refused, with code
    /// `host_key_unverified`, when `relay_pub_ok` was false, and with `invalid_pairing_uri`
    /// when `route_check` was `invalid`.
    #[wasm_bindgen]
    pub fn commit_claim(&mut self) -> Result<Vec<u8>, JsValue> {
        self.commit_claim_inner().map_err(to_js_err)
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn is_awaiting_commit(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(PairingInitiator::is_awaiting_commit)
    }

    #[wasm_bindgen]
    pub fn feed_bytes(&mut self, bytes: &[u8], roster: &mut WasmRoster) -> Result<String, JsValue> {
        self.step_bytes(bytes, roster).map_err(to_js_err)
    }
}

/// What an initiator session learned from `HostHello`, kept after its machine is gone.
#[derive(Default)]
struct SessionEvidence {
    presented_rotation: Vec<RotationRecord>,
    recovery: Option<VerifiedRouteStatement>,
    host_keys: Option<(String, String)>,
}

impl SessionEvidence {
    fn capture(&mut self, rotation: &[RotationRecord], recovery: Option<&VerifiedRouteStatement>) {
        if !rotation.is_empty() {
            self.presented_rotation = rotation.to_vec();
        }
        if let Some(statement) = recovery {
            self.recovery = Some(statement.clone());
        }
    }

    /// Records the keys of the authenticated handshake: the Noise static key and the signing
    /// key `HostHello` verified, read from the entry the session verified against.
    fn record_host_keys(
        &mut self,
        static_pub: &[u8; 32],
        verified_entry: Option<&tendril_core::roster::RosterEntry>,
    ) {
        if let Some(signing) = verified_entry.and_then(|e| e.signing_pub.as_ref()) {
            self.host_keys = Some((b64url_encode(static_pub), signing.to_b64url()));
        }
    }

    fn rotation_json(&self) -> Result<String, WasmError> {
        serde_json::to_string(&self.presented_rotation).map_err(WasmError::from)
    }

    fn recovery_json(&self) -> Option<String> {
        let statement = self.recovery.as_ref()?;
        Some(
            json!({
                "route_seq": u64_to_f64(statement.route_seq()).ok(),
                "hints": statement.hints(),
                "relay_pub_b64": statement.relay_pub().map(|k| b64url_encode(k)),
                "host_id": statement.host_id(),
                "rotation_seq": statement.rotation_seq().and_then(|s| u64_to_f64(s).ok()),
            })
            .to_string(),
        )
    }

    fn host_keys_json(&self, wire: u8) -> Option<String> {
        let (static_pub, signing_pub) = self.host_keys.as_ref()?;
        Some(
            json!({
                "static_pub_b64": static_pub,
                "signing_pub_b64": signing_pub,
                "wire": wire,
            })
            .to_string(),
        )
    }
}

fn require_unstarted(started: bool) -> Result<(), WasmError> {
    if started {
        return Err(WasmError::from(tendril_core::error::CoreError::NotReady(
            "route options are set on an initiator before start()",
        )));
    }
    Ok(())
}

fn parse_route_expectation(
    target_peer_id: &str,
    recovery_uri: Option<&str>,
    relay_key_b64: Option<&str>,
) -> Result<RouteExpectation, WasmError> {
    let operator_key = match relay_key_b64 {
        Some(k) if !k.is_empty() => {
            let key = b64url_decode_array::<32>(k)
                .map_err(|e| invalid_route(format!("invalid relay key: {e}")))?;
            if !is_valid_ed25519_public_key(&key) {
                return Err(invalid_route(
                    "invalid relay key: not an Ed25519 public key",
                ));
            }
            Some(key)
        }
        _ => None,
    };
    RouteExpectation::for_connect(
        target_peer_id,
        recovery_uri.filter(|u| !u.is_empty()),
        operator_key,
        None,
    )
    .map_err(WasmError::from)
}

fn route_seq_arg(route_seq: Option<f64>) -> Result<Option<u64>, WasmError> {
    route_seq.map(|v| f64_to_u64(v, "route_seq")).transpose()
}

fn route_sets_json(sets: &[RouteSet]) -> String {
    serde_json::Value::Array(
        sets.iter()
            .map(|set| json!(b64url_encode(&set.encode())))
            .collect(),
    )
    .to_string()
}

/// Sans-I/O authenticated `Intent::Session` client state machine.
#[wasm_bindgen]
pub struct WasmSessionClient {
    inner: Option<SessionMachine>,
    target_host_id: String,
    peer_device_id: Option<String>,
    pending_rendezvous: Vec<GroupRendezvousFrame>,
    evidence: SessionEvidence,
    started: bool,
}

impl WasmSessionClient {
    fn new_inner(
        identity: &WasmIdentity,
        target_host_id: &str,
        grant_json: Option<&str>,
        crl_seq: Option<f64>,
    ) -> Result<Self, WasmError> {
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.is_empty() => Some(serde_json::from_str(s).map_err(WasmError::from)?),
            _ => None,
        };
        let cseq = match crl_seq {
            Some(v) => Some(f64_to_u64(v, "crl_seq")?),
            None => None,
        };
        let inner = SessionMachine::new_initiator(
            &identity.inner,
            target_host_id.to_owned(),
            grant,
            cseq,
            None,
        )
        .map_err(WasmError::from)?;
        Ok(Self {
            inner: Some(inner),
            target_host_id: target_host_id.to_owned(),
            peer_device_id: None,
            pending_rendezvous: Vec::new(),
            evidence: SessionEvidence::default(),
            started: false,
        })
    }

    fn machine(&self) -> Result<&SessionMachine, WasmError> {
        self.inner
            .as_ref()
            .ok_or_else(|| WasmError::from("session unavailable"))
    }

    fn machine_mut(&mut self) -> Result<&mut SessionMachine, WasmError> {
        self.inner
            .as_mut()
            .ok_or_else(|| WasmError::from("session unavailable"))
    }

    /// Keeps what `HostHello` showed, whatever the outcome of the handshake.
    fn capture_evidence(&mut self) {
        if let Some(machine) = &self.inner {
            self.evidence.capture(
                machine.presented_rotation(),
                machine.verified_recovery_statement(),
            );
        }
    }

    fn with_route_expectation_inner(
        &mut self,
        target_peer_id: &str,
        recovery_uri: Option<&str>,
        relay_key_b64: Option<&str>,
    ) -> Result<(), WasmError> {
        require_unstarted(self.started)?;
        let expectation = parse_route_expectation(target_peer_id, recovery_uri, relay_key_b64)?;
        let machine = self
            .inner
            .take()
            .ok_or_else(|| WasmError::from("session unavailable"))?;
        self.inner = Some(
            machine
                .with_route_expectation(expectation)
                .map_err(WasmError::from)?,
        );
        Ok(())
    }

    fn with_route_seq_inner(&mut self, route_seq: Option<f64>) -> Result<(), WasmError> {
        require_unstarted(self.started)?;
        let seq = route_seq_arg(route_seq)?;
        let machine = self
            .inner
            .take()
            .ok_or_else(|| WasmError::from("session unavailable"))?;
        self.inner = Some(machine.with_route_seq(seq).map_err(WasmError::from)?);
        Ok(())
    }

    fn take_route_sets_json(&mut self) -> Result<String, WasmError> {
        let sets = self.machine_mut()?.take_route_sets();
        Ok(route_sets_json(&sets))
    }

    fn step_bytes(
        &mut self,
        bytes: &[u8],
        now_unix: f64,
        now_ms: f64,
        roster: &mut WasmRoster,
    ) -> Result<String, WasmError> {
        let now_u = f64_to_u64(now_unix, "now_unix")?;
        let now_m = f64_to_u64(now_ms, "now_ms")?;
        let result = self
            .machine_mut()?
            .feed_bytes(bytes, now_u, now_m, &mut roster.inner);
        self.capture_evidence();
        let actions = result.map_err(WasmError::from)?;

        let mut writes = Vec::new();
        let mut events = Vec::new();
        for action in actions {
            match action {
                SessionAction::WriteBytes(chunk) => writes.extend_from_slice(&chunk),
                SessionAction::Established {
                    peer_static_pub, ..
                } => {
                    self.peer_device_id = Some(core_device_id(&peer_static_pub));
                    self.evidence
                        .record_host_keys(&peer_static_pub, roster.inner.get(&self.target_host_id));
                }
                SessionAction::AppData(data) => events.push(json!({
                    "event": "data",
                    "data_b64": b64url_encode(&data),
                })),
                SessionAction::Rekeyed { direction } => events.push(json!({
                    "event": "rekeyed",
                    "direction": format!("{direction:?}"),
                })),
                SessionAction::GrantUpdated(g) => events.push(json!({
                    "event": "grant_updated",
                    "grant": g,
                })),
                SessionAction::RevocationUpdated { issuer, seq } => events.push(json!({
                    "event": "revocation_updated",
                    "issuer": issuer,
                    "seq": seq,
                })),
                SessionAction::GroupManifestReceived(manifest) => events.push(json!({
                    "event": "group_manifest_unverified",
                    "group_id": manifest.group_id,
                    "seq": manifest.seq,
                    "manifest_json": manifest_wire_json(&manifest)?,
                })),
                SessionAction::GroupRendezvousReceived(frame) => {
                    events.push(json!({
                        "event": "group_rendezvous_unverified",
                        "group_id": frame.group_id,
                        "seq": frame.seq,
                    }));
                    if self.pending_rendezvous.len() >= MAX_PENDING_RENDEZVOUS {
                        self.pending_rendezvous.remove(0);
                    }
                    self.pending_rendezvous.push(frame);
                }
                SessionAction::PongReceived(cookie) => events.push(json!({
                    "event": "pong",
                    "cookie": cookie,
                })),
                SessionAction::Audit(audit) => events.push(json!({
                    "event": "audit",
                    "audit": audit,
                })),
                SessionAction::CloseTransport { code, reason } => events.push(json!({
                    "event": "closed",
                    "code": code,
                    "reason": reason,
                })),
            }
        }

        Ok(json!({
            "write_b64": b64url_encode(&writes),
            "established": self.is_established(),
            "closed": self.is_closed(),
            "events": events,
        })
        .to_string())
    }
}

#[wasm_bindgen]
impl WasmSessionClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        identity: &WasmIdentity,
        target_host_id: &str,
        grant_json: Option<String>,
        crl_seq: Option<f64>,
    ) -> Result<WasmSessionClient, JsValue> {
        Self::new_inner(identity, target_host_id, grant_json.as_deref(), crl_seq).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn new_with_roster(
        identity: &WasmIdentity,
        target_host_id: &str,
        roster: &WasmRoster,
        grant_json: Option<String>,
        crl_seq: Option<f64>,
    ) -> Result<WasmSessionClient, JsValue> {
        check_peer_allows_wire_v1(&roster.inner, target_host_id).map_err(to_js_err)?;
        Self::new_inner(identity, target_host_id, grant_json.as_deref(), crl_seq).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn start(&mut self) -> Result<Vec<u8>, JsValue> {
        let actions = self
            .machine_mut()
            .map_err(to_js_err)?
            .start()
            .map_err(to_js_err)?;
        self.started = true;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    pub fn feed_bytes(
        &mut self,
        bytes: &[u8],
        now_unix: f64,
        now_ms: f64,
        roster: &mut WasmRoster,
    ) -> Result<String, JsValue> {
        self.step_bytes(bytes, now_unix, now_ms, roster)
            .map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn send_data(&mut self, payload: &[u8], now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let actions = self
            .machine_mut()
            .map_err(to_js_err)?
            .send_data(payload, now_m)
            .map_err(to_js_err)?;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    pub fn send_rekey(&mut self, now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let actions = self
            .machine_mut()
            .map_err(to_js_err)?
            .send_rekey(now_m)
            .map_err(to_js_err)?;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    pub fn send_ping(&mut self, cookie: f64, now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let c = f64_to_u64(cookie, "cookie").map_err(to_js_err)?;
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let actions = self
            .machine_mut()
            .map_err(to_js_err)?
            .send_ping(c, now_m)
            .map_err(to_js_err)?;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    pub fn send_close(&mut self, code: f64, reason: &str) -> Result<Vec<u8>, JsValue> {
        let close_code = f64_to_u16(code, "code").map_err(to_js_err)?;
        let actions = self
            .machine_mut()
            .map_err(to_js_err)?
            .send_close(close_code, reason)
            .map_err(to_js_err)?;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    pub fn tick(
        &mut self,
        now_unix: f64,
        now_ms: f64,
        roster: &WasmRoster,
    ) -> Result<Vec<u8>, JsValue> {
        let now_u = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let actions = self
            .machine_mut()
            .map_err(to_js_err)?
            .tick(now_u, now_m, &roster.inner)
            .map_err(to_js_err)?;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn authorize(&self, requested_cap: &str, now_unix: f64, roster: &WasmRoster) -> bool {
        let Ok(now_u) = f64_to_u64(now_unix, "now_unix") else {
            return false;
        };
        self.machine()
            .is_ok_and(|m| m.authorize(requested_cap, now_u, &roster.inner).0.is_ok())
    }

    /// Device id derived from the static key authenticated by the handshake, once established.
    #[wasm_bindgen]
    #[must_use]
    pub fn peer_device_id(&self) -> Option<String> {
        self.peer_device_id.clone()
    }

    /// Applies buffered `0x0B` frames to `book` as delivered by this authenticated peer.
    ///
    /// Frames stay inside WASM memory; the returned JSON carries group ids and errors only.
    #[wasm_bindgen]
    pub fn apply_group_rendezvous(
        &mut self,
        book: &mut WasmGroupBook,
        roster: &WasmRoster,
        now_unix: f64,
    ) -> Result<String, JsValue> {
        let now = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        let frames = std::mem::take(&mut self.pending_rendezvous);
        Ok(book
            .apply_rendezvous_inner(&roster.inner, self.peer_device_id.as_deref(), &frames, now)
            .to_string())
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(SessionMachine::is_established)
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.as_ref().is_none_or(SessionMachine::is_closed)
    }

    /// Sets what the connect expects of the host, checked against `HostHello` before `msg3`.
    /// Valid only before `start()`.
    #[wasm_bindgen]
    pub fn with_route_expectation(
        &mut self,
        target_peer_id: &str,
        recovery_uri: Option<String>,
        relay_key_b64: Option<String>,
    ) -> Result<(), JsValue> {
        self.with_route_expectation_inner(
            target_peer_id,
            recovery_uri.as_deref(),
            relay_key_b64.as_deref(),
        )
        .map_err(to_js_err)
    }

    /// Sets `SessionHello.route_seq` (opting in to route sets). Valid only before `start()`.
    #[wasm_bindgen]
    pub fn with_route_seq(&mut self, route_seq: Option<f64>) -> Result<(), JsValue> {
        self.with_route_seq_inner(route_seq).map_err(to_js_err)
    }

    /// `HostHello.rotation` records the host presented (JSON array), kept on every outcome.
    #[wasm_bindgen]
    pub fn presented_rotation_json(&self) -> Result<String, JsValue> {
        self.evidence.rotation_json().map_err(to_js_err)
    }

    /// The recovery URI's route statement verified under the presented host key, as JSON, or
    /// `undefined` when there is none.
    #[wasm_bindgen]
    #[must_use]
    pub fn verified_recovery_statement_json(&self) -> Option<String> {
        self.evidence.recovery_json()
    }

    /// Keys the host presented, `{static_pub_b64, signing_pub_b64, wire}`, once established.
    #[wasm_bindgen]
    #[must_use]
    pub fn presented_host_keys_json(&self) -> Option<String> {
        self.evidence.host_keys_json(1)
    }

    /// Drains the received `0x0C` route sets as a JSON array of base64url payloads, to be
    /// applied with `WasmRoster.apply_route_announcement`.
    #[wasm_bindgen]
    pub fn take_route_sets(&mut self) -> Result<String, JsValue> {
        self.take_route_sets_json().map_err(to_js_err)
    }
}

#[derive(Deserialize)]
struct WasmV2PinnedHostInput {
    #[serde(default)]
    host_id: Option<String>,
    static_pub_b64: String,
    signing_pub_b64: String,
    #[serde(default)]
    rotation_seq: Option<u64>,
    #[serde(default)]
    min_wire_version: Option<u8>,
}

/// Sans-I/O Wire v2 (`0x02`) PAKE pairing initiator for JS transport layers.
#[wasm_bindgen]
pub struct WasmV2PakePairInitiator {
    inner: Option<V2PakePairInitiator>,
    pending_events: Vec<serde_json::Value>,
    routes: PairRouteContext,
    started: bool,
}

impl WasmV2PakePairInitiator {
    fn new_inner(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        code: &str,
        pinned_host_json: Option<&str>,
    ) -> Result<Self, WasmError> {
        let pinned = match pinned_host_json {
            Some(raw) if !raw.trim().is_empty() => {
                let parsed: WasmV2PinnedHostInput = serde_json::from_str(raw)
                    .map_err(|e| WasmError::from(format!("invalid pinned_host_json: {e}")))?;
                let static_pub =
                    b64url_decode_array::<32>(&parsed.static_pub_b64).map_err(WasmError::from)?;
                let signing_pin =
                    parse_signing_pin_b64(&parsed.signing_pub_b64, "signing_pub_b64")?;
                let base = PinnedHost {
                    host_id: parsed.host_id.filter(|h| !h.is_empty()),
                    static_pub,
                    signing_pin,
                    rotation_seq: parsed.rotation_seq.unwrap_or(0),
                };
                Some(
                    V2PinnedHost::new(base, parsed.min_wire_version.unwrap_or(WIRE_VERSION_V2))
                        .map_err(WasmError::from)?,
                )
            }
            _ => None,
        };
        let inner = V2PakePairInitiator::new(
            &identity.inner,
            device_name,
            device_kind,
            code,
            pinned,
            PakeArgon2Params::default(),
        )
        .map_err(WasmError::from)?;
        Ok(Self {
            inner: Some(inner),
            pending_events: Vec::new(),
            routes: PairRouteContext::new(code),
            started: false,
        })
    }

    fn machine(&mut self) -> Result<&mut V2PakePairInitiator, WasmError> {
        self.inner
            .as_mut()
            .ok_or_else(|| WasmError::from("pairing initiator unavailable"))
    }

    fn enable_deferred_claim_inner(&mut self) -> Result<(), WasmError> {
        if self.started {
            return Err("the deferred claim is set before start()".to_owned().into());
        }
        let machine = self
            .inner
            .take()
            .ok_or_else(|| WasmError::from("pairing initiator unavailable"))?;
        self.inner = Some(machine.with_deferred_claim());
        Ok(())
    }

    fn commit_claim_inner(&mut self) -> Result<Vec<u8>, WasmError> {
        self.routes.require_committable()?;
        let actions = self.machine()?.commit_claim().map_err(WasmError::from)?;
        Ok(collect_v2_pair_writes(actions))
    }

    fn step_bytes(&mut self, bytes: &[u8], roster: &mut WasmRoster) -> Result<String, WasmError> {
        let actions = self.machine()?.feed_bytes(bytes).map_err(WasmError::from)?;
        let mut writes = Vec::new();
        let mut sas: Option<String> = None;
        let mut outcome_json: Option<serde_json::Value> = None;

        for action in actions {
            match action {
                V2PairAction::WriteBytes(chunk) => writes.extend_from_slice(&chunk),
                V2PairAction::SasReady {
                    pairing_sas,
                    host_id,
                    ..
                } => {
                    sas = Some(pairing_sas.clone());
                    self.pending_events.push(json!({
                        "event": "sas_ready",
                        "sas": pairing_sas,
                        "host_id": host_id,
                    }));
                }
                V2PairAction::Completed(
                    ref outcome @ V2PairOutcome::InitiatorPending {
                        ref device_id,
                        ref host_id,
                        ref host_signing_pub,
                        ref pairing_sas,
                        host_pin_verified,
                        ..
                    },
                ) => {
                    let (plan, route_check) = self.routes.plan(host_signing_pub);
                    let (_, merge) = roster
                        .inner
                        .apply_v2_pair_initiator_outcome_with_plan(
                            outcome,
                            self.routes.host_name(host_id),
                            &plan,
                        )
                        .map_err(WasmError::from)?;
                    sas = Some(pairing_sas.clone());
                    let mut obj = json!({
                        "status": "pending",
                        "device_id": device_id,
                        "host_id": host_id,
                        "sas": pairing_sas,
                        "host_confirmed": host_pin_verified,
                    });
                    annotate_outcome(&mut obj, &merge, route_check);
                    self.pending_events.push(json!({
                        "event": "completed",
                        "outcome": obj,
                    }));
                    outcome_json = Some(obj);
                }
                V2PairAction::Completed(V2PairOutcome::Rejected { error }) => {
                    let obj = json!({
                        "status": "rejected",
                        "error": error,
                    });
                    self.pending_events.push(json!({
                        "event": "completed",
                        "outcome": obj,
                    }));
                    outcome_json = Some(obj);
                }
                V2PairAction::Completed(V2PairOutcome::ResponderPending { .. }) => {
                    return Err("unexpected responder outcome".to_owned().into());
                }
                V2PairAction::CloseTransport(reason) => {
                    self.pending_events.push(json!({
                        "event": "close_transport",
                        "reason": reason,
                    }));
                }
            }
        }

        let awaiting = self.machine()?.is_awaiting_commit();
        let host = if awaiting {
            self.machine()?.verified_host()
        } else {
            None
        };
        if let Some(host) = host {
            let mut report = self.routes.host_verified_json(&host);
            report["sas"] = json!(sas);
            report["outcome"] = serde_json::Value::Null;
            self.pending_events.push(json!({
                "event": "host_verified",
                "host_id": report["host_id"],
                "relay_pub_ok": report["relay_pub_ok"],
                "route_check": report["route_check"],
            }));
            return Ok(report.to_string());
        }

        Ok(json!({
            "write_b64": b64url_encode(&writes),
            "sas": sas,
            "outcome": outcome_json,
        })
        .to_string())
    }
}

fn collect_v2_pair_writes(actions: Vec<V2PairAction>) -> Vec<u8> {
    let mut out = Vec::new();
    for action in actions {
        if let V2PairAction::WriteBytes(chunk) = action {
            out.extend_from_slice(&chunk);
        }
    }
    out
}

#[wasm_bindgen]
impl WasmV2PakePairInitiator {
    #[wasm_bindgen(constructor)]
    pub fn new(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        code: &str,
        pinned_host_json: Option<String>,
    ) -> Result<WasmV2PakePairInitiator, JsValue> {
        Self::new_inner(
            identity,
            device_name,
            device_kind,
            code,
            pinned_host_json.as_deref(),
        )
        .map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn new_bytes(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        code: &mut [u8],
        pinned_host_json: Option<String>,
    ) -> Result<WasmV2PakePairInitiator, JsValue> {
        let res = match core::str::from_utf8(code) {
            Ok(code_str) => Self::new_inner(
                identity,
                device_name,
                device_kind,
                code_str,
                pinned_host_json.as_deref(),
            )
            .map_err(to_js_err),
            Err(err) => Err(to_js_err(format!("invalid UTF-8 pairing code: {err}"))),
        };
        code.zeroize();
        res
    }

    #[wasm_bindgen]
    pub fn start(&mut self) -> Result<Vec<u8>, JsValue> {
        let actions = self
            .machine()
            .map_err(to_js_err)?
            .start()
            .map_err(to_js_err)?;
        self.started = true;
        Ok(collect_v2_pair_writes(actions))
    }

    /// Defers `msg3`: a verified `msg2` makes `feed_bytes` report `host_verified: true` (with
    /// `relay_pub_ok` and `route_check`, and no `write_b64`) until [`Self::commit_claim`].
    /// Valid only before `start()`.
    #[wasm_bindgen]
    pub fn enable_deferred_claim(&mut self) -> Result<(), JsValue> {
        self.enable_deferred_claim_inner().map_err(to_js_err)
    }

    /// Supplies the pairing URI whose `rp` and route statement are checked against the
    /// verified host. Valid before `msg2` is processed.
    #[wasm_bindgen]
    pub fn set_pairing_uri(&mut self, uri: &str) -> Result<(), JsValue> {
        self.routes.set_uri(uri).map_err(to_js_err)
    }

    /// Sets the route persist options: `route_policy`, `operator_endpoint`, `save_committed`
    /// and `winner_hint`, as a JSON object.
    #[wasm_bindgen]
    pub fn set_persist_options(&mut self, opts_json: &str) -> Result<(), JsValue> {
        self.routes.set_options(opts_json).map_err(to_js_err)
    }

    /// Writes `msg3` once `feed_bytes` reported `host_verified: true`. Refused, with code
    /// `host_key_unverified`, when `relay_pub_ok` was false, and with `invalid_pairing_uri`
    /// when `route_check` was `invalid`.
    #[wasm_bindgen]
    pub fn commit_claim(&mut self) -> Result<Vec<u8>, JsValue> {
        self.commit_claim_inner().map_err(to_js_err)
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn is_awaiting_commit(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(V2PakePairInitiator::is_awaiting_commit)
    }

    #[wasm_bindgen]
    pub fn feed_bytes(&mut self, bytes: &[u8], roster: &mut WasmRoster) -> Result<String, JsValue> {
        self.step_bytes(bytes, roster).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn drain_events_json(&mut self) -> String {
        serde_json::Value::Array(std::mem::take(&mut self.pending_events)).to_string()
    }
}

enum V2WasmSessionPhase {
    Active(Box<V2SessionInitiator>),
    Closed,
}

fn collect_v2_writes(actions: Vec<V2SessionAction>) -> Vec<u8> {
    let mut out = Vec::new();
    for action in actions {
        if let V2SessionAction::WriteBytes(chunk) = action {
            out.extend_from_slice(&chunk);
        }
    }
    out
}

/// Sans-I/O Wire v2 (`0x02`) pseudonymous session initiator for JS transport layers.
#[wasm_bindgen]
pub struct WasmV2SessionInitiator {
    phase: V2WasmSessionPhase,
    target_host_id: String,
    peer_device_id: Option<String>,
    pending_rendezvous: Vec<GroupRendezvousFrame>,
    pending_writes: Vec<u8>,
    pending_events: Vec<serde_json::Value>,
    evidence: SessionEvidence,
    started: bool,
}

impl WasmV2SessionInitiator {
    fn new_inner(
        identity: &WasmIdentity,
        target_host_id: &str,
        roster: &WasmRoster,
        grant_json: Option<&str>,
        crl_seq: Option<f64>,
    ) -> Result<Self, WasmError> {
        let secrets = roster.peer_v2_secrets(target_host_id)?;
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.trim().is_empty() => {
                Some(serde_json::from_str(s).map_err(WasmError::from)?)
            }
            _ => None,
        };
        let cseq = match crl_seq {
            Some(v) => Some(f64_to_u64(v, "crl_seq")?),
            None => roster.inner.crl(target_host_id).map(|c| c.seq),
        };
        let machine = V2SessionInitiator::new(
            &identity.inner,
            target_host_id,
            *secrets.reconnect_secret(),
            grant,
            cseq,
        )
        .map_err(WasmError::from)?
        .with_padding_policy(PaddingPolicy::v2_default());
        Ok(Self {
            phase: V2WasmSessionPhase::Active(Box::new(machine)),
            target_host_id: target_host_id.to_owned(),
            peer_device_id: None,
            pending_rendezvous: Vec::new(),
            pending_writes: Vec::new(),
            pending_events: Vec::new(),
            evidence: SessionEvidence::default(),
            started: false,
        })
    }

    fn with_route_expectation_inner(
        &mut self,
        target_peer_id: &str,
        recovery_uri: Option<&str>,
        relay_key_b64: Option<&str>,
    ) -> Result<(), WasmError> {
        require_unstarted(self.started)?;
        let expectation = parse_route_expectation(target_peer_id, recovery_uri, relay_key_b64)?;
        let V2WasmSessionPhase::Active(machine) =
            std::mem::replace(&mut self.phase, V2WasmSessionPhase::Closed)
        else {
            return Err("v2 session closed".to_owned().into());
        };
        let machine = (*machine)
            .with_route_expectation(expectation)
            .map_err(WasmError::from)?;
        self.phase = V2WasmSessionPhase::Active(Box::new(machine));
        Ok(())
    }

    fn with_route_seq_inner(&mut self, route_seq: Option<f64>) -> Result<(), WasmError> {
        require_unstarted(self.started)?;
        let seq = route_seq_arg(route_seq)?;
        let V2WasmSessionPhase::Active(machine) =
            std::mem::replace(&mut self.phase, V2WasmSessionPhase::Closed)
        else {
            return Err("v2 session closed".to_owned().into());
        };
        let machine = (*machine).with_route_seq(seq).map_err(WasmError::from)?;
        self.phase = V2WasmSessionPhase::Active(Box::new(machine));
        Ok(())
    }

    fn take_route_sets_json(&mut self) -> String {
        match self.phase {
            V2WasmSessionPhase::Active(ref mut machine) => {
                route_sets_json(&machine.take_route_sets())
            }
            V2WasmSessionPhase::Closed => "[]".to_owned(),
        }
    }

    fn push_v2_action(
        &mut self,
        action: V2SessionAction,
        roster: &mut Roster,
    ) -> Result<(), WasmError> {
        match action {
            V2SessionAction::WriteBytes(chunk) => {
                self.pending_writes.extend_from_slice(&chunk);
            }
            V2SessionAction::Established {
                peer_device_id,
                peer_static_pub,
                ..
            } => {
                roster
                    .set_peer_min_wire_version(&self.target_host_id, WIRE_VERSION_V2)
                    .map_err(WasmError::from)?;
                self.evidence
                    .record_host_keys(&peer_static_pub, roster.get(&self.target_host_id));
                self.peer_device_id = Some(core_device_id(&peer_static_pub));
                self.pending_events.push(json!({
                    "event": "established",
                    "peer_device_id": peer_device_id,
                }));
            }
            V2SessionAction::AppData(data) => {
                self.pending_events.push(json!({
                    "event": "data",
                    "data_b64": b64url_encode(&data),
                }));
            }
            V2SessionAction::GrantUpdated(g) => {
                self.pending_events.push(json!({
                    "event": "grant_updated",
                    "grant": g,
                }));
            }
            V2SessionAction::RevocationUpdated { issuer, seq } => {
                let seq_f64 = u64_to_f64(seq)?;
                self.pending_events.push(json!({
                    "event": "revocation_updated",
                    "issuer": issuer,
                    "seq": seq_f64,
                }));
            }
            V2SessionAction::Rekeyed { direction } => {
                self.pending_events.push(json!({
                    "event": "rekeyed",
                    "direction": format!("{direction:?}"),
                }));
            }
            V2SessionAction::GroupManifestReceived(manifest) => {
                self.pending_events.push(json!({
                    "event": "group_manifest_unverified",
                    "group_id": manifest.group_id,
                    "seq": manifest.seq,
                    "manifest_json": manifest_wire_json(&manifest)?,
                }));
            }
            V2SessionAction::GroupRendezvousReceived(frame) => {
                #[allow(clippy::cast_precision_loss)]
                let seq_f64 = frame.seq as f64;
                self.pending_events.push(json!({
                    "event": "group_rendezvous_unverified",
                    "group_id": frame.group_id,
                    "seq": seq_f64,
                }));
                if self.pending_rendezvous.len() >= MAX_PENDING_RENDEZVOUS {
                    self.pending_rendezvous.remove(0);
                }
                self.pending_rendezvous.push(frame);
            }
            V2SessionAction::PongReceived(cookie) => {
                let cookie_f64 = u64_to_f64(cookie).unwrap_or(0.0);
                self.pending_events.push(json!({
                    "event": "pong",
                    "cookie": cookie_f64,
                }));
            }
            V2SessionAction::Audit(audit) => {
                self.pending_events.push(json!({
                    "event": "audit",
                    "audit": audit,
                }));
            }
            V2SessionAction::CloseTransport { code, reason } => {
                self.pending_events.push(json!({
                    "event": "closed",
                    "code": code,
                    "reason": reason,
                }));
            }
        }
        Ok(())
    }

    fn step_bytes(
        &mut self,
        chunk: &[u8],
        now_unix: f64,
        now_ms: f64,
        roster: &mut WasmRoster,
    ) -> Result<String, WasmError> {
        let now_u = f64_to_u64(now_unix, "now_unix")?;
        let now_m = f64_to_u64(now_ms, "now_ms")?;
        let prev = std::mem::replace(&mut self.phase, V2WasmSessionPhase::Closed);
        let mut machine = match prev {
            V2WasmSessionPhase::Active(m) => m,
            V2WasmSessionPhase::Closed => return Err("v2 session closed".to_owned().into()),
        };
        let result = machine.feed_bytes(chunk, now_u, now_m, &mut roster.inner);
        self.evidence.capture(
            machine.presented_rotation(),
            machine.verified_recovery_statement(),
        );
        let actions = match result {
            Ok(a) => a,
            Err(err) => {
                if !machine.is_closed() {
                    self.phase = V2WasmSessionPhase::Active(machine);
                }
                return Err(WasmError::from(err));
            }
        };
        for action in actions {
            if let Err(err) = self.push_v2_action(action, &mut roster.inner) {
                if !machine.is_closed() {
                    self.phase = V2WasmSessionPhase::Active(machine);
                }
                return Err(err);
            }
        }
        if !machine.is_closed() {
            self.phase = V2WasmSessionPhase::Active(machine);
        }

        Ok(json!({
            "established": self.is_established(),
            "closed": self.is_closed(),
            "has_writes": !self.pending_writes.is_empty(),
            "event_count": self.pending_events.len(),
        })
        .to_string())
    }
}

#[wasm_bindgen]
impl WasmV2SessionInitiator {
    #[wasm_bindgen(constructor)]
    pub fn new(
        identity: &WasmIdentity,
        target_host_id: &str,
        roster: &WasmRoster,
        grant_json: Option<String>,
        crl_seq: Option<f64>,
    ) -> Result<WasmV2SessionInitiator, JsValue> {
        Self::new_inner(
            identity,
            target_host_id,
            roster,
            grant_json.as_deref(),
            crl_seq,
        )
        .map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn start(&mut self, now_unix: f64) -> Result<Vec<u8>, JsValue> {
        let now_u = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        let V2WasmSessionPhase::Active(ref mut machine) = self.phase else {
            return Err(to_js_err("v2 session closed"));
        };
        let actions = machine.start(now_u).map_err(to_js_err)?;
        self.started = true;
        Ok(collect_v2_writes(actions))
    }

    #[wasm_bindgen]
    pub fn feed_bytes(
        &mut self,
        chunk: &[u8],
        now_unix: f64,
        now_ms: f64,
        roster: &mut WasmRoster,
    ) -> Result<String, JsValue> {
        self.step_bytes(chunk, now_unix, now_ms, roster)
            .map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn poll_write(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_writes)
    }

    #[wasm_bindgen]
    pub fn drain_events_json(&mut self) -> String {
        serde_json::Value::Array(std::mem::take(&mut self.pending_events)).to_string()
    }

    #[wasm_bindgen]
    pub fn send_data(&mut self, payload: &[u8], now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let V2WasmSessionPhase::Active(ref mut machine) = self.phase else {
            return Err(to_js_err("v2 session closed"));
        };
        let actions = machine.seal_data(payload, now_m).map_err(to_js_err)?;
        Ok(collect_v2_writes(actions))
    }

    #[wasm_bindgen]
    pub fn send_dummy_cover(
        &mut self,
        bucket_size: usize,
        now_ms: f64,
    ) -> Result<Vec<u8>, JsValue> {
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let V2WasmSessionPhase::Active(ref mut machine) = self.phase else {
            return Err(to_js_err("v2 session closed"));
        };
        let actions = machine
            .seal_dummy_cover(bucket_size, now_m)
            .map_err(to_js_err)?;
        Ok(collect_v2_writes(actions))
    }

    #[wasm_bindgen]
    pub fn next_ping_delay_ms(&self) -> Result<f64, JsValue> {
        let V2WasmSessionPhase::Active(ref machine) = self.phase else {
            return Err(to_js_err("v2 session closed"));
        };
        let delay = machine.next_ping_delay_ms().map_err(to_js_err)?;
        u64_to_f64(delay).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn send_ping(&mut self, cookie: f64, now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let c = f64_to_u64(cookie, "cookie").map_err(to_js_err)?;
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let V2WasmSessionPhase::Active(ref mut machine) = self.phase else {
            return Err(to_js_err("v2 session closed"));
        };
        let actions = machine.seal_ping(c, now_m).map_err(to_js_err)?;
        Ok(collect_v2_writes(actions))
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn authorize(&self, requested_cap: &str, now_unix: f64, roster: &WasmRoster) -> bool {
        let V2WasmSessionPhase::Active(ref machine) = self.phase else {
            return false;
        };
        let Ok(now_u) = f64_to_u64(now_unix, "now_unix") else {
            return false;
        };
        machine
            .authorize(requested_cap, now_u, &roster.inner)
            .0
            .is_ok()
    }

    #[wasm_bindgen]
    pub fn rekey(&mut self, now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let V2WasmSessionPhase::Active(ref mut machine) = self.phase else {
            return Err(to_js_err("v2 session closed"));
        };
        let actions = machine.seal_rekey(now_m).map_err(to_js_err)?;
        Ok(collect_v2_writes(actions))
    }

    #[wasm_bindgen]
    pub fn close(&mut self, code: f64, reason: &str, now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let close_code = f64_to_u16(code, "code").map_err(to_js_err)?;
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let V2WasmSessionPhase::Active(ref mut machine) = self.phase else {
            return Ok(Vec::new());
        };
        if !machine.is_established() {
            self.phase = V2WasmSessionPhase::Closed;
            return Ok(Vec::new());
        }
        let actions = machine
            .seal_close(close_code, reason, now_m)
            .map_err(to_js_err)?;
        self.phase = V2WasmSessionPhase::Closed;
        Ok(collect_v2_writes(actions))
    }

    #[wasm_bindgen]
    pub fn tick(
        &mut self,
        now_unix: f64,
        now_ms: f64,
        roster: &WasmRoster,
    ) -> Result<Vec<u8>, JsValue> {
        let now_u = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let V2WasmSessionPhase::Active(ref mut machine) = self.phase else {
            return Err(to_js_err("v2 session closed"));
        };
        let actions = match machine.tick(now_u, now_m, &roster.inner) {
            Ok(a) => a,
            Err(err) => {
                if machine.is_closed() {
                    self.phase = V2WasmSessionPhase::Closed;
                }
                return Err(to_js_err(err));
            }
        };
        Ok(collect_v2_writes(actions))
    }

    /// Device id derived from the static key authenticated by the handshake, once established.
    #[wasm_bindgen]
    #[must_use]
    pub fn peer_device_id(&self) -> Option<String> {
        self.peer_device_id.clone()
    }

    /// Applies buffered `0x0B` frames to `book` as delivered by this authenticated peer.
    ///
    /// Frames stay inside WASM memory; the returned JSON carries group ids and errors only.
    #[wasm_bindgen]
    pub fn apply_group_rendezvous(
        &mut self,
        book: &mut WasmGroupBook,
        roster: &WasmRoster,
        now_unix: f64,
    ) -> Result<String, JsValue> {
        let now = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        let frames = std::mem::take(&mut self.pending_rendezvous);
        Ok(book
            .apply_rendezvous_inner(&roster.inner, self.peer_device_id.as_deref(), &frames, now)
            .to_string())
    }

    /// Sets what the connect expects of the host, checked against `HostHello` before `msg3`.
    /// Valid only before `start()`.
    #[wasm_bindgen]
    pub fn with_route_expectation(
        &mut self,
        target_peer_id: &str,
        recovery_uri: Option<String>,
        relay_key_b64: Option<String>,
    ) -> Result<(), JsValue> {
        self.with_route_expectation_inner(
            target_peer_id,
            recovery_uri.as_deref(),
            relay_key_b64.as_deref(),
        )
        .map_err(to_js_err)
    }

    /// Sets `SessionHello.route_seq` (opting in to route sets). Valid only before `start()`.
    #[wasm_bindgen]
    pub fn with_route_seq(&mut self, route_seq: Option<f64>) -> Result<(), JsValue> {
        self.with_route_seq_inner(route_seq).map_err(to_js_err)
    }

    /// `HostHello.rotation` records the host presented (JSON array), kept on every outcome.
    #[wasm_bindgen]
    pub fn presented_rotation_json(&self) -> Result<String, JsValue> {
        self.evidence.rotation_json().map_err(to_js_err)
    }

    /// The recovery URI's route statement verified under the presented host key, as JSON, or
    /// `undefined` when there is none.
    #[wasm_bindgen]
    #[must_use]
    pub fn verified_recovery_statement_json(&self) -> Option<String> {
        self.evidence.recovery_json()
    }

    /// Keys the host presented, `{static_pub_b64, signing_pub_b64, wire}`, once established.
    #[wasm_bindgen]
    #[must_use]
    pub fn presented_host_keys_json(&self) -> Option<String> {
        self.evidence.host_keys_json(2)
    }

    /// Drains the received `0x0C` route sets as a JSON array of base64url payloads, to be
    /// applied with `WasmRoster.apply_route_announcement`.
    #[wasm_bindgen]
    pub fn take_route_sets(&mut self) -> String {
        self.take_route_sets_json()
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn is_established(&self) -> bool {
        matches!(self.phase, V2WasmSessionPhase::Active(ref m) if m.is_established())
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self.phase, V2WasmSessionPhase::Closed)
            || matches!(self.phase, V2WasmSessionPhase::Active(ref m) if m.is_closed())
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PlannerCandidateInput {
    Hint(String),
    Descriptor {
        addr: String,
        #[serde(default)]
        id: Option<usize>,
        #[serde(default)]
        provider: Option<String>,
    },
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct WasmPathPolicyConfigInput {
    attempt_stagger_ms: Option<f64>,
    p2p_cold_delay_ms: Option<f64>,
    per_attempt_timeout_ms: Option<f64>,
    exhaustion_timeout_ms: Option<f64>,
}

fn parse_provider_id(name: &str) -> Result<ProviderId, WasmError> {
    match name {
        "local" => Ok(ProviderId::Local),
        "direct" => Ok(ProviderId::Direct),
        "overlay" => Ok(ProviderId::Overlay),
        "p2p" => Ok(ProviderId::P2p),
        "relay" => Ok(ProviderId::Relay),
        "broker" => Ok(ProviderId::Broker),
        _ => Err(WasmError::from(format!("unknown provider '{name}'"))),
    }
}

fn candidate_endpoint_json(c: &CandidateEndpoint) -> serde_json::Value {
    json!({
        "id": c.id,
        "provider": provider_name(c.provider),
        "addr": c.addr,
        "is_numeric_host": c.is_numeric_host,
    })
}

fn planner_action_json(action: &PlannerAction) -> serde_json::Value {
    match action {
        PlannerAction::DialCandidate(c) => json!({
            "action": "dial_candidate",
            "candidate": candidate_endpoint_json(c),
        }),
        PlannerAction::CancelCandidate(id) => json!({
            "action": "cancel_candidate",
            "id": id,
        }),
        PlannerAction::ActivatePath(c) => json!({
            "action": "activate_path",
            "candidate": candidate_endpoint_json(c),
        }),
        PlannerAction::ProbeBetterPath(c) => json!({
            "action": "probe_better_path",
            "candidate": candidate_endpoint_json(c),
        }),
        PlannerAction::CloseActivePath { id, reason } => json!({
            "action": "close_active_path",
            "id": id,
            "reason": reason,
        }),
        PlannerAction::AllCandidatesExhausted => json!({
            "action": "all_candidates_exhausted",
        }),
    }
}

/// Sans-I/O Happy Eyeballs multi-route path planner wrapping `tendril_core::policy::PathPlanner`.
#[wasm_bindgen]
pub struct WasmPathPlanner {
    inner: PathPlanner,
    per_attempt_timeout_ms: Option<u64>,
    exhaustion_timeout_ms: Option<u64>,
    exhaustion_deadline_ms: Option<u64>,
    in_flight: BTreeSet<usize>,
    attempt_deadlines: BTreeMap<usize, u64>,
    pending: VecDeque<PlannerAction>,
    started: bool,
    exhausted: bool,
}

impl WasmPathPlanner {
    fn new_inner(candidates_json: &str, config_json: Option<&str>) -> Result<Self, WasmError> {
        let raw_candidates: Vec<PlannerCandidateInput> = serde_json::from_str(candidates_json)
            .map_err(|e| WasmError::from(format!("invalid candidates_json: {e}")))?;
        let mut seen_ids = BTreeSet::new();
        let mut candidates = Vec::with_capacity(raw_candidates.len());
        for (idx, item) in raw_candidates.into_iter().enumerate() {
            let (id, provider, addr) = match item {
                PlannerCandidateInput::Hint(hint) => {
                    let provider = classify_endpoint_hint(&hint).map_err(WasmError::from)?;
                    (idx, provider, hint)
                }
                PlannerCandidateInput::Descriptor { addr, id, provider } => {
                    if addr.trim().is_empty() {
                        return Err(WasmError::from("candidate addr must not be empty"));
                    }
                    let cid = id.unwrap_or(idx);
                    let prov = match provider.as_deref() {
                        Some(p) => parse_provider_id(p)?,
                        None => classify_endpoint_hint(&addr).map_err(WasmError::from)?,
                    };
                    (cid, prov, addr)
                }
            };
            if !seen_ids.insert(id) {
                return Err(WasmError::from(format!("duplicate candidate id {id}")));
            }
            candidates.push(CandidateEndpoint::new(id, provider, addr));
        }

        let cfg_input: WasmPathPolicyConfigInput = match config_json {
            Some(raw) if !raw.trim().is_empty() => serde_json::from_str(raw)
                .map_err(|e| WasmError::from(format!("invalid config_json: {e}")))?,
            _ => WasmPathPolicyConfigInput::default(),
        };
        let mut policy = PathPolicyConfig::default();
        if let Some(v) = cfg_input.attempt_stagger_ms {
            policy.happy_eyeballs_stagger_ms = f64_to_u64(v, "attempt_stagger_ms")?;
        }
        if let Some(v) = cfg_input.p2p_cold_delay_ms {
            policy.p2p_cold_delay_ms = f64_to_u64(v, "p2p_cold_delay_ms")?;
        }
        let per_attempt_timeout_ms = cfg_input
            .per_attempt_timeout_ms
            .map(|v| f64_to_u64(v, "per_attempt_timeout_ms"))
            .transpose()?;
        let exhaustion_timeout_ms = cfg_input
            .exhaustion_timeout_ms
            .map(|v| f64_to_u64(v, "exhaustion_timeout_ms"))
            .transpose()?;

        Ok(Self {
            inner: PathPlanner::new(policy, candidates),
            per_attempt_timeout_ms,
            exhaustion_timeout_ms,
            exhaustion_deadline_ms: None,
            in_flight: BTreeSet::new(),
            attempt_deadlines: BTreeMap::new(),
            pending: VecDeque::new(),
            started: false,
            exhausted: false,
        })
    }

    fn absorb_inner_actions(&mut self, now_ms: u64) {
        for action in self.inner.drain_actions() {
            match &action {
                PlannerAction::DialCandidate(cand) => {
                    self.in_flight.insert(cand.id);
                    if let Some(timeout_ms) = self.per_attempt_timeout_ms {
                        self.attempt_deadlines
                            .insert(cand.id, now_ms.saturating_add(timeout_ms));
                    }
                }
                PlannerAction::CancelCandidate(id) | PlannerAction::CloseActivePath { id, .. } => {
                    self.in_flight.remove(id);
                    self.attempt_deadlines.remove(id);
                }
                PlannerAction::ActivatePath(_) => {
                    self.in_flight.clear();
                    self.attempt_deadlines.clear();
                    self.exhaustion_deadline_ms = None;
                }
                PlannerAction::AllCandidatesExhausted => {
                    self.exhausted = true;
                    self.in_flight.clear();
                    self.attempt_deadlines.clear();
                    self.exhaustion_deadline_ms = None;
                }
                PlannerAction::ProbeBetterPath(_) => {}
            }
            self.pending.push_back(action);
        }
    }

    fn start_inner(&mut self, now_ms: f64) -> Result<(), WasmError> {
        let now = f64_to_u64(now_ms, "now_ms")?;
        self.started = true;
        self.exhausted = false;
        self.in_flight.clear();
        self.attempt_deadlines.clear();
        self.exhaustion_deadline_ms = self.exhaustion_timeout_ms.map(|t| now.saturating_add(t));
        self.inner.start(now);
        self.absorb_inner_actions(now);
        Ok(())
    }

    fn tick_inner(&mut self, now_ms: f64) -> Result<(), WasmError> {
        let now = f64_to_u64(now_ms, "now_ms")?;
        if !self.started || self.exhausted {
            return Ok(());
        }
        if self.inner.active_candidate().is_none() {
            if let Some(exhaust_at) = self.exhaustion_deadline_ms
                && now >= exhaust_at
            {
                let to_cancel: Vec<usize> = self.in_flight.iter().copied().collect();
                for id in to_cancel {
                    self.pending.push_back(PlannerAction::CancelCandidate(id));
                }
                self.in_flight.clear();
                self.attempt_deadlines.clear();
                self.exhaustion_deadline_ms = None;
                self.exhausted = true;
                self.pending
                    .push_back(PlannerAction::AllCandidatesExhausted);
                return Ok(());
            }
            let timed_out: Vec<usize> = self
                .attempt_deadlines
                .iter()
                .filter_map(|(&id, &dl)| (now >= dl).then_some(id))
                .collect();
            for id in timed_out {
                self.in_flight.remove(&id);
                self.attempt_deadlines.remove(&id);
                self.pending.push_back(PlannerAction::CancelCandidate(id));
                self.inner.on_dial_failed(id, "attempt timed out", now);
                self.absorb_inner_actions(now);
            }
            if self.exhausted {
                return Ok(());
            }
        }
        self.inner.tick(now);
        self.absorb_inner_actions(now);
        Ok(())
    }

    fn on_dial_succeeded_inner(&mut self, id: usize, now_ms: f64) -> Result<(), WasmError> {
        let now = f64_to_u64(now_ms, "now_ms")?;
        self.in_flight.remove(&id);
        self.attempt_deadlines.remove(&id);
        self.inner.on_dial_succeeded(id, now);
        self.absorb_inner_actions(now);
        Ok(())
    }

    fn on_dial_failed_inner(
        &mut self,
        id: usize,
        reason: &str,
        now_ms: f64,
    ) -> Result<(), WasmError> {
        let now = f64_to_u64(now_ms, "now_ms")?;
        self.in_flight.remove(&id);
        self.attempt_deadlines.remove(&id);
        self.inner.on_dial_failed(id, reason, now);
        self.absorb_inner_actions(now);
        Ok(())
    }

    fn drain_actions_json(&mut self) -> String {
        let actions: Vec<serde_json::Value> = self
            .pending
            .drain(..)
            .map(|a| planner_action_json(&a))
            .collect();
        serde_json::Value::Array(actions).to_string()
    }

    fn next_deadline_inner(&self) -> Option<f64> {
        if !self.started || self.exhausted {
            return None;
        }
        if self.inner.active_candidate().is_some() {
            return self
                .inner
                .next_deadline_ms()
                .and_then(|v| u64_to_f64(v).ok());
        }
        let mut earliest = self.inner.next_deadline_ms();
        if let Some(attempt_dl) = self.attempt_deadlines.values().copied().min() {
            earliest = Some(earliest.map_or(attempt_dl, |e| e.min(attempt_dl)));
        }
        if let Some(exhaust_dl) = self.exhaustion_deadline_ms {
            earliest = Some(earliest.map_or(exhaust_dl, |e| e.min(exhaust_dl)));
        }
        earliest.and_then(|v| u64_to_f64(v).ok())
    }
}

#[wasm_bindgen]
impl WasmPathPlanner {
    #[wasm_bindgen(constructor)]
    pub fn new(
        candidates_json: &str,
        config_json: Option<String>,
    ) -> Result<WasmPathPlanner, JsValue> {
        Self::new_inner(candidates_json, config_json.as_deref()).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn start(&mut self, now_ms: f64) -> Result<(), JsValue> {
        self.start_inner(now_ms).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn tick(&mut self, now_ms: f64) -> Result<(), JsValue> {
        self.tick_inner(now_ms).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn on_dial_succeeded(&mut self, id: usize, now_ms: f64) -> Result<(), JsValue> {
        self.on_dial_succeeded_inner(id, now_ms).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn on_dial_failed(&mut self, id: usize, reason: &str, now_ms: f64) -> Result<(), JsValue> {
        self.on_dial_failed_inner(id, reason, now_ms)
            .map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn drain_actions(&mut self) -> String {
        self.drain_actions_json()
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn next_deadline_ms(&self) -> Option<f64> {
        self.next_deadline_inner()
    }
}

#[cfg(test)]
mod tests {
    use tendril_core::crypto::b64url_decode;
    use tendril_core::pairing::{
        PairingCodeKind, PairingConfig, PairingManager, PairingPathKind, PairingResponder,
    };

    use super::*;

    #[test]
    fn wasm_identity_roundtrip_and_full_pair_session_handshake() {
        let host_id = EndpointIdentity::generate()
            .unwrap()
            .with_host_id("wasm-test-host");
        let mut host_roster = Roster::new();
        let mut mgr = PairingManager::new(PairingConfig::default());
        let now = 1_795_564_800u64;
        let code = mgr.issue_code(PairingCodeKind::Remote3Group, now).unwrap();

        let cli_id = WasmIdentity::generate_inner(Some("wasm-cli")).unwrap();
        let cli_saved = cli_id.serialize_json().unwrap();
        let cli_reloaded = WasmIdentity::parse_json(&cli_saved).unwrap();
        assert_eq!(cli_id.info_string(), cli_reloaded.info_string());

        let mut cli_roster = WasmRoster::new();
        let mut pair_init = WasmPairInitiator::new_inner(
            &cli_reloaded,
            "web",
            "browser",
            &code,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let mut pair_resp = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();

        let init_m1: Vec<u8> = match pair_init.machine().unwrap().start().unwrap().pop().unwrap() {
            PairAction::WriteBytes(b) => b,
            other => panic!("unexpected start action: {other:?}"),
        };
        let resp_acts1 = pair_resp
            .feed_bytes(&init_m1, now, &mut mgr, &mut host_roster)
            .unwrap();
        let m2: Vec<u8> = resp_acts1
            .into_iter()
            .filter_map(|a| match a {
                PairAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();

        let step1_val: serde_json::Value =
            serde_json::from_str(&pair_init.step_bytes(&m2, &mut cli_roster).unwrap()).unwrap();
        let m3 = b64url_decode(step1_val["write_b64"].as_str().unwrap()).unwrap();
        let resp_acts2 = pair_resp
            .feed_bytes(&m3, now, &mut mgr, &mut host_roster)
            .unwrap();
        let mut resp_bytes = Vec::new();
        let mut cli_dev_id = String::new();
        let mut host_sas = String::new();
        for a in resp_acts2 {
            match a {
                PairAction::WriteBytes(b) => resp_bytes.extend_from_slice(&b),
                PairAction::Completed(PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    ..
                }) => {
                    cli_dev_id = device_id;
                    host_sas = pairing_sas;
                }
                _ => {}
            }
        }
        let step2_val: serde_json::Value =
            serde_json::from_str(&pair_init.step_bytes(&resp_bytes, &mut cli_roster).unwrap())
                .unwrap();
        assert_eq!(step2_val["sas"].as_str().unwrap(), host_sas);
        assert_eq!(step2_val["outcome"]["status"], "pending");

        host_roster
            .confirm_peer(&cli_dev_id, Some(&host_sas))
            .unwrap();
        cli_roster
            .inner
            .confirm_peer("wasm-test-host", Some(&host_sas))
            .unwrap();
        let grant = host_roster
            .mint_grant(
                &host_id,
                &cli_dev_id,
                vec!["fs.read".to_owned()],
                now,
                now + 3600,
                [0x77; 16],
            )
            .unwrap();
        let grant_json = serde_json::to_string(&grant).unwrap();

        #[allow(clippy::cast_precision_loss)]
        let mut cli_sess =
            WasmSessionClient::new_inner(&cli_reloaded, "wasm-test-host", Some(&grant_json), None)
                .unwrap();
        let mut host_sess = SessionMachine::new_responder(&host_id, None).unwrap();
        let sm1: Vec<u8> = match cli_sess
            .machine_mut()
            .unwrap()
            .start()
            .unwrap()
            .pop()
            .unwrap()
        {
            SessionAction::WriteBytes(b) => b,
            _ => panic!("expected write bytes"),
        };
        let sa1 = host_sess
            .feed_bytes(&sm1, now, 10, &mut host_roster)
            .unwrap();
        let sm2: Vec<u8> = sa1
            .into_iter()
            .filter_map(|a| match a {
                SessionAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();
        #[allow(clippy::cast_precision_loss)]
        let s_res: serde_json::Value = serde_json::from_str(
            &cli_sess
                .step_bytes(&sm2, now as f64, 20.0, &mut cli_roster)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(s_res["established"], true);
        let sm3 = b64url_decode(s_res["write_b64"].as_str().unwrap()).unwrap();
        host_sess
            .feed_bytes(&sm3, now, 25, &mut host_roster)
            .unwrap();
        assert!(host_sess.is_established());
    }

    #[test]
    fn wasm_v1_session_feeds_group_book_from_authenticated_peer() {
        use tendril_core::group::{
            GroupBuildParams, GroupIngestStatus, GroupMember, GroupSigner, add_member,
            create_group, encode_group_rendezvous_frame,
        };

        let host_id = EndpointIdentity::generate()
            .unwrap()
            .with_host_id("wasm-grp-host");
        let mut host_roster = Roster::new();
        let mut mgr = PairingManager::new(PairingConfig::default());
        let now = 1_795_564_800u64;
        let code = mgr.issue_code(PairingCodeKind::Remote3Group, now).unwrap();

        let cli_id = WasmIdentity::generate_inner(Some("wasm-grp-cli")).unwrap();
        let mut cli_roster = WasmRoster::new();
        let mut pair_init = WasmPairInitiator::new_inner(
            &cli_id, "web", "browser", &code, None, None, None, None, None,
        )
        .unwrap();
        let mut pair_resp = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();
        let m1: Vec<u8> = match pair_init.machine().unwrap().start().unwrap().pop().unwrap() {
            PairAction::WriteBytes(b) => b,
            other => panic!("unexpected start action: {other:?}"),
        };
        let writes = |acts: Vec<PairAction>| -> Vec<u8> {
            acts.into_iter()
                .filter_map(|a| match a {
                    PairAction::WriteBytes(b) => Some(b),
                    _ => None,
                })
                .flatten()
                .collect()
        };
        let m2 = writes(
            pair_resp
                .feed_bytes(&m1, now, &mut mgr, &mut host_roster)
                .unwrap(),
        );
        let step1: serde_json::Value =
            serde_json::from_str(&pair_init.step_bytes(&m2, &mut cli_roster).unwrap()).unwrap();
        let m3 = b64url_decode(step1["write_b64"].as_str().unwrap()).unwrap();
        let mut cli_dev_id = String::new();
        let mut host_sas = String::new();
        let mut resp_bytes = Vec::new();
        for a in pair_resp
            .feed_bytes(&m3, now, &mut mgr, &mut host_roster)
            .unwrap()
        {
            match a {
                PairAction::WriteBytes(b) => resp_bytes.extend_from_slice(&b),
                PairAction::Completed(PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    ..
                }) => {
                    cli_dev_id = device_id;
                    host_sas = pairing_sas;
                }
                _ => {}
            }
        }
        pair_init.step_bytes(&resp_bytes, &mut cli_roster).unwrap();
        host_roster
            .confirm_peer(&cli_dev_id, Some(&host_sas))
            .unwrap();
        cli_roster
            .inner
            .confirm_peer("wasm-grp-host", Some(&host_sas))
            .unwrap();

        let grant = host_roster
            .mint_grant(
                &host_id,
                &cli_dev_id,
                vec!["fs.read".to_owned()],
                now,
                now + 3600,
                [0x55; 16],
            )
            .unwrap();
        let grant_json = serde_json::to_string(&grant).unwrap();
        let mut cli_sess =
            WasmSessionClient::new_inner(&cli_id, "wasm-grp-host", Some(&grant_json), None)
                .unwrap();
        let mut host_sess = SessionMachine::new_responder(&host_id, None).unwrap();
        let sm1 = collect_session_writes(cli_sess.machine_mut().unwrap().start().unwrap());
        let sm2 = collect_session_writes(
            host_sess
                .feed_bytes(&sm1, now, 10, &mut host_roster)
                .unwrap(),
        );
        #[allow(clippy::cast_precision_loss)]
        let est: serde_json::Value = serde_json::from_str(
            &cli_sess
                .step_bytes(&sm2, now as f64, 20.0, &mut cli_roster)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(est["established"], true);
        host_sess
            .feed_bytes(
                &b64url_decode(est["write_b64"].as_str().unwrap()).unwrap(),
                now,
                25,
                &mut host_roster,
            )
            .unwrap();
        assert_eq!(
            cli_sess.peer_device_id().as_deref(),
            Some(host_id.device_id().as_str())
        );

        let host_member = GroupMember::new(
            host_id.static_key().public_bytes(),
            "host",
            host_id.signing_key().public_key(),
            Vec::new(),
            Vec::new(),
        );
        let params = GroupBuildParams::new(now);
        let (g1, s1) = create_group(host_id.signing_key(), "mesh", 1, host_member, params).unwrap();
        let gid = g1.group_id.clone();
        let cli_member = GroupMember::new(
            cli_id.inner.static_key().public_bytes(),
            "web",
            cli_id.inner.signing_key().public_key(),
            Vec::new(),
            vec![format!("group.send:{gid}"), format!("group.recv:{gid}")],
        );
        let (g2, s2) = add_member(
            &g1,
            &GroupSigner::root(host_id.signing_key()),
            cli_member,
            &s1,
            params,
        )
        .unwrap();

        let mut book = WasmGroupBook::new(&cli_id);
        fn relay(
            cli_sess: &mut WasmSessionClient,
            roster: &mut WasmRoster,
            actions: Vec<SessionAction>,
            now: u64,
        ) -> serde_json::Value {
            let bytes = collect_session_writes(actions);
            #[allow(clippy::cast_precision_loss)]
            serde_json::from_str(
                &cli_sess
                    .step_bytes(&bytes, now as f64, 30.0, roster)
                    .unwrap(),
            )
            .unwrap()
        }

        let actions = host_sess.send_group_manifest(&g2, 30).unwrap();
        let step = relay(&mut cli_sess, &mut cli_roster, actions, now);
        let event = step["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["event"] == "group_manifest_unverified")
            .unwrap()
            .to_string();
        let sender = cli_sess.peer_device_id().unwrap();
        let out = book
            .ingest_event_inner(&cli_roster.inner, &sender, &event, now)
            .unwrap();
        assert_eq!(out.group_id, gid);
        assert_eq!(out.status, GroupIngestStatus::Created);

        let payload = encode_group_rendezvous_frame(&gid, 2, &[0x42; 32]).unwrap();
        let actions = host_sess
            .send_group_rendezvous(payload.as_ref(), 40)
            .unwrap();
        let step = relay(&mut cli_sess, &mut cli_roster, actions, now);
        let rv = step["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["event"] == "group_rendezvous_unverified")
            .unwrap();
        assert!(!rv.to_string().contains(&b64url_encode(&[0x42; 32])));
        assert_eq!(cli_sess.pending_rendezvous.len(), 1);
        let frames = std::mem::take(&mut cli_sess.pending_rendezvous);
        let applied = book.apply_rendezvous_inner(
            &cli_roster.inner,
            cli_sess.peer_device_id().as_deref(),
            &frames,
            now,
        );
        assert_eq!(applied["applied"].as_array().unwrap().len(), 1, "{applied}");
        assert!(book.inner.secrets(&gid).is_some());
        let _ = s2;
    }

    #[test]
    fn wasm_m2m_enrollment_and_replay_rejection() {
        use tendril_core::pairing::EnrollmentPolicy;

        let host_id = EndpointIdentity::generate()
            .unwrap()
            .with_host_id("wasm-m2m-host");
        let anchor_id = EndpointIdentity::generate()
            .unwrap()
            .with_host_id("wasm-m2m-anchor");
        let mut host_roster = Roster::new();
        host_roster
            .add_trust_anchor(
                "wasm-m2m-anchor".to_owned(),
                anchor_id.signing_key().public_key().clone(),
            )
            .unwrap();
        let mut mgr = PairingManager::new(PairingConfig::default());
        let now = 1_795_564_800u64;

        let tok =
            core_mint_enrollment_token(&anchor_id, "wasm-m2m-host", None, now, 900, [0xA1; 16])
                .unwrap();
        let tok_json = serde_json::to_string(&tok).unwrap();

        let cli_id = WasmIdentity::generate_inner(Some("wasm-m2m-cli")).unwrap();
        let mut cli_roster = WasmRoster::new();
        let mut pair_init = WasmPairInitiator::new_m2m_inner(
            &cli_id,
            "web-machine",
            "machine",
            "wasm-m2m-host",
            &b64url_encode(host_id.static_key().public_bytes()),
            &host_id.signing_key().public_key().to_b64url(),
            None,
            &tok_json,
            None,
        )
        .unwrap();
        let mut pair_resp = PairingResponder::with_enrollment_policy(
            &host_id,
            PairingPathKind::Remote,
            None,
            EnrollmentPolicy::enabled_default(),
        )
        .unwrap();

        let init_m1: Vec<u8> = match pair_init.machine().unwrap().start().unwrap().pop().unwrap() {
            PairAction::WriteBytes(b) => b,
            other => panic!("unexpected start action: {other:?}"),
        };
        let resp_acts1 = pair_resp
            .feed_bytes(&init_m1, now, &mut mgr, &mut host_roster)
            .unwrap();
        let m2: Vec<u8> = resp_acts1
            .into_iter()
            .filter_map(|a| match a {
                PairAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();

        let step1: serde_json::Value =
            serde_json::from_str(&pair_init.step_bytes(&m2, &mut cli_roster).unwrap()).unwrap();
        let m3 = b64url_decode(step1["write_b64"].as_str().unwrap()).unwrap();
        let resp_acts2 = pair_resp
            .feed_bytes(&m3, now, &mut mgr, &mut host_roster)
            .unwrap();
        let mut resp_bytes = Vec::new();
        let mut enrolled_id = String::new();
        for a in resp_acts2 {
            match a {
                PairAction::WriteBytes(b) => resp_bytes.extend_from_slice(&b),
                PairAction::Completed(PairOutcome::ResponderEnrolled { device_id, .. }) => {
                    enrolled_id = device_id;
                }
                _ => {}
            }
        }
        let step2: serde_json::Value =
            serde_json::from_str(&pair_init.step_bytes(&resp_bytes, &mut cli_roster).unwrap())
                .unwrap();
        assert_eq!(step2["outcome"]["status"], "active");
        assert_eq!(step2["outcome"]["device_id"], enrolled_id);

        // Single-use replay fails closed.
        let mut rep_init = WasmPairInitiator::new_m2m_inner(
            &cli_id,
            "web-machine",
            "machine",
            "wasm-m2m-host",
            &b64url_encode(host_id.static_key().public_bytes()),
            &b64url_encode(&host_id.signing_key().signing_pub_hash()),
            None,
            &tok_json,
            None,
        )
        .unwrap();
        let mut rep_resp = PairingResponder::with_enrollment_policy(
            &host_id,
            PairingPathKind::Remote,
            None,
            EnrollmentPolicy::enabled_default(),
        )
        .unwrap();
        let rep_m1: Vec<u8> = match rep_init.machine().unwrap().start().unwrap().pop().unwrap() {
            PairAction::WriteBytes(b) => b,
            _ => unreachable!(),
        };
        let rep_m2: Vec<u8> = rep_resp
            .feed_bytes(&rep_m1, now, &mut mgr, &mut host_roster)
            .unwrap()
            .into_iter()
            .filter_map(|a| match a {
                PairAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();
        let rep_step1: serde_json::Value =
            serde_json::from_str(&rep_init.step_bytes(&rep_m2, &mut cli_roster).unwrap()).unwrap();
        let rep_m3 = b64url_decode(rep_step1["write_b64"].as_str().unwrap()).unwrap();
        let rep_acts2 = rep_resp
            .feed_bytes(&rep_m3, now, &mut mgr, &mut host_roster)
            .unwrap();
        assert!(rep_acts2.iter().any(|a| matches!(
            a,
            PairAction::Completed(PairOutcome::Rejected { error }) if error == "token_replayed"
        )));
    }

    #[test]
    fn wasm_v2_pake_pair_and_session_roundtrip_and_downgrade_rejection() {
        use tendril_core::v2::{V2PakePairResponder, V2SessionResponder};

        let host_id = EndpointIdentity::generate()
            .unwrap()
            .with_host_id("wasm-v2-host");
        let mut host_roster = Roster::new();
        let mut mgr = PairingManager::new(PairingConfig::default());
        let now = 1_795_564_800u64;
        let code = mgr.issue_code(PairingCodeKind::Remote3Group, now).unwrap();

        let cli_id = WasmIdentity::generate_inner(Some("wasm-v2-cli")).unwrap();
        let mut cli_roster = WasmRoster::new();
        let mut pair_init =
            WasmV2PakePairInitiator::new_inner(&cli_id, "web", "browser", &code, None).unwrap();
        let mut pair_resp = V2PakePairResponder::new(
            &host_id,
            PairingPathKind::Remote,
            PakeArgon2Params::default(),
        )
        .unwrap();

        let init_m1 = pair_init.start().unwrap();
        let resp_acts1 = pair_resp
            .feed_bytes(&init_m1, now, &mut mgr, &mut host_roster)
            .unwrap();
        let m2: Vec<u8> = resp_acts1
            .into_iter()
            .filter_map(|a| match a {
                V2PairAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();

        let step1_val: serde_json::Value =
            serde_json::from_str(&pair_init.step_bytes(&m2, &mut cli_roster).unwrap()).unwrap();
        let m3 = b64url_decode(step1_val["write_b64"].as_str().unwrap()).unwrap();
        let resp_acts2 = pair_resp
            .feed_bytes(&m3, now, &mut mgr, &mut host_roster)
            .unwrap();
        let mut resp_bytes = Vec::new();
        let mut cli_dev_id = String::new();
        let mut host_sas = String::new();
        let mut resp_v2_secrets = None;
        for a in resp_acts2 {
            match a {
                V2PairAction::WriteBytes(b) => resp_bytes.extend_from_slice(&b),
                V2PairAction::Completed(V2PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    v2_secrets,
                    ..
                }) => {
                    cli_dev_id = device_id;
                    host_sas = pairing_sas;
                    resp_v2_secrets = Some(v2_secrets);
                }
                _ => {}
            }
        }
        let step2_val: serde_json::Value =
            serde_json::from_str(&pair_init.step_bytes(&resp_bytes, &mut cli_roster).unwrap())
                .unwrap();
        assert_eq!(step2_val["sas"].as_str().unwrap(), host_sas);
        assert_eq!(step2_val["outcome"]["status"], "pending");

        host_roster
            .confirm_peer(&cli_dev_id, Some(&host_sas))
            .unwrap();
        host_roster
            .upgrade_peer_to_v2(&cli_dev_id, resp_v2_secrets.unwrap())
            .unwrap();
        cli_roster
            .inner
            .confirm_peer("wasm-v2-host", Some(&host_sas))
            .unwrap();

        assert_eq!(
            cli_roster
                .inner
                .pairing_floor(host_id.static_key().public_bytes()),
            2
        );
        // V1 pairing fallback against a known v2 peer must fail closed.
        let v1_downgrade = WasmPairInitiator::new_inner(
            &cli_id,
            "web",
            "browser",
            &code,
            Some(&b64url_encode(host_id.static_key().public_bytes())),
            Some(&host_id.signing_key().public_key().to_b64url()),
            Some("wasm-v2-host"),
            None,
            Some(&cli_roster),
        );
        assert!(v1_downgrade.is_err());

        let grant = host_roster
            .mint_grant(
                &host_id,
                &cli_dev_id,
                vec!["fs.read".to_owned()],
                now,
                now + 3600,
                [0x88; 16],
            )
            .unwrap();
        let grant_json = serde_json::to_string(&grant).unwrap();

        let mut cli_sess = WasmV2SessionInitiator::new_inner(
            &cli_id,
            "wasm-v2-host",
            &cli_roster,
            Some(&grant_json),
            None,
        )
        .unwrap();
        let mut host_sess = V2SessionResponder::new(&host_id).unwrap();

        #[allow(clippy::cast_precision_loss)]
        let sm1 = cli_sess.start(now as f64).unwrap();
        let sa1 = host_sess
            .feed_bytes(&sm1, now, 10, &mut host_roster)
            .unwrap();
        let sm2: Vec<u8> = sa1
            .into_iter()
            .filter_map(|a| match a {
                V2SessionAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();

        #[allow(clippy::cast_precision_loss)]
        let s_res: serde_json::Value = serde_json::from_str(
            &cli_sess
                .step_bytes(&sm2, now as f64, 20.0, &mut cli_roster)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(s_res["established"], true);
        let sm3 = cli_sess.poll_write();
        host_sess
            .feed_bytes(&sm3, now, 25, &mut host_roster)
            .unwrap();
        assert!(host_sess.is_established());

        let summary: serde_json::Value =
            serde_json::from_str(&cli_roster.peer_v2_summary("wasm-v2-host").unwrap()).unwrap();
        assert_eq!(summary["min_wire_version"], 2);
        assert_eq!(summary["has_v2_secrets"], true);

        #[allow(clippy::cast_precision_loss)]
        {
            assert!(cli_sess.authorize("fs.read", now as f64, &cli_roster));
            assert!(!cli_sess.authorize("shell.exec", now as f64, &cli_roster));
        }
        assert!(cli_sess.next_ping_delay_ms().unwrap() > 0.0);

        let cover = cli_sess.send_dummy_cover(256, 30.0).unwrap();
        let cover_acts = host_sess
            .feed_bytes(&cover, now, 35, &mut host_roster)
            .unwrap();
        assert!(cover_acts.is_empty());

        let data_wire = cli_sess.send_data(b"hello-v2", 40.0).unwrap();
        let data_acts = host_sess
            .feed_bytes(&data_wire, now, 45, &mut host_roster)
            .unwrap();
        assert!(
            data_acts
                .iter()
                .any(|a| matches!(a, V2SessionAction::AppData(d) if d == b"hello-v2"))
        );

        let rk_wire = cli_sess.rekey(50.0).unwrap();
        let rk_acts = host_sess
            .feed_bytes(&rk_wire, now, 55, &mut host_roster)
            .unwrap();
        assert!(
            rk_acts
                .iter()
                .any(|a| matches!(a, V2SessionAction::Rekeyed { .. }))
        );

        // PRIV-05: send_ping on WasmV2SessionInitiator produces an encrypted ping answered with pong.
        let ping_wire = cli_sess.send_ping(1337.0, 56.0).unwrap();
        let ping_acts = host_sess
            .feed_bytes(&ping_wire, now, 57, &mut host_roster)
            .unwrap();
        let pong_wire: Vec<u8> = ping_acts
            .into_iter()
            .filter_map(|a| match a {
                V2SessionAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(!pong_wire.is_empty());
        #[allow(clippy::cast_precision_loss)]
        cli_sess
            .step_bytes(&pong_wire, now as f64, 58.0, &mut cli_roster)
            .unwrap();
        let evs: serde_json::Value = serde_json::from_str(&cli_sess.drain_events_json()).unwrap();
        assert!(
            evs.as_array()
                .unwrap()
                .iter()
                .any(|e| e["event"] == "pong" && e["cookie"] == 1337.0)
        );

        // PRIV-04: v1 session pre-flight check against a v2 peer fails closed before emitting msg1.
        assert!(check_peer_allows_wire_v1(&cli_roster.inner, "wasm-v2-host").is_err());

        let close_wire = cli_sess.close(1000.0, "bye", 60.0).unwrap();
        assert!(cli_sess.is_closed());
        let close_acts = host_sess
            .feed_bytes(&close_wire, now, 65, &mut host_roster)
            .unwrap();
        assert!(close_acts.iter().any(
            |a| matches!(a, V2SessionAction::CloseTransport { code: 1000, reason } if reason == "bye")
        ));
    }

    #[test]
    fn wasm_v2_session_revocation_crl_closes_session() {
        use tendril_core::grants::{RevocationListUnsigned, sign_crl};
        use tendril_core::v2::{V2PakePairResponder, V2SessionResponder};

        let host_id = EndpointIdentity::generate()
            .unwrap()
            .with_host_id("wasm-v2-rev-host");
        let mut host_roster = Roster::new();
        let mut mgr = PairingManager::new(PairingConfig::default());
        let now = 1_795_564_800u64;
        let code = mgr.issue_code(PairingCodeKind::Remote3Group, now).unwrap();

        let cli_id = WasmIdentity::generate_inner(Some("wasm-v2-rev-cli")).unwrap();
        let mut cli_roster = WasmRoster::new();
        let mut pair_init =
            WasmV2PakePairInitiator::new_inner(&cli_id, "web", "browser", &code, None).unwrap();
        let mut pair_resp = V2PakePairResponder::new(
            &host_id,
            PairingPathKind::Remote,
            PakeArgon2Params::default(),
        )
        .unwrap();

        let init_m1 = pair_init.start().unwrap();
        let m2: Vec<u8> = pair_resp
            .feed_bytes(&init_m1, now, &mut mgr, &mut host_roster)
            .unwrap()
            .into_iter()
            .filter_map(|a| match a {
                V2PairAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();
        let step1_val: serde_json::Value =
            serde_json::from_str(&pair_init.step_bytes(&m2, &mut cli_roster).unwrap()).unwrap();
        let m3 = b64url_decode(step1_val["write_b64"].as_str().unwrap()).unwrap();
        let mut resp_bytes = Vec::new();
        let mut cli_dev_id = String::new();
        let mut host_sas = String::new();
        let mut resp_v2_secrets = None;
        for a in pair_resp
            .feed_bytes(&m3, now, &mut mgr, &mut host_roster)
            .unwrap()
        {
            match a {
                V2PairAction::WriteBytes(b) => resp_bytes.extend_from_slice(&b),
                V2PairAction::Completed(V2PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    v2_secrets,
                    ..
                }) => {
                    cli_dev_id = device_id;
                    host_sas = pairing_sas;
                    resp_v2_secrets = Some(v2_secrets);
                }
                _ => {}
            }
        }
        pair_init.step_bytes(&resp_bytes, &mut cli_roster).unwrap();
        host_roster
            .confirm_peer(&cli_dev_id, Some(&host_sas))
            .unwrap();
        host_roster
            .upgrade_peer_to_v2(&cli_dev_id, resp_v2_secrets.unwrap())
            .unwrap();
        cli_roster
            .inner
            .confirm_peer("wasm-v2-rev-host", Some(&host_sas))
            .unwrap();

        let grant = host_roster
            .mint_grant(
                &host_id,
                &cli_dev_id,
                vec!["fs.read".to_owned()],
                now,
                now + 3600,
                [0x99; 16],
            )
            .unwrap();
        let grant_json = serde_json::to_string(&grant).unwrap();

        let mut cli_sess = WasmV2SessionInitiator::new_inner(
            &cli_id,
            "wasm-v2-rev-host",
            &cli_roster,
            Some(&grant_json),
            None,
        )
        .unwrap();
        let mut host_sess = V2SessionResponder::new(&host_id).unwrap();

        #[allow(clippy::cast_precision_loss)]
        let sm1 = cli_sess.start(now as f64).unwrap();
        let sm2: Vec<u8> = host_sess
            .feed_bytes(&sm1, now, 10, &mut host_roster)
            .unwrap()
            .into_iter()
            .filter_map(|a| match a {
                V2SessionAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();
        #[allow(clippy::cast_precision_loss)]
        cli_sess
            .step_bytes(&sm2, now as f64, 20.0, &mut cli_roster)
            .unwrap();
        let sm3 = cli_sess.poll_write();
        host_sess
            .feed_bytes(&sm3, now, 25, &mut host_roster)
            .unwrap();
        assert!(cli_sess.is_established());
        assert!(!cli_sess.is_closed());

        // Host issues a CRL revoking the local device and seals it over the established session.
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: "wasm-v2-rev-host".to_owned(),
                seq: 1,
                ts: "2026-11-21T12:00:00Z".to_owned(),
                revoked_devices: vec![cli_dev_id],
                revoked_nonces: Vec::new(),
            },
            host_id.signing_key(),
        )
        .unwrap();
        let crl_wire: Vec<u8> = host_sess
            .seal_revocation(&crl, 30)
            .unwrap()
            .into_iter()
            .filter_map(|a| match a {
                V2SessionAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect();

        #[allow(clippy::cast_precision_loss)]
        let rev_res = cli_sess.step_bytes(&crl_wire, now as f64, 35.0, &mut cli_roster);
        assert!(rev_res.is_err());
        assert!(cli_sess.is_closed());
        assert!(!cli_sess.is_established());
    }

    #[test]
    fn sec12_canonical_relay_host_and_priv07_byte_zeroization() {
        assert_eq!(core_canonical_relay_host("[::1]").unwrap(), "[::1]");
        assert_eq!(
            core_canonical_relay_host("[0:0:0:0:0:0:0:1]").unwrap(),
            "[::1]"
        );
        assert_eq!(
            core_canonical_relay_host("Relay.Example.").unwrap(),
            "relay.example"
        );
        assert!(core_canonical_relay_host("relay.example:443").is_err());

        // PRIV-07: byte-slice serialization and zeroization on load
        let id = WasmIdentity::generate_inner(Some("zeroize-cli")).unwrap();
        let mut id_bytes = id.serialize_json_bytes().unwrap().to_vec();
        assert!(!id_bytes.is_empty());
        let reloaded = WasmIdentity::from_json_bytes(&mut id_bytes).unwrap();
        assert!(id_bytes.iter().all(|&b| b == 0));
        assert_eq!(id.info_string(), reloaded.info_string());

        let mut roster = WasmRoster::new();
        let mut r_bytes = serde_json::to_vec(&roster.inner).unwrap();
        let r2 = WasmRoster::from_json_bytes(&mut r_bytes).unwrap();
        assert!(r_bytes.iter().all(|&b| b == 0));
        let mut r2_bytes = serde_json::to_vec(&r2.inner).unwrap();
        roster.replace_from_json_bytes(&mut r2_bytes).unwrap();
        assert!(r2_bytes.iter().all(|&b| b == 0));

        let mut code_bytes = b"4829-1704-9999".to_vec();
        let _pake =
            WasmV2PakePairInitiator::new_bytes(&reloaded, "web", "browser", &mut code_bytes, None)
                .unwrap();
        assert!(code_bytes.iter().all(|&b| b == 0));
    }
}

#[cfg(test)]
mod route_tests {
    use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_decode};
    use tendril_core::error::CoreError;
    use tendril_core::grants::{RevocationListUnsigned, sign_crl};
    use tendril_core::pairing::{
        IssueOptions, IssuedPairingUri, PairingConfig, PairingManager, PairingPathKind,
        PairingResponder, sign_route_statement,
    };
    use tendril_core::roster::{RouteOrigin, V2PeerSecrets};
    use tendril_core::v2::{V2PakePairResponder, V2SessionResponder};

    use super::*;

    const NOW: u64 = 1_795_564_800;
    const NOWF: f64 = 1_795_564_800.0;
    const RELAY_V1: &str = "wss://relay.example.test/v1/relay";
    const RELAY_V2: &str = "wss://mail.example.test/v2/relay";
    const DIRECT: &str = "direct:192.168.1.20:9100";

    fn identity(tag: u8) -> EndpointIdentity {
        EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([tag; 32]),
            SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
        )
    }

    fn wasm_identity(tag: u8) -> WasmIdentity {
        WasmIdentity {
            inner: identity(tag),
        }
    }

    fn secrets() -> V2PeerSecrets {
        V2PeerSecrets::new([0x66; 32], [0x77; 32])
    }

    fn to_json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    fn pair_writes(actions: Vec<PairAction>) -> Vec<u8> {
        actions
            .into_iter()
            .filter_map(|a| match a {
                PairAction::WriteBytes(b) => Some(b),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn v2_pair_writes(actions: Vec<V2PairAction>) -> Vec<u8> {
        collect_v2_pair_writes(actions)
    }

    struct TestHost {
        identity: EndpointIdentity,
        roster: Roster,
        mgr: PairingManager,
    }

    impl TestHost {
        fn new(tag: u8, host_id: &str) -> Self {
            Self {
                identity: identity(tag).with_host_id(host_id),
                roster: Roster::new(),
                mgr: PairingManager::new(PairingConfig::default()),
            }
        }

        fn issue(&mut self, hints: &[&str]) -> IssuedPairingUri {
            let endpoints: Vec<String> = hints.iter().map(|h| (*h).to_owned()).collect();
            let set = PairingManager::announced_route_set(&self.identity, &endpoints);
            let state = self.roster.bump_local_routes(&set, NOW).unwrap();
            self.mgr
                .issue_pairing_uri(
                    &self.identity,
                    "Studio",
                    &state,
                    IssueOptions::default(),
                    NOW,
                )
                .unwrap()
        }
    }

    fn flip_rs(uri: &str) -> String {
        let at = uri.find("&rs=").unwrap() + 4 + 10;
        let mut bytes = uri.as_bytes().to_vec();
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        String::from_utf8(bytes).unwrap()
    }

    /// A deferred v1 pairing driven to the host-verified report.
    struct V1Pairing {
        init: WasmPairInitiator,
        resp: PairingResponder,
        report: serde_json::Value,
    }

    fn v1_pairing_to_host_verified(
        host: &mut TestHost,
        issued: &IssuedPairingUri,
        uri_for_check: &str,
        persist: &str,
        pinned: bool,
        cli: &WasmIdentity,
        cli_roster: &mut WasmRoster,
    ) -> V1Pairing {
        let uri = &issued.parsed;
        let static_b64 = b64url_encode(&uri.host_static_pub);
        let sh_b64 = b64url_encode(&uri.host_signing_pub_hash);
        #[allow(clippy::cast_precision_loss)]
        let mut init = WasmPairInitiator::new_inner(
            cli,
            "web",
            "browser",
            &uri.code,
            pinned.then_some(static_b64.as_str()),
            pinned.then_some(sh_b64.as_str()),
            uri.host_id.as_deref(),
            uri.rotation_seq.map(|s| s as f64),
            None,
        )
        .unwrap();
        init.enable_deferred_claim_inner().unwrap();
        init.routes.set_uri(uri_for_check).unwrap();
        init.routes.set_options(persist).unwrap();
        let mut resp =
            PairingResponder::new(&host.identity, PairingPathKind::Remote, None).unwrap();
        let m1 = init.start().unwrap();
        let m2 = pair_writes(
            resp.feed_bytes(&m1, NOW, &mut host.mgr, &mut host.roster)
                .unwrap(),
        );
        let report = to_json(&init.step_bytes(&m2, cli_roster).unwrap());
        V1Pairing { init, resp, report }
    }

    #[test]
    fn parse_pairing_uri_reports_providers_relay_key_and_route_fields() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[DIRECT, RELAY_V1]);
        let v = parse_pairing_uri_value(&issued.uri).unwrap();
        assert_eq!(v["providers"], json!(["direct", "relay"]));
        assert_eq!(
            v["relay_pub_b64"],
            json!(b64url_encode(
                host.identity.signing_key().ed25519_public_bytes()
            ))
        );
        assert_eq!(v["route_seq"], json!(1.0));
        assert_eq!(v["route_signed"], json!(true));
        assert_eq!(v["endpoints"], json!([DIRECT, RELAY_V1]));

        let unsigned = PairingUri::new(
            "Studio",
            "TND-ABCD-EFGH",
            *host.identity.static_key().public_bytes(),
            host.identity.signing_key().signing_pub_hash(),
            vec![DIRECT.to_owned()],
            None,
            None,
        )
        .try_encode()
        .unwrap();
        let v = parse_pairing_uri_value(&unsigned).unwrap();
        assert_eq!(v["route_signed"], json!(false));
        assert_eq!(v["route_seq"], serde_json::Value::Null);
        assert_eq!(v["relay_pub_b64"], serde_json::Value::Null);
        assert_eq!(v["providers"], json!(["direct"]));
    }

    #[test]
    fn classify_pairing_code_and_origin_gate_call_core() {
        assert_eq!(
            classify_pairing_code_inner("TND-ABCD-EFGH").unwrap(),
            "lan2_group"
        );
        assert_eq!(
            classify_pairing_code_inner("TND-ABCD-EFGH-JKLM").unwrap(),
            "remote3_group"
        );
        for bad in [
            "",
            "tnd-abcd-efgh",
            "TND-ABCD",
            "TND-ABCD-EFGH-JKLM-NOPQ",
            " TND-ABCD-EFGH",
        ] {
            assert!(classify_pairing_code_inner(bad).is_err(), "{bad:?}");
        }
        let origins = r#"["wss://relay.example.test"]"#;
        assert!(relay_auth_origin_allowed_inner(RELAY_V1, origins).unwrap());
        assert!(
            !relay_auth_origin_allowed_inner("wss://relay.example.test:8443/v1/relay", origins)
                .unwrap()
        );
        assert!(!relay_auth_origin_allowed_inner(RELAY_V1, "[]").unwrap());
        assert!(relay_auth_origin_allowed_inner(RELAY_V1, "not json").is_err());
    }

    #[test]
    fn deferred_v1_pairing_reports_host_then_commits_and_persists_signed_routes() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[DIRECT, RELAY_V1]);
        let cli = wasm_identity(0x41);
        let mut cli_roster = WasmRoster::new();
        let mut p = v1_pairing_to_host_verified(
            &mut host,
            &issued,
            &issued.uri,
            "",
            true,
            &cli,
            &mut cli_roster,
        );
        assert_eq!(p.report["host_verified"], json!(true));
        assert!(p.report.get("write_b64").is_none());
        assert_eq!(p.report["relay_pub_ok"], json!(true));
        assert_eq!(p.report["route_check"], json!("verified"));
        assert_eq!(p.report["route_seq"], json!(1.0));
        assert!(p.init.is_awaiting_commit());
        assert!(cli_roster.inner.get("host-l6a").is_none());

        let m3 = p.init.commit_claim_inner().unwrap();
        assert!(!m3.is_empty());
        assert!(!p.init.is_awaiting_commit());
        let resp_bytes = pair_writes(
            p.resp
                .feed_bytes(&m3, NOW, &mut host.mgr, &mut host.roster)
                .unwrap(),
        );
        let done = to_json(&p.init.step_bytes(&resp_bytes, &mut cli_roster).unwrap());
        let outcome = &done["outcome"];
        assert_eq!(outcome["status"], json!("pending"));
        assert_eq!(outcome["route_check"], json!("verified"));
        assert_eq!(
            outcome["routes"],
            json!([
                { "hint": DIRECT, "source": "signed" },
                { "hint": RELAY_V1, "source": "signed" },
            ])
        );
        assert!(outcome.get("routes_reason").is_some());
        assert!(outcome.get("route_reason").is_none());
        let entry = cli_roster.inner.get("host-l6a").unwrap();
        assert_eq!(entry.name, "Studio");
        assert_eq!(entry.route_meta.unwrap().seq, 1);
        assert_eq!(entry.route_meta.unwrap().origin, RouteOrigin::Uri);
        assert_eq!(entry.routes.len(), 2);
        assert!(p.init.commit_claim_inner().is_err());
    }

    #[test]
    fn deferred_v1_pairing_applies_persist_policy_and_operator_endpoint() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[DIRECT, RELAY_V1]);
        let cli = wasm_identity(0x41);
        let mut cli_roster = WasmRoster::new();
        let persist = json!({
            "route_policy": "committedOnly",
            "operator_endpoint": "wss://op.example.test/v1/relay",
            "winner_hint": RELAY_V1,
        })
        .to_string();
        let mut p = v1_pairing_to_host_verified(
            &mut host,
            &issued,
            &issued.uri,
            &persist,
            true,
            &cli,
            &mut cli_roster,
        );
        let m3 = p.init.commit_claim_inner().unwrap();
        let resp_bytes = pair_writes(
            p.resp
                .feed_bytes(&m3, NOW, &mut host.mgr, &mut host.roster)
                .unwrap(),
        );
        let done = to_json(&p.init.step_bytes(&resp_bytes, &mut cli_roster).unwrap());
        assert_eq!(
            done["outcome"]["routes"],
            json!([
                { "hint": RELAY_V1, "source": "signed" },
                { "hint": "wss://op.example.test/v1/relay", "source": "operator" },
            ])
        );
        let mut conflicting = PairRouteContext::new("TND-AAAA-AAAA");
        assert!(
            conflicting
                .set_options(r#"{"route_policy":"none","save_committed":true}"#)
                .is_err()
        );
        assert!(
            conflicting
                .set_options(r#"{"route_policy":"bogus"}"#)
                .is_err()
        );
    }

    #[test]
    fn deferred_v1_pairing_reports_invalid_and_rotated_route_statements() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[DIRECT, RELAY_V1]);
        let cli = wasm_identity(0x41);

        let tampered = flip_rs(&issued.uri);
        let mut cli_roster = WasmRoster::new();
        let mut p = v1_pairing_to_host_verified(
            &mut host,
            &issued,
            &tampered,
            "",
            true,
            &cli,
            &mut cli_roster,
        );
        assert_eq!(p.report["route_check"], json!("invalid"));
        assert_eq!(p.report["host_verified"], json!(true));
        // An invalid statement is fatal: the claim is never written.
        assert!(p.init.commit_claim_inner().is_err());
        assert!(cli_roster.inner.get("host-l6a").is_none());

        // A host that no longer hashes to the URI's `sh` is `route_key_rotated`.
        let mut rotated = TestHost::new(0x51, "host-l6a");
        let mut other_roster = WasmRoster::new();
        let p = v1_pairing_to_host_verified(
            &mut rotated,
            &issued,
            &issued.uri,
            "",
            false,
            &cli,
            &mut other_roster,
        );
        assert_eq!(p.report["route_check"], json!("route_key_rotated"));
        assert_eq!(p.report["relay_pub_ok"], json!(false));
    }

    #[test]
    fn deferred_v1_pairing_reports_relay_pub_mismatch() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[RELAY_V1]);
        let mut uri = PairingUri::new(
            "Studio",
            issued.parsed.code.clone(),
            issued.parsed.host_static_pub,
            issued.parsed.host_signing_pub_hash,
            vec![RELAY_V1.to_owned()],
            issued.parsed.host_id.clone(),
            issued.parsed.rotation_seq,
        );
        uri.relay_pub = Some([9; 32]);
        let forged = uri.try_encode().unwrap();
        let cli = wasm_identity(0x41);
        let mut cli_roster = WasmRoster::new();
        let p = v1_pairing_to_host_verified(
            &mut host,
            &issued,
            &forged,
            "",
            true,
            &cli,
            &mut cli_roster,
        );
        assert_eq!(p.report["relay_pub_ok"], json!(false));
        assert_eq!(p.report["route_check"], json!("unsigned"));
    }

    #[test]
    fn deferred_options_are_valid_only_before_start() {
        let cli = wasm_identity(0x41);
        let mut init = WasmPairInitiator::new_inner(
            &cli,
            "web",
            "browser",
            "TND-ABCD-EFGH",
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        init.start().unwrap();
        assert!(init.enable_deferred_claim_inner().is_err());
        let mut v2 =
            WasmV2PakePairInitiator::new_inner(&cli, "web", "browser", "TND-ABCD-EFGH", None)
                .unwrap();
        v2.start().unwrap();
        assert!(v2.enable_deferred_claim_inner().is_err());
        assert!(v2.commit_claim_inner().is_err());
    }

    #[test]
    fn deferred_v2_pairing_persists_signed_and_operator_routes_on_first_pairing() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[DIRECT, RELAY_V1]);
        let uri = &issued.parsed;
        let cli = wasm_identity(0x41);
        let mut cli_roster = WasmRoster::new();
        let pinned = json!({
            "host_id": uri.host_id,
            "static_pub_b64": b64url_encode(&uri.host_static_pub),
            "signing_pub_b64": b64url_encode(&uri.host_signing_pub_hash),
            "rotation_seq": uri.rotation_seq,
        })
        .to_string();
        let mut init =
            WasmV2PakePairInitiator::new_inner(&cli, "web", "browser", &uri.code, Some(&pinned))
                .unwrap();
        init.enable_deferred_claim_inner().unwrap();
        init.routes.set_uri(&issued.uri).unwrap();
        init.routes
            .set_options(r#"{"operator_endpoint":"wss://op.example.test/v2/relay#mailbox"}"#)
            .unwrap();
        let mut resp = V2PakePairResponder::new(
            &host.identity,
            PairingPathKind::Remote,
            PakeArgon2Params::default(),
        )
        .unwrap();
        let m1 = init.start().unwrap();
        let m2 = v2_pair_writes(
            resp.feed_bytes(&m1, NOW, &mut host.mgr, &mut host.roster)
                .unwrap(),
        );
        let report = to_json(&init.step_bytes(&m2, &mut cli_roster).unwrap());
        assert_eq!(report["host_verified"], json!(true));
        assert!(report.get("write_b64").is_none());
        assert_eq!(report["relay_pub_ok"], json!(true));
        assert_eq!(report["route_check"], json!("verified"));
        assert!(init.is_awaiting_commit());

        let m3 = init.commit_claim_inner().unwrap();
        let resp_bytes = v2_pair_writes(
            resp.feed_bytes(&m3, NOW, &mut host.mgr, &mut host.roster)
                .unwrap(),
        );
        let done = to_json(&init.step_bytes(&resp_bytes, &mut cli_roster).unwrap());
        assert_eq!(done["outcome"]["status"], json!("pending"));
        assert_eq!(done["outcome"]["route_check"], json!("verified"));
        assert!(done["outcome"].get("routes_reason").is_some());
        let entry = cli_roster.inner.get("host-l6a").unwrap();
        assert_eq!(entry.name, "Studio");
        assert!(entry.v2_secrets.is_some());
        assert_eq!(entry.min_wire_version, 2);
        let hints: Vec<(&str, &str)> = entry
            .routes
            .iter()
            .map(|r| (r.hint.as_str(), r.source.as_str()))
            .collect();
        assert!(hints.contains(&(RELAY_V1, "signed")));
        assert!(hints.contains(&("wss://op.example.test/v2/relay", "operator")));
        assert_eq!(entry.route_meta.unwrap().seq, 1);
    }

    // ---- Day-2 sessions against a rotated host ----

    struct RotatedHost {
        host: EndpointIdentity,
        old_static: [u8; 32],
        old_signing: HybridSigningPublicKey,
    }

    fn rotated_host() -> RotatedHost {
        let mut host = identity(0x20).with_host_id("host-route");
        let old_static = *host.static_key().public_bytes();
        let old_signing = host.signing_key().public_key().clone();
        host.rotate(
            StaticKeypair::from_scalar([0x22; 32]),
            SigningKeypair::from_seed([0x23; 32]),
            NOW,
        )
        .unwrap();
        RotatedHost {
            host,
            old_static,
            old_signing,
        }
    }

    fn host_side_roster(cli: &EndpointIdentity) -> Roster {
        let mut roster = Roster::new();
        roster
            .record_pending_pair(
                *cli.static_key().public_bytes(),
                None,
                "Cli".into(),
                "cli".into(),
                "abcd".into(),
            )
            .unwrap();
        roster.confirm_peer(&cli.device_id(), Some("abcd")).unwrap();
        roster
            .set_peer_v2_secrets(&cli.device_id(), secrets())
            .unwrap();
        roster
    }

    fn client_roster(rh: &RotatedHost) -> WasmRoster {
        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                rh.host.host_id().into(),
                "Host".into(),
                rh.old_static,
                Some(rh.old_signing.clone()),
                0,
                vec![],
            )
            .unwrap();
        roster
            .set_peer_v2_secrets(rh.host.host_id(), secrets())
            .unwrap();
        WasmRoster { inner: roster }
    }

    fn recovery_uri(host: &EndpointIdentity, hints: &[&str], rq: u64) -> String {
        let mut uri = PairingUri::new(
            "Studio",
            "TND-ABCD-EFGH-JKLM",
            *host.static_key().public_bytes(),
            host.signing_key().signing_pub_hash(),
            hints.iter().map(|h| (*h).to_owned()).collect(),
            Some(host.host_id().to_owned()),
            Some(host.rotation_seq()),
        );
        let needs_rp = hints.iter().any(|h| {
            classify_endpoint_hint(h).is_ok_and(|p| p == ProviderId::Relay) && !is_v2_relay_hint(h)
        });
        uri.relay_pub = needs_rp.then_some(*host.signing_key().ed25519_public_bytes());
        let prefix = format!("{}&rq={rq}", uri.try_encode().unwrap());
        let sig = sign_route_statement(host, &prefix);
        format!("{prefix}&rs={}", b64url_encode(&sig))
    }

    fn session_writes(actions: Vec<SessionAction>) -> Vec<u8> {
        collect_session_writes(actions)
    }

    struct V1Run {
        sess: WasmSessionClient,
        roster: WasmRoster,
        resp: SessionMachine,
        hroster: Roster,
        result: Result<String, WasmError>,
    }

    fn v1_run(rh: &RotatedHost, recovery: Option<&str>, route_seq: Option<f64>) -> V1Run {
        let cli = wasm_identity(0x40);
        let mut roster = client_roster(rh);
        let mut sess = WasmSessionClient::new_inner(&cli, rh.host.host_id(), None, None).unwrap();
        if let Some(rq) = route_seq {
            sess.with_route_seq_inner(Some(rq)).unwrap();
        }
        if let Some(uri) = recovery {
            sess.with_route_expectation_inner(rh.host.host_id(), Some(uri), None)
                .unwrap();
        }
        let mut resp = SessionMachine::new_responder(&rh.host, None).unwrap();
        let mut hroster = host_side_roster(&cli.inner);
        let m1 = sess.start().unwrap();
        let m2 = session_writes(resp.feed_bytes(&m1, NOW, 1, &mut hroster).unwrap());
        let result = sess.step_bytes(&m2, NOWF, 2.0, &mut roster);
        V1Run {
            sess,
            roster,
            resp,
            hroster,
            result,
        }
    }

    struct V2Run {
        sess: WasmV2SessionInitiator,
        roster: WasmRoster,
        resp: V2SessionResponder,
        hroster: Roster,
        result: Result<String, WasmError>,
    }

    fn v2_run(rh: &RotatedHost, recovery: Option<&str>, route_seq: Option<f64>) -> V2Run {
        let cli = wasm_identity(0x40);
        let mut roster = client_roster(rh);
        let mut sess =
            WasmV2SessionInitiator::new_inner(&cli, rh.host.host_id(), &roster, None, None)
                .unwrap();
        if let Some(rq) = route_seq {
            sess.with_route_seq_inner(Some(rq)).unwrap();
        }
        if let Some(uri) = recovery {
            sess.with_route_expectation_inner(rh.host.host_id(), Some(uri), None)
                .unwrap();
        }
        let mut resp = V2SessionResponder::new(&rh.host).unwrap();
        let mut hroster = host_side_roster(&cli.inner);
        let m1 = sess.start(NOWF).unwrap();
        let m2 = collect_v2_writes(resp.feed_bytes(&m1, NOW, 1, &mut hroster).unwrap());
        let result = sess.step_bytes(&m2, NOWF, 2.0, &mut roster);
        V2Run {
            sess,
            roster,
            resp,
            hroster,
            result,
        }
    }

    const TAMPERED_ERR: &str = "route statement does not verify";

    #[test]
    fn session_recovery_expectation_and_evidence_v1_and_v2() {
        for v2 in [false, true] {
            let rh = rotated_host();
            let valid = recovery_uri(&rh.host, &[RELAY_V1, DIRECT], 5);
            let tampered = valid.replacen("192.168.1.20", "192.168.1.21", 1);
            assert_ne!(valid, tampered);

            // A tampered statement fails before msg3, keeps the rotation evidence and changes
            // nothing in the roster.
            let (err, rotation, statement, before, after) = if v2 {
                let rh2 = rotated_host();
                let roster = client_roster(&rh2);
                let before = serde_json::to_value(&roster.inner).unwrap();
                let run = v2_run(&rh2, Some(&tampered), None);
                (
                    run.result.unwrap_err(),
                    run.sess.evidence.rotation_json().unwrap(),
                    run.sess.evidence.recovery_json(),
                    before,
                    serde_json::to_value(&run.roster.inner).unwrap(),
                )
            } else {
                let roster = client_roster(&rh);
                let before = serde_json::to_value(&roster.inner).unwrap();
                let run = v1_run(&rh, Some(&tampered), None);
                (
                    run.result.unwrap_err(),
                    run.sess.evidence.rotation_json().unwrap(),
                    run.sess.evidence.recovery_json(),
                    before,
                    serde_json::to_value(&run.roster.inner).unwrap(),
                )
            };
            assert!(err.message.contains(TAMPERED_ERR), "v2={v2}: {err}");
            assert_eq!(to_json(&rotation).as_array().unwrap().len(), 1, "v2={v2}");
            assert!(statement.is_none());
            assert_eq!(before, after, "v2={v2}");

            // A valid statement is checked before the rotation is applied and exposes its
            // verified fields and the keys the host presented.
            let (result, rotation, statement, keys, roster) = if v2 {
                let run = v2_run(&rh, Some(&valid), None);
                (
                    run.result,
                    run.sess.evidence.rotation_json().unwrap(),
                    run.sess.verified_recovery_statement_json(),
                    run.sess.presented_host_keys_json(),
                    run.roster,
                )
            } else {
                let run = v1_run(&rh, Some(&valid), None);
                (
                    run.result,
                    run.sess.evidence.rotation_json().unwrap(),
                    run.sess.verified_recovery_statement_json(),
                    run.sess.presented_host_keys_json(),
                    run.roster,
                )
            };
            result.unwrap();
            let statement = to_json(&statement.unwrap());
            assert_eq!(statement["route_seq"], json!(5.0));
            assert_eq!(statement["hints"], json!([RELAY_V1, DIRECT]));
            let keys = to_json(&keys.unwrap());
            assert_eq!(
                keys["static_pub_b64"],
                json!(b64url_encode(rh.host.static_key().public_bytes()))
            );
            assert_eq!(
                keys["signing_pub_b64"],
                json!(rh.host.signing_key().public_key().to_b64url())
            );
            assert_eq!(keys["wire"], json!(if v2 { 2 } else { 1 }));

            // The browser reconciliation steps against a fresh roster at the old pin.
            let mut main = client_roster(&rh);
            let snap = main.pin_snapshot_inner(rh.host.host_id()).unwrap();
            main.reconcile_rotation_evidence_inner(rh.host.host_id(), &snap, &rotation)
                .unwrap();
            let seq = main
                .apply_verified_rotation_inner(rh.host.host_id(), &rotation)
                .unwrap();
            assert_eq!(seq, 1.0);
            let static_b64 = keys["static_pub_b64"].as_str().unwrap();
            let signing_b64 = keys["signing_pub_b64"].as_str().unwrap();
            main.check_established_session_inner(
                rh.host.host_id(),
                static_b64,
                signing_b64,
                1 + u8::from(v2),
            )
            .unwrap();
            assert_eq!(
                main.inner.get(rh.host.host_id()).unwrap().signing_pub,
                roster.inner.get(rh.host.host_id()).unwrap().signing_pub
            );
        }
    }

    #[test]
    fn route_options_are_set_before_start_and_opt_in_route_sets() {
        let rh = rotated_host();
        let cli = wasm_identity(0x40);
        let roster = client_roster(&rh);

        let mut v1 = WasmSessionClient::new_inner(&cli, rh.host.host_id(), None, None).unwrap();
        v1.start().unwrap();
        assert!(v1.with_route_seq_inner(Some(1.0)).is_err());
        assert!(
            v1.with_route_expectation_inner(rh.host.host_id(), None, None)
                .is_err()
        );
        // A refused call leaves the started session usable.
        assert!(!v1.is_closed());
        let mut v2 =
            WasmV2SessionInitiator::new_inner(&cli, rh.host.host_id(), &roster, None, None)
                .unwrap();
        v2.start(NOWF).unwrap();
        assert!(v2.with_route_seq_inner(Some(1.0)).is_err());
        assert!(
            v2.with_route_expectation_inner(rh.host.host_id(), None, None)
                .is_err()
        );
        assert!(!v2.is_closed());

        let mut fresh = WasmSessionClient::new_inner(&cli, rh.host.host_id(), None, None).unwrap();
        assert!(fresh.with_route_seq_inner(Some(2f64.powi(53))).is_err());
        assert!(fresh.with_route_seq_inner(Some(-1.0)).is_err());
        fresh.with_route_seq_inner(None).unwrap();
        let other = recovery_uri(&identity(0x77).with_host_id("someone-else"), &[RELAY_V1], 1);
        assert!(
            fresh
                .with_route_expectation_inner(rh.host.host_id(), Some(&other), None)
                .unwrap_err()
                .message
                .contains("different host")
        );

        // `SessionHello.route_seq` reaches the host before msg3, on both wires.
        let valid = recovery_uri(&rh.host, &[RELAY_V1], 5);
        let mut run = v1_run(&rh, Some(&valid), Some(7.0));
        let m3 =
            b64url_decode(to_json(&run.result.unwrap())["write_b64"].as_str().unwrap()).unwrap();
        run.resp.feed_bytes(&m3, NOW, 3, &mut run.hroster).unwrap();
        assert_eq!(run.resp.peer_route_seq(), Some(7));
        let mut run2 = v2_run(&rh, Some(&valid), Some(7.0));
        run2.result.unwrap();
        let m3 = run2.sess.poll_write();
        run2.resp
            .feed_bytes(&m3, NOW, 3, &mut run2.hroster)
            .unwrap();
        assert_eq!(run2.resp.peer_route_seq(), Some(7));
        // Without the option the host sees no opt-in.
        let mut plain = v1_run(&rh, None, None);
        let m3 = b64url_decode(
            to_json(&plain.result.unwrap())["write_b64"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        plain
            .resp
            .feed_bytes(&m3, NOW, 3, &mut plain.hroster)
            .unwrap();
        assert_eq!(plain.resp.peer_route_seq(), None);
    }

    #[test]
    fn route_sets_drain_and_apply_under_the_high_water_rule() {
        let rh = rotated_host();
        let valid = recovery_uri(&rh.host, &[RELAY_V1], 5);
        let set = RouteSet::sign(
            &rh.host,
            9,
            NOW,
            vec![RELAY_V1.to_owned(), DIRECT.to_owned()],
        )
        .unwrap();

        // Wire v1.
        let mut run = v1_run(&rh, Some(&valid), Some(0.0));
        let m3 =
            b64url_decode(to_json(&run.result.unwrap())["write_b64"].as_str().unwrap()).unwrap();
        run.resp.feed_bytes(&m3, NOW, 3, &mut run.hroster).unwrap();
        let frame = session_writes(run.resp.send_route_set(&set.encode(), 30).unwrap());
        run.sess
            .step_bytes(&frame, NOWF, 31.0, &mut run.roster)
            .unwrap();
        let payloads: Vec<String> =
            serde_json::from_str(&run.sess.take_route_sets_json().unwrap()).unwrap();
        assert_eq!(payloads.len(), 1);
        assert!(run.sess.take_route_sets_json().unwrap() == "[]");
        let payload = b64url_decode(&payloads[0]).unwrap();
        let applied = to_json(
            &run.roster
                .apply_route_announcement_inner(rh.host.host_id(), &payload, NOWF)
                .unwrap(),
        );
        assert_eq!(applied["outcome"], json!("applied"));
        assert_eq!(applied["added"], json!([RELAY_V1, DIRECT]));
        let meta = run
            .roster
            .inner
            .get(rh.host.host_id())
            .unwrap()
            .route_meta
            .unwrap();
        assert_eq!((meta.seq, meta.origin), (9, RouteOrigin::Session));
        let again = to_json(
            &run.roster
                .apply_route_announcement_inner(rh.host.host_id(), &payload, NOWF)
                .unwrap(),
        );
        assert_eq!(
            again,
            json!({ "outcome": "ignored", "reason": "stale_seq" })
        );
        assert!(
            run.roster
                .apply_route_announcement_inner(rh.host.host_id(), b"garbage", NOWF)
                .is_err()
        );

        // Wire v2.
        let mut run = v2_run(&rh, Some(&valid), Some(0.0));
        run.result.unwrap();
        let m3 = run.sess.poll_write();
        run.resp.feed_bytes(&m3, NOW, 3, &mut run.hroster).unwrap();
        let frame = collect_v2_writes(run.resp.send_route_set(&set.encode(), 30).unwrap());
        run.sess
            .step_bytes(&frame, NOWF, 31.0, &mut run.roster)
            .unwrap();
        let payloads: Vec<String> = serde_json::from_str(&run.sess.take_route_sets_json()).unwrap();
        assert_eq!(payloads.len(), 1);
        let payload = b64url_decode(&payloads[0]).unwrap();
        let applied = to_json(
            &run.roster
                .apply_route_announcement_inner(rh.host.host_id(), &payload, NOWF)
                .unwrap(),
        );
        assert_eq!(applied["outcome"], json!("applied"));
    }

    #[test]
    fn rotation_reconcile_detects_forks_and_rejects_foreign_snapshots() {
        let rh = rotated_host();
        let mut roster = client_roster(&rh);
        roster
            .inner
            .insert_pinned_host(
                "other-host".into(),
                "Other".into(),
                *identity(0x61).static_key().public_bytes(),
                Some(identity(0x61).signing_key().public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        let snap = roster.pin_snapshot_inner(rh.host.host_id()).unwrap();
        assert_eq!(snap.peer_id(), rh.host.host_id());
        assert_eq!(snap.min_wire_version(), 1);
        assert!(roster.pin_snapshot_inner("nobody").is_err());

        let chain = serde_json::to_string(rh.host.rotation_chain()).unwrap();
        roster
            .reconcile_rotation_evidence_inner(rh.host.host_id(), &snap, &chain)
            .unwrap();
        roster
            .reconcile_rotation_evidence_inner(rh.host.host_id(), &snap, "")
            .unwrap();
        assert_eq!(
            roster
                .reconcile_rotation_evidence_inner("other-host", &snap, &chain)
                .unwrap_err(),
            WasmError::from(CoreError::HostKeyUnverified)
        );

        // Two different successors of the pinned key are a fork: the entry is revoked.
        let mut sibling = identity(0x20).with_host_id("host-route");
        sibling
            .rotate(
                StaticKeypair::from_scalar([0x32; 32]),
                SigningKeypair::from_seed([0x33; 32]),
                NOW,
            )
            .unwrap();
        let mut records = rh.host.rotation_chain().to_vec();
        records.extend_from_slice(sibling.rotation_chain());
        let err = roster
            .reconcile_rotation_evidence_inner(
                rh.host.host_id(),
                &snap,
                &serde_json::to_string(&records).unwrap(),
            )
            .unwrap_err();
        assert_eq!(err.code, "rotation_fork_detected", "{err}");
        assert_eq!(
            roster.inner.get(rh.host.host_id()).unwrap().state,
            PeerState::Revoked
        );
    }

    #[test]
    fn established_session_check_enforces_pin_floor_and_state() {
        let rh = rotated_host();
        let mut roster = client_roster(&rh);
        let id = rh.host.host_id();
        let old_static = b64url_encode(&rh.old_static);
        let old_signing = rh.old_signing.to_b64url();
        roster
            .check_established_session_inner(id, &old_static, &old_signing, 1)
            .unwrap();
        let new_static = b64url_encode(rh.host.static_key().public_bytes());
        let new_signing = rh.host.signing_key().public_key().to_b64url();
        assert_eq!(
            roster
                .check_established_session_inner(id, &new_static, &new_signing, 1)
                .unwrap_err(),
            WasmError::from(CoreError::HostKeyUnverified)
        );
        roster.inner.set_peer_min_wire_version(id, 2).unwrap();
        assert!(
            roster
                .check_established_session_inner(id, &old_static, &old_signing, 1)
                .unwrap_err()
                .code
                == "version_downgrade"
        );
        roster
            .check_established_session_inner(id, &old_static, &old_signing, 2)
            .unwrap();
        assert!(
            roster
                .check_established_session_inner("nobody", &old_static, &old_signing, 2)
                .is_err()
        );
        assert!(
            roster
                .check_established_session_inner(id, "not-b64", &old_signing, 2)
                .is_err()
        );
    }

    #[test]
    fn crl_evidence_exports_from_clones_and_merges_only_verifiable_lists() {
        let rh = rotated_host();
        let mut main = client_roster(&rh);
        main.inner
            .insert_pinned_host(
                "victim".into(),
                "Victim".into(),
                *identity(0x61).static_key().public_bytes(),
                Some(identity(0x61).signing_key().public_key().clone()),
                0,
                vec![],
            )
            .unwrap();
        let mut clone = main.clone_roster();
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: rh.host.host_id().to_owned(),
                seq: 1,
                ts: "2026-11-21T12:00:00Z".to_owned(),
                revoked_devices: vec!["victim".to_owned()],
                revoked_nonces: Vec::new(),
            },
            // The clone verifies against the pin it holds (the old key).
            &SigningKeypair::from_seed([0x21; 32]),
        )
        .unwrap();
        assert!(main.export_crls_inner().is_empty());
        clone
            .inner
            .ingest_crl(crl, rh.host.host_id(), &rh.old_signing)
            .unwrap();
        // The clone is independent of its source.
        assert_eq!(main.inner.get("victim").unwrap().state, PeerState::Active);
        assert_eq!(clone.inner.get("victim").unwrap().state, PeerState::Revoked);

        let exported = serde_json::to_string(&clone.export_crls_inner()).unwrap();
        let exported_json = to_json(&exported);
        assert_eq!(exported_json.as_array().unwrap().len(), 1);
        assert_eq!(exported_json[0]["issuer"], json!(rh.host.host_id()));
        assert_eq!(main.merge_crl_evidence_inner(&exported).unwrap(), 1.0);
        assert_eq!(main.inner.get("victim").unwrap().state, PeerState::Revoked);
        assert_eq!(main.inner.crl(rh.host.host_id()).unwrap().seq, 1);

        // Unknown issuers and malformed JSON ingest nothing.
        let mut fresh = client_roster(&rh);
        let unknown = exported.replace(rh.host.host_id(), "nobody");
        assert_eq!(fresh.merge_crl_evidence_inner(&unknown).unwrap(), 0.0);
        assert_eq!(fresh.merge_crl_evidence_inner("").unwrap(), 0.0);
        assert!(fresh.merge_crl_evidence_inner("{").is_err());
    }

    fn roster_with_routes() -> (WasmRoster, EndpointIdentity) {
        let host = identity(0x31).with_host_id("host-l6a");
        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                "host-l6a".into(),
                "Host".into(),
                *host.static_key().public_bytes(),
                Some(host.signing_key().public_key().clone()),
                0,
                vec!["wss://legacy.example.test/v1/relay".into()],
            )
            .unwrap();
        roster.set_peer_v2_secrets("host-l6a", secrets()).unwrap();
        (WasmRoster { inner: roster }, host)
    }

    #[test]
    fn apply_signed_route_uri_follows_the_high_water_rules() {
        let (mut roster, host) = roster_with_routes();
        let uri5 = recovery_uri(&host, &[RELAY_V1, RELAY_V2, DIRECT], 5);
        let out = to_json(&roster.apply_signed_route_uri_inner(&uri5, None).unwrap());
        assert_eq!(out["applied"], json!(true));
        assert_eq!(out["peer_id"], json!("host-l6a"));
        assert_eq!(out["route_meta"]["seq"], json!(5));
        assert_eq!(out["routes"].as_array().unwrap().len(), 3);

        let uri4 = recovery_uri(&host, &[RELAY_V1], 4);
        let stale = to_json(&roster.apply_signed_route_uri_inner(&uri4, None).unwrap());
        assert_eq!(stale["applied"], json!(false));
        assert_eq!(stale["reason"], json!("stale_route_seq"));
        assert_eq!(stale["routes"].as_array().unwrap().len(), 3);

        let approved = to_json(
            &roster
                .apply_signed_route_uri_inner(&uri4, Some(r#"{"replace_routes":true}"#))
                .unwrap(),
        );
        assert_eq!(approved["applied"], json!(true));
        assert_eq!(approved["route_meta"]["origin"], json!("approved"));
        assert_eq!(approved["route_meta"]["seq"], json!(5));
        assert_eq!(
            approved["routes"],
            json!([{ "hint": RELAY_V1, "source": "signed" }])
        );

        let uri9 = recovery_uri(&host, &[DIRECT], 9);
        let policy = to_json(
            &roster
                .apply_signed_route_uri_inner(&uri9, Some(r#"{"route_policy":"none"}"#))
                .unwrap(),
        );
        assert_eq!(policy["applied"], json!(false));
        assert_eq!(policy["reason"], json!("route_policy"));
        assert_eq!(policy["route_meta"]["seq"], json!(5));
    }

    #[test]
    fn apply_signed_route_uri_fails_closed_without_changing_the_roster() {
        let (mut roster, host) = roster_with_routes();
        let before = serde_json::to_value(&roster.inner).unwrap();
        let signed = recovery_uri(&host, &[RELAY_V1], 5);
        let unsigned = signed.split("&rq=").next().unwrap().to_owned();
        let tampered = flip_rs(&signed);
        let stranger = recovery_uri(&identity(0x77), &[RELAY_V1], 5);
        for (uri, expect) in [
            (unsigned.as_str(), "not host-signed"),
            (tampered.as_str(), TAMPERED_ERR),
            (stranger.as_str(), "no paired host matches"),
        ] {
            let err = roster.apply_signed_route_uri_inner(uri, None).unwrap_err();
            assert!(err.message.contains(expect), "{err}");
        }
        assert!(
            roster
                .apply_signed_route_uri_inner("not a uri", None)
                .is_err()
        );
        assert!(
            roster
                .apply_signed_route_uri_inner(&signed, Some(r#"{"route_policy":"bogus"}"#))
                .is_err()
        );
        assert_eq!(before, serde_json::to_value(&roster.inner).unwrap());
    }

    #[test]
    fn set_and_clear_operator_routes_normalize_and_fail_closed() {
        let (mut roster, host) = roster_with_routes();
        let ed = b64url_encode(host.signing_key().ed25519_public_bytes());
        let routes = json!([
            "10.0.0.5:9100",
            "/run/tendril.sock",
            format!("wss://op.example.test/v1/relay#{ed}"),
            "wss://mail.example.test/v2/relay#mailbox",
        ])
        .to_string();
        let out = to_json(&roster.set_routes_inner("host-l6a", &routes).unwrap());
        let hints: Vec<&str> = out
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["hint"].as_str().unwrap())
            .collect();
        assert_eq!(
            hints,
            [
                "direct:10.0.0.5:9100",
                "local:/run/tendril.sock",
                "wss://op.example.test/v1/relay",
                RELAY_V2,
            ]
        );
        assert!(
            out.as_array()
                .unwrap()
                .iter()
                .all(|r| r["source"] == "operator")
        );

        // Every failure leaves the previous list in place.
        let before = serde_json::to_value(&roster.inner).unwrap();
        let wrong_key = format!(
            "wss://op.example.test/v1/relay#{}",
            b64url_encode(identity(0x77).signing_key().ed25519_public_bytes())
        );
        let too_many = json!([
            "10.0.0.1:1",
            "10.0.0.2:1",
            "10.0.0.3:1",
            "10.0.0.4:1",
            "10.0.0.5:1",
            "10.0.0.6:1",
            "10.0.0.7:1"
        ])
        .to_string();
        for (raw, expect) in [
            (
                json!([wrong_key]).to_string(),
                "does not match the pinned host key",
            ),
            (
                json!(["wss://op.example.test/v1/relay#short"]).to_string(),
                "invalid relay key",
            ),
            (
                json!(["10.0.0.5:9100#x"]).to_string(),
                "fragment not allowed",
            ),
            (
                json!(["wss://240.0.0.1/v1/relay"]).to_string(),
                "blocked_address",
            ),
            (json!(["wss://[fe80::1]/v1/relay"]).to_string(), ""),
            (json!(["direct:169.254.169.254:80"]).to_string(), ""),
            (
                json!(["wss://metadata.google.internal/v1/relay"]).to_string(),
                "invalid endpoint",
            ),
            (json!(["wss://:443/v1/relay"]).to_string(), ""),
            (too_many, "at most 6 operator routes"),
        ] {
            let err = roster.set_routes_inner("host-l6a", &raw).unwrap_err();
            assert!(err.message.contains(expect), "{raw}: {err}");
            assert_eq!(
                before,
                serde_json::to_value(&roster.inner).unwrap(),
                "{raw}"
            );
        }
        assert!(roster.set_routes_inner("nobody", "[]").is_err());

        roster
            .clear_routes_inner("host-l6a", Some("operator"))
            .unwrap();
        assert!(roster.inner.get("host-l6a").unwrap().routes.is_empty());
        assert!(
            roster
                .clear_routes_inner("host-l6a", Some("bogus"))
                .is_err()
        );
        roster.set_routes_inner("host-l6a", "").unwrap();
    }

    fn candidates_of(v: &serde_json::Value) -> Vec<(String, String)> {
        v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["hint"].as_str().unwrap().to_owned(),
                    c["source"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    fn skipped_of(v: &serde_json::Value) -> Vec<(String, String)> {
        v["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["hint"].as_str().unwrap().to_owned(),
                    c["reason"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn session_candidates_filter_stored_routes_by_wire_gate_and_scheme() {
        let (mut roster, host) = roster_with_routes();
        let ed = b64url_encode(host.signing_key().ed25519_public_bytes());
        let iroh = "iroh://abcdefghijklmnop";
        let signed = recovery_uri(&host, &[RELAY_V1, RELAY_V2, DIRECT, iroh], 3);
        roster.apply_signed_route_uri_inner(&signed, None).unwrap();
        roster
            .set_routes_inner(
                "host-l6a",
                &json!([
                    "wss://op.example.test/v1/relay",
                    RELAY_V1.replace("relay.", "alt.")
                ])
                .to_string(),
            )
            .unwrap();

        // Wire v1 drops every /v2/relay hint and what a browser cannot dial.
        let v1 = to_json(
            &roster
                .session_candidates_inner("host-l6a", Some("{}"))
                .unwrap(),
        );
        assert_eq!(
            candidates_of(&v1),
            [
                (RELAY_V1.to_owned(), "signed".to_owned()),
                (
                    "wss://op.example.test/v1/relay".to_owned(),
                    "operator".to_owned()
                ),
                (
                    "wss://alt.example.test/v1/relay".to_owned(),
                    "operator".to_owned()
                ),
            ]
        );
        let skipped = skipped_of(&v1);
        assert!(skipped.contains(&(RELAY_V2.to_owned(), "wire_v1_no_relay_v2".to_owned())));
        assert!(skipped.contains(&(DIRECT.to_owned(), "browser_unsupported".to_owned())));
        assert!(skipped.contains(&(iroh.to_owned(), "p2p_feature_disabled".to_owned())));
        assert_eq!(v1["relay_key_b64"], json!(ed));
        assert_eq!(v1["legacy_relay_hints"], json!(true));
        assert_eq!(v1["route_seq"], json!(0.0));

        // Wire v2 admits the stored signed /v2/relay hint; p2p ranks before relay.
        let v2 = to_json(
            &roster
                .session_candidates_inner("host-l6a", Some(r#"{"wire":2,"p2p":true}"#))
                .unwrap(),
        );
        let hints: Vec<String> = candidates_of(&v2).into_iter().map(|(h, _)| h).collect();
        assert_eq!(hints[0], iroh);
        assert!(hints.contains(&RELAY_V2.to_owned()));
        assert_eq!(v2["candidates"][0]["provider"], json!("p2p"));

        // The policy decides the route_seq to send.
        let none = to_json(
            &roster
                .session_candidates_inner("host-l6a", Some(r#"{"route_policy":"none"}"#))
                .unwrap(),
        );
        assert_eq!(none["route_seq"], serde_json::Value::Null);
        assert!(
            roster
                .session_candidates_inner("host-l6a", Some(r#"{"wire":3}"#))
                .is_err()
        );
        assert!(roster.session_candidates_inner("nobody", None).is_err());
    }

    #[test]
    fn session_candidates_gate_v2_relay_and_unauthorized_sources() {
        let (mut roster, host) = roster_with_routes();
        roster.inner.get("host-l6a").map(|_| ()).unwrap();
        // A committed-only /v2/relay cannot exist; an unsigned stored route is never
        // authorized. Only operator and signed sources pass the gate.
        let signed = recovery_uri(&host, &[RELAY_V2], 3);
        roster.apply_signed_route_uri_inner(&signed, None).unwrap();
        let wire2 = r#"{"wire":2}"#;
        let ok = to_json(
            &roster
                .session_candidates_inner("host-l6a", Some(wire2))
                .unwrap(),
        );
        assert_eq!(
            candidates_of(&ok),
            [(RELAY_V2.to_owned(), "signed".to_owned())]
        );

        // Without v2 secrets the same stored route is skipped.
        let mut no_secrets = roster.clone_roster();
        let mut json_roster: serde_json::Value = serde_json::to_value(&no_secrets.inner).unwrap();
        json_roster["entries"]["host-l6a"]
            .as_object_mut()
            .unwrap()
            .remove("v2_secrets");
        no_secrets
            .replace_from_json(&json_roster.to_string())
            .unwrap();
        let skipped = to_json(
            &no_secrets
                .session_candidates_inner("host-l6a", Some(wire2))
                .unwrap(),
        );
        assert!(candidates_of(&skipped).is_empty());
        assert_eq!(
            skipped_of(&skipped),
            [(RELAY_V2.to_owned(), "relay_v2_not_authorized".to_owned())]
        );

        // A /v2/relay hint that only a recovery URI carries is not an authorized stored route.
        let recovery = recovery_uri(&host, &["wss://other.example.test/v2/relay"], 9);
        let out = to_json(
            &roster
                .session_candidates_inner(
                    "host-l6a",
                    Some(&json!({ "wire": 2, "recovery_uri": recovery }).to_string()),
                )
                .unwrap(),
        );
        assert_eq!(
            skipped_of(&out),
            [(
                "wss://other.example.test/v2/relay".to_owned(),
                "relay_v2_not_authorized".to_owned()
            )]
        );
        assert_eq!(
            candidates_of(&out),
            [(RELAY_V2.to_owned(), "signed".to_owned())]
        );

        // Revoked and pending peers fail the whole call.
        let mut revoked = roster.clone_roster();
        revoked.inner.revoke_peer("host-l6a").unwrap();
        assert!(
            revoked
                .session_candidates_inner("host-l6a", None)
                .unwrap_err()
                .code
                == "peer_revoked"
        );
    }

    #[test]
    fn session_candidates_add_signed_recovery_hints_after_the_same_checks() {
        let (mut roster, host) = roster_with_routes();
        roster
            .set_routes_inner("host-l6a", &json!([RELAY_V1]).to_string())
            .unwrap();
        let hints = [
            RELAY_V1,
            "wss://new.example.test/v1/relay",
            "wss://240.0.0.1/v1/relay",
            "ws://127.0.0.1:9/v1/relay",
            "local:/run/x.sock",
        ];
        let signed = recovery_uri(&host, &hints, 8);
        let call = |opts: serde_json::Value| {
            to_json(
                &roster
                    .session_candidates_inner("host-l6a", Some(&opts.to_string()))
                    .unwrap(),
            )
        };
        let out = call(json!({ "wire": 2, "recovery_uri": signed }));
        assert_eq!(
            candidates_of(&out),
            [
                ("ws://127.0.0.1:9/v1/relay".to_owned(), "uri".to_owned()),
                (RELAY_V1.to_owned(), "operator".to_owned()),
                (
                    "wss://new.example.test/v1/relay".to_owned(),
                    "uri".to_owned()
                ),
            ]
        );
        let skipped = skipped_of(&out);
        assert!(skipped.contains(&(
            "wss://240.0.0.1/v1/relay".to_owned(),
            "blocked_address".to_owned()
        )));
        assert!(!skipped.iter().any(|(h, _)| h.starts_with("local:")));
        assert_eq!(
            out["relay_key_b64"],
            json!(b64url_encode(host.signing_key().ed25519_public_bytes()))
        );

        // An unsigned recovery URI adds no candidates; a URI of another host is an error.
        let unsigned = signed.split("&rq=").next().unwrap().to_owned();
        let none = call(json!({ "recovery_uri": unsigned }));
        assert_eq!(
            candidates_of(&none),
            [(RELAY_V1.to_owned(), "operator".to_owned())]
        );
        let foreign = recovery_uri(&identity(0x77).with_host_id("someone-else"), &[RELAY_V1], 1);
        assert!(
            roster
                .session_candidates_inner(
                    "host-l6a",
                    Some(&json!({ "recovery_uri": foreign }).to_string())
                )
                .is_err()
        );
    }

    /// Encodings of 32 bytes that are not usable Ed25519 keys: all zero and the identity point.
    fn bad_ed25519_keys() -> [String; 2] {
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        for key in [[0u8; 32], identity_point] {
            assert!(!tendril_core::crypto::is_valid_ed25519_public_key(&key));
        }
        [b64url_encode(&[0u8; 32]), b64url_encode(&identity_point)]
    }

    #[test]
    fn operator_relay_keys_must_be_valid_ed25519_points() {
        let (mut roster, host) = roster_with_routes();
        let before = serde_json::to_value(&roster.inner).unwrap();
        for key in bad_ed25519_keys() {
            let raw = format!("wss://op.example.test/v1/relay#{key}");
            let err = normalize_operator_endpoint(&raw).unwrap_err();
            assert_eq!(err.code, "invalid_pairing_uri", "{err}");
            assert!(err.message.contains("invalid relay key"), "{err}");
            assert!(
                roster
                    .set_routes_inner("host-l6a", &json!([raw]).to_string())
                    .is_err()
            );
            let err = parse_route_expectation("host-l6a", None, Some(key.as_str())).unwrap_err();
            assert_eq!(err.code, "invalid_pairing_uri", "{err}");
        }
        assert_eq!(before, serde_json::to_value(&roster.inner).unwrap());
        let ed = b64url_encode(host.signing_key().ed25519_public_bytes());
        assert!(parse_route_expectation("host-l6a", None, Some(&ed)).is_ok());
        assert!(
            normalize_operator_endpoint(&format!("wss://op.example.test/v1/relay#{ed}")).is_ok()
        );
    }

    #[cfg(feature = "p2p-iroh")]
    #[test]
    fn operator_iroh_relay_urls_use_the_p2p_relay_validation() {
        let id = "iroh://abcdefghijklmnop";
        for bad in [
            format!("{id}?relay=https://relay.example.test/?token=x"),
            format!("{id}?relay=https://relay.example.test/path?"),
        ] {
            let err = normalize_peer_routes(std::slice::from_ref(&bad)).unwrap_err();
            assert!(err.message.contains("invalid URL"), "{bad}: {err}");
        }
        assert!(
            normalize_peer_routes(&[format!("{id}?relay=https://relay.example.test/")]).is_ok()
        );
        assert!(normalize_peer_routes(&[format!("{id}?relay=http://127.0.0.1:3340/")]).is_ok());
    }

    fn endpoints_of(v: &serde_json::Value) -> Vec<(String, String)> {
        v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["hint"].as_str().unwrap().to_owned(),
                    c["endpoint"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn session_candidates_strip_iroh_relays_and_blocked_destinations() {
        let (mut roster, host) = roster_with_routes();
        let signed_hint = "iroh://signedpeer?addr=203.0.113.5:4433&addr=240.0.0.1:1&relay=https://r.example.test/";
        let signed_blocked_only = "iroh://signedblocked?addr=240.0.0.1:1";
        let signed = recovery_uri(&host, &[signed_hint, signed_blocked_only], 3);
        roster.apply_signed_route_uri_inner(&signed, None).unwrap();
        let operator_hint = "iroh://operatorpeer?addr=240.0.0.1:1&addr=203.0.113.7:1&relay=https://op.example.test/";
        let operator_blocked = "iroh://operatorblocked?addr=240.0.0.1:1&relay=https://[fec0::1]/";
        roster
            .inner
            .set_routes(
                "host-l6a",
                [operator_hint, operator_blocked]
                    .iter()
                    .map(|h| OperatorEndpoint {
                        hint: (*h).to_owned(),
                        relay_key: None,
                    })
                    .collect(),
            )
            .unwrap();
        let recovery_hint = "iroh://recoverypeer?relay=https://r2.example.test/&addr=203.0.113.9:9";
        let recovery = recovery_uri(&host, &[recovery_hint], 9);
        let out = to_json(
            &roster
                .session_candidates_inner(
                    "host-l6a",
                    Some(&json!({ "p2p": true, "recovery_uri": recovery }).to_string()),
                )
                .unwrap(),
        );
        let endpoints = endpoints_of(&out);
        // Non-operator hints lose every relay= and their blocked addr=; operator hints keep
        // their relays and lose only blocked destinations.
        for expected in [
            (signed_hint, "iroh://signedpeer?addr=203.0.113.5:4433"),
            (signed_blocked_only, "iroh://signedblocked"),
            (
                operator_hint,
                "iroh://operatorpeer?addr=203.0.113.7:1&relay=https://op.example.test/",
            ),
            (recovery_hint, "iroh://recoverypeer?addr=203.0.113.9:9"),
        ] {
            assert!(
                endpoints.contains(&(expected.0.to_owned(), expected.1.to_owned())),
                "{expected:?} not in {endpoints:?}"
            );
        }
        assert_eq!(
            skipped_of(&out),
            [(operator_blocked.to_owned(), "blocked_address".to_owned())]
        );
    }

    #[test]
    fn session_candidates_fail_wire_v1_below_the_peer_floor() {
        let (mut roster, _host) = roster_with_routes();
        roster
            .set_routes_inner("host-l6a", &json!([RELAY_V1]).to_string())
            .unwrap();
        roster
            .inner
            .set_peer_min_wire_version("host-l6a", 2)
            .unwrap();
        let err = roster
            .session_candidates_inner("host-l6a", Some(r#"{"wire":1}"#))
            .unwrap_err();
        assert_eq!(err.code, "version_downgrade", "{err}");
        assert_eq!(
            roster
                .session_candidates_inner("host-l6a", None)
                .unwrap_err()
                .code,
            "version_downgrade"
        );
        assert!(
            roster
                .session_candidates_inner("host-l6a", Some(r#"{"wire":2}"#))
                .is_ok()
        );
    }

    #[test]
    fn operator_relay_key_conflicting_with_the_uri_rp_fails_before_dialing() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[RELAY_V1]);
        assert!(issued.parsed.relay_pub.is_some());
        let other = b64url_encode(identity(0x77).signing_key().ed25519_public_bytes());
        let own = b64url_encode(host.identity.signing_key().ed25519_public_bytes());
        let conflicting =
            json!({ "operator_endpoint": format!("wss://op.example.test/v1/relay#{other}") })
                .to_string();
        let matching =
            json!({ "operator_endpoint": format!("wss://op.example.test/v1/relay#{own}") })
                .to_string();

        let mut uri_first = PairRouteContext::new(&issued.parsed.code);
        uri_first.set_uri(&issued.uri).unwrap();
        let err = uri_first.set_options(&conflicting).unwrap_err();
        assert_eq!(err.code, "invalid_pairing_uri", "{err}");
        assert!(err.message.contains("does not match the URI rp"), "{err}");

        let mut options_first = PairRouteContext::new(&issued.parsed.code);
        options_first.set_options(&conflicting).unwrap();
        let err = options_first.set_uri(&issued.uri).unwrap_err();
        assert_eq!(err.code, "invalid_pairing_uri", "{err}");

        let mut ok = PairRouteContext::new(&issued.parsed.code);
        ok.set_uri(&issued.uri).unwrap();
        ok.set_options(&matching).unwrap();
    }

    #[test]
    fn commit_claim_refuses_relay_key_mismatch_before_an_invalid_statement() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[RELAY_V1]);
        let cli = wasm_identity(0x41);

        // rp names another key: refused as an unverified host key.
        let mut forged = PairingUri::new(
            "Studio",
            issued.parsed.code.clone(),
            issued.parsed.host_static_pub,
            issued.parsed.host_signing_pub_hash,
            vec![RELAY_V1.to_owned()],
            issued.parsed.host_id.clone(),
            issued.parsed.rotation_seq,
        );
        forged.relay_pub = Some(*identity(0x77).signing_key().ed25519_public_bytes());
        let forged = forged.try_encode().unwrap();
        let mut roster = WasmRoster::new();
        let mut p =
            v1_pairing_to_host_verified(&mut host, &issued, &forged, "", true, &cli, &mut roster);
        assert_eq!(p.report["relay_pub_ok"], json!(false));
        let err = p.init.commit_claim_inner().unwrap_err();
        assert_eq!(err.code, "host_key_unverified", "{err}");
        assert!(p.init.is_awaiting_commit());

        // Both a wrong rp and a broken signature: the rp check ranks first.
        let both = format!("{forged}&rq=1&rs={}", b64url_encode(&[0u8; 64]));
        let mut roster = WasmRoster::new();
        let mut p =
            v1_pairing_to_host_verified(&mut host, &issued, &both, "", true, &cli, &mut roster);
        assert_eq!(p.report["relay_pub_ok"], json!(false));
        assert_eq!(p.report["route_check"], json!("invalid"));
        assert_eq!(
            p.init.commit_claim_inner().unwrap_err().code,
            "host_key_unverified"
        );
    }

    #[test]
    fn commit_claim_refuses_an_invalid_route_statement_on_both_wires() {
        let mut host = TestHost::new(0x31, "host-l6a");
        let issued = host.issue(&[DIRECT, RELAY_V1]);
        let tampered = flip_rs(&issued.uri);
        let cli = wasm_identity(0x41);
        let mut roster = WasmRoster::new();
        let mut p =
            v1_pairing_to_host_verified(&mut host, &issued, &tampered, "", true, &cli, &mut roster);
        assert_eq!(p.report["route_check"], json!("invalid"));
        let err = p.init.commit_claim_inner().unwrap_err();
        assert_eq!(err.code, "invalid_pairing_uri", "{err}");
        assert!(roster.inner.get("host-l6a").is_none());

        let uri = &issued.parsed;
        let pinned = json!({
            "host_id": uri.host_id,
            "static_pub_b64": b64url_encode(&uri.host_static_pub),
            "signing_pub_b64": b64url_encode(&uri.host_signing_pub_hash),
            "rotation_seq": uri.rotation_seq,
        })
        .to_string();
        let mut init =
            WasmV2PakePairInitiator::new_inner(&cli, "web", "browser", &uri.code, Some(&pinned))
                .unwrap();
        init.enable_deferred_claim_inner().unwrap();
        init.routes.set_uri(&tampered).unwrap();
        let mut resp = V2PakePairResponder::new(
            &host.identity,
            PairingPathKind::Remote,
            PakeArgon2Params::default(),
        )
        .unwrap();
        let m1 = init.start().unwrap();
        let m2 = v2_pair_writes(
            resp.feed_bytes(&m1, NOW, &mut host.mgr, &mut host.roster)
                .unwrap(),
        );
        let report = to_json(&init.step_bytes(&m2, &mut roster).unwrap());
        assert_eq!(report["route_check"], json!("invalid"));
        let err = init.commit_claim_inner().unwrap_err();
        assert_eq!(err.code, "invalid_pairing_uri", "{err}");
    }

    #[test]
    fn clear_routes_defaults_to_operator_routes() {
        let (mut roster, host) = roster_with_routes();
        let signed = recovery_uri(&host, &[RELAY_V1], 3);
        roster.apply_signed_route_uri_inner(&signed, None).unwrap();
        roster
            .set_routes_inner("host-l6a", &json!([DIRECT]).to_string())
            .unwrap();
        let sources = |r: &WasmRoster| -> Vec<String> {
            r.inner
                .get("host-l6a")
                .unwrap()
                .routes
                .iter()
                .map(|s| s.source.as_str().to_owned())
                .collect()
        };
        for default in [None, Some("")] {
            let mut copy = roster.clone_roster();
            copy.clear_routes_inner("host-l6a", default).unwrap();
            assert_eq!(sources(&copy), ["signed"], "{default:?}");
        }
        roster.clear_routes_inner("host-l6a", Some("all")).unwrap();
        assert!(sources(&roster).is_empty());
    }

    #[test]
    fn v2_session_errors_keep_the_core_code() {
        let rh = rotated_host();
        let cli = wasm_identity(0x40);
        let mut roster = client_roster(&rh);
        let missing = WasmV2SessionInitiator::new_inner(&cli, "nobody", &roster, None, None).err();
        assert_eq!(missing.unwrap().code, "peer_not_found");
        let mut sess =
            WasmV2SessionInitiator::new_inner(&cli, rh.host.host_id(), &roster, None, None)
                .unwrap();
        sess.start(NOWF).unwrap();
        let err = sess
            .step_bytes(&[0xffu8; 64], NOWF, 2.0, &mut roster)
            .unwrap_err();
        assert_ne!(err.code, GENERIC_ERROR_CODE, "{err}");
    }

    #[test]
    fn route_input_errors_keep_the_code_and_never_echo_input() {
        const SECRET: &str = "s3cr3tTok";
        let (mut roster, _host) = roster_with_routes();
        let before = serde_json::to_value(&roster.inner).unwrap();
        for (raw, message) in [
            (
                format!("direct:{SECRET} host:1"),
                "invalid pairing URI: invalid endpoint",
            ),
            (
                format!("wss://999.0.0.1/v1/relay?token={SECRET}"),
                "invalid pairing URI: invalid URL in endpoint",
            ),
            (
                format!("wss://240.0.0.1/v1/relay?token={SECRET}"),
                "invalid pairing URI: blocked_address",
            ),
        ] {
            let err = normalize_peer_routes(std::slice::from_ref(&raw)).unwrap_err();
            assert_eq!(err.code, "invalid_pairing_uri", "{raw}: {err}");
            assert_eq!(err.message, message, "{raw}");
            let err = roster
                .set_routes_inner("host-l6a", &json!([raw]).to_string())
                .unwrap_err();
            assert!(!err.message.contains(SECRET), "{err}");
        }
        assert_eq!(before, serde_json::to_value(&roster.inner).unwrap());
        let err = roster
            .clear_routes_inner("host-l6a", Some(SECRET))
            .unwrap_err();
        assert_eq!(err.code, "invalid_pairing_uri");
        assert!(!err.message.contains(SECRET), "{err}");
    }

    #[test]
    fn key_and_peer_errors_keep_the_core_code() {
        let err = parse_signing_pin_b64("!!", "host_signing_pub").unwrap_err();
        assert_eq!(err.code, "base64_decode", "{err}");
        assert!(
            err.message.starts_with("invalid host_signing_pub: "),
            "{err}"
        );
        let zeros = b64url_encode(&[0u8; HYBRID_SIGNING_PUB_LEN]);
        let err = parse_signing_pin_b64(&zeros, "host_signing_pub").unwrap_err();
        assert_eq!(err.code, "invalid_signature", "{err}");

        let (roster, _host) = roster_with_routes();
        assert_eq!(
            roster.peer_entry("nobody").unwrap_err().code,
            "peer_not_found"
        );
        assert_eq!(
            roster.peer_v2_secrets("nobody").unwrap_err().code,
            "peer_not_found"
        );
        assert!(roster.peer_v2_secrets("host-l6a").is_ok());
        let mut json_roster: serde_json::Value = serde_json::to_value(&roster.inner).unwrap();
        json_roster["entries"]["host-l6a"]
            .as_object_mut()
            .unwrap()
            .remove("v2_secrets");
        let mut no_secrets = roster.clone_roster();
        no_secrets
            .replace_from_json(&json_roster.to_string())
            .unwrap();
        assert_eq!(
            no_secrets.peer_v2_secrets("host-l6a").unwrap_err().code,
            "not_ready"
        );
        let cli = wasm_identity(0x41);
        let err = WasmV2SessionInitiator::new_inner(&cli, "host-l6a", &no_secrets, None, None)
            .err()
            .unwrap();
        assert_eq!(err.code, "not_ready", "{err}");
    }

    #[test]
    fn wasm_errors_carry_the_core_variant_code() {
        for (err, code) in [
            (
                CoreError::RotationForkDetected { seq: 3 },
                "rotation_fork_detected",
            ),
            (CoreError::PeerRevoked("p".into()), "peer_revoked"),
            (
                CoreError::VersionDowngrade {
                    peer_min: 2,
                    negotiated: 1,
                },
                "version_downgrade",
            ),
            (CoreError::HostKeyUnverified, "host_key_unverified"),
            (
                CoreError::InvalidPairingUri("x".into()),
                "invalid_pairing_uri",
            ),
            (CoreError::PairingCodeInvalid, "pairing_code_invalid"),
        ] {
            let message = err.to_string();
            let wasm = WasmError::from(err);
            assert_eq!(wasm.code, code);
            assert_eq!(wasm.message, message);
        }
        let generic = WasmError::from("session unavailable");
        assert_eq!(generic.code, GENERIC_ERROR_CODE);
        assert_eq!(generic.to_string(), "session unavailable");
        let (roster, _) = roster_with_routes();
        assert_eq!(
            roster
                .session_candidates_inner("nobody", None)
                .unwrap_err()
                .code,
            "peer_not_found"
        );
        assert_eq!(
            invalid_route("x").code,
            "invalid_pairing_uri",
            "route input errors are invalid_pairing_uri"
        );
    }

    #[test]
    fn session_candidates_admit_broker_allow_insecure_ws_and_rank_v2_before_v1() {
        let (mut roster, _host) = roster_with_routes();
        roster
            .set_routes_inner(
                "host-l6a",
                &json!([
                    "wss://198.51.100.10/v1/relay",
                    "wss://dns.example.test/v2/relay",
                    "broker+wss://broker.example.test/b",
                    "broker+ws://127.0.0.1:9000/b",
                ])
                .to_string(),
            )
            .unwrap();
        let mut json_roster: serde_json::Value = serde_json::to_value(&roster.inner).unwrap();
        json_roster["entries"]["host-l6a"]["routes"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "hint": "broker+ws://insecure-broker.example.test/b", "source": "operator" }));
        json_roster["entries"]["host-l6a"]["routes"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "hint": "ws://insecure-relay.example.test/v1/relay", "source": "operator" }));
        json_roster["entries"]["host-l6a"]["routes"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "hint": "broker+ws://169.254.169.254/b", "source": "operator" }));
        json_roster["entries"]["host-l6a"]["routes"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "hint": "broker+wss://169.254.169.254/b", "source": "operator" }));
        roster.replace_from_json(&json_roster.to_string()).unwrap();

        let default_v2 = to_json(
            &roster
                .session_candidates_inner("host-l6a", Some(r#"{"wire":2}"#))
                .unwrap(),
        );
        assert_eq!(
            candidates_of(&default_v2),
            [
                (
                    "wss://dns.example.test/v2/relay".to_owned(),
                    "operator".to_owned()
                ),
                (
                    "wss://198.51.100.10/v1/relay".to_owned(),
                    "operator".to_owned()
                ),
                (
                    "broker+ws://127.0.0.1:9000/b".to_owned(),
                    "operator".to_owned()
                ),
                (
                    "broker+wss://broker.example.test/b".to_owned(),
                    "operator".to_owned()
                ),
            ]
        );
        let skipped = skipped_of(&default_v2);
        assert!(skipped.contains(&(
            "broker+ws://insecure-broker.example.test/b".to_owned(),
            "insecure_ws".to_owned()
        )));
        assert!(skipped.contains(&(
            "ws://insecure-relay.example.test/v1/relay".to_owned(),
            "insecure_ws".to_owned()
        )));
        assert!(skipped.contains(&(
            "broker+ws://169.254.169.254/b".to_owned(),
            "blocked_address".to_owned()
        )));
        assert!(skipped.contains(&(
            "broker+wss://169.254.169.254/b".to_owned(),
            "blocked_address".to_owned()
        )));

        let allow_insecure = to_json(
            &roster
                .session_candidates_inner(
                    "host-l6a",
                    Some(r#"{"wire":2,"allow_insecure_ws":true}"#),
                )
                .unwrap(),
        );
        let hints: Vec<String> = candidates_of(&allow_insecure)
            .into_iter()
            .map(|(h, _)| h)
            .collect();
        assert!(hints.contains(&"broker+ws://insecure-broker.example.test/b".to_owned()));
        assert!(hints.contains(&"ws://insecure-relay.example.test/v1/relay".to_owned()));
        assert_eq!(hints[0], "wss://dns.example.test/v2/relay");
    }

    #[test]
    fn wasm_path_planner_staggers_enforces_p2p_cold_delay_and_rejects_bad_timestamps() {
        let cands = json!([
            { "addr": "wss://198.51.100.10/v1/relay", "id": 10, "provider": "relay" },
            { "addr": "wss://v2.example.test/v2/relay", "id": 11, "provider": "relay" },
            { "addr": "iroh://abcdefghijklmnop", "id": 12 },
            { "addr": "broker+wss://broker.example.test/b", "id": 13 },
        ])
        .to_string();
        let mut planner = WasmPathPlanner::new_inner(&cands, None).unwrap();
        assert_eq!(planner.next_deadline_inner(), None);

        // Reject negative / non-finite / fractional timestamps cleanly.
        assert!(planner.start_inner(-1.0).is_err());
        assert!(planner.start_inner(f64::NAN).is_err());
        assert!(planner.start_inner(f64::INFINITY).is_err());
        assert!(planner.tick_inner(-5.0).is_err());
        assert!(planner.on_dial_succeeded_inner(12, f64::NAN).is_err());
        assert!(planner.on_dial_failed_inner(12, "err", -1.0).is_err());

        // Start launches P2P (id 12) at t=0; /v2/relay (id 11) waits 250 ms stagger.
        planner.start_inner(0.0).unwrap();
        let a0: Vec<serde_json::Value> =
            serde_json::from_str(&planner.drain_actions_json()).unwrap();
        assert_eq!(a0.len(), 1);
        assert_eq!(a0[0]["action"], "dial_candidate");
        assert_eq!(a0[0]["candidate"]["id"], 12);
        assert_eq!(planner.next_deadline_inner(), Some(250.0));

        // At t=250, /v2/relay launches; next stagger is /v1/relay (id 10) at t=500.
        planner.tick_inner(250.0).unwrap();
        let a1: Vec<serde_json::Value> =
            serde_json::from_str(&planner.drain_actions_json()).unwrap();
        assert_eq!(a1.len(), 1);
        assert_eq!(a1[0]["candidate"]["id"], 11);
        assert_eq!(planner.next_deadline_inner(), Some(500.0));

        // /v2/relay succeeds at t=300 -> cancels P2P (id 12) and activates /v2/relay.
        planner.on_dial_succeeded_inner(11, 300.0).unwrap();
        let win: Vec<serde_json::Value> =
            serde_json::from_str(&planner.drain_actions_json()).unwrap();
        assert_eq!(win[0]["action"], "cancel_candidate");
        assert_eq!(win[0]["id"], 12);
        assert_eq!(win[1]["action"], "activate_path");
        assert_eq!(win[1]["candidate"]["id"], 11);

        // Cold-start P2P hold delay when non-P2P starts first, plus per_attempt_timeout_ms.
        let cold_cands = json!(["direct:192.168.1.10:7000", "iroh://abcdefghijklmnop"]).to_string();
        let mut cold = WasmPathPlanner::new_inner(
            &cold_cands,
            Some(r#"{"per_attempt_timeout_ms":1000,"exhaustion_timeout_ms":3000}"#),
        )
        .unwrap();
        cold.start_inner(0.0).unwrap();
        let first: Vec<serde_json::Value> =
            serde_json::from_str(&cold.drain_actions_json()).unwrap();
        assert_eq!(first[0]["candidate"]["provider"], "direct");
        assert_eq!(cold.next_deadline_inner(), Some(500.0));

        // Failing direct early at t=100 still holds P2P until 500 ms.
        cold.on_dial_failed_inner(0, "refused", 100.0).unwrap();
        let after_fail: Vec<serde_json::Value> =
            serde_json::from_str(&cold.drain_actions_json()).unwrap();
        assert!(after_fail.is_empty());
        assert_eq!(cold.next_deadline_inner(), Some(500.0));

        cold.tick_inner(500.0).unwrap();
        let p2p_act: Vec<serde_json::Value> =
            serde_json::from_str(&cold.drain_actions_json()).unwrap();
        assert_eq!(p2p_act[0]["candidate"]["provider"], "p2p");
        assert_eq!(cold.next_deadline_inner(), Some(1500.0));

        // Per-attempt timeout at t=1500 cancels P2P and exhausts all candidates.
        cold.tick_inner(1500.0).unwrap();
        let timeout_acts: Vec<serde_json::Value> =
            serde_json::from_str(&cold.drain_actions_json()).unwrap();
        assert_eq!(timeout_acts[0]["action"], "cancel_candidate");
        assert_eq!(timeout_acts[0]["id"], 1);
        assert_eq!(timeout_acts[1]["action"], "all_candidates_exhausted");
        assert_eq!(cold.next_deadline_inner(), None);
    }

    #[test]
    fn wasm_relay_server_verifiers_cover_v1_v2_and_admission() {
        let constants: serde_json::Value =
            serde_json::from_str(&relay_protocol_constants_json_inner()).unwrap();
        assert_eq!(constants["relay_path"], "/v1/relay");
        assert_eq!(constants["relay_v2_path"], "/v2/relay");
        assert_eq!(constants["health_path"], "/healthz");
        assert_eq!(constants["max_standby_per_mailbox"], 4);
        assert_eq!(constants["max_relay_frame_len"], 65_521);
        assert_eq!(constants["v2_epoch_secs"], 3_600);

        assert_eq!(v2_epoch_for_unix_inner(3_600.0).unwrap(), 1.0);
        assert!(v2_epoch_for_unix_inner(-1.0).is_err());

        let mut ok_secret = b"super-secret".to_vec();
        validate_relay_auth_secret_bytes_inner(&mut ok_secret).unwrap();
        assert!(ok_secret.iter().all(|&b| b == 0));

        let mut empty_secret = Vec::new();
        assert!(validate_relay_auth_secret_bytes_inner(&mut empty_secret).is_err());

        let nonce = [0x11; 32];
        let conn_id = [0x22; 16];
        let conn_b64 = b64url_encode(&conn_id);
        assert_eq!(
            decode_b64url_exact_inner(&conn_b64, 16).unwrap(),
            conn_id.to_vec()
        );
        assert_eq!(
            decode_b64url_exact_inner(&conn_b64, 32).unwrap_err().code,
            "invalid_length"
        );
        assert_eq!(
            decode_b64url_exact_inner("not!valid", 16).unwrap_err().code,
            "base64_decode"
        );

        let id = EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x43; 32]),
            SigningKeypair::from_seed([0x44; 32]),
        );
        let signing_kp = id.signing_key().ed25519_signing_key();
        let pub_b64 = b64url_encode(&signing_kp.verifying_key().to_bytes());
        assert_eq!(
            validate_ed25519_pub_b64_inner(&pub_b64).unwrap(),
            signing_kp.verifying_key().to_bytes().to_vec()
        );
        let zero_b64 = b64url_encode(&[0u8; 32]);
        assert_eq!(
            validate_ed25519_pub_b64_inner(&zero_b64).unwrap_err().code,
            "invalid_signature"
        );

        assert_eq!(decode_relay_init_frame_b64_inner(None).unwrap(), None);
        assert_eq!(
            decode_relay_init_frame_b64_inner(Some(""))
                .unwrap_err()
                .code,
            "bad_request"
        );
        let big_init = b64url_encode(&[0x55; 65_522]);
        assert_eq!(
            decode_relay_init_frame_b64_inner(Some(&big_init))
                .unwrap_err()
                .code,
            "frame_too_large"
        );

        let (_, reg_sig) = tendril_core::sign_relay_register(&signing_kp, "relay.example", &nonce);
        assert_eq!(
            verify_relay_register_v1_inner(&pub_b64, &reg_sig, "relay.example", &nonce).unwrap(),
            signing_kp.verifying_key().to_bytes().to_vec()
        );
        assert!(
            verify_relay_register_v1_inner(&pub_b64, &reg_sig, "evil.example", &nonce).is_err()
        );

        let acc_sig =
            tendril_core::sign_relay_accept(&signing_kp, "relay.example", &nonce, &conn_id);
        let acc_out =
            verify_relay_accept_v1_inner(&pub_b64, &conn_b64, &acc_sig, "relay.example", &nonce)
                .unwrap();
        assert_eq!(&acc_out[..32], &signing_kp.verifying_key().to_bytes());
        assert_eq!(&acc_out[32..], &conn_id);

        let v2_mailbox = derive_epoch_mailbox(&[0x33; 32], 42);
        let v2_sig =
            tendril_core::v2::sign_v2_relay_register(&v2_mailbox, "relay.example", &nonce).unwrap();
        let v2_pub_b64 = b64url_encode(&v2_mailbox.mailbox_id);
        assert_eq!(
            verify_v2_relay_register_b64_inner(
                &v2_pub_b64,
                42.0,
                "relay.example",
                &nonce,
                &b64url_encode(&v2_sig),
            )
            .unwrap(),
            v2_mailbox.mailbox_id.to_vec()
        );
        let v2_acc_sig =
            tendril_core::v2::sign_v2_relay_accept(&v2_mailbox, "relay.example", &nonce, &conn_id)
                .unwrap();
        let v2_acc_out = verify_v2_relay_accept_b64_inner(
            &v2_pub_b64,
            42.0,
            "relay.example",
            &nonce,
            &conn_b64,
            &b64url_encode(&v2_acc_sig),
        )
        .unwrap();
        assert_eq!(&v2_acc_out[..32], &v2_mailbox.mailbox_id);
        assert_eq!(&v2_acc_out[32..], &conn_id);

        let mut hmac_secret = b"relay-secret-bytes".to_vec();
        let mac = core_compute_relay_auth_hmac_b64(
            &hmac_secret,
            "register",
            "relay.example",
            &nonce,
            &v2_mailbox.mailbox_id,
        )
        .unwrap();
        verify_relay_auth_hmac_b64_inner(
            &mut hmac_secret,
            "register",
            "relay.example",
            &nonce,
            &v2_mailbox.mailbox_id,
            &mac,
        )
        .unwrap();
        assert!(hmac_secret.iter().all(|&b| b == 0));

        let ticket = core_mint_relay_ticket(
            &signing_kp,
            "relay.example",
            RelayAuthRole::Dial,
            "*",
            1_700_000_000,
            600,
        )
        .unwrap();
        let ticket_json = serde_json::to_string(&ticket).unwrap();
        let issuers_json = serde_json::to_string(&vec![pub_b64]).unwrap();
        assert_eq!(
            verify_relay_ticket_json_inner(
                &ticket_json,
                &issuers_json,
                "relay.example",
                "dial",
                &v2_mailbox.mailbox_id,
                1_700_000_100.0,
            )
            .unwrap(),
            signing_kp.verifying_key().to_bytes().to_vec()
        );
        validate_relay_ticket_schema_json_inner(&ticket_json).unwrap();
        assert!(validate_relay_ticket_schema_json_inner(r#"{"bogus":1}"#).is_err());
    }
}
