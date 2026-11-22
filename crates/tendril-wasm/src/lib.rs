//! Sans-I/O WebAssembly bindings exposing `tendril-core` primitives and state machines,
//! plus opt-in `p2p-iroh` browser WebSocket relay transport.

#[cfg(feature = "p2p-iroh")]
pub mod p2p;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, SigningKeypair,
    StaticKeypair, b64url_decode, b64url_decode_array, b64url_encode,
    compute_code_mac as core_compute_code_mac, device_id as core_device_id,
    fingerprint_device as core_fingerprint_device, fingerprint_host as core_fingerprint_host,
    pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::grants::{Grant, RevocationList, authorize_grant};
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, verify_rotation_chain,
};
use tendril_core::pairing::{
    PairAction, PairOutcome, PairingInitiator, PairingUri, PinnedHost,
    mint_enrollment_token as core_mint_enrollment_token,
};
use tendril_core::relay_auth::{
    RelayAuthRole, compute_relay_auth_hmac_b64 as core_compute_relay_auth_hmac_b64,
    mint_relay_ticket as core_mint_relay_ticket,
};
use tendril_core::roster::Roster;
use tendril_core::session::{SessionAction, SessionMachine, check_peer_allows_wire_v1};
use tendril_core::v2::{
    PaddingPolicy, PakeArgon2Params, V2PairAction, V2PairOutcome, V2PakePairInitiator,
    V2PinnedHost, V2SessionAction, V2SessionInitiator, VerifiedRelayHost,
    canonical_relay_host as core_canonical_relay_host, derive_epoch_mailbox, epoch_for_unix,
    epoch_within_skew, sign_v2_relay_dial,
};
use tendril_core::wire::WIRE_VERSION_V2;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize as _, Zeroizing};

fn to_js_err(err: impl fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
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

fn as_32(bytes: &[u8], name: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be exactly 32 bytes"))
}

fn parse_signing_pin_b64(encoded: &str, name: &str) -> Result<SigningKeyPin, String> {
    let bytes = b64url_decode(encoded).map_err(|e| format!("invalid {name}: {e}"))?;
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        HybridSigningPublicKey::from_bytes(&bytes)
            .map(SigningKeyPin::Full)
            .map_err(|e| format!("invalid {name}: {e}"))
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let hash: [u8; HYBRID_SIGNING_HASH_LEN] = bytes
            .try_into()
            .map_err(|_| format!("invalid {name} hash length"))?;
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(format!(
            "{name} must be {HYBRID_SIGNING_PUB_LEN} or {HYBRID_SIGNING_HASH_LEN} bytes"
        ))
    }
}

fn f64_to_u64(v: f64, name: &str) -> Result<u64, String> {
    if !(0.0..=9_007_199_254_740_991.0).contains(&v) || v.fract() != 0.0 {
        return Err(format!("{name} must be a non-negative safe integer"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(v as u64)
}

fn f64_to_u16(v: f64, name: &str) -> Result<u16, String> {
    let n = f64_to_u64(v, name)?;
    u16::try_from(n).map_err(|_| format!("{name} must be within 0..=65535"))
}

#[allow(clippy::cast_precision_loss)]
fn u64_to_f64(v: u64) -> Result<f64, String> {
    if v > 9_007_199_254_740_991 {
        return Err("sequence exceeds JavaScript safe integer range".to_owned());
    }
    Ok(v as f64)
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
            .and_then(|hh| core_compute_code_mac(code, &hh).map_err(|e| e.to_string()))
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
                    .map_err(|e| e.to_string())
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
) -> Result<String, String> {
    let host = VerifiedRelayHost::new(relay_host).map_err(|e| e.to_string())?;
    let unix = f64_to_u64(unix_secs, "unix_secs")?;
    let nonce = as_32(dial_nonce, "dial_nonce")?;
    let cid: [u8; 16] = conn_id
        .try_into()
        .map_err(|_| "conn_id must be exactly 16 bytes".to_owned())?;
    let epoch = epoch_for_unix(unix);
    let mailbox = derive_epoch_mailbox(mailbox_secret, epoch);
    let dial_token =
        sign_v2_relay_dial(&mailbox, host.as_str(), &nonce, &cid).map_err(|e| e.to_string())?;
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
            .map_err(|e| to_js_err(format!("invalid key for {id}: {e}")))?;
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
    let parsed = PairingUri::parse(uri).map_err(to_js_err)?;
    let rotation_seq = parsed
        .rotation_seq
        .map(u64_to_f64)
        .transpose()
        .map_err(to_js_err)?;
    Ok(json!({
        "host_name": parsed.host_name,
        "code": parsed.code,
        "host_static_pub_b64": b64url_encode(&parsed.host_static_pub),
        "host_signing_pub_hash_b64": b64url_encode(&parsed.host_signing_pub_hash),
        "endpoints": parsed.endpoints,
        "host_id": parsed.host_id,
        "rotation_seq": rotation_seq,
    })
    .to_string())
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
    fn generate_inner(host_id: Option<&str>) -> Result<Self, String> {
        let mut id = EndpointIdentity::generate().map_err(|e| e.to_string())?;
        if let Some(h) = host_id
            && !h.is_empty()
        {
            id = id.with_host_id(h);
        }
        Ok(Self { inner: id })
    }

    fn serialize_json(&self) -> Result<Zeroizing<String>, String> {
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
            .map_err(|e| e.to_string())
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

    fn parse_json(json_str: &str) -> Result<Self, String> {
        let doc: PersistedWasmIdentity =
            serde_json::from_str(json_str).map_err(|e| e.to_string())?;
        let static_scalar = Zeroizing::new(
            b64url_decode_array::<32>(&doc.static_secret_b64).map_err(|e| e.to_string())?,
        );
        let signing_seed = Zeroizing::new(
            b64url_decode_array::<32>(&doc.signing_seed_b64).map_err(|e| e.to_string())?,
        );
        let pq_signing_seed = Zeroizing::new(
            b64url_decode_array::<32>(&doc.pq_signing_seed_b64).map_err(|e| e.to_string())?,
        );
        let inner = EndpointIdentity::from_persisted(
            doc.host_id.clone(),
            StaticKeypair::from_scalar(*static_scalar),
            SigningKeypair::from_seeds(*signing_seed, *pq_signing_seed),
            doc.rotation_chain.clone(),
            doc.rotation_seq,
        )
        .map_err(|e| e.to_string())?;
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

/// Sans-I/O peer roster and verified CRL store managed by host JS storage.
#[wasm_bindgen]
pub struct WasmRoster {
    inner: Roster,
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
        let entry = self
            .inner
            .get(peer_id)
            .ok_or_else(|| to_js_err("peer not found"))?;
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
        let entry = self
            .inner
            .get(peer_id)
            .ok_or_else(|| to_js_err("peer not found"))?;
        let secrets = entry
            .v2_secrets
            .as_ref()
            .ok_or_else(|| to_js_err("peer has no v2 secrets"))?;
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

impl Default for WasmRoster {
    fn default() -> Self {
        Self::new()
    }
}

/// Sans-I/O pairing initiator driving `Intent::Pair` bytes for JS transport layers.
#[wasm_bindgen]
pub struct WasmPairInitiator {
    inner: PairingInitiator,
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
    ) -> Result<Self, String> {
        let pinned = match (host_static_pub_b64, host_signing_pub_b64) {
            (Some(st), Some(sg)) if !st.is_empty() && !sg.is_empty() => {
                let seq = match host_rotation_seq {
                    Some(v) => f64_to_u64(v, "host_rotation_seq")?,
                    None => 0,
                };
                Some(PinnedHost {
                    host_id: host_id.filter(|h| !h.is_empty()).map(ToOwned::to_owned),
                    static_pub: b64url_decode_array::<32>(st).map_err(|e| e.to_string())?,
                    signing_pin: parse_signing_pin_b64(sg, "host_signing_pub_b64")?,
                    rotation_seq: seq,
                })
            }
            (None | Some(""), None | Some("")) => None,
            _ => {
                return Err(
                    "both host_static_pub_b64 and host_signing_pub_b64 must be set together"
                        .to_owned(),
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
        .map_err(|e| e.to_string())?;
        if let Some(roster_ref) = roster_opt {
            if let Some(ref p) = pinned {
                let floor = roster_ref.inner.pairing_floor(&p.static_pub);
                inner = inner
                    .with_min_wire_version(floor)
                    .map_err(|e| e.to_string())?;
            }
            inner = inner.with_roster_floors(&roster_ref.inner);
        }
        Ok(Self { inner })
    }

    fn step_bytes(&mut self, bytes: &[u8], roster: &mut WasmRoster) -> Result<String, String> {
        let actions = self.inner.feed_bytes(bytes).map_err(|e| e.to_string())?;
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
                    let pin_res = if host_pin_verified {
                        roster.inner.insert_pinned_host(
                            host_id.clone(),
                            host_id.clone(),
                            host_static_pub,
                            Some(host_signing_pub),
                            host_rotation_seq,
                            Vec::new(),
                        )
                    } else {
                        roster.inner.record_pending_host(
                            host_id.clone(),
                            host_id.clone(),
                            host_static_pub,
                            host_signing_pub,
                            host_rotation_seq,
                            pairing_sas.clone(),
                            Vec::new(),
                        )
                    };
                    pin_res.map_err(|e| e.to_string())?;
                    sas = Some(pairing_sas.clone());
                    outcome_json = Some(json!({
                        "status": "pending",
                        "device_id": device_id,
                        "host_id": host_id,
                        "sas": pairing_sas,
                        "host_confirmed": host_pin_verified,
                    }));
                }
                PairAction::Completed(PairOutcome::InitiatorEnrolled {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    token_nonce,
                }) => {
                    roster
                        .inner
                        .insert_pinned_host(
                            host_id.clone(),
                            host_id.clone(),
                            host_static_pub,
                            Some(host_signing_pub),
                            host_rotation_seq,
                            Vec::new(),
                        )
                        .map_err(|e| e.to_string())?;
                    outcome_json = Some(json!({
                        "status": "active",
                        "device_id": device_id,
                        "host_id": host_id,
                        "host_rotation_seq": host_rotation_seq,
                        "token_nonce": token_nonce,
                    }));
                }
                PairAction::Completed(PairOutcome::Rejected { error }) => {
                    outcome_json = Some(json!({
                        "status": "rejected",
                        "error": error,
                    }));
                }
                PairAction::Completed(PairOutcome::ResponderPending { .. })
                | PairAction::Completed(PairOutcome::ResponderEnrolled { .. }) => {
                    return Err("unexpected responder outcome".to_owned());
                }
                PairAction::CloseTransport(_) => {}
            }
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
    ) -> Result<Self, String> {
        let seq = match host_rotation_seq {
            Some(v) => f64_to_u64(v, "host_rotation_seq")?,
            None => 0,
        };
        let static_pub =
            b64url_decode_array::<32>(host_static_pub_b64).map_err(|e| e.to_string())?;
        let signing_pin = parse_signing_pin_b64(host_signing_pub_b64, "host_signing_pub_b64")?;
        let token: Grant =
            serde_json::from_str(token_json).map_err(|e| format!("invalid token_json: {e}"))?;
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
        .map_err(|e| e.to_string())?;
        if let Some(roster_ref) = roster_opt {
            let floor = roster_ref.inner.pairing_floor(&static_pub);
            inner = inner
                .with_min_wire_version(floor)
                .map_err(|e| e.to_string())?;
            inner = inner.with_roster_floors(&roster_ref.inner);
        }
        Ok(Self { inner })
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
        let actions = self.inner.start().map_err(to_js_err)?;
        let mut out = Vec::new();
        for action in actions {
            if let PairAction::WriteBytes(chunk) = action {
                out.extend_from_slice(&chunk);
            }
        }
        Ok(out)
    }

    #[wasm_bindgen]
    pub fn feed_bytes(&mut self, bytes: &[u8], roster: &mut WasmRoster) -> Result<String, JsValue> {
        self.step_bytes(bytes, roster).map_err(to_js_err)
    }
}

/// Sans-I/O authenticated `Intent::Session` client state machine.
#[wasm_bindgen]
pub struct WasmSessionClient {
    inner: SessionMachine,
}

impl WasmSessionClient {
    fn new_inner(
        identity: &WasmIdentity,
        target_host_id: &str,
        grant_json: Option<&str>,
        crl_seq: Option<f64>,
    ) -> Result<Self, String> {
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.is_empty() => Some(serde_json::from_str(s).map_err(|e| e.to_string())?),
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
        .map_err(|e| e.to_string())?;
        Ok(Self { inner })
    }

    fn step_bytes(
        &mut self,
        bytes: &[u8],
        now_unix: f64,
        now_ms: f64,
        roster: &mut WasmRoster,
    ) -> Result<String, String> {
        let now_u = f64_to_u64(now_unix, "now_unix")?;
        let now_m = f64_to_u64(now_ms, "now_ms")?;
        let actions = self
            .inner
            .feed_bytes(bytes, now_u, now_m, &mut roster.inner)
            .map_err(|e| e.to_string())?;

        let mut writes = Vec::new();
        let mut events = Vec::new();
        for action in actions {
            match action {
                SessionAction::WriteBytes(chunk) => writes.extend_from_slice(&chunk),
                SessionAction::Established { .. } => {}
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
            "established": self.inner.is_established(),
            "closed": self.inner.is_closed(),
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
        let actions = self.inner.start().map_err(to_js_err)?;
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
        let actions = self.inner.send_data(payload, now_m).map_err(to_js_err)?;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    pub fn send_rekey(&mut self, now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let actions = self.inner.send_rekey(now_m).map_err(to_js_err)?;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    pub fn send_ping(&mut self, cookie: f64, now_ms: f64) -> Result<Vec<u8>, JsValue> {
        let c = f64_to_u64(cookie, "cookie").map_err(to_js_err)?;
        let now_m = f64_to_u64(now_ms, "now_ms").map_err(to_js_err)?;
        let actions = self.inner.send_ping(c, now_m).map_err(to_js_err)?;
        Ok(collect_session_writes(actions))
    }

    #[wasm_bindgen]
    pub fn send_close(&mut self, code: f64, reason: &str) -> Result<Vec<u8>, JsValue> {
        let close_code = f64_to_u16(code, "code").map_err(to_js_err)?;
        let actions = self
            .inner
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
            .inner
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
        self.inner
            .authorize(requested_cap, now_u, &roster.inner)
            .0
            .is_ok()
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.inner.is_established()
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
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
    inner: V2PakePairInitiator,
    pending_events: Vec<serde_json::Value>,
}

impl WasmV2PakePairInitiator {
    fn new_inner(
        identity: &WasmIdentity,
        device_name: &str,
        device_kind: &str,
        code: &str,
        pinned_host_json: Option<&str>,
    ) -> Result<Self, String> {
        let pinned = match pinned_host_json {
            Some(raw) if !raw.trim().is_empty() => {
                let parsed: WasmV2PinnedHostInput = serde_json::from_str(raw)
                    .map_err(|e| format!("invalid pinned_host_json: {e}"))?;
                let static_pub =
                    b64url_decode_array::<32>(&parsed.static_pub_b64).map_err(|e| e.to_string())?;
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
                        .map_err(|e| e.to_string())?,
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
        .map_err(|e| e.to_string())?;
        Ok(Self {
            inner,
            pending_events: Vec::new(),
        })
    }

    fn step_bytes(&mut self, bytes: &[u8], roster: &mut WasmRoster) -> Result<String, String> {
        let actions = self.inner.feed_bytes(bytes).map_err(|e| e.to_string())?;
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
                        ref pairing_sas,
                        host_pin_verified,
                        ..
                    },
                ) => {
                    roster
                        .inner
                        .apply_v2_pair_initiator_outcome(outcome, host_id.clone(), Vec::new())
                        .map_err(|e| e.to_string())?;
                    sas = Some(pairing_sas.clone());
                    let obj = json!({
                        "status": "pending",
                        "device_id": device_id,
                        "host_id": host_id,
                        "sas": pairing_sas,
                        "host_confirmed": host_pin_verified,
                    });
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
                    return Err("unexpected responder outcome".to_owned());
                }
                V2PairAction::CloseTransport(reason) => {
                    self.pending_events.push(json!({
                        "event": "close_transport",
                        "reason": reason,
                    }));
                }
            }
        }

        Ok(json!({
            "write_b64": b64url_encode(&writes),
            "sas": sas,
            "outcome": outcome_json,
        })
        .to_string())
    }
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
        let actions = self.inner.start().map_err(to_js_err)?;
        let mut out = Vec::new();
        for action in actions {
            if let V2PairAction::WriteBytes(chunk) = action {
                out.extend_from_slice(&chunk);
            }
        }
        Ok(out)
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
    pending_writes: Vec<u8>,
    pending_events: Vec<serde_json::Value>,
}

impl WasmV2SessionInitiator {
    fn new_inner(
        identity: &WasmIdentity,
        target_host_id: &str,
        roster: &WasmRoster,
        grant_json: Option<&str>,
        crl_seq: Option<f64>,
    ) -> Result<Self, String> {
        let entry = roster
            .inner
            .get(target_host_id)
            .ok_or_else(|| format!("peer not found: {target_host_id}"))?;
        let secrets = entry
            .v2_secrets
            .as_ref()
            .ok_or_else(|| format!("peer {target_host_id} has no v2 secrets"))?;
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.trim().is_empty() => {
                Some(serde_json::from_str(s).map_err(|e| e.to_string())?)
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
        .map_err(|e| e.to_string())?
        .with_padding_policy(PaddingPolicy::v2_default());
        Ok(Self {
            phase: V2WasmSessionPhase::Active(Box::new(machine)),
            target_host_id: target_host_id.to_owned(),
            pending_writes: Vec::new(),
            pending_events: Vec::new(),
        })
    }

    fn push_v2_action(
        &mut self,
        action: V2SessionAction,
        roster: &mut Roster,
    ) -> Result<(), String> {
        match action {
            V2SessionAction::WriteBytes(chunk) => {
                self.pending_writes.extend_from_slice(&chunk);
            }
            V2SessionAction::Established { peer_device_id, .. } => {
                roster
                    .set_peer_min_wire_version(&self.target_host_id, WIRE_VERSION_V2)
                    .map_err(|e| e.to_string())?;
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
    ) -> Result<String, String> {
        let now_u = f64_to_u64(now_unix, "now_unix")?;
        let now_m = f64_to_u64(now_ms, "now_ms")?;
        let prev = std::mem::replace(&mut self.phase, V2WasmSessionPhase::Closed);
        let mut machine = match prev {
            V2WasmSessionPhase::Active(m) => m,
            V2WasmSessionPhase::Closed => return Err("v2 session closed".to_owned()),
        };
        let actions = match machine.feed_bytes(chunk, now_u, now_m, &mut roster.inner) {
            Ok(a) => a,
            Err(err) => {
                if !machine.is_closed() {
                    self.phase = V2WasmSessionPhase::Active(machine);
                }
                return Err(err.to_string());
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

        let init_m1: Vec<u8> = match pair_init.inner.start().unwrap().pop().unwrap() {
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
        let sm1: Vec<u8> = match cli_sess.inner.start().unwrap().pop().unwrap() {
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

        let init_m1: Vec<u8> = match pair_init.inner.start().unwrap().pop().unwrap() {
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
        let rep_m1: Vec<u8> = match rep_init.inner.start().unwrap().pop().unwrap() {
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
