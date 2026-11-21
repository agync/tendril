//! Sans-I/O WebAssembly bindings exposing `tendril-core` primitives and state machines,
//! plus opt-in `p2p-iroh` browser WebSocket relay transport.

#[cfg(feature = "p2p-iroh")]
pub mod p2p;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tendril_core::crypto::{
    SigningKeypair, StaticKeypair, b64url_decode_array, b64url_encode,
    compute_code_mac as core_compute_code_mac, device_id as core_device_id,
    fingerprint_device as core_fingerprint_device, fingerprint_host as core_fingerprint_host,
    pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::grants::{Grant, RevocationList, authorize_grant};
use tendril_core::identity::{EndpointIdentity, RotationRecord, verify_rotation_chain};
use tendril_core::pairing::{
    PairAction, PairOutcome, PairingInitiator, PairingUri, PinnedHost,
    mint_enrollment_token as core_mint_enrollment_token,
};
use tendril_core::roster::Roster;
use tendril_core::session::{SessionAction, SessionMachine};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

fn to_js_err(err: impl fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn as_32(bytes: &[u8], name: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be exactly 32 bytes"))
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
pub fn verify_rotation_chain_json(
    pinned_signing_b64: &str,
    pinned_static_b64: &str,
    pinned_seq: f64,
    chain_json: &str,
    cur_static_b64: &str,
    cur_signing_b64: &str,
) -> Result<f64, JsValue> {
    let p_seq = f64_to_u64(pinned_seq, "pinned_seq").map_err(to_js_err)?;
    let psig = b64url_decode_array::<32>(pinned_signing_b64).map_err(to_js_err)?;
    let pstat = b64url_decode_array::<32>(pinned_static_b64).map_err(to_js_err)?;
    let cstat = b64url_decode_array::<32>(cur_static_b64).map_err(to_js_err)?;
    let csig = b64url_decode_array::<32>(cur_signing_b64).map_err(to_js_err)?;
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
        let k = b64url_decode_array::<32>(&b64)
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
        |id| key_map.get(id).copied(),
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
        "host_signing_pub_b64": b64url_encode(&parsed.host_signing_pub),
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
    #[serde(default)]
    rotation_chain: Vec<RotationRecord>,
    #[serde(default)]
    rotation_seq: u64,
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

    fn serialize_json(&self) -> Result<String, String> {
        let doc = PersistedWasmIdentity {
            host_id: self.inner.host_id().to_owned(),
            static_secret_b64: b64url_encode(self.inner.static_key().secret_bytes()),
            signing_seed_b64: b64url_encode(self.inner.signing_key().seed_bytes()),
            rotation_chain: self.inner.rotation_chain().to_vec(),
            rotation_seq: self.inner.rotation_seq(),
        };
        serde_json::to_string(&doc).map_err(|e| e.to_string())
    }

    fn parse_json(json_str: &str) -> Result<Self, String> {
        let doc: PersistedWasmIdentity =
            serde_json::from_str(json_str).map_err(|e| e.to_string())?;
        let static_scalar: [u8; 32] =
            b64url_decode_array(&doc.static_secret_b64).map_err(|e| e.to_string())?;
        let signing_seed: [u8; 32] =
            b64url_decode_array(&doc.signing_seed_b64).map_err(|e| e.to_string())?;
        let inner = EndpointIdentity::from_persisted(
            doc.host_id,
            StaticKeypair::from_scalar(static_scalar),
            SigningKeypair::from_seed(signing_seed),
            doc.rotation_chain,
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
            "signing_pub": b64url_encode(self.inner.signing_key().public_bytes()),
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
    pub fn to_json(&self) -> Result<String, JsValue> {
        self.serialize_json().map_err(to_js_err)
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
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner).map_err(to_js_err)
    }

    #[wasm_bindgen]
    pub fn replace_from_json(&mut self, json: &str) -> Result<(), JsValue> {
        self.inner = serde_json::from_str(json).map_err(to_js_err)?;
        Ok(())
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
            Some(ref s) if !s.is_empty() => Some(b64url_decode_array::<32>(s).map_err(to_js_err)?),
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
        let key = b64url_decode_array::<32>(signing_pub_b64).map_err(to_js_err)?;
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
                    signing_pub: b64url_decode_array::<32>(sg).map_err(|e| e.to_string())?,
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
        let inner = PairingInitiator::new(
            &identity.inner,
            device_name.to_owned(),
            device_kind.to_owned(),
            code.to_owned(),
            pinned,
            None,
        )
        .map_err(|e| e.to_string())?;
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
    ) -> Result<Self, String> {
        let seq = match host_rotation_seq {
            Some(v) => f64_to_u64(v, "host_rotation_seq")?,
            None => 0,
        };
        let static_pub =
            b64url_decode_array::<32>(host_static_pub_b64).map_err(|e| e.to_string())?;
        let signing_pub =
            b64url_decode_array::<32>(host_signing_pub_b64).map_err(|e| e.to_string())?;
        let token: Grant =
            serde_json::from_str(token_json).map_err(|e| format!("invalid token_json: {e}"))?;
        let pinned = PinnedHost {
            host_id: Some(host_id.to_owned()),
            static_pub,
            signing_pub,
            rotation_seq: seq,
        };
        let inner = PairingInitiator::new_m2m(
            &identity.inner,
            device_name.to_owned(),
            device_kind.to_owned(),
            token,
            pinned,
            None,
        )
        .map_err(|e| e.to_string())?;
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
                *anchor_id.signing_key().public_bytes(),
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
            &b64url_encode(host_id.signing_key().public_bytes()),
            None,
            &tok_json,
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
            &b64url_encode(host_id.signing_key().public_bytes()),
            None,
            &tok_json,
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
}
