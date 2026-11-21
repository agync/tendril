//! Node.js N-API native addon over `tendril-core` and `tendril-runtime`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, b64url_decode_array,
    b64url_encode, compute_code_mac as core_compute_code_mac, device_id as core_device_id,
    fingerprint_device as core_fingerprint_device, fingerprint_host as core_fingerprint_host,
    pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::grants::{Grant, RevocationList, authorize_grant};
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, verify_rotation_chain,
};
use tendril_core::pairing::{
    EnrollmentPolicy, PairOutcome, PairingCodeKind, PairingConfig, PairingManager, PinnedHost,
    mint_enrollment_token as core_mint_enrollment_token,
};
use tendril_core::roster::{AnchorState, Roster};
use tendril_runtime::{
    ConcurrentSession, DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT, DirectListener,
    InboundRouter, P2pListener, PathListener, PathStream, RelayListener, SessionDriver,
    SessionEvent, StateStore, dial_endpoint as runtime_dial_endpoint,
    drive_m2m_enroll_initiator_with_floor, drive_m2m_enroll_initiator_with_store,
    drive_pair_initiator_with_floor, drive_pair_initiator_with_store,
    drive_pair_responder_with_policy_and_store, pairing_path_kind_for_provider,
    parse_p2p_relay_mode, pinned_pairing_floor,
};
use tokio::time::timeout;

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

fn persist_store_roster(
    store: Option<&Arc<StateStore>>,
    roster: &Arc<StdMutex<Roster>>,
) -> Result<()> {
    if let Some(s) = store {
        let guard = roster.lock().expect("roster mutex poisoned");
        s.save_roster(&guard).map_err(to_generic_err)?;
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
        .map_err(|e| Error::new(Status::InvalidArg, format!("invalid {name}: {e}")))
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
    Error::new(Status::GenericFailure, err.to_string())
}

async fn dial_endpoint(
    endpoint: &str,
    relay_host: Option<&str>,
) -> std::result::Result<Box<dyn PathStream>, String> {
    runtime_dial_endpoint(endpoint, relay_host)
        .await
        .map_err(|e| e.to_string())
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
    let chain: Vec<RotationRecord> = serde_json::from_str(&chain_json).map_err(to_generic_err)?;
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
    let grant: Grant = serde_json::from_str(&grant_json).map_err(to_generic_err)?;
    let key_map_raw: HashMap<String, String> =
        serde_json::from_str(&issuer_keys_json).map_err(to_generic_err)?;
    let mut key_map = HashMap::with_capacity(key_map_raw.len());
    for (id, b64) in key_map_raw {
        let k = HybridSigningPublicKey::from_b64url(&b64).map_err(to_generic_err)?;
        key_map.insert(id, k);
    }
    let crl: Option<RevocationList> = match crl_json {
        Some(s) if !s.is_empty() => Some(serde_json::from_str(&s).map_err(to_generic_err)?),
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
pub struct Endpoint {
    store: Option<Arc<StateStore>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    router: InboundRouter,
    self_m2m_enabled: AtomicBool,
    m2m_enabled: AtomicBool,
}

impl Endpoint {
    fn persist_roster(&self, roster: &Roster) -> Result<()> {
        if let Some(store) = &self.store {
            store.save_roster(roster).map_err(to_generic_err)?;
        }
        Ok(())
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
                identity = identity.with_host_id(h);
            }
            (None, identity, Roster::new())
        };

        let has_active_anchor = roster
            .trust_anchors()
            .any(|(_, a)| a.state == AnchorState::Active);
        Ok(Self {
            store,
            identity: Arc::new(identity),
            roster: Arc::new(StdMutex::new(roster)),
            pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
            router: InboundRouter::new(),
            self_m2m_enabled: AtomicBool::new(false),
            m2m_enabled: AtomicBool::new(has_active_anchor),
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
            .map_err(|e| Error::new(Status::InvalidArg, format!("invalid address: {e}")))?;
        let listener = DirectListener::bind(addr, None)
            .await
            .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        Ok(ep)
    }

    #[napi]
    pub async fn serve_relay(
        &self,
        relay_url: String,
        expected_host: Option<String>,
    ) -> Result<String> {
        let key = self.identity.signing_key().ed25519_signing_key();
        let listener = RelayListener::bind(relay_url, expected_host, key, DEFAULT_WRITE_TIMEOUT)
            .await
            .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        Ok(ep)
    }

    #[napi(js_name = "serveP2p")]
    pub async fn serve_p2p(&self, relay_mode: Option<String>) -> Result<String> {
        let mode = parse_p2p_relay_mode(relay_mode.as_deref())
            .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        let seed = self.identity.derive_p2p_identity_seed();
        let listener = P2pListener::bind_with_secret(mode, seed)
            .await
            .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        Ok(ep)
    }

    #[napi]
    pub fn issue_code(&self, kind: Option<String>) -> Result<String> {
        let pk = match kind.as_deref() {
            None | Some("" | "lan") => PairingCodeKind::Lan2Group,
            Some("remote") => PairingCodeKind::Remote3Group,
            Some(other) => {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!("invalid pairing code kind '{other}'"),
                ));
            }
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
        let mut stream = dial_endpoint(&endpoint, relay_host.as_deref())
            .await
            .map_err(to_generic_err)?;
        let device_name = name.unwrap_or_else(|| "node-device".to_owned());
        let device_kind = kind.unwrap_or_else(|| "node".to_owned());
        let res = if let Some(ref store) = self.store {
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
        } else {
            drive_pair_initiator_with_floor(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                None,
                tendril_core::WIRE_VERSION,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        let _ = stream.close().await;
        let res = res.map_err(to_generic_err)?;

        match res.outcome {
            PairOutcome::InitiatorPending {
                device_id,
                host_id,
                host_static_pub,
                host_signing_pub,
                host_rotation_seq,
                pairing_sas,
                host_pin_verified,
            } => {
                let mut roster = self.roster.lock().expect("roster mutex poisoned");
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
                pin_res.map_err(to_generic_err)?;
                self.persist_roster(&roster)?;
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
        let res = drive_pair_responder_with_policy_and_store(
            stream.as_mut(),
            &self.identity,
            &self.pair_mgr,
            &self.roster,
            self.store.as_deref(),
            path_kind,
            now_unix(),
            policy,
            Some(self.router.rate_limiter()),
            Some(guard),
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .map_err(to_generic_err)?;

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
        let mut roster = self.roster.lock().expect("roster mutex poisoned");
        roster
            .confirm_peer(&peer_id, sas.as_deref())
            .map_err(to_generic_err)?;
        self.persist_roster(&roster)
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
        let mut roster = self.roster.lock().expect("roster mutex poisoned");
        let now = now_unix();
        let grant = roster
            .mint_grant(
                &self.identity,
                &peer_id,
                caps,
                now,
                now.saturating_add(ttl),
                nonce,
            )
            .map_err(to_generic_err)?;
        self.persist_roster(&roster)?;
        serde_json::to_string(&grant).map_err(to_generic_err)
    }

    #[napi]
    pub fn revoke_peer(&self, peer_id: String) -> Result<()> {
        let mut roster = self.roster.lock().expect("roster mutex poisoned");
        roster.revoke_peer(&peer_id).map_err(to_generic_err)?;
        self.persist_roster(&roster)?;
        self.refresh_m2m_enabled(&roster);
        Ok(())
    }

    #[napi]
    pub fn add_trust_anchor(&self, anchor_id: String, signing_pub: Buffer) -> Result<()> {
        let key = parse_hybrid_signing_pub(signing_pub.as_ref(), "signing_pub")?;
        let mut roster = self.roster.lock().expect("roster mutex poisoned");
        roster
            .add_trust_anchor(anchor_id, key)
            .map_err(to_generic_err)?;
        self.persist_roster(&roster)?;
        self.refresh_m2m_enabled(&roster);
        self.router.set_pair_enabled(true);
        Ok(())
    }

    #[napi]
    pub fn revoke_trust_anchor(&self, anchor_id: String) -> Result<()> {
        let mut roster = self.roster.lock().expect("roster mutex poisoned");
        roster
            .revoke_trust_anchor(&anchor_id)
            .map_err(to_generic_err)?;
        self.persist_roster(&roster)?;
        self.refresh_m2m_enabled(&roster);
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
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        if target_host_id == self.identity.host_id() {
            self.self_m2m_enabled.store(true, Ordering::Release);
            let roster = self.roster.lock().expect("roster mutex poisoned");
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
        let token: Grant = serde_json::from_str(&token_json)
            .map_err(|e| Error::new(Status::InvalidArg, format!("invalid token_json: {e}")))?;
        let pinned_host = PinnedHost {
            host_id: Some(host_id),
            static_pub,
            signing_pin,
            rotation_seq: rot_seq,
        };

        let fallback_floor = {
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pinned_pairing_floor(&roster, &pinned_host)
        };
        let mut stream = dial_endpoint(&endpoint, relay_host.as_deref())
            .await
            .map_err(to_generic_err)?;
        let device_name = name.unwrap_or_else(|| "node-machine".to_owned());
        let device_kind = kind.unwrap_or_else(|| "machine".to_owned());
        let res = if let Some(ref store) = self.store {
            drive_m2m_enroll_initiator_with_store(
                stream.as_mut(),
                &self.identity,
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
                &self.identity,
                device_name,
                device_kind,
                token,
                pinned_host,
                fallback_floor,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        let _ = stream.close().await;
        let res = res.map_err(to_generic_err)?;

        match res.outcome {
            PairOutcome::InitiatorEnrolled {
                device_id,
                host_id,
                host_static_pub,
                host_signing_pub,
                host_rotation_seq,
                token_nonce,
            } => {
                let mut roster = self.roster.lock().expect("roster mutex poisoned");
                roster
                    .insert_pinned_host(
                        host_id.clone(),
                        host_id.clone(),
                        host_static_pub,
                        Some(host_signing_pub),
                        host_rotation_seq,
                        Vec::new(),
                    )
                    .map_err(to_generic_err)?;
                self.persist_roster(&roster)?;
                Ok(serde_json::json!({
                    "device_id": device_id,
                    "host_id": host_id,
                    "status": "active",
                    "host_rotation_seq": host_rotation_seq,
                    "token_nonce": token_nonce,
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

    #[napi]
    pub async fn connect(
        &self,
        endpoint: String,
        target_host_id: String,
        grant_json: Option<String>,
        relay_host: Option<String>,
    ) -> Result<Session> {
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.is_empty() => Some(serde_json::from_str(&s).map_err(to_generic_err)?),
            _ => None,
        };
        let stream = dial_endpoint(&endpoint, relay_host.as_deref())
            .await
            .map_err(to_generic_err)?;
        let driver = match SessionDriver::connect_locked(
            stream,
            &self.identity,
            &target_host_id,
            grant,
            &self.roster,
            now_unix(),
        )
        .await
        {
            Ok(drv) => {
                persist_store_roster(self.store.as_ref(), &self.roster)?;
                drv
            }
            Err(e) => {
                if let Err(pe) = persist_store_roster(self.store.as_ref(), &self.roster) {
                    return Err(Error::new(Status::GenericFailure, format!("{e} ({pe})")));
                }
                return Err(to_generic_err(e));
            }
        };

        Ok(Session {
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(driver.into_concurrent()),
        })
    }

    #[napi]
    pub async fn accept_session(&self, timeout_ms: Option<f64>) -> Result<Session> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        let (stream, guard) = match self.router.recv_session(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting session")),
        };

        let driver = SessionDriver::accept_locked(
            stream,
            &self.identity,
            &self.roster,
            now_unix(),
            Some(self.router.rate_limiter()),
            Some(guard),
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .map_err(to_generic_err)?;

        Ok(Session {
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(driver.into_concurrent()),
        })
    }

    #[napi]
    pub fn close(&self) {
        self.router.close();
    }
}

#[napi]
pub struct Session {
    store: Option<Arc<StateStore>>,
    roster: Arc<StdMutex<Roster>>,
    session: Arc<ConcurrentSession>,
}

#[napi]
impl Session {
    #[napi]
    pub async fn send_data(&self, payload: Buffer) -> Result<()> {
        self.session
            .send_data(payload.as_ref())
            .await
            .map_err(to_generic_err)
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
                        persist_store_roster(self.store.as_ref(), &self.roster)?;
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
                    SessionEvent::Closed { code, reason } => serde_json::json!({
                        "status": "event",
                        "event": "closed",
                        "code": code,
                        "reason": reason,
                    }),
                };
                Ok(json.to_string())
            }
            Ok(Ok(None)) => Ok(serde_json::json!({ "status": "eof" }).to_string()),
            Ok(Err(e)) => {
                if let Err(pe) = persist_store_roster(self.store.as_ref(), &self.roster) {
                    Err(Error::new(Status::GenericFailure, format!("{e} ({pe})")))
                } else {
                    Err(to_generic_err(e))
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
        self.session.send_rekey().await.map_err(to_generic_err)
    }

    #[napi]
    pub async fn close(&self, code: Option<f64>, reason: Option<String>) -> Result<()> {
        let close_code = f64_to_u16(code, 1000, "code")?;
        self.session
            .send_close(close_code, reason.as_deref().unwrap_or("normal"))
            .await
            .map_err(to_generic_err)
    }
}
