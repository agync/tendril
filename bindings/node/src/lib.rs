//! Node.js N-API native addon over `tendril-core` and `tendril-runtime`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::{
    b64url_decode_array, b64url_encode, compute_code_mac as core_compute_code_mac,
    device_id as core_device_id, fingerprint_device as core_fingerprint_device,
    fingerprint_host as core_fingerprint_host, pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::grants::{Grant, RevocationList, authorize_grant};
use tendril_core::identity::{EndpointIdentity, RotationRecord, verify_rotation_chain};
use tendril_core::pairing::{
    PairOutcome, PairingCodeKind, PairingConfig, PairingManager, PairingPathKind,
};
use tendril_core::policy::ProviderId;
use tendril_core::roster::Roster;
use tendril_core::wire::{Intent, Preamble};
use tendril_runtime::{
    DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, LocalDialer,
    PathDialer, PathListener, PathStream, PreAuthConfig, PreAuthRateLimiter, PrefixedPathStream,
    RelayDialer, RelayListener, SessionDriver, SessionEvent, StateStore, drive_pair_initiator,
    drive_pair_responder_with_options, peek_exact,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;

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

fn to_generic_err(err: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, err.to_string())
}

async fn dial_endpoint(
    endpoint: &str,
    relay_host: Option<&str>,
) -> std::result::Result<Box<dyn PathStream>, String> {
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        let mut dialer = RelayDialer::new();
        if let Some(host) = relay_host {
            dialer = dialer.with_expected_host(host);
        }
        dialer.dial(endpoint).await.map_err(|e| e.to_string())
    } else if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        LocalDialer::new()
            .dial(endpoint)
            .await
            .map_err(|e| e.to_string())
    } else {
        DirectDialer::new()
            .dial(endpoint)
            .await
            .map_err(|e| e.to_string())
    }
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
    pinned_seq: i64,
    chain_json: String,
    cur_static_b64: String,
    cur_signing_b64: String,
) -> Result<u32> {
    let pinned_seq_u64 = u64::try_from(pinned_seq)
        .map_err(|_| Error::new(Status::InvalidArg, "pinned_seq must be non-negative"))?;
    let psig = b64url_decode_array::<32>(&pinned_signing_b64).map_err(to_generic_err)?;
    let pstat = b64url_decode_array::<32>(&pinned_static_b64).map_err(to_generic_err)?;
    let cstat = b64url_decode_array::<32>(&cur_static_b64).map_err(to_generic_err)?;
    let csig = b64url_decode_array::<32>(&cur_signing_b64).map_err(to_generic_err)?;
    let chain: Vec<RotationRecord> = serde_json::from_str(&chain_json).map_err(to_generic_err)?;
    let seq = verify_rotation_chain(&psig, &pstat, pinned_seq_u64, &chain, &cstat, &csig)
        .map_err(to_generic_err)?;
    u32::try_from(seq).map_err(to_generic_err)
}

#[napi]
pub fn verify_grant_json(
    grant_json: String,
    issuer_keys_json: String,
    expected_subject: String,
    expected_root_issuer: String,
    requested_cap: String,
    now_unix_secs: i64,
    crl_json: Option<String>,
) -> Result<bool> {
    let now_u64 = u64::try_from(now_unix_secs)
        .map_err(|_| Error::new(Status::InvalidArg, "now_unix_secs must be non-negative"))?;
    let grant: Grant = serde_json::from_str(&grant_json).map_err(to_generic_err)?;
    let key_map_raw: HashMap<String, String> =
        serde_json::from_str(&issuer_keys_json).map_err(to_generic_err)?;
    let mut key_map = HashMap::with_capacity(key_map_raw.len());
    for (id, b64) in key_map_raw {
        let k = b64url_decode_array::<32>(&b64).map_err(to_generic_err)?;
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
        |id| key_map.get(id).copied(),
    );
    Ok(res.is_ok())
}

#[napi]
pub struct Endpoint {
    store: Option<Arc<StateStore>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    rate_limiter: PreAuthRateLimiter,
    accepted_tx: mpsc::Sender<Box<dyn PathStream>>,
    accepted_rx: Arc<AsyncMutex<mpsc::Receiver<Box<dyn PathStream>>>>,
    listener_tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl Endpoint {
    fn persist_roster(&self, roster: &Roster) -> Result<()> {
        if let Some(store) = &self.store {
            store.save_roster(roster).map_err(to_generic_err)?;
        }
        Ok(())
    }

    fn spawn_listener(&self, mut listener: Box<dyn PathListener>) {
        let tx = self.accepted_tx.clone();
        let handle = tokio::spawn(async move {
            while let Ok(stream) = listener.accept().await {
                if tx.send(stream).await.is_err() {
                    break;
                }
            }
        });
        self.listener_tasks
            .lock()
            .expect("listener_tasks mutex poisoned")
            .push(handle);
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.listener_tasks.lock() {
            for h in tasks.drain(..) {
                h.abort();
            }
        }
    }
}

#[napi]
impl Endpoint {
    #[napi(constructor)]
    pub fn new(state_dir: Option<String>, host_id: Option<String>) -> Result<Self> {
        let host_opt = host_id.as_deref();
        let (store, identity, roster) = if let Some(dir) = state_dir {
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

        let (accepted_tx, accepted_rx) = mpsc::channel(32);
        Ok(Self {
            store,
            identity: Arc::new(identity),
            roster: Arc::new(StdMutex::new(roster)),
            pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
            rate_limiter: PreAuthRateLimiter::new(PreAuthConfig::default()),
            accepted_tx,
            accepted_rx: Arc::new(AsyncMutex::new(accepted_rx)),
            listener_tasks: StdMutex::new(Vec::new()),
        })
    }

    #[napi]
    pub fn info_json(&self) -> String {
        serde_json::json!({
            "host_id": self.identity.host_id(),
            "device_id": self.identity.device_id(),
            "static_pub": b64url_encode(self.identity.static_key().public_bytes()),
            "signing_pub": b64url_encode(self.identity.signing_key().public_bytes()),
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
        let key = self.identity.signing_key().signing_key();
        let listener = RelayListener::bind(relay_url, expected_host, key, DEFAULT_WRITE_TIMEOUT)
            .await
            .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        Ok(ep)
    }

    #[napi]
    pub fn issue_code(&self, kind: Option<String>) -> Result<String> {
        let pk = match kind.as_deref() {
            Some("remote") => PairingCodeKind::Remote3Group,
            _ => PairingCodeKind::Lan2Group,
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
        let res = drive_pair_initiator(
            stream.as_mut(),
            &self.identity,
            name.unwrap_or_else(|| "node-device".to_owned()),
            kind.unwrap_or_else(|| "node".to_owned()),
            code,
            None,
        )
        .await
        .map_err(to_generic_err)?;

        match res.outcome {
            PairOutcome::InitiatorPending {
                device_id,
                host_id,
                host_static_pub,
                host_signing_pub,
                host_rotation_seq,
                pairing_sas,
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
                    "sas": pairing_sas,
                })
                .to_string())
            }
            PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            PairOutcome::ResponderPending { .. } => {
                Err(to_generic_err("unexpected responder outcome"))
            }
        }
    }

    #[napi]
    pub async fn pair_accept(&self, timeout_ms: Option<u32>) -> Result<String> {
        let wait = Duration::from_millis(u64::from(timeout_ms.unwrap_or(5000).max(1)));
        let mut rx = self.accepted_rx.lock().await;
        let mut stream = match timeout(wait, rx.recv()).await {
            Ok(Some(s)) => s,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(_) => return Err(to_generic_err("timed out accepting pair")),
        };
        drop(rx);

        let guard = self
            .rate_limiter
            .try_acquire(stream.peer_ip())
            .map_err(to_generic_err)?;
        let peeked = timeout(
            DEFAULT_PRE_AUTH_TIMEOUT,
            peek_exact(stream.as_mut(), PREAMBLE_LEN),
        )
        .await
        .map_err(|_| to_generic_err("preamble read timed out"))?
        .map_err(to_generic_err)?;
        let preamble = Preamble::decode(&peeked[..PREAMBLE_LEN]).map_err(to_generic_err)?;
        if preamble.intent != Intent::Pair {
            return Err(to_generic_err("expected pair preamble"));
        }
        let mut wrapped = PrefixedPathStream::new(stream, peeked);
        let path_kind = if wrapped.provider_id() == ProviderId::Relay {
            PairingPathKind::Remote
        } else {
            PairingPathKind::Lan
        };
        let res = drive_pair_responder_with_options(
            &mut wrapped,
            &self.identity,
            &self.pair_mgr,
            &self.roster,
            path_kind,
            now_unix(),
            Some(&self.rate_limiter),
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
            } => {
                let roster = self.roster.lock().expect("roster mutex poisoned");
                self.persist_roster(&roster)?;
                Ok(serde_json::json!({
                    "device_id": device_id,
                    "sas": pairing_sas,
                    "name": name,
                    "kind": kind,
                })
                .to_string())
            }
            PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            PairOutcome::InitiatorPending { .. } => {
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
        ttl_secs: Option<u32>,
    ) -> Result<String> {
        let nonce = random_bytes::<16>().map_err(to_generic_err)?;
        let mut roster = self.roster.lock().expect("roster mutex poisoned");
        let now = now_unix();
        let ttl = u64::from(ttl_secs.unwrap_or(3600));
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
        self.persist_roster(&roster)
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
        let driver = SessionDriver::connect_locked(
            stream,
            &self.identity,
            &target_host_id,
            grant,
            &self.roster,
            now_unix(),
        )
        .await
        .map_err(to_generic_err)?;

        Ok(Session {
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            driver: Arc::new(AsyncMutex::new(driver)),
        })
    }

    #[napi]
    pub async fn accept_session(&self, timeout_ms: Option<u32>) -> Result<Session> {
        let wait = Duration::from_millis(u64::from(timeout_ms.unwrap_or(5000).max(1)));
        let mut rx = self.accepted_rx.lock().await;
        let stream = match timeout(wait, rx.recv()).await {
            Ok(Some(s)) => s,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(_) => return Err(to_generic_err("timed out accepting session")),
        };
        drop(rx);

        let guard = self
            .rate_limiter
            .try_acquire(stream.peer_ip())
            .map_err(to_generic_err)?;
        let driver = SessionDriver::accept_locked(
            stream,
            &self.identity,
            &self.roster,
            now_unix(),
            Some(&self.rate_limiter),
            Some(guard),
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .map_err(to_generic_err)?;

        Ok(Session {
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            driver: Arc::new(AsyncMutex::new(driver)),
        })
    }

    #[napi]
    pub fn close(&self) {
        if let Ok(mut tasks) = self.listener_tasks.lock() {
            for h in tasks.drain(..) {
                h.abort();
            }
        }
    }
}

#[napi]
pub struct Session {
    store: Option<Arc<StateStore>>,
    roster: Arc<StdMutex<Roster>>,
    driver: Arc<AsyncMutex<SessionDriver>>,
}

#[napi]
impl Session {
    #[napi]
    pub async fn send_data(&self, payload: Buffer) -> Result<()> {
        let mut guard = self.driver.lock().await;
        guard
            .send_data(payload.as_ref())
            .await
            .map_err(to_generic_err)
    }

    #[napi]
    pub async fn poll_event(&self, timeout_ms: Option<u32>) -> Result<String> {
        let wait = Duration::from_millis(u64::from(timeout_ms.unwrap_or(5000).max(1)));
        let mut guard = self.driver.lock().await;
        match timeout(wait, guard.next_event_locked(now_unix(), &self.roster)).await {
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
                        if let Some(s) = &self.store {
                            let rg = self.roster.lock().expect("roster mutex poisoned");
                            let _ = s.save_roster(&rg);
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
            Ok(Err(e)) => Err(to_generic_err(e)),
            Err(_) => Ok(serde_json::json!({ "status": "would_block" }).to_string()),
        }
    }

    #[napi]
    pub async fn authorize(&self, requested_cap: String) -> bool {
        let guard = self.driver.lock().await;
        let r = self.roster.lock().expect("roster mutex poisoned");
        guard.authorize(&requested_cap, now_unix(), &r).0.is_ok()
    }

    #[napi]
    pub async fn rekey(&self) -> Result<()> {
        let mut guard = self.driver.lock().await;
        guard.send_rekey().await.map_err(to_generic_err)
    }

    #[napi]
    pub async fn close(&self, code: Option<u16>, reason: Option<String>) -> Result<()> {
        let mut guard = self.driver.lock().await;
        guard
            .send_close(code.unwrap_or(1000), reason.as_deref().unwrap_or("normal"))
            .await
            .map_err(to_generic_err)
    }
}
