//! Line-delimited JSON stdin/stdout conformance peer driving `tendril-runtime`.

use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::{HybridSigningPublicKey, b64url_decode, b64url_encode, random_bytes};
use tendril_core::grants::Grant;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    EnrollmentPolicy, PairOutcome, PairingCodeKind, PairingConfig, PairingManager, PairingPathKind,
    mint_enrollment_token as core_mint_enrollment_token,
};
use tendril_core::policy::ProviderId;
use tendril_core::roster::{AnchorState, Roster};
use tendril_core::wire::{Intent, Preamble};
use tendril_runtime::{
    DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, LocalDialer,
    PathDialer, PathListener, PathStream, PrefixedPathStream, RelayDialer, RelayListener,
    SessionDriver, SessionEvent, StateStore, drive_pair_initiator_with_floor,
    drive_pair_responder_with_policy, peek_exact,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum PeerCmd {
    Init {
        state_dir: Option<PathBuf>,
        host_id: Option<String>,
    },
    ServeDirect {
        listen: Option<SocketAddr>,
    },
    ServeRelay {
        relay_url: String,
        expected_host: Option<String>,
    },
    IssueCode {
        kind: Option<String>,
    },
    AddTrustAnchor {
        anchor_id: String,
        signing_pub: String,
    },
    RevokeTrustAnchor {
        anchor_id: String,
    },
    MintEnrollmentToken {
        target_host_id: String,
        subject: Option<String>,
        ttl_secs: Option<u64>,
    },
    Pair {
        endpoint: Option<String>,
        relay_host: Option<String>,
        code: Option<String>,
        name: Option<String>,
        kind: Option<String>,
    },
    Confirm {
        peer_id: String,
        sas: Option<String>,
    },
    Mint {
        peer_id: String,
        caps: Vec<String>,
        ttl_secs: Option<u64>,
    },
    Connect {
        endpoint: Option<String>,
        relay_host: Option<String>,
        target_host_id: Option<String>,
        grant: Option<Grant>,
    },
    Send {
        data_b64: Option<String>,
        data_utf8: Option<String>,
    },
    Recv {
        timeout_ms: Option<u64>,
    },
    Authorize {
        cap: String,
    },
    Rekey,
    Revoke {
        peer_id: String,
    },
    Close {
        code: Option<u16>,
        reason: Option<String>,
    },
    Shutdown,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct PeerState {
    store: Option<StateStore>,
    identity: Option<EndpointIdentity>,
    roster: Roster,
    pair_mgr: PairingManager,
    self_m2m_enabled: bool,
    accepted_tx: mpsc::Sender<Box<dyn PathStream>>,
    accepted_rx: mpsc::Receiver<Box<dyn PathStream>>,
    listener_tasks: Vec<JoinHandle<()>>,
    session: Option<SessionDriver>,
}

impl PeerState {
    fn new() -> Self {
        let (accepted_tx, accepted_rx) = mpsc::channel(32);
        Self {
            store: None,
            identity: None,
            roster: Roster::new(),
            pair_mgr: PairingManager::new(PairingConfig::default()),
            self_m2m_enabled: false,
            accepted_tx,
            accepted_rx,
            listener_tasks: Vec::new(),
            session: None,
        }
    }

    fn persist_roster(&self) -> Result<(), String> {
        if let Some(store) = &self.store {
            store.save_roster(&self.roster).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn spawn_listener(&self, mut listener: Box<dyn PathListener>) -> JoinHandle<()> {
        let tx = self.accepted_tx.clone();
        tokio::spawn(async move {
            while let Ok(stream) = listener.accept().await {
                if tx.send(stream).await.is_err() {
                    break;
                }
            }
        })
    }

    fn shutdown_listeners(&mut self) {
        for handle in self.listener_tasks.drain(..) {
            handle.abort();
        }
    }
}

async fn dial_endpoint(
    endpoint: &str,
    relay_host: Option<&str>,
) -> Result<Box<dyn PathStream>, String> {
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

fn ok_json<T: Serialize>(v: T) -> serde_json::Value {
    serde_json::to_value(v)
        .unwrap_or_else(|e| serde_json::json!({ "ok": false, "error": e.to_string() }))
}

fn err_json(msg: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "ok": false, "error": msg.into() })
}

async fn dispatch_cmd(state: &mut PeerState, cmd: PeerCmd) -> (serde_json::Value, bool) {
    match cmd {
        PeerCmd::Init { state_dir, host_id } => {
            let identity_res = if let Some(dir) = state_dir {
                match StateStore::open_or_create(&dir) {
                    Ok(store) => {
                        let id = store.load_or_generate_identity(host_id.as_deref());
                        match id {
                            Ok(id) => {
                                state.roster = store.load_roster().unwrap_or_default();
                                state.store = Some(store);
                                Ok(id)
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            } else {
                EndpointIdentity::generate()
                    .map(|id| match host_id {
                        Some(h) if !h.is_empty() => id.with_host_id(h),
                        _ => id,
                    })
                    .map_err(|e| e.to_string())
            };
            match identity_res {
                Ok(id) => {
                    let resp = serde_json::json!({
                        "ok": true,
                        "host_id": id.host_id(),
                        "device_id": id.device_id(),
                        "static_pub": b64url_encode(id.static_key().public_bytes()),
                        "signing_pub": id.signing_key().public_key().to_b64url(),
                        "signing_pub_hash": b64url_encode(&id.signing_key().signing_pub_hash()),
                        "relay_pub": b64url_encode(id.signing_key().ed25519_public_bytes()),
                    });
                    state.identity = Some(id);
                    (resp, false)
                }
                Err(e) => (err_json(e), false),
            }
        }
        PeerCmd::ServeDirect { listen } => {
            let addr = listen.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
            match DirectListener::bind(addr, None).await {
                Ok(listener) => {
                    let ep = listener.local_endpoint();
                    let task = state.spawn_listener(Box::new(listener));
                    state.listener_tasks.push(task);
                    (serde_json::json!({ "ok": true, "endpoint": ep }), false)
                }
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::ServeRelay {
            relay_url,
            expected_host,
        } => {
            let Some(id) = state.identity.as_ref() else {
                return (err_json("init required before serve_relay"), false);
            };
            match RelayListener::bind(
                relay_url,
                expected_host,
                id.signing_key().ed25519_signing_key(),
                DEFAULT_WRITE_TIMEOUT,
            )
            .await
            {
                Ok(listener) => {
                    let ep = listener.local_endpoint();
                    let task = state.spawn_listener(Box::new(listener));
                    state.listener_tasks.push(task);
                    (serde_json::json!({ "ok": true, "endpoint": ep }), false)
                }
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::IssueCode { kind } => {
            let pk = match kind.as_deref() {
                Some("remote") => PairingCodeKind::Remote3Group,
                _ => PairingCodeKind::Lan2Group,
            };
            match state.pair_mgr.issue_code(pk, now_unix()) {
                Ok(code) => (serde_json::json!({ "ok": true, "code": code }), false),
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::AddTrustAnchor {
            anchor_id,
            signing_pub,
        } => {
            let signing_key = match HybridSigningPublicKey::from_b64url(&signing_pub) {
                Ok(k) => k,
                Err(e) => return (err_json(e.to_string()), false),
            };
            if let Err(e) = state.roster.add_trust_anchor(anchor_id, signing_key) {
                return (err_json(e.to_string()), false);
            }
            if let Err(e) = state.persist_roster() {
                return (err_json(e), false);
            }
            (serde_json::json!({ "ok": true }), false)
        }
        PeerCmd::RevokeTrustAnchor { anchor_id } => {
            if let Err(e) = state.roster.revoke_trust_anchor(&anchor_id) {
                return (err_json(e.to_string()), false);
            }
            if let Err(e) = state.persist_roster() {
                return (err_json(e), false);
            }
            (serde_json::json!({ "ok": true }), false)
        }
        PeerCmd::MintEnrollmentToken {
            target_host_id,
            subject,
            ttl_secs,
        } => {
            let Some(id) = state.identity.as_ref() else {
                return (
                    err_json("init required before mint_enrollment_token"),
                    false,
                );
            };
            let nonce = match random_bytes::<16>() {
                Ok(n) => n,
                Err(e) => return (err_json(e.to_string()), false),
            };
            let token = match core_mint_enrollment_token(
                id,
                &target_host_id,
                subject.as_deref(),
                now_unix(),
                ttl_secs.unwrap_or(900),
                nonce,
            ) {
                Ok(t) => t,
                Err(e) => return (err_json(e.to_string()), false),
            };
            if target_host_id == id.host_id() {
                state.self_m2m_enabled = true;
            }
            let json = Zeroizing::new(serde_json::to_string(&token).expect("serialize token"));
            (
                serde_json::json!({ "ok": true, "token_json": *json }),
                false,
            )
        }
        PeerCmd::Pair {
            endpoint,
            relay_host,
            code,
            name,
            kind,
        } => {
            let Some(id) = state.identity.clone() else {
                return (err_json("init required before pair"), false);
            };
            if let Some(ep) = endpoint {
                let Some(code_str) = code else {
                    return (err_json("initiator pair requires 'code'"), false);
                };
                let mut stream = match dial_endpoint(&ep, relay_host.as_deref()).await {
                    Ok(s) => s,
                    Err(e) => return (err_json(e), false),
                };
                match drive_pair_initiator_with_floor(
                    stream.as_mut(),
                    &id,
                    name.unwrap_or_else(|| "peer-client".to_owned()),
                    kind.unwrap_or_else(|| "cli".to_owned()),
                    code_str,
                    None,
                    tendril_core::WIRE_VERSION,
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                {
                    Ok(res) => match res.outcome {
                        PairOutcome::InitiatorPending {
                            device_id,
                            host_id,
                            host_static_pub,
                            host_signing_pub,
                            host_rotation_seq,
                            pairing_sas,
                            host_pin_verified,
                        } => {
                            let pin_res = if host_pin_verified {
                                state.roster.insert_pinned_host(
                                    host_id.clone(),
                                    host_id.clone(),
                                    host_static_pub,
                                    Some(host_signing_pub),
                                    host_rotation_seq,
                                    Vec::new(),
                                )
                            } else {
                                state.roster.record_pending_host(
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
                                return (err_json(e.to_string()), false);
                            }
                            if let Err(e) = state.persist_roster() {
                                return (err_json(e), false);
                            }
                            (
                                serde_json::json!({
                                    "ok": true,
                                    "role": "initiator",
                                    "device_id": device_id,
                                    "host_id": host_id,
                                    "sas": pairing_sas,
                                    "host_confirmed": host_pin_verified,
                                }),
                                false,
                            )
                        }
                        PairOutcome::Rejected { error } => (err_json(error), false),
                        PairOutcome::ResponderPending { .. }
                        | PairOutcome::ResponderEnrolled { .. } => {
                            (err_json("unexpected responder outcome"), false)
                        }
                        PairOutcome::InitiatorEnrolled { .. } => {
                            (err_json("unexpected m2m enrollment outcome"), false)
                        }
                    },
                    Err(e) => (err_json(e.to_string()), false),
                }
            } else {
                let Ok(Some(mut stream)) =
                    timeout(Duration::from_secs(10), state.accepted_rx.recv()).await
                else {
                    return (err_json("timed out accepting pairing connection"), false);
                };
                let Ok(Ok(peeked)) = timeout(
                    Duration::from_secs(10),
                    peek_exact(stream.as_mut(), PREAMBLE_LEN),
                )
                .await
                else {
                    return (err_json("timed out reading pairing preamble"), false);
                };
                if let Err(e) = Preamble::decode(&peeked[..PREAMBLE_LEN])
                    .map_err(|e| e.to_string())
                    .and_then(|p| {
                        (p.intent == Intent::Pair)
                            .then_some(())
                            .ok_or_else(|| "expected pair preamble".to_owned())
                    })
                {
                    return (err_json(e), false);
                }
                let mut wrapped = PrefixedPathStream::new(stream, peeked);
                let path_kind = if wrapped.provider_id() == ProviderId::Relay {
                    PairingPathKind::Remote
                } else {
                    PairingPathKind::Lan
                };
                let policy = if state.self_m2m_enabled
                    || state
                        .roster
                        .trust_anchors()
                        .any(|(_, a)| a.state == AnchorState::Active)
                {
                    EnrollmentPolicy::enabled_default()
                } else {
                    EnrollmentPolicy::default()
                };
                let mgr_lock = StdMutex::new(std::mem::replace(
                    &mut state.pair_mgr,
                    PairingManager::new(PairingConfig::default()),
                ));
                let roster_lock = StdMutex::new(std::mem::take(&mut state.roster));
                let pair_res = drive_pair_responder_with_policy(
                    &mut wrapped,
                    &id,
                    &mgr_lock,
                    &roster_lock,
                    path_kind,
                    now_unix(),
                    policy,
                    None,
                    None,
                    tendril_runtime::DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await;
                state.pair_mgr = mgr_lock.into_inner().expect("lock");
                state.roster = roster_lock.into_inner().expect("lock");
                match pair_res {
                    Ok(res) => match res.outcome {
                        PairOutcome::ResponderPending {
                            device_id,
                            pairing_sas,
                            name,
                            kind,
                            ..
                        } => {
                            if let Err(e) = state.persist_roster() {
                                return (err_json(e), false);
                            }
                            (
                                serde_json::json!({
                                    "ok": true,
                                    "role": "responder",
                                    "device_id": device_id,
                                    "sas": pairing_sas,
                                    "name": name,
                                    "kind": kind,
                                }),
                                false,
                            )
                        }
                        PairOutcome::ResponderEnrolled {
                            device_id,
                            token_nonce,
                            name,
                            kind,
                            ..
                        } => {
                            if let Err(e) = state.persist_roster() {
                                return (err_json(e), false);
                            }
                            (
                                serde_json::json!({
                                    "ok": true,
                                    "role": "responder",
                                    "status": "active",
                                    "device_id": device_id,
                                    "token_nonce": token_nonce,
                                    "name": name,
                                    "kind": kind,
                                }),
                                false,
                            )
                        }
                        PairOutcome::Rejected { error } => (err_json(error), false),
                        PairOutcome::InitiatorPending { .. }
                        | PairOutcome::InitiatorEnrolled { .. } => {
                            (err_json("unexpected initiator outcome"), false)
                        }
                    },
                    Err(e) => (err_json(e.to_string()), false),
                }
            }
        }
        PeerCmd::Confirm { peer_id, sas } => {
            if let Err(e) = state.roster.confirm_peer(&peer_id, sas.as_deref()) {
                return (err_json(e.to_string()), false);
            }
            if let Err(e) = state.persist_roster() {
                return (err_json(e), false);
            }
            (serde_json::json!({ "ok": true, "peer_id": peer_id }), false)
        }
        PeerCmd::Mint {
            peer_id,
            caps,
            ttl_secs,
        } => {
            let Some(id) = state.identity.as_ref() else {
                return (err_json("init required before mint"), false);
            };
            let nonce = match random_bytes::<16>() {
                Ok(n) => n,
                Err(e) => return (err_json(e.to_string()), false),
            };
            let now = now_unix();
            match state.roster.mint_grant(
                id,
                &peer_id,
                caps,
                now,
                now.saturating_add(ttl_secs.unwrap_or(3600)),
                nonce,
            ) {
                Ok(grant) => {
                    if let Err(e) = state.persist_roster() {
                        return (err_json(e), false);
                    }
                    (
                        serde_json::json!({ "ok": true, "grant": ok_json(grant) }),
                        false,
                    )
                }
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::Connect {
            endpoint,
            relay_host,
            target_host_id,
            grant,
        } => {
            let Some(id) = state.identity.clone() else {
                return (err_json("init required before connect"), false);
            };
            let driver_res = if let Some(ep) = endpoint {
                let Some(target) = target_host_id else {
                    return (
                        err_json("initiator connect requires 'target_host_id'"),
                        false,
                    );
                };
                let stream = match dial_endpoint(&ep, relay_host.as_deref()).await {
                    Ok(s) => s,
                    Err(e) => return (err_json(e), false),
                };
                SessionDriver::connect(stream, &id, &target, grant, &mut state.roster, now_unix())
                    .await
            } else {
                let Ok(Some(stream)) =
                    timeout(Duration::from_secs(10), state.accepted_rx.recv()).await
                else {
                    return (err_json("timed out accepting session connection"), false);
                };
                SessionDriver::accept(stream, &id, &mut state.roster, now_unix(), None).await
            };
            match driver_res {
                Ok(driver) => {
                    let peer_device_id = driver.peer_device_id().map(ToOwned::to_owned);
                    let peer_crl_seq = driver.peer_crl_seq();
                    let provider = format!("{:?}", driver.provider_id());
                    state.session = Some(driver);
                    (
                        serde_json::json!({
                            "ok": true,
                            "peer_device_id": peer_device_id,
                            "peer_crl_seq": peer_crl_seq,
                            "provider": provider,
                        }),
                        false,
                    )
                }
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::Send {
            data_b64,
            data_utf8,
        } => {
            let Some(session) = state.session.as_mut() else {
                return (err_json("no active session"), false);
            };
            let payload = if let Some(b64) = data_b64 {
                match b64url_decode(&b64) {
                    Ok(bytes) => bytes,
                    Err(e) => return (err_json(e.to_string()), false),
                }
            } else if let Some(text) = data_utf8 {
                text.into_bytes()
            } else {
                return (err_json("send requires 'data_b64' or 'data_utf8'"), false);
            };
            match session.send_data(&payload).await {
                Ok(()) => (
                    serde_json::json!({ "ok": true, "sent_bytes": payload.len() }),
                    false,
                ),
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::Recv { timeout_ms } => {
            let Some(session) = state.session.as_mut() else {
                return (err_json("no active session"), false);
            };
            let wait = Duration::from_millis(timeout_ms.unwrap_or(5_000));
            match timeout(wait, session.next_event_now(&mut state.roster)).await {
                Ok(Ok(Some(SessionEvent::AppData(data)))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "data",
                        "data_b64": b64url_encode(&data),
                        "data_utf8": String::from_utf8_lossy(&data),
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::Rekeyed { direction }))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "rekeyed",
                        "direction": format!("{direction:?}"),
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::GrantUpdated(grant)))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "grant_updated",
                        "grant": ok_json(grant),
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::RevocationUpdated { issuer, seq }))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "revocation_updated",
                        "issuer": issuer,
                        "seq": seq,
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::PongReceived(cookie)))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "pong",
                        "cookie": cookie,
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::Audit(audit)))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "audit",
                        "audit": ok_json(audit),
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::Closed { code, reason }))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "closed",
                        "code": code,
                        "reason": reason,
                    }),
                    false,
                ),
                Ok(Ok(None)) => (serde_json::json!({ "ok": true, "event": "eof" }), false),
                Ok(Err(e)) => (err_json(e.to_string()), false),
                Err(_) => (err_json("recv timed out"), false),
            }
        }
        PeerCmd::Authorize { cap } => {
            let Some(session) = state.session.as_ref() else {
                return (err_json("no active session"), false);
            };
            let (res, audit) = session.authorize(&cap, now_unix(), &state.roster);
            (
                serde_json::json!({
                    "ok": true,
                    "allowed": res.is_ok(),
                    "audit": ok_json(audit),
                }),
                false,
            )
        }
        PeerCmd::Rekey => {
            let Some(session) = state.session.as_mut() else {
                return (err_json("no active session"), false);
            };
            match session.send_rekey().await {
                Ok(()) => (serde_json::json!({ "ok": true }), false),
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::Revoke { peer_id } => {
            if let Err(e) = state.roster.revoke_peer(&peer_id) {
                return (err_json(e.to_string()), false);
            }
            if let Err(e) = state.persist_roster() {
                return (err_json(e), false);
            }
            (serde_json::json!({ "ok": true, "revoked": peer_id }), false)
        }
        PeerCmd::Close { code, reason } => {
            if let Some(mut session) = state.session.take() {
                match session
                    .send_close(code.unwrap_or(1000), reason.as_deref().unwrap_or("normal"))
                    .await
                {
                    Ok(()) => (serde_json::json!({ "ok": true }), false),
                    Err(e) => (err_json(e.to_string()), false),
                }
            } else {
                (serde_json::json!({ "ok": true }), false)
            }
        }
        PeerCmd::Shutdown => {
            if let Some(mut session) = state.session.take() {
                let _ = session.send_close(1000, "shutdown").await;
            }
            state.shutdown_listeners();
            (serde_json::json!({ "ok": true }), true)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (line_tx, mut line_rx) = mpsc::channel::<String>(32);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(text) => {
                    if line_tx.blocking_send(text).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut state = PeerState::new();
    let stdout = std::io::stdout();

    while let Some(line) = line_rx.recv().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (resp, should_exit) = match serde_json::from_str::<PeerCmd>(trimmed) {
            Ok(cmd) => dispatch_cmd(&mut state, cmd).await,
            Err(err) => (err_json(format!("invalid command json: {err}")), false),
        };
        let encoded = serde_json::to_string(&resp)?;
        {
            let mut out = stdout.lock();
            out.write_all(encoded.as_bytes())?;
            out.write_all(b"\n")?;
            out.flush()?;
        }
        if should_exit {
            break;
        }
    }

    state.shutdown_listeners();
    Ok(())
}
