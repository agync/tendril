//! Python PyO3 bindings over `tendril-core` and `tendril-runtime` with GIL release.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tendril_core::crypto::{
    b64url_decode_array, b64url_encode, compute_code_mac as core_compute_code_mac,
    device_id as core_device_id, fingerprint_device as core_fingerprint_device,
    fingerprint_host as core_fingerprint_host, pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::grants::{Grant, RevocationList, authorize_grant};
use tendril_core::identity::{EndpointIdentity, RotationRecord, verify_rotation_chain};
use tendril_core::pairing::{PairOutcome, PairingCodeKind, PairingConfig, PairingManager};
use tendril_core::roster::Roster;
use tendril_runtime::{
    ConcurrentSession, DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT, DirectListener,
    InboundRouter, P2pListener, PathListener, PathStream, RelayListener, SessionDriver,
    SessionEvent, StateStore, dial_endpoint as runtime_dial_endpoint, drive_pair_initiator,
    drive_pair_responder_with_options, pairing_path_kind_for_provider, parse_p2p_relay_mode,
};
use tokio::runtime::Runtime;
use tokio::time::timeout;

fn persist_store_roster(
    store: Option<&Arc<StateStore>>,
    roster: &Arc<StdMutex<Roster>>,
) -> PyResult<()> {
    if let Some(s) = store {
        let guard = roster.lock().expect("roster mutex poisoned");
        s.save_roster(&guard)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn as_32(bytes: &[u8], name: &str) -> PyResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{name} must be exactly 32 bytes")))
}

async fn dial_endpoint(
    endpoint: &str,
    relay_host: Option<&str>,
) -> Result<Box<dyn PathStream>, String> {
    runtime_dial_endpoint(endpoint, relay_host)
        .await
        .map_err(|e| e.to_string())
}

#[pyfunction]
fn device_id(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_device_id(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn fingerprint_host(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_fingerprint_host(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn fingerprint_device(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_fingerprint_device(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn pairing_sas(handshake_hash: &[u8]) -> PyResult<String> {
    Ok(core_pairing_sas(&as_32(handshake_hash, "handshake_hash")?))
}

#[pyfunction]
fn compute_code_mac(py: Python<'_>, code: &str, handshake_hash: &[u8]) -> PyResult<Py<PyBytes>> {
    let hh = as_32(handshake_hash, "handshake_hash")?;
    let code_owned = code.to_owned();
    let mac = py
        .detach(move || core_compute_code_mac(&code_owned, &hh))
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &mac).unbind())
}

#[pyfunction]
fn verify_rotation_chain_json(
    pinned_signing_b64: &str,
    pinned_static_b64: &str,
    pinned_seq: u64,
    chain_json: &str,
    cur_static_b64: &str,
    cur_signing_b64: &str,
) -> PyResult<u64> {
    let psig = b64url_decode_array::<32>(pinned_signing_b64)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let pstat = b64url_decode_array::<32>(pinned_static_b64)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let cstat = b64url_decode_array::<32>(cur_static_b64)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let csig = b64url_decode_array::<32>(cur_signing_b64)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let chain: Vec<RotationRecord> =
        serde_json::from_str(chain_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    verify_rotation_chain(&psig, &pstat, pinned_seq, &chain, &cstat, &csig)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (grant_json, issuer_keys_json, expected_subject, expected_root_issuer, requested_cap, now_unix_secs, crl_json=None))]
fn verify_grant_json(
    grant_json: &str,
    issuer_keys_json: &str,
    expected_subject: &str,
    expected_root_issuer: &str,
    requested_cap: &str,
    now_unix_secs: u64,
    crl_json: Option<&str>,
) -> PyResult<bool> {
    let grant: Grant =
        serde_json::from_str(grant_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let key_map_raw: HashMap<String, String> =
        serde_json::from_str(issuer_keys_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let mut key_map = HashMap::with_capacity(key_map_raw.len());
    for (id, b64) in key_map_raw {
        let k = b64url_decode_array::<32>(&b64)
            .map_err(|e| PyValueError::new_err(format!("invalid key for {id}: {e}")))?;
        key_map.insert(id, k);
    }
    let crl: Option<RevocationList> = match crl_json {
        Some(s) if !s.is_empty() => {
            Some(serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?)
        }
        _ => None,
    };
    let (res, _) = authorize_grant(
        Some(&grant),
        expected_subject,
        expected_root_issuer,
        requested_cap,
        now_unix_secs,
        crl.as_ref(),
        |id| key_map.get(id).copied(),
    );
    Ok(res.is_ok())
}

#[pyclass(frozen)]
struct Endpoint {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    router: Arc<InboundRouter>,
}

#[pymethods]
impl Endpoint {
    #[new]
    #[pyo3(signature = (state_dir=None, host_id=None))]
    fn new(py: Python<'_>, state_dir: Option<&str>, host_id: Option<&str>) -> PyResult<Self> {
        let dir_owned = state_dir.filter(|s| !s.is_empty()).map(ToOwned::to_owned);
        let host_owned = host_id.map(ToOwned::to_owned);
        py.detach(move || {
            let rt = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
            );
            let (store, identity, roster) = if let Some(dir) = dir_owned {
                let store = Arc::new(
                    StateStore::open_or_create(dir)
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
                );
                let identity = store
                    .load_or_generate_identity(host_owned.as_deref())
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                let roster = store
                    .load_roster()
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                (Some(store), identity, roster)
            } else {
                let mut identity = EndpointIdentity::generate()
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                if let Some(h) = host_owned.as_deref()
                    && !h.is_empty()
                {
                    identity = identity.with_host_id(h);
                }
                (None, identity, Roster::new())
            };

            Ok(Self {
                rt,
                store,
                identity: Arc::new(identity),
                roster: Arc::new(StdMutex::new(roster)),
                pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
                router: Arc::new(InboundRouter::new()),
            })
        })
    }

    fn info_json(&self) -> String {
        serde_json::json!({
            "host_id": self.identity.host_id(),
            "device_id": self.identity.device_id(),
            "static_pub": b64url_encode(self.identity.static_key().public_bytes()),
            "signing_pub": b64url_encode(self.identity.signing_key().public_bytes()),
        })
        .to_string()
    }

    #[pyo3(signature = (listen_addr="127.0.0.1:0"))]
    fn serve_direct(&self, py: Python<'_>, listen_addr: &str) -> PyResult<String> {
        let addr: SocketAddr = listen_addr
            .parse()
            .map_err(|e| PyValueError::new_err(format!("invalid address: {e}")))?;
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        py.detach(move || {
            let listener = rt
                .block_on(DirectListener::bind(addr, None))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let ep = listener.local_endpoint();
            router.spawn_listener(rt.handle(), Box::new(listener));
            Ok(ep)
        })
    }

    #[pyo3(signature = (relay_url, expected_host=None))]
    fn serve_relay(
        &self,
        py: Python<'_>,
        relay_url: &str,
        expected_host: Option<&str>,
    ) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let url = relay_url.to_owned();
        let exp = expected_host.map(ToOwned::to_owned);
        let key = self.identity.signing_key().signing_key();
        py.detach(move || {
            let listener = rt
                .block_on(RelayListener::bind(url, exp, key, DEFAULT_WRITE_TIMEOUT))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let ep = listener.local_endpoint();
            router.spawn_listener(rt.handle(), Box::new(listener));
            Ok(ep)
        })
    }

    #[pyo3(signature = (relay_mode=None))]
    fn serve_p2p(&self, py: Python<'_>, relay_mode: Option<&str>) -> PyResult<String> {
        let mode =
            parse_p2p_relay_mode(relay_mode).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let seed = self.identity.derive_p2p_identity_seed();
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        py.detach(move || {
            let listener = rt
                .block_on(P2pListener::bind_with_secret(mode, seed))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let ep = listener.local_endpoint();
            router.spawn_listener(rt.handle(), Box::new(listener));
            Ok(ep)
        })
    }

    #[pyo3(signature = (kind="lan"))]
    fn issue_code(&self, py: Python<'_>, kind: &str) -> PyResult<String> {
        let pk = match kind {
            "" | "lan" => PairingCodeKind::Lan2Group,
            "remote" => PairingCodeKind::Remote3Group,
            other => {
                return Err(PyValueError::new_err(format!(
                    "invalid pairing code kind '{other}'"
                )));
            }
        };
        let mgr = Arc::clone(&self.pair_mgr);
        py.detach(move || {
            let mut guard = mgr.lock().expect("pair_mgr mutex poisoned");
            guard
                .issue_code(pk, now_unix())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }

    #[pyo3(signature = (endpoint, code, relay_host=None, name="py-device", kind="python"))]
    fn pair_initiate(
        &self,
        py: Python<'_>,
        endpoint: &str,
        code: &str,
        relay_host: Option<&str>,
        name: &str,
        kind: &str,
    ) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let code_s = code.to_owned();
        let name_s = name.to_owned();
        let kind_s = kind.to_owned();

        py.detach(move || {
            let res = rt.block_on(async move {
                let mut stream = dial_endpoint(&ep_s, rh_s.as_deref())
                    .await
                    .map_err(PyRuntimeError::new_err)?;
                let pair_res =
                    drive_pair_initiator(stream.as_mut(), &identity, name_s, kind_s, code_s, None)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()));
                let _ = stream.close().await;
                pair_res
            })?;

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
                    {
                        let mut roster = roster_arc.lock().expect("roster mutex poisoned");
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
                        pin_res.map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                    }
                    persist_store_roster(store.as_ref(), &roster_arc)?;
                    Ok(serde_json::json!({
                        "device_id": device_id,
                        "host_id": host_id,
                        "sas": pairing_sas,
                        "status": if host_pin_verified { "active" } else { "pending" },
                        "host_confirmed": host_pin_verified,
                    })
                    .to_string())
                }
                PairOutcome::Rejected { error } => Err(PyRuntimeError::new_err(error)),
                PairOutcome::ResponderPending { .. } => {
                    Err(PyRuntimeError::new_err("unexpected responder outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn pair_accept(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let pair_mgr = Arc::clone(&self.pair_mgr);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let wait = Duration::from_millis(timeout_ms);

        py.detach(move || {
            let roster_in = Arc::clone(&roster_arc);
            let res = rt.block_on(async move {
                let (mut stream, guard) = match router.recv_pair(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => return Err(PyRuntimeError::new_err("timed out accepting pair")),
                };

                let path_kind = pairing_path_kind_for_provider(stream.provider_id());
                drive_pair_responder_with_options(
                    stream.as_mut(),
                    &identity,
                    &pair_mgr,
                    &roster_in,
                    path_kind,
                    now_unix(),
                    Some(router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })?;

            match res.outcome {
                PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => {
                    persist_store_roster(store.as_ref(), &roster_arc)?;
                    Ok(serde_json::json!({
                        "device_id": device_id,
                        "sas": pairing_sas,
                        "name": name,
                        "kind": kind,
                    })
                    .to_string())
                }
                PairOutcome::Rejected { error } => Err(PyRuntimeError::new_err(error)),
                PairOutcome::InitiatorPending { .. } => {
                    Err(PyRuntimeError::new_err("unexpected initiator outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (peer_id, sas=None))]
    fn confirm_peer(&self, py: Python<'_>, peer_id: &str, sas: Option<&str>) -> PyResult<()> {
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let pid = peer_id.to_owned();
        let sas_owned = sas.map(ToOwned::to_owned);
        py.detach(move || {
            {
                let mut roster = roster_arc.lock().expect("roster mutex poisoned");
                roster
                    .confirm_peer(&pid, sas_owned.as_deref())
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            }
            persist_store_roster(store.as_ref(), &roster_arc)
        })
    }

    #[pyo3(signature = (peer_id, caps, ttl_secs=3600))]
    fn mint_grant(
        &self,
        py: Python<'_>,
        peer_id: &str,
        caps: Vec<String>,
        ttl_secs: u64,
    ) -> PyResult<String> {
        let roster_arc = Arc::clone(&self.roster);
        let identity = Arc::clone(&self.identity);
        let store = self.store.clone();
        let pid = peer_id.to_owned();
        py.detach(move || {
            let nonce = random_bytes::<16>().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let grant = {
                let mut roster = roster_arc.lock().expect("roster mutex poisoned");
                let now = now_unix();
                roster
                    .mint_grant(
                        &identity,
                        &pid,
                        caps,
                        now,
                        now.saturating_add(ttl_secs),
                        nonce,
                    )
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            };
            persist_store_roster(store.as_ref(), &roster_arc)?;
            serde_json::to_string(&grant).map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }

    fn revoke_peer(&self, py: Python<'_>, peer_id: &str) -> PyResult<()> {
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let pid = peer_id.to_owned();
        py.detach(move || {
            {
                let mut roster = roster_arc.lock().expect("roster mutex poisoned");
                roster
                    .revoke_peer(&pid)
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            }
            persist_store_roster(store.as_ref(), &roster_arc)
        })
    }

    #[pyo3(signature = (endpoint, target_host_id, grant_json=None, relay_host=None))]
    fn connect(
        &self,
        py: Python<'_>,
        endpoint: &str,
        target_host_id: &str,
        grant_json: Option<&str>,
        relay_host: Option<&str>,
    ) -> PyResult<Session> {
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.is_empty() => {
                Some(serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?)
            }
            _ => None,
        };
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let target_s = target_host_id.to_owned();

        let driver = py.detach(move || {
            let roster_in = Arc::clone(&roster);
            let res = rt.block_on(async move {
                let stream = dial_endpoint(&ep_s, rh_s.as_deref())
                    .await
                    .map_err(PyRuntimeError::new_err)?;
                SessionDriver::connect_locked(
                    stream,
                    &identity,
                    &target_s,
                    grant,
                    &roster_in,
                    now_unix(),
                )
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            });
            match res {
                Ok(drv) => {
                    persist_store_roster(store.as_ref(), &roster)?;
                    Ok(drv)
                }
                Err(err) => {
                    if let Err(pe) = persist_store_roster(store.as_ref(), &roster) {
                        Err(PyRuntimeError::new_err(format!(
                            "{err} (roster persist error: {pe})"
                        )))
                    } else {
                        Err(err)
                    }
                }
            }
        })?;

        Ok(Session {
            rt: Arc::clone(&self.rt),
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(driver.into_concurrent()),
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn accept_session(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Session> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let wait = Duration::from_millis(timeout_ms);

        let driver = py.detach(move || {
            rt.block_on(async move {
                let (stream, guard) = match router.recv_session(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => return Err(PyRuntimeError::new_err("timed out accepting session")),
                };

                SessionDriver::accept_locked(
                    stream,
                    &identity,
                    &roster,
                    now_unix(),
                    Some(router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })
        })?;

        Ok(Session {
            rt: Arc::clone(&self.rt),
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(driver.into_concurrent()),
        })
    }

    fn close(&self, py: Python<'_>) {
        let router = Arc::clone(&self.router);
        py.detach(move || router.close());
    }
}

#[pyclass(frozen)]
struct Session {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    roster: Arc<StdMutex<Roster>>,
    session: Arc<ConcurrentSession>,
}

#[pymethods]
impl Session {
    fn send_data(&self, py: Python<'_>, payload: &[u8]) -> PyResult<()> {
        let data = payload.to_vec();
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        py.detach(move || {
            rt.block_on(async move {
                sess.send_data(&data)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn poll_event(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let wait = Duration::from_millis(timeout_ms);

        py.detach(move || {
            rt.block_on(async move {
                match timeout(wait, sess.next_event_locked_now(&roster)).await {
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
                                persist_store_roster(store.as_ref(), &roster)?;
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
                        if let Err(pe) = persist_store_roster(store.as_ref(), &roster) {
                            Err(PyRuntimeError::new_err(format!("{e} ({pe})")))
                        } else {
                            Err(PyRuntimeError::new_err(e.to_string()))
                        }
                    }
                    Err(_) => Ok(serde_json::json!({ "status": "would_block" }).to_string()),
                }
            })
        })
    }

    fn authorize(&self, py: Python<'_>, requested_cap: &str) -> bool {
        let sess = Arc::clone(&self.session);
        let roster = Arc::clone(&self.roster);
        let cap = requested_cap.to_owned();
        py.detach(move || sess.authorize_locked(&cap, now_unix(), &roster).0.is_ok())
    }

    fn rekey(&self, py: Python<'_>) -> PyResult<()> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        py.detach(move || {
            rt.block_on(async move {
                sess.send_rekey()
                    .await
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })
        })
    }

    #[pyo3(signature = (code=1000, reason="normal"))]
    fn close(&self, py: Python<'_>, code: u16, reason: &str) -> PyResult<()> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        let reason_s = reason.to_owned();
        py.detach(move || {
            rt.block_on(async move {
                sess.send_close(code, &reason_s)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })
        })
    }
}

#[pymodule]
fn _tendril(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(device_id, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_host, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_device, m)?)?;
    m.add_function(wrap_pyfunction!(pairing_sas, m)?)?;
    m.add_function(wrap_pyfunction!(compute_code_mac, m)?)?;
    m.add_function(wrap_pyfunction!(verify_rotation_chain_json, m)?)?;
    m.add_function(wrap_pyfunction!(verify_grant_json, m)?)?;
    m.add_class::<Endpoint>()?;
    m.add_class::<Session>()?;
    Ok(())
}
