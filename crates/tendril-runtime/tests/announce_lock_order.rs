//! Lock order of a store-backed host: issuing pairing URIs while Wire v1 and v2 pairings claim
//! codes under the roster file lock must never deadlock.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::tempdir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    EnrollmentPolicy, IssueOptions, PairingCodeKind, PairingConfig, PairingManager, PairingPathKind,
};
use tendril_runtime::announce::unix_ms;
use tendril_runtime::{
    AddressSource, AdvertiseInputs, AdvertiseMode, DEFAULT_PRE_AUTH_TIMEOUT, LocalDialer,
    LocalListener, PathDialer, PathListener, RosterAccess, RouteAnnouncer, RuntimeError,
    StateStore, V2ResponderState, drive_pair_initiator_with_store, drive_pair_responder_with_store,
    drive_v2_pake_pair_initiator_with_store, drive_v2_pake_pair_responder_with_store,
};
use tokio::sync::Mutex as AsyncMutex;

/// Two pairings per wire use every live code slot (`MAX_LIVE_PAIRING_CODES`) up front.
const PAIRINGS_PER_WIRE: u8 = 2;

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
    )
}

fn inputs(endpoint: &str) -> AdvertiseInputs {
    AdvertiseInputs {
        mode: AdvertiseMode::Explicit,
        advertised_endpoints: vec![endpoint.to_owned()],
        ..AdvertiseInputs::default()
    }
}

fn now_unix() -> u64 {
    unix_ms() / 1000
}

/// One client pairing with the host over a fresh Unix socket, Wire v1 or v2.
#[allow(clippy::too_many_arguments)]
async fn pair_once(
    host: &EndpointIdentity,
    mgr: &Arc<Mutex<PairingManager>>,
    store: &StateStore,
    store_lock: &Arc<AsyncMutex<()>>,
    v2_state: &Arc<V2ResponderState>,
    code: String,
    tag: u8,
    v2: bool,
) {
    let sock_dir = tempdir().unwrap();
    let mut listener = LocalListener::bind(sock_dir.path().join("pair.sock")).unwrap();
    let ep = listener.local_endpoint();
    let responder = {
        let (host, mgr, store, lock, state) = (
            host.clone(),
            Arc::clone(mgr),
            store.clone(),
            Arc::clone(store_lock),
            Arc::clone(v2_state),
        );
        tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            if v2 {
                drive_v2_pake_pair_responder_with_store(
                    s.as_mut(),
                    &host,
                    &mgr,
                    &store,
                    &lock,
                    PairingPathKind::Remote,
                    now_unix(),
                    &state,
                    None,
                    None,
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                .map(|r| r.sas)
            } else {
                drive_pair_responder_with_store(
                    s.as_mut(),
                    &host,
                    &mgr,
                    &store,
                    &lock,
                    PairingPathKind::Remote,
                    now_unix(),
                    EnrollmentPolicy::default(),
                    None,
                    None,
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                .map(|r| r.sas)
            }
        })
    };
    let cli = identity(tag);
    let cli_dir = tempdir().unwrap();
    let cli_store = StateStore::open_or_create(cli_dir.path()).unwrap();
    let mut stream = LocalDialer::new().dial(&ep).await.unwrap();
    let init_sas = if v2 {
        drive_v2_pake_pair_initiator_with_store(
            stream.as_mut(),
            &cli,
            format!("Client {tag}"),
            "cli".to_owned(),
            code,
            None,
            "Host".to_owned(),
            vec![],
            &cli_store,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .unwrap()
        .sas
    } else {
        drive_pair_initiator_with_store(
            stream.as_mut(),
            &cli,
            format!("Client {tag}"),
            "cli".to_owned(),
            code,
            None,
            &cli_store,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .unwrap()
        .sas
    };
    responder.await.unwrap().expect("responder completes");
    assert!(init_sas.is_some(), "initiator completes with a SAS");
}

async fn scenario() -> usize {
    let host = identity(0x11).with_host_id("host-lock-order");
    let dir = tempdir().unwrap();
    let store = StateStore::open_or_create(dir.path()).unwrap();
    let access = RosterAccess::from_store(Arc::new(store.clone())).unwrap();
    let ann = Arc::new(RouteAnnouncer::new(
        host.clone(),
        access,
        inputs("192.168.7.1:9100"),
        AddressSource::Native,
    ));
    let mgr = Arc::new(Mutex::new(PairingManager::new(PairingConfig::default())));
    let store_lock = Arc::new(AsyncMutex::new(()));
    let v2_state = Arc::new(V2ResponderState::new());

    let mut codes: Vec<String> = (0..2 * PAIRINGS_PER_WIRE)
        .map(|_| {
            mgr.lock()
                .unwrap()
                .issue_code(PairingCodeKind::Remote3Group, now_unix())
                .unwrap()
        })
        .collect();

    let stop = Arc::new(AtomicBool::new(false));
    let issued = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let issuer = {
        let (ann, mgr, stop, issued, attempts) = (
            Arc::clone(&ann),
            Arc::clone(&mgr),
            Arc::clone(&stop),
            Arc::clone(&issued),
            Arc::clone(&attempts),
        );
        std::thread::spawn(move || {
            let mut flip = false;
            while !stop.load(Ordering::Acquire) {
                // Alternating endpoints make every publish a roster update.
                flip = !flip;
                ann.set_inputs(inputs(if flip {
                    "192.168.7.1:9100"
                } else {
                    "192.168.7.2:9100"
                }));
                // Every live code slot may be taken: the refusal still runs the publish.
                match ann.issue_pairing_uri(&mgr, "Studio", IssueOptions::default(), unix_ms()) {
                    Ok(_) => {
                        issued.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(RuntimeError::Core(CoreError::ProtocolViolation(
                        "too many live pairing codes",
                    ))) => {}
                    Err(err) => panic!("issue: {err}"),
                }
                attempts.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    for i in 0..PAIRINGS_PER_WIRE {
        for (tag, v2) in [(0x40 + i, false), (0x60 + i, true)] {
            let code = codes.pop().unwrap();
            pair_once(&host, &mgr, &store, &store_lock, &v2_state, code, tag, v2).await;
        }
    }
    stop.store(true, Ordering::Release);
    issuer.join().unwrap();
    let roster = store.load_roster().unwrap();
    assert_eq!(roster.entries().count(), 2 * usize::from(PAIRINGS_PER_WIRE));
    assert!(
        issued.load(Ordering::Relaxed) > 0,
        "burned codes free slots for URIs"
    );
    attempts.load(Ordering::Relaxed)
}

#[test]
fn issuing_uris_during_v1_and_v2_pairing_on_a_store_backed_host_completes() {
    let (tx, rx) = std::sync::mpsc::channel();
    // A deadlock leaves this thread blocked; the test fails on the timeout instead of hanging.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let _ = tx.send(rt.block_on(scenario()));
    });
    let attempts = rx
        .recv_timeout(Duration::from_secs(120))
        .expect("pairing and URI issuance finish without a lock-order deadlock");
    assert!(attempts > 0, "the issuer ran during the pairings");
}
