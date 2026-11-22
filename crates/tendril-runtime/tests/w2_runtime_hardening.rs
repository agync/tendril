//! Regression tests for the wave 2 runtime audit fixes (inbound router recovery, PAKE lock
//! scope, revocation persistence, and wire-floor preflight).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tempfile::tempdir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::identity::{EndpointIdentity, sign_rotation};
use tendril_core::pairing::{PairingCodeKind, PairingConfig, PairingManager, PairingPathKind};
use tendril_core::policy::{CandidateEndpoint, PathPolicyConfig, ProviderId};
use tendril_core::roster::{PeerState, Roster, V2PeerSecrets};
use tendril_core::wire::{Intent, Preamble};
use tendril_runtime::{
    DirectDialer, DirectListener, InboundRouter, LocalDialer, LocalListener, PathDialer,
    PathListener, PathStream, PreAuthConfig, RuntimeError, SessionDriver, StateStore,
    V2ResponderConfig, V2ResponderState, V2SessionDriver, drive_v2_pake_pair_initiator,
    drive_v2_pake_pair_responder,
};
use tokio::sync::Mutex as AsyncMutex;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct FlakyListener {
    inner: DirectListener,
    failures: usize,
}

#[async_trait]
impl PathListener for FlakyListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        if self.failures > 0 {
            self.failures -= 1;
            return Err(RuntimeError::Io(std::io::Error::other("transient accept")));
        }
        self.inner.accept().await
    }

    fn local_endpoint(&self) -> String {
        self.inner.local_endpoint()
    }
}

#[tokio::test]
async fn sec02_transient_accept_errors_do_not_kill_the_router_listener() {
    let inner = DirectListener::bind("127.0.0.1:0".parse().expect("addr"), None)
        .await
        .expect("bind");
    let ep = inner.local_endpoint();
    let router = InboundRouter::new();
    router.spawn_listener(
        &tokio::runtime::Handle::current(),
        Box::new(FlakyListener { inner, failures: 3 }),
    );

    let mut conn = DirectDialer::new().dial(&ep).await.expect("dial");
    conn.send_chunk(&Preamble::v1(Intent::Session).encode())
        .await
        .expect("send preamble");
    let routed = router
        .recv_session(Duration::from_secs(5))
        .await
        .expect("router stayed alive")
        .expect("session stream routed after transient accept errors");
    drop(routed);
    router.close();
}

#[tokio::test]
async fn sec02_single_source_is_capped_at_max_half_open_per_key() {
    let cfg = PreAuthConfig {
        max_entries: 64,
        max_half_open: 16,
        untrusted_max_half_open: 16,
        ip_burst: 64,
        ip_refill_per_sec: 64,
        peer_burst: 64,
        peer_refill_per_sec: 64,
        max_half_open_per_key: 2,
        ..PreAuthConfig::default()
    };
    let listener = DirectListener::bind("127.0.0.1:0".parse().expect("addr"), None)
        .await
        .expect("bind");
    let ep = listener.local_endpoint();
    let router = InboundRouter::with_config_and_ttl(cfg, Duration::from_secs(30));
    router.spawn_listener(&tokio::runtime::Handle::current(), Box::new(listener));

    let dialer = DirectDialer::new();
    let mut held = Vec::new();
    for _ in 0..6 {
        let mut s = dialer.dial(&ep).await.expect("dial");
        s.send_chunk(&Preamble::v1(Intent::Session).encode())
            .await
            .expect("send preamble");
        held.push(s);
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        router.session_rate_limiter().active_half_open(),
        2,
        "one source must never hold more than max_half_open_per_key queued guards"
    );
    router.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec05_concurrent_pake_msg1_never_hold_the_pairing_manager_lock() {
    const CONCURRENT: usize = 4;
    let now_unix = now_unix_secs();
    let host_id = EndpointIdentity::generate()
        .expect("host")
        .with_host_id("host-sec05");
    let mut mgr = PairingManager::new(PairingConfig::default());
    let codes: Vec<String> = (0..CONCURRENT)
        .map(|_| {
            mgr.issue_code(PairingCodeKind::Remote3Group, now_unix)
                .expect("issue code")
        })
        .collect();
    let mgr = Arc::new(Mutex::new(mgr));
    let roster = Arc::new(Mutex::new(Roster::new()));
    let state = Arc::new(V2ResponderState::with_config(V2ResponderConfig {
        max_concurrent_argon2: CONCURRENT,
        argon2_acquire_timeout: Duration::from_millis(250),
        ..V2ResponderConfig::default()
    }));
    let dir = tempdir().expect("tempdir");

    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let mgr = Arc::clone(&mgr);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let mut worst = Duration::ZERO;
            while !done.load(std::sync::atomic::Ordering::Acquire) {
                let started = Instant::now();
                loop {
                    match mgr.try_lock() {
                        Ok(guard) => {
                            drop(guard);
                            break;
                        }
                        Err(std::sync::TryLockError::WouldBlock) => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(std::sync::TryLockError::Poisoned(_)) => return worst,
                    }
                }
                worst = worst.max(started.elapsed());
                std::thread::sleep(Duration::from_millis(2));
            }
            worst
        })
    };

    let mut tasks = Vec::new();
    for (i, code) in codes.into_iter().enumerate() {
        let sock = dir.path().join(format!("p{i}.sock"));
        let mut listener = LocalListener::bind(&sock).expect("bind");
        let ep = listener.local_endpoint();
        let (host, mgr, roster, state) = (
            host_id.clone(),
            Arc::clone(&mgr),
            Arc::clone(&roster),
            Arc::clone(&state),
        );
        let responder = tokio::spawn(async move {
            let mut s = listener.accept().await.expect("accept");
            drive_v2_pake_pair_responder(
                s.as_mut(),
                &host,
                &mgr,
                &roster,
                PairingPathKind::Remote,
                now_unix,
                &state,
                None,
            )
            .await
        });
        let initiator = tokio::spawn(async move {
            let cli = EndpointIdentity::generate().expect("cli");
            let mut s = LocalDialer::new().dial(&ep).await.expect("dial");
            drive_v2_pake_pair_initiator(
                s.as_mut(),
                &cli,
                "Cli".to_owned(),
                "cli".to_owned(),
                code,
                None,
            )
            .await
        });
        tasks.push((responder, initiator));
    }
    for (responder, initiator) in tasks {
        responder
            .await
            .expect("responder join")
            .expect("responder not rate limited");
        initiator
            .await
            .expect("initiator join")
            .expect("initiator pairs");
    }
    done.store(true, std::sync::atomic::Ordering::Release);
    let worst = sampler.join().expect("sampler");
    assert!(
        worst < Duration::from_millis(150),
        "PairingManager lock was contended for {worst:?} while Argon2id ran"
    );
}

fn fork_roster_entry(roster: &mut Roster, id: &str) -> (SigningKeypair, [u8; 32]) {
    let static_pub = *StaticKeypair::from_scalar([0x31; 32]).public_bytes();
    let signing = SigningKeypair::from_seed([0x32; 32]);
    roster
        .insert_pinned_host(
            id.to_owned(),
            "Fork Host".to_owned(),
            static_pub,
            Some(signing.public_key().clone()),
            0,
            vec![],
        )
        .expect("pin host");
    (signing, static_pub)
}

#[tokio::test]
async fn sec03_fork_revocation_is_persisted_despite_transactional_rollback() {
    let dir = tempdir().expect("tempdir");
    let store = StateStore::open_or_create(dir.path()).expect("store");
    let secrets = V2PeerSecrets::new([0x61; 32], [0x62; 32]);
    let signing = store
        .update_roster(|rst| {
            let (signing, _) = fork_roster_entry(rst, "fork-host");
            rst.upgrade_peer_to_v2("fork-host", secrets.clone())?;
            Ok(signing)
        })
        .expect("seed roster");

    let next_stat_1 = *StaticKeypair::from_scalar([0x41; 32]).public_bytes();
    let next_sig_1 = SigningKeypair::from_seed([0x42; 32]).public_key().clone();
    let next_stat_2 = *StaticKeypair::from_scalar([0x51; 32]).public_bytes();
    let next_sig_2 = SigningKeypair::from_seed([0x52; 32]).public_key().clone();
    let rec1 = sign_rotation(1, &signing, &next_sig_1, &next_stat_1, 1_795_133_000).unwrap();
    let rec2 = sign_rotation(1, &signing, &next_sig_2, &next_stat_2, 1_795_133_001).unwrap();

    let err = store
        .update_roster_persisting_revocations(|rst| {
            rst.apply_verified_rotation("fork-host", &[rec1, rec2], &next_stat_1, &next_sig_1)
                .map_err(RuntimeError::from)?;
            Ok(())
        })
        .expect_err("fork must fail the update");
    assert!(matches!(
        err,
        RuntimeError::Core(CoreError::RotationForkDetected { .. })
    ));
    let reloaded = store.load_roster().expect("reload");
    let entry = reloaded.get("fork-host").expect("entry");
    assert_eq!(entry.state, PeerState::Revoked);
    assert!(entry.v2_secrets.is_none());

    // Plain update_roster still rolls back everything on error.
    let dir2 = tempdir().expect("tempdir");
    let store2 = StateStore::open_or_create(dir2.path()).expect("store2");
    store2
        .update_roster(|rst| {
            fork_roster_entry(rst, "plain");
            Ok(())
        })
        .expect("seed");
    let _ = store2.update_roster(|rst| -> Result<(), RuntimeError> {
        rst.revoke_peer("plain")?;
        Err(RuntimeError::Closed)
    });
    assert_eq!(
        store2.load_roster().unwrap().get("plain").unwrap().state,
        PeerState::Active
    );

    // A persisted revocation rejects every later reconnect.
    let sock_dir = tempdir().expect("tempdir");
    let sock = sock_dir.path().join("fork.sock");
    let mut listener = LocalListener::bind(&sock).expect("bind");
    let ep = listener.local_endpoint();
    let accept = tokio::spawn(async move { listener.accept().await });
    let stream = LocalDialer::new().dial(&ep).await.expect("dial");
    let id = EndpointIdentity::generate().expect("id");
    let lock = AsyncMutex::new(());
    let reconnect = V2SessionDriver::connect_with_store(
        stream,
        &id,
        "fork-host",
        None,
        &store,
        &lock,
        now_unix_secs(),
    )
    .await;
    assert!(reconnect.is_err(), "revoked peer must not reconnect");
    drop(accept);
}

#[tokio::test]
async fn sec03_accept_side_store_persists_revocations_on_error_paths() {
    let dir = tempdir().expect("tempdir");
    let store = StateStore::open_or_create(dir.path()).expect("store");
    store
        .update_roster(|rst| {
            fork_roster_entry(rst, "peer-a");
            Ok(())
        })
        .expect("seed");
    let res: Result<(), RuntimeError> = store.update_roster_persisting_revocations(|rst| {
        rst.revoke_peer("peer-a")?;
        Err(RuntimeError::Closed)
    });
    assert!(matches!(res, Err(RuntimeError::Closed)));
    assert_eq!(
        store.load_roster().unwrap().get("peer-a").unwrap().state,
        PeerState::Revoked
    );
}

#[tokio::test]
async fn priv04_v1_connect_writes_no_bytes_when_peer_floor_exceeds_wire_v1() {
    let host = EndpointIdentity::generate().expect("host");
    let cli = EndpointIdentity::generate().expect("cli");
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.host_id().to_owned(),
            "Host".to_owned(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            vec![],
        )
        .expect("pin");
    roster
        .set_peer_min_wire_version(host.host_id(), 2)
        .expect("floor");

    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("v1.sock");
    let mut listener = LocalListener::bind(&sock).expect("bind");
    let ep = listener.local_endpoint();
    let dial = LocalDialer::new().dial(&ep).await.expect("dial");
    let mut server = listener.accept().await.expect("accept");

    let err = match SessionDriver::connect(
        dial,
        &cli,
        host.host_id(),
        None,
        &mut roster,
        now_unix_secs(),
    )
    .await
    {
        Ok(_) => panic!("downgrade must fail closed"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        RuntimeError::Core(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1,
        })
    ));
    let mut buf = [0u8; 64];
    let n = server.recv_chunk(&mut buf).await.expect("recv");
    assert_eq!(n, 0, "no v1 preamble or msg1 may reach the peer");
}

struct CountingDialer(Arc<AtomicUsize>);

#[async_trait]
impl PathDialer for CountingDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    async fn dial(&self, _endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(RuntimeError::Closed)
    }
}

#[tokio::test]
async fn priv04_connect_with_policy_checks_wire_floor_before_dialing() {
    let host = EndpointIdentity::generate().expect("host");
    let cli = Arc::new(EndpointIdentity::generate().expect("cli"));
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.host_id().to_owned(),
            "Host".to_owned(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            vec![],
        )
        .expect("pin");
    roster
        .set_peer_min_wire_version(host.host_id(), 2)
        .expect("floor");

    let dials = Arc::new(AtomicUsize::new(0));
    let dialers: Vec<Arc<dyn PathDialer>> = vec![Arc::new(CountingDialer(Arc::clone(&dials)))];
    let res = SessionDriver::connect_with_policy(
        &dialers,
        PathPolicyConfig::default(),
        vec![CandidateEndpoint::new(1, ProviderId::Direct, "127.0.0.1:9")],
        cli,
        host.host_id(),
        None,
        &mut roster,
        now_unix_secs(),
    )
    .await;
    assert!(matches!(
        res,
        Err(RuntimeError::Core(CoreError::VersionDowngrade { .. }))
    ));
    assert_eq!(
        dials.load(Ordering::SeqCst),
        0,
        "no transport may be dialed"
    );
}
