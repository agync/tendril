use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tempfile::TempDir;
use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::grants::AuditEvent;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    PairOutcome, PairingCodeKind, PairingConfig, PairingManager, PairingPathKind,
};
use tendril_core::policy::{CandidateEndpoint, PathPolicyConfig, ProviderId};
use tendril_core::roster::{PeerState, Roster};
use tendril_core::wire::ResumableFrameReader;
use tendril_relay::{RelayConfig, RelayHandle, RelayServer};
use tendril_runtime::{
    DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, LocalDialer, LocalListener,
    MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathStream, PreAuthConfig, PreAuthRateLimiter,
    RelayDialer, RelayListener, RuntimeError, SessionDriver, SessionEvent, StateStore,
    dial_with_policy, drive_pair_initiator, drive_pair_responder, recv_tendril_frame,
    send_tendril_frame,
};
use tokio::time::timeout;

struct ProviderPair {
    listener: Box<dyn PathListener>,
    dialer: Box<dyn PathDialer>,
    endpoint: String,
    _tmp: Option<TempDir>,
    _relay: Option<RelayHandle>,
}

async fn setup_provider(provider: ProviderId) -> ProviderPair {
    match provider {
        ProviderId::Local => {
            let tmp = TempDir::new().expect("tempdir");
            let sock = tmp.path().join("tendril.sock");
            let listener = LocalListener::bind(&sock).expect("bind local");
            let endpoint = listener.local_endpoint();
            ProviderPair {
                listener: Box::new(listener),
                dialer: Box::new(LocalDialer::new()),
                endpoint,
                _tmp: Some(tmp),
                _relay: None,
            }
        }
        ProviderId::Direct => {
            let listener = DirectListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)), None)
                .await
                .expect("bind direct");
            let endpoint = listener.local_endpoint();
            ProviderPair {
                listener: Box::new(listener),
                dialer: Box::new(DirectDialer::new()),
                endpoint,
                _tmp: None,
                _relay: None,
            }
        }
        ProviderId::Relay => {
            let server = RelayServer::bind(RelayConfig::default())
                .await
                .expect("bind relay server");
            let handle = server.spawn();
            let key = SigningKeypair::generate().expect("signing key");
            let listener = RelayListener::bind(
                handle.ws_url(),
                Some("localhost".to_owned()),
                key.signing_key(),
                DEFAULT_WRITE_TIMEOUT,
            )
            .await
            .expect("bind relay listener");
            let endpoint = listener.local_endpoint();
            ProviderPair {
                listener: Box::new(listener),
                dialer: Box::new(RelayDialer::new().with_expected_host("localhost")),
                endpoint,
                _tmp: None,
                _relay: Some(handle),
            }
        }
        other => panic!("unsupported provider in Phase 2 contract: {other:?}"),
    }
}

async fn open_pair(pair: &mut ProviderPair) -> (Box<dyn PathStream>, Box<dyn PathStream>) {
    let ep = pair.endpoint.clone();
    let (acc, dial) = tokio::join!(pair.listener.accept(), pair.dialer.dial(&ep));
    (acc.expect("accept stream"), dial.expect("dial stream"))
}

struct WireTapStream {
    inner: Box<dyn PathStream>,
    recorded: Arc<Mutex<Vec<u8>>>,
}

#[async_trait]
impl PathStream for WireTapStream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.inner.peer_ip()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.recorded.lock().expect("lock").extend_from_slice(bytes);
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        let n = self.inner.recv_chunk(buf).await?;
        if n > 0 {
            self.recorded
                .lock()
                .expect("lock")
                .extend_from_slice(&buf[..n]);
        }
        Ok(n)
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }
}

async fn run_six_point_contract(provider: ProviderId) {
    let mut pair = setup_provider(provider).await;

    // 1. 1 B and MAX_FRAME_LEN (65519 B) round-trip intact.
    {
        let (mut srv, mut cli) = open_pair(&mut pair).await;
        let mut srv_reader = ResumableFrameReader::new();
        let mut cli_reader = ResumableFrameReader::new();

        send_tendril_frame(cli.as_mut(), &[0x5A])
            .await
            .expect("send 1B");
        assert_eq!(
            recv_tendril_frame(srv.as_mut(), &mut srv_reader)
                .await
                .expect("recv 1B"),
            vec![0x5A]
        );

        let max_payload: Vec<u8> = (0..MAX_FRAME_LEN).map(|i| (i % 251) as u8).collect();
        let send_fut = send_tendril_frame(srv.as_mut(), &max_payload);
        let recv_fut = recv_tendril_frame(cli.as_mut(), &mut cli_reader);
        let (s_res, r_res) = tokio::join!(send_fut, recv_fut);
        s_res.expect("send max");
        assert_eq!(r_res.expect("recv max"), max_payload);
    }

    // 2. 64-frame strict FIFO ordering.
    {
        let (mut srv, mut cli) = open_pair(&mut pair).await;
        let mut srv_reader = ResumableFrameReader::new();
        let sender = tokio::spawn(async move {
            for seq in 0u8..64 {
                let mut payload = vec![seq; 256];
                payload[0] = seq;
                payload[255] = seq.wrapping_mul(3);
                send_tendril_frame(cli.as_mut(), &payload)
                    .await
                    .expect("send fifo");
            }
            cli
        });
        for seq in 0u8..64 {
            let got = recv_tendril_frame(srv.as_mut(), &mut srv_reader)
                .await
                .expect("recv fifo");
            assert_eq!(got.len(), 256);
            assert_eq!(got[0], seq);
            assert_eq!(got[255], seq.wrapping_mul(3));
        }
        let _ = sender.await.expect("sender finished");
    }

    // 3. Peer close detection <= 2 s.
    {
        let (mut srv, mut cli) = open_pair(&mut pair).await;
        cli.close().await.expect("close cli");
        drop(cli);
        let mut buf = vec![0u8; 1024];
        let res = timeout(Duration::from_secs(2), srv.recv_chunk(&mut buf))
            .await
            .expect("peer close must arrive within 2s");
        match res {
            Ok(0)
            | Err(RuntimeError::Closed)
            | Err(RuntimeError::Io(_))
            | Err(RuntimeError::Protocol(_)) => {}
            other => panic!("unexpected recv after peer close on {provider:?}: {other:?}"),
        }
    }

    // 4. Slow-reader write backpressure timeout terminates writes without hanging.
    {
        let (srv, mut cli) = open_pair(&mut pair).await;
        let payload = vec![0xCDu8; MAX_FRAME_LEN];
        let started = Instant::now();
        let mut hit_backpressure = false;
        let _hold_srv = srv;
        for _ in 0..512 {
            match timeout(
                Duration::from_secs(5),
                send_tendril_frame(cli.as_mut(), &payload),
            )
            .await
            {
                Ok(Ok(())) => continue,
                Ok(Err(_)) | Err(_) => {
                    hit_backpressure = true;
                    break;
                }
            }
        }
        assert!(
            hit_backpressure,
            "slow reader must trigger bounded write failure on {provider:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(12));
    }

    // 5. Oversized frame body (65520 B) and oversize raw chunk (65522 B) rejected cleanly.
    {
        let (_srv, mut cli) = open_pair(&mut pair).await;
        let oversize_body = vec![0x11u8; MAX_FRAME_LEN + 1];
        assert!(
            send_tendril_frame(cli.as_mut(), &oversize_body)
                .await
                .is_err()
        );

        let oversize_chunk = vec![0x22u8; MAX_OUTER_FRAME_LEN + 1];
        assert!(matches!(
            cli.send_chunk(&oversize_chunk).await,
            Err(RuntimeError::FrameTooLarge { .. })
        ));
    }

    // 6. Wire-tap canary check inside real Noise XX session.
    {
        let (srv, cli) = open_pair(&mut pair).await;
        let tapped_wire = Arc::new(Mutex::new(Vec::<u8>::new()));
        let tapped_cli: Box<dyn PathStream> = Box::new(WireTapStream {
            inner: cli,
            recorded: Arc::clone(&tapped_wire),
        });

        let host_id_ent = EndpointIdentity::generate().expect("host id");
        let cli_id_ent = EndpointIdentity::generate().expect("cli id");

        let mut host_roster = Roster::new();
        let host_for_cli = EndpointIdentity::from_persisted(
            host_id_ent.host_id().to_owned(),
            StaticKeypair::from_scalar(*host_id_ent.static_key().secret_bytes()),
            SigningKeypair::from_seed(*host_id_ent.signing_key().seed_bytes()),
            Vec::new(),
            0,
        )
        .expect("clone id");
        host_roster
            .insert_pinned_host(
                cli_id_ent.device_id(),
                "client".to_owned(),
                *cli_id_ent.static_key().public_bytes(),
                Some(*cli_id_ent.signing_key().public_bytes()),
                0,
                Vec::new(),
            )
            .expect("pin client on host");

        let mut cli_roster = Roster::new();
        cli_roster
            .insert_pinned_host(
                host_for_cli.host_id().to_owned(),
                "host".to_owned(),
                *host_for_cli.static_key().public_bytes(),
                Some(*host_for_cli.signing_key().public_bytes()),
                0,
                Vec::new(),
            )
            .expect("pin host on client");

        let now = 1_795_132_800;
        let target_host = host_for_cli.host_id().to_owned();
        let (acc_res, conn_res) = tokio::join!(
            SessionDriver::accept(srv, &host_id_ent, &mut host_roster, now, None),
            SessionDriver::connect(
                tapped_cli,
                &cli_id_ent,
                &target_host,
                None,
                &mut cli_roster,
                now
            )
        );
        let mut host_sess = acc_res.expect("host accept session");
        let mut cli_sess = conn_res.expect("cli connect session");

        let canary = b"TENDRIL_SECRET_CANARY_982341";
        cli_sess.send_data(canary).await.expect("send canary");
        let ev = host_sess
            .next_event(now, &mut host_roster)
            .await
            .expect("next event")
            .expect("some event");
        assert_eq!(ev, SessionEvent::AppData(canary.to_vec()));

        let wire = tapped_wire.lock().expect("lock");
        assert!(
            !wire.windows(canary.len()).any(|w| w == canary),
            "plaintext canary leaked on wire for {provider:?}"
        );
    }

    if let Some(relay) = pair._relay.take() {
        relay.stop().await.expect("stop relay");
    }
}

#[tokio::test]
async fn six_point_provider_contract_local() {
    run_six_point_contract(ProviderId::Local).await;
}

#[tokio::test]
async fn six_point_provider_contract_direct() {
    run_six_point_contract(ProviderId::Direct).await;
}

#[tokio::test]
async fn six_point_provider_contract_relay() {
    run_six_point_contract(ProviderId::Relay).await;
}

#[tokio::test]
async fn pre_auth_rate_limiter_enforces_half_open_cap_32_and_ip_burst() {
    let limiter = PreAuthRateLimiter::new(PreAuthConfig {
        max_entries: 4,
        max_half_open: 32,
        ip_burst: 40,
        ip_refill_per_sec: 1,
        peer_burst: 3,
        peer_refill_per_sec: 1,
    });
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mut guards = Vec::new();
    for _ in 0..32 {
        guards.push(limiter.try_acquire(Some(ip)).expect("acquire slot"));
    }
    assert_eq!(limiter.active_half_open(), 32);
    assert!(matches!(
        limiter.try_acquire(Some(ip)),
        Err(RuntimeError::RateLimited(_))
    ));
    drop(guards.pop());
    assert_eq!(limiter.active_half_open(), 31);
    guards.push(
        limiter
            .try_acquire(Some(ip))
            .expect("re-acquire after drop"),
    );

    // Peer rate limit exhausts after burst = 3.
    assert!(limiter.check_peer("peer-a").is_ok());
    assert!(limiter.check_peer("peer-a").is_ok());
    assert!(limiter.check_peer("peer-a").is_ok());
    assert!(matches!(
        limiter.check_peer("peer-a"),
        Err(RuntimeError::RateLimited(_))
    ));
}

#[test]
fn state_store_sets_permissions_and_preserves_rotated_identity() {
    let tmp = TempDir::new().expect("tempdir");
    let store_dir = tmp.path().join("state");
    let store = StateStore::open_or_create(&store_dir).expect("open store");
    let mut identity = store
        .load_or_generate_identity(Some("host-abc"))
        .expect("generate identity");
    identity
        .rotate(
            StaticKeypair::from_scalar([0x41; 32]),
            SigningKeypair::from_seed([0x42; 32]),
            1_795_132_800,
        )
        .expect("rotate");
    store.save_identity(&identity).expect("save rotated");

    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            "peer-1".to_owned(),
            "phone".to_owned(),
            [0x51; 32],
            Some([0x52; 32]),
            0,
            vec!["wss://relay.example/v1/relay".to_owned()],
        )
        .expect("insert peer");
    store.save_roster(&roster).expect("save roster");

    #[cfg(unix)]
    {
        let dir_mode = std::fs::metadata(&store_dir)
            .expect("dir meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        let id_mode = std::fs::metadata(store.identity_path())
            .expect("id meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(id_mode, 0o600);
        let roster_mode = std::fs::metadata(store.roster_path())
            .expect("roster meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(roster_mode, 0o600);
    }

    let reloaded_id = store.load_identity().expect("reload identity");
    assert_eq!(reloaded_id.host_id(), "host-abc");
    assert_eq!(reloaded_id.rotation_seq(), 1);
    assert_eq!(reloaded_id.rotation_chain().len(), 1);

    let reloaded_roster = store.load_roster().expect("reload roster");
    assert_eq!(
        reloaded_roster.get("peer-1").map(|p| p.state),
        Some(PeerState::Active)
    );
}

#[tokio::test]
async fn dial_with_policy_fails_over_from_unreachable_direct_to_live_relay() {
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let relay_handle = server.spawn();
    let key = SigningKeypair::generate().expect("key");
    let mut relay_listener = RelayListener::bind(
        relay_handle.ws_url(),
        Some("localhost".to_owned()),
        key.signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .expect("bind relay listener");

    // Pick a bound port then drop listener so TCP dial fails immediately (connection refused).
    let dead_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind dead port");
    let dead_addr = dead_listener.local_addr().expect("dead addr");
    drop(dead_listener);

    let dialers: Vec<Arc<dyn PathDialer>> = vec![
        Arc::new(DirectDialer::new()),
        Arc::new(RelayDialer::new().with_expected_host("localhost")),
    ];
    let candidates = vec![
        CandidateEndpoint::new(1, ProviderId::Direct, dead_addr.to_string()),
        CandidateEndpoint::new(2, ProviderId::Relay, relay_listener.local_endpoint()),
    ];

    let accept_task = tokio::spawn(async move { relay_listener.accept().await.expect("accept") });
    let (winner, mut cli_stream) =
        dial_with_policy(&dialers, PathPolicyConfig::default(), candidates)
            .await
            .expect("dial with policy failover");
    assert_eq!(winner.provider, ProviderId::Relay);
    let mut srv_stream = accept_task.await.expect("join accept");

    let mut reader = ResumableFrameReader::new();
    send_tendril_frame(cli_stream.as_mut(), b"failover-ok")
        .await
        .expect("send");
    assert_eq!(
        recv_tendril_frame(srv_stream.as_mut(), &mut reader)
            .await
            .expect("recv"),
        b"failover-ok"
    );

    relay_handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn full_lifecycle_pair_confirm_mint_connect_authorize_data_rekey_revoke_across_providers() {
    for provider in [ProviderId::Local, ProviderId::Direct, ProviderId::Relay] {
        let mut pair = setup_provider(provider).await;
        let now = 1_795_132_800;

        let host_id = EndpointIdentity::generate().expect("host identity");
        let client_id = EndpointIdentity::generate().expect("client identity");

        let manager = Mutex::new(PairingManager::new(PairingConfig::default()));
        let code = manager
            .lock()
            .expect("lock")
            .issue_code(PairingCodeKind::Remote3Group, now)
            .expect("issue code");
        let host_roster_sync = Mutex::new(Roster::new());
        let mut client_roster = Roster::new();

        // Step 1: Pair over transport.
        let (srv_pair, mut cli_pair) = open_pair(&mut pair).await;
        let (srv_res, cli_res) = tokio::join!(
            async {
                let mut srv_s = srv_pair;
                drive_pair_responder(
                    srv_s.as_mut(),
                    &host_id,
                    &manager,
                    &host_roster_sync,
                    PairingPathKind::Remote,
                    now,
                    None,
                )
                .await
            },
            drive_pair_initiator(
                cli_pair.as_mut(),
                &client_id,
                "laptop".to_owned(),
                "cli".to_owned(),
                code,
                None,
            )
        );
        let srv_out = srv_res.expect("host pair").outcome;
        let cli_res_val = cli_res.expect("cli pair");
        let cli_sas = cli_res_val.sas.expect("client sas");
        let cli_out = cli_res_val.outcome;

        let PairOutcome::ResponderPending {
            device_id: peer_dev_id,
            pairing_sas: host_sas,
            ..
        } = srv_out
        else {
            panic!("expected ResponderPending: {srv_out:?}");
        };
        let PairOutcome::InitiatorPending {
            host_id: learned_host_id,
            host_static_pub,
            host_signing_pub,
            host_rotation_seq,
            pairing_sas: cli_out_sas,
            ..
        } = cli_out
        else {
            panic!("expected InitiatorPending: {cli_out:?}");
        };
        assert_eq!(host_sas, cli_sas);
        assert_eq!(host_sas, cli_out_sas);

        let mut host_roster = host_roster_sync.into_inner().expect("lock");
        // Step 2: Confirm (responder already recorded Pending into roster) and mint grant.
        host_roster
            .confirm_peer(&peer_dev_id, Some(&host_sas))
            .expect("confirm peer");
        let grant = host_roster
            .mint_grant(
                &host_id,
                &peer_dev_id,
                vec!["fs.read".to_owned()],
                now,
                now + 3600,
                [0x77; 16],
            )
            .expect("mint grant");

        client_roster
            .insert_pinned_host(
                learned_host_id.clone(),
                "workstation".to_owned(),
                host_static_pub,
                Some(host_signing_pub),
                host_rotation_seq,
                Vec::new(),
            )
            .expect("pin host");

        // Step 3: Session connect, authorize, data, rekey, revoke.
        let (srv_sess_stream, cli_sess_stream) = open_pair(&mut pair).await;
        let rate_limiter = PreAuthRateLimiter::new(PreAuthConfig::default());
        let (acc_sess, conn_sess) = tokio::join!(
            SessionDriver::accept(
                srv_sess_stream,
                &host_id,
                &mut host_roster,
                now,
                Some(&rate_limiter)
            ),
            SessionDriver::connect(
                cli_sess_stream,
                &client_id,
                &learned_host_id,
                Some(grant),
                &mut client_roster,
                now
            )
        );
        let mut host_sess = acc_sess.expect("host session accept");
        let mut cli_sess = conn_sess.expect("cli session connect");

        let (allow_res, allow_audit): (_, AuditEvent) =
            host_sess.authorize("fs.read", now, &host_roster);
        assert!(allow_res.is_ok());
        assert!(allow_audit.allow);
        let (deny_res, deny_audit) = host_sess.authorize("shell.exec", now, &host_roster);
        assert!(deny_res.is_err());
        assert!(!deny_audit.allow);

        cli_sess
            .send_data(b"ping-payload")
            .await
            .expect("send data");
        assert_eq!(
            host_sess
                .next_event(now, &mut host_roster)
                .await
                .expect("next"),
            Some(SessionEvent::AppData(b"ping-payload".to_vec()))
        );

        cli_sess.send_rekey().await.expect("send rekey");
        cli_sess
            .send_data(b"after-rekey")
            .await
            .expect("send after rekey");
        assert!(matches!(
            host_sess
                .next_event(now, &mut host_roster)
                .await
                .expect("rekey ev"),
            Some(SessionEvent::Rekeyed { .. })
        ));
        assert_eq!(
            host_sess
                .next_event(now, &mut host_roster)
                .await
                .expect("data ev"),
            Some(SessionEvent::AppData(b"after-rekey".to_vec()))
        );

        // Step 4: Revoke blocks authorize and tick, plus fails subsequent reconnects closed.
        host_roster.revoke_peer(&peer_dev_id).expect("revoke");
        let (rev_auth, _) = host_sess.authorize("fs.read", now, &host_roster);
        assert!(rev_auth.is_err());
        assert!(host_sess.tick(now, &host_roster).await.is_err());

        let (srv_fail, cli_fail) = open_pair(&mut pair).await;
        let (acc_rev, _conn_rev) = tokio::join!(
            SessionDriver::accept(srv_fail, &host_id, &mut host_roster, now, None),
            SessionDriver::connect(
                cli_fail,
                &client_id,
                &learned_host_id,
                None,
                &mut client_roster,
                now
            )
        );
        assert!(acc_rev.is_err());

        if let Some(relay) = pair._relay.take() {
            relay.stop().await.expect("stop relay");
        }
    }
}

#[tokio::test]
async fn pre_auth_slowloris_times_out_and_releases_half_open_slot() {
    use tendril_core::wire::{Intent, Preamble};
    use tendril_runtime::drive_pair_responder_with_options;

    let limiter = PreAuthRateLimiter::new(PreAuthConfig::default());
    let host_id = EndpointIdentity::generate().expect("host id");
    let now = 1_795_132_800;

    // 1. Stalled SessionDriver::accept_with_options releasing HalfOpenGuard cleanly.
    let mut pair = setup_provider(ProviderId::Direct).await;
    let (srv_sess, mut cli_sess) = open_pair(&mut pair).await;
    cli_sess
        .send_chunk(&Preamble::v1(Intent::Session).encode())
        .await
        .expect("send preamble only");
    let mut roster = Roster::new();
    let res = SessionDriver::accept_with_options(
        srv_sess,
        &host_id,
        &mut roster,
        now,
        Some(&limiter),
        None,
        Duration::from_millis(120),
    )
    .await;
    assert!(matches!(res, Err(RuntimeError::Timeout(_))));
    assert_eq!(limiter.active_half_open(), 0);
    drop(cli_sess);

    // 2. Stalled drive_pair_responder_with_options releasing HalfOpenGuard cleanly.
    let (mut srv_pair, mut cli_pair) = open_pair(&mut pair).await;
    cli_pair
        .send_chunk(&Preamble::v1(Intent::Pair).encode())
        .await
        .expect("send pair preamble only");
    let mgr = Mutex::new(PairingManager::new(PairingConfig::default()));
    let roster_sync = Mutex::new(Roster::new());
    let pair_res = drive_pair_responder_with_options(
        srv_pair.as_mut(),
        &host_id,
        &mgr,
        &roster_sync,
        PairingPathKind::Lan,
        now,
        Some(&limiter),
        None,
        Duration::from_millis(120),
    )
    .await;
    assert!(matches!(pair_res, Err(RuntimeError::Timeout(_))));
    assert_eq!(limiter.active_half_open(), 0);
}

#[tokio::test]
async fn relay_listener_verifies_url_host_even_when_expected_host_is_none() {
    // Server claims host = "localhost", URL connects to "ws://127.0.0.1:<port>/v1/relay".
    let srv_mismatch = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind mismatch relay");
    let h_mismatch = srv_mismatch.spawn();
    let key = SigningKeypair::generate().expect("key");
    let res = RelayListener::bind(
        h_mismatch.ws_url(),
        None,
        key.signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await;
    assert!(
        matches!(res, Err(RuntimeError::Protocol(_))),
        "expected host verification failure when challenge.host != URL host"
    );
    h_mismatch.stop().await.expect("stop");

    // Server whose host matches URL authority ("127.0.0.1") succeeds with expected_host = None.
    let srv_match = RelayServer::bind(RelayConfig {
        host: "127.0.0.1".to_owned(),
        ..RelayConfig::default()
    })
    .await
    .expect("bind matching relay");
    let h_match = srv_match.spawn();
    let listener = RelayListener::bind(
        h_match.ws_url(),
        None,
        key.signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .expect("matching URL host must succeed with None override");
    drop(listener);
    h_match.stop().await.expect("stop");
}

#[tokio::test]
async fn inbound_router_separates_pair_and_session_and_wakes_on_close() {
    use std::sync::Arc;
    use tendril_core::wire::{Intent, Preamble};
    use tendril_runtime::{DirectDialer, DirectListener, InboundRouter};

    let listener = DirectListener::bind("127.0.0.1:0".parse().expect("addr"), None)
        .await
        .expect("bind direct");
    let ep = listener.local_endpoint();
    let router = Arc::new(InboundRouter::new());
    router.spawn_listener(&tokio::runtime::Handle::current(), Box::new(listener));

    assert!(matches!(router.recv_pair(Duration::ZERO).await, Err(())));
    assert!(matches!(router.recv_session(Duration::ZERO).await, Err(())));

    let dialer = DirectDialer::new();
    let mut sess_conn = dialer.dial(&ep).await.expect("dial session first");
    sess_conn
        .send_chunk(&Preamble::v1(Intent::Session).encode())
        .await
        .expect("send session preamble");

    let mut pair_conn = dialer.dial(&ep).await.expect("dial pair second");
    pair_conn
        .send_chunk(&Preamble::v1(Intent::Pair).encode())
        .await
        .expect("send pair preamble");

    // recv_pair must receive the Pair stream even though Session arrived first.
    let (_pair_stream, _pair_guard) = router
        .recv_pair(Duration::from_secs(2))
        .await
        .expect("pair wait ok")
        .expect("pair stream");
    let (_sess_stream, _sess_guard) = router
        .recv_session(Duration::from_secs(2))
        .await
        .expect("session wait ok")
        .expect("session stream");

    // close() must wake a blocked waiter far before the long timeout elapses.
    let r2 = Arc::clone(&router);
    let waiter = tokio::spawn(async move { r2.recv_pair(Duration::from_secs(30)).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    router.close();
    let woke = tokio::time::timeout(Duration::from_millis(500), waiter)
        .await
        .expect("waiter must wake promptly on close")
        .expect("join");
    assert!(matches!(woke, Ok(None)));
}
