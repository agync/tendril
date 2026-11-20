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
    BrokerDialer, BrokerListener, BrokerServerConfig, DEFAULT_PRE_AUTH_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, EmbeddedRelay, LocalDialer, LocalListener,
    MAX_OUTER_FRAME_LEN, OverlayConfig, OverlayDialer, OverlayHelperDialer, OverlayHelperListener,
    OverlayListener, OverlayMode, OverlayResolvedMode, PathDialer, PathListener, PathStream,
    PreAuthConfig, PreAuthRateLimiter, RelayDialer, RelayListener, RuntimeError, SessionDriver,
    SessionEvent, StateStore, dial_with_policy, drive_pair_initiator, drive_pair_responder,
    drive_pair_responder_with_options, is_tailnet_ip, pairing_path_kind_for_provider,
    recv_tendril_frame, select_overlay_mode, send_tendril_frame,
};
#[cfg(feature = "p2p-iroh")]
use tendril_runtime::{P2pDialer, P2pListener, P2pRelayMode};
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
        ProviderId::Overlay => {
            let listener = OverlayListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)), None)
                .await
                .expect("bind overlay");
            let endpoint = listener.local_endpoint();
            ProviderPair {
                listener: Box::new(listener),
                dialer: Box::new(OverlayDialer::new()),
                endpoint,
                _tmp: None,
                _relay: None,
            }
        }
        #[cfg(feature = "p2p-iroh")]
        ProviderId::P2p => {
            let listener = P2pListener::bind(P2pRelayMode::Disabled)
                .await
                .expect("bind p2p");
            let dialer = P2pDialer::bind(P2pRelayMode::Disabled)
                .await
                .expect("bind p2p dialer");
            let endpoint = listener.local_endpoint();
            ProviderPair {
                listener: Box::new(listener),
                dialer: Box::new(dialer),
                endpoint,
                _tmp: None,
                _relay: None,
            }
        }
        #[cfg(not(feature = "p2p-iroh"))]
        ProviderId::P2p => panic!("p2p requires p2p-iroh feature"),
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
        ProviderId::Broker => {
            let listener = BrokerListener::bind(BrokerServerConfig {
                auth_header: Some(("authorization".to_owned(), "Bearer test-token".to_owned())),
                ..BrokerServerConfig::default()
            })
            .await
            .expect("bind broker");
            let endpoint = listener.local_endpoint();
            ProviderPair {
                listener: Box::new(listener),
                dialer: Box::new(
                    BrokerDialer::new().with_header("authorization", "Bearer test-token"),
                ),
                endpoint,
                _tmp: None,
                _relay: None,
            }
        }
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
async fn six_point_provider_contract_overlay() {
    run_six_point_contract(ProviderId::Overlay).await;
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn six_point_provider_contract_p2p() {
    run_six_point_contract(ProviderId::P2p).await;
}

#[tokio::test]
async fn six_point_provider_contract_broker() {
    run_six_point_contract(ProviderId::Broker).await;
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
    #[cfg(feature = "p2p-iroh")]
    let providers = [
        ProviderId::Local,
        ProviderId::Direct,
        ProviderId::Overlay,
        ProviderId::P2p,
        ProviderId::Relay,
        ProviderId::Broker,
    ];
    #[cfg(not(feature = "p2p-iroh"))]
    let providers = [
        ProviderId::Local,
        ProviderId::Direct,
        ProviderId::Overlay,
        ProviderId::Relay,
        ProviderId::Broker,
    ];
    for provider in providers {
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
            host_pin_verified,
            ..
        } = cli_out
        else {
            panic!("expected InitiatorPending: {cli_out:?}");
        };
        assert!(!host_pin_verified);
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
            .record_pending_host(
                learned_host_id.clone(),
                "workstation".to_owned(),
                host_static_pub,
                host_signing_pub,
                host_rotation_seq,
                cli_out_sas.clone(),
                Vec::new(),
            )
            .expect("record pending host");
        client_roster
            .confirm_peer(&learned_host_id, Some(&cli_out_sas))
            .expect("confirm host on client");

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

#[tokio::test]
async fn overlay_mode_selection_and_scoped_unix_helper_roundtrip() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    assert!(is_tailnet_ip("100.100.100.100".parse().expect("v4")));
    assert!(!is_tailnet_ip("192.168.1.10".parse().expect("lan")));
    assert!(is_tailnet_ip("fd7a:115c:a1e0::1".parse().expect("ts v6")));
    assert!(!is_tailnet_ip("fe80::1".parse().expect("ll")));

    let base_cfg = OverlayConfig::default();
    assert_eq!(
        select_overlay_mode(&base_cfg, false),
        OverlayResolvedMode::Unavailable
    );
    assert_eq!(
        select_overlay_mode(&base_cfg, true),
        OverlayResolvedMode::Host
    );

    let tmp = TempDir::new().expect("tempdir");
    let key_file = tmp.path().join("authkey");
    let missing_cred_cfg = OverlayConfig {
        mode: OverlayMode::Helper,
        helper_bin: Some(tmp.path().join("tendril-tsnet")),
        ..OverlayConfig::default()
    };
    assert_eq!(
        select_overlay_mode(&missing_cred_cfg, true),
        OverlayResolvedMode::Unavailable
    );
    let helper_cfg = OverlayConfig {
        mode: OverlayMode::Auto,
        helper_bin: Some(tmp.path().join("tendril-tsnet")),
        auth_key_file: Some(key_file),
        ..OverlayConfig::default()
    };
    assert_eq!(
        select_overlay_mode(&helper_cfg, true),
        OverlayResolvedMode::Helper
    );
    let disabled_cfg = OverlayConfig {
        mode: OverlayMode::Disabled,
        ..helper_cfg
    };
    assert_eq!(
        select_overlay_mode(&disabled_cfg, true),
        OverlayResolvedMode::Unavailable
    );

    let ipc_dir = tmp.path().join("tsnet-ipc");
    let listen_sock = ipc_dir.join("accept.sock");
    let dial_sock = ipc_dir.join("dial.sock");
    let mut overlay_listener =
        OverlayHelperListener::bind(&listen_sock).expect("bind helper accept");
    #[cfg(unix)]
    {
        let dir_mode = std::fs::metadata(&ipc_dir)
            .expect("dir meta")
            .permissions()
            .mode()
            & 0o777;
        let sock_mode = std::fs::metadata(&listen_sock)
            .expect("sock meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(sock_mode, 0o600);
    }

    let helper_dial_listener = UnixListener::bind(&dial_sock).expect("bind helper dial");
    let listen_sock_c = listen_sock.clone();
    tokio::spawn(async move {
        if let Ok((cli_ipc, _)) = helper_dial_listener.accept().await {
            let mut reader = BufReader::new(cli_ipc);
            let mut req_line = String::new();
            let _ = reader.read_line(&mut req_line).await;
            let mut cli_ipc = reader.into_inner();
            let mut srv_ipc = UnixStream::connect(&listen_sock_c)
                .await
                .expect("connect accept");
            srv_ipc
                .write_all(b"{\"op\":\"accept\",\"peer_ip\":\"100.64.0.10\"}\n")
                .await
                .expect("send accept");
            let mut ack_buf = [0u8; 64];
            let n = tokio::io::AsyncReadExt::read(&mut srv_ipc, &mut ack_buf)
                .await
                .expect("read ack");
            assert!(
                std::str::from_utf8(&ack_buf[..n])
                    .expect("utf8")
                    .contains("\"ok\":true")
            );
            cli_ipc
                .write_all(b"{\"ok\":true}\n")
                .await
                .expect("send dial ack");
            let _ = tokio::io::copy_bidirectional(&mut cli_ipc, &mut srv_ipc).await;
        }
    });

    let dialer = OverlayHelperDialer::new(&dial_sock);
    let (acc, dialed) = tokio::join!(
        overlay_listener.accept(),
        dialer.dial("overlay-helper://demo-host.ts.net:443")
    );
    let mut srv_stream = acc.expect("accept helper");
    let mut cli_stream = dialed.expect("dial helper");
    assert_eq!(srv_stream.provider_id(), ProviderId::Overlay);
    assert_eq!(cli_stream.provider_id(), ProviderId::Overlay);
    assert_eq!(
        srv_stream.peer_ip(),
        Some("100.64.0.10".parse().expect("ip"))
    );

    send_tendril_frame(cli_stream.as_mut(), b"hello-overlay-helper")
        .await
        .expect("send frame");
    let mut reader = ResumableFrameReader::new();
    let got = recv_tendril_frame(srv_stream.as_mut(), &mut reader)
        .await
        .expect("recv frame");
    assert_eq!(got, b"hello-overlay-helper");

    // Verify {"ok":false} helper rejection and oversized control line rejection.
    let err_sock = ipc_dir.join("err-dial.sock");
    let err_listener = UnixListener::bind(&err_sock).expect("bind err sock");
    tokio::spawn(async move {
        if let Ok((mut s, _)) = err_listener.accept().await {
            let mut reader = BufReader::new(&mut s);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            let _ = s.write_all(b"{\"ok\":false,\"error\":\"denied\"}\n").await;
        }
        if let Ok((mut s, _)) = err_listener.accept().await {
            let mut reader = BufReader::new(&mut s);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            let long_line = vec![b'x'; 2048];
            let _ = s.write_all(&long_line).await;
        }
    });
    let err_dialer = OverlayHelperDialer::new(&err_sock);
    assert!(matches!(
        err_dialer.dial("overlay-helper://x").await,
        Err(RuntimeError::Protocol(_))
    ));
    assert!(matches!(
        err_dialer.dial("overlay-helper://x").await,
        Err(RuntimeError::Protocol(_))
    ));
}

#[tokio::test]
async fn broker_rejects_wrong_path_and_invalid_auth_header() {
    use futures_util::SinkExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    let mut listener = BrokerListener::bind(BrokerServerConfig {
        path: "/custom/tunnel".to_owned(),
        auth_header: Some(("x-tendril-token".to_owned(), "secret-v1".to_owned())),
        ..BrokerServerConfig::default()
    })
    .await
    .expect("bind broker");
    let addr = listener.local_addr();

    let wrong_path = BrokerDialer::new()
        .with_header("x-tendril-token", "secret-v1")
        .dial(&format!("broker+ws://{addr}/wrong"))
        .await;
    assert!(matches!(wrong_path, Err(RuntimeError::Protocol(_))));

    let missing_auth = BrokerDialer::new()
        .dial(&format!("broker+ws://{addr}/custom/tunnel"))
        .await;
    assert!(matches!(missing_auth, Err(RuntimeError::Protocol(_))));

    let bad_auth = BrokerDialer::new()
        .with_header("x-tendril-token", "wrong-token")
        .dial(&format!("broker+ws://{addr}/custom/tunnel"))
        .await;
    assert!(matches!(bad_auth, Err(RuntimeError::Protocol(_))));

    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut dup_req = format!("ws://{addr}/custom/tunnel")
        .into_client_request()
        .expect("dup req");
    dup_req
        .headers_mut()
        .append("x-tendril-token", "secret-v1".parse().expect("hdr"));
    dup_req
        .headers_mut()
        .append("x-tendril-token", "secret-v1".parse().expect("hdr"));
    assert!(connect_async(dup_req).await.is_err());

    let mut raw = TcpStream::connect(addr).await.expect("raw tcp");
    raw.write_all(
        b"POST /custom/tunnel HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nx-tendril-token: secret-v1\r\n\r\n",
    )
    .await
    .expect("write POST");
    let mut http_buf = [0u8; 256];
    let n = raw.read(&mut http_buf).await.expect("read POST reply");
    let resp = std::str::from_utf8(&http_buf[..n]).unwrap_or_default();
    assert!(
        n == 0 || resp.starts_with("HTTP/1.1 4"),
        "unexpected HTTP reply to POST upgrade: {resp:?}"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "listener should not accept POST upgrade"
    );

    // Connect a raw authenticated WebSocket and verify non-binary text frame is rejected.
    let mut req = format!("ws://{addr}/custom/tunnel")
        .into_client_request()
        .expect("req");
    req.headers_mut()
        .insert("x-tendril-token", "secret-v1".parse().expect("hdr"));
    let (mut raw_ws, _) = connect_async(req).await.expect("connect text test");
    let mut accepted = listener.accept().await.expect("accept text test");
    raw_ws
        .send(Message::Text("bad-text".into()))
        .await
        .expect("send text");
    let mut tmp_buf = [0u8; 64];
    assert!(matches!(
        accepted.recv_chunk(&mut tmp_buf).await,
        Err(RuntimeError::Protocol(_))
    ));

    let ok_stream = BrokerDialer::new()
        .with_header("x-tendril-token", "secret-v1")
        .dial(&format!("broker+ws://{addr}/custom/tunnel"))
        .await
        .expect("valid broker dial");
    assert_eq!(ok_stream.provider_id(), ProviderId::Broker);
    drop(listener);
}

#[tokio::test]
async fn relay_hint_migration_public_to_self_hosted_to_embedded_without_repairing() {
    let relay_a = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay a")
        .spawn();
    let relay_b = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay b")
        .spawn();
    let relay_c = EmbeddedRelay::bind_local("localhost")
        .await
        .expect("bind embedded relay");

    let host_dir = TempDir::new().expect("host dir");
    let cli_dir = TempDir::new().expect("cli dir");
    let host_store = StateStore::open_or_create(host_dir.path()).expect("host store");
    let cli_store = StateStore::open_or_create(cli_dir.path()).expect("cli store");
    let host_id = host_store
        .load_or_generate_identity(Some("mig-host"))
        .expect("host id");
    let cli_id = cli_store
        .load_or_generate_identity(Some("mig-cli"))
        .expect("cli id");

    let mut cli_roster = Roster::new();
    let mgr = Mutex::new(PairingManager::new(PairingConfig::default()));
    let now = 1_795_132_800;

    // Step 1: Pair ONCE through Relay A (simulating public relay).
    let mut host_relay_a = RelayListener::bind(
        relay_a.ws_url(),
        Some("localhost".to_owned()),
        host_id.signing_key().signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .expect("host listen A");
    let ep_a = host_relay_a.local_endpoint();
    let code = mgr
        .lock()
        .expect("lock")
        .issue_code(PairingCodeKind::Remote3Group, now)
        .expect("code");
    let dialer = RelayDialer::new().with_expected_host("localhost");

    let (srv_p, cli_p) = tokio::join!(host_relay_a.accept(), dialer.dial(&ep_a));
    let mut srv_p = srv_p.expect("accept pair A");
    let mut cli_p = cli_p.expect("dial pair A");
    let host_r = Mutex::new(Roster::new());
    let (h_res, c_res) = tokio::join!(
        drive_pair_responder(
            srv_p.as_mut(),
            &host_id,
            &mgr,
            &host_r,
            PairingPathKind::Remote,
            now,
            None
        ),
        drive_pair_initiator(
            cli_p.as_mut(),
            &cli_id,
            "phone".to_owned(),
            "ios".to_owned(),
            code,
            None
        )
    );
    let h_pair = h_res.expect("host pair");
    let c_pair = c_res.expect("cli pair");
    let mut host_roster = host_r.into_inner().expect("unlock");
    let (cli_dev, sas) = match h_pair.outcome {
        PairOutcome::ResponderPending {
            device_id,
            pairing_sas,
            ..
        } => (device_id, pairing_sas),
        other => panic!("unexpected pair: {other:?}"),
    };
    let PairOutcome::InitiatorPending {
        host_id: learned_host_id,
        host_static_pub,
        host_signing_pub,
        host_rotation_seq,
        pairing_sas: cli_sas,
        ..
    } = c_pair.outcome
    else {
        panic!("expected InitiatorPending");
    };
    cli_roster
        .record_pending_host(
            learned_host_id.clone(),
            "mig-host".to_owned(),
            host_static_pub,
            host_signing_pub,
            host_rotation_seq,
            cli_sas.clone(),
            vec![ep_a.clone()],
        )
        .expect("record pending host");
    cli_roster
        .confirm_peer(&learned_host_id, Some(&cli_sas))
        .expect("confirm host on client");
    host_roster
        .confirm_peer(&cli_dev, Some(&sas))
        .expect("confirm");
    let grant = host_roster
        .mint_grant(
            &host_id,
            &cli_dev,
            vec!["fs.read:/notes/*".to_owned()],
            now - 60,
            now + 3600,
            [9u8; 16],
        )
        .expect("mint");
    cli_store.save_roster(&cli_roster).expect("save cli A");

    // Step 2: Migrate relay hints from Relay A -> Relay B (self-hosted), zero re-pairing.
    drop(host_relay_a);
    relay_a.stop().await.expect("stop A");
    let mut host_relay_b = RelayListener::bind(
        relay_b.ws_url(),
        Some("localhost".to_owned()),
        host_id.signing_key().signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .expect("host listen B");
    let ep_b = host_relay_b.local_endpoint();
    let mut cli_roster = cli_store.load_roster().expect("reload cli roster");
    cli_roster
        .update_relay_hints(&learned_host_id, vec![ep_b.clone()])
        .expect("update hint B");
    cli_store.save_roster(&cli_roster).expect("save cli B");

    let (srv_b, cli_b) = tokio::join!(host_relay_b.accept(), dialer.dial(&ep_b));
    let (h_b, c_b) = tokio::join!(
        SessionDriver::accept(srv_b.expect("srv B"), &host_id, &mut host_roster, now, None),
        SessionDriver::connect(
            cli_b.expect("cli B"),
            &cli_id,
            &learned_host_id,
            Some(grant.clone()),
            &mut cli_roster,
            now
        )
    );
    let mut host_sess_b = h_b.expect("host sess B");
    let mut cli_sess_b = c_b.expect("cli sess B");
    cli_sess_b
        .send_data(b"via-self-hosted-relay")
        .await
        .expect("send B");
    assert_eq!(
        host_sess_b
            .next_event(now, &mut host_roster)
            .await
            .expect("ev B"),
        Some(SessionEvent::AppData(b"via-self-hosted-relay".to_vec()))
    );
    drop(cli_sess_b);
    drop(host_sess_b);

    // Step 3: Migrate relay hints from Relay B -> EmbeddedRelay, keeping same pin + grant + rekey.
    drop(host_relay_b);
    relay_b.stop().await.expect("stop B");
    let mut host_relay_c = RelayListener::bind(
        relay_c.ws_url(),
        Some(relay_c.host().to_owned()),
        host_id.signing_key().signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .expect("host listen C");
    let ep_c = host_relay_c.local_endpoint();
    cli_roster
        .update_relay_hints(&learned_host_id, vec![ep_c.clone()])
        .expect("update hint C");
    cli_store.save_roster(&cli_roster).expect("save cli C");

    let mut reloaded_cli = cli_store.load_roster().expect("reload cli C");
    assert_eq!(
        reloaded_cli.get(&learned_host_id).expect("pin").relay_hints,
        vec![ep_c.clone()]
    );
    let (srv_c, cli_c) = tokio::join!(host_relay_c.accept(), dialer.dial(&ep_c));
    let (h_c, c_c) = tokio::join!(
        SessionDriver::accept(srv_c.expect("srv C"), &host_id, &mut host_roster, now, None),
        SessionDriver::connect(
            cli_c.expect("cli C"),
            &cli_id,
            &learned_host_id,
            Some(grant),
            &mut reloaded_cli,
            now
        )
    );
    let mut host_sess_c = h_c.expect("host sess C");
    let mut cli_sess_c = c_c.expect("cli sess C");
    assert!(
        host_sess_c
            .authorize("fs.read:/notes/1.md", now, &host_roster)
            .0
            .is_ok()
    );
    cli_sess_c.send_rekey().await.expect("rekey C");
    cli_sess_c
        .send_data(b"via-embedded-relay")
        .await
        .expect("send C");
    let mut got_rekey = false;
    let mut got_data = false;
    for _ in 0..4 {
        match host_sess_c
            .next_event(now, &mut host_roster)
            .await
            .expect("ev C")
        {
            Some(SessionEvent::Rekeyed { .. }) => got_rekey = true,
            Some(SessionEvent::AppData(d)) if d == b"via-embedded-relay" => {
                got_data = true;
                break;
            }
            _ => {}
        }
    }
    assert!(got_rekey && got_data);
    drop(host_relay_c);
    relay_c.shutdown().await.expect("shutdown embedded relay");
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn dial_with_policy_respects_p2p_cold_delay_and_falls_back_across_rungs() {
    let mut p2p_listener = P2pListener::bind(P2pRelayMode::Disabled)
        .await
        .expect("bind p2p");
    let p2p_ep = p2p_listener.local_endpoint();
    let p2p_dialer = Arc::new(
        P2pDialer::bind(P2pRelayMode::Disabled)
            .await
            .expect("p2p dialer"),
    );

    let unused_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind unused");
    let dead_addr = unused_listener.local_addr().expect("unused addr");
    drop(unused_listener);

    // Dead Direct + live P2p -> falls back to P2p after cold delay.
    let dialers: Vec<Arc<dyn PathDialer>> = vec![
        Arc::new(DirectDialer::new()),
        Arc::clone(&p2p_dialer) as Arc<dyn PathDialer>,
    ];
    let cands = vec![
        CandidateEndpoint::new(1, ProviderId::Direct, dead_addr.to_string()),
        CandidateEndpoint::new(2, ProviderId::P2p, p2p_ep.clone()),
    ];
    let accept_task = tokio::spawn(async move { p2p_listener.accept().await });
    let (winner, mut cli_stream) = dial_with_policy(&dialers, PathPolicyConfig::default(), cands)
        .await
        .expect("fallback to p2p");
    assert_eq!(winner.provider, ProviderId::P2p);
    let mut srv_stream = accept_task.await.expect("join").expect("accept");
    send_tendril_frame(cli_stream.as_mut(), b"policy-p2p")
        .await
        .expect("send");
    let mut reader = ResumableFrameReader::new();
    assert_eq!(
        recv_tendril_frame(srv_stream.as_mut(), &mut reader)
            .await
            .expect("recv"),
        b"policy-p2p"
    );

    // Dead P2p -> falls back cleanly to live Broker.
    let mut broker_listener = BrokerListener::bind(BrokerServerConfig::default())
        .await
        .expect("bind broker");
    let broker_ep = broker_listener.local_endpoint();
    let dialers2: Vec<Arc<dyn PathDialer>> = vec![p2p_dialer, Arc::new(BrokerDialer::new())];
    let bad_p2p =
        "iroh://0000000000000000000000000000000000000000000000000000000000000000?addr=127.0.0.1:9";
    let cands2 = vec![
        CandidateEndpoint::new(1, ProviderId::P2p, bad_p2p),
        CandidateEndpoint::new(2, ProviderId::Broker, broker_ep),
    ];
    let accept_broker = tokio::spawn(async move { broker_listener.accept().await });
    let (winner2, _cli2) = dial_with_policy(
        &dialers2,
        PathPolicyConfig {
            p2p_cold_delay_ms: 50,
            ..PathPolicyConfig::default()
        },
        cands2,
    )
    .await
    .expect("fallback to broker");
    assert_eq!(winner2.provider, ProviderId::Broker);
    let _srv2 = accept_broker.await.expect("join").expect("broker accept");
}

#[test]
fn pre_auth_rate_limiter_keys_p2p_by_transport_peer_id() {
    let limiter = PreAuthRateLimiter::new(PreAuthConfig {
        max_entries: 16,
        max_half_open: 32,
        ip_burst: 1,
        ip_refill_per_sec: 1,
        peer_burst: 2,
        peer_refill_per_sec: 1,
    });
    let shared_relay_ip: IpAddr = "198.51.100.1".parse().expect("ip");

    let g1 = limiter
        .try_acquire_for_peer(Some(shared_relay_ip), Some("peer-a"))
        .expect("peer-a 1");
    let g2 = limiter
        .try_acquire_for_peer(Some(shared_relay_ip), Some("peer-a"))
        .expect("peer-a 2");
    assert!(matches!(
        limiter.try_acquire_for_peer(Some(shared_relay_ip), Some("peer-a")),
        Err(RuntimeError::RateLimited(_))
    ));
    drop((g1, g2));

    let g_other_peer = limiter
        .try_acquire_for_peer(Some(shared_relay_ip), Some("peer-b"))
        .expect("peer-b behind same IP is not starved");
    drop(g_other_peer);

    // Direct IP path without transport PeerID still enforces ip_burst independently.
    let g_ip = limiter
        .try_acquire_for_peer(Some(shared_relay_ip), None)
        .expect("ip bucket still full");
    assert!(matches!(
        limiter.try_acquire_for_peer(Some(shared_relay_ip), None),
        Err(RuntimeError::RateLimited(_))
    ));
    drop(g_ip);
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn p2p_deterministic_endpoint_id_and_peer_transport_id() {
    let mut id = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x51; 32]),
        SigningKeypair::from_seed([0x52; 32]),
    )
    .with_host_id("deterministic-p2p-host");
    let seed1 = id.derive_p2p_identity_seed();

    let l1 = P2pListener::bind_with_secret(P2pRelayMode::Disabled, seed1.clone())
        .await
        .expect("bind l1");
    let ep_id1 = l1.endpoint_id();
    drop(l1);

    let l2 = P2pListener::bind_with_secret(P2pRelayMode::Disabled, seed1)
        .await
        .expect("rebind l2");
    assert_eq!(l2.endpoint_id(), ep_id1);
    drop(l2);

    id.rotate(
        StaticKeypair::from_scalar([0x53; 32]),
        SigningKeypair::from_seed([0x54; 32]),
        1_795_132_950,
    )
    .expect("rotate identity");
    let seed2 = id.derive_p2p_identity_seed();

    let mut l3 = P2pListener::bind_with_secret(P2pRelayMode::Disabled, seed2)
        .await
        .expect("bind rotated l3");
    assert_ne!(l3.endpoint_id(), ep_id1);
    let ep3 = l3.local_endpoint();

    let accept_task = tokio::spawn(async move { l3.accept().await });
    let dialer = P2pDialer::bind(P2pRelayMode::Disabled)
        .await
        .expect("bind dialer");
    let mut cli_stream = dialer.dial(&ep3).await.expect("dial rotated");
    drop(dialer);

    let mut srv_stream = accept_task
        .await
        .expect("join accept")
        .expect("accept rotated");
    let transport_pid = srv_stream
        .peer_transport_id()
        .expect("p2p stream exposes remote transport peer id");
    assert!(!transport_pid.is_empty());
    assert_ne!(transport_pid, ep_id1.to_string());

    let _ = srv_stream.close().await;
    let _ = cli_stream.close().await;
}

struct MockPeerIdEofStream {
    ip: Option<IpAddr>,
    transport_id: Option<String>,
}

#[async_trait]
impl PathStream for MockPeerIdEofStream {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.ip
    }

    fn peer_transport_id(&self) -> Option<String> {
        self.transport_id.clone()
    }

    async fn send_chunk(&mut self, _bytes: &[u8]) -> Result<(), RuntimeError> {
        Ok(())
    }

    async fn recv_chunk(&mut self, _buf: &mut [u8]) -> Result<usize, RuntimeError> {
        Ok(0)
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        Ok(())
    }
}

#[test]
fn pairing_path_kind_for_provider_maps_all_providers() {
    assert_eq!(
        pairing_path_kind_for_provider(ProviderId::Local),
        PairingPathKind::Lan
    );
    assert_eq!(
        pairing_path_kind_for_provider(ProviderId::Direct),
        PairingPathKind::Lan
    );
    for provider in [
        ProviderId::Overlay,
        ProviderId::P2p,
        ProviderId::Relay,
        ProviderId::Broker,
    ] {
        assert_eq!(
            pairing_path_kind_for_provider(provider),
            PairingPathKind::Remote
        );
    }
}

#[tokio::test]
async fn direct_driver_paths_enforce_peer_transport_id_rate_limit() {
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x61; 32]),
        SigningKeypair::from_seed([0x62; 32]),
    )
    .with_host_id("direct-rl-host");
    let mgr = Mutex::new(PairingManager::new(PairingConfig::default()));
    let mut roster = Roster::new();
    let shared_ip: IpAddr = "198.51.100.7".parse().expect("ip");
    let limiter = PreAuthRateLimiter::new(PreAuthConfig {
        max_entries: 16,
        max_half_open: 16,
        ip_burst: 1,
        ip_refill_per_sec: 1,
        peer_burst: 1,
        peer_refill_per_sec: 1,
    });

    // SessionDriver::accept uses peer_transport_id("peer-a") instead of colliding on shared_ip.
    let err1 = SessionDriver::accept(
        Box::new(MockPeerIdEofStream {
            ip: Some(shared_ip),
            transport_id: Some("peer-a".to_owned()),
        }),
        &host,
        &mut roster,
        1_795_133_000,
        Some(&limiter),
    )
    .await;
    assert!(matches!(err1, Err(RuntimeError::Closed)));

    let err2 = SessionDriver::accept(
        Box::new(MockPeerIdEofStream {
            ip: Some(shared_ip),
            transport_id: Some("peer-a".to_owned()),
        }),
        &host,
        &mut roster,
        1_795_133_000,
        Some(&limiter),
    )
    .await;
    assert!(matches!(err2, Err(RuntimeError::RateLimited(_))));

    // Direct pair responder also scopes independently per peer_transport_id("peer-b").
    let roster_sync = Mutex::new(Roster::new());
    let mut stream_b = MockPeerIdEofStream {
        ip: Some(shared_ip),
        transport_id: Some("peer-b".to_owned()),
    };
    let pair_b1 = drive_pair_responder_with_options(
        &mut stream_b,
        &host,
        &mgr,
        &roster_sync,
        PairingPathKind::Remote,
        1_795_133_000,
        Some(&limiter),
        None,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await;
    assert!(matches!(pair_b1, Err(RuntimeError::Closed)));

    let pair_b2 = drive_pair_responder_with_options(
        &mut stream_b,
        &host,
        &mgr,
        &roster_sync,
        PairingPathKind::Remote,
        1_795_133_000,
        Some(&limiter),
        None,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await;
    assert!(matches!(pair_b2, Err(RuntimeError::RateLimited(_))));
}
