use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tempfile::TempDir;
use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{SigningKeypair, StaticKeypair, random_bytes};
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
    BrokerDialer, BrokerListener, BrokerServerConfig, ConcurrentSession, DEFAULT_PRE_AUTH_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, EmbeddedRelay, LocalDialer, LocalListener,
    MAX_OUTER_FRAME_LEN, OverlayConfig, OverlayDialer, OverlayHelperDialer, OverlayHelperListener,
    OverlayListener, OverlayMode, OverlayResolvedMode, PathDialer, PathListener, PathReader,
    PathStream, PathWriter, PreAuthConfig, PreAuthRateLimiter, RelayDialer, RelayListener,
    RuntimeError, SessionDriver, SessionEvent, StateStore, dial_with_policy, drive_pair_responder,
    drive_pair_responder_with_options, is_tailnet_ip, pairing_path_kind_for_provider,
    recv_tendril_frame, select_overlay_mode, send_tendril_frame, split_path_stream_fallback,
};
#[cfg(feature = "p2p-iroh")]
use tendril_runtime::{P2pDialer, P2pListener, P2pRelayMode};
use tokio::time::timeout;

/// A loopback port nothing listens on, held for the guard's lifetime. The port is the local end
/// of an established loopback connection: dials to it are refused at once, and ordinary `bind(0)`
/// allocation will not hand it to another listener, so a retrying client aimed at it cannot land
/// on a socket bound later by a parallel test. (On macOS an explicit `SO_REUSEADDR` rebind of the
/// exact port can still succeed; the guard prevents ephemeral allocation, not that.) A socket
/// that is only bound is not enough, because Darwin drops SYNs to it without a reset and the dial
/// hangs until the OS connect timeout.
struct DeadPort {
    _client: std::net::TcpStream,
    _server: std::net::TcpStream,
    addr: SocketAddr,
}

const DEAD_PORT_SETUP_DEADLINE: Duration = Duration::from_secs(5);

impl DeadPort {
    fn new() -> Self {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind seed");
        let client = std::net::TcpStream::connect(listener.local_addr().expect("seed addr"))
            .expect("connect seed");
        Self::from_listener(listener, client)
    }

    /// Keeps the accepted stream whose peer is `client`, dropping any foreign connection (a host
    /// process may probe a new loopback listener before the client arrives), then closes the
    /// seed listener. Panics if the client's stream is not accepted before the setup deadline.
    fn from_listener(listener: std::net::TcpListener, client: std::net::TcpStream) -> Self {
        let addr = client.local_addr().expect("dead port addr");
        listener
            .set_nonblocking(true)
            .expect("nonblocking seed listener");
        let deadline = Instant::now() + DEAD_PORT_SETUP_DEADLINE;
        let server = loop {
            match listener.accept() {
                Ok((stream, peer)) if peer == addr => break stream,
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "dead port setup: seed listener never accepted the client at {addr}"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("accept seed: {err}"),
            }
        };
        Self {
            _client: client,
            _server: server,
            addr,
        }
    }
}

fn assert_dead_port_held(guard: &DeadPort) {
    let started = Instant::now();
    let err = std::net::TcpStream::connect_timeout(&guard.addr, Duration::from_secs(2))
        .expect_err("dial must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "refusal was not immediate"
    );
    let rebind = tokio::net::TcpSocket::new_v4().expect("rebind socket");
    let err = rebind.bind(guard.addr).expect_err("port must stay held");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    #[cfg(target_os = "linux")]
    {
        let err = std::net::TcpListener::bind(guard.addr).expect_err("held against SO_REUSEADDR");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }
    for _ in 0..2000 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        assert_ne!(
            probe.local_addr().expect("probe addr").port(),
            guard.addr.port(),
            "bind(0) returned the guarded port"
        );
    }
}

#[test]
fn dead_port_guard_refuses_dials_and_holds_the_port() {
    assert_dead_port_held(&DeadPort::new());
}

#[test]
fn dead_port_guard_ignores_a_foreign_connection_that_arrives_first() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind seed");
    let seed = listener.local_addr().expect("seed addr");
    let stray = std::net::TcpStream::connect(seed).expect("connect stray");
    let client = std::net::TcpStream::connect(seed).expect("connect client");
    assert_ne!(
        stray.local_addr().expect("stray addr"),
        client.local_addr().expect("client addr")
    );
    let guard = DeadPort::from_listener(listener, client);
    assert_dead_port_held(&guard);
    drop(stray);
}

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
                .expect("bind overlay")
                .with_allow_non_tailnet(true);
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
            let listener = P2pListener::bind_with_options(
                tendril_runtime::P2pOptions::for_listener(P2pRelayMode::Disabled)
                    .with_port_mapping(false),
                None,
            )
            .await
            .expect("bind p2p");
            let dialer = P2pDialer::bind_with_options(
                tendril_runtime::P2pOptions::for_dialer(P2pRelayMode::Disabled)
                    .with_port_mapping(false),
            )
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
                key.ed25519_signing_key(),
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

const DIAL_TAG_LEN: usize = 16;

/// Opens one stream pair. A loopback TCP listener also accepts connections from other processes
/// on the host (a local service-discovery daemon sends `GET /` to every new listening port), and
/// one stray accepted in place of the dialed stream shifts every later pairing in the test. The
/// dialer therefore sends a random tag first, and only the accepted stream carrying it is kept.
async fn open_pair(pair: &mut ProviderPair) -> (Box<dyn PathStream>, Box<dyn PathStream>) {
    let tag: [u8; DIAL_TAG_LEN] = random_bytes().expect("dial tag");
    let ep = pair.endpoint.clone();
    let dialer = &pair.dialer;
    let dial = async {
        let mut cli = dialer.dial(&ep).await.expect("dial stream");
        cli.send_chunk(&tag).await.expect("send dial tag");
        cli
    };
    let (srv, cli) = tokio::join!(accept_dialed(pair.listener.as_mut(), tag), dial);
    (srv, cli)
}

/// Accepts until a stream presents `tag`. Each candidate is read in its own task, and one deadline
/// covers its whole tag read, so a silent or trickling stray cannot delay the dialed stream;
/// strays are dropped.
async fn accept_dialed(
    listener: &mut dyn PathListener,
    tag: [u8; DIAL_TAG_LEN],
) -> Box<dyn PathStream> {
    let mut checks = tokio::task::JoinSet::new();
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let mut stream = accepted.expect("accept stream");
                checks.spawn(async move {
                    let mut got = [0u8; DIAL_TAG_LEN];
                    let read_tag = async {
                        let mut filled = 0;
                        while filled < got.len() {
                            match stream.recv_chunk(&mut got[filled..]).await {
                                Ok(n) if n > 0 => filled += n,
                                _ => return false,
                            }
                        }
                        true
                    };
                    let complete = timeout(Duration::from_secs(5), read_tag).await == Ok(true);
                    (complete && got == tag).then_some(stream)
                });
            }
            Some(checked) = checks.join_next() => {
                if let Some(stream) = checked.expect("dial tag check") {
                    return stream;
                }
            }
            () = &mut deadline => panic!("no accepted stream carried the dial tag"),
        }
    }
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

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        split_path_stream_fallback(self)
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
            host_id_ent.signing_key().clone(),
            Vec::new(),
            0,
        )
        .expect("clone id");
        host_roster
            .insert_pinned_host(
                cli_id_ent.device_id(),
                "client".to_owned(),
                *cli_id_ent.static_key().public_bytes(),
                Some(cli_id_ent.signing_key().public_key().clone()),
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
                Some(host_for_cli.signing_key().public_key().clone()),
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
async fn open_pair_skips_foreign_connections_without_waiting_on_silent_ones() {
    use tokio::io::AsyncWriteExt;
    for provider in [ProviderId::Direct, ProviderId::Overlay] {
        let mut pair = setup_provider(provider).await;
        let addr = pair
            .endpoint
            .strip_prefix("overlay://")
            .unwrap_or(&pair.endpoint)
            .to_owned();
        let _silent = tokio::net::TcpStream::connect(&addr)
            .await
            .expect("silent stray");
        let mut http = tokio::net::TcpStream::connect(&addr)
            .await
            .expect("http stray");
        http.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("write stray request");

        let (mut srv, mut cli) = timeout(Duration::from_secs(4), open_pair(&mut pair))
            .await
            .expect("open_pair must not wait for the silent stray");

        send_tendril_frame(cli.as_mut(), b"dialed")
            .await
            .expect("send");
        let mut reader = ResumableFrameReader::new();
        let got = timeout(
            Duration::from_secs(2),
            recv_tendril_frame(srv.as_mut(), &mut reader),
        )
        .await
        .map_err(|_| format!("{provider:?}: accepted stream is silent, not the dialed one"))
        .expect("recv in time")
        .expect("recv");
        assert_eq!(
            got, b"dialed",
            "{provider:?}: accepted stream is not the dialed one"
        );
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
        max_half_open_per_key: 32,
        ..PreAuthConfig::default()
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

    let peer_static = *tendril_core::crypto::StaticKeypair::from_scalar([0x51; 32]).public_bytes();
    let peer_signing = tendril_core::crypto::SigningKeypair::from_seed([0x52; 32])
        .public_key()
        .clone();
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            "peer-1".to_owned(),
            "phone".to_owned(),
            peer_static,
            Some(peer_signing),
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
        key.ed25519_signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .expect("bind relay listener");

    let dead = DeadPort::new();
    let dead_addr = dead.addr;

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

#[allow(deprecated)]
#[tokio::test]
async fn full_lifecycle_pair_confirm_mint_connect_authorize_data_rekey_revoke_across_providers() {
    use tendril_runtime::drive_pair_initiator;
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
        key.ed25519_signing_key(),
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
        key.ed25519_signing_key(),
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

#[allow(deprecated)]
#[tokio::test]
async fn relay_hint_migration_public_to_self_hosted_to_embedded_without_repairing() {
    use tendril_runtime::drive_pair_initiator;
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
        host_id.signing_key().ed25519_signing_key(),
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
        host_id.signing_key().ed25519_signing_key(),
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
        host_id.signing_key().ed25519_signing_key(),
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
    let mut p2p_listener = P2pListener::bind_with_options(
        tendril_runtime::P2pOptions::for_listener(P2pRelayMode::Disabled).with_port_mapping(false),
        None,
    )
    .await
    .expect("bind p2p");
    let p2p_ep = p2p_listener.local_endpoint();
    let p2p_dialer = Arc::new(
        P2pDialer::bind_with_options(
            tendril_runtime::P2pOptions::for_dialer(P2pRelayMode::Disabled)
                .with_port_mapping(false),
        )
        .await
        .expect("p2p dialer"),
    );

    let dead = DeadPort::new();
    let dead_addr = dead.addr;

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
        ..PreAuthConfig::default()
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

    let l1 = P2pListener::bind_with_options(
        tendril_runtime::P2pOptions::for_listener(P2pRelayMode::Disabled).with_port_mapping(false),
        Some(seed1.clone()),
    )
    .await
    .expect("bind l1");
    let ep_id1 = l1.endpoint_id();
    drop(l1);

    let l2 = P2pListener::bind_with_options(
        tendril_runtime::P2pOptions::for_listener(P2pRelayMode::Disabled).with_port_mapping(false),
        Some(seed1),
    )
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

    let mut l3 = P2pListener::bind_with_options(
        tendril_runtime::P2pOptions::for_listener(P2pRelayMode::Disabled).with_port_mapping(false),
        Some(seed2),
    )
    .await
    .expect("bind rotated l3");
    assert_ne!(l3.endpoint_id(), ep_id1);
    let ep3 = l3.local_endpoint();

    let accept_task = tokio::spawn(async move { l3.accept().await });
    let dialer = P2pDialer::bind_with_options(
        tendril_runtime::P2pOptions::for_dialer(P2pRelayMode::Disabled).with_port_mapping(false),
    )
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

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        split_path_stream_fallback(self)
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
        ..PreAuthConfig::default()
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

#[tokio::test]
async fn batch1_sec03_inbound_router_isolates_queues_expires_stale_and_gates_pair() {
    use tendril_core::wire::{Intent, Preamble};
    use tendril_runtime::{DirectDialer, DirectListener, InboundRouter};

    let cfg = PreAuthConfig {
        max_entries: 64,
        max_half_open: 16,
        ip_burst: 64,
        ip_refill_per_sec: 32,
        peer_burst: 32,
        peer_refill_per_sec: 16,
        ..PreAuthConfig::default()
    };
    let listener = DirectListener::bind("127.0.0.1:0".parse().expect("addr"), None)
        .await
        .expect("bind direct");
    let ep = listener.local_endpoint();
    let router = Arc::new(InboundRouter::with_config_and_ttl(
        cfg,
        Duration::from_millis(80),
    ));
    router.spawn_listener(&tokio::runtime::Handle::current(), Box::new(listener));

    let dialer = DirectDialer::new();
    // Fill the isolated Intent::Pair queue without ever polling recv_pair().
    let mut held_pair_streams = Vec::new();
    for _ in 0..16 {
        let mut s = dialer.dial(&ep).await.expect("dial pair");
        s.send_chunk(&Preamble::v1(Intent::Pair).encode())
            .await
            .expect("send pair preamble");
        held_pair_streams.push(s);
    }

    // Legitimate Intent::Session connections MUST succeed immediately despite full pair queue.
    let mut sess_conn = dialer.dial(&ep).await.expect("dial session");
    sess_conn
        .send_chunk(&Preamble::v1(Intent::Session).encode())
        .await
        .expect("send session preamble");
    let (_sess_stream, sess_guard) = router
        .recv_session(Duration::from_secs(2))
        .await
        .expect("session wait ok")
        .expect("session stream");
    assert_eq!(router.session_rate_limiter().active_half_open(), 1);
    drop((_sess_stream, sess_guard));
    assert_eq!(router.session_rate_limiter().active_half_open(), 0);

    // Unconsumed queued Intent::Pair streams automatically expire after queue_ttl.
    let mut drained = false;
    for _ in 0..30 {
        if router.pair_rate_limiter().active_half_open() == 0 {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(drained, "expected unpolled pair queue guards to expire");

    // Disabling Intent::Pair rejects pair preambles without consuming pair queue slots.
    router.set_pair_enabled(false);
    let mut disabled_pair = dialer.dial(&ep).await.expect("dial disabled pair");
    disabled_pair
        .send_chunk(&Preamble::v1(Intent::Pair).encode())
        .await
        .expect("send disabled pair preamble");
    assert!(matches!(
        router.recv_pair(Duration::from_millis(100)).await,
        Err(())
    ));
    assert_eq!(router.pair_rate_limiter().active_half_open(), 0);
    router.close();
}

#[test]
fn batch1_sec04_state_store_flock_serializes_concurrent_updates() {
    use tendril_core::roster::PeerState;
    use tendril_runtime::StateStore;

    let tmp = TempDir::new().expect("temp dir");
    let store = StateStore::open_or_create(tmp.path()).expect("store");
    let target = tendril_core::identity::EndpointIdentity::generate().expect("target");
    let target_id = "peer-target".to_owned();
    let target_pub = *target.static_key().public_bytes();
    let target_sig = target.signing_key().public_key().clone();

    store
        .update_roster(|r| {
            r.insert_pinned_host(
                target_id.clone(),
                "Target".into(),
                target_pub,
                Some(target_sig),
                0,
                vec![],
            )?;
            Ok(())
        })
        .expect("seed target");

    let mut handles = Vec::new();
    for i in 0..8usize {
        let dir = tmp.path().to_path_buf();
        let tid = target_id.clone();
        handles.push(std::thread::spawn(move || {
            let st = StateStore::open_or_create(dir).expect("reopen");
            if i == 3 {
                st.update_roster(|r| {
                    r.revoke_peer(&tid)?;
                    Ok(())
                })
                .expect("revoke");
            } else {
                let peer = tendril_core::identity::EndpointIdentity::generate().expect("peer");
                st.update_roster(|r| {
                    r.insert_pinned_host(
                        format!("peer-{i}"),
                        format!("Peer {i}"),
                        *peer.static_key().public_bytes(),
                        Some(peer.signing_key().public_key().clone()),
                        0,
                        vec![],
                    )?;
                    Ok(())
                })
                .expect("insert peer");
            }
        }));
    }
    for h in handles {
        h.join().expect("join thread");
    }

    let (final_roster, loaded_stamp) = store.load_roster_with_stamp().expect("load final roster");
    assert_eq!(
        loaded_stamp,
        store.roster_stamp().expect("read stamp after load")
    );
    assert_eq!(
        final_roster.get(&target_id).expect("target present").state,
        PeerState::Revoked
    );
    for i in 0..8usize {
        if i != 3 {
            assert!(
                final_roster.get(&format!("peer-{i}")).is_some(),
                "lost concurrent peer-{i}"
            );
        }
    }

    let ((), updated_roster, updated_stamp) = store
        .update_roster_with_state(|r| {
            r.update_relay_hints("peer-0", vec!["wss://relay.example/v1/relay".to_owned()])?;
            Ok(())
        })
        .expect("update with state");
    assert_eq!(
        updated_stamp,
        store.roster_stamp().expect("read stamp after update")
    );
    assert_eq!(
        updated_roster.get(&target_id).expect("target").state,
        PeerState::Revoked
    );
    assert_eq!(
        updated_roster.get("peer-0").expect("peer-0").relay_hints,
        vec!["wss://relay.example/v1/relay".to_owned()]
    );
}

#[test]
fn batch2a_sec05_relay_partition_and_unattributed_bucket() {
    let limiter = PreAuthRateLimiter::new(PreAuthConfig {
        max_entries: 64,
        max_half_open: 8,
        untrusted_max_half_open: 3,
        ip_burst: 64,
        ip_refill_per_sec: 16,
        peer_burst: 64,
        peer_refill_per_sec: 16,
        unattributed_burst: 2,
        unattributed_refill_per_sec: 1,
        max_half_open_per_key: 2,
    });

    // Unattributed untrusted relay connections draw from unattributed_burst (2), never starving trusted slots.
    let g1 = limiter
        .try_acquire_for_stream(ProviderId::Relay, None, None)
        .expect("unattributed 1");
    let g2 = limiter
        .try_acquire_for_stream(ProviderId::Broker, None, None)
        .expect("unattributed 2");
    assert_eq!(limiter.untrusted_active_half_open(), 2);
    assert_eq!(limiter.active_half_open(), 0);
    assert!(matches!(
        limiter.try_acquire_for_stream(ProviderId::Relay, None, None),
        Err(RuntimeError::RateLimited(_))
    ));
    drop((g1, g2));
    assert_eq!(limiter.untrusted_active_half_open(), 0);

    // Attributed relay streams hit untrusted_max_half_open (3) while trusted Direct streams still work.
    let g3 = limiter
        .try_acquire_for_stream(ProviderId::Relay, None, Some("relay-peer-a"))
        .expect("relay a1");
    let g4 = limiter
        .try_acquire_for_stream(ProviderId::Relay, None, Some("relay-peer-a"))
        .expect("relay a2");
    assert!(
        matches!(
            limiter.try_acquire_for_stream(ProviderId::Relay, None, Some("relay-peer-a")),
            Err(RuntimeError::RateLimited(_))
        ),
        "single peer exceeds max_half_open_per_key=2"
    );
    let g5 = limiter
        .try_acquire_for_stream(ProviderId::Relay, None, Some("relay-peer-b"))
        .expect("relay b1 fills untrusted cap=3");
    assert!(matches!(
        limiter.try_acquire_for_stream(ProviderId::Relay, None, Some("relay-peer-c")),
        Err(RuntimeError::RateLimited(_))
    ));
    let direct_g = limiter
        .try_acquire_for_stream(
            ProviderId::Direct,
            Some("203.0.113.10".parse().expect("ip")),
            None,
        )
        .expect("trusted direct must remain unaffected when untrusted cap is saturated");
    assert_eq!(limiter.active_half_open(), 1);
    drop((g3, g4, g5, direct_g));
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn batch2a_sec06_p2p_per_peer_accept_cap() {
    use tendril_runtime::{TENDRIL_P2P_ALPN, parse_p2p_endpoint};

    let mut listener = P2pListener::bind_with_options(
        tendril_runtime::P2pOptions::for_listener(P2pRelayMode::Disabled).with_port_mapping(false),
        None,
    )
    .await
    .expect("bind p2p listener");
    let ep_str = listener.local_endpoint();
    let target_addr = parse_p2p_endpoint(&ep_str).expect("parse p2p endpoint");

    let attacker_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
        .bind()
        .await
        .expect("bind attacker endpoint");

    // Peer A floods 68 concurrent connections (> MAX_CONCURRENT_ACCEPTS = 64) without writing the
    // 0x54 stream magic byte; per-peer pre/post-handshake caps limit Peer A to 4 slots.
    let started = Instant::now();
    let held = Arc::new(Mutex::new(Vec::new()));
    let mut burst = Vec::new();
    for _ in 0..68 {
        let ep = attacker_ep.clone();
        let addr = target_addr.clone();
        let held_c = Arc::clone(&held);
        burst.push(tokio::spawn(async move {
            if let Ok(Ok(conn)) = timeout(
                Duration::from_millis(250),
                ep.connect(addr, TENDRIL_P2P_ALPN),
            )
            .await
                && let Ok(bi) = conn.open_bi().await
            {
                held_c.lock().expect("held lock").push((conn, bi));
            }
        }));
    }
    tokio::time::sleep(Duration::from_millis(260)).await;
    let held_count = held.lock().expect("held lock").len();
    assert!(
        held_count >= 4,
        "expected >= 4 attacker connections holding per-peer cap, got {held_count}"
    );

    let legit_dialer = P2pDialer::bind_with_options(
        tendril_runtime::P2pOptions::for_dialer(P2pRelayMode::Disabled).with_port_mapping(false),
    )
    .await
    .expect("bind legit dialer");
    let dial_task = tokio::spawn(async move { legit_dialer.dial(&ep_str).await });
    let srv_stream = timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("legit peer accept must not be blocked by attacker peer")
        .expect("accept ok");
    let cli_stream = dial_task.await.expect("dial join").expect("legit dial ok");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "legit dial must succeed before attacker accept_bi timeouts expire"
    );
    assert_eq!(srv_stream.provider_id(), ProviderId::P2p);
    assert_eq!(cli_stream.provider_id(), ProviderId::P2p);

    for handle in burst {
        handle.abort();
    }
    drop(held);
    attacker_ep.close().await;
}

#[test]
fn batch2a_sec13_runtime_pre_auth_ipv6_and_eviction() {
    use std::net::Ipv6Addr;

    let limiter = PreAuthRateLimiter::new(PreAuthConfig {
        max_entries: 2,
        max_half_open: 16,
        untrusted_max_half_open: 8,
        ip_burst: 1,
        ip_refill_per_sec: 1,
        peer_burst: 1,
        peer_refill_per_sec: 1,
        unattributed_burst: 1,
        unattributed_refill_per_sec: 1,
        max_half_open_per_key: 8,
    });

    let v6_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x10, 0x20, 0, 0, 0, 1));
    let v6_b = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x10, 0x20, 1, 2, 3, 4));
    let g_a = limiter.try_acquire(Some(v6_a)).expect("v6 /64 first");
    assert!(matches!(
        limiter.try_acquire(Some(v6_b)),
        Err(RuntimeError::RateLimited(_))
    ));
    drop(g_a);

    // Exhaust mapped v4/v6 sharing.
    let v4: IpAddr = "198.51.100.5".parse().expect("v4");
    let v4_mapped: IpAddr = "::ffff:198.51.100.5".parse().expect("v4 mapped");
    let g_v4 = limiter.try_acquire(Some(v4)).expect("v4 first");
    assert!(matches!(
        limiter.try_acquire(Some(v4_mapped)),
        Err(RuntimeError::RateLimited(_))
    ));
    drop(g_v4);

    // Table is at max_entries=2; overflow bucket allows 1 eviction insertion then blocks burst reset.
    let new1: IpAddr = "203.0.113.1".parse().expect("new1");
    let new2: IpAddr = "203.0.113.2".parse().expect("new2");
    let g_n1 = limiter.try_acquire(Some(new1)).expect("overflow slot 1");
    drop(g_n1);
    assert!(matches!(
        limiter.try_acquire(Some(new2)),
        Err(RuntimeError::RateLimited(_))
    ));
}

#[tokio::test]
async fn batch2a_sec14_url_ssrf_and_filtered_p2p_addrs() {
    use tendril_runtime::{is_loopback_host, is_metadata_or_link_local_ip};

    assert!(is_loopback_host("localhost"));
    assert!(is_loopback_host("sub.LOCALHOST."));
    assert!(is_loopback_host("127.0.0.42"));
    assert!(is_loopback_host("[::1]"));
    assert!(is_loopback_host("[::ffff:127.0.0.1]"));
    assert!(is_loopback_host("my-\u{00e9}.localhost"));
    assert!(!is_loopback_host("my-\u{00e9}-host.org"));
    assert!(!is_loopback_host("example.com"));

    assert!(is_metadata_or_link_local_ip(
        "169.254.169.254".parse().expect("ip")
    ));
    assert!(is_metadata_or_link_local_ip(
        "::ffff:169.254.169.254".parse().expect("ip")
    ));
    assert!(is_metadata_or_link_local_ip("fe80::1".parse().expect("ip")));
    assert!(is_metadata_or_link_local_ip(
        "fd00:ec2::254".parse().expect("ip")
    ));
    assert!(is_metadata_or_link_local_ip("0.0.0.0".parse().expect("ip")));

    let target_b64 = tendril_core::crypto::b64url_encode(&[7u8; 32]);
    let kp = SigningKeypair::generate().expect("kp");
    assert!(matches!(
        RelayListener::bind(
            "ws://relay.example/v1/relay",
            None,
            kp.ed25519_signing_key(),
            DEFAULT_WRITE_TIMEOUT
        )
        .await,
        Err(RuntimeError::Protocol(_))
    ));
    assert!(matches!(
        RelayDialer::new()
            .dial(&format!("ws://relay.example/v1/relay#{target_b64}"))
            .await,
        Err(RuntimeError::Protocol(msg)) if msg.contains("explicit opt-in")
    ));
    assert!(matches!(
        RelayDialer::new()
            .with_allow_insecure_ws(true)
            .dial(&format!("ws://169.254.169.254/v1/relay#{target_b64}"))
            .await,
        Err(RuntimeError::Protocol(msg)) if msg.contains("link-local or metadata")
    ));
    assert!(matches!(
        BrokerDialer::new().dial("broker+ws://broker.example/ws").await,
        Err(RuntimeError::Protocol(msg)) if msg.contains("explicit opt-in")
    ));
    assert!(matches!(
        BrokerDialer::new()
            .with_allow_insecure_ws(true)
            .dial("broker+wss://[::ffff:169.254.169.254]/ws")
            .await,
        Err(RuntimeError::Protocol(msg)) if msg.contains("link-local or metadata")
    ));
    assert!(matches!(
        BrokerDialer::new().dial("wss://user@broker.example/ws").await,
        Err(RuntimeError::Protocol(msg)) if msg.contains("userinfo")
    ));
    assert!(matches!(
        BrokerDialer::new()
            .dial("wss://metadata.google.internal./ws")
            .await,
        Err(RuntimeError::Protocol(msg)) if msg.contains("metadata hostname")
    ));
    for bad_broker_url in [
        "broker+wss://169.254.169.254./ws",
        "broker+wss://169.254.169.254../ws",
        "broker+wss://0xa9fea9fe/ws",
        "broker+wss://2852039166/ws",
        "broker+wss://metadata%2egoogle.internal/ws",
        "broker+wss://169.254.169%2e254/ws",
        "broker+ws://0xa9fea9fe/ws",
        "BROKER+WSS://0xa9fea9fe/ws",
        "broker+http://example.com/ws",
        "broker+ws:169.254.169.254/ws",
    ] {
        assert!(
            matches!(
                BrokerDialer::new().dial(bad_broker_url).await,
                Err(RuntimeError::Protocol(_))
            ),
            "default BrokerDialer must reject {bad_broker_url}"
        );
        assert!(
            matches!(
                BrokerDialer::new()
                    .with_allow_insecure_ws(true)
                    .dial(bad_broker_url)
                    .await,
                Err(RuntimeError::Protocol(_))
            ),
            "opt-in BrokerDialer must reject {bad_broker_url}"
        );
    }
    assert!(matches!(
        RelayDialer::new()
            .dial(&format!("broker+wss://relay.example/v1/relay#{target_b64}"))
            .await,
        Err(RuntimeError::Protocol(_))
    ));

    #[cfg(feature = "p2p-iroh")]
    {
        use tendril_runtime::{parse_p2p_endpoint_filtered, parse_p2p_relay_mode};

        assert!(parse_p2p_relay_mode(Some("http://relay.example/")).is_err());
        assert!(parse_p2p_relay_mode(Some("https://169.254.169.254/")).is_err());
        assert!(parse_p2p_relay_mode(Some("https://169.254.169.254../")).is_err());
        assert!(parse_p2p_relay_mode(Some("https://relay.example/\n")).is_err());
        assert!(parse_p2p_relay_mode(Some("http://127.0.0.1:8080/")).is_ok());
        assert!(parse_p2p_relay_mode(Some("https://relay.example/")).is_ok());

        let ep_id = iroh::SecretKey::from_bytes(&[11u8; 32]).public();
        let uri = format!(
            "iroh://{ep_id}?addr=192.168.1.5:4433&addr=10.0.0.5:4433&addr=100.64.0.1:4433&addr=127.0.0.1:4433&addr=169.254.169.254:80&addr=[fe80::1]:4433&addr=93.184.216.34:4433&relay=https://relay.example/"
        );
        let filtered = parse_p2p_endpoint_filtered(&uri, false).expect("filtered");
        let kept: Vec<String> = filtered.ip_addrs().map(ToString::to_string).collect();
        assert_eq!(kept, vec!["93.184.216.34:4433"]);
        assert_eq!(filtered.relay_urls().count(), 1);

        let allow_priv = parse_p2p_endpoint_filtered(&uri, true).expect("allow priv");
        let priv_ips: Vec<String> = allow_priv.ip_addrs().map(ToString::to_string).collect();
        assert!(!priv_ips.iter().any(|a| a.starts_with("169.254.")));
        assert!(!priv_ips.iter().any(|a| a.starts_with("[fe80:")));
        assert!(priv_ips.contains(&"127.0.0.1:4433".to_owned()));
        assert!(priv_ips.contains(&"93.184.216.34:4433".to_owned()));

        assert!(
            parse_p2p_endpoint_filtered(
                &format!("iroh://{ep_id}?relay=http://evil.example/"),
                false
            )
            .is_err()
        );
    }
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn batch2a_priv01_priv02_p2p_options_and_endpoint_formatting() {
    use iroh::{EndpointAddr, TransportAddr};
    use tendril_runtime::{P2pOptions, format_p2p_endpoint, format_p2p_endpoint_with_addrs};

    let custom_opts =
        P2pOptions::for_listener(P2pRelayMode::Custom("https://relay.example/".to_owned()));
    assert!(!custom_opts.publish_pkarr);
    assert!(!custom_opts.resolve_pkarr);
    assert!(!custom_opts.advertise_direct_addrs);
    assert!(!custom_opts.allow_private_addrs);

    let default_listener_opts = P2pOptions::for_listener(P2pRelayMode::N0Public);
    assert!(default_listener_opts.publish_pkarr);
    assert!(default_listener_opts.resolve_pkarr);
    assert!(!default_listener_opts.advertise_direct_addrs);

    let default_dialer_opts = P2pOptions::for_dialer(P2pRelayMode::N0Public);
    assert!(!default_dialer_opts.publish_pkarr);
    assert!(default_dialer_opts.resolve_pkarr);

    let id = iroh::SecretKey::from_bytes(&[13u8; 32]).public();
    let addr = EndpointAddr::from_parts(
        id,
        [
            TransportAddr::Ip("192.168.1.10:4433".parse().expect("ip1")),
            TransportAddr::Ip("169.254.169.254:80".parse().expect("meta")),
            TransportAddr::Ip("93.184.216.34:4433".parse().expect("pub")),
            TransportAddr::Relay("https://relay.example/".parse().expect("relay")),
        ],
    );
    let default_fmt = format_p2p_endpoint(&addr);
    assert_eq!(
        default_fmt,
        format!("iroh://{id}?relay=https://relay.example/")
    );
    assert!(!default_fmt.contains("addr="));

    let with_addrs = format_p2p_endpoint_with_addrs(&addr, true);
    assert!(with_addrs.contains("addr=192.168.1.10:4433"));
    assert!(with_addrs.contains("addr=93.184.216.34:4433"));
    assert!(!with_addrs.contains("169.254.169.254"));
    assert!(with_addrs.contains("relay=https://relay.example/"));

    let disabled_listener = P2pListener::bind_with_options(
        tendril_runtime::P2pOptions::for_listener(P2pRelayMode::Disabled).with_port_mapping(false),
        None,
    )
    .await
    .expect("bind disabled");
    assert!(disabled_listener.local_endpoint().contains("addr="));

    let hidden_listener = P2pListener::bind_with_options(
        P2pOptions::for_listener(P2pRelayMode::Disabled)
            .with_advertise_direct_addrs(false)
            .with_port_mapping(false),
        None,
    )
    .await
    .expect("bind hidden");
    assert!(!hidden_listener.local_endpoint().contains("addr="));
}

#[tokio::test]
async fn batch2a_sec20_connect_with_policy_fails_over_past_malicious_direct() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Bind a decoy Direct TCP listener that responds immediately with garbage bytes.
    let decoy = TcpListener::bind("127.0.0.1:0").await.expect("bind decoy");
    let decoy_addr = decoy.local_addr().expect("decoy addr");
    let decoy_task = tokio::spawn(async move {
        let mut sink = Vec::new();
        while let Ok((mut s, _)) = decoy.accept().await {
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            sink.push(s);
        }
    });

    // Real host & paired client over live Relay.
    let relay = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let relay_handle = relay.spawn();

    let host_id = EndpointIdentity::generate()
        .expect("host id")
        .with_host_id("sec20-host");
    let cli_id = Arc::new(
        EndpointIdentity::generate()
            .expect("cli id")
            .with_host_id("sec20-cli"),
    );

    let mut host_roster = Roster::new();
    host_roster
        .insert_pinned_host(
            cli_id.device_id(),
            "cli".to_owned(),
            *cli_id.static_key().public_bytes(),
            Some(cli_id.signing_key().public_key().clone()),
            cli_id.rotation_seq(),
            Vec::new(),
        )
        .expect("pin cli");

    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host_id.host_id().to_owned(),
            "host".to_owned(),
            *host_id.static_key().public_bytes(),
            Some(host_id.signing_key().public_key().clone()),
            host_id.rotation_seq(),
            Vec::new(),
        )
        .expect("pin host");

    let mut relay_listener = RelayListener::bind(
        relay_handle.ws_url(),
        Some("localhost".to_owned()),
        host_id.signing_key().ed25519_signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await
    .expect("bind relay listener");
    let relay_ep = relay_listener.local_endpoint();

    let srv_task = tokio::spawn(async move {
        let stream = relay_listener.accept().await.expect("accept relay");
        let mut srv_driver =
            SessionDriver::accept(stream, &host_id, &mut host_roster, 1_795_564_800, None)
                .await
                .expect("srv accept noise");
        let ev = srv_driver
            .next_event(1_795_564_800, &mut host_roster)
            .await
            .expect("srv event");
        assert!(matches!(ev, Some(SessionEvent::AppData(d)) if d == b"verified-path"));
    });

    let dialers: Vec<Arc<dyn PathDialer>> = vec![
        Arc::new(DirectDialer::new()),
        Arc::new(RelayDialer::new().with_expected_host("localhost")),
    ];
    let candidates = vec![
        CandidateEndpoint::new(1, ProviderId::Direct, decoy_addr.to_string()),
        CandidateEndpoint::new(2, ProviderId::Relay, relay_ep),
    ];

    // Canceling SessionDriver::connect_with_policy mid-flight must preserve existing roster entries.
    let silent_decoy = TcpListener::bind("127.0.0.1:0").await.expect("bind silent");
    let silent_addr = silent_decoy.local_addr().expect("silent addr");
    let _silent_hold = tokio::spawn(async move {
        let _s = silent_decoy.accept().await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let canceled = timeout(
        Duration::from_millis(60),
        SessionDriver::connect_with_policy(
            &dialers,
            PathPolicyConfig::default(),
            vec![CandidateEndpoint::new(
                1,
                ProviderId::Direct,
                silent_addr.to_string(),
            )],
            Arc::clone(&cli_id),
            "sec20-host",
            None,
            &mut cli_roster,
            1_795_564_800,
        ),
    )
    .await;
    assert!(canceled.is_err(), "expected timeout cancel");
    assert!(
        cli_roster.get("sec20-host").is_some(),
        "canceling connect_with_policy must not wipe caller roster"
    );

    let (winner, mut cli_driver) = SessionDriver::connect_with_policy(
        &dialers,
        PathPolicyConfig::default(),
        candidates,
        Arc::clone(&cli_id),
        "sec20-host",
        None,
        &mut cli_roster,
        1_795_564_800,
    )
    .await
    .expect("connect_with_policy must fail over to Noise-authenticated relay");
    assert_eq!(winner.provider, ProviderId::Relay);
    cli_driver
        .send_data(b"verified-path")
        .await
        .expect("send data");
    srv_task.await.expect("srv join");

    decoy_task.abort();
    relay_handle.stop().await.expect("stop relay");
}

#[cfg(unix)]
#[tokio::test]
async fn batch2a_sec26_unix_socket_and_store_hardening() {
    let tmp = TempDir::new().expect("tempdir");

    // 1. Refuse to unlink pre-existing regular files and symlinks.
    let reg_file = tmp.path().join("important.txt");
    std::fs::write(&reg_file, "do-not-delete").expect("write reg file");
    assert!(matches!(
        LocalListener::bind(&reg_file),
        Err(RuntimeError::Storage(_))
    ));
    assert_eq!(
        std::fs::read_to_string(&reg_file).expect("read intact"),
        "do-not-delete"
    );

    let sym_sock = tmp.path().join("sym.sock");
    std::os::unix::fs::symlink(&reg_file, &sym_sock).expect("symlink");
    assert!(matches!(
        LocalListener::bind(&sym_sock),
        Err(RuntimeError::Storage(_))
    ));
    assert!(matches!(
        OverlayHelperListener::bind(&sym_sock),
        Err(RuntimeError::Storage(_))
    ));

    // 2. Binding inside a 0o755 parent uses staging without chmod-ing parent; socket is 0o600 and dialable.
    let shared_dir = tmp.path().join("shared755");
    std::fs::create_dir(&shared_dir).expect("mkdir shared");
    std::fs::set_permissions(&shared_dir, std::fs::Permissions::from_mode(0o755))
        .expect("chmod 755");
    let sock_path = shared_dir.join("ipc.sock");
    let mut local_listener = LocalListener::bind(&sock_path).expect("bind local in 755");
    let parent_mode = std::fs::symlink_metadata(&shared_dir)
        .expect("parent meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o755);
    let sock_mode = std::fs::symlink_metadata(&sock_path)
        .expect("sock meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(sock_mode, 0o600);
    let local_dialer = LocalDialer::new();
    let (cli, srv) = tokio::join!(local_dialer.connect(&sock_path), local_listener.accept());
    assert_eq!(cli.expect("cli").provider_id(), ProviderId::Local);
    assert_eq!(srv.expect("srv").provider_id(), ProviderId::Local);

    // 3. StateStore rejects group/world-readable modes & symlinks, and serializes concurrent init.
    let store_dir = tmp.path().join("store");
    let store = StateStore::open_or_create(&store_dir).expect("open store");
    let id = store
        .load_or_generate_identity(Some("sec26-host"))
        .expect("gen");
    std::fs::set_permissions(
        store.identity_path(),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("weaken mode");
    assert!(matches!(
        store.load_identity(),
        Err(RuntimeError::Storage(_))
    ));
    std::fs::remove_file(store.identity_path()).expect("rm id");
    std::os::unix::fs::symlink(&reg_file, store.identity_path()).expect("id symlink");
    assert!(matches!(
        store.load_identity(),
        Err(RuntimeError::Storage(_))
    ));
    std::os::unix::fs::symlink(&reg_file, store.roster_path()).expect("roster symlink");
    assert!(matches!(store.load_roster(), Err(RuntimeError::Storage(_))));
    let _ = id;

    let conc_dir = tmp.path().join("conc-store");
    let mut threads = Vec::new();
    for _ in 0..4 {
        let p = conc_dir.clone();
        threads.push(std::thread::spawn(move || {
            StateStore::open_or_create(&p)
                .expect("open")
                .load_or_generate_identity(Some("conc-host"))
                .expect("load_or_gen")
                .device_id()
        }));
    }
    let ids: Vec<String> = threads
        .into_iter()
        .map(|h| h.join().expect("thread join"))
        .collect();
    assert!(ids.iter().all(|d| d == &ids[0]));
}

#[allow(deprecated)]
#[tokio::test]
async fn batch2a_sec30_drive_pair_initiator_times_out_on_stalled_peer() {
    use tendril_runtime::drive_pair_initiator_with_timeout;

    let mut listener = DirectListener::bind("127.0.0.1:0".parse().expect("addr"), None)
        .await
        .expect("bind");
    let ep = listener.local_endpoint();
    let hold = tokio::spawn(async move {
        let _s = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let id = EndpointIdentity::generate().expect("id");
    let mut cli = DirectDialer::new().dial(&ep).await.expect("dial");
    let started = Instant::now();
    let res = drive_pair_initiator_with_timeout(
        cli.as_mut(),
        &id,
        "dev".to_owned(),
        "cli".to_owned(),
        "TND-1234-5678".to_owned(),
        None,
        Duration::from_millis(120),
    )
    .await;
    assert!(matches!(res, Err(RuntimeError::Timeout(_))));
    assert!(started.elapsed() < Duration::from_secs(1));
    hold.abort();
}

#[tokio::test]
async fn batch2b_sec17_sec31_concurrent_session_and_fresh_now_unix() {
    use std::sync::atomic::{AtomicU64, Ordering};

    for provider in [
        ProviderId::Direct,
        ProviderId::Relay,
        #[cfg(feature = "p2p-iroh")]
        ProviderId::P2p,
    ] {
        let mut pair = setup_provider(provider).await;
        let ep = pair.endpoint.clone();
        let (acc_s, dial_s) = tokio::join!(pair.listener.accept(), pair.dialer.dial(&ep));
        let acc_s = acc_s.expect("accept");
        let dial_s = dial_s.expect("dial");

        let host_id = EndpointIdentity::generate()
            .unwrap()
            .with_host_id("conc-host");
        let cli_id = EndpointIdentity::generate().unwrap();
        let mut host_roster = Roster::new();
        host_roster
            .insert_pinned_host(
                cli_id.device_id(),
                "cli".to_owned(),
                *cli_id.static_key().public_bytes(),
                Some(cli_id.signing_key().public_key().clone()),
                0,
                Vec::new(),
            )
            .unwrap();
        let mut cli_roster = Roster::new();
        cli_roster
            .insert_pinned_host(
                "conc-host".to_owned(),
                "conc-host".to_owned(),
                *host_id.static_key().public_bytes(),
                Some(host_id.signing_key().public_key().clone()),
                0,
                Vec::new(),
            )
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let grant = host_roster
            .mint_grant(
                &host_id,
                &cli_id.device_id(),
                vec!["fs.read".to_owned()],
                now.saturating_sub(10),
                now + 600,
                random_bytes::<16>().unwrap(),
            )
            .unwrap();

        let (host_drv, cli_drv) = tokio::join!(
            SessionDriver::accept(acc_s, &host_id, &mut host_roster, now, None),
            SessionDriver::connect(
                dial_s,
                &cli_id,
                "conc-host",
                Some(grant),
                &mut cli_roster,
                now
            )
        );
        let host_conc: Arc<ConcurrentSession> =
            Arc::new(host_drv.expect("host accept").into_concurrent());
        let cli_conc: Arc<ConcurrentSession> =
            Arc::new(cli_drv.expect("cli connect").into_concurrent());
        let host_roster_mux = Arc::new(Mutex::new(host_roster));

        // Concurrent AB-BA stress check: stream inbound frames into next_event_locked_now while
        // hammer-calling authorize_locked on the same host session + shared Mutex<Roster>.
        if provider == ProviderId::Direct {
            let drain_hr = Arc::clone(&host_roster_mux);
            let drain_hc = Arc::clone(&host_conc);
            let recv_loop = tokio::spawn(async move {
                let mut seen = 0usize;
                while seen < 32 {
                    match drain_hc.next_event_locked_now(&drain_hr).await {
                        Ok(Some(SessionEvent::AppData(_))) => seen += 1,
                        Ok(Some(_)) => {}
                        other => panic!("unexpected stress event: {other:?}"),
                    }
                }
            });
            let auth_hr = Arc::clone(&host_roster_mux);
            let auth_hc = Arc::clone(&host_conc);
            let auth_loop = tokio::spawn(async move {
                for _ in 0..200 {
                    assert!(auth_hc.authorize_locked("fs.read", now, &auth_hr).0.is_ok());
                    tokio::task::yield_now().await;
                }
            });
            for i in 0..32u8 {
                cli_conc.send_data(&[i; 32]).await.expect("cli stress send");
            }
            timeout(Duration::from_secs(15), recv_loop)
                .await
                .expect("stress recv timed out (possible deadlock)")
                .expect("recv join");
            timeout(Duration::from_secs(15), auth_loop)
                .await
                .expect("stress auth timed out (possible deadlock)")
                .expect("auth join");
        }

        let hc = Arc::clone(&host_conc);
        let hr = Arc::clone(&host_roster_mux);
        let poll_task = tokio::spawn(async move {
            timeout(Duration::from_secs(5), hc.next_event_locked_now(&hr)).await
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        let t0 = Instant::now();
        assert!(
            host_conc
                .authorize_locked("fs.read", now, &host_roster_mux)
                .0
                .is_ok()
        );
        host_conc
            .send_data(b"full-duplex-host")
            .await
            .expect("send while polling");
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "concurrent write/auth stalled on {provider:?}"
        );

        let cli_roster_mux = Arc::new(Mutex::new(cli_roster));
        let ev_cli = timeout(
            Duration::from_secs(2),
            cli_conc.next_event_locked_now(&cli_roster_mux),
        )
        .await
        .expect("cli recv")
        .expect("ok")
        .expect("some");
        assert_eq!(ev_cli, SessionEvent::AppData(b"full-duplex-host".to_vec()));

        host_conc.shutdown();
        let poll_res = poll_task
            .await
            .expect("join")
            .expect("no timeout")
            .expect("ok");
        assert!(
            poll_res.is_none(),
            "shutdown must unblock poll with None on {provider:?}"
        );
    }

    // SEC-31: ConcurrentSession and SessionDriver sample fresh now_unix when frame arrives.
    let mut pair = setup_provider(ProviderId::Direct).await;
    let ep = pair.endpoint.clone();
    let (acc_s, dial_s) = tokio::join!(pair.listener.accept(), pair.dialer.dial(&ep));
    let host_id = EndpointIdentity::generate()
        .unwrap()
        .with_host_id("exp-host");
    let cli_id = EndpointIdentity::generate().unwrap();
    let mut host_roster = Roster::new();
    host_roster
        .insert_pinned_host(
            cli_id.device_id(),
            "cli".to_owned(),
            *cli_id.static_key().public_bytes(),
            Some(cli_id.signing_key().public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            "exp-host".to_owned(),
            "exp-host".to_owned(),
            *host_id.static_key().public_bytes(),
            Some(host_id.signing_key().public_key().clone()),
            0,
            Vec::new(),
        )
        .unwrap();
    let base_now = 1_795_564_800u64;
    let grant = host_roster
        .mint_grant(
            &host_id,
            &cli_id.device_id(),
            vec!["fs.read".to_owned()],
            base_now - 10,
            base_now + 5,
            random_bytes::<16>().unwrap(),
        )
        .unwrap();
    let (host_drv, cli_drv) = tokio::join!(
        SessionDriver::accept(acc_s.unwrap(), &host_id, &mut host_roster, base_now, None),
        SessionDriver::connect(
            dial_s.unwrap(),
            &cli_id,
            "exp-host",
            Some(grant),
            &mut cli_roster,
            base_now
        )
    );
    let host_conc = host_drv.unwrap().into_concurrent();
    let cli_conc = cli_drv.unwrap().into_concurrent();
    let host_roster_mux = Arc::new(Mutex::new(host_roster));

    let fake_clock = Arc::new(AtomicU64::new(base_now));
    let clock_c = Arc::clone(&fake_clock);
    let poll_fut =
        host_conc.next_event_with_clock(&host_roster_mux, move || clock_c.load(Ordering::SeqCst));
    tokio::pin!(poll_fut);
    tokio::select! {
        _ = &mut poll_fut => panic!("unexpected early completion"),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {
            fake_clock.store(base_now + 20, Ordering::SeqCst);
            cli_conc.send_rekey().await.unwrap();
        }
    }
    let res = timeout(Duration::from_secs(2), poll_fut)
        .await
        .expect("timeout");
    assert!(
        res.is_err(),
        "expired grant must be rejected on REKEY when clock advanced mid-poll"
    );
}

#[tokio::test]
async fn ws_binary_path_stream_rejects_zero_byte_binary_frame() {
    use futures_util::SinkExt;
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let mut bl = BrokerListener::bind(BrokerServerConfig::default())
        .await
        .expect("bind broker");
    let url = format!("ws://{}/tendril/v1/stream", bl.local_addr());
    let (mut cli_ws, _) = connect_async(&url).await.expect("connect ws");
    let mut srv_stream = bl.accept().await.expect("accept broker stream");

    cli_ws
        .send(Message::Binary(Vec::new().into()))
        .await
        .expect("send 0-byte frame");
    let mut buf = [0u8; 64];
    let err = timeout(Duration::from_secs(2), srv_stream.recv_chunk(&mut buf))
        .await
        .expect("recv before timeout")
        .expect_err("0-byte binary frame must fail closed");
    assert!(
        matches!(err, RuntimeError::Protocol(_)),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn overlay_listener_requires_tailnet_by_default_and_helper_is_non_blocking() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpStream, UnixStream};

    let mut default_ol = OverlayListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)), None)
        .await
        .expect("bind default overlay");
    let ol_addr = default_ol.local_addr();
    let _loopback_probe = TcpStream::connect(ol_addr).await.expect("connect loopback");
    assert!(
        timeout(Duration::from_millis(120), default_ol.accept())
            .await
            .is_err(),
        "default OverlayListener must drop non-tailnet loopback sources"
    );

    let mut permissive_ol = OverlayListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)), None)
        .await
        .expect("bind permissive overlay")
        .with_allow_non_tailnet(true);
    let p_addr = permissive_ol.local_addr();
    let _cli = OverlayDialer::new()
        .with_connect_timeout(Duration::from_secs(2))
        .dial(&format!("overlay://{p_addr}"))
        .await
        .expect("dial permissive overlay");
    let accepted = timeout(Duration::from_secs(2), permissive_ol.accept())
        .await
        .expect("accept timeout")
        .expect("accept stream");
    assert_eq!(accepted.provider_id(), ProviderId::Overlay);

    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("accept.sock");
    let mut helper = OverlayHelperListener::bind(&sock).expect("bind helper");

    let _stalled = UnixStream::connect(&sock).await.expect("connect stalled");
    let mut valid = UnixStream::connect(&sock).await.expect("connect valid");
    valid
        .write_all(b"{\"op\":\"accept\",\"peer_ip\":\"100.64.0.20\"}\n")
        .await
        .expect("write valid ctrl");

    let stream = timeout(Duration::from_secs(1), helper.accept())
        .await
        .expect("stalled helper must not block valid accept")
        .expect("accept valid helper stream");
    assert_eq!(stream.peer_ip(), Some("100.64.0.20".parse().expect("ip")));
}

#[tokio::test]
async fn broker_dialer_debug_redacts_secrets_and_direct_dialer_timeout_works() {
    use tokio::net::TcpListener;

    let dialer = BrokerDialer::new().with_header("Authorization", "Bearer super-secret-token");
    let dbg = format!("{dialer:?}");
    assert!(dbg.contains("Authorization"));
    assert!(dbg.contains("<redacted>"));
    assert!(!dbg.contains("super-secret-token"));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let stream = DirectDialer::new()
        .with_connect_timeout(Duration::from_secs(2))
        .connect(addr)
        .await
        .expect("connect direct with timeout");
    assert_eq!(stream.provider_id(), ProviderId::Direct);
}

#[tokio::test]
async fn relay_client_auth_v1_and_v2_hmac_and_tickets_end_to_end() {
    use tendril_core::relay_auth::{
        RelayAuthRole, RelayAuthScope, RelayAuthSecret, mint_relay_ticket,
    };
    use tendril_runtime::{
        RelayClientAuth, RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig,
        dial_endpoint_with_auth,
    };

    let shared_secret = RelayAuthSecret::from_bytes(b"runtime-relay-client-auth-secret").unwrap();
    let issuer_kp = SigningKeypair::generate().unwrap();
    let issuer_sk = issuer_kp.ed25519_signing_key();
    let issuer_pub = issuer_sk.verifying_key().to_bytes();

    // Redaction check on RelayClientAuth::Debug.
    let hmac_auth = RelayClientAuth::HmacSecret(shared_secret.clone());
    let dbg = format!("{hmac_auth:?}");
    assert!(dbg.contains("<redacted>"));
    assert!(!dbg.contains("runtime-relay-client-auth-secret"));

    let relay = RelayServer::bind(RelayConfig {
        host: "relay.example".to_owned(),
        auth_secret: Some(zeroize::Zeroizing::new(shared_secret.as_bytes().to_vec())),
        trusted_issuers: vec![issuer_pub],
        auth_scope: RelayAuthScope::All,
        ..RelayConfig::default()
    })
    .await
    .unwrap()
    .spawn();

    // 1. v1 RelayListener + RelayDialer + dial_endpoint_with_auth with HMAC and Ticket.
    let listener_kp = SigningKeypair::generate().unwrap();
    let unauth_listener = RelayListener::bind(
        relay.ws_url(),
        Some("relay.example".to_owned()),
        listener_kp.ed25519_signing_key(),
        DEFAULT_WRITE_TIMEOUT,
    )
    .await;
    assert!(unauth_listener.is_err());

    let mut listener = RelayListener::bind_with_auth(
        relay.ws_url(),
        Some("relay.example".to_owned()),
        listener_kp.ed25519_signing_key(),
        DEFAULT_WRITE_TIMEOUT,
        hmac_auth.clone(),
    )
    .await
    .expect("bind authenticated v1 listener");
    let ep = listener.local_endpoint();

    let unauth_dial = RelayDialer::new()
        .with_expected_host("relay.example")
        .dial(&ep)
        .await;
    assert!(unauth_dial.is_err());

    let now_u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dial_ticket = mint_relay_ticket(
        &issuer_sk,
        "relay.example",
        RelayAuthRole::Dial,
        listener.mailbox_pub_b64(),
        now_u64,
        60,
    )
    .unwrap();

    let (acc_res, dial_res) = tokio::join!(
        listener.accept(),
        dial_endpoint_with_auth(
            &ep,
            Some("relay.example"),
            RelayClientAuth::Ticket(dial_ticket),
        ),
    );
    let mut srv_s = acc_res.expect("accept v1");
    let mut cli_s = dial_res.expect("dial v1");
    send_tendril_frame(cli_s.as_mut(), b"v1-auth-ok")
        .await
        .unwrap();
    let mut rd = ResumableFrameReader::new();
    assert_eq!(
        recv_tendril_frame(srv_s.as_mut(), &mut rd).await.unwrap(),
        b"v1-auth-ok"
    );
    drop((srv_s, cli_s, listener));

    // 2. v2 RelayV2Listener + RelayV2Dialer with HMAC & Ticket.
    let mb_secret = [0x9A; 32];
    let unauth_v2 = RelayV2Listener::bind(
        relay.ws_v2_url(),
        Some("relay.example".to_owned()),
        mb_secret,
        DEFAULT_WRITE_TIMEOUT,
    )
    .await;
    assert!(unauth_v2.is_err());

    let mut v2_listener = RelayV2Listener::bind_with_auth(
        relay.ws_v2_url(),
        Some("relay.example".to_owned()),
        mb_secret,
        DEFAULT_WRITE_TIMEOUT,
        hmac_auth.clone(),
    )
    .await
    .expect("bind authenticated v2 listener");
    let v2_ep = v2_listener.local_endpoint();

    let unauth_v2_dial = RelayV2Dialer::new(mb_secret)
        .with_expected_host("relay.example")
        .dial(&v2_ep)
        .await;
    assert!(unauth_v2_dial.is_err());

    let v2_dialer = RelayV2Dialer::new(mb_secret)
        .with_expected_host("relay.example")
        .with_auth(hmac_auth);
    let (v2_acc_res, v2_dial_res) = tokio::join!(v2_listener.accept(), v2_dialer.dial(&v2_ep));
    let mut v2_srv = v2_acc_res.expect("accept v2");
    let mut v2_cli = v2_dial_res.expect("dial v2");
    send_tendril_frame(v2_cli.as_mut(), b"v2-auth-ok")
        .await
        .unwrap();
    let mut rd2 = ResumableFrameReader::new();
    assert_eq!(
        recv_tendril_frame(v2_srv.as_mut(), &mut rd2).await.unwrap(),
        b"v2-auth-ok"
    );

    let _ = RelayV2ListenerConfig::default();
    drop((v2_srv, v2_cli, v2_listener));
    relay.stop().await.unwrap();
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn p2p_custom_many_validation_and_live_gated_iroh_relay_pairing_and_rekey() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tendril_core::roster::Roster;
    use tendril_core::session::RekeyDirection;
    use tendril_runtime::{
        MAX_P2P_CUSTOM_RELAYS, P2pOptions, P2pRelayAuth, V2ResponderState, V2SessionDriver,
        drive_v2_pake_pair_initiator, drive_v2_pake_pair_responder, parse_p2p_relay_modes,
    };
    use zeroize::Zeroizing;

    // 1. parse_p2p_relay_modes & P2pOptions validation.
    assert!(parse_p2p_relay_modes(&[]).is_err());
    assert_eq!(
        parse_p2p_relay_modes(&["https://r1.example".to_owned()]).unwrap(),
        P2pRelayMode::Custom("https://r1.example/".to_owned())
    );
    let many_urls: Vec<String> = (1..=MAX_P2P_CUSTOM_RELAYS)
        .map(|i| format!("https://r{i}.example/"))
        .collect();
    assert_eq!(
        parse_p2p_relay_modes(&many_urls).unwrap(),
        P2pRelayMode::CustomMany(many_urls.clone())
    );
    let too_many: Vec<String> = (1..=MAX_P2P_CUSTOM_RELAYS + 1)
        .map(|i| format!("https://r{i}.example/"))
        .collect();
    assert!(parse_p2p_relay_modes(&too_many).is_err());

    let auth_tok =
        P2pRelayAuth::BearerToken(Zeroizing::new("super-secret-bearer-token".to_owned()));
    let dbg = format!("{auth_tok:?}");
    assert!(dbg.contains("<redacted>"));
    assert!(!dbg.contains("super-secret-bearer-token"));

    assert!(
        P2pListener::bind_with_options(
            P2pOptions::for_listener(P2pRelayMode::Disabled)
                .with_relay_auth(Some(auth_tok.clone())),
            None,
        )
        .await
        .is_err()
    );
    assert!(
        P2pListener::bind_with_options(
            P2pOptions::for_listener(P2pRelayMode::Custom("https://r1.example".to_owned()))
                .with_relay_auth(Some(P2pRelayAuth::BearerToken(Zeroizing::new(
                    String::new()
                )))),
            None,
        )
        .await
        .is_err()
    );
    assert!(
        P2pListener::bind_with_options(
            P2pOptions::for_listener(P2pRelayMode::Custom("https://r1.example".to_owned()))
                .with_relay_auth(Some(P2pRelayAuth::BearerToken(Zeroizing::new(
                    "bad\ntoken".to_owned()
                )))),
            None,
        )
        .await
        .is_err()
    );
    assert!(
        P2pListener::bind_with_options(
            P2pOptions::for_listener(P2pRelayMode::Custom("https://r1.example".to_owned()))
                .with_relay_auth(Some(P2pRelayAuth::BearerToken(Zeroizing::new(
                    "a".repeat(4097)
                )))),
            None,
        )
        .await
        .is_err()
    );

    // 2. Spawn live in-process iroh_relay::server::Server requiring Bearer token.
    #[derive(Debug)]
    struct BearerAccess {
        expected: String,
        seen_good: Arc<AtomicUsize>,
        seen_bad: Arc<AtomicUsize>,
    }

    impl iroh_relay::server::AccessControl for BearerAccess {
        async fn on_connect(
            &self,
            request: &iroh_relay::server::ClientRequest,
        ) -> iroh_relay::server::Access {
            if request.auth_token().as_deref() == Some(self.expected.as_str()) {
                self.seen_good.fetch_add(1, Ordering::AcqRel);
                iroh_relay::server::Access::Allow
            } else {
                self.seen_bad.fetch_add(1, Ordering::AcqRel);
                iroh_relay::server::Access::Deny {
                    reason: Some("invalid token".to_owned()),
                }
            }
        }
    }

    let seen_good = Arc::new(AtomicUsize::new(0));
    let seen_bad = Arc::new(AtomicUsize::new(0));
    let mut relay_cfg =
        iroh_relay::server::RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    relay_cfg.key_cache_capacity = Some(1024);
    relay_cfg.access = Arc::new(BearerAccess {
        expected: "super-secret-bearer-token".to_owned(),
        seen_good: Arc::clone(&seen_good),
        seen_bad: Arc::clone(&seen_bad),
    });
    let mut server_cfg = iroh_relay::server::ServerConfig::default();
    server_cfg.relay = Some(relay_cfg);
    let iroh_srv = iroh_relay::server::Server::spawn(server_cfg)
        .await
        .expect("spawn iroh-relay server");
    let live_relay_url = format!("http://{}", iroh_srv.http_addr().expect("http addr"));

    // A held dead port so CustomMany([dead, live]) fails over to live.
    let dead = DeadPort::new();
    let dead_url = format!("http://{}", dead.addr);

    let custom_many = parse_p2p_relay_modes(&[dead_url, live_relay_url.clone()]).unwrap();
    assert!(matches!(custom_many, P2pRelayMode::CustomMany(_)));

    // Negative control: wrong token cannot authenticate to the gated relay and cannot pair over relay-only.
    let bad_auth = P2pRelayAuth::BearerToken(Zeroizing::new("wrong-bearer-token".to_owned()));
    let bad_listener = P2pListener::bind_with_options(
        P2pOptions::for_listener(custom_many.clone())
            .with_relay_auth(Some(bad_auth.clone()))
            .with_port_mapping(false),
        None,
    )
    .await
    .expect("bind bad listener");
    let bad_ep = bad_listener.local_endpoint();
    assert!(!bad_ep.contains("wrong-bearer-token"));
    let bad_dialer = P2pDialer::bind_with_options(
        P2pOptions::for_dialer(custom_many.clone())
            .with_relay_auth(Some(bad_auth))
            .with_port_mapping(false),
    )
    .await
    .expect("bind bad dialer");
    // Ensure wrong-token endpoint cannot connect via the relay (with direct addrs stripped/disabled).
    let stripped_ep = format!(
        "iroh://{}?relay={live_relay_url}/",
        bad_listener.endpoint_id()
    );
    let bad_dial_res = timeout(Duration::from_millis(600), bad_dialer.dial(&stripped_ep)).await;
    assert!(
        !matches!(bad_dial_res, Ok(Ok(_))),
        "wrong-token dial must not succeed"
    );
    assert!(seen_bad.load(Ordering::Acquire) > 0);
    assert_eq!(seen_good.load(Ordering::Acquire), 0);
    drop(bad_listener);
    bad_dialer.close().await;

    // Positive control: CustomMany + valid BearerToken completes Noise_XXhfs pairing + grant + REKEY.
    let srv_opts = P2pOptions::for_listener(custom_many.clone())
        .with_relay_auth(Some(auth_tok.clone()))
        .with_port_mapping(false);
    assert!(!srv_opts.publish_pkarr);
    assert!(!srv_opts.resolve_pkarr);
    assert!(!srv_opts.advertise_direct_addrs);
    let mut listener = P2pListener::bind_with_options(srv_opts, None)
        .await
        .expect("bind gated p2p listener");

    // Wait briefly until the endpoint homes onto the live relay URL.
    let mut listener_ep = listener.local_endpoint();
    for _ in 0..30 {
        if listener_ep.contains("?relay=") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        listener_ep = listener.current_endpoint();
    }
    assert!(!listener_ep.contains("super-secret-bearer-token"));
    assert!(
        listener_ep.contains("?relay="),
        "expected relay hint in {listener_ep}"
    );

    let cli_opts = P2pOptions::for_dialer(custom_many)
        .with_relay_auth(Some(auth_tok))
        .with_port_mapping(false);
    let dialer = P2pDialer::bind_with_options(cli_opts)
        .await
        .expect("bind gated p2p dialer");

    let host_id = EndpointIdentity::generate()
        .unwrap()
        .with_host_id("p2p-host");
    let cli_id = EndpointIdentity::generate().unwrap();
    let now_unix = 1_795_132_800;
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, now_unix)
        .unwrap();
    let mgr = Arc::new(Mutex::new(mgr));
    let host_rst = Arc::new(Mutex::new(Roster::new()));
    let v2_state = Arc::new(V2ResponderState::new());

    // 1) PAKE pairing over gated custom relay.
    let host_c = host_id.clone();
    let mgr_c = Arc::clone(&mgr);
    let rst_c = Arc::clone(&host_rst);
    let state_c = Arc::clone(&v2_state);
    let ep_pair = listener_ep.clone();
    let srv_pair_task = tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        let res = drive_v2_pake_pair_responder(
            s.as_mut(),
            &host_c,
            &mgr_c,
            &rst_c,
            PairingPathKind::Remote,
            now_unix,
            &state_c,
            None,
        )
        .await
        .unwrap();
        (listener, res)
    });

    let mut pair_cli_s = dialer
        .dial(&ep_pair)
        .await
        .expect("dial pair over gated relay");
    let init_pair = drive_v2_pake_pair_initiator(
        pair_cli_s.as_mut(),
        &cli_id,
        "Workstation".to_owned(),
        "cli".to_owned(),
        code,
        None,
    )
    .await
    .unwrap();
    let (mut listener, resp_pair) = srv_pair_task.await.unwrap();
    assert_eq!(init_pair.sas, resp_pair.sas);
    drop(pair_cli_s);

    // 2) Confirm peer, mint grant, and run Noise_XXhfs session + REKEY over gated relay.
    let cli_dev = cli_id.device_id();
    let grant = {
        let mut rst = host_rst.lock().unwrap();
        rst.confirm_peer(&cli_dev, init_pair.sas.as_deref())
            .unwrap();
        rst.mint_grant(
            &host_id,
            &cli_dev,
            vec!["fs.read:/docs/*".to_owned()],
            now_unix,
            now_unix + 3600,
            [0x33; 16],
        )
        .unwrap()
    };
    let mut cli_rst = Roster::new();
    let v2_secrets = host_rst
        .lock()
        .unwrap()
        .get(&cli_dev)
        .unwrap()
        .v2_secrets
        .clone()
        .unwrap();
    cli_rst
        .insert_pinned_host(
            host_id.host_id().to_owned(),
            "Host".to_owned(),
            *host_id.static_key().public_bytes(),
            Some(host_id.signing_key().public_key().clone()),
            host_id.rotation_seq(),
            vec![],
        )
        .unwrap();
    cli_rst
        .upgrade_peer_to_v2(host_id.host_id(), v2_secrets)
        .unwrap();

    let host_c2 = host_id.clone();
    let rst_c2 = Arc::clone(&host_rst);
    let state_c2 = Arc::clone(&v2_state);
    let srv_sess_task = tokio::spawn(async move {
        let s = listener.accept().await.unwrap();
        let mut hr = rst_c2.lock().unwrap().clone();
        let mut drv = V2SessionDriver::accept(s, &host_c2, &mut hr, now_unix, &state_c2, None)
            .await
            .unwrap();
        assert_eq!(
            drv.next_event(now_unix, &mut hr).await.unwrap(),
            Some(SessionEvent::Rekeyed {
                direction: RekeyDirection::Incoming,
            })
        );
        assert_eq!(
            drv.next_event(now_unix, &mut hr).await.unwrap(),
            Some(SessionEvent::AppData(b"p2p-gated-rekey-ok".to_vec()))
        );
        (listener, drv)
    });

    let sess_cli_s = dialer
        .dial(&listener_ep)
        .await
        .expect("dial sess over gated relay");
    let mut cli_drv = V2SessionDriver::connect(
        sess_cli_s,
        &cli_id,
        host_id.host_id(),
        Some(grant),
        &mut cli_rst,
        now_unix,
    )
    .await
    .unwrap();
    cli_drv.send_rekey().await.unwrap();
    cli_drv.send_data(b"p2p-gated-rekey-ok").await.unwrap();
    assert_eq!(
        cli_drv.next_event(now_unix, &mut cli_rst).await.unwrap(),
        Some(SessionEvent::Rekeyed {
            direction: RekeyDirection::Outgoing,
        })
    );

    let (listener, _srv_drv) = srv_sess_task.await.unwrap();
    assert!(seen_good.load(Ordering::Acquire) >= 2);
    drop((cli_drv, listener));
    dialer.close().await;
    let _ = iroh_srv.shutdown().await;
}

#[cfg(feature = "p2p-iroh-services")]
#[tokio::test]
async fn p2p_iroh_services_derives_rcan_token_on_custom_many_without_pkarr_leak() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tendril_runtime::{P2pOptions, P2pRelayAuth, parse_p2p_relay_modes};
    use zeroize::Zeroizing;

    let api_secret_sk = iroh::SecretKey::from_bytes(&[0x44; 32]);
    let svc_peer_id = iroh::SecretKey::from_bytes(&[0x45; 32]).public();
    let api_secret = iroh_services::api_secret::ApiSecret::new(api_secret_sk, svc_peer_id);
    let api_secret_str = api_secret.to_string();

    #[derive(Debug)]
    struct RcanAccess {
        saw_valid_rcan: Arc<AtomicBool>,
    }

    impl iroh_relay::server::AccessControl for RcanAccess {
        async fn on_connect(
            &self,
            request: &iroh_relay::server::ClientRequest,
        ) -> iroh_relay::server::Access {
            let Some(tok) = request.auth_token() else {
                return iroh_relay::server::Access::Deny {
                    reason: Some("missing token".to_owned()),
                };
            };
            let Ok(decoded) =
                data_encoding::BASE32_NOPAD.decode(tok.to_ascii_uppercase().as_bytes())
            else {
                return iroh_relay::server::Access::Deny {
                    reason: Some("invalid base32 RCAN".to_owned()),
                };
            };
            if decoded.is_empty() {
                return iroh_relay::server::Access::Deny {
                    reason: Some("empty RCAN".to_owned()),
                };
            }
            self.saw_valid_rcan.store(true, Ordering::Release);
            iroh_relay::server::Access::Allow
        }
    }

    let saw_valid_rcan = Arc::new(AtomicBool::new(false));
    let mut relay_cfg =
        iroh_relay::server::RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    relay_cfg.key_cache_capacity = Some(1024);
    relay_cfg.access = Arc::new(RcanAccess {
        saw_valid_rcan: Arc::clone(&saw_valid_rcan),
    });
    let mut server_cfg = iroh_relay::server::ServerConfig::default();
    server_cfg.relay = Some(relay_cfg);
    let iroh_srv = iroh_relay::server::Server::spawn(server_cfg)
        .await
        .expect("spawn iroh-relay server");
    let live_relay_url = format!("http://{}", iroh_srv.http_addr().expect("http addr"));

    let dead = DeadPort::new();
    let dead_url = format!("http://{}", dead.addr);

    let mode = parse_p2p_relay_modes(&[dead_url, live_relay_url]).unwrap();
    let auth = P2pRelayAuth::IrohServicesSecret(Zeroizing::new(api_secret_str.clone()));
    assert!(format!("{auth:?}").contains("<redacted>"));
    assert!(!format!("{auth:?}").contains(&api_secret_str));

    let opts = P2pOptions::for_listener(mode)
        .with_relay_auth(Some(auth))
        .with_port_mapping(false);
    assert!(!opts.publish_pkarr);
    assert!(!opts.resolve_pkarr);

    let listener = P2pListener::bind_with_options(opts, None)
        .await
        .expect("bind iroh-services p2p listener");

    for _ in 0..40 {
        if saw_valid_rcan.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        saw_valid_rcan.load(Ordering::Acquire),
        "expected iroh-services RCAN token to authenticate against gated relay"
    );
    let ep = listener.local_endpoint();
    assert!(!ep.contains(&api_secret_str));
    drop(listener);
    let _ = iroh_srv.shutdown().await;
}

#[cfg(feature = "p2p-iroh")]
fn loopback_only_options(
    v4: Option<std::net::SocketAddrV4>,
    v6: Option<std::net::SocketAddrV6>,
) -> tendril_runtime::P2pOptions {
    tendril_runtime::P2pOptions::for_listener(P2pRelayMode::Disabled)
        .with_port_mapping(false)
        .with_bind_addrs(tendril_runtime::P2pBindAddrs::Only { v4, v6 })
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn p2p_listener_binds_only_loopback_v4() {
    let v4 = std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let listener = P2pListener::bind_with_options(loopback_only_options(Some(v4), None), None)
        .await
        .expect("bind loopback v4");
    let sockets = listener.bound_sockets();
    assert!(!sockets.is_empty(), "no bound sockets");
    for sock in &sockets {
        assert!(
            matches!(sock, SocketAddr::V4(a) if *a.ip() == Ipv4Addr::LOCALHOST),
            "{sock}"
        );
        assert_ne!(sock.port(), 0);
    }
    drop(listener);
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn p2p_listener_binds_only_loopback_v6() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("skipping: IPv6 loopback is unavailable on this host");
        return;
    }
    let v6 = std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 0, 0, 0);
    let listener = P2pListener::bind_with_options(loopback_only_options(None, Some(v6)), None)
        .await
        .expect("bind loopback v6");
    let sockets = listener.bound_sockets();
    assert!(!sockets.is_empty(), "no bound sockets");
    for sock in &sockets {
        assert!(
            matches!(sock, SocketAddr::V6(a) if *a.ip() == std::net::Ipv6Addr::LOCALHOST),
            "{sock}"
        );
        assert_ne!(sock.port(), 0);
    }
    drop(listener);
}

#[cfg(feature = "p2p-iroh")]
#[tokio::test]
async fn p2p_loopback_bind_round_trip() {
    let v4 = std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let mut listener = P2pListener::bind_with_options(
        loopback_only_options(Some(v4), None).with_advertise_direct_addrs(true),
        None,
    )
    .await
    .expect("bind loopback listener");
    let endpoint = listener.local_endpoint();
    let dialer = P2pDialer::bind_with_options(
        tendril_runtime::P2pOptions::for_dialer(P2pRelayMode::Disabled)
            .with_port_mapping(false)
            .with_bind_addrs(tendril_runtime::P2pBindAddrs::Only {
                v4: Some(v4),
                v6: None,
            }),
    )
    .await
    .expect("bind loopback dialer");
    let dialer_sockets = dialer.bound_sockets();
    assert!(!dialer_sockets.is_empty(), "no dialer sockets");
    assert!(
        dialer_sockets
            .iter()
            .all(|sock| matches!(sock, SocketAddr::V4(a) if *a.ip() == Ipv4Addr::LOCALHOST)),
        "{dialer_sockets:?}"
    );

    let accept = tokio::spawn(async move { (listener.accept().await, listener) });
    let mut client = timeout(Duration::from_secs(20), dialer.dial(&endpoint))
        .await
        .expect("dial timeout")
        .expect("dial");
    let (server, listener) = accept.await.expect("join");
    let mut server = server.expect("accept");
    send_tendril_frame(client.as_mut(), b"ping")
        .await
        .expect("send");
    let mut reader = ResumableFrameReader::new();
    assert_eq!(
        recv_tendril_frame(server.as_mut(), &mut reader)
            .await
            .expect("recv"),
        b"ping"
    );
    send_tendril_frame(server.as_mut(), b"pong")
        .await
        .expect("echo");
    let mut reader = ResumableFrameReader::new();
    assert_eq!(
        recv_tendril_frame(client.as_mut(), &mut reader)
            .await
            .expect("recv echo"),
        b"pong"
    );
    dialer.close().await;
    drop(listener);
}
