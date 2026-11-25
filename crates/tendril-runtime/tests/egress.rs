//! Dial-time egress policy (`providers::egress`) and the lookup-free Iroh hint dialer.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tendril_core::pairing::{PairingCodeKind, PairingPathKind};
use tendril_core::policy::ProviderId;
use tendril_core::roster::RouteSource;
use tendril_runtime::providers::egress::{
    CheckedHint, EgressAddrPolicy, EgressContext, EgressDialer, EgressKind, HintSource,
    HostResolver, SkipReason, SkippedHint, SystemResolver, check_hint,
};
use tendril_runtime::{BrokerDialer, OverlayDialer, PathDialer, RuntimeError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

/// Stub resolver: fixed answers per host, a lookup counter, and hosts that never answer.
#[derive(Default)]
struct StubResolver {
    answers: HashMap<String, Result<Vec<IpAddr>, String>>,
    hang: Vec<String>,
    lookups: AtomicUsize,
}

impl StubResolver {
    fn with(mut self, host: &str, ips: &[&str]) -> Self {
        let ips = ips.iter().map(|ip| ip.parse().expect("ip")).collect();
        self.answers.insert(host.to_owned(), Ok(ips));
        self
    }

    fn failing(mut self, host: &str) -> Self {
        self.answers
            .insert(host.to_owned(), Err("no such host".to_owned()));
        self
    }

    fn hanging(mut self, host: &str) -> Self {
        self.hang.push(host.to_owned());
        self
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl HostResolver for StubResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        if self.hang.iter().any(|h| h == host) {
            std::future::pending::<()>().await;
        }
        match self.answers.get(host) {
            Some(Ok(ips)) => Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect()),
            Some(Err(msg)) => Err(RuntimeError::Protocol(msg.clone())),
            None => Err(RuntimeError::Protocol(format!("unknown stub host {host}"))),
        }
    }
}

fn ctx(kind: EgressKind, resolver: &Arc<StubResolver>) -> EgressContext {
    EgressContext::new(kind).with_resolver(Arc::clone(resolver) as Arc<dyn HostResolver>)
}

fn session(resolver: &Arc<StubResolver>) -> EgressContext {
    ctx(EgressKind::Session, resolver)
}

async fn skipped(hint: &str, source: HintSource, ctx: &EgressContext) -> SkipReason {
    let err: SkippedHint = check_hint(hint, source, ctx)
        .await
        .map(|c| c.dial_endpoint)
        .expect_err(hint);
    assert_eq!(err.hint, hint, "skip keeps the original hint");
    err.reason
}

async fn checked(hint: &str, source: HintSource, ctx: &EgressContext) -> CheckedHint {
    check_hint(hint, source, ctx)
        .await
        .unwrap_or_else(|err| panic!("{hint}: {err:?}"))
}

#[tokio::test]
async fn direct_hints_take_checked_ip_literals_only() {
    let resolver = Arc::new(StubResolver::default());
    let ctx = session(&resolver);
    assert_eq!(
        skipped("direct:relay.example:9100", HintSource::Uri, &ctx).await,
        SkipReason::DirectRequiresIpLiteral
    );
    assert_eq!(
        skipped("relay.example:9100", HintSource::Uri, &ctx).await,
        SkipReason::DirectRequiresIpLiteral
    );
    for blocked in ["direct:240.0.0.1:9", "direct:0.1.2.3:9"] {
        for source in [HintSource::Uri, HintSource::Operator] {
            assert_eq!(
                skipped(blocked, source, &ctx).await,
                SkipReason::BlockedAddress,
                "{blocked} {source:?}"
            );
        }
    }
    let lan = checked("direct:192.168.1.20:9100", HintSource::Uri, &ctx).await;
    assert_eq!(lan.provider, ProviderId::Direct);
    assert_eq!(lan.dial_endpoint, "192.168.1.20:9100");
    assert_eq!(lan.path_class, PairingPathKind::Lan);
    assert!(lan.addr_policy.is_none());
    let public = checked("direct:203.0.113.7:9", HintSource::Uri, &ctx).await;
    assert_eq!(public.path_class, PairingPathKind::Remote);
    let loopback = checked("direct:[::1]:9", HintSource::Uri, &ctx).await;
    assert_eq!(loopback.dial_endpoint, "[::1]:9");
    assert_eq!(loopback.path_class, PairingPathKind::Lan);
    assert_eq!(resolver.lookups(), 0, "direct hints never resolve");
}

#[tokio::test]
async fn ipc_hints_are_operator_only() {
    let resolver = Arc::new(StubResolver::default());
    let ctx = session(&resolver);
    for source in [
        HintSource::Uri,
        HintSource::Stored(RouteSource::Signed),
        HintSource::Stored(RouteSource::Committed),
    ] {
        for hint in ["local:/tmp/tendril.sock", "unix:///tmp/tendril.sock"] {
            assert_eq!(
                skipped(hint, source, &ctx).await,
                SkipReason::IpcFromUri,
                "{hint} {source:?}"
            );
        }
    }
    for source in [
        HintSource::Operator,
        HintSource::Stored(RouteSource::Operator),
    ] {
        let local = checked("local:/tmp/tendril.sock", source, &ctx).await;
        assert_eq!(local.provider, ProviderId::Local);
        assert_eq!(local.dial_endpoint, "/tmp/tendril.sock");
        assert_eq!(local.path_class, PairingPathKind::Lan);
    }
}

#[tokio::test]
async fn lan_code_dials_only_lan_class_paths() {
    let resolver = Arc::new(StubResolver::default().with("tail.example", &["100.101.1.2"]));
    let ctx = ctx(EgressKind::Pairing(PairingCodeKind::Lan2Group), &resolver);
    for hint in [
        "direct:203.0.113.7:9",
        "direct:100.101.1.2:9",
        "overlay://tail.example:9200",
        "overlay://192.168.1.5:9200",
        "wss://relay.example/v1/relay",
        "broker+wss://broker.example/b",
    ] {
        assert_eq!(
            skipped(hint, HintSource::Uri, &ctx).await,
            SkipReason::LanCodeRemoteHint,
            "{hint}"
        );
    }
    assert_eq!(resolver.lookups(), 0, "the guard runs before any lookup");
    assert_eq!(
        checked("direct:10.0.0.2:9", HintSource::Uri, &ctx)
            .await
            .path_class,
        PairingPathKind::Lan
    );
    assert_eq!(
        checked("local:/tmp/t.sock", HintSource::Operator, &ctx)
            .await
            .path_class,
        PairingPathKind::Lan
    );
    let remote = ctx_remote(&resolver);
    assert_eq!(
        checked("overlay://tail.example:9200", HintSource::Uri, &remote)
            .await
            .path_class,
        PairingPathKind::Remote
    );
}

fn ctx_remote(resolver: &Arc<StubResolver>) -> EgressContext {
    ctx(EgressKind::Pairing(PairingCodeKind::Remote3Group), resolver)
}

#[tokio::test]
async fn overlay_names_resolve_once_and_dial_a_checked_literal() {
    let resolver = Arc::new(
        StubResolver::default()
            .with("tail.example", &["100.101.1.2"])
            .with("tail6.example", &["fd7a:115c:a1e0::5"])
            .with("mixed.example", &["10.0.0.1", "169.254.1.1"])
            .with("empty.example", &[])
            .failing("gone.example"),
    );
    let ctx = session(&resolver);
    let hit = checked("overlay://tail.example:9200", HintSource::Uri, &ctx).await;
    assert_eq!(hit.provider, ProviderId::Overlay);
    assert_eq!(hit.dial_endpoint, "overlay://100.101.1.2:9200");
    assert_eq!(
        hit.destinations,
        vec!["100.101.1.2".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(resolver.lookups(), 1, "one lookup per overlay hint");
    assert_eq!(
        checked("overlay://tail6.example:9200", HintSource::Uri, &ctx)
            .await
            .dial_endpoint,
        "overlay://[fd7a:115c:a1e0::5]:9200"
    );
    assert_eq!(
        skipped("overlay://mixed.example:9200", HintSource::Uri, &ctx).await,
        SkipReason::BlockedAddress,
        "one blocked answer rejects the hint"
    );
    assert_eq!(
        skipped("overlay://mixed.example:9200", HintSource::Operator, &ctx).await,
        SkipReason::BlockedAddress,
        "operator routes still get the always-blocked set"
    );
    assert_eq!(
        skipped("overlay://empty.example:9200", HintSource::Uri, &ctx).await,
        SkipReason::Unresolved
    );
    assert_eq!(
        skipped("overlay://gone.example:9200", HintSource::Uri, &ctx).await,
        SkipReason::Unresolved
    );
    assert_eq!(
        skipped("overlay://240.0.0.9:9200", HintSource::Uri, &ctx).await,
        SkipReason::BlockedAddress
    );
}

#[tokio::test(start_paused = true)]
async fn overlay_lookup_timeout_rejects_the_hint() {
    let resolver = Arc::new(StubResolver::default().hanging("slow.example"));
    let ctx = session(&resolver);
    assert_eq!(
        skipped("overlay://slow.example:9200", HintSource::Uri, &ctx).await,
        SkipReason::Unresolved
    );
    assert_eq!(resolver.lookups(), 1);
}

#[tokio::test]
async fn overlay_dial_uses_the_checked_literal_not_the_name() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let resolver = Arc::new(StubResolver::default().with("box.example", &["127.0.0.1"]));
    let hint = format!("overlay://box.example:{port}");
    let ok = checked(&hint, HintSource::Uri, &session(&resolver)).await;
    assert_eq!(ok.dial_endpoint, format!("overlay://127.0.0.1:{port}"));
    let accept = tokio::spawn(async move { listener.accept().await.map(|(_, peer)| peer) });
    let stream = OverlayDialer::new()
        .dial(&ok.dial_endpoint)
        .await
        .expect("overlay dial");
    assert_eq!(stream.peer_ip(), Some("127.0.0.1".parse().unwrap()));
    accept.await.expect("join").expect("accept");
}

/// Accepts until a connection sends `token`; foreign connections (host probes) are ignored.
fn accept_token(listener: TcpListener, token: &'static [u8]) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                return false;
            };
            let mut buf = vec![0u8; token.len()];
            if conn.read_exact(&mut buf).await.is_ok() && buf == token {
                return true;
            }
        }
    })
}

#[tokio::test]
async fn overlay_dial_falls_through_to_the_next_checked_address() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let resolver =
        Arc::new(StubResolver::default().with("multi.example", &["127.0.0.2", "127.0.0.1"]));
    let hint = format!("overlay://multi.example:{port}");
    let ok = checked(&hint, HintSource::Uri, &session(&resolver)).await;
    assert_eq!(
        ok.dial_endpoint,
        format!("overlay://127.0.0.2:{port},127.0.0.1:{port}")
    );
    let seen = accept_token(listener, b"fx-rt-nonce");
    let mut stream = OverlayDialer::new()
        .dial(&ok.dial_endpoint)
        .await
        .expect("second address connects");
    assert_eq!(stream.peer_ip(), Some("127.0.0.1".parse().unwrap()));
    stream.send_chunk(b"fx-rt-nonce").await.expect("send");
    assert!(
        timeout(Duration::from_secs(5), seen)
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(resolver.lookups(), 1, "dialing never re-resolves");
}

#[tokio::test]
async fn overlay_dial_never_tries_an_unchecked_address() {
    let bystander = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = bystander.local_addr().expect("addr").port();
    let resolver =
        Arc::new(StubResolver::default().with("none.example", &["127.0.0.2", "127.0.0.4"]));
    let hint = format!("overlay://none.example:{port}");
    let ok = checked(&hint, HintSource::Uri, &session(&resolver)).await;
    let seen = accept_token(bystander, b"fx-rt-nonce");
    let err = OverlayDialer::new().dial(&ok.dial_endpoint).await;
    assert!(err.is_err(), "no checked address is reachable");
    assert!(
        timeout(Duration::from_millis(200), seen).await.is_err(),
        "the unchecked listener got no token"
    );
    let unchecked = OverlayDialer::new()
        .dial(&format!("overlay://127.0.0.2:{port},none.example:{port}"))
        .await;
    assert!(
        matches!(unchecked, Err(RuntimeError::Protocol(_))),
        "list entries must be literals"
    );
    assert_eq!(resolver.lookups(), 1, "the dialer never resolves");
}

#[tokio::test]
async fn websocket_hints_keep_the_url_and_carry_an_addr_policy() {
    let resolver = Arc::new(StubResolver::default());
    let ctx = session(&resolver);
    let relay = checked("relay:wss://relay.example/v1/relay", HintSource::Uri, &ctx).await;
    assert_eq!(relay.provider, ProviderId::Relay);
    assert_eq!(relay.dial_endpoint, "wss://relay.example/v1/relay");
    assert!(relay.addr_policy.is_some());
    assert_eq!(relay.path_class, PairingPathKind::Remote);
    let broker = checked("broker+wss://broker.example/b", HintSource::Uri, &ctx).await;
    assert_eq!(broker.provider, ProviderId::Broker);
    assert_eq!(broker.dial_endpoint, "broker+wss://broker.example/b");
    assert!(broker.addr_policy.is_some());
    assert_eq!(
        resolver.lookups(),
        0,
        "names are resolved inside the connect"
    );
    assert_eq!(
        skipped("wss://240.0.0.1/v1/relay", HintSource::Uri, &ctx).await,
        SkipReason::BlockedAddress
    );
    assert_eq!(
        skipped("wss://relay.example/v1/relay#key", HintSource::Uri, &ctx).await,
        SkipReason::Invalid
    );
}

/// Captures the `Host` header of upgrade requests for `path`, ignoring foreign probes.
async fn capture_upgrade_hosts(listener: TcpListener, path: String, seen: Arc<Mutex<Vec<String>>>) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let path = path.clone();
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
                match timeout(Duration::from_secs(5), sock.read(&mut chunk)).await {
                    Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                    _ => return,
                }
            }
            let head = String::from_utf8_lossy(&buf).into_owned();
            if !head.starts_with(&format!("GET {path} ")) {
                return;
            }
            if let Some(host) = head.lines().find_map(|l| {
                l.strip_prefix("Host: ")
                    .or_else(|| l.strip_prefix("host: "))
            }) {
                seen.lock().unwrap().push(host.trim().to_owned());
            }
            let _ = sock
                .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
                .await;
        });
    }
}

#[tokio::test]
async fn websocket_dial_resolves_once_and_keeps_the_original_authority() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let path = "/egress-authority-probe".to_owned();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(capture_upgrade_hosts(
        listener,
        path.clone(),
        Arc::clone(&seen),
    ));
    let resolver = Arc::new(StubResolver::default().with("relay.localhost", &["127.0.0.1"]));
    let policy = Arc::new(EgressAddrPolicy::new(
        Arc::clone(&resolver) as Arc<dyn HostResolver>
    ));
    let dialer = EgressDialer::new(Arc::new(BrokerDialer::new()), policy);
    assert_eq!(dialer.provider_id(), ProviderId::Broker);
    let url = format!("ws://relay.localhost:{port}{path}");
    let err = dialer
        .dial(&url)
        .await
        .err()
        .expect("the stub server refuses the upgrade");
    assert!(!matches!(err, RuntimeError::Timeout(_)), "{err:?}");
    assert_eq!(
        resolver.lookups(),
        1,
        "exactly one lookup through the policy"
    );
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [format!("relay.localhost:{port}")],
        "Host header keeps the original authority"
    );
    server.abort();
}

#[tokio::test]
async fn websocket_dial_refuses_blocked_answers_before_connecting() {
    for blocked in [
        "240.0.0.1",
        "224.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "fe80::1",
        "fec0::1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b::f000:1",
        "64:ff9b:1::a",
        "::a9fe:a9fe",
        "::ffff:0:f000:1",
        "2002:a9fe:a9fe::1",
    ] {
        let resolver = Arc::new(StubResolver::default().with("evil.localhost", &[blocked]));
        let policy = Arc::new(EgressAddrPolicy::new(
            Arc::clone(&resolver) as Arc<dyn HostResolver>
        ));
        let dialer = EgressDialer::new(Arc::new(BrokerDialer::new()), policy);
        let err = dialer
            .dial("ws://evil.localhost:9/b")
            .await
            .err()
            .expect("blocked answer");
        assert_eq!(
            err.skip_reason(),
            Some(SkipReason::BlockedAddress),
            "{blocked}: {err:?}"
        );
        assert_eq!(resolver.lookups(), 1, "{blocked}");
    }
}

#[tokio::test]
async fn ipv6_forms_embedding_blocked_ipv4_are_blocked_literals() {
    let resolver = Arc::new(StubResolver::default());
    let ctx = session(&resolver);
    for hint in [
        "direct:[64:ff9b::f000:1]:9",
        "direct:[::f000:1]:9",
        "direct:[2002:f000:1::1]:9",
        "direct:[fec0::1]:9",
    ] {
        for source in [HintSource::Uri, HintSource::Operator] {
            assert_eq!(
                skipped(hint, source, &ctx).await,
                SkipReason::BlockedAddress,
                "{hint} {source:?}"
            );
        }
    }
    // Hints embedding a link-local IPv4, local-use NAT64 and Teredo are refused by the parser.
    for nat64 in [
        "wss://[64:ff9b::a9fe:a9fe]/v1/relay",
        "direct:[64:ff9b::a9fe:a9fe]:9",
        "direct:[64:ff9b:1::1]:9",
        "direct:[2001::1]:9",
    ] {
        for source in [HintSource::Uri, HintSource::Operator] {
            assert_eq!(
                skipped(nat64, source, &ctx).await,
                SkipReason::Invalid,
                "{nat64} {source:?}"
            );
        }
    }
    let public = checked("direct:[64:ff9b::cb00:7107]:9", HintSource::Uri, &ctx).await;
    assert_eq!(public.path_class, PairingPathKind::Remote);
}

/// Dials `url` through an [`EgressDialer`] with `resolver` and returns the error.
async fn ws_dial_err(resolver: &Arc<StubResolver>, url: &str) -> RuntimeError {
    let policy = Arc::new(EgressAddrPolicy::new(
        Arc::clone(resolver) as Arc<dyn HostResolver>
    ));
    EgressDialer::new(Arc::new(BrokerDialer::new()), policy)
        .dial(url)
        .await
        .err()
        .expect("dial fails")
}

#[tokio::test]
async fn websocket_dns_rejections_keep_a_typed_skip_reason() {
    let closed = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let closed_port = closed.local_addr().expect("addr").port();
    drop(closed);
    let resolver = Arc::new(
        StubResolver::default()
            .failing("gone.localhost")
            .with("empty.localhost", &[])
            .with("mixed.localhost", &["127.0.0.1", "240.0.0.1"])
            .with("ok.localhost", &["127.0.0.1"]),
    );
    let cases = [
        ("gone.localhost", Some(SkipReason::Unresolved)),
        ("empty.localhost", Some(SkipReason::Unresolved)),
        ("mixed.localhost", Some(SkipReason::BlockedAddress)),
        ("ok.localhost", None),
    ];
    for (host, want) in cases {
        let err = ws_dial_err(&resolver, &format!("ws://{host}:{closed_port}/b")).await;
        assert_eq!(err.skip_reason(), want, "{host}: {err:?}");
        if let Some(reason) = want {
            assert!(
                matches!(err, RuntimeError::Egress { .. }),
                "{host}: {err:?}"
            );
            assert!(err.to_string().contains(reason.as_str()), "{err}");
        } else {
            assert!(
                matches!(err, RuntimeError::Io(_)),
                "a refused connect after the check stays transport I/O: {err:?}"
            );
        }
    }
}

/// Records the SNI of every TLS ClientHello and offers no certificate.
#[derive(Debug, Default)]
struct SniSpy(Mutex<Vec<String>>);

impl rustls::server::ResolvesServerCert for SniSpy {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = hello.server_name().unwrap_or("<none>").to_owned();
        self.0.lock().unwrap().push(name);
        None
    }
}

/// Feeds each connection to a rustls server until its ClientHello is parsed; foreign plaintext
/// probes fail the TLS parse and record nothing.
async fn capture_sni(listener: TcpListener, spy: Arc<SniSpy>) {
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_cert_resolver(spy),
    );
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut buf = [0u8; 4096];
            loop {
                let n = match timeout(Duration::from_secs(5), sock.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return,
                };
                let mut rd = &buf[..n];
                while !rd.is_empty() {
                    if conn.read_tls(&mut rd).is_err() || conn.process_new_packets().is_err() {
                        return;
                    }
                }
            }
        });
    }
}

#[tokio::test]
async fn tls_dial_keeps_the_hostname_for_sni_and_makes_no_system_lookup() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let spy = Arc::new(SniSpy::default());
    let server = tokio::spawn(capture_sni(listener, Arc::clone(&spy)));
    // `.invalid` never resolves through the system resolver (RFC 6761): only the policy's
    // resolver can reach the listener.
    let host = "relay.egress-probe.invalid";
    let resolver = Arc::new(StubResolver::default().with(host, &["127.0.0.1"]));
    let system_before = SystemResolver::lookups();
    let err = ws_dial_err(&resolver, &format!("wss://{host}:{port}/b")).await;
    assert_eq!(err.skip_reason(), None, "the egress check passed: {err:?}");
    assert_eq!(resolver.lookups(), 1, "one lookup, through the policy");
    assert_eq!(
        SystemResolver::lookups(),
        system_before,
        "no second lookup through the system resolver"
    );
    assert_eq!(
        spy.0.lock().unwrap().as_slice(),
        [host.to_owned()],
        "TLS SNI (and so certificate verification) uses the original host, not the address"
    );
    server.abort();
}

/// A stub resolver that answers after `delay`.
struct SlowResolver {
    inner: StubResolver,
    delay: Duration,
}

#[async_trait]
impl HostResolver for SlowResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
        tokio::time::sleep(self.delay).await;
        self.inner.resolve(host, port).await
    }
}

/// Waits `delay` inside the caller's scope before dialing, so the connect reads its address
/// policy after other dials have entered theirs.
struct DelayedDialer {
    delay: Duration,
    inner: BrokerDialer,
}

#[async_trait]
impl PathDialer for DelayedDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Broker
    }

    async fn dial(
        &self,
        endpoint: &str,
    ) -> Result<Box<dyn tendril_runtime::PathStream>, RuntimeError> {
        tokio::time::sleep(self.delay).await;
        self.inner.dial(endpoint).await
    }
}

fn egress_dialer(inner: Arc<dyn PathDialer>, resolver: Arc<dyn HostResolver>) -> EgressDialer {
    EgressDialer::new(inner, Arc::new(EgressAddrPolicy::new(resolver)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_policies_stay_with_their_own_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let path = "/egress-scope-probe".to_owned();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(capture_upgrade_hosts(
        listener,
        path.clone(),
        Arc::clone(&seen),
    ));
    let url = format!("ws://scope.localhost:{port}{path}");
    // The blocking dial enters its scope after the permitting dials entered theirs and holds it
    // (a slow lookup) while they read their policy: a policy that leaked across dials, on the
    // same task or another one, would block them.
    let blocking = Arc::new(SlowResolver {
        inner: StubResolver::default().with("scope.localhost", &["240.0.0.1"]),
        delay: Duration::from_millis(600),
    });
    let permitting = Arc::new(StubResolver::default().with("scope.localhost", &["127.0.0.1"]));
    let delayed = || -> Arc<dyn PathDialer> {
        Arc::new(DelayedDialer {
            delay: Duration::from_millis(200),
            inner: BrokerDialer::new(),
        })
    };
    let block_dialer = egress_dialer(
        Arc::new(BrokerDialer::new()),
        Arc::clone(&blocking) as Arc<dyn HostResolver>,
    );
    let same_task = egress_dialer(delayed(), Arc::clone(&permitting) as Arc<dyn HostResolver>);
    let other_task = egress_dialer(delayed(), Arc::clone(&permitting) as Arc<dyn HostResolver>);
    let spawned_url = url.clone();
    let spawned = tokio::spawn(async move { other_task.dial(&spawned_url).await.err() });
    let (permitted, blocked) = tokio::join!(same_task.dial(&url), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        block_dialer.dial(&url).await
    });
    let blocked = blocked.err().expect("blocked");
    assert_eq!(blocked.skip_reason(), Some(SkipReason::BlockedAddress));
    let permitted = permitted.err().expect("stub refuses the upgrade");
    assert_eq!(permitted.skip_reason(), None, "{permitted:?}");
    let spawned = spawned.await.expect("join").expect("stub refuses");
    assert_eq!(spawned.skip_reason(), None, "{spawned:?}");
    assert_eq!(blocking.inner.lookups(), 1);
    assert_eq!(permitting.lookups(), 2);
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "both permitted dials reached the listener"
    );
    server.abort();
}

#[cfg(feature = "p2p-iroh")]
mod iroh_hints {
    use super::*;
    use tendril_runtime::providers::filter_p2p_hint;
    use tendril_runtime::{P2pDialer, P2pListener, P2pOptions, P2pRelayMode, PathListener};

    fn node_id() -> String {
        iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string()
    }

    fn configured() -> P2pRelayMode {
        P2pRelayMode::Custom("https://relay.one.example/".to_owned())
    }

    #[test]
    fn hint_relays_outside_the_map_are_dropped() {
        let id = node_id();
        let kept = filter_p2p_hint(
            &format!("iroh://{id}?relay=https://relay.one.example/"),
            &configured(),
        )
        .expect("configured relay");
        assert!(kept.dropped_relays.is_empty());
        assert_eq!(
            kept.endpoint,
            format!("iroh://{id}?relay=https://relay.one.example/")
        );

        let swapped = filter_p2p_hint(
            &format!("p2p:iroh://{id}?relay=https://evil.example/&addr=203.0.113.7:4433"),
            &configured(),
        )
        .expect("map relays replace the dropped one");
        assert_eq!(swapped.dropped_relays, vec!["https://evil.example/"]);
        assert!(
            !swapped.endpoint.contains("evil.example"),
            "{}",
            swapped.endpoint
        );
        assert!(
            swapped
                .endpoint
                .contains("relay=https://relay.one.example/")
        );
        assert!(swapped.endpoint.contains("addr=203.0.113.7:4433"));

        let none = filter_p2p_hint(&format!("iroh://{id}"), &configured()).expect("no relay");
        assert!(none.endpoint.contains("relay=https://relay.one.example/"));
    }

    #[test]
    fn disabled_map_needs_a_surviving_addr() {
        let id = node_id();
        assert_eq!(
            filter_p2p_hint(
                &format!("iroh://{id}?relay=https://relay.one.example/"),
                &P2pRelayMode::Disabled
            ),
            Err(SkipReason::IrohRelayNotConfigured)
        );
        let only_blocked = format!("iroh://{id}?addr=[ff02::1]:4433&addr=240.0.0.1:4433");
        assert_eq!(
            filter_p2p_hint(&only_blocked, &P2pRelayMode::Disabled),
            Err(SkipReason::IrohRelayNotConfigured)
        );
        let lan = filter_p2p_hint(
            &format!("iroh://{id}?addr=127.0.0.1:4433&addr=240.0.0.1:4433&addr=192.168.1.4:4433"),
            &P2pRelayMode::Disabled,
        )
        .expect("loopback and LAN addrs survive");
        assert_eq!(
            lan.endpoint,
            format!("iroh://{id}?addr=127.0.0.1:4433&addr=192.168.1.4:4433")
        );
        assert_eq!(
            filter_p2p_hint("iroh://not-a-node-id", &P2pRelayMode::Disabled),
            Err(SkipReason::Invalid)
        );
    }

    #[tokio::test]
    async fn check_hint_routes_uri_iroh_hints_to_the_hint_dialer() {
        // Operator relay host names resolve once at check time (stub answer below).
        let resolver = Arc::new(StubResolver::default().with("evil.example", &["203.0.113.66"]));
        let id = node_id();
        let ctx = session(&resolver).with_iroh_relay_mode(configured());
        let hint = format!("p2p:iroh://{id}?relay=https://evil.example/");
        let uri = checked(&hint, HintSource::Stored(RouteSource::Signed), &ctx).await;
        assert!(uri.p2p_hint_dialer);
        assert_eq!(uri.provider, ProviderId::P2p);
        assert_eq!(uri.dropped_relays, vec!["https://evil.example/"]);
        assert_eq!(
            uri.dial_endpoint,
            format!("iroh://{id}?relay=https://relay.one.example/")
        );
        let operator = checked(&hint, HintSource::Operator, &ctx).await;
        assert!(
            !operator.p2p_hint_dialer,
            "operator endpoints keep their dialer"
        );
        assert_eq!(
            operator.dial_endpoint,
            format!("iroh://{id}?relay=https://evil.example/")
        );
        assert_eq!(
            operator.relay_pins,
            vec![(
                "evil.example".to_owned(),
                vec!["203.0.113.66".parse::<std::net::IpAddr>().unwrap()]
            )]
        );
        let disabled = session(&resolver).with_iroh_relay_mode(P2pRelayMode::Disabled);
        assert_eq!(
            skipped(&hint, HintSource::Uri, &disabled).await,
            SkipReason::IrohRelayNotConfigured
        );
    }

    #[tokio::test]
    async fn operator_iroh_endpoints_still_drop_blocked_destinations() {
        let resolver = Arc::new(
            StubResolver::default()
                .with("relay.one.example", &["203.0.113.1"])
                .with("relay.two.example", &["203.0.113.2", "0.0.0.9"]),
        );
        let id = node_id();
        let ctx = session(&resolver).with_iroh_relay_mode(P2pRelayMode::Disabled);
        let hint = format!(
            "iroh://{id}?addr=240.0.0.1:4433&addr=192.168.1.4:4433&addr=[64:ff9b::f000:1]:1\
             &relay=https://0.0.0.7/&relay=https://relay.one.example/"
        );
        for source in [
            HintSource::Operator,
            HintSource::Stored(RouteSource::Operator),
        ] {
            let ok = checked(&hint, source, &ctx).await;
            assert!(!ok.p2p_hint_dialer, "{source:?} keeps the operator dialer");
            assert_eq!(
                ok.dial_endpoint,
                format!("iroh://{id}?addr=192.168.1.4:4433&relay=https://relay.one.example/"),
                "{source:?}"
            );
            let only_blocked = format!("p2p:iroh://{id}?addr=240.0.0.1:4433&addr=0.1.2.3:9");
            assert_eq!(
                skipped(&only_blocked, source, &ctx).await,
                SkipReason::BlockedAddress,
                "{source:?}"
            );
        }
        // A relay host name with one blocked answer is removed like a blocked literal.
        let resolved_blocked = format!(
            "iroh://{id}?relay=https://relay.two.example/&relay=https://relay.one.example/"
        );
        let ok = checked(&resolved_blocked, HintSource::Operator, &ctx).await;
        assert_eq!(
            ok.dial_endpoint,
            format!("iroh://{id}?relay=https://relay.one.example/")
        );
        let only_resolved_blocked = format!("iroh://{id}?relay=https://relay.two.example/");
        assert_eq!(
            skipped(&only_resolved_blocked, HintSource::Operator, &ctx).await,
            SkipReason::BlockedAddress
        );
        let plain = format!("iroh://{id}?addr=192.168.1.4:4433");
        assert_eq!(
            checked(&plain, HintSource::Operator, &ctx)
                .await
                .dial_endpoint,
            plain
        );
    }

    /// Counts connections that send anything other than a foreign `GET /` probe.
    async fn count_relay_contacts(listener: TcpListener) -> Arc<AtomicUsize> {
        let contacts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&contacts);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(Ok(n)) = timeout(Duration::from_secs(5), sock.read(&mut buf)).await
                        && n > 0
                        && !buf[..n].starts_with(b"GET / ")
                    {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        contacts
    }

    #[tokio::test]
    async fn hint_dialer_never_contacts_a_reachable_off_map_relay() {
        let off_map = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let off_url = format!(
            "http://127.0.0.1:{}/",
            off_map.local_addr().expect("a").port()
        );
        let off_contacts = count_relay_contacts(off_map).await;
        let on_map = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let on_url = format!(
            "http://127.0.0.1:{}/",
            on_map.local_addr().expect("a").port()
        );
        let _on_contacts = count_relay_contacts(on_map).await;
        let hint = format!("iroh://{}?relay={off_url}", node_id());

        let dialer = P2pDialer::bind_with_options(
            P2pOptions::for_hint_dialer(P2pRelayMode::Custom(on_url)).with_port_mapping(false),
        )
        .await
        .expect("hint dialer");
        let _ = timeout(Duration::from_secs(3), dialer.dial(&hint)).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            off_contacts.load(Ordering::SeqCst),
            0,
            "the hint dialer made no contact with the off-map relay"
        );
        dialer.close().await;

        // Control: a dialer that trusts the hint's relay does contact the same listener.
        let control_opts = P2pOptions::for_endpoint(&hint, None, true)
            .expect("control options")
            .with_resolve_pkarr(false)
            .with_publish_pkarr(false)
            .with_port_mapping(false);
        let control = P2pDialer::bind_with_options(control_opts)
            .await
            .expect("control dialer");
        let _ = timeout(Duration::from_secs(3), control.dial(&hint)).await;
        for _ in 0..50 {
            if off_contacts.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            off_contacts.load(Ordering::SeqCst) > 0,
            "control: the listener observes relay contact"
        );
        control.close().await;
    }

    #[tokio::test]
    async fn hint_dialer_never_installs_address_lookup() {
        let relay = P2pRelayMode::Custom("http://127.0.0.1:9/".to_owned());
        let forced = P2pOptions::for_hint_dialer(relay.clone())
            .with_resolve_pkarr(true)
            .with_publish_pkarr(true)
            .with_port_mapping(false);
        let hint_dialer = P2pDialer::bind_with_options(forced)
            .await
            .expect("hint dialer");
        assert!(hint_dialer.is_hint_dialer());
        assert!(
            !hint_dialer.uses_address_lookup(),
            "no Pkarr or DNS lookup on the hint dialer"
        );
        hint_dialer.close().await;

        let operator = P2pDialer::bind_with_options(
            P2pOptions::for_dialer(relay)
                .with_resolve_pkarr(true)
                .with_port_mapping(false),
        )
        .await
        .expect("operator dialer");
        assert!(!operator.is_hint_dialer());
        assert!(
            operator.uses_address_lookup(),
            "control: the operator dialer keeps its lookup"
        );
        operator.close().await;
    }

    #[tokio::test]
    async fn hint_dialer_reaches_a_listener_over_a_filtered_addr() {
        let mut listener = P2pListener::bind_with_options(
            P2pOptions::for_listener(P2pRelayMode::Disabled).with_port_mapping(false),
            None,
        )
        .await
        .expect("listener");
        let advertised = listener.local_endpoint();
        let sep = if advertised.contains('?') { '&' } else { '?' };
        let hint = format!("{advertised}{sep}relay=https://evil.example/");
        let resolver = Arc::new(StubResolver::default());
        let ctx = session(&resolver).with_iroh_relay_mode(P2pRelayMode::Disabled);
        let ok = checked(&hint, HintSource::Uri, &ctx).await;
        assert_eq!(ok.dropped_relays, vec!["https://evil.example/"]);
        let dialer = P2pDialer::bind_with_options(
            P2pOptions::for_hint_dialer(P2pRelayMode::Disabled).with_port_mapping(false),
        )
        .await
        .expect("hint dialer");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = timeout(Duration::from_secs(20), dialer.dial(&hint))
            .await
            .expect("dial in time")
            .expect("hint dial");
        assert_eq!(stream.provider_id(), ProviderId::P2p);
        timeout(Duration::from_secs(20), accept)
            .await
            .expect("accept in time")
            .expect("join")
            .expect("accept");

        let id = advertised
            .strip_prefix("iroh://")
            .and_then(|r| r.split('?').next())
            .expect("id");
        let err = dialer
            .dial(&format!("iroh://{id}?relay=https://evil.example/"))
            .await
            .err()
            .expect("relay-only hint outside an empty map");
        assert!(
            matches!(&err, RuntimeError::Protocol(m) if m.contains("iroh_relay_not_configured")),
            "{err:?}"
        );
    }
}

#[cfg(not(feature = "p2p-iroh"))]
#[tokio::test]
async fn iroh_hints_need_the_p2p_feature() {
    let resolver = Arc::new(StubResolver::default());
    assert_eq!(
        skipped(
            "iroh://abc?relay=https://relay.example/",
            HintSource::Uri,
            &session(&resolver)
        )
        .await,
        SkipReason::P2pFeatureDisabled
    );
}
