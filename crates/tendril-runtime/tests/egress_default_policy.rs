//! Dial and bind paths outside the hint dialer refuse every destination
//! `classify_destination` marks `Blocked`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use tendril_runtime::providers::egress::{
    EgressAddrPolicy, HostResolver, SkipReason, with_addr_policy,
};
use tendril_runtime::{
    BrokerDialer, BrokerListener, BrokerServerConfig, DirectDialer, DirectListener, OverlayDialer,
    OverlayListener, PathDialer, RelayDialer, RelayListener, RelayV2Dialer, RelayV2Listener,
    RuntimeError, dial_endpoint,
};
use tokio::time::timeout;

/// Teredo, local-use NAT64, site-local and IPv4-embedded metadata literals that the previous
/// default policy accepted.
const BLOCKED_HOSTS: [&str; 6] = [
    "[2001::1]",
    "[64:ff9b:1::1]",
    "[fec0::1]",
    "[64:ff9b::a9fe:a9fe]",
    "[2002:a9fe:a9fe::1]",
    "[::ffff:0:a9fe:a9fe]",
];

const BUDGET: Duration = Duration::from_secs(20);

fn assert_refused<T>(what: &str, host: &str, result: Result<Result<T, RuntimeError>, impl Sized>) {
    let Ok(result) = result else {
        panic!("{what} {host}: attempted a connection instead of refusing the address");
    };
    match result {
        Ok(_) => panic!("{what} {host}: must be refused"),
        Err(err) => assert!(
            err.to_string().contains("not permitted"),
            "{what} {host}: {err}"
        ),
    }
}

#[tokio::test]
async fn relay_dialer_refuses_blocked_literals() {
    for host in BLOCKED_HOSTS {
        let url = format!("wss://{host}:9/");
        let got = timeout(BUDGET, RelayDialer::new().connect(&url, &[7u8; 32])).await;
        assert_refused("relay dial", host, got);
    }
}

#[tokio::test]
async fn relay_v2_dialer_refuses_blocked_literals() {
    for host in BLOCKED_HOSTS {
        let url = format!("wss://{host}:9/");
        let got = timeout(BUDGET, RelayV2Dialer::new([7u8; 32]).connect(&url)).await;
        assert_refused("relay v2 dial", host, got);
    }
}

#[tokio::test]
async fn broker_dialer_refuses_blocked_literals() {
    for host in BLOCKED_HOSTS {
        let url = format!("broker+wss://{host}:9/");
        let got = timeout(BUDGET, BrokerDialer::new().dial(&url)).await;
        assert_refused("broker dial", host, got);
    }
}

#[tokio::test]
async fn relay_listeners_refuse_blocked_literals_on_bind() {
    for host in BLOCKED_HOSTS {
        let url = format!("wss://{host}:9/");
        let v1 = timeout(
            BUDGET,
            RelayListener::bind(
                url.clone(),
                None,
                SigningKey::from_bytes(&[3u8; 32]),
                Duration::from_secs(1),
            ),
        )
        .await;
        assert_refused("relay bind", host, v1);
        let v2 = timeout(
            BUDGET,
            RelayV2Listener::bind(url, None, [3u8; 32], Duration::from_secs(1)),
        )
        .await;
        assert_refused("relay v2 bind", host, v2);
    }
}

#[tokio::test]
async fn loopback_relay_is_still_dialed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let got = timeout(
        BUDGET,
        RelayDialer::new()
            .with_allow_insecure_ws(true)
            .connect(&format!("ws://127.0.0.1:{port}/"), &[7u8; 32]),
    )
    .await
    .expect("loopback connect fails fast");
    let err = got.err().expect("closed port");
    assert!(!err.to_string().contains("not permitted"), "{err}");
}

/// Bare socket addresses (no URL) in the blocked set, as `direct:` and `overlay://` endpoints.
const BLOCKED_SOCKETS: [&str; 7] = [
    "[2001::1]:9",
    "[64:ff9b:1::1]:9",
    "[fec0::1]:9",
    "[64:ff9b::a9fe:a9fe]:9",
    "[2002:a9fe:a9fe::1]:9",
    "224.0.0.1:9",
    "240.0.0.1:9",
];

fn assert_blocked<T>(
    what: &str,
    target: &str,
    result: Result<Result<T, RuntimeError>, impl Sized>,
) {
    let Ok(result) = result else {
        panic!("{what} {target}: attempted a connection instead of refusing the address");
    };
    match result {
        Ok(_) => panic!("{what} {target}: must be refused"),
        Err(err) => assert_eq!(
            err.skip_reason(),
            Some(SkipReason::BlockedAddress),
            "{what} {target}: {err:?}"
        ),
    }
}

#[tokio::test]
async fn direct_dialer_refuses_blocked_addresses() {
    for target in BLOCKED_SOCKETS {
        for endpoint in [target.to_owned(), format!("tcp://{target}")] {
            let got = timeout(BUDGET, DirectDialer::new().dial(&endpoint)).await;
            assert_blocked("direct dial", &endpoint, got);
        }
        let addr: SocketAddr = target.parse().expect("addr");
        let got = timeout(BUDGET, DirectDialer::new().connect(addr)).await;
        assert_blocked("direct connect", target, got);
    }
}

#[tokio::test]
async fn overlay_dialer_refuses_blocked_addresses_and_lists_holding_one() {
    for target in BLOCKED_SOCKETS {
        let got = timeout(
            BUDGET,
            OverlayDialer::new().dial(&format!("overlay://{target}")),
        )
        .await;
        assert_blocked("overlay dial", target, got);
        let list = format!("overlay://10.0.0.1:9,{target}");
        let got = timeout(BUDGET, OverlayDialer::new().dial(&list)).await;
        assert_blocked("overlay list", &list, got);
    }
}

#[tokio::test]
async fn dial_endpoint_refuses_blocked_direct_overlay_and_group_endpoints() {
    for target in BLOCKED_SOCKETS {
        for endpoint in [
            target.to_owned(),
            format!("tcp://{target}"),
            format!("overlay://{target}"),
        ] {
            let got = timeout(BUDGET, dial_endpoint(&endpoint, None)).await;
            assert_blocked("dial_endpoint", &endpoint, got);
        }
    }
}

/// Fixed answers per host for the resolver seam of the scoped address policy.
struct StubResolver(HashMap<String, Vec<IpAddr>>);

#[async_trait]
impl HostResolver for StubResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, RuntimeError> {
        self.0
            .get(host)
            .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
            .ok_or_else(|| RuntimeError::Protocol(format!("unknown stub host {host}")))
    }
}

fn scoped(answers: &[(&str, &[&str])]) -> Arc<EgressAddrPolicy> {
    let map = answers
        .iter()
        .map(|(host, ips)| {
            (
                (*host).to_owned(),
                ips.iter().map(|ip| ip.parse().expect("ip")).collect(),
            )
        })
        .collect();
    Arc::new(EgressAddrPolicy::new(Arc::new(StubResolver(map))))
}

#[tokio::test]
async fn overlay_names_are_resolved_through_the_policy_and_blocked_answers_refused() {
    for blocked in ["2001::1", "fec0::1", "64:ff9b::a9fe:a9fe", "224.0.0.1"] {
        let policy = scoped(&[("peer.example", &["10.0.0.1", blocked])]);
        let got = timeout(
            BUDGET,
            with_addr_policy(
                policy,
                OverlayDialer::new().dial("overlay://peer.example:9"),
            ),
        )
        .await;
        assert_blocked("overlay name", blocked, got);
    }
}

#[tokio::test]
async fn overlay_names_connect_to_the_checked_loopback_answer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accept = tokio::spawn(async move { listener.accept().await.is_ok() });
    let policy = scoped(&[("peer.example", &["127.0.0.1"])]);
    let dialed = timeout(
        BUDGET,
        with_addr_policy(
            policy,
            OverlayDialer::new().dial(&format!("overlay://peer.example:{port}")),
        ),
    )
    .await
    .expect("in budget");
    assert!(dialed.is_ok(), "loopback stays dialable by name");
    assert!(accept.await.expect("join"));
}

#[tokio::test]
async fn listeners_refuse_blocked_bind_addresses_and_keep_local_binds() {
    for target in [
        "[2001::1]:0",
        "[fec0::1]:0",
        "[64:ff9b:1::1]:0",
        "224.0.0.1:0",
        "240.0.0.1:0",
    ] {
        let addr: SocketAddr = target.parse().expect("addr");
        let direct = DirectListener::bind(addr, None)
            .await
            .err()
            .expect("direct");
        assert_eq!(
            direct.skip_reason(),
            Some(SkipReason::BlockedAddress),
            "{target}"
        );
        let overlay = OverlayListener::bind(addr, None)
            .await
            .err()
            .expect("overlay");
        assert_eq!(
            overlay.skip_reason(),
            Some(SkipReason::BlockedAddress),
            "{target}"
        );
        let broker = BrokerListener::bind(BrokerServerConfig {
            listen_addr: addr,
            ..BrokerServerConfig::default()
        })
        .await
        .err()
        .expect("broker");
        assert_eq!(
            broker.skip_reason(),
            Some(SkipReason::BlockedAddress),
            "{target}"
        );
    }
    for target in ["127.0.0.1:0", "0.0.0.0:0"] {
        let addr: SocketAddr = target.parse().expect("addr");
        DirectListener::bind(addr, None).await.expect("direct bind");
        OverlayListener::bind(addr, None)
            .await
            .expect("overlay bind");
        BrokerListener::bind(BrokerServerConfig {
            listen_addr: addr,
            ..BrokerServerConfig::default()
        })
        .await
        .expect("broker bind");
    }
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn webtransport_listener_refuses_blocked_bind_addresses() {
    for target in ["[2001::1]:0", "[fec0::1]:0", "224.0.0.1:0"] {
        let addr: SocketAddr = target.parse().expect("addr");
        let err = tendril_runtime::WtListener::bind(addr)
            .await
            .err()
            .expect("wt");
        assert_eq!(
            err.skip_reason(),
            Some(SkipReason::BlockedAddress),
            "{target}"
        );
    }
    tendril_runtime::WtListener::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("loopback bind");
}
