//! Dial and bind paths outside the hint dialer refuse every destination
//! `classify_destination` marks `Blocked`.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use tendril_runtime::{
    BrokerDialer, PathDialer, RelayDialer, RelayListener, RelayV2Dialer, RelayV2Listener,
    RuntimeError,
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
