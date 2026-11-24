//! Runtime error text never echoes operator input: hints, relay URLs, iroh endpoints and
//! network snapshots (credentials, tokens, paths and pairing codes stay out).

use tendril_runtime::NetworkSnapshot;
use tendril_runtime::providers::hints::{normalize_operator_endpoint, normalize_peer_routes};
use tendril_runtime::redact::{redact_error, redact_hint};
use tendril_runtime::{DirectDialer, PathDialer, RelayDialer, RuntimeError};

const SECRETS: [&str; 6] = ["s3cret", "s3cr3t", "pw;x", "tok=", "abcd-efgh", "x,y;z"];

fn assert_clean(err: &impl std::fmt::Display) {
    let text = err.to_string().to_ascii_lowercase();
    for s in SECRETS {
        assert!(!text.contains(s), "{s:?} leaked: {text}");
    }
}

#[test]
fn operator_endpoint_errors_never_echo_the_input() {
    for raw in [
        "x's3cr3t",
        "https://user:pw;x@host/ trailing",
        "wss://u:s3cret@relay/v1/relay?tok=a b",
        "TND-ABCD-EFGH",
        "x,y;z=s3cret",
        "user:s3cret@[::1",
    ] {
        let err = normalize_operator_endpoint(raw).expect_err(raw);
        assert_clean(&err);
    }
    let err = normalize_peer_routes(&["wss://u:s3cret@relay:1/v1/relay?tok=x y".to_owned()])
        .expect_err("space in URL");
    assert_clean(&err);
}

#[test]
fn blocked_route_errors_never_echo_the_hint() {
    let hint = "wss://240.0.0.1/s3cret/v1/relay?tok=x".to_owned();
    let err = normalize_peer_routes(&[hint]).expect_err("reserved literal");
    assert!(err.to_string().contains("blocked_address"), "{err}");
    assert_clean(&err);
}

#[test]
fn snapshot_json_errors_report_position_only() {
    let err = NetworkSnapshot::from_json(r#"{"networks":"s3cret tok=x"}"#).unwrap_err();
    assert_clean(&err);
    assert!(err.to_string().contains("line 1 column"), "{err}");
}

#[tokio::test]
async fn dial_errors_never_echo_the_endpoint() {
    let err = DirectDialer::new()
        .dial("tcp:user:s3cret@host")
        .await
        .err()
        .expect("invalid tcp endpoint");
    assert_clean(&err);
    let err = RelayDialer::new()
        .dial("https://u:s3cret@relay/v1/relay?tok=x")
        .await
        .err()
        .expect("not a websocket relay URL");
    assert_clean(&err);
}

#[cfg(feature = "p2p-iroh")]
#[test]
fn iroh_relay_and_endpoint_errors_never_echo_the_input() {
    use tendril_runtime::{parse_p2p_endpoint, parse_p2p_relay_mode, parse_p2p_relay_modes};

    for mode in [
        "wss://u:s3cret@relay/v1/relay?tok=a b",
        "x's3cr3t",
        "ftp://u:s3cret@relay/",
    ] {
        let err = parse_p2p_relay_mode(Some(mode)).expect_err(mode);
        assert_clean(&err);
    }
    let err = parse_p2p_relay_modes(&["https://u:s3cret@relay/?tok=x".to_owned()])
        .expect_err("query string");
    assert_clean(&err);
    for ep in [
        "iroh://s3cret",
        "iroh://abcd?x,y;z=s3cret",
        "iroh://abcd?s3cret",
        "iroh://abcd?addr=s3cret",
    ] {
        let err = parse_p2p_endpoint(ep).expect_err(ep);
        assert_clean(&err);
    }
}

#[test]
fn shared_helpers_are_reexported() {
    let err = RuntimeError::Protocol("dial wss://u:s3cret@relay/v1?tok=x failed".to_owned());
    assert_eq!(
        redact_error(&err),
        "protocol error: dial wss://relay failed"
    );
    assert_eq!(redact_hint("tnd-abcd-efgh"), "<redacted>");
}
