//! Responders refuse an invalid local `host_id` before touching the stream.

use std::sync::{Arc, Mutex};

use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{PairingConfig, PairingManager, PairingPathKind};
use tendril_core::roster::Roster;
use tendril_runtime::{
    DirectListener, PathListener, PathStream, RuntimeError, SessionDriver, V2ResponderState,
    V2SessionDriver, drive_pair_responder, drive_v2_pake_pair_responder,
};
use tokio::net::TcpStream;

const NOW: u64 = 1_795_564_800;

fn forged() -> EndpointIdentity {
    EndpointIdentity::generate()
        .expect("identity")
        .with_host_id("has#hash")
}

async fn stream() -> (Box<dyn PathStream>, TcpStream) {
    let mut listener = DirectListener::bind("127.0.0.1:0".parse().expect("addr"), None)
        .await
        .expect("bind");
    let addr = listener.local_endpoint();
    let host = addr.trim_start_matches("direct:").to_owned();
    let client = TcpStream::connect(host).await.expect("connect");
    (listener.accept().await.expect("accept"), client)
}

fn refused<T>(res: Result<T, RuntimeError>) -> bool {
    matches!(res, Err(RuntimeError::Core(ref e)) if e.to_string().contains("invalid local host_id"))
}

#[tokio::test]
async fn v1_session_responder_refuses_an_invalid_local_host_id() {
    let (stream, _client) = stream().await;
    let mut roster = Roster::new();
    let res = SessionDriver::accept(stream, &forged(), &mut roster, NOW, None).await;
    assert!(refused(res));
}

#[tokio::test]
async fn v1_pair_responder_refuses_an_invalid_local_host_id() {
    let (mut stream, _client) = stream().await;
    let manager = Mutex::new(PairingManager::new(PairingConfig::default()));
    let roster = Mutex::new(Roster::new());
    let res = drive_pair_responder(
        &mut *stream,
        &forged(),
        &manager,
        &roster,
        PairingPathKind::Lan,
        NOW,
        None,
    )
    .await;
    assert!(refused(res));
}

#[tokio::test]
async fn v2_session_responder_refuses_an_invalid_local_host_id() {
    let (stream, _client) = stream().await;
    let mut roster = Roster::new();
    let res = V2SessionDriver::accept(
        stream,
        &forged(),
        &mut roster,
        NOW,
        &V2ResponderState::new(),
        None,
    )
    .await;
    assert!(refused(res));
}

#[tokio::test]
async fn v2_pake_pair_responder_refuses_an_invalid_local_host_id() {
    let (mut stream, _client) = stream().await;
    let manager = Arc::new(Mutex::new(PairingManager::new(PairingConfig::default())));
    let roster = Mutex::new(Roster::new());
    let res = drive_v2_pake_pair_responder(
        &mut *stream,
        &forged(),
        &manager,
        &roster,
        PairingPathKind::Lan,
        NOW,
        &V2ResponderState::new(),
        None,
    )
    .await;
    assert!(refused(res));
}
