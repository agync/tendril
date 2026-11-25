//! Integration tests for in-band WebRTC session upgrade.

#![cfg(feature = "webrtc")]

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tendril_core::UPGRADE_CAP_WEBRTC_V1;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::grants::{Grant, GrantUnsigned, sign_grant};
use tendril_core::identity::EndpointIdentity;
use tendril_core::policy::ProviderId;
use tendril_core::roster::{PeerState, Roster, V2PeerSecrets};
use tendril_core::wire::{PathUpgradeMsg, encode_frame};
use tendril_runtime::driver::{SessionDriver, SessionEvent};
use tendril_runtime::providers::webrtc::{WebRtcActiveDialer, WebRtcUpgradeEndpoint};
use tendril_runtime::v2_driver::{V2ResponderConfig, V2ResponderState, V2SessionDriver};
use tendril_runtime::{
    DEFAULT_PRE_AUTH_TIMEOUT, PathListener, PathReader, PathStream, PathWriter, RuntimeError,
    split_path_stream_fallback,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::time::timeout;

struct MockStream {
    inner: DuplexStream,
    provider: ProviderId,
}

impl MockStream {
    fn pair(provider: ProviderId) -> (Box<dyn PathStream>, Box<dyn PathStream>) {
        let (a, b) = duplex(128 * 1024);
        (
            Box::new(Self { inner: a, provider }),
            Box::new(Self { inner: b, provider }),
        )
    }
}

#[async_trait]
impl PathStream for MockStream {
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        None
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.inner
            .write_all(bytes)
            .await
            .map_err(RuntimeError::from)
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.inner.read(buf).await.map_err(RuntimeError::from)
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.shutdown().await.map_err(RuntimeError::from)
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        split_path_stream_fallback(self)
    }
}

fn make_identities() -> (EndpointIdentity, EndpointIdentity) {
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41; 32]),
        SigningKeypair::from_seed([0x42; 32]),
    )
    .with_host_id("host-webrtc-test");
    let cli = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x51; 32]),
        SigningKeypair::from_seed([0x52; 32]),
    );
    (host, cli)
}

fn setup_rosters(
    host: &EndpointIdentity,
    cli: &EndpointIdentity,
    v2_secrets: Option<V2PeerSecrets>,
) -> (Roster, Roster) {
    let mut host_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            Some(cli.signing_key().public_key().clone()),
            "cli".to_owned(),
            "cli".to_owned(),
            "1234".to_owned(),
        )
        .expect("host pending pair");
    host_roster
        .confirm_peer(&cli.device_id(), Some("1234"))
        .expect("host confirm");

    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host.host_id().to_owned(),
            "Host".to_owned(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            Vec::new(),
        )
        .expect("cli pinned host");

    if let Some(sec) = v2_secrets {
        host_roster
            .upgrade_peer_to_v2(&cli.device_id(), sec.clone())
            .expect("host v2 upgrade");
        cli_roster
            .upgrade_peer_to_v2(host.host_id(), sec)
            .expect("cli v2 upgrade");
    }
    assert_eq!(
        host_roster.get(&cli.device_id()).unwrap().state,
        PeerState::Active
    );
    (host_roster, cli_roster)
}

fn mint_grant(host_id: &EndpointIdentity, subject: &str) -> Grant {
    sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: host_id.host_id().to_owned(),
            subject: subject.to_owned(),
            caps: vec!["fs.read".to_owned()],
            not_before: "2020-01-01T00:00:00Z".to_owned(),
            not_after: "2099-01-01T00:00:00Z".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
            delegated_from: Vec::new(),
            uses: None,
            machine: None,
        },
        host_id.signing_key(),
    )
    .expect("sign grant")
}

#[tokio::test]
async fn unspecified_bind_produces_concrete_host_candidates() {
    let (_handle_unused, listener) =
        WebRtcUpgradeEndpoint::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .expect("bind 0.0.0.0:0");
    assert_ne!(listener.local_addr().port(), 0);
    assert!(listener.local_endpoint().starts_with("webrtc://"));

    let (handle, _listener2) = WebRtcUpgradeEndpoint::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .expect("bind responder");
    let stream = WebRtcActiveDialer::dial(
        SocketAddr::from(([0, 0, 0, 0], 0)),
        |offer_sdp| async move {
            let offer_cands: Vec<&str> = offer_sdp
                .lines()
                .filter(|l| l.starts_with("a=candidate:"))
                .collect();
            assert!(
                !offer_cands.is_empty(),
                "offer SDP missing candidates:\n{offer_sdp}"
            );
            for cand in &offer_cands {
                assert!(
                    !cand.contains("0.0.0.0"),
                    "offer candidate leaked 0.0.0.0: {cand}"
                );
            }
            let answer_sdp = handle.accept_offer(&offer_sdp).await?;
            let answer_cands: Vec<&str> = answer_sdp
                .lines()
                .filter(|l| l.starts_with("a=candidate:"))
                .collect();
            assert!(
                !answer_cands.is_empty(),
                "answer SDP missing candidates:\n{answer_sdp}"
            );
            for cand in &answer_cands {
                assert!(
                    !cand.contains("0.0.0.0"),
                    "answer candidate leaked 0.0.0.0: {cand}"
                );
            }
            Ok(answer_sdp)
        },
    )
    .await
    .expect("dial localhost via concrete candidate");

    assert_eq!(stream.provider_id(), ProviderId::P2p);
}

#[tokio::test]
async fn wrong_datachannel_label_does_not_surface_as_accepted_stream() {
    let (handle, mut listener) = WebRtcUpgradeEndpoint::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind endpoint");

    let dial_task = tokio::spawn(async move {
        WebRtcActiveDialer::dial_with_channel_label(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            "wrong/v1",
            |offer_sdp| async move { handle.accept_offer(&offer_sdp).await },
        )
        .await
    });

    let accepted = timeout(Duration::from_millis(600), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "listener must reject/never accept wrong DataChannel label"
    );
    dial_task.abort();
}

#[tokio::test]
async fn split_write_close_preserves_buffered_reads() {
    let (handle, mut listener) = WebRtcUpgradeEndpoint::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind endpoint");

    let client_task = tokio::spawn(async move {
        WebRtcActiveDialer::dial(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            |offer_sdp| async move { handle.accept_offer(&offer_sdp).await },
        )
        .await
        .expect("dial")
    });

    let mut server_stream = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept stream");
    let client_stream = timeout(Duration::from_secs(5), client_task)
        .await
        .expect("client timeout")
        .expect("client join");

    let frame = encode_frame(b"buffered-before-write-close").expect("encode frame");
    server_stream.send_chunk(&frame).await.expect("send chunk");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let (mut read_half, mut write_half) = Box::new(client_stream).into_split();
    write_half.close().await.expect("close write half");

    let mut buf = vec![0u8; 256];
    let n = timeout(Duration::from_secs(2), read_half.recv_chunk(&mut buf))
        .await
        .expect("read timeout")
        .expect("read chunk");
    assert!(n >= frame.len(), "expected buffered frame bytes, got {n}");
}

#[tokio::test]
async fn v1_inband_webrtc_upgrade_and_cutover() {
    let now = 1_750_000_000;
    let (host_id, client_id) = make_identities();
    let (mut host_roster, mut client_roster) = setup_rosters(&host_id, &client_id, None);
    let grant = mint_grant(&host_id, &client_id.device_id());

    let (handle, mut webrtc_listener) =
        WebRtcUpgradeEndpoint::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind webrtc");

    let (c_relay, s_relay) = MockStream::pair(ProviderId::Relay);
    let caps = vec![UPGRADE_CAP_WEBRTC_V1.to_owned()];

    let (c_sess_res, s_sess_res) = tokio::join!(
        SessionDriver::connect_with_upgrade_caps(
            c_relay,
            &client_id,
            host_id.host_id(),
            Some(grant.clone()),
            &mut client_roster,
            now,
            caps.clone(),
        ),
        SessionDriver::accept_with_upgrade_caps(
            s_relay,
            &host_id,
            &mut host_roster,
            now,
            None,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
            caps,
        ),
    );
    let mut client_relay = c_sess_res.expect("client v1 connect");
    let mut server_relay = s_sess_res
        .expect("server v1 accept")
        .with_webrtc_upgrade_handle(handle);
    assert_eq!(
        client_relay.negotiated_upgrade_caps(),
        &[UPGRADE_CAP_WEBRTC_V1]
    );
    assert_eq!(
        server_relay.negotiated_upgrade_caps(),
        &[UPGRADE_CAP_WEBRTC_V1]
    );

    let host_roster_arc = Arc::new(Mutex::new(host_roster));
    let host_roster_pump = Arc::clone(&host_roster_arc);
    let server_pump = tokio::spawn(async move {
        while let Ok(Some(_ev)) = server_relay.next_event_locked(now, &host_roster_pump).await {}
    });

    let client_stream =
        WebRtcActiveDialer::dial(SocketAddr::from(([127, 0, 0, 1], 0)), |offer_sdp| async {
            client_relay
                .send_path_upgrade(&PathUpgradeMsg::Offer {
                    upgrade_id: 1,
                    protocol: UPGRADE_CAP_WEBRTC_V1.to_owned(),
                    sdp: offer_sdp,
                })
                .await?;
            loop {
                match timeout(
                    Duration::from_secs(5),
                    client_relay.next_event(now, &mut client_roster),
                )
                .await
                {
                    Ok(Ok(Some(SessionEvent::PathUpgrade(PathUpgradeMsg::Answer {
                        upgrade_id: 1,
                        sdp,
                        ..
                    })))) => return Ok(sdp),
                    Ok(Ok(Some(_))) => continue,
                    Ok(Ok(None)) => return Err(RuntimeError::Closed),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(RuntimeError::Timeout("timed out waiting for 0x0D answer"));
                    }
                }
            }
        })
        .await
        .expect("dial webrtc over 0x0D signaling");

    let accepted_webrtc = timeout(Duration::from_secs(5), webrtc_listener.accept())
        .await
        .expect("accept webrtc timeout")
        .expect("accept webrtc");
    assert_eq!(accepted_webrtc.provider_id(), ProviderId::P2p);

    let mut host_roster_direct = host_roster_arc.lock().unwrap().clone();
    let (c_direct_res, s_direct_res) = tokio::join!(
        SessionDriver::connect(
            Box::new(client_stream),
            &client_id,
            host_id.host_id(),
            Some(grant),
            &mut client_roster,
            now,
        ),
        SessionDriver::accept(
            accepted_webrtc,
            &host_id,
            &mut host_roster_direct,
            now,
            None,
        ),
    );
    let mut client_direct = c_direct_res.expect("client v1 direct connect");
    let mut server_direct = s_direct_res.expect("server v1 direct accept");
    assert_eq!(client_direct.provider_id(), ProviderId::P2p);
    assert_eq!(server_direct.provider_id(), ProviderId::P2p);

    let _ = client_relay.send_close(1000, "upgraded").await;
    drop(client_relay);
    let _ = timeout(Duration::from_secs(2), server_pump).await;

    client_direct.send_rekey().await.expect("rekey on webrtc");
    client_direct.send_ping(99).await.expect("ping on webrtc");
    client_direct
        .send_data(b"hello-over-v1-webrtc")
        .await
        .expect("data on webrtc");

    let mut saw_rekey = false;
    let mut saw_data = false;
    while !(saw_rekey && saw_data) {
        match timeout(
            Duration::from_secs(3),
            server_direct.next_event(now, &mut host_roster_direct),
        )
        .await
        .expect("direct recv timeout")
        .expect("direct recv")
        .expect("direct eof")
        {
            SessionEvent::Rekeyed { .. } => saw_rekey = true,
            SessionEvent::AppData(d) => {
                assert_eq!(d, b"hello-over-v1-webrtc");
                saw_data = true;
            }
            _ => {}
        }
    }
    let mut saw_pong = false;
    while !saw_pong {
        match timeout(
            Duration::from_secs(3),
            client_direct.next_event(now, &mut client_roster),
        )
        .await
        .expect("pong timeout")
        .expect("pong")
        .expect("pong eof")
        {
            SessionEvent::PongReceived(99) => saw_pong = true,
            SessionEvent::Rekeyed { .. } => {}
            other => panic!("unexpected event waiting for pong: {other:?}"),
        }
    }
}

#[tokio::test]
async fn v2_inband_webrtc_upgrade_and_cutover() {
    let now = 1_750_000_000;
    let (host_id, client_id) = make_identities();
    let (mut host_roster_relay, mut client_roster) = setup_rosters(
        &host_id,
        &client_id,
        Some(V2PeerSecrets::new([0x31; 32], [0x32; 32])),
    );
    let grant = mint_grant(&host_id, &client_id.device_id());

    let (handle, mut webrtc_listener) =
        WebRtcUpgradeEndpoint::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind webrtc");

    let v2_cfg = V2ResponderConfig {
        webrtc_upgrade_handle: Some(handle),
        ..Default::default()
    };
    let v2_state = V2ResponderState::with_config(v2_cfg);

    let (c_relay, s_relay) = MockStream::pair(ProviderId::Relay);

    let (c_sess_res, s_sess_res) = tokio::join!(
        V2SessionDriver::connect_with_upgrade_caps(
            c_relay,
            &client_id,
            host_id.host_id(),
            Some(grant.clone()),
            &mut client_roster,
            now,
            vec![UPGRADE_CAP_WEBRTC_V1.to_owned()],
        ),
        V2SessionDriver::accept(
            s_relay,
            &host_id,
            &mut host_roster_relay,
            now,
            &v2_state,
            None,
        ),
    );
    let mut client_relay = c_sess_res.expect("client v2 connect");
    let mut server_relay = s_sess_res.expect("server v2 accept");
    assert_eq!(
        client_relay.negotiated_upgrade_caps(),
        &[UPGRADE_CAP_WEBRTC_V1]
    );
    assert_eq!(
        server_relay.negotiated_upgrade_caps(),
        &[UPGRADE_CAP_WEBRTC_V1]
    );

    let host_roster_arc = Arc::new(Mutex::new(host_roster_relay));
    let host_roster_pump = Arc::clone(&host_roster_arc);
    let server_pump = tokio::spawn(async move {
        while let Ok(Some(_ev)) = server_relay.next_event_locked(now, &host_roster_pump).await {}
    });

    let client_stream =
        WebRtcActiveDialer::dial(SocketAddr::from(([127, 0, 0, 1], 0)), |offer_sdp| async {
            client_relay
                .send_path_upgrade(&PathUpgradeMsg::Offer {
                    upgrade_id: 1,
                    protocol: UPGRADE_CAP_WEBRTC_V1.to_owned(),
                    sdp: offer_sdp,
                })
                .await?;
            loop {
                match timeout(
                    Duration::from_secs(5),
                    client_relay.next_event(now, &mut client_roster),
                )
                .await
                {
                    Ok(Ok(Some(SessionEvent::PathUpgrade(PathUpgradeMsg::Answer {
                        upgrade_id: 1,
                        sdp,
                        ..
                    })))) => return Ok(sdp),
                    Ok(Ok(Some(_))) => continue,
                    Ok(Ok(None)) => return Err(RuntimeError::Closed),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(RuntimeError::Timeout(
                            "timed out waiting for v2 0x0D answer",
                        ));
                    }
                }
            }
        })
        .await
        .expect("dial v2 webrtc");

    let accepted_webrtc = timeout(Duration::from_secs(5), webrtc_listener.accept())
        .await
        .expect("accept webrtc timeout")
        .expect("accept webrtc");
    assert_eq!(accepted_webrtc.provider_id(), ProviderId::P2p);

    let mut host_roster_direct = host_roster_arc.lock().unwrap().clone();
    let (c_direct_res, s_direct_res) = tokio::join!(
        V2SessionDriver::connect_with_upgrade_caps(
            Box::new(client_stream),
            &client_id,
            host_id.host_id(),
            Some(grant),
            &mut client_roster,
            now,
            Vec::new(),
        ),
        V2SessionDriver::accept(
            accepted_webrtc,
            &host_id,
            &mut host_roster_direct,
            now,
            &v2_state,
            None,
        ),
    );
    let mut client_direct = c_direct_res.expect("client v2 direct connect");
    let mut server_direct = s_direct_res.expect("server v2 direct accept");
    assert_eq!(client_direct.provider_id(), ProviderId::P2p);
    assert_eq!(server_direct.provider_id(), ProviderId::P2p);
    assert!(server_direct.negotiated_upgrade_caps().is_empty());

    let _ = client_relay.send_close(1000, "upgraded").await;
    drop(client_relay);
    let _ = timeout(Duration::from_secs(2), server_pump).await;

    client_direct
        .send_data(b"hello-over-v2-webrtc")
        .await
        .expect("v2 data on webrtc");
    let ev = timeout(
        Duration::from_secs(3),
        server_direct.next_event(now, &mut host_roster_direct),
    )
    .await
    .expect("v2 recv timeout")
    .expect("v2 recv")
    .expect("v2 eof");
    assert!(matches!(ev, SessionEvent::AppData(ref d) if d == b"hello-over-v2-webrtc"));
}

#[tokio::test]
async fn unsplit_webrtc_stream_drop_releases_session_slot() {
    use tendril_runtime::providers::webrtc::MAX_WEBRTC_SESSIONS;

    let (handle, mut listener) = WebRtcUpgradeEndpoint::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind endpoint");

    let captured_offer = Arc::new(Mutex::new(None));
    let capture_slot = Arc::clone(&captured_offer);
    let _ = WebRtcActiveDialer::dial(SocketAddr::from(([127, 0, 0, 1], 0)), |offer_sdp| {
        *capture_slot.lock().unwrap() = Some(offer_sdp);
        async { Err(RuntimeError::Closed) }
    })
    .await;
    let template_offer = captured_offer
        .lock()
        .unwrap()
        .take()
        .expect("captured offer SDP");

    // Occupy 1 slot with a real unsplit WebRtcStream.
    let client_task = tokio::spawn({
        let h = handle.clone();
        async move {
            WebRtcActiveDialer::dial(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                |offer_sdp| async move { h.accept_offer(&offer_sdp).await },
            )
            .await
            .expect("dial")
        }
    });
    let server_stream = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept stream");
    let _client_stream = timeout(Duration::from_secs(5), client_task)
        .await
        .expect("client timeout")
        .expect("client join");

    // Fill the remaining MAX_WEBRTC_SESSIONS - 1 slots via accept_offer.
    for i in 1..MAX_WEBRTC_SESSIONS {
        handle
            .accept_offer(&template_offer)
            .await
            .unwrap_or_else(|err| panic!("expected slot {i} to be available: {err:?}"));
    }

    // Next accept_offer must fail with CapacityExceeded while the unsplit stream holds slot 64.
    let err = handle
        .accept_offer(&template_offer)
        .await
        .expect_err("capacity must be exhausted");
    assert!(
        matches!(err, RuntimeError::CapacityExceeded(_)),
        "expected CapacityExceeded, got {err:?}"
    );

    // Dropping the unsplit WebRtcStream must immediately release its slot in the mux.
    drop(server_stream);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match handle.accept_offer(&template_offer).await {
            Ok(_) => break,
            Err(RuntimeError::CapacityExceeded(_)) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(other) => panic!("expected released slot after stream drop, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn dropping_handles_and_streams_exits_mux_cleanly() {
    let (handle, mut listener) = WebRtcUpgradeEndpoint::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind endpoint");
    let bound_addr = listener.local_addr();

    // While the mux is alive, its UDP socket holds bound_addr.
    assert!(
        std::net::UdpSocket::bind(bound_addr).is_err(),
        "expected mux UDP socket to hold {bound_addr}"
    );

    let client_task = tokio::spawn({
        let h = handle.clone();
        async move {
            WebRtcActiveDialer::dial(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                |offer_sdp| async move { h.accept_offer(&offer_sdp).await },
            )
            .await
            .expect("dial")
        }
    });
    let server_stream = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept stream");
    let client_stream = timeout(Duration::from_secs(5), client_task)
        .await
        .expect("client timeout")
        .expect("client join");

    drop(handle);
    drop(listener);
    // Stream is still alive, so mux remains bound until all stream halves drop.
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        std::net::UdpSocket::bind(bound_addr).is_err(),
        "mux must stay bound while WebRtcStream is still open"
    );

    drop(server_stream);
    drop(client_stream);

    // Once handle, listener, and all streams are dropped, run_endpoint_mux exits and frees bound_addr.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if std::net::UdpSocket::bind(bound_addr).is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for mux UDP socket {bound_addr} to close after handle/listener/stream drop"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
