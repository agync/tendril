use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tempfile::tempdir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::grants::{GrantUnsigned, RevocationListUnsigned, sign_crl, sign_grant};
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    PairingCodeKind, PairingConfig, PairingManager, PairingPathKind, PinnedHost,
};
use tendril_core::policy::ProviderId;
use tendril_core::roster::{PeerState, Roster, V2PeerSecrets};
use tendril_core::session::RekeyDirection;
use tendril_core::v2::{
    PakeArgon2Params, V2PinnedHost, V2SessionInitiator, canonical_relay_host, derive_epoch_mailbox,
    sign_v2_relay_dial,
};
use tendril_core::wire::{Intent, Preamble, WIRE_VERSION_V2};
use tendril_relay::{MAX_RELAY_FRAME_LEN, RelayV2ClientMsg, RelayV2ServerMsg};
use tendril_runtime::{
    DEFAULT_PRE_AUTH_TIMEOUT, EmbeddedRelay, HttpWakeProvider, LocalDialer, LocalListener,
    MemoryWakeProvider, NoopWakeProvider, PathDialer, PathListener, PathReader, PathStream,
    PathWriter, RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig, RuntimeError, SessionEvent,
    StateStore, V2ResponderConfig, V2ResponderState, V2SessionDriver, WakeAdapterKind,
    WakeDialOptions, WakeOutcome, WakeProvider, WakeSecret, WakeTag, WakeTarget,
    drive_m2m_enroll_initiator_with_store, drive_pair_initiator_with_store,
    drive_v2_pake_pair_initiator_with_store, drive_v2_pake_pair_responder,
    drive_v2_pake_pair_responder_with_store, drive_v2_session_initiator,
    drive_v2_session_responder, split_path_stream_fallback, verify_epoch_wake_tag_window,
    wake_and_connect_v2_session, wake_and_dial_v2,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn make_identities() -> (EndpointIdentity, EndpointIdentity) {
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41; 32]),
        SigningKeypair::from_seed([0x42; 32]),
    )
    .with_host_id("host-v2-e2e");
    let cli = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x51; 32]),
        SigningKeypair::from_seed([0x52; 32]),
    );
    (host, cli)
}

fn setup_paired_v2_rosters(
    host: &EndpointIdentity,
    cli: &EndpointIdentity,
    secrets: &V2PeerSecrets,
) -> (Roster, Roster) {
    let mut host_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".to_owned(),
            "cli".to_owned(),
            "1234".to_owned(),
        )
        .unwrap();
    host_roster
        .confirm_peer(&cli.device_id(), Some("1234"))
        .unwrap();
    host_roster
        .upgrade_peer_to_v2(&cli.device_id(), secrets.clone())
        .unwrap();

    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host.host_id().to_owned(),
            "Host".to_owned(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            vec![],
        )
        .unwrap();
    cli_roster
        .upgrade_peer_to_v2(host.host_id(), secrets.clone())
        .unwrap();

    (host_roster, cli_roster)
}

#[tokio::test]
async fn live_v2_relay_pake_pair_session_rekey_padding_and_security_rejections() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();

    let host_dir = tempdir().unwrap();
    let cli_dir = tempdir().unwrap();
    let host_store = StateStore::open_or_create(host_dir.path()).unwrap();
    let cli_store = StateStore::open_or_create(cli_dir.path()).unwrap();
    let host_store_lock = Arc::new(AsyncMutex::new(()));
    let cli_store_lock = Arc::new(AsyncMutex::new(()));

    let sock_dir = tempdir().unwrap();
    let sock_path = sock_dir.path().join("pair.sock");
    let mut pair_listener = LocalListener::bind(&sock_path).unwrap();
    let pair_ep = pair_listener.local_endpoint();

    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, now_unix)
        .unwrap();
    let mgr = Arc::new(Mutex::new(mgr));
    let v2_state = Arc::new(V2ResponderState::new());

    let host_id_c = host_id.clone();
    let mgr_c = Arc::clone(&mgr);
    let host_store_c = host_store.clone();
    let host_lock_c = Arc::clone(&host_store_lock);
    let state_c = Arc::clone(&v2_state);
    let resp_task = tokio::spawn(async move {
        let mut s = pair_listener.accept().await.unwrap();
        drive_v2_pake_pair_responder_with_store(
            s.as_mut(),
            &host_id_c,
            &mgr_c,
            &host_store_c,
            &host_lock_c,
            PairingPathKind::Remote,
            now_unix,
            &state_c,
            None,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .unwrap()
    });

    let mut pair_stream = LocalDialer::new().dial(&pair_ep).await.unwrap();
    let init_pair = drive_v2_pake_pair_initiator_with_store(
        pair_stream.as_mut(),
        &cli_id,
        "Workstation".to_owned(),
        "cli".to_owned(),
        code,
        None,
        "Host".to_owned(),
        vec![],
        &cli_store,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
    .unwrap();
    let resp_pair = resp_task.await.unwrap();
    assert_eq!(init_pair.sas, resp_pair.sas);

    // Confirm client on host and persist v2 floor.
    let cli_dev_id = cli_id.device_id();
    let grant = host_store
        .update_roster(|rst| {
            let entry = rst.get(&cli_dev_id).unwrap();
            assert_eq!(entry.min_wire_version, WIRE_VERSION_V2);
            assert_eq!(entry.state, PeerState::Pending);
            rst.confirm_peer(&cli_dev_id, init_pair.sas.as_deref())?;
            let g = rst.mint_grant(
                &host_id,
                &cli_dev_id,
                vec!["fs.read:/docs/*".to_owned()],
                now_unix,
                now_unix + 3600,
                [0x12; 16],
            )?;
            Ok(g)
        })
        .unwrap();
    cli_store
        .update_roster(|rst| {
            rst.confirm_peer(host_id.host_id(), init_pair.sas.as_deref())?;
            Ok(())
        })
        .unwrap();

    let host_roster_loaded = host_store.load_roster().unwrap();
    let cli_roster_loaded = cli_store.load_roster().unwrap();
    let host_v2 = host_roster_loaded
        .get(&cli_dev_id)
        .unwrap()
        .v2_secrets
        .clone()
        .unwrap();
    let cli_v2 = cli_roster_loaded
        .get(host_id.host_id())
        .unwrap()
        .v2_secrets
        .clone()
        .unwrap();
    assert_eq!(host_v2, cli_v2);
    let mailbox_secret = *host_v2.mailbox_secret();

    // Start EmbeddedRelay and verify /v2/relay host mismatch rejection on both sides.
    let relay = EmbeddedRelay::bind_local("relay.example").await.unwrap();
    let relay_v2_url = relay.ws_v2_url();

    let bad_listener = RelayV2Listener::bind(
        &relay_v2_url,
        Some("wrong-host.example".to_owned()),
        mailbox_secret,
        Duration::from_secs(1),
    )
    .await;
    assert!(matches!(bad_listener, Err(RuntimeError::Core(_))));

    let bad_dialer = RelayV2Dialer::new(mailbox_secret).with_expected_host("wrong-host.example");
    assert!(matches!(
        bad_dialer.connect(&relay_v2_url).await,
        Err(RuntimeError::Core(_))
    ));

    // Bind legitimate RelayV2Listener and verify 3 isolated per-epoch control sockets.
    let mut relay_listener = RelayV2Listener::bind(
        &relay_v2_url,
        Some("relay.example".to_owned()),
        mailbox_secret,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(relay_listener.active_control_socket_count(), 3);

    // Forged dial_token over raw /v2/relay socket must be silently dropped by listener
    // (must time out on dial without opening an accept socket).
    let epoch = now_unix / 3600;
    let epoch_mb = derive_epoch_mailbox(&mailbox_secret, epoch);
    {
        let (mut evil_ws, _) = connect_async(&relay_v2_url).await.unwrap();
        let _challenge = evil_ws.next().await;
        evil_ws
            .send(Message::Text(
                serde_json::to_string(&RelayV2ClientMsg::Dial {
                    target_mailbox_id: epoch_mb.mailbox_id_b64url(),
                    epoch,
                    conn_id: b64url_encode(&[0xFA; 16]),
                    dial_token: b64url_encode(&[0x00; 32]),
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        // Listener must NOT emit a PathStream for the forged dial.
        assert!(
            tokio::time::timeout(Duration::from_millis(120), relay_listener.accept())
                .await
                .is_err()
        );
    }

    // Legitimate dial through RelayV2Dialer + V2SessionDriver over StateStore + REKEY + cover frame.
    let host_id_c2 = host_id.clone();
    let host_store_c2 = host_store.clone();
    let host_lock_c2 = Arc::clone(&host_store_lock);
    let state_c2 = Arc::clone(&v2_state);
    let accept_task = tokio::spawn(async move {
        let s = relay_listener.accept().await.unwrap();
        assert_eq!(s.provider_id(), ProviderId::Relay);
        let mut drv = V2SessionDriver::accept_with_store(
            s,
            &host_id_c2,
            &host_store_c2,
            &host_lock_c2,
            now_unix,
            &state_c2,
            None,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .unwrap();

        let mut rst = host_store_c2.load_roster().unwrap();
        // First event must skip the 0x08 cover frame and return the padded 0x01 DATA payload.
        assert_eq!(
            drv.next_event(now_unix, &mut rst).await.unwrap(),
            Some(SessionEvent::AppData(b"hello-over-v2-relay".to_vec()))
        );
        assert_eq!(
            drv.next_event(now_unix, &mut rst).await.unwrap(),
            Some(SessionEvent::Rekeyed {
                direction: RekeyDirection::Incoming,
            })
        );
        assert_eq!(
            drv.next_event(now_unix, &mut rst).await.unwrap(),
            Some(SessionEvent::AppData(b"post-rekey-secret".to_vec()))
        );
        drv.send_data(b"host-ack").await.unwrap();
        drv
    });

    let dialer = RelayV2Dialer::new(mailbox_secret).with_expected_host("relay.example");
    let stream = dialer.connect(&relay_v2_url).await.unwrap();
    let mut cli_driver = V2SessionDriver::connect_with_store(
        stream,
        &cli_id,
        host_id.host_id(),
        Some(grant),
        &cli_store,
        &cli_store_lock,
        now_unix,
    )
    .await
    .unwrap();

    // Send a 0x08 cover frame, padded app data, trigger jittered REKEY, and send post-rekey data.
    cli_driver.send_dummy_cover(256).await.unwrap();
    cli_driver.send_data(b"hello-over-v2-relay").await.unwrap();
    cli_driver.send_rekey().await.unwrap();
    cli_driver.send_data(b"post-rekey-secret").await.unwrap();

    let mut cli_rst_mem = cli_store.load_roster().unwrap();
    assert_eq!(
        cli_driver
            .next_event(now_unix, &mut cli_rst_mem)
            .await
            .unwrap(),
        Some(SessionEvent::Rekeyed {
            direction: RekeyDirection::Outgoing,
        })
    );
    assert_eq!(
        cli_driver
            .next_event(now_unix, &mut cli_rst_mem)
            .await
            .unwrap(),
        Some(SessionEvent::AppData(b"host-ack".to_vec()))
    );

    let host_driver = accept_task.await.unwrap();
    // Verify exported secrets persisted post-establish match on both sides while keeping mailbox_secret.
    let host_after = host_store.load_roster().unwrap();
    let cli_after = cli_store.load_roster().unwrap();
    let host_sec_after = host_after
        .get(&cli_dev_id)
        .unwrap()
        .v2_secrets
        .as_ref()
        .unwrap();
    let cli_sec_after = cli_after
        .get(host_id.host_id())
        .unwrap()
        .v2_secrets
        .as_ref()
        .unwrap();
    assert_eq!(
        host_sec_after.reconnect_secret(),
        cli_sec_after.reconnect_secret()
    );
    assert_eq!(
        host_sec_after.reconnect_secret(),
        host_v2.reconnect_secret()
    );
    assert_eq!(
        host_after.get(&cli_dev_id).unwrap().min_wire_version,
        WIRE_VERSION_V2
    );
    assert_eq!(
        cli_after.get(host_id.host_id()).unwrap().min_wire_version,
        WIRE_VERSION_V2
    );
    assert_eq!(host_sec_after.mailbox_secret(), &mailbox_secret);
    assert_eq!(cli_sec_after.mailbox_secret(), &mailbox_secret);
    assert_ne!(
        host_driver
            .exported_v2_secrets()
            .unwrap()
            .reconnect_secret(),
        host_sec_after.reconnect_secret()
    );

    relay.shutdown().await.unwrap();
}

#[tokio::test]
async fn relay_v2_listener_drops_replayed_incoming_from_malicious_relay() {
    let mailbox_secret = [0x66; 32];
    let now_unix = now_unix_secs();
    let epoch = now_unix / 3600;
    let mb = derive_epoch_mailbox(&mailbox_secret, epoch);

    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let url = format!("ws://{addr}/v2/relay");
    let dial_nonce = [0x91; 32];
    let conn_id = [0x42; 16];
    let dial_token = sign_v2_relay_dial(&mb, "127.0.0.1", &dial_nonce, &conn_id).unwrap();

    let accept_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accept_count_c = Arc::clone(&accept_count);
    let srv_task = tokio::spawn(async move {
        let mut accepted_conn = false;
        loop {
            let Ok((stream, _)) = tcp.accept().await else {
                break;
            };
            let accept_count_cc = Arc::clone(&accept_count_c);
            let mb_c = mb.clone();
            tokio::spawn(async move {
                let mut ws = accept_async(stream).await.unwrap();
                ws.send(Message::Text(
                    serde_json::to_string(&RelayV2ServerMsg::Challenge {
                        nonce: b64url_encode(&[0x10; 32]),
                        host: canonical_relay_host("127.0.0.1").unwrap(),
                        epoch,
                        max_frame: MAX_RELAY_FRAME_LEN,
                        auth_required: None,
                    })
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();

                let Some(Ok(Message::Text(first))) = ws.next().await else {
                    return;
                };
                match serde_json::from_str::<RelayV2ClientMsg>(&first).unwrap() {
                    RelayV2ClientMsg::Register {
                        mailbox_id,
                        epoch: reg_epoch,
                        ..
                    } => {
                        ws.send(Message::Text(
                            serde_json::to_string(&RelayV2ServerMsg::Registered {
                                mailbox_id: mailbox_id.clone(),
                                epoch: reg_epoch,
                            })
                            .unwrap()
                            .into(),
                        ))
                        .await
                        .unwrap();
                        if reg_epoch == mb_c.epoch {
                            let incoming = RelayV2ServerMsg::Incoming {
                                mailbox_id,
                                epoch: reg_epoch,
                                conn_id: b64url_encode(&conn_id),
                                dial_nonce: b64url_encode(&dial_nonce),
                                dial_token: b64url_encode(&dial_token),
                            };
                            let text = serde_json::to_string(&incoming).unwrap();
                            // Send authentic incoming once, then maliciously replay the exact same incoming!
                            ws.send(Message::Text(text.clone().into())).await.unwrap();
                            ws.send(Message::Text(text.into())).await.unwrap();
                        }
                        while let Some(Ok(_)) = ws.next().await {}
                    }
                    RelayV2ClientMsg::Accept { conn_id, .. } => {
                        accept_count_cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        ws.send(Message::Text(
                            serde_json::to_string(&RelayV2ServerMsg::Ready { conn_id })
                                .unwrap()
                                .into(),
                        ))
                        .await
                        .unwrap();
                        while let Some(Ok(_)) = ws.next().await {}
                    }
                    RelayV2ClientMsg::Dial { .. } => {}
                }
            });
            if !accepted_conn {
                accepted_conn = true;
            }
        }
    });

    let mut listener = RelayV2Listener::bind_with_config(
        &url,
        mailbox_secret,
        RelayV2ListenerConfig {
            unix_secs: Some(now_unix),
            ..RelayV2ListenerConfig::default()
        },
    )
    .await
    .unwrap();

    // First authentic incoming triggers exactly 1 accept stream.
    let _first = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    // Replayed incoming MUST NOT open a second accept socket!
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(accept_count.load(std::sync::atomic::Ordering::SeqCst), 1);

    drop(listener);
    srv_task.abort();
}

#[tokio::test]
async fn shared_rendezvous_replay_cache_and_argon2_semaphore_protect_responder() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();
    let secrets = V2PeerSecrets::new([0x77; 32], [0x88; 32]);
    let (host_roster, _cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &secrets);
    let host_roster = Arc::new(Mutex::new(host_roster));

    let v2_state = Arc::new(V2ResponderState::new());
    let sock_dir = tempdir().unwrap();
    let sock_path = sock_dir.path().join("sess.sock");
    let mut listener = LocalListener::bind(&sock_path).unwrap();
    let ep = listener.local_endpoint();

    // Spawn 4 inbound responder handshakes sharing the SAME V2ResponderState.
    let host_c = host_id.clone();
    let rst_c = Arc::clone(&host_roster);
    let state_c = Arc::clone(&v2_state);
    let srv = tokio::spawn(async move {
        let mut results = Vec::new();
        for _ in 0..4 {
            let s = listener.accept().await.unwrap();
            let mut r = rst_c.lock().unwrap().clone();
            let res =
                drive_v2_session_responder(s, &host_c, &mut r, now_unix, &state_c, None).await;
            results.push(res.is_ok());
        }
        results
    });

    // Connection 1: legitimate handshake completes and inserts its rendezvous tag into shared cache.
    let mut machine1 = V2SessionInitiator::new(
        &cli_id,
        host_id.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let actions1 = machine1.start(now_unix).unwrap();
    let msg1_wire: Vec<u8> = actions1
        .into_iter()
        .filter_map(|a| match a {
            tendril_core::v2::V2SessionAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect();

    let mut s1 = LocalDialer::new().dial(&ep).await.unwrap();
    s1.send_chunk(&msg1_wire).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let n1 = s1.recv_chunk(&mut buf).await.unwrap();
    let mut cli_r = setup_paired_v2_rosters(&host_id, &cli_id, &secrets).1;
    let msg2_actions = machine1
        .feed_bytes(&buf[..n1], now_unix, 10, &mut cli_r)
        .unwrap();
    for a in msg2_actions {
        if let tendril_core::v2::V2SessionAction::WriteBytes(b) = a {
            s1.send_chunk(&b).await.unwrap();
        }
    }
    assert!(machine1.is_established());
    drop(s1);
    assert_eq!(v2_state.replay_cache().lock().unwrap().len(), 1);

    // Connection 2: capture msg1_b from machine_b without consuming machine_b on genuine msg2_b.
    let mut machine_b = V2SessionInitiator::new(
        &cli_id,
        host_id.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let msg1_b: Vec<u8> = machine_b
        .start(now_unix)
        .unwrap()
        .into_iter()
        .filter_map(|a| match a {
            tendril_core::v2::V2SessionAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect();
    let mut s2 = LocalDialer::new().dial(&ep).await.unwrap();
    s2.send_chunk(&msg1_b).await.unwrap();
    let n2 = s2.recv_chunk(&mut buf).await.unwrap();
    let genuine_msg2_b = buf[..n2].to_vec();
    s2.close().await.unwrap();
    assert_eq!(v2_state.replay_cache().lock().unwrap().len(), 2);

    // Connection 3: replay exact msg1_b -> shared cache rejects it with a decoy msg2_b,
    // without inserting a new cache entry; the REAL machine_b must reject decoy_msg2_b.
    let mut s3 = LocalDialer::new().dial(&ep).await.unwrap();
    s3.send_chunk(&msg1_b).await.unwrap();
    let n3 = s3.recv_chunk(&mut buf).await.unwrap();
    assert!(n3 > 0);
    let decoy_msg2_b = buf[..n3].to_vec();
    assert_ne!(decoy_msg2_b, genuine_msg2_b);
    s3.close().await.unwrap();
    assert_eq!(v2_state.replay_cache().lock().unwrap().len(), 2);
    assert!(
        machine_b
            .feed_bytes(&decoy_msg2_b, now_unix, 10, &mut cli_r)
            .is_err(),
        "real initiator for msg1_b must reject decoy msg2 from replayed msg1"
    );

    // Connection 4: replay Connection 1's msg1_wire across another connection -> still cached!
    let mut s4 = LocalDialer::new().dial(&ep).await.unwrap();
    s4.send_chunk(&msg1_wire).await.unwrap();
    let n4 = s4.recv_chunk(&mut buf).await.unwrap();
    assert!(n4 > 0);
    s4.close().await.unwrap();
    assert_eq!(v2_state.replay_cache().lock().unwrap().len(), 2);

    let srv_outcomes = srv.await.unwrap();
    assert_eq!(srv_outcomes, vec![true, false, false, false]);

    // Verify Argon2id Semaphore saturation rejects fast, permits async reactor ticks while
    // spawn_blocking runs Argon2id, and recovers once permits are released.
    let sat_state = V2ResponderState::with_config(V2ResponderConfig {
        max_concurrent_argon2: 1,
        argon2_acquire_timeout: Duration::from_millis(40),
        ..V2ResponderConfig::default()
    });
    let held_permit = sat_state.argon2_semaphore().acquire_owned().await.unwrap();
    assert_eq!(sat_state.available_argon2_permits(), 0);

    let pair_sock = sock_dir.path().join("sat.sock");
    let mut sat_listener = LocalListener::bind(&pair_sock).unwrap();
    let sat_ep = sat_listener.local_endpoint();
    let mut sat_mgr = PairingManager::new(PairingConfig::default());
    let sat_code = sat_mgr
        .issue_code(PairingCodeKind::Remote3Group, now_unix)
        .unwrap();
    let sat_mgr = Arc::new(Mutex::new(sat_mgr));
    let sat_rst = Arc::new(Mutex::new(Roster::new()));

    let mut sat_cli = LocalDialer::new().dial(&sat_ep).await.unwrap();
    let mut sat_srv = sat_listener.accept().await.unwrap();
    let mut pake_init = tendril_core::v2::V2PakePairInitiator::new(
        &cli_id,
        "Cli".to_owned(),
        "cli".to_owned(),
        sat_code,
        None,
        PakeArgon2Params::production(),
    )
    .unwrap();
    for a in pake_init.start().unwrap() {
        if let tendril_core::v2::V2PairAction::WriteBytes(b) = a {
            sat_cli.send_chunk(&b).await.unwrap();
        }
    }
    let err = drive_v2_pake_pair_responder(
        sat_srv.as_mut(),
        &host_id,
        &sat_mgr,
        &sat_rst,
        PairingPathKind::Remote,
        now_unix,
        &sat_state,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RuntimeError::RateLimited(_)));

    // Release permit, verify permit count returns to 1, and run real PAKE responder in parallel
    // with an async timer tick proving spawn_blocking does not stall the Tokio reactor.
    drop(held_permit);
    assert_eq!(sat_state.available_argon2_permits(), 1);
    let rec_code = sat_mgr
        .lock()
        .unwrap()
        .issue_code(PairingCodeKind::Remote3Group, now_unix)
        .unwrap();
    let host_c2 = host_id.clone();
    let mgr_c2 = Arc::clone(&sat_mgr);
    let rst_c2 = Arc::clone(&sat_rst);
    let state_c2 = sat_state;
    let srv_rec = tokio::spawn(async move {
        let mut s = sat_listener.accept().await.unwrap();
        drive_v2_pake_pair_responder(
            s.as_mut(),
            &host_c2,
            &mgr_c2,
            &rst_c2,
            PairingPathKind::Remote,
            now_unix,
            &state_c2,
            None,
        )
        .await
    });
    let mut rec_cli = LocalDialer::new().dial(&sat_ep).await.unwrap();
    let cli_rec = tendril_runtime::drive_v2_pake_pair_initiator(
        rec_cli.as_mut(),
        &cli_id,
        "Cli".to_owned(),
        "cli".to_owned(),
        rec_code,
        None,
    );
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done_c = Arc::clone(&done);
    let ticker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        let mut ticks = 0usize;
        while !done_c.load(std::sync::atomic::Ordering::Acquire) {
            tokio::select! {
                _ = interval.tick() => {
                    ticks += 1;
                }
                () = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
        ticks
    });
    let (srv_res, cli_res) = tokio::join!(srv_rec, cli_rec);
    done.store(true, std::sync::atomic::Ordering::Release);
    let ticks = ticker.await.unwrap();
    assert!(
        ticks >= 2,
        "expected ticker progress during Argon2id, got {ticks}"
    );
    srv_res.unwrap().unwrap();
    cli_res.unwrap();
}

#[tokio::test]
async fn mid_session_v2_revocation_terminates_authorization_immediately() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();
    let secrets = V2PeerSecrets::new([0x55; 32], [0x66; 32]);
    let (mut host_roster, mut cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &secrets);

    let grant = host_roster
        .mint_grant(
            &host_id,
            &cli_id.device_id(),
            vec!["fs.read:/docs/*".to_owned()],
            now_unix,
            now_unix + 3600,
            [0x22; 16],
        )
        .unwrap();

    let sock_dir = tempdir().unwrap();
    let sock_path = sock_dir.path().join("rev.sock");
    let mut listener = LocalListener::bind(&sock_path).unwrap();
    let ep = listener.local_endpoint();
    let v2_state = Arc::new(V2ResponderState::new());

    let host_c = host_id.clone();
    let state_c = Arc::clone(&v2_state);
    let cli_dev_c = cli_id.device_id();
    let srv_task = tokio::spawn(async move {
        let s = listener.accept().await.unwrap();
        let mut drv =
            drive_v2_session_responder(s, &host_c, &mut host_roster, now_unix, &state_c, None)
                .await
                .unwrap();

        let (auth_ok, _) = drv.authorize("fs.read:/docs/a.txt", now_unix, &host_roster);
        assert!(auth_ok.is_ok());

        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: host_c.host_id().to_owned(),
                seq: 1,
                revoked_nonces: vec![],
                revoked_devices: vec![cli_dev_c],
                ts: "2026-11-21T00:00:00Z".to_owned(),
            },
            host_c.signing_key(),
        )
        .unwrap();
        host_roster
            .ingest_crl(
                crl.clone(),
                host_c.host_id(),
                host_c.signing_key().public_key(),
            )
            .unwrap();
        drv.send_revocation(&crl).await.unwrap();

        // Host-side authorization also fails closed immediately.
        let (auth_after, _) = drv.authorize("fs.read:/docs/a.txt", now_unix + 1, &host_roster);
        assert!(matches!(auth_after, Err(CoreError::PeerRevoked(_))));
    });

    let stream = LocalDialer::new().dial(&ep).await.unwrap();
    let mut cli_drv = drive_v2_session_initiator(
        stream,
        &cli_id,
        host_id.host_id(),
        Some(grant),
        &mut cli_roster,
        now_unix,
    )
    .await
    .unwrap();

    let (cli_auth_ok, _) = cli_drv.authorize("fs.read:/docs/a.txt", now_unix, &cli_roster);
    assert!(cli_auth_ok.is_ok());

    let err = cli_drv
        .next_event(now_unix + 1, &mut cli_roster)
        .await
        .unwrap_err();
    assert!(matches!(err, RuntimeError::Core(CoreError::PeerRevoked(_))));
    let (cli_auth_after, _) = cli_drv.authorize("fs.read:/docs/a.txt", now_unix + 1, &cli_roster);
    assert!(cli_auth_after.is_err());

    srv_task.await.unwrap();
}

#[tokio::test]
async fn v1_pairing_downgrade_is_rejected_for_v2_paired_host_before_sending_bytes() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();

    let host_dir = tempdir().unwrap();
    let cli_dir = tempdir().unwrap();
    let host_store = StateStore::open_or_create(host_dir.path()).unwrap();
    let cli_store = StateStore::open_or_create(cli_dir.path()).unwrap();
    let host_lock = Arc::new(AsyncMutex::new(()));

    let sock_dir = tempdir().unwrap();
    let sock_path = sock_dir.path().join("downgrade.sock");
    let mut listener = LocalListener::bind(&sock_path).unwrap();
    let ep = listener.local_endpoint();

    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, now_unix)
        .unwrap();
    let mgr = Arc::new(Mutex::new(mgr));
    let v2_state = Arc::new(V2ResponderState::new());

    let host_c = host_id.clone();
    let mgr_c = Arc::clone(&mgr);
    let host_store_c = host_store.clone();
    let host_lock_c = Arc::clone(&host_lock);
    let state_c = Arc::clone(&v2_state);
    let resp_task = tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        drive_v2_pake_pair_responder_with_store(
            s.as_mut(),
            &host_c,
            &mgr_c,
            &host_store_c,
            &host_lock_c,
            PairingPathKind::Remote,
            now_unix,
            &state_c,
            None,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .unwrap();
        listener
    });

    let mut s = LocalDialer::new().dial(&ep).await.unwrap();
    let v2_pin = V2PinnedHost::new(
        PinnedHost::with_full_key(
            Some(host_id.host_id().to_owned()),
            *host_id.static_key().public_bytes(),
            host_id.signing_key().public_key().clone(),
            host_id.rotation_seq(),
        ),
        WIRE_VERSION_V2,
    )
    .unwrap();
    drive_v2_pake_pair_initiator_with_store(
        s.as_mut(),
        &cli_id,
        "Cli".to_owned(),
        "cli".to_owned(),
        code,
        Some(v2_pin),
        "Host".to_owned(),
        vec![],
        &cli_store,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
    .unwrap();
    let mut listener = resp_task.await.unwrap();

    // Now attempt v1 pairing against the persisted v2-pinned host using drive_pair_initiator_with_store.
    let v1_pin = PinnedHost::with_full_key(
        Some(host_id.host_id().to_owned()),
        *host_id.static_key().public_bytes(),
        host_id.signing_key().public_key().clone(),
        host_id.rotation_seq(),
    );
    let mut raw_pair = LocalDialer::new().dial(&ep).await.unwrap();
    let mut server_seen = listener.accept().await.unwrap();
    let err = drive_pair_initiator_with_store(
        raw_pair.as_mut(),
        &cli_id,
        "Cli".to_owned(),
        "cli".to_owned(),
        "TND-AAAA-BBBB-CCCC".to_owned(),
        Some(v1_pin.clone()),
        &cli_store,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        RuntimeError::Core(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1,
        })
    ));
    drop(raw_pair);

    // Zero bytes were transmitted to the server before VersionDowngrade aborted.
    let mut probe_buf = [0u8; 64];
    let n = server_seen.recv_chunk(&mut probe_buf).await.unwrap();
    assert_eq!(n, 0);

    // M2M enrollment downgrade attempt also fails closed with VersionDowngrade.
    let m2m_token = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: host_id.host_id().to_owned(),
            subject: cli_id.device_id(),
            caps: vec!["enroll.device".to_owned()],
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            not_after: "2099-01-01T00:00:00Z".to_owned(),
            nonce: b64url_encode(&[0x33; 16]),
            delegated_from: vec![],
            uses: None,
            machine: None,
        },
        host_id.signing_key(),
    )
    .unwrap();
    let mut raw_m2m = LocalDialer::new().dial(&ep).await.unwrap();
    let err_m2m = drive_m2m_enroll_initiator_with_store(
        raw_m2m.as_mut(),
        &cli_id,
        "Cli".to_owned(),
        "cli".to_owned(),
        m2m_token,
        v1_pin,
        &cli_store,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err_m2m,
        RuntimeError::Core(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1,
        })
    ));
}

#[tokio::test]
async fn wake_provider_memory_http_and_noop_integrate_with_v2_relay() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();
    let secrets = V2PeerSecrets::new([0x91; 32], [0x92; 32]);
    let (mut host_roster, mut cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &secrets);
    let mailbox_secret = *secrets.mailbox_secret();

    let relay = EmbeddedRelay::bind_local("relay.example").await.unwrap();
    let relay_v2_url = relay.ws_v2_url();
    let v2_state = Arc::new(V2ResponderState::new());

    // 1. MemoryWakeProvider wakes a sleeping listener to register on /v2/relay and accept V2Session.
    let mem_wake = Arc::new(MemoryWakeProvider::with_cooldown_secs(0));
    let wake_secret = WakeSecret::from_bytes([0xAB; 32]);
    let wake_target =
        WakeTarget::new(WakeAdapterKind::UnifiedPush, "https://push.example/up/dev1").unwrap();
    let wake_opts = WakeDialOptions::new(
        Arc::clone(&mem_wake) as Arc<dyn tendril_runtime::WakeProvider>,
        wake_target,
        wake_secret.clone(),
    )
    .with_retry_delay(Duration::from_millis(40))
    .with_max_attempts(25);

    let mem_wake_c = Arc::clone(&mem_wake);
    let url_c = relay_v2_url.clone();
    let host_c = host_id.clone();
    let state_c = Arc::clone(&v2_state);
    let wake_secret_c = wake_secret.clone();
    let mut host_rst_1 = host_roster.clone();
    let sleeper_task = tokio::spawn(async move {
        // Poll MemoryWakeProvider for the opaque WakeTag, verify it, then bind RelayV2Listener.
        let rec = loop {
            if let Some(ev) = mem_wake_c.recorded().pop() {
                break ev;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(verify_epoch_wake_tag_window(
            wake_secret_c.as_bytes(),
            &rec.tag,
            now_unix
        ));
        let mut listener = RelayV2Listener::bind(
            &url_c,
            Some("relay.example".to_owned()),
            mailbox_secret,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let s = listener.accept().await.unwrap();
        let mut drv =
            drive_v2_session_responder(s, &host_c, &mut host_rst_1, now_unix, &state_c, None)
                .await
                .unwrap();
        assert_eq!(
            drv.next_event(now_unix, &mut host_rst_1).await.unwrap(),
            Some(SessionEvent::AppData(b"woken-by-memory".to_vec()))
        );
    });

    let dialer = RelayV2Dialer::new(mailbox_secret).with_expected_host("relay.example");
    let (mut cli_drv_1, outcome_1) = wake_and_connect_v2_session(
        &dialer,
        &relay_v2_url,
        &wake_opts,
        &cli_id,
        host_id.host_id(),
        None,
        &mut cli_roster,
        now_unix,
    )
    .await
    .unwrap();
    assert_eq!(outcome_1, Some(WakeOutcome::Delivered));
    cli_drv_1.send_data(b"woken-by-memory").await.unwrap();
    sleeper_task.await.unwrap();

    // 2. Loopback HttpWakeProvider delivers WakeTag over HTTP/1.1 to wake a second listener.
    let http_sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_sink.local_addr().unwrap();
    let wake_notify = Arc::new(Notify::new());
    let wake_notify_c = Arc::clone(&wake_notify);
    let wake_secret_http = wake_secret.clone();
    let sink_task = tokio::spawn(async move {
        let (mut sock, _) = http_sink.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let header_end;
        loop {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }
        let headers = std::str::from_utf8(&buf[..header_end]).unwrap().to_owned();
        let clen = headers
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap();
        while buf.len() < header_end + clen {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&tmp[..n]);
        }
        let json: serde_json::Value =
            serde_json::from_slice(&buf[header_end..header_end + clen]).unwrap();
        let tag = WakeTag::from_b64url(json["wake_tag"].as_str().unwrap()).unwrap();
        assert!(verify_epoch_wake_tag_window(
            wake_secret_http.as_bytes(),
            &tag,
            now_unix
        ));
        sock.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        wake_notify_c.notify_one();
    });

    let url_c2 = relay_v2_url.clone();
    let host_c2 = host_id.clone();
    let state_c2 = Arc::clone(&v2_state);
    let mut host_rst_2 = host_roster.clone();
    let sleeper_http = tokio::spawn(async move {
        wake_notify.notified().await;
        let mut listener = RelayV2Listener::bind(
            &url_c2,
            Some("relay.example".to_owned()),
            mailbox_secret,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let s = listener.accept().await.unwrap();
        let mut drv =
            drive_v2_session_responder(s, &host_c2, &mut host_rst_2, now_unix, &state_c2, None)
                .await
                .unwrap();
        assert_eq!(
            drv.next_event(now_unix, &mut host_rst_2).await.unwrap(),
            Some(SessionEvent::AppData(b"woken-by-http".to_vec()))
        );
    });

    let http_provider = Arc::new(HttpWakeProvider::new().with_cooldown_secs(0));
    let http_target = WakeTarget::new(
        WakeAdapterKind::Webhook,
        &format!("http://{http_addr}/wake"),
    )
    .unwrap();
    let http_opts = WakeDialOptions::new(http_provider, http_target, wake_secret.clone())
        .with_retry_delay(Duration::from_millis(40))
        .with_max_attempts(25);
    let (mut cli_drv_2, outcome_2) = wake_and_connect_v2_session(
        &dialer,
        &relay_v2_url,
        &http_opts,
        &cli_id,
        host_id.host_id(),
        None,
        &mut cli_roster,
        now_unix,
    )
    .await
    .unwrap();
    assert_eq!(outcome_2, Some(WakeOutcome::Delivered));
    cli_drv_2.send_data(b"woken-by-http").await.unwrap();
    sink_task.await.unwrap();
    sleeper_http.await.unwrap();

    // 3. NoopWakeProvider works identically with zero push infrastructure when already listening.
    let mut active_listener = RelayV2Listener::bind(
        &relay_v2_url,
        Some("relay.example".to_owned()),
        mailbox_secret,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let host_c3 = host_id.clone();
    let state_c3 = Arc::clone(&v2_state);
    let noop_srv = tokio::spawn(async move {
        let s = active_listener.accept().await.unwrap();
        let mut drv =
            drive_v2_session_responder(s, &host_c3, &mut host_roster, now_unix, &state_c3, None)
                .await
                .unwrap();
        assert_eq!(
            drv.next_event(now_unix, &mut host_roster).await.unwrap(),
            Some(SessionEvent::AppData(b"noop-wake-ok".to_vec()))
        );
    });

    let noop_target =
        WakeTarget::new(WakeAdapterKind::UnifiedPush, "https://push.example/up/noop").unwrap();
    let noop_opts = WakeDialOptions::new(Arc::new(NoopWakeProvider), noop_target, wake_secret)
        .with_pre_wake(true);
    let (mut cli_drv_3, outcome_3) = wake_and_connect_v2_session(
        &dialer,
        &relay_v2_url,
        &noop_opts,
        &cli_id,
        host_id.host_id(),
        None,
        &mut cli_roster,
        now_unix,
    )
    .await
    .unwrap();
    assert_eq!(outcome_3, Some(WakeOutcome::Noop));
    cli_drv_3.send_data(b"noop-wake-ok").await.unwrap();
    noop_srv.await.unwrap();

    relay.shutdown().await.unwrap();
}

#[tokio::test]
async fn concurrent_v2_session_and_relay_v2_epoch_window_work_end_to_end() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();
    let epoch = now_unix / 3600;
    let secrets = V2PeerSecrets::new([0xA1; 32], [0xB2; 32]);
    let (host_roster, mut cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &secrets);
    let host_roster = Arc::new(Mutex::new(host_roster));
    let mailbox_secret = *secrets.mailbox_secret();

    let relay = EmbeddedRelay::bind_local("relay.example").await.unwrap();
    let relay_v2_url = relay.ws_v2_url();

    let mut listener = RelayV2Listener::bind(
        &relay_v2_url,
        Some("relay.example".to_owned()),
        mailbox_secret,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let v2_state = Arc::new(V2ResponderState::new());

    let host_c = host_id.clone();
    let rst_c = Arc::clone(&host_roster);
    let state_c = Arc::clone(&v2_state);
    let srv_task = tokio::spawn(async move {
        for expected_msg in [b"epoch-prev".as_slice(), b"epoch-next".as_slice()] {
            let s = listener.accept().await.unwrap();
            let drv = V2SessionDriver::accept_locked(
                s,
                &host_c,
                &rst_c,
                now_unix,
                &state_c,
                None,
                None,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .unwrap();
            let conc = Arc::new(drv.into_concurrent());
            let ev = conc.next_event_locked_now(&rst_c).await.unwrap();
            assert_eq!(ev, Some(SessionEvent::AppData(expected_msg.to_vec())));
            conc.send_data(b"concurrent-pong").await.unwrap();
            conc.send_close(1000, "done").await.unwrap();
        }
    });

    let dialer = RelayV2Dialer::new(mailbox_secret).with_expected_host("relay.example");
    let cli_roster_lock = Arc::new(Mutex::new(cli_roster.clone()));
    for (target_epoch, msg) in [
        (epoch.saturating_sub(1), b"epoch-prev".as_slice()),
        (epoch + 1, b"epoch-next".as_slice()),
    ] {
        let s = dialer
            .connect_for_epoch(&relay_v2_url, target_epoch)
            .await
            .unwrap();
        let drv = V2SessionDriver::connect(
            s,
            &cli_id,
            host_id.host_id(),
            None,
            &mut cli_roster,
            now_unix,
        )
        .await
        .unwrap();
        let conc = drv.into_concurrent();
        conc.send_ping(42).await.unwrap();
        conc.send_data(msg).await.unwrap();
        assert_eq!(
            conc.next_event_locked_now(&cli_roster_lock).await.unwrap(),
            Some(SessionEvent::PongReceived(42))
        );
        assert_eq!(
            conc.next_event_locked_now(&cli_roster_lock).await.unwrap(),
            Some(SessionEvent::AppData(b"concurrent-pong".to_vec()))
        );
        assert_eq!(
            conc.next_event_locked_now(&cli_roster_lock).await.unwrap(),
            Some(SessionEvent::Closed {
                code: 1000,
                reason: "done".to_owned(),
            })
        );
    }

    srv_task.await.unwrap();
    relay.shutdown().await.unwrap();
}

struct CorruptMsg3Stream {
    inner: Box<dyn PathStream>,
    saw_msg2: bool,
    corrupted_msg3: bool,
}

#[async_trait]
impl PathStream for CorruptMsg3Stream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.peer_ip()
    }

    fn peer_transport_id(&self) -> Option<String> {
        self.inner.peer_transport_id()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if self.saw_msg2 && !self.corrupted_msg3 && !bytes.is_empty() {
            self.corrupted_msg3 = true;
            let mut corrupted = bytes.to_vec();
            let last = corrupted.len() - 1;
            corrupted[last] ^= 0xFF;
            return self.inner.send_chunk(&corrupted).await;
        }
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        let n = self.inner.recv_chunk(buf).await?;
        if n > 0 {
            self.saw_msg2 = true;
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

struct FailWriteAfterEstablishStream {
    inner: Box<dyn PathStream>,
    fail_writes: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl PathStream for FailWriteAfterEstablishStream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.inner.peer_ip()
    }

    fn peer_transport_id(&self) -> Option<String> {
        self.inner.peer_transport_id()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(RuntimeError::Closed);
        }
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.inner.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        split_path_stream_fallback(self)
    }
}

struct HungWakeProvider {
    called: Arc<Notify>,
}

#[async_trait]
impl WakeProvider for HungWakeProvider {
    async fn notify(
        &self,
        _target: &WakeTarget,
        _tag: &WakeTag,
        _now_unix: u64,
    ) -> Result<WakeOutcome, RuntimeError> {
        self.called.notify_one();
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok(WakeOutcome::Delivered)
    }
}

#[tokio::test]
async fn blocker2_corrupted_msg3_preserves_v2_secrets_for_subsequent_reconnect() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();
    let secrets = V2PeerSecrets::new([0x33; 32], [0x44; 32]);
    let (host_roster, cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &secrets);

    let host_dir = tempdir().unwrap();
    let cli_dir = tempdir().unwrap();
    let host_store = StateStore::open_or_create(host_dir.path()).unwrap();
    let cli_store = StateStore::open_or_create(cli_dir.path()).unwrap();
    host_store.save_roster(&host_roster).unwrap();
    cli_store.save_roster(&cli_roster).unwrap();
    let host_lock = Arc::new(AsyncMutex::new(()));
    let cli_lock = Arc::new(AsyncMutex::new(()));

    let sock_dir = tempdir().unwrap();
    let mut listener = LocalListener::bind(sock_dir.path().join("reconnect.sock")).unwrap();
    let ep = listener.local_endpoint();
    let v2_state = Arc::new(V2ResponderState::new());

    // Reconnect 1: msg3 is corrupted on the wire after client completes connect_with_store.
    let host_c1 = host_id.clone();
    let hs1 = host_store.clone();
    let hl1 = Arc::clone(&host_lock);
    let vs1 = Arc::clone(&v2_state);
    let srv1 = tokio::spawn(async move {
        let s = listener.accept().await.unwrap();
        let res = V2SessionDriver::accept_with_store(
            s,
            &host_c1,
            &hs1,
            &hl1,
            now_unix,
            &vs1,
            None,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await;
        (res.is_err(), listener)
    });

    let raw_s1 = LocalDialer::new().dial(&ep).await.unwrap();
    let corrupt_s1: Box<dyn PathStream> = Box::new(CorruptMsg3Stream {
        inner: raw_s1,
        saw_msg2: false,
        corrupted_msg3: false,
    });
    let drv_cli1 = V2SessionDriver::connect_with_store(
        corrupt_s1,
        &cli_id,
        host_id.host_id(),
        None,
        &cli_store,
        &cli_lock,
        now_unix,
    )
    .await
    .unwrap();
    drop(drv_cli1);

    let (srv1_failed, mut listener) = srv1.await.unwrap();
    assert!(srv1_failed, "responder must reject corrupted msg3");

    // Reconnect 2: pairing-derived v2_secrets must still match across both StateStores!
    let host_c2 = host_id.clone();
    let hs2 = host_store.clone();
    let hl2 = Arc::clone(&host_lock);
    let vs2 = Arc::clone(&v2_state);
    let srv2 = tokio::spawn(async move {
        let s = listener.accept().await.unwrap();
        let mut drv = V2SessionDriver::accept_with_store(
            s,
            &host_c2,
            &hs2,
            &hl2,
            now_unix,
            &vs2,
            None,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .unwrap();
        let mut r = hs2.load_roster().unwrap();
        let ev = drv.next_event(now_unix, &mut r).await.unwrap();
        assert_eq!(
            ev,
            Some(SessionEvent::AppData(b"after-corrupt-msg3".to_vec()))
        );
    });

    let raw_s2 = LocalDialer::new().dial(&ep).await.unwrap();
    let mut drv_cli2 = V2SessionDriver::connect_with_store(
        raw_s2,
        &cli_id,
        host_id.host_id(),
        None,
        &cli_store,
        &cli_lock,
        now_unix,
    )
    .await
    .unwrap();
    drv_cli2.send_data(b"after-corrupt-msg3").await.unwrap();
    drv_cli2.send_close(1000, "ok").await.unwrap();
    srv2.await.unwrap();
}

#[tokio::test]
async fn relay_v2_listener_drop_closes_control_sockets_and_dialer_sees_offline() {
    let relay = EmbeddedRelay::bind_local("relay.example").await.unwrap();
    let relay_v2_url = relay.ws_v2_url();
    let mailbox_secret = [0x99; 32];

    let listener = RelayV2Listener::bind(
        &relay_v2_url,
        Some("relay.example".to_owned()),
        mailbox_secret,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let epoch = listener.epoch_window().center_epoch;

    // Dropping the listener without an explicit async shutdown must immediately close its
    // epoch control sockets so the relay unregisters all three epoch mailboxes.
    drop(listener);

    let dialer = RelayV2Dialer::new(mailbox_secret).with_expected_host("relay.example");
    for target_epoch in [epoch.saturating_sub(1), epoch, epoch + 1] {
        let mut got_offline = false;
        for _ in 0..40 {
            match dialer.connect_for_epoch(&relay_v2_url, target_epoch).await {
                Err(RuntimeError::Protocol(msg)) if msg.contains("offline") => {
                    got_offline = true;
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
                Ok(_) => panic!(
                    "dial for epoch {target_epoch} must not succeed after RelayV2Listener drop"
                ),
            }
        }
        assert!(
            got_offline,
            "dropped RelayV2Listener did not unregister epoch {target_epoch} as offline"
        );
    }
    relay.shutdown().await.unwrap();
}

#[tokio::test]
async fn relay_v2_listener_reconnects_after_control_socket_killed_on_relay() {
    let relay = EmbeddedRelay::bind_local("relay.example").await.unwrap();
    let relay_v2_url = relay.ws_v2_url();
    let relay_host_port = relay_v2_url
        .strip_prefix("ws://")
        .unwrap()
        .strip_suffix("/v2/relay")
        .unwrap()
        .to_owned();

    // Proxy TCP connections to EmbeddedRelay so the test can drop an active control socket.
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_ws_url = format!("ws://{proxy_addr}/v2/relay");

    let active_forwarders: Arc<Mutex<Vec<tokio::task::AbortHandle>>> =
        Arc::new(Mutex::new(Vec::new()));
    let forwarders_c = Arc::clone(&active_forwarders);
    let target_c = relay_host_port.clone();
    let proxy_task = tokio::spawn(async move {
        while let Ok((mut client_tcp, _)) = proxy_listener.accept().await {
            let target = target_c.clone();
            let handle = tokio::spawn(async move {
                if let Ok(mut server_tcp) = tokio::net::TcpStream::connect(&target).await {
                    let _ = tokio::io::copy_bidirectional(&mut client_tcp, &mut server_tcp).await;
                }
            });
            forwarders_c.lock().unwrap().push(handle.abort_handle());
        }
    });

    let mailbox_secret = [0xAB; 32];
    let mut listener = RelayV2Listener::bind(
        &proxy_ws_url,
        Some("relay.example".to_owned()),
        mailbox_secret,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(listener.active_control_socket_count(), 3);

    // Kill the first active proxied control connection and verify it recovers back to 3.
    {
        let handles = active_forwarders.lock().unwrap();
        assert!(!handles.is_empty());
        handles[0].abort();
    }
    let mut dropped_below_3 = false;
    for _ in 0..40 {
        if listener.active_control_socket_count() < 3 {
            dropped_below_3 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        dropped_below_3,
        "expected killed control socket to drop active count"
    );

    let mut recovered = false;
    for _ in 0..80 {
        if listener.active_control_socket_count() == 3 {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        recovered,
        "RelayV2Listener failed to reconnect killed control socket back to 3 active sockets"
    );

    // Now dial through the proxy -> relay and exchange bytes on the accepted stream.
    let dialer = RelayV2Dialer::new(mailbox_secret).with_expected_host("relay.example");
    let srv_accept = tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        let mut buf = [0u8; 32];
        let n = s.recv_chunk(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after-ctrl-kill");
        s.send_chunk(b"ctrl-recovered").await.unwrap();
        listener
    });

    let mut cli_s = dialer.dial(&proxy_ws_url).await.unwrap();
    cli_s.send_chunk(b"after-ctrl-kill").await.unwrap();
    let mut buf = [0u8; 32];
    let n = cli_s.recv_chunk(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ctrl-recovered");
    let listener = srv_accept.await.unwrap();

    drop(listener);
    proxy_task.abort();
    relay.shutdown().await.unwrap();
}

#[tokio::test]
async fn unpinned_v1_pairing_with_store_rejects_v2_floored_host_on_learned_static_key() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();

    let cli_dir = tempdir().unwrap();
    let cli_store = StateStore::open_or_create(cli_dir.path()).unwrap();
    let v2_secrets = V2PeerSecrets::new([0x71; 32], [0x72; 32]);
    let (_, cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &v2_secrets);
    cli_store.save_roster(&cli_roster).unwrap();

    // Verify pinned_pairing_floor takes max(static_floor, entry_floor).
    let pin = PinnedHost::with_full_key(
        Some(host_id.host_id().to_owned()),
        *host_id.static_key().public_bytes(),
        host_id.signing_key().public_key().clone(),
        host_id.rotation_seq(),
    );
    assert_eq!(tendril_runtime::pinned_pairing_floor(&cli_roster, &pin), 2);

    let sock_dir = tempdir().unwrap();
    let mut listener = LocalListener::bind(sock_dir.path().join("unpinned_v1.sock")).unwrap();
    let ep = listener.local_endpoint();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, now_unix)
        .unwrap();
    let mgr = Mutex::new(mgr);
    let host_rst = Mutex::new(Roster::new());

    let host_c = host_id.clone();
    let srv = tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        let _ = tendril_runtime::drive_pair_responder(
            s.as_mut(),
            &host_c,
            &mgr,
            &host_rst,
            PairingPathKind::Remote,
            now_unix,
            None,
        )
        .await;
    });

    let mut cli_s = LocalDialer::new().dial(&ep).await.unwrap();
    let err = match drive_pair_initiator_with_store(
        cli_s.as_mut(),
        &cli_id,
        "Workstation".to_owned(),
        "cli".to_owned(),
        code,
        None,
        &cli_store,
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("unpinned v1 pair against stored v2-floored host must fail closed"),
    };
    assert!(
        matches!(
            err,
            RuntimeError::Core(CoreError::VersionDowngrade {
                peer_min: 2,
                negotiated: 1
            })
        ),
        "expected VersionDowngrade(2, 1), got {err:?}"
    );
    srv.await.unwrap();
}

#[tokio::test]
async fn concurrent_v2_session_persists_ingested_crl_to_state_store_and_errors_closed() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();
    let secrets = V2PeerSecrets::new([0x55; 32], [0x66; 32]);
    let (mut host_roster, cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &secrets);

    let host_dir = tempdir().unwrap();
    let cli_dir = tempdir().unwrap();
    let host_store = StateStore::open_or_create(host_dir.path()).unwrap();
    let cli_store = StateStore::open_or_create(cli_dir.path()).unwrap();
    host_store.save_roster(&host_roster).unwrap();
    cli_store.save_roster(&cli_roster).unwrap();
    let host_lock = Arc::new(AsyncMutex::new(()));
    let cli_lock = Arc::new(AsyncMutex::new(()));

    let sock_dir = tempdir().unwrap();
    let mut listener = LocalListener::bind(sock_dir.path().join("crl.sock")).unwrap();
    let ep = listener.local_endpoint();
    let v2_state = Arc::new(V2ResponderState::new());

    let host_c = host_id.clone();
    let hs_c = host_store.clone();
    let hl_c = Arc::clone(&host_lock);
    let vs_c = Arc::clone(&v2_state);
    let srv = tokio::spawn(async move {
        let s = listener.accept().await.unwrap();
        V2SessionDriver::accept_with_store(
            s,
            &host_c,
            &hs_c,
            &hl_c,
            now_unix,
            &vs_c,
            None,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .unwrap()
    });

    let grant = host_roster
        .mint_grant(
            &host_id,
            &cli_id.device_id(),
            vec!["fs.read".to_owned()],
            now_unix,
            now_unix + 3600,
            [0x44; 16],
        )
        .unwrap();
    let raw_cli = LocalDialer::new().dial(&ep).await.unwrap();
    let drv_cli = V2SessionDriver::connect_with_store(
        raw_cli,
        &cli_id,
        host_id.host_id(),
        Some(grant.clone()),
        &cli_store,
        &cli_lock,
        now_unix,
    )
    .await
    .unwrap();
    let drv_srv = srv.await.unwrap();

    let conc_cli = drv_cli.into_concurrent();
    let conc_srv = drv_srv.into_concurrent();

    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host_id.host_id().to_owned(),
            seq: 1,
            revoked_nonces: vec![grant.nonce],
            revoked_devices: vec![cli_id.device_id()],
            ts: "2026-11-21T00:00:00Z".to_owned(),
        },
        host_id.signing_key(),
    )
    .unwrap();
    host_roster
        .ingest_crl(
            crl.clone(),
            host_id.host_id(),
            host_id.signing_key().public_key(),
        )
        .unwrap();
    conc_srv.send_revocation(&crl).await.unwrap();

    let cli_roster_lock = Arc::new(Mutex::new(cli_store.load_roster().unwrap()));
    let err = conc_cli
        .next_event_locked_now(&cli_roster_lock)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            RuntimeError::Core(CoreError::PeerRevoked(_))
                | RuntimeError::Core(CoreError::GrantDenied(_))
        ),
        "expected PeerRevoked or GrantDenied, got {err:?}"
    );
    let persisted = cli_store.load_roster().unwrap();
    assert_eq!(
        persisted.crl(host_id.host_id()).map(|c| c.seq),
        Some(1),
        "CRL seq=1 must be persisted to StateStore before returning PeerRevoked"
    );
    assert_eq!(
        conc_cli
            .next_event_locked_now(&cli_roster_lock)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn hung_wake_provider_times_out_cleanly_via_wake_timeout() {
    let relay = EmbeddedRelay::bind_local("relay.example").await.unwrap();
    let relay_v2_url = relay.ws_v2_url();
    let dialer = RelayV2Dialer::new([0xCD; 32]).with_expected_host("relay.example");

    let called = Arc::new(Notify::new());
    let provider = Arc::new(HungWakeProvider {
        called: Arc::clone(&called),
    });
    let target =
        WakeTarget::new(WakeAdapterKind::UnifiedPush, "https://push.example/up/hung").unwrap();
    let wake = WakeDialOptions::new(provider, target, WakeSecret::from_bytes([0xAB; 32]))
        .with_pre_wake(true)
        .with_wake_timeout(Duration::from_millis(25))
        .with_retry_delay(Duration::from_millis(10))
        .with_max_attempts(2);

    let started = std::time::Instant::now();
    let res = wake_and_dial_v2(&dialer, &relay_v2_url, &wake, now_unix_secs()).await;
    assert!(res.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "hung wake provider must not stall past wake_timeout"
    );
    relay.shutdown().await.unwrap();
}

#[tokio::test]
async fn send_rekey_write_error_closes_v2_session_without_rekeyed_event() {
    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();
    let secrets = V2PeerSecrets::new([0x21; 32], [0x32; 32]);
    let (mut host_roster, mut cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &secrets);

    let sock_dir = tempdir().unwrap();
    let mut listener = LocalListener::bind(sock_dir.path().join("rekey_err.sock")).unwrap();
    let ep = listener.local_endpoint();
    let v2_state = Arc::new(V2ResponderState::new());

    // Sequential V2SessionDriver::send_rekey failure closes session without spurious event.
    let host_c = host_id.clone();
    let vs_c = Arc::clone(&v2_state);
    let srv1 = tokio::spawn(async move {
        let s = listener.accept().await.unwrap();
        let _drv = drive_v2_session_responder(s, &host_c, &mut host_roster, now_unix, &vs_c, None)
            .await
            .unwrap();
        listener
    });
    let fail_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let raw1 = LocalDialer::new().dial(&ep).await.unwrap();
    let wrapped1: Box<dyn PathStream> = Box::new(FailWriteAfterEstablishStream {
        inner: raw1,
        fail_writes: Arc::clone(&fail_flag),
    });
    let mut drv1 = V2SessionDriver::connect(
        wrapped1,
        &cli_id,
        host_id.host_id(),
        None,
        &mut cli_roster,
        now_unix,
    )
    .await
    .unwrap();
    fail_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(drv1.send_rekey().await.is_err());
    assert_eq!(
        drv1.next_event(now_unix, &mut cli_roster).await.unwrap(),
        None
    );
    let mut listener = srv1.await.unwrap();

    // ConcurrentV2Session::send_rekey failure closes session without spurious event.
    let (mut host_roster2, mut cli_roster2) = setup_paired_v2_rosters(&host_id, &cli_id, &secrets);
    let host_c2 = host_id.clone();
    let vs_c2 = Arc::clone(&v2_state);
    let srv2 = tokio::spawn(async move {
        let s = listener.accept().await.unwrap();
        drive_v2_session_responder(s, &host_c2, &mut host_roster2, now_unix, &vs_c2, None)
            .await
            .unwrap();
    });
    let fail_flag2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let raw2 = LocalDialer::new().dial(&ep).await.unwrap();
    let wrapped2: Box<dyn PathStream> = Box::new(FailWriteAfterEstablishStream {
        inner: raw2,
        fail_writes: Arc::clone(&fail_flag2),
    });
    let drv2 = V2SessionDriver::connect(
        wrapped2,
        &cli_id,
        host_id.host_id(),
        None,
        &mut cli_roster2,
        now_unix,
    )
    .await
    .unwrap();
    let conc2 = drv2.into_concurrent();
    fail_flag2.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(conc2.send_rekey().await.is_err());
    let cli_lock2 = Mutex::new(cli_roster2);
    assert_eq!(conc2.next_event_locked_now(&cli_lock2).await.unwrap(), None);
    srv2.await.unwrap();
}

#[tokio::test]
async fn v2_responders_reject_v1_preamble_with_unsupported_version() {
    let (host_id, _cli_id) = make_identities();
    let now_unix = now_unix_secs();
    let sock_dir = tempdir().unwrap();
    let mut listener = LocalListener::bind(sock_dir.path().join("v1_reject.sock")).unwrap();
    let ep = listener.local_endpoint();
    let v2_state = Arc::new(V2ResponderState::new());

    // 1. V2SessionDriver::accept rejects Wire v1 Intent::Session preamble.
    let mut cli_s1 = LocalDialer::new().dial(&ep).await.unwrap();
    let srv_s1 = listener.accept().await.unwrap();
    let v1_sess_pre = Preamble::v1(Intent::Session).encode();
    cli_s1.send_chunk(&v1_sess_pre).await.unwrap();
    let mut r1 = Roster::new();
    let Err(err1) =
        V2SessionDriver::accept(srv_s1, &host_id, &mut r1, now_unix, &v2_state, None).await
    else {
        panic!("v1 session preamble must fail");
    };
    assert!(matches!(
        err1,
        RuntimeError::Core(CoreError::UnsupportedVersion(1))
    ));

    // 2. drive_v2_pake_pair_responder rejects Wire v1 Intent::Pair preamble.
    let mut cli_s2 = LocalDialer::new().dial(&ep).await.unwrap();
    let mut srv_s2 = listener.accept().await.unwrap();
    let mut v1_pair_msg = Preamble::v1(Intent::Pair).encode().to_vec();
    v1_pair_msg.extend_from_slice(&[0x00, 0x02, b'{', b'}']);
    cli_s2.send_chunk(&v1_pair_msg).await.unwrap();
    let mgr = Arc::new(Mutex::new(PairingManager::new(PairingConfig::default())));
    let rst = Arc::new(Mutex::new(Roster::new()));
    let err2 = drive_v2_pake_pair_responder(
        srv_s2.as_mut(),
        &host_id,
        &mgr,
        &rst,
        PairingPathKind::Remote,
        now_unix,
        &v2_state,
        None,
    )
    .await
    .expect_err("v1 pair preamble must fail");
    assert!(matches!(
        err2,
        RuntimeError::Core(CoreError::UnsupportedVersion(1))
    ));
}

#[tokio::test]
async fn inbound_router_isolates_v1_and_v2_pair_and_session_queues_concurrently() {
    use tendril_core::PREAMBLE_LEN;
    use tendril_core::wire::WIRE_VERSION;
    use tendril_runtime::InboundRouter;

    let sock_dir = tempdir().unwrap();
    let listener = LocalListener::bind(sock_dir.path().join("router_v1_v2.sock")).unwrap();
    let ep = listener.local_endpoint();
    let router = InboundRouter::new();
    let handle = tokio::runtime::Handle::current();
    router.spawn_listener(&handle, Box::new(listener));

    let mut c_v1_pair = LocalDialer::new().dial(&ep).await.unwrap();
    let mut c_v1_sess = LocalDialer::new().dial(&ep).await.unwrap();
    let mut c_v2_pair = LocalDialer::new().dial(&ep).await.unwrap();
    let mut c_v2_sess = LocalDialer::new().dial(&ep).await.unwrap();

    c_v1_pair
        .send_chunk(&Preamble::v1(Intent::Pair).encode())
        .await
        .unwrap();
    c_v1_sess
        .send_chunk(&Preamble::v1(Intent::Session).encode())
        .await
        .unwrap();
    c_v2_pair
        .send_chunk(&Preamble::v2_pake_pair().encode())
        .await
        .unwrap();
    c_v2_sess
        .send_chunk(&Preamble::v2(Intent::Session, 0).encode())
        .await
        .unwrap();

    let (mut s_v1_pair, _) = router
        .recv_pair(Duration::from_secs(2))
        .await
        .unwrap()
        .unwrap();
    let (mut s_v1_sess, _) = router
        .recv_session(Duration::from_secs(2))
        .await
        .unwrap()
        .unwrap();
    let (mut s_v2_pair, _) = router
        .recv_v2_pair(Duration::from_secs(2))
        .await
        .unwrap()
        .unwrap();
    let (mut s_v2_sess, _) = router
        .recv_v2_session(Duration::from_secs(2))
        .await
        .unwrap()
        .unwrap();

    let mut buf = [0u8; PREAMBLE_LEN];
    assert_eq!(s_v1_pair.recv_chunk(&mut buf).await.unwrap(), PREAMBLE_LEN);
    assert_eq!(Preamble::decode(&buf).unwrap().version, WIRE_VERSION);
    assert_eq!(Preamble::decode(&buf).unwrap().intent, Intent::Pair);

    assert_eq!(s_v1_sess.recv_chunk(&mut buf).await.unwrap(), PREAMBLE_LEN);
    assert_eq!(Preamble::decode(&buf).unwrap().version, WIRE_VERSION);
    assert_eq!(Preamble::decode(&buf).unwrap().intent, Intent::Session);

    assert_eq!(s_v2_pair.recv_chunk(&mut buf).await.unwrap(), PREAMBLE_LEN);
    assert_eq!(Preamble::decode(&buf).unwrap().version, WIRE_VERSION_V2);
    assert_eq!(Preamble::decode(&buf).unwrap().intent, Intent::Pair);

    assert_eq!(s_v2_sess.recv_chunk(&mut buf).await.unwrap(), PREAMBLE_LEN);
    assert_eq!(Preamble::decode(&buf).unwrap().version, WIRE_VERSION_V2);
    assert_eq!(Preamble::decode(&buf).unwrap().intent, Intent::Session);

    // No cross-contamination into opposite queues.
    assert!(router.recv_pair(Duration::from_millis(50)).await.is_err());
    assert!(
        router
            .recv_v2_pair(Duration::from_millis(50))
            .await
            .is_err()
    );

    // Disabling v2 pair drops v2 Pair without affecting v1 Pair.
    router.set_v2_pair_enabled(false);
    assert!(!router.is_v2_pair_enabled());
    let mut dropped_v2 = LocalDialer::new().dial(&ep).await.unwrap();
    dropped_v2
        .send_chunk(&Preamble::v2_pake_pair().encode())
        .await
        .unwrap();
    assert!(
        router
            .recv_v2_pair(Duration::from_millis(80))
            .await
            .is_err()
    );

    let mut ok_v1 = LocalDialer::new().dial(&ep).await.unwrap();
    ok_v1
        .send_chunk(&Preamble::v1(Intent::Pair).encode())
        .await
        .unwrap();
    assert!(
        router
            .recv_pair(Duration::from_secs(1))
            .await
            .unwrap()
            .is_some()
    );

    let (v2_pq, v2_sq) = router.split_v2_queues();
    router.close();
    assert!(
        tendril_runtime::recv_routed(&v2_pq, Duration::from_secs(1))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        tendril_runtime::recv_routed(&v2_sq, Duration::from_secs(1))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unpinned_v1_tofu_aborts_at_msg2_with_zero_msg3_bytes_on_wire() {
    use tendril_core::pairing::{PairAction, PairingResponder};

    let (host_id, cli_id) = make_identities();
    let now_unix = now_unix_secs();

    // Pre-populate client store with host at min_wire_version = 2.
    let cli_dir = tempdir().unwrap();
    let cli_store = StateStore::open_or_create(cli_dir.path()).unwrap();
    let v2_secrets = V2PeerSecrets::new([0x71; 32], [0x72; 32]);
    let (_, cli_roster) = setup_paired_v2_rosters(&host_id, &cli_id, &v2_secrets);
    cli_store.save_roster(&cli_roster).unwrap();

    // Test both matching static_pub AND rotated static_pub with matching host_id.
    let rotated_host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x91; 32]),
        SigningKeypair::from_seed([0x92; 32]),
    )
    .with_host_id(host_id.host_id().to_owned());

    for responder_id in [host_id.clone(), rotated_host] {
        let sock_dir = tempdir().unwrap();
        let mut listener = LocalListener::bind(sock_dir.path().join("zero_msg3.sock")).unwrap();
        let ep = listener.local_endpoint();
        let mut mgr = PairingManager::new(PairingConfig::default());
        let code = mgr
            .issue_code(PairingCodeKind::Remote3Group, now_unix)
            .unwrap();
        let mut rst = Roster::new();

        let srv = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            let mut resp =
                PairingResponder::new(&responder_id, PairingPathKind::Remote, None).unwrap();
            let mut buf = vec![0u8; 4096];
            // Read msg1 (preamble + Noise e).
            let n1 = s.recv_chunk(&mut buf).await.unwrap();
            assert!(n1 > 0);
            let actions = resp
                .feed_bytes(&buf[..n1], now_unix, &mut mgr, &mut rst)
                .unwrap();
            let mut sent_msg2 = false;
            for a in actions {
                if let PairAction::WriteBytes(b) = a {
                    s.send_chunk(&b).await.unwrap();
                    sent_msg2 = true;
                }
            }
            assert!(sent_msg2);
            // Initiator MUST abort at msg2 and send ZERO msg3 (PairClaim) bytes!
            let after_msg2 = s.recv_chunk(&mut buf).await;
            match after_msg2 {
                Ok(0) | Err(RuntimeError::Closed) | Err(RuntimeError::Io(_)) => {}
                Ok(n) => panic!("expected zero msg3 bytes on wire after msg2, received {n} bytes"),
                Err(e) => panic!("unexpected recv error after msg2: {e:?}"),
            }
        });

        let mut cli_s = LocalDialer::new().dial(&ep).await.unwrap();
        let err = drive_pair_initiator_with_store(
            cli_s.as_mut(),
            &cli_id,
            "Workstation".to_owned(),
            "cli".to_owned(),
            code,
            None,
            &cli_store,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .expect_err("unpinned v1 TOFU against v2-floored host must fail at msg2");
        assert!(matches!(
            err,
            RuntimeError::Core(CoreError::VersionDowngrade {
                peer_min: 2,
                negotiated: 1
            })
        ));
        drop(cli_s);
        srv.await.unwrap();
    }
}

#[test]
fn pinned_pairing_floor_takes_max_of_static_and_host_floors() {
    let host_sk = StaticKeypair::from_scalar([0xA1; 32]);
    let host_vk = SigningKeypair::from_seed([0xA2; 32]);
    let other_sk = StaticKeypair::from_scalar([0xB1; 32]);
    let other_vk = SigningKeypair::from_seed([0xB2; 32]);

    // 1. Entry with host_id="h1" & static_pub=host_sk at v2; pin has different static_pub (other_sk) -> max(1, 2) == 2.
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            "h1".to_owned(),
            "Host1".to_owned(),
            *host_sk.public_bytes(),
            Some(host_vk.public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    roster
        .upgrade_peer_to_v2("h1", V2PeerSecrets::new([1; 32], [2; 32]))
        .unwrap();

    let pin_by_host = PinnedHost::with_full_key(
        Some("h1".to_owned()),
        *other_sk.public_bytes(),
        other_vk.public_key().clone(),
        0,
    );
    assert_eq!(
        tendril_runtime::pinned_pairing_floor(&roster, &pin_by_host),
        2
    );

    // 2. Pin with unknown host_id="h2" (or None) matching static_pub=host_sk -> max(2, 1) == 2.
    let pin_by_static = PinnedHost::with_full_key(
        Some("h2".to_owned()),
        *host_sk.public_bytes(),
        host_vk.public_key().clone(),
        0,
    );
    assert_eq!(
        tendril_runtime::pinned_pairing_floor(&roster, &pin_by_static),
        2
    );

    // 3. Pin matching neither -> 1.
    let pin_none = PinnedHost::with_full_key(
        Some("h2".to_owned()),
        *other_sk.public_bytes(),
        other_vk.public_key().clone(),
        0,
    );
    assert_eq!(tendril_runtime::pinned_pairing_floor(&roster, &pin_none), 1);
}
