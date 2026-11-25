use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{b64url_decode_array, b64url_encode};
use tendril_relay::{
    MAX_RELAY_FRAME_LEN, RelayClientMsg, RelayConfig, RelayServer, RelayServerMsg, RelayTestHook,
    RelayTestPoint, sign_relay_accept, sign_relay_register,
};
use tokio::sync::Notify;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

async fn recv_server_msg(ws: &mut tendril_relay::server::ClientWsStream) -> Option<RelayServerMsg> {
    while let Some(item) = ws.next().await {
        match item {
            Ok(Message::Text(text)) => return serde_json::from_str(&text).ok(),
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            _ => return None,
        }
    }
    None
}

async fn send_client_msg(ws: &mut tendril_relay::server::ClientWsStream, msg: &RelayClientMsg) {
    let text = serde_json::to_string(msg).expect("serialize client msg");
    ws.send(Message::Text(text.into()))
        .await
        .expect("send text msg");
}

#[tokio::test]
async fn relay_register_dial_accept_and_bidirectional_binary_bridge() {
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let handle = server.spawn();
    let url = handle.ws_url();

    let listener_key = SigningKey::from_bytes(&[0x11; 32]);
    let (mut listener_ws, _) = connect_async(&url).await.expect("connect listener");
    let RelayServerMsg::Challenge {
        nonce,
        host,
        max_frame,
        auth_required,
        ..
    } = recv_server_msg(&mut listener_ws).await.expect("challenge")
    else {
        panic!("expected challenge");
    };
    assert_eq!(host, "localhost");
    assert_eq!(max_frame, MAX_RELAY_FRAME_LEN);
    assert_eq!(auth_required, None);
    let nonce_bytes = b64url_decode_array::<32>(&nonce).expect("nonce bytes");
    let (pub_b64, sig_b64) = sign_relay_register(&listener_key, &host, &nonce_bytes);
    send_client_msg(
        &mut listener_ws,
        &RelayClientMsg::Register {
            pub_key: pub_b64.clone(),
            sig: sig_b64,
            auth: None,
            fast_open: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut listener_ws).await,
        Some(RelayServerMsg::Registered {
            pub_key: pub_b64.clone()
        })
    );

    let (mut dialer_ws, _) = connect_async(&url).await.expect("connect dialer");
    assert!(matches!(
        recv_server_msg(&mut dialer_ws).await,
        Some(RelayServerMsg::Challenge { .. })
    ));
    let conn_id_b64 = b64url_encode(&[0x55; 16]);
    send_client_msg(
        &mut dialer_ws,
        &RelayClientMsg::Dial {
            target_pub: pub_b64.clone(),
            conn_id: conn_id_b64.clone(),
            auth: None,
            init_frame: None,
        },
    )
    .await;

    assert_eq!(
        recv_server_msg(&mut listener_ws).await,
        Some(RelayServerMsg::Incoming {
            conn_id: conn_id_b64.clone(),
            init_frame: None,
        })
    );

    let (mut accept_ws, _) = connect_async(&url).await.expect("connect acceptor");
    let RelayServerMsg::Challenge {
        nonce: acc_nonce_b64,
        host: acc_host,
        ..
    } = recv_server_msg(&mut accept_ws)
        .await
        .expect("accept challenge")
    else {
        panic!("expected accept challenge");
    };
    let acc_nonce = b64url_decode_array::<32>(&acc_nonce_b64).expect("acc nonce");
    let acc_sig_b64 = sign_relay_accept(&listener_key, &acc_host, &acc_nonce, &[0x55; 16]);
    send_client_msg(
        &mut accept_ws,
        &RelayClientMsg::Accept {
            pub_key: pub_b64,
            conn_id: conn_id_b64.clone(),
            sig: acc_sig_b64,
            auth: None,
        },
    )
    .await;

    assert_eq!(
        recv_server_msg(&mut accept_ws).await,
        Some(RelayServerMsg::Ready {
            conn_id: conn_id_b64.clone()
        })
    );
    assert_eq!(
        recv_server_msg(&mut dialer_ws).await,
        Some(RelayServerMsg::Ready {
            conn_id: conn_id_b64
        })
    );

    dialer_ws
        .send(Message::Binary(b"hello-via-relay".to_vec().into()))
        .await
        .expect("send dialer frame");
    let from_dialer = accept_ws
        .next()
        .await
        .expect("acceptor recv")
        .expect("frame");
    assert_eq!(
        from_dialer,
        Message::Binary(b"hello-via-relay".to_vec().into())
    );

    accept_ws
        .send(Message::Binary(b"ack-from-acceptor".to_vec().into()))
        .await
        .expect("send acceptor frame");
    let from_acceptor = dialer_ws.next().await.expect("dialer recv").expect("frame");
    assert_eq!(
        from_acceptor,
        Message::Binary(b"ack-from-acceptor".to_vec().into())
    );

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_rejects_bad_proofs_hijacks_wrong_path_and_oversize_frames() {
    let config = RelayConfig {
        max_pending_per_mailbox: 2,
        accept_timeout: Duration::from_secs(5),
        ..RelayConfig::default()
    };
    let server = RelayServer::bind(config).await.expect("bind relay");
    let handle = server.spawn();
    let url = handle.ws_url();
    let base_wrong_path = format!("ws://{}/wrong", handle.local_addr());

    // Wrong HTTP path rejected before upgrade.
    assert!(connect_async(&base_wrong_path).await.is_err());

    // Wrong host in register signature rejected as unauthorized.
    let key_a = SigningKey::from_bytes(&[0x21; 32]);
    let key_attacker = SigningKey::from_bytes(&[0x99; 32]);
    let (mut bad_reg_ws, _) = connect_async(&url).await.expect("connect");
    let RelayServerMsg::Challenge { nonce, host, .. } =
        recv_server_msg(&mut bad_reg_ws).await.expect("challenge")
    else {
        panic!("expected challenge");
    };
    let nonce_bytes = b64url_decode_array::<32>(&nonce).expect("nonce");
    let (pub_a, bad_sig) = sign_relay_register(&key_a, "wrong.example", &nonce_bytes);
    send_client_msg(
        &mut bad_reg_ws,
        &RelayClientMsg::Register {
            pub_key: pub_a.clone(),
            sig: bad_sig,
            auth: None,
            fast_open: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut bad_reg_ws).await,
        Some(RelayServerMsg::Error {
            code: "unauthorized".to_owned()
        })
    );

    // Offline mailbox dial returns offline.
    let (mut off_ws, _) = connect_async(&url).await.expect("connect offline");
    assert!(recv_server_msg(&mut off_ws).await.is_some());
    send_client_msg(
        &mut off_ws,
        &RelayClientMsg::Dial {
            target_pub: pub_a.clone(),
            conn_id: b64url_encode(&[1; 16]),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut off_ws).await,
        Some(RelayServerMsg::Error {
            code: "offline".to_owned()
        })
    );

    // Valid register for key_a.
    let (mut reg_ws, _) = connect_async(&url).await.expect("connect reg");
    let RelayServerMsg::Challenge { nonce, .. } =
        recv_server_msg(&mut reg_ws).await.expect("challenge")
    else {
        panic!("expected challenge");
    };
    let nonce_bytes = b64url_decode_array::<32>(&nonce).expect("nonce");
    let (pub_a, sig_a) = sign_relay_register(&key_a, &host, &nonce_bytes);
    send_client_msg(
        &mut reg_ws,
        &RelayClientMsg::Register {
            pub_key: pub_a.clone(),
            sig: sig_a,
            auth: None,
            fast_open: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut reg_ws).await,
        Some(RelayServerMsg::Registered { .. })
    ));

    // Pending dial #1 and #2 stay open; #3 hits rate_limited.
    let (mut d1, _) = connect_async(&url).await.expect("d1");
    assert!(recv_server_msg(&mut d1).await.is_some());
    send_client_msg(
        &mut d1,
        &RelayClientMsg::Dial {
            target_pub: pub_a.clone(),
            conn_id: b64url_encode(&[0x01; 16]),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut reg_ws).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    let (mut d2, _) = connect_async(&url).await.expect("d2");
    assert!(recv_server_msg(&mut d2).await.is_some());
    send_client_msg(
        &mut d2,
        &RelayClientMsg::Dial {
            target_pub: pub_a.clone(),
            conn_id: b64url_encode(&[0x02; 16]),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut reg_ws).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    let (mut d3, _) = connect_async(&url).await.expect("d3");
    assert!(recv_server_msg(&mut d3).await.is_some());
    send_client_msg(
        &mut d3,
        &RelayClientMsg::Dial {
            target_pub: pub_a.clone(),
            conn_id: b64url_encode(&[0x03; 16]),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut d3).await,
        Some(RelayServerMsg::Error {
            code: "rate_limited".to_owned()
        })
    );

    // Attacker tries to steal pending dial #1 with attacker's key -> rejected, pending #1 intact.
    let (mut hijack_ws, _) = connect_async(&url).await.expect("hijack");
    let RelayServerMsg::Challenge {
        nonce: hj_nonce, ..
    } = recv_server_msg(&mut hijack_ws).await.expect("hj challenge")
    else {
        panic!("expected challenge");
    };
    let hj_nonce_bytes = b64url_decode_array::<32>(&hj_nonce).expect("hj nonce");
    let att_pub = b64url_encode(key_attacker.verifying_key().as_bytes());
    let att_sig = sign_relay_accept(&key_attacker, &host, &hj_nonce_bytes, &[0x01; 16]);
    send_client_msg(
        &mut hijack_ws,
        &RelayClientMsg::Accept {
            pub_key: att_pub,
            conn_id: b64url_encode(&[0x01; 16]),
            sig: att_sig,
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut hijack_ws).await,
        Some(RelayServerMsg::Error {
            code: "unauthorized".to_owned()
        })
    );

    // Legitimate owner accepts pending dial #1 -> succeeds, then oversize binary frame closes both.
    let (mut acc1, _) = connect_async(&url).await.expect("acc1");
    let RelayServerMsg::Challenge {
        nonce: acc_nonce, ..
    } = recv_server_msg(&mut acc1).await.expect("acc challenge")
    else {
        panic!("expected challenge");
    };
    let acc_nonce_bytes = b64url_decode_array::<32>(&acc_nonce).expect("acc nonce");
    let legit_sig = sign_relay_accept(&key_a, &host, &acc_nonce_bytes, &[0x01; 16]);
    send_client_msg(
        &mut acc1,
        &RelayClientMsg::Accept {
            pub_key: pub_a.clone(),
            conn_id: b64url_encode(&[0x01; 16]),
            sig: legit_sig,
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut acc1).await,
        Some(RelayServerMsg::Ready { .. })
    ));
    assert!(matches!(
        recv_server_msg(&mut d1).await,
        Some(RelayServerMsg::Ready { .. })
    ));

    let oversize = vec![0xAAu8; MAX_RELAY_FRAME_LEN + 1];
    let _ = d1.send(Message::Binary(oversize.into())).await;
    let next_on_acc = tokio::time::timeout(Duration::from_secs(2), acc1.next())
        .await
        .expect("close before timeout");
    match next_on_acc {
        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {}
        Some(Ok(other)) => panic!("oversize frame must never be forwarded: {other:?}"),
    }

    // Text frame after Ready also closes both peers cleanly without forwarding.
    let (mut acc2, _) = connect_async(&url).await.expect("acc2");
    let RelayServerMsg::Challenge {
        nonce: acc2_nonce, ..
    } = recv_server_msg(&mut acc2).await.expect("acc2 challenge")
    else {
        panic!("expected challenge");
    };
    let acc2_nonce_bytes = b64url_decode_array::<32>(&acc2_nonce).expect("acc2 nonce");
    let legit_sig2 = sign_relay_accept(&key_a, &host, &acc2_nonce_bytes, &[0x02; 16]);
    send_client_msg(
        &mut acc2,
        &RelayClientMsg::Accept {
            pub_key: pub_a,
            conn_id: b64url_encode(&[0x02; 16]),
            sig: legit_sig2,
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut acc2).await,
        Some(RelayServerMsg::Ready { .. })
    ));
    assert!(matches!(
        recv_server_msg(&mut d2).await,
        Some(RelayServerMsg::Ready { .. })
    ));
    let _ = d2
        .send(Message::Text("illegal-text-after-ready".into()))
        .await;
    let next_on_acc2 = tokio::time::timeout(Duration::from_secs(2), acc2.next())
        .await
        .expect("close before timeout");
    match next_on_acc2 {
        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {}
        Some(Ok(other)) => panic!("text frame after ready must close bridge: {other:?}"),
    }

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_rejects_zero_byte_binary_frames_without_forwarding() {
    let server = RelayServer::bind(RelayConfig {
        accept_timeout: Duration::from_secs(5),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let url = handle.ws_url();

    let key = SigningKey::from_bytes(&[0x33; 32]);
    let (mut reg_ws, _) = connect_async(&url).await.expect("connect reg");
    let RelayServerMsg::Challenge { nonce, host, .. } =
        recv_server_msg(&mut reg_ws).await.expect("challenge")
    else {
        panic!("expected challenge");
    };
    let nonce_bytes = b64url_decode_array::<32>(&nonce).expect("nonce");
    let (pub_b64, reg_sig) = sign_relay_register(&key, &host, &nonce_bytes);
    send_client_msg(
        &mut reg_ws,
        &RelayClientMsg::Register {
            pub_key: pub_b64.clone(),
            sig: reg_sig,
            auth: None,
            fast_open: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut reg_ws).await,
        Some(RelayServerMsg::Registered { .. })
    ));

    let conn_id_bytes = [0x44u8; 16];
    let conn_id_b64 = b64url_encode(&conn_id_bytes);
    let (mut dialer_ws, _) = connect_async(&url).await.expect("connect dialer");
    assert!(recv_server_msg(&mut dialer_ws).await.is_some());
    send_client_msg(
        &mut dialer_ws,
        &RelayClientMsg::Dial {
            target_pub: pub_b64.clone(),
            conn_id: conn_id_b64.clone(),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut reg_ws).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    let (mut acc_ws, _) = connect_async(&url).await.expect("connect acc");
    let RelayServerMsg::Challenge {
        nonce: acc_nonce, ..
    } = recv_server_msg(&mut acc_ws).await.expect("acc challenge")
    else {
        panic!("expected acc challenge");
    };
    let acc_nonce_bytes = b64url_decode_array::<32>(&acc_nonce).expect("acc nonce");
    let acc_sig = sign_relay_accept(&key, &host, &acc_nonce_bytes, &conn_id_bytes);
    send_client_msg(
        &mut acc_ws,
        &RelayClientMsg::Accept {
            pub_key: pub_b64,
            conn_id: conn_id_b64,
            sig: acc_sig,
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut acc_ws).await,
        Some(RelayServerMsg::Ready { .. })
    ));
    assert!(matches!(
        recv_server_msg(&mut dialer_ws).await,
        Some(RelayServerMsg::Ready { .. })
    ));

    dialer_ws
        .send(Message::Binary(Vec::new().into()))
        .await
        .expect("send 0-byte frame");
    let next_on_acc = tokio::time::timeout(Duration::from_secs(2), acc_ws.next())
        .await
        .expect("bridge close before timeout");
    match next_on_acc {
        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {}
        Some(Ok(other)) => panic!("0-byte binary frame must close bridge: {other:?}"),
    }

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_fails_a_pending_dial_offline_when_its_registration_ends() {
    // The accept deadline is far beyond the bound below, so only the registration ending can
    // answer the dial in time.
    let server = RelayServer::bind(RelayConfig {
        accept_timeout: Duration::from_secs(300),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let url = handle.ws_url();

    let listener_key = SigningKey::from_bytes(&[0x61; 32]);
    let (mut listener_ws, _) = connect_async(&url).await.expect("connect listener");
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) =
        recv_server_msg(&mut listener_ws).await
    else {
        panic!("expected challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce bytes");
    let (pub_b64, sig_b64) = sign_relay_register(&listener_key, &host, &nonce);
    send_client_msg(
        &mut listener_ws,
        &RelayClientMsg::Register {
            pub_key: pub_b64.clone(),
            sig: sig_b64,
            auth: None,
            fast_open: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut listener_ws).await,
        Some(RelayServerMsg::Registered { .. })
    ));

    let (mut dialer_ws, _) = connect_async(&url).await.expect("connect dialer");
    assert!(matches!(
        recv_server_msg(&mut dialer_ws).await,
        Some(RelayServerMsg::Challenge { .. })
    ));
    send_client_msg(
        &mut dialer_ws,
        &RelayClientMsg::Dial {
            target_pub: pub_b64,
            conn_id: b64url_encode(&[0x62; 16]),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut listener_ws).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    // The listener vanishes without a close frame and without accepting.
    drop(listener_ws);
    let reply = tokio::time::timeout(Duration::from_secs(10), recv_server_msg(&mut dialer_ws))
        .await
        .expect("pending dial outlived its registration");
    assert_eq!(
        reply,
        Some(RelayServerMsg::Error {
            code: "offline".to_owned()
        })
    );
    handle.stop().await.expect("stop relay");
}

/// Hooks that hold a claimed accept until the dialer has seen its registration end.
fn claim_then_teardown_hook() -> (RelayTestHook, Arc<Notify>) {
    let claimed = Arc::new(Notify::new());
    let teardown = Arc::new(Notify::new());
    let on_claim = Arc::clone(&claimed);
    let hook: RelayTestHook = Arc::new(move |point| {
        let claimed = Arc::clone(&on_claim);
        let teardown = Arc::clone(&teardown);
        Box::pin(async move {
            match point {
                RelayTestPoint::AcceptClaimed => {
                    claimed.notify_one();
                    teardown.notified().await;
                }
                RelayTestPoint::DialTeardown => teardown.notify_one(),
                _ => {}
            }
        })
    });
    (hook, claimed)
}

#[tokio::test]
async fn relay_an_accept_that_claimed_a_dial_wins_over_registration_end() {
    let (hook, claimed) = claim_then_teardown_hook();
    let server = RelayServer::bind(RelayConfig {
        accept_timeout: Duration::from_secs(300),
        test_hook: Some(hook),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let url = handle.ws_url();

    let listener_key = SigningKey::from_bytes(&[0x71; 32]);
    let (mut listener_ws, _) = connect_async(&url).await.expect("connect listener");
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) =
        recv_server_msg(&mut listener_ws).await
    else {
        panic!("expected challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce bytes");
    let (pub_b64, sig_b64) = sign_relay_register(&listener_key, &host, &nonce);
    send_client_msg(
        &mut listener_ws,
        &RelayClientMsg::Register {
            pub_key: pub_b64.clone(),
            sig: sig_b64,
            auth: None,
            fast_open: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut listener_ws).await,
        Some(RelayServerMsg::Registered { .. })
    ));

    let conn_id = [0x72; 16];
    let conn_id_b64 = b64url_encode(&conn_id);
    let (mut dialer_ws, _) = connect_async(&url).await.expect("connect dialer");
    assert!(matches!(
        recv_server_msg(&mut dialer_ws).await,
        Some(RelayServerMsg::Challenge { .. })
    ));
    send_client_msg(
        &mut dialer_ws,
        &RelayClientMsg::Dial {
            target_pub: pub_b64.clone(),
            conn_id: conn_id_b64.clone(),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut listener_ws).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    let (mut accept_ws, _) = connect_async(&url).await.expect("connect acceptor");
    let Some(RelayServerMsg::Challenge {
        nonce: acc_nonce,
        host: acc_host,
        ..
    }) = recv_server_msg(&mut accept_ws).await
    else {
        panic!("expected accept challenge");
    };
    let acc_nonce = b64url_decode_array::<32>(&acc_nonce).expect("acc nonce");
    send_client_msg(
        &mut accept_ws,
        &RelayClientMsg::Accept {
            pub_key: pub_b64,
            conn_id: conn_id_b64.clone(),
            sig: sign_relay_accept(&listener_key, &acc_host, &acc_nonce, &conn_id),
            auth: None,
        },
    )
    .await;

    // The accept holds its claim until the dialer has seen the registration end.
    claimed.notified().await;
    drop(listener_ws);
    let ready = Some(RelayServerMsg::Ready {
        conn_id: conn_id_b64,
    });
    let bound = Duration::from_secs(10);
    let dialer_reply = tokio::time::timeout(bound, recv_server_msg(&mut dialer_ws))
        .await
        .expect("dialer reply");
    let acceptor_reply = tokio::time::timeout(bound, recv_server_msg(&mut accept_ws))
        .await
        .expect("acceptor reply");
    assert_eq!(dialer_reply, ready);
    assert_eq!(acceptor_reply, ready);

    dialer_ws
        .send(Message::Binary(b"after-race".to_vec().into()))
        .await
        .expect("send dialer frame");
    let frame = tokio::time::timeout(bound, accept_ws.next())
        .await
        .expect("bridged frame")
        .expect("acceptor recv")
        .expect("frame");
    assert_eq!(frame, Message::Binary(b"after-race".to_vec().into()));
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v1_standby_registration_zero_accept_hit_and_init_frame() {
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let handle = server.spawn();
    let url = handle.ws_url();

    let listener_key = SigningKey::from_bytes(&[0x31; 32]);
    let (mut ctrl_ws, _) = connect_async(&url).await.expect("connect ctrl");
    let Some(RelayServerMsg::Challenge {
        nonce,
        host,
        fast_open,
        standby,
        ..
    }) = recv_server_msg(&mut ctrl_ws).await
    else {
        panic!("expected challenge");
    };
    assert_eq!(fast_open, Some(true));
    assert_eq!(standby, Some(true));
    let nonce_bytes = b64url_decode_array::<32>(&nonce).unwrap();
    let (pub_b64, sig_b64) = sign_relay_register(&listener_key, &host, &nonce_bytes);
    send_client_msg(
        &mut ctrl_ws,
        &RelayClientMsg::Register {
            pub_key: pub_b64.clone(),
            sig: sig_b64,
            auth: None,
            fast_open: Some(true),
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut ctrl_ws).await,
        Some(RelayServerMsg::Registered {
            pub_key: pub_b64.clone()
        })
    );

    let (mut standby_ws, _) = connect_async(&url).await.expect("connect standby");
    let Some(RelayServerMsg::Challenge {
        nonce: sb_nonce,
        host: sb_host,
        ..
    }) = recv_server_msg(&mut standby_ws).await
    else {
        panic!("expected standby challenge");
    };
    let sb_nonce_bytes = b64url_decode_array::<32>(&sb_nonce).unwrap();
    let (_, sb_sig) = sign_relay_register(&listener_key, &sb_host, &sb_nonce_bytes);
    send_client_msg(
        &mut standby_ws,
        &RelayClientMsg::Standby {
            pub_key: pub_b64.clone(),
            sig: sb_sig,
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut standby_ws).await,
        Some(RelayServerMsg::StandbyReady)
    );

    let (mut dialer_ws, _) = connect_async(&url).await.expect("connect dialer");
    assert!(matches!(
        recv_server_msg(&mut dialer_ws).await,
        Some(RelayServerMsg::Challenge {
            fast_open: Some(true),
            standby: Some(true),
            ..
        })
    ));
    let conn_id_b64 = b64url_encode(&[0x32; 16]);
    let init_bytes = b"TND\x01\x01\x00\x00\x04ping";
    let init_b64 = b64url_encode(init_bytes);
    send_client_msg(
        &mut dialer_ws,
        &RelayClientMsg::Dial {
            target_pub: pub_b64,
            conn_id: conn_id_b64.clone(),
            auth: None,
            init_frame: Some(init_b64.clone()),
        },
    )
    .await;

    // Standby socket gets Incoming with init_frame directly; control socket stays idle; zero Accept needed.
    assert_eq!(
        recv_server_msg(&mut standby_ws).await,
        Some(RelayServerMsg::Incoming {
            conn_id: conn_id_b64.clone(),
            init_frame: Some(init_b64),
        })
    );
    assert_eq!(
        recv_server_msg(&mut dialer_ws).await,
        Some(RelayServerMsg::Ready {
            conn_id: conn_id_b64
        })
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), ctrl_ws.next())
            .await
            .is_err(),
        "control socket must not receive Incoming when standby handled Dial"
    );

    // Bridge is live immediately without Accept or Ready on standby_ws.
    standby_ws
        .send(Message::Binary(b"msg2-from-standby".to_vec().into()))
        .await
        .expect("standby send");
    assert_eq!(
        dialer_ws.next().await.unwrap().unwrap(),
        Message::Binary(b"msg2-from-standby".to_vec().into())
    );
    dialer_ws
        .send(Message::Binary(b"msg3-from-dialer".to_vec().into()))
        .await
        .expect("dialer send");
    assert_eq!(
        standby_ws.next().await.unwrap().unwrap(),
        Message::Binary(b"msg3-from-dialer".to_vec().into())
    );

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v1_standby_dead_socket_skipped_and_classic_init_frame_fallback_modes() {
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let handle = server.spawn();
    let url = handle.ws_url();

    // Case A: fast_open = true listener with dead standby -> skips dead standby and falls back to control Incoming with init_frame.
    let key_a = SigningKey::from_bytes(&[0x41; 32]);
    let (mut ctrl_a, _) = connect_async(&url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_server_msg(&mut ctrl_a).await
    else {
        panic!("challenge");
    };
    let (pub_a, sig_a) =
        sign_relay_register(&key_a, &host, &b64url_decode_array::<32>(&nonce).unwrap());
    send_client_msg(
        &mut ctrl_a,
        &RelayClientMsg::Register {
            pub_key: pub_a.clone(),
            sig: sig_a,
            auth: None,
            fast_open: Some(true),
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut ctrl_a).await,
        Some(RelayServerMsg::Registered { .. })
    ));

    let (mut sb_dead, _) = connect_async(&url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_server_msg(&mut sb_dead).await
    else {
        panic!("challenge");
    };
    let (_, sb_sig) =
        sign_relay_register(&key_a, &host, &b64url_decode_array::<32>(&nonce).unwrap());
    send_client_msg(
        &mut sb_dead,
        &RelayClientMsg::Standby {
            pub_key: pub_a.clone(),
            sig: sb_sig,
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut sb_dead).await,
        Some(RelayServerMsg::StandbyReady)
    );
    drop(sb_dead);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let (mut dial_a, _) = connect_async(&url).await.unwrap();
    assert!(matches!(
        recv_server_msg(&mut dial_a).await,
        Some(RelayServerMsg::Challenge { .. })
    ));
    let cid_a = [0x42; 16];
    let cid_a_b64 = b64url_encode(&cid_a);
    let init_a = b64url_encode(b"classic-fast-open-bytes");
    send_client_msg(
        &mut dial_a,
        &RelayClientMsg::Dial {
            target_pub: pub_a.clone(),
            conn_id: cid_a_b64.clone(),
            auth: None,
            init_frame: Some(init_a.clone()),
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut ctrl_a).await,
        Some(RelayServerMsg::Incoming {
            conn_id: cid_a_b64.clone(),
            init_frame: Some(init_a),
        })
    );

    let (mut acc_a, _) = connect_async(&url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_server_msg(&mut acc_a).await
    else {
        panic!("challenge");
    };
    send_client_msg(
        &mut acc_a,
        &RelayClientMsg::Accept {
            pub_key: pub_a,
            conn_id: cid_a_b64.clone(),
            sig: sign_relay_accept(
                &key_a,
                &host,
                &b64url_decode_array::<32>(&nonce).unwrap(),
                &cid_a,
            ),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut acc_a).await,
        Some(RelayServerMsg::Ready {
            conn_id: cid_a_b64.clone()
        })
    );
    assert_eq!(
        recv_server_msg(&mut dial_a).await,
        Some(RelayServerMsg::Ready { conn_id: cid_a_b64 })
    );

    // Case B: legacy listener (Register.fast_open == None) receives Incoming without init_frame, then receives decoded binary frame after Ready!
    let key_b = SigningKey::from_bytes(&[0x43; 32]);
    let (mut ctrl_b, _) = connect_async(&url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_server_msg(&mut ctrl_b).await
    else {
        panic!("challenge");
    };
    let (pub_b, sig_b) =
        sign_relay_register(&key_b, &host, &b64url_decode_array::<32>(&nonce).unwrap());
    send_client_msg(
        &mut ctrl_b,
        &RelayClientMsg::Register {
            pub_key: pub_b.clone(),
            sig: sig_b,
            auth: None,
            fast_open: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut ctrl_b).await,
        Some(RelayServerMsg::Registered { .. })
    ));

    let (mut dial_b, _) = connect_async(&url).await.unwrap();
    assert!(matches!(
        recv_server_msg(&mut dial_b).await,
        Some(RelayServerMsg::Challenge { .. })
    ));
    let cid_b = [0x44; 16];
    let cid_b_b64 = b64url_encode(&cid_b);
    let injected_bytes = b"injected-first-binary-frame";
    send_client_msg(
        &mut dial_b,
        &RelayClientMsg::Dial {
            target_pub: pub_b.clone(),
            conn_id: cid_b_b64.clone(),
            auth: None,
            init_frame: Some(b64url_encode(injected_bytes)),
        },
    )
    .await;
    let Message::Text(raw_incoming) = ctrl_b.next().await.unwrap().unwrap() else {
        panic!("expected incoming text");
    };
    assert!(
        !raw_incoming.contains("init_frame"),
        "legacy listener without fast_open must not receive init_frame field: {raw_incoming}"
    );

    let (mut acc_b, _) = connect_async(&url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_server_msg(&mut acc_b).await
    else {
        panic!("challenge");
    };
    send_client_msg(
        &mut acc_b,
        &RelayClientMsg::Accept {
            pub_key: pub_b,
            conn_id: cid_b_b64.clone(),
            sig: sign_relay_accept(
                &key_b,
                &host,
                &b64url_decode_array::<32>(&nonce).unwrap(),
                &cid_b,
            ),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut acc_b).await,
        Some(RelayServerMsg::Ready {
            conn_id: cid_b_b64.clone()
        })
    );
    assert_eq!(
        recv_server_msg(&mut dial_b).await,
        Some(RelayServerMsg::Ready { conn_id: cid_b_b64 })
    );
    assert_eq!(
        acc_b.next().await.unwrap().unwrap(),
        Message::Binary(injected_bytes.to_vec().into())
    );

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v1_standby_hit_without_fast_open_omits_incoming_init_frame_and_injects_binary() {
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let handle = server.spawn();
    let url = handle.ws_url();

    let key = SigningKey::from_bytes(&[0x45; 32]);
    let (mut ctrl_ws, _) = connect_async(&url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_server_msg(&mut ctrl_ws).await
    else {
        panic!("challenge");
    };
    let (pub_b64, sig) =
        sign_relay_register(&key, &host, &b64url_decode_array::<32>(&nonce).unwrap());
    send_client_msg(
        &mut ctrl_ws,
        &RelayClientMsg::Register {
            pub_key: pub_b64.clone(),
            sig,
            auth: None,
            fast_open: None,
        },
    )
    .await;
    assert!(matches!(
        recv_server_msg(&mut ctrl_ws).await,
        Some(RelayServerMsg::Registered { .. })
    ));

    let (mut standby_ws, _) = connect_async(&url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) =
        recv_server_msg(&mut standby_ws).await
    else {
        panic!("challenge");
    };
    let (_, sb_sig) = sign_relay_register(&key, &host, &b64url_decode_array::<32>(&nonce).unwrap());
    send_client_msg(
        &mut standby_ws,
        &RelayClientMsg::Standby {
            pub_key: pub_b64.clone(),
            sig: sb_sig,
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_server_msg(&mut standby_ws).await,
        Some(RelayServerMsg::StandbyReady)
    );

    let (mut dial_ws, _) = connect_async(&url).await.unwrap();
    assert!(matches!(
        recv_server_msg(&mut dial_ws).await,
        Some(RelayServerMsg::Challenge { .. })
    ));
    let cid = [0x46; 16];
    let cid_b64 = b64url_encode(&cid);
    let init_bytes = b"v1-standby-legacy-binary-inject";
    send_client_msg(
        &mut dial_ws,
        &RelayClientMsg::Dial {
            target_pub: pub_b64,
            conn_id: cid_b64.clone(),
            auth: None,
            init_frame: Some(b64url_encode(init_bytes)),
        },
    )
    .await;

    let Message::Text(raw_inc) = standby_ws.next().await.unwrap().unwrap() else {
        panic!("expected standby incoming text");
    };
    assert!(
        !raw_inc.contains("init_frame"),
        "legacy standby without Register.fast_open must omit Incoming.init_frame: {raw_inc}"
    );
    assert_eq!(
        serde_json::from_str::<RelayServerMsg>(&raw_inc).unwrap(),
        RelayServerMsg::Incoming {
            conn_id: cid_b64.clone(),
            init_frame: None,
        }
    );
    assert_eq!(
        recv_server_msg(&mut dial_ws).await,
        Some(RelayServerMsg::Ready { conn_id: cid_b64 })
    );
    assert_eq!(
        standby_ws.next().await.unwrap().unwrap(),
        Message::Binary(init_bytes.to_vec().into())
    );
    standby_ws
        .send(Message::Binary(b"v1-sb-legacy-reply".to_vec().into()))
        .await
        .unwrap();
    assert_eq!(
        dial_ws.next().await.unwrap().unwrap(),
        Message::Binary(b"v1-sb-legacy-reply".to_vec().into())
    );

    handle.stop().await.expect("stop relay");
}
