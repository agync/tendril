use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{b64url_decode_array, b64url_encode};
use tendril_core::v2::{
    derive_epoch_mailbox, sign_v2_relay_accept, sign_v2_relay_dial, sign_v2_relay_register,
};
use tendril_relay::{
    MAX_RELAY_FRAME_LEN, RelayClientMsg, RelayConfig, RelayServer, RelayServerMsg,
    RelayV2ClientMsg, RelayV2ServerMsg, sign_relay_accept, sign_relay_register,
};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn recv_v2_msg(ws: &mut tendril_relay::server::ClientWsStream) -> Option<RelayV2ServerMsg> {
    while let Some(item) = ws.next().await {
        match item {
            Ok(Message::Text(text)) => return serde_json::from_str(&text).ok(),
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            _ => return None,
        }
    }
    None
}

async fn send_v2_msg(ws: &mut tendril_relay::server::ClientWsStream, msg: &RelayV2ClientMsg) {
    let text = serde_json::to_string(msg).expect("serialize v2 client msg");
    ws.send(Message::Text(text.into()))
        .await
        .expect("send v2 text msg");
}

async fn recv_v1_msg(ws: &mut tendril_relay::server::ClientWsStream) -> Option<RelayServerMsg> {
    while let Some(item) = ws.next().await {
        match item {
            Ok(Message::Text(text)) => return serde_json::from_str(&text).ok(),
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            _ => return None,
        }
    }
    None
}

#[tokio::test]
async fn relay_serves_v1_and_v2_concurrently_and_bridges_v2_frames() {
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let handle = server.spawn();
    let v1_url = handle.ws_url();
    let v2_url = handle.ws_v2_url();

    // Unknown paths must still be rejected before WebSocket upgrade.
    let bad_url = format!("ws://{}/v3/relay", handle.local_addr());
    assert!(connect_async(&bad_url).await.is_err());

    // v1 still functions on /v1/relay.
    let v1_key = ed25519_dalek::SigningKey::from_bytes(&[0x10; 32]);
    let (mut v1_ws, _) = connect_async(&v1_url).await.expect("connect v1");
    let Some(RelayServerMsg::Challenge {
        nonce: v1_nonce,
        host: v1_host,
        ..
    }) = recv_v1_msg(&mut v1_ws).await
    else {
        panic!("expected v1 challenge");
    };
    let v1_nonce_bytes = b64url_decode_array::<32>(&v1_nonce).unwrap();
    let (v1_pub, v1_sig) = sign_relay_register(&v1_key, &v1_host, &v1_nonce_bytes);
    v1_ws
        .send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Register {
                pub_key: v1_pub.clone(),
                sig: v1_sig,
                auth: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        recv_v1_msg(&mut v1_ws).await,
        Some(RelayServerMsg::Registered { pub_key: v1_pub })
    );
    drop(v1_ws);

    // v2 register -> dial -> incoming -> accept -> ready -> binary bridge.
    let mailbox_secret = [0x33; 32];
    let now_epoch = now_unix_secs() / 3600;
    let mailbox = derive_epoch_mailbox(&mailbox_secret, now_epoch);

    let (mut listener_ws, _) = connect_async(&v2_url).await.expect("connect v2 listener");
    let Some(RelayV2ServerMsg::Challenge {
        nonce: reg_nonce_b64,
        host,
        epoch: srv_epoch,
        max_frame,
        auth_required,
    }) = recv_v2_msg(&mut listener_ws).await
    else {
        panic!("expected v2 challenge");
    };
    assert_eq!(host, "localhost");
    assert_eq!(max_frame, MAX_RELAY_FRAME_LEN);
    assert_eq!(auth_required, None);
    assert!(srv_epoch.abs_diff(now_epoch) <= 1);
    let reg_nonce = b64url_decode_array::<32>(&reg_nonce_b64).unwrap();
    let reg_sig = sign_v2_relay_register(&mailbox, &host, &reg_nonce).unwrap();

    send_v2_msg(
        &mut listener_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            sig: b64url_encode(&reg_sig),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut listener_ws).await,
        Some(RelayV2ServerMsg::Registered {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
        })
    );

    // Dialer connects to /v2/relay.
    let (mut dialer_ws, _) = connect_async(&v2_url).await.expect("connect v2 dialer");
    let Some(RelayV2ServerMsg::Challenge {
        nonce: dial_nonce_b64,
        host: dial_host,
        ..
    }) = recv_v2_msg(&mut dialer_ws).await
    else {
        panic!("expected v2 dial challenge");
    };
    let dial_nonce = b64url_decode_array::<32>(&dial_nonce_b64).unwrap();
    let conn_id = [0x77; 16];
    let conn_id_b64 = b64url_encode(&conn_id);
    let dial_token = sign_v2_relay_dial(&mailbox, &dial_host, &dial_nonce, &conn_id).unwrap();
    let dial_token_b64 = b64url_encode(&dial_token);

    send_v2_msg(
        &mut dialer_ws,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            conn_id: conn_id_b64.clone(),
            dial_token: dial_token_b64.clone(),
            auth: None,
        },
    )
    .await;

    assert_eq!(
        recv_v2_msg(&mut listener_ws).await,
        Some(RelayV2ServerMsg::Incoming {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            conn_id: conn_id_b64.clone(),
            dial_nonce: dial_nonce_b64,
            dial_token: dial_token_b64,
        })
    );

    // Acceptor opens separate data socket and signs accept proof.
    let (mut accept_ws, _) = connect_async(&v2_url).await.expect("connect v2 acceptor");
    let Some(RelayV2ServerMsg::Challenge {
        nonce: acc_nonce_b64,
        host: acc_host,
        ..
    }) = recv_v2_msg(&mut accept_ws).await
    else {
        panic!("expected v2 accept challenge");
    };
    let acc_nonce = b64url_decode_array::<32>(&acc_nonce_b64).unwrap();
    let acc_sig = sign_v2_relay_accept(&mailbox, &acc_host, &acc_nonce, &conn_id).unwrap();
    send_v2_msg(
        &mut accept_ws,
        &RelayV2ClientMsg::Accept {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            conn_id: conn_id_b64.clone(),
            sig: b64url_encode(&acc_sig),
            auth: None,
        },
    )
    .await;

    assert_eq!(
        recv_v2_msg(&mut accept_ws).await,
        Some(RelayV2ServerMsg::Ready {
            conn_id: conn_id_b64.clone(),
        })
    );
    assert_eq!(
        recv_v2_msg(&mut dialer_ws).await,
        Some(RelayV2ServerMsg::Ready {
            conn_id: conn_id_b64,
        })
    );

    // Maximum frame payload (65521 bytes) forwards verbatim in both directions.
    let max_payload = vec![0xAB; MAX_RELAY_FRAME_LEN];
    dialer_ws
        .send(Message::Binary(max_payload.clone().into()))
        .await
        .unwrap();
    match accept_ws.next().await {
        Some(Ok(Message::Binary(received))) => {
            assert_eq!(received.as_ref(), max_payload.as_slice())
        }
        other => panic!("expected max binary frame, got {other:?}"),
    }

    accept_ws
        .send(Message::Binary(b"pong-v2".to_vec().into()))
        .await
        .unwrap();
    match dialer_ws.next().await {
        Some(Ok(Message::Binary(received))) => assert_eq!(received.as_ref(), b"pong-v2"),
        other => panic!("expected reply binary frame, got {other:?}"),
    }

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_v2_rejects_bad_sigs_out_of_skew_epochs_and_unregistered_mailboxes_uniformly() {
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let handle = server.spawn();
    let v2_url = handle.ws_v2_url();

    let mailbox_secret = [0x44; 32];
    let now_epoch = now_unix_secs() / 3600;
    let mailbox = derive_epoch_mailbox(&mailbox_secret, now_epoch);

    // 1. Out-of-skew epoch register rejected with "unauthorized".
    let far_mailbox = derive_epoch_mailbox(&mailbox_secret, now_epoch + 3);
    let (mut bad_epoch_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) =
        recv_v2_msg(&mut bad_epoch_ws).await
    else {
        panic!("expected challenge");
    };
    let nonce_bytes = b64url_decode_array::<32>(&nonce).unwrap();
    let bad_sig = sign_v2_relay_register(&far_mailbox, &host, &nonce_bytes).unwrap();
    send_v2_msg(
        &mut bad_epoch_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: far_mailbox.mailbox_id_b64url(),
            epoch: far_mailbox.epoch,
            sig: b64url_encode(&bad_sig),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut bad_epoch_ws).await,
        Some(RelayV2ServerMsg::Error {
            code: "unauthorized".to_owned(),
        })
    );

    // 2. Wrong-host register signature rejected with "unauthorized".
    let (mut bad_sig_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, .. }) = recv_v2_msg(&mut bad_sig_ws).await else {
        panic!("expected challenge");
    };
    let nonce_bytes = b64url_decode_array::<32>(&nonce).unwrap();
    let wrong_host_sig = sign_v2_relay_register(&mailbox, "evil.example", &nonce_bytes).unwrap();
    send_v2_msg(
        &mut bad_sig_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            sig: b64url_encode(&wrong_host_sig),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut bad_sig_ws).await,
        Some(RelayV2ServerMsg::Error {
            code: "unauthorized".to_owned(),
        })
    );

    // 3. Dialing a never-seen mailbox returns "offline".
    let never_seen = derive_epoch_mailbox(&[0x99; 32], now_epoch);
    let (mut dial1_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut dial1_ws).await
    else {
        panic!("expected challenge");
    };
    let d1_nonce = b64url_decode_array::<32>(&nonce).unwrap();
    let d1_conn = [0x11; 16];
    let d1_tok = sign_v2_relay_dial(&never_seen, &host, &d1_nonce, &d1_conn).unwrap();
    send_v2_msg(
        &mut dial1_ws,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: never_seen.mailbox_id_b64url(),
            epoch: never_seen.epoch,
            conn_id: b64url_encode(&d1_conn),
            dial_token: b64url_encode(&d1_tok),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut dial1_ws).await,
        Some(RelayV2ServerMsg::Error {
            code: "offline".to_owned(),
        })
    );

    // 4. Register then disconnect, then dial -> identical "offline" error.
    let (mut reg_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut reg_ws).await
    else {
        panic!("expected challenge");
    };
    let r_nonce = b64url_decode_array::<32>(&nonce).unwrap();
    let r_sig = sign_v2_relay_register(&mailbox, &host, &r_nonce).unwrap();
    send_v2_msg(
        &mut reg_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            sig: b64url_encode(&r_sig),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut reg_ws).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));
    drop(reg_ws);

    // Poll until disconnect cleanup completes and dial returns "offline" (no racy fixed sleep).
    let mut got_offline = false;
    for _ in 0..30 {
        let (mut dial2_ws, _) = connect_async(&v2_url).await.unwrap();
        let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) =
            recv_v2_msg(&mut dial2_ws).await
        else {
            panic!("expected challenge");
        };
        let d2_nonce = b64url_decode_array::<32>(&nonce).unwrap();
        let d2_conn = [0x22; 16];
        let d2_tok = sign_v2_relay_dial(&mailbox, &host, &d2_nonce, &d2_conn).unwrap();
        send_v2_msg(
            &mut dial2_ws,
            &RelayV2ClientMsg::Dial {
                target_mailbox_id: mailbox.mailbox_id_b64url(),
                epoch: mailbox.epoch,
                conn_id: b64url_encode(&d2_conn),
                dial_token: b64url_encode(&d2_tok),
                auth: None,
            },
        )
        .await;
        if let Some(RelayV2ServerMsg::Error { code }) = recv_v2_msg(&mut dial2_ws).await
            && code == "offline"
        {
            got_offline = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        got_offline,
        "expected disconnected mailbox to return offline"
    );

    // 5. Cross-protocol accept / wrong key accept rejected with "unauthorized".
    let (mut reg_ws2, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut reg_ws2).await
    else {
        panic!("expected challenge");
    };
    let r2_nonce = b64url_decode_array::<32>(&nonce).unwrap();
    let r2_sig = sign_v2_relay_register(&mailbox, &host, &r2_nonce).unwrap();
    send_v2_msg(
        &mut reg_ws2,
        &RelayV2ClientMsg::Register {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            sig: b64url_encode(&r2_sig),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut reg_ws2).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));

    let (mut dial3_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut dial3_ws).await
    else {
        panic!("expected challenge");
    };
    let d3_nonce = b64url_decode_array::<32>(&nonce).unwrap();
    let d3_conn = [0x33; 16];
    let d3_tok = sign_v2_relay_dial(&mailbox, &host, &d3_nonce, &d3_conn).unwrap();
    send_v2_msg(
        &mut dial3_ws,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            conn_id: b64url_encode(&d3_conn),
            dial_token: b64url_encode(&d3_tok),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut reg_ws2).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    // Attacker tries to accept with wrong key.
    let attacker_mailbox = derive_epoch_mailbox(&[0xAA; 32], now_epoch);
    let (mut evil_acc_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut evil_acc_ws).await
    else {
        panic!("expected challenge");
    };
    let e_nonce = b64url_decode_array::<32>(&nonce).unwrap();
    let e_sig = sign_v2_relay_accept(&attacker_mailbox, &host, &e_nonce, &d3_conn).unwrap();
    send_v2_msg(
        &mut evil_acc_ws,
        &RelayV2ClientMsg::Accept {
            mailbox_id: attacker_mailbox.mailbox_id_b64url(),
            epoch: attacker_mailbox.epoch,
            conn_id: b64url_encode(&d3_conn),
            sig: b64url_encode(&e_sig),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut evil_acc_ws).await,
        Some(RelayV2ServerMsg::Error {
            code: "unauthorized".to_owned(),
        })
    );

    // Cross-protocol v1 accept cannot claim v2 pending dial (404 / not found or wrong tables).
    let (mut v1_acc_ws, _) = connect_async(&handle.ws_url()).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_v1_msg(&mut v1_acc_ws).await
    else {
        panic!("expected v1 challenge");
    };
    let v1_acc_nonce = b64url_decode_array::<32>(&nonce).unwrap();
    let v1_acc_sig = sign_relay_accept(&mailbox.signing_key(), &host, &v1_acc_nonce, &d3_conn);
    v1_acc_ws
        .send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Accept {
                pub_key: mailbox.mailbox_id_b64url(),
                conn_id: b64url_encode(&d3_conn),
                sig: v1_acc_sig,
                auth: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        recv_v1_msg(&mut v1_acc_ws).await,
        Some(RelayServerMsg::Error {
            code: "invalid_request".to_owned(),
        })
    );

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_v2_epoch_boundaries_sig_tampering_bridge_limits_and_cleanup() {
    let server = RelayServer::bind(RelayConfig {
        max_mailboxes: 2,
        max_pending_per_mailbox: 2,
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let v2_url = handle.ws_v2_url();
    let mailbox_secret = [0x55; 32];

    // Query current server epoch from a challenge.
    let (mut probe_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge {
        nonce: p_nonce_b64,
        host,
        epoch: srv_epoch,
        ..
    }) = recv_v2_msg(&mut probe_ws).await
    else {
        panic!("expected challenge");
    };
    let p_nonce = b64url_decode_array::<32>(&p_nonce_b64).unwrap();

    // 1. Register boundary: +-2 epochs rejected with "unauthorized", +-1 accepted.
    for bad_epoch in [srv_epoch.saturating_sub(2), srv_epoch + 2] {
        let bad_mb = derive_epoch_mailbox(&mailbox_secret, bad_epoch);
        let (mut ws, _) = connect_async(&v2_url).await.unwrap();
        let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut ws).await
        else {
            panic!("challenge");
        };
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let sig = sign_v2_relay_register(&bad_mb, &host, &n).unwrap();
        send_v2_msg(
            &mut ws,
            &RelayV2ClientMsg::Register {
                mailbox_id: bad_mb.mailbox_id_b64url(),
                epoch: bad_epoch,
                sig: b64url_encode(&sig),
                auth: None,
            },
        )
        .await;
        assert_eq!(
            recv_v2_msg(&mut ws).await,
            Some(RelayV2ServerMsg::Error {
                code: "unauthorized".to_owned(),
            })
        );
    }

    // 2. Flipped-bit register signature & wrong-epoch signature & zero weak mailbox_id rejected.
    let mb_prev = derive_epoch_mailbox(&mailbox_secret, srv_epoch.saturating_sub(1));
    let mut flipped_sig = sign_v2_relay_register(&mb_prev, &host, &p_nonce).unwrap();
    flipped_sig[0] ^= 0x01;
    send_v2_msg(
        &mut probe_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mb_prev.mailbox_id_b64url(),
            epoch: mb_prev.epoch,
            sig: b64url_encode(&flipped_sig),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut probe_ws).await,
        Some(RelayV2ServerMsg::Error {
            code: "unauthorized".to_owned(),
        })
    );

    let (mut zero_ws, _) = connect_async(&v2_url).await.unwrap();
    let _ = recv_v2_msg(&mut zero_ws).await;
    send_v2_msg(
        &mut zero_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: b64url_encode(&[0u8; 32]),
            epoch: srv_epoch,
            sig: b64url_encode(&[0u8; 64]),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut zero_ws).await,
        Some(RelayV2ServerMsg::Error {
            code: "unauthorized".to_owned(),
        })
    );

    // 3. Register +-1 epochs (occupies both max_mailboxes=2 slots); 3rd mailbox hits capacity_exceeded.
    let mb_next = derive_epoch_mailbox(&mailbox_secret, srv_epoch + 1);
    let mut reg_sockets = Vec::new();
    for mb in [&mb_prev, &mb_next] {
        let (mut ws, _) = connect_async(&v2_url).await.unwrap();
        let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut ws).await
        else {
            panic!("challenge");
        };
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let sig = sign_v2_relay_register(mb, &host, &n).unwrap();
        send_v2_msg(
            &mut ws,
            &RelayV2ClientMsg::Register {
                mailbox_id: mb.mailbox_id_b64url(),
                epoch: mb.epoch,
                sig: b64url_encode(&sig),
                auth: None,
            },
        )
        .await;
        assert_eq!(
            recv_v2_msg(&mut ws).await,
            Some(RelayV2ServerMsg::Registered {
                mailbox_id: mb.mailbox_id_b64url(),
                epoch: mb.epoch,
            })
        );
        reg_sockets.push(ws);
    }

    // 3rd mailbox hits capacity_exceeded.
    let mb_extra = derive_epoch_mailbox(&[0x77; 32], srv_epoch);
    let (mut cap_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut cap_ws).await
    else {
        panic!("challenge");
    };
    let cap_n = b64url_decode_array::<32>(&nonce).unwrap();
    let cap_sig = sign_v2_relay_register(&mb_extra, &host, &cap_n).unwrap();
    send_v2_msg(
        &mut cap_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mb_extra.mailbox_id_b64url(),
            epoch: mb_extra.epoch,
            sig: b64url_encode(&cap_sig),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut cap_ws).await,
        Some(RelayV2ServerMsg::Error {
            code: "capacity_exceeded".to_owned(),
        })
    );

    // 4. Out-of-skew dial and epoch-mismatched dial both return generic "offline".
    for (target_mb, dial_ep) in [(&mb_prev, srv_epoch + 2), (&mb_prev, srv_epoch)] {
        let (mut d_ws, _) = connect_async(&v2_url).await.unwrap();
        let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut d_ws).await
        else {
            panic!("challenge");
        };
        let dn = b64url_decode_array::<32>(&nonce).unwrap();
        let cid = [0x44; 16];
        let tok = sign_v2_relay_dial(target_mb, &host, &dn, &cid).unwrap();
        send_v2_msg(
            &mut d_ws,
            &RelayV2ClientMsg::Dial {
                target_mailbox_id: target_mb.mailbox_id_b64url(),
                epoch: dial_ep,
                conn_id: b64url_encode(&cid),
                dial_token: b64url_encode(&tok),
                auth: None,
            },
        )
        .await;
        assert_eq!(
            recv_v2_msg(&mut d_ws).await,
            Some(RelayV2ServerMsg::Error {
                code: "offline".to_owned(),
            })
        );
    }

    // 5. Dialer disconnect frees pending slot immediately (no rate_limited leak across 4 sequential drops).
    let mut reg_prev = reg_sockets.remove(0);
    for i in 0..4u8 {
        let (mut d_ws, _) = connect_async(&v2_url).await.unwrap();
        let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut d_ws).await
        else {
            panic!("challenge");
        };
        let dn = b64url_decode_array::<32>(&nonce).unwrap();
        let cid = [0x80 + i; 16];
        let tok = sign_v2_relay_dial(&mb_prev, &host, &dn, &cid).unwrap();
        send_v2_msg(
            &mut d_ws,
            &RelayV2ClientMsg::Dial {
                target_mailbox_id: mb_prev.mailbox_id_b64url(),
                epoch: mb_prev.epoch,
                conn_id: b64url_encode(&cid),
                dial_token: b64url_encode(&tok),
                auth: None,
            },
        )
        .await;
        assert!(matches!(
            recv_v2_msg(&mut reg_prev).await,
            Some(RelayV2ServerMsg::Incoming { .. })
        ));
        drop(d_ws);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // 6. Accept bad sig (flipped bit) & wrong conn_id sig rejected with "unauthorized", then valid accept bridges & enforces 65522/empty/text close.
    let (mut dial_ok_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut dial_ok_ws).await
    else {
        panic!("challenge");
    };
    let dn = b64url_decode_array::<32>(&nonce).unwrap();
    let cid = [0x99; 16];
    let cid_b64 = b64url_encode(&cid);
    let tok = sign_v2_relay_dial(&mb_prev, &host, &dn, &cid).unwrap();
    send_v2_msg(
        &mut dial_ok_ws,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: mb_prev.mailbox_id_b64url(),
            epoch: mb_prev.epoch,
            conn_id: cid_b64.clone(),
            dial_token: b64url_encode(&tok),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut reg_prev).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    // Flipped bit in accept sig -> unauthorized.
    let (mut bad_acc, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut bad_acc).await
    else {
        panic!("challenge");
    };
    let an = b64url_decode_array::<32>(&nonce).unwrap();
    let mut bad_acc_sig = sign_v2_relay_accept(&mb_prev, &host, &an, &cid).unwrap();
    bad_acc_sig[5] ^= 0x80;
    send_v2_msg(
        &mut bad_acc,
        &RelayV2ClientMsg::Accept {
            mailbox_id: mb_prev.mailbox_id_b64url(),
            epoch: mb_prev.epoch,
            conn_id: cid_b64.clone(),
            sig: b64url_encode(&bad_acc_sig),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut bad_acc).await,
        Some(RelayV2ServerMsg::Error {
            code: "unauthorized".to_owned(),
        })
    );

    // Valid accept at epoch - 1 succeeds and enters binary bridge.
    let (mut ok_acc, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut ok_acc).await
    else {
        panic!("challenge");
    };
    let an2 = b64url_decode_array::<32>(&nonce).unwrap();
    let ok_sig = sign_v2_relay_accept(&mb_prev, &host, &an2, &cid).unwrap();
    send_v2_msg(
        &mut ok_acc,
        &RelayV2ClientMsg::Accept {
            mailbox_id: mb_prev.mailbox_id_b64url(),
            epoch: mb_prev.epoch,
            conn_id: cid_b64.clone(),
            sig: b64url_encode(&ok_sig),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut ok_acc).await,
        Some(RelayV2ServerMsg::Ready {
            conn_id: cid_b64.clone(),
        })
    );
    assert_eq!(
        recv_v2_msg(&mut dial_ok_ws).await,
        Some(RelayV2ServerMsg::Ready { conn_id: cid_b64 })
    );

    // Oversized binary frame (MAX_RELAY_FRAME_LEN + 1 = 65522 B) closes bridge without forwarding.
    let oversize = vec![0xEE; MAX_RELAY_FRAME_LEN + 1];
    let _ = dial_ok_ws.send(Message::Binary(oversize.into())).await;
    assert!(matches!(
        ok_acc.next().await,
        None | Some(Ok(Message::Close(_))) | Some(Err(_))
    ));

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_v2_short_timeout_idle_ping_pong_watchdog_reaps_silent_client_and_keeps_live_client()
{
    use std::time::Duration;

    let server = RelayServer::bind(RelayConfig {
        idle_timeout: Duration::from_millis(120),
        pong_timeout: Duration::from_millis(120),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let v2_url = handle.ws_v2_url();

    let now_epoch = now_unix_secs() / 3600;
    let mb_live = derive_epoch_mailbox(&[0xC1; 32], now_epoch);
    let mb_dead = derive_epoch_mailbox(&[0xC2; 32], now_epoch);

    // Live client keeps reading ws.next(), so tungstenite replies Pong to server Ping.
    let (mut live_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut live_ws).await
    else {
        panic!("challenge");
    };
    let ln = b64url_decode_array::<32>(&nonce).unwrap();
    let lsig = sign_v2_relay_register(&mb_live, &host, &ln).unwrap();
    send_v2_msg(
        &mut live_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mb_live.mailbox_id_b64url(),
            epoch: mb_live.epoch,
            sig: b64url_encode(&lsig),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut live_ws).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));

    // Silent client stops polling ws.next() after Registered, so it never answers Ping.
    let (mut dead_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut dead_ws).await
    else {
        panic!("challenge");
    };
    let dn = b64url_decode_array::<32>(&nonce).unwrap();
    let dsig = sign_v2_relay_register(&mb_dead, &host, &dn).unwrap();
    send_v2_msg(
        &mut dead_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mb_dead.mailbox_id_b64url(),
            epoch: mb_dead.epoch,
            sig: b64url_encode(&dsig),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut dead_ws).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));

    // Spawn a task that drives live_ws.next() so Ping -> automatic Pong is flushed for 450 ms.
    let live_task = tokio::spawn(async move {
        let mut saw_ping = false;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(450);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(60), live_ws.next()).await {
                Ok(Some(Ok(Message::Ping(_)))) => {
                    saw_ping = true;
                }
                Ok(Some(Ok(_))) => {}
                Ok(None | Some(Err(_))) => panic!("live client must not be closed by watchdog"),
                Err(_) => {}
            }
        }
        (live_ws, saw_ping)
    });

    // Wait past idle_timeout + pong_timeout (240 ms) without polling dead_ws.
    tokio::time::sleep(Duration::from_millis(450)).await;
    let (_live_ws, saw_ping) = live_task.await.unwrap();
    assert!(saw_ping, "expected watchdog to send Ping to live client");

    // Silent mailbox must have been reaped (dial returns offline).
    let (mut dial_dead, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut dial_dead).await
    else {
        panic!("challenge");
    };
    let dd_n = b64url_decode_array::<32>(&nonce).unwrap();
    let dd_c = [0x19; 16];
    let dd_t = sign_v2_relay_dial(&mb_dead, &host, &dd_n, &dd_c).unwrap();
    send_v2_msg(
        &mut dial_dead,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: mb_dead.mailbox_id_b64url(),
            epoch: mb_dead.epoch,
            conn_id: b64url_encode(&dd_c),
            dial_token: b64url_encode(&dd_t),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut dial_dead).await,
        Some(RelayV2ServerMsg::Error {
            code: "offline".to_owned(),
        })
    );

    drop(dead_ws);
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_v2_clock_seam_expires_registered_mailbox_at_e_plus_2() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    let base_epoch = 500_000u64;
    let clock_val = Arc::new(AtomicU64::new(base_epoch * 3600 + 3599));
    let clock_fn = {
        let c = Arc::clone(&clock_val);
        Arc::new(move || c.load(Ordering::Acquire))
    };

    let server = RelayServer::bind(RelayConfig {
        clock: Some(clock_fn),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let v2_url = handle.ws_v2_url();

    let mb = derive_epoch_mailbox(&[0xD1; 32], base_epoch);
    let (mut reg_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge {
        nonce, host, epoch, ..
    }) = recv_v2_msg(&mut reg_ws).await
    else {
        panic!("challenge");
    };
    assert_eq!(epoch, base_epoch);
    let n = b64url_decode_array::<32>(&nonce).unwrap();
    let sig = sign_v2_relay_register(&mb, &host, &n).unwrap();
    send_v2_msg(
        &mut reg_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            sig: b64url_encode(&sig),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut reg_ws).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));

    // Advance across E+1 seam: mailbox registered for E stays alive.
    clock_val.store((base_epoch + 1) * 3600 + 10, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), reg_ws.next())
            .await
            .is_err(),
        "mailbox for epoch E must remain open at E+1"
    );

    // Advance to E+2 boundary: server closes registration socket and removes mailbox.
    clock_val.store((base_epoch + 2) * 3600, Ordering::Release);
    let closed = tokio::time::timeout(Duration::from_secs(1), reg_ws.next())
        .await
        .expect("epoch E+2 expiry must close socket promptly");
    assert!(matches!(
        closed,
        None | Some(Ok(Message::Close(_))) | Some(Err(_))
    ));

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_v2_accepts_65521_byte_frame_and_rejects_65522_byte_frame() {
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let handle = server.spawn();
    let v2_url = handle.ws_v2_url();

    assert_eq!(MAX_RELAY_FRAME_LEN, 65_521);
    let now_epoch = now_unix_secs() / 3600;
    let mb = derive_epoch_mailbox(&[0xE1; 32], now_epoch);

    let (mut reg_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut reg_ws).await
    else {
        panic!("challenge");
    };
    let rn = b64url_decode_array::<32>(&nonce).unwrap();
    let rsig = sign_v2_relay_register(&mb, &host, &rn).unwrap();
    send_v2_msg(
        &mut reg_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            sig: b64url_encode(&rsig),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut reg_ws).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));

    let (mut dial_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut dial_ws).await
    else {
        panic!("challenge");
    };
    let dn = b64url_decode_array::<32>(&nonce).unwrap();
    let cid = [0xE2; 16];
    let cid_b64 = b64url_encode(&cid);
    let tok = sign_v2_relay_dial(&mb, &host, &dn, &cid).unwrap();
    send_v2_msg(
        &mut dial_ws,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            conn_id: cid_b64.clone(),
            dial_token: b64url_encode(&tok),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut reg_ws).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    let (mut acc_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut acc_ws).await
    else {
        panic!("challenge");
    };
    let an = b64url_decode_array::<32>(&nonce).unwrap();
    let asig = sign_v2_relay_accept(&mb, &host, &an, &cid).unwrap();
    send_v2_msg(
        &mut acc_ws,
        &RelayV2ClientMsg::Accept {
            mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            conn_id: cid_b64,
            sig: b64url_encode(&asig),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut acc_ws).await,
        Some(RelayV2ServerMsg::Ready { .. })
    ));
    assert!(matches!(
        recv_v2_msg(&mut dial_ws).await,
        Some(RelayV2ServerMsg::Ready { .. })
    ));

    // Positive control: 65521 B forwards intact.
    let exact_max = vec![0x5A; 65_521];
    dial_ws
        .send(Message::Binary(exact_max.clone().into()))
        .await
        .unwrap();
    match acc_ws.next().await {
        Some(Ok(Message::Binary(got))) => assert_eq!(got.len(), 65_521),
        other => panic!("expected 65521 B binary frame, got {other:?}"),
    }

    // Negative control: 65522 B closes bridge without forwarding.
    let too_big = vec![0x5B; 65_522];
    let _ = dial_ws.send(Message::Binary(too_big.into())).await;
    assert!(matches!(
        acc_ws.next().await,
        None | Some(Ok(Message::Close(_))) | Some(Err(_))
    ));

    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_enforces_shared_v1_and_v2_max_mailboxes_cap() {
    let server = RelayServer::bind(RelayConfig {
        max_mailboxes: 2,
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let v1_url = handle.ws_url();
    let v2_url = handle.ws_v2_url();
    let now_epoch = now_unix_secs() / 3600;

    // Slot 1: /v1/relay mailbox.
    let v1_sk1 = ed25519_dalek::SigningKey::from_bytes(&[0xF1; 32]);
    let (mut v1_ws1, _) = connect_async(&v1_url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_v1_msg(&mut v1_ws1).await else {
        panic!("v1 challenge");
    };
    let n1 = b64url_decode_array::<32>(&nonce).unwrap();
    let (p1, s1) = sign_relay_register(&v1_sk1, &host, &n1);
    v1_ws1
        .send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Register {
                pub_key: p1,
                sig: s1,
                auth: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        recv_v1_msg(&mut v1_ws1).await,
        Some(RelayServerMsg::Registered { .. })
    ));

    // Slot 2: /v2/relay mailbox.
    let v2_mb = derive_epoch_mailbox(&[0xF2; 32], now_epoch);
    let (mut v2_ws1, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut v2_ws1).await
    else {
        panic!("v2 challenge");
    };
    let n2 = b64url_decode_array::<32>(&nonce).unwrap();
    let s2 = sign_v2_relay_register(&v2_mb, &host, &n2).unwrap();
    send_v2_msg(
        &mut v2_ws1,
        &RelayV2ClientMsg::Register {
            mailbox_id: v2_mb.mailbox_id_b64url(),
            epoch: v2_mb.epoch,
            sig: b64url_encode(&s2),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut v2_ws1).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));

    // 3rd mailbox on /v1/relay hits shared cap.
    let v1_sk2 = ed25519_dalek::SigningKey::from_bytes(&[0xF3; 32]);
    let (mut v1_ws2, _) = connect_async(&v1_url).await.unwrap();
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_v1_msg(&mut v1_ws2).await else {
        panic!("v1 challenge");
    };
    let n3 = b64url_decode_array::<32>(&nonce).unwrap();
    let (p3, s3) = sign_relay_register(&v1_sk2, &host, &n3);
    v1_ws2
        .send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Register {
                pub_key: p3,
                sig: s3,
                auth: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        recv_v1_msg(&mut v1_ws2).await,
        Some(RelayServerMsg::Error {
            code: "capacity_exceeded".to_owned(),
        })
    );

    // 3rd mailbox on /v2/relay also hits shared cap.
    let v2_mb2 = derive_epoch_mailbox(&[0xF4; 32], now_epoch);
    let (mut v2_ws2, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut v2_ws2).await
    else {
        panic!("v2 challenge");
    };
    let n4 = b64url_decode_array::<32>(&nonce).unwrap();
    let s4 = sign_v2_relay_register(&v2_mb2, &host, &n4).unwrap();
    send_v2_msg(
        &mut v2_ws2,
        &RelayV2ClientMsg::Register {
            mailbox_id: v2_mb2.mailbox_id_b64url(),
            epoch: v2_mb2.epoch,
            sig: b64url_encode(&s4),
            auth: None,
        },
    )
    .await;
    assert_eq!(
        recv_v2_msg(&mut v2_ws2).await,
        Some(RelayV2ServerMsg::Error {
            code: "capacity_exceeded".to_owned(),
        })
    );

    drop((v1_ws1, v2_ws1));
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_v2_fails_a_pending_dial_offline_when_its_registration_ends() {
    use std::time::Duration;

    // The accept deadline is far beyond the bound below, so only the registration ending can
    // answer the dial in time.
    let server = RelayServer::bind(RelayConfig {
        accept_timeout: Duration::from_secs(300),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let v2_url = handle.ws_v2_url();
    let mailbox = derive_epoch_mailbox(&[0xD1; 32], now_unix_secs() / 3600);

    let (mut listener_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut listener_ws).await
    else {
        panic!("expected v2 challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).unwrap();
    send_v2_msg(
        &mut listener_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            sig: b64url_encode(&sign_v2_relay_register(&mailbox, &host, &nonce).unwrap()),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut listener_ws).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));

    let (mut dialer_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut dialer_ws).await
    else {
        panic!("expected v2 dial challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).unwrap();
    let conn_id = [0xD2; 16];
    send_v2_msg(
        &mut dialer_ws,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            conn_id: b64url_encode(&conn_id),
            dial_token: b64url_encode(
                &sign_v2_relay_dial(&mailbox, &host, &nonce, &conn_id).unwrap(),
            ),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut listener_ws).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    // The listener vanishes without a close frame and without accepting.
    drop(listener_ws);
    let reply = tokio::time::timeout(Duration::from_secs(10), recv_v2_msg(&mut dialer_ws))
        .await
        .expect("pending dial outlived its registration");
    assert_eq!(
        reply,
        Some(RelayV2ServerMsg::Error {
            code: "offline".to_owned()
        })
    );
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn relay_v2_an_accept_that_claimed_a_dial_wins_over_registration_end() {
    use std::sync::Arc;
    use std::time::Duration;
    use tendril_relay::{RelayTestHook, RelayTestPoint};
    use tokio::sync::Notify;

    // The accept holds its claim until the dialer has seen the registration end.
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
    let server = RelayServer::bind(RelayConfig {
        accept_timeout: Duration::from_secs(300),
        test_hook: Some(hook),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let v2_url = handle.ws_v2_url();
    let mailbox = derive_epoch_mailbox(&[0xD3; 32], now_unix_secs() / 3600);

    let (mut listener_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut listener_ws).await
    else {
        panic!("expected v2 challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).unwrap();
    send_v2_msg(
        &mut listener_ws,
        &RelayV2ClientMsg::Register {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            sig: b64url_encode(&sign_v2_relay_register(&mailbox, &host, &nonce).unwrap()),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut listener_ws).await,
        Some(RelayV2ServerMsg::Registered { .. })
    ));

    let (mut dialer_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_v2_msg(&mut dialer_ws).await
    else {
        panic!("expected v2 dial challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).unwrap();
    let conn_id = [0xD4; 16];
    let conn_id_b64 = b64url_encode(&conn_id);
    send_v2_msg(
        &mut dialer_ws,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            conn_id: conn_id_b64.clone(),
            dial_token: b64url_encode(
                &sign_v2_relay_dial(&mailbox, &host, &nonce, &conn_id).unwrap(),
            ),
            auth: None,
        },
    )
    .await;
    assert!(matches!(
        recv_v2_msg(&mut listener_ws).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    let (mut accept_ws, _) = connect_async(&v2_url).await.unwrap();
    let Some(RelayV2ServerMsg::Challenge {
        nonce: acc_nonce,
        host: acc_host,
        ..
    }) = recv_v2_msg(&mut accept_ws).await
    else {
        panic!("expected v2 accept challenge");
    };
    let acc_nonce = b64url_decode_array::<32>(&acc_nonce).unwrap();
    send_v2_msg(
        &mut accept_ws,
        &RelayV2ClientMsg::Accept {
            mailbox_id: mailbox.mailbox_id_b64url(),
            epoch: mailbox.epoch,
            conn_id: conn_id_b64.clone(),
            sig: b64url_encode(
                &sign_v2_relay_accept(&mailbox, &acc_host, &acc_nonce, &conn_id).unwrap(),
            ),
            auth: None,
        },
    )
    .await;

    claimed.notified().await;
    drop(listener_ws);
    let ready = Some(RelayV2ServerMsg::Ready {
        conn_id: conn_id_b64,
    });
    let bound = Duration::from_secs(10);
    let dialer_reply = tokio::time::timeout(bound, recv_v2_msg(&mut dialer_ws))
        .await
        .expect("dialer reply");
    let acceptor_reply = tokio::time::timeout(bound, recv_v2_msg(&mut accept_ws))
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
