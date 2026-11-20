use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{b64url_decode_array, b64url_encode};
use tendril_relay::{
    MAX_RELAY_FRAME_LEN, RelayClientMsg, RelayConfig, RelayServer, RelayServerMsg,
    sign_relay_accept, sign_relay_register,
};
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
    } = recv_server_msg(&mut listener_ws).await.expect("challenge")
    else {
        panic!("expected challenge");
    };
    assert_eq!(host, "localhost");
    assert_eq!(max_frame, MAX_RELAY_FRAME_LEN);
    let nonce_bytes = b64url_decode_array::<32>(&nonce).expect("nonce bytes");
    let (pub_b64, sig_b64) = sign_relay_register(&listener_key, &host, &nonce_bytes);
    send_client_msg(
        &mut listener_ws,
        &RelayClientMsg::Register {
            pub_key: pub_b64.clone(),
            sig: sig_b64,
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
        },
    )
    .await;

    assert_eq!(
        recv_server_msg(&mut listener_ws).await,
        Some(RelayServerMsg::Incoming {
            conn_id: conn_id_b64.clone()
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
