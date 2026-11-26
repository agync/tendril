//! Registration lifecycle: ticket expiry and last-writer-wins replacement on both relay versions.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tendril_core::crypto::{b64url_decode_array, b64url_encode};
use tendril_core::relay_auth::{
    RELAY_TICKET_CLOCK_SKEW_SECS, RelayAuthRole, RelayTicket, mint_relay_ticket,
};
use tendril_core::v2::{
    DerivedMailbox, derive_epoch_mailbox, sign_v2_relay_accept, sign_v2_relay_dial,
    sign_v2_relay_register,
};
use tendril_relay::server::ClientWsStream;
use tendril_relay::{
    RelayAuthProof, RelayAuthScope, RelayClientMsg, RelayConfig, RelayHandle, RelayServer,
    RelayServerMsg, RelayTestHook, RelayTestPoint, RelayV2ClientMsg, RelayV2ServerMsg,
    sign_relay_accept, sign_relay_register,
};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const BOUND: Duration = Duration::from_secs(5);

/// Reads the next control frame, failing the test if none arrives within [`BOUND`].
async fn recv_text<T: serde::de::DeserializeOwned>(ws: &mut ClientWsStream) -> Option<T> {
    let next = async {
        while let Some(item) = ws.next().await {
            match item {
                Ok(Message::Text(text)) => return serde_json::from_str(&text).ok(),
                Ok(Message::Ping(_) | Message::Pong(_)) => continue,
                _ => return None,
            }
        }
        None
    };
    tokio::time::timeout(BOUND, next)
        .await
        .expect("control frame within bound")
}

fn error(code: &str) -> Option<RelayServerMsg> {
    Some(RelayServerMsg::Error {
        code: code.to_owned(),
    })
}

fn v2_error(code: &str) -> Option<RelayV2ServerMsg> {
    Some(RelayV2ServerMsg::Error {
        code: code.to_owned(),
    })
}

async fn send_text<T: serde::Serialize>(ws: &mut ClientWsStream, msg: &T) {
    let text = serde_json::to_string(msg).expect("serialize client msg");
    ws.send(Message::Text(text.into()))
        .await
        .expect("send text msg");
}

/// Asserts the socket closes within [`BOUND`] without delivering another text frame first.
async fn assert_closes(ws: &mut ClientWsStream, what: &str) {
    let next = tokio::time::timeout(BOUND, ws.next())
        .await
        .unwrap_or_else(|_| panic!("{what} stayed open"));
    assert!(
        matches!(next, None | Some(Ok(Message::Close(_)) | Err(_))),
        "{what} must close, got {next:?}"
    );
}

/// Asserts the relay still serves the socket by completing a ping round trip.
async fn assert_alive(ws: &mut ClientWsStream, what: &str) {
    ws.send(Message::Ping(b"alive".to_vec().into()))
        .await
        .unwrap_or_else(|err| panic!("{what} closed: {err}"));
    let pong = tokio::time::timeout(BOUND, ws.next())
        .await
        .unwrap_or_else(|_| panic!("{what} did not answer"));
    assert!(
        matches!(&pong, Some(Ok(Message::Pong(p))) if p.as_ref() == b"alive"),
        "{what} must stay open, got {pong:?}"
    );
}

/// Hook that parks every handler reaching one of `points` so tests observe the state before
/// the matching teardown runs.
fn block_at(points: &'static [RelayTestPoint]) -> RelayTestHook {
    Arc::new(move |point| {
        Box::pin(async move {
            if points.contains(&point) {
                std::future::pending::<()>().await;
            }
        })
    })
}

struct Clock(Arc<AtomicU64>);

impl Clock {
    fn set(&self, unix: u64) {
        self.0.store(unix, Ordering::Release);
    }
}

async fn ticket_relay(issuer: &SigningKey, now: u64) -> (RelayHandle, Clock) {
    ticket_relay_with_hook(issuer, now, None).await
}

async fn ticket_relay_with_hook(
    issuer: &SigningKey,
    now: u64,
    test_hook: Option<RelayTestHook>,
) -> (RelayHandle, Clock) {
    let value = Arc::new(AtomicU64::new(now));
    let read = Arc::clone(&value);
    let server = RelayServer::bind(RelayConfig {
        trusted_issuers: vec![issuer.verifying_key().to_bytes()],
        auth_scope: RelayAuthScope::RegisterOnly,
        clock: Some(Arc::new(move || read.load(Ordering::Acquire))),
        accept_timeout: Duration::from_secs(300),
        test_hook,
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    (server.spawn(), Clock(value))
}

fn ticket_auth(ticket: &RelayTicket) -> Option<RelayAuthProof> {
    Some(RelayAuthProof::Ticket {
        ticket: ticket.clone(),
    })
}

fn register_ticket(
    issuer: &SigningKey,
    target: &[u8; 32],
    not_before: u64,
    ttl: u64,
) -> RelayTicket {
    mint_relay_ticket(
        issuer,
        "localhost",
        RelayAuthRole::Register,
        &b64url_encode(target),
        not_before,
        ttl,
    )
    .expect("mint ticket")
}

/// Opens a `/v1/relay` socket and sends `register` (or `standby`) for `key`.
async fn v1_control(
    url: &str,
    key: &SigningKey,
    standby: bool,
    auth: Option<RelayAuthProof>,
) -> (ClientWsStream, String) {
    let (mut ws, _) = connect_async(url).await.expect("connect");
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_text(&mut ws).await else {
        panic!("expected challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce");
    let (pub_key, sig) = sign_relay_register(key, &host, &nonce);
    let msg = if standby {
        RelayClientMsg::Standby {
            pub_key: pub_key.clone(),
            sig,
            auth,
        }
    } else {
        RelayClientMsg::Register {
            pub_key: pub_key.clone(),
            sig,
            auth,
            fast_open: None,
        }
    };
    send_text(&mut ws, &msg).await;
    let reply = recv_text::<RelayServerMsg>(&mut ws).await;
    if standby {
        assert_eq!(reply, Some(RelayServerMsg::StandbyReady));
    } else {
        assert!(
            matches!(reply, Some(RelayServerMsg::Registered { .. })),
            "{reply:?}"
        );
    }
    (ws, pub_key)
}

async fn v1_dial(url: &str, target_pub: &str, conn_id: [u8; 16]) -> ClientWsStream {
    let (mut ws, _) = connect_async(url).await.expect("connect dialer");
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut ws).await,
        Some(RelayServerMsg::Challenge { .. })
    ));
    send_text(
        &mut ws,
        &RelayClientMsg::Dial {
            target_pub: target_pub.to_owned(),
            conn_id: b64url_encode(&conn_id),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    ws
}

async fn v2_control(
    url: &str,
    mb: &DerivedMailbox,
    standby: bool,
    auth: Option<RelayAuthProof>,
) -> ClientWsStream {
    let (mut ws, _) = connect_async(url).await.expect("connect");
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_text(&mut ws).await else {
        panic!("expected v2 challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce");
    let sig = b64url_encode(&sign_v2_relay_register(mb, &host, &nonce).expect("sign"));
    let msg = if standby {
        RelayV2ClientMsg::Standby {
            mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            sig,
            auth,
        }
    } else {
        RelayV2ClientMsg::Register {
            mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            sig,
            auth,
            fast_open: None,
        }
    };
    send_text(&mut ws, &msg).await;
    let reply = recv_text::<RelayV2ServerMsg>(&mut ws).await;
    if standby {
        assert!(
            matches!(reply, Some(RelayV2ServerMsg::StandbyReady { .. })),
            "{reply:?}"
        );
    } else {
        assert!(
            matches!(reply, Some(RelayV2ServerMsg::Registered { .. })),
            "{reply:?}"
        );
    }
    ws
}

async fn v2_dial(url: &str, mb: &DerivedMailbox, conn_id: [u8; 16]) -> ClientWsStream {
    let (mut ws, _) = connect_async(url).await.expect("connect dialer");
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_text(&mut ws).await else {
        panic!("expected v2 challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce");
    let token = sign_v2_relay_dial(mb, &host, &nonce, &conn_id).expect("dial token");
    send_text(
        &mut ws,
        &RelayV2ClientMsg::Dial {
            target_mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            conn_id: b64url_encode(&conn_id),
            dial_token: b64url_encode(&token),
            auth: None,
            init_frame: None,
        },
    )
    .await;
    ws
}

/// Opens a `/v1/relay` socket and sends `accept` for `conn_id` signed by `key`.
async fn v1_accept(url: &str, key: &SigningKey, conn_id: [u8; 16]) -> ClientWsStream {
    v1_accept_with(url, key, conn_id, None).await
}

async fn v1_accept_with(
    url: &str,
    key: &SigningKey,
    conn_id: [u8; 16],
    auth: Option<RelayAuthProof>,
) -> ClientWsStream {
    let (mut ws, _) = connect_async(url).await.expect("connect acceptor");
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_text(&mut ws).await else {
        panic!("expected challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce");
    send_text(
        &mut ws,
        &RelayClientMsg::Accept {
            pub_key: b64url_encode(&key.verifying_key().to_bytes()),
            conn_id: b64url_encode(&conn_id),
            sig: sign_relay_accept(key, &host, &nonce, &conn_id),
            auth,
        },
    )
    .await;
    ws
}

async fn v2_accept_with(
    url: &str,
    mb: &DerivedMailbox,
    conn_id: [u8; 16],
    auth: Option<RelayAuthProof>,
) -> ClientWsStream {
    let (mut ws, _) = connect_async(url).await.expect("connect acceptor");
    let Some(RelayV2ServerMsg::Challenge { nonce, host, .. }) = recv_text(&mut ws).await else {
        panic!("expected v2 challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce");
    let sig = sign_v2_relay_accept(mb, &host, &nonce, &conn_id).expect("sign accept");
    send_text(
        &mut ws,
        &RelayV2ClientMsg::Accept {
            mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            conn_id: b64url_encode(&conn_id),
            sig: b64url_encode(&sig),
            auth,
        },
    )
    .await;
    ws
}

/// Connects and signs a `/v1/relay` `register` for `key` without sending it yet.
async fn v1_staged_register(
    url: &str,
    key: &SigningKey,
    auth: Option<RelayAuthProof>,
) -> (ClientWsStream, RelayClientMsg) {
    let (mut ws, _) = connect_async(url).await.expect("connect");
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_text(&mut ws).await else {
        panic!("expected challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce");
    let (pub_key, sig) = sign_relay_register(key, &host, &nonce);
    let msg = RelayClientMsg::Register {
        pub_key,
        sig,
        auth,
        fast_open: None,
    };
    (ws, msg)
}

async fn assert_bridged(a: &mut ClientWsStream, b: &mut ClientWsStream, payload: &[u8]) {
    a.send(Message::Binary(payload.to_vec().into()))
        .await
        .expect("send bridged frame");
    let got = tokio::time::timeout(BOUND, b.next())
        .await
        .expect("bridged frame in time")
        .expect("bridge open")
        .expect("frame");
    assert_eq!(got, Message::Binary(payload.to_vec().into()));
}

#[tokio::test]
async fn v1_ticket_registration_and_standby_end_after_not_after_plus_skew() {
    let now = 1_760_000_000;
    let issuer = SigningKey::from_bytes(&[0xA1; 32]);
    let (handle, clock) = ticket_relay(&issuer, now).await;
    let url = handle.ws_url();

    let listener = SigningKey::from_bytes(&[0xA2; 32]);
    let ticket = register_ticket(&issuer, &listener.verifying_key().to_bytes(), now - 10, 70);
    let deadline = ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS;
    let auth = || {
        Some(RelayAuthProof::Ticket {
            ticket: ticket.clone(),
        })
    };

    let (mut control, pub_b64) = v1_control(&url, &listener, false, auth()).await;
    let (mut bridged_sb, _) = v1_control(&url, &listener, true, auth()).await;
    let (mut live_sb, _) = v1_control(&url, &listener, true, auth()).await;
    let (mut parked_sb, _) = v1_control(&url, &listener, true, auth()).await;

    // A stream bridged before expiry runs until it closes.
    let mut dialer = v1_dial(&url, &pub_b64, [0xA3; 16]).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut dialer).await,
        Some(RelayServerMsg::Ready { .. })
    ));
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut bridged_sb).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    // At not_after + skew the ticket still verifies, so a dial still finds a standby socket.
    clock.set(deadline);
    let mut edge = v1_dial(&url, &pub_b64, [0xA5; 16]).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut edge).await,
        Some(RelayServerMsg::Ready { .. })
    ));
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut live_sb).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    clock.set(deadline + 1);
    assert_closes(&mut control, "expired registration").await;
    assert_closes(&mut parked_sb, "expired standby socket").await;
    assert_bridged(&mut dialer, &mut bridged_sb, b"after-expiry").await;
    assert_bridged(&mut bridged_sb, &mut dialer, b"reply").await;

    let mut late = v1_dial(&url, &pub_b64, [0xA4; 16]).await;
    assert_eq!(
        recv_text::<RelayServerMsg>(&mut late).await,
        Some(RelayServerMsg::Error {
            code: "offline".to_owned()
        })
    );
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v2_ticket_registration_and_standby_end_after_not_after_plus_skew() {
    let epoch = 490_000u64;
    let now = epoch * 3600 + 100;
    let issuer = SigningKey::from_bytes(&[0xB1; 32]);
    let (handle, clock) = ticket_relay(&issuer, now).await;
    let url = handle.ws_v2_url();

    let mb = derive_epoch_mailbox(&[0xB2; 32], epoch);
    let ticket = register_ticket(&issuer, &mb.mailbox_id, now - 10, 70);
    let deadline = ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS;
    let auth = || {
        Some(RelayAuthProof::Ticket {
            ticket: ticket.clone(),
        })
    };

    let mut control = v2_control(&url, &mb, false, auth()).await;
    let mut live_sb = v2_control(&url, &mb, true, auth()).await;
    let mut parked_sb = v2_control(&url, &mb, true, auth()).await;

    clock.set(deadline);
    let mut edge = v2_dial(&url, &mb, [0xB3; 16]).await;
    assert!(matches!(
        recv_text::<RelayV2ServerMsg>(&mut edge).await,
        Some(RelayV2ServerMsg::Ready { .. })
    ));
    assert!(matches!(
        recv_text::<RelayV2ServerMsg>(&mut live_sb).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    clock.set(deadline + 1);
    assert_closes(&mut control, "expired v2 registration").await;
    assert_closes(&mut parked_sb, "expired v2 standby socket").await;
    handle.stop().await.expect("stop relay");
}

async fn plain_relay() -> RelayHandle {
    RelayServer::bind(RelayConfig {
        accept_timeout: Duration::from_secs(300),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay")
    .spawn()
}

#[tokio::test]
async fn v1_replaced_registration_fails_pending_dials_and_closes_with_replaced() {
    let handle = plain_relay().await;
    let url = handle.ws_url();
    let listener = SigningKey::from_bytes(&[0xC1; 32]);

    let (mut old, pub_b64) = v1_control(&url, &listener, false, None).await;
    let mut dialer = v1_dial(&url, &pub_b64, [0xC2; 16]).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut old).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    let (mut new, _) = v1_control(&url, &listener, false, None).await;
    let offline = Some(RelayServerMsg::Error {
        code: "offline".to_owned(),
    });
    let replaced = Some(RelayServerMsg::Error {
        code: "replaced".to_owned(),
    });
    let dial_reply = recv_text::<RelayServerMsg>(&mut dialer).await;
    assert_eq!(dial_reply, offline);
    let old_reply = recv_text::<RelayServerMsg>(&mut old).await;
    assert_eq!(old_reply, replaced);
    assert_closes(&mut old, "replaced control socket").await;

    let _next = v1_dial(&url, &pub_b64, [0xC3; 16]).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut new).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    // Without a pending dial the replaced socket still learns why it closed.
    let (_third, _) = v1_control(&url, &listener, false, None).await;
    let new_reply = recv_text::<RelayServerMsg>(&mut new).await;
    assert_eq!(new_reply, replaced);
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v2_replaced_registration_fails_pending_dials_and_closes_with_replaced() {
    let handle = plain_relay().await;
    let url = handle.ws_v2_url();
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        / 3600;
    let mb = derive_epoch_mailbox(&[0xD1; 32], epoch);

    let mut old = v2_control(&url, &mb, false, None).await;
    let mut dialer = v2_dial(&url, &mb, [0xD2; 16]).await;
    assert!(matches!(
        recv_text::<RelayV2ServerMsg>(&mut old).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    let mut new = v2_control(&url, &mb, false, None).await;
    let dial_reply = recv_text::<RelayV2ServerMsg>(&mut dialer).await;
    assert_eq!(
        dial_reply,
        Some(RelayV2ServerMsg::Error {
            code: "offline".to_owned()
        })
    );
    let old_reply = recv_text::<RelayV2ServerMsg>(&mut old).await;
    assert_eq!(
        old_reply,
        Some(RelayV2ServerMsg::Error {
            code: "replaced".to_owned()
        })
    );
    assert_closes(&mut old, "replaced v2 control socket").await;

    let _next = v2_dial(&url, &mb, [0xD3; 16]).await;
    assert!(matches!(
        recv_text::<RelayV2ServerMsg>(&mut new).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    // Without a pending dial the replaced socket still learns why it closed.
    let _third = v2_control(&url, &mb, false, None).await;
    let new_reply = recv_text::<RelayV2ServerMsg>(&mut new).await;
    assert_eq!(
        new_reply,
        Some(RelayV2ServerMsg::Error {
            code: "replaced".to_owned()
        })
    );
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v1_expired_registration_refuses_dials_and_standby_before_teardown() {
    let now = 1_760_000_000;
    let issuer = SigningKey::from_bytes(&[0xE1; 32]);
    let hook = block_at(&[RelayTestPoint::RegistrationExpired]);
    let (handle, clock) = ticket_relay_with_hook(&issuer, now, Some(hook)).await;
    let url = handle.ws_url();
    let listener = SigningKey::from_bytes(&[0xE2; 32]);
    let ticket = register_ticket(&issuer, &listener.verifying_key().to_bytes(), now - 10, 70);
    let (_control, pub_b64) = v1_control(&url, &listener, false, ticket_auth(&ticket)).await;

    // Teardown is held, so only the lookup itself can notice the expiry.
    clock.set(ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1);
    let mut dialer = v1_dial(&url, &pub_b64, [0xE3; 16]).await;
    assert_eq!(
        recv_text::<RelayServerMsg>(&mut dialer).await,
        error("offline")
    );

    // A second expired registration that no dial has evicted yet: the standby lookup itself
    // must notice the expiry.
    let other = SigningKey::from_bytes(&[0xE0; 32]);
    let other_key = other.verifying_key().to_bytes();
    clock.set(now);
    let other_ticket = register_ticket(&issuer, &other_key, now - 10, 70);
    let _other_control = v1_control(&url, &other, false, ticket_auth(&other_ticket)).await;
    clock.set(other_ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1);
    let fresh = register_ticket(&issuer, &other_key, now + 100, 70);
    let (mut sb, _) = connect_async(&url).await.expect("connect standby");
    let Some(RelayServerMsg::Challenge { nonce, host, .. }) = recv_text(&mut sb).await else {
        panic!("expected challenge");
    };
    let nonce = b64url_decode_array::<32>(&nonce).expect("nonce");
    let (pub_key, sig) = sign_relay_register(&other, &host, &nonce);
    send_text(
        &mut sb,
        &RelayClientMsg::Standby {
            pub_key,
            sig,
            auth: ticket_auth(&fresh),
        },
    )
    .await;
    assert_eq!(recv_text::<RelayServerMsg>(&mut sb).await, error("offline"));
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v1_expired_standby_is_skipped_before_teardown() {
    let now = 1_760_000_000;
    let issuer = SigningKey::from_bytes(&[0xE4; 32]);
    let hook = block_at(&[RelayTestPoint::StandbyExpired]);
    let (handle, clock) = ticket_relay_with_hook(&issuer, now, Some(hook)).await;
    let url = handle.ws_url();
    let listener = SigningKey::from_bytes(&[0xE5; 32]);
    let key = listener.verifying_key().to_bytes();
    let long = register_ticket(&issuer, &key, now - 10, 3600);
    let short = register_ticket(&issuer, &key, now - 10, 70);
    let (mut control, pub_b64) = v1_control(&url, &listener, false, ticket_auth(&long)).await;
    let (_sb, _) = v1_control(&url, &listener, true, ticket_auth(&short)).await;

    clock.set(short.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1);
    let _dialer = v1_dial(&url, &pub_b64, [0xE6; 16]).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut control).await,
        Some(RelayServerMsg::Incoming { .. })
    ));
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v1_standby_ticket_expiry_closes_only_the_standby() {
    let now = 1_760_000_000;
    let issuer = SigningKey::from_bytes(&[0xE7; 32]);
    let (handle, clock) = ticket_relay(&issuer, now).await;
    let url = handle.ws_url();
    let listener = SigningKey::from_bytes(&[0xE8; 32]);
    let key = listener.verifying_key().to_bytes();
    let long = register_ticket(&issuer, &key, now - 10, 3600);
    let short = register_ticket(&issuer, &key, now - 10, 70);
    let (mut control, pub_b64) = v1_control(&url, &listener, false, ticket_auth(&long)).await;
    let (mut sb, _) = v1_control(&url, &listener, true, ticket_auth(&short)).await;

    clock.set(short.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1);
    assert_closes(&mut sb, "expired standby socket").await;
    assert_alive(&mut control, "registration with a longer ticket").await;
    let _dialer = v1_dial(&url, &pub_b64, [0xE9; 16]).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut control).await,
        Some(RelayServerMsg::Incoming { .. })
    ));
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v1_pending_dial_fails_offline_on_ticket_expiry() {
    let now = 1_760_000_000;
    let issuer = SigningKey::from_bytes(&[0xEA; 32]);
    let (handle, clock) = ticket_relay(&issuer, now).await;
    let url = handle.ws_url();
    let listener = SigningKey::from_bytes(&[0xEB; 32]);
    let ticket = register_ticket(&issuer, &listener.verifying_key().to_bytes(), now - 10, 70);
    let (mut control, pub_b64) = v1_control(&url, &listener, false, ticket_auth(&ticket)).await;
    let mut dialer = v1_dial(&url, &pub_b64, [0xEC; 16]).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut control).await,
        Some(RelayServerMsg::Incoming { .. })
    ));

    clock.set(ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1);
    assert_eq!(
        recv_text::<RelayServerMsg>(&mut dialer).await,
        error("offline")
    );
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v2_expired_registration_refuses_dials_before_teardown() {
    let epoch = 490_001u64;
    let now = epoch * 3600 + 100;
    let issuer = SigningKey::from_bytes(&[0xED; 32]);
    let hook = block_at(&[RelayTestPoint::RegistrationExpired]);
    let (handle, clock) = ticket_relay_with_hook(&issuer, now, Some(hook)).await;
    let url = handle.ws_v2_url();
    let mb = derive_epoch_mailbox(&[0xEE; 32], epoch);
    let ticket = register_ticket(&issuer, &mb.mailbox_id, now - 10, 70);
    let _control = v2_control(&url, &mb, false, ticket_auth(&ticket)).await;

    clock.set(ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1);
    let mut dialer = v2_dial(&url, &mb, [0xEF; 16]).await;
    assert_eq!(
        recv_text::<RelayV2ServerMsg>(&mut dialer).await,
        v2_error("offline")
    );
    handle.stop().await.expect("stop relay");
}

async fn teardown_blocking_relay(max_pending: usize) -> RelayHandle {
    RelayServer::bind(RelayConfig {
        accept_timeout: Duration::from_secs(300),
        max_pending_per_mailbox: max_pending,
        test_hook: Some(block_at(&[RelayTestPoint::DialTeardown])),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay")
    .spawn()
}

#[tokio::test]
async fn v1_replacement_drops_old_pending_dials_at_once() {
    let handle = teardown_blocking_relay(2).await;
    let url = handle.ws_url();
    let listener = SigningKey::from_bytes(&[0xF1; 32]);
    let (mut old, pub_b64) = v1_control(&url, &listener, false, None).await;
    let mut old_dials = Vec::new();
    for conn_id in [[0xF2; 16], [0xF3; 16]] {
        old_dials.push(v1_dial(&url, &pub_b64, conn_id).await);
        assert!(matches!(
            recv_text::<RelayServerMsg>(&mut old).await,
            Some(RelayServerMsg::Incoming { .. })
        ));
    }

    let (mut new, _) = v1_control(&url, &listener, false, None).await;
    for dialer in &mut old_dials {
        assert_eq!(recv_text::<RelayServerMsg>(dialer).await, error("offline"));
    }
    let mut late = v1_accept(&url, &listener, [0xF2; 16]).await;
    assert_eq!(
        recv_text::<RelayServerMsg>(&mut late).await,
        error("invalid_request")
    );
    for conn_id in [[0xF4; 16], [0xF5; 16]] {
        let _dialer = v1_dial(&url, &pub_b64, conn_id).await;
        assert!(matches!(
            recv_text::<RelayServerMsg>(&mut new).await,
            Some(RelayServerMsg::Incoming { .. })
        ));
    }
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn v2_replacement_drops_old_pending_dials_at_once() {
    let handle = teardown_blocking_relay(1).await;
    let url = handle.ws_v2_url();
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        / 3600;
    let mb = derive_epoch_mailbox(&[0xF6; 32], epoch);
    let mut old = v2_control(&url, &mb, false, None).await;
    let mut old_dialer = v2_dial(&url, &mb, [0xF7; 16]).await;
    assert!(matches!(
        recv_text::<RelayV2ServerMsg>(&mut old).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    let mut new = v2_control(&url, &mb, false, None).await;
    assert_eq!(
        recv_text::<RelayV2ServerMsg>(&mut old_dialer).await,
        v2_error("offline")
    );
    let _dialer = v2_dial(&url, &mb, [0xF8; 16]).await;
    assert!(matches!(
        recv_text::<RelayV2ServerMsg>(&mut new).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn bind_rejects_scope_all_without_proof_tier_and_invalid_keys() {
    let valid = SigningKey::from_bytes(&[0xF9; 32])
        .verifying_key()
        .to_bytes();
    let mut identity = [0u8; 32];
    identity[0] = 1;

    let allowlist_all = RelayConfig {
        allowed_mailboxes: vec![valid],
        auth_scope: RelayAuthScope::All,
        ..RelayConfig::default()
    };
    assert!(RelayServer::bind(allowlist_all).await.is_err());
    let allowlist_register_only = RelayConfig {
        allowed_mailboxes: vec![valid],
        auth_scope: RelayAuthScope::RegisterOnly,
        ..RelayConfig::default()
    };
    assert!(RelayServer::bind(allowlist_register_only).await.is_ok());

    for bad in [[0u8; 32], identity] {
        let bad_mailbox = RelayConfig {
            allowed_mailboxes: vec![bad],
            auth_scope: RelayAuthScope::RegisterOnly,
            ..RelayConfig::default()
        };
        assert!(RelayServer::bind(bad_mailbox).await.is_err());
        let bad_issuer = RelayConfig {
            trusted_issuers: vec![bad],
            ..RelayConfig::default()
        };
        assert!(RelayServer::bind(bad_issuer).await.is_err());
    }
}

#[tokio::test]
async fn v1_reregister_after_expiry_closes_the_old_listener_without_replaced() {
    let now = 1_760_000_000;
    let issuer = SigningKey::from_bytes(&[0xC4; 32]);
    let (handle, clock) = ticket_relay(&issuer, now).await;
    let url = handle.ws_url();
    let listener = SigningKey::from_bytes(&[0xC5; 32]);
    let key = listener.verifying_key().to_bytes();
    let ticket = register_ticket(&issuer, &key, now - 10, 70);
    let deadline = ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1;
    let (mut old, _) = v1_control(&url, &listener, false, ticket_auth(&ticket)).await;
    let fresh = register_ticket(&issuer, &key, deadline - 5, 70);
    let (mut next, register) = v1_staged_register(&url, &listener, ticket_auth(&fresh)).await;

    // Register again the moment the old ticket expires, before its teardown has run.
    clock.set(deadline);
    send_text(&mut next, &register).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut next).await,
        Some(RelayServerMsg::Registered { .. })
    ));
    assert_closes(&mut old, "expired registration taken over").await;
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn expired_registrations_do_not_count_against_capacity() {
    let epoch = 490_002u64;
    let now = epoch * 3600 + 100;
    let issuer = SigningKey::from_bytes(&[0xC6; 32]);
    let value = Arc::new(AtomicU64::new(now));
    let read = Arc::clone(&value);
    let handle = RelayServer::bind(RelayConfig {
        trusted_issuers: vec![issuer.verifying_key().to_bytes()],
        auth_scope: RelayAuthScope::RegisterOnly,
        clock: Some(Arc::new(move || read.load(Ordering::Acquire))),
        max_mailboxes: 2,
        test_hook: Some(block_at(&[RelayTestPoint::RegistrationExpired])),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay")
    .spawn();
    let clock = Clock(value);

    let a = SigningKey::from_bytes(&[0xC7; 32]);
    let a_ticket = register_ticket(&issuer, &a.verifying_key().to_bytes(), now - 10, 70);
    let _a = v1_control(&handle.ws_url(), &a, false, ticket_auth(&a_ticket)).await;
    let c = derive_epoch_mailbox(&[0xC8; 32], epoch);
    let c_ticket = register_ticket(&issuer, &c.mailbox_id, now - 10, 70);
    let _c = v2_control(&handle.ws_v2_url(), &c, false, ticket_auth(&c_ticket)).await;

    let later = a_ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1;
    clock.set(later);
    let b = SigningKey::from_bytes(&[0xC9; 32]);
    let b_ticket = register_ticket(&issuer, &b.verifying_key().to_bytes(), later - 5, 70);
    let _b = v1_control(&handle.ws_url(), &b, false, ticket_auth(&b_ticket)).await;
    let d = derive_epoch_mailbox(&[0xCA; 32], epoch);
    let d_ticket = register_ticket(&issuer, &d.mailbox_id, later - 5, 70);
    let _d = v2_control(&handle.ws_v2_url(), &d, false, ticket_auth(&d_ticket)).await;
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn accept_for_an_expired_registration_fails_and_ends_the_dial() {
    let epoch = 490_003u64;
    let now = epoch * 3600 + 100;
    let issuer = SigningKey::from_bytes(&[0xCB; 32]);
    let hook = block_at(&[RelayTestPoint::RegistrationExpired]);
    let (handle, clock) = ticket_relay_with_hook(&issuer, now, Some(hook)).await;

    let listener = SigningKey::from_bytes(&[0xCC; 32]);
    let key = listener.verifying_key().to_bytes();
    let ticket = register_ticket(&issuer, &key, now - 10, 70);
    let (mut control, pub_b64) =
        v1_control(&handle.ws_url(), &listener, false, ticket_auth(&ticket)).await;
    let mut dialer = v1_dial(&handle.ws_url(), &pub_b64, [0xCD; 16]).await;
    assert!(matches!(
        recv_text::<RelayServerMsg>(&mut control).await,
        Some(RelayServerMsg::Incoming { .. })
    ));
    let mb = derive_epoch_mailbox(&[0xCE; 32], epoch);
    let mb_ticket = register_ticket(&issuer, &mb.mailbox_id, now - 10, 70);
    let mut v2_ctl = v2_control(&handle.ws_v2_url(), &mb, false, ticket_auth(&mb_ticket)).await;
    let mut v2_dialer = v2_dial(&handle.ws_v2_url(), &mb, [0xCF; 16]).await;
    assert!(matches!(
        recv_text::<RelayV2ServerMsg>(&mut v2_ctl).await,
        Some(RelayV2ServerMsg::Incoming { .. })
    ));

    // The accept carries its own valid ticket; only the registration has expired.
    let later = ticket.not_after + RELAY_TICKET_CLOCK_SKEW_SECS + 1;
    clock.set(later);
    let accept_ticket = register_ticket(&issuer, &key, later - 5, 70);
    let mut acceptor = v1_accept_with(
        &handle.ws_url(),
        &listener,
        [0xCD; 16],
        ticket_auth(&accept_ticket),
    )
    .await;
    assert_eq!(
        recv_text::<RelayServerMsg>(&mut acceptor).await,
        error("invalid_request")
    );
    assert_eq!(
        recv_text::<RelayServerMsg>(&mut dialer).await,
        error("offline")
    );

    let v2_accept_ticket = register_ticket(&issuer, &mb.mailbox_id, later - 5, 70);
    let mut v2_acceptor = v2_accept_with(
        &handle.ws_v2_url(),
        &mb,
        [0xCF; 16],
        ticket_auth(&v2_accept_ticket),
    )
    .await;
    assert_eq!(
        recv_text::<RelayV2ServerMsg>(&mut v2_acceptor).await,
        v2_error("invalid_request")
    );
    assert_eq!(
        recv_text::<RelayV2ServerMsg>(&mut v2_dialer).await,
        v2_error("offline")
    );
    handle.stop().await.expect("stop relay");
}
