use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tempfile::TempDir;
use tendril_core::crypto::SigningKeypair;
use tendril_relay::protocol::{RelayClientMsg, RelayServerMsg, sign_relay_register};
use tendril_relay::rate_limit::{IpTokenLimiter, normalize_rate_limit_ip};
use tendril_relay::server::{IpCidr, RelayConfig, RelayError, RelayServer};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, connect_async_with_config};

fn generate_ephemeral_cert(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let ca_key = dir.join("ca.key");
    let ca_cert = dir.join("ca.crt");
    let leaf_key = dir.join("relay.key");
    let leaf_csr = dir.join("relay.csr");
    let leaf_cert = dir.join("relay.crt");
    let ext_file = dir.join("leaf.ext");
    std::fs::write(
        &ext_file,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
    )
    .expect("write ext");

    let ca_status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ed25519",
            "-keyout",
            ca_key.to_str().expect("utf8"),
            "-out",
            ca_cert.to_str().expect("utf8"),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=Tendril Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign",
        ])
        .status()
        .expect("run openssl ca");
    assert!(ca_status.success(), "openssl ca generation failed");

    let csr_status = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "ed25519",
            "-keyout",
            leaf_key.to_str().expect("utf8"),
            "-out",
            leaf_csr.to_str().expect("utf8"),
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .status()
        .expect("run openssl csr");
    assert!(csr_status.success(), "openssl csr generation failed");

    let sign_status = Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-in",
            leaf_csr.to_str().expect("utf8"),
            "-CA",
            ca_cert.to_str().expect("utf8"),
            "-CAkey",
            ca_key.to_str().expect("utf8"),
            "-CAcreateserial",
            "-out",
            leaf_cert.to_str().expect("utf8"),
            "-days",
            "1",
            "-extfile",
            ext_file.to_str().expect("utf8"),
        ])
        .status()
        .expect("run openssl x509 sign");
    assert!(sign_status.success(), "openssl leaf sign failed");

    (ca_cert, leaf_cert, leaf_key)
}

#[tokio::test]
async fn sec15_native_rustls_wss_listener_and_config_validation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = TempDir::new().expect("tempdir");
    let (ca_cert_path, cert_path, key_path) = generate_ephemeral_cert(tmp.path());

    let bad_cfg = RelayConfig {
        tls_cert_path: Some(cert_path.clone()),
        tls_key_path: None,
        ..RelayConfig::default()
    };
    assert!(matches!(
        RelayServer::bind(bad_cfg).await,
        Err(RelayError::InvalidConfig(_))
    ));

    let server = RelayServer::bind(RelayConfig {
        tls_cert_path: Some(cert_path),
        tls_key_path: Some(key_path),
        ..RelayConfig::default()
    })
    .await
    .expect("bind tls relay");
    let handle = server.spawn();
    let wss_url = handle.ws_url();
    assert!(
        wss_url.starts_with("wss://"),
        "expected wss:// URL, got {wss_url}"
    );

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&ca_cert_path).expect("open ca cert") {
        roots
            .add(cert.expect("parse ca cert"))
            .expect("add ca cert");
    }
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let (mut ws, _) = connect_async_tls_with_config(
        &wss_url,
        None,
        false,
        Some(Connector::Rustls(Arc::new(client_cfg))),
    )
    .await
    .expect("wss connect");

    let msg = timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("challenge wait")
        .expect("ws item")
        .expect("ws ok");
    let Message::Text(txt) = msg else {
        panic!("expected text challenge");
    };
    let parsed: RelayServerMsg = serde_json::from_str(&txt).expect("parse challenge");
    assert!(matches!(
        parsed,
        RelayServerMsg::Challenge { host, .. } if host == "localhost"
    ));

    let _ = ws.close(None).await;
    handle.stop().await.expect("stop relay");
}

#[tokio::test]
async fn sec15_trusted_proxy_right_to_left_xff_and_spoof_rejection() {
    let mapped_cidr: IpCidr = "::ffff:10.0.0.0/104".parse().expect("mapped v6 cidr");
    assert!(mapped_cidr.contains("10.1.2.3".parse().expect("v4")));
    assert!(!mapped_cidr.contains("11.1.2.3".parse().expect("v4 out")));

    let trusted_server = RelayServer::bind(RelayConfig {
        trusted_proxies: vec![
            "127.0.0.1/32".parse::<IpCidr>().expect("loopback cidr"),
            mapped_cidr,
        ],
        ip_burst_capacity: 1,
        ip_refill_per_sec: 1,
        ..RelayConfig::default()
    })
    .await
    .expect("bind trusted relay");
    let trusted_handle = trusted_server.spawn();
    let ws_url = trusted_handle.ws_url();

    // Spoofed leftmost IP changes across calls while real rightmost untrusted IP stays 203.0.113.7.
    let mut req1 = ws_url.clone().into_client_request().expect("req1");
    req1.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("198.51.100.1, 203.0.113.7, 10.1.2.3"),
    );
    let (mut ws1, _) = connect_async_with_config(req1, None, false)
        .await
        .expect("ws1 connect");
    let first_msg = ws1
        .next()
        .await
        .expect("ws1 item")
        .expect("ws1 ok")
        .into_text()
        .expect("ws1 text");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&first_msg).expect("msg1"),
        RelayServerMsg::Challenge { .. }
    ));

    let mut req2 = ws_url.clone().into_client_request().expect("req2");
    req2.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("198.51.100.99, 203.0.113.7, 10.1.2.3"),
    );
    let (mut ws2, _) = connect_async_with_config(req2, None, false)
        .await
        .expect("ws2 connect");
    let second_msg = ws2
        .next()
        .await
        .expect("ws2 item")
        .expect("ws2 ok")
        .into_text()
        .expect("ws2 text");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&second_msg).expect("msg2"),
        RelayServerMsg::Error { code } if code == "rate_limited"
    ));

    // RFC 7239 Forwarded takes precedence even if an untrusted client injected X-Forwarded-For.
    let mut req3 = ws_url.clone().into_client_request().expect("req3");
    req3.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
    req3.headers_mut().insert(
        "forwarded",
        HeaderValue::from_static("for=\"[2001:db8:cafe:beef::1]\";proto=https, for=10.0.0.9"),
    );
    let (mut ws3, _) = connect_async_with_config(req3, None, false)
        .await
        .expect("ws3 connect");
    let third_msg = ws3
        .next()
        .await
        .expect("ws3 item")
        .expect("ws3 ok")
        .into_text()
        .expect("ws3 text");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&third_msg).expect("msg3"),
        RelayServerMsg::Challenge { .. }
    ));

    // A second request with the same Forwarded client IP shares that bucket despite changing XFF.
    let mut req4 = ws_url.into_client_request().expect("req4");
    req4.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.77"));
    req4.headers_mut().insert(
        "forwarded",
        HeaderValue::from_static("for=\"[2001:db8:cafe:beef::1]\";proto=https, for=10.0.0.9"),
    );
    let (mut ws4, _) = connect_async_with_config(req4, None, false)
        .await
        .expect("ws4 connect");
    let fourth_msg = ws4
        .next()
        .await
        .expect("ws4 item")
        .expect("ws4 ok")
        .into_text()
        .expect("ws4 text");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&fourth_msg).expect("msg4"),
        RelayServerMsg::Error { code } if code == "rate_limited"
    ));

    drop((ws1, ws2, ws3, ws4));
    trusted_handle.stop().await.expect("stop trusted");

    // Untrusted proxy configuration must ignore X-Forwarded-For completely.
    let untrusted_server = RelayServer::bind(RelayConfig {
        trusted_proxies: Vec::new(),
        ip_burst_capacity: 1,
        ip_refill_per_sec: 1,
        ..RelayConfig::default()
    })
    .await
    .expect("bind untrusted relay");
    let untrusted_handle = untrusted_server.spawn();
    let u_url = untrusted_handle.ws_url();

    let mut ureq1 = u_url.clone().into_client_request().expect("ureq1");
    ureq1
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
    let (mut uws1, _) = connect_async_with_config(ureq1, None, false)
        .await
        .expect("uws1");
    let umsg1 = uws1
        .next()
        .await
        .expect("uws1 item")
        .expect("uws1 ok")
        .into_text()
        .expect("uws1 text");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&umsg1).expect("umsg1"),
        RelayServerMsg::Challenge { .. }
    ));

    let mut ureq2 = u_url.into_client_request().expect("ureq2");
    ureq2
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.2"));
    let ures2 = connect_async_with_config(ureq2, None, false).await;
    assert!(
        ures2.is_err(),
        "second loopback attempt must be rejected despite spoofed XFF"
    );

    drop(uws1);
    untrusted_handle.stop().await.expect("stop untrusted");
}

#[test]
fn sec13_ipv6_prefix_bucketing_and_eviction_pressure_retention() {
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
    assert_eq!(normalize_rate_limit_ip(mapped), v4);

    let v6_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 0, 0, 0, 1));
    let v6_b = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 0xffff, 1, 2, 3));
    assert_eq!(normalize_rate_limit_ip(v6_a), normalize_rate_limit_ip(v6_b));

    let now = Instant::now();
    let mut limiter = IpTokenLimiter::new(4, 1, 1);

    assert!(limiter.allow(v4, now));
    assert!(!limiter.allow(mapped, now), "mapped v6 shares v4 bucket");
    assert!(limiter.allow(v6_a, now));
    assert!(!limiter.allow(v6_b, now), "same /64 shares bucket");

    // Fill remaining 2 table slots to hit max_entries = 4, then cause eviction pressure.
    assert!(limiter.allow(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), now));
    assert!(limiter.allow(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), now));

    // Under eviction pressure, global overflow bucket limits eviction churn (cap=1 allows 1, then denies).
    let flood1 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let flood2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    assert!(limiter.allow(flood1, now));
    assert!(!limiter.allow(flood2, now));

    // Even after 1s refills 1 token on the overflow bucket, newly inserted keys get 0 initial tokens.
    let later = now + Duration::from_secs(1);
    assert!(limiter.allow(flood2, later));
    assert!(
        !limiter.allow(flood2, later),
        "eviction insertion must not grant fresh burst capacity"
    );
}

#[tokio::test]
async fn sec13_global_connection_and_mailbox_caps() {
    let server = RelayServer::bind(RelayConfig {
        max_total_connections: 2,
        max_mailboxes: 1,
        ..RelayConfig::default()
    })
    .await
    .expect("bind capped relay");
    let handle = server.spawn();
    let addr = handle.local_addr();
    let ws_url = handle.ws_url();

    let s1 = TcpStream::connect(addr).await.expect("tcp1");
    let s2 = TcpStream::connect(addr).await.expect("tcp2");
    tokio::time::sleep(Duration::from_millis(20)).await;

    let third_ws = timeout(
        Duration::from_secs(1),
        connect_async_with_config(&ws_url, None, false),
    )
    .await;
    assert!(
        !matches!(third_ws, Ok(Ok(_))),
        "3rd connection must be rejected when max_total_connections=2"
    );
    drop((s1, s2));
    tokio::time::sleep(Duration::from_millis(20)).await;

    async fn register_mailbox(
        ws_url: &str,
        kp: &SigningKeypair,
    ) -> (
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        RelayServerMsg,
    ) {
        let (mut ws, _) = connect_async_with_config(ws_url, None, false)
            .await
            .expect("connect");
        let ch_txt = ws
            .next()
            .await
            .expect("ch")
            .expect("ok")
            .into_text()
            .expect("txt");
        let RelayServerMsg::Challenge { nonce, host, .. } =
            serde_json::from_str(&ch_txt).expect("parse")
        else {
            panic!("expected challenge");
        };
        let nonce_bytes: [u8; 32] =
            tendril_core::crypto::b64url_decode_array(&nonce).expect("nonce");
        let (pub_b64, sig_b64) =
            sign_relay_register(&kp.ed25519_signing_key(), &host, &nonce_bytes);
        let reg = serde_json::to_string(&RelayClientMsg::Register {
            pub_key: pub_b64,
            sig: sig_b64,
            auth: None,
        })
        .expect("ser");
        ws.send(Message::Text(reg.into())).await.expect("send reg");
        let resp_txt = ws
            .next()
            .await
            .expect("resp")
            .expect("ok")
            .into_text()
            .expect("txt");
        let msg: RelayServerMsg = serde_json::from_str(&resp_txt).expect("parse resp");
        (ws, msg)
    }

    let kp1 = SigningKeypair::generate().expect("kp1");
    let (ws1, resp1) = register_mailbox(&ws_url, &kp1).await;
    assert!(matches!(resp1, RelayServerMsg::Registered { .. }));

    let kp2 = SigningKeypair::generate().expect("kp2");
    let (ws2, resp2) = register_mailbox(&ws_url, &kp2).await;
    assert!(matches!(
        resp2,
        RelayServerMsg::Error { code } if code == "capacity_exceeded"
    ));

    drop((ws1, ws2));
    handle.stop().await.expect("stop");
}

#[tokio::test]
async fn relay_stateless_admission_tiers_and_option_1a_on_v1_and_v2() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tendril_core::crypto::{b64url_decode_array, b64url_encode};
    use tendril_core::relay_auth::{
        RELAY_TICKET_CLOCK_SKEW_SECS, RelayAuthProof, RelayAuthRole, RelayAuthScope,
        compute_relay_auth_hmac_b64, mint_relay_ticket,
    };
    use tendril_core::v2::{
        derive_epoch_mailbox, sign_v2_relay_accept, sign_v2_relay_dial, sign_v2_relay_register,
    };
    use tendril_relay::protocol::{RelayV2ClientMsg, RelayV2ServerMsg, sign_relay_accept};
    use zeroize::Zeroizing;

    let now_u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let clock_val = Arc::new(AtomicU64::new(now_u64));
    let clock_fn = {
        let c = Arc::clone(&clock_val);
        Arc::new(move || c.load(Ordering::Acquire))
    };

    // 0. Open relay omits auth_required on both /v1/relay and /v2/relay.
    {
        let open_cfg = RelayConfig::default();
        assert!(format!("{open_cfg:?}").contains("auth_secret: None"));
        let open_srv = RelayServer::bind(open_cfg).await.unwrap().spawn();
        let (mut v1_ws, _) = tokio_tungstenite::connect_async(&open_srv.ws_url())
            .await
            .unwrap();
        let v1_ch: RelayServerMsg =
            serde_json::from_str(&v1_ws.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap();
        assert!(matches!(
            v1_ch,
            RelayServerMsg::Challenge {
                auth_required: None,
                ..
            }
        ));
        let (mut v2_ws, _) = tokio_tungstenite::connect_async(&open_srv.ws_v2_url())
            .await
            .unwrap();
        let v2_ch: RelayV2ServerMsg =
            serde_json::from_str(&v2_ws.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap();
        assert!(matches!(
            v2_ch,
            RelayV2ServerMsg::Challenge {
                auth_required: None,
                ..
            }
        ));
        open_srv.stop().await.unwrap();
    }

    // 1. Tier 1 only (allowed_mailboxes): auth_required=["register"], dial open, non-allowlisted register/accept fail closed.
    {
        let allowed_v1_kp = SigningKeypair::generate().unwrap();
        let allowed_v1_pub = allowed_v1_kp
            .ed25519_signing_key()
            .verifying_key()
            .to_bytes();
        let other_v1_kp = SigningKeypair::generate().unwrap();

        let v2_secret = [0x22; 32];
        let epoch = now_u64 / 3600;
        let allowed_v2_mb = derive_epoch_mailbox(&v2_secret, epoch);
        let other_v2_mb = derive_epoch_mailbox(&[0x23; 32], epoch);

        let cfg = RelayConfig {
            allowed_mailboxes: vec![allowed_v1_pub, allowed_v2_mb.mailbox_id],
            ..RelayConfig::default()
        };
        let srv = RelayServer::bind(cfg).await.unwrap().spawn();

        // /v1/relay challenge advertises ["register"] only.
        let (mut reg_ws, _) = tokio_tungstenite::connect_async(&srv.ws_url())
            .await
            .unwrap();
        let RelayServerMsg::Challenge {
            nonce,
            host,
            auth_required,
            ..
        } = serde_json::from_str(&reg_ws.next().await.unwrap().unwrap().into_text().unwrap())
            .unwrap()
        else {
            panic!("expected v1 challenge");
        };
        assert_eq!(auth_required, Some(vec!["register".to_owned()]));
        let nonce_b = b64url_decode_array::<32>(&nonce).unwrap();

        // Non-allowlisted v1 register fails closed with unauthorized.
        let (other_pub, other_sig) =
            sign_relay_register(&other_v1_kp.ed25519_signing_key(), &host, &nonce_b);
        reg_ws
            .send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Register {
                    pub_key: other_pub.clone(),
                    sig: other_sig,
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        let err: RelayServerMsg =
            serde_json::from_str(&reg_ws.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap();
        assert_eq!(
            err,
            RelayServerMsg::Error {
                code: "unauthorized".to_owned()
            }
        );

        // Allowlisted v1 register succeeds without auth proof.
        let (mut ok_reg_ws, _) = tokio_tungstenite::connect_async(&srv.ws_url())
            .await
            .unwrap();
        let RelayServerMsg::Challenge { nonce, host, .. } = serde_json::from_str(
            &ok_reg_ws
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap() else {
            panic!("expected v1 challenge");
        };
        let nonce_b = b64url_decode_array::<32>(&nonce).unwrap();
        let (ok_pub, ok_sig) =
            sign_relay_register(&allowed_v1_kp.ed25519_signing_key(), &host, &nonce_b);
        ok_reg_ws
            .send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Register {
                    pub_key: ok_pub.clone(),
                    sig: ok_sig,
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayServerMsg>(
                &ok_reg_ws
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayServerMsg::Registered { .. }
        ));

        // Open dial on Tier 1 only returns "offline" for non-registered target (no token needed).
        let (mut dial_ws, _) = tokio_tungstenite::connect_async(&srv.ws_url())
            .await
            .unwrap();
        let _ = dial_ws.next().await;
        dial_ws
            .send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Dial {
                    target_pub: other_pub,
                    conn_id: b64url_encode(&[0x55; 16]),
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        let d_err: RelayServerMsg =
            serde_json::from_str(&dial_ws.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap();
        assert_eq!(
            d_err,
            RelayServerMsg::Error {
                code: "offline".to_owned()
            }
        );

        // /v2/relay Tier 1 only fails closed for non-allowlisted mailbox_id and allows allowlisted.
        let (mut v2_bad, _) = tokio_tungstenite::connect_async(&srv.ws_v2_url())
            .await
            .unwrap();
        let RelayV2ServerMsg::Challenge {
            nonce,
            host,
            auth_required,
            ..
        } = serde_json::from_str(&v2_bad.next().await.unwrap().unwrap().into_text().unwrap())
            .unwrap()
        else {
            panic!("expected v2 challenge");
        };
        assert_eq!(auth_required, Some(vec!["register".to_owned()]));
        let n2 = b64url_decode_array::<32>(&nonce).unwrap();
        let bad_sig = sign_v2_relay_register(&other_v2_mb, &host, &n2).unwrap();
        v2_bad
            .send(Message::Text(
                serde_json::to_string(&RelayV2ClientMsg::Register {
                    mailbox_id: other_v2_mb.mailbox_id_b64url(),
                    epoch: other_v2_mb.epoch,
                    sig: b64url_encode(&bad_sig),
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayV2ServerMsg>(
                &v2_bad.next().await.unwrap().unwrap().into_text().unwrap()
            )
            .unwrap(),
            RelayV2ServerMsg::Error {
                code: "unauthorized".to_owned()
            }
        );

        let (mut v2_ok, _) = tokio_tungstenite::connect_async(&srv.ws_v2_url())
            .await
            .unwrap();
        let RelayV2ServerMsg::Challenge { nonce, host, .. } =
            serde_json::from_str(&v2_ok.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap()
        else {
            panic!("expected v2 challenge");
        };
        let n2_ok = b64url_decode_array::<32>(&nonce).unwrap();
        let ok_sig = sign_v2_relay_register(&allowed_v2_mb, &host, &n2_ok).unwrap();
        v2_ok
            .send(Message::Text(
                serde_json::to_string(&RelayV2ClientMsg::Register {
                    mailbox_id: allowed_v2_mb.mailbox_id_b64url(),
                    epoch: allowed_v2_mb.epoch,
                    sig: b64url_encode(&ok_sig),
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayV2ServerMsg>(
                &v2_ok.next().await.unwrap().unwrap().into_text().unwrap()
            )
            .unwrap(),
            RelayV2ServerMsg::Registered { .. }
        ));

        drop((ok_reg_ws, v2_ok));
        srv.stop().await.unwrap();
    }

    // 2. Tier 2 (HMAC) + Tier 3 (Ed25519 Ticket) with Option 1A auth_scope = All.
    {
        let secret = b"super-secret-relay-hmac-key";
        let issuer_kp = SigningKeypair::generate().unwrap();
        let issuer_sk = issuer_kp.ed25519_signing_key();
        let issuer_pub = issuer_sk.verifying_key().to_bytes();
        let untrusted_issuer_kp = SigningKeypair::generate().unwrap();
        let untrusted_sk = untrusted_issuer_kp.ed25519_signing_key();

        let cfg = RelayConfig {
            host: "relay.example".to_owned(),
            auth_secret: Some(Zeroizing::new(secret.to_vec())),
            trusted_issuers: vec![issuer_pub],
            auth_scope: RelayAuthScope::All,
            clock: Some(clock_fn.clone()),
            ..RelayConfig::default()
        };
        let dbg_str = format!("{cfg:?}");
        assert!(dbg_str.contains("<redacted>"));
        assert!(!dbg_str.contains("super-secret-relay-hmac-key"));
        let srv = RelayServer::bind(cfg).await.unwrap().spawn();

        let v1_key = SigningKeypair::generate().unwrap();
        let v1_sk = v1_key.ed25519_signing_key();
        let v1_pub_bytes = v1_sk.verifying_key().to_bytes();
        let v1_pub_b64 = b64url_encode(&v1_pub_bytes);

        let v2_mb = derive_epoch_mailbox(&[0x77; 32], now_u64 / 3600);

        // Unauthorized dial to unregistered target returns "unauthorized" (NOT "offline") on both v1 and v2.
        for is_v2 in [false, true] {
            if !is_v2 {
                let (mut ws, _) = tokio_tungstenite::connect_async(&srv.ws_url())
                    .await
                    .unwrap();
                let RelayServerMsg::Challenge { auth_required, .. } =
                    serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap())
                        .unwrap()
                else {
                    panic!("v1 challenge");
                };
                assert_eq!(
                    auth_required,
                    Some(vec!["register".to_owned(), "dial".to_owned()])
                );
                ws.send(Message::Text(
                    serde_json::to_string(&RelayClientMsg::Dial {
                        target_pub: v1_pub_b64.clone(),
                        conn_id: b64url_encode(&[0x11; 16]),
                        auth: None,
                    })
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();
                assert_eq!(
                    serde_json::from_str::<RelayServerMsg>(
                        &ws.next().await.unwrap().unwrap().into_text().unwrap()
                    )
                    .unwrap(),
                    RelayServerMsg::Error {
                        code: "unauthorized".to_owned()
                    }
                );
            } else {
                let (mut ws, _) = tokio_tungstenite::connect_async(&srv.ws_v2_url())
                    .await
                    .unwrap();
                let RelayV2ServerMsg::Challenge {
                    nonce,
                    host,
                    auth_required,
                    ..
                } = serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap())
                    .unwrap()
                else {
                    panic!("v2 challenge");
                };
                assert_eq!(
                    auth_required,
                    Some(vec!["register".to_owned(), "dial".to_owned()])
                );
                let n = b64url_decode_array::<32>(&nonce).unwrap();
                let cid = [0x12; 16];
                let tok = sign_v2_relay_dial(&v2_mb, &host, &n, &cid).unwrap();
                ws.send(Message::Text(
                    serde_json::to_string(&RelayV2ClientMsg::Dial {
                        target_mailbox_id: v2_mb.mailbox_id_b64url(),
                        epoch: v2_mb.epoch + 5, // out-of-skew epoch, yet auth MUST fail first!
                        conn_id: b64url_encode(&cid),
                        dial_token: b64url_encode(&tok),
                        auth: None,
                    })
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();
                assert_eq!(
                    serde_json::from_str::<RelayV2ServerMsg>(
                        &ws.next().await.unwrap().unwrap().into_text().unwrap()
                    )
                    .unwrap(),
                    RelayV2ServerMsg::Error {
                        code: "unauthorized".to_owned()
                    }
                );
            }
        }

        // Ticket rejections on /v1/relay register:
        // (a) dial ticket rejected on register
        let dial_ticket = mint_relay_ticket(
            &issuer_sk,
            "relay.example",
            RelayAuthRole::Dial,
            &v1_pub_b64,
            now_u64,
            60,
        )
        .unwrap();
        // (b) wrong target_pub ticket rejected
        let wrong_target_b64 = b64url_encode(&[0x33; 32]);
        let wrong_target_ticket = mint_relay_ticket(
            &issuer_sk,
            "relay.example",
            RelayAuthRole::Register,
            &wrong_target_b64,
            now_u64,
            60,
        )
        .unwrap();
        // (c) unknown issuer ticket rejected
        let unknown_issuer_ticket = mint_relay_ticket(
            &untrusted_sk,
            "relay.example",
            RelayAuthRole::Register,
            &v1_pub_b64,
            now_u64,
            60,
        )
        .unwrap();
        // (d) expired beyond +-30s clock skew rejected
        let expired_ticket = mint_relay_ticket(
            &issuer_sk,
            "relay.example",
            RelayAuthRole::Register,
            &v1_pub_b64,
            now_u64 - 100,
            60, // not_after = now - 40 < now - 30
        )
        .unwrap();
        // (e) within +-30s clock skew accepted!
        let skew_edge_ticket = mint_relay_ticket(
            &issuer_sk,
            "relay.example",
            RelayAuthRole::Register,
            &v1_pub_b64,
            now_u64 - 90,
            60 + RELAY_TICKET_CLOCK_SKEW_SECS - 30, // not_after = now - 30
        )
        .unwrap();

        for bad_ticket in [
            dial_ticket.clone(),
            wrong_target_ticket,
            unknown_issuer_ticket,
            expired_ticket,
        ] {
            let (mut ws, _) = tokio_tungstenite::connect_async(&srv.ws_url())
                .await
                .unwrap();
            let RelayServerMsg::Challenge { nonce, host, .. } =
                serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap())
                    .unwrap()
            else {
                panic!("challenge");
            };
            let n = b64url_decode_array::<32>(&nonce).unwrap();
            let (pk, sig) = sign_relay_register(&v1_sk, &host, &n);
            ws.send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Register {
                    pub_key: pk,
                    sig,
                    auth: Some(RelayAuthProof::Ticket { ticket: bad_ticket }),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
            assert_eq!(
                serde_json::from_str::<RelayServerMsg>(
                    &ws.next().await.unwrap().unwrap().into_text().unwrap()
                )
                .unwrap(),
                RelayServerMsg::Error {
                    code: "unauthorized".to_owned()
                }
            );
        }

        // Skew-edge ticket registers v1 mailbox, then dial ticket dials it, and HMAC accepts it!
        let (mut v1_reg_ws, _) = tokio_tungstenite::connect_async(&srv.ws_url())
            .await
            .unwrap();
        let RelayServerMsg::Challenge { nonce, host, .. } = serde_json::from_str(
            &v1_reg_ws
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap() else {
            panic!("challenge");
        };
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let (pk, sig) = sign_relay_register(&v1_sk, &host, &n);
        v1_reg_ws
            .send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Register {
                    pub_key: pk.clone(),
                    sig,
                    auth: Some(RelayAuthProof::Ticket {
                        ticket: skew_edge_ticket,
                    }),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayServerMsg>(
                &v1_reg_ws
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayServerMsg::Registered { .. }
        ));

        let (mut v1_dial_ws, _) = tokio_tungstenite::connect_async(&srv.ws_url())
            .await
            .unwrap();
        let _ = v1_dial_ws.next().await;
        let cid1 = [0x61; 16];
        v1_dial_ws
            .send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Dial {
                    target_pub: pk.clone(),
                    conn_id: b64url_encode(&cid1),
                    auth: Some(RelayAuthProof::Ticket {
                        ticket: dial_ticket,
                    }),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayServerMsg>(
                &v1_reg_ws
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayServerMsg::Incoming { .. }
        ));

        // Accept with invalid HMAC rejected, then valid HMAC succeeds.
        let (mut v1_acc_bad, _) = tokio_tungstenite::connect_async(&srv.ws_url())
            .await
            .unwrap();
        let RelayServerMsg::Challenge { nonce, host, .. } = serde_json::from_str(
            &v1_acc_bad
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap() else {
            panic!("challenge");
        };
        let an_bad = b64url_decode_array::<32>(&nonce).unwrap();
        let acc_sig_bad = sign_relay_accept(&v1_sk, &host, &an_bad, &cid1);
        v1_acc_bad
            .send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Accept {
                    pub_key: pk.clone(),
                    conn_id: b64url_encode(&cid1),
                    sig: acc_sig_bad,
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayServerMsg>(
                &v1_acc_bad
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayServerMsg::Error {
                code: "unauthorized".to_owned()
            }
        );

        let (mut v1_acc_ok, _) = tokio_tungstenite::connect_async(&srv.ws_url())
            .await
            .unwrap();
        let RelayServerMsg::Challenge { nonce, host, .. } = serde_json::from_str(
            &v1_acc_ok
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap() else {
            panic!("challenge");
        };
        let an_ok = b64url_decode_array::<32>(&nonce).unwrap();
        let acc_sig_ok = sign_relay_accept(&v1_sk, &host, &an_ok, &cid1);
        let acc_mac =
            compute_relay_auth_hmac_b64(secret, "accept", &host, &an_ok, &v1_pub_bytes).unwrap();
        v1_acc_ok
            .send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Accept {
                    pub_key: pk,
                    conn_id: b64url_encode(&cid1),
                    sig: acc_sig_ok,
                    auth: Some(RelayAuthProof::Hmac { mac: acc_mac }),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayServerMsg>(
                &v1_acc_ok
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayServerMsg::Ready { .. }
        ));

        // Same Tier 2/3 checks on /v2/relay: wildcard register ticket + dial HMAC + accept HMAC.
        let wildcard_reg_ticket = mint_relay_ticket(
            &issuer_sk,
            "relay.example",
            RelayAuthRole::Register,
            "*",
            now_u64,
            60,
        )
        .unwrap();
        let (mut v2_reg_ws, _) = tokio_tungstenite::connect_async(&srv.ws_v2_url())
            .await
            .unwrap();
        let RelayV2ServerMsg::Challenge { nonce, host, .. } = serde_json::from_str(
            &v2_reg_ws
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap() else {
            panic!("v2 challenge");
        };
        let n2 = b64url_decode_array::<32>(&nonce).unwrap();
        let sig2 = sign_v2_relay_register(&v2_mb, &host, &n2).unwrap();
        v2_reg_ws
            .send(Message::Text(
                serde_json::to_string(&RelayV2ClientMsg::Register {
                    mailbox_id: v2_mb.mailbox_id_b64url(),
                    epoch: v2_mb.epoch,
                    sig: b64url_encode(&sig2),
                    auth: Some(RelayAuthProof::Ticket {
                        ticket: wildcard_reg_ticket,
                    }),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayV2ServerMsg>(
                &v2_reg_ws
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayV2ServerMsg::Registered { .. }
        ));

        // Dial /v2/relay with HMAC.
        let (mut v2_dial_ws, _) = tokio_tungstenite::connect_async(&srv.ws_v2_url())
            .await
            .unwrap();
        let RelayV2ServerMsg::Challenge { nonce, host, .. } = serde_json::from_str(
            &v2_dial_ws
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap() else {
            panic!("v2 dial challenge");
        };
        let dn2 = b64url_decode_array::<32>(&nonce).unwrap();
        let cid2 = [0x62; 16];
        let tok2 = sign_v2_relay_dial(&v2_mb, &host, &dn2, &cid2).unwrap();
        let dial_mac =
            compute_relay_auth_hmac_b64(secret, "dial", &host, &dn2, &v2_mb.mailbox_id).unwrap();
        v2_dial_ws
            .send(Message::Text(
                serde_json::to_string(&RelayV2ClientMsg::Dial {
                    target_mailbox_id: v2_mb.mailbox_id_b64url(),
                    epoch: v2_mb.epoch,
                    conn_id: b64url_encode(&cid2),
                    dial_token: b64url_encode(&tok2),
                    auth: Some(RelayAuthProof::Hmac { mac: dial_mac }),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayV2ServerMsg>(
                &v2_reg_ws
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayV2ServerMsg::Incoming { .. }
        ));

        // Accept /v2/relay with HMAC.
        let (mut v2_acc_ws, _) = tokio_tungstenite::connect_async(&srv.ws_v2_url())
            .await
            .unwrap();
        let RelayV2ServerMsg::Challenge { nonce, host, .. } = serde_json::from_str(
            &v2_acc_ws
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap() else {
            panic!("v2 acc challenge");
        };
        let an2 = b64url_decode_array::<32>(&nonce).unwrap();
        let acc_sig2 = sign_v2_relay_accept(&v2_mb, &host, &an2, &cid2).unwrap();
        let acc_mac2 =
            compute_relay_auth_hmac_b64(secret, "accept", &host, &an2, &v2_mb.mailbox_id).unwrap();
        v2_acc_ws
            .send(Message::Text(
                serde_json::to_string(&RelayV2ClientMsg::Accept {
                    mailbox_id: v2_mb.mailbox_id_b64url(),
                    epoch: v2_mb.epoch,
                    conn_id: b64url_encode(&cid2),
                    sig: b64url_encode(&acc_sig2),
                    auth: Some(RelayAuthProof::Hmac { mac: acc_mac2 }),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayV2ServerMsg>(
                &v2_acc_ws
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayV2ServerMsg::Ready { .. }
        ));

        drop((
            v1_reg_ws, v1_dial_ws, v1_acc_ok, v2_reg_ws, v2_dial_ws, v2_acc_ws,
        ));
        srv.stop().await.unwrap();
    }

    // 3. auth_scope = RegisterOnly with Tier 2 HMAC: challenge=["register"], dial allowed without auth, register/accept still require auth.
    {
        let secret = b"register-only-secret";
        let cfg = RelayConfig {
            auth_secret: Some(Zeroizing::new(secret.to_vec())),
            auth_scope: RelayAuthScope::RegisterOnly,
            ..RelayConfig::default()
        };
        let srv = RelayServer::bind(cfg).await.unwrap().spawn();

        let kp = SigningKeypair::generate().unwrap();
        let pub_b64 = b64url_encode(kp.ed25519_signing_key().verifying_key().as_bytes());
        let (mut dial_ws, _) = tokio_tungstenite::connect_async(&srv.ws_url())
            .await
            .unwrap();
        let RelayServerMsg::Challenge { auth_required, .. } =
            serde_json::from_str(&dial_ws.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap()
        else {
            panic!("challenge");
        };
        assert_eq!(auth_required, Some(vec!["register".to_owned()]));
        dial_ws
            .send(Message::Text(
                serde_json::to_string(&RelayClientMsg::Dial {
                    target_pub: pub_b64,
                    conn_id: b64url_encode(&[0x71; 16]),
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayServerMsg>(
                &dial_ws.next().await.unwrap().unwrap().into_text().unwrap()
            )
            .unwrap(),
            RelayServerMsg::Error {
                code: "offline".to_owned()
            }
        );

        let (mut v2_dial_ws, _) = tokio_tungstenite::connect_async(&srv.ws_v2_url())
            .await
            .unwrap();
        let RelayV2ServerMsg::Challenge {
            nonce,
            host,
            auth_required,
            ..
        } = serde_json::from_str(
            &v2_dial_ws
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap()
        else {
            panic!("v2 challenge");
        };
        assert_eq!(auth_required, Some(vec!["register".to_owned()]));
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let mb = derive_epoch_mailbox(&[0x88; 32], now_u64 / 3600);
        let cid = [0x72; 16];
        let tok = sign_v2_relay_dial(&mb, &host, &n, &cid).unwrap();
        v2_dial_ws
            .send(Message::Text(
                serde_json::to_string(&RelayV2ClientMsg::Dial {
                    target_mailbox_id: mb.mailbox_id_b64url(),
                    epoch: mb.epoch,
                    conn_id: b64url_encode(&cid),
                    dial_token: b64url_encode(&tok),
                    auth: None,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayV2ServerMsg>(
                &v2_dial_ws
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap()
            )
            .unwrap(),
            RelayV2ServerMsg::Error {
                code: "offline".to_owned()
            }
        );

        srv.stop().await.unwrap();
    }
}
