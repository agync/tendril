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
use tendril_relay::server::{IpCidr, RelayConfig, RelayError, RelayServer, TrustedProxyHeader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, connect_async_with_config};

fn generate_ephemeral_cert(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let ca_cnf = dir.join("ca.cnf");
    let ca_key = dir.join("ca.key");
    let ca_cert = dir.join("ca.crt");
    let leaf_key = dir.join("relay.key");
    let leaf_csr = dir.join("relay.csr");
    let leaf_cert = dir.join("relay.crt");
    let ext_file = dir.join("leaf.ext");
    std::fs::write(
        &ca_cnf,
        "[req]\ndistinguished_name = dn\nx509_extensions = v3_ca\nprompt = no\n\n[dn]\nCN = Tendril Test CA\n\n[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign\n",
    )
    .expect("write ca.cnf");
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
            "-config",
            ca_cnf.to_str().expect("utf8"),
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&leaf_key, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600 leaf_key");
    }

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
            mapped_cidr.clone(),
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

    drop((ws1, ws2));
    trusted_handle.stop().await.expect("stop trusted");

    // When explicitly configured for RFC 7239 Forwarded, X-Forwarded-For is ignored.
    let fwd_server = RelayServer::bind(RelayConfig {
        trusted_proxies: vec![
            "127.0.0.1/32".parse::<IpCidr>().expect("loopback cidr"),
            mapped_cidr.clone(),
        ],
        trusted_proxy_header: TrustedProxyHeader::Forwarded,
        ip_burst_capacity: 1,
        ip_refill_per_sec: 1,
        ..RelayConfig::default()
    })
    .await
    .expect("bind forwarded relay");
    let fwd_handle = fwd_server.spawn();
    let fwd_url = fwd_handle.ws_url();

    let mut req3 = fwd_url.clone().into_client_request().expect("req3");
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
    let mut req4 = fwd_url.into_client_request().expect("req4");
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

    drop((ws3, ws4));
    fwd_handle.stop().await.expect("stop forwarded");

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
            fast_open: None,
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
                    fast_open: None,
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
                    fast_open: None,
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
                    init_frame: None,
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
                    fast_open: None,
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
                    fast_open: None,
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
                        init_frame: None,
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
                        init_frame: None,
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
                    fast_open: None,
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
                    fast_open: None,
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
                    init_frame: None,
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
                    fast_open: None,
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
                    init_frame: None,
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
                    init_frame: None,
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
                    init_frame: None,
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

#[tokio::test]
async fn sec08_forged_forwarded_header_does_not_bypass_default_xff() {
    let server = RelayServer::bind(RelayConfig {
        trusted_proxies: vec!["127.0.0.1/32".parse::<IpCidr>().expect("loopback cidr")],
        ip_burst_capacity: 1,
        ip_refill_per_sec: 1,
        ..RelayConfig::default()
    })
    .await
    .expect("bind trusted relay");
    let handle = server.spawn();
    let ws_url = handle.ws_url();

    // First connection from 203.0.113.7 consumes its single token.
    let mut req1 = ws_url.clone().into_client_request().expect("req1");
    req1.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
    let (mut ws1, _) = connect_async_with_config(req1, None, false)
        .await
        .expect("ws1 connect");
    let msg1 = ws1
        .next()
        .await
        .expect("ws1 item")
        .expect("ws1 ok")
        .into_text()
        .expect("ws1 text");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&msg1).expect("msg1"),
        RelayServerMsg::Challenge { .. }
    ));

    // Attacker appends a forged Forwarded header while X-Forwarded-For stays 203.0.113.7.
    // Under default Xff mode, Forwarded must be ignored so the bucket is still rate_limited.
    let mut req2 = ws_url.clone().into_client_request().expect("req2");
    req2.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
    req2.headers_mut().insert(
        "forwarded",
        HeaderValue::from_static("for=198.51.100.55;proto=https"),
    );
    let (mut ws2, _) = connect_async_with_config(req2, None, false)
        .await
        .expect("ws2 connect");
    let msg2 = ws2
        .next()
        .await
        .expect("ws2 item")
        .expect("ws2 ok")
        .into_text()
        .expect("ws2 text");
    assert!(
        matches!(
            serde_json::from_str::<RelayServerMsg>(&msg2).expect("msg2"),
            RelayServerMsg::Error { code } if code == "rate_limited"
        ),
        "forged Forwarded header must not bypass default XFF rate limit, got {msg2}"
    );

    // Forged Forwarded containing a trusted proxy IP must not collapse distinct XFF clients
    // into the loopback proxy bucket.
    let mut req3 = ws_url.clone().into_client_request().expect("req3");
    req3.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.8"));
    req3.headers_mut()
        .insert("forwarded", HeaderValue::from_static("for=127.0.0.1"));
    let (mut ws3, _) = connect_async_with_config(req3, None, false)
        .await
        .expect("ws3 connect");
    let msg3 = ws3
        .next()
        .await
        .expect("ws3 item")
        .expect("ws3 ok")
        .into_text()
        .expect("ws3 text");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&msg3).expect("msg3"),
        RelayServerMsg::Challenge { .. }
    ));

    let mut req4 = ws_url.into_client_request().expect("req4");
    req4.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
    req4.headers_mut()
        .insert("forwarded", HeaderValue::from_static("for=127.0.0.1"));
    let (mut ws4, _) = connect_async_with_config(req4, None, false)
        .await
        .expect("ws4 connect");
    let msg4 = ws4
        .next()
        .await
        .expect("ws4 item")
        .expect("ws4 ok")
        .into_text()
        .expect("ws4 text");
    assert!(
        matches!(
            serde_json::from_str::<RelayServerMsg>(&msg4).expect("msg4"),
            RelayServerMsg::Challenge { .. }
        ),
        "forged Forwarded must not collapse distinct XFF buckets into proxy IP, got {msg4}"
    );

    drop((ws1, ws2, ws3, ws4));
    handle.stop().await.expect("stop");
}

#[tokio::test]
async fn sec09_v1_early_dialer_disconnect_frees_pending_slot_immediately() {
    use tendril_core::crypto::{b64url_decode_array, b64url_encode};

    let server = RelayServer::bind(RelayConfig {
        max_pending_per_mailbox: 2,
        accept_timeout: Duration::from_secs(15),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let ws_url = handle.ws_url();

    let kp = SigningKeypair::generate().expect("kp");
    let (mut reg_ws, _) = connect_async_with_config(&ws_url, None, false)
        .await
        .expect("connect reg");
    let ch_txt = reg_ws
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
    let nonce_bytes: [u8; 32] = b64url_decode_array(&nonce).expect("nonce");
    let (pub_b64, sig_b64) = sign_relay_register(&kp.ed25519_signing_key(), &host, &nonce_bytes);
    reg_ws
        .send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Register {
                pub_key: pub_b64.clone(),
                sig: sig_b64,
                auth: None,
                fast_open: None,
            })
            .expect("ser")
            .into(),
        ))
        .await
        .expect("send reg");
    let reg_resp = reg_ws
        .next()
        .await
        .expect("resp")
        .expect("ok")
        .into_text()
        .expect("txt");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&reg_resp).expect("parse"),
        RelayServerMsg::Registered { .. }
    ));

    let started = Instant::now();
    for i in 0..4u8 {
        let (mut d_ws, _) = connect_async_with_config(&ws_url, None, false)
            .await
            .expect("connect dialer");
        let _ = d_ws.next().await;
        d_ws.send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Dial {
                target_pub: pub_b64.clone(),
                conn_id: b64url_encode(&[0x90 + i; 16]),
                auth: None,
                init_frame: None,
            })
            .expect("ser")
            .into(),
        ))
        .await
        .expect("send dial");

        let inc = timeout(Duration::from_secs(2), reg_ws.next())
            .await
            .expect("incoming before timeout")
            .expect("incoming item")
            .expect("incoming ok")
            .into_text()
            .expect("incoming txt");
        assert!(
            matches!(
                serde_json::from_str::<RelayServerMsg>(&inc).expect("parse inc"),
                RelayServerMsg::Incoming { .. }
            ),
            "dial #{i} should reach mailbox without hitting rate_limited"
        );
        drop(d_ws);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "early dialer disconnects must free slots immediately"
    );

    drop(reg_ws);
    handle.stop().await.expect("stop");
}

#[tokio::test]
async fn sec09_v1_idle_ping_pong_watchdog_reaps_silent_client_and_keeps_live_client() {
    use tendril_core::crypto::{b64url_decode_array, b64url_encode};

    let server = RelayServer::bind(RelayConfig {
        idle_timeout: Duration::from_millis(120),
        pong_timeout: Duration::from_millis(120),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let ws_url = handle.ws_url();

    async fn reg_v1(
        ws_url: &str,
        kp: &SigningKeypair,
    ) -> (
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        String,
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
        let nonce_bytes: [u8; 32] = b64url_decode_array(&nonce).expect("nonce");
        let (pub_b64, sig_b64) =
            sign_relay_register(&kp.ed25519_signing_key(), &host, &nonce_bytes);
        ws.send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Register {
                pub_key: pub_b64.clone(),
                sig: sig_b64,
                auth: None,
                fast_open: None,
            })
            .expect("ser")
            .into(),
        ))
        .await
        .expect("send reg");
        let resp = ws
            .next()
            .await
            .expect("resp")
            .expect("ok")
            .into_text()
            .expect("txt");
        assert!(matches!(
            serde_json::from_str::<RelayServerMsg>(&resp).expect("parse"),
            RelayServerMsg::Registered { .. }
        ));
        (ws, pub_b64)
    }

    let live_kp = SigningKeypair::generate().expect("live kp");
    let dead_kp = SigningKeypair::generate().expect("dead kp");
    let (mut live_ws, _live_pub) = reg_v1(&ws_url, &live_kp).await;
    let (dead_ws, dead_pub) = reg_v1(&ws_url, &dead_kp).await;

    let live_task = tokio::spawn(async move {
        let mut saw_ping = false;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(450);
        while tokio::time::Instant::now() < deadline {
            match timeout(Duration::from_millis(60), live_ws.next()).await {
                Ok(Some(Ok(Message::Ping(_)))) => {
                    saw_ping = true;
                }
                Ok(Some(Ok(_))) => {}
                Ok(None | Some(Err(_))) => panic!("live v1 client must not be closed by watchdog"),
                Err(_) => {}
            }
        }
        (live_ws, saw_ping)
    });

    tokio::time::sleep(Duration::from_millis(450)).await;
    let (_live_ws, saw_ping) = live_task.await.expect("live task");
    assert!(saw_ping, "expected v1 watchdog to send Ping to live client");

    let (mut dial_dead, _) = connect_async_with_config(&ws_url, None, false)
        .await
        .expect("dial dead");
    let _ = dial_dead.next().await;
    dial_dead
        .send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Dial {
                target_pub: dead_pub,
                conn_id: b64url_encode(&[0x42; 16]),
                auth: None,
                init_frame: None,
            })
            .expect("ser")
            .into(),
        ))
        .await
        .expect("send dial");
    let resp = timeout(Duration::from_secs(2), dial_dead.next())
        .await
        .expect("dial resp before timeout")
        .expect("item")
        .expect("ok")
        .into_text()
        .expect("txt");
    assert_eq!(
        serde_json::from_str::<RelayServerMsg>(&resp).expect("parse"),
        RelayServerMsg::Error {
            code: "offline".to_owned()
        }
    );

    drop(dead_ws);
    handle.stop().await.expect("stop");
}

#[tokio::test]
async fn sec16_pre_upgrade_trusted_proxy_stall_is_bounded() {
    let server = RelayServer::bind(RelayConfig {
        max_total_connections: 8,
        trusted_proxies: vec!["127.0.0.1/32".parse::<IpCidr>().expect("loopback cidr")],
        accept_timeout: Duration::from_millis(300),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let handle = server.spawn();
    let addr = handle.local_addr();
    let ws_url = handle.ws_url();

    // First establish 2 upgraded WS connections; they must release their pre-upgrade permits.
    let mut req_a = ws_url.clone().into_client_request().expect("req_a");
    req_a
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    let (ws_a, _) = connect_async_with_config(req_a, None, false)
        .await
        .expect("ws_a");

    let mut req_b = ws_url.clone().into_client_request().expect("req_b");
    req_b
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.11"));
    let (ws_b, _) = connect_async_with_config(req_b, None, false)
        .await
        .expect("ws_b");

    // Open 2 stalled raw TCP connections from the trusted proxy; this saturates
    // pre_upgrade_cap = (8 / 4).max(1) = 2 while max_total_connections=8 still has 4 free slots.
    let stall1 = TcpStream::connect(addr).await.expect("stall1");
    let stall2 = TcpStream::connect(addr).await.expect("stall2");
    tokio::time::sleep(Duration::from_millis(30)).await;

    let mut req_c = ws_url.clone().into_client_request().expect("req_c");
    req_c
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.12"));
    let rejected = timeout(
        Duration::from_millis(200),
        connect_async_with_config(req_c, None, false),
    )
    .await;
    assert!(
        !matches!(rejected, Ok(Ok(_))),
        "3rd concurrent pre-upgrade trusted-proxy connection must be rejected at pre-upgrade cap"
    );

    // Wait for upgrade timeout (300ms) to evict stalled pre-upgrade sockets, then upgrade succeeds.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut req_d = ws_url.into_client_request().expect("req_d");
    req_d
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.13"));
    let (ws_d, _) = connect_async_with_config(req_d, None, false)
        .await
        .expect("ws_d after stall timeout");

    drop((stall1, stall2, ws_a, ws_b, ws_d));
    handle.stop().await.expect("stop");
}

#[cfg(unix)]
#[tokio::test]
async fn sec18_tls_key_rejects_symlink_and_world_readable() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = TempDir::new().expect("tempdir");
    let (_ca_cert_path, cert_path, key_path) = generate_ephemeral_cert(tmp.path());

    // World-readable (0o644) TLS key must be rejected.
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
    let res_644 = RelayServer::bind(RelayConfig {
        tls_cert_path: Some(cert_path.clone()),
        tls_key_path: Some(key_path.clone()),
        ..RelayConfig::default()
    })
    .await;
    assert!(
        matches!(res_644, Err(RelayError::Tls(_))),
        "0o644 TLS key must be rejected"
    );

    // Fix key permissions to 0o600, then verify symlink to it is rejected.
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    let link_path = tmp.path().join("relay-key-link.pem");
    symlink(&key_path, &link_path).expect("symlink");
    let res_link = RelayServer::bind(RelayConfig {
        tls_cert_path: Some(cert_path),
        tls_key_path: Some(link_path),
        ..RelayConfig::default()
    })
    .await;
    assert!(
        matches!(res_link, Err(RelayError::Tls(_))),
        "symlink TLS key must be rejected"
    );
}

#[tokio::test]
async fn w2_standby_cap_control_lifecycle_and_zero_presence_leak() {
    use tendril_core::crypto::{b64url_decode_array, b64url_encode};
    use tendril_core::relay_auth::{RelayAuthProof, RelayAuthScope, compute_relay_auth_hmac_b64};
    use tendril_core::v2::{derive_epoch_mailbox, sign_v2_relay_dial, sign_v2_relay_register};
    use tendril_relay::protocol::{
        MAX_RELAY_FRAME_LEN, MAX_STANDBY_PER_MAILBOX, RelayV2ClientMsg, RelayV2ServerMsg,
    };
    use zeroize::Zeroizing;

    assert_eq!(MAX_STANDBY_PER_MAILBOX, 4);
    let secret = b"standby-auth-secret-32bytes-long!".to_vec();
    let srv = RelayServer::bind(RelayConfig {
        auth_secret: Some(Zeroizing::new(secret.clone())),
        auth_scope: RelayAuthScope::All,
        ..RelayConfig::default()
    })
    .await
    .unwrap()
    .spawn();
    let v1_url = srv.ws_url();
    let v2_url = srv.ws_v2_url();

    let kp = SigningKeypair::generate().unwrap();
    let sk = kp.ed25519_signing_key();
    let pub_bytes = sk.verifying_key().to_bytes();
    let pub_b64 = b64url_encode(&pub_bytes);

    // 1. Standby without active Register fails closed ("offline" after auth/sig pass, "unauthorized" if bad auth).
    {
        let (mut ws, _) = tokio_tungstenite::connect_async(&v1_url).await.unwrap();
        let RelayServerMsg::Challenge { nonce, host, .. } =
            serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap()
        else {
            panic!("challenge");
        };
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let (_, sig) = sign_relay_register(&sk, &host, &n);
        let mac = compute_relay_auth_hmac_b64(&secret, "register", &host, &n, &pub_bytes).unwrap();
        ws.send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Standby {
                pub_key: pub_b64.clone(),
                sig,
                auth: Some(RelayAuthProof::Hmac { mac }),
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
                code: "offline".to_owned()
            }
        );
    }

    // 2. Register v1 control, park 4 standby sockets, verify 5th gets rate_limited.
    let (mut ctrl_v1, _) = tokio_tungstenite::connect_async(&v1_url).await.unwrap();
    let RelayServerMsg::Challenge { nonce, host, .. } =
        serde_json::from_str(&ctrl_v1.next().await.unwrap().unwrap().into_text().unwrap()).unwrap()
    else {
        panic!("challenge");
    };
    let n = b64url_decode_array::<32>(&nonce).unwrap();
    let (_, sig) = sign_relay_register(&sk, &host, &n);
    let mac = compute_relay_auth_hmac_b64(&secret, "register", &host, &n, &pub_bytes).unwrap();
    ctrl_v1
        .send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Register {
                pub_key: pub_b64.clone(),
                sig,
                auth: Some(RelayAuthProof::Hmac { mac }),
                fast_open: Some(true),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(
            &ctrl_v1.next().await.unwrap().unwrap().into_text().unwrap()
        )
        .unwrap(),
        RelayServerMsg::Registered { .. }
    ));

    let mut standbys = Vec::new();
    for _ in 0..MAX_STANDBY_PER_MAILBOX {
        let (mut ws, _) = tokio_tungstenite::connect_async(&v1_url).await.unwrap();
        let RelayServerMsg::Challenge { nonce, host, .. } =
            serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap()
        else {
            panic!("challenge");
        };
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let (_, sig) = sign_relay_register(&sk, &host, &n);
        let mac = compute_relay_auth_hmac_b64(&secret, "register", &host, &n, &pub_bytes).unwrap();
        ws.send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Standby {
                pub_key: pub_b64.clone(),
                sig,
                auth: Some(RelayAuthProof::Hmac { mac }),
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
            RelayServerMsg::StandbyReady
        );
        standbys.push(ws);
    }

    // 5th standby socket must fail closed with rate_limited.
    {
        let (mut ws5, _) = tokio_tungstenite::connect_async(&v1_url).await.unwrap();
        let RelayServerMsg::Challenge { nonce, host, .. } =
            serde_json::from_str(&ws5.next().await.unwrap().unwrap().into_text().unwrap()).unwrap()
        else {
            panic!("challenge");
        };
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let (_, sig) = sign_relay_register(&sk, &host, &n);
        let mac = compute_relay_auth_hmac_b64(&secret, "register", &host, &n, &pub_bytes).unwrap();
        ws5.send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Standby {
                pub_key: pub_b64.clone(),
                sig,
                auth: Some(RelayAuthProof::Hmac { mac }),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayServerMsg>(
                &ws5.next().await.unwrap().unwrap().into_text().unwrap()
            )
            .unwrap(),
            RelayServerMsg::Error {
                code: "rate_limited".to_owned()
            }
        );
    }

    // 3. Unauthorized Dial (missing auth, with and without init_frame) must return "unauthorized" without leaking presence or popping standby.
    for init_frame in [None, Some(b64url_encode(b"probe"))] {
        let (mut d_ws, _) = tokio_tungstenite::connect_async(&v1_url).await.unwrap();
        let _ = d_ws.next().await;
        d_ws.send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Dial {
                target_pub: pub_b64.clone(),
                conn_id: b64url_encode(&[0x91; 16]),
                auth: None,
                init_frame,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayServerMsg>(
                &d_ws.next().await.unwrap().unwrap().into_text().unwrap()
            )
            .unwrap(),
            RelayServerMsg::Error {
                code: "unauthorized".to_owned()
            }
        );
    }

    // 4. Invalid / empty / oversized init_frame must be rejected BEFORE popping standby!
    for (bad_init, expected_code) in [
        ("!!!not-b64url!!!".to_owned(), "bad_request"),
        (String::new(), "bad_request"),
        (
            b64url_encode(&vec![0xAA; MAX_RELAY_FRAME_LEN + 1]),
            "frame_too_large",
        ),
    ] {
        let (mut d_ws, _) = tokio_tungstenite::connect_async(&v1_url).await.unwrap();
        let RelayServerMsg::Challenge { nonce, host, .. } =
            serde_json::from_str(&d_ws.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap()
        else {
            panic!("challenge");
        };
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let mac = compute_relay_auth_hmac_b64(&secret, "dial", &host, &n, &pub_bytes).unwrap();
        d_ws.send(Message::Text(
            serde_json::to_string(&RelayClientMsg::Dial {
                target_pub: pub_b64.clone(),
                conn_id: b64url_encode(&[0x92; 16]),
                auth: Some(RelayAuthProof::Hmac { mac }),
                init_frame: Some(bad_init),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayServerMsg>(
                &d_ws.next().await.unwrap().unwrap().into_text().unwrap()
            )
            .unwrap(),
            RelayServerMsg::Error {
                code: expected_code.to_owned()
            }
        );
    }

    // None of the 4 standby sockets should have been consumed! Dropping control closes them.
    for sb in &mut standbys {
        assert!(
            tokio::time::timeout(Duration::from_millis(30), sb.next())
                .await
                .is_err(),
            "standby socket must not be consumed by rejected dials"
        );
    }
    drop(ctrl_v1);
    for mut sb in standbys {
        let closed = tokio::time::timeout(Duration::from_secs(2), sb.next())
            .await
            .expect("standby must close when control disconnects");
        assert!(matches!(
            closed,
            None | Some(Ok(Message::Close(_))) | Some(Err(_))
        ));
    }

    // 5. Same zero-presence-leak and init_frame validation on /v2/relay.
    let now_u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mb = derive_epoch_mailbox(&[0x7C; 32], now_u64 / 3600);
    let (mut ctrl_v2, _) = tokio_tungstenite::connect_async(&v2_url).await.unwrap();
    let RelayV2ServerMsg::Challenge { nonce, host, .. } =
        serde_json::from_str(&ctrl_v2.next().await.unwrap().unwrap().into_text().unwrap()).unwrap()
    else {
        panic!("v2 challenge");
    };
    let n = b64url_decode_array::<32>(&nonce).unwrap();
    let reg_sig = sign_v2_relay_register(&mb, &host, &n).unwrap();
    let mac = compute_relay_auth_hmac_b64(&secret, "register", &host, &n, &mb.mailbox_id).unwrap();
    ctrl_v2
        .send(Message::Text(
            serde_json::to_string(&RelayV2ClientMsg::Register {
                mailbox_id: mb.mailbox_id_b64url(),
                epoch: mb.epoch,
                sig: b64url_encode(&reg_sig),
                auth: Some(RelayAuthProof::Hmac { mac }),
                fast_open: Some(true),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        serde_json::from_str::<RelayV2ServerMsg>(
            &ctrl_v2.next().await.unwrap().unwrap().into_text().unwrap()
        )
        .unwrap(),
        RelayV2ServerMsg::Registered { .. }
    ));

    let (mut v2_sb, _) = tokio_tungstenite::connect_async(&v2_url).await.unwrap();
    let RelayV2ServerMsg::Challenge { nonce, host, .. } =
        serde_json::from_str(&v2_sb.next().await.unwrap().unwrap().into_text().unwrap()).unwrap()
    else {
        panic!("v2 standby challenge");
    };
    let n = b64url_decode_array::<32>(&nonce).unwrap();
    let sb_sig = sign_v2_relay_register(&mb, &host, &n).unwrap();
    let mac = compute_relay_auth_hmac_b64(&secret, "register", &host, &n, &mb.mailbox_id).unwrap();
    v2_sb
        .send(Message::Text(
            serde_json::to_string(&RelayV2ClientMsg::Standby {
                mailbox_id: mb.mailbox_id_b64url(),
                epoch: mb.epoch,
                sig: b64url_encode(&sb_sig),
                auth: Some(RelayAuthProof::Hmac { mac }),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        serde_json::from_str::<RelayV2ServerMsg>(
            &v2_sb.next().await.unwrap().unwrap().into_text().unwrap()
        )
        .unwrap(),
        RelayV2ServerMsg::StandbyReady { .. }
    ));

    // Unauthorized v2 Dial (with and without init_frame) must return "unauthorized" without consuming standby.
    for unauth_init in [None, Some(b64url_encode(b"probe-v2"))] {
        let (mut d_unauth, _) = tokio_tungstenite::connect_async(&v2_url).await.unwrap();
        let _ = d_unauth.next().await;
        d_unauth
            .send(Message::Text(
                serde_json::to_string(&RelayV2ClientMsg::Dial {
                    target_mailbox_id: mb.mailbox_id_b64url(),
                    epoch: mb.epoch,
                    conn_id: b64url_encode(&[0x95; 16]),
                    dial_token: b64url_encode(&[0x00; 32]),
                    auth: None,
                    init_frame: unauth_init,
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayV2ServerMsg>(
                &d_unauth.next().await.unwrap().unwrap().into_text().unwrap()
            )
            .unwrap(),
            RelayV2ServerMsg::Error {
                code: "unauthorized".to_owned()
            }
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), v2_sb.next())
            .await
            .is_err(),
        "v2 standby socket must stay idle on unauthorized dial"
    );

    // Also park a second v2 standby socket to test control-disconnect eviction after dial tests.
    let (mut v2_sb_evict, _) = tokio_tungstenite::connect_async(&v2_url).await.unwrap();
    let RelayV2ServerMsg::Challenge { nonce, host, .. } = serde_json::from_str(
        &v2_sb_evict
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap(),
    )
    .unwrap() else {
        panic!("v2 standby2 challenge");
    };
    let n = b64url_decode_array::<32>(&nonce).unwrap();
    let sb2_sig = sign_v2_relay_register(&mb, &host, &n).unwrap();
    let sb2_mac =
        compute_relay_auth_hmac_b64(&secret, "register", &host, &n, &mb.mailbox_id).unwrap();
    v2_sb_evict
        .send(Message::Text(
            serde_json::to_string(&RelayV2ClientMsg::Standby {
                mailbox_id: mb.mailbox_id_b64url(),
                epoch: mb.epoch,
                sig: b64url_encode(&sb2_sig),
                auth: Some(RelayAuthProof::Hmac { mac: sb2_mac }),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        serde_json::from_str::<RelayV2ServerMsg>(
            &v2_sb_evict
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap()
        )
        .unwrap(),
        RelayV2ServerMsg::StandbyReady { .. }
    ));

    // Oversized init_frame on v2 rejected with frame_too_large before popping standby.
    {
        let (mut d_ws, _) = tokio_tungstenite::connect_async(&v2_url).await.unwrap();
        let RelayV2ServerMsg::Challenge { nonce, host, .. } =
            serde_json::from_str(&d_ws.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap()
        else {
            panic!("v2 dial challenge");
        };
        let n = b64url_decode_array::<32>(&nonce).unwrap();
        let cid = [0x93; 16];
        let tok = sign_v2_relay_dial(&mb, &host, &n, &cid).unwrap();
        let mac = compute_relay_auth_hmac_b64(&secret, "dial", &host, &n, &mb.mailbox_id).unwrap();
        d_ws.send(Message::Text(
            serde_json::to_string(&RelayV2ClientMsg::Dial {
                target_mailbox_id: mb.mailbox_id_b64url(),
                epoch: mb.epoch,
                conn_id: b64url_encode(&cid),
                dial_token: b64url_encode(&tok),
                auth: Some(RelayAuthProof::Hmac { mac }),
                init_frame: Some(b64url_encode(&vec![0xBB; MAX_RELAY_FRAME_LEN + 1])),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<RelayV2ServerMsg>(
                &d_ws.next().await.unwrap().unwrap().into_text().unwrap()
            )
            .unwrap(),
            RelayV2ServerMsg::Error {
                code: "frame_too_large".to_owned()
            }
        );
    }

    // Standby socket still intact and receives valid Dial with MAX_RELAY_FRAME_LEN init_frame.
    let (mut d_ok, _) = tokio_tungstenite::connect_async(&v2_url).await.unwrap();
    let RelayV2ServerMsg::Challenge { nonce, host, .. } =
        serde_json::from_str(&d_ok.next().await.unwrap().unwrap().into_text().unwrap()).unwrap()
    else {
        panic!("v2 dial ok challenge");
    };
    let n = b64url_decode_array::<32>(&nonce).unwrap();
    let cid = [0x94; 16];
    let tok = sign_v2_relay_dial(&mb, &host, &n, &cid).unwrap();
    let mac = compute_relay_auth_hmac_b64(&secret, "dial", &host, &n, &mb.mailbox_id).unwrap();
    let max_init_b64 = b64url_encode(&vec![0x55; MAX_RELAY_FRAME_LEN]);
    d_ok.send(Message::Text(
        serde_json::to_string(&RelayV2ClientMsg::Dial {
            target_mailbox_id: mb.mailbox_id_b64url(),
            epoch: mb.epoch,
            conn_id: b64url_encode(&cid),
            dial_token: b64url_encode(&tok),
            auth: Some(RelayAuthProof::Hmac { mac }),
            init_frame: Some(max_init_b64.clone()),
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    let inc: RelayV2ServerMsg =
        serde_json::from_str(&v2_sb.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert!(matches!(
        inc,
        RelayV2ServerMsg::Incoming {
            init_frame: Some(ref f),
            ..
        } if f == &max_init_b64
    ));

    // Dropping v2 control socket must evict and close remaining parked v2 standby sockets.
    drop(ctrl_v2);
    let evicted = tokio::time::timeout(Duration::from_secs(2), v2_sb_evict.next())
        .await
        .expect("v2 standby must close when v2 control disconnects");
    assert!(matches!(
        evicted,
        None | Some(Ok(Message::Close(_))) | Some(Err(_))
    ));

    srv.stop().await.unwrap();
}

#[tokio::test]
async fn paas_healthz_probe_serves_http_and_rejects_ws_upgrade_over_plain_and_tls() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn read_http_response<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        io: &mut S,
        req: &[u8],
    ) -> String {
        io.write_all(req).await.expect("write http req");
        io.flush().await.expect("flush http req");
        let mut buf = Vec::new();
        timeout(Duration::from_secs(2), io.read_to_end(&mut buf))
            .await
            .expect("http read timed out")
            .expect("http read failed");
        String::from_utf8(buf).expect("valid utf8 http response")
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let server = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind plain relay");
    let handle = server.spawn();
    let addr = handle.local_addr();

    // GET /healthz across split header writes returns 200 OK with body "ok".
    {
        let mut sock = TcpStream::connect(addr).await.expect("connect plain");
        sock.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap();
        sock.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        let resp =
            read_http_response(&mut sock, b"Host: localhost\r\nConnection: close\r\n\r\n").await;
        assert!(
            resp.starts_with("HTTP/1.1 200 OK\r\n"),
            "expected 200 OK on GET /healthz, got: {resp:?}"
        );
        assert!(resp.contains("Content-Length: 2\r\n"));
        assert!(resp.contains("Cache-Control: no-store\r\n"));
        assert!(
            resp.ends_with("\r\n\r\nok"),
            "expected body ok, got: {resp:?}"
        );
    }

    // HEAD /healthz returns 200 OK with Content-Length: 2 and empty body.
    {
        let mut sock = TcpStream::connect(addr).await.expect("connect head");
        let resp = read_http_response(
            &mut sock,
            b"HEAD /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 200 OK\r\n"),
            "expected 200 OK on HEAD /healthz, got: {resp:?}"
        );
        assert!(resp.contains("Content-Length: 2\r\n"));
        assert!(
            resp.ends_with("\r\n\r\n"),
            "HEAD must have empty body, got: {resp:?}"
        );
    }

    // Non-GET/HEAD methods, query suffixes, Upgrade/HTTP anomalies, and other paths must not return 200 OK.
    for req in [
        b"POST /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
        b"GET /healthz?probe=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
        b"GET /healthz HTTP/9.9\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
        b"GET /healthz HTTP/1.1\r\nHost: localhost\nUpgrade: websocket\r\n\r\n".as_slice(),
        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\n\r\n"
            .as_slice(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
    ] {
        let mut sock = TcpStream::connect(addr).await.expect("connect non-healthz");
        let resp = read_http_response(&mut sock, req).await;
        assert!(
            !resp.starts_with("HTTP/1.1 200 OK"),
            "unexpected 200 OK for {}: {resp:?}",
            String::from_utf8_lossy(req)
        );
    }

    // WebSocket upgrades targeting /healthz MUST be rejected before upgrade.
    let bad_ws_url = format!("ws://{addr}/healthz");
    assert!(
        tokio_tungstenite::connect_async(&bad_ws_url).await.is_err(),
        "websocket upgrade to /healthz must be rejected"
    );

    // /v1/relay still serves WebSocket challenges on the same listener.
    let (mut ws, _) = tokio_tungstenite::connect_async(&handle.ws_url())
        .await
        .expect("v1 ws connect");
    let first = timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("challenge timeout")
        .expect("challenge item")
        .expect("challenge ok")
        .into_text()
        .expect("challenge text");
    assert!(matches!(
        serde_json::from_str::<RelayServerMsg>(&first).expect("parse challenge"),
        RelayServerMsg::Challenge { .. }
    ));
    drop(ws);
    handle.stop().await.expect("stop plain relay");

    // TLS listener serves GET /healthz with 200 OK as well.
    let tmp = TempDir::new().expect("tempdir");
    let (ca_cert_path, cert_path, key_path) = generate_ephemeral_cert(tmp.path());
    let tls_server = RelayServer::bind(RelayConfig {
        tls_cert_path: Some(cert_path),
        tls_key_path: Some(key_path),
        ..RelayConfig::default()
    })
    .await
    .expect("bind tls relay");
    let tls_handle = tls_server.spawn();
    let tls_addr = tls_handle.local_addr();

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&ca_cert_path).expect("open ca cert") {
        roots
            .add(cert.expect("parse ca cert"))
            .expect("add ca cert");
    }
    let tls_cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let tls_connector = tokio_rustls::TlsConnector::from(tls_cfg);
    let tcp = TcpStream::connect(tls_addr).await.expect("connect tls tcp");
    let server_name = rustls_pki_types::ServerName::try_from("localhost").expect("server name");
    let mut tls_stream = tls_connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");
    let tls_resp = read_http_response(
        &mut tls_stream,
        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        tls_resp.starts_with("HTTP/1.1 200 OK\r\n") && tls_resp.ends_with("\r\n\r\nok"),
        "expected TLS GET /healthz 200 OK with body ok, got: {tls_resp:?}"
    );
    tls_handle.stop().await.expect("stop tls relay");
}

#[tokio::test]
async fn paas_cli_env_configures_listen_host_and_healthz() {
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command as StdCommand, Stdio};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let bin = env!("CARGO_BIN_EXE_tendril-relay");
    let child = StdCommand::new(bin)
        .env_clear()
        .env("RUST_LOG", "info")
        .env("TENDRIL_RELAY_LISTEN", "127.0.0.1:0")
        .env("FLY_APP_NAME", "tendril-paas-smoke")
        .env("TENDRIL_RELAY_AUTH_SECRET", "paas-smoke-secret-value")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tendril-relay");
    let mut guard = ChildGuard(child);

    let stdout = guard.0.stdout.take().expect("stdout pipe");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if let Some(pos) = line.find("ws://") {
                let candidate = line[pos..]
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                if candidate.ends_with("/v1/relay") {
                    let _ = tx.send(candidate);
                    break;
                }
            }
        }
    });
    let ws_url = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("tendril-relay did not log listening URL");
    let host_port = ws_url
        .strip_prefix("ws://")
        .and_then(|s| s.strip_suffix("/v1/relay"))
        .expect("parse ws_url");
    let addr: std::net::SocketAddr = host_port.parse().expect("parse socket addr");

    let mut sock = timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .expect("connect timeout")
        .expect("connect child");
    sock.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    timeout(Duration::from_secs(2), sock.read_to_end(&mut body))
        .await
        .expect("healthz read timeout")
        .unwrap();
    let resp = String::from_utf8(body).unwrap();
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n") && resp.ends_with("\r\n\r\nok"),
        "expected /healthz 200 OK, got: {resp:?}"
    );

    let (mut ws, _) = timeout(
        Duration::from_secs(2),
        tokio_tungstenite::connect_async(&ws_url),
    )
    .await
    .expect("ws connect timeout")
    .expect("connect child ws");
    let first = timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timeout")
        .expect("item")
        .expect("ok")
        .into_text()
        .expect("txt");
    match serde_json::from_str::<RelayServerMsg>(&first).expect("parse") {
        RelayServerMsg::Challenge {
            host,
            auth_required,
            ..
        } => {
            assert_eq!(host, "tendril-paas-smoke.fly.dev");
            assert_eq!(
                auth_required,
                Some(vec!["register".to_owned(), "dial".to_owned()])
            );
        }
        other => panic!("unexpected msg: {other:?}"),
    }
}
