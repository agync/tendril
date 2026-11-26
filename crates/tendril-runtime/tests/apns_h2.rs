use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde_json::Value;
use tendril_core::crypto::{b64url_decode, b64url_encode};
use tendril_runtime::{
    ApnsH2Auth, ApnsH2WakeProvider, ApnsPayload, ApnsPushMode, DEFAULT_APNS_LOC_KEY,
    HttpWakeProvider, MAX_WAKE_ENDPOINT_URL_LEN, MAX_WAKE_PEM_BYTES, RuntimeError, WAKE_EPOCH_SECS,
    WakeAdapterKind, WakeConfigSpec, WakeOutcome, WakeProvider, WakeSecret, WakeTarget,
    build_wake_provider, build_wake_provider_with_root_certs, default_wake_root_certs,
    validate_apns_loc_key, wake_epoch_start_secs,
};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};
use tokio_rustls::TlsAcceptor;

fn b64_std_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn der_to_pkcs8_pem(der: &[u8]) -> String {
    let body = b64_std_encode(der);
    let mut wrapped = String::new();
    wrapped.push_str(concat!("-----BEGIN ", "PRIVATE KEY-----\n"));
    for chunk in body.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).expect("ascii b64"));
        wrapped.push('\n');
    }
    wrapped.push_str(concat!("-----END ", "PRIVATE KEY-----\n"));
    wrapped
}

fn generate_p256_pkcs8_pem_and_pub() -> (String, Vec<u8>) {
    let rng = SystemRandom::new();
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("generate p256 pkcs8");
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng)
        .expect("parse p256 pkcs8");
    let pub_bytes = kp.public_key().as_ref().to_vec();
    let pem = der_to_pkcs8_pem(doc.as_ref());
    (pem, pub_bytes)
}

struct EphemeralPki {
    root_store: RootCertStore,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
    client_cert_pem: String,
    client_key_pem: String,
}

fn generate_test_pki() -> EphemeralPki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed ca");
    let issuer = Issuer::new(ca_params, ca_key);

    let mut srv_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("srv params");
    srv_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("srv key");
    let srv_cert = srv_params.signed_by(&srv_key, &issuer).expect("sign srv");

    let mut cli_params = CertificateParams::new(vec!["tendril-client".to_owned()]).unwrap();
    cli_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cli_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cli_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("cli key");
    let cli_cert = cli_params.signed_by(&cli_key, &issuer).expect("sign cli");

    let mut root_store = RootCertStore::empty();
    root_store.add(ca_cert.der().clone()).expect("add ca root");

    let server_key_der = PrivateKeyDer::try_from(srv_key.serialize_der()).expect("srv key der");
    let client_key_pem = der_to_pkcs8_pem(&cli_key.serialize_der());

    EphemeralPki {
        root_store,
        server_cert_der: srv_cert.der().clone(),
        server_key_der,
        client_cert_pem: cli_cert.pem(),
        client_key_pem,
    }
}

#[derive(Debug, Clone)]
struct CapturedH2Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Value,
}

impl CapturedH2Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone)]
struct MockServerBehavior {
    status: StatusCode,
    response_body: Bytes,
    goaway_after_req_num: Option<usize>,
}

impl Default for MockServerBehavior {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            response_body: Bytes::new(),
            goaway_after_req_num: None,
        }
    }
}

struct MockApnsH2Server {
    addr: SocketAddr,
    conn_count: Arc<AtomicUsize>,
    req_count: Arc<AtomicUsize>,
    captured: Arc<Mutex<Vec<CapturedH2Request>>>,
    behavior: Arc<Mutex<MockServerBehavior>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockApnsH2Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockApnsH2Server {
    async fn start(pki: &EphemeralPki, require_client_auth: bool) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let builder = rustls::ServerConfig::builder();
        let builder = if require_client_auth {
            let verifier = WebPkiClientVerifier::builder(Arc::new(pki.root_store.clone()))
                .build()
                .expect("client verifier");
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let mut server_cfg = builder
            .with_single_cert(
                vec![pki.server_cert_der.clone()],
                pki.server_key_der.clone_key(),
            )
            .expect("server tls cfg");
        server_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let conn_count = Arc::new(AtomicUsize::new(0));
        let req_count = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let behavior = Arc::new(Mutex::new(MockServerBehavior::default()));

        let conn_count_c = Arc::clone(&conn_count);
        let req_count_c = Arc::clone(&req_count);
        let captured_c = Arc::clone(&captured);
        let behavior_c = Arc::clone(&behavior);

        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let conn_count = Arc::clone(&conn_count_c);
                let req_count = Arc::clone(&req_count_c);
                let captured = Arc::clone(&captured_c);
                let behavior = Arc::clone(&behavior_c);

                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut h2_conn) = h2::server::handshake(tls).await else {
                        return;
                    };
                    conn_count.fetch_add(1, Ordering::SeqCst);
                    let close_notify = Arc::new(Notify::new());

                    loop {
                        let next_req = tokio::select! {
                            res = h2_conn.accept() => res,
                            _ = close_notify.notified() => {
                                h2_conn.graceful_shutdown();
                                let _ = tokio::time::timeout(Duration::from_millis(200), async {
                                    while let Some(res) = h2_conn.accept().await {
                                        if res.is_err() {
                                            break;
                                        }
                                    }
                                }).await;
                                break;
                            }
                        };
                        let Some(Ok((req, mut respond))) = next_req else {
                            break;
                        };
                        let req_num = req_count.fetch_add(1, Ordering::SeqCst) + 1;
                        let captured = Arc::clone(&captured);
                        let behavior = Arc::clone(&behavior);
                        let close_notify = Arc::clone(&close_notify);

                        tokio::spawn(async move {
                            let method = req.method().to_string();
                            let path = req.uri().path().to_owned();
                            let headers: Vec<(String, String)> = req
                                .headers()
                                .iter()
                                .map(|(k, v)| {
                                    (
                                        k.as_str().to_owned(),
                                        v.to_str().unwrap_or("<non-utf8>").to_owned(),
                                    )
                                })
                                .collect();
                            let mut body_stream = req.into_body();
                            let mut raw_body = Vec::new();
                            while let Some(Ok(chunk)) = body_stream.data().await {
                                raw_body.extend_from_slice(&chunk);
                                let _ = body_stream.flow_control().release_capacity(chunk.len());
                            }
                            let body_json: Value =
                                serde_json::from_slice(&raw_body).unwrap_or(Value::Null);
                            captured.lock().await.push(CapturedH2Request {
                                method,
                                path,
                                headers,
                                body: body_json,
                            });

                            let beh = behavior.lock().await.clone();
                            let resp = Response::builder()
                                .status(beh.status)
                                .body(())
                                .expect("build h2 resp");
                            if let Ok(mut send_stream) =
                                respond.send_response(resp, beh.response_body.is_empty())
                                && !beh.response_body.is_empty()
                            {
                                let _ = send_stream.send_data(beh.response_body, true);
                            }
                            if beh.goaway_after_req_num == Some(req_num) {
                                close_notify.notify_one();
                            }
                        });
                    }
                });
            }
        });

        Self {
            addr,
            conn_count,
            req_count,
            captured,
            behavior,
            task,
        }
    }
}

fn verify_es256_jwt(token: &str, pub_bytes: &[u8], expected_team: &str, expected_kid: &str) -> u64 {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWT must have 3 segments");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64url_decode(parts[2]).expect("decode jwt sig");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pub_bytes)
        .verify(signing_input.as_bytes(), &sig_bytes)
        .expect("ES256 JWT signature must verify");

    let hdr: Value =
        serde_json::from_slice(&b64url_decode(parts[0]).expect("hdr b64")).expect("hdr json");
    assert_eq!(hdr["alg"], "ES256");
    assert_eq!(hdr["kid"], expected_kid);

    let claims: Value =
        serde_json::from_slice(&b64url_decode(parts[1]).expect("claims b64")).expect("claims json");
    assert_eq!(claims["iss"], expected_team);
    claims["iat"].as_u64().expect("iat u64")
}

#[tokio::test]
async fn apns_h2_es256_jwt_headers_caching_and_refresh() {
    let pki = generate_test_pki();
    let server = MockApnsH2Server::start(&pki, false).await;
    let (p8_pem, pub_bytes) = generate_p256_pkcs8_pem_and_pub();

    let provider = ApnsH2WakeProvider::new(ApnsH2Auth::ProviderToken {
        team_id: "TEAM123456".to_owned(),
        key_id: "KEY9876543".to_owned(),
        p8_pem: p8_pem.into_bytes().into(),
    })
    .expect("construct ApnsH2WakeProvider")
    .with_root_certs(pki.root_store.clone())
    .expect("set test root certs")
    .with_topic("dev.tendril.ios")
    .expect("set topic")
    .with_cooldown_secs(0);

    let device_hex = "a".repeat(64);
    let url = format!(
        "https://127.0.0.1:{}/3/device/{device_hex}",
        server.addr.port()
    );
    let target = WakeTarget::new(WakeAdapterKind::ApnsH2, &url).expect("target");
    let secret = WakeSecret::from_bytes([0x33; 32]);
    let t0 = 1_700_000_100;
    let tag0 = secret.derive_tag(t0);

    let outcome = provider.notify(&target, &tag0, t0).await.expect("notify 1");
    assert_eq!(outcome, WakeOutcome::Delivered);

    // Within 45 min (2700s): cached JWT token must be reused.
    let t1 = t0 + 2_699;
    let tag1 = secret.derive_tag(t1);
    assert_eq!(
        provider.notify(&target, &tag1, t1).await.expect("notify 2"),
        WakeOutcome::Delivered
    );

    // At >= 2700s: JWT must be refreshed with updated `iat`.
    let t2 = t0 + 2_700;
    let tag2 = secret.derive_tag(t2);
    assert_eq!(
        provider.notify(&target, &tag2, t2).await.expect("notify 3"),
        WakeOutcome::Delivered
    );

    let captured = server.captured.lock().await;
    assert_eq!(captured.len(), 3);
    assert_eq!(server.conn_count.load(Ordering::SeqCst), 1);

    let r0 = &captured[0];
    assert_eq!(r0.method, "POST");
    assert_eq!(r0.path, format!("/3/device/{device_hex}"));
    assert_eq!(r0.header("apns-topic"), Some("dev.tendril.ios"));
    assert_eq!(r0.header("apns-push-type"), Some("background"));
    assert_eq!(r0.header("apns-priority"), Some("5"));
    assert_eq!(
        r0.header("apns-collapse-id"),
        Some(tag0.to_b64url().as_str())
    );
    assert_eq!(
        r0.header("apns-expiration"),
        Some(
            (wake_epoch_start_secs(t0) + WAKE_EPOCH_SECS)
                .to_string()
                .as_str()
        )
    );
    assert_eq!(r0.header("content-type"), Some("application/json"));

    let auth0 = r0.header("authorization").expect("auth header 0");
    let jwt0 = auth0
        .strip_prefix("bearer ")
        .expect("lowercase bearer prefix");
    let iat0 = verify_es256_jwt(jwt0, &pub_bytes, "TEAM123456", "KEY9876543");
    assert_eq!(iat0, t0);

    let jwt1 = captured[1]
        .header("authorization")
        .unwrap()
        .strip_prefix("bearer ")
        .unwrap();
    assert_eq!(jwt1, jwt0, "JWT must be cached within 2700s");

    let jwt2 = captured[2]
        .header("authorization")
        .unwrap()
        .strip_prefix("bearer ")
        .unwrap();
    assert_ne!(jwt2, jwt0, "JWT must refresh at 2700s");
    let iat2 = verify_es256_jwt(jwt2, &pub_bytes, "TEAM123456", "KEY9876543");
    assert_eq!(iat2, t2);
}

#[tokio::test]
async fn mutable_alert_payload_headers_and_loc_key_validation() {
    let pki = generate_test_pki();
    let server = MockApnsH2Server::start(&pki, false).await;

    let provider =
        ApnsH2WakeProvider::new(ApnsH2Auth::BearerToken("pre-minted-jwt".to_owned().into()))
            .expect("provider")
            .with_root_certs(pki.root_store.clone())
            .expect("roots")
            .with_topic("dev.tendril.ios")
            .expect("topic")
            .with_cooldown_secs(0);

    let url = format!(
        "https://localhost:{}/3/device/{}",
        server.addr.port(),
        "b".repeat(64)
    );
    let target = WakeTarget::new(WakeAdapterKind::ApnsH2, &url)
        .unwrap()
        .with_apns_mode(ApnsPushMode::MutableAlert)
        .unwrap()
        .with_apns_loc_key("TENDRIL_PEER_READY")
        .unwrap();

    let secret = WakeSecret::from_bytes([0x44; 32]);
    let now = 1_700_005_500;
    let tag = secret.derive_tag(now);

    assert_eq!(
        provider.notify(&target, &tag, now).await.unwrap(),
        WakeOutcome::Delivered
    );

    let captured = server.captured.lock().await;
    assert_eq!(captured.len(), 1);
    let req = &captured[0];
    assert_eq!(req.header("apns-push-type"), Some("alert"));
    assert_eq!(req.header("apns-priority"), Some("10"));
    assert_eq!(req.header("authorization"), Some("bearer pre-minted-jwt"));

    let obj = req.body.as_object().expect("json object");
    assert_eq!(obj.len(), 4);
    assert_eq!(obj["v"], 1);
    assert_eq!(obj["wake_tag"], tag.to_b64url());
    assert_eq!(obj["epoch_s"], wake_epoch_start_secs(now));
    let aps = obj["aps"].as_object().expect("aps object");
    assert_eq!(aps.len(), 2);
    assert_eq!(aps["mutable-content"], 1);
    assert!(aps.get("content-available").is_none());
    let alert = aps["alert"].as_object().expect("alert object");
    assert_eq!(alert.len(), 1);
    assert_eq!(alert["loc-key"], "TENDRIL_PEER_READY");
    assert!(alert.get("loc-args").is_none());
    assert!(alert.get("body").is_none());
    assert!(alert.get("title").is_none());

    // Default loc_key works; invalid / dynamic loc_key inputs fail closed.
    let default_alert =
        ApnsPayload::with_mode(&tag, now, ApnsPushMode::MutableAlert, None).unwrap();
    assert_eq!(
        default_alert.aps.alert.as_ref().unwrap().loc_key,
        DEFAULT_APNS_LOC_KEY
    );
    for bad_key in [
        "",
        "hello world",
        "alert:%@",
        "peer=host_123",
        "line\nbreak",
        &"x".repeat(65),
    ] {
        assert!(
            validate_apns_loc_key(bad_key).is_err(),
            "accepted {bad_key:?}"
        );
        assert!(
            WakeTarget::new(WakeAdapterKind::ApnsH2, &url)
                .unwrap()
                .with_apns_loc_key(bad_key)
                .is_err(),
            "WakeTarget accepted {bad_key:?}"
        );
    }
}

#[tokio::test]
async fn apns_h2_connection_reuse_goaway_reconnect_and_coalescing() {
    let pki = generate_test_pki();
    let server = MockApnsH2Server::start(&pki, false).await;
    {
        let mut beh = server.behavior.lock().await;
        // Close connection 1 with GOAWAY after the 2nd request.
        beh.goaway_after_req_num = Some(2);
    }

    let provider = ApnsH2WakeProvider::new(ApnsH2Auth::BearerToken("tok-reuse".to_owned().into()))
        .unwrap()
        .with_root_certs(pki.root_store.clone())
        .unwrap()
        .with_topic("dev.tendril.ios")
        .unwrap()
        .with_cooldown_secs(5);

    let url = format!(
        "https://127.0.0.1:{}/3/device/{}",
        server.addr.port(),
        "c".repeat(64)
    );
    let target = WakeTarget::new(WakeAdapterKind::ApnsH2, &url).unwrap();
    let secret = WakeSecret::from_bytes([0x55; 32]);
    let t0 = 1_700_010_000;
    let tag = secret.derive_tag(t0);

    // Send 1 -> opens conn #1.
    assert_eq!(
        provider.notify(&target, &tag, t0).await.unwrap(),
        WakeOutcome::Delivered
    );
    // Throttled within 5s window -> Coalesced without touching network.
    assert_eq!(
        provider.notify(&target, &tag, t0 + 2).await.unwrap(),
        WakeOutcome::Coalesced
    );
    assert_eq!(server.req_count.load(Ordering::SeqCst), 1);

    // Send 2 after cooldown -> reuses conn #1 (which then emits GOAWAY).
    assert_eq!(
        provider.notify(&target, &tag, t0 + 5).await.unwrap(),
        WakeOutcome::Delivered
    );
    assert_eq!(server.conn_count.load(Ordering::SeqCst), 1);
    assert_eq!(server.req_count.load(Ordering::SeqCst), 2);

    // Allow GOAWAY frame to arrive and verify Send 3 reconnects cleanly on conn #2.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        provider.notify(&target, &tag, t0 + 10).await.unwrap(),
        WakeOutcome::Delivered
    );
    assert_eq!(server.conn_count.load(Ordering::SeqCst), 2);
    assert_eq!(server.req_count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn http_wake_provider_empty_roots_fails_https_while_valid_roots_succeed_and_default_has_webpki()
 {
    let pki = generate_test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_cfg = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![pki.server_cert_der.clone()],
                pki.server_key_der.clone_key(),
            )
            .unwrap(),
    );
    let acceptor = TlsAcceptor::from(server_cfg);
    let srv_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = tls.flush().await;
            });
        }
    });

    // Default HttpWakeProvider loads Mozilla/WebPKI roots (non-empty).
    let default_provider = HttpWakeProvider::new();
    assert!(
        default_provider.root_cert_count() >= 100
            && default_provider.root_cert_count() == default_wake_root_certs().len(),
        "default HttpWakeProvider must load webpki-roots"
    );

    let target = WakeTarget::new(
        WakeAdapterKind::Webhook,
        &format!("https://127.0.0.1:{}/wake", addr.port()),
    )
    .unwrap();
    let tag = WakeSecret::from_bytes([0x66; 32]).derive_tag(1_700_020_000);

    // Empty root store MUST fail TLS verification.
    let empty_provider = HttpWakeProvider::with_empty_roots().with_cooldown_secs(0);
    assert_eq!(empty_provider.root_cert_count(), 0);
    let err = empty_provider
        .notify(&target, &tag, 1_700_020_000)
        .await
        .expect_err("with_empty_roots must fail HTTPS");
    assert!(matches!(
        err,
        RuntimeError::Protocol(_) | RuntimeError::Io(_)
    ));

    // Untrusted test CA also fails against default WebPKI roots (no verification bypass).
    assert!(
        default_provider
            .notify(&target, &tag, 1_700_020_000)
            .await
            .is_err()
    );

    // Provider configured with the matching test CA succeeds over HTTPS.
    let trusted_provider = HttpWakeProvider::new()
        .with_root_certs(pki.root_store)
        .with_cooldown_secs(0);
    assert_eq!(
        trusted_provider
            .notify(&target, &tag, 1_700_020_000)
            .await
            .expect("trusted CA must succeed"),
        WakeOutcome::Delivered
    );

    srv_task.abort();
}

#[tokio::test]
async fn apns_h2_mtls_and_non_2xx_error_redaction() {
    let pki = generate_test_pki();
    let server = MockApnsH2Server::start(&pki, true).await;
    {
        let mut beh = server.behavior.lock().await;
        beh.status = StatusCode::BAD_REQUEST;
        beh.response_body = Bytes::from_static(br#"{"reason":"BadDeviceToken"}"#);
    }

    let secret_token = "super-secret-jwt-should-never-appear";
    let (p8_pem, _) = generate_p256_pkcs8_pem_and_pub();

    let mut spec = WakeConfigSpec::default();
    spec.wake_url = Some(format!(
        "https://127.0.0.1:{}/3/device/{}",
        server.addr.port(),
        "d".repeat(64)
    ));
    spec.wake_adapter = Some(WakeAdapterKind::ApnsH2);
    spec.wake_secret_b64 = Some(b64url_encode(&[0x77; 32]));
    spec.wake_apns_topic = Some("dev.tendril.ios".to_owned());
    spec.wake_apns_client_cert_pem = Some(pki.client_cert_pem.clone());
    spec.wake_apns_client_key_pem = Some(pki.client_key_pem.clone());
    let settings = build_wake_provider_with_root_certs(spec, Some(pki.root_store.clone()))
        .expect("build mtls wake provider")
        .expect("some settings");

    let tag = settings.secret.derive_tag(1_700_030_000);
    let err = settings
        .provider
        .notify(&settings.target, &tag, 1_700_030_000)
        .await
        .expect_err("400 BadDeviceToken must map to Err");
    let msg = err.to_string();
    assert!(msg.contains("400"), "unexpected error: {msg}");
    assert!(msg.contains("BadDeviceToken"), "unexpected error: {msg}");

    // Ensure BearerToken error body reflection never leaks the bearer token or PEM.
    let server2 = MockApnsH2Server::start(&pki, false).await;
    {
        let mut beh = server2.behavior.lock().await;
        beh.status = StatusCode::FORBIDDEN;
        beh.response_body = Bytes::from(format!(
            "echo token={secret_token} url=https://user:pw@evil.example/p?q=1"
        ));
    }
    let bearer_provider =
        ApnsH2WakeProvider::new(ApnsH2Auth::BearerToken(secret_token.to_owned().into()))
            .unwrap()
            .with_root_certs(pki.root_store.clone())
            .unwrap()
            .with_topic("dev.tendril.ios")
            .unwrap();
    let target2 = WakeTarget::new(
        WakeAdapterKind::ApnsH2,
        &format!(
            "https://127.0.0.1:{}/3/device/{}",
            server2.addr.port(),
            "e".repeat(64)
        ),
    )
    .unwrap();
    let err2 = bearer_provider
        .notify(&target2, &tag, 1_700_030_000)
        .await
        .expect_err("403 must map to Err")
        .to_string();
    assert!(err2.contains("403"), "{err2}");
    assert!(!err2.contains(secret_token), "bearer token leaked: {err2}");
    assert!(!err2.contains("pw"), "url credentials leaked: {err2}");
    assert!(!p8_pem.is_empty());
}

#[test]
fn apns_h2_ssrf_apple_paths_and_config_mutual_exclusions_fail_closed() {
    let (p8_pem, _) = generate_p256_pkcs8_pem_and_pub();
    let valid_hex = "0123456789abcdef".repeat(4);

    // SSRF, cleartext http://, and non-/3/device/<hex> path rejections on apns_h2
    for bad_url in [
        "http://127.0.0.1:8443/3/device/0123456789abcdef",
        "http://localhost:8443/3/device/0123456789abcdef",
        "https://169.254.169.254/latest/meta-data",
        "https://metadata.google.internal/computeMetadata",
        "https://[fe80::1]/3/device/abc",
        "https://127.0.0.1:8443/3/device/has space",
        "https://127.0.0.1:8443/3/device/has\nctl",
        "https://127.0.0.1:8443/wrong/path",
        "https://127.0.0.1:8443/3/device/short",
        "https://api.push.apple.com/3/device/tooshort",
        "https://api.sandbox.push.apple.com/3/device/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "https://api.push.apple.com/wrong/path",
        &format!("https://api.push.apple.com/3/device/{}", "a".repeat(201)),
        &format!(
            "https://example.com/{}",
            "a".repeat(MAX_WAKE_ENDPOINT_URL_LEN)
        ),
    ] {
        assert!(
            WakeTarget::new(WakeAdapterKind::ApnsH2, bad_url).is_err(),
            "expected ApnsH2 URL rejection for {bad_url:?}"
        );
    }

    assert!(
        WakeTarget::new(
            WakeAdapterKind::ApnsH2,
            &format!("https://api.push.apple.com/3/device/{valid_hex}")
        )
        .is_ok()
    );
    assert!(
        WakeTarget::new(
            WakeAdapterKind::ApnsH2,
            &format!("https://api.sandbox.push.apple.com/3/device/{valid_hex}")
        )
        .is_ok()
    );

    // WakeTarget Debug redacts device token path and query string.
    let apns_target_dbg = format!(
        "{:?}",
        WakeTarget::new(
            WakeAdapterKind::ApnsH2,
            &format!("https://api.push.apple.com/3/device/{valid_hex}")
        )
        .unwrap()
    );
    assert!(apns_target_dbg.contains("https://api.push.apple.com"));
    assert!(!apns_target_dbg.contains(&valid_hex));

    let base_apns_h2 = || {
        let mut s = WakeConfigSpec::default();
        s.wake_url = Some(format!("https://api.push.apple.com/3/device/{valid_hex}"));
        s.wake_adapter = Some(WakeAdapterKind::ApnsH2);
        s.wake_secret_b64 = Some(b64url_encode(&[0x11; 32]));
        s.wake_apns_topic = Some("dev.tendril.ios".to_owned());
        s
    };

    // Arbitrary public hosts, private RFC1918/ULA IPs, and non-443 Apple ports fail closed by default.
    for blocked_url in [
        format!("https://evil.example/3/device/{valid_hex}"),
        format!("https://10.0.0.1/3/device/{valid_hex}"),
        format!("https://172.16.0.1/3/device/{valid_hex}"),
        format!("https://192.168.1.10/3/device/{valid_hex}"),
        format!("https://[fc00::1]/3/device/{valid_hex}"),
        format!("https://[fd12:3456::1]/3/device/{valid_hex}"),
        format!("https://api.push.apple.com:8443/3/device/{valid_hex}"),
    ] {
        let mut blocked_spec = base_apns_h2();
        blocked_spec.wake_url = Some(blocked_url.clone());
        blocked_spec.wake_auth_token = Some("tok".to_owned());
        assert!(
            build_wake_provider(blocked_spec).is_err(),
            "expected build_wake_provider rejection for {blocked_url}"
        );
    }

    // Oversized inline PEM (> 16 KiB) fails closed.
    let mut big_p8_spec = base_apns_h2();
    big_p8_spec.wake_apns_team_id = Some("TEAM123".to_owned());
    big_p8_spec.wake_apns_key_id = Some("KEY123".to_owned());
    big_p8_spec.wake_apns_p8_pem = Some("A".repeat(MAX_WAKE_PEM_BYTES + 1));
    assert!(build_wake_provider(big_p8_spec).is_err());

    let mut big_cert_spec = base_apns_h2();
    big_cert_spec.wake_apns_client_cert_pem = Some("C".repeat(MAX_WAKE_PEM_BYTES + 1));
    big_cert_spec.wake_apns_client_key_pem = Some("K".to_owned());
    assert!(build_wake_provider(big_cert_spec).is_err());

    // Missing auth on apns_h2
    assert!(build_wake_provider(base_apns_h2()).is_err());

    // Missing team_id or key_id with p8_pem
    let mut missing_team = base_apns_h2();
    missing_team.wake_apns_p8_pem = Some(p8_pem.clone());
    missing_team.wake_apns_key_id = Some("KEY123".to_owned());
    assert!(build_wake_provider(missing_team).is_err());

    // Mutual exclusion: p8_pem + wake_auth_token
    let mut p8_and_tok = base_apns_h2();
    p8_and_tok.wake_apns_p8_pem = Some(p8_pem.clone());
    p8_and_tok.wake_apns_team_id = Some("TEAM123".to_owned());
    p8_and_tok.wake_apns_key_id = Some("KEY123".to_owned());
    p8_and_tok.wake_auth_token = Some("tok".to_owned());
    assert!(build_wake_provider(p8_and_tok).is_err());

    // Mutual exclusion: p8_pem + mTLS cert
    let pki = generate_test_pki();
    let mut p8_and_mtls = base_apns_h2();
    p8_and_mtls.wake_apns_p8_pem = Some(p8_pem.clone());
    p8_and_mtls.wake_apns_team_id = Some("TEAM123".to_owned());
    p8_and_mtls.wake_apns_key_id = Some("KEY123".to_owned());
    p8_and_mtls.wake_apns_client_cert_pem = Some(pki.client_cert_pem.clone());
    p8_and_mtls.wake_apns_client_key_pem = Some(pki.client_key_pem.clone());
    assert!(build_wake_provider(p8_and_mtls).is_err());

    // Missing apns_topic on apns_h2
    let mut missing_topic = base_apns_h2();
    missing_topic.wake_apns_topic = None;
    missing_topic.wake_auth_token = Some("tok".to_owned());
    assert!(build_wake_provider(missing_topic).is_err());

    // Reject apns_* on non-APNs adapter
    let mut webhook_with_apns = WakeConfigSpec::default();
    webhook_with_apns.wake_url = Some("https://hook.example/wake".to_owned());
    webhook_with_apns.wake_adapter = Some(WakeAdapterKind::Webhook);
    webhook_with_apns.wake_secret_b64 = Some(b64url_encode(&[0x11; 32]));
    webhook_with_apns.wake_apns_mode = Some(ApnsPushMode::MutableAlert);
    assert!(build_wake_provider(webhook_with_apns).is_err());

    // Debug redaction on WakeConfigSpec
    let mut debug_spec = base_apns_h2();
    debug_spec.wake_apns_p8_pem = Some(p8_pem);
    debug_spec.wake_apns_team_id = Some("TEAM123".to_owned());
    debug_spec.wake_apns_key_id = Some("KEY123".to_owned());
    let dbg = format!("{debug_spec:?}");
    assert!(dbg.contains("REDACTED"));
    assert!(!dbg.contains("PRIVATE KEY"));

    // Valid MutableAlert on HTTP/1.1 Apns adapter builds cleanly
    let mut apns_http1 = WakeConfigSpec::default();
    apns_http1.wake_url = Some("https://gateway.example/push".to_owned());
    apns_http1.wake_adapter = Some(WakeAdapterKind::Apns);
    apns_http1.wake_secret_b64 = Some(b64url_encode(&[0x22; 32]));
    apns_http1.wake_apns_mode = Some(ApnsPushMode::MutableAlert);
    apns_http1.wake_apns_loc_key = Some("WAKE_KEY".to_owned());
    assert!(build_wake_provider(apns_http1).unwrap().is_some());
}

#[tokio::test]
async fn apns_h2_rejects_arbitrary_hosts_without_opt_in_target_token_conflict_and_missing_alpn() {
    let pki = generate_test_pki();
    let valid_hex = "f".repeat(64);
    let tag = WakeSecret::from_bytes([0x99; 32]).derive_tag(1_700_040_000);

    // Default ApnsH2WakeProvider rejects arbitrary non-Apple hosts and private IPs.
    let provider = ApnsH2WakeProvider::new(ApnsH2Auth::BearerToken("tok".to_owned().into()))
        .unwrap()
        .with_root_certs(pki.root_store.clone())
        .unwrap()
        .with_topic("dev.tendril.ios")
        .unwrap();

    for bad_host_url in [
        format!("https://evil.example/3/device/{valid_hex}"),
        format!("https://10.0.0.1/3/device/{valid_hex}"),
        format!("https://[fd00::1]/3/device/{valid_hex}"),
        format!("https://api.push.apple.com:8443/3/device/{valid_hex}"),
    ] {
        let target = WakeTarget::new(WakeAdapterKind::ApnsH2, &bad_host_url).unwrap();
        let err = provider
            .notify(&target, &tag, 1_700_040_000)
            .await
            .expect_err("non-Apple / private host must be rejected by default");
        assert!(matches!(err, RuntimeError::Protocol(_)));
    }

    // Opting into allow_custom_host passes host check (fails only on unreachable DNS/connect).
    let custom_provider = ApnsH2WakeProvider::new(ApnsH2Auth::BearerToken("tok".to_owned().into()))
        .unwrap()
        .with_topic("dev.tendril.ios")
        .unwrap()
        .with_allow_custom_host(true)
        .with_timeout(Duration::from_millis(200));
    let evil_target = WakeTarget::new(
        WakeAdapterKind::ApnsH2,
        &format!("https://invalid.test/3/device/{valid_hex}"),
    )
    .unwrap();
    let custom_err = custom_provider
        .notify(&evil_target, &tag, 1_700_040_000)
        .await
        .expect_err("unreachable .invalid fails at DNS/connect, not host policy");
    assert!(!custom_err.to_string().contains("*.push.apple.com"));

    // BearerToken provider rejects conflicting WakeTarget::auth_token; build_wake_provider leaves target token empty.
    let server = MockApnsH2Server::start(&pki, false).await;
    let url = format!(
        "https://127.0.0.1:{}/3/device/{valid_hex}",
        server.addr.port()
    );
    let conflict_target = WakeTarget::new(WakeAdapterKind::ApnsH2, &url)
        .unwrap()
        .with_auth_token("conflicting-token")
        .unwrap();
    assert!(
        provider
            .notify(&conflict_target, &tag, 1_700_040_000)
            .await
            .is_err()
    );

    let mut bearer_spec = WakeConfigSpec::default();
    bearer_spec.wake_url = Some(url.clone());
    bearer_spec.wake_adapter = Some(WakeAdapterKind::ApnsH2);
    bearer_spec.wake_secret_b64 = Some(b64url_encode(&[0xaa; 32]));
    bearer_spec.wake_auth_token = Some("spec-bearer-jwt".to_owned());
    bearer_spec.wake_apns_topic = Some("dev.tendril.ios".to_owned());
    let settings = build_wake_provider_with_root_certs(bearer_spec, Some(pki.root_store.clone()))
        .unwrap()
        .unwrap();
    assert!(settings.target.auth_token().is_none());
    assert_eq!(
        settings
            .provider
            .notify(&settings.target, &tag, 1_700_040_000)
            .await
            .unwrap(),
        WakeOutcome::Delivered
    );
    let captured = server.captured.lock().await;
    assert_eq!(
        captured[0].header("authorization"),
        Some("bearer spec-bearer-jwt")
    );

    // Server without ALPN h2 must fail closed.
    let no_alpn_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let no_alpn_addr = no_alpn_listener.local_addr().unwrap();
    let no_alpn_cfg = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![pki.server_cert_der.clone()],
                pki.server_key_der.clone_key(),
            )
            .unwrap(),
    );
    let no_alpn_acceptor = TlsAcceptor::from(no_alpn_cfg);
    let no_alpn_task = tokio::spawn(async move {
        if let Ok((tcp, _)) = no_alpn_listener.accept().await {
            let _ = no_alpn_acceptor.accept(tcp).await;
        }
    });
    let no_alpn_target = WakeTarget::new(
        WakeAdapterKind::ApnsH2,
        &format!(
            "https://127.0.0.1:{}/3/device/{valid_hex}",
            no_alpn_addr.port()
        ),
    )
    .unwrap();
    let alpn_err = provider
        .notify(&no_alpn_target, &tag, 1_700_040_000)
        .await
        .expect_err("missing h2 ALPN must fail closed");
    assert!(alpn_err.to_string().contains("ALPN"), "{alpn_err}");
    no_alpn_task.abort();
}

#[tokio::test]
async fn wake_coalescer_debug_redacts_targets_and_tokens() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pki = generate_test_pki();
    let apns_server = MockApnsH2Server::start(&pki, false).await;

    let hook_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = hook_listener.local_addr().unwrap();
    let hook_task = tokio::spawn(async move {
        if let Ok((mut tcp, _)) = hook_listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = tcp.read(&mut buf).await;
            let _ = tcp
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = tcp.flush().await;
        }
    });

    let hook_path = "/hooks/private-room-42";
    let hook_secret = "SECRET_WEBHOOK_QUERY_TOKEN_98765";
    let hook_url = format!(
        "http://127.0.0.1:{}{hook_path}?token={hook_secret}",
        hook_addr.port()
    );
    let hook_target = WakeTarget::new(WakeAdapterKind::Webhook, &hook_url)
        .unwrap()
        .with_auth_token("WEBHOOK_AUTH_BEARER_SECRET")
        .unwrap();

    let http_provider = HttpWakeProvider::new().with_cooldown_secs(60);
    let tag = WakeSecret::from_bytes([0xab; 32]).derive_tag(1_700_050_000);
    assert_eq!(
        http_provider
            .notify(&hook_target, &tag, 1_700_050_000)
            .await
            .unwrap(),
        WakeOutcome::Delivered
    );
    assert_eq!(
        http_provider
            .notify(&hook_target, &tag, 1_700_050_005)
            .await
            .unwrap(),
        WakeOutcome::Coalesced
    );

    let device_token = "0123456789abcdef".repeat(4);
    let apns_url = format!(
        "https://127.0.0.1:{}/3/device/{device_token}",
        apns_server.addr.port()
    );
    let apns_target = WakeTarget::new(WakeAdapterKind::ApnsH2, &apns_url).unwrap();
    let apns_bearer = "APNS_BEARER_SECRET_XYZ";
    let apns_provider =
        ApnsH2WakeProvider::new(ApnsH2Auth::BearerToken(apns_bearer.to_owned().into()))
            .unwrap()
            .with_root_certs(pki.root_store)
            .unwrap()
            .with_topic("dev.tendril.ios")
            .unwrap()
            .with_cooldown_secs(60);
    assert_eq!(
        apns_provider
            .notify(&apns_target, &tag, 1_700_050_000)
            .await
            .unwrap(),
        WakeOutcome::Delivered
    );
    assert_eq!(
        apns_provider
            .notify(&apns_target, &tag, 1_700_050_005)
            .await
            .unwrap(),
        WakeOutcome::Coalesced
    );

    let http_dbg = format!("{http_provider:?}");
    assert!(http_dbg.contains("entry_count: 1"), "{http_dbg}");
    assert!(!http_dbg.contains(hook_path), "{http_dbg}");
    assert!(!http_dbg.contains(hook_secret), "{http_dbg}");
    assert!(!http_dbg.contains("127.0.0.1"), "{http_dbg}");

    let apns_dbg = format!("{apns_provider:?}");
    assert!(apns_dbg.contains("entry_count: 1"), "{apns_dbg}");
    assert!(!apns_dbg.contains(&device_token), "{apns_dbg}");
    assert!(!apns_dbg.contains("/3/device"), "{apns_dbg}");
    assert!(!apns_dbg.contains(apns_bearer), "{apns_dbg}");
    assert!(!apns_dbg.contains("127.0.0.1"), "{apns_dbg}");

    hook_task.abort();
}

#[tokio::test]
async fn apns_h2_pooled_conn_drop_aborts_task_and_closes_peer() {
    let pki = generate_test_pki();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![pki.server_cert_der.clone()],
            pki.server_key_der.clone_key(),
        )
        .unwrap();
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conn_closed = Arc::new(Notify::new());
    let conn_closed_srv = Arc::clone(&conn_closed);
    let stream_opened = Arc::new(Notify::new());
    let stream_opened_srv = Arc::clone(&stream_opened);

    // Server sends response headers with end_of_stream = false so an active H2 stream remains
    // open until the client tears down the underlying connection task.
    let srv_task = tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(tls) = acceptor.accept(tcp).await else {
            return;
        };
        let Ok(mut h2_conn) = h2::server::handshake(tls).await else {
            return;
        };
        let mut _held_stream = None;
        while let Some(res) = h2_conn.accept().await {
            match res {
                Ok((_req, mut respond)) => {
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    if let Ok(send_stream) = respond.send_response(resp, false) {
                        _held_stream = Some(send_stream);
                        stream_opened_srv.notify_one();
                    }
                }
                Err(_) => break,
            }
        }
        conn_closed_srv.notify_one();
    });

    let provider = ApnsH2WakeProvider::new(ApnsH2Auth::BearerToken("tok-abort".to_owned().into()))
        .unwrap()
        .with_root_certs(pki.root_store.clone())
        .unwrap()
        .with_topic("dev.tendril.ios")
        .unwrap()
        .with_cooldown_secs(0)
        .with_timeout(Duration::from_secs(1));

    let url = format!(
        "https://127.0.0.1:{}/3/device/{}",
        addr.port(),
        "e".repeat(64)
    );
    let target = WakeTarget::new(WakeAdapterKind::ApnsH2, &url).unwrap();
    let tag = WakeSecret::from_bytes([0xcd; 32]).derive_tag(1_700_060_000);

    let opened_fut = stream_opened.notified();
    tokio::pin!(opened_fut);
    let err = provider
        .notify(&target, &tag, 1_700_060_000)
        .await
        .expect_err("open stream without END_STREAM must time out");
    assert!(matches!(err, RuntimeError::Timeout(_)), "{err}");
    tokio::time::timeout(Duration::from_secs(2), opened_fut)
        .await
        .expect("mock H2 server must observe opened stream before timeout");

    let closed_fut = conn_closed.notified();
    tokio::pin!(closed_fut);
    // Clearing pooled connections via with_root_certs drops PooledH2Conn, aborting conn_task
    // and closing the socket so the peer sees EOF promptly.
    let _provider = provider.with_root_certs(pki.root_store).unwrap();
    tokio::time::timeout(Duration::from_secs(2), closed_fut)
        .await
        .expect("server must observe connection EOF promptly when PooledH2Conn drops");

    srv_task.abort();
}
