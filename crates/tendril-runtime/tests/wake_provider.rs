use std::time::Duration;

use serde_json::Value;
use tendril_runtime::{
    HttpWakeProvider, MAX_WAKE_ENDPOINT_URL_LEN, MemoryWakeProvider, NoopWakeProvider,
    WAKE_EPOCH_SECS, WakeAdapterKind, WakeOutcome, WakeProvider, WakeSecret, WakeTag, WakeTarget,
    derive_epoch_wake_tag, validate_wake_endpoint_url, verify_epoch_wake_tag_window, wake_epoch,
    wake_epoch_start_secs,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn read_one_http_request(listener: &TcpListener) -> (String, Value) {
    loop {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let mut header_end = None;
        loop {
            let n = stream.read(&mut tmp).await.expect("read");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(pos + 4);
                break;
            }
        }
        let Some(header_end) = header_end else {
            continue;
        };
        let headers_str = std::str::from_utf8(&buf[..header_end])
            .expect("utf8 headers")
            .to_owned();
        if !headers_str.starts_with("POST ") {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            continue;
        }
        let content_len = headers_str
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .expect("content-length header");
        while buf.len() < header_end + content_len {
            let n = stream.read(&mut tmp).await.expect("read body");
            assert!(n > 0, "unexpected EOF before body");
            buf.extend_from_slice(&tmp[..n]);
        }
        let body_json: Value =
            serde_json::from_slice(&buf[header_end..header_end + content_len]).expect("valid json");

        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .expect("write response");
        stream.flush().await.expect("flush");
        return (headers_str, body_json);
    }
}

#[tokio::test]
async fn noop_wake_provider_is_pull_only_baseline() {
    let provider = NoopWakeProvider;
    let target =
        WakeTarget::new(WakeAdapterKind::UnifiedPush, "https://push.example/up/abc").unwrap();
    let secret = WakeSecret::from_bytes([0x11; 32]);
    let tag = secret.derive_tag(1_700_000_000);

    let outcome = provider.notify(&target, &tag, 1_700_000_000).await.unwrap();
    assert_eq!(outcome, WakeOutcome::Noop);
}

#[test]
fn epoch_wake_tag_is_deterministic_and_unlinkable_across_epochs_and_secrets() {
    let secret_a = [0x42; 32];
    let secret_b = [0x43; 32];
    let t0 = 1_700_002_800; // aligned epoch boundary? check via wake_epoch
    let e0 = wake_epoch(t0);
    let same_epoch = e0 * WAKE_EPOCH_SECS + WAKE_EPOCH_SECS - 1;
    let next_epoch = (e0 + 1) * WAKE_EPOCH_SECS;

    let tag_a1 = derive_epoch_wake_tag(&secret_a, e0 * WAKE_EPOCH_SECS);
    let tag_a2 = derive_epoch_wake_tag(&secret_a, same_epoch);
    let tag_next = derive_epoch_wake_tag(&secret_a, next_epoch);
    let tag_b = derive_epoch_wake_tag(&secret_b, e0 * WAKE_EPOCH_SECS);

    assert_eq!(tag_a1, tag_a2);
    assert_ne!(tag_a1, tag_next);
    assert_ne!(tag_a1, tag_b);

    let encoded = tag_a1.to_b64url();
    let decoded = WakeTag::from_b64url(&encoded).unwrap();
    assert_eq!(decoded, tag_a1);

    let center_secs = e0 * WAKE_EPOCH_SECS;
    let prev_tag = derive_epoch_wake_tag(&secret_a, center_secs - WAKE_EPOCH_SECS);
    let two_hours_later = derive_epoch_wake_tag(&secret_a, center_secs + 2 * WAKE_EPOCH_SECS);
    assert!(verify_epoch_wake_tag_window(
        &secret_a,
        &prev_tag,
        center_secs
    ));
    assert!(verify_epoch_wake_tag_window(
        &secret_a,
        &tag_a1,
        center_secs
    ));
    assert!(verify_epoch_wake_tag_window(
        &secret_a,
        &tag_next,
        center_secs
    ));
    assert!(!verify_epoch_wake_tag_window(
        &secret_a,
        &two_hours_later,
        center_secs
    ));
    assert!(!verify_epoch_wake_tag_window(
        &secret_b,
        &tag_a1,
        center_secs
    ));
}

#[tokio::test]
async fn memory_wake_provider_records_and_coalesces() {
    let provider = MemoryWakeProvider::with_cooldown_secs(5);
    let target = WakeTarget::new(WakeAdapterKind::Webhook, "https://hook.example/wake").unwrap();
    let secret = WakeSecret::generate().unwrap();
    let now = 1_700_005_000;
    let tag = secret.derive_tag(now);

    assert_eq!(
        provider.notify(&target, &tag, now).await.unwrap(),
        WakeOutcome::Delivered
    );
    assert_eq!(
        provider.notify(&target, &tag, now + 4).await.unwrap(),
        WakeOutcome::Coalesced
    );
    assert_eq!(
        provider.notify(&target, &tag, now + 5).await.unwrap(),
        WakeOutcome::Delivered
    );

    let recorded = provider.recorded();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].tag, tag);
    assert_eq!(recorded[0].epoch_s, wake_epoch_start_secs(now));
}

#[tokio::test]
async fn http_wake_provider_delivers_all_adapter_envelopes_and_coalesces() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provider = HttpWakeProvider::new().with_cooldown_secs(5);
    let secret = WakeSecret::from_bytes([0x5a; 32]);
    let now = 1_700_010_123;
    let tag = secret.derive_tag(now);
    let expected_epoch_s = wake_epoch_start_secs(now);

    let server = tokio::spawn(async move {
        let mut captured = Vec::new();
        for _ in 0..4 {
            captured.push(read_one_http_request(&listener).await);
        }
        captured
    });

    // 1. UnifiedPush + coalescing check
    let up_target = WakeTarget::new(
        WakeAdapterKind::UnifiedPush,
        &format!("http://{addr}/up/token123"),
    )
    .unwrap();
    assert_eq!(
        provider.notify(&up_target, &tag, now).await.unwrap(),
        WakeOutcome::Delivered
    );
    assert_eq!(
        provider.notify(&up_target, &tag, now + 2).await.unwrap(),
        WakeOutcome::Coalesced
    );

    // 2. Webhook with bearer token
    let wh_target = WakeTarget::new(WakeAdapterKind::Webhook, &format!("http://{addr}/webhook"))
        .unwrap()
        .with_auth_token("super-secret-bearer-token")
        .unwrap();
    assert_eq!(
        provider.notify(&wh_target, &tag, now).await.unwrap(),
        WakeOutcome::Delivered
    );

    // 3. APNs silent background push
    let apns_target = WakeTarget::new(
        WakeAdapterKind::Apns,
        &format!("http://{addr}/3/device/opaque"),
    )
    .unwrap()
    .with_auth_token("apns-jwt-secret")
    .unwrap();
    assert_eq!(
        provider.notify(&apns_target, &tag, now).await.unwrap(),
        WakeOutcome::Delivered
    );

    // 4. FCM high-priority data-only push
    let fcm_target = WakeTarget::new(
        WakeAdapterKind::Fcm,
        &format!("http://{addr}/v1/projects/p/messages:send"),
    )
    .unwrap()
    .with_auth_token("fcm-oauth-secret")
    .unwrap();
    assert_eq!(
        provider.notify(&fcm_target, &tag, now).await.unwrap(),
        WakeOutcome::Delivered
    );

    let captured = server.await.unwrap();
    assert_eq!(captured.len(), 4);

    // Verify UnifiedPush
    let (up_hdrs, up_body) = &captured[0];
    assert!(up_hdrs.starts_with("POST /up/token123 HTTP/1.1\r\n"));
    let up_obj = up_body.as_object().unwrap();
    assert_eq!(up_obj.len(), 3);
    assert_eq!(up_obj["v"], 1);
    assert_eq!(up_obj["wake_tag"], tag.to_b64url());
    assert_eq!(up_obj["epoch_s"], expected_epoch_s);

    // Verify Webhook
    let (wh_hdrs, wh_body) = &captured[1];
    assert!(wh_hdrs.contains("Authorization: Bearer super-secret-bearer-token\r\n"));
    assert_eq!(wh_body["wake_tag"], tag.to_b64url());

    // Verify APNs
    let (apns_hdrs, apns_body) = &captured[2];
    assert!(apns_hdrs.contains("apns-push-type: background\r\n"));
    assert!(apns_hdrs.contains("apns-priority: 5\r\n"));
    assert!(apns_hdrs.contains("Authorization: Bearer apns-jwt-secret\r\n"));
    let apns_obj = apns_body.as_object().unwrap();
    assert_eq!(apns_obj.len(), 4);
    assert_eq!(apns_obj["aps"]["content-available"], 1);
    assert!(apns_obj["aps"].get("alert").is_none());
    assert_eq!(apns_obj["v"], 1);
    assert_eq!(apns_obj["wake_tag"], tag.to_b64url());
    assert_eq!(apns_obj["epoch_s"], expected_epoch_s);

    // Verify FCM
    let (fcm_hdrs, fcm_body) = &captured[3];
    assert!(fcm_hdrs.contains("Authorization: Bearer fcm-oauth-secret\r\n"));
    let msg = fcm_body["message"].as_object().unwrap();
    assert!(msg.get("notification").is_none());
    assert_eq!(msg["android"]["priority"], "high");
    assert_eq!(msg["data"]["v"], "1");
    assert_eq!(msg["data"]["wake_tag"], tag.to_b64url());
    assert_eq!(msg["data"]["epoch_s"], expected_epoch_s.to_string());
}

#[test]
fn ssrf_url_validation_and_debug_redaction_fail_closed() {
    // Non-loopback cleartext HTTP rejected
    assert!(validate_wake_endpoint_url("http://example.com/wake").is_err());
    assert!(validate_wake_endpoint_url("ftp://example.com/wake").is_err());

    // Metadata and link-local addresses rejected
    assert!(validate_wake_endpoint_url("https://169.254.169.254/latest/meta-data").is_err());
    assert!(
        validate_wake_endpoint_url("https://metadata.google.internal/computeMetadata").is_err()
    );
    assert!(validate_wake_endpoint_url("https://[fe80::1]/wake").is_err());

    // Credentials and fragments rejected
    assert!(validate_wake_endpoint_url("https://user:pass@example.com/wake").is_err());
    assert!(validate_wake_endpoint_url("https://example.com/wake#frag").is_err());

    // Oversized URL rejected
    let long_path = "a".repeat(MAX_WAKE_ENDPOINT_URL_LEN);
    assert!(validate_wake_endpoint_url(&format!("https://example.com/{long_path}")).is_err());

    // Loopback HTTP allowed
    assert!(validate_wake_endpoint_url("http://127.0.0.1:8080/wake").is_ok());
    assert!(validate_wake_endpoint_url("http://[::1]:8080/wake").is_ok());
    assert!(validate_wake_endpoint_url("http://localhost:8080/wake").is_ok());

    // Debug output never leaks secrets
    let secret = WakeSecret::from_bytes([0x99; 32]);
    let secret_dbg = format!("{secret:?}");
    assert!(!secret_dbg.contains("99"));
    assert!(secret_dbg.contains("REDACTED"));

    let target = WakeTarget::new(WakeAdapterKind::Webhook, "https://push.example/wake")
        .unwrap()
        .with_auth_token("tok-do-not-leak")
        .unwrap();
    let target_dbg = format!("{target:?}");
    assert!(!target_dbg.contains("tok-do-not-leak"));
    assert!(target_dbg.contains("REDACTED"));
}

#[tokio::test]
async fn notify_best_effort_skips_stalling_or_error_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Accept and hold open without replying to trigger timeout
    let _stall = tokio::spawn(async move {
        let (_sock, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let provider = HttpWakeProvider::new().with_timeout(Duration::from_millis(100));
    let target =
        WakeTarget::new(WakeAdapterKind::Webhook, &format!("http://{addr}/stall")).unwrap();
    let tag = WakeSecret::from_bytes([0x07; 32]).derive_tag(1_700_000_000);

    let outcome = provider
        .notify_best_effort(&target, &tag, 1_700_000_000)
        .await;
    assert_eq!(outcome, WakeOutcome::Skipped);
}
