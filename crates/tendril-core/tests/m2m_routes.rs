//! Host-signed routes in the M2M enrolment reply (`spec/pairing-v1.md` Section 7.5): the claim
//! request, the responder rules, the initiator check order, and that no route set outcome can
//! fail an enrolment whose token is already burned.

use serde_json::{Value, json};
use tendril_core::crypto::{
    HYBRID_SIG_LEN, SigningKeypair, StaticKeypair, b64url_encode, compute_code_mac,
};
use tendril_core::error::CoreError;
use tendril_core::grants::Grant;
use tendril_core::identity::EndpointIdentity;
use tendril_core::noise::NoiseHfsHandshakeBuilder;
use tendril_core::pairing::{
    EnrollmentPolicy, EnrollmentRouteReject, EnrollmentRoutes, MAX_ENROLLMENT_ROUTE_SET_B64_LEN,
    PairAction, PairOutcome, PairingCodeKind, PairingConfig, PairingInitiator, PairingManager,
    PairingPathKind, PairingResponder, PinnedHost, mint_enrollment_token, sign_enroll_proof,
    verify_enrollment_route_set,
};
use tendril_core::roster::Roster;
use tendril_core::routes::{MAX_ROUTE_SET_PAYLOAD, ROUTE_SET_DOMAIN, RouteSet};
use tendril_core::wire::{
    HostHello, Intent, MAX_TRANSPORT_PLAINTEXT, PairClaim, PairResponse, Preamble, RouteSetField,
    decode_frame, encode_frame,
};

const NOW: u64 = 1_795_564_800;

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seeds([tag.wrapping_add(1); 32], [tag.wrapping_add(2); 32]),
    )
}

fn pin(host: &EndpointIdentity) -> PinnedHost {
    PinnedHost::with_hash(
        Some(host.host_id().to_owned()),
        *host.static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        0,
    )
}

fn token(host: &EndpointIdentity, peer: &EndpointIdentity, nonce: u8) -> Grant {
    mint_enrollment_token(
        host,
        host.host_id(),
        Some(&peer.device_id()),
        NOW,
        900,
        [nonce; 16],
    )
    .unwrap()
}

fn writes(actions: &[PairAction]) -> Vec<u8> {
    actions
        .iter()
        .filter_map(|a| match a {
            PairAction::WriteBytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

fn completed(actions: &[PairAction]) -> &PairOutcome {
    actions
        .iter()
        .find_map(|a| match a {
            PairAction::Completed(o) => Some(o),
            _ => None,
        })
        .expect("completed")
}

fn routes() -> Vec<String> {
    vec![
        "direct:192.168.1.20:9100".into(),
        "wss://relay.example.com/v1/relay".into(),
    ]
}

fn encoded(set: &RouteSet) -> Value {
    Value::String(b64url_encode(&set.encode()))
}

/// A route set body naming `host` with a genuine hybrid signature by `signer`.
fn signed_by(host: &EndpointIdentity, signer: &EndpointIdentity) -> Vec<u8> {
    let honest = RouteSet::sign_deterministic(host, 3, NOW, routes())
        .unwrap()
        .encode();
    let body = &honest[..honest.len() - HYBRID_SIG_LEN];
    let mut signed = ROUTE_SET_DOMAIN.to_vec();
    signed.extend_from_slice(body);
    let sig = signer.signing_key().sign_deterministic(&signed).unwrap();
    [body, &sig].concat()
}

/// An M2M initiator enrolling with a scripted host that answers `msg3` with a `PairResponse`
/// carrying `route_set` (omitted when `None`). `chain` is presented in `HostHello.rotation`.
fn enrol_with_reply(
    host: &EndpointIdentity,
    pinned: PinnedHost,
    request: Option<u64>,
    route_set: Option<Value>,
) -> (PairingInitiator, Vec<PairAction>, PairClaim) {
    let peer = identity(0x31);
    let mut init = PairingInitiator::new_m2m(
        &peer,
        "runner",
        "machine",
        token(host, &peer, 0x01),
        pinned,
        None,
    )
    .unwrap();
    if let Some(seq) = request {
        init = init.with_enrollment_routes(seq).unwrap();
    }
    let (actions, claim) = scripted_reply(host, &peer, &mut init, "active", route_set).unwrap();
    (init, actions, claim)
}

/// Runs `init` against a scripted host that answers `msg3` with a `PairResponse` of `status`
/// carrying `route_set` (omitted when `None`).
fn scripted_reply(
    host: &EndpointIdentity,
    peer: &EndpointIdentity,
    init: &mut PairingInitiator,
    status: &str,
    route_set: Option<Value>,
) -> Result<(Vec<PairAction>, PairClaim), CoreError> {
    scripted_raw_reply(host, peer, init, status, route_set.map(|v| v.to_string()))
}

/// [`scripted_reply`] with `route_set` given as raw JSON text, for values `Value` cannot hold.
fn scripted_raw_reply(
    host: &EndpointIdentity,
    peer: &EndpointIdentity,
    init: &mut PairingInitiator,
    status: &str,
    route_set: Option<String>,
) -> Result<(Vec<PairAction>, PairClaim), CoreError> {
    let preamble = Preamble::v1(Intent::Pair).encode();
    let mut resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&preamble)
        .build_responder()
        .unwrap();
    let m1 = writes(&init.start().unwrap());
    resp.read_message_vec(decode_frame(&m1[6..]).unwrap().0)
        .unwrap();
    let hello = serde_json::to_vec(&HostHello {
        host_id: host.host_id().to_owned(),
        proto_version: 1,
        signing_pub: host.signing_key().public_key().to_b64url(),
        rotation: host.rotation_chain().to_vec(),
        upgrade: vec![],
    })
    .unwrap();
    let m2 = resp.write_message_vec(&hello).unwrap();
    let m3 = writes(&init.feed_bytes(&encode_frame(&m2).unwrap()).unwrap());
    let claim_json = resp.read_message_vec(decode_frame(&m3).unwrap().0).unwrap();
    let claim: PairClaim = serde_json::from_slice(&claim_json).unwrap();
    let mut tx = resp.into_transport_mode().unwrap();
    let mut reply = json!({
        "device_id": peer.device_id(),
        "status": status,
        "host_signing_pub": host.signing_key().public_key().to_b64url(),
    })
    .to_string();
    if let Some(raw) = route_set {
        reply.pop();
        reply.push_str(&format!(r#","route_set":{raw}}}"#));
    }
    let m4 = tx.write_message_vec(reply.as_bytes()).unwrap();
    let actions = init.feed_bytes(&encode_frame(&m4).unwrap())?;
    Ok((actions, claim))
}

fn assert_enrolled(actions: &[PairAction]) {
    assert!(
        matches!(completed(actions), PairOutcome::InitiatorEnrolled { .. }),
        "{actions:?}"
    );
}

/// `route_set` nested `depth` arrays deep.
fn nested(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

/// A JSON value nested `depth` arrays deep, past `serde_json`'s parse recursion limit.
fn deep_value(depth: usize) -> Value {
    (0..depth).fold(Value::Null, |inner, _| Value::Array(vec![inner]))
}

fn parse(route_set: &str) -> Result<PairResponse, serde_json::Error> {
    serde_json::from_str(&format!(
        r#"{{"device_id":"d","status":"active","host_signing_pub":"AA","route_set":{route_set}}}"#
    ))
}

#[test]
fn pair_response_parses_with_and_without_route_set() {
    let parsed = parse(r#""AAAA""#).expect("route_set parses");
    assert!(matches!(
        parsed,
        PairResponse::Success { route_set: Some(RouteSetField::Encoded(ref s)), .. } if s == "AAAA"
    ));

    let legacy =
        r#"{"device_id":"dev_0011223344556677","status":"active","host_signing_pub":"AA"}"#;
    let parsed: PairResponse = serde_json::from_str(legacy).expect("legacy reply parses");
    assert!(matches!(
        parsed,
        PairResponse::Success {
            route_set: None,
            ..
        }
    ));
    assert_eq!(serde_json::to_string(&parsed).unwrap(), legacy);
    let error: PairResponse = serde_json::from_str(r#"{"error":"unauthorized"}"#).unwrap();
    assert_eq!(
        error,
        PairResponse::Error {
            error: "unauthorized".into()
        }
    );

    // Any value parses and never fails the reply; only a bounded string is kept.
    let at_bound = format!("\"{}\"", "A".repeat(MAX_ENROLLMENT_ROUTE_SET_B64_LEN));
    assert!(matches!(
        parse(&at_bound).unwrap(),
        PairResponse::Success {
            route_set: Some(RouteSetField::Encoded(_)),
            ..
        }
    ));
    let escaped = parse(r#""\u0041AAA""#).unwrap();
    assert!(matches!(
        escaped,
        PairResponse::Success { route_set: Some(RouteSetField::Encoded(ref s)), .. } if s == "AAAA"
    ));
    let over = format!("\"{}\"", "A".repeat(MAX_ENROLLMENT_ROUTE_SET_B64_LEN + 1));
    for value in [
        over.as_str(),
        "7",
        "-1",
        "1.5",
        "true",
        "null",
        r#"{"a":[1,{"b":null}]}"#,
        &nested(200),
        &format!(r#"{{"x":{}}}"#, nested(4_000)),
        "18446744073709551616",
        "-18446744073709551617",
        "1e400",
        "[[1e400],{\"a\":18446744073709551616}]",
        &format!("\"{}\"", "\\u0041".repeat(2_000)),
    ] {
        assert!(
            matches!(
                parse(value).unwrap(),
                PairResponse::Success {
                    route_set: Some(RouteSetField::Malformed),
                    ..
                }
            ),
            "{}",
            &value[..value.len().min(40)]
        );
    }

    for bad in [
        r#"{"device_id":"d","status":"active","host_signing_pub":"AA","routes":"x"}"#,
        r#"{"device_id":"d","device_id":"d","status":"active","host_signing_pub":"AA"}"#,
        r#"{"device_id":"d","status":"active","host_signing_pub":"AA","route_set":"A","route_set":"A"}"#,
        r#"{"device_id":"d","status":"active"}"#,
        r#"{"error":"x","device_id":"d"}"#,
        r#"{"error":"x","route_set":"A"}"#,
        r#"[]"#,
    ] {
        assert!(serde_json::from_str::<PairResponse>(bad).is_err(), "{bad}");
    }
}

#[test]
fn pair_claim_route_seq_is_bounded_and_omitted_when_unset() {
    let base = r#"{"name":"n","kind":"machine""#;
    let claim: PairClaim = serde_json::from_str(&format!("{base},\"route_seq\":0}}")).unwrap();
    assert_eq!(claim.route_seq, Some(0));
    let max = (1u64 << 53) - 1;
    let claim: PairClaim = serde_json::from_str(&format!("{base},\"route_seq\":{max}}}")).unwrap();
    assert_eq!(claim.route_seq, Some(max));
    assert!(
        serde_json::from_str::<PairClaim>(&format!("{base},\"route_seq\":{}}}", max + 1)).is_err()
    );
    let claim: PairClaim = serde_json::from_str(&format!("{base}}}")).unwrap();
    assert_eq!(claim.route_seq, None);
    assert!(!serde_json::to_string(&claim).unwrap().contains("route_seq"));
}

#[test]
fn verified_route_set_is_returned_with_the_enrolment() {
    let host = identity(0x11);
    let set = RouteSet::sign(&host, 3, NOW, routes()).unwrap();
    let (init, actions, claim) = enrol_with_reply(&host, pin(&host), Some(0), Some(encoded(&set)));
    assert_eq!(claim.route_seq, Some(0));
    assert_enrolled(&actions);
    assert_eq!(
        init.enrollment_routes(),
        Some(&EnrollmentRoutes::Verified(set))
    );
}

#[test]
fn bad_route_sets_are_dropped_and_the_enrolment_stands() {
    let host = identity(0x12);
    let other = identity(0x13);
    let cases: Vec<(&str, Value, EnrollmentRouteReject)> = vec![
        (
            "set signed by another host for itself",
            encoded(&RouteSet::sign(&other, 3, NOW, routes()).unwrap()),
            EnrollmentRouteReject::KeyMismatch,
        ),
        (
            "set naming the host, signed by another key",
            Value::String(b64url_encode(&signed_by(&host, &other))),
            EnrollmentRouteReject::BadSignature,
        ),
        (
            "not base64url",
            Value::String("!!!".into()),
            EnrollmentRouteReject::Malformed,
        ),
        (
            "base64url of a non-payload",
            Value::String(b64url_encode(b"not a route set")),
            EnrollmentRouteReject::Malformed,
        ),
        (
            "over the length bound",
            Value::String("A".repeat(MAX_ENROLLMENT_ROUTE_SET_B64_LEN + 1)),
            EnrollmentRouteReject::Malformed,
        ),
        ("a number", json!(7), EnrollmentRouteReject::Malformed),
        ("null", Value::Null, EnrollmentRouteReject::Malformed),
        (
            "nested 200 arrays deep",
            deep_value(200),
            EnrollmentRouteReject::Malformed,
        ),
        (
            "an object",
            json!({"routes": []}),
            EnrollmentRouteReject::Malformed,
        ),
    ];
    for (name, value, reason) in cases {
        let (init, actions, _) = enrol_with_reply(&host, pin(&host), Some(0), Some(value));
        assert_enrolled(&actions);
        assert_eq!(
            init.enrollment_routes(),
            Some(&EnrollmentRoutes::Rejected(reason)),
            "{name}"
        );
    }
}

#[test]
fn absent_and_unrequested_route_sets() {
    let host = identity(0x14);
    let (init, actions, _) = enrol_with_reply(&host, pin(&host), Some(0), None);
    assert_enrolled(&actions);
    assert_eq!(init.enrollment_routes(), Some(&EnrollmentRoutes::Absent));

    // Unrequested: the claim omits `route_seq` and the field is ignored without parsing.
    let (init, actions, claim) =
        enrol_with_reply(&host, pin(&host), None, Some(Value::String("!!!".into())));
    assert_eq!(claim.route_seq, None);
    assert_enrolled(&actions);
    assert_eq!(init.enrollment_routes(), None);
}

#[test]
fn rotated_host_route_set_must_be_signed_by_the_chain_verified_key() {
    let old = identity(0x15);
    let mut host = old.clone();
    host.rotate(
        StaticKeypair::from_scalar([0x16; 32]),
        SigningKeypair::from_seeds([0x17; 32], [0x18; 32]),
        NOW,
    )
    .unwrap();

    let current = RouteSet::sign(&host, 3, NOW, routes()).unwrap();
    let (init, actions, _) = enrol_with_reply(&host, pin(&old), Some(0), Some(encoded(&current)));
    assert_enrolled(&actions);
    assert_eq!(
        init.enrollment_routes(),
        Some(&EnrollmentRoutes::Verified(current))
    );

    let stale = RouteSet::sign(&old, 3, NOW, routes()).unwrap();
    let (init, actions, _) = enrol_with_reply(&host, pin(&old), Some(0), Some(encoded(&stale)));
    assert_enrolled(&actions);
    assert_eq!(
        init.enrollment_routes(),
        Some(&EnrollmentRoutes::Rejected(
            EnrollmentRouteReject::KeyMismatch
        ))
    );
}

#[test]
fn route_requests_are_m2m_only_and_bounded() {
    let host = identity(0x19);
    let peer = identity(0x32);
    let human = PairingInitiator::new(&peer, "p", "cli", "TND-ABCD-EFGH-JKLM", None, None).unwrap();
    assert!(matches!(
        human.with_enrollment_routes(0),
        Err(CoreError::ProtocolViolation(_))
    ));
    let m2m = || {
        PairingInitiator::new_m2m(
            &peer,
            "p",
            "machine",
            token(&host, &peer, 2),
            pin(&host),
            None,
        )
        .unwrap()
    };
    assert!(m2m().with_enrollment_routes(1 << 53).is_err());
    let mut started = m2m();
    started.start().unwrap();
    assert!(started.with_enrollment_routes(0).is_err());
}

/// A real M2M-enabled responder whose roster holds `published` as its route state.
fn responder_host(tag: u8, published: Option<&[String]>) -> (EndpointIdentity, Roster) {
    let host = identity(tag);
    let mut roster = Roster::new();
    if let Some(hints) = published {
        let set = PairingManager::announced_route_set(&host, hints);
        roster.bump_local_routes(&set, NOW).unwrap();
    }
    (host, roster)
}

/// Sends `claim` (built from the post-`msg2` hash) to a real responder and returns its
/// decrypted `PairResponse` JSON.
fn raw_claim(
    host: &EndpointIdentity,
    roster: &mut Roster,
    mgr: &mut PairingManager,
    peer: &EndpointIdentity,
    claim: impl FnOnce(&[u8; 32]) -> PairClaim,
) -> Value {
    let mut resp = PairingResponder::with_enrollment_policy(
        host,
        PairingPathKind::Lan,
        None,
        EnrollmentPolicy::enabled_default(),
    )
    .unwrap();
    let preamble = Preamble::v1(Intent::Pair).encode();
    let mut init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(peer.static_key().secret_bytes())
        .prologue(&preamble)
        .build_initiator()
        .unwrap();
    let m1 = encode_frame(&init.write_message_vec(&[]).unwrap()).unwrap();
    let m2 = writes(
        &resp
            .feed_bytes(&[&preamble[..], &m1].concat(), NOW, mgr, roster)
            .unwrap(),
    );
    init.read_message_vec(decode_frame(&m2).unwrap().0).unwrap();
    let h = *init.get_handshake_hash();
    let body = serde_json::to_vec(&claim(&h)).unwrap();
    let m3 = encode_frame(&init.write_message_vec(&body).unwrap()).unwrap();
    let m4 = writes(&resp.feed_bytes(&m3, NOW, mgr, roster).unwrap());
    let mut tx = init.into_transport_mode().unwrap();
    let pt = tx.read_message_vec(decode_frame(&m4).unwrap().0).unwrap();
    serde_json::from_slice(&pt).unwrap()
}

fn m2m_claim(
    host: &EndpointIdentity,
    peer: &EndpointIdentity,
    nonce: u8,
    route_seq: Option<u64>,
) -> impl FnOnce(&[u8; 32]) -> PairClaim {
    let tok = token(host, peer, nonce);
    let peer = peer.clone();
    move |h| PairClaim {
        name: "runner".into(),
        kind: "machine".into(),
        code_mac: None,
        enroll_proof: Some(b64url_encode(
            &sign_enroll_proof(
                peer.signing_key(),
                h,
                peer.static_key().public_bytes(),
                &tok.nonce,
            )
            .unwrap(),
        )),
        enrollment_token: Some(tok),
        signing_pub: Some(peer.signing_key().public_key().to_b64url()),
        route_seq,
    }
}

#[test]
fn responder_sends_its_signed_set_only_when_requested_and_newer() {
    let hints = vec!["direct:192.168.1.20:9100".to_owned()];
    let mut mgr = PairingManager::new(PairingConfig::default());
    let (host, mut roster) = responder_host(0x21, Some(&hints));
    let local = roster.local_routes().unwrap().clone();

    // Requested from 0: the reply carries C(seq), verifiable by the initiator's checks.
    let peer = identity(0x41);
    let reply = raw_claim(
        &host,
        &mut roster,
        &mut mgr,
        &peer,
        m2m_claim(&host, &peer, 1, Some(0)),
    );
    assert_eq!(reply["status"], "active");
    let set = verify_enrollment_route_set(
        reply["route_set"].as_str().expect("route_set"),
        host.static_key().public_bytes(),
        host.signing_key().public_key(),
    )
    .expect("verifies");
    assert_eq!(set.seq, local.seq());
    assert_eq!(set.issued_at, local.issued_at());
    assert_eq!(set.routes, local.routes());

    // Not requested, or not newer: no field, the enrolment is unchanged.
    for (tag, nonce, route_seq) in [(0x42, 2, None), (0x43, 3, Some(local.seq()))] {
        let peer = identity(tag);
        let reply = raw_claim(
            &host,
            &mut roster,
            &mut mgr,
            &peer,
            m2m_claim(&host, &peer, nonce, route_seq),
        );
        assert_eq!(reply["status"], "active");
        assert!(reply.get("route_set").is_none(), "{reply}");
    }

    // No route state: no field.
    let (bare, mut bare_roster) = responder_host(0x22, None);
    let peer = identity(0x44);
    let reply = raw_claim(
        &bare,
        &mut bare_roster,
        &mut mgr,
        &peer,
        m2m_claim(&bare, &peer, 4, Some(0)),
    );
    assert_eq!(reply["status"], "active");
    assert!(reply.get("route_set").is_none());
}

#[test]
fn human_claim_with_route_seq_is_a_protocol_error_before_the_code_is_checked() {
    let (host, mut roster) = responder_host(0x23, None);
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr.issue_code(PairingCodeKind::Remote3Group, NOW).unwrap();
    let peer = identity(0x45);
    let reply = raw_claim(&host, &mut roster, &mut mgr, &peer, |h| PairClaim {
        name: "phone".into(),
        kind: "phone".into(),
        code_mac: Some(b64url_encode(&compute_code_mac(&code, h).unwrap())),
        enrollment_token: None,
        signing_pub: None,
        enroll_proof: None,
        route_seq: Some(0),
    });
    assert_eq!(reply, json!({"error": "protocol_error"}));
    assert_eq!(mgr.live_code_count(NOW), 1, "the code is not consumed");
    assert_eq!(roster.entries().count(), 0);
}

fn long_hint(tag: char) -> String {
    let prefix = format!("wss://relay.example.com/{tag}");
    let mut hint = prefix.clone();
    hint.extend(std::iter::repeat_n('a', 256 - prefix.len()));
    hint
}

#[test]
fn largest_reply_fits_one_frame() {
    let host = identity(0x24);
    let hints: Vec<String> = "abcdef".chars().map(long_hint).collect();
    let set = RouteSet::sign(&host, 1, NOW, hints).unwrap();
    assert_eq!(set.encode().len(), MAX_ROUTE_SET_PAYLOAD);
    let reply = PairResponse::Success {
        device_id: identity(0x46).device_id(),
        status: "active".into(),
        host_signing_pub: host.signing_key().public_key().to_b64url(),
        route_set: Some(RouteSetField::Encoded(b64url_encode(&set.encode()))),
    };
    let json = serde_json::to_vec(&reply).unwrap();
    assert_eq!(
        reply_route_set_len(&reply),
        MAX_ENROLLMENT_ROUTE_SET_B64_LEN
    );
    assert_eq!(json.len(), 9_408);
    assert!(json.len() <= MAX_TRANSPORT_PLAINTEXT);
}

fn reply_route_set_len(reply: &PairResponse) -> usize {
    match reply {
        PairResponse::Success {
            route_set: Some(RouteSetField::Encoded(s)),
            ..
        } => s.len(),
        _ => 0,
    }
}

#[test]
fn deep_route_set_after_the_burn_never_fails_the_enrolment() {
    let host = identity(0x25);
    let (init, actions, _) = enrol_with_reply(&host, pin(&host), Some(0), Some(deep_value(300)));
    assert_enrolled(&actions);
    assert_eq!(
        init.enrollment_routes(),
        Some(&EnrollmentRoutes::Rejected(
            EnrollmentRouteReject::Malformed
        ))
    );
    let (init, actions, _) = enrol_with_reply(&host, pin(&host), None, Some(deep_value(300)));
    assert_enrolled(&actions);
    assert_eq!(init.enrollment_routes(), None);
}

#[test]
fn human_initiator_rejects_any_route_set() {
    let host = identity(0x26);
    let peer = identity(0x47);
    for value in [Value::String("AAAA".into()), json!(7), deep_value(300)] {
        let mut init = PairingInitiator::new(
            &peer,
            "p",
            "cli",
            "TND-ABCD-EFGH-JKLM",
            Some(pin(&host)),
            None,
        )
        .unwrap();
        let err = scripted_reply(&host, &peer, &mut init, "pending", Some(value))
            .expect_err("route_set in a human reply");
        assert_eq!(
            err,
            CoreError::ProtocolViolation("route_set in a human pair response")
        );
    }
    let mut init = PairingInitiator::new(
        &peer,
        "p",
        "cli",
        "TND-ABCD-EFGH-JKLM",
        Some(pin(&host)),
        None,
    )
    .unwrap();
    let (actions, _) = scripted_reply(&host, &peer, &mut init, "pending", None).unwrap();
    assert!(matches!(
        completed(&actions),
        PairOutcome::InitiatorPending { .. }
    ));
}

#[test]
fn out_of_range_numbers_after_the_burn_never_fail_the_enrolment() {
    let host = identity(0x27);
    for raw in [
        "18446744073709551616",
        "1e400",
        r#"[[1e400],{"a":18446744073709551616}]"#,
    ] {
        for request in [Some(0), None] {
            let peer = identity(0x31);
            let mut init = PairingInitiator::new_m2m(
                &peer,
                "runner",
                "machine",
                token(&host, &peer, 0x05),
                pin(&host),
                None,
            )
            .unwrap();
            if let Some(seq) = request {
                init = init.with_enrollment_routes(seq).unwrap();
            }
            let (actions, _) =
                scripted_raw_reply(&host, &peer, &mut init, "active", Some(raw.to_owned()))
                    .unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_enrolled(&actions);
            let expected =
                request.map(|_| EnrollmentRoutes::Rejected(EnrollmentRouteReject::Malformed));
            assert_eq!(init.enrollment_routes(), expected.as_ref(), "{raw}");
        }
    }
}
