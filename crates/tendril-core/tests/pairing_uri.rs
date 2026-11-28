//! Pairing URI fields, route statements, persistence plans, the announced set and the builder.

use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    DropReason, DroppedHint, IssueOptions, LocalRouteState, MAX_PAIRING_URI_LEN,
    PAIRING_ROUTES_DOMAIN, PairAction, PairOutcome, PairRouteBinding, PairingCodeKind,
    PairingConfig, PairingInitiator, PairingManager, PairingPathKind, PairingResponder, PairingUri,
    PersistOpts, PersistPlan, PinnedHost, RouteCheck, RoutePolicy, UnsignedReason,
    classify_endpoint_hint, is_valid_pairing_endpoint_hint, mint_enrollment_token,
    persistable_routes, qr_version_m, sign_route_statement,
};
use tendril_core::policy::ProviderId;
use tendril_core::roster::Roster;
use tendril_core::routes::RouteSet;
use tendril_core::session::RouteExpectation;

const NOW_UNIX: u64 = 1_795_564_800;

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
    )
}

fn ed_b64(id: &EndpointIdentity) -> String {
    b64url_encode(id.signing_key().ed25519_public_bytes())
}

fn owned(hints: &[&str]) -> Vec<String> {
    hints.iter().map(|h| (*h).to_owned()).collect()
}

fn base_uri(id: &EndpointIdentity, code: &str, hints: &[&str]) -> PairingUri {
    let mut uri = PairingUri::new(
        "Studio",
        code,
        *id.static_key().public_bytes(),
        id.signing_key().signing_pub_hash(),
        owned(hints),
        Some(id.host_id().to_owned()),
        Some(0),
    );
    if hints.iter().any(|h| h.contains("/v1/relay")) {
        uri.relay_pub = Some(*id.signing_key().ed25519_public_bytes());
    }
    uri
}

/// Signs `uri` the way the builder does: unsigned fields, `&rq=`, then `&rs=`.
fn sign(id: &EndpointIdentity, uri: &PairingUri, rq: u64) -> String {
    let prefix = format!("{}&rq={rq}", uri.try_encode().unwrap());
    let sig = sign_route_statement(id, &prefix);
    format!("{prefix}&rs={}", b64url_encode(&sig))
}

const SIGNED_HINTS: [&str; 3] = [
    "direct:192.168.1.20:9100",
    "overlay://100.64.0.10:9100",
    "wss://relay.example.com/v1/relay",
];
const CODE3: &str = "TND-ABCD-EFGH-JKLM";

fn signed_fixture(id: &EndpointIdentity) -> String {
    sign(id, &base_uri(id, CODE3, &SIGNED_HINTS), 5)
}

fn verified(id: &EndpointIdentity, uri: &str) -> RouteCheck {
    PairingUri::parse(uri)
        .unwrap()
        .verify_route_statement(id.signing_key().public_key())
}

fn is_invalid_uri<T: std::fmt::Debug>(r: Result<T, CoreError>) -> bool {
    matches!(r, Err(CoreError::InvalidPairingUri(_)))
}

fn roster_with_local_routes(seq: u64, routes: &[String]) -> Result<Roster, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "entries": {},
        "crls": {},
        "local_routes": {
            "seq": seq,
            "issued_at": NOW_UNIX,
            "digest": LocalRouteState::digest_of(routes),
            "routes": routes,
        },
    }))
}

/// A published `C(seq)` as a host roster stores it.
fn published(seq: u64, routes: &[String]) -> LocalRouteState {
    roster_with_local_routes(seq, routes)
        .unwrap()
        .local_routes()
        .unwrap()
        .clone()
}

const SIX: [&str; 6] = [
    "direct:192.168.1.20:9100",
    "direct:127.0.0.1:9100",
    "overlay://100.64.0.10:9100",
    "iroh://k51qzi5uqu5dl",
    "wss://relay.example.com/v1/relay",
    "broker+wss://broker.example.com/v1/broker",
];

#[test]
fn six_hint_signed_uri_round_trips() {
    let id = identity(0x11);
    for swap_v2 in [false, true] {
        let mut hints = SIX.to_vec();
        if swap_v2 {
            hints[5] = "wss://relay.example.com/v2/relay";
        }
        let announced_set = PairingManager::announced_route_set(&id, &owned(&hints));
        assert!(announced_set.dropped().is_empty(), "{announced_set:?}");
        let set = announced_set.routes().to_vec();
        let announced = published(9, &set);
        let mut mgr = PairingManager::new(PairingConfig::default());
        let issued = mgr
            .issue_pairing_uri(&id, "Studio", &announced, IssueOptions::default(), NOW_UNIX)
            .unwrap();
        assert_eq!(issued.code_kind, PairingCodeKind::Remote3Group);
        assert_eq!(issued.route_seq, Some(9));
        assert!(issued.dropped.is_empty());
        assert_eq!(issued.uri_len, issued.uri.len());
        assert!(issued.uri.ends_with(&issued.uri[issued.uri.len() - 86..]));
        let parsed = PairingUri::parse(&issued.uri).unwrap();
        assert_eq!(parsed, issued.parsed);
        assert_eq!(parsed.endpoints, set);
        assert_eq!(
            parsed.relay_pub,
            Some(*id.signing_key().ed25519_public_bytes())
        );
        assert_eq!(parsed.route_seq(), Some(9));
        assert!(parsed.is_signed());
        assert_eq!(parsed.try_encode().unwrap(), issued.uri);
        let RouteCheck::Verified(s) = parsed.verify_route_statement(id.signing_key().public_key())
        else {
            panic!("builder output must verify");
        };
        assert_eq!(s.hints(), set.as_slice());
        assert_eq!(s.route_seq(), 9);
        assert_eq!(s.code(), parsed.code);
        assert_eq!(s.relay_pub(), parsed.relay_pub.as_ref());
        parsed
            .check_relay_pub(id.signing_key().public_key())
            .unwrap();
    }

    let v2_only = base_uri(&id, CODE3, &["wss://relay.example.com/v2/relay"]);
    assert_eq!(v2_only.relay_pub, None);
    let encoded = v2_only.try_encode().unwrap();
    assert!(!encoded.contains("&rp="));
    assert_eq!(PairingUri::parse(&encoded).unwrap(), v2_only);
}

#[test]
fn code_classifier_table() {
    assert_eq!(
        PairingCodeKind::from_code("TND-ABCD-EFGH"),
        Ok(PairingCodeKind::Lan2Group)
    );
    assert_eq!(
        PairingCodeKind::from_code("TND-ABCD-EFGH-JKLM"),
        Ok(PairingCodeKind::Remote3Group)
    );
    for bad in [
        "TND-ABCD",
        "TND-ABCDEFGH",
        "TND-ABCD-EFGH-JKLM-NPQR",
        "tnd-abcd-efgh",
        "TND-ABCD-EFG",
        "TND-ABCD-EFGH ",
        "XYZ-ABCD-EFGH",
        "",
    ] {
        assert_eq!(
            PairingCodeKind::from_code(bad),
            Err(CoreError::PairingCodeInvalid),
            "{bad:?}"
        );
    }
}

#[test]
fn endpoint_hint_classifier_table() {
    for (hint, provider) in [
        ("local:/run/t.sock", ProviderId::Local),
        ("unix:///run/t.sock", ProviderId::Local),
        ("direct:192.168.1.2:80", ProviderId::Direct),
        ("192.168.1.2:80", ProviderId::Direct),
        ("overlay://100.64.0.1:80", ProviderId::Overlay),
        ("iroh://abc", ProviderId::P2p),
        ("p2p:iroh://abc", ProviderId::P2p),
        ("wss://r.example/v1/relay", ProviderId::Relay),
        ("ws://127.0.0.1:9/v1/relay", ProviderId::Relay),
        ("relay:wss://r.example/v1/relay", ProviderId::Relay),
        ("broker+wss://b.example/v1/broker", ProviderId::Broker),
        ("broker+ws://127.0.0.1:9/v1/broker", ProviderId::Broker),
    ] {
        assert_eq!(classify_endpoint_hint(hint), Ok(provider), "{hint}");
    }
    assert!(is_invalid_uri(classify_endpoint_hint(
        "ws://evil.example/v1/relay"
    )));
    assert!(is_invalid_uri(classify_endpoint_hint(
        "javascript:alert(1)"
    )));
}

fn raw(id: &EndpointIdentity, code: &str, tail: &str) -> String {
    format!(
        "tendril://pair?v=1&host=h&code={code}&k={}&sh={}{tail}",
        b64url_encode(id.static_key().public_bytes()),
        b64url_encode(&id.signing_key().signing_pub_hash()),
    )
}

#[test]
fn parse_and_try_encode_enforce_bounds_and_rules() {
    let id = identity(0x21);
    let rp = ed_b64(&id);

    let six: Vec<String> = (1..=6)
        .map(|i| format!("direct:192.168.1.{i}:80"))
        .collect();
    let mut uri = PairingUri::new(
        "h",
        CODE3,
        *id.static_key().public_bytes(),
        id.signing_key().signing_pub_hash(),
        six,
        None,
        None,
    );
    assert!(PairingUri::parse(&uri.try_encode().unwrap()).is_ok());
    uri.endpoints.push("direct:192.168.1.7:80".into());
    assert!(is_invalid_uri(uri.try_encode()));
    let seven = (1..=7)
        .map(|i| format!("direct%3A192.168.1.{i}%3A80"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(is_invalid_uri(PairingUri::parse(&raw(
        &id,
        CODE3,
        &format!("&ep={seven}")
    ))));

    let host256 = format!(
        "wss://{}.example/v2/relay",
        "a".repeat(256 - "wss://.example/v2/relay".len())
    );
    assert_eq!(host256.len(), 256);
    let ok = base_uri(&id, CODE3, &[&host256]);
    assert!(PairingUri::parse(&ok.try_encode().unwrap()).is_ok());
    let host257 = host256.replacen("wss://", "wss://a", 1);
    let long = base_uri(&id, CODE3, &[&host257]);
    assert!(is_invalid_uri(long.try_encode()));
    assert!(is_invalid_uri(PairingUri::parse(&raw(
        &id,
        CODE3,
        &format!("&ep={host257}")
    ))));

    let empty = PairingUri::new(
        "h",
        CODE3,
        *id.static_key().public_bytes(),
        id.signing_key().signing_pub_hash(),
        vec![],
        None,
        None,
    );
    let base_len = empty.try_encode().unwrap().len();
    let mut at_limit = empty.clone();
    at_limit.host_name = "h".repeat(1 + MAX_PAIRING_URI_LEN - base_len);
    let s = at_limit.try_encode().unwrap();
    assert_eq!(s.len(), MAX_PAIRING_URI_LEN);
    assert!(PairingUri::parse(&s).is_ok());
    let mut over = at_limit.clone();
    over.host_name.push('h');
    assert!(is_invalid_uri(over.try_encode()));
    let s1025 = s.replacen("host=", "host=h", 1);
    assert_eq!(s1025.len(), MAX_PAIRING_URI_LEN + 1);
    assert!(is_invalid_uri(PairingUri::parse(&s1025)));

    let relay = "&ep=wss%3A%2F%2Fr.example%2Fv1%2Frelay";
    assert!(PairingUri::parse(&raw(&id, CODE3, &format!("&rp={rp}{relay}"))).is_ok());
    assert!(is_invalid_uri(PairingUri::parse(&raw(&id, CODE3, relay))));
    assert!(is_invalid_uri(PairingUri::parse(&raw(
        &id,
        CODE3,
        &format!("&rp={rp}")
    ))));
    assert!(is_invalid_uri(PairingUri::parse(&raw(
        &id,
        CODE3,
        &format!("&rp={}{relay}", &rp[..42])
    ))));
    assert!(is_invalid_uri(PairingUri::parse(&raw(
        &id,
        CODE3,
        &format!("&rp={rp}A{relay}")
    ))));
    let zero_key = b64url_encode(&[0u8; 32]);
    assert!(is_invalid_uri(PairingUri::parse(&raw(
        &id,
        CODE3,
        &format!("&rp={zero_key}{relay}")
    ))));
    let mut no_rp = base_uri(&id, CODE3, &["wss://relay.example.com/v1/relay"]);
    no_rp.relay_pub = None;
    assert!(is_invalid_uri(no_rp.try_encode()));

    for tail in [
        "&ep=wss%3A%2F%2Fr.example%2Fv2%2Frelay%23x",
        "&ep=direct%3A0.0.0.0%3A80",
        "&ep=direct%3A192.168.1.2%3A80%23x",
    ] {
        assert!(
            is_invalid_uri(PairingUri::parse(&raw(&id, CODE3, tail))),
            "{tail}"
        );
    }

    let lan_code = "TND-ABCD-EFGH";
    for tail in [
        "&ep=direct%3A192.168.1.2%3A80",
        "&ep=direct%3A127.0.0.1%3A80",
        "&ep=direct%3A%5Bfd00%3A%3A2%5D%3A80",
        "&ep=local%3A%2Frun%2Ft.sock",
    ] {
        assert!(
            PairingUri::parse(&raw(&id, lan_code, tail)).is_ok(),
            "{tail}"
        );
    }
    for tail in [
        "&ep=direct%3A8.8.8.8%3A80",
        "&ep=overlay%3A%2F%2F192.168.1.2%3A80",
        "&ep=iroh%3A%2F%2Fabc",
        "&ep=wss%3A%2F%2Fr.example%2Fv2%2Frelay",
        "&ep=broker%2Bws%3A%2F%2F127.0.0.1%3A9%2Fv1%2Fbroker",
    ] {
        let err = PairingUri::parse(&raw(&id, lan_code, tail)).unwrap_err();
        assert_eq!(
            err,
            CoreError::InvalidPairingUri(
                "lan 2-group code cannot be paired with remote endpoint hints".into()
            ),
            "{tail}"
        );
    }
}

#[test]
fn route_statement_detects_every_field_tamper() {
    let id = identity(0x31);
    let other = identity(0x32);
    let uri = signed_fixture(&id);
    assert!(matches!(verified(&id, &uri), RouteCheck::Verified(_)));

    let k = b64url_encode(id.static_key().public_bytes());
    let k2 = b64url_encode(other.static_key().public_bytes());
    let rp = ed_b64(&id);
    let rp2 = ed_b64(&other);
    let host_id = id.host_id().to_owned();
    let mut host_id2 = host_id.clone();
    let last = host_id2.pop().unwrap();
    host_id2.push(if last == 'a' { 'b' } else { 'a' });
    for (field, from, to) in [
        ("host", "host=Studio", "host=Studjo"),
        ("code", "code=TND-ABCD", "code=TND-ABCE"),
        ("k", &format!("k={k}")[..], &format!("k={k2}")[..]),
        (
            "id",
            &format!("id={host_id}")[..],
            &format!("id={host_id2}")[..],
        ),
        ("seq", "seq=0", "seq=1"),
        ("rp", &format!("rp={rp}")[..], &format!("rp={rp2}")[..]),
        ("hint", "192.168.1.20", "192.168.1.21"),
        ("rq", "&rq=5", "&rq=6"),
    ] {
        assert_eq!(uri.matches(from).count(), 1, "{field}");
        let tampered = uri.replacen(from, to, 1);
        assert_eq!(verified(&id, &tampered), RouteCheck::Invalid, "{field}");
    }

    let sh = b64url_encode(&id.signing_key().signing_pub_hash());
    let sh2 = b64url_encode(&other.signing_key().signing_pub_hash());
    let swapped_sh = uri.replacen(&format!("sh={sh}"), &format!("sh={sh2}"), 1);
    assert_eq!(verified(&other, &swapped_sh), RouteCheck::Invalid);

    let unsigned = base_uri(&id, CODE3, &SIGNED_HINTS).try_encode().unwrap();
    assert_eq!(
        verified(&id, &unsigned),
        RouteCheck::Unsigned(UnsignedReason::Absent)
    );
    assert_eq!(verified(&id, &unsigned).as_str(), "unsigned");
}

#[test]
fn route_statement_position_and_form() {
    let id = identity(0x41);
    let uri = signed_fixture(&id);
    assert!(PairingUri::parse(&uri).is_ok());
    let (prefix, rs) = uri.rsplit_once("&rs=").unwrap();
    assert_eq!(rs.len(), 86);
    let (before_rq, _) = prefix.rsplit_once("&rq=").unwrap();
    let ep_at = before_rq.find("&ep=").unwrap();

    let rs_not_last = format!(
        "{}&rs={rs}{}&rq=5",
        &before_rq[..ep_at],
        &before_rq[ep_at..]
    );
    let rq_not_adjacent = format!(
        "{}&rq=5{}&rs={rs}",
        &before_rq[..ep_at],
        &before_rq[ep_at..]
    );
    let cases = [
        ("rs not last", rs_not_last),
        ("bytes after rs", format!("{uri}&x=1")),
        ("trailing byte", format!("{uri}A")),
        ("two rs", format!("{prefix}&rs={rs}&rs={rs}")),
        ("rs 85", format!("{prefix}&rs={}", &rs[..85])),
        ("rs 87", format!("{prefix}&rs={rs}A")),
        ("rs bad char", format!("{prefix}&rs={}=", &rs[..85])),
        ("rs without rq", format!("{before_rq}&rs={rs}")),
        ("rq not before rs", rq_not_adjacent),
        ("rq=0", format!("{before_rq}&rq=0&rs={rs}")),
        ("rq=01", format!("{before_rq}&rq=01&rs={rs}")),
        (
            "rq=2^53",
            format!("{before_rq}&rq=9007199254740992&rs={rs}"),
        ),
        ("rq=-1", format!("{before_rq}&rq=-1&rs={rs}")),
        ("rq=+1", format!("{before_rq}&rq=+1&rs={rs}")),
        ("rq without rs", prefix.to_owned()),
    ];
    for (name, case) in cases {
        assert!(is_invalid_uri(PairingUri::parse(&case)), "{name}: {case}");
    }
    let max = format!("{before_rq}&rq=9007199254740991");
    let sig = sign_route_statement(&id, &max);
    let max_uri = format!("{max}&rs={}", b64url_encode(&sig));
    assert_eq!(
        PairingUri::parse(&max_uri).unwrap().route_seq(),
        Some((1 << 53) - 1)
    );
}

#[test]
fn route_statement_under_rotated_key() {
    let a = identity(0x51);
    let b = identity(0x52);
    let uri = PairingUri::parse(&signed_fixture(&a)).unwrap();
    let check = uri.verify_route_statement(b.signing_key().public_key());
    assert_eq!(check, RouteCheck::Unsigned(UnsignedReason::KeyRotated));
    assert_eq!(check.as_str(), "route_key_rotated");
    assert_eq!(
        uri.verify_route_statement_for_session(b.signing_key().public_key()),
        RouteCheck::Invalid
    );
    assert!(matches!(
        uri.verify_route_statement_for_session(a.signing_key().public_key()),
        RouteCheck::Verified(_)
    ));
    assert_eq!(
        uri.check_relay_pub(b.signing_key().public_key()),
        Err(CoreError::HostKeyUnverified)
    );
}

#[test]
fn signing_domains_are_prefix_free() {
    let domains: [(&str, &[u8]); 20] = [
        ("pairing routes", PAIRING_ROUTES_DOMAIN),
        ("route set", tendril_core::routes::ROUTE_SET_DOMAIN),
        ("rotation", tendril_core::identity::ROTATION_DOMAIN),
        ("grant", tendril_core::grants::GRANT_DOMAIN),
        ("crl", tendril_core::grants::CRL_DOMAIN),
        ("group", tendril_core::group::GROUP_MANIFEST_DOMAIN),
        ("enroll", tendril_core::ENROLL_PROOF_DOMAIN),
        ("pair key", tendril_core::PAIR_KEY_PROOF_DOMAIN),
        ("relay auth", tendril_core::RELAY_AUTH_HMAC_DOMAIN),
        ("relay ticket", tendril_core::RELAY_TICKET_DOMAIN),
        ("relay reg v1", b"tendril-relay-reg-v1\0"),
        ("relay accept v1", b"tendril-relay-accept-v1\0"),
        ("relay reg v2", b"tendril-relay-reg-v2\0"),
        ("relay v2 dial", b"tendril-relay-v2-dial\0"),
        ("relay accept v2", b"tendril-relay-accept-v2\0"),
        ("v2 rendezvous", b"tendril-v2-rendezvous\0"),
        ("pake msg1", b"tendril-v2-pake-msg1\0"),
        ("pake resp", b"tendril-v2-pake-resp\0"),
        ("pake init", b"tendril-v2-pake-init\0"),
        ("group v2 rendezvous", b"tendril-group-v2-rendezvous\0"),
    ];
    assert_eq!(PAIRING_ROUTES_DOMAIN.len(), 26);
    for (i, (na, a)) in domains.iter().enumerate() {
        for (j, (nb, b)) in domains.iter().enumerate() {
            if i != j {
                assert!(!b.starts_with(a), "{na} is a prefix of {nb}");
            }
        }
    }
}

fn opts(policy: RoutePolicy, save: bool, operator: Option<&str>) -> PersistOpts {
    PersistOpts {
        operator_endpoint: operator.map(str::to_owned),
        policy,
        save_committed: save,
    }
}

type PlanView = (
    Vec<String>,
    Option<u64>,
    Option<String>,
    Option<String>,
    Option<&'static str>,
);

fn view(p: &PersistPlan) -> PlanView {
    (
        p.signed().to_vec(),
        p.route_seq(),
        p.committed.clone(),
        p.operator.clone(),
        p.reason,
    )
}

#[test]
fn persistable_routes_matrix() {
    let id = identity(0x61);
    let with_ipc = [
        "direct:192.168.1.20:9100",
        "local:/run/t.sock",
        "wss://relay.example.com/v1/relay",
    ];
    let signed = sign(&id, &base_uri(&id, CODE3, &with_ipc), 7);
    let check = verified(&id, &signed);
    assert!(matches!(check, RouteCheck::Verified(_)));
    let non_ipc = owned(&[
        "direct:192.168.1.20:9100",
        "wss://relay.example.com/v1/relay",
    ]);
    let winner = Some("direct:192.168.1.20:9100");
    let op = Some("direct:10.0.0.9:7000");
    let override_code = "TND-ZZZZ-YYYY-XXXX";
    let absent = RouteCheck::Unsigned(UnsignedReason::Absent);
    let rotated = RouteCheck::Unsigned(UnsignedReason::KeyRotated);

    let plan = |c: &RouteCheck, code: &str, w: Option<&str>, o: &PersistOpts| {
        view(&persistable_routes(c, code, w, o))
    };
    let signed_plan = |signed: Vec<String>, operator: Option<&str>| -> PlanView {
        (signed, Some(7), None, operator.map(str::to_owned), None)
    };
    let unsigned_plan = |committed: Option<&str>, reason: &'static str| -> PlanView {
        (
            vec![],
            None,
            committed.map(str::to_owned),
            None,
            Some(reason),
        )
    };
    let only_operator = |operator: Option<&str>| -> PlanView {
        (vec![], None, None, operator.map(str::to_owned), None)
    };
    let empty: PlanView = (vec![], None, None, None, None);

    let full = persistable_routes(
        &check,
        CODE3,
        winner,
        &opts(RoutePolicy::AllSigned, false, None),
    );
    assert_eq!(
        full.signed_host_keys(),
        Some(&(
            *id.static_key().public_bytes(),
            id.signing_key().signing_pub_hash()
        ))
    );
    assert_eq!(
        persistable_routes(
            &absent,
            CODE3,
            winner,
            &opts(RoutePolicy::AllSigned, true, None)
        )
        .signed_host_keys(),
        None
    );

    // Signed and bound.
    for save in [false, true] {
        assert_eq!(
            plan(
                &check,
                CODE3,
                winner,
                &opts(RoutePolicy::AllSigned, save, None)
            ),
            signed_plan(non_ipc.clone(), None)
        );
    }
    assert_eq!(
        plan(
            &check,
            CODE3,
            winner,
            &opts(RoutePolicy::AllSigned, false, op)
        ),
        signed_plan(non_ipc.clone(), op)
    );
    assert_eq!(
        plan(
            &check,
            CODE3,
            winner,
            &opts(RoutePolicy::CommittedOnly, false, None)
        ),
        signed_plan(owned(&["direct:192.168.1.20:9100"]), None)
    );
    assert_eq!(
        plan(
            &check,
            CODE3,
            None,
            &opts(RoutePolicy::CommittedOnly, false, op)
        ),
        only_operator(op)
    );
    assert_eq!(
        plan(
            &check,
            CODE3,
            Some("local:/run/t.sock"),
            &opts(RoutePolicy::CommittedOnly, false, None)
        ),
        empty.clone()
    );
    assert_eq!(
        plan(
            &check,
            CODE3,
            Some("direct:192.168.1.99:1"),
            &opts(RoutePolicy::CommittedOnly, false, None)
        ),
        empty.clone()
    );
    for save in [false, true] {
        assert_eq!(
            plan(
                &check,
                CODE3,
                Some("direct:192.168.1.99:1"),
                &opts(RoutePolicy::CommittedOnly, save, op)
            ),
            only_operator(op)
        );
    }
    assert_eq!(
        plan(&check, CODE3, winner, &opts(RoutePolicy::None, false, None)),
        empty.clone()
    );
    assert_eq!(
        plan(&check, CODE3, winner, &opts(RoutePolicy::None, false, op)),
        only_operator(op)
    );

    // Verified, but the effective code was overridden: unsigned rules.
    for c in [&check, &absent] {
        assert_eq!(
            plan(
                c,
                override_code,
                winner,
                &opts(RoutePolicy::AllSigned, false, None)
            ),
            unsigned_plan(None, "unsigned_uri")
        );
        assert_eq!(
            plan(
                c,
                override_code,
                winner,
                &opts(RoutePolicy::AllSigned, true, None)
            ),
            unsigned_plan(winner, "unsigned_uri")
        );
        assert_eq!(
            plan(
                c,
                override_code,
                winner,
                &opts(RoutePolicy::CommittedOnly, false, None)
            ),
            unsigned_plan(winner, "unsigned_uri")
        );
        assert_eq!(
            plan(
                c,
                override_code,
                winner,
                &opts(RoutePolicy::None, false, None)
            ),
            empty.clone()
        );
    }
    assert_eq!(
        plan(
            &rotated,
            CODE3,
            winner,
            &opts(RoutePolicy::AllSigned, false, None)
        ),
        unsigned_plan(None, "route_key_rotated")
    );
    assert_eq!(
        plan(
            &rotated,
            CODE3,
            winner,
            &opts(RoutePolicy::CommittedOnly, false, op)
        ),
        (
            vec![],
            None,
            winner.map(str::to_owned),
            op.map(str::to_owned),
            Some("route_key_rotated")
        )
    );
    for bad_winner in ["wss://relay.example.com/v2/relay", "local:/run/t.sock"] {
        assert_eq!(
            plan(
                &absent,
                CODE3,
                Some(bad_winner),
                &opts(RoutePolicy::CommittedOnly, false, None)
            ),
            unsigned_plan(None, "unsigned_uri")
        );
    }
    assert_eq!(
        plan(
            &RouteCheck::Invalid,
            CODE3,
            winner,
            &opts(RoutePolicy::AllSigned, true, op)
        ),
        empty.clone()
    );

    assert_eq!(
        opts(RoutePolicy::None, true, None).validate(),
        Err(CoreError::InvalidPairingUri(
            "--save-route conflicts with --route-policy none".into()
        ))
    );
    opts(RoutePolicy::CommittedOnly, true, None)
        .validate()
        .unwrap();
    opts(RoutePolicy::AllSigned, true, None).validate().unwrap();
    opts(RoutePolicy::None, false, op).validate().unwrap();
}

#[test]
fn route_policy_and_reason_spellings() {
    assert_eq!(RoutePolicy::default(), RoutePolicy::AllSigned);
    for (p, s) in [
        (RoutePolicy::AllSigned, "all_signed"),
        (RoutePolicy::CommittedOnly, "committed_only"),
        (RoutePolicy::None, "none"),
    ] {
        assert_eq!(serde_json::to_string(&p).unwrap(), format!("\"{s}\""));
        assert_eq!(p.as_str(), s);
        assert_eq!(s.parse::<RoutePolicy>().unwrap(), p);
        assert_eq!(s.replace('_', "-").parse::<RoutePolicy>().unwrap(), p);
    }
    assert_eq!(
        "allSigned".parse::<RoutePolicy>().unwrap(),
        RoutePolicy::AllSigned
    );
    assert!("signed".parse::<RoutePolicy>().is_err());
    let d = DroppedHint {
        hint: "x".into(),
        reason: DropReason::LanCodeRemoteHint,
    };
    assert_eq!(
        serde_json::to_string(&d).unwrap(),
        r#"{"hint":"x","reason":"lan_code_remote_hint"}"#
    );
    assert_eq!(RouteCheck::Invalid.as_str(), "invalid");
}

#[test]
fn route_statement_rejects_mutated_public_fields() {
    let id = identity(0x71);
    let key = id.signing_key().public_key();
    for mutate in [
        (|u: &mut PairingUri| u.endpoints = vec!["wss://evil.example/v1/relay".into()])
            as fn(&mut PairingUri),
        |u| u.code = "TND-WXYZ-WXYZ-WXYZ".into(),
        |u| u.host_name.push('x'),
        |u| u.host_static_pub[0] ^= 1,
        |u| u.host_signing_pub_hash[0] ^= 1,
        |u| u.host_id = None,
        |u| u.rotation_seq = Some(3),
        |u| u.relay_pub = None,
    ] {
        let mut u = PairingUri::parse(&signed_fixture(&id)).unwrap();
        assert!(matches!(
            u.verify_route_statement(key),
            RouteCheck::Verified(_)
        ));
        mutate(&mut u);
        assert_eq!(
            u.try_encode(),
            Err(CoreError::InvalidPairingUri(
                "signed pairing URI fields were modified".into()
            ))
        );
        assert_eq!(u.verify_route_statement(key), RouteCheck::Invalid);
        assert_eq!(
            u.verify_route_statement_for_session(key),
            RouteCheck::Invalid
        );
        assert_eq!(u.route_seq(), Some(5));
    }

    let check = PairingUri::parse(&signed_fixture(&id))
        .unwrap()
        .verify_route_statement(key);
    assert_eq!(check.statement().unwrap().code(), CODE3);
    let plan = persistable_routes(&check, "TND-WXYZ-WXYZ-WXYZ", None, &PersistOpts::default());
    assert!(plan.signed().is_empty());
    assert_eq!(plan.reason, Some("unsigned_uri"));
}

#[test]
fn announced_set_normalizes_listener_formats() {
    let id = identity(0x81);
    let other = identity(0x82);
    let long_iroh = format!(
        "iroh://node1?relay=https://iroh.example{}",
        (0..20)
            .map(|i| format!("&addr=192.168.7.{i}:4433"))
            .collect::<String>()
    );
    assert!(long_iroh.len() > 256);
    let inputs = owned(&[
        "192.168.1.5:7000",
        "[fd00::5]:7000",
        &format!("wss://relay.example.com/v1/relay#{}", ed_b64(&id)),
        &format!("wss://other.example.com/v1/relay#{}", ed_b64(&other)),
        "wss://relay.example.com/v2/relay#mailbox123",
        "/run/tendril.sock",
        "local:/run/tendril.sock",
        "unix:///run/tendril.sock",
        "0.0.0.0:7000",
        "direct:[::]:7000",
        "direct:169.254.169.254:80",
        "direct:255.255.255.255:80",
        "ws://relay.example.com/v1/relay",
        "direct:host.example:7000",
        "host.example:7000",
        "192.168.1.5:7000",
        "javascript:alert(1)",
        &long_iroh,
    ]);
    let announced = PairingManager::announced_route_set(&id, &inputs);
    let (set, dropped) = (announced.routes(), announced.dropped());
    let iroh = set.iter().find(|h| h.starts_with("iroh://")).unwrap();
    assert!(iroh.len() <= 256 && iroh.starts_with("iroh://node1?relay=https://iroh.example&addr="));
    assert!(PairingUri::parse(&raw(&id, CODE3, "")).is_ok());
    assert_eq!(
        set,
        vec![
            "direct:192.168.1.5:7000".to_owned(),
            "direct:[fd00::5]:7000".to_owned(),
            iroh.clone(),
            "wss://relay.example.com/v1/relay".to_owned(),
            "wss://relay.example.com/v2/relay".to_owned(),
        ]
    );
    let reason_of = |h: &str| {
        dropped
            .iter()
            .find(|d| d.hint == h)
            .map(|d| d.reason)
            .unwrap_or_else(|| panic!("{h} not dropped: {dropped:?}"))
    };
    assert_eq!(reason_of(&inputs[3]), DropReason::RelayNotServed);
    for h in [
        "/run/tendril.sock",
        "local:/run/tendril.sock",
        "unix:///run/tendril.sock",
    ] {
        assert_eq!(reason_of(h), DropReason::IpcNotAdvertised);
    }
    assert_eq!(reason_of("0.0.0.0:7000"), DropReason::UnspecifiedBind);
    assert_eq!(reason_of("direct:[::]:7000"), DropReason::UnspecifiedBind);
    assert_eq!(
        reason_of("direct:169.254.169.254:80"),
        DropReason::BlockedAddress
    );
    assert_eq!(
        reason_of("direct:255.255.255.255:80"),
        DropReason::BlockedAddress
    );
    assert_eq!(
        reason_of("ws://relay.example.com/v1/relay"),
        DropReason::InsecureWs
    );
    assert_eq!(
        reason_of("direct:host.example:7000"),
        DropReason::DirectRequiresIpLiteral
    );
    assert_eq!(
        reason_of("host.example:7000"),
        DropReason::DirectRequiresIpLiteral
    );
    assert_eq!(reason_of("direct:192.168.1.5:7000"), DropReason::Duplicate);
    assert_eq!(reason_of("javascript:alert(1)"), DropReason::Invalid);
}

#[test]
fn announced_set_orders_lan_first_and_caps() {
    let id = identity(0x91);
    let inputs = owned(&[
        "broker+wss://b.example/v1/broker",
        "direct:8.8.8.8:80",
        "direct:1.1.1.1:80",
        "direct:192.168.1.9:80",
        "wss://relay.example.com/v1/relay",
        "wss://relay2.example.com/v1/relay",
        "wss://relay3.example.com/v1/relay",
        "overlay://overlay.example:80",
        "overlay://100.64.0.1:80",
        "iroh://n1",
        "iroh://n2",
    ]);
    let announced = PairingManager::announced_route_set(&id, &inputs);
    let (set, dropped) = (announced.routes(), announced.dropped());
    assert_eq!(
        set,
        owned(&[
            "direct:192.168.1.9:80",
            "direct:8.8.8.8:80",
            "overlay://100.64.0.1:80",
            "overlay://overlay.example:80",
            "iroh://n1",
            "iroh://n2",
        ])
    );
    let reasons: Vec<(&str, DropReason)> = dropped
        .iter()
        .map(|d| (d.hint.as_str(), d.reason))
        .collect();
    assert_eq!(
        reasons,
        vec![
            ("direct:1.1.1.1:80", DropReason::ProviderCap),
            ("wss://relay.example.com/v1/relay", DropReason::CountCap),
            ("wss://relay2.example.com/v1/relay", DropReason::CountCap),
            ("wss://relay3.example.com/v1/relay", DropReason::ProviderCap),
            ("broker+wss://b.example/v1/broker", DropReason::CountCap),
        ]
    );
}

#[test]
fn announced_set_keeps_ipv4_overlay_first() {
    let id = identity(0x92);
    let inputs = owned(&[
        "overlay://[fd7a:115c:a1e0::5]:9200",
        "overlay://[fd12::5]:9200",
        "overlay://100.101.1.2:9200",
        "direct:8.8.8.8:80",
        "direct:[fd34::9]:9200",
    ]);
    let announced = PairingManager::announced_route_set(&id, &inputs);
    assert_eq!(
        announced.routes(),
        owned(&[
            "direct:[fd34::9]:9200",
            "direct:8.8.8.8:80",
            "overlay://100.101.1.2:9200",
            "overlay://[fd7a:115c:a1e0::5]:9200",
        ]),
        "LAN-first applies to Direct only; overlay keeps IPv4 first"
    );
    assert_eq!(
        announced
            .dropped()
            .iter()
            .map(|d| (d.hint.as_str(), d.reason))
            .collect::<Vec<_>>(),
        vec![("overlay://[fd12::5]:9200", DropReason::ProviderCap)]
    );
}

fn is_subsequence(sub: &[String], full: &[String]) -> bool {
    let mut it = full.iter();
    sub.iter().all(|s| it.any(|f| f == s))
}

#[test]
fn builder_selects_kind_and_issues_a_subset_of_the_announced_set() {
    let id = identity(0xA1);
    let inputs = owned(&[
        "direct:8.8.8.8:80",
        "direct:1.1.1.1:80",
        "direct:192.168.1.9:80",
        "wss://relay.example.com/v1/relay",
    ]);
    let set = PairingManager::announced_route_set(&id, &inputs)
        .routes()
        .to_vec();
    assert_eq!(set[0], "direct:192.168.1.9:80");
    let announced = published(4, &set);
    for (host, kinds) in [
        (
            "Studio".to_owned(),
            [
                None,
                Some(PairingCodeKind::Lan2Group),
                Some(PairingCodeKind::Remote3Group),
            ],
        ),
        (
            "x".repeat(680),
            [
                None,
                Some(PairingCodeKind::Lan2Group),
                Some(PairingCodeKind::Remote3Group),
            ],
        ),
    ] {
        for kind in kinds {
            let mut mgr = PairingManager::new(PairingConfig::default());
            let issued = mgr
                .issue_pairing_uri(
                    &id,
                    &host,
                    &announced,
                    IssueOptions {
                        requested_kind: kind,
                        sign_routes: true,
                    },
                    NOW_UNIX,
                )
                .unwrap();
            assert!(issued.uri_len <= MAX_PAIRING_URI_LEN);
            assert!(is_subsequence(&issued.parsed.endpoints, &set), "{kind:?}");
            match kind {
                Some(PairingCodeKind::Lan2Group) => {
                    assert_eq!(issued.code_kind, PairingCodeKind::Lan2Group);
                    assert_eq!(issued.parsed.endpoints, owned(&["direct:192.168.1.9:80"]));
                    assert!(
                        issued
                            .dropped
                            .iter()
                            .any(|d| d.reason == DropReason::LanCodeRemoteHint)
                    );
                    assert_eq!(issued.parsed.relay_pub, None);
                }
                Some(PairingCodeKind::Remote3Group) => {
                    assert_eq!(issued.code_kind, PairingCodeKind::Remote3Group);
                }
                None => {
                    let lan_only =
                        !issued.parsed.endpoints.is_empty()
                            && issued.parsed.endpoints.iter().all(|h| {
                                h == "direct:192.168.1.9:80" || h.starts_with("direct:127.")
                            });
                    let expected = if lan_only {
                        PairingCodeKind::Lan2Group
                    } else {
                        PairingCodeKind::Remote3Group
                    };
                    assert_eq!(issued.code_kind, expected);
                }
            }
            assert_eq!(
                PairingCodeKind::from_code(&issued.parsed.code).unwrap(),
                issued.code_kind
            );
        }
    }

    let lan_only = published(2, &owned(&["direct:192.168.1.9:80", "direct:127.0.0.1:80"]));
    let mut mgr = PairingManager::new(PairingConfig::default());
    let issued = mgr
        .issue_pairing_uri(&id, "Studio", &lan_only, IssueOptions::default(), NOW_UNIX)
        .unwrap();
    assert_eq!(issued.code_kind, PairingCodeKind::Lan2Group);

    let empty = published(1, &[]);
    let issued = mgr
        .issue_pairing_uri(&id, "Studio", &empty, IssueOptions::default(), NOW_UNIX)
        .unwrap();
    assert_eq!(issued.code_kind, PairingCodeKind::Remote3Group);
    assert!(issued.parsed.endpoints.is_empty());

    let unsigned = mgr
        .issue_pairing_uri(
            &id,
            "Studio",
            &announced,
            IssueOptions {
                requested_kind: None,
                sign_routes: false,
            },
            NOW_UNIX,
        )
        .unwrap();
    assert!(!unsigned.uri.contains("&rq=") && !unsigned.uri.contains("&rs="));
    assert_eq!(unsigned.route_seq, None);
    assert!(!unsigned.parsed.is_signed());
}

#[test]
fn builder_size_trim_counts_signature_bytes() {
    let id = identity(0xB1);
    let set = owned(&SIX);
    let announced = published(123_456, &set);
    let issue = |host: &str, sign_routes: bool| {
        let mut mgr = PairingManager::new(PairingConfig::default());
        let r = mgr.issue_pairing_uri(
            &id,
            host,
            &announced,
            IssueOptions {
                requested_kind: None,
                sign_routes,
            },
            NOW_UNIX,
        );
        (r, mgr.live_code_count(NOW_UNIX))
    };
    let full_unsigned = issue("Studio", false).0.unwrap().uri_len;
    let full_signed = issue("Studio", true).0.unwrap().uri_len;
    assert_eq!(full_signed, full_unsigned + "&rq=123456".len() + 90);

    let pad = MAX_PAIRING_URI_LEN - full_unsigned;
    let host = "S".repeat("Studio".len() + pad);
    let (unsigned, _) = issue(&host, false);
    let unsigned = unsigned.unwrap();
    assert_eq!(unsigned.uri_len, MAX_PAIRING_URI_LEN);
    assert!(unsigned.dropped.is_empty());
    let (signed, _) = issue(&host, true);
    let signed = signed.unwrap();
    assert!(signed.uri_len <= MAX_PAIRING_URI_LEN);
    assert!(!signed.dropped.is_empty());
    assert!(
        signed
            .dropped
            .iter()
            .all(|d| d.reason == DropReason::SizeCap)
    );
    let kept = &signed.parsed.endpoints;
    assert_eq!(kept.as_slice(), &set[..kept.len()]);
    let dropped: Vec<String> = signed.dropped.iter().map(|d| d.hint.clone()).collect();
    let mut tail = set[kept.len()..].to_vec();
    tail.reverse();
    assert_eq!(dropped, tail);
    assert!(matches!(
        signed
            .parsed
            .verify_route_statement(id.signing_key().public_key()),
        RouteCheck::Verified(_)
    ));

    let (err, live) = issue(&"S".repeat(1_000), true);
    assert_eq!(
        err.unwrap_err(),
        CoreError::InvalidPairingUri("host name too long".into())
    );
    assert_eq!(live, 0);
    let (err, live) = issue("", true);
    assert!(is_invalid_uri(err));
    assert_eq!(live, 0);

    let mut mgr = PairingManager::new(PairingConfig::default());
    for _ in 0..4 {
        mgr.issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
            .unwrap();
    }
    assert_eq!(
        mgr.issue_pairing_uri(&id, "Studio", &announced, IssueOptions::default(), NOW_UNIX),
        Err(CoreError::ProtocolViolation("too many live pairing codes"))
    );
}

#[test]
fn qr_version_thresholds() {
    assert_eq!(qr_version_m(1), 1);
    assert_eq!(qr_version_m(711), 21);
    assert_eq!(qr_version_m(712), 22);
    assert_eq!(qr_version_m(997), 25);
    assert_eq!(qr_version_m(MAX_PAIRING_URI_LEN), 26);
}

#[test]
fn local_route_digest_matches_route_set_body() {
    let id = identity(0xC1);
    let routes = owned(&SIX);
    let state = published(3, &routes);
    let set = RouteSet::sign(&id, 3, NOW_UNIX, routes.clone()).unwrap();
    let payload = set.encode();
    let body_routes = &payload[81..payload.len() - tendril_core::crypto::HYBRID_SIG_LEN];
    use sha2::Digest as _;
    let expected: [u8; 32] = sha2::Sha256::digest(body_routes).into();
    assert_eq!(*state.digest(), expected);
    assert_ne!(LocalRouteState::digest_of(&routes[..5]), *state.digest());
}

fn write_bytes(actions: &[PairAction]) -> Vec<u8> {
    actions
        .iter()
        .find_map(|a| match a {
            PairAction::WriteBytes(b) => Some(b.clone()),
            _ => None,
        })
        .expect("WriteBytes action")
}

#[test]
fn v1_deferred_claim_commits_on_demand() {
    let host = identity(0xD1);
    let dev = identity(0xD3);
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let uri = PairingUri::parse(&base_uri(&host, &code, &[]).try_encode().unwrap()).unwrap();
    let mut roster = Roster::new();
    let mut init = PairingInitiator::new(
        &dev,
        "Phone",
        "mobile",
        &code,
        Some(uri.to_pinned_host()),
        None,
    )
    .unwrap()
    .with_deferred_claim();
    let mut resp = PairingResponder::new(&host, PairingPathKind::Remote, None).unwrap();

    assert_eq!(
        init.commit_claim(),
        Err(CoreError::NotReady(
            "pairing initiator is not awaiting commit"
        ))
    );
    assert!(!init.is_awaiting_commit());
    assert!(init.verified_host().is_none());

    let m1 = write_bytes(&init.start().unwrap());
    let m2 = write_bytes(
        &resp
            .feed_bytes(&m1, NOW_UNIX, &mut mgr, &mut roster)
            .unwrap(),
    );
    let actions = init.feed_bytes(&m2).unwrap();
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], PairAction::SasReady { .. }));
    assert!(init.is_awaiting_commit());
    let vh = init.verified_host().unwrap();
    assert_eq!(&vh.static_pub, host.static_key().public_bytes());
    assert_eq!(&vh.signing_pub, host.signing_key().public_key());
    assert_eq!(vh.host_id, host.host_id());
    assert_eq!(vh.rotation_seq, 0);
    uri.check_relay_pub(&vh.signing_pub).unwrap();
    assert_eq!(mgr.live_code_count(NOW_UNIX), 1);

    let m3 = write_bytes(&init.commit_claim().unwrap());
    assert!(!init.is_awaiting_commit());
    assert_eq!(
        init.commit_claim(),
        Err(CoreError::NotReady(
            "pairing initiator is not awaiting commit"
        ))
    );
    let resp_actions = resp
        .feed_bytes(&m3, NOW_UNIX, &mut mgr, &mut roster)
        .unwrap();
    assert_eq!(mgr.live_code_count(NOW_UNIX), 0);
    let done = init.feed_bytes(&write_bytes(&resp_actions)).unwrap();
    assert!(done.iter().any(|a| matches!(
        a,
        PairAction::Completed(PairOutcome::InitiatorPending {
            host_pin_verified: true,
            ..
        })
    )));
}

#[test]
fn v1_claim_without_deferral_is_unchanged() {
    let host = identity(0xE1);
    let dev = identity(0xE3);
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Lan2Group, NOW_UNIX)
        .unwrap();
    let mut roster = Roster::new();
    let mut init = PairingInitiator::new(&dev, "Phone", "mobile", &code, None, None).unwrap();
    let mut resp = PairingResponder::new(&host, PairingPathKind::Lan, None).unwrap();
    let m1 = write_bytes(&init.start().unwrap());
    let m2 = write_bytes(
        &resp
            .feed_bytes(&m1, NOW_UNIX, &mut mgr, &mut roster)
            .unwrap(),
    );
    let actions = init.feed_bytes(&m2).unwrap();
    assert_eq!(actions.len(), 2);
    assert!(matches!(actions[0], PairAction::SasReady { .. }));
    assert!(matches!(actions[1], PairAction::WriteBytes(_)));
    assert!(!init.is_awaiting_commit());
    assert!(init.verified_host().is_some());
    assert_eq!(
        init.commit_claim(),
        Err(CoreError::NotReady(
            "pairing initiator is not awaiting commit"
        ))
    );
}

#[test]
fn deferred_initiator_rejects_frames_before_commit() {
    let host = identity(0xF1);
    let dev = identity(0xF3);
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let mut roster = Roster::new();
    let mut init = PairingInitiator::new(&dev, "Phone", "mobile", &code, None, None)
        .unwrap()
        .with_deferred_claim();
    let mut resp = PairingResponder::new(&host, PairingPathKind::Remote, None).unwrap();
    let m1 = write_bytes(&init.start().unwrap());
    let m2 = write_bytes(
        &resp
            .feed_bytes(&m1, NOW_UNIX, &mut mgr, &mut roster)
            .unwrap(),
    );
    init.feed_bytes(&m2).unwrap();
    assert!(init.is_awaiting_commit());
    assert!(init.feed_bytes(&[0, 2, 0xAA, 0xBB]).is_err());
    assert!(!init.is_awaiting_commit());
    assert!(init.commit_claim().is_err());
    assert_eq!(mgr.live_code_count(NOW_UNIX), 1);
}

/// A v1 pairing bound to a URI, run until the initiator has `msg2` in hand.
struct BoundV1 {
    init: PairingInitiator,
    resp: PairingResponder,
    mgr: PairingManager,
    roster: Roster,
    m2: Vec<u8>,
}

fn bound_v1(host: &EndpointIdentity, uri: &str, deferred: bool) -> BoundV1 {
    let dev = identity(0xC3);
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let uri = PairingUri::parse(uri).unwrap();
    let mut init = PairingInitiator::new(&dev, "Phone", "mobile", &code, None, None)
        .unwrap()
        .with_pairing_uri(&uri);
    if deferred {
        init = init.with_deferred_claim();
    }
    let mut resp = PairingResponder::new(host, PairingPathKind::Remote, None).unwrap();
    let mut roster = Roster::new();
    let m1 = write_bytes(&init.start().unwrap());
    let m2 = write_bytes(
        &resp
            .feed_bytes(&m1, NOW_UNIX, &mut mgr, &mut roster)
            .unwrap(),
    );
    BoundV1 {
        init,
        resp,
        mgr,
        roster,
        m2,
    }
}

fn rp_mismatch_uri(host: &EndpointIdentity) -> String {
    let mut uri = base_uri(host, CODE3, &["wss://relay.example.com/v1/relay"]);
    uri.relay_pub = Some(*identity(0xC5).signing_key().ed25519_public_bytes());
    uri.try_encode().unwrap()
}

fn tampered_rs_uri(host: &EndpointIdentity) -> String {
    signed_fixture(host).replacen("192.168.1.20", "192.168.1.21", 1)
}

const NOT_AWAITING: CoreError = CoreError::NotReady("pairing initiator is not awaiting commit");

fn assert_refused(p: &mut BoundV1, expected: &CoreError) {
    assert_eq!(p.init.feed_bytes(&p.m2).as_ref().err(), Some(expected));
    assert!(p.init.route_verdict().is_some());
    assert!(!p.init.is_awaiting_commit());
    assert_eq!(p.init.commit_claim(), Err(NOT_AWAITING));
    assert!(matches!(
        p.init.feed_bytes(&p.m2),
        Err(CoreError::SessionClosed { .. })
    ));
    assert_eq!(p.mgr.live_code_count(NOW_UNIX), 1);
}

#[test]
fn v1_uri_bound_initiator_refuses_msg3_on_rp_mismatch() {
    let host = identity(0xC1);
    let uri = rp_mismatch_uri(&host);

    let mut p = bound_v1(&host, &uri, true);
    let actions = p.init.feed_bytes(&p.m2).unwrap();
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], PairAction::SasReady { .. }));
    assert!(p.init.is_awaiting_commit());
    assert!(p.init.verified_host().is_some());
    let verdict = p.init.route_verdict().unwrap();
    assert!(!verdict.relay_pub_ok());
    assert_eq!(verdict.committable(), Err(CoreError::HostKeyUnverified));
    assert_eq!(p.init.commit_claim(), Err(CoreError::HostKeyUnverified));
    assert!(!p.init.is_awaiting_commit());
    assert_eq!(p.init.commit_claim(), Err(NOT_AWAITING));
    assert_eq!(p.mgr.live_code_count(NOW_UNIX), 1);

    let mut p = bound_v1(&host, &uri, false);
    assert_refused(&mut p, &CoreError::HostKeyUnverified);
}

#[test]
fn v1_uri_bound_initiator_refuses_msg3_on_invalid_rs() {
    let host = identity(0xC1);
    let uri = tampered_rs_uri(&host);
    let invalid = CoreError::InvalidPairingUri("route statement does not verify".into());

    let mut p = bound_v1(&host, &uri, true);
    p.init.feed_bytes(&p.m2).unwrap();
    assert!(p.init.is_awaiting_commit());
    let verdict = p.init.route_verdict().unwrap();
    assert!(verdict.relay_pub_ok());
    assert_eq!(verdict.route_check(), &RouteCheck::Invalid);
    assert_eq!(p.init.commit_claim(), Err(invalid.clone()));
    assert!(!p.init.is_awaiting_commit());
    assert_eq!(p.init.commit_claim(), Err(NOT_AWAITING));
    assert_eq!(p.mgr.live_code_count(NOW_UNIX), 1);

    let mut p = bound_v1(&host, &uri, false);
    assert_refused(&mut p, &invalid);
}

#[test]
fn v1_uri_bound_initiator_commits_on_verified_and_rotated() {
    let host = identity(0xC1);
    let mut rotated_host = identity(0xC7);
    let rotated = sign(
        &rotated_host,
        &base_uri(&rotated_host, CODE3, &["direct:192.168.1.20:9100"]),
        5,
    );
    rotated_host
        .rotate(
            StaticKeypair::from_scalar([0xCB; 32]),
            SigningKeypair::from_seed([0xCC; 32]),
            NOW_UNIX,
        )
        .unwrap();
    for (responder, uri, label) in [
        (&host, signed_fixture(&host), "verified"),
        (&rotated_host, rotated, "route_key_rotated"),
    ] {
        for deferred in [true, false] {
            let mut p = bound_v1(responder, &uri, deferred);
            let mut actions = p.init.feed_bytes(&p.m2).unwrap();
            let verdict = p.init.route_verdict().unwrap();
            assert!(verdict.relay_pub_ok(), "{label}");
            assert_eq!(verdict.route_check().as_str(), label);
            assert_eq!(verdict.committable(), Ok(verdict.route_check()));
            if deferred {
                actions = p.init.commit_claim().unwrap();
            }
            let resp_actions = p
                .resp
                .feed_bytes(&write_bytes(&actions), NOW_UNIX, &mut p.mgr, &mut p.roster)
                .unwrap();
            let done = p.init.feed_bytes(&write_bytes(&resp_actions)).unwrap();
            assert!(
                done.iter().any(|a| matches!(
                    a,
                    PairAction::Completed(PairOutcome::InitiatorPending { .. })
                )),
                "{label} deferred={deferred}"
            );
            assert_eq!(
                p.init.route_verdict().unwrap().route_check().as_str(),
                label
            );
        }
    }
}

#[test]
fn route_binding_rejects_disagreeing_operator_key() {
    let host = identity(0xC1);
    let other = *identity(0xC5).signing_key().ed25519_public_bytes();
    let own = *host.signing_key().ed25519_public_bytes();
    let uri = PairingUri::parse(&signed_fixture(&host)).unwrap();
    assert_eq!(
        PairRouteBinding::new(Some(uri.clone()), Some(other)).err(),
        Some(CoreError::InvalidPairingUri(
            "operator relay key does not match the URI rp".into()
        ))
    );
    let agreeing = PairRouteBinding::new(Some(uri.clone()), Some(own)).unwrap();
    assert_eq!(agreeing.uri(), Some(&uri));
    let key = host.signing_key().public_key();
    assert!(agreeing.verdict(key).relay_pub_ok());
    assert!(matches!(
        agreeing.verdict(key).route_check(),
        RouteCheck::Verified(_)
    ));

    let operator_only = PairRouteBinding::new(None, Some(other)).unwrap();
    let verdict = operator_only.verdict(key);
    assert!(!verdict.relay_pub_ok());
    assert_eq!(
        verdict.route_check(),
        &RouteCheck::Unsigned(UnsignedReason::Absent)
    );
    assert_eq!(verdict.committable(), Err(CoreError::HostKeyUnverified));

    let unbound = PairRouteBinding::default().verdict(key);
    assert!(unbound.relay_pub_ok());
    assert_eq!(
        unbound.committable(),
        Ok(&RouteCheck::Unsigned(UnsignedReason::Absent))
    );

    let mut p = bound_v1(&host, &signed_fixture(&host), true);
    p.init
        .set_route_binding(PairRouteBinding::new(None, Some(other)).unwrap())
        .unwrap();
    p.init.feed_bytes(&p.m2).unwrap();
    assert_eq!(p.init.commit_claim(), Err(CoreError::HostKeyUnverified));
}

#[test]
fn set_route_binding_after_msg2_is_not_ready() {
    let host = identity(0xC1);
    let late = CoreError::NotReady("pairing route binding is set before msg2");
    let mut p = bound_v1(&host, &rp_mismatch_uri(&host), true);
    p.init
        .set_route_binding(PairRouteBinding::default())
        .unwrap();
    p.init.feed_bytes(&p.m2).unwrap();
    assert!(p.init.route_verdict().unwrap().relay_pub_ok());
    assert_eq!(
        p.init.set_route_binding(PairRouteBinding::default()),
        Err(late.clone())
    );
    let uri = PairingUri::parse(&rp_mismatch_uri(&host)).unwrap();
    assert_eq!(
        p.init
            .set_route_binding(PairRouteBinding::new(Some(uri), None).unwrap()),
        Err(late)
    );
    assert!(p.init.route_verdict().unwrap().relay_pub_ok());
    assert!(p.init.commit_claim().is_ok());
}

#[test]
fn v1_uri_binding_enforces_the_uri_host_pin() {
    let host = identity(0xC1);
    let unrelated = identity(0xC9);
    for uri in [
        signed_fixture(&unrelated),
        base_uri(&unrelated, CODE3, &["direct:192.168.1.20:9100"])
            .try_encode()
            .unwrap(),
    ] {
        for deferred in [true, false] {
            let mut p = bound_v1(&host, &uri, deferred);
            assert_eq!(
                p.init.feed_bytes(&p.m2).err(),
                Some(CoreError::HostKeyUnverified),
                "deferred={deferred}"
            );
            assert!(p.init.route_verdict().is_none());
            assert_eq!(p.init.commit_claim(), Err(NOT_AWAITING));
            assert_eq!(p.mgr.live_code_count(NOW_UNIX), 1);
        }
    }

    let mut p = bound_v1(&host, &signed_fixture(&host), false);
    let actions = p.init.feed_bytes(&p.m2).unwrap();
    let resp_actions = p
        .resp
        .feed_bytes(&write_bytes(&actions), NOW_UNIX, &mut p.mgr, &mut p.roster)
        .unwrap();
    let done = p.init.feed_bytes(&write_bytes(&resp_actions)).unwrap();
    assert!(done.iter().any(|a| matches!(
        a,
        PairAction::Completed(PairOutcome::InitiatorPending {
            host_pin_verified: true,
            ..
        })
    )));
}

/// Runs a URI-bound, non-deferred v1 pairing with `pin` to completion and returns whether the
/// outcome reports a verified host pin.
fn pair_with_pin(host: &EndpointIdentity, pin: Option<PinnedHost>, uri: &PairingUri) -> bool {
    let dev = identity(0xC3);
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let mut init = PairingInitiator::new(&dev, "Phone", "mobile", &code, pin, None)
        .unwrap()
        .with_pairing_uri(uri);
    let mut resp = PairingResponder::new(host, PairingPathKind::Remote, None).unwrap();
    let mut roster = Roster::new();
    let m1 = write_bytes(&init.start().unwrap());
    let m2 = write_bytes(
        &resp
            .feed_bytes(&m1, NOW_UNIX, &mut mgr, &mut roster)
            .unwrap(),
    );
    let m3 = write_bytes(&init.feed_bytes(&m2).unwrap());
    let m4 = write_bytes(
        &resp
            .feed_bytes(&m3, NOW_UNIX, &mut mgr, &mut roster)
            .unwrap(),
    );
    init.feed_bytes(&m4).unwrap().iter().any(|a| {
        matches!(
            a,
            PairAction::Completed(PairOutcome::InitiatorPending {
                host_pin_verified: true,
                ..
            })
        )
    })
}

fn full_pin(host: &EndpointIdentity, host_id: Option<&str>, seq: u64) -> PinnedHost {
    PinnedHost::with_full_key(
        host_id.map(ToOwned::to_owned),
        *host.static_key().public_bytes(),
        host.signing_key().public_key().clone(),
        seq,
    )
}

#[test]
fn v1_uri_binding_agrees_with_an_equivalent_pin() {
    let host = identity(0xC1);
    let uri = PairingUri::parse(&signed_fixture(&host)).unwrap();
    assert!(pair_with_pin(
        &host,
        Some(full_pin(&host, Some(host.host_id()), 0)),
        &uri
    ));
    assert!(pair_with_pin(&host, Some(full_pin(&host, None, 0)), &uri));
    let mut no_id = base_uri(&host, CODE3, &SIGNED_HINTS);
    no_id.host_id = None;
    let no_id = PairingUri::parse(&sign(&host, &no_id, 5)).unwrap();
    assert!(pair_with_pin(
        &host,
        Some(full_pin(&host, Some(host.host_id()), 0)),
        &no_id
    ));

    // A legacy URI without `seq` issued after one rotation, and a caller pin at `seq = 1`.
    let mut rotated = identity(0xD5);
    rotated
        .rotate(
            StaticKeypair::from_scalar([0xD7; 32]),
            SigningKeypair::from_seed([0xD8; 32]),
            NOW_UNIX,
        )
        .unwrap();
    let legacy = PairingUri::new(
        "Studio",
        CODE3,
        *rotated.static_key().public_bytes(),
        rotated.signing_key().signing_pub_hash(),
        owned(&["direct:192.168.1.20:9100"]),
        Some(rotated.host_id().to_owned()),
        None,
    );
    let legacy = PairingUri::parse(&legacy.try_encode().unwrap()).unwrap();
    assert!(pair_with_pin(
        &rotated,
        Some(full_pin(&rotated, Some(rotated.host_id()), 1)),
        &legacy
    ));

    let dev = identity(0xC3);
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let other = identity(0xC9);
    let refused = [
        full_pin(&other, Some(host.host_id()), 0),
        PinnedHost {
            static_pub: *other.static_key().public_bytes(),
            ..full_pin(&host, None, 0)
        },
        PinnedHost::with_hash(
            None,
            *host.static_key().public_bytes(),
            other.signing_key().signing_pub_hash(),
            0,
        ),
        full_pin(&host, Some("another-host"), 0),
        full_pin(&host, Some(host.host_id()), 1),
    ];
    for pin in refused {
        let mut init =
            PairingInitiator::new(&dev, "Phone", "mobile", &code, Some(pin.clone()), None).unwrap();
        assert_eq!(
            init.set_route_binding(PairRouteBinding::new(Some(uri.clone()), None).unwrap()),
            Err(CoreError::InvalidPairingUri(
                "pairing URI does not match the pinned host".into()
            )),
            "{pin:?}"
        );
    }
}

#[test]
fn m2m_uri_binding_agrees_with_its_full_key_pin() {
    let host = identity(0xC1);
    let dev = identity(0xC3);
    let uri = PairingUri::parse(&signed_fixture(&host)).unwrap();
    let token = mint_enrollment_token(
        &host,
        host.host_id(),
        Some(&dev.device_id()),
        NOW_UNIX,
        900,
        [0xA1; 16],
    )
    .unwrap();
    let mut init = PairingInitiator::new_m2m(
        &dev,
        "runner",
        "machine",
        token,
        full_pin(&host, Some(host.host_id()), 0),
        None,
    )
    .unwrap();
    init.set_route_binding(PairRouteBinding::new(Some(uri), None).unwrap())
        .unwrap();
    let other = PairingUri::parse(&signed_fixture(&identity(0xC9))).unwrap();
    assert_eq!(
        init.set_route_binding(PairRouteBinding::new(Some(other), None).unwrap()),
        Err(CoreError::InvalidPairingUri(
            "pairing URI does not match the pinned host".into()
        ))
    );
}

#[test]
fn v1_uri_binding_refuses_a_disagreeing_pin() {
    let host = identity(0xC1);
    let unrelated = identity(0xC9);
    let dev = identity(0xC3);
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let host_uri = PairingUri::parse(&signed_fixture(&host)).unwrap();
    let other_uri = PairingUri::parse(&signed_fixture(&unrelated)).unwrap();
    let pinned = || {
        PairingInitiator::new(
            &dev,
            "Phone",
            "mobile",
            &code,
            Some(host_uri.to_pinned_host()),
            None,
        )
        .unwrap()
    };

    let mut agreeing = pinned();
    agreeing
        .set_route_binding(PairRouteBinding::new(Some(host_uri.clone()), None).unwrap())
        .unwrap();
    let mut setter = pinned();
    assert_eq!(
        setter.set_route_binding(PairRouteBinding::new(Some(other_uri.clone()), None).unwrap()),
        Err(CoreError::InvalidPairingUri(
            "pairing URI does not match the pinned host".into()
        ))
    );

    for deferred in [true, false] {
        let mut init = pinned().with_pairing_uri(&other_uri);
        if deferred {
            init = init.with_deferred_claim();
        }
        let mut resp = PairingResponder::new(&host, PairingPathKind::Remote, None).unwrap();
        let mut roster = Roster::new();
        let m1 = write_bytes(&init.start().unwrap());
        let m2 = write_bytes(
            &resp
                .feed_bytes(&m1, NOW_UNIX, &mut mgr, &mut roster)
                .unwrap(),
        );
        assert_eq!(
            init.feed_bytes(&m2).err(),
            Some(CoreError::HostKeyUnverified),
            "deferred={deferred}"
        );
        assert!(init.route_verdict().is_none());
    }
    assert_eq!(mgr.live_code_count(NOW_UNIX), 1);
}

#[test]
fn announced_set_checks_iroh_nested_destinations() {
    let id = identity(0xE1);
    let blocked = [
        "iroh://n1?addr=240.0.0.1:4433",
        "iroh://n2?addr=255.255.255.255:4433",
        "iroh://n3?addr=0.1.2.3:4433",
        "iroh://n4?relay=https://0.1.2.3/",
        "iroh://n5?relay=https://240.0.0.9:443/",
        "iroh://n6?addr=192.168.1.4:4433&relay=https://[::ffff:255.255.255.255]/",
        // Noncanonical numeric hosts, blocked once the URL parser normalizes them.
        "iroh://n8?relay=https://0xf0.1/",
        "iroh://n9?relay=https://4294967295/",
        "iroh://n10?relay=https://0.0x10.0.1:443/",
        "wss://0xff.1/v1/relay",
    ];
    let ok = "iroh://n7?relay=https://iroh.example&addr=192.168.1.4:4433";
    let mut inputs = owned(&blocked);
    inputs.push(ok.to_owned());
    let announced = PairingManager::announced_route_set(&id, &inputs);
    assert_eq!(announced.routes(), owned(&[ok]).as_slice());
    for hint in blocked {
        assert!(
            announced
                .dropped()
                .iter()
                .any(|d| d.hint == hint && d.reason == DropReason::BlockedAddress),
            "{hint}: {:?}",
            announced.dropped()
        );
    }
}

#[test]
fn local_route_state_comes_only_from_a_published_set() {
    let id = identity(0xE3);
    let mut roster = Roster::new();
    let first = PairingManager::announced_route_set(
        &id,
        &owned(&["direct:192.168.1.9:80", "wss://relay.example.com/v1/relay"]),
    );
    let state = roster.bump_local_routes(&first, NOW_UNIX).unwrap();
    assert_eq!(state.seq(), 1);
    assert_eq!(state.routes(), first.routes());
    let mut mgr = PairingManager::new(PairingConfig::default());
    let issued = mgr
        .issue_pairing_uri(&id, "Studio", &state, IssueOptions::default(), NOW_UNIX)
        .unwrap();
    assert_eq!(issued.route_seq, Some(1));
    assert!(is_subsequence(&issued.parsed.endpoints, state.routes()));

    let reloaded: Roster = serde_json::from_str(&serde_json::to_string(&roster).unwrap()).unwrap();
    assert_eq!(reloaded.local_routes(), Some(&state));

    let two = owned(&["direct:192.168.1.9:80", "direct:192.168.1.10:80"]);
    assert!(roster_with_local_routes(1, &two).is_ok());
    assert!(roster_with_local_routes(0, &two).is_err());
    assert!(roster_with_local_routes(1 << 53, &two).is_err());
    let mut over_cap = two.clone();
    over_cap.push("direct:192.168.1.11:80".into());
    assert!(roster_with_local_routes(2, &over_cap).is_err());
    for bad in [
        "192.168.1.9:80",
        "local:/run/t.sock",
        "direct:255.255.255.255:80",
        "iroh://n1?addr=240.0.0.1:4433",
        "wss://relay.example.com/v1/relay#abc",
        "direct:host.example:80",
    ] {
        assert!(
            roster_with_local_routes(2, &owned(&[bad])).is_err(),
            "{bad}"
        );
    }
    let dup = owned(&["direct:192.168.1.9:80", "direct:192.168.1.9:80"]);
    assert!(roster_with_local_routes(2, &dup).is_err());
    let tampered: Result<Roster, _> = serde_json::from_value(serde_json::json!({
        "entries": {},
        "crls": {},
        "local_routes": {
            "seq": 3,
            "issued_at": NOW_UNIX,
            "digest": LocalRouteState::digest_of(&two),
            "routes": ["direct:192.168.1.9:80"],
        },
    }));
    assert!(tampered.is_err());
}

#[test]
fn uri_and_name_errors_never_echo_their_input() {
    let base = "tendril://pair?v=1&host=Studio&code=TND-ABCD-EFGH-JKLM";
    for (uri, secret) in [
        (format!("{base}&a,b;s3cr3t=1"), "s3cr3t"),
        (format!("{base}&x%2Cy%3Bsecret,;=1"), "secret"),
        (format!("{base}&code=TND-WXYZ-WXYZ-WXYZ"), "WXYZ"),
    ] {
        let err = PairingUri::parse(&uri).unwrap_err().to_string();
        assert!(
            matches!(
                PairingUri::parse(&uri),
                Err(CoreError::InvalidPairingUri(_))
            ),
            "{err}"
        );
        assert!(!err.contains(secret), "{err}");
        assert!(!err.contains(",;") && !err.contains("a,b;"), "{err}");
    }
    let err = "s3cr3t-policy"
        .parse::<RoutePolicy>()
        .unwrap_err()
        .to_string();
    assert!(!err.contains("s3cr3t"), "{err}");
    let err = "x's3cr3t"
        .parse::<PairingCodeKind>()
        .unwrap_err()
        .to_string();
    assert!(!err.contains("s3cr3t"), "{err}");
    assert_eq!(
        "LAN".parse::<PairingCodeKind>().unwrap(),
        PairingCodeKind::Lan2Group
    );
    assert_eq!(
        "remote".parse::<PairingCodeKind>().unwrap(),
        PairingCodeKind::Remote3Group
    );
}

#[test]
fn dropped_hints_print_redacted() {
    let dropped = DroppedHint {
        hint: "wss://u:s3cret@relay.example/v1/relay?tok=x".into(),
        reason: DropReason::Duplicate,
    };
    assert_eq!(dropped.redacted_hint(), "wss://relay.example");
    assert!(
        dropped.hint.contains("s3cret"),
        "the raw hint stays for the operator"
    );
}

#[test]
fn url_hints_reject_non_canonical_ipv4_hosts() {
    for host in [
        "0xa9.254.169.254",
        "2852039166",
        "0251.0376.0.1",
        "169.254.1",
        "0xa9fea9fe",
    ] {
        for hint in [
            format!("wss://{host}/v1/relay"),
            format!("relay:wss://{host}/v1/relay"),
            format!("broker+wss://{host}/v1/relay"),
        ] {
            assert!(
                !is_valid_pairing_endpoint_hint(&hint),
                "{hint} must be rejected at parse time"
            );
        }
    }
    assert!(!is_valid_pairing_endpoint_hint(
        "wss://169.254.169.254/v1/relay"
    ));
    assert!(is_valid_pairing_endpoint_hint(
        "wss://relay.example.com/v1/relay"
    ));
    assert!(is_valid_pairing_endpoint_hint("wss://203.0.113.7/v1/relay"));
}

#[test]
fn debug_output_redacts_the_pairing_code() {
    let id = identity(0x31);
    let uri = PairingUri::parse(&raw(&id, CODE3, "")).expect("uri");
    let shown = format!("{uri:?}");
    assert!(!shown.contains(CODE3), "{shown}");
    assert!(!shown.contains("ABCD-EFGH"), "{shown}");
    let expectation = RouteExpectation::for_connect("h", Some(&raw(&id, CODE3, "")), None, None)
        .expect("expectation");
    let shown = format!("{expectation:?}");
    assert!(!shown.contains(CODE3), "{shown}");
    assert!(!shown.contains("ABCD-EFGH"), "{shown}");
}

#[test]
fn wt_endpoint_hints_validate_classify_announce_and_gate_lan2_codes() {
    let valid_hash = b64url_encode(&[0xABu8; 32]);
    assert_eq!(valid_hash.len(), 43);

    for good in [
        format!("wt://192.168.1.10:4433?certhash={valid_hash}"),
        format!("wt://127.0.0.1:4433/tendril?certhash={valid_hash}"),
        format!("wt://[fd00::1]:4433?certhash={valid_hash}"),
        "wt://peer.example:4433".to_owned(),
        "wt://peer.example:443/wt".to_owned(),
    ] {
        assert_eq!(
            classify_endpoint_hint(&good),
            Ok(ProviderId::Direct),
            "{good}"
        );
        assert!(is_valid_pairing_endpoint_hint(&good), "{good}");
    }

    for bad in [
        "wt://192.168.1.10",
        "wt://192.168.1.10:0",
        "wt://192.168.1.10:4433?",
        "wt://192.168.1.10:4433?foo=bar",
        &format!("wt://192.168.1.10:4433?certhash={valid_hash}&extra=1"),
        &format!("wt://192.168.1.10:4433?certhash={}=", &valid_hash[..42]),
        "wt://192.168.1.10:4433?certhash=too_short",
        "wt://192.168.1.10:4433?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",
        // 43 chars with non-zero trailing padding bits in final sextet ('B' = 1)
        "wt://192.168.1.10:4433?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        "wt://user@192.168.1.10:4433",
        "wt://192.168.1.10:4433#frag",
        "wt://192.168.1.10:4433\\evil",
        "wt://0.0.0.0:4433",
        "wt://169.254.169.254:4433",
        "wt://0xa9.254.169.254:4433",
        "wt://224.0.0.1:4433",
        "wt://[fe80::1]:4433",
        "wt://metadata.google.internal:4433",
        "wt://.:4433",
        "wt://192.168.1.10:4433\n",
    ] {
        assert!(!is_valid_pairing_endpoint_hint(bad), "must reject {bad}");
        assert!(classify_endpoint_hint(bad).is_err(), "must reject {bad}");
    }

    let id = identity(0x41);
    let lan_wt = format!("wt://192.168.1.10:4433?certhash={valid_hash}");
    let lo_wt = format!("wt://[::1]:4433?certhash={valid_hash}");
    let pub_wt = format!("wt://203.0.113.5:4433?certhash={valid_hash}");
    let dns_wt = "wt://peer.example:4433".to_owned();

    // Auto code kind picks Lan2Group for LAN/loopback wt:// literals and Remote3Group for public/domain wt://.
    let mut roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());

    let lan_ann = PairingManager::announced_route_set(&id, &[lan_wt.clone(), lo_wt.clone()]);
    assert_eq!(lan_ann.routes(), &[lan_wt.clone(), lo_wt.clone()]);
    let lan_state = roster.bump_local_routes(&lan_ann, NOW_UNIX).unwrap();
    let lan_issued = mgr
        .issue_pairing_uri(&id, "Studio", &lan_state, IssueOptions::default(), NOW_UNIX)
        .unwrap();
    assert_eq!(lan_issued.code_kind, PairingCodeKind::Lan2Group);
    assert_eq!(lan_issued.parsed.endpoints, vec![lan_wt.clone(), lo_wt]);

    let pub_ann = PairingManager::announced_route_set(&id, std::slice::from_ref(&pub_wt));
    assert_eq!(pub_ann.routes(), std::slice::from_ref(&pub_wt));
    let pub_state = roster.bump_local_routes(&pub_ann, NOW_UNIX).unwrap();
    let pub_issued = mgr
        .issue_pairing_uri(&id, "Studio", &pub_state, IssueOptions::default(), NOW_UNIX)
        .unwrap();
    assert_eq!(pub_issued.code_kind, PairingCodeKind::Remote3Group);

    // Public or domain wt:// hints are rejected on Lan2Group pairing URIs.
    assert!(PairingUri::parse(&raw(&id, "TND-ABCD-EFGH", &format!("&ep={}", lan_wt))).is_ok());
    assert!(PairingUri::parse(&raw(&id, "TND-ABCD-EFGH", &format!("&ep={}", pub_wt))).is_err());
    assert!(PairingUri::parse(&raw(&id, "TND-ABCD-EFGH", &format!("&ep={}", dns_wt))).is_err());
}

#[test]
fn iroh_v2_hints_validate_reject_addr_and_never_commit() {
    use tendril_core::pairing::{is_v2_p2p_hint, is_valid_pairing_endpoint_hint};

    let v2 = "iroh://v2?relay=https://relay.example.com";
    let v2_bare = "iroh://v2";
    let v2_prefixed = "p2p:iroh://v2?relay=https://relay.example.com";
    assert!(is_v2_p2p_hint(v2));
    assert!(is_v2_p2p_hint(v2_bare));
    assert!(is_v2_p2p_hint(v2_prefixed));
    assert!(!is_v2_p2p_hint(
        "iroh://node1?relay=https://relay.example.com"
    ));

    assert!(is_valid_pairing_endpoint_hint(v2));
    assert!(is_valid_pairing_endpoint_hint(v2_bare));
    assert!(is_valid_pairing_endpoint_hint(v2_prefixed));
    assert_eq!(classify_endpoint_hint(v2), Ok(ProviderId::P2p));

    // Unsigned iroh://v2 must fail validation; ?addr= and empty query are rejected.
    for bad in [
        "iroh://v2?",
        "iroh://v2?addr=192.0.2.10:11204",
        "iroh://v2?relay=https://relay.example.com&addr=192.0.2.10:11204",
        "p2p:iroh://v2?addr=127.0.0.1:11204",
        "iroh://v2?relay=http://169.254.169.254",
    ] {
        assert!(!is_valid_pairing_endpoint_hint(bad), "must reject {bad}");
        assert!(classify_endpoint_hint(bad).is_err(), "must reject {bad}");
    }

    // Announced set keeps Direct ahead of P2p; persist plan keeps signed iroh://v2 out of committed routes.
    let id = identity(0x52);
    let ann = PairingManager::announced_route_set(
        &id,
        &[v2.to_owned(), "direct:192.168.1.9:9100".to_owned()],
    );
    assert_eq!(
        ann.routes(),
        &["direct:192.168.1.9:9100".to_owned(), v2.to_owned()]
    );
    let raw_uri = format!(
        "tendril://pair?v=1&host=Host&code=TND-ABCD-EFGH-JKLM&k={}&sh={}&ep=iroh%3A%2F%2Fv2%3Frelay%3Dhttps%3A%2F%2Frelay.example.com",
        b64url_encode(id.static_key().public_bytes()),
        b64url_encode(&id.signing_key().signing_pub_hash()),
    );
    let parsed = PairingUri::parse(&raw_uri).unwrap();
    assert_eq!(parsed.endpoints, vec![v2.to_owned()]);

    let plan = persistable_routes(
        &RouteCheck::Unsigned(UnsignedReason::Absent),
        "TND-ABCD-EFGH-JKLM",
        Some(v2),
        &PersistOpts {
            policy: RoutePolicy::AllSigned,
            save_committed: true,
            operator_endpoint: None,
        },
    );
    assert_eq!(plan.committed, None);
}
