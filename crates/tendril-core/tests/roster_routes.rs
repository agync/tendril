//! Roster routes, route metadata, announcements and Day-2 session authorization.

use tendril_core::crypto::{HybridSigningPublicKey, SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationList, RevocationListUnsigned, sign_crl};
use tendril_core::identity::{EndpointIdentity, sign_rotation};
use tendril_core::pairing::{
    IssueOptions, PairingCodeKind, PairingConfig, PairingManager, PairingUri, PersistOpts,
    PersistPlan, RouteCheck, RoutePolicy, VerifiedRouteStatement, persistable_routes,
    sign_route_statement,
};
use tendril_core::roster::{
    MAX_ROUTE_SET_FUTURE_SECS, OperatorEndpoint, PeerState, Roster, RouteMeta, RouteOrigin,
    RouteSetIgnored, RouteSetOutcome, RouteSource, StoredRoute, V2PeerSecrets,
};
use tendril_core::routes::{MAX_ROUTE_SEQ, RouteSet};

const NOW: u64 = 1_795_564_800;
const CODE3: &str = "TND-ABCD-EFGH-JKLM";

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
    )
}

fn owned(hints: &[&str]) -> Vec<String> {
    hints.iter().map(|h| (*h).to_owned()).collect()
}

/// A client roster holding an `Active` pin for `host`; returns the roster and the peer key.
fn client_of(host: &EndpointIdentity) -> (Roster, String) {
    let mut roster = Roster::new();
    let peer = host.host_id().to_owned();
    roster
        .insert_pinned_host(
            peer.clone(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    (roster, peer)
}

fn signed_uri_with_code(host: &EndpointIdentity, code: &str, hints: &[&str], rq: u64) -> String {
    let mut uri = PairingUri::new(
        "Studio",
        code,
        *host.static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        owned(hints),
        Some(host.host_id().to_owned()),
        Some(0),
    );
    if hints.iter().any(|h| h.contains("/v1/relay")) {
        uri.relay_pub = Some(*host.signing_key().ed25519_public_bytes());
    }
    let prefix = format!("{}&rq={rq}", uri.try_encode().unwrap());
    let sig = sign_route_statement(host, &prefix);
    format!("{prefix}&rs={}", b64url_encode(&sig))
}

fn check_for(host: &EndpointIdentity, uri: &str) -> RouteCheck {
    PairingUri::parse(uri)
        .unwrap()
        .verify_route_statement(host.signing_key().public_key())
}

fn statement(host: &EndpointIdentity, hints: &[&str], rq: u64) -> VerifiedRouteStatement {
    match check_for(host, &signed_uri_with_code(host, CODE3, hints, rq)) {
        RouteCheck::Verified(s) => s,
        other => panic!("statement must verify: {other:?}"),
    }
}

fn all_signed() -> PersistOpts {
    PersistOpts::default()
}

fn plan(host: &EndpointIdentity, hints: &[&str], rq: u64, opts: &PersistOpts) -> PersistPlan {
    let check = RouteCheck::Verified(statement(host, hints, rq));
    persistable_routes(&check, CODE3, None, opts)
}

fn route_set(host: &EndpointIdentity, seq: u64, routes: &[&str]) -> RouteSet {
    RouteSet::sign(host, seq, NOW, owned(routes)).unwrap()
}

fn hints_of(roster: &Roster, peer: &str, source: RouteSource) -> Vec<String> {
    roster
        .get(peer)
        .unwrap()
        .routes_from(source)
        .map(str::to_owned)
        .collect()
}

fn meta(roster: &Roster, peer: &str) -> Option<RouteMeta> {
    roster.get(peer).unwrap().route_meta
}

fn op(hint: &str) -> OperatorEndpoint {
    OperatorEndpoint {
        hint: hint.into(),
        relay_key: None,
    }
}

fn is_invalid<T: std::fmt::Debug>(r: Result<T, CoreError>) -> bool {
    matches!(r, Err(CoreError::InvalidPairingUri(_)))
}

const A: [&str; 2] = [
    "direct:192.168.1.20:9100",
    "wss://relay.example.com/v1/relay",
];
const B: [&str; 2] = ["direct:192.168.1.30:9100", "overlay://100.64.0.10:9100"];

#[test]
fn apply_route_announcement_runs_checks_in_order() {
    let host = identity(0x11);
    let other = identity(0x21);
    let (mut roster, peer) = client_of(&host);
    let set1 = route_set(&host, 1, &A);
    let apply = |r: &mut Roster, p: &str, s: &RouteSet, now: u64| {
        r.apply_route_announcement(p, s, now).unwrap()
    };
    let ignored = RouteSetOutcome::Ignored;

    assert_eq!(
        apply(&mut roster.clone(), "unknown", &set1, NOW),
        ignored(RouteSetIgnored::PeerInactive)
    );
    let mut pending = Roster::new();
    pending
        .record_pending_host(
            peer.clone(),
            "Host".into(),
            *host.static_key().public_bytes(),
            host.signing_key().public_key().clone(),
            0,
            "SAS".into(),
            vec![],
        )
        .unwrap();
    assert_eq!(
        apply(&mut pending, &peer, &set1, NOW),
        ignored(RouteSetIgnored::PeerInactive)
    );
    let mut revoked = roster.clone();
    revoked.revoke_peer(&peer).unwrap();
    assert_eq!(
        apply(&mut revoked, &peer, &set1, NOW),
        ignored(RouteSetIgnored::PeerInactive)
    );
    let (mut crl_revoked, _) = crl_revoked_but_active(&host);
    assert_eq!(
        apply(&mut crl_revoked, &peer, &set1, NOW),
        ignored(RouteSetIgnored::PeerInactive)
    );

    let foreign = route_set(&other, 1, &A);
    assert_eq!(
        apply(&mut roster, &peer, &foreign, NOW),
        ignored(RouteSetIgnored::KeyMismatch)
    );
    let mut wrong_sh = set1.clone();
    wrong_sh.sh[0] ^= 1;
    assert_eq!(
        apply(&mut roster, &peer, &wrong_sh, NOW),
        ignored(RouteSetIgnored::KeyMismatch)
    );
    let mut tampered = set1.clone();
    tampered.routes.pop();
    assert_eq!(
        apply(&mut roster, &peer, &tampered, NOW),
        ignored(RouteSetIgnored::BadSignature)
    );
    let future = RouteSet::sign(&host, 1, NOW + MAX_ROUTE_SET_FUTURE_SECS + 1, owned(&A)).unwrap();
    assert_eq!(
        apply(&mut roster, &peer, &future, NOW),
        ignored(RouteSetIgnored::FutureIssuedAt)
    );
    assert_eq!(meta(&roster, &peer), None);
    assert!(roster.get(&peer).unwrap().routes.is_empty());

    let edge = RouteSet::sign(&host, 2, NOW + MAX_ROUTE_SET_FUTURE_SECS, owned(&A)).unwrap();
    assert_eq!(
        apply(&mut roster.clone(), &peer, &edge, NOW),
        RouteSetOutcome::Applied {
            added: owned(&A),
            removed: vec![]
        }
    );

    // Operator and committed records hold the same hint as the announcement.
    roster.set_routes(&peer, vec![op(A[0])]).unwrap();
    let mut committed = PersistPlan::default();
    committed.committed = Some(A[1].into());
    roster.merge_pair_plan(&peer, &committed).unwrap();

    assert_eq!(
        apply(&mut roster, &peer, &set1, NOW),
        RouteSetOutcome::Applied {
            added: owned(&A),
            removed: vec![]
        }
    );
    assert_eq!(
        meta(&roster, &peer),
        Some(RouteMeta {
            seq: 1,
            issued_at: Some(NOW),
            origin: RouteOrigin::Session
        })
    );
    // Replay and equal sequence over a Session origin.
    assert_eq!(
        apply(&mut roster, &peer, &set1, NOW),
        ignored(RouteSetIgnored::StaleSeq)
    );
    let equal = route_set(&host, 1, &B);
    assert_eq!(
        apply(&mut roster, &peer, &equal, NOW),
        ignored(RouteSetIgnored::StaleSeq)
    );
    let set3 = route_set(&host, 3, &B);
    assert_eq!(
        apply(&mut roster, &peer, &set3, NOW),
        RouteSetOutcome::Applied {
            added: owned(&B),
            removed: owned(&A)
        }
    );
    assert_eq!(
        apply(&mut roster, &peer, &route_set(&host, 2, &A), NOW),
        ignored(RouteSetIgnored::StaleSeq)
    );
    assert_eq!(hints_of(&roster, &peer, RouteSource::Signed), owned(&B));
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Operator),
        owned(&[A[0]])
    );
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Committed),
        owned(&[A[1]])
    );

    // Equal sequence over a URI origin applies once, then the Session origin rejects it.
    let (mut uri_roster, peer) = client_of(&host);
    uri_roster
        .merge_pair_plan(&peer, &plan(&host, &A[..1], 4, &all_signed()))
        .unwrap();
    let equal4 = route_set(&host, 4, &A);
    assert_eq!(
        apply(&mut uri_roster, &peer, &equal4, NOW),
        RouteSetOutcome::Applied {
            added: owned(&A[1..]),
            removed: vec![]
        }
    );
    assert_eq!(
        apply(&mut uri_roster, &peer, &equal4, NOW),
        ignored(RouteSetIgnored::StaleSeq)
    );
    assert_eq!(RouteSetIgnored::FutureIssuedAt.as_str(), "future_issued_at");
}

#[test]
fn bump_local_routes_persists_a_monotonic_sequence() {
    let host = identity(0x31);
    let one = PairingManager::announced_route_set(&host, &owned(&A));
    let two = PairingManager::announced_route_set(&host, &owned(&B));
    let mut roster = Roster::new();
    let s1 = roster.bump_local_routes(&one, NOW).unwrap();
    assert_eq!((s1.seq(), s1.issued_at()), (1, NOW));
    assert_eq!(roster.bump_local_routes(&one, NOW + 5).unwrap(), s1);
    let s2 = roster.bump_local_routes(&two, NOW + 9).unwrap();
    assert_eq!((s2.seq(), s2.issued_at()), (2, NOW + 9));
    assert_eq!(s2.routes(), two.routes());

    let mut reloaded: Roster =
        serde_json::from_str(&serde_json::to_string(&roster).unwrap()).unwrap();
    assert_eq!(reloaded.local_routes(), Some(&s2));
    assert_eq!(reloaded.bump_local_routes(&two, NOW + 20).unwrap(), s2);
    assert_eq!(reloaded.bump_local_routes(&one, NOW + 30).unwrap().seq(), 3);
}

#[test]
fn bump_local_routes_fails_closed_at_exhaustion() {
    let host = identity(0x33);
    let one = PairingManager::announced_route_set(&host, &owned(&A));
    let two = PairingManager::announced_route_set(&host, &owned(&B));
    let mut roster: Roster = serde_json::from_value(serde_json::json!({
        "entries": {},
        "crls": {},
        "local_routes": {
            "seq": MAX_ROUTE_SEQ,
            "issued_at": NOW,
            "digest": tendril_core::pairing::LocalRouteState::digest_of(one.routes()),
            "routes": one.routes(),
        },
    }))
    .unwrap();
    let stored = roster.local_routes().unwrap().clone();
    assert_eq!(roster.bump_local_routes(&one, NOW + 1).unwrap(), stored);
    assert_eq!(
        roster.bump_local_routes(&two, NOW + 1),
        Err(CoreError::ProtocolViolation("route sequence exhausted"))
    );
    assert_eq!(roster.local_routes(), Some(&stored));
}

#[test]
fn roster_writers_validate_state_sources_and_caps() {
    let host = identity(0x41);
    let (mut roster, peer) = client_of(&host);

    assert!(matches!(
        roster.set_routes("nobody", vec![op(A[0])]),
        Err(CoreError::PeerNotFound(_))
    ));
    let mut pending = Roster::new();
    pending
        .record_pending_host(
            peer.clone(),
            "Host".into(),
            *host.static_key().public_bytes(),
            host.signing_key().public_key().clone(),
            0,
            "SAS".into(),
            vec![],
        )
        .unwrap();
    assert!(matches!(
        pending.set_routes(&peer, vec![op(A[0])]),
        Err(CoreError::PeerPending(_))
    ));
    let mut revoked = roster.clone();
    revoked.revoke_peer(&peer).unwrap();
    assert!(matches!(
        revoked.set_routes(&peer, vec![op(A[0])]),
        Err(CoreError::PeerRevoked(_))
    ));
    let (mut crl_revoked, _) = crl_revoked_but_active(&host);
    assert!(matches!(
        crl_revoked.set_routes(&peer, vec![op(A[0])]),
        Err(CoreError::PeerRevoked(_))
    ));

    // Operator /v2/relay needs v2 secrets.
    let v2 = "wss://relay.example.com/v2/relay";
    assert_eq!(
        roster.set_routes(&peer, vec![op(v2)]),
        Err(CoreError::InvalidPairingUri(
            "/v2/relay route needs a Wire v2 pairing with this peer".into()
        ))
    );
    let mut with_v2 = roster.clone();
    with_v2
        .set_peer_v2_secrets(&peer, V2PeerSecrets::new([1; 32], [2; 32]))
        .unwrap();
    with_v2
        .set_routes(&peer, vec![op(v2), op("local:/run/t.sock")])
        .unwrap();
    // A committed /v2/relay route is never accepted.
    let mut committed_v2 = PersistPlan::default();
    committed_v2.committed = Some(v2.into());
    assert!(is_invalid(with_v2.merge_pair_plan(&peer, &committed_v2)));
    let mut committed_ipc = PersistPlan::default();
    committed_ipc.committed = Some("local:/run/t.sock".into());
    assert!(is_invalid(roster.merge_pair_plan(&peer, &committed_ipc)));
    // A signed /v2/relay route is allowed without secrets.
    roster
        .merge_pair_plan(&peer, &plan(&host, &[v2], 1, &all_signed()))
        .unwrap();
    assert_eq!(hints_of(&roster, &peer, RouteSource::Signed), owned(&[v2]));

    // Hint validity.
    for bad in [
        "javascript:alert(1)",
        "wss://relay.example.com/v1/relay#key",
    ] {
        assert!(is_invalid(roster.set_routes(&peer, vec![op(bad)])), "{bad}");
    }

    // Caps: 6 operator, 6 signed, 1 committed.
    let seven: Vec<OperatorEndpoint> = (1..=7)
        .map(|i| op(&format!("direct:192.168.5.{i}:80")))
        .collect();
    assert!(is_invalid(roster.set_routes(&peer, seven.clone())));
    let six = seven[..6].to_vec();
    roster.set_routes(&peer, six).unwrap();
    let mut dup = seven[..6].to_vec();
    dup.push(seven[0].clone());
    roster.set_routes(&peer, dup).unwrap();
    assert_eq!(hints_of(&roster, &peer, RouteSource::Operator).len(), 6);
    let mut extra_op = PersistPlan::default();
    extra_op.operator = Some("direct:192.168.6.1:80".into());
    assert!(is_invalid(roster.merge_pair_plan(&peer, &extra_op)));
    for c in ["direct:192.168.7.1:80", "direct:192.168.7.2:80"] {
        let mut p = PersistPlan::default();
        p.committed = Some(c.into());
        roster.merge_pair_plan(&peer, &p).unwrap();
    }
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Committed),
        owned(&["direct:192.168.7.2:80"])
    );
    let six_signed = [
        "direct:192.168.1.1:1",
        "direct:192.168.1.2:1",
        "overlay://100.64.0.1:1",
        "overlay://100.64.0.2:1",
        "iroh://a1",
        "iroh://a2",
    ];
    roster
        .merge_pair_plan(&peer, &plan(&host, &six_signed, 2, &all_signed()))
        .unwrap();
    assert_eq!(roster.get(&peer).unwrap().routes.len(), 13);

    // Relay key check against this entry's pin.
    let relay = "wss://relay.example.com/v1/relay";
    let mut keyed = op(relay);
    keyed.relay_key = Some(*identity(0x42).signing_key().ed25519_public_bytes());
    assert_eq!(
        roster.set_routes(&peer, vec![keyed.clone()]),
        Err(CoreError::InvalidPairingUri(
            "relay key does not match the pinned host key".into()
        ))
    );
    keyed.relay_key = Some(*host.signing_key().ed25519_public_bytes());
    let routes = roster.set_routes(&peer, vec![keyed]).unwrap().to_vec();
    assert!(routes.contains(&StoredRoute {
        hint: relay.into(),
        source: RouteSource::Operator
    }));
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Signed),
        owned(&six_signed)
    );

    // clear_routes keeps route_meta.
    let before = meta(&roster, &peer);
    roster
        .clear_routes(&peer, Some(RouteSource::Signed))
        .unwrap();
    assert!(hints_of(&roster, &peer, RouteSource::Signed).is_empty());
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Operator),
        owned(&[relay])
    );
    roster.clear_routes(&peer, None).unwrap();
    assert!(roster.get(&peer).unwrap().routes.is_empty());
    assert_eq!(meta(&roster, &peer), before);
    assert_eq!(
        roster.apply_route_announcement(&peer, &route_set(&host, 1, &A), NOW),
        Ok(RouteSetOutcome::Ignored(RouteSetIgnored::StaleSeq))
    );

    // replace_signed_routes needs a newer rq; replace_routes_approved keeps max(seq).
    assert!(
        !roster
            .replace_signed_routes(&peer, &statement(&host, &A, 2))
            .unwrap()
    );
    assert!(
        roster
            .replace_signed_routes(&peer, &statement(&host, &A, 7))
            .unwrap()
    );
    assert_eq!(
        meta(&roster, &peer),
        Some(RouteMeta {
            seq: 7,
            issued_at: None,
            origin: RouteOrigin::Uri
        })
    );
    roster
        .replace_routes_approved(&peer, &statement(&host, &B, 3))
        .unwrap();
    assert_eq!(hints_of(&roster, &peer, RouteSource::Signed), owned(&B));
    assert_eq!(
        meta(&roster, &peer),
        Some(RouteMeta {
            seq: 7,
            issued_at: None,
            origin: RouteOrigin::Approved
        })
    );
    roster
        .replace_routes_approved(&peer, &statement(&host, &A, 9))
        .unwrap();
    assert_eq!(meta(&roster, &peer).unwrap().seq, 9);
    // A statement for another host never writes this entry.
    assert_eq!(
        roster.replace_routes_approved(&peer, &statement(&identity(0x43), &A, 20)),
        Err(CoreError::HostKeyUnverified)
    );
}

/// A roster whose host entry is `Active` while an ingested CRL lists it.
fn crl_revoked_but_active(host: &EndpointIdentity) -> (Roster, String) {
    let (mut roster, peer) = client_of(host);
    let root = identity(0x7A);
    roster
        .insert_pinned_host(
            "root-id".into(),
            "Root".into(),
            *root.static_key().public_bytes(),
            Some(root.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let crl = crl_from(&root, 1, vec![peer.clone()]);
    roster
        .ingest_crl(crl, "root-id", root.signing_key().public_key())
        .unwrap();
    let mut value = serde_json::to_value(&roster).unwrap();
    value["entries"][&peer]["state"] = serde_json::json!("active");
    let roster: Roster = serde_json::from_value(value).unwrap();
    assert_eq!(roster.get(&peer).unwrap().state, PeerState::Active);
    (roster, peer)
}

fn crl_from(issuer: &EndpointIdentity, seq: u64, revoked: Vec<String>) -> RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: "root-id".into(),
            seq,
            revoked_devices: revoked,
            revoked_nonces: vec![],
            ts: "2026-11-20T00:00:00Z".into(),
        },
        issuer.signing_key(),
    )
    .unwrap()
}

#[test]
fn check_established_session_errors() {
    let host = identity(0x51);
    let (mut roster, peer) = client_of(&host);
    let st = *host.static_key().public_bytes();
    let sig = host.signing_key().public_key().clone();
    roster
        .check_established_session(&peer, &st, &sig, 1)
        .unwrap();
    assert!(matches!(
        roster.check_established_session("nobody", &st, &sig, 1),
        Err(CoreError::PeerNotFound(_))
    ));
    let other = identity(0x52);
    assert_eq!(
        roster.check_established_session(&peer, other.static_key().public_bytes(), &sig, 1),
        Err(CoreError::HostKeyUnverified)
    );
    assert_eq!(
        roster.check_established_session(&peer, &st, other.signing_key().public_key(), 1),
        Err(CoreError::HostKeyUnverified)
    );
    roster.set_peer_min_wire_version(&peer, 2).unwrap();
    assert_eq!(
        roster.check_established_session(&peer, &st, &sig, 1),
        Err(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        })
    );
    roster
        .check_established_session(&peer, &st, &sig, 2)
        .unwrap();

    let (crl_roster, _) = crl_revoked_but_active(&host);
    assert!(matches!(
        crl_roster.check_established_session(&peer, &st, &sig, 1),
        Err(CoreError::PeerRevoked(_))
    ));
    let mut revoked = roster.clone();
    revoked.revoke_peer(&peer).unwrap();
    assert!(matches!(
        revoked.check_established_session(&peer, &st, &sig, 2),
        Err(CoreError::PeerRevoked(_))
    ));
}

/// Stored `{seq: 5, origin: Session}` with routes B, plus operator O and committed C.
fn high_water_fixture(host: &EndpointIdentity) -> (Roster, String) {
    let (mut roster, peer) = client_of(host);
    roster
        .set_routes(&peer, vec![op("direct:10.0.0.9:7000")])
        .unwrap();
    let mut c = PersistPlan::default();
    c.committed = Some("direct:10.0.0.8:7000".into());
    roster.merge_pair_plan(&peer, &c).unwrap();
    let applied = roster
        .apply_route_announcement(&peer, &route_set(host, 5, &B), NOW)
        .unwrap();
    assert!(matches!(applied, RouteSetOutcome::Applied { .. }));
    (roster, peer)
}

#[test]
fn merge_pair_plan_high_water() {
    let host = identity(0x61);
    let session5 = Some(RouteMeta {
        seq: 5,
        issued_at: Some(NOW),
        origin: RouteOrigin::Session,
    });
    let untouched = |r: &Roster, p: &str| {
        assert_eq!(
            hints_of(r, p, RouteSource::Operator),
            owned(&["direct:10.0.0.9:7000"])
        );
        assert_eq!(
            hints_of(r, p, RouteSource::Committed),
            owned(&["direct:10.0.0.8:7000"])
        );
    };

    let (mut r, p) = high_water_fixture(&host);
    let out = r
        .merge_pair_plan(&p, &plan(&host, &A, 4, &all_signed()))
        .unwrap();
    assert_eq!(out.reason, Some("stale_route_seq"));
    assert!(out.persisted.is_empty());
    assert_eq!(hints_of(&r, &p, RouteSource::Signed), owned(&B));
    assert_eq!(meta(&r, &p), session5);
    untouched(&r, &p);

    let (mut r, p) = high_water_fixture(&host);
    let out = r
        .merge_pair_plan(&p, &plan(&host, &A[..1], 5, &all_signed()))
        .unwrap();
    assert_eq!(out.reason, None);
    let signed = hints_of(&r, &p, RouteSource::Signed);
    assert_eq!(signed.len(), 3);
    assert!(
        B.iter()
            .chain(&A[..1])
            .all(|h| signed.iter().any(|s| s == h))
    );
    assert_eq!(meta(&r, &p), session5);
    untouched(&r, &p);

    let (mut r, p) = high_water_fixture(&host);
    let op_plan = PersistOpts {
        operator_endpoint: Some("direct:10.0.0.7:7000".into()),
        ..PersistOpts::default()
    };
    let out = r
        .merge_pair_plan(&p, &plan(&host, &A, 6, &op_plan))
        .unwrap();
    assert_eq!(out.persisted.len(), 3);
    assert_eq!(hints_of(&r, &p, RouteSource::Signed), owned(&A));
    assert_eq!(
        meta(&r, &p),
        Some(RouteMeta {
            seq: 6,
            issued_at: None,
            origin: RouteOrigin::Uri
        })
    );
    assert_eq!(
        hints_of(&r, &p, RouteSource::Operator),
        owned(&["direct:10.0.0.9:7000", "direct:10.0.0.7:7000"])
    );
    assert_eq!(
        hints_of(&r, &p, RouteSource::Committed),
        owned(&["direct:10.0.0.8:7000"])
    );
}

/// Deterministic xorshift for write-order permutations.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn route_seq_never_decreases_across_write_orders() {
    let host = identity(0x63);
    let statements: Vec<VerifiedRouteStatement> =
        (1..=8).map(|rq| statement(&host, &A[..1], rq)).collect();
    let plans: Vec<PersistPlan> = (1..=8)
        .map(|rq| plan(&host, &B[..1], rq, &all_signed()))
        .collect();
    let sets: Vec<RouteSet> = (1..=8).map(|s| route_set(&host, s, &A)).collect();
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    for _ in 0..100 {
        let (mut roster, peer) = client_of(&host);
        let mut high = 0;
        for _ in 0..24 {
            let pick = usize::try_from(next(&mut state) % 8).unwrap();
            match next(&mut state) % 4 {
                0 => {
                    roster.merge_pair_plan(&peer, &plans[pick]).unwrap();
                }
                1 => {
                    roster
                        .apply_route_announcement(&peer, &sets[pick], NOW)
                        .unwrap();
                }
                2 => {
                    roster
                        .replace_signed_routes(&peer, &statements[pick])
                        .unwrap();
                }
                _ => roster
                    .replace_routes_approved(&peer, &statements[pick])
                    .unwrap(),
            }
            let seq = meta(&roster, &peer).map_or(0, |m| m.seq);
            assert!(seq >= high, "seq went from {high} to {seq}");
            high = seq;
            roster.clear_routes(&peer, None).unwrap();
            assert_eq!(meta(&roster, &peer).map_or(0, |m| m.seq), high);
        }
    }
}

#[test]
fn independent_provenance_per_source() {
    let host = identity(0x71);
    let h = "direct:192.168.1.20:9100";
    let (mut roster, peer) = client_of(&host);
    let mut committed = PersistPlan::default();
    committed.committed = Some(h.into());
    roster.merge_pair_plan(&peer, &committed).unwrap();
    roster
        .apply_route_announcement(&peer, &route_set(&host, 1, &[h]), NOW)
        .unwrap();
    assert_eq!(roster.get(&peer).unwrap().routes.len(), 2);
    let out = roster
        .apply_route_announcement(&peer, &route_set(&host, 2, &B), NOW)
        .unwrap();
    assert_eq!(
        out,
        RouteSetOutcome::Applied {
            added: owned(&B),
            removed: owned(&[h])
        }
    );
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Committed),
        owned(&[h])
    );

    // An empty operator write keeps the committed record; a non-empty one replaces it.
    roster.set_routes(&peer, vec![]).unwrap();
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Committed),
        owned(&[h])
    );
    roster.set_routes(&peer, vec![op(B[0])]).unwrap();
    assert_eq!(roster.get(&peer).unwrap().routes.len(), 3);
    assert!(hints_of(&roster, &peer, RouteSource::Committed).is_empty());
    roster
        .clear_routes(&peer, Some(RouteSource::Signed))
        .unwrap();
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Operator),
        owned(&[B[0]])
    );
}

#[test]
fn approved_replacement_holds_against_equal_sets() {
    let host = identity(0x81);
    let (mut roster, peer) = client_of(&host);
    roster
        .merge_pair_plan(&peer, &plan(&host, &A, 5, &all_signed()))
        .unwrap();
    assert_eq!(
        roster
            .get(&peer)
            .unwrap()
            .hello_route_seq(RoutePolicy::AllSigned),
        Some(0)
    );
    roster
        .replace_routes_approved(&peer, &statement(&host, &B, 3))
        .unwrap();
    assert_eq!(
        meta(&roster, &peer),
        Some(RouteMeta {
            seq: 5,
            issued_at: None,
            origin: RouteOrigin::Approved
        })
    );
    let entry = roster.get(&peer).unwrap();
    assert_eq!(entry.hello_route_seq(RoutePolicy::AllSigned), Some(5));
    assert_eq!(entry.hello_route_seq(RoutePolicy::CommittedOnly), None);
    assert_eq!(entry.hello_route_seq(RoutePolicy::None), None);
    assert_eq!(
        roster.apply_route_announcement(&peer, &route_set(&host, 5, &A), NOW),
        Ok(RouteSetOutcome::Ignored(RouteSetIgnored::StaleSeq))
    );
    assert_eq!(hints_of(&roster, &peer, RouteSource::Signed), owned(&B));
    assert!(matches!(
        roster.apply_route_announcement(&peer, &route_set(&host, 6, &A), NOW),
        Ok(RouteSetOutcome::Applied { .. })
    ));
    assert_eq!(hints_of(&roster, &peer, RouteSource::Signed), owned(&A));
}

#[test]
fn equal_sequence_pairing_keeps_approved_routes_within_caps() {
    let host = identity(0x83);
    let approved = [
        "wss://r1.example.com/v1/relay",
        "wss://r2.example.com/v1/relay",
        "broker+wss://b1.example.com/v1/broker",
        "broker+wss://b2.example.com/v1/broker",
        "iroh://a1",
        "iroh://a2",
    ];
    let live = [
        "direct:192.168.2.1:1",
        "direct:192.168.2.2:1",
        "overlay://100.64.0.1:1",
        "overlay://100.64.0.2:1",
        "iroh://b1",
        "iroh://b2",
    ];
    let (mut roster, peer) = client_of(&host);
    roster
        .merge_pair_plan(&peer, &plan(&host, &live[..1], 5, &all_signed()))
        .unwrap();
    roster
        .replace_routes_approved(&peer, &statement(&host, &approved, 3))
        .unwrap();
    roster
        .merge_pair_plan(&peer, &plan(&host, &live, 5, &all_signed()))
        .unwrap();
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Signed),
        owned(&approved)
    );
    assert_eq!(meta(&roster, &peer).unwrap().origin, RouteOrigin::Approved);

    // With two approved routes, the best-ranked live routes fill the caps.
    let (mut roster, peer) = client_of(&host);
    roster
        .merge_pair_plan(&peer, &plan(&host, &live[..1], 5, &all_signed()))
        .unwrap();
    roster
        .replace_routes_approved(&peer, &statement(&host, &approved[4..], 3))
        .unwrap();
    roster
        .merge_pair_plan(&peer, &plan(&host, &live, 5, &all_signed()))
        .unwrap();
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Signed),
        owned(&[
            "iroh://a1",
            "iroh://a2",
            "direct:192.168.2.1:1",
            "direct:192.168.2.2:1",
            "overlay://100.64.0.1:1",
            "overlay://100.64.0.2:1",
        ])
    );
}

#[test]
fn equal_sequence_pairing_protects_only_explicitly_approved_routes() {
    let host = identity(0x85);
    let approved = "direct:192.168.3.1:1";
    let (mut roster, peer) = client_of(&host);
    roster
        .merge_pair_plan(&peer, &plan(&host, &["iroh://a0"], 5, &all_signed()))
        .unwrap();
    roster
        .replace_routes_approved(&peer, &statement(&host, &[approved], 3))
        .unwrap();
    assert_eq!(
        roster.get(&peer).unwrap().approved_signed_routes(),
        owned(&[approved])
    );

    // The first equal-sequence pairing fills the free direct slot with a lower-ranked route.
    roster
        .merge_pair_plan(&peer, &plan(&host, &["direct:8.8.8.8:1"], 5, &all_signed()))
        .unwrap();
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Signed),
        owned(&[approved, "direct:8.8.8.8:1"])
    );
    // That route was not approved: a later higher-ranked LAN route displaces it.
    roster
        .merge_pair_plan(
            &peer,
            &plan(&host, &["direct:192.168.3.2:1"], 5, &all_signed()),
        )
        .unwrap();
    assert_eq!(
        hints_of(&roster, &peer, RouteSource::Signed),
        owned(&[approved, "direct:192.168.3.2:1"])
    );
    assert_eq!(meta(&roster, &peer).unwrap().origin, RouteOrigin::Approved);
    assert_eq!(
        roster.get(&peer).unwrap().approved_signed_routes(),
        owned(&[approved])
    );

    // A fresher signed set ends the approval.
    assert_eq!(
        roster.replace_signed_routes(&peer, &statement(&host, &B, 6)),
        Ok(true)
    );
    assert!(
        roster
            .get(&peer)
            .unwrap()
            .approved_signed_routes()
            .is_empty()
    );
}

fn is_subsequence(sub: &[String], full: &[String]) -> bool {
    let mut it = full.iter();
    sub.iter().all(|s| it.any(|f| f == s))
}

#[test]
fn equal_sequence_announcement_never_removes_a_qr_hint() {
    let host = identity(0x91);
    let inputs = owned(&[
        "direct:8.8.8.8:80",
        "direct:1.1.1.1:80",
        "direct:192.168.1.9:80",
        "wss://relay.example.com/v1/relay",
        "overlay://100.64.0.1:80",
        "iroh://n1?relay=https://iroh.example&addr=192.168.1.9:4433",
        "broker+wss://b.example.com/v1/broker",
    ]);
    let mut host_roster = Roster::new();
    let announced = PairingManager::announced_route_set(&host, &inputs);
    let state = host_roster.bump_local_routes(&announced, NOW).unwrap();
    let directs: Vec<&String> = state
        .routes()
        .iter()
        .filter(|h| h.starts_with("direct:"))
        .collect();
    assert_eq!(directs[0], "direct:192.168.1.9:80");
    let full_set = RouteSet::sign(
        &host,
        state.seq(),
        state.issued_at(),
        state.routes().to_vec(),
    )
    .unwrap();

    let mut cases = 0;
    for kind in [
        None,
        Some(PairingCodeKind::Lan2Group),
        Some(PairingCodeKind::Remote3Group),
    ] {
        for host_len in (0..=900).step_by(25) {
            let name = format!("S{}", "x".repeat(host_len));
            let mut mgr = PairingManager::new(PairingConfig::default());
            let issued = match mgr.issue_pairing_uri(
                &host,
                &name,
                &state,
                IssueOptions {
                    requested_kind: kind,
                    sign_routes: true,
                },
                NOW,
            ) {
                Ok(issued) => issued,
                Err(CoreError::InvalidPairingUri(m)) if m == "host name too long" => continue,
                Err(err) => panic!("{err:?}"),
            };
            let qr = issued.parsed.endpoints.clone();
            assert!(is_subsequence(&qr, state.routes()), "{kind:?} {host_len}");
            let check = issued
                .parsed
                .verify_route_statement(host.signing_key().public_key());
            let plan = persistable_routes(&check, &issued.parsed.code, None, &all_signed());
            let (mut client, peer) = (Roster::new(), host.host_id().to_owned());
            client
                .insert_pinned_host_with_plan(
                    peer.clone(),
                    "Host".into(),
                    *host.static_key().public_bytes(),
                    Some(host.signing_key().public_key().clone()),
                    0,
                    &plan,
                )
                .unwrap();
            assert_eq!(hints_of(&client, &peer, RouteSource::Signed), qr);
            let out = client
                .apply_route_announcement(&peer, &full_set, NOW)
                .unwrap();
            let RouteSetOutcome::Applied { removed, .. } = out else {
                panic!("equal-sequence set over a URI origin must apply: {out:?}");
            };
            assert!(removed.is_empty(), "{kind:?} {host_len}: {removed:?}");
            let stored = hints_of(&client, &peer, RouteSource::Signed);
            assert!(qr.iter().all(|h| stored.contains(h)));
            assert_eq!(stored, state.routes());
            cases += 1;
        }
    }
    assert!(cases > 60);
}

#[test]
fn pairing_with_plan_is_one_transaction() {
    let host = identity(0xA1);
    let other = identity(0xA3);
    let mut roster = Roster::new();
    let peer = host.host_id().to_owned();
    let foreign = plan(&other, &A, 3, &all_signed());
    assert_eq!(
        roster.insert_pinned_host_with_plan(
            peer.clone(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            &foreign,
        ),
        Err(CoreError::HostKeyUnverified)
    );
    assert!(roster.get(&peer).is_none());

    let out = roster
        .record_pending_host_with_plan(
            peer.clone(),
            "Host".into(),
            *host.static_key().public_bytes(),
            host.signing_key().public_key().clone(),
            0,
            "SAS".into(),
            &plan(&host, &A, 3, &all_signed()),
        )
        .unwrap();
    assert_eq!(out.persisted.len(), 2);
    let entry = roster.get(&peer).unwrap();
    assert_eq!(entry.state, PeerState::Pending);
    assert!(entry.relay_hints.is_empty());
    assert_eq!(entry.route_meta.unwrap().seq, 3);

    // Same-key re-pair keeps routes and the high-water mark.
    roster.confirm_peer_without_sas(&peer).unwrap();
    let out = roster
        .insert_pinned_host_with_plan(
            peer.clone(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            &plan(&host, &B, 2, &all_signed()),
        )
        .unwrap();
    assert_eq!(out.reason, Some("stale_route_seq"));
    assert_eq!(hints_of(&roster, &peer, RouteSource::Signed), owned(&A));
}

#[test]
fn merge_crl_evidence_verifies_against_this_roster() {
    let host = identity(0xB1);
    let root = identity(0xB3);
    let forger = identity(0xB5);
    let (mut roster, peer) = client_of(&host);
    roster
        .insert_pinned_host(
            "root-id".into(),
            "Root".into(),
            *root.static_key().public_bytes(),
            Some(root.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let forged = crl_from(&forger, 5, vec![peer.clone()]);
    assert_eq!(roster.merge_crl_evidence(&[("root-id".into(), forged)]), 0);
    assert_eq!(roster.get(&peer).unwrap().state, PeerState::Active);
    let unknown = crl_from(&root, 5, vec![peer.clone()]);
    assert_eq!(roster.merge_crl_evidence(&[("nobody".into(), unknown)]), 0);

    let crl2 = crl_from(&root, 2, vec![]);
    let crl1 = crl_from(&root, 1, vec![peer.clone()]);
    assert_eq!(roster.merge_crl_evidence(&[("root-id".into(), crl2)]), 1);
    assert_eq!(roster.merge_crl_evidence(&[("root-id".into(), crl1)]), 0);
    assert_eq!(roster.get(&peer).unwrap().state, PeerState::Active);
    let crl3 = crl_from(&root, 3, vec![peer.clone()]);
    assert_eq!(roster.merge_crl_evidence(&[("root-id".into(), crl3)]), 1);
    assert_eq!(roster.get(&peer).unwrap().state, PeerState::Revoked);
}

#[test]
fn merge_crl_evidence_accepts_trust_anchor_crls() {
    let host = identity(0xB7);
    let anchor = identity(0xB9);
    let (mut roster, peer) = client_of(&host);
    roster
        .add_trust_anchor("root-id".into(), anchor.signing_key().public_key().clone())
        .unwrap();
    let forged = crl_from(&identity(0xBB), 4, vec![peer.clone()]);
    assert_eq!(roster.merge_crl_evidence(&[("root-id".into(), forged)]), 0);
    assert_eq!(roster.get(&peer).unwrap().state, PeerState::Active);

    let crl = crl_from(&anchor, 4, vec![peer.clone()]);
    assert_eq!(roster.merge_crl_evidence(&[("root-id".into(), crl)]), 1);
    assert_eq!(roster.crl("root-id").map(|c| c.seq), Some(4));
    assert_eq!(roster.get(&peer).unwrap().state, PeerState::Revoked);
}

#[test]
fn reconcile_rotation_evidence_detects_forks_across_candidates() {
    let sk0 = SigningKeypair::from_seed([0xC2; 32]);
    let host = EndpointIdentity::from_keys(StaticKeypair::from_scalar([0xC1; 32]), sk0.clone());
    let (mut roster, peer) = client_of(&host);
    let snapshot = roster.pin_snapshot(&peer).unwrap();
    assert_eq!(snapshot.rotation_seq(), 0);
    let key = |tag: u8| -> (HybridSigningPublicKey, [u8; 32]) {
        (
            SigningKeypair::from_seed([tag; 32]).public_key().clone(),
            *StaticKeypair::from_scalar([tag.wrapping_add(1); 32]).public_bytes(),
        )
    };
    let (k1a, s1a) = key(0xD1);
    let (k1b, s1b) = key(0xD3);
    let rec_a = sign_rotation(1, &sk0, &k1a, &s1a, NOW).unwrap();
    let rec_b = sign_rotation(1, &sk0, &k1b, &s1b, NOW + 1).unwrap();

    roster
        .reconcile_rotation_evidence(&peer, &snapshot, &[rec_a.clone(), rec_a.clone()])
        .unwrap();
    let stranger = SigningKeypair::from_seed([0xE1; 32]);
    let x1 = sign_rotation(1, &stranger, &k1a, &s1a, NOW).unwrap();
    let x2 = sign_rotation(1, &stranger, &k1b, &s1b, NOW).unwrap();
    let mut bad_sig = rec_b.clone();
    bad_sig.ts = "2026-11-21T00:00:00Z".into();
    roster
        .reconcile_rotation_evidence(&peer, &snapshot, &[rec_a.clone(), x1, x2, bad_sig])
        .unwrap();
    assert_eq!(roster.get(&peer).unwrap().state, PeerState::Active);

    assert_eq!(
        roster.reconcile_rotation_evidence(&peer, &snapshot, &[rec_a, rec_b]),
        Err(CoreError::RotationForkDetected { seq: 1 })
    );
    let entry = roster.get(&peer).unwrap();
    assert_eq!(entry.state, PeerState::Revoked);
    assert!(entry.grants.is_empty());
    assert!(matches!(
        roster.pin_snapshot(&peer),
        Err(CoreError::PeerRevoked(_))
    ));
}

#[test]
fn reconcile_rotation_evidence_rejects_a_snapshot_of_another_peer() {
    let sk0 = SigningKeypair::from_seed([0xC4; 32]);
    let host_a = EndpointIdentity::from_keys(StaticKeypair::from_scalar([0xC3; 32]), sk0.clone());
    let host_b = identity(0xC5);
    let (mut roster, peer_a) = client_of(&host_a);
    let peer_b = host_b.host_id().to_owned();
    roster
        .insert_pinned_host(
            peer_b.clone(),
            "B".into(),
            *host_b.static_key().public_bytes(),
            Some(host_b.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let snapshot_a = roster.pin_snapshot(&peer_a).unwrap();
    assert_eq!(snapshot_a.peer_id(), peer_a);
    let (k1a, s1a) = (
        SigningKeypair::from_seed([0xD5; 32]).public_key().clone(),
        *StaticKeypair::from_scalar([0xD6; 32]).public_bytes(),
    );
    let (k1b, s1b) = (
        SigningKeypair::from_seed([0xD7; 32]).public_key().clone(),
        *StaticKeypair::from_scalar([0xD8; 32]).public_bytes(),
    );
    let fork = [
        sign_rotation(1, &sk0, &k1a, &s1a, NOW).unwrap(),
        sign_rotation(1, &sk0, &k1b, &s1b, NOW + 1).unwrap(),
    ];

    let before = serde_json::to_value(&roster).unwrap();
    assert_eq!(
        roster.reconcile_rotation_evidence(&peer_b, &snapshot_a, &fork),
        Err(CoreError::HostKeyUnverified)
    );
    assert_eq!(serde_json::to_value(&roster).unwrap(), before);
    assert_eq!(roster.get(&peer_b).unwrap().state, PeerState::Active);
    assert_eq!(roster.get(&peer_a).unwrap().state, PeerState::Active);

    // The matching target still detects the fork.
    assert_eq!(
        roster.reconcile_rotation_evidence(&peer_a, &snapshot_a, &fork),
        Err(CoreError::RotationForkDetected { seq: 1 })
    );
    assert_eq!(roster.get(&peer_a).unwrap().state, PeerState::Revoked);
    assert_eq!(roster.get(&peer_b).unwrap().state, PeerState::Active);
}

#[test]
fn legacy_rosters_load_and_never_dial_relay_hints() {
    let host = identity(0xF1);
    let mut roster = Roster::new();
    let peer = host.host_id().to_owned();
    roster
        .insert_pinned_host(
            peer.clone(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            owned(&["wss://legacy.example.com/v1/relay"]),
        )
        .unwrap();
    let json = serde_json::to_string(&roster).unwrap();
    for key in ["\"routes\"", "\"route_meta\"", "\"local_routes\""] {
        assert!(
            !json.contains(key),
            "{key} must not appear in a legacy roster"
        );
    }
    let loaded: Roster = serde_json::from_str(&json).unwrap();
    let entry = loaded.get(&peer).unwrap();
    assert_eq!(
        entry.relay_hints,
        owned(&["wss://legacy.example.com/v1/relay"])
    );
    assert!(entry.routes.is_empty());
    assert_eq!(entry.route_meta, None);
    assert_eq!(entry.hello_route_seq(RoutePolicy::AllSigned), None);
    assert_eq!(loaded.local_routes(), None);
    assert_eq!(serde_json::to_string(&loaded).unwrap(), json);

    let mut with_routes = loaded.clone();
    with_routes
        .merge_pair_plan(&peer, &plan(&host, &A, 1, &all_signed()))
        .unwrap();
    let round: Roster =
        serde_json::from_str(&serde_json::to_string(&with_routes).unwrap()).unwrap();
    assert_eq!(round.get(&peer), with_routes.get(&peer));
    let value = serde_json::to_value(&with_routes).unwrap();
    assert_eq!(value["entries"][&peer]["routes"][0]["source"], "signed");
    assert_eq!(value["entries"][&peer]["route_meta"]["origin"], "uri");
}
