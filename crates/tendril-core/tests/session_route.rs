//! Session route expectations, `0x0C ROUTE_SET` frames, v2 deferred claims, the v2 pairing
//! route plan and relay credential origins.

use tendril_core::crypto::{HybridSigningPublicKey, SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::noise::{NoiseHfsHandshakeBuilder, NoiseTransport};
use tendril_core::pairing::{
    PairingCodeKind, PairingConfig, PairingManager, PairingPathKind, PairingUri, PersistOpts,
    RouteCheck, persistable_routes, sign_route_statement,
};
use tendril_core::relay_auth::origin_allowed;
use tendril_core::roster::{PeerState, Roster, RouteOrigin, RouteSource, V2PeerSecrets};
use tendril_core::routes::{MIN_ROUTE_SET_PAYLOAD, RouteSet};
use tendril_core::session::{RouteExpectation, SessionAction, SessionMachine};
use tendril_core::v2::{
    PaddingPolicy, PakeArgon2Params, SealedSession, V2InnerFrame, V2PairAction, V2PairOutcome,
    V2PakePairInitiator, V2PakePairResponder, V2SessionAction, V2SessionInitiator,
    V2SessionResponder, decode_v2_inner_frame, pad_inner_frame,
};
use tendril_core::wire::{InnerFrameType, WIRE_VERSION_V2, encode_inner_frame};

const NOW: u64 = 1_795_564_800;
const CODE3: &str = "TND-ABCD-EFGH-JKLM";
const HINTS: [&str; 2] = [
    "direct:192.168.1.20:9100",
    "wss://relay.example.com/v1/relay",
];

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
    )
}

fn secrets() -> V2PeerSecrets {
    V2PeerSecrets::new([0x66; 32], [0x77; 32])
}

/// A host that rotated once after the client pinned it, plus the keys the client pinned.
struct RotatedHost {
    host: EndpointIdentity,
    old_static: [u8; 32],
    old_signing: HybridSigningPublicKey,
}

fn rotated_host() -> RotatedHost {
    let mut host = identity(0x20).with_host_id("host-route");
    let old_static = *host.static_key().public_bytes();
    let old_signing = host.signing_key().public_key().clone();
    host.rotate(
        StaticKeypair::from_scalar([0x22; 32]),
        SigningKeypair::from_seed([0x23; 32]),
        NOW,
    )
    .unwrap();
    RotatedHost {
        host,
        old_static,
        old_signing,
    }
}

fn host_roster(cli: &EndpointIdentity) -> Roster {
    let mut roster = Roster::new();
    roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "abcd".into(),
        )
        .unwrap();
    roster.confirm_peer(&cli.device_id(), Some("abcd")).unwrap();
    roster
        .set_peer_v2_secrets(&cli.device_id(), secrets())
        .unwrap();
    roster
}

fn client_roster(host_id: &str, static_pub: [u8; 32], signing: &HybridSigningPublicKey) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host_id.into(),
            "Host".into(),
            static_pub,
            Some(signing.clone()),
            0,
            vec![],
        )
        .unwrap();
    roster.set_peer_v2_secrets(host_id, secrets()).unwrap();
    roster
}

fn uri_for(
    host_id: &str,
    static_pub: [u8; 32],
    sh: [u8; 32],
    relay_pub: Option<[u8; 32]>,
) -> PairingUri {
    let mut uri = PairingUri::new(
        "Studio",
        CODE3,
        static_pub,
        sh,
        HINTS.iter().map(|h| (*h).to_owned()).collect(),
        Some(host_id.to_owned()),
        Some(1),
    );
    uri.relay_pub = relay_pub;
    uri
}

/// The host's current keys as a recovery URI, unsigned.
fn unsigned_recovery(host: &EndpointIdentity) -> PairingUri {
    uri_for(
        host.host_id(),
        *host.static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        Some(*host.signing_key().ed25519_public_bytes()),
    )
}

/// Signs `uri` as the builder does, with `rq = 5`.
fn sign(host: &EndpointIdentity, uri: &PairingUri) -> String {
    let prefix = format!("{}&rq=5", uri.try_encode().unwrap());
    let sig = sign_route_statement(host, &prefix);
    format!("{prefix}&rs={}", b64url_encode(&sig))
}

fn snapshot(roster: &Roster) -> serde_json::Value {
    serde_json::to_value(roster).unwrap()
}

fn v1_bytes(actions: Vec<SessionAction>) -> Vec<u8> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            SessionAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect()
}

fn v2_bytes(actions: Vec<V2SessionAction>) -> Vec<u8> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            V2SessionAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Runs a v1 session up to the initiator's handling of `msg2`.
fn v1_connect(
    cli: &EndpointIdentity,
    host: &EndpointIdentity,
    cli_roster: &mut Roster,
    expectation: Option<RouteExpectation>,
) -> (SessionMachine, Result<Vec<SessionAction>, CoreError>) {
    let mut init = SessionMachine::new_initiator(cli, host.host_id(), None, None, None).unwrap();
    if let Some(exp) = expectation {
        init = init.with_route_expectation(exp).unwrap();
    }
    let mut resp = SessionMachine::new_responder(host, None).unwrap();
    let mut hroster = host_roster(cli);
    let m1 = v1_bytes(init.start().unwrap());
    let m2 = v1_bytes(resp.feed_bytes(&m1, NOW, 1, &mut hroster).unwrap());
    let res = init.feed_bytes(&m2, NOW, 2, cli_roster);
    (init, res)
}

/// Runs a v2 session up to the initiator's handling of `msg2`.
fn v2_connect(
    cli: &EndpointIdentity,
    host: &EndpointIdentity,
    cli_roster: &mut Roster,
    expectation: Option<RouteExpectation>,
) -> (V2SessionInitiator, Result<Vec<V2SessionAction>, CoreError>) {
    let mut init = V2SessionInitiator::new(
        cli,
        host.host_id(),
        *secrets().reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    if let Some(exp) = expectation {
        init = init.with_route_expectation(exp).unwrap();
    }
    let mut resp = V2SessionResponder::new(host).unwrap();
    let mut hroster = host_roster(cli);
    let m1 = v2_bytes(init.start(NOW).unwrap());
    let m2 = v2_bytes(resp.feed_bytes(&m1, NOW, 1, &mut hroster).unwrap());
    let res = init.feed_bytes(&m2, NOW, 2, cli_roster);
    (init, res)
}

enum Outcome {
    Ok {
        msg3: bool,
        statement_hints: Option<Vec<String>>,
    },
    Err(CoreError),
}

/// Connects over v1 or v2 to a rotated host with `expectation`, returning the outcome, the
/// client roster before and after, and the presented rotation length.
fn connect_rotated(
    v2: bool,
    expectation: RouteExpectation,
) -> (Outcome, serde_json::Value, serde_json::Value, usize) {
    let rh = rotated_host();
    let cli = identity(0x40);
    let mut roster = client_roster(rh.host.host_id(), rh.old_static, &rh.old_signing);
    let before = snapshot(&roster);
    let (outcome, presented) = if v2 {
        let (init, res) = v2_connect(&cli, &rh.host, &mut roster, Some(expectation));
        let out = match res {
            Ok(actions) => Outcome::Ok {
                msg3: actions
                    .iter()
                    .any(|a| matches!(a, V2SessionAction::WriteBytes(_))),
                statement_hints: init
                    .verified_recovery_statement()
                    .map(|s| s.hints().to_vec()),
            },
            Err(err) => Outcome::Err(err),
        };
        (out, init.presented_rotation().len())
    } else {
        let (init, res) = v1_connect(&cli, &rh.host, &mut roster, Some(expectation));
        let out = match res {
            Ok(actions) => Outcome::Ok {
                msg3: actions
                    .iter()
                    .any(|a| matches!(a, SessionAction::WriteBytes(_))),
                statement_hints: init
                    .verified_recovery_statement()
                    .map(|s| s.hints().to_vec()),
            },
            Err(err) => Outcome::Err(err),
        };
        (out, init.presented_rotation().len())
    };
    (outcome, before, snapshot(&roster), presented)
}

fn expect_for(rh: &RotatedHost, uri: &str) -> RouteExpectation {
    RouteExpectation::for_connect(rh.host.host_id(), Some(uri), None, None).unwrap()
}

#[test]
fn recovery_statement_checked_before_rotation_and_msg3() {
    for v2 in [false, true] {
        let rh = rotated_host();
        let valid = sign(&rh.host, &unsigned_recovery(&rh.host));
        let tampered = valid.replacen("192.168.1.20", "192.168.1.21", 1);
        assert_ne!(valid, tampered);

        let (out, before, after, presented) = connect_rotated(v2, expect_for(&rh, &tampered));
        match out {
            Outcome::Err(err) => assert_eq!(
                err,
                CoreError::InvalidPairingUri("route statement does not verify".into()),
                "v2={v2}"
            ),
            Outcome::Ok { .. } => panic!("tampered recovery URI accepted (v2={v2})"),
        }
        assert_eq!(before, after, "roster changed on failure (v2={v2})");
        assert_eq!(presented, 1, "presented rotation kept on error (v2={v2})");

        let (out, before, after, _) = connect_rotated(v2, expect_for(&rh, &valid));
        match out {
            Outcome::Ok {
                msg3,
                statement_hints,
            } => {
                assert!(msg3);
                assert_eq!(statement_hints.unwrap(), HINTS.map(String::from).to_vec());
            }
            Outcome::Err(err) => panic!("valid recovery URI rejected (v2={v2}): {err:?}"),
        }
        assert_ne!(before, after, "rotation applied after the checks (v2={v2})");
    }
}

#[test]
fn unsigned_recovery_binds_k_and_sh() {
    for v2 in [false, true] {
        let rh = rotated_host();
        let other = identity(0x60);

        let good = unsigned_recovery(&rh.host).try_encode().unwrap();
        let (out, _, _, _) = connect_rotated(v2, expect_for(&rh, &good));
        assert!(
            matches!(
                out,
                Outcome::Ok {
                    msg3: true,
                    statement_hints: None
                }
            ),
            "v2={v2}"
        );

        let wrong_k = uri_for(
            rh.host.host_id(),
            *other.static_key().public_bytes(),
            rh.host.signing_key().signing_pub_hash(),
            Some(*rh.host.signing_key().ed25519_public_bytes()),
        );
        let wrong_sh = uri_for(
            rh.host.host_id(),
            *rh.host.static_key().public_bytes(),
            other.signing_key().signing_pub_hash(),
            Some(*rh.host.signing_key().ed25519_public_bytes()),
        );
        for uri in [wrong_k, wrong_sh] {
            let uri = uri.try_encode().unwrap();
            let (out, before, after, _) = connect_rotated(v2, expect_for(&rh, &uri));
            assert!(
                matches!(out, Outcome::Err(CoreError::HostKeyUnverified)),
                "v2={v2}"
            );
            assert_eq!(before, after, "v2={v2}");
        }
    }
}

#[test]
fn relay_key_expectation_binds_presented_signing_key() {
    for v2 in [false, true] {
        let rh = rotated_host();
        let current = *rh.host.signing_key().ed25519_public_bytes();
        let stale = *SigningKeypair::from_seed([0x21; 32]).ed25519_public_bytes();

        let ok =
            RouteExpectation::for_connect(rh.host.host_id(), None, Some(current), None).unwrap();
        assert!(matches!(
            connect_rotated(v2, ok).0,
            Outcome::Ok { msg3: true, .. }
        ));

        let bad =
            RouteExpectation::for_connect(rh.host.host_id(), None, Some(stale), None).unwrap();
        let (out, before, after, _) = connect_rotated(v2, bad);
        assert!(matches!(out, Outcome::Err(CoreError::HostKeyUnverified)));
        assert_eq!(before, after);
    }
}

#[test]
fn for_connect_rejects_foreign_ids_and_key_conflicts() {
    let rh = rotated_host();
    let uri = unsigned_recovery(&rh.host).try_encode().unwrap();
    let rp = *rh.host.signing_key().ed25519_public_bytes();
    let other = [0x55; 32];

    assert!(matches!(
        RouteExpectation::for_connect("another-host", Some(&uri), None, None),
        Err(CoreError::InvalidPairingUri(_))
    ));
    assert!(matches!(
        RouteExpectation::for_connect(rh.host.host_id(), Some(&uri), Some(other), None),
        Err(CoreError::InvalidPairingUri(_))
    ));
    assert!(matches!(
        RouteExpectation::for_connect(rh.host.host_id(), None, Some(rp), Some(other)),
        Err(CoreError::InvalidPairingUri(_))
    ));
    assert!(
        RouteExpectation::for_connect(rh.host.host_id(), Some("tendril://x"), None, None).is_err()
    );

    let exp =
        RouteExpectation::for_connect(rh.host.host_id(), Some(&uri), Some(rp), Some(rp)).unwrap();
    assert_eq!(exp.relay_pub(), Some(&rp));
    assert_eq!(
        exp.recovery_uri().unwrap().host_id.as_deref(),
        Some(rh.host.host_id())
    );
    let none = RouteExpectation::for_connect(rh.host.host_id(), None, None, None).unwrap();
    assert_eq!(none, RouteExpectation::default());
}

#[test]
fn route_options_are_initiator_only_and_before_start() {
    let host = identity(0x20);
    let cli = identity(0x40);
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    init.start().unwrap();
    assert!(init.with_route_seq(Some(1)).is_err());
    let resp = SessionMachine::new_responder(&host, None).unwrap();
    assert!(
        resp.with_route_expectation(RouteExpectation::default())
            .is_err()
    );
    let fresh = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    assert!(matches!(
        fresh.with_route_seq(Some(1 << 53)),
        Err(CoreError::ProtocolViolation(_))
    ));

    let started_v2 = || {
        let mut v2 = V2SessionInitiator::new(&cli, host.host_id(), [0; 32], None, None).unwrap();
        v2.start(NOW).unwrap();
        v2
    };
    assert!(matches!(
        started_v2().with_route_seq(Some(1)),
        Err(CoreError::NotReady(_))
    ));
    assert!(matches!(
        started_v2().with_route_expectation(RouteExpectation::default()),
        Err(CoreError::NotReady(_))
    ));
    let fresh_v2 = V2SessionInitiator::new(&cli, host.host_id(), [0; 32], None, None).unwrap();
    assert!(matches!(
        fresh_v2.with_route_seq(Some(1 << 53)),
        Err(CoreError::ProtocolViolation(_))
    ));
}

// ---------------------------------------------------------------------------
// 0x0C on Wire v2
// ---------------------------------------------------------------------------

struct V2Session {
    init: V2SessionInitiator,
    resp: V2SessionResponder,
    cli_roster: Roster,
}

fn v2_session(route_seq: Option<u64>, resp_padding: Option<PaddingPolicy>) -> V2Session {
    let host = identity(0x20).with_host_id("host-route");
    let cli = identity(0x40);
    let mut cli_roster = client_roster(
        host.host_id(),
        *host.static_key().public_bytes(),
        host.signing_key().public_key(),
    );
    cli_roster
        .set_peer_min_wire_version(host.host_id(), WIRE_VERSION_V2)
        .unwrap();
    let mut init = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *secrets().reconnect_secret(),
        None,
        None,
    )
    .unwrap()
    .with_route_seq(route_seq)
    .unwrap();
    let mut resp = V2SessionResponder::new(&host).unwrap();
    if let Some(p) = resp_padding {
        resp = resp.with_padding_policy(p);
    }
    let mut hroster = host_roster(&cli);
    let m1 = v2_bytes(init.start(NOW).unwrap());
    let m2 = v2_bytes(resp.feed_bytes(&m1, NOW, 1, &mut hroster).unwrap());
    let m3 = v2_bytes(init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    resp.feed_bytes(&m3, NOW, 3, &mut hroster).unwrap();
    assert!(init.is_established() && resp.is_established());
    V2Session {
        init,
        resp,
        cli_roster,
    }
}

fn route_set(signer: &EndpointIdentity, seq: u64) -> Vec<u8> {
    RouteSet::sign(signer, seq, NOW, vec![HINTS[0].to_owned()])
        .unwrap()
        .encode()
}

fn malformed_payloads() -> [Vec<u8>; 2] {
    let mut trailing = route_set(&identity(0x20), 1);
    trailing.push(0);
    [vec![0; MIN_ROUTE_SET_PAYLOAD - 1], trailing]
}

fn sealed_frame(sealed: &mut SealedSession, kind: InnerFrameType, payload: &[u8]) -> Vec<u8> {
    tendril_core::wire::encode_frame(&sealed.seal(kind, payload, 10).unwrap().ciphertext).unwrap()
}

#[test]
fn v2_route_seq_negotiation_and_queue() {
    let mut s = v2_session(Some(0), None);
    assert_eq!(s.resp.peer_route_seq(), Some(0));
    let host = identity(0x20);
    let other = identity(0x70);

    for seq in 1..=5 {
        let signer = if seq == 5 { &other } else { &host };
        let wire = v2_bytes(s.resp.send_route_set(&route_set(signer, seq), 10).unwrap());
        let actions = s
            .init
            .feed_bytes(&wire, NOW, 10, &mut s.cli_roster)
            .unwrap();
        assert!(actions.is_empty(), "no action for a queued route set");
    }
    let queued = s.init.take_route_sets();
    assert_eq!(
        queued.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![2, 3, 4, 5]
    );
    assert!(
        queued[3].verify(host.signing_key().public_key()).is_err(),
        "a bad signature is queued for the runtime to ignore"
    );
    assert!(s.init.take_route_sets().is_empty());
    assert!(s.init.is_established());

    let plain = v2_session(None, None);
    assert_eq!(plain.resp.peer_route_seq(), None);
}

#[test]
fn v2_negotiated_malformed_route_set_closes() {
    for payload in malformed_payloads() {
        let s = v2_session(Some(0), None);
        let (mut init, resp, mut roster) = (s.init, s.resp, s.cli_roster);
        let mut sealed = resp.into_sealed_session().unwrap();
        let wire = sealed_frame(&mut sealed, InnerFrameType::RouteSet, &payload);
        assert_eq!(
            init.feed_bytes(&wire, NOW, 10, &mut roster),
            Err(CoreError::InvalidInnerFramePayload("route set"))
        );
        assert!(init.is_closed());
    }
}

#[test]
fn v2_unnegotiated_initiator_drops_route_sets_unparsed() {
    let s = v2_session(None, None);
    let (mut init, resp, mut roster) = (s.init, s.resp, s.cli_roster);
    let mut sealed = resp.into_sealed_session().unwrap();
    let [short, trailing] = malformed_payloads();
    for payload in [route_set(&identity(0x20), 1), short, trailing] {
        let wire = sealed_frame(&mut sealed, InnerFrameType::RouteSet, &payload);
        assert_eq!(init.feed_bytes(&wire, NOW, 10, &mut roster), Ok(vec![]));
        assert!(init.is_established());
    }
    assert!(init.take_route_sets().is_empty());
    let wire = sealed_frame(&mut sealed, InnerFrameType::Data, b"still open");
    assert_eq!(
        init.feed_bytes(&wire, NOW, 11, &mut roster),
        Ok(vec![V2SessionAction::AppData(b"still open".to_vec())])
    );
}

#[test]
fn v2_responder_closes_on_route_set() {
    let [short, _] = malformed_payloads();
    for payload in [route_set(&identity(0x20), 1), short] {
        let host = identity(0x20).with_host_id("host-route");
        let cli = identity(0x40);
        let mut cli_roster = client_roster(
            host.host_id(),
            *host.static_key().public_bytes(),
            host.signing_key().public_key(),
        );
        let mut init = V2SessionInitiator::new(
            &cli,
            host.host_id(),
            *secrets().reconnect_secret(),
            None,
            None,
        )
        .unwrap();
        let mut resp = V2SessionResponder::new(&host).unwrap();
        let mut hroster = host_roster(&cli);
        let m1 = v2_bytes(init.start(NOW).unwrap());
        let m2 = v2_bytes(resp.feed_bytes(&m1, NOW, 1, &mut hroster).unwrap());
        let m3 = v2_bytes(init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
        resp.feed_bytes(&m3, NOW, 3, &mut hroster).unwrap();

        let mut sealed = init.into_sealed_session().unwrap();
        let wire = sealed_frame(&mut sealed, InnerFrameType::RouteSet, &payload);
        assert_eq!(
            resp.feed_bytes(&wire, NOW, 10, &mut hroster),
            Err(CoreError::InvalidInnerFramePayload(
                "route set from initiator"
            ))
        );
        assert!(resp.is_closed());
    }
}

#[test]
fn v2_send_route_set_needs_negotiation_and_a_fitting_bucket() {
    let payload = route_set(&identity(0x20), 1);

    let mut plain = v2_session(None, None);
    assert!(matches!(
        plain.resp.send_route_set(&payload, 10),
        Err(CoreError::NotReady(_))
    ));
    assert!(plain.resp.is_established());

    let mut s = v2_session(Some(0), None);
    assert_eq!(
        s.resp.send_route_set(&[0; 16], 10),
        Err(CoreError::InvalidInnerFramePayload("route set"))
    );

    let small = PaddingPolicy::with_buckets(vec![1_024, payload.len() + 3], false).unwrap();
    let mut s = v2_session(Some(0), Some(small));
    assert!(matches!(
        s.resp.send_route_set(&payload, 10),
        Err(CoreError::FrameTooLarge { .. })
    ));
    assert!(s.resp.is_established());
    let wire = v2_bytes(s.resp.seal_data(b"after", 11).unwrap());
    assert_eq!(
        s.init.feed_bytes(&wire, NOW, 11, &mut s.cli_roster),
        Ok(vec![V2SessionAction::AppData(b"after".to_vec())]),
        "a refused route set leaves TX state unchanged"
    );

    let exact = PaddingPolicy::with_buckets(vec![payload.len() + 4], false).unwrap();
    let mut s = v2_session(Some(0), Some(exact));
    let wire = v2_bytes(s.resp.send_route_set(&payload, 10).unwrap());
    s.init
        .feed_bytes(&wire, NOW, 10, &mut s.cli_roster)
        .unwrap();
    assert_eq!(s.init.take_route_sets().len(), 1);

    let mut s = v2_session(Some(0), Some(PaddingPolicy::disabled()));
    assert_eq!(
        s.resp.send_route_set(&payload, 10),
        Err(CoreError::UnknownInnerFrameType(0x0C))
    );
    assert!(s.resp.is_established());
}

#[test]
fn v2_send_route_set_too_large_with_rekey_due_leaves_tx_unchanged() {
    let payload = route_set(&identity(0x20), 1);
    let small = PaddingPolicy::with_buckets(vec![1_024, payload.len() + 3], false).unwrap();
    let mut s = v2_session(Some(0), Some(small));
    let due_ms = u64::MAX / 2;
    assert!(matches!(
        s.resp.send_route_set(&payload, due_ms),
        Err(CoreError::FrameTooLarge { .. })
    ));
    assert!(s.resp.is_established());
    // The refused send neither rekeyed nor consumed a nonce: the rekey is still due and the
    // next frame decrypts on the peer.
    let actions = s.resp.seal_data(b"after", due_ms).unwrap();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, V2SessionAction::Rekeyed { .. }))
    );
    let got = s
        .init
        .feed_bytes(&v2_bytes(actions), NOW, 11, &mut s.cli_roster)
        .unwrap();
    assert!(
        got.contains(&V2SessionAction::AppData(b"after".to_vec())),
        "{got:?}"
    );
}

fn noise_pair() -> (NoiseTransport, NoiseTransport) {
    let a = identity(0x40);
    let b = identity(0x20);
    let mut i = NoiseHfsHandshakeBuilder::new()
        .local_private_key(a.static_key().secret_bytes())
        .prologue(b"TND\x02\x01\x00")
        .build_initiator()
        .unwrap();
    let mut r = NoiseHfsHandshakeBuilder::new()
        .local_private_key(b.static_key().secret_bytes())
        .prologue(b"TND\x02\x01\x00")
        .build_responder()
        .unwrap();
    let m1 = i.write_message_vec(&[]).unwrap();
    r.read_message_vec(&m1).unwrap();
    let m2 = r.write_message_vec(&[]).unwrap();
    i.read_message_vec(&m2).unwrap();
    let m3 = i.write_message_vec(&[]).unwrap();
    r.read_message_vec(&m3).unwrap();
    (
        i.into_transport_mode().unwrap(),
        r.into_transport_mode().unwrap(),
    )
}

#[test]
fn route_set_is_padded_only_on_wire_v2() {
    let payload = route_set(&identity(0x20), 1);
    let bare = encode_inner_frame(InnerFrameType::RouteSet, &payload).unwrap();
    assert_eq!(
        decode_v2_inner_frame(&bare, true),
        Err(CoreError::UnknownInnerFrameType(0x0C))
    );
    let padded = pad_inner_frame(
        InnerFrameType::RouteSet,
        &payload,
        &PaddingPolicy::v2_default(),
    )
    .unwrap();
    assert!(matches!(
        decode_v2_inner_frame(&padded, true),
        Ok(V2InnerFrame::Frame {
            kind: InnerFrameType::RouteSet,
            ..
        })
    ));

    // Padding disabled: 0x0C is never sealed and never returned bare.
    let (mut tx_i, tx_r) = noise_pair();
    let bare_ct = tx_i.write_message_vec(&bare).unwrap();
    let mut rx = SealedSession::new(tx_r);
    assert_eq!(
        rx.unseal(&bare_ct),
        Err(CoreError::UnknownInnerFrameType(0x0C))
    );
    let mut sx = SealedSession::new(tx_i);
    let nonce = sx.tx_nonce();
    assert_eq!(
        sx.seal(InnerFrameType::RouteSet, &payload, 0),
        Err(CoreError::UnknownInnerFrameType(0x0C))
    );
    assert_eq!(sx.tx_nonce(), nonce);
}

// ---------------------------------------------------------------------------
// v2 deferred claim
// ---------------------------------------------------------------------------

fn pair_bytes(actions: &[V2PairAction]) -> Vec<u8> {
    actions
        .iter()
        .filter_map(|a| match a {
            V2PairAction::WriteBytes(b) => Some(b.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn v2_deferred_claim_parks_until_commit() {
    let host = identity(0x20).with_host_id("host-route");
    let cli = identity(0x40);
    let params = PakeArgon2Params::production();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr.issue_code(PairingCodeKind::Remote3Group, NOW).unwrap();
    let mut init = V2PakePairInitiator::new(&cli, "Cli", "cli", &code, None, params)
        .unwrap()
        .with_deferred_claim();
    assert!(matches!(init.commit_claim(), Err(CoreError::NotReady(_))));
    let mut resp = V2PakePairResponder::new(&host, PairingPathKind::Remote, params).unwrap();
    let mut hroster = Roster::new();

    let m1 = pair_bytes(&init.start().unwrap());
    let m2 = pair_bytes(&resp.feed_bytes(&m1, NOW, &mut mgr, &mut hroster).unwrap());
    let actions = init.feed_bytes(&m2).unwrap();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, V2PairAction::SasReady { .. }))
    );
    assert!(pair_bytes(&actions).is_empty(), "no msg3 before commit");
    assert!(init.is_awaiting_commit());
    let verified = init.verified_host().unwrap();
    assert_eq!(verified.host_id, host.host_id());
    assert_eq!(&verified.static_pub, host.static_key().public_bytes());
    assert_eq!(&verified.signing_pub, host.signing_key().public_key());
    assert_eq!(verified.rotation_seq, 0);

    let m3 = pair_bytes(&init.commit_claim().unwrap());
    assert!(!m3.is_empty());
    assert!(!init.is_awaiting_commit());
    assert!(matches!(init.commit_claim(), Err(CoreError::NotReady(_))));
    assert_eq!(init.verified_host().unwrap(), verified);

    let resp_actions = resp.feed_bytes(&m3, NOW, &mut mgr, &mut hroster).unwrap();
    assert!(resp_actions.iter().any(|a| matches!(
        a,
        V2PairAction::Completed(V2PairOutcome::ResponderPending { .. })
    )));
    let done = init.feed_bytes(&pair_bytes(&resp_actions)).unwrap();
    assert!(done.iter().any(|a| matches!(
        a,
        V2PairAction::Completed(V2PairOutcome::InitiatorPending { .. })
    )));
}

#[test]
fn v2_deferred_claim_reports_rotation_and_closes_on_an_unexpected_frame() {
    let rh = rotated_host();
    let cli = identity(0x40);
    let params = PakeArgon2Params::production();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr.issue_code(PairingCodeKind::Remote3Group, NOW).unwrap();
    let mut init = V2PakePairInitiator::new(&cli, "Cli", "cli", &code, None, params)
        .unwrap()
        .with_deferred_claim();
    let mut resp = V2PakePairResponder::new(&rh.host, PairingPathKind::Remote, params).unwrap();
    let mut hroster = Roster::new();
    let m1 = pair_bytes(&init.start().unwrap());
    let m2 = pair_bytes(&resp.feed_bytes(&m1, NOW, &mut mgr, &mut hroster).unwrap());
    init.feed_bytes(&m2).unwrap();
    assert!(init.is_awaiting_commit());
    let verified = init.verified_host().unwrap();
    assert_eq!(&verified.signing_pub, rh.host.signing_key().public_key());
    assert_eq!(verified.rotation_seq, 1);

    assert_eq!(
        init.feed_bytes(&[0, 2, 0xAA, 0xBB]),
        Err(CoreError::ProtocolViolation(
            "unexpected frame while awaiting the v2 PAKE claim commit"
        ))
    );
    assert!(!init.is_awaiting_commit());
    assert!(init.verified_host().is_none());
    assert!(matches!(init.commit_claim(), Err(CoreError::NotReady(_))));
    assert!(matches!(
        init.feed_bytes(&m2),
        Err(CoreError::SessionClosed { .. })
    ));
}

// ---------------------------------------------------------------------------
// v2 pairing outcome with a route plan
// ---------------------------------------------------------------------------

fn initiator_outcome(host: &EndpointIdentity, verified: bool) -> V2PairOutcome {
    V2PairOutcome::InitiatorPending {
        device_id: identity(0x40).device_id(),
        host_id: host.host_id().to_owned(),
        host_static_pub: *host.static_key().public_bytes(),
        host_signing_pub: host.signing_key().public_key().clone(),
        host_rotation_seq: 0,
        pairing_sas: "sas".into(),
        host_pin_verified: verified,
        v2_secrets: secrets(),
    }
}

fn signed_plan(host: &EndpointIdentity) -> tendril_core::pairing::PersistPlan {
    let uri = sign(host, &unsigned_recovery(host));
    let check = PairingUri::parse(&uri)
        .unwrap()
        .verify_route_statement(host.signing_key().public_key());
    assert!(matches!(check, RouteCheck::Verified(_)));
    persistable_routes(&check, CODE3, None, &PersistOpts::default())
}

#[test]
fn v2_pair_outcome_applies_route_plan_atomically() {
    let host = identity(0x20).with_host_id("host-route");
    let plan = signed_plan(&host);

    for verified in [true, false] {
        let mut roster = Roster::new();
        let (id, merged) = roster
            .apply_v2_pair_initiator_outcome_with_plan(
                &initiator_outcome(&host, verified),
                "Host",
                &plan,
            )
            .unwrap();
        assert_eq!(id, host.host_id());
        assert_eq!(merged.reason, None);
        let entry = roster.get(&id).unwrap();
        let expected_state = if verified {
            PeerState::Active
        } else {
            PeerState::Pending
        };
        assert_eq!(entry.state, expected_state);
        assert_eq!(
            entry.routes_from(RouteSource::Signed).collect::<Vec<_>>(),
            HINTS.to_vec()
        );
        let meta = entry.route_meta.unwrap();
        assert_eq!((meta.seq, meta.origin), (5, RouteOrigin::Uri));
        assert_eq!(entry.min_wire_version, WIRE_VERSION_V2);
        assert!(entry.v2_secrets.is_some());
        assert!(entry.relay_hints.is_empty());
    }

    // A plan signed for another host's keys fails and leaves the roster unchanged.
    let other = identity(0x70).with_host_id("host-route");
    let mut roster = Roster::new();
    let before = snapshot(&roster);
    assert_eq!(
        roster.apply_v2_pair_initiator_outcome_with_plan(
            &initiator_outcome(&host, true),
            "Host",
            &signed_plan(&other)
        ),
        Err(CoreError::HostKeyUnverified)
    );
    assert_eq!(snapshot(&roster), before);
}

#[test]
fn v2_pair_outcome_accepts_an_operator_v2_relay_route() {
    let host = identity(0x20).with_host_id("host-route");
    let uri = sign(&host, &unsigned_recovery(&host));
    let check = PairingUri::parse(&uri)
        .unwrap()
        .verify_route_statement(host.signing_key().public_key());
    let v2_relay = "wss://relay.example.com/v2/relay";
    let opts = PersistOpts {
        operator_endpoint: Some(v2_relay.into()),
        ..PersistOpts::default()
    };
    let plan = persistable_routes(&check, CODE3, None, &opts);
    assert_eq!(plan.operator.as_deref(), Some(v2_relay));

    for verified in [true, false] {
        let mut roster = Roster::new();
        let (id, merged) = roster
            .apply_v2_pair_initiator_outcome_with_plan(
                &initiator_outcome(&host, verified),
                "Host",
                &plan,
            )
            .unwrap();
        let entry = roster.get(&id).unwrap();
        assert_eq!(
            entry.routes_from(RouteSource::Operator).collect::<Vec<_>>(),
            vec![v2_relay]
        );
        assert!(
            merged
                .persisted
                .iter()
                .any(|r| r.hint == v2_relay && r.source == RouteSource::Operator)
        );
        assert_eq!(entry.min_wire_version, WIRE_VERSION_V2);
    }
}

// ---------------------------------------------------------------------------
// relay_auth::origin_allowed
// ---------------------------------------------------------------------------

#[test]
fn relay_auth_origin_is_byte_exact() {
    let origins = [
        "wss://relay.example.com:443",
        "ws://127.0.0.1:8080/",
        "wss://[2001:db8::1]:8443",
    ];
    for url in [
        "wss://relay.example.com/v1/relay",
        "wss://relay.example.com:443/v1/relay#abc",
        "wss://relay.example.com?x=1",
        "ws://127.0.0.1:8080/v2/relay",
        "wss://[2001:db8::1]:8443/v1/relay",
    ] {
        assert!(origin_allowed(url, &origins), "{url}");
    }
    for url in [
        "wss://relay.example.com:8443/v1/relay",
        "ws://relay.example.com/v1/relay",
        "https://relay.example.com/v1/relay",
        "wss://Relay.example.com/v1/relay",
        "WSS://relay.example.com/v1/relay",
        "wss://relay.example.com./v1/relay",
        "wss://user@relay.example.com/v1/relay",
        "wss://relay.example.com@evil.example/v1/relay",
        "wss://evil.example\\@relay.example.com/v1/relay",
        "wss://relay.example.com:0443/v1/relay",
        "wss://relay.example.com:/v1/relay",
        "wss://relay%2Eexample.com/v1/relay",
        "ws://127.0.0.1/v2/relay",
        "ws://127.0.0.1:8081/v2/relay",
        "wss://[2001:db8::1]/v1/relay",
        "relay.example.com:443",
        "",
    ] {
        assert!(!origin_allowed(url, &origins), "{url}");
    }
    let empty: [&str; 0] = [];
    assert!(!origin_allowed("wss://relay.example.com/v1/relay", &empty));
    // Default ports are made explicit on both sides; configured origins carry no path.
    assert!(origin_allowed(
        "wss://relay.example.com:443/v1/relay",
        &["wss://relay.example.com".to_owned()]
    ));
    assert!(!origin_allowed(
        "wss://relay.example.com/v1/relay",
        &["wss://relay.example.com/v1/relay"]
    ));
    assert!(origin_allowed(
        "http://relay.example.com:80/",
        &["http://relay.example.com"]
    ));
}
