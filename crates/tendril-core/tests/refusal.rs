//! Authenticated refusal of a known but revoked or pending peer (`spec/conformance.md` Section 4).
//!
//! Test names carry the `REF-nn` case they cover. Runtime-only cases (`REF-15`, `REF-21`,
//! `REF-23`) and the audit half of `REF-16` live with the runtime.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256};
use tendril_core::crypto::{SigningKeypair, StaticKeypair, hkdf_sha256_32};
use tendril_core::error::{AdmissionRefusalCode, CoreError, RefusalReason};
use tendril_core::grants::{RevocationListUnsigned, sign_crl};
use tendril_core::identity::EndpointIdentity;
use tendril_core::noise::{MSG1_LEN, NoiseHfsHandshake, NoiseHfsHandshakeBuilder};
use tendril_core::refusal::{
    MAX_REFUSAL_REPLAY_ENTRIES, RefusalLimiter, RefusalMode, RefusalReplayCache,
};
use tendril_core::roster::{PeerState, RefusalPolicy, Roster, V2PeerSecrets};
use tendril_core::session::{SessionAction, SessionCloseCode, SessionMachine};
use tendril_core::v2::{
    MAX_RENDEZVOUS_REPLAY_ENTRIES, PaddingPolicy, RendezvousReplayCache, V2RefusalCaches,
    V2SessionAction, V2SessionInitiator, V2SessionResponder, compute_rendezvous_mac,
    open_v2_refusal_envelope, seal_v2_refusal_envelope, unseal_v2_hello_envelope,
};
use tendril_core::wire::{
    AEAD_TAG_LEN, Intent, PREAMBLE_FLAG_NONE, Preamble, WIRE_VERSION, WIRE_VERSION_V2,
    decode_frame, encode_frame,
};

const NOW: u64 = 1_795_564_800;
const TTL: u64 = 2_592_000;

fn identities() -> (EndpointIdentity, EndpointIdentity) {
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41; 32]),
        SigningKeypair::from_seed([0x42; 32]),
    )
    .with_host_id("host-refusal");
    let cli = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x51; 32]),
        SigningKeypair::from_seed([0x52; 32]),
    );
    (host, cli)
}

fn other_client(seed: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([seed; 32]),
        SigningKeypair::from_seed([seed.wrapping_add(1); 32]),
    )
}

/// Records `cli` on a host roster as `Pending`, then confirms it when `active`.
fn add_client(
    roster: &mut Roster,
    cli: &EndpointIdentity,
    active: bool,
    floor: u8,
    secrets: Option<&V2PeerSecrets>,
) {
    let id = cli.device_id();
    roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "sas".into(),
        )
        .unwrap();
    if active {
        roster.confirm_peer(&id, Some("sas")).unwrap();
    }
    if let Some(secrets) = secrets {
        roster.set_peer_v2_secrets(&id, secrets.clone()).unwrap();
    }
    roster.set_peer_min_wire_version(&id, floor).unwrap();
}

fn host_roster(cli: &EndpointIdentity, active: bool, floor: u8) -> Roster {
    let mut roster = Roster::new();
    add_client(&mut roster, cli, active, floor, None);
    roster
}

fn client_roster(host: &EndpointIdentity) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    roster
}

/// Puts a CRL issued by the host and naming `revoked_id` into `roster` without ingesting it,
/// so the entry stays `Active` and is revoked only by the stored list.
fn store_crl(roster: &Roster, host: &EndpointIdentity, revoked_id: &str) -> Roster {
    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            seq: 1,
            revoked_devices: vec![revoked_id.to_string()],
            revoked_nonces: vec![],
            ts: "2026-11-20T00:00:00Z".into(),
        },
        host.signing_key(),
    )
    .unwrap();
    let mut json = serde_json::to_value(roster).unwrap();
    json["crls"][host.host_id()] = serde_json::to_value(crl).unwrap();
    serde_json::from_value(json).unwrap()
}

fn v1_writes(actions: &[SessionAction]) -> Vec<u8> {
    actions
        .iter()
        .filter_map(|a| match a {
            SessionAction::WriteBytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

/// Runs a v1 session handshake and returns the responder's result for `msg3` and the
/// initiator, which has written `msg3` and reported `Established`.
fn run_v1(
    host: &EndpointIdentity,
    cli: &EndpointIdentity,
    host_roster: &mut Roster,
    mode: RefusalMode,
    limiter: Option<&mut RefusalLimiter>,
    now: u64,
) -> (Result<Vec<SessionAction>, CoreError>, SessionMachine) {
    let mut cli_roster = client_roster(host);
    let mut init = SessionMachine::new_initiator(cli, host.host_id(), None, None, None).unwrap();
    let mut resp = SessionMachine::new_responder_with_refusal(host, None, mode).unwrap();
    let mut scratch = RefusalLimiter::new();
    let limiter = limiter.unwrap_or(&mut scratch);
    let m1 = v1_writes(&init.start().unwrap());
    let m2 = v1_writes(
        &resp
            .feed_bytes_with_limiter(&m1, now, 1, host_roster, limiter)
            .unwrap(),
    );
    let init_actions = init.feed_bytes(&m2, now, 2, &mut cli_roster).unwrap();
    assert!(
        init_actions
            .iter()
            .any(|a| matches!(a, SessionAction::Established { .. })),
        "a v1 initiator reports Established when it writes msg3"
    );
    let m3 = v1_writes(&init_actions);
    let out = resp.feed_bytes_with_limiter(&m3, now, 3, host_roster, limiter);
    (out, init)
}

fn assert_silent(out: &Result<Vec<SessionAction>, CoreError>) {
    match out {
        Err(_) => {}
        Ok(actions) => panic!("expected a silent drop, got {actions:?}"),
    }
}

fn assert_v1_refused(
    out: Result<Vec<SessionAction>, CoreError>,
    mut init: SessionMachine,
    cli: &EndpointIdentity,
    code: u16,
) {
    let actions = out.expect("refusal is an Ok action list");
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, SessionAction::Established { .. })),
        "a responder never emits Established for a refused peer"
    );
    let frame = v1_writes(&actions);
    assert_eq!(frame.len(), 21, "uint16_be(19) || AEAD(0x07 || code)");
    assert_eq!(&frame[..2], &19u16.to_be_bytes());
    assert_eq!(
        actions.last(),
        Some(&SessionAction::Refused {
            peer_device_id: cli.device_id(),
            code,
        })
    );
    let mut cli_roster = Roster::new();
    let closed = init.feed_bytes(&frame, NOW, 4, &mut cli_roster).unwrap();
    assert_eq!(
        closed,
        vec![SessionAction::CloseTransport {
            code,
            reason: String::new(),
        }]
    );
    assert!(matches!(
        init.send_data(b"after", 5),
        Err(CoreError::SessionClosed { code: c, .. }) if c == code
    ));
}

#[test]
fn ref01_v1_revoked_with_notice_gets_close_4001() {
    let (host, cli) = identities();
    let mut roster = host_roster(&cli, true, WIRE_VERSION);
    roster.revoke_peer_at(&cli.device_id(), true, NOW).unwrap();
    let mut limiter = RefusalLimiter::new();
    let (out, init) = run_v1(
        &host,
        &cli,
        &mut roster,
        RefusalMode::Enabled,
        Some(&mut limiter),
        NOW,
    );
    assert_v1_refused(out, init, &cli, SessionCloseCode::PEER_REVOKED);
}

#[test]
fn ref02_v1_pending_gets_close_4004() {
    let (host, cli) = identities();
    let mut roster = host_roster(&cli, false, WIRE_VERSION);
    let (out, init) = run_v1(&host, &cli, &mut roster, RefusalMode::Enabled, None, NOW);
    assert_v1_refused(out, init, &cli, SessionCloseCode::PEER_PENDING);
}

#[test]
fn ref03_v1_stranger_is_dropped_unchanged() {
    let (host, cli) = identities();
    for mode in [RefusalMode::Enabled, RefusalMode::Off] {
        let mut roster = Roster::new();
        let (out, _) = run_v1(&host, &cli, &mut roster, mode, None, NOW);
        assert_eq!(out, Err(CoreError::PeerNotFound(cli.device_id())));
    }
    // The pre-refusal constructor and feed behave the same.
    let mut roster = Roster::new();
    let mut cli_roster = client_roster(&host);
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp = SessionMachine::new_responder(&host, None).unwrap();
    let m1 = v1_writes(&init.start().unwrap());
    let m2 = v1_writes(&resp.feed_bytes(&m1, NOW, 1, &mut roster).unwrap());
    let m3 = v1_writes(&init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    assert_eq!(
        resp.feed_bytes(&m3, NOW, 3, &mut roster),
        Err(CoreError::PeerNotFound(cli.device_id()))
    );
}

#[test]
fn ref04_v1_crl_revoked_active_then_silent_cases() {
    let (host, cli) = identities();
    let id = cli.device_id();

    let mut roster = store_crl(&host_roster(&cli, true, WIRE_VERSION), &host, &id);
    assert_eq!(roster.get(&id).unwrap().state, PeerState::Active);
    let (out, init) = run_v1(&host, &cli, &mut roster, RefusalMode::Enabled, None, NOW);
    assert_v1_refused(out, init, &cli, SessionCloseCode::PEER_REVOKED);

    let mut silent = host_roster(&cli, true, WIRE_VERSION);
    silent.revoke_peer_at(&id, false, NOW).unwrap();
    let (out, _) = run_v1(&host, &cli, &mut silent, RefusalMode::Enabled, None, NOW);
    assert_eq!(out, Err(CoreError::PeerRevoked(id.clone())));

    let mut expired = host_roster(&cli, true, WIRE_VERSION);
    expired.revoke_peer_at(&id, true, NOW).unwrap();
    let (out, _) = run_v1(
        &host,
        &cli,
        &mut expired,
        RefusalMode::Enabled,
        None,
        NOW + TTL,
    );
    assert_eq!(out, Err(CoreError::PeerRevoked(id.clone())));
    assert!(
        expired.get(&id).unwrap().refusal_notice().is_none(),
        "the responder prunes expired notices before classifying"
    );

    let mut limited = host_roster(&cli, true, WIRE_VERSION);
    limited.revoke_peer_at(&id, true, NOW).unwrap();
    let mut limiter = RefusalLimiter::new();
    let (first, init) = run_v1(
        &host,
        &cli,
        &mut limited,
        RefusalMode::Enabled,
        Some(&mut limiter),
        NOW,
    );
    assert_v1_refused(first, init, &cli, SessionCloseCode::PEER_REVOKED);
    let (second, _) = run_v1(
        &host,
        &cli,
        &mut limited,
        RefusalMode::Enabled,
        Some(&mut limiter),
        NOW + 9,
    );
    assert_eq!(second, Err(CoreError::PeerRevoked(id)));
}

#[test]
fn ref16_v1_second_refusal_within_window_is_silent() {
    let (host, cli) = identities();
    let mut roster = host_roster(&cli, false, WIRE_VERSION);
    let mut limiter = RefusalLimiter::new();
    let (first, init) = run_v1(
        &host,
        &cli,
        &mut roster,
        RefusalMode::Enabled,
        Some(&mut limiter),
        NOW,
    );
    assert_v1_refused(first, init, &cli, SessionCloseCode::PEER_PENDING);
    let (second, _) = run_v1(
        &host,
        &cli,
        &mut roster,
        RefusalMode::Enabled,
        Some(&mut limiter),
        NOW + 1,
    );
    assert_eq!(second, Err(CoreError::PeerPending(cli.device_id())));
    let (third, init) = run_v1(
        &host,
        &cli,
        &mut roster,
        RefusalMode::Enabled,
        Some(&mut limiter),
        NOW + 10,
    );
    assert_v1_refused(third, init, &cli, SessionCloseCode::PEER_PENDING);
}

#[test]
fn ref19_v1_v2_floored_pending_and_revoked_get_version_downgrade() {
    let (host, cli) = identities();
    let downgrade = Err(CoreError::VersionDowngrade {
        peer_min: WIRE_VERSION_V2,
        negotiated: WIRE_VERSION,
    });

    let mut pending = host_roster(&cli, false, WIRE_VERSION_V2);
    let (out, _) = run_v1(&host, &cli, &mut pending, RefusalMode::Enabled, None, NOW);
    assert_eq!(out, downgrade);

    let mut revoked = host_roster(&cli, true, WIRE_VERSION_V2);
    revoked.revoke_peer_at(&cli.device_id(), true, NOW).unwrap();
    let (out, _) = run_v1(&host, &cli, &mut revoked, RefusalMode::Enabled, None, NOW);
    assert_eq!(out, downgrade);
}

#[test]
fn v1_listener_mode_off_manifest_pins_and_missing_limiter_are_silent() {
    let (host, cli) = identities();
    let mut roster = host_roster(&cli, false, WIRE_VERSION);
    let (out, _) = run_v1(&host, &cli, &mut roster, RefusalMode::Off, None, NOW);
    assert_eq!(out, Err(CoreError::PeerPending(cli.device_id())));

    let mut pinned = host_roster(&cli, false, WIRE_VERSION);
    pinned
        .pin_signing_hash(&cli.device_id(), [0x11; 32])
        .unwrap();
    let (out, _) = run_v1(&host, &cli, &mut pinned, RefusalMode::Enabled, None, NOW);
    assert_silent(&out);

    let mut off = host_roster(&cli, false, WIRE_VERSION);
    off.set_refusal_policy(RefusalPolicy {
        pending: false,
        revoked_notice_ttl_secs: TTL,
    });
    let (out, _) = run_v1(&host, &cli, &mut off, RefusalMode::Enabled, None, NOW);
    assert_silent(&out);

    // An enabled responder fed without a limiter falls back to the silent drop.
    let mut roster = host_roster(&cli, false, WIRE_VERSION);
    let mut cli_roster = client_roster(&host);
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp =
        SessionMachine::new_responder_with_refusal(&host, None, RefusalMode::Enabled).unwrap();
    let m1 = v1_writes(&init.start().unwrap());
    let m2 = v1_writes(&resp.feed_bytes(&m1, NOW, 1, &mut roster).unwrap());
    let m3 = v1_writes(&init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    assert_eq!(
        resp.feed_bytes(&m3, NOW, 3, &mut roster),
        Err(CoreError::PeerPending(cli.device_id()))
    );
}

#[test]
fn ref24_v1_close_codes_map_only_on_initiators() {
    let (host, cli) = identities();
    for (code, refusal) in [
        (SessionCloseCode::GRANT_EXPIRED, false),
        (SessionCloseCode::KEY_UNVERIFIED, false),
        (SessionCloseCode::NORMAL, false),
        (4450, true),
        (SessionCloseCode::PEER_REVOKED, true),
    ] {
        let mut roster = host_roster(&cli, true, WIRE_VERSION);
        let mut cli_roster = client_roster(&host);
        let mut init =
            SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
        let mut resp = SessionMachine::new_responder(&host, None).unwrap();
        let m1 = v1_writes(&init.start().unwrap());
        let m2 = v1_writes(&resp.feed_bytes(&m1, NOW, 1, &mut roster).unwrap());
        let m3 = v1_writes(&init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
        resp.feed_bytes(&m3, NOW, 3, &mut roster).unwrap();

        // Responder to initiator.
        let close = v1_writes(&resp.send_close(code, "").unwrap());
        let got = init.feed_bytes(&close, NOW, 4, &mut cli_roster).unwrap();
        assert_eq!(
            got,
            vec![SessionAction::CloseTransport {
                code,
                reason: String::new()
            }]
        );
        let later = init.send_data(b"x", 5).unwrap_err();
        let expected = if refusal {
            code
        } else {
            SessionCloseCode::NORMAL
        };
        assert!(
            matches!(later, CoreError::SessionClosed { code: c, .. } if c == expected),
            "code {code}: {later:?}"
        );
        assert_eq!(RefusalReason::from_close_code(code).is_some(), refusal);
    }

    // Initiator to responder: the responder keeps the raw code and never maps it.
    let mut roster = host_roster(&cli, true, WIRE_VERSION);
    let mut cli_roster = client_roster(&host);
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp = SessionMachine::new_responder(&host, None).unwrap();
    let m1 = v1_writes(&init.start().unwrap());
    let m2 = v1_writes(&resp.feed_bytes(&m1, NOW, 1, &mut roster).unwrap());
    let m3 = v1_writes(&init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    resp.feed_bytes(&m3, NOW, 3, &mut roster).unwrap();
    let close = v1_writes(
        &init
            .send_close(SessionCloseCode::PEER_REVOKED, "x")
            .unwrap(),
    );
    assert_eq!(
        resp.feed_bytes(&close, NOW, 4, &mut roster).unwrap(),
        vec![SessionAction::CloseTransport {
            code: SessionCloseCode::PEER_REVOKED,
            reason: "x".into()
        }]
    );
    assert!(matches!(
        resp.send_data(b"x", 5),
        Err(CoreError::SessionClosed {
            code: SessionCloseCode::NORMAL,
            ..
        })
    ));
}

#[test]
fn v1_active_peer_still_connects_on_an_enabled_listener() {
    let (host, cli) = identities();
    let mut roster = host_roster(&cli, true, WIRE_VERSION);
    let other = other_client(0x61);
    add_client(&mut roster, &other, true, WIRE_VERSION, None);
    roster
        .revoke_peer_at(&other.device_id(), true, NOW)
        .unwrap();
    let (out, _) = run_v1(&host, &cli, &mut roster, RefusalMode::Enabled, None, NOW);
    assert!(
        out.unwrap()
            .iter()
            .any(|a| matches!(a, SessionAction::Established { .. }))
    );
}

// ---------------------------------------------------------------------------
// Wire v2
// ---------------------------------------------------------------------------

const SECRET: [u8; 32] = [0x66; 32];

fn secrets(seed: u8) -> V2PeerSecrets {
    V2PeerSecrets::new([seed; 32], [seed ^ 0xFF; 32])
}

fn v2_writes(actions: &[V2SessionAction]) -> Vec<u8> {
    actions
        .iter()
        .filter_map(|a| match a {
            V2SessionAction::WriteBytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

fn refused_actions(actions: &[V2SessionAction]) -> Vec<&V2SessionAction> {
    actions
        .iter()
        .filter(|a| matches!(a, V2SessionAction::Refused { .. }))
        .collect()
}

/// The endpoint-wide caches a runtime owns for its v2 listener.
#[derive(Default)]
struct Caches {
    replay: RendezvousReplayCache,
    refusal: RefusalReplayCache,
    limiter: RefusalLimiter,
}

impl Caches {
    fn feed(
        &mut self,
        resp: &mut V2SessionResponder,
        bytes: &[u8],
        now: u64,
        roster: &mut Roster,
    ) -> Result<Vec<V2SessionAction>, CoreError> {
        resp.feed_bytes_with_caches(
            bytes,
            now,
            1,
            roster,
            &mut self.replay,
            V2RefusalCaches {
                replay: &mut self.refusal,
                limiter: &mut self.limiter,
            },
        )
    }
}

fn v2_host_roster(cli: &EndpointIdentity, active: bool, s: &V2PeerSecrets) -> Roster {
    let mut roster = Roster::new();
    add_client(&mut roster, cli, active, WIRE_VERSION_V2, Some(s));
    roster
}

fn enabled_responder(host: &EndpointIdentity) -> V2SessionResponder {
    V2SessionResponder::new_with_refusal(host, RefusalMode::Enabled).unwrap()
}

/// Sends a v2 `msg1` under `secret` and returns the responder's `msg1` actions and the result
/// of the initiator reading `msg2`.
#[allow(clippy::too_many_arguments)]
fn v2_attempt(
    host: &EndpointIdentity,
    cli: &EndpointIdentity,
    secret: [u8; 32],
    roster: &mut Roster,
    caches: &mut Caches,
    nonce: Option<[u8; 16]>,
    ts: u64,
    now: u64,
) -> (
    Vec<V2SessionAction>,
    Result<Vec<V2SessionAction>, CoreError>,
) {
    let mut init = V2SessionInitiator::new(cli, host.host_id(), secret, None, None).unwrap();
    if let Some(n) = nonce {
        init = init.with_rendezvous_nonce_for_testing_only(n);
    }
    let mut resp = enabled_responder(host);
    let m1 = v2_writes(&init.start(ts).unwrap());
    let resp_actions = caches.feed(&mut resp, &m1, now, roster).unwrap();
    let m2 = v2_writes(&resp_actions);
    let mut cli_roster = client_roster(host);
    let init_out = init.feed_bytes(&m2, now, 2, &mut cli_roster);
    if init_out.is_err() {
        assert!(init.is_closed());
    }
    (resp_actions, init_out)
}

fn assert_v2_refused(
    resp_actions: &[V2SessionAction],
    init_out: Result<Vec<V2SessionAction>, CoreError>,
    cli: &EndpointIdentity,
    reason: RefusalReason,
) {
    assert_eq!(
        refused_actions(resp_actions),
        vec![&V2SessionAction::Refused {
            peer_device_id: cli.device_id(),
            code: reason.close_code(),
            at_msg2: true,
        }]
    );
    assert_eq!(
        init_out,
        Err(CoreError::PeerRefused { reason }),
        "the initiator stops at msg2 and writes no msg3"
    );
}

fn assert_v2_decoy(
    resp_actions: &[V2SessionAction],
    init_out: &Result<Vec<V2SessionAction>, CoreError>,
) {
    assert!(refused_actions(resp_actions).is_empty(), "{resp_actions:?}");
    assert_eq!(init_out, &Err(CoreError::HostKeyUnverified));
}

/// A hand-built initiator that exposes the raw `msg2`: it sends `msg1` under `secret` with
/// `nonce` and returns the handshake, ready to read `msg2`.
fn raw_initiator(
    cli: &EndpointIdentity,
    secret: &[u8; 32],
    nonce: [u8; 16],
    ts: u64,
) -> (NoiseHfsHandshake, Vec<u8>) {
    let preamble = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    let mut hs = NoiseHfsHandshakeBuilder::new()
        .local_private_key(cli.static_key().secret_bytes())
        .prologue(&preamble)
        .build_initiator()
        .unwrap();
    let msg1 = hs
        .write_msg1_with_payload(|e_pub, ek| {
            let ek_hash: [u8; 32] = Sha256::digest(ek).into();
            let mac = compute_rendezvous_mac(secret, &preamble, e_pub, &ek_hash, &nonce, ts);
            let mut p = nonce.to_vec();
            p.extend_from_slice(&ts.to_be_bytes());
            p.extend_from_slice(&mac);
            Ok(p)
        })
        .unwrap();
    let mut wire = preamble.to_vec();
    wire.extend_from_slice(&encode_frame(&msg1).unwrap());
    (hs, wire)
}

struct RawMsg2 {
    len: usize,
    envelope: Vec<u8>,
    h_pre: [u8; 32],
    remote_static: [u8; 32],
}

fn raw_msg2(hs: &mut NoiseHfsHandshake, m2: &[u8]) -> RawMsg2 {
    let (body, _) = decode_frame(m2).unwrap();
    let (env, h_pre) = hs.read_msg2_with_pre_payload_hash(body).unwrap();
    RawMsg2 {
        len: m2.len(),
        envelope: env.to_vec(),
        h_pre,
        remote_static: *hs.get_remote_static().unwrap(),
    }
}

#[test]
fn ref05_v2_revoked_with_notice_is_refused_at_msg2() {
    let (host, cli) = identities();
    let s = secrets(0x66);
    let mut roster = v2_host_roster(&cli, true, &s);
    roster.revoke_peer_at(&cli.device_id(), true, NOW).unwrap();
    let mut caches = Caches::default();
    let (resp_actions, init_out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW,
        NOW,
    );
    assert_v2_refused(&resp_actions, init_out, &cli, RefusalReason::Revoked);
    assert!(
        caches.replay.is_empty(),
        "refusals never use the shared cache"
    );
    assert_eq!(caches.refusal.len(), 1);

    // The refusal uses a decoy static, and the responder then behaves exactly as on a decoy.
    let nonce = [0x0A; 16];
    let (mut hs, m1) = raw_initiator(&cli, &SECRET, nonce, NOW);
    let mut resp = enabled_responder(&host);
    let m2 = v2_writes(&caches.feed(&mut resp, &m1, NOW + 10, &mut roster).unwrap());
    let raw = raw_msg2(&mut hs, &m2);
    assert_ne!(&raw.remote_static, host.static_key().public_bytes());
    assert_eq!(
        open_v2_refusal_envelope(
            &SECRET,
            &nonce,
            &raw.h_pre,
            &raw.envelope,
            &raw.remote_static
        ),
        Ok(RefusalReason::Revoked)
    );
    let msg3 = hs.write_message_vec(&[0u8; 512]).unwrap();
    assert!(
        !resp.is_closed(),
        "the responder waits for msg3 as on a decoy"
    );
    assert_eq!(
        caches.feed(
            &mut resp,
            &encode_frame(&msg3).unwrap(),
            NOW + 10,
            &mut roster
        ),
        Err(CoreError::HostKeyUnverified)
    );
}

#[test]
fn ref06_v2_genuine_decoy_and_refusal_msg2_have_equal_length() {
    let (mut host, cli) = identities();
    let revoked = other_client(0x61);
    for rotated in [false, true] {
        if rotated {
            host.rotate(
                StaticKeypair::from_scalar([0x43; 32]),
                SigningKeypair::from_seed([0x44; 32]),
                NOW - 100,
            )
            .unwrap();
        }
        let mut roster = v2_host_roster(&cli, true, &secrets(0x66));
        add_client(
            &mut roster,
            &revoked,
            true,
            WIRE_VERSION_V2,
            Some(&secrets(0x67)),
        );
        roster
            .revoke_peer_at(&revoked.device_id(), true, NOW)
            .unwrap();
        let mut caches = Caches::default();
        let mut lens = Vec::new();
        let mut kinds = Vec::new();
        for (who, secret, n) in [
            (&cli, [0x66; 32], 1u8),
            (&cli, [0x99; 32], 2),
            (&revoked, [0x67; 32], 3),
        ] {
            let (mut hs, m1) = raw_initiator(who, &secret, [n; 16], NOW);
            let mut resp = enabled_responder(&host);
            let actions = caches.feed(&mut resp, &m1, NOW, &mut roster).unwrap();
            kinds.push(refused_actions(&actions).len());
            let raw = raw_msg2(&mut hs, &v2_writes(&actions));
            lens.push(raw.len);
            assert!([4096, 16_384].contains(&raw.envelope.len()));
        }
        assert_eq!(kinds, vec![0, 0, 1], "genuine, decoy, refusal");
        assert!(
            lens.iter().all(|l| *l == lens[0]),
            "rotated={rotated}: {lens:?}"
        );
        assert_eq!(lens[0] > 16_384, rotated);
    }
}

#[test]
fn ref07_v2_pending_with_secrets_is_refused_pending() {
    let (host, cli) = identities();
    let mut roster = v2_host_roster(&cli, false, &secrets(0x66));
    let mut caches = Caches::default();
    let (resp_actions, init_out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW,
        NOW,
    );
    assert_v2_refused(&resp_actions, init_out, &cli, RefusalReason::Pending);
}

#[test]
fn ref08_v2_stale_replayed_or_full_cache_gets_decoy_without_charging_the_limiter() {
    let (host, cli) = identities();

    let mut roster = v2_host_roster(&cli, false, &secrets(0x66));
    let mut caches = Caches::default();
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW - 400,
        NOW,
    );
    assert_v2_decoy(&a, &out);
    assert!(
        caches.limiter.is_empty(),
        "stale ts never charges the limiter"
    );

    // Replay of a refused msg1 (nonce in the refusal cache).
    let nonce = [0x21; 16];
    let mut init = V2SessionInitiator::new(&cli, host.host_id(), SECRET, None, None)
        .unwrap()
        .with_rendezvous_nonce_for_testing_only(nonce);
    let m1 = v2_writes(&init.start(NOW).unwrap());
    let mut caches = Caches::default();
    let first = caches
        .feed(&mut enabled_responder(&host), &m1, NOW, &mut roster)
        .unwrap();
    assert_eq!(refused_actions(&first).len(), 1);
    let replay = caches
        .feed(&mut enabled_responder(&host), &m1, NOW + 10, &mut roster)
        .unwrap();
    assert!(refused_actions(&replay).is_empty());
    // Had the replay charged the limiter at NOW + 10, this attempt would be limited.
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW + 15,
        NOW + 15,
    );
    assert_v2_refused(&a, out, &cli, RefusalReason::Pending);

    // Nonce already in the shared replay cache.
    let mut caches = Caches::default();
    let nonce = [0x22; 16];
    assert!(caches.replay.record(nonce, NOW, NOW));
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        Some(nonce),
        NOW,
        NOW,
    );
    assert_v2_decoy(&a, &out);
    assert!(caches.limiter.is_empty());

    // Full refusal cache.
    let mut caches = Caches::default();
    for i in 0..MAX_REFUSAL_REPLAY_ENTRIES {
        let mut n = [0xEE; 16];
        n[..8].copy_from_slice(&(i as u64).to_be_bytes());
        assert!(caches.refusal.insert(n, NOW, NOW));
    }
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW,
        NOW,
    );
    assert_v2_decoy(&a, &out);
    assert!(caches.limiter.is_empty());
}

#[test]
fn ref09_v2_old_initiator_reads_a_refusal_as_host_key_unverified() {
    let (host, cli) = identities();
    let mut roster = v2_host_roster(&cli, false, &secrets(0x66));
    let nonce = [0x31; 16];
    let (mut hs, m1) = raw_initiator(&cli, &SECRET, nonce, NOW);
    let mut caches = Caches::default();
    let m2 = v2_writes(
        &caches
            .feed(&mut enabled_responder(&host), &m1, NOW, &mut roster)
            .unwrap(),
    );
    let raw = raw_msg2(&mut hs, &m2);
    assert_eq!(
        unseal_v2_hello_envelope(&SECRET, &nonce, &raw.h_pre, &raw.envelope).map(|_| ()),
        Err(CoreError::HostKeyUnverified)
    );
    assert_eq!(
        open_v2_refusal_envelope(
            &SECRET,
            &nonce,
            &raw.h_pre,
            &raw.envelope,
            &raw.remote_static
        ),
        Ok(RefusalReason::Pending)
    );
}

/// Answers a real initiator's `msg1` with a refusal envelope built from `pt`, sealed under the
/// genuine refusal key, and returns the initiator's result.
fn malformed_refusal(pt: Vec<u8>) -> Result<Vec<V2SessionAction>, CoreError> {
    let (host, cli) = identities();
    let nonce = [0x41; 16];
    let mut init = V2SessionInitiator::new(&cli, host.host_id(), SECRET, None, None)
        .unwrap()
        .with_rendezvous_nonce_for_testing_only(nonce);
    let m1 = v2_writes(&init.start(NOW).unwrap());
    let preamble = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    let mut hs = NoiseHfsHandshakeBuilder::new()
        .local_private_key(StaticKeypair::from_scalar([0x77; 32]).secret_bytes())
        .prologue(&preamble)
        .build_responder()
        .unwrap();
    let (body, _) = decode_frame(&m1[6..]).unwrap();
    hs.read_message_vec(body).unwrap();
    let key = hkdf_sha256_32(&SECRET, &nonce, b"tendril-v2-refusal-seal");
    let msg2 = hs
        .write_msg2_with_hash(|h_pre| {
            let mut buf = pt.clone();
            ChaCha20Poly1305::new_from_slice(&*key)
                .unwrap()
                .encrypt_in_place(&Nonce::from([0u8; 12]), h_pre, &mut buf)
                .unwrap();
            Ok(buf)
        })
        .unwrap();
    let mut cli_roster = client_roster(&host);
    let out = init.feed_bytes(&encode_frame(&msg2).unwrap(), NOW, 2, &mut cli_roster);
    assert!(init.is_closed());
    out
}

fn refusal_pt(len: usize, prefix: u16, body: &[u8]) -> Vec<u8> {
    let mut pt = vec![0u8; len];
    pt[..2].copy_from_slice(&prefix.to_be_bytes());
    pt[2..2 + body.len()].copy_from_slice(body);
    pt
}

#[test]
fn ref10_v2_malformed_opened_refusals_are_protocol_violations() {
    let bucket_pt = 4096 - AEAD_TAG_LEN;
    let good = refusal_pt(bucket_pt, 3, &[0x01, 0x0F, 0xA1]);
    assert_eq!(
        malformed_refusal(good.clone()),
        Err(CoreError::PeerRefused {
            reason: RefusalReason::Revoked
        })
    );
    let mut nonzero_pad = good;
    *nonzero_pad.last_mut().unwrap() = 1;
    let cases = [
        ("version", refusal_pt(bucket_pt, 3, &[0x02, 0x0F, 0xA1])),
        ("len", refusal_pt(bucket_pt, 4, &[0x01, 0x0F, 0xA1, 0x00])),
        ("len overflow", refusal_pt(bucket_pt, 0xFFFF, &[0x01])),
        ("padding", nonzero_pad),
        ("code 4002", refusal_pt(bucket_pt, 3, &[0x01, 0x0F, 0xA2])),
        ("code 1000", refusal_pt(bucket_pt, 3, &[0x01, 0x03, 0xE8])),
        (
            "bucket",
            refusal_pt(4000 - AEAD_TAG_LEN, 3, &[0x01, 0x0F, 0xA1]),
        ),
    ];
    for (name, pt) in cases {
        let out = malformed_refusal(pt);
        assert!(
            matches!(out, Err(CoreError::ProtocolViolation(_))),
            "{name}: {out:?}"
        );
    }
}

#[test]
fn ref10_v2_refusal_from_a_low_order_static_is_a_protocol_violation() {
    let nonce = [0x42; 16];
    let h_pre = [0x43; 32];
    let env =
        seal_v2_refusal_envelope(&SECRET, &nonce, &h_pre, 4096, RefusalReason::Revoked).unwrap();
    let valid = *StaticKeypair::from_scalar([0x44; 32]).public_bytes();
    assert_eq!(
        open_v2_refusal_envelope(&SECRET, &nonce, &h_pre, &env, &valid),
        Ok(RefusalReason::Revoked)
    );
    for low_order in [[0u8; 32], {
        let mut p = [0u8; 32];
        p[0] = 1;
        p
    }] {
        assert!(matches!(
            open_v2_refusal_envelope(&SECRET, &nonce, &h_pre, &env, &low_order),
            Err(CoreError::ProtocolViolation(_))
        ));
    }
    assert_eq!(
        open_v2_refusal_envelope(&[0x01; 32], &nonce, &h_pre, &env, &valid),
        Err(CoreError::HostKeyUnverified)
    );
    let other = RefusalReason::Other(AdmissionRefusalCode::new(4450).unwrap());
    let env = seal_v2_refusal_envelope(&SECRET, &nonce, &h_pre, 16_384, other).unwrap();
    assert_eq!(env.len(), 16_384);
    assert_eq!(
        open_v2_refusal_envelope(&SECRET, &nonce, &h_pre, &env, &valid),
        Ok(other)
    );
    assert!(seal_v2_refusal_envelope(&SECRET, &nonce, &h_pre, 4000, other).is_err());
}

/// Runs a genuine v2 handshake up to the responder reading `msg3`, letting `between` change
/// the host roster after `msg2`.
fn v2_race(
    padding: PaddingPolicy,
    secret: [u8; 32],
    alternate: Option<V2PeerSecrets>,
    between: impl FnOnce(&mut Roster, &str),
) -> (
    Result<Vec<V2SessionAction>, CoreError>,
    V2SessionInitiator,
    V2SessionResponder,
) {
    let (host, cli) = identities();
    let mut roster = v2_host_roster(&cli, true, &secrets(0x66));
    if let Some(alt) = alternate {
        roster
            .add_rendezvous_alternate(&cli.device_id(), alt)
            .unwrap();
    }
    let mut cli_roster = client_roster(&host);
    let mut caches = Caches::default();
    let mut init = V2SessionInitiator::new(&cli, host.host_id(), secret, None, None)
        .unwrap()
        .with_padding_policy(padding.clone());
    let mut resp = enabled_responder(&host).with_padding_policy(padding);
    let m1 = v2_writes(&init.start(NOW).unwrap());
    let m2 = v2_writes(&caches.feed(&mut resp, &m1, NOW, &mut roster).unwrap());
    let init_actions = init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap();
    assert!(init.is_established());
    between(&mut roster, &cli.device_id());
    let out = caches.feed(&mut resp, &v2_writes(&init_actions), NOW, &mut roster);
    (out, init, resp)
}

#[test]
fn ref11_v2_msg3_race_refuses_after_establish_under_the_session_padding() {
    for (padding, bare) in [
        (PaddingPolicy::v2_default(), false),
        (PaddingPolicy::disabled(), true),
    ] {
        let (out, mut init, resp) = v2_race(padding, SECRET, None, |r, id| {
            r.revoke_peer_at(id, true, NOW).unwrap();
        });
        let actions = out.unwrap();
        assert!(resp.is_closed());
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, V2SessionAction::Established { .. }))
        );
        assert_eq!(
            actions.last(),
            Some(&V2SessionAction::Refused {
                peer_device_id: identities().1.device_id(),
                code: SessionCloseCode::PEER_REVOKED,
                at_msg2: false,
            })
        );
        let frame = v2_writes(&actions);
        assert_eq!(frame.len() == 2 + 3 + AEAD_TAG_LEN, bare, "{}", frame.len());
        let mut cli_roster = Roster::new();
        assert_eq!(
            init.feed_bytes(&frame, NOW, 3, &mut cli_roster).unwrap(),
            vec![V2SessionAction::CloseTransport {
                code: SessionCloseCode::PEER_REVOKED,
                reason: String::new(),
            }]
        );
        assert!(matches!(
            init.seal_data(b"x", 4),
            Err(CoreError::SessionClosed {
                code: SessionCloseCode::PEER_REVOKED,
                ..
            })
        ));
    }
}

#[test]
fn ref11_v2_msg3_race_without_notice_or_via_alternate_is_silent() {
    let (out, _, _) = v2_race(PaddingPolicy::v2_default(), SECRET, None, |r, id| {
        r.revoke_peer_at(id, false, NOW).unwrap();
    });
    assert!(matches!(out, Err(CoreError::PeerRevoked(_))), "{out:?}");

    let alt = secrets(0x88);
    let (out, _, _) = v2_race(
        PaddingPolicy::v2_default(),
        *alt.reconnect_secret(),
        Some(alt.clone()),
        |r, id| {
            r.revoke_peer_at(id, true, NOW).unwrap();
        },
    );
    assert!(matches!(out, Err(CoreError::PeerRevoked(_))), "{out:?}");
}

#[test]
fn ref16_v2_second_refusal_within_window_is_a_decoy() {
    let (host, cli) = identities();
    let mut roster = v2_host_roster(&cli, true, &secrets(0x66));
    roster.revoke_peer_at(&cli.device_id(), true, NOW).unwrap();
    let mut caches = Caches::default();
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW,
        NOW,
    );
    assert_v2_refused(&a, out, &cli, RefusalReason::Revoked);
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW + 9,
        NOW + 9,
    );
    assert_v2_decoy(&a, &out);
    assert_eq!(caches.refusal.len(), 1, "a limited refusal inserts nothing");
}

#[test]
fn ref20_v2_refusal_flood_never_starves_active_peers() {
    let (host, cli) = identities();
    let revoked = other_client(0x61);
    let mut roster = v2_host_roster(&cli, true, &secrets(0x66));
    add_client(
        &mut roster,
        &revoked,
        true,
        WIRE_VERSION_V2,
        Some(&secrets(0x67)),
    );
    roster
        .revoke_peer_at(&revoked.device_id(), true, NOW)
        .unwrap();
    let mut caches = Caches::default();

    // One msg1 body, re-proved under a fresh nonce each time: the proof is cleartext.
    let (_, base) = raw_initiator(&revoked, &[0x67; 32], [0; 16], NOW);
    let preamble: [u8; 6] = base[..6].try_into().unwrap();
    let (body, _) = decode_frame(&base[6..]).unwrap();
    let mut body = body.to_vec();
    let e_pub: [u8; 32] = body[..32].try_into().unwrap();
    let ek_hash: [u8; 32] = Sha256::digest(&body[32..MSG1_LEN]).into();
    let mut refused = 0;
    for i in 0..(MAX_RENDEZVOUS_REPLAY_ENTRIES + 100) {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let mac = compute_rendezvous_mac(&[0x67; 32], &preamble, &e_pub, &ek_hash, &nonce, NOW);
        body[MSG1_LEN..MSG1_LEN + 16].copy_from_slice(&nonce);
        body[MSG1_LEN + 24..MSG1_LEN + 56].copy_from_slice(&mac);
        let mut wire = preamble.to_vec();
        wire.extend_from_slice(&encode_frame(&body).unwrap());
        let actions = caches
            .feed(&mut enabled_responder(&host), &wire, NOW, &mut roster)
            .unwrap();
        refused += refused_actions(&actions).len();
    }
    assert_eq!(refused, 1, "the limiter allows one refusal per window");
    assert!(caches.replay.is_empty());
    assert_eq!(caches.refusal.len(), 1);

    let mut cli_roster = client_roster(&host);
    let mut init = V2SessionInitiator::new(&cli, host.host_id(), SECRET, None, None).unwrap();
    let mut resp = enabled_responder(&host);
    let m1 = v2_writes(&init.start(NOW).unwrap());
    let m2 = v2_writes(&caches.feed(&mut resp, &m1, NOW, &mut roster).unwrap());
    let m3 = v2_writes(&init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    let done = caches.feed(&mut resp, &m3, NOW, &mut roster).unwrap();
    assert!(
        done.iter()
            .any(|a| matches!(a, V2SessionAction::Established { .. }))
    );
}

#[test]
fn ref22_v2_identity_collision_is_silent_in_either_order() {
    let (host, _) = identities();
    let a = other_client(0x71);
    let b = other_client(0x73);
    for (revoke, connect) in [(&a, &b), (&b, &a)] {
        let mut roster = Roster::new();
        add_client(&mut roster, &a, true, WIRE_VERSION_V2, Some(&secrets(0x66)));
        add_client(&mut roster, &b, true, WIRE_VERSION_V2, Some(&secrets(0x66)));
        roster
            .revoke_peer_at(&revoke.device_id(), true, NOW)
            .unwrap();
        for who in [connect, revoke] {
            let mut caches = Caches::default();
            let (acts, out) =
                v2_attempt(&host, who, SECRET, &mut roster, &mut caches, None, NOW, NOW);
            assert_v2_decoy(&acts, &out);
            assert!(caches.limiter.is_empty());
        }
    }
}

#[test]
fn ref22_v2_crl_revoked_alternates_are_never_genuine() {
    let (host, cli) = identities();
    let base = v2_host_roster(&cli, true, &secrets(0x66));
    let mut roster = store_crl(&base, &host, &cli.device_id());
    let alt = secrets(0x88);
    roster
        .add_rendezvous_alternate(&cli.device_id(), alt.clone())
        .unwrap();
    let mut caches = Caches::default();
    let (acts, out) = v2_attempt(
        &host,
        &cli,
        *alt.reconnect_secret(),
        &mut roster,
        &mut caches,
        None,
        NOW,
        NOW,
    );
    assert_v2_decoy(&acts, &out);
    let (acts, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW,
        NOW,
    );
    assert_v2_refused(&acts, out, &cli, RefusalReason::Revoked);
}

#[test]
fn v2_genuine_msg1_whose_nonce_was_refused_gets_a_decoy() {
    let (host, cli) = identities();
    let mut roster = v2_host_roster(&cli, false, &secrets(0x66));
    let mut caches = Caches::default();
    let nonce = [0x51; 16];
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        Some(nonce),
        NOW,
        NOW,
    );
    assert_v2_refused(&a, out, &cli, RefusalReason::Pending);
    roster.confirm_peer(&cli.device_id(), Some("sas")).unwrap();
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        Some(nonce),
        NOW,
        NOW,
    );
    assert_v2_decoy(&a, &out);
    assert!(caches.replay.is_empty());
}

#[test]
fn v2_mode_off_policy_off_manifest_pins_and_plain_feed_are_decoys() {
    let (host, cli) = identities();
    let run = |roster: &mut Roster, mode: RefusalMode, plain: bool| {
        let mut init = V2SessionInitiator::new(&cli, host.host_id(), SECRET, None, None).unwrap();
        let mut resp = V2SessionResponder::new_with_refusal(&host, mode).unwrap();
        let m1 = v2_writes(&init.start(NOW).unwrap());
        let acts = if plain {
            resp.feed_bytes(&m1, NOW, 1, roster).unwrap()
        } else {
            Caches::default().feed(&mut resp, &m1, NOW, roster).unwrap()
        };
        let out = init.feed_bytes(&v2_writes(&acts), NOW, 2, &mut client_roster(&host));
        assert_v2_decoy(&acts, &out);
    };
    run(
        &mut v2_host_roster(&cli, false, &secrets(0x66)),
        RefusalMode::Off,
        false,
    );
    run(
        &mut v2_host_roster(&cli, false, &secrets(0x66)),
        RefusalMode::Enabled,
        true,
    );
    let mut pinned = v2_host_roster(&cli, false, &secrets(0x66));
    pinned
        .pin_signing_hash(&cli.device_id(), [0x11; 32])
        .unwrap();
    run(&mut pinned, RefusalMode::Enabled, false);
    let mut policy_off = v2_host_roster(&cli, false, &secrets(0x66));
    policy_off.set_refusal_policy(RefusalPolicy {
        pending: false,
        revoked_notice_ttl_secs: TTL,
    });
    run(&mut policy_off, RefusalMode::Enabled, false);
    let mut expired = v2_host_roster(&cli, true, &secrets(0x66));
    expired
        .revoke_peer_at(&cli.device_id(), true, NOW - TTL)
        .unwrap();
    run(&mut expired, RefusalMode::Enabled, false);
    assert!(
        expired
            .get(&cli.device_id())
            .unwrap()
            .refusal_notice()
            .is_none()
    );
}

#[test]
fn ref15_v1_initiator_data_after_established_still_reads_the_refusal() {
    let (host, cli) = identities();
    let mut roster = host_roster(&cli, true, WIRE_VERSION);
    roster.revoke_peer_at(&cli.device_id(), true, NOW).unwrap();
    let mut limiter = RefusalLimiter::new();
    let mut cli_roster = client_roster(&host);
    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    let mut resp =
        SessionMachine::new_responder_with_refusal(&host, None, RefusalMode::Enabled).unwrap();
    let m1 = v1_writes(&init.start().unwrap());
    let m2 = v1_writes(
        &resp
            .feed_bytes_with_limiter(&m1, NOW, 1, &mut roster, &mut limiter)
            .unwrap(),
    );
    let m3 = v1_writes(&init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    // The initiator sends DATA as soon as it reports Established, before the refusal arrives.
    let data = v1_writes(&init.send_data(b"early", 3).unwrap());
    let mut inbound = m3;
    inbound.extend_from_slice(&data);
    let refused = resp
        .feed_bytes_with_limiter(&inbound, NOW, 4, &mut roster, &mut limiter)
        .unwrap();
    let close = v1_writes(&refused);
    assert_eq!(close.len(), 21);
    assert!(resp.is_closed(), "the responder never reads the early DATA");
    assert_eq!(
        init.feed_bytes(&close, NOW, 5, &mut cli_roster).unwrap(),
        vec![SessionAction::CloseTransport {
            code: SessionCloseCode::PEER_REVOKED,
            reason: String::new(),
        }]
    );
}

#[test]
fn ref24_v2_close_codes_map_only_on_initiators() {
    let (host, cli) = identities();
    let established = || {
        let mut roster = v2_host_roster(&cli, true, &secrets(0x66));
        let mut cli_roster = client_roster(&host);
        let mut init = V2SessionInitiator::new(&cli, host.host_id(), SECRET, None, None).unwrap();
        let mut resp = V2SessionResponder::new(&host).unwrap();
        let m1 = v2_writes(&init.start(NOW).unwrap());
        let m2 = v2_writes(&resp.feed_bytes(&m1, NOW, 1, &mut roster).unwrap());
        let m3 = v2_writes(&init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
        resp.feed_bytes(&m3, NOW, 3, &mut roster).unwrap();
        (init, resp, roster, cli_roster)
    };
    for (code, refusal) in [
        (SessionCloseCode::GRANT_EXPIRED, false),
        (SessionCloseCode::KEY_UNVERIFIED, false),
        (SessionCloseCode::NORMAL, false),
        (4450, true),
    ] {
        let (mut init, mut resp, _, mut cli_roster) = established();
        let close = v2_writes(&resp.seal_close(code, "", 4).unwrap());
        assert_eq!(
            init.feed_bytes(&close, NOW, 5, &mut cli_roster).unwrap(),
            vec![V2SessionAction::CloseTransport {
                code,
                reason: String::new()
            }]
        );
        let later = init.seal_data(b"x", 6).unwrap_err();
        if refusal {
            assert!(
                matches!(later, CoreError::SessionClosed { code: c, .. } if c == code),
                "{later:?}"
            );
        } else {
            assert!(
                !matches!(later, CoreError::SessionClosed { code: c, .. } if c == code),
                "code {code} must not map to a refusal: {later:?}"
            );
        }
    }
    let (mut init, mut resp, mut roster, _) = established();
    let close = v2_writes(
        &init
            .seal_close(SessionCloseCode::PEER_REVOKED, "x", 4)
            .unwrap(),
    );
    assert_eq!(
        resp.feed_bytes(&close, NOW, 5, &mut roster).unwrap(),
        vec![V2SessionAction::CloseTransport {
            code: SessionCloseCode::PEER_REVOKED,
            reason: "x".into()
        }]
    );
}

#[test]
fn an_alias_and_a_device_entry_for_one_key_share_one_limiter_window() {
    let (host, cli) = identities();
    let id = cli.device_id();
    // Floor 1 with v2 secrets, so the same key can be refused on both wires.
    let mut roster = Roster::new();
    add_client(&mut roster, &cli, true, WIRE_VERSION, Some(&secrets(0x66)));
    roster
        .insert_pinned_host(
            "a-alias".into(),
            "Alias".into(),
            *cli.static_key().public_bytes(),
            None,
            0,
            vec![],
        )
        .unwrap();
    // The device entry carries the notice and tombstone; the alias sorts first.
    roster.revoke_peer_at(&id, true, NOW).unwrap();
    assert_eq!(roster.get("a-alias").unwrap().state, PeerState::Revoked);
    assert!(roster.get("a-alias").unwrap().refusal_notice().is_none());

    let mut caches = Caches::default();
    let (out, init) = run_v1(
        &host,
        &cli,
        &mut roster,
        RefusalMode::Enabled,
        Some(&mut caches.limiter),
        NOW,
    );
    assert_v1_refused(out, init, &cli, SessionCloseCode::PEER_REVOKED);
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW + 1,
        NOW + 1,
    );
    assert_v2_decoy(&a, &out);
    assert_eq!(caches.limiter.len(), 1, "one window per static key");
    let (a, out) = v2_attempt(
        &host,
        &cli,
        SECRET,
        &mut roster,
        &mut caches,
        None,
        NOW + 10,
        NOW + 10,
    );
    assert_v2_refused(&a, out, &cli, RefusalReason::Revoked);
}

#[test]
fn every_send_after_a_received_refusal_reports_the_refusal_code() {
    let (host, cli) = identities();
    let mut roster = host_roster(&cli, true, WIRE_VERSION);
    roster.revoke_peer_at(&cli.device_id(), true, NOW).unwrap();
    let (out, mut init) = run_v1(&host, &cli, &mut roster, RefusalMode::Enabled, None, NOW);
    let close = v1_writes(&out.unwrap());
    init.feed_bytes(&close, NOW, 4, &mut Roster::new()).unwrap();
    let refused = |r: Result<Vec<SessionAction>, CoreError>| {
        matches!(
            r,
            Err(CoreError::SessionClosed {
                code: SessionCloseCode::PEER_REVOKED,
                ..
            })
        )
    };
    let offer = tendril_core::wire::PathUpgradeMsg::Offer {
        upgrade_id: 1,
        protocol: "webrtc/v1".into(),
        sdp: "v=0".into(),
    };
    assert!(refused(init.send_path_upgrade(&offer, 5)));
    assert!(refused(init.send_rekey(5)));
    assert!(refused(init.send_close(SessionCloseCode::NORMAL, "")));
    assert!(refused(init.send_ping(1, 5)));

    let (out, mut v2_init, _) = v2_race(PaddingPolicy::v2_default(), SECRET, None, |r, id| {
        r.revoke_peer_at(id, true, NOW).unwrap();
    });
    v2_init
        .feed_bytes(&v2_writes(&out.unwrap()), NOW, 3, &mut Roster::new())
        .unwrap();
    assert!(matches!(
        v2_init.send_path_upgrade(&offer, 5),
        Err(CoreError::SessionClosed {
            code: SessionCloseCode::PEER_REVOKED,
            ..
        })
    ));
}
