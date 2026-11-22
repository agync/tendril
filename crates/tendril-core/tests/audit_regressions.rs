//! Regression tests for the core protocol and crypto audit findings.

use tendril_core::crypto::{SigningKeypair, StaticKeypair, device_id};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationListUnsigned, sign_crl};
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{PairingCodeKind, PairingConfig, PairingManager, PairingPathKind};
use tendril_core::roster::{PeerState, Roster, V2PeerSecrets};
use tendril_core::v2::{
    PakeArgon2Params, RelayDialReplayCache, RendezvousReplayCache, V2_RENDEZVOUS_MAX_SKEW_SECS,
    V2PairAction, V2PakePairInitiator, V2PakePairResponder, V2SessionAction, V2SessionInitiator,
    V2SessionResponder,
};
use tendril_core::wire::{AEAD_TAG_LEN, WIRE_VERSION, WIRE_VERSION_V2, decode_frame};

const NOW: u64 = 1_795_564_800;
const MAX_LIVE_PAIRING_CODES: usize = 4;

fn host_and_cli() -> (EndpointIdentity, EndpointIdentity) {
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41; 32]),
        SigningKeypair::from_seed([0x42; 32]),
    )
    .with_host_id("host-audit");
    let cli = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x51; 32]),
        SigningKeypair::from_seed([0x52; 32]),
    );
    (host, cli)
}

fn crl_for(
    issuer: &str,
    seq: u64,
    revoked: Vec<String>,
    key: &SigningKeypair,
) -> tendril_core::grants::RevocationList {
    sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: issuer.into(),
            seq,
            revoked_devices: revoked,
            revoked_nonces: vec![],
            ts: "2026-11-20T00:00:00Z".into(),
        },
        key,
    )
    .unwrap()
}

fn wire(actions: &[V2PairAction]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let V2PairAction::WriteBytes(b) = a {
            out.extend_from_slice(b);
        }
    }
    out
}

fn session_wire(actions: Vec<V2SessionAction>) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let V2SessionAction::WriteBytes(b) = a {
            out.extend_from_slice(&b);
        }
    }
    out
}

#[test]
fn sec01_crl_with_derived_device_id_revokes_host_keyed_entry() {
    let root = SigningKeypair::from_seed([0x11; 32]);
    let static_pub = *StaticKeypair::from_scalar([0x22; 32]).public_bytes();
    let signing = SigningKeypair::from_seed([0x23; 32]).public_key().clone();

    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            "friendly-host-name".into(),
            "Host".into(),
            static_pub,
            Some(signing),
            0,
            vec![],
        )
        .unwrap();

    let crl = crl_for("root-id", 1, vec![device_id(&static_pub)], &root);
    roster
        .ingest_crl(crl, "root-id", root.public_key())
        .unwrap();

    assert_eq!(
        roster.get("friendly-host-name").unwrap().state,
        PeerState::Revoked
    );
}

#[test]
fn sec01_pinned_and_pending_host_refuse_identity_revoked_by_crl() {
    let root = SigningKeypair::from_seed([0x11; 32]);
    let static_pub = *StaticKeypair::from_scalar([0x22; 32]).public_bytes();
    let signing = SigningKeypair::from_seed([0x23; 32]).public_key().clone();

    let mut roster = Roster::new();
    let crl = crl_for("root-id", 1, vec![device_id(&static_pub)], &root);
    roster
        .ingest_crl(crl, "root-id", root.public_key())
        .unwrap();

    assert!(matches!(
        roster.insert_pinned_host(
            "alias".into(),
            "Host".into(),
            static_pub,
            Some(signing.clone()),
            0,
            vec![],
        ),
        Err(CoreError::PeerRevoked(_))
    ));
    assert!(matches!(
        roster.record_pending_host(
            "alias".into(),
            "Host".into(),
            static_pub,
            signing,
            0,
            "abcd".into(),
            vec![],
        ),
        Err(CoreError::PeerRevoked(_))
    ));
    assert!(roster.get("alias").is_none());
}

#[test]
fn sec01_pinned_host_refuses_keys_of_revoked_sibling_entry() {
    let static_pub = *StaticKeypair::from_scalar([0x22; 32]).public_bytes();
    let signing = SigningKeypair::from_seed([0x23; 32]).public_key().clone();

    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            "alias-a".into(),
            "A".into(),
            static_pub,
            Some(signing.clone()),
            0,
            vec![],
        )
        .unwrap();
    roster.revoke_peer("alias-a").unwrap();

    assert!(matches!(
        roster.insert_pinned_host(
            "alias-b".into(),
            "B".into(),
            static_pub,
            Some(signing),
            0,
            vec![],
        ),
        Err(CoreError::PeerRevoked(_))
    ));
}

#[test]
fn sec07_dial_replay_cache_prunes_min_epoch_regardless_of_arrival_order() {
    let mut cache = RelayDialReplayCache::new();
    assert!(cache.check_and_record(10, &[1; 32], &[1; 16], 0));
    assert!(cache.check_and_record(5, &[2; 32], &[2; 16], 0));
    assert!(cache.check_and_record(11, &[3; 32], &[3; 16], 8));
    assert_eq!(
        cache.len(),
        2,
        "epoch 5 must be evicted although it arrived second"
    );
    assert!(
        cache.check_and_record(5, &[2; 32], &[2; 16], 0),
        "pruned stale epoch no longer occupies the cache"
    );
}

#[test]
fn sec07_rendezvous_replay_cache_prunes_oldest_timestamp_first() {
    let mut cache = RendezvousReplayCache::new();
    let base = NOW;
    assert!(cache.record([1; 16], base + 100, base + 100));
    assert!(cache.record([2; 16], base, base + 100));
    let later = base + V2_RENDEZVOUS_MAX_SKEW_SECS + 50;
    assert!(!cache.contains(&[2; 16], later));
    assert_eq!(cache.len(), 1);
    assert!(cache.contains(&[1; 16], later));
}

#[test]
fn sec13_live_code_count_is_capped_and_expiry_or_burn_frees_slots() {
    let mut mgr = PairingManager::new(PairingConfig::default());
    for i in 0..MAX_LIVE_PAIRING_CODES {
        let entropy = [u8::try_from(i).unwrap() + 1; 32];
        mgr.issue_code_with_entropy(PairingCodeKind::Remote3Group, NOW, &entropy)
            .unwrap();
    }
    assert!(
        mgr.issue_code_with_entropy(PairingCodeKind::Remote3Group, NOW, &[0x77; 32])
            .is_err()
    );
    assert_eq!(mgr.live_code_count(NOW), MAX_LIVE_PAIRING_CODES);

    let far_future = NOW + 100_000;
    mgr.issue_code_with_entropy(PairingCodeKind::Remote3Group, far_future, &[0x78; 32])
        .unwrap();
    assert_eq!(mgr.live_code_count(far_future), 1);
}

#[test]
fn sec14_established_v2_session_raises_min_wire_version_on_both_peers() {
    let (host, cli) = host_and_cli();
    let secrets = V2PeerSecrets::new([0x66; 32], [0x77; 32]);

    let mut host_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "abcd".into(),
        )
        .unwrap();
    host_roster
        .confirm_peer(&cli.device_id(), Some("abcd"))
        .unwrap();
    host_roster
        .set_peer_v2_secrets(&cli.device_id(), secrets.clone())
        .unwrap();
    host_roster
        .set_peer_min_wire_version(&cli.device_id(), WIRE_VERSION_V2)
        .unwrap();

    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            vec![],
        )
        .unwrap();
    cli_roster
        .set_peer_v2_secrets(host.host_id(), secrets.clone())
        .unwrap();
    assert_eq!(
        cli_roster.get(host.host_id()).unwrap().min_wire_version,
        WIRE_VERSION
    );

    let mut init = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let mut resp = V2SessionResponder::new(&host).unwrap();
    let m1 = session_wire(init.start(NOW).unwrap());
    let m2 = session_wire(resp.feed_bytes(&m1, NOW, 1, &mut host_roster).unwrap());
    let m3 = session_wire(init.feed_bytes(&m2, NOW, 2, &mut cli_roster).unwrap());
    resp.feed_bytes(&m3, NOW, 3, &mut host_roster).unwrap();

    assert!(init.is_established() && resp.is_established());
    assert_eq!(
        cli_roster.get(host.host_id()).unwrap().min_wire_version,
        WIRE_VERSION_V2
    );
    assert_eq!(
        host_roster.get(&cli.device_id()).unwrap().min_wire_version,
        WIRE_VERSION_V2
    );
}

#[test]
fn sec06_lan_code_over_remote_path_yields_decoy_and_keeps_code_live() {
    let (host, cli) = host_and_cli();
    let mut roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr.issue_code(PairingCodeKind::Lan2Group, NOW).unwrap();

    let mut init = V2PakePairInitiator::new(
        &cli,
        "Cli",
        "cli",
        &code,
        None,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let mut resp = V2PakePairResponder::new(
        &host,
        PairingPathKind::Remote,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let m1 = wire(&init.start().unwrap());
    let m2 = wire(&resp.feed_bytes(&m1, NOW, &mut mgr, &mut roster).unwrap());

    assert_eq!(init.feed_bytes(&m2), Err(CoreError::PairingAuthFailed));
    assert_eq!(mgr.live_code_count(NOW), 1);
}

fn pake_pair_lengths(device_name: &str) -> (usize, usize) {
    let (host, cli) = host_and_cli();
    let mut roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr.issue_code(PairingCodeKind::Remote3Group, NOW).unwrap();
    let mut init = V2PakePairInitiator::new(
        &cli,
        device_name,
        "cli",
        &code,
        None,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let mut resp = V2PakePairResponder::new(
        &host,
        PairingPathKind::Remote,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let m1 = wire(&init.start().unwrap());
    let m2 = wire(&resp.feed_bytes(&m1, NOW, &mut mgr, &mut roster).unwrap());
    let m3 = wire(&init.feed_bytes(&m2).unwrap());
    let m4 = wire(&resp.feed_bytes(&m3, NOW, &mut mgr, &mut roster).unwrap());
    let completed = init.feed_bytes(&m4).unwrap();
    assert!(
        completed
            .iter()
            .any(|a| matches!(a, V2PairAction::Completed(_)))
    );
    let body4 = decode_frame(&m4).unwrap().0.len();
    (m3.len(), body4)
}

#[test]
fn priv03_pake_msg3_and_pair_response_lengths_hide_claim_and_response_size() {
    let (short_m3, short_m4) = pake_pair_lengths("A");
    let (long_m3, long_m4) = pake_pair_lengths(&"N".repeat(200));
    assert_eq!(
        short_m3, long_m3,
        "msg3 length must not reveal the PairClaim size"
    );
    assert_eq!(short_m4, long_m4);

    let payload_len = short_m4 - AEAD_TAG_LEN;
    assert!(
        [512, 1024, 2048, 4096, 8192, 16_384, 32_768, 63_488].contains(&payload_len),
        "PairResponse payload length {payload_len} must be a padding bucket"
    );
}
