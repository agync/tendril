//! Comprehensive tests for Wire v2 (`0x02`) and Relay v2 (`ADR 0003` + `Phase 7`).

use std::collections::BTreeSet;

use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::grants::{RevocationListUnsigned, sign_crl};
use tendril_core::identity::EndpointIdentity;
use tendril_core::noise::NoiseHfsHandshakeBuilder;
use tendril_core::pairing::{
    PairingCodeKind, PairingConfig, PairingInitiator, PairingManager, PairingPathKind,
    PairingResponder, PinnedHost,
};
use tendril_core::roster::{PeerState, Roster, RosterEntry, V2PeerSecrets};
use tendril_core::session::{SessionAction, SessionMachine};
use tendril_core::v2::{
    DerivedMailbox, MAX_PADDED_PAYLOAD_LEN, MAX_REKEY_FRAMES_CEILING,
    MAX_RELAY_DIAL_REPLAY_ENTRIES, MAX_RENDEZVOUS_REPLAY_ENTRIES, PaddingPolicy, PakeArgon2Params,
    RELAY_V2_EPOCH_SECS, RekeyStatus, RekeyThresholds, RelayDialReplayCache, RendezvousReplayCache,
    ScheduleJitterPolicy, SealedSession, V2_MSG2_ENVELOPE_LEN, V2_PADDING_BUCKETS,
    V2_RENDEZVOUS_MAX_SKEW_SECS, V2InnerFrame, V2PairAction, V2PairOutcome, V2PakePairInitiator,
    V2PakePairResponder, V2PinnedHost, V2SessionAction, V2SessionInitiator, V2SessionResponder,
    VerifiedRelayHost, canonical_relay_host, decode_v2_inner_frame, derive_epoch_mailbox,
    derive_epoch_mailbox_window, derive_mailbox_secret, derive_reconnect_secret,
    encode_dummy_cover_frame, epoch_for_unix, epoch_within_skew, pad_inner_frame,
    sign_v2_relay_accept, sign_v2_relay_dial, sign_v2_relay_register, unpad_inner_frame,
    verify_and_record_v2_relay_dial, verify_v2_relay_accept, verify_v2_relay_challenge_host,
    verify_v2_relay_dial, verify_v2_relay_dial_in_window, verify_v2_relay_register,
};
use tendril_core::wire::{
    AEAD_TAG_LEN, FLAG_PAKE_PAIR, InnerFrameType, Intent, PREAMBLE_FLAG_NONE, Preamble,
    WIRE_VERSION, WIRE_VERSION_V2, decode_frame, encode_frame, encode_inner_frame,
};

fn test_identities() -> (EndpointIdentity, EndpointIdentity) {
    let host = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x41; 32]),
        SigningKeypair::from_seed([0x42; 32]),
    )
    .with_host_id("host-v2-alpha");
    let cli = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x51; 32]),
        SigningKeypair::from_seed([0x52; 32]),
    );
    (host, cli)
}

fn setup_rosters_v2(
    host: &EndpointIdentity,
    cli: &EndpointIdentity,
    secrets: &V2PeerSecrets,
    min_wire_version: u8,
) -> (Roster, Roster) {
    let mut host_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".to_string(),
            "cli".to_string(),
            "abcd".to_string(),
        )
        .unwrap();
    host_roster
        .confirm_peer(&cli.device_id(), Some("abcd"))
        .unwrap();
    host_roster
        .set_peer_v2_secrets(&cli.device_id(), secrets.clone())
        .unwrap();
    host_roster
        .set_peer_min_wire_version(&cli.device_id(), min_wire_version)
        .unwrap();

    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".to_string(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            vec![],
        )
        .unwrap();
    cli_roster
        .set_peer_v2_secrets(host.host_id(), secrets.clone())
        .unwrap();
    cli_roster
        .set_peer_min_wire_version(host.host_id(), min_wire_version)
        .unwrap();

    (host_roster, cli_roster)
}

fn collect_v2_session_bytes(actions: Vec<V2SessionAction>) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let V2SessionAction::WriteBytes(b) = a {
            out.extend_from_slice(&b);
        }
    }
    out
}

fn collect_v2_pair_bytes(actions: &[V2PairAction]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let V2PairAction::WriteBytes(b) = a {
            out.extend_from_slice(b);
        }
    }
    out
}

fn collect_v1_session_bytes(actions: Vec<SessionAction>) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let SessionAction::WriteBytes(b) = a {
            out.extend_from_slice(&b);
        }
    }
    out
}

fn collect_v1_pair_bytes(actions: &[tendril_core::pairing::PairAction]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let tendril_core::pairing::PairAction::WriteBytes(b) = a {
            out.extend_from_slice(b);
        }
    }
    out
}

#[test]
fn anti_downgrade_enforces_min_wire_version_and_preamble_prologue_integrity() {
    let (host, cli) = test_identities();
    let secrets = V2PeerSecrets::new([0xAA; 32], [0xBB; 32]);

    // Legacy v1 serialized RosterEntry without min_wire_version defaults to 1.
    let legacy_json = serde_json::json!({
        "device_id": "dev_1122334455667788",
        "name": "Legacy",
        "kind": "cli",
        "static_pub": vec![0u8; 32],
        "rotation_seq": 0,
        "state": "active"
    });
    let legacy_entry: RosterEntry = serde_json::from_value(legacy_json).unwrap();
    assert_eq!(legacy_entry.min_wire_version, WIRE_VERSION);
    assert!(legacy_entry.v2_secrets.is_none());

    // Invalid min_wire_version values (0, 3) MUST fail closed on deserialization.
    for bad_ver in [0u8, 3u8, 99u8] {
        let bad_json = serde_json::json!({
            "device_id": "dev_1122334455667788",
            "name": "Bad",
            "kind": "cli",
            "static_pub": vec![0u8; 32],
            "rotation_seq": 0,
            "state": "active",
            "min_wire_version": bad_ver
        });
        assert!(serde_json::from_value::<RosterEntry>(bad_json).is_err());
    }

    let (mut host_roster, mut cli_roster) =
        setup_rosters_v2(&host, &cli, &secrets, WIRE_VERSION_V2);

    // Unknown peer fails closed on enforce_min_wire_version.
    assert_eq!(
        host_roster.enforce_min_wire_version("unknown-peer", WIRE_VERSION),
        Err(CoreError::PeerNotFound("unknown-peer".to_string()))
    );
    assert_eq!(
        host_roster.enforce_min_wire_version(&cli.device_id(), WIRE_VERSION),
        Err(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        })
    );

    // Decreasing min_wire_version from 2 to 1 must fail closed.
    assert_eq!(
        host_roster.set_peer_min_wire_version(&cli.device_id(), WIRE_VERSION),
        Err(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        })
    );

    // v1 PairingInitiator enforces min_wire_version >= 2 before PairClaim.
    let v1_pair_downgrade = PairingInitiator::new_with_min_wire_version(
        &cli,
        "Cli",
        "cli",
        "TND-AAAA-BBBB-CCCC",
        None,
        WIRE_VERSION_V2,
        None,
    );
    assert!(matches!(
        v1_pair_downgrade,
        Err(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        })
    ));
    assert!(matches!(
        PairingInitiator::new(&cli, "Cli", "cli", "TND-AAAA-BBBB-CCCC", None, None)
            .unwrap()
            .with_min_wire_version(WIRE_VERSION_V2),
        Err(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        })
    ));

    // v1 SessionMachine initiator must fail closed before transmitting msg3 when host requires v2.
    let mut v1_init =
        SessionMachine::new_initiator(&cli, host.host_id(), None, None, Some([0x11; 32])).unwrap();
    let mut v1_resp = SessionMachine::new_responder(&host, Some([0x22; 32])).unwrap();
    let m1 = collect_v1_session_bytes(v1_init.start().unwrap());
    let mut v1_host_roster = Roster::new();
    v1_host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "abcd".into(),
        )
        .unwrap();
    v1_host_roster
        .confirm_peer(&cli.device_id(), Some("abcd"))
        .unwrap();
    let m2 = collect_v1_session_bytes(
        v1_resp
            .feed_bytes(&m1, 1_795_564_800, 1, &mut v1_host_roster)
            .unwrap(),
    );
    let init_err = v1_init
        .feed_bytes(&m2, 1_795_564_800, 2, &mut cli_roster)
        .unwrap_err();
    assert_eq!(
        init_err,
        CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        }
    );

    // v1 SessionMachine responder must ALSO fail closed on msg3 if peer requires v2.
    let mut v1_init2 =
        SessionMachine::new_initiator(&cli, host.host_id(), None, None, Some([0x13; 32])).unwrap();
    let mut v1_resp2 = SessionMachine::new_responder(&host, Some([0x23; 32])).unwrap();
    let mut permissive_cli_roster = Roster::new();
    permissive_cli_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let m1_2 = collect_v1_session_bytes(v1_init2.start().unwrap());
    let m2_2 = collect_v1_session_bytes(
        v1_resp2
            .feed_bytes(&m1_2, 1_795_564_800, 1, &mut v1_host_roster)
            .unwrap(),
    );
    let m3_2 = collect_v1_session_bytes(
        v1_init2
            .feed_bytes(&m2_2, 1_795_564_800, 2, &mut permissive_cli_roster)
            .unwrap(),
    );
    let resp_err = v1_resp2
        .feed_bytes(&m3_2, 1_795_564_800, 3, &mut host_roster)
        .unwrap_err();
    assert_eq!(
        resp_err,
        CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        }
    );

    // v1 PairingResponder rejects re-pairing from static key with min_wire_version = 2 WITHOUT burning code.
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Lan2Group, 1_795_564_800)
        .unwrap();
    let mut v1_pair_resp =
        PairingResponder::new(&host, PairingPathKind::Lan, Some([0x31; 32])).unwrap();
    let mut v1_pair_init =
        PairingInitiator::new(&cli, "Cli", "cli", &code, None, Some([0x32; 32])).unwrap();
    let pm1 = collect_v1_pair_bytes(&v1_pair_init.start().unwrap());
    let pm2 = collect_v1_pair_bytes(
        &v1_pair_resp
            .feed_bytes(&pm1, 1_795_564_800, &mut mgr, &mut host_roster)
            .unwrap(),
    );
    let pm3 = collect_v1_pair_bytes(&v1_pair_init.feed_bytes(&pm2).unwrap());
    assert_eq!(
        v1_pair_resp.feed_bytes(&pm3, 1_795_564_800, &mut mgr, &mut host_roster),
        Err(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        })
    );
    assert_eq!(mgr.live_code_count(1_795_564_800), 1);

    // Mutating any preamble byte in a 0x02 Noise handshake causes AEAD failure in msg2.
    let pre_valid = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    let mut pre_flipped = pre_valid;
    pre_flipped[5] ^= 0x01;
    let mut hs_i = NoiseHfsHandshakeBuilder::new()
        .local_private_key(cli.static_key().secret_bytes())
        .prologue(&pre_valid)
        .build_initiator()
        .unwrap();
    let mut hs_r = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&pre_flipped)
        .build_responder()
        .unwrap();
    let raw_m1 = hs_i.write_message_vec(&[]).unwrap();
    hs_r.read_message_vec(&raw_m1).unwrap();
    let raw_m2 = hs_r.write_message_vec(b"hello").unwrap();
    assert!(matches!(
        hs_i.read_message_vec(&raw_m2),
        Err(CoreError::Noise(_))
    ));

    assert_eq!(Preamble::v2_pake_pair().flags, FLAG_PAKE_PAIR);
    assert!(matches!(
        Preamble::decode(b"TND\x02\x01\x01"),
        Err(CoreError::InvalidPreambleFlags {
            intent: 0x01,
            flags: 0x01
        })
    ));
    assert!(matches!(
        Preamble::decode(b"TND\x02\x02\x02"),
        Err(CoreError::InvalidPreambleFlags {
            intent: 0x02,
            flags: 0x02
        })
    ));
}

#[test]
fn blinded_relay_v2_mailboxes_are_unlinkable_and_authenticated() {
    let host_static_pub = *StaticKeypair::from_scalar([0x41; 32]).public_bytes();
    let ikm = [0x77u8; 32];
    let mailbox_secret_a = derive_mailbox_secret(&ikm, &host_static_pub);
    let mailbox_secret_b = derive_mailbox_secret(&ikm, &host_static_pub);
    assert_eq!(&*mailbox_secret_a, &*mailbox_secret_b);
    let reconnect_a = derive_reconnect_secret(&ikm, &host_static_pub);
    assert_ne!(&*reconnect_a, &*mailbox_secret_a);

    // Canonical relay host checks and challenge host verification.
    assert_eq!(
        canonical_relay_host("Relay.Example.INVALID.").unwrap(),
        "relay.example.invalid"
    );
    verify_v2_relay_challenge_host("relay.example.invalid", "RELAY.EXAMPLE.INVALID.").unwrap();
    assert!(verify_v2_relay_challenge_host("relay.example.invalid", "evil.example").is_err());
    assert!(canonical_relay_host("relay.example.invalid:8443").is_err());
    assert!(canonical_relay_host("user@relay.example.invalid").is_err());

    let t_epoch10 = 10 * RELAY_V2_EPOCH_SECS + 120;
    let e10 = epoch_for_unix(t_epoch10);
    assert_eq!(e10, 10);
    assert!(epoch_within_skew(10, 9));
    assert!(epoch_within_skew(10, 11));
    assert!(!epoch_within_skew(10, 12));

    let init_m10 = derive_epoch_mailbox(&mailbox_secret_a, e10);
    let resp_m10 = derive_epoch_mailbox(&mailbox_secret_b, e10);
    assert_eq!(init_m10.mailbox_id, resp_m10.mailbox_id);
    assert_eq!(init_m10.dial_auth_key(), resp_m10.dial_auth_key());

    // Epoch E+1 produces an unlinkable distinct Ed25519 mailbox public key.
    let m11 = derive_epoch_mailbox(&mailbox_secret_a, e10 + 1);
    assert_ne!(init_m10.mailbox_id, m11.mailbox_id);
    assert_ne!(init_m10.dial_auth_key(), m11.dial_auth_key());

    let relay_host = "relay.example.invalid";
    let reg_nonce = [0x91u8; 32];
    let reg_sig = sign_v2_relay_register(&resp_m10, relay_host, &reg_nonce).unwrap();
    verify_v2_relay_register(&resp_m10.mailbox_id, e10, relay_host, &reg_nonce, &reg_sig).unwrap();

    // Tampered relay host, nonce, epoch, or signature fail closed.
    assert_eq!(
        verify_v2_relay_register(
            &resp_m10.mailbox_id,
            e10,
            "evil.example",
            &reg_nonce,
            &reg_sig
        ),
        Err(CoreError::InvalidSignature)
    );
    assert_eq!(
        verify_v2_relay_register(
            &resp_m10.mailbox_id,
            e10 + 1,
            relay_host,
            &reg_nonce,
            &reg_sig
        ),
        Err(CoreError::InvalidSignature)
    );
    let mut bad_nonce = reg_nonce;
    bad_nonce[0] ^= 0x01;
    assert_eq!(
        verify_v2_relay_register(&resp_m10.mailbox_id, e10, relay_host, &bad_nonce, &reg_sig),
        Err(CoreError::InvalidSignature)
    );
    let mut bad_sig = reg_sig;
    bad_sig[63] ^= 0x01;
    assert_eq!(
        verify_v2_relay_register(&resp_m10.mailbox_id, e10, relay_host, &reg_nonce, &bad_sig),
        Err(CoreError::InvalidSignature)
    );

    // Dial challenge proof binds conn_id; replay cache rejects duplicate (epoch, dial_nonce, conn_id).
    let dial_nonce = [0xA2u8; 32];
    let conn_id = [0xC4u8; 16];
    let dial_token = sign_v2_relay_dial(&init_m10, relay_host, &dial_nonce, &conn_id).unwrap();
    verify_v2_relay_dial(&resp_m10, relay_host, &dial_nonce, &conn_id, &dial_token).unwrap();

    let mut other_conn = conn_id;
    other_conn[0] ^= 0x01;
    assert_eq!(
        verify_v2_relay_dial(&resp_m10, relay_host, &dial_nonce, &other_conn, &dial_token),
        Err(CoreError::InvalidSignature)
    );
    let mut bad_tok = dial_token;
    bad_tok[0] ^= 0x80;
    assert_eq!(
        verify_v2_relay_dial(&resp_m10, relay_host, &dial_nonce, &conn_id, &bad_tok),
        Err(CoreError::InvalidSignature)
    );

    let mut replay_cache = RelayDialReplayCache::new();
    assert!(replay_cache.check_and_record(e10, &dial_nonce, &conn_id, e10 - 1));
    assert!(!replay_cache.check_and_record(e10, &dial_nonce, &conn_id, e10 - 1));

    let accept_nonce = [0xB3u8; 32];
    let accept_sig = sign_v2_relay_accept(&resp_m10, relay_host, &accept_nonce, &conn_id).unwrap();
    verify_v2_relay_accept(
        &resp_m10.mailbox_id,
        e10,
        relay_host,
        &accept_nonce,
        &conn_id,
        &accept_sig,
    )
    .unwrap();
    assert_eq!(
        verify_v2_relay_accept(
            &resp_m10.mailbox_id,
            e10,
            relay_host,
            &accept_nonce,
            &other_conn,
            &accept_sig
        ),
        Err(CoreError::InvalidSignature)
    );

    // Window centered at E=10 accepts E=9, E=10, E=11 and rejects E=8.
    let window = derive_epoch_mailbox_window(&mailbox_secret_a, t_epoch10);
    assert_eq!(window.mailboxes().len(), 3);
    assert!(window.find_by_mailbox_id(&init_m10.mailbox_id).is_some());

    let m9 = derive_epoch_mailbox(&mailbox_secret_a, 9);
    let m11_dial = sign_v2_relay_dial(&m11, relay_host, &dial_nonce, &conn_id).unwrap();
    let m9_dial = sign_v2_relay_dial(&m9, relay_host, &dial_nonce, &conn_id).unwrap();
    let matched_prev: &DerivedMailbox =
        verify_v2_relay_dial_in_window(&window, 9, relay_host, &dial_nonce, &conn_id, &m9_dial)
            .unwrap();
    assert_eq!(matched_prev.epoch, 9);
    let matched_next =
        verify_v2_relay_dial_in_window(&window, 11, relay_host, &dial_nonce, &conn_id, &m11_dial)
            .unwrap();
    assert_eq!(matched_next.epoch, 11);

    let m8 = derive_epoch_mailbox(&mailbox_secret_a, 8);
    let m8_dial = sign_v2_relay_dial(&m8, relay_host, &dial_nonce, &conn_id).unwrap();
    assert_eq!(
        verify_v2_relay_dial_in_window(&window, 8, relay_host, &dial_nonce, &conn_id, &m8_dial)
            .err(),
        Some(CoreError::InvalidSignature)
    );
}

#[test]
fn pseudonymous_v2_reconnect_hides_host_hello_from_active_scanners() {
    let (mut host, cli) = test_identities();
    let initial_secrets = V2PeerSecrets::new([0x66; 32], [0x77; 32]);
    let (mut host_roster, mut cli_roster) =
        setup_rosters_v2(&host, &cli, &initial_secrets, WIRE_VERSION_V2);

    let now_unix = 1_795_564_800;

    // Rotate host once: HostHello now exceeds 4096 B and moves to the 16384 B bucket.
    let new_host_static = StaticKeypair::from_scalar([0x43; 32]);
    let new_host_signing = SigningKeypair::from_seed([0x44; 32]);
    host.rotate(new_host_static, new_host_signing, now_unix - 100)
        .unwrap();

    let mut init = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *initial_secrets.reconnect_secret(),
        None,
        Some(12),
    )
    .unwrap();
    let mut resp = V2SessionResponder::new(&host).unwrap();

    let m1 = collect_v2_session_bytes(init.start(now_unix).unwrap());
    let m2 = collect_v2_session_bytes(
        resp.feed_bytes(&m1, now_unix, 10, &mut host_roster)
            .unwrap(),
    );
    let m3 = collect_v2_session_bytes(init.feed_bytes(&m2, now_unix, 20, &mut cli_roster).unwrap());
    let est_resp = resp
        .feed_bytes(&m3, now_unix, 30, &mut host_roster)
        .unwrap();

    assert!(init.is_established());
    assert!(resp.is_established());
    assert_eq!(init.applied_rotation().len(), 1);
    assert_eq!(resp.peer_device_id(), Some(cli.device_id().as_str()));
    assert_eq!(resp.peer_crl_seq(), Some(12));
    assert_eq!(init.exported_v2_secrets(), resp.exported_v2_secrets());
    assert!(
        est_resp
            .iter()
            .any(|a| matches!(a, V2SessionAction::Established { .. }))
    );

    // Active scanner probe against the ROTATED host: decoy msg2 MUST match rotated msg2 length AND
    // MUST use an ephemeral decoy static key (not host's real static key)!
    let pre = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    let scanner_key = StaticKeypair::from_scalar([0x99; 32]);
    let mut scanner_hs = NoiseHfsHandshakeBuilder::new()
        .local_private_key(scanner_key.secret_bytes())
        .prologue(&pre)
        .build_initiator()
        .unwrap();
    let mut scanner_resp = V2SessionResponder::new(&host).unwrap();
    let sm1_raw = scanner_hs.write_message_vec(&[0x55; 56]).unwrap();
    let mut sm1 = pre.to_vec();
    sm1.extend_from_slice(&encode_frame(&sm1_raw).unwrap());
    let sm2 = collect_v2_session_bytes(
        scanner_resp
            .feed_bytes(&sm1, now_unix, 1, &mut host_roster)
            .unwrap(),
    );
    // Rotated host decoy size MUST equal rotated legit msg2 size (16384 + 1200 + 2).
    assert_eq!(sm2.len(), m2.len());
    assert!(m2.len() > V2_MSG2_ENVELOPE_LEN + 1200);
    let (sm2_body, _) = decode_frame(&sm2).unwrap();
    let scanner_pt = scanner_hs.read_message_vec(sm2_body).unwrap();
    assert_ne!(
        scanner_hs.get_remote_static(),
        Some(host.static_key().public_bytes())
    );
    assert!(serde_json::from_slice::<tendril_core::wire::HostHello>(&scanner_pt).is_err());
    assert!(
        !scanner_pt
            .windows(host.host_id().len())
            .any(|w| w == host.host_id().as_bytes())
    );

    let sm3_raw = scanner_hs.write_message_vec(b"{}").unwrap();
    let sm3 = encode_frame(&sm3_raw).unwrap();
    assert_eq!(
        scanner_resp.feed_bytes(&sm3, now_unix, 2, &mut host_roster),
        Err(CoreError::HostKeyUnverified)
    );

    // Replayed msg1 against shared RendezvousReplayCache is rejected on msg3 (never reuses ChaCha key/nonce).
    let mut shared_cache = RendezvousReplayCache::new();
    let mut replay_init = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *initial_secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let rm1 = collect_v2_session_bytes(replay_init.start(now_unix).unwrap());
    let mut r_resp1 = V2SessionResponder::new(&host).unwrap();
    let _rm2_first = r_resp1
        .feed_bytes_with_replay_cache(&rm1, now_unix, 1, &mut host_roster, &mut shared_cache)
        .unwrap();
    // Second connection replaying exact rm1 must be routed to decoy and reject msg3.
    let mut r_resp2 = V2SessionResponder::new(&host).unwrap();
    let rm2_replay = collect_v2_session_bytes(
        r_resp2
            .feed_bytes_with_replay_cache(&rm1, now_unix, 1, &mut host_roster, &mut shared_cache)
            .unwrap(),
    );
    assert_eq!(rm2_replay.len(), m2.len());
    // Legit initiator fails because decoy used an ephemeral static key and random envelope.
    assert!(
        replay_init
            .feed_bytes(&rm2_replay, now_unix, 2, &mut cli_roster)
            .is_err()
    );

    // Stale msg1 timestamp (> 300s skew) routes to decoy.
    let mut stale_init = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *initial_secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let stale_m1 = collect_v2_session_bytes(stale_init.start(now_unix - 400).unwrap());
    let mut stale_resp = V2SessionResponder::new(&host).unwrap();
    let stale_m2 = collect_v2_session_bytes(
        stale_resp
            .feed_bytes(&stale_m1, now_unix, 1, &mut host_roster)
            .unwrap(),
    );
    assert!(
        stale_init
            .feed_bytes(&stale_m2, now_unix, 2, &mut cli_roster)
            .is_err()
    );

    // Mid-session Grant + Revocation + Post-Rekey CRL enforcement in v2.
    let grant = host_roster
        .mint_grant(
            &host,
            &cli.device_id(),
            vec!["fs.read:/vault/*".to_string()],
            now_unix - 10,
            now_unix + 600,
            [0x11; 16],
        )
        .unwrap();
    let grant_wire = collect_v2_session_bytes(init.seal_grant(&grant, 40).unwrap());
    let grant_actions = resp
        .feed_bytes(&grant_wire, now_unix, 41, &mut host_roster)
        .unwrap();
    assert!(
        grant_actions
            .iter()
            .any(|a| matches!(a, V2SessionAction::GrantUpdated(_)))
    );
    let (auth_ok, _) = resp.authorize_path("fs.read", "/vault/notes.md", now_unix, &host_roster);
    assert!(auth_ok.is_ok());

    let data_out = collect_v2_session_bytes(init.seal_data(b"v2-secret-msg", 50).unwrap());
    let cover_out = collect_v2_session_bytes(init.seal_dummy_cover(512, 51).unwrap());
    let mut wire_stream = data_out;
    wire_stream.extend_from_slice(&cover_out);
    let resp_actions = resp
        .feed_bytes(&wire_stream, now_unix, 52, &mut host_roster)
        .unwrap();
    assert_eq!(
        resp_actions,
        vec![V2SessionAction::AppData(b"v2-secret-msg".to_vec())]
    );

    // Mid-session Revocation revoking cli's device_id fails closed immediately.
    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            seq: 1,
            revoked_devices: vec![cli.device_id()],
            revoked_nonces: vec![],
            ts: "2026-11-20T00:00:00Z".to_string(),
        },
        host.signing_key(),
    )
    .unwrap();
    let crl_wire = collect_v2_session_bytes(init.seal_revocation(&crl, 60).unwrap());
    assert!(matches!(
        resp.feed_bytes(&crl_wire, now_unix, 61, &mut host_roster),
        Err(CoreError::PeerRevoked(_))
    ));
}

#[test]
fn hybrid_pake_mlkem768_pairing_protects_host_hello_and_exports_v2_secrets() {
    let (host, cli) = test_identities();
    let mut host_roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());

    // 0. When NO live code exists, responder msg2 MUST NOT verify under constant dummy code
    //    and MUST NOT expose responder's real static_pub!
    let mut nocode_resp = V2PakePairResponder::new(
        &host,
        PairingPathKind::Remote,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let mut dummy_init = V2PakePairInitiator::new(
        &cli,
        "Probe",
        "cli",
        "TND-AAAA-AAAA-AAAA",
        None,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let nm1 = collect_v2_pair_bytes(&dummy_init.start().unwrap());
    let nm2 = collect_v2_pair_bytes(
        &nocode_resp
            .feed_bytes(&nm1, 1_795_564_800, &mut mgr, &mut host_roster)
            .unwrap(),
    );
    assert_eq!(
        dummy_init.feed_bytes(&nm2),
        Err(CoreError::PairingAuthFailed)
    );
    assert!(
        !nm2.windows(host.host_id().len())
            .any(|w| w == host.host_id().as_bytes())
    );

    // 1. Happy path with production Argon2id parameters (19 MiB, t = 2, p = 1).
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, 1_795_564_800)
        .unwrap();
    let code_lower = code.to_ascii_lowercase();

    let pin = V2PinnedHost::new(
        PinnedHost::with_hash(
            Some(host.host_id().to_string()),
            *host.static_key().public_bytes(),
            host.signing_key().signing_pub_hash(),
            0,
        ),
        WIRE_VERSION_V2,
    )
    .unwrap();

    let mut p_init = V2PakePairInitiator::new(
        &cli,
        "Workstation",
        "cli",
        &code_lower,
        Some(pin),
        PakeArgon2Params::production(),
    )
    .unwrap();
    let mut p_resp = V2PakePairResponder::new(
        &host,
        PairingPathKind::Remote,
        PakeArgon2Params::production(),
    )
    .unwrap();

    let m1 = collect_v2_pair_bytes(&p_init.start().unwrap());
    let m2_actions = p_resp
        .feed_bytes(&m1, 1_795_564_800, &mut mgr, &mut host_roster)
        .unwrap();
    let m2 = collect_v2_pair_bytes(&m2_actions);
    let init_m2_actions = p_init.feed_bytes(&m2).unwrap();
    let init_sas = init_m2_actions
        .iter()
        .find_map(|a| match a {
            V2PairAction::SasReady { pairing_sas, .. } => Some(pairing_sas.clone()),
            _ => None,
        })
        .expect("SasReady");
    let m3 = collect_v2_pair_bytes(&init_m2_actions);
    let resp_m3_actions = p_resp
        .feed_bytes(&m3, 1_795_564_800, &mut mgr, &mut host_roster)
        .unwrap();
    let m4 = collect_v2_pair_bytes(&resp_m3_actions);
    let init_final = p_init.feed_bytes(&m4).unwrap();

    let init_outcome = init_final.iter().find_map(|a| match a {
        V2PairAction::Completed(o) => Some(o.clone()),
        _ => None,
    });
    let resp_outcome = resp_m3_actions.iter().find_map(|a| match a {
        V2PairAction::Completed(o) => Some(o.clone()),
        _ => None,
    });

    let (
        Some(V2PairOutcome::InitiatorPending {
            v2_secrets: init_secrets,
            pairing_sas: init_done_sas,
            host_pin_verified,
            ..
        }),
        Some(V2PairOutcome::ResponderPending {
            v2_secrets: resp_secrets,
            pairing_sas: resp_sas,
            ..
        }),
    ) = (init_outcome.clone(), resp_outcome)
    else {
        panic!("expected both sides to reach Pending outcome");
    };

    assert!(host_pin_verified);
    assert_eq!(init_sas, init_done_sas);
    assert_eq!(init_done_sas, resp_sas);
    assert_eq!(init_secrets, resp_secrets);
    assert_eq!(mgr.live_code_count(1_795_564_800), 0);
    let host_entry = host_roster.get(&cli.device_id()).unwrap();
    assert_eq!(host_entry.state, PeerState::Pending);
    assert_eq!(host_entry.min_wire_version, WIRE_VERSION_V2);
    assert_eq!(host_entry.v2_secrets.as_ref(), Some(&resp_secrets));

    // Confirm peer and apply initiator outcome atomically via Roster::apply_v2_pair_initiator_outcome.
    host_roster
        .confirm_peer(&cli.device_id(), Some(&resp_sas))
        .unwrap();
    let mut cli_roster = Roster::new();
    cli_roster
        .apply_v2_pair_initiator_outcome(&init_outcome.unwrap(), "Host", vec![])
        .unwrap();
    assert_eq!(
        cli_roster.get(host.host_id()).unwrap().min_wire_version,
        WIRE_VERSION_V2
    );

    let mut sess_i = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *init_secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let mut sess_r = V2SessionResponder::new(&host).unwrap();
    let sm1 = collect_v2_session_bytes(sess_i.start(1_795_564_810).unwrap());
    let sm2 = collect_v2_session_bytes(
        sess_r
            .feed_bytes(&sm1, 1_795_564_810, 1, &mut host_roster)
            .unwrap(),
    );
    let sm3 = collect_v2_session_bytes(
        sess_i
            .feed_bytes(&sm2, 1_795_564_810, 2, &mut cli_roster)
            .unwrap(),
    );
    sess_r
        .feed_bytes(&sm3, 1_795_564_810, 3, &mut host_roster)
        .unwrap();
    assert!(sess_i.is_established());
    assert!(sess_r.is_established());

    // 2. Wrong pairing code and unauthenticated msg1/msg3 garbage MUST fail closed without leaking
    //    HostHello AND MUST NOT burn/charge live pairing codes!
    let code2 = mgr
        .issue_code(PairingCodeKind::Remote3Group, 1_795_564_820)
        .unwrap();
    for _ in 0..6 {
        let mut bad_init = V2PakePairInitiator::new(
            &cli,
            "Workstation",
            "cli",
            "TND-WRONG-CODE-0000",
            None,
            PakeArgon2Params::production(),
        )
        .unwrap();
        let mut bad_resp = V2PakePairResponder::new(
            &host,
            PairingPathKind::Remote,
            PakeArgon2Params::production(),
        )
        .unwrap();
        let bm1 = collect_v2_pair_bytes(&bad_init.start().unwrap());
        let bm2 = collect_v2_pair_bytes(
            &bad_resp
                .feed_bytes(&bm1, 1_795_564_820, &mut mgr, &mut host_roster)
                .unwrap(),
        );
        assert_eq!(bm2.len(), m2.len());
        assert_eq!(bad_init.feed_bytes(&bm2), Err(CoreError::PairingAuthFailed));
        assert!(
            !bm2.windows(host.host_id().len())
                .any(|w| w == host.host_id().as_bytes())
        );
        let bogus_m3 = encode_frame(&[0x55; 96]).unwrap();
        assert_eq!(
            bad_resp.feed_bytes(&bogus_m3, 1_795_564_820, &mut mgr, &mut host_roster),
            Err(CoreError::PairingAuthFailed)
        );
    }
    // Live code2 MUST still be unburned after unauthenticated probes!
    assert_eq!(mgr.live_code_count(1_795_564_820), 1);

    // Tampered msg2 fails closed on legitimate code2 initiator.
    let mut good_init = V2PakePairInitiator::new(
        &cli,
        "Workstation",
        "cli",
        &code2,
        None,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let mut good_resp = V2PakePairResponder::new(
        &host,
        PairingPathKind::Remote,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let gm1 = collect_v2_pair_bytes(&good_init.start().unwrap());
    let mut gm2 = collect_v2_pair_bytes(
        &good_resp
            .feed_bytes(&gm1, 1_795_564_820, &mut mgr, &mut host_roster)
            .unwrap(),
    );
    let idx = gm2.len() - 5;
    gm2[idx] ^= 0x40;
    assert_eq!(
        good_init.feed_bytes(&gm2),
        Err(CoreError::PairingAuthFailed)
    );
}

#[test]
fn bucketed_inner_padding_and_dummy_cover_frames() {
    let (host, cli) = test_identities();
    let pre = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    let mut hs_i = NoiseHfsHandshakeBuilder::new()
        .local_private_key(cli.static_key().secret_bytes())
        .prologue(&pre)
        .build_initiator()
        .unwrap();
    let mut hs_r = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&pre)
        .build_responder()
        .unwrap();
    let m1 = hs_i.write_message_vec(&[]).unwrap();
    hs_r.read_message_vec(&m1).unwrap();
    let m2 = hs_r.write_message_vec(&[]).unwrap();
    hs_i.read_message_vec(&m2).unwrap();
    let m3 = hs_i.write_message_vec(&[]).unwrap();
    hs_r.read_message_vec(&m3).unwrap();

    let tx_i = hs_i.into_transport_mode().unwrap();
    let tx_r = hs_r.into_transport_mode().unwrap();

    let mut sealed_i = SealedSession::with_v2_policies(
        tx_i,
        PaddingPolicy::v2_strict(),
        RekeyThresholds::default(),
        None,
        0,
    );
    let mut sealed_r = SealedSession::with_v2_policies(
        tx_r,
        PaddingPolicy::v2_strict(),
        RekeyThresholds::default(),
        None,
        0,
    );

    let cases: [(usize, usize); 9] = [
        (0, 256),
        (1, 256),
        (250, 256),
        (252, 256),
        (253, 512),
        (1000, 1024),
        (32_764, 32_768),
        (32_765, 65_503),
        (MAX_PADDED_PAYLOAD_LEN, 65_503),
    ];

    for (len, expected_bucket) in cases {
        let payload = vec![0xAB; len];
        let out = sealed_i.seal(InnerFrameType::Data, &payload, 10).unwrap();
        assert_eq!(out.ciphertext.len(), expected_bucket + AEAD_TAG_LEN);
        let decoded = sealed_r.unseal(&out.ciphertext).unwrap();
        assert_eq!(
            decoded,
            V2InnerFrame::Frame {
                kind: InnerFrameType::Data,
                payload
            }
        );
    }

    // seal() rejects Rekey, Padding, Padded without mutating TX nonce.
    let tx_before_bad_kind = sealed_i.tx_nonce();
    for bad_kind in [
        InnerFrameType::Rekey,
        InnerFrameType::Padding,
        InnerFrameType::Padded,
    ] {
        assert!(matches!(
            sealed_i.seal(bad_kind, &[], 15),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));
    }
    assert_eq!(sealed_i.tx_nonce(), tx_before_bad_kind);

    // Oversized payload > 65499 fails closed WITHOUT mutating TX nonce or frames_sent.
    let tx_before = sealed_i.tx_nonce();
    let frames_before = sealed_i.frames_sent();
    let oversized = vec![0xCD; MAX_PADDED_PAYLOAD_LEN + 1];
    assert!(matches!(
        sealed_i.seal(InnerFrameType::Data, &oversized, 20),
        Err(CoreError::FrameTooLarge { .. })
    ));
    assert_eq!(sealed_i.tx_nonce(), tx_before);
    assert_eq!(sealed_i.frames_sent(), frames_before);

    // 0x08 dummy cover frames advance TX and RX nonces cleanly and return DummyCover.
    let rx_before = sealed_r.rx_nonce();
    let tx_before_cover = sealed_i.tx_nonce();
    let cover = sealed_i.seal_dummy_cover(1024, 30).unwrap();
    assert_eq!(cover.ciphertext.len(), 1024 + AEAD_TAG_LEN);
    assert_eq!(sealed_i.tx_nonce(), tx_before_cover + 1);
    assert_eq!(
        sealed_r.unseal(&cover.ciphertext).unwrap(),
        V2InnerFrame::DummyCover {
            plaintext_len: 1024
        }
    );
    assert_eq!(sealed_r.rx_nonce(), rx_before + 1);

    // Strict v2 mode rejects unpadded 0x01..=0x07 frames on RX.
    let mut hs_u1 = NoiseHfsHandshakeBuilder::new()
        .local_private_key(cli.static_key().secret_bytes())
        .prologue(&pre)
        .build_initiator()
        .unwrap();
    let mut hs_u2 = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&pre)
        .build_responder()
        .unwrap();
    let um1 = hs_u1.write_message_vec(&[]).unwrap();
    hs_u2.read_message_vec(&um1).unwrap();
    let um2 = hs_u2.write_message_vec(&[]).unwrap();
    hs_u1.read_message_vec(&um2).unwrap();
    let um3 = hs_u1.write_message_vec(&[]).unwrap();
    hs_u2.read_message_vec(&um3).unwrap();
    let mut tx_unpadded = hs_u1.into_transport_mode().unwrap();
    let mut strict_rx = SealedSession::with_v2_policies(
        hs_u2.into_transport_mode().unwrap(),
        PaddingPolicy::v2_strict(),
        RekeyThresholds::default(),
        None,
        0,
    );
    let raw_v1_ct = tx_unpadded
        .write_message_vec(&encode_inner_frame(InnerFrameType::Data, b"unpadded").unwrap())
        .unwrap();
    assert_eq!(
        strict_rx.unseal(&raw_v1_ct),
        Err(CoreError::UnknownInnerFrameType(InnerFrameType::Data as u8))
    );

    // Non-zero padding bytes, truncated lengths, nested 0x08/0x09, and non-zero cover bytes fail closed.
    let mut padded =
        pad_inner_frame(InnerFrameType::Data, b"ok", &PaddingPolicy::v2_default()).unwrap();
    assert_eq!(
        unpad_inner_frame(&padded).unwrap(),
        (InnerFrameType::Data, b"ok".to_vec())
    );
    padded[200] = 0x01;
    assert!(matches!(
        unpad_inner_frame(&padded),
        Err(CoreError::InvalidInnerFramePayload(_))
    ));
    let mut bad_len = vec![
        InnerFrameType::Padded as u8,
        InnerFrameType::Data as u8,
        0x04,
        0x00,
        0x00,
    ];
    bad_len.resize(256, 0);
    assert!(matches!(
        unpad_inner_frame(&bad_len),
        Err(CoreError::InvalidInnerFramePayload(_))
    ));
    let mut nested = vec![
        InnerFrameType::Padded as u8,
        InnerFrameType::Padded as u8,
        0x00,
        0x00,
    ];
    nested.resize(256, 0);
    assert!(matches!(
        unpad_inner_frame(&nested),
        Err(CoreError::InvalidInnerFramePayload(_))
    ));
    let mut bad_cover = encode_dummy_cover_frame(256).unwrap();
    bad_cover[42] = 0xFF;
    assert!(matches!(
        decode_v2_inner_frame(&bad_cover, false),
        Err(CoreError::InvalidInnerFramePayload(_))
    ));
    assert!(PaddingPolicy::with_buckets(vec![], false).is_err());
    assert!(PaddingPolicy::with_buckets(vec![512, 256], false).is_err());
    assert!(PaddingPolicy::with_buckets(vec![3], false).is_err());
    let custom_policy = PaddingPolicy::with_buckets(vec![64, 512], true).unwrap();
    assert_eq!(
        pad_inner_frame(InnerFrameType::Data, b"custom", &custom_policy)
            .unwrap()
            .len(),
        64
    );

    // Legacy SealedSession::new (v1 mode) preserves unpadded v1 sizes AND rejects 0x08/0x09 on RX.
    let mut hs_i2 = NoiseHfsHandshakeBuilder::new()
        .local_private_key(cli.static_key().secret_bytes())
        .prologue(b"TND\x01\x01\x00")
        .build_initiator()
        .unwrap();
    let mut hs_r2 = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(b"TND\x01\x01\x00")
        .build_responder()
        .unwrap();
    let m1 = hs_i2.write_message_vec(&[]).unwrap();
    hs_r2.read_message_vec(&m1).unwrap();
    let m2 = hs_r2.write_message_vec(&[]).unwrap();
    hs_i2.read_message_vec(&m2).unwrap();
    let m3 = hs_i2.write_message_vec(&[]).unwrap();
    hs_r2.read_message_vec(&m3).unwrap();
    let mut tx_i2 = hs_i2.into_transport_mode().unwrap();
    let tx_r2 = hs_r2.into_transport_mode().unwrap();
    let v2_cover_on_v1 = tx_i2
        .write_message_vec(&encode_dummy_cover_frame(256).unwrap())
        .unwrap();
    let mut v1_r = SealedSession::new(tx_r2);
    assert_eq!(
        v1_r.unseal(&v2_cover_on_v1),
        Err(CoreError::UnknownInnerFrameType(
            InnerFrameType::Padding as u8
        ))
    );
    let mut v1_i = SealedSession::new(tx_i2);
    let v1_out = v1_i.seal(InnerFrameType::Data, b"hi", 0).unwrap();
    assert_eq!(v1_out.ciphertext.len(), 1 + 2 + AEAD_TAG_LEN);
    assert_eq!(V2_PADDING_BUCKETS.len(), 9);
}

#[test]
fn jittered_keepalive_and_rekey_atomicity_and_age_trigger() {
    let policy = ScheduleJitterPolicy::default();
    let (min_ping, max_ping) = policy.ping_bounds_ms();
    assert_eq!((min_ping, max_ping), (18_750, 31_250));

    let mut pings = BTreeSet::new();
    for _ in 0..64 {
        let d = policy.next_ping_delay_ms().unwrap();
        assert!(d >= min_ping && d <= max_ping);
        pings.insert(d);
    }
    assert!(pings.len() > 1, "ping jitter must vary across samples");

    let (min_frames, max_frames) = policy.rekey_frame_bounds();
    let (min_age, max_age) = policy.rekey_age_bounds_ms();
    assert_eq!((min_frames, max_frames), (786_432, 1_048_576));
    assert_eq!((min_age, max_age), (675_000, 900_000));

    let mut frame_set = BTreeSet::new();
    let mut age_set = BTreeSet::new();
    for _ in 0..64 {
        let t = policy.sample_rekey_thresholds().unwrap();
        assert!(t.max_frames >= min_frames && t.max_frames <= max_frames);
        assert!(t.max_age_ms >= min_age && t.max_age_ms <= max_age);
        frame_set.insert(t.max_frames);
        age_set.insert(t.max_age_ms);
    }
    assert!(frame_set.len() > 1);
    assert!(age_set.len() > 1);

    // Seeded determinism & degenerate min==max bounds & ceiling enforcement.
    let degenerate = ScheduleJitterPolicy::new(100, 0, 10, 5, 10_000).unwrap();
    assert_eq!(degenerate.ping_bounds_ms(), (100, 100));
    assert_eq!(degenerate.next_ping_delay_ms().unwrap(), 100);
    assert_eq!(
        policy.next_ping_delay_ms_from_seed(&[0x12; 32], 7),
        policy.next_ping_delay_ms_from_seed(&[0x12; 32], 7)
    );
    assert!(RekeyThresholds::new(MAX_REKEY_FRAMES_CEILING + 1, 1000).is_err());
    assert!(ScheduleJitterPolicy::new(1000, 2500, MAX_REKEY_FRAMES_CEILING + 1, 10, 7500).is_err());

    let (host, cli) = test_identities();
    let pre = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    let mut hs_i = NoiseHfsHandshakeBuilder::new()
        .local_private_key(cli.static_key().secret_bytes())
        .prologue(&pre)
        .build_initiator()
        .unwrap();
    let mut hs_r = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&pre)
        .build_responder()
        .unwrap();
    let m1 = hs_i.write_message_vec(&[]).unwrap();
    hs_r.read_message_vec(&m1).unwrap();
    let m2 = hs_r.write_message_vec(&[]).unwrap();
    hs_i.read_message_vec(&m2).unwrap();
    let m3 = hs_i.write_message_vec(&[]).unwrap();
    hs_r.read_message_vec(&m3).unwrap();

    let small_policy = ScheduleJitterPolicy::new(1_000, 2500, 4, 10, 7500).unwrap();
    let sampled = small_policy.sample_rekey_thresholds_from_seed(&[0x33; 32], 1);
    assert!(sampled.max_frames >= 3 && sampled.max_frames <= 4);

    let mut s_i = SealedSession::with_v2_policies(
        hs_i.into_transport_mode().unwrap(),
        PaddingPolicy::v2_default(),
        sampled,
        Some(small_policy),
        100,
    );
    let mut s_r = SealedSession::with_v2_policies(
        hs_r.into_transport_mode().unwrap(),
        PaddingPolicy::v2_default(),
        sampled,
        Some(small_policy),
        100,
    );

    for step in 1..sampled.max_frames {
        let out = s_i.seal(InnerFrameType::Data, b"ping", 100 + step).unwrap();
        assert_eq!(out.rekey_status, RekeyStatus::Ok);
        s_r.unseal(&out.ciphertext).unwrap();
    }
    let trigger = s_i
        .seal(InnerFrameType::Data, b"last-before-rekey", 110)
        .unwrap();
    assert_eq!(trigger.rekey_status, RekeyStatus::RekeyDue);
    s_r.unseal(&trigger.ciphertext).unwrap();

    // Regression tests for Rekey Atomicity: while RekeyDue, failed seal_auto_rekey (bad PING len)
    // and failed seal_dummy_cover_auto_rekey (bucket not in policy) MUST NOT rotate TX key or bump nonce!
    let tx_nonce_before = s_i.tx_nonce();
    let frames_before = s_i.frames_sent();
    assert!(matches!(
        s_i.seal_auto_rekey(InnerFrameType::Ping, &[1, 2, 3], 111),
        Err(CoreError::InvalidInnerFramePayload(_))
    ));
    assert_eq!(s_i.tx_nonce(), tx_nonce_before);
    assert_eq!(s_i.frames_sent(), frames_before);

    assert!(matches!(
        s_i.seal_dummy_cover_auto_rekey(777, 111),
        Err(CoreError::InvalidInnerFramePayload(_))
    ));
    assert_eq!(s_i.tx_nonce(), tx_nonce_before);
    assert_eq!(s_i.frames_sent(), frames_before);

    // Valid seal_auto_rekey triggers rekey cleanly and receiver unseals both frames in sync.
    let (rekey_opt, post_out) = s_i
        .seal_auto_rekey(InnerFrameType::Data, b"post-rekey", 112)
        .unwrap();
    let rekey_ct = rekey_opt.expect("rekey frame emitted");
    assert_eq!(
        s_r.unseal(&rekey_ct).unwrap(),
        V2InnerFrame::Frame {
            kind: InnerFrameType::Rekey,
            payload: vec![]
        }
    );
    assert_eq!(
        s_r.unseal(&post_out.ciphertext).unwrap(),
        V2InnerFrame::Frame {
            kind: InnerFrameType::Data,
            payload: b"post-rekey".to_vec()
        }
    );

    // Age-based RekeyDue trigger when now_ms - last_rekey_ms >= max_age_ms.
    let age_due_ms = 112 + s_i.rekey_thresholds().max_age_ms;
    assert_eq!(s_i.rekey_status(age_due_ms - 1), RekeyStatus::Ok);
    assert_eq!(s_i.rekey_status(age_due_ms), RekeyStatus::RekeyDue);
}

#[cfg(not(feature = "test-utils"))]
#[test]
fn derive_pake_keys_and_responders_reject_sub_production_params_without_test_utils() {
    let (host, cli) = test_identities();
    let weak = PakeArgon2Params {
        memory_kib: 256,
        time_cost: 1,
        parallelism: 1,
    };
    assert!(matches!(
        tendril_core::v2::derive_pake_keys("TND-AAAA-BBBB-CCCC", &[0x11; 16], weak),
        Err(CoreError::Argon2(_))
    ));
    assert!(matches!(
        V2PakePairInitiator::new(&cli, "Workstation", "cli", "TND-AAAA-BBBB-CCCC", None, weak),
        Err(CoreError::Argon2(_))
    ));
    assert!(matches!(
        V2PakePairResponder::new(&host, PairingPathKind::Remote, weak),
        Err(CoreError::Argon2(_))
    ));
}

#[cfg(feature = "test-utils")]
#[test]
fn test_utils_feature_enables_fast_pake_and_deterministic_test_knobs() {
    let (host, cli) = test_identities();
    let mut host_roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let now_unix = 1_795_564_800;
    let code = mgr
        .issue_code(PairingCodeKind::Lan2Group, now_unix)
        .unwrap();

    let mut p_init = V2PakePairInitiator::new(
        &cli,
        "Cli",
        "cli",
        &code,
        None,
        PakeArgon2Params::for_testing_only(),
    )
    .unwrap()
    .with_channel_salt_for_testing_only([0xAA; 16])
    .with_fixed_ephemeral_for_testing_only([0x11; 32]);
    let mut p_init_clone = V2PakePairInitiator::new(
        &cli,
        "Cli",
        "cli",
        &code,
        None,
        PakeArgon2Params::for_testing_only(),
    )
    .unwrap()
    .with_channel_salt_for_testing_only([0xAA; 16])
    .with_fixed_ephemeral_for_testing_only([0x11; 32]);
    let mut p_resp = V2PakePairResponder::new(
        &host,
        PairingPathKind::Lan,
        PakeArgon2Params::for_testing_only(),
    )
    .unwrap()
    .with_fixed_ephemeral_for_testing_only([0x22; 32]);
    let m1 = collect_v2_pair_bytes(&p_init.start().unwrap());
    let m1_clone = collect_v2_pair_bytes(&p_init_clone.start().unwrap());
    assert_eq!(m1, m1_clone);
    let m2 = collect_v2_pair_bytes(
        &p_resp
            .feed_bytes(&m1, now_unix, &mut mgr, &mut host_roster)
            .unwrap(),
    );
    let m3 = collect_v2_pair_bytes(&p_init.feed_bytes(&m2).unwrap());
    let m4 = collect_v2_pair_bytes(
        &p_resp
            .feed_bytes(&m3, now_unix, &mut mgr, &mut host_roster)
            .unwrap(),
    );
    let final_acts = p_init.feed_bytes(&m4).unwrap();
    assert!(final_acts.iter().any(|a| matches!(
        a,
        V2PairAction::Completed(V2PairOutcome::InitiatorPending { .. })
    )));

    let secrets = V2PeerSecrets::new([0x33; 32], [0x44; 32]);
    let (mut h_r, mut c_r) = setup_rosters_v2(&host, &cli, &secrets, WIRE_VERSION_V2);
    let mut si1 = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap()
    .with_fixed_ephemeral_for_testing_only([0x71; 32])
    .unwrap()
    .with_rendezvous_nonce_for_testing_only([0x81; 16]);
    let mut si2 = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap()
    .with_fixed_ephemeral_for_testing_only([0x71; 32])
    .unwrap()
    .with_rendezvous_nonce_for_testing_only([0x81; 16]);
    let sm1_a = collect_v2_session_bytes(si1.start(now_unix).unwrap());
    let sm1_b = collect_v2_session_bytes(si2.start(now_unix).unwrap());
    assert_eq!(sm1_a, sm1_b);
    let mut sr = V2SessionResponder::new(&host)
        .unwrap()
        .with_fixed_ephemeral_for_testing_only([0x72; 32]);
    let sm2 = collect_v2_session_bytes(sr.feed_bytes(&sm1_a, now_unix, 1, &mut h_r).unwrap());
    let sm3 = collect_v2_session_bytes(si1.feed_bytes(&sm2, now_unix, 2, &mut c_r).unwrap());
    sr.feed_bytes(&sm3, now_unix, 3, &mut h_r).unwrap();
    assert!(si1.is_established());
    assert!(sr.is_established());
}

#[test]
fn pake_msg1_replay_and_bad_msg3_do_not_burn_live_codes() {
    let (host, cli) = test_identities();
    let mut host_roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let now_unix = 1_795_564_800;
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, now_unix)
        .unwrap();

    // Legitimate initiator captures msg1; attacker replays that msg1 5 times with garbage msg3.
    let mut legit_init = V2PakePairInitiator::new(
        &cli,
        "Workstation",
        "cli",
        &code,
        None,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let captured_m1 = collect_v2_pair_bytes(&legit_init.start().unwrap());

    for attempt in 0..5 {
        let mut resp = V2PakePairResponder::new(
            &host,
            PairingPathKind::Remote,
            PakeArgon2Params::production(),
        )
        .unwrap();
        let m2 = collect_v2_pair_bytes(
            &resp
                .feed_bytes(&captured_m1, now_unix + attempt, &mut mgr, &mut host_roster)
                .unwrap(),
        );
        assert!(
            !m2.windows(host.host_id().len())
                .any(|w| w == host.host_id().as_bytes())
        );
        if attempt == 1 {
            // Replay #1 of captured_m1 MUST route to decoy, so even the original initiator
            // that generated captured_m1 rejects its decoy msg2 with PairingAuthFailed!
            assert_eq!(
                legit_init.feed_bytes(&m2),
                Err(CoreError::PairingAuthFailed)
            );
        }
        let garbage_m3 = encode_frame(&[0xAB; 128]).unwrap();
        assert_eq!(
            resp.feed_bytes(&garbage_m3, now_unix + attempt, &mut mgr, &mut host_roster),
            Err(CoreError::PairingAuthFailed)
        );
        assert_eq!(mgr.live_code_count(now_unix + attempt), 1);
    }

    // Legitimate pairing with a fresh msg1 salt still succeeds using the unburned code!
    let mut fresh_init = V2PakePairInitiator::new(
        &cli,
        "Workstation",
        "cli",
        &code,
        None,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let mut fresh_resp = V2PakePairResponder::new(
        &host,
        PairingPathKind::Remote,
        PakeArgon2Params::production(),
    )
    .unwrap();
    let fm1 = collect_v2_pair_bytes(&fresh_init.start().unwrap());
    let fm2 = collect_v2_pair_bytes(
        &fresh_resp
            .feed_bytes(&fm1, now_unix + 10, &mut mgr, &mut host_roster)
            .unwrap(),
    );
    let fm3 = collect_v2_pair_bytes(&fresh_init.feed_bytes(&fm2).unwrap());
    let fm4 = collect_v2_pair_bytes(
        &fresh_resp
            .feed_bytes(&fm3, now_unix + 10, &mut mgr, &mut host_roster)
            .unwrap(),
    );
    fresh_init.feed_bytes(&fm4).unwrap();
    assert_eq!(mgr.live_code_count(now_unix + 10), 0);
}

#[test]
fn replay_caches_fail_closed_at_live_capacity_and_pruning_frees_expired_slots() {
    let base_ts = 1_795_564_800u64;
    let mut r_cache = RendezvousReplayCache::new();
    for idx in 0..MAX_RENDEZVOUS_REPLAY_ENTRIES {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&(idx as u64).to_be_bytes());
        assert!(r_cache.can_accept(&nonce, base_ts));
        assert!(r_cache.record(nonce, base_ts, base_ts));
    }
    assert_eq!(r_cache.len(), MAX_RENDEZVOUS_REPLAY_ENTRIES);
    let extra_nonce = [0xFF; 16];
    // Cache full of live entries MUST fail closed without evicting any live entry.
    assert!(!r_cache.can_accept(&extra_nonce, base_ts + V2_RENDEZVOUS_MAX_SKEW_SECS));
    assert!(!r_cache.record(
        extra_nonce,
        base_ts + V2_RENDEZVOUS_MAX_SKEW_SECS,
        base_ts + V2_RENDEZVOUS_MAX_SKEW_SECS,
    ));
    let first_nonce = [0u8; 16];
    assert!(r_cache.contains(&first_nonce, base_ts + V2_RENDEZVOUS_MAX_SKEW_SECS));

    // Past the 300s skew boundary, expired entries prune and new nonces succeed.
    let expired_now = base_ts + V2_RENDEZVOUS_MAX_SKEW_SECS + 1;
    assert!(r_cache.can_accept(&extra_nonce, expired_now));
    assert!(r_cache.record(extra_nonce, expired_now, expired_now));
    assert_eq!(r_cache.len(), 1);

    // RelayDialReplayCache behaves identically on live epoch capacity and expiry.
    let mut d_cache = RelayDialReplayCache::new();
    let conn_id = [0x22; 16];
    for idx in 0..MAX_RELAY_DIAL_REPLAY_ENTRIES {
        let mut dial_nonce = [0u8; 32];
        dial_nonce[..8].copy_from_slice(&(idx as u64).to_be_bytes());
        assert!(d_cache.check_and_record(10, &dial_nonce, &conn_id, 9));
    }
    assert_eq!(d_cache.len(), MAX_RELAY_DIAL_REPLAY_ENTRIES);
    assert!(!d_cache.check_and_record(10, &[0xFE; 32], &conn_id, 9));
    // Old epoch=9 entries remain live until min_valid_epoch advances past 10.
    assert!(!d_cache.check_and_record(11, &[0xFE; 32], &conn_id, 10));
    assert!(d_cache.check_and_record(11, &[0xFE; 32], &conn_id, 11));
    assert_eq!(d_cache.len(), 1);
}

#[test]
fn reconnect_skew_boundary_and_malformed_msg1_payload_len_route_to_decoy() {
    let (host, cli) = test_identities();
    let secrets = V2PeerSecrets::new([0x66; 32], [0x77; 32]);
    let (mut host_roster, mut cli_roster) =
        setup_rosters_v2(&host, &cli, &secrets, WIRE_VERSION_V2);
    let now_unix = 1_795_564_800u64;

    // Exact +300 and -300 offsets succeed.
    for init_ts in [
        now_unix - V2_RENDEZVOUS_MAX_SKEW_SECS,
        now_unix + V2_RENDEZVOUS_MAX_SKEW_SECS,
    ] {
        let mut init = V2SessionInitiator::new(
            &cli,
            host.host_id(),
            *secrets.reconnect_secret(),
            None,
            None,
        )
        .unwrap();
        let mut resp = V2SessionResponder::new(&host).unwrap();
        let m1 = collect_v2_session_bytes(init.start(init_ts).unwrap());
        let m2 =
            collect_v2_session_bytes(resp.feed_bytes(&m1, now_unix, 1, &mut host_roster).unwrap());
        let m3 =
            collect_v2_session_bytes(init.feed_bytes(&m2, now_unix, 2, &mut cli_roster).unwrap());
        resp.feed_bytes(&m3, now_unix, 3, &mut host_roster).unwrap();
        assert!(init.is_established());
        assert!(resp.is_established());
    }

    // Offsets +301 and -301 route to decoy and surface as HostKeyUnverified.
    for bad_ts in [
        now_unix - V2_RENDEZVOUS_MAX_SKEW_SECS - 1,
        now_unix + V2_RENDEZVOUS_MAX_SKEW_SECS + 1,
    ] {
        let mut init = V2SessionInitiator::new(
            &cli,
            host.host_id(),
            *secrets.reconnect_secret(),
            None,
            None,
        )
        .unwrap();
        let mut resp = V2SessionResponder::new(&host).unwrap();
        let m1 = collect_v2_session_bytes(init.start(bad_ts).unwrap());
        let m2 =
            collect_v2_session_bytes(resp.feed_bytes(&m1, now_unix, 1, &mut host_roster).unwrap());
        assert_eq!(
            init.feed_bytes(&m2, now_unix, 2, &mut cli_roster),
            Err(CoreError::HostKeyUnverified)
        );
    }

    // Malformed payload lengths (0, 55, 57) execute decoy path cleanly without short-circuit error on msg1.
    let pre = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    for bad_len in [0usize, 55usize, 57usize] {
        let scanner_key = StaticKeypair::from_scalar([0x98; 32]);
        let mut hs_i = NoiseHfsHandshakeBuilder::new()
            .local_private_key(scanner_key.secret_bytes())
            .prologue(&pre)
            .build_initiator()
            .unwrap();
        let m1_body = hs_i.write_message_vec(&vec![0x33; bad_len]).unwrap();
        let mut wire = pre.to_vec();
        wire.extend_from_slice(&encode_frame(&m1_body).unwrap());
        let mut resp = V2SessionResponder::new(&host).unwrap();
        let m2 = collect_v2_session_bytes(
            resp.feed_bytes(&wire, now_unix, 1, &mut host_roster)
                .unwrap(),
        );
        let (m2_body, _) = decode_frame(&m2).unwrap();
        hs_i.read_message_vec(m2_body).unwrap();
        assert_ne!(
            hs_i.get_remote_static(),
            Some(host.static_key().public_bytes())
        );
    }
}

#[test]
fn verify_and_record_v2_relay_dial_verifies_before_caching_and_enforces_host() {
    let mailbox_secret = [0x5B; 32];
    let epoch = 123u64;
    let window = derive_epoch_mailbox_window(&mailbox_secret, epoch * RELAY_V2_EPOCH_SECS);
    let m = derive_epoch_mailbox(&mailbox_secret, epoch);
    let dial_nonce = [0x11; 32];
    let conn_id = [0x22; 16];

    let verified_host =
        VerifiedRelayHost::from_challenge("Relay.Example.NET.", "relay.example.net").unwrap();
    assert_eq!(verified_host.as_str(), "relay.example.net");
    assert!(VerifiedRelayHost::from_challenge("relay.example.net", "evil.example.net").is_err());

    let proof = sign_v2_relay_dial(&m, verified_host.as_str(), &dial_nonce, &conn_id).unwrap();
    let mut cache = RelayDialReplayCache::new();

    // Wrong proof MUST fail with InvalidSignature and NOT record into RelayDialReplayCache!
    let mut bad_proof = proof;
    bad_proof[0] ^= 0xFF;
    assert_eq!(
        verify_and_record_v2_relay_dial(
            &mut cache,
            &window,
            &verified_host,
            epoch,
            &dial_nonce,
            &conn_id,
            &bad_proof,
        )
        .err(),
        Some(CoreError::InvalidSignature)
    );
    assert!(cache.is_empty());

    // Valid proof verifies and records, returning the matching DerivedMailbox; replay fails closed.
    let matched = verify_and_record_v2_relay_dial(
        &mut cache,
        &window,
        &verified_host,
        epoch,
        &dial_nonce,
        &conn_id,
        &proof,
    )
    .unwrap();
    assert_eq!(matched.mailbox_id, m.mailbox_id);
    assert_eq!(cache.len(), 1);
    assert!(matches!(
        verify_and_record_v2_relay_dial(
            &mut cache,
            &window,
            &verified_host,
            epoch,
            &dial_nonce,
            &conn_id,
            &proof,
        ),
        Err(CoreError::ProtocolViolation(_))
    ));
}

#[test]
fn initiator_v2_grant_revocation_post_rekey_crl_and_roster_rollback_and_pairing_floor() {
    let (host, cli) = test_identities();
    let secrets = V2PeerSecrets::new([0x66; 32], [0x77; 32]);
    let (mut host_roster, mut cli_roster) =
        setup_rosters_v2(&host, &cli, &secrets, WIRE_VERSION_V2);
    assert_eq!(
        cli_roster.pairing_floor(host.static_key().public_bytes()),
        WIRE_VERSION_V2
    );
    assert_eq!(cli_roster.pairing_floor(&[0x99; 32]), WIRE_VERSION);
    let m2m_grant = host_roster
        .mint_grant(
            &host,
            &cli.device_id(),
            vec!["fs.read:/docs/*".to_string()],
            1_795_564_790,
            1_795_565_800,
            [0x99; 16],
        )
        .unwrap();
    let m2m_pin = PinnedHost::with_hash(
        Some(host.host_id().to_string()),
        *host.static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        0,
    );
    assert!(matches!(
        PairingInitiator::new_m2m_with_min_wire_version(
            &cli,
            "Cli",
            "cli",
            m2m_grant,
            m2m_pin,
            cli_roster.pairing_floor(host.static_key().public_bytes()),
            None,
        ),
        Err(CoreError::VersionDowngrade {
            peer_min: 2,
            negotiated: 1
        })
    ));

    // Rollback safety: if apply_v2_pair_initiator_outcome fails after staging, roster stays intact.
    let mut bad_roster = Roster::new();
    let conflict_id = "existing-conflict".to_string();
    bad_roster
        .record_pending_host(
            conflict_id.clone(),
            "Conflict".into(),
            [0x12; 32],
            cli.signing_key().public_key().clone(),
            0,
            "1234".into(),
            vec![],
        )
        .unwrap();
    let snapshot_before = bad_roster.clone();
    let invalid_outcome = V2PairOutcome::InitiatorPending {
        device_id: cli.device_id(),
        host_id: conflict_id,
        host_static_pub: [0x13; 32],
        host_signing_pub: cli.signing_key().public_key().clone(),
        host_rotation_seq: 1,
        pairing_sas: "9999".into(),
        host_pin_verified: true,
        v2_secrets: secrets.clone(),
    };
    assert!(
        bad_roster
            .apply_v2_pair_initiator_outcome(&invalid_outcome, "Host", vec![])
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(&bad_roster).unwrap(),
        serde_json::to_value(&snapshot_before).unwrap()
    );

    // Initiator-side Grant, Revocation, and post-Rekey CRL fail-closed + Responder post-Rekey CRL.
    let now_unix = 1_795_564_800u64;
    let mut init = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let mut resp = V2SessionResponder::new(&host).unwrap();
    let m1 = collect_v2_session_bytes(init.start(now_unix).unwrap());
    let m2 = collect_v2_session_bytes(resp.feed_bytes(&m1, now_unix, 1, &mut host_roster).unwrap());
    let m3 = collect_v2_session_bytes(init.feed_bytes(&m2, now_unix, 2, &mut cli_roster).unwrap());
    resp.feed_bytes(&m3, now_unix, 3, &mut host_roster).unwrap();

    let grant = host_roster
        .mint_grant(
            &host,
            &cli.device_id(),
            vec!["fs.read:/docs/*".to_string()],
            now_unix - 5,
            now_unix + 600,
            [0x5A; 16],
        )
        .unwrap();
    let grant_wire = collect_v2_session_bytes(resp.seal_grant(&grant, 10).unwrap());
    let init_actions = init
        .feed_bytes(&grant_wire, now_unix, 11, &mut cli_roster)
        .unwrap();
    assert!(
        init_actions
            .iter()
            .any(|a| matches!(a, V2SessionAction::GrantUpdated(_)))
    );
    assert_eq!(init.active_grant(), Some(&grant));

    // Trigger outgoing Rekey on resp via tick() at 2_000_000 ms, apply CRL on cli_roster,
    // and assert initiator's post-Rekey CRL check fails closed on the revoked grant nonce!
    let rekey_to_init =
        collect_v2_session_bytes(resp.tick(now_unix, 2_000_000, &host_roster).unwrap());
    assert!(!rekey_to_init.is_empty());

    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            seq: 2,
            revoked_devices: vec![],
            revoked_nonces: vec![grant.nonce.clone()],
            ts: "2026-11-20T00:00:00Z".to_string(),
        },
        host.signing_key(),
    )
    .unwrap();
    cli_roster
        .ingest_crl(crl, host.host_id(), host.signing_key().public_key())
        .unwrap();

    assert!(matches!(
        init.feed_bytes(&rekey_to_init, now_unix, 2_000_001, &mut cli_roster),
        Err(CoreError::GrantDenied(_))
    ));

    // Also test initiator-side Revocation frame handling AND responder-side post-Rekey CRL check.
    let (mut h_r2, mut c_r2) = setup_rosters_v2(&host, &cli, &secrets, WIRE_VERSION_V2);
    let mut i2 = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let mut r2 = V2SessionResponder::new(&host).unwrap();
    let x1 = collect_v2_session_bytes(i2.start(now_unix).unwrap());
    let x2 = collect_v2_session_bytes(r2.feed_bytes(&x1, now_unix, 1, &mut h_r2).unwrap());
    let x3 = collect_v2_session_bytes(i2.feed_bytes(&x2, now_unix, 2, &mut c_r2).unwrap());
    r2.feed_bytes(&x3, now_unix, 3, &mut h_r2).unwrap();

    // Responder-side post-Rekey CRL check fails closed after peer device is revoked in roster.
    let rekey_to_resp = collect_v2_session_bytes(i2.tick(now_unix, 2_000_000, &c_r2).unwrap());
    assert!(!rekey_to_resp.is_empty());
    h_r2.ingest_crl(
        sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: host.host_id().to_string(),
                seq: 3,
                revoked_devices: vec![cli.device_id()],
                revoked_nonces: vec![],
                ts: "2026-11-20T00:01:00Z".to_string(),
            },
            host.signing_key(),
        )
        .unwrap(),
        host.host_id(),
        host.signing_key().public_key(),
    )
    .unwrap();
    assert!(matches!(
        r2.feed_bytes(&rekey_to_resp, now_unix, 2_000_001, &mut h_r2),
        Err(CoreError::PeerRevoked(_))
    ));

    // Initiator-side Revocation frame fails closed when host revokes itself/cli.
    let (mut h_r3, mut c_r3) = setup_rosters_v2(&host, &cli, &secrets, WIRE_VERSION_V2);
    let mut i3 = V2SessionInitiator::new(
        &cli,
        host.host_id(),
        *secrets.reconnect_secret(),
        None,
        None,
    )
    .unwrap();
    let mut r3 = V2SessionResponder::new(&host).unwrap();
    let y1 = collect_v2_session_bytes(i3.start(now_unix).unwrap());
    let y2 = collect_v2_session_bytes(r3.feed_bytes(&y1, now_unix, 1, &mut h_r3).unwrap());
    let y3 = collect_v2_session_bytes(i3.feed_bytes(&y2, now_unix, 2, &mut c_r3).unwrap());
    r3.feed_bytes(&y3, now_unix, 3, &mut h_r3).unwrap();
    let crl_to_init = collect_v2_session_bytes(
        r3.seal_revocation(
            &sign_crl(
                RevocationListUnsigned {
                    v: 1,
                    issuer: host.host_id().to_string(),
                    seq: 4,
                    revoked_devices: vec![cli.device_id()],
                    revoked_nonces: vec![],
                    ts: "2026-11-20T00:02:00Z".to_string(),
                },
                host.signing_key(),
            )
            .unwrap(),
            30,
        )
        .unwrap(),
    );
    assert!(matches!(
        i3.feed_bytes(&crl_to_init, now_unix, 31, &mut c_r3),
        Err(CoreError::PeerRevoked(_))
    ));
}

#[cfg(feature = "test-utils")]
#[test]
fn pake_responder_pads_to_fixed_argon2_pass_floor() {
    use tendril_core::v2::V2_PAKE_FIXED_ARGON2_PASSES;

    assert_eq!(V2_PAKE_FIXED_ARGON2_PASSES, 4);
    let (host, cli) = test_identities();
    let now_unix = 1_795_132_800;
    let params = PakeArgon2Params::for_testing_only();

    for live_count in 0..=4usize {
        let mut mgr = PairingManager::new(PairingConfig::default());
        let mut last_code = "TND-AAAA-BBBB-CCCC".to_string();
        for idx in 0..live_count {
            let mut entropy = [0x10u8; 32];
            entropy[0] = (idx as u8) + 1;
            last_code = mgr
                .issue_code_with_entropy(PairingCodeKind::Remote3Group, now_unix, &entropy)
                .unwrap();
        }
        let mut host_roster = Roster::new();
        let mut init =
            V2PakePairInitiator::new(&cli, "Dev", "cli", &last_code, None, params).unwrap();
        let mut resp = V2PakePairResponder::new(&host, PairingPathKind::Remote, params).unwrap();

        let m1 = collect_v2_pair_bytes(&init.start().unwrap());
        let m2 = collect_v2_pair_bytes(
            &resp
                .feed_bytes(&m1, now_unix + 1, &mut mgr, &mut host_roster)
                .unwrap(),
        );
        if live_count == 0 {
            assert_eq!(init.feed_bytes(&m2), Err(CoreError::PairingAuthFailed));
        } else {
            let m3 = collect_v2_pair_bytes(&init.feed_bytes(&m2).unwrap());
            let m4 = collect_v2_pair_bytes(
                &resp
                    .feed_bytes(&m3, now_unix + 2, &mut mgr, &mut host_roster)
                    .unwrap(),
            );
            let actions = init.feed_bytes(&m4).unwrap();
            assert!(actions.iter().any(|a| matches!(
                a,
                V2PairAction::Completed(V2PairOutcome::InitiatorPending { .. })
            )));
        }
    }
}
