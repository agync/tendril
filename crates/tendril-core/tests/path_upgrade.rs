//! Tests for `HostHello`/`SessionHello` `upgrade` negotiation and `0x0D PATH_UPGRADE`.

use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::noise::{NoiseHfsHandshakeBuilder, NoiseTransport};
use tendril_core::pairing::{
    PairingCodeKind, PairingConfig, PairingInitiator, PairingManager, PairingPathKind,
    PairingResponder,
};
use tendril_core::roster::{Roster, V2PeerSecrets};
use tendril_core::routes::MAX_ROUTE_SEQ;
use tendril_core::session::{SessionAction, SessionMachine};
use tendril_core::v2::{
    PaddingPolicy, PakeArgon2Params, V2PairAction, V2PakePairInitiator, V2PakePairResponder,
    V2SessionAction, V2SessionInitiator, V2SessionResponder, compute_pake_resp_mac,
    derive_pake_keys, pake_msg2_bucket_for_hello_len, seal_pake_host_hello,
};
use tendril_core::wire::{
    HostHello, InnerFrameType, Intent, MAX_PATH_UPGRADE_LEN, MAX_PATH_UPGRADE_OFFERS_PER_SESSION,
    MAX_UPGRADE_CAP_LEN, MAX_UPGRADE_CAPS, PathUpgradeMsg, Preamble, SessionHello,
    UPGRADE_CAP_WEBRTC_V1, WIRE_VERSION, WIRE_VERSION_V2, decode_frame, encode_frame,
    encode_inner_frame, validate_upgrade_caps,
};

const NOW_UNIX: u64 = 1_795_564_800;
const NOW_MS: u64 = 10_000;

fn host_id() -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x11; 32]),
        SigningKeypair::from_seed([0x21; 32]),
    )
    .with_host_id("laptop-host")
}

fn client_id() -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([0x12; 32]),
        SigningKeypair::from_seed([0x22; 32]),
    )
}

fn build_client_roster(host: &EndpointIdentity, min_wire: u8) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".to_string(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            min_wire.into(),
            vec![],
        )
        .unwrap();
    roster
}

fn build_host_roster(client: &EndpointIdentity, v2_secrets: Option<V2PeerSecrets>) -> Roster {
    let mut roster = Roster::new();
    roster
        .record_pending_pair(
            *client.static_key().public_bytes(),
            None,
            "Client".to_string(),
            "cli".to_string(),
            "abcd".to_string(),
        )
        .unwrap();
    roster
        .confirm_peer(&client.device_id(), Some("abcd"))
        .unwrap();
    if let Some(secrets) = v2_secrets {
        roster
            .set_peer_v2_secrets(&client.device_id(), secrets)
            .unwrap();
    }
    roster
}

fn v1_wire(actions: &[SessionAction]) -> Vec<u8> {
    let mut out = Vec::new();
    for action in actions {
        if let SessionAction::WriteBytes(bytes) = action {
            out.extend_from_slice(bytes);
        }
    }
    out
}

fn v2_wire(actions: &[V2SessionAction]) -> Vec<u8> {
    let mut out = Vec::new();
    for action in actions {
        if let V2SessionAction::WriteBytes(bytes) = action {
            out.extend_from_slice(bytes);
        }
    }
    out
}

fn establish_v1(
    init_caps: Vec<String>,
    resp_caps: Vec<String>,
) -> (SessionMachine, SessionMachine, Roster, Roster) {
    let host = host_id();
    let client = client_id();
    let mut client_roster = build_client_roster(&host, WIRE_VERSION);
    let mut host_roster = build_host_roster(&client, None);

    let mut init = SessionMachine::new_initiator(&client, host.host_id(), None, None, None)
        .unwrap()
        .with_upgrade_caps(init_caps)
        .unwrap();
    let mut resp = SessionMachine::new_responder(&host, None)
        .unwrap()
        .with_upgrade_caps(resp_caps)
        .unwrap();

    let m1 = v1_wire(&init.start().unwrap());
    let m2 = v1_wire(
        &resp
            .feed_bytes(&m1, NOW_UNIX, NOW_MS, &mut host_roster)
            .unwrap(),
    );
    let m3 = v1_wire(
        &init
            .feed_bytes(&m2, NOW_UNIX, NOW_MS, &mut client_roster)
            .unwrap(),
    );
    resp.feed_bytes(&m3, NOW_UNIX, NOW_MS, &mut host_roster)
        .unwrap();

    assert!(init.is_established());
    assert!(resp.is_established());
    (init, resp, client_roster, host_roster)
}

fn establish_v2(
    init_caps: Vec<String>,
    resp_caps: Vec<String>,
    init_padding: PaddingPolicy,
    resp_padding: PaddingPolicy,
) -> (V2SessionInitiator, V2SessionResponder, Roster, Roster) {
    let host = host_id();
    let client = client_id();
    let secret = [0x5A; 32];

    let mut host_roster = build_host_roster(&client, Some(V2PeerSecrets::new(secret, [0x6B; 32])));
    let mut client_roster = build_client_roster(&host, WIRE_VERSION_V2);

    let mut init = V2SessionInitiator::new(&client, host.host_id(), secret, None, None)
        .unwrap()
        .with_padding_policy(init_padding)
        .with_upgrade_caps(init_caps)
        .unwrap();
    let mut resp = V2SessionResponder::new(&host)
        .unwrap()
        .with_padding_policy(resp_padding)
        .with_upgrade_caps(resp_caps)
        .unwrap();

    let m1 = v2_wire(&init.start(NOW_UNIX).unwrap());
    let m2 = v2_wire(
        &resp
            .feed_bytes(&m1, NOW_UNIX, NOW_MS, &mut host_roster)
            .unwrap(),
    );
    let m3 = v2_wire(
        &init
            .feed_bytes(&m2, NOW_UNIX, NOW_MS, &mut client_roster)
            .unwrap(),
    );
    resp.feed_bytes(&m3, NOW_UNIX, NOW_MS, &mut host_roster)
        .unwrap();

    assert!(init.is_established());
    assert!(resp.is_established());
    (init, resp, client_roster, host_roster)
}

#[test]
fn upgrade_caps_and_hello_json_validation() {
    let base_host = HostHello {
        host_id: "h1".to_string(),
        proto_version: 1,
        signing_pub: "sig".to_string(),
        rotation: vec![],
        upgrade: vec![],
    };
    let host_json = serde_json::to_string(&base_host).unwrap();
    assert!(!host_json.contains("upgrade"));
    assert_eq!(
        serde_json::from_str::<HostHello>(&host_json).unwrap(),
        base_host
    );

    let base_sess = SessionHello {
        device_id: "dev".to_string(),
        grant: None,
        crl_seq: None,
        groups: None,
        route_seq: None,
        upgrade: vec![],
    };
    let sess_json = serde_json::to_string(&base_sess).unwrap();
    assert!(!sess_json.contains("upgrade"));
    assert_eq!(
        serde_json::from_str::<SessionHello>(&sess_json).unwrap(),
        base_sess
    );

    // Explicit empty JSON array `"upgrade": []` must be rejected.
    assert!(
        serde_json::from_value::<HostHello>(serde_json::json!({
            "host_id": "h1",
            "proto_version": 1,
            "signing_pub": "sig",
            "upgrade": []
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<SessionHello>(serde_json::json!({
            "device_id": "dev",
            "upgrade": []
        }))
        .is_err()
    );

    // Valid roundtrip.
    assert!(validate_upgrade_caps(&[UPGRADE_CAP_WEBRTC_V1.to_string()]).is_ok());

    // > 4 capabilities rejected.
    let too_many: Vec<String> = (0..=MAX_UPGRADE_CAPS).map(|i| format!("cap/{i}")).collect();
    assert!(validate_upgrade_caps(&too_many).is_err());

    // > 32 char, empty, whitespace, control-char, and duplicate capabilities rejected.
    let too_long = "a".repeat(MAX_UPGRADE_CAP_LEN + 1);
    for bad in [
        vec!["".to_string()],
        vec![too_long],
        vec!["webrtc v1".to_string()],
        vec!["webrtc\nv1".to_string()],
        vec!["WEBRTC/V1".to_string()],
        vec!["bad;cap".to_string()],
        vec![
            UPGRADE_CAP_WEBRTC_V1.to_string(),
            UPGRADE_CAP_WEBRTC_V1.to_string(),
        ],
    ] {
        assert!(
            validate_upgrade_caps(&bad).is_err(),
            "expected error for {bad:?}"
        );
        assert!(
            serde_json::from_value::<HostHello>(serde_json::json!({
                "host_id": "h1",
                "proto_version": 1,
                "signing_pub": "sig",
                "upgrade": bad
            }))
            .is_err()
        );
    }
}

#[test]
fn path_upgrade_msg_validation_bounds() {
    let offer = PathUpgradeMsg::Offer {
        upgrade_id: 1,
        protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
        sdp: "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n".to_string(),
    };
    let encoded = offer.encode().unwrap();
    assert_eq!(PathUpgradeMsg::decode(&encoded).unwrap(), offer);

    assert_eq!(
        PathUpgradeMsg::decode(&[]),
        Err(CoreError::InvalidInnerFramePayload(
            "PATH_UPGRADE payload cannot be empty"
        ))
    );
    assert_eq!(
        PathUpgradeMsg::decode(&vec![b' '; MAX_PATH_UPGRADE_LEN + 1]),
        Err(CoreError::FrameTooLarge {
            len: MAX_PATH_UPGRADE_LEN + 1,
            max: MAX_PATH_UPGRADE_LEN
        })
    );

    assert!(
        PathUpgradeMsg::Offer {
            upgrade_id: 0,
            protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
            sdp: "v=0".to_string(),
        }
        .validate()
        .is_err()
    );
    assert!(
        PathUpgradeMsg::Reject {
            upgrade_id: 0,
            reason: "busy".to_string(),
        }
        .validate()
        .is_err()
    );
    assert!(matches!(
        PathUpgradeMsg::Offer {
            upgrade_id: 1,
            protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
            sdp: "\r".repeat(15_000),
        }
        .validate(),
        Err(CoreError::FrameTooLarge { .. })
    ));
    assert!(
        PathUpgradeMsg::Offer {
            upgrade_id: MAX_ROUTE_SEQ + 1,
            protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
            sdp: "v=0".to_string(),
        }
        .validate()
        .is_err()
    );
    assert!(
        PathUpgradeMsg::Offer {
            upgrade_id: 1,
            protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
            sdp: "v=0\0bad".to_string(),
        }
        .validate()
        .is_err()
    );
    assert!(
        PathUpgradeMsg::Offer {
            upgrade_id: 1,
            protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
            sdp: "x".repeat(15_361),
        }
        .validate()
        .is_err()
    );
    assert!(
        PathUpgradeMsg::Reject {
            upgrade_id: 1,
            reason: "bad\nreason".to_string(),
        }
        .validate()
        .is_err()
    );
    assert!(
        PathUpgradeMsg::Reject {
            upgrade_id: 1,
            reason: "r".repeat(257),
        }
        .validate()
        .is_err()
    );
}

#[test]
fn pairing_rejects_host_hello_upgrade_caps_v1_and_v2_pake() {
    let host = host_id();
    let client = client_id();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Lan2Group, NOW_UNIX)
        .unwrap();
    let mut host_roster = Roster::new();

    // v1 pairing: responder omits upgrade; crafted responder injecting HostHello.upgrade fails initiator.
    let mut resp_pair = PairingResponder::new(&host, PairingPathKind::Lan, None).unwrap();
    let mut init_check =
        PairingInitiator::new(&client, "client", "desktop", &code, None, None).unwrap();
    let check_m1: Vec<u8> = init_check
        .start()
        .unwrap()
        .into_iter()
        .filter_map(|a| match a {
            tendril_core::pairing::PairAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect();
    let check_m2: Vec<u8> = resp_pair
        .feed_bytes(&check_m1, NOW_UNIX, &mut mgr, &mut host_roster)
        .unwrap()
        .into_iter()
        .filter_map(|a| match a {
            tendril_core::pairing::PairAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(init_check.feed_bytes(&check_m2).is_ok());

    let mut init_v1 =
        PairingInitiator::new(&client, "client", "desktop", &code, None, None).unwrap();
    let mut raw_resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&Preamble::v1(Intent::Pair).encode())
        .build_responder()
        .unwrap();
    let m1 = init_v1
        .start()
        .unwrap()
        .into_iter()
        .find_map(|a| match a {
            tendril_core::pairing::PairAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .unwrap();
    raw_resp
        .read_message_vec(decode_frame(&m1[6..]).unwrap().0)
        .unwrap();
    let injected_hh = serde_json::to_vec(&HostHello {
        host_id: host.host_id().to_string(),
        proto_version: 1,
        signing_pub: host.signing_key().public_key().to_b64url(),
        rotation: vec![],
        upgrade: vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
    })
    .unwrap();
    let m2 = raw_resp.write_message_vec(&injected_hh).unwrap();
    let err = init_v1.feed_bytes(&encode_frame(&m2).unwrap()).unwrap_err();
    assert_eq!(
        err,
        CoreError::ProtocolViolation("upgrade capabilities not allowed in pairing")
    );

    // v2 PAKE pairing: verify responder succeeds cleanly and initiator rejects injected upgrade.
    let params = PakeArgon2Params::production();
    let mut pake_resp = V2PakePairResponder::new(&host, PairingPathKind::Lan, params).unwrap();
    let mut pake_init_ok =
        V2PakePairInitiator::new(&client, "client", "desktop", &code, None, params).unwrap();
    let pm1_ok: Vec<u8> = pake_init_ok
        .start()
        .unwrap()
        .into_iter()
        .filter_map(|a| match a {
            V2PairAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect();
    let pm2_ok: Vec<u8> = pake_resp
        .feed_bytes(&pm1_ok, NOW_UNIX, &mut mgr, &mut host_roster)
        .unwrap()
        .into_iter()
        .filter_map(|a| match a {
            V2PairAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(pake_init_ok.feed_bytes(&pm2_ok).is_ok());

    let mut pake_init =
        V2PakePairInitiator::new(&client, "client", "desktop", &code, None, params).unwrap();
    let pm1 = pake_init
        .start()
        .unwrap()
        .into_iter()
        .find_map(|a| match a {
            V2PairAction::WriteBytes(b) => Some(b),
            _ => None,
        })
        .unwrap();
    let pm1_body = decode_frame(&pm1[6..]).unwrap().0;
    let salt_start = pm1_body.len() - 48;
    let salt: [u8; 16] = pm1_body[salt_start..salt_start + 16].try_into().unwrap();
    let keys = derive_pake_keys(&code, &salt, params).unwrap();
    let prologue = tendril_core::v2::pake_noise_prologue(&keys.pake_context_tag);
    let mut raw_pake = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&prologue)
        .build_responder()
        .unwrap();
    let _pm1_dec = raw_pake.read_message_vec(pm1_body).unwrap();
    let pake_hh = serde_json::to_vec(&HostHello {
        host_id: host.host_id().to_string(),
        proto_version: WIRE_VERSION_V2,
        signing_pub: host.signing_key().public_key().to_b64url(),
        rotation: vec![],
        upgrade: vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
    })
    .unwrap();
    let bucket_len = pake_msg2_bucket_for_hello_len(pake_hh.len()).unwrap();
    let pm2 = raw_pake
        .write_msg2_with_hash(|h_pre| {
            let sealed = seal_pake_host_hello(&keys.pake_hello_key, h_pre, &pake_hh)?;
            let mac = compute_pake_resp_mac(&keys.pake_confirm_key, h_pre, &sealed);
            let mut pl = Vec::with_capacity(bucket_len);
            pl.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
            pl.extend_from_slice(&sealed);
            pl.extend_from_slice(&mac);
            pl.resize(bucket_len, 0);
            Ok(pl)
        })
        .unwrap();
    let pake_err = pake_init
        .feed_bytes(&encode_frame(&pm2).unwrap())
        .unwrap_err();
    assert_eq!(
        pake_err,
        CoreError::ProtocolViolation("upgrade capabilities not allowed in pairing")
    );
}

#[test]
fn session_negotiation_intersection_and_unoffered_rejection() {
    // 1. Intersection when host offers subset.
    let (init, resp, _, _) = establish_v1(
        vec![UPGRADE_CAP_WEBRTC_V1.to_string(), "alt/v2".to_string()],
        vec!["alt/v2".to_string()],
    );
    assert_eq!(init.negotiated_upgrade_caps(), &["alt/v2".to_string()]);
    assert_eq!(resp.negotiated_upgrade_caps(), &["alt/v2".to_string()]);

    // 2. Older host without upgrade caps -> empty negotiated caps on both sides.
    let (init2, resp2, _, _) = establish_v1(vec![UPGRADE_CAP_WEBRTC_V1.to_string()], vec![]);
    assert!(init2.negotiated_upgrade_caps().is_empty());
    assert!(resp2.negotiated_upgrade_caps().is_empty());

    // 3. Initiator injects unoffered upgrade cap in SessionHello -> responder rejects with ProtocolViolation.
    let host = host_id();
    let client = client_id();
    let mut host_roster = build_host_roster(&client, None);
    let mut resp3 = SessionMachine::new_responder(&host, None).unwrap();
    let mut raw_init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(client.static_key().secret_bytes())
        .prologue(&Preamble::v1(Intent::Session).encode())
        .build_initiator()
        .unwrap();
    let m1 = raw_init.write_message_vec(&[]).unwrap();
    let mut wire1 = Preamble::v1(Intent::Session).encode().to_vec();
    wire1.extend_from_slice(&encode_frame(&m1).unwrap());
    let m2 = v1_wire(
        &resp3
            .feed_bytes(&wire1, NOW_UNIX, NOW_MS, &mut host_roster)
            .unwrap(),
    );
    let _hh: HostHello = serde_json::from_slice(
        &raw_init
            .read_message_vec(decode_frame(&m2).unwrap().0)
            .unwrap(),
    )
    .unwrap();
    let bad_sh = serde_json::to_vec(&SessionHello {
        device_id: client.device_id(),
        grant: None,
        crl_seq: None,
        groups: None,
        route_seq: None,
        upgrade: vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
    })
    .unwrap();
    let m3 = encode_frame(&raw_init.write_message_vec(&bad_sh).unwrap()).unwrap();
    let err = resp3
        .feed_bytes(&m3, NOW_UNIX, NOW_MS, &mut host_roster)
        .unwrap_err();
    assert_eq!(
        err,
        CoreError::ProtocolViolation("unoffered upgrade capability in session hello")
    );
}

#[test]
fn v1_path_upgrade_round_trip_and_state_machine_guards() {
    let (mut init, mut resp, mut client_roster, mut host_roster) = establish_v1(
        vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
        vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
    );

    // Wrong direction sends rejected without mutating offer budget.
    assert!(
        init.send_path_upgrade(
            &PathUpgradeMsg::Reject {
                upgrade_id: 1,
                reason: "no".to_string()
            },
            NOW_MS
        )
        .is_err()
    );
    assert!(
        resp.send_path_upgrade(
            &PathUpgradeMsg::Offer {
                upgrade_id: 1,
                protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
                sdp: "v=0".to_string()
            },
            NOW_MS
        )
        .is_err()
    );
    // Unnegotiated protocol rejected.
    assert!(
        init.send_path_upgrade(
            &PathUpgradeMsg::Offer {
                upgrade_id: 1,
                protocol: "quic/v9".to_string(),
                sdp: "v=0".to_string()
            },
            NOW_MS
        )
        .is_err()
    );

    // Offer 1 -> Answer 1.
    let offer1 = PathUpgradeMsg::Offer {
        upgrade_id: 1,
        protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
        sdp: "v=0\r\na=offer1\r\n".to_string(),
    };
    let wire_offer1 = v1_wire(&init.send_path_upgrade(&offer1, NOW_MS).unwrap());
    let rev = resp
        .feed_bytes(&wire_offer1, NOW_UNIX, NOW_MS, &mut host_roster)
        .unwrap();
    assert!(matches!(
        rev.as_slice(),
        [SessionAction::PathUpgradeReceived(msg)] if msg == &offer1
    ));

    // Duplicate upgrade_id from initiator fails send.
    assert!(init.send_path_upgrade(&offer1, NOW_MS).is_err());

    let answer1 = PathUpgradeMsg::Answer {
        upgrade_id: 1,
        protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
        sdp: "v=0\r\na=answer1\r\n".to_string(),
    };
    let wire_answer1 = v1_wire(&resp.send_path_upgrade(&answer1, NOW_MS).unwrap());
    // Responder cannot answer twice for same upgrade_id.
    assert!(resp.send_path_upgrade(&answer1, NOW_MS).is_err());
    // Unknown upgrade_id from responder fails send.
    assert!(
        resp.send_path_upgrade(
            &PathUpgradeMsg::Reject {
                upgrade_id: 99,
                reason: "unknown".to_string()
            },
            NOW_MS
        )
        .is_err()
    );

    let iev = init
        .feed_bytes(&wire_answer1, NOW_UNIX, NOW_MS, &mut client_roster)
        .unwrap();
    assert!(matches!(
        iev.as_slice(),
        [SessionAction::PathUpgradeReceived(msg)] if msg == &answer1
    ));

    // Exhaust remaining 3 of 4 offers; 5th fails.
    for id in 2..=MAX_PATH_UPGRADE_OFFERS_PER_SESSION as u64 {
        let off = PathUpgradeMsg::Offer {
            upgrade_id: id,
            protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
            sdp: format!("v=0\r\na=offer{id}\r\n"),
        };
        let wo = v1_wire(&init.send_path_upgrade(&off, NOW_MS).unwrap());
        resp.feed_bytes(&wo, NOW_UNIX, NOW_MS, &mut host_roster)
            .unwrap();
        let rej = PathUpgradeMsg::Reject {
            upgrade_id: id,
            reason: "busy".to_string(),
        };
        let wr = v1_wire(&resp.send_path_upgrade(&rej, NOW_MS).unwrap());
        init.feed_bytes(&wr, NOW_UNIX, NOW_MS, &mut client_roster)
            .unwrap();
    }
    assert!(
        init.send_path_upgrade(
            &PathUpgradeMsg::Offer {
                upgrade_id: 5,
                protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
                sdp: "v=0".to_string(),
            },
            NOW_MS,
        )
        .is_err()
    );
}

#[test]
fn v2_path_upgrade_padded_only_and_padding_disabled_suppression() {
    // Padding enabled: full Offer -> Answer round-trip inside 0x09 PADDED.
    let (mut init, mut resp, mut client_roster, mut host_roster) = establish_v2(
        vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
        vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
        PaddingPolicy::v2_default(),
        PaddingPolicy::v2_default(),
    );
    assert_eq!(init.negotiated_upgrade_caps(), &[UPGRADE_CAP_WEBRTC_V1]);
    assert_eq!(resp.negotiated_upgrade_caps(), &[UPGRADE_CAP_WEBRTC_V1]);

    let offer = PathUpgradeMsg::Offer {
        upgrade_id: 1,
        protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
        sdp: "v=0\r\na=v2\r\n".to_string(),
    };
    let wire_offer = v2_wire(&init.send_path_upgrade(&offer, NOW_MS).unwrap());
    let rev = resp
        .feed_bytes(&wire_offer, NOW_UNIX, NOW_MS, &mut host_roster)
        .unwrap();
    assert!(matches!(
        rev.as_slice(),
        [V2SessionAction::PathUpgradeReceived(msg)] if msg == &offer
    ));

    let answer = PathUpgradeMsg::Answer {
        upgrade_id: 1,
        protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
        sdp: "v=0\r\na=v2ans\r\n".to_string(),
    };
    let wire_answer = v2_wire(&resp.send_path_upgrade(&answer, NOW_MS).unwrap());
    let iev = init
        .feed_bytes(&wire_answer, NOW_UNIX, NOW_MS, &mut client_roster)
        .unwrap();
    assert!(matches!(
        iev.as_slice(),
        [V2SessionAction::PathUpgradeReceived(msg)] if msg == &answer
    ));

    // Padding disabled suppresses upgrade caps on both sides even if configured.
    let (init_nopad, resp_nopad, _, _) = establish_v2(
        vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
        vec![UPGRADE_CAP_WEBRTC_V1.to_string()],
        PaddingPolicy::disabled(),
        PaddingPolicy::disabled(),
    );
    assert!(init_nopad.negotiated_upgrade_caps().is_empty());
    assert!(resp_nopad.negotiated_upgrade_caps().is_empty());
    assert!(init_nopad.peer_upgrade_caps().is_empty());
    assert!(resp_nopad.peer_upgrade_caps().is_empty());

    // Bare 0x0D PATH_UPGRADE rejected directly by v2 frame decoder.
    let bare_inner =
        encode_inner_frame(InnerFrameType::PathUpgrade, &offer.encode().unwrap()).unwrap();
    assert_eq!(
        tendril_core::v2::decode_v2_inner_frame(&bare_inner, true),
        Err(CoreError::UnknownInnerFrameType(
            InnerFrameType::PathUpgrade as u8
        ))
    );
}

#[test]
fn v1_unsolicited_and_replayed_path_upgrade_fails_closed() {
    // 1. Unsolicited 0x0D when nothing was negotiated -> ProtocolViolation on receiver.
    let host = host_id();
    let client = client_id();
    let mut host_roster = build_host_roster(&client, None);
    let mut resp = SessionMachine::new_responder(&host, None).unwrap();
    let mut raw_init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(client.static_key().secret_bytes())
        .prologue(&Preamble::v1(Intent::Session).encode())
        .build_initiator()
        .unwrap();
    let m1 = raw_init.write_message_vec(&[]).unwrap();
    let mut w1 = Preamble::v1(Intent::Session).encode().to_vec();
    w1.extend_from_slice(&encode_frame(&m1).unwrap());
    let m2 = v1_wire(
        &resp
            .feed_bytes(&w1, NOW_UNIX, NOW_MS, &mut host_roster)
            .unwrap(),
    );
    raw_init
        .read_message_vec(decode_frame(&m2).unwrap().0)
        .unwrap();
    let sh = serde_json::to_vec(&SessionHello {
        device_id: client.device_id(),
        grant: None,
        crl_seq: None,
        groups: None,
        route_seq: None,
        upgrade: vec![],
    })
    .unwrap();
    let m3 = encode_frame(&raw_init.write_message_vec(&sh).unwrap()).unwrap();
    resp.feed_bytes(&m3, NOW_UNIX, NOW_MS, &mut host_roster)
        .unwrap();
    let mut tx_init: NoiseTransport = raw_init.into_transport_mode().unwrap();
    let offer = PathUpgradeMsg::Offer {
        upgrade_id: 1,
        protocol: UPGRADE_CAP_WEBRTC_V1.to_string(),
        sdp: "v=0".to_string(),
    };
    let inner = encode_inner_frame(InnerFrameType::PathUpgrade, &offer.encode().unwrap()).unwrap();
    let ct = encode_frame(&tx_init.write_message_vec(&inner).unwrap()).unwrap();
    assert_eq!(
        resp.feed_bytes(&ct, NOW_UNIX, NOW_MS, &mut host_roster),
        Err(CoreError::ProtocolViolation(
            "unsolicited path upgrade frame without negotiated capabilities"
        ))
    );
    assert!(resp.is_closed());
}

#[test]
fn cross_protocol_answer_mismatch_fails_closed() {
    let caps = vec!["webrtc/v1".to_string(), "proto/v2".to_string()];
    let (mut init, mut resp, mut client_roster, mut host_roster) = establish_v1(caps.clone(), caps);

    let offer = PathUpgradeMsg::Offer {
        upgrade_id: 1,
        protocol: "webrtc/v1".to_string(),
        sdp: "v=0\r\na=offer1\r\n".to_string(),
    };
    let wire_offer = v1_wire(&init.send_path_upgrade(&offer, NOW_MS).unwrap());
    resp.feed_bytes(&wire_offer, NOW_UNIX, NOW_MS, &mut host_roster)
        .unwrap();

    // Responder refuses to seal Answer with a different protocol than the pending offer.
    let mismatched_answer = PathUpgradeMsg::Answer {
        upgrade_id: 1,
        protocol: "proto/v2".to_string(),
        sdp: "v=0\r\na=ans1\r\n".to_string(),
    };
    assert!(matches!(
        resp.send_path_upgrade(&mismatched_answer, NOW_MS),
        Err(CoreError::NotReady(_))
    ));

    // Craft an encrypted Answer frame carrying the mismatched protocol over the wire; initiator rejects.
    let mut state = tendril_core::wire::PathUpgradeState::new(true);
    state.set_negotiated(vec!["webrtc/v1".to_string(), "proto/v2".to_string()]);
    assert!(state.prepare_send(&offer).is_ok());
    state.commit_send(&offer);
    let encoded_mismatch = mismatched_answer.encode().unwrap();
    assert_eq!(
        state.receive(&encoded_mismatch),
        Err(CoreError::ProtocolViolation(
            "unknown, replayed, or protocol-mismatched upgrade_id in path upgrade answer"
        ))
    );

    // Real matching answer still succeeds on the untouched session.
    let good_answer = PathUpgradeMsg::Answer {
        upgrade_id: 1,
        protocol: "webrtc/v1".to_string(),
        sdp: "v=0\r\na=ans1\r\n".to_string(),
    };
    let wire_good = v1_wire(&resp.send_path_upgrade(&good_answer, NOW_MS).unwrap());
    let evs = init
        .feed_bytes(&wire_good, NOW_UNIX, NOW_MS, &mut client_roster)
        .unwrap();
    assert!(matches!(
        evs.as_slice(),
        [SessionAction::PathUpgradeReceived(msg)] if msg == &good_answer
    ));
}
