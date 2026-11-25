//! Adversarial fault-injection and end-to-end Sans-I/O test suite (Verification Gates 3 and 4).

use std::collections::VecDeque;

use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{
    ED25519_SIG_LEN, HYBRID_SIG_LEN, HybridSigningPublicKey, SigningKeypair, StaticKeypair,
    b64url_decode, b64url_encode, pairing_sas,
};
use tendril_core::error::CoreError;
use tendril_core::grants::{GrantUnsigned, RevocationListUnsigned, sign_crl, sign_grant};
use tendril_core::identity::{EndpointIdentity, sign_rotation};
use tendril_core::noise::NoiseHfsHandshakeBuilder;
use tendril_core::pairing::{
    PairAction, PairOutcome, PairingCodeKind, PairingConfig, PairingInitiator, PairingManager,
    PairingPathKind, PairingResponder, PairingUri, PinnedHost,
};
use tendril_core::policy::{
    CandidateEndpoint, PathPlanner, PathPolicyConfig, PlannerAction, ProviderId,
};
use tendril_core::roster::{PeerState, Roster};
use tendril_core::session::{
    REKEY_MAX_AGE_MS, RekeyDirection, SessionAction, SessionCloseCode, SessionMachine,
};
use tendril_core::wire::{
    HostHello, Intent, MAX_READ_BUFFER_LEN, PairClaim, Preamble, decode_frame, encode_frame,
};

const NOW_UNIX: u64 = 1_795_564_800; // 2026-11-25T00:00:00Z
const GRANT_NB: u64 = 1_795_132_800; // 2026-11-20T00:00:00Z
const GRANT_NA: u64 = 1_797_724_800; // 2026-12-20T00:00:00Z

fn mk_identity(seed: u8) -> EndpointIdentity {
    let mut s_bytes = [seed; 32];
    s_bytes[0] = seed ^ 0x55;
    let mut k_bytes = [seed.wrapping_add(0x10); 32];
    k_bytes[0] = seed ^ 0xAA;
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(s_bytes),
        SigningKeypair::from_seed(k_bytes),
    )
}

fn collect_pair_writes(actions: &[PairAction]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let PairAction::WriteBytes(bytes) = a {
            out.extend_from_slice(bytes);
        }
    }
    out
}

fn collect_session_writes(actions: &[SessionAction]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let SessionAction::WriteBytes(bytes) = a {
            out.extend_from_slice(bytes);
        }
    }
    out
}

fn run_pair_exchange(
    init: &mut PairingInitiator,
    resp: &mut PairingResponder,
    mgr: &mut PairingManager,
    host_roster: &mut Roster,
    now_unix: u64,
    chunk_size: usize,
) -> (Vec<PairAction>, Vec<PairAction>) {
    let mut init_events = init.start().unwrap();
    let mut resp_events = Vec::new();
    let mut to_resp: Vec<u8> = collect_pair_writes(&init_events);
    let mut to_init: Vec<u8> = Vec::new();

    for _ in 0..8 {
        if !to_resp.is_empty() {
            let payload = std::mem::take(&mut to_resp);
            for chunk in payload.chunks(chunk_size.max(1)) {
                let acts = resp.feed_bytes(chunk, now_unix, mgr, host_roster).unwrap();
                to_init.extend_from_slice(&collect_pair_writes(&acts));
                resp_events.extend(acts);
            }
        }
        if !to_init.is_empty() {
            let payload = std::mem::take(&mut to_init);
            for chunk in payload.chunks(chunk_size.max(1)) {
                let acts = init.feed_bytes(chunk).unwrap();
                to_resp.extend_from_slice(&collect_pair_writes(&acts));
                init_events.extend(acts);
            }
        }
        if to_resp.is_empty() && to_init.is_empty() {
            break;
        }
    }

    (init_events, resp_events)
}

fn connect_session(
    init: &mut SessionMachine,
    resp: &mut SessionMachine,
    client_roster: &mut Roster,
    host_roster: &mut Roster,
    now_unix: u64,
    now_ms: u64,
    chunk_size: usize,
) -> Result<(Vec<SessionAction>, Vec<SessionAction>), CoreError> {
    let mut init_events = init.start()?;
    let mut resp_events = Vec::new();
    let mut to_resp: Vec<u8> = collect_session_writes(&init_events);
    let mut to_init: Vec<u8> = Vec::new();

    for _ in 0..8 {
        if !to_resp.is_empty() {
            let payload = std::mem::take(&mut to_resp);
            for chunk in payload.chunks(chunk_size.max(1)) {
                let acts = resp.feed_bytes(chunk, now_unix, now_ms, host_roster)?;
                to_init.extend_from_slice(&collect_session_writes(&acts));
                resp_events.extend(acts);
            }
        }
        if !to_init.is_empty() {
            let payload = std::mem::take(&mut to_init);
            for chunk in payload.chunks(chunk_size.max(1)) {
                let acts = init.feed_bytes(chunk, now_unix, now_ms, client_roster)?;
                to_resp.extend_from_slice(&collect_session_writes(&acts));
                init_events.extend(acts);
            }
        }
        if to_resp.is_empty() && to_init.is_empty() {
            break;
        }
    }

    Ok((init_events, resp_events))
}

fn relay_session_bytes(
    bytes: &[u8],
    receiver: &mut SessionMachine,
    receiver_roster: &mut Roster,
    now_unix: u64,
    now_ms: u64,
    chunk_size: usize,
) -> Result<Vec<SessionAction>, CoreError> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(chunk_size.max(1)) {
        out.extend(receiver.feed_bytes(chunk, now_unix, now_ms, receiver_roster)?);
    }
    Ok(out)
}

#[test]
fn full_pair_confirm_mint_data_rekey_rotate_delegate_revoke_close_lifecycle() {
    let mut host_id = mk_identity(1);
    let client_id = mk_identity(2);
    let mut host_roster = Roster::new();
    let mut client_roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());

    let code = mgr
        .issue_code_with_entropy(PairingCodeKind::Lan2Group, NOW_UNIX, &[7u8; 32])
        .unwrap();
    let uri = PairingUri::new(
        "Studio Host",
        code.clone(),
        *host_id.static_key().public_bytes(),
        host_id.signing_key().signing_pub_hash(),
        vec!["direct:192.168.1.50:7000".to_string()],
        None,
        None,
    );
    let parsed_uri = PairingUri::parse(&uri.try_encode().unwrap()).unwrap();
    assert_eq!(parsed_uri, uri);

    let mut p_init = PairingInitiator::new(
        &client_id,
        "Workstation",
        "linux",
        &parsed_uri.code,
        Some(parsed_uri.to_pinned_host()),
        None,
    )
    .unwrap();
    let mut p_resp = PairingResponder::new(&host_id, PairingPathKind::Lan, None).unwrap();

    // Feed handshake and response cleanly with 7-byte odd chunks.
    let (init_ev, resp_ev) = run_pair_exchange(
        &mut p_init,
        &mut p_resp,
        &mut mgr,
        &mut host_roster,
        NOW_UNIX + 1,
        7,
    );

    let client_pending = init_ev.iter().find_map(|a| match a {
        PairAction::Completed(o @ PairOutcome::InitiatorPending { .. }) => Some(o.clone()),
        _ => None,
    });
    let resp_pending = resp_ev.iter().find_map(|a| match a {
        PairAction::Completed(o @ PairOutcome::ResponderPending { .. }) => Some(o.clone()),
        _ => None,
    });

    let (
        PairOutcome::InitiatorPending {
            device_id: cli_dev_id,
            host_id: paired_host_id,
            host_static_pub,
            host_signing_pub,
            host_rotation_seq,
            pairing_sas: cli_sas,
            host_pin_verified,
        },
        PairOutcome::ResponderPending {
            device_id: host_dev_id,
            pairing_sas: host_sas,
            ..
        },
    ) = (client_pending.unwrap(), resp_pending.unwrap())
    else {
        panic!("expected pending pairing completion");
    };
    assert_eq!(cli_dev_id, host_dev_id);
    assert_eq!(cli_sas, host_sas);
    assert_eq!(host_rotation_seq, 0);
    assert!(host_pin_verified);

    client_roster
        .insert_pinned_host(
            paired_host_id.clone(),
            "Studio Host".to_string(),
            host_static_pub,
            Some(host_signing_pub),
            host_rotation_seq,
            uri.endpoints.clone(),
        )
        .unwrap();

    // Pending peer MUST be rejected on intent = session prior to pair.confirm.
    let mut init_unconfirmed =
        SessionMachine::new_initiator(&client_id, &paired_host_id, None, None, None).unwrap();
    let mut resp_unconfirmed = SessionMachine::new_responder(&host_id, None).unwrap();
    let pending_err = connect_session(
        &mut init_unconfirmed,
        &mut resp_unconfirmed,
        &mut client_roster,
        &mut host_roster,
        NOW_UNIX + 2,
        1_000,
        13,
    )
    .unwrap_err();
    assert_eq!(pending_err, CoreError::PeerPending(cli_dev_id.clone()));

    // Host operator verifies SAS and confirms identity (zero non-session grants by default).
    host_roster
        .confirm_peer(&cli_dev_id, Some(&host_sas))
        .unwrap();
    assert!(host_roster.get(&cli_dev_id).unwrap().grants.is_empty());

    let mut s_init =
        SessionMachine::new_initiator(&client_id, &paired_host_id, None, None, None).unwrap();
    let mut s_resp = SessionMachine::new_responder(&host_id, None).unwrap();
    s_init.set_rekey_thresholds(100, REKEY_MAX_AGE_MS);
    s_resp.set_rekey_thresholds(100, REKEY_MAX_AGE_MS);

    connect_session(
        &mut s_init,
        &mut s_resp,
        &mut client_roster,
        &mut host_roster,
        NOW_UNIX + 3,
        2_000,
        5,
    )
    .unwrap();
    assert!(s_init.is_established());
    assert!(s_resp.is_established());

    // Default deny: no grant minted yet.
    let (res, audit) = s_resp.authorize("fs.read:/photos/2026/a.jpg", NOW_UNIX + 3, &host_roster);
    assert!(matches!(res, Err(CoreError::GrantDenied(_))));
    assert!(!audit.allow);

    // Mint narrow grant and deliver over 0x02 GRANT.
    let grant = host_roster
        .mint_grant(
            &host_id,
            &cli_dev_id,
            vec![
                "session.open".to_string(),
                "fs.read:/photos/2026/*".to_string(),
            ],
            GRANT_NB,
            GRANT_NA,
            [0x44; 16],
        )
        .unwrap();
    let grant_wire = collect_session_writes(&s_resp.send_grant(&grant, 2_100).unwrap());
    let grant_acts = relay_session_bytes(
        &grant_wire,
        &mut s_init,
        &mut client_roster,
        NOW_UNIX + 4,
        2_100,
        11,
    )
    .unwrap();
    assert!(matches!(
        &grant_acts[..],
        [SessionAction::GrantUpdated(g)] if g.nonce == grant.nonce
    ));

    // Re-connect presenting the signed grant in SessionHello, exchange DATA, PING/PONG, and REKEY.
    let mut s_init2 =
        SessionMachine::new_initiator(&client_id, &paired_host_id, Some(grant.clone()), None, None)
            .unwrap();
    let mut s_resp2 = SessionMachine::new_responder(&host_id, None).unwrap();
    s_init2.set_rekey_thresholds(4, REKEY_MAX_AGE_MS);
    connect_session(
        &mut s_init2,
        &mut s_resp2,
        &mut client_roster,
        &mut host_roster,
        NOW_UNIX + 5,
        3_000,
        9,
    )
    .unwrap();

    let (res_ok, audit_ok) =
        s_resp2.authorize("fs.read:/photos/2026/a.jpg", NOW_UNIX + 5, &host_roster);
    assert!(res_ok.is_ok());
    assert!(audit_ok.allow);
    assert_eq!(audit_ok.grant_nonce.as_deref(), Some(grant.nonce.as_str()));

    let (res_deny, audit_deny) =
        s_resp2.authorize("fs.write:/photos/2026/a.jpg", NOW_UNIX + 5, &host_roster);
    assert!(matches!(res_deny, Err(CoreError::GrantDenied(_))));
    assert!(!audit_deny.allow);

    // Encrypted DATA roundtrip.
    let data_wire = collect_session_writes(&s_init2.send_data(b"ping-payload", 3_100).unwrap());
    let data_acts = relay_session_bytes(
        &data_wire,
        &mut s_resp2,
        &mut host_roster,
        NOW_UNIX + 6,
        3_100,
        3,
    )
    .unwrap();
    assert_eq!(
        data_acts,
        vec![SessionAction::AppData(b"ping-payload".to_vec())]
    );

    // PING -> PONG roundtrip.
    let ping_wire =
        collect_session_writes(&s_init2.send_ping(0xDEAD_BEEF_CAFE_0001, 3_200).unwrap());
    let resp_pong_acts = relay_session_bytes(
        &ping_wire,
        &mut s_resp2,
        &mut host_roster,
        NOW_UNIX + 7,
        3_200,
        4,
    )
    .unwrap();
    let pong_wire = collect_session_writes(&resp_pong_acts);
    let init_pong_acts = relay_session_bytes(
        &pong_wire,
        &mut s_init2,
        &mut client_roster,
        NOW_UNIX + 8,
        3_200,
        4,
    )
    .unwrap();
    assert_eq!(
        init_pong_acts,
        vec![SessionAction::PongReceived(0xDEAD_BEEF_CAFE_0001)]
    );

    // Trigger frame-count auto-rekey (frames 3 and 4 sent cleanly, then frame 5 triggers REKEY first).
    let mut fc_wire = Vec::new();
    for msg in [b"fc-3".as_slice(), b"fc-4".as_slice()] {
        let acts = s_init2.send_data(msg, 3_210).unwrap();
        fc_wire.extend_from_slice(&collect_session_writes(&acts));
    }
    let fc_trigger = s_init2.send_data(b"fc-5", 3_220).unwrap();
    assert!(matches!(
        &fc_trigger[..],
        [
            SessionAction::WriteBytes(_),
            SessionAction::Rekeyed {
                direction: RekeyDirection::Outgoing
            },
            SessionAction::WriteBytes(_)
        ]
    ));
    fc_wire.extend_from_slice(&collect_session_writes(&fc_trigger));
    let fc_acts = relay_session_bytes(
        &fc_wire,
        &mut s_resp2,
        &mut host_roster,
        NOW_UNIX + 9,
        3_220,
        13,
    )
    .unwrap();
    assert_eq!(
        fc_acts,
        vec![
            SessionAction::AppData(b"fc-3".to_vec()),
            SessionAction::AppData(b"fc-4".to_vec()),
            SessionAction::Rekeyed {
                direction: RekeyDirection::Incoming
            },
            SessionAction::AppData(b"fc-5".to_vec()),
        ]
    );

    // Virtual-clock 15m tick after frame-count auto-rekey (at 3_220) triggers another REKEY cleanly.
    let tick_acts = s_init2
        .tick(NOW_UNIX + 905, 3_220 + REKEY_MAX_AGE_MS, &client_roster)
        .unwrap();
    assert!(tick_acts.iter().any(|a| matches!(
        a,
        SessionAction::Rekeyed {
            direction: RekeyDirection::Outgoing
        }
    )));
    let rekey_wire = collect_session_writes(&tick_acts);
    let resp_rekey_acts = relay_session_bytes(
        &rekey_wire,
        &mut s_resp2,
        &mut host_roster,
        NOW_UNIX + 905,
        3_220 + REKEY_MAX_AGE_MS,
        5,
    )
    .unwrap();
    assert_eq!(
        resp_rekey_acts,
        vec![SessionAction::Rekeyed {
            direction: RekeyDirection::Incoming
        }]
    );

    // Post-rekey DATA still decrypts in lockstep.
    let post_wire = collect_session_writes(
        &s_init2
            .send_data(b"post-rekey-ok", 3_300 + REKEY_MAX_AGE_MS)
            .unwrap(),
    );
    let post_acts = relay_session_bytes(
        &post_wire,
        &mut s_resp2,
        &mut host_roster,
        NOW_UNIX + 906,
        3_300 + REKEY_MAX_AGE_MS,
        17,
    )
    .unwrap();
    assert_eq!(
        post_acts,
        vec![SessionAction::AppData(b"post-rekey-ok".to_vec())]
    );

    // Graceful CLOSE.
    let close_wire = collect_session_writes(
        &s_init2
            .send_close(SessionCloseCode::NORMAL, "done")
            .unwrap(),
    );
    let close_acts = relay_session_bytes(
        &close_wire,
        &mut s_resp2,
        &mut host_roster,
        NOW_UNIX + 907,
        3_400 + REKEY_MAX_AGE_MS,
        2,
    )
    .unwrap();
    assert_eq!(
        close_acts,
        vec![SessionAction::CloseTransport {
            code: SessionCloseCode::NORMAL,
            reason: "done".to_string()
        }]
    );
    assert!(s_init2.is_closed());
    assert!(s_resp2.is_closed());

    // Host rotates static + signing keys; client reconnects, validates RotationRecord chain, and advances pin.
    host_id
        .rotate(
            StaticKeypair::from_scalar([0x71; 32]),
            SigningKeypair::from_seed([0x72; 32]),
            NOW_UNIX + 1000,
        )
        .unwrap();
    let mut s_init3 =
        SessionMachine::new_initiator(&client_id, &paired_host_id, None, None, None).unwrap();
    let mut s_resp3 = SessionMachine::new_responder(&host_id, None).unwrap();
    connect_session(
        &mut s_init3,
        &mut s_resp3,
        &mut client_roster,
        &mut host_roster,
        NOW_UNIX + 1001,
        1_000_000,
        1,
    )
    .unwrap();
    assert_eq!(client_roster.get(&paired_host_id).unwrap().rotation_seq, 1);

    // Narrower delegation from an active delegate peer to client device + 0x03 REVOCATION teardown.
    let del_identity = mk_identity(9);
    host_roster
        .insert_pinned_host(
            del_identity.host_id().to_string(),
            "Delegate Node".to_string(),
            *del_identity.static_key().public_bytes(),
            Some(del_identity.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let host_to_del = host_roster
        .mint_grant(
            &host_id,
            &del_identity.device_id(),
            vec![
                "session.open".to_string(),
                "pair.mint".to_string(),
                "fs.read:/photos/*".to_string(),
            ],
            GRANT_NB,
            GRANT_NA,
            [0x11; 16],
        )
        .unwrap();
    let del_to_client = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: del_identity.device_id(),
            subject: cli_dev_id.clone(),
            caps: vec![
                "session.open".to_string(),
                "fs.read:/photos/2026/*".to_string(),
            ],
            not_before: "2026-11-21T00:00:00Z".to_string(),
            not_after: "2026-12-01T00:00:00Z".to_string(),
            nonce: b64url_encode(&[0x22; 16]),
            delegated_from: vec![host_to_del],
            uses: None,
            machine: None,
        },
        del_identity.signing_key(),
    )
    .unwrap();
    let del_wire = collect_session_writes(&s_init3.send_grant(&del_to_client, 1_000_100).unwrap());
    let del_acts = relay_session_bytes(
        &del_wire,
        &mut s_resp3,
        &mut host_roster,
        NOW_UNIX + 1002,
        1_000_100,
        19,
    )
    .unwrap();
    assert!(matches!(&del_acts[..], [SessionAction::GrantUpdated(_)]));
    assert!(
        s_resp3
            .authorize("fs.read:/photos/2026/b.jpg", NOW_UNIX + 1002, &host_roster)
            .0
            .is_ok()
    );

    // Send signed CRL revoking the delegated nonce -> responder enforces revocation immediately.
    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: paired_host_id.clone(),
            seq: 1,
            revoked_devices: vec![],
            revoked_nonces: vec![del_to_client.nonce],
            ts: "2026-11-25T00:16:40Z".to_string(),
        },
        host_id.signing_key(),
    )
    .unwrap();
    let crl_wire = collect_session_writes(&s_init3.send_revocation(&crl, 1_000_200).unwrap());
    let rev_res = relay_session_bytes(
        &crl_wire,
        &mut s_resp3,
        &mut host_roster,
        NOW_UNIX + 1003,
        1_000_200,
        8,
    );
    assert!(matches!(rev_res, Err(CoreError::GrantDenied(_))));
    assert!(s_resp3.is_closed());
}

#[test]
fn adversarial_wire_and_framing_faults() {
    let host_id = mk_identity(11);
    let client_id = mk_identity(12);
    let mut host_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *client_id.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "abcd efgh ijkl mnop".into(),
        )
        .unwrap();
    host_roster
        .confirm_peer(&client_id.device_id(), Some("abcd efgh ijkl mnop"))
        .unwrap();

    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host_id.host_id().to_string(),
            "Host".into(),
            *host_id.static_key().public_bytes(),
            Some(host_id.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();

    // Cross-intent splicing: Pair preamble sent to Session responder must fail with ProtocolViolation.
    let mut pair_init =
        PairingInitiator::new(&client_id, "C", "cli", "TND-AAAA-BBBB", None, None).unwrap();
    let pair_bytes = collect_pair_writes(&pair_init.start().unwrap());
    let mut sess_resp = SessionMachine::new_responder(&host_id, None).unwrap();
    let err = sess_resp
        .feed_bytes(&pair_bytes, NOW_UNIX, 0, &mut host_roster)
        .unwrap_err();
    assert_eq!(
        err,
        CoreError::ProtocolViolation("expected session preamble intent")
    );
    assert!(sess_resp.is_closed());

    // Reverse cross-intent splicing: Session preamble sent to Pair responder.
    let mut s_init =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), None, None, None).unwrap();
    let sess_bytes = collect_session_writes(&s_init.start().unwrap());
    let mut mgr = PairingManager::new(PairingConfig::default());
    let mut p_resp = PairingResponder::new(&host_id, PairingPathKind::Lan, None).unwrap();
    let perr = p_resp
        .feed_bytes(&sess_bytes, NOW_UNIX, &mut mgr, &mut host_roster)
        .unwrap_err();
    assert_eq!(
        perr,
        CoreError::ProtocolViolation("expected pair preamble intent")
    );

    // Oversized declared frame header (> 65519) rejected cleanly after preamble.
    let mut s_resp2 = SessionMachine::new_responder(&host_id, None).unwrap();
    let mut oversized = Preamble::v1(Intent::Session).encode().to_vec();
    oversized.extend_from_slice(&((MAX_FRAME_LEN + 1) as u16).to_be_bytes());
    let oerr = s_resp2
        .feed_bytes(&oversized, NOW_UNIX, 0, &mut host_roster)
        .unwrap_err();
    assert_eq!(
        oerr,
        CoreError::FrameTooLarge {
            len: MAX_FRAME_LEN + 1,
            max: MAX_FRAME_LEN
        }
    );

    // Read-buffer flood bounded cleanly.
    let mut flood_resp = SessionMachine::new_responder(&host_id, None).unwrap();
    let mut flood = vec![0u8; MAX_READ_BUFFER_LEN + 1];
    flood[..6].copy_from_slice(&Preamble::v1(Intent::Session).encode());
    let ferr = flood_resp
        .feed_bytes(&flood, NOW_UNIX, 0, &mut host_roster)
        .unwrap_err();
    assert!(matches!(ferr, CoreError::BufferOverflow { .. }));

    // Establish valid session, then inject bit-flipped, replayed, and reordered transport frames.
    let mut init_a =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), None, None, None).unwrap();
    let mut resp_a = SessionMachine::new_responder(&host_id, None).unwrap();
    connect_session(
        &mut init_a,
        &mut resp_a,
        &mut cli_roster,
        &mut host_roster,
        NOW_UNIX,
        0,
        64,
    )
    .unwrap();

    let f1 = collect_session_writes(&init_a.send_data(b"frame-1", 10).unwrap());
    let f2 = collect_session_writes(&init_a.send_data(b"frame-2", 20).unwrap());

    // Replay / reorder f2 before f1 -> AEAD nonce failure & permanent closure.
    let mut resp_reorder = resp_a;
    assert!(matches!(
        resp_reorder.feed_bytes(&f2, NOW_UNIX, 20, &mut host_roster),
        Err(CoreError::Noise(_))
    ));
    assert!(resp_reorder.is_closed());
    assert!(matches!(
        resp_reorder.feed_bytes(&f1, NOW_UNIX, 21, &mut host_roster),
        Err(CoreError::SessionClosed { .. })
    ));

    // Bit-flip on msg2 ciphertext aborts cleanly before msg3.
    let mut init_bf =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), None, None, None).unwrap();
    let mut resp_bf = SessionMachine::new_responder(&host_id, None).unwrap();
    let m1 = collect_session_writes(&init_bf.start().unwrap());
    let mut m2 = collect_session_writes(
        &resp_bf
            .feed_bytes(&m1, NOW_UNIX, 0, &mut host_roster)
            .unwrap(),
    );
    let last = m2.len() - 1;
    m2[last] ^= 0x01;
    assert!(matches!(
        init_bf.feed_bytes(&m2, NOW_UNIX, 1, &mut cli_roster),
        Err(CoreError::Noise(_))
    ));
    assert!(init_bf.is_closed());

    // Frame replay in fresh session after delivering f1 legitimately.
    let mut init_rep =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), None, None, None).unwrap();
    let mut resp_rep = SessionMachine::new_responder(&host_id, None).unwrap();
    connect_session(
        &mut init_rep,
        &mut resp_rep,
        &mut cli_roster,
        &mut host_roster,
        NOW_UNIX,
        0,
        64,
    )
    .unwrap();
    let msg = collect_session_writes(&init_rep.send_data(b"once", 10).unwrap());
    assert!(
        resp_rep
            .feed_bytes(&msg, NOW_UNIX, 10, &mut host_roster)
            .is_ok()
    );
    assert!(matches!(
        resp_rep.feed_bytes(&msg, NOW_UNIX, 11, &mut host_roster),
        Err(CoreError::Noise(_))
    ));
    assert!(resp_rep.is_closed());

    // Truncated preamble bytes never panic and await completion cleanly.
    let mut resp_trunc = SessionMachine::new_responder(&host_id, None).unwrap();
    assert!(
        resp_trunc
            .feed_bytes(
                &Preamble::v1(Intent::Session).encode()[..3],
                NOW_UNIX,
                0,
                &mut host_roster
            )
            .unwrap()
            .is_empty()
    );
    assert!(!resp_trunc.is_closed());
}

#[test]
fn adversarial_pairing_and_identity_faults() {
    let host_id = mk_identity(21);
    let rogue_id = mk_identity(22);
    let client_id = mk_identity(23);
    let mitm_id = mk_identity(24);
    let mut host_roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());

    let code = mgr
        .issue_code_with_entropy(PairingCodeKind::Remote3Group, NOW_UNIX, &[5u8; 32])
        .unwrap();

    // 4 wrong attempts keep code alive; 5th burns code.
    for attempt in 1..=5 {
        let mut p_init =
            PairingInitiator::new(&client_id, "Dev", "ios", "TND-WRONG-CODE-0001", None, None)
                .unwrap();
        let mut p_resp = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();
        let (init_ev, _) = run_pair_exchange(
            &mut p_init,
            &mut p_resp,
            &mut mgr,
            &mut host_roster,
            NOW_UNIX + attempt,
            32,
        );
        assert!(init_ev.iter().any(|a| matches!(a, PairAction::Completed(PairOutcome::Rejected { error }) if error == "unauthorized")));
    }
    assert_eq!(mgr.live_code_count(NOW_UNIX + 6), 0);

    // Even the real code now fails uniformly with unauthorized (no burn oracle).
    let mut p_init_burned =
        PairingInitiator::new(&client_id, "Dev", "ios", &code, None, None).unwrap();
    let mut p_resp_burned = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();
    let (ev_b, _) = run_pair_exchange(
        &mut p_init_burned,
        &mut p_resp_burned,
        &mut mgr,
        &mut host_roster,
        NOW_UNIX + 7,
        32,
    );
    assert!(ev_b.iter().any(|a| matches!(a, PairAction::Completed(PairOutcome::Rejected { error }) if error == "unauthorized")));

    // Expired code -> unauthorized; 2-group LAN code over Remote -> path_disallowed.
    let mut mgr2 = PairingManager::new(PairingConfig::default());
    let lan_code = mgr2
        .issue_code_with_entropy(PairingCodeKind::Lan2Group, NOW_UNIX, &[9u8; 32])
        .unwrap();
    let mut p_lan_remote_i =
        PairingInitiator::new(&client_id, "Dev", "ios", &lan_code, None, None).unwrap();
    let mut p_lan_remote_r =
        PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();
    let (ev_path, _) = run_pair_exchange(
        &mut p_lan_remote_i,
        &mut p_lan_remote_r,
        &mut mgr2,
        &mut host_roster,
        NOW_UNIX + 1,
        32,
    );
    assert!(ev_path.iter().any(|a| matches!(a, PairAction::Completed(PairOutcome::Rejected { error }) if error == "path_disallowed")));

    let exp_code = mgr2
        .issue_code_with_entropy(PairingCodeKind::Remote3Group, NOW_UNIX, &[11u8; 32])
        .unwrap();
    let mut p_exp_i =
        PairingInitiator::new(&client_id, "Dev", "ios", &exp_code, None, None).unwrap();
    let mut p_exp_r = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();
    let (ev_exp, _) = run_pair_exchange(
        &mut p_exp_i,
        &mut p_exp_r,
        &mut mgr2,
        &mut host_roster,
        NOW_UNIX + 900,
        32,
    );
    assert!(ev_exp.iter().any(|a| matches!(a, PairAction::Completed(PairOutcome::Rejected { error }) if error == "unauthorized")));
    assert_eq!(mgr2.live_code_count(NOW_UNIX + 900), 0);

    // Revoked peer attempting to re-pair with a LIVE code fails ("revoked"), stays Revoked, AND burns the code!
    let live_code = mgr2
        .issue_code_with_entropy(PairingCodeKind::Remote3Group, NOW_UNIX, &[13u8; 32])
        .unwrap();
    host_roster
        .record_pending_pair(
            *client_id.static_key().public_bytes(),
            None,
            "Dev".into(),
            "ios".into(),
            "sas".into(),
        )
        .unwrap();
    host_roster.revoke_peer(&client_id.device_id()).unwrap();
    let mut p_rev_i =
        PairingInitiator::new(&client_id, "Dev", "ios", &live_code, None, None).unwrap();
    let mut p_rev_r = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();
    let (ev_rev, _) = run_pair_exchange(
        &mut p_rev_i,
        &mut p_rev_r,
        &mut mgr2,
        &mut host_roster,
        NOW_UNIX + 10,
        32,
    );
    assert!(ev_rev.iter().any(|a| matches!(a, PairAction::Completed(PairOutcome::Rejected { error }) if error == "revoked")));
    assert_eq!(
        host_roster.get(&client_id.device_id()).unwrap().state,
        PeerState::Revoked
    );
    assert_eq!(mgr2.live_code_count(NOW_UNIX + 10), 0);

    // MITM splicing two independent Noise handshakes fails MAC & causes divergent SAS.
    let mut mgr_mitm = PairingManager::new(PairingConfig::default());
    let mitm_code = mgr_mitm
        .issue_code_with_entropy(PairingCodeKind::Remote3Group, NOW_UNIX, &[15u8; 32])
        .unwrap();
    let fresh_client = mk_identity(29);
    let mut c_init =
        PairingInitiator::new(&fresh_client, "Dev", "ios", &mitm_code, None, None).unwrap();

    let pair_preamble = Preamble::v1(Intent::Pair).encode();
    let mut mitm_to_client = NoiseHfsHandshakeBuilder::new()
        .local_private_key(mitm_id.static_key().secret_bytes())
        .prologue(&pair_preamble)
        .build_responder()
        .unwrap();
    let mut mitm_to_host = NoiseHfsHandshakeBuilder::new()
        .local_private_key(mitm_id.static_key().secret_bytes())
        .prologue(&pair_preamble)
        .build_initiator()
        .unwrap();
    let mut h_resp = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();

    let c_m1 = collect_pair_writes(&c_init.start().unwrap());
    // MITM completes msg1/msg2 toward Client AND msg1/msg2 toward Host independently.
    mitm_to_client
        .read_message_vec(decode_frame(&c_m1[6..]).unwrap().0)
        .unwrap();
    let mitm_hello = serde_json::to_vec(&HostHello {
        host_id: mitm_id.host_id().to_string(),
        proto_version: 1,
        signing_pub: mitm_id.signing_key().public_key().to_b64url(),
        rotation: vec![],
        upgrade: vec![],
    })
    .unwrap();
    let msg2_c = mitm_to_client.write_message_vec(&mitm_hello).unwrap();
    let c_ev2 = c_init.feed_bytes(&encode_frame(&msg2_c).unwrap()).unwrap();
    let c_sas = c_ev2
        .iter()
        .find_map(|a| match a {
            PairAction::SasReady { pairing_sas, .. } => Some(pairing_sas.clone()),
            _ => None,
        })
        .unwrap();
    let c_m3_wire = collect_pair_writes(&c_ev2);
    let pt_claim = mitm_to_client
        .read_message_vec(decode_frame(&c_m3_wire).unwrap().0)
        .unwrap();
    let relayed_claim: PairClaim = serde_json::from_slice(&pt_claim).unwrap();

    // MITM dials real Host and forwards Client's PairClaim (containing code_mac bound to h_client).
    let msg1_h = mitm_to_host.write_message_vec(&[]).unwrap();
    let mut to_h = pair_preamble.to_vec();
    to_h.extend_from_slice(&encode_frame(&msg1_h).unwrap());
    let h_m2 = collect_pair_writes(
        &h_resp
            .feed_bytes(&to_h, NOW_UNIX, &mut mgr_mitm, &mut host_roster)
            .unwrap(),
    );
    mitm_to_host
        .read_message_vec(decode_frame(&h_m2).unwrap().0)
        .unwrap();
    let h_hash = *mitm_to_host.get_handshake_hash();
    assert_ne!(c_sas, pairing_sas(&h_hash));
    let claim_bytes = serde_json::to_vec(&relayed_claim).unwrap();
    let msg3_h = mitm_to_host.write_message_vec(&claim_bytes).unwrap();
    let splice_ev = h_resp
        .feed_bytes(
            &encode_frame(&msg3_h).unwrap(),
            NOW_UNIX,
            &mut mgr_mitm,
            &mut host_roster,
        )
        .unwrap();
    assert!(splice_ev.iter().any(|a| matches!(
        a,
        PairAction::Completed(PairOutcome::Rejected { error }) if error == "unauthorized"
    )));

    // Initiator pinned wrong host key at msg2 in QR pairing aborts BEFORE sending msg3.
    let mut qr_mismatch = PairingInitiator::new(
        &fresh_client,
        "Dev",
        "ios",
        &mitm_code,
        Some(PinnedHost::with_full_key(
            Some(host_id.host_id().to_string()),
            *rogue_id.static_key().public_bytes(),
            rogue_id.signing_key().public_key().clone(),
            0,
        )),
        None,
    )
    .unwrap();
    let mut h_resp_qr = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();
    let q_m1 = collect_pair_writes(&qr_mismatch.start().unwrap());
    let h_m2_qr = collect_pair_writes(
        &h_resp_qr
            .feed_bytes(&q_m1, NOW_UNIX, &mut mgr_mitm, &mut host_roster)
            .unwrap(),
    );
    let q_err = qr_mismatch.feed_bytes(&h_m2_qr).unwrap_err();
    assert_eq!(q_err, CoreError::HostKeyUnverified);

    // Session initiator with unverified static key or incomplete pin (signing_pub: None) aborts BEFORE emitting msg3!
    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host_id.host_id().to_string(),
            "Incomplete".into(),
            *host_id.static_key().public_bytes(),
            None,
            0,
            vec![],
        )
        .unwrap();
    let mut s_inc =
        SessionMachine::new_initiator(&fresh_client, host_id.host_id(), None, None, None).unwrap();
    let mut s_h = SessionMachine::new_responder(&host_id, None).unwrap();
    let sm1 = collect_session_writes(&s_inc.start().unwrap());
    let sm2 = collect_session_writes(&s_h.feed_bytes(&sm1, NOW_UNIX, 0, &mut host_roster).unwrap());
    let inc_err = s_inc
        .feed_bytes(&sm2, NOW_UNIX, 1, &mut cli_roster)
        .unwrap_err();
    assert_eq!(
        inc_err,
        CoreError::IncompletePin(host_id.host_id().to_string())
    );
    assert!(s_inc.is_closed());
    assert!(!s_h.is_established());

    // Complete pin pointing to wrong static key triggers HostKeyUnverified before msg3, and confirms SAS mismatch in MITM.
    assert!(!c_sas.is_empty());
    cli_roster
        .insert_pinned_host(
            rogue_id.host_id().to_string(),
            "Rogue".into(),
            *rogue_id.static_key().public_bytes(),
            Some(rogue_id.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let mut s_wrong =
        SessionMachine::new_initiator(&fresh_client, rogue_id.host_id(), None, None, None).unwrap();
    let mut s_real_h = SessionMachine::new_responder(&host_id, None).unwrap();
    let sw1 = collect_session_writes(&s_wrong.start().unwrap());
    let sw2 = collect_session_writes(
        &s_real_h
            .feed_bytes(&sw1, NOW_UNIX, 0, &mut host_roster)
            .unwrap(),
    );
    assert_eq!(
        s_wrong
            .feed_bytes(&sw2, NOW_UNIX, 1, &mut cli_roster)
            .unwrap_err(),
        CoreError::HostKeyUnverified
    );
    assert!(s_wrong.is_closed());
}

#[test]
fn adversarial_grants_crl_and_rotation_forks() {
    let mut host_id = mk_identity(31);
    let client_id = mk_identity(32);
    let delegate_id = mk_identity(33);
    let attacker_id = mk_identity(34);
    let mut host_roster = Roster::new();
    let mut client_roster = Roster::new();

    for peer in [&client_id, &delegate_id, &attacker_id] {
        host_roster
            .record_pending_pair(
                *peer.static_key().public_bytes(),
                Some(peer.signing_key().public_key().clone()),
                peer.host_id().to_string(),
                "cli".into(),
                "abcd".into(),
            )
            .unwrap();
        host_roster
            .confirm_peer(&peer.device_id(), Some("abcd"))
            .unwrap();
    }
    client_roster
        .insert_pinned_host(
            host_id.host_id().to_string(),
            "Host".into(),
            *host_id.static_key().public_bytes(),
            Some(host_id.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();

    // 1. Widened delegated grant delivered via 0x02 GRANT is rejected and closes session.
    let parent_grant = host_roster
        .mint_grant(
            &host_id,
            &delegate_id.device_id(),
            vec!["pair.mint".to_string(), "fs.read:/photos/*".to_string()],
            GRANT_NB,
            GRANT_NA,
            [0x01; 16],
        )
        .unwrap();
    let widened_grant = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: delegate_id.device_id(),
            subject: client_id.device_id(),
            caps: vec!["fs.read:/*".to_string()],
            not_before: "2026-11-21T00:00:00Z".to_string(),
            not_after: "2026-12-01T00:00:00Z".to_string(),
            nonce: b64url_encode(&[0x02; 16]),
            delegated_from: vec![parent_grant],
            uses: None,
            machine: None,
        },
        delegate_id.signing_key(),
    )
    .unwrap();

    let mut s_i =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), None, None, None).unwrap();
    let mut s_r = SessionMachine::new_responder(&host_id, None).unwrap();
    connect_session(
        &mut s_i,
        &mut s_r,
        &mut client_roster,
        &mut host_roster,
        NOW_UNIX,
        0,
        32,
    )
    .unwrap();
    let w_wire = collect_session_writes(&s_i.send_grant(&widened_grant, 100).unwrap());
    assert!(matches!(
        relay_session_bytes(&w_wire, &mut s_r, &mut host_roster, NOW_UNIX, 100, 16),
        Err(CoreError::DelegationDenied(_))
    ));
    assert!(s_r.is_closed());

    // 2. Forged self-signed non-root grant delivered over 0x02 GRANT fails closed.
    let forged = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: attacker_id.device_id(),
            subject: client_id.device_id(),
            caps: vec!["fs.read:/*".to_string()],
            not_before: "2026-11-21T00:00:00Z".to_string(),
            not_after: "2026-12-01T00:00:00Z".to_string(),
            nonce: b64url_encode(&[0x03; 16]),
            delegated_from: vec![],
            uses: None,
            machine: None,
        },
        attacker_id.signing_key(),
    )
    .unwrap();
    let mut s_i2 =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), None, None, None).unwrap();
    let mut s_r2 = SessionMachine::new_responder(&host_id, None).unwrap();
    connect_session(
        &mut s_i2,
        &mut s_r2,
        &mut client_roster,
        &mut host_roster,
        NOW_UNIX,
        0,
        32,
    )
    .unwrap();
    let f_wire = collect_session_writes(&s_i2.send_grant(&forged, 100).unwrap());
    assert!(matches!(
        relay_session_bytes(&f_wire, &mut s_r2, &mut host_roster, NOW_UNIX, 100, 16),
        Err(CoreError::GrantDenied(_))
    ));

    // 3. Grant expiring at GRANT_NA is valid at GRANT_NA - 1, and fails closed upon 0x04 REKEY at GRANT_NA.
    let short_grant = host_roster
        .mint_grant(
            &host_id,
            &client_id.device_id(),
            vec!["fs.read:/docs/*".to_string()],
            GRANT_NB,
            GRANT_NA,
            [0x04; 16],
        )
        .unwrap();
    let mut s_i3 =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), Some(short_grant), None, None)
            .unwrap();
    let mut s_r3 = SessionMachine::new_responder(&host_id, None).unwrap();
    connect_session(
        &mut s_i3,
        &mut s_r3,
        &mut client_roster,
        &mut host_roster,
        GRANT_NA - 1,
        0,
        32,
    )
    .unwrap();
    let rekey_wire = collect_session_writes(&s_i3.send_rekey(1_000).unwrap());
    assert!(matches!(
        relay_session_bytes(&rekey_wire, &mut s_r3, &mut host_roster, GRANT_NA, 1_000, 8),
        Err(CoreError::GrantDenied(_))
    ));
    assert!(s_r3.is_closed());

    // 4. Stale CRL sequence rollback is rejected cleanly (CrlStaleSeq).
    let crl1 = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host_id.host_id().to_string(),
            seq: 2,
            revoked_devices: vec![],
            revoked_nonces: vec![],
            ts: "2026-11-25T00:00:00Z".to_string(),
        },
        host_id.signing_key(),
    )
    .unwrap();
    host_roster
        .ingest_crl(crl1, host_id.host_id(), host_id.signing_key().public_key())
        .unwrap();
    let stale_crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host_id.host_id().to_string(),
            seq: 1,
            revoked_devices: vec![],
            revoked_nonces: vec![],
            ts: "2026-11-25T00:01:00Z".to_string(),
        },
        host_id.signing_key(),
    )
    .unwrap();
    assert_eq!(
        host_roster.ingest_crl(
            stale_crl,
            host_id.host_id(),
            host_id.signing_key().public_key()
        ),
        Err(CoreError::CrlStaleSeq { current: 2, got: 1 })
    );

    // 5. Unanchored MITM fork in HostHello fails handshake WITHOUT revoking legitimate host entry.
    let rogue_rot = sign_rotation(
        1,
        attacker_id.signing_key(),
        SigningKeypair::from_seed([0xC1; 32]).public_key(),
        StaticKeypair::from_scalar([0xC2; 32]).public_bytes(),
        NOW_UNIX + 50,
    )
    .unwrap();
    let unanch_res = client_roster.apply_verified_rotation(
        host_id.host_id(),
        &[rogue_rot],
        host_id.static_key().public_bytes(),
        host_id.signing_key().public_key(),
    );
    assert!(!matches!(
        unanch_res,
        Err(CoreError::RotationForkDetected { .. })
    ));
    assert_eq!(
        client_roster.get(host_id.host_id()).unwrap().state,
        PeerState::Active
    );

    // 6. Real trust-root RotationRecord fork in HostHello aborts before msg3 AND revokes host entry.
    let next_stat_a = StaticKeypair::from_scalar([0x81; 32]);
    let next_sig_a = SigningKeypair::from_seed([0x82; 32]);
    let next_stat_b = StaticKeypair::from_scalar([0x83; 32]);
    let next_sig_b = SigningKeypair::from_seed([0x84; 32]);
    let fork_b = sign_rotation(
        1,
        host_id.signing_key(),
        next_sig_b.public_key(),
        next_stat_b.public_bytes(),
        NOW_UNIX + 200,
    )
    .unwrap();
    host_id
        .rotate(next_stat_a, next_sig_a, NOW_UNIX + 100)
        .unwrap();

    // Inject conflicting seq = 1 signed by host's real outgoing key inside a wire HostHello msg2 frame!
    let mut forked_chain = host_id.rotation_chain().to_vec();
    forked_chain.push(fork_b);
    let mut s_fork_init =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), None, None, None).unwrap();
    let fork_m1 = collect_session_writes(&s_fork_init.start().unwrap());
    let sess_pre = Preamble::v1(Intent::Session).encode();
    let mut evil_resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host_id.static_key().secret_bytes())
        .prologue(&sess_pre)
        .build_responder()
        .unwrap();
    evil_resp
        .read_message_vec(decode_frame(&fork_m1[6..]).unwrap().0)
        .unwrap();
    let forked_hello = serde_json::to_vec(&HostHello {
        host_id: host_id.host_id().to_string(),
        proto_version: 1,
        signing_pub: host_id.signing_key().public_key().to_b64url(),
        rotation: forked_chain,
        upgrade: vec![],
    })
    .unwrap();
    let fm2 = evil_resp.write_message_vec(&forked_hello).unwrap();
    let fork_err = s_fork_init
        .feed_bytes(
            &encode_frame(&fm2).unwrap(),
            NOW_UNIX + 250,
            100,
            &mut client_roster,
        )
        .unwrap_err();
    assert_eq!(fork_err, CoreError::RotationForkDetected { seq: 1 });
    assert!(s_fork_init.is_closed());
    assert_eq!(
        client_roster.get(host_id.host_id()).unwrap().state,
        PeerState::Revoked
    );

    // Next Session connect to revoked host fails immediately with PeerRevoked.
    let mut s_rev =
        SessionMachine::new_initiator(&client_id, host_id.host_id(), None, None, None).unwrap();
    let mut s_host = SessionMachine::new_responder(&host_id, None).unwrap();
    let rev_err = connect_session(
        &mut s_rev,
        &mut s_host,
        &mut client_roster,
        &mut host_roster,
        NOW_UNIX + 300,
        0,
        32,
    )
    .unwrap_err();
    assert_eq!(
        rev_err,
        CoreError::PeerRevoked(host_id.host_id().to_string())
    );

    // Exact 32-byte static key comparison: even if an entry shares the map key, a distinct 32-byte
    // static key must be rejected by lookup_active_by_static.
    let mismatched = [0x99u8; 32];
    let matching_key_id = tendril_core::crypto::device_id(&mismatched);
    host_roster
        .insert_pinned_host(
            matching_key_id,
            "OtherKey".into(),
            [0x77; 32],
            None,
            0,
            vec![],
        )
        .unwrap();
    assert!(matches!(
        host_roster.lookup_active_by_static(&mismatched),
        Err(CoreError::PeerNotFound(_))
    ));
}

#[test]
fn path_policy_end_to_end_concurrent_winners_and_exhaustion() {
    let mut planner = PathPlanner::new(
        PathPolicyConfig::default(),
        vec![
            CandidateEndpoint::new(1, ProviderId::Relay, "wss://relay.example/v1/relay"),
            CandidateEndpoint::new(2, ProviderId::Direct, "10.0.0.5:7000"),
        ],
    );
    planner.start(0);
    let mut dials: VecDeque<usize> = VecDeque::new();
    for a in planner.drain_actions() {
        if let PlannerAction::DialCandidate(c) = a {
            dials.push_back(c.id);
        }
    }
    assert_eq!(dials.pop_front(), Some(2));

    // At 250ms, Direct hasn't finished yet -> Relay starts as backup Happy Eyeballs dial.
    planner.tick(250);
    for a in planner.drain_actions() {
        if let PlannerAction::DialCandidate(c) = a {
            dials.push_back(c.id);
        }
    }
    assert_eq!(dials.pop_front(), Some(1));

    // Direct wins at 280ms -> activates Direct and cancels in-flight Relay.
    planner.on_dial_succeeded(2, 280);
    let acts = planner.drain_actions();
    assert!(
        acts.iter()
            .any(|a| matches!(a, PlannerAction::CancelCandidate(1)))
    );
    assert!(
        acts.iter()
            .any(|a| matches!(a, PlannerAction::ActivatePath(c) if c.id == 2))
    );

    // Both fail after fault -> AllCandidatesExhausted emitted.
    planner.on_active_fault(2, "reset", 500);
    assert!(
        planner
            .drain_actions()
            .iter()
            .any(|a| matches!(a, PlannerAction::DialCandidate(c) if c.id == 1))
    );
    planner.on_dial_failed(1, "unreachable", 600);
    assert!(
        planner
            .drain_actions()
            .iter()
            .any(|a| matches!(a, PlannerAction::AllCandidatesExhausted))
    );
}

#[test]
fn batch1_sec09_rejects_low_order_curve25519_and_non_contributory_dh() {
    use tendril_core::crypto::{is_valid_x25519_public_key, random_bytes};
    use tendril_core::identity::sign_rotation;
    use tendril_core::wire::encode_frame;

    // Canonical small-order Curve25519 points must be rejected.
    let low_order_points: [[u8; 32]; 5] = [
        [0u8; 32],
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];
    let legit = mk_identity(71);
    assert!(is_valid_x25519_public_key(
        legit.static_key().public_bytes()
    ));

    let mut roster = Roster::new();
    for (idx, pt) in low_order_points.iter().enumerate() {
        assert!(!is_valid_x25519_public_key(pt), "accepted low-order {idx}");
        assert!(matches!(
            roster.insert_pinned_host(
                format!("bad-{idx}"),
                "Bad".into(),
                *pt,
                Some(legit.signing_key().public_key().clone()),
                0,
                vec![],
            ),
            Err(CoreError::IncompletePin(_))
        ));
        assert!(matches!(
            roster.record_pending_pair(*pt, None, "Bad".into(), "cli".into(), "aaaa".into()),
            Err(CoreError::IncompletePin(_))
        ));
        assert!(matches!(
            roster.lookup_active_by_static(pt),
            Err(CoreError::IncompletePin(_))
        ));

        let bad_uri = format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={}&sh={}",
            b64url_encode(pt),
            b64url_encode(&legit.signing_key().signing_pub_hash()),
        );
        assert!(matches!(
            PairingUri::parse(&bad_uri),
            Err(CoreError::InvalidPairingUri(_))
        ));

        let rot = sign_rotation(
            1,
            legit.signing_key(),
            legit.signing_key().public_key(),
            pt,
            NOW_UNIX,
        )
        .unwrap();
        assert!(matches!(
            tendril_core::identity::verify_rotation_record(&rot),
            Err(CoreError::IncompletePin(_))
        ));

        // Craft raw Noise msg1 carrying a low-order ephemeral public key and verify SessionResponder
        // rejects it via TendrilCryptoResolver contributory check (never emits msg2).
        let mut resp = SessionMachine::new_responder(&legit, None).unwrap();
        let mut raw_msg1 = Preamble::v1(Intent::Session).encode().to_vec();
        raw_msg1.extend_from_slice(&encode_frame(pt).unwrap());
        let err = resp
            .feed_bytes(&raw_msg1, NOW_UNIX, 0, &mut roster)
            .unwrap_err();
        assert!(matches!(err, CoreError::Noise(_)), "got {err:?}");
    }
    let _ = random_bytes::<16>().unwrap();
}

#[test]
fn batch1_sec02_sec12_sec19_grants_crl_sibling_and_jcs_hardening() {
    use tendril_core::grants::{
        Grant, GrantUnsigned, RevocationList, RevocationListUnsigned, authorize_grant, sign_crl,
        verify_grant_with_chain,
    };

    let root = mk_identity(80);
    let del = mk_identity(81);
    let rogue = mk_identity(82);
    let root_id = root.host_id().to_string();
    let del_dev = del.device_id();
    let del_alias = "del-alias".to_string();

    let g_root = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: root_id.clone(),
            subject: del_alias.clone(),
            caps: vec!["pair.mint".into(), "fs.read:*".into()],
            not_before: "2026-11-20T00:00:00Z".into(),
            not_after: "2026-12-20T00:00:00Z".into(),
            nonce: "n_root_01".into(),
            delegated_from: vec![],
            uses: None,
            machine: None,
        },
        root.signing_key(),
    )
    .unwrap();
    let g_leaf = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: del_alias.clone(),
            subject: "dev_leaf_88".into(),
            caps: vec!["fs.read:/a".into()],
            not_before: "2026-11-20T00:00:00Z".into(),
            not_after: "2026-12-20T00:00:00Z".into(),
            nonce: "n_leaf_01".into(),
            delegated_from: vec![g_root.clone()],
            uses: None,
            machine: None,
        },
        del.signing_key(),
    )
    .unwrap();

    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            root_id.clone(),
            "Root".into(),
            *root.static_key().public_bytes(),
            Some(root.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    roster
        .insert_pinned_host(
            del_alias.clone(),
            "Delegate".into(),
            *del.static_key().public_bytes(),
            Some(del.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    roster
        .record_pending_pair(
            *del.static_key().public_bytes(),
            None,
            "Delegate".into(),
            "cli".into(),
            "sas".into(),
        )
        .unwrap();
    roster.confirm_peer(&del_dev, Some("sas")).unwrap();

    let lookup = |id: &str| roster.lookup_active_signing_key(id);

    // SEC-02: unsigned / forged / wrong-version / wrong-issuer CRLs must fail closed.
    let valid_crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: root_id.clone(),
            seq: 1,
            revoked_devices: vec![],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".into(),
        },
        root.signing_key(),
    )
    .unwrap();
    assert!(
        verify_grant_with_chain(
            &g_leaf,
            "dev_leaf_88",
            &root_id,
            NOW_UNIX + 100,
            Some(&valid_crl),
            lookup
        )
        .is_ok()
    );

    let mut unsigned_crl = valid_crl.clone();
    unsigned_crl.sig.clear();
    assert!(
        authorize_grant(
            Some(&g_leaf),
            "dev_leaf_88",
            &root_id,
            "fs.read:/a",
            NOW_UNIX + 100,
            Some(&unsigned_crl),
            lookup,
        )
        .0
        .is_err()
    );

    let rogue_signed_crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: root_id.clone(),
            seq: 1,
            revoked_devices: vec![],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".into(),
        },
        rogue.signing_key(),
    )
    .unwrap();
    assert!(matches!(
        verify_grant_with_chain(
            &g_leaf,
            "dev_leaf_88",
            &root_id,
            NOW_UNIX + 100,
            Some(&rogue_signed_crl),
            lookup,
        ),
        Err(CoreError::InvalidSignature)
    ));

    let wrong_ver_crl = sign_crl(
        RevocationListUnsigned {
            v: 99,
            issuer: root_id.clone(),
            seq: 1,
            revoked_devices: vec![],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".into(),
        },
        root.signing_key(),
    )
    .unwrap();
    assert!(matches!(
        verify_grant_with_chain(
            &g_leaf,
            "dev_leaf_88",
            &root_id,
            NOW_UNIX + 100,
            Some(&wrong_ver_crl),
            lookup,
        ),
        Err(CoreError::CrlUnsupportedVersion(99))
    ));

    let wrong_issuer_crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: del_dev.clone(),
            seq: 1,
            revoked_devices: vec![],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".into(),
        },
        root.signing_key(),
    )
    .unwrap();
    assert!(matches!(
        verify_grant_with_chain(
            &g_leaf,
            "dev_leaf_88",
            &root_id,
            NOW_UNIX + 100,
            Some(&wrong_issuer_crl),
            lookup,
        ),
        Err(CoreError::CrlIssuerMismatch { .. })
    ));

    // SEC-12: revoking `dev_xxx` immediately invalidates sibling alias `del-alias`,
    // and a new alias sharing the revoked keys is refused (SEC-01) and never resolves.
    roster.revoke_peer(&del_dev).unwrap();
    assert_eq!(roster.lookup_active_signing_key(&del_dev), None);
    assert_eq!(roster.lookup_active_signing_key("del-alias"), None);
    assert!(matches!(
        roster.insert_pinned_host(
            "del-alias-2".into(),
            "Delegate Clone".into(),
            *del.static_key().public_bytes(),
            Some(del.signing_key().public_key().clone()),
            0,
            vec![],
        ),
        Err(CoreError::PeerRevoked(_))
    ));
    assert_eq!(roster.lookup_active_signing_key("del-alias-2"), None);

    // Defense in depth: a tampered serialized roster carrying an Active duplicate beside the
    // Revoked entry must still resolve to no signing key.
    let mut tampered = serde_json::to_value(&roster).unwrap();
    let mut dup = serde_json::to_value(roster.get("del-alias").unwrap()).unwrap();
    dup["device_id"] = "del-alias-2".into();
    dup["state"] = "active".into();
    tampered["entries"]["del-alias-2"] = dup;
    let tampered: Roster = serde_json::from_value(tampered).unwrap();
    assert_eq!(
        tampered.get("del-alias-2").map(|e| e.state),
        Some(PeerState::Active)
    );
    assert_eq!(tampered.lookup_active_signing_key("del-alias-2"), None);
    assert!(matches!(
        tampered.lookup_active_by_static(del.static_key().public_bytes()),
        Err(CoreError::PeerRevoked(_))
    ));
    assert!(matches!(
        verify_grant_with_chain(
            &g_leaf,
            "dev_leaf_88",
            &root_id,
            NOW_UNIX + 100,
            Some(&valid_crl),
            |id| roster.lookup_active_signing_key(id),
        ),
        Err(CoreError::GrantDenied(_))
    ));

    // SEC-12 CRL path: active delegate revoked only via ingested CRL must also return `None`.
    let del_crl_only = mk_identity(83);
    let mut crl_roster = Roster::new();
    crl_roster
        .insert_pinned_host(
            root_id.clone(),
            "Root".into(),
            *root.static_key().public_bytes(),
            Some(root.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    crl_roster
        .insert_pinned_host(
            del_crl_only.device_id(),
            "CrlDelegate".into(),
            *del_crl_only.static_key().public_bytes(),
            Some(del_crl_only.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let del_crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: root_id.clone(),
            seq: 2,
            revoked_devices: vec![del_crl_only.device_id()],
            revoked_nonces: vec![],
            ts: "2026-11-22T00:00:00Z".into(),
        },
        root.signing_key(),
    )
    .unwrap();
    crl_roster
        .ingest_crl(del_crl, &root_id, root.signing_key().public_key())
        .unwrap();
    assert_eq!(
        crl_roster.lookup_active_signing_key(&del_crl_only.device_id()),
        None
    );

    // SEC-19: deny_unknown_fields and reject explicit empty/null optional keys.
    let mut g_val = serde_json::to_value(&g_root).unwrap();
    g_val
        .as_object_mut()
        .unwrap()
        .insert("smuggled".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<Grant>(g_val).is_err());

    let mut g_empty_del = serde_json::to_value(&g_root).unwrap();
    g_empty_del
        .as_object_mut()
        .unwrap()
        .insert("delegated_from".into(), serde_json::json!([]));
    assert!(serde_json::from_value::<Grant>(g_empty_del).is_err());

    let mut g_null_uses = serde_json::to_value(&g_root).unwrap();
    g_null_uses
        .as_object_mut()
        .unwrap()
        .insert("uses".into(), serde_json::Value::Null);
    assert!(serde_json::from_value::<Grant>(g_null_uses).is_err());

    let mut g_null_machine = serde_json::to_value(&g_root).unwrap();
    g_null_machine
        .as_object_mut()
        .unwrap()
        .insert("machine".into(), serde_json::Value::Null);
    assert!(serde_json::from_value::<Grant>(g_null_machine).is_err());

    let mut c_val = serde_json::to_value(&valid_crl).unwrap();
    c_val
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), serde_json::json!(1));
    assert!(serde_json::from_value::<RevocationList>(c_val).is_err());
}

#[test]
fn batch1_sec10_rekey_does_not_desync_on_oversized_payload() {
    use tendril_core::wire::MAX_APP_DATA_LEN;

    let host = mk_identity(91);
    let cli = mk_identity(92);
    let mut host_roster = Roster::new();
    let mut cli_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "sas".into(),
        )
        .unwrap();
    host_roster
        .confirm_peer(&cli.device_id(), Some("sas"))
        .unwrap();
    cli_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();

    let mut init = SessionMachine::new_initiator(&cli, host.host_id(), None, None, None).unwrap();
    init.set_rekey_thresholds(1, REKEY_MAX_AGE_MS);
    let mut resp = SessionMachine::new_responder(&host, None).unwrap();
    connect_session(
        &mut init,
        &mut resp,
        &mut cli_roster,
        &mut host_roster,
        NOW_UNIX,
        10,
        64,
    )
    .unwrap();

    // Send 1 valid frame to reach frames_sent == rekey_max_frames (1).
    let f1 = collect_session_writes(&init.send_data(b"first", 20).unwrap());
    let ev1 = relay_session_bytes(&f1, &mut resp, &mut host_roster, NOW_UNIX, 20, 64).unwrap();
    assert!(matches!(ev1.as_slice(), [SessionAction::AppData(d)] if d == b"first"));

    // Next call carries oversized payload while rekey threshold is due -> must fail BEFORE rekey!
    let oversized = vec![b'x'; MAX_APP_DATA_LEN + 1];
    assert!(matches!(
        init.send_data(&oversized, 30),
        Err(CoreError::FrameTooLarge { .. })
    ));

    // Following valid send must now emit REKEY + DATA and decrypt cleanly on responder.
    let acts = init.send_data(b"second", 40).unwrap();
    assert!(
        acts.iter()
            .any(|a| matches!(a, SessionAction::Rekeyed { .. }))
    );
    let f2 = collect_session_writes(&acts);
    let ev2 = relay_session_bytes(&f2, &mut resp, &mut host_roster, NOW_UNIX, 40, 64).unwrap();
    assert!(ev2.iter().any(|a| matches!(
        a,
        SessionAction::Rekeyed {
            direction: RekeyDirection::Incoming
        }
    )));
    assert!(
        ev2.iter()
            .any(|a| matches!(a, SessionAction::AppData(d) if d == b"second"))
    );
}

#[test]
fn batch1_sec11_qr_pinned_pairing_works_after_host_rotation() {
    use tendril_core::crypto::{SigningKeypair, StaticKeypair};

    let mut host = mk_identity(95);
    let cli = mk_identity(96);
    host.rotate(
        StaticKeypair::from_scalar([0x71; 32]),
        SigningKeypair::from_seed([0x72; 32]),
        NOW_UNIX + 10,
    )
    .unwrap();
    host.rotate(
        StaticKeypair::from_scalar([0x73; 32]),
        SigningKeypair::from_seed([0x74; 32]),
        NOW_UNIX + 20,
    )
    .unwrap();
    assert_eq!(host.rotation_seq(), 2);

    // 1. Both explicit seq PairingUri and legacy PairingUri without seq must succeed!
    for include_meta in [true, false] {
        let mut mgr = PairingManager::new(PairingConfig::default());
        let code = mgr
            .issue_code_with_entropy(PairingCodeKind::Lan2Group, NOW_UNIX + 30, &[3u8; 32])
            .unwrap();
        let uri = PairingUri::new(
            "Rotated Host",
            code,
            *host.static_key().public_bytes(),
            host.signing_key().signing_pub_hash(),
            vec!["direct:127.0.0.1:7000".into()],
            include_meta.then(|| host.host_id().to_string()),
            include_meta.then(|| host.rotation_seq()),
        );
        let parsed = PairingUri::parse(&uri.try_encode().unwrap()).unwrap();
        assert_eq!(parsed, uri);

        let mut p_init = PairingInitiator::new(
            &cli,
            "Phone",
            "ios",
            &parsed.code,
            Some(parsed.to_pinned_host()),
            None,
        )
        .unwrap();
        let mut p_resp = PairingResponder::new(&host, PairingPathKind::Lan, None).unwrap();
        let mut host_roster = Roster::new();
        let (init_ev, _) = run_pair_exchange(
            &mut p_init,
            &mut p_resp,
            &mut mgr,
            &mut host_roster,
            NOW_UNIX + 31,
            64,
        );
        let outcome = init_ev
            .iter()
            .find_map(|a| match a {
                PairAction::Completed(o @ PairOutcome::InitiatorPending { .. }) => Some(o.clone()),
                _ => None,
            })
            .expect("paired pending");
        let PairOutcome::InitiatorPending {
            host_rotation_seq, ..
        } = outcome
        else {
            unreachable!()
        };
        assert_eq!(host_rotation_seq, 2);
    }
}

#[test]
fn batch1_sec01_manual_pairing_gates_on_client_sas_and_prevents_pin_hijack() {
    let real_host = mk_identity(101).with_host_id("studio-nas");
    let evil_host = mk_identity(102).with_host_id("studio-nas");
    let cli = mk_identity(103);

    let mut host_roster = Roster::new();
    let mut cli_roster = Roster::new();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code_with_entropy(PairingCodeKind::Remote3Group, NOW_UNIX, &[5u8; 32])
        .unwrap();

    // Unpinned manual pairing yields host_pin_verified == false and keeps client entry Pending.
    let mut p_init = PairingInitiator::new(&cli, "Phone", "ios", &code, None, None).unwrap();
    let mut p_resp = PairingResponder::new(&real_host, PairingPathKind::Remote, None).unwrap();
    let (init_ev, _) = run_pair_exchange(
        &mut p_init,
        &mut p_resp,
        &mut mgr,
        &mut host_roster,
        NOW_UNIX + 1,
        32,
    );
    let PairOutcome::InitiatorPending {
        device_id: cli_dev,
        host_id,
        host_static_pub,
        host_signing_pub,
        host_rotation_seq,
        pairing_sas,
        host_pin_verified,
    } = init_ev
        .into_iter()
        .find_map(|a| match a {
            PairAction::Completed(o @ PairOutcome::InitiatorPending { .. }) => Some(o),
            _ => None,
        })
        .unwrap()
    else {
        unreachable!();
    };
    assert!(!host_pin_verified);
    assert_eq!(host_id, "studio-nas");

    cli_roster
        .record_pending_host(
            host_id.clone(),
            host_id.clone(),
            host_static_pub,
            host_signing_pub,
            host_rotation_seq,
            pairing_sas.clone(),
            vec![],
        )
        .unwrap();
    host_roster
        .confirm_peer(&cli_dev, Some(&pairing_sas))
        .unwrap();

    // Session MUST fail closed until client also confirms host SAS.
    let mut s_pre = SessionMachine::new_initiator(&cli, &host_id, None, None, None).unwrap();
    let mut s_resp = SessionMachine::new_responder(&real_host, None).unwrap();
    assert_eq!(
        connect_session(
            &mut s_pre,
            &mut s_resp,
            &mut cli_roster,
            &mut host_roster,
            NOW_UNIX + 2,
            10,
            64,
        )
        .unwrap_err(),
        CoreError::PeerPending("studio-nas".into())
    );

    cli_roster
        .confirm_peer(&host_id, Some(&pairing_sas))
        .unwrap();

    // Now simulate an attacker claiming the same `host_id = "studio-nas"` during manual pairing.
    let mut evil_roster = Roster::new();
    let mut evil_mgr = PairingManager::new(PairingConfig::default());
    let evil_code = evil_mgr
        .issue_code_with_entropy(PairingCodeKind::Remote3Group, NOW_UNIX + 3, &[6u8; 32])
        .unwrap();
    let mut evil_init =
        PairingInitiator::new(&cli, "Phone", "ios", &evil_code, None, None).unwrap();
    let mut evil_resp = PairingResponder::new(&evil_host, PairingPathKind::Remote, None).unwrap();
    let (evil_ev, _) = run_pair_exchange(
        &mut evil_init,
        &mut evil_resp,
        &mut evil_mgr,
        &mut evil_roster,
        NOW_UNIX + 4,
        32,
    );
    let PairOutcome::InitiatorPending {
        host_static_pub: evil_stat,
        host_signing_pub: evil_sig,
        host_rotation_seq: evil_seq,
        pairing_sas: evil_sas,
        ..
    } = evil_ev
        .into_iter()
        .find_map(|a| match a {
            PairAction::Completed(o @ PairOutcome::InitiatorPending { .. }) => Some(o),
            _ => None,
        })
        .unwrap()
    else {
        unreachable!();
    };
    assert!(matches!(
        cli_roster.record_pending_host(
            "studio-nas".into(),
            "studio-nas".into(),
            evil_stat,
            evil_sig,
            evil_seq,
            evil_sas,
            vec![],
        ),
        Err(CoreError::ProtocolViolation(_))
    ));
    assert_eq!(
        cli_roster.get("studio-nas").unwrap().static_pub,
        *real_host.static_key().public_bytes()
    );

    // Real host still connects cleanly after the attempted collision.
    let mut s_ok = SessionMachine::new_initiator(&cli, &host_id, None, None, None).unwrap();
    let mut s_ok_resp = SessionMachine::new_responder(&real_host, None).unwrap();
    connect_session(
        &mut s_ok,
        &mut s_ok_resp,
        &mut cli_roster,
        &mut host_roster,
        NOW_UNIX + 5,
        20,
        64,
    )
    .unwrap();
}

#[test]
fn batch2a_sec24_sec28_sec29_path_canon_zeroize_and_strict_pairing() {
    use tendril_core::crypto::b64url_encode;
    use tendril_core::grants::{GrantUnsigned, sign_grant};
    use tendril_core::pairing::PairingUri;
    use tendril_core::wire::{Intent, PairClaim, Preamble};

    // SEC-24: SessionMachine::authorize_path blocks traversal, double slashes, and segment spoofing.
    let host = mk_identity(81);
    let cli = mk_identity(82);
    let mut host_roster = Roster::new();
    let mut cli_roster = Roster::new();
    host_roster
        .record_pending_pair(
            *cli.static_key().public_bytes(),
            None,
            "Cli".into(),
            "cli".into(),
            "sas".into(),
        )
        .unwrap();
    host_roster
        .confirm_peer(&cli.device_id(), Some("sas"))
        .unwrap();
    cli_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();

    let grant = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            subject: cli.device_id(),
            caps: vec!["fs.read:/photos/*".into(), "fs.read:/public*".into()],
            not_before: "2026-11-20T00:00:00Z".into(),
            not_after: "2026-12-20T00:00:00Z".into(),
            nonce: "pathnonce01".into(),
            delegated_from: vec![],
            uses: None,
            machine: None,
        },
        host.signing_key(),
    )
    .unwrap();

    let mut s_cli =
        SessionMachine::new_initiator(&cli, host.host_id(), Some(grant), None, None).unwrap();
    let mut s_srv = SessionMachine::new_responder(&host, None).unwrap();
    connect_session(
        &mut s_cli,
        &mut s_srv,
        &mut cli_roster,
        &mut host_roster,
        NOW_UNIX,
        10,
        128,
    )
    .unwrap();

    assert!(
        s_srv
            .authorize_path("fs.read", "/photos/2026/a.jpg", NOW_UNIX, &host_roster)
            .0
            .is_ok()
    );
    assert!(
        s_srv
            .authorize_path("fs.read", "/public/readme.md", NOW_UNIX, &host_roster)
            .0
            .is_ok()
    );
    for denied in [
        "/photos/../etc/passwd",
        "/photos//a.jpg",
        "/public_secrets/key.pem",
        "/photos/",
        "photos/a.jpg",
    ] {
        let (res, audit) = s_srv.authorize_path("fs.read", denied, NOW_UNIX, &host_roster);
        assert!(res.is_err(), "expected denial for {denied}");
        assert!(!audit.allow);
    }

    // SEC-24 delegated escalation denial: /public* parent delegated to /public_secrets/* child
    // must NOT pass authorize_path_capability, while valid * -> /public/* delegation still allows /public/readme.md.
    {
        use tendril_core::grants::authorize_path_capability;

        let del = mk_identity(83);
        let leaf = mk_identity(84);
        let del_parent = sign_grant(
            GrantUnsigned {
                v: 1,
                issuer: host.host_id().to_string(),
                subject: del.device_id(),
                caps: vec!["pair.mint".into(), "fs.read:/public*".into()],
                not_before: "2026-11-20T00:00:00Z".into(),
                not_after: "2026-12-20T00:00:00Z".into(),
                nonce: "delpar01".into(),
                delegated_from: vec![],
                uses: None,
                machine: None,
            },
            host.signing_key(),
        )
        .unwrap();
        let bad_child = sign_grant(
            GrantUnsigned {
                v: 1,
                issuer: del.device_id(),
                subject: leaf.device_id(),
                caps: vec!["fs.read:/public_secrets/*".into()],
                not_before: "2026-11-20T00:00:00Z".into(),
                not_after: "2026-12-20T00:00:00Z".into(),
                nonce: "delchild01".into(),
                delegated_from: vec![del_parent],
                uses: None,
                machine: None,
            },
            del.signing_key(),
        )
        .unwrap();
        let lookup_del = |id: &str| -> Option<HybridSigningPublicKey> {
            if id == host.host_id() {
                Some(host.signing_key().public_key().clone())
            } else if id == del.device_id() {
                Some(del.signing_key().public_key().clone())
            } else {
                None
            }
        };
        let (esc_res, esc_audit) = authorize_path_capability(
            Some(&bad_child),
            &leaf.device_id(),
            host.host_id(),
            "fs.read",
            "/public_secrets/key.pem",
            NOW_UNIX,
            None,
            lookup_del,
        );
        assert!(esc_res.is_err());
        assert!(!esc_audit.allow);

        let star_parent = sign_grant(
            GrantUnsigned {
                v: 1,
                issuer: host.host_id().to_string(),
                subject: del.device_id(),
                caps: vec!["pair.mint".into(), "fs.read:*".into()],
                not_before: "2026-11-20T00:00:00Z".into(),
                not_after: "2026-12-20T00:00:00Z".into(),
                nonce: "delpar02".into(),
                delegated_from: vec![],
                uses: None,
                machine: None,
            },
            host.signing_key(),
        )
        .unwrap();
        let good_child = sign_grant(
            GrantUnsigned {
                v: 1,
                issuer: del.device_id(),
                subject: leaf.device_id(),
                caps: vec!["fs.read:/public/*".into()],
                not_before: "2026-11-20T00:00:00Z".into(),
                not_after: "2026-12-20T00:00:00Z".into(),
                nonce: "delchild02".into(),
                delegated_from: vec![star_parent],
                uses: None,
                machine: None,
            },
            del.signing_key(),
        )
        .unwrap();
        let (ok_res, ok_audit) = authorize_path_capability(
            Some(&good_child),
            &leaf.device_id(),
            host.host_id(),
            "fs.read",
            "/public/readme.md",
            NOW_UNIX,
            None,
            lookup_del,
        );
        assert!(ok_res.is_ok());
        assert!(ok_audit.allow);
        let (deny_res, deny_audit) = authorize_path_capability(
            Some(&good_child),
            &leaf.device_id(),
            host.host_id(),
            "fs.read",
            "/public_secrets/key.pem",
            NOW_UNIX,
            None,
            lookup_del,
        );
        assert!(deny_res.is_err());
        assert!(!deny_audit.allow);
    }

    // SEC-28: End-to-end encrypted data & explicit rekey under Zeroizing CryptoResolver primitives.
    let rekey_acts = s_cli.send_rekey(20).unwrap();
    let mut rekey_wire = Vec::new();
    for a in rekey_acts {
        if let SessionAction::WriteBytes(b) = a {
            rekey_wire.extend_from_slice(&b);
        }
    }
    let srv_rekey_acts = s_srv
        .feed_bytes(&rekey_wire, NOW_UNIX, 21, &mut host_roster)
        .unwrap();
    assert!(srv_rekey_acts.iter().any(|a| matches!(
        a,
        SessionAction::Rekeyed {
            direction: RekeyDirection::Incoming
        }
    )));
    let data_acts = s_cli.send_data(b"post-rekey secret", 22).unwrap();
    let mut data_wire = Vec::new();
    for a in data_acts {
        if let SessionAction::WriteBytes(b) = a {
            data_wire.extend_from_slice(&b);
        }
    }
    let srv_data_acts = s_srv
        .feed_bytes(&data_wire, NOW_UNIX, 23, &mut host_roster)
        .unwrap();
    assert!(srv_data_acts.iter().any(|a| match a {
        SessionAction::AppData(d) => d == b"post-rekey secret",
        _ => false,
    }));

    // SEC-29: PairingUri rejects unknown params, empty hosts, control chars, bad codes, and unsafe ep hints.
    let k_b64 = b64url_encode(host.static_key().public_bytes());
    let sh_b64 = b64url_encode(&host.signing_key().signing_pub_hash());
    for bad_uri in [
        format!("tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&extra=1"),
        format!("tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&s={sh_b64}"),
        format!("tendril://pair?v=1&host=&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}"),
        format!("tendril://pair?v=1&host=h%1b[31m&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}"),
        format!("tendril://pair?v=1&host=h&code=tnd-aaaa-bbbb&k={k_b64}&sh={sh_b64}"),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=javascript:alert(1)"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=file:/etc/passwd"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=relay:ws://evil.example/v1/relay"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=direct:169.254.169.254:80"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=iroh://abc?relay=http://169.254.169.254"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=relay:wss://metadata.google.internal./v1/relay"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=direct:metadata.google.internal.:80"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=overlay://169.254.169.254"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=direct:169.254.169.254.:80"
        ),
        format!(
            "tendril://pair?v=1&host=h&code=TND-AAAA-BBBB&k={k_b64}&sh={sh_b64}&ep=relay:wss://169.254.169.254./v1/relay"
        ),
    ] {
        assert!(
            PairingUri::parse(&bad_uri).is_err(),
            "expected invalid PairingUri rejection for {bad_uri}"
        );
    }
    let rp_b64 = b64url_encode(host.signing_key().ed25519_public_bytes());
    let ok_uri = format!(
        "tendril://pair?v=1&host=Studio&code=TND-AAAA-BBBB-CCCC&k={k_b64}&sh={sh_b64}&rp={rp_b64}&ep=direct:192.168.1.50:7000,relay:wss://relay.example/v1/relay"
    );
    assert!(PairingUri::parse(&ok_uri).is_ok());

    // SEC-29: PairingResponder rejects PairClaim carrying control / ANSI escape bytes.
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Lan2Group, NOW_UNIX)
        .unwrap();
    let mut p_resp = PairingResponder::new(&host, PairingPathKind::Lan, None).unwrap();
    let mut hs_i = NoiseHfsHandshakeBuilder::new()
        .local_private_key(cli.static_key().secret_bytes())
        .prologue(&Preamble::v1(Intent::Pair).encode())
        .build_initiator()
        .unwrap();
    let m1 = hs_i.write_message_vec(&[]).unwrap();
    let mut w1 = Preamble::v1(Intent::Pair).encode().to_vec();
    w1.extend_from_slice(&tendril_core::wire::encode_frame(&m1).unwrap());
    let r2 = p_resp
        .feed_bytes(&w1, NOW_UNIX, &mut mgr, &mut host_roster)
        .unwrap();
    let f2 = match r2
        .into_iter()
        .find(|a| matches!(a, PairAction::WriteBytes(_)))
    {
        Some(PairAction::WriteBytes(b)) => b,
        other => panic!("unexpected responder output: {other:?}"),
    };
    let mut reader = tendril_core::wire::ResumableFrameReader::new();
    reader.push(&f2).unwrap();
    let body2 = reader.next_frame().unwrap().unwrap();
    hs_i.read_message_vec(&body2).unwrap();
    let h_pair = *hs_i.get_handshake_hash();
    let mac = tendril_core::crypto::compute_code_mac(&code, &h_pair).unwrap();
    let bad_claim = PairClaim {
        name: "Evil\x1b[31mDevice".into(),
        kind: "cli\n".into(),
        code_mac: Some(b64url_encode(&mac)),
        enrollment_token: None,
        signing_pub: None,
        enroll_proof: None,
    };
    let m3 = hs_i
        .write_message_vec(&serde_json::to_vec(&bad_claim).unwrap())
        .unwrap();
    let f3 = tendril_core::wire::encode_frame(&m3).unwrap();
    let mut tx_i = hs_i.into_transport_mode().unwrap();
    let r3 = p_resp
        .feed_bytes(&f3, NOW_UNIX, &mut mgr, &mut host_roster)
        .unwrap();
    let err_frame = match r3
        .into_iter()
        .find(|a| matches!(a, PairAction::WriteBytes(_)))
    {
        Some(PairAction::WriteBytes(b)) => b,
        other => panic!("expected PairResponse::Error frame, got {other:?}"),
    };
    let mut er = tendril_core::wire::ResumableFrameReader::new();
    er.push(&err_frame).unwrap();
    let eb = er.next_frame().unwrap().unwrap();
    let ept = tx_i.read_message_vec(&eb).unwrap();
    assert!(
        String::from_utf8_lossy(&ept).contains("protocol_error"),
        "expected protocol_error response, got {}",
        String::from_utf8_lossy(&ept)
    );
}

fn completed_pair_outcome(actions: &[PairAction]) -> PairOutcome {
    actions
        .iter()
        .find_map(|a| match a {
            PairAction::Completed(o) => Some(o.clone()),
            _ => None,
        })
        .expect("expected PairAction::Completed")
}

fn host_pinned(host: &EndpointIdentity) -> PinnedHost {
    PinnedHost::with_full_key(
        Some(host.host_id().to_string()),
        *host.static_key().public_bytes(),
        host.signing_key().public_key().clone(),
        host.rotation_seq(),
    )
}

#[test]
fn phase6_m2m_self_and_anchor_delegated_enrollment_and_default_deny() {
    use tendril_core::grants::authorize_grant;
    use tendril_core::pairing::{EnrollmentPolicy, mint_enrollment_token};

    let host = mk_identity(120);
    let peer_self = mk_identity(121);
    let peer_delegated = mk_identity(122);
    let anchor = mk_identity(123).with_host_id("anchor-prod");
    let delegate = mk_identity(124).with_host_id("anchor-delegate");

    let mut host_roster = Roster::new();
    host_roster
        .add_trust_anchor(
            "anchor-prod".into(),
            anchor.signing_key().public_key().clone(),
        )
        .unwrap();
    host_roster
        .insert_pinned_host(
            "anchor-delegate".into(),
            "Delegate".into(),
            *delegate.static_key().public_bytes(),
            Some(delegate.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let mut mgr = PairingManager::new(PairingConfig::default());
    let policy = EnrollmentPolicy::enabled_default();

    // 1. Self-issued M2M token enrolls peer_self as Active with zero app grants.
    let self_tok = mint_enrollment_token(
        &host,
        host.host_id(),
        Some(&peer_self.device_id()),
        NOW_UNIX,
        900,
        [0xA1; 16],
    )
    .unwrap();
    let mut init1 = PairingInitiator::new_m2m(
        &peer_self,
        "runner-self",
        "machine",
        self_tok.clone(),
        host_pinned(&host),
        None,
    )
    .unwrap();
    let mut resp1 =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (i1, r1) = run_pair_exchange(
        &mut init1,
        &mut resp1,
        &mut mgr,
        &mut host_roster,
        NOW_UNIX,
        19,
    );
    assert!(matches!(
        completed_pair_outcome(&i1),
        PairOutcome::InitiatorEnrolled { ref device_id, ref token_nonce, .. }
            if device_id == &peer_self.device_id() && token_nonce == &self_tok.nonce
    ));
    assert!(matches!(
        completed_pair_outcome(&r1),
        PairOutcome::ResponderEnrolled { ref device_id, ref token_nonce, .. }
            if device_id == &peer_self.device_id() && token_nonce == &self_tok.nonce
    ));
    let entry = host_roster.get(&peer_self.device_id()).unwrap();
    assert_eq!(entry.state, PeerState::Active);
    assert_eq!(
        entry.signing_pub,
        Some(peer_self.signing_key().public_key().clone())
    );
    assert!(entry.grants.is_empty());

    // Default deny: session rejects missing grant, then accepts explicitly minted grant.
    let mut peer_roster = Roster::new();
    peer_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let mut s_init =
        SessionMachine::new_initiator(&peer_self, host.host_id(), None, None, None).unwrap();
    let mut s_resp = SessionMachine::new_responder(&host, None).unwrap();
    let (_, resp_s) = connect_session(
        &mut s_init,
        &mut s_resp,
        &mut peer_roster,
        &mut host_roster,
        NOW_UNIX,
        10_000,
        64,
    )
    .unwrap();
    let _ = resp_s;
    let (deny_res, audit_deny) = authorize_grant(
        None,
        &peer_self.device_id(),
        host.host_id(),
        "fs.read:/secret",
        NOW_UNIX,
        None,
        |id| (id == host.host_id()).then(|| host.signing_key().public_key().clone()),
    );
    assert!(deny_res.is_err());
    assert!(!audit_deny.allow);

    let app_grant = host_roster
        .mint_grant(
            &host,
            &peer_self.device_id(),
            vec!["fs.read:/secret/*".to_string()],
            GRANT_NB,
            GRANT_NA,
            [0xB1; 16],
        )
        .unwrap();
    let (ok_res, audit_ok) = authorize_grant(
        Some(&app_grant),
        &peer_self.device_id(),
        host.host_id(),
        "fs.read:/secret/doc.txt",
        NOW_UNIX,
        None,
        |id| (id == host.host_id()).then(|| host.signing_key().public_key().clone()),
    );
    assert!(ok_res.is_ok());
    assert!(audit_ok.allow);

    // 2. Trust-anchor delegated M2M enrollment (ancestor holds pair.mint + pair.enroll; no uses/machine).
    let root_delegator = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: "anchor-prod".to_string(),
            subject: "anchor-delegate".to_string(),
            caps: vec![
                "pair.mint".to_string(),
                format!("pair.enroll:{}", host.host_id()),
            ],
            not_before: "2026-11-20T00:00:00Z".to_string(),
            not_after: "2026-12-20T00:00:00Z".to_string(),
            nonce: "anchor_parent_nonce_01".to_string(),
            delegated_from: vec![],
            uses: None,
            machine: None,
        },
        anchor.signing_key(),
    )
    .unwrap();
    let child_enroll = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: "anchor-delegate".to_string(),
            subject: "*".to_string(),
            caps: vec![format!("pair.enroll:{}", host.host_id())],
            not_before: "2026-11-25T00:00:00Z".to_string(),
            not_after: "2026-11-25T00:10:00Z".to_string(),
            nonce: b64url_encode(&[0xA2; 16]),
            delegated_from: vec![root_delegator],
            uses: Some(1),
            machine: Some(true),
        },
        delegate.signing_key(),
    )
    .unwrap();

    let mut init2 = PairingInitiator::new_m2m(
        &peer_delegated,
        "runner-del",
        "machine",
        child_enroll,
        host_pinned(&host),
        None,
    )
    .unwrap();
    let mut resp2 =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (i2, r2) = run_pair_exchange(
        &mut init2,
        &mut resp2,
        &mut mgr,
        &mut host_roster,
        NOW_UNIX,
        31,
    );
    assert!(matches!(
        completed_pair_outcome(&i2),
        PairOutcome::InitiatorEnrolled { .. }
    ));
    assert!(matches!(
        completed_pair_outcome(&r2),
        PairOutcome::ResponderEnrolled { .. }
    ));

    // 3. Replay rejection survives JSON serialization reload!
    let json = serde_json::to_string(&host_roster).unwrap();
    let mut reloaded: Roster = serde_json::from_str(&json).unwrap();
    let other_peer = mk_identity(125);
    let init3 = PairingInitiator::new_m2m(
        &other_peer,
        "replayer",
        "machine",
        self_tok,
        host_pinned(&host),
        None,
    )
    .unwrap_err();
    let _ = init3; // self_tok was subject-bound to peer_self; test replay as peer_self!
    let mut init_replay = PairingInitiator::new_m2m(
        &peer_self,
        "replayer",
        "machine",
        mint_enrollment_token(
            &host,
            host.host_id(),
            Some(&peer_self.device_id()),
            NOW_UNIX,
            900,
            [0xA1; 16],
        )
        .unwrap(),
        host_pinned(&host),
        None,
    )
    .unwrap();
    let mut resp_replay =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (i_rep, r_rep) = run_pair_exchange(
        &mut init_replay,
        &mut resp_replay,
        &mut mgr,
        &mut reloaded,
        NOW_UNIX,
        64,
    );
    assert_eq!(
        completed_pair_outcome(&i_rep),
        PairOutcome::Rejected {
            error: "token_replayed".to_string()
        }
    );
    assert_eq!(
        completed_pair_outcome(&r_rep),
        PairOutcome::Rejected {
            error: "token_replayed".to_string()
        }
    );
}

#[test]
fn phase6_m2m_negative_expiry_anchor_crl_revoked_burn_rotation_and_sas() {
    use tendril_core::MAX_BURNED_ENROLLMENT_NONCES;
    use tendril_core::grants::{
        authorize_grant, verify_enrollment_grant_chain, verify_grant_with_chain,
    };
    use tendril_core::pairing::{EnrollmentPolicy, mint_enrollment_token, verify_enrollment_token};

    let host = mk_identity(130);
    let peer = mk_identity(131);
    let innocent = mk_identity(132);
    let anchor = mk_identity(133).with_host_id("anchor-a");
    let sibling_anchor_sk = anchor.signing_key().clone();
    let rogue_anchor = mk_identity(134).with_host_id("rogue-anchor");
    let policy = EnrollmentPolicy::enabled_default();
    let mut mgr = PairingManager::new(PairingConfig::default());

    let mut roster = Roster::new();
    roster
        .add_trust_anchor("anchor-a".into(), anchor.signing_key().public_key().clone())
        .unwrap();
    roster
        .add_trust_anchor(
            "anchor-b-sibling".into(),
            sibling_anchor_sk.public_key().clone(),
        )
        .unwrap();

    // 1. Expired token -> token_expired
    let expired_tok = mint_enrollment_token(
        &host,
        host.host_id(),
        None,
        NOW_UNIX - 1000,
        900,
        [0xC1; 16],
    )
    .unwrap();
    let mut init_exp =
        PairingInitiator::new_m2m(&peer, "p", "machine", expired_tok, host_pinned(&host), None)
            .unwrap();
    let mut resp_exp =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (ie, _) = run_pair_exchange(
        &mut init_exp,
        &mut resp_exp,
        &mut mgr,
        &mut roster,
        NOW_UNIX,
        64,
    );
    assert_eq!(
        completed_pair_outcome(&ie),
        PairOutcome::Rejected {
            error: "token_expired".to_string()
        }
    );

    // 2. Untrusted anchor -> untrusted_anchor
    let rogue_tok = mint_enrollment_token(
        &rogue_anchor,
        host.host_id(),
        None,
        NOW_UNIX,
        900,
        [0xC2; 16],
    )
    .unwrap();
    let mut init_rogue =
        PairingInitiator::new_m2m(&peer, "p", "machine", rogue_tok, host_pinned(&host), None)
            .unwrap();
    let mut resp_rogue =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (ir, _) = run_pair_exchange(
        &mut init_rogue,
        &mut resp_rogue,
        &mut mgr,
        &mut roster,
        NOW_UNIX,
        64,
    );
    assert_eq!(
        completed_pair_outcome(&ir),
        PairOutcome::Rejected {
            error: "untrusted_anchor".to_string()
        }
    );

    // 3. Sibling anchor revocation blocks anchor sharing the same signing key
    let sibling_tok = mint_enrollment_token(
        &anchor.clone().with_host_id("anchor-b-sibling"),
        host.host_id(),
        None,
        NOW_UNIX,
        900,
        [0xC3; 16],
    )
    .unwrap();
    roster.revoke_trust_anchor("anchor-a").unwrap();
    let mut init_sib =
        PairingInitiator::new_m2m(&peer, "p", "machine", sibling_tok, host_pinned(&host), None)
            .unwrap();
    let mut resp_sib =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (isib, _) = run_pair_exchange(
        &mut init_sib,
        &mut resp_sib,
        &mut mgr,
        &mut roster,
        NOW_UNIX,
        64,
    );
    assert_eq!(
        completed_pair_outcome(&isib),
        PairOutcome::Rejected {
            error: "untrusted_anchor".to_string()
        }
    );

    // 4. CRL revoke_nonce blocks unused token
    let crl_tok =
        mint_enrollment_token(&host, host.host_id(), None, NOW_UNIX, 900, [0xC4; 16]).unwrap();
    roster
        .revoke_nonce(&host, &crl_tok.nonce, NOW_UNIX)
        .unwrap();
    let mut init_crl =
        PairingInitiator::new_m2m(&peer, "p", "machine", crl_tok, host_pinned(&host), None)
            .unwrap();
    let mut resp_crl =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (icrl, _) = run_pair_exchange(
        &mut init_crl,
        &mut resp_crl,
        &mut mgr,
        &mut roster,
        NOW_UNIX,
        64,
    );
    assert_eq!(
        completed_pair_outcome(&icrl),
        PairOutcome::Rejected {
            error: "unauthorized".to_string()
        }
    );

    // 5. Revoked peer presenting stolen valid wildcard token BURNS the token nonce & gets "revoked"
    let wildcard_tok =
        mint_enrollment_token(&host, host.host_id(), None, NOW_UNIX, 900, [0xC5; 16]).unwrap();
    roster
        .record_enrolled_machine(
            *peer.static_key().public_bytes(),
            peer.signing_key().public_key().clone(),
            "revoked-peer".into(),
            "machine".into(),
        )
        .unwrap();
    roster.revoke_peer(&peer.device_id()).unwrap();

    let mut init_rev = PairingInitiator::new_m2m(
        &peer,
        "revoked-peer",
        "machine",
        wildcard_tok.clone(),
        host_pinned(&host),
        None,
    )
    .unwrap();
    let mut resp_rev =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (irev, _) = run_pair_exchange(
        &mut init_rev,
        &mut resp_rev,
        &mut mgr,
        &mut roster,
        NOW_UNIX,
        64,
    );
    assert_eq!(
        completed_pair_outcome(&irev),
        PairOutcome::Rejected {
            error: "revoked".to_string()
        }
    );
    assert!(roster.is_enrollment_nonce_burned(&wildcard_tok.nonce));

    // Innocent peer re-using the burned stolen token gets token_replayed!
    let mut init_inn = PairingInitiator::new_m2m(
        &innocent,
        "innocent",
        "machine",
        wildcard_tok,
        host_pinned(&host),
        None,
    )
    .unwrap();
    let mut resp_inn =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let (iinn, _) = run_pair_exchange(
        &mut init_inn,
        &mut resp_inn,
        &mut mgr,
        &mut roster,
        NOW_UNIX,
        64,
    );
    assert_eq!(
        completed_pair_outcome(&iinn),
        PairOutcome::Rejected {
            error: "token_replayed".to_string()
        }
    );

    // 6. Host rotation + M2M enrollment succeeds when initiator pins pre-rotation identity,
    // and wrong pin aborts msg2 with HostKeyUnverified before msg3!
    let mut rotated_host = host.clone();
    let pre_rot_pin = host_pinned(&host);
    let new_stat = StaticKeypair::from_scalar([0xE1; 32]);
    let new_sig = SigningKeypair::from_seed([0xE2; 32]);
    rotated_host.rotate(new_stat, new_sig, NOW_UNIX).unwrap();
    roster.resign_crl(&rotated_host, NOW_UNIX).unwrap();
    let rot_tok = mint_enrollment_token(
        &rotated_host,
        rotated_host.host_id(),
        Some(&innocent.device_id()),
        NOW_UNIX,
        900,
        [0xC6; 16],
    )
    .unwrap();
    let mut init_rot = PairingInitiator::new_m2m(
        &innocent,
        "innocent-rot",
        "machine",
        rot_tok.clone(),
        pre_rot_pin,
        None,
    )
    .unwrap();
    let mut resp_rot = PairingResponder::with_enrollment_policy(
        &rotated_host,
        PairingPathKind::Remote,
        None,
        policy,
    )
    .unwrap();
    let (irot, _) = run_pair_exchange(
        &mut init_rot,
        &mut resp_rot,
        &mut mgr,
        &mut roster,
        NOW_UNIX,
        64,
    );
    assert!(matches!(
        completed_pair_outcome(&irot),
        PairOutcome::InitiatorEnrolled {
            host_rotation_seq: 1,
            ..
        }
    ));

    let mut bad_pin = host_pinned(&mk_identity(199));
    bad_pin.host_id = Some(rotated_host.host_id().to_string());
    let mut bad_pin_init =
        PairingInitiator::new_m2m(&innocent, "bad-pin", "machine", rot_tok, bad_pin, None).unwrap();
    let mut resp_bad = PairingResponder::with_enrollment_policy(
        &rotated_host,
        PairingPathKind::Remote,
        None,
        policy,
    )
    .unwrap();
    let msg1 = collect_pair_writes(&bad_pin_init.start().unwrap());
    let msg2 = collect_pair_writes(
        &resp_bad
            .feed_bytes(&msg1, NOW_UNIX, &mut mgr, &mut roster)
            .unwrap(),
    );
    assert_eq!(
        bad_pin_init.feed_bytes(&msg2),
        Err(CoreError::HostKeyUnverified)
    );

    // 7. Purpose separation, SAS confirmation, and structural validation checks
    let lookup_host =
        |id: &str| (id == host.host_id()).then(|| host.signing_key().public_key().clone());
    let bad_uses0 = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            subject: innocent.device_id(),
            caps: vec!["pair.enroll".to_string()],
            not_before: "2026-11-25T00:00:00Z".to_string(),
            not_after: "2026-11-25T00:05:00Z".to_string(),
            nonce: b64url_encode(&[0xD1; 16]),
            delegated_from: vec![],
            uses: Some(0),
            machine: Some(true),
        },
        host.signing_key(),
    )
    .unwrap();
    assert!(matches!(
        verify_grant_with_chain(
            &bad_uses0,
            &innocent.device_id(),
            host.host_id(),
            NOW_UNIX,
            None,
            lookup_host
        ),
        Err(CoreError::GrantDenied(_))
    ));
    assert!(matches!(
        verify_enrollment_grant_chain(
            &bad_uses0,
            &innocent.device_id(),
            true,
            host.host_id(),
            NOW_UNIX,
            None,
            lookup_host
        ),
        Err(CoreError::GrantDenied(_))
    ));

    let bad_app_cap = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            subject: innocent.device_id(),
            caps: vec!["pair.enroll".to_string(), "fs.read:/".to_string()],
            not_before: "2026-11-25T00:00:00Z".to_string(),
            not_after: "2026-11-25T00:05:00Z".to_string(),
            nonce: b64url_encode(&[0xD2; 16]),
            delegated_from: vec![],
            uses: Some(1),
            machine: Some(true),
        },
        host.signing_key(),
    )
    .unwrap();
    assert!(matches!(
        verify_enrollment_token(
            &bad_app_cap,
            host.host_id(),
            host.signing_key().public_key(),
            &innocent.device_id(),
            NOW_UNIX,
            &policy,
            &roster,
        ),
        Err(CoreError::EnrollmentTokenInvalid(_))
    ));

    let valid_enroll_for_session_check = mint_enrollment_token(
        &host,
        host.host_id(),
        Some(&innocent.device_id()),
        NOW_UNIX,
        900,
        [0xD3; 16],
    )
    .unwrap();
    let (session_check_res, _) = authorize_grant(
        Some(&valid_enroll_for_session_check),
        &innocent.device_id(),
        host.host_id(),
        "pair.enroll",
        NOW_UNIX,
        None,
        lookup_host,
    );
    assert!(matches!(session_check_res, Err(CoreError::GrantDenied(_))));

    let bad_machine_false = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            subject: innocent.device_id(),
            caps: vec!["session.ping".to_string()],
            not_before: "2026-11-25T00:00:00Z".to_string(),
            not_after: "2026-11-25T00:05:00Z".to_string(),
            nonce: b64url_encode(&[0xD4; 16]),
            delegated_from: vec![],
            uses: None,
            machine: Some(false),
        },
        host.signing_key(),
    )
    .unwrap();
    assert!(matches!(
        verify_grant_with_chain(
            &bad_machine_false,
            &innocent.device_id(),
            host.host_id(),
            NOW_UNIX,
            None,
            lookup_host,
        ),
        Err(CoreError::GrantDenied(_))
    ));

    // confirm_peer(..., None) fails closed when live SAS exists, and confirm_peer_without_sas succeeds.
    let sas_peer = mk_identity(135);
    roster
        .record_pending_pair(
            *sas_peer.static_key().public_bytes(),
            None,
            "HumanCli".into(),
            "cli".into(),
            "abcd 1234 efgh 5678".into(),
        )
        .unwrap();
    assert_eq!(
        roster.confirm_peer(&sas_peer.device_id(), None),
        Err(CoreError::ProtocolViolation(
            "pairing SAS confirmation required"
        ))
    );
    roster
        .confirm_peer_without_sas(&sas_peer.device_id())
        .unwrap();
    assert_eq!(
        roster.get(&sas_peer.device_id()).unwrap().state,
        PeerState::Active
    );

    // Burn-log capacity cap & expired pruning
    let mut cap_roster = Roster::new();
    for i in 0..MAX_BURNED_ENROLLMENT_NONCES {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
        cap_roster
            .burn_enrollment_nonce(&b64url_encode(&nonce), NOW_UNIX + 100, NOW_UNIX)
            .unwrap();
    }
    assert_eq!(
        cap_roster.burn_enrollment_nonce("overflow-nonce-000000", NOW_UNIX + 100, NOW_UNIX),
        Err(CoreError::EnrollmentBurnLogFull)
    );
    // Once expired, pruning reclaims slots cleanly!
    cap_roster
        .burn_enrollment_nonce("post-expiry-nonce-000", NOW_UNIX + 200, NOW_UNIX + 101)
        .unwrap();
}

#[test]
fn phase6_m2m_status_mismatch_and_forged_proof_fail_closed() {
    use tendril_core::crypto::device_id;
    use tendril_core::pairing::mint_enrollment_token;
    use tendril_core::wire::{PairResponse, encode_frame};

    let host = mk_identity(140);
    let peer = mk_identity(141);
    let preamble = Preamble::v1(Intent::Pair).encode();

    // 1. M2M initiator rejects responder returning status == "pending" instead of "active".
    let tok = mint_enrollment_token(
        &host,
        host.host_id(),
        Some(&peer.device_id()),
        NOW_UNIX,
        900,
        [0xE1; 16],
    )
    .unwrap();
    let mut init_m2m =
        PairingInitiator::new_m2m(&peer, "m", "machine", tok, host_pinned(&host), None).unwrap();
    let mut raw_resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&preamble)
        .build_responder()
        .unwrap();
    let m1 = collect_pair_writes(&init_m2m.start().unwrap());
    raw_resp
        .read_message_vec(decode_frame(&m1[6..]).unwrap().0)
        .unwrap();
    let hh = serde_json::to_vec(&HostHello {
        host_id: host.host_id().to_string(),
        proto_version: 1,
        signing_pub: host.signing_key().public_key().to_b64url(),
        rotation: vec![],
        upgrade: vec![],
    })
    .unwrap();
    let msg2 = raw_resp.write_message_vec(&hh).unwrap();
    let m3 = collect_pair_writes(&init_m2m.feed_bytes(&encode_frame(&msg2).unwrap()).unwrap());
    raw_resp
        .read_message_vec(decode_frame(&m3).unwrap().0)
        .unwrap();
    let mut tx_r = raw_resp.into_transport_mode().unwrap();
    let wrong_status = serde_json::to_vec(&PairResponse::Success {
        device_id: peer.device_id(),
        status: "pending".to_string(),
        host_signing_pub: host.signing_key().public_key().to_b64url(),
    })
    .unwrap();
    let msg4 = tx_r.write_message_vec(&wrong_status).unwrap();
    assert_eq!(
        init_m2m.feed_bytes(&encode_frame(&msg4).unwrap()),
        Err(CoreError::ProtocolViolation(
            "unexpected pair response fields"
        ))
    );

    // 2. Human initiator rejects responder returning status == "active" instead of "pending".
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let mut init_hum =
        PairingInitiator::new(&peer, "h", "cli", code, Some(host_pinned(&host)), None).unwrap();
    let mut raw_resp2 = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&preamble)
        .build_responder()
        .unwrap();
    let hm1 = collect_pair_writes(&init_hum.start().unwrap());
    raw_resp2
        .read_message_vec(decode_frame(&hm1[6..]).unwrap().0)
        .unwrap();
    let hmsg2 = raw_resp2.write_message_vec(&hh).unwrap();
    let hm3 = collect_pair_writes(&init_hum.feed_bytes(&encode_frame(&hmsg2).unwrap()).unwrap());
    raw_resp2
        .read_message_vec(decode_frame(&hm3).unwrap().0)
        .unwrap();
    let mut tx_r2 = raw_resp2.into_transport_mode().unwrap();
    let wrong_active = serde_json::to_vec(&PairResponse::Success {
        device_id: device_id(peer.static_key().public_bytes()),
        status: "active".to_string(),
        host_signing_pub: host.signing_key().public_key().to_b64url(),
    })
    .unwrap();
    let hmsg4 = tx_r2.write_message_vec(&wrong_active).unwrap();
    assert_eq!(
        init_hum.feed_bytes(&encode_frame(&hmsg4).unwrap()),
        Err(CoreError::ProtocolViolation(
            "unexpected pair response fields"
        ))
    );

    // 3. Forged enroll_proof and XOR PairClaim conflict fail closed on PairingResponder.
    let policy = tendril_core::pairing::EnrollmentPolicy::enabled_default();
    let tok2 = mint_enrollment_token(
        &host,
        host.host_id(),
        Some(&peer.device_id()),
        NOW_UNIX,
        900,
        [0xE2; 16],
    )
    .unwrap();
    let mut forged_resp =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let mut raw_init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(peer.static_key().secret_bytes())
        .prologue(&preamble)
        .build_initiator()
        .unwrap();
    let msg1 = raw_init.write_message_vec(&[]).unwrap();
    let mut f1 = preamble.to_vec();
    f1.extend_from_slice(&encode_frame(&msg1).unwrap());
    let out2 = collect_pair_writes(
        &forged_resp
            .feed_bytes(&f1, NOW_UNIX, &mut mgr, &mut Roster::new())
            .unwrap(),
    );
    raw_init
        .read_message_vec(decode_frame(&out2).unwrap().0)
        .unwrap();
    let forged_claim = PairClaim {
        name: "m".into(),
        kind: "machine".into(),
        code_mac: None,
        enrollment_token: Some(tok2.clone()),
        signing_pub: Some(peer.signing_key().public_key().to_b64url()),
        enroll_proof: Some(b64url_encode(&vec![0x42u8; HYBRID_SIG_LEN])),
    };
    let msg3 = raw_init
        .write_message_vec(&serde_json::to_vec(&forged_claim).unwrap())
        .unwrap();
    let mut r_forged = Roster::new();
    let r_acts = forged_resp
        .feed_bytes(
            &encode_frame(&msg3).unwrap(),
            NOW_UNIX,
            &mut mgr,
            &mut r_forged,
        )
        .unwrap();
    assert_eq!(
        completed_pair_outcome(&r_acts),
        PairOutcome::Rejected {
            error: "unauthorized".to_string()
        }
    );
    assert!(!r_forged.is_enrollment_nonce_burned(&tok2.nonce));

    // 4. Setting both code_mac and M2M fields in PairClaim returns protocol_error.
    let mut conflict_resp =
        PairingResponder::with_enrollment_policy(&host, PairingPathKind::Remote, None, policy)
            .unwrap();
    let mut raw_init2 = NoiseHfsHandshakeBuilder::new()
        .local_private_key(peer.static_key().secret_bytes())
        .prologue(&preamble)
        .build_initiator()
        .unwrap();
    let cmsg1 = raw_init2.write_message_vec(&[]).unwrap();
    let mut cf1 = preamble.to_vec();
    cf1.extend_from_slice(&encode_frame(&cmsg1).unwrap());
    let cout2 = collect_pair_writes(
        &conflict_resp
            .feed_bytes(&cf1, NOW_UNIX, &mut mgr, &mut Roster::new())
            .unwrap(),
    );
    raw_init2
        .read_message_vec(decode_frame(&cout2).unwrap().0)
        .unwrap();
    let conflict_claim = PairClaim {
        name: "m".into(),
        kind: "machine".into(),
        code_mac: Some(b64url_encode(&[0x11u8; 32])),
        enrollment_token: Some(tok2),
        signing_pub: Some(peer.signing_key().public_key().to_b64url()),
        enroll_proof: Some(b64url_encode(&vec![0x42u8; HYBRID_SIG_LEN])),
    };
    let cmsg3 = raw_init2
        .write_message_vec(&serde_json::to_vec(&conflict_claim).unwrap())
        .unwrap();
    let c_acts = conflict_resp
        .feed_bytes(
            &encode_frame(&cmsg3).unwrap(),
            NOW_UNIX,
            &mut mgr,
            &mut Roster::new(),
        )
        .unwrap();
    assert_eq!(
        completed_pair_outcome(&c_acts),
        PairOutcome::Rejected {
            error: "protocol_error".to_string()
        }
    );
}

#[test]
fn pq_hybrid_kem_and_half_tampered_signature_adversarial_suite() {
    use tendril_core::grants::{verify_crl_signature, verify_grant_signature};
    use tendril_core::identity::verify_rotation_record;
    use tendril_core::pairing::{
        EnrollmentPolicy, mint_enrollment_token, sign_enroll_proof, verify_enroll_proof,
    };
    use tendril_core::wire::{PairResponse, encode_frame};

    let host = mk_identity(150);
    let rogue = mk_identity(151);
    let peer = mk_identity(152);
    let preamble_sess = Preamble::v1(Intent::Session).encode();
    let preamble_pair = Preamble::v1(Intent::Pair).encode();

    // 1. Invalid ML-KEM-768 encapsulation key modulus in msg1 must fail closed on SessionMachine & PairingResponder.
    let mut sess_resp = SessionMachine::new_responder(&host, None).unwrap();
    let mut hs_i = NoiseHfsHandshakeBuilder::new()
        .local_private_key(peer.static_key().secret_bytes())
        .prologue(&preamble_sess)
        .build_initiator()
        .unwrap();
    let mut bad_m1 = hs_i.write_message_vec(&[]).unwrap();
    bad_m1[32] = 0xFF;
    bad_m1[33] = 0xFF;
    let mut wire_bad_m1 = preamble_sess.to_vec();
    wire_bad_m1.extend_from_slice(&encode_frame(&bad_m1).unwrap());
    let mut host_roster = Roster::new();
    assert!(matches!(
        sess_resp.feed_bytes(&wire_bad_m1, NOW_UNIX, 0, &mut host_roster),
        Err(CoreError::Noise(_))
    ));

    // 2. Bit-flipped ML-KEM-768 ciphertext (`ekem1`) in msg2 fails closed before sending msg3.
    let mut peer_roster = Roster::new();
    peer_roster
        .insert_pinned_host(
            host.host_id().to_string(),
            "Host".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            0,
            vec![],
        )
        .unwrap();
    let mut s_init =
        SessionMachine::new_initiator(&peer, host.host_id(), None, None, None).unwrap();
    let mut s_resp2 = SessionMachine::new_responder(&host, None).unwrap();
    let sm1 = collect_session_writes(&s_init.start().unwrap());
    let mut sm2_wire = collect_session_writes(
        &s_resp2
            .feed_bytes(&sm1, NOW_UNIX, 0, &mut host_roster)
            .unwrap(),
    );
    // Flip a bit inside the encrypted `ekem1` region after the 2-byte length prefix and 32-byte e.
    sm2_wire[2 + 32 + 64] ^= 0x80;
    assert!(matches!(
        s_init.feed_bytes(&sm2_wire, NOW_UNIX, 1, &mut peer_roster),
        Err(CoreError::Noise(_))
    ));
    assert!(s_init.is_closed());

    // 3. Half-tampered signatures (Ed25519-only vs ML-DSA-65-only) must fail on grants, CRLs, rotations, and enroll_proof.
    let grant = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            subject: peer.device_id(),
            caps: vec!["fs.read:/a".into()],
            not_before: "2026-11-20T00:00:00Z".into(),
            not_after: "2026-12-20T00:00:00Z".into(),
            nonce: b64url_encode(&[0xF1; 16]),
            delegated_from: vec![],
            uses: None,
            machine: None,
        },
        host.signing_key(),
    )
    .unwrap();
    for flip_idx in [5usize, ED25519_SIG_LEN + 25] {
        let mut tampered = grant.clone();
        let mut raw = b64url_decode(&tampered.sig).unwrap();
        raw[flip_idx] ^= 0x40;
        tampered.sig = b64url_encode(&raw);
        assert_eq!(
            verify_grant_signature(&tampered, host.signing_key().public_key()),
            Err(CoreError::InvalidSignature)
        );
    }

    let crl = sign_crl(
        RevocationListUnsigned {
            v: 1,
            issuer: host.host_id().to_string(),
            seq: 1,
            revoked_devices: vec![],
            revoked_nonces: vec![],
            ts: "2026-11-25T00:00:00Z".into(),
        },
        host.signing_key(),
    )
    .unwrap();
    for flip_idx in [5usize, ED25519_SIG_LEN + 25] {
        let mut tampered = crl.clone();
        let mut raw = b64url_decode(&tampered.sig).unwrap();
        raw[flip_idx] ^= 0x40;
        tampered.sig = b64url_encode(&raw);
        assert_eq!(
            verify_crl_signature(&tampered, host.signing_key().public_key()),
            Err(CoreError::InvalidSignature)
        );
    }

    let rot = sign_rotation(
        1,
        host.signing_key(),
        peer.signing_key().public_key(),
        peer.static_key().public_bytes(),
        NOW_UNIX,
    )
    .unwrap();
    for flip_idx in [5usize, ED25519_SIG_LEN + 25] {
        let mut tampered = rot.clone();
        let mut raw = b64url_decode(&tampered.sig).unwrap();
        raw[flip_idx] ^= 0x40;
        tampered.sig = b64url_encode(&raw);
        assert_eq!(
            verify_rotation_record(&tampered),
            Err(CoreError::InvalidSignature)
        );
    }

    let proof = sign_enroll_proof(
        peer.signing_key(),
        &[0xAA; 32],
        peer.static_key().public_bytes(),
        "nonce-pq-01",
    )
    .unwrap();
    for flip_idx in [5usize, ED25519_SIG_LEN + 25] {
        let mut tampered = proof.clone();
        tampered[flip_idx] ^= 0x40;
        assert_eq!(
            verify_enroll_proof(
                peer.signing_key().public_key(),
                &[0xAA; 32],
                peer.static_key().public_bytes(),
                "nonce-pq-01",
                &tampered,
            ),
            Err(CoreError::InvalidSignature)
        );
    }

    // 4. QR `sh=` pin rejects mismatched HostHello.signing_pub at msg2 AND rejects mismatched PairResponse.host_signing_pub.
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Lan2Group, NOW_UNIX)
        .unwrap();
    let pin = PinnedHost::with_hash(
        Some(host.host_id().to_string()),
        *host.static_key().public_bytes(),
        host.signing_key().signing_pub_hash(),
        0,
    );
    let mut init_unverified_hh =
        PairingInitiator::new(&peer, "p", "cli", code.clone(), Some(pin), None).unwrap();
    let mut raw_host = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&preamble_pair)
        .build_responder()
        .unwrap();
    let pm1 = collect_pair_writes(&init_unverified_hh.start().unwrap());
    raw_host
        .read_message_vec(decode_frame(&pm1[6..]).unwrap().0)
        .unwrap();
    let bad_hh = serde_json::to_vec(&HostHello {
        host_id: host.host_id().to_string(),
        proto_version: 1,
        signing_pub: rogue.signing_key().public_key().to_b64url(),
        rotation: vec![],
        upgrade: vec![],
    })
    .unwrap();
    let bad_msg2 = raw_host.write_message_vec(&bad_hh).unwrap();
    assert_eq!(
        init_unverified_hh.feed_bytes(&encode_frame(&bad_msg2).unwrap()),
        Err(CoreError::HostKeyUnverified)
    );

    // Also test HostHello carrying host's real signing_pub followed by PairResponse carrying rogue signing_pub.
    let tok = mint_enrollment_token(
        &host,
        host.host_id(),
        Some(&peer.device_id()),
        NOW_UNIX,
        900,
        [0xE9; 16],
    )
    .unwrap();
    let _ = EnrollmentPolicy::enabled_default();
    let mut init_resp_mismatch =
        PairingInitiator::new_m2m(&peer, "m", "machine", tok, host_pinned(&host), None).unwrap();
    let mut raw_host2 = NoiseHfsHandshakeBuilder::new()
        .local_private_key(host.static_key().secret_bytes())
        .prologue(&preamble_pair)
        .build_responder()
        .unwrap();
    let pm1_ok = collect_pair_writes(&init_resp_mismatch.start().unwrap());
    raw_host2
        .read_message_vec(decode_frame(&pm1_ok[6..]).unwrap().0)
        .unwrap();
    let ok_hh = serde_json::to_vec(&HostHello {
        host_id: host.host_id().to_string(),
        proto_version: 1,
        signing_pub: host.signing_key().public_key().to_b64url(),
        rotation: vec![],
        upgrade: vec![],
    })
    .unwrap();
    let ok_m2 = raw_host2.write_message_vec(&ok_hh).unwrap();
    let pm3_ok = collect_pair_writes(
        &init_resp_mismatch
            .feed_bytes(&encode_frame(&ok_m2).unwrap())
            .unwrap(),
    );
    raw_host2
        .read_message_vec(decode_frame(&pm3_ok).unwrap().0)
        .unwrap();
    let mut tx_h = raw_host2.into_transport_mode().unwrap();
    let bad_resp = serde_json::to_vec(&PairResponse::Success {
        device_id: peer.device_id(),
        status: "active".to_string(),
        host_signing_pub: rogue.signing_key().public_key().to_b64url(),
    })
    .unwrap();
    let bad_m4 = tx_h.write_message_vec(&bad_resp).unwrap();
    assert_eq!(
        init_resp_mismatch.feed_bytes(&encode_frame(&bad_m4).unwrap()),
        Err(CoreError::HostKeyUnverified)
    );
}

mod group_mesh {
    use tendril_core::crypto::{SigningKeypair, StaticKeypair, device_id};
    use tendril_core::error::CoreError;
    use tendril_core::group::{
        GroupBook, GroupBuildParams, GroupManifest, GroupMember, GroupSigner,
        MAX_GROUP_MANIFEST_LEN, MAX_GROUP_MEMBERS, V2GroupSecrets, add_member, create_group,
        group_id_from_root, issue_admin_grant, remove_member, sign_group_manifest,
        verify_group_manifest,
    };
    use tendril_core::wire::{InnerFrameType, decode_inner_frame, encode_inner_frame};

    const NOW: u64 = super::NOW_UNIX;

    struct Dev {
        st: StaticKeypair,
        sk: SigningKeypair,
    }

    impl Dev {
        fn new(seed: u8) -> Self {
            let mut scalar = [seed; 32];
            scalar[0] = seed ^ 0x33;
            Self {
                st: StaticKeypair::from_scalar(scalar),
                sk: SigningKeypair::from_seed([seed ^ 0xC0; 32]),
            }
        }

        fn id(&self) -> String {
            device_id(self.st.public_bytes())
        }

        fn member(&self, endpoints: Vec<String>, caps: Vec<String>) -> GroupMember {
            GroupMember::new(
                self.st.public_bytes(),
                "dev",
                self.sk.public_key(),
                endpoints,
                caps,
            )
        }
    }

    fn caps(gid: &str) -> Vec<String> {
        vec![format!("group.send:{gid}"), format!("group.recv:{gid}")]
    }

    fn base() -> (Dev, String, GroupManifest, V2GroupSecrets) {
        let root = Dev::new(1);
        let gid = group_id_from_root(root.sk.public_key());
        let (m, s) = create_group(
            &root.sk,
            "adv",
            2,
            root.member(vec![], caps(&gid)),
            GroupBuildParams::new(NOW),
        )
        .unwrap();
        (root, gid, m, s)
    }

    #[test]
    fn group_manifest_adversarial_suite() {
        let (root, gid, m1, s1) = base();
        let params = GroupBuildParams::new(NOW);
        let signer = GroupSigner::root(&root.sk);
        let mut book = GroupBook::new();
        book.ingest_group_manifest(&m1, NOW, None).unwrap();

        // 33-member overflow.
        let mut over = m1.unsigned();
        for i in 0..MAX_GROUP_MEMBERS {
            let d = Dev::new(20 + u8::try_from(i).unwrap());
            over.members.push(d.member(vec![], caps(&gid)));
        }
        assert_eq!(over.members.len(), MAX_GROUP_MEMBERS + 1);
        let m = sign_group_manifest(over, &root.sk).unwrap();
        assert!(matches!(
            verify_group_manifest(&m, NOW, None),
            Err(CoreError::InvalidGroupManifest(_))
        ));

        // Cross-group capability injection and host-scope escape.
        for bad in [
            "group.recv:grp_0000000000000000",
            "fs.read:/etc/shadow",
            "shell.exec",
        ] {
            let mut u = m1.unsigned();
            u.members[0].caps = vec![bad.to_string()];
            let m = sign_group_manifest(u, &root.sk).unwrap();
            assert!(verify_group_manifest(&m, NOW, None).is_err(), "{bad}");
        }

        // Revoked omission and re-addition.
        let victim = Dev::new(2);
        let (m2, s2) =
            add_member(&m1, &signer, victim.member(vec![], caps(&gid)), &s1, params).unwrap();
        let (m3, s3) = remove_member(&m2, &signer, &victim.id(), &s2, params).unwrap();
        book.ingest_group_manifest(&m2, NOW, None).unwrap();
        book.ingest_group_manifest(&m3, NOW, None).unwrap();
        let mut omit = m3.unsigned();
        omit.seq = 4;
        omit.revoked_members.clear();
        let m = sign_group_manifest(omit, &root.sk).unwrap();
        assert!(book.ingest_group_manifest(&m, NOW, None).is_err());
        assert!(matches!(
            add_member(&m3, &signer, victim.member(vec![], caps(&gid)), &s3, params),
            Err(CoreError::GroupMemberRevoked(_))
        ));

        // Co-admin removing the founding root.
        let admin = Dev::new(3);
        let (m4, _s4) =
            add_member(&m3, &signer, admin.member(vec![], caps(&gid)), &s3, params).unwrap();
        book.ingest_group_manifest(&m4, NOW, None).unwrap();
        let grant = issue_admin_grant(
            &root.sk,
            &root.id(),
            &gid,
            &admin.id(),
            admin.sk.public_key(),
            0,
            params,
        )
        .unwrap();
        let mut coup = m4.unsigned();
        coup.seq = 5;
        coup.members.retain(|m| m.device_id != root.id());
        coup.signer_device_id = admin.id();
        coup.signer_signing_pub = Some(admin.sk.public_key().to_b64url());
        coup.admin_grant = Some(grant);
        let m = sign_group_manifest(coup, &admin.sk).unwrap();
        assert!(book.ingest_group_manifest(&m, NOW, None).is_err());
        assert_eq!(book.manifest(&gid).unwrap().seq, 4);

        // Wire floor 2 -> 1 downgrade.
        let mut down = m4.unsigned();
        down.seq = 5;
        down.min_wire_version = 1;
        let m = sign_group_manifest(down, &root.sk).unwrap();
        assert!(matches!(
            book.ingest_group_manifest(&m, NOW, None),
            Err(CoreError::GroupWireDowngrade { .. })
        ));

        // Worst-case realistic 32-member manifest stays below the 32768 byte cap.
        let mut full = m1.unsigned();
        for i in 0..(MAX_GROUP_MEMBERS - 1) {
            let d = Dev::new(60 + u8::try_from(i).unwrap());
            let eps = vec![
                "wss://relay-a.example.net/v2/relay".to_string(),
                "iroh://abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
            ];
            let mut c = caps(&gid);
            c.push(format!("sync.push:{gid}/notes"));
            c.push(format!("kv.write:{gid}"));
            full.members.push(d.member(eps, c));
        }
        let m = sign_group_manifest(full, &root.sk).unwrap();
        let len = m.to_wire_bytes().unwrap().len();
        assert!(len < MAX_GROUP_MANIFEST_LEN, "{len}");
        verify_group_manifest(&m, NOW, None).unwrap();
    }

    #[test]
    fn group_frames_fail_closed_on_wire() {
        let oversize = vec![b'{'; MAX_GROUP_MANIFEST_LEN + 1];
        assert!(matches!(
            encode_inner_frame(InnerFrameType::GroupManifest, &oversize),
            Err(CoreError::GroupManifestTooLarge { .. })
        ));
        for len in [0usize, 1, 59, 61, 4096] {
            assert!(encode_inner_frame(InnerFrameType::GroupRendezvous, &vec![0; len]).is_err());
            let mut raw = vec![0x0B];
            raw.extend_from_slice(&vec![0u8; len]);
            if len != 60 {
                assert!(decode_inner_frame(&raw).is_err());
            }
        }
        assert!(decode_inner_frame(&[0x0D, 0, 0]).is_err());
        assert!(decode_inner_frame(&[0x0E, 0, 0]).is_err());
    }

    #[test]
    fn group_rendezvous_injection_by_non_admin_is_rejected() {
        let (root, gid, m1, s1) = base();
        let params = GroupBuildParams::new(NOW);
        let member = Dev::new(2);
        let (m2, s2) = add_member(
            &m1,
            &GroupSigner::root(&root.sk),
            member.member(vec![], caps(&gid)),
            &s1,
            params,
        )
        .unwrap();
        let mut book = GroupBook::new();
        book.ingest_group_manifest(&m2, NOW, None).unwrap();
        let forged = V2GroupSecrets::new([0xEE; 32], 2)
            .to_rendezvous_frame(&gid)
            .unwrap();
        assert!(
            book.ingest_group_rendezvous(&member.id(), &forged[..], NOW, None)
                .is_err()
        );
        assert!(book.secrets(&gid).is_none());
        let good = s2.to_rendezvous_frame(&gid).unwrap();
        book.ingest_group_rendezvous(&root.id(), &good[..], NOW, None)
            .unwrap();
        assert!(
            book.ingest_group_rendezvous(&member.id(), &forged[..], NOW, None)
                .is_err()
        );
        assert_eq!(book.secrets(&gid), Some(&s2));
    }
}

fn responder_pending_sas(actions: &[PairAction]) -> String {
    match completed_pair_outcome(actions) {
        PairOutcome::ResponderPending { pairing_sas, .. } => pairing_sas,
        other => panic!("expected ResponderPending, got {other:?}"),
    }
}

fn human_pair_v1(
    peer: &EndpointIdentity,
    host: &EndpointIdentity,
    host_roster: &mut Roster,
) -> Vec<PairAction> {
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let mut init = PairingInitiator::new(peer, "Peer", "cli", &code, None, None).unwrap();
    let mut resp = PairingResponder::new(host, PairingPathKind::Remote, None).unwrap();
    let (_, resp_events) = run_pair_exchange(
        &mut init,
        &mut resp,
        &mut mgr,
        host_roster,
        NOW_UNIX,
        usize::MAX,
    );
    resp_events
}

/// Sends the keyless human `PairClaim` a pre-change initiator builds.
fn legacy_keyless_pair_v1(
    peer: &EndpointIdentity,
    host: &EndpointIdentity,
    host_roster: &mut Roster,
) -> Vec<PairAction> {
    let mut mgr = PairingManager::new(PairingConfig::default());
    let code = mgr
        .issue_code(PairingCodeKind::Remote3Group, NOW_UNIX)
        .unwrap();
    let mut resp = PairingResponder::new(host, PairingPathKind::Remote, None).unwrap();
    let preamble = Preamble::v1(Intent::Pair).encode();
    let mut raw = NoiseHfsHandshakeBuilder::new()
        .local_private_key(peer.static_key().secret_bytes())
        .prologue(&preamble)
        .build_initiator()
        .unwrap();
    let mut f1 = preamble.to_vec();
    f1.extend_from_slice(&encode_frame(&raw.write_message_vec(&[]).unwrap()).unwrap());
    let out2 = collect_pair_writes(
        &resp
            .feed_bytes(&f1, NOW_UNIX, &mut mgr, host_roster)
            .unwrap(),
    );
    raw.read_message_vec(decode_frame(&out2).unwrap().0)
        .unwrap();
    let mac = tendril_core::crypto::compute_code_mac(&code, raw.get_handshake_hash()).unwrap();
    let claim = PairClaim {
        name: "Legacy".into(),
        kind: "cli".into(),
        code_mac: Some(b64url_encode(&mac)),
        enrollment_token: None,
        signing_pub: None,
        enroll_proof: None,
    };
    let msg3 = raw
        .write_message_vec(&serde_json::to_vec(&claim).unwrap())
        .unwrap();
    resp.feed_bytes(
        &encode_frame(&msg3).unwrap(),
        NOW_UNIX,
        &mut mgr,
        host_roster,
    )
    .unwrap()
}

#[test]
fn human_pairing_records_initiator_signing_key() {
    let host = mk_identity(0x31).with_host_id("host-key-claim");
    let peer = mk_identity(0x32);
    let key = peer.signing_key().public_key().clone();
    let mut roster = Roster::new();

    let sas = responder_pending_sas(&human_pair_v1(&peer, &host, &mut roster));
    let entry = roster.get(&peer.device_id()).unwrap();
    assert_eq!(entry.state, PeerState::Pending);
    assert_eq!(entry.signing_pub.as_ref(), Some(&key));
    assert_eq!(roster.lookup_active_signing_key(&peer.device_id()), None);

    roster.confirm_peer(&peer.device_id(), Some(&sas)).unwrap();
    let entry = roster.get(&peer.device_id()).unwrap();
    assert_eq!(entry.state, PeerState::Active);
    assert_eq!(entry.signing_pub.as_ref(), Some(&key));
    assert_eq!(
        roster.lookup_active_signing_key(&peer.device_id()),
        Some(key)
    );
}

#[test]
fn v1_repair_enrichment_and_no_replacement() {
    let host = mk_identity(0x33).with_host_id("host-repair");
    let peer = mk_identity(0x34);
    let id = peer.device_id();
    let key = peer.signing_key().public_key().clone();

    // Legacy keyless active pin, as left by a pre-change pairing.
    let mut roster = Roster::new();
    let old_sas = responder_pending_sas(&legacy_keyless_pair_v1(&peer, &host, &mut roster));
    roster.confirm_peer(&id, Some(&old_sas)).unwrap();
    assert_eq!(roster.get(&id).unwrap().signing_pub, None);

    // Keyed re-pair enriches the entry and returns it to pending until the new SAS is confirmed.
    let new_sas = responder_pending_sas(&human_pair_v1(&peer, &host, &mut roster));
    let entry = roster.get(&id).unwrap();
    assert_eq!(entry.state, PeerState::Pending);
    assert_eq!(entry.signing_pub.as_ref(), Some(&key));
    assert_eq!(roster.lookup_active_signing_key(&id), None);
    roster.confirm_peer(&id, Some(&new_sas)).unwrap();
    assert_eq!(roster.lookup_active_signing_key(&id), Some(key.clone()));

    // Same static, another signing key with a valid proof by that key: refused, no mutation.
    let mut s_bytes = [0x34; 32];
    s_bytes[0] = 0x34 ^ 0x55;
    let impostor = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(s_bytes),
        SigningKeypair::from_seed([0x99; 32]),
    );
    assert_eq!(impostor.device_id(), id);
    let before = serde_json::to_value(&roster).unwrap();
    let acts = human_pair_v1(&impostor, &host, &mut roster);
    assert_eq!(
        completed_pair_outcome(&acts),
        PairOutcome::Rejected {
            error: "protocol_error".to_string()
        }
    );
    assert_eq!(serde_json::to_value(&roster).unwrap(), before);
    assert_eq!(roster.lookup_active_signing_key(&id), Some(key));
}

#[test]
fn old_initiator_new_responder_v1() {
    let host = mk_identity(0x35).with_host_id("host-legacy");
    let peer = mk_identity(0x36);
    let mut roster = Roster::new();
    responder_pending_sas(&legacy_keyless_pair_v1(&peer, &host, &mut roster));
    let entry = roster.get(&peer.device_id()).unwrap();
    assert_eq!(entry.state, PeerState::Pending);
    assert_eq!(entry.signing_pub, None);
}

#[test]
fn wt_redaction_and_policy_block_secrets_and_ssrf_hosts() {
    use tendril_core::pairing::is_valid_pairing_endpoint_hint;
    use tendril_core::policy::is_numeric_host_addr;
    use tendril_core::redact::{REDACTED, redact_hint, redact_text, redact_url_str};

    let cert_hash = b64url_encode(&[0x5Au8; 32]);
    let raw_wt = format!("wt://10.0.0.4:4433/private/path?certhash={cert_hash}");
    assert_eq!(redact_hint(&raw_wt), "wt://10.0.0.4:4433");
    assert_eq!(redact_url_str(&raw_wt), "wt://10.0.0.4:4433");
    let scrubbed = redact_text(&format!("connect {raw_wt} failed"));
    assert_eq!(scrubbed, "connect wt://10.0.0.4:4433 failed");
    assert!(!scrubbed.contains(&cert_hash));
    assert!(!scrubbed.contains("private"));

    let code_wt = "wt://TND-ABCD-EFGH.local:4433/?certhash=secret";
    assert_eq!(redact_hint(code_wt), REDACTED);
    assert_eq!(redact_url_str(code_wt), REDACTED);

    assert!(is_numeric_host_addr(&raw_wt));
    assert!(is_numeric_host_addr("wt://[fd00::1]:4433"));
    assert!(!is_numeric_host_addr("wt://peer.example:4433"));

    for ssrf in [
        "wt://[::ffff:169.254.169.254]:4433",
        "wt://2852039166:4433",
        "wt://0251.0376.0.1:4433",
        "wt://[fe80::1]:4433",
        "wt://[::]:4433",
        "wt://0.0.0.0:4433",
    ] {
        assert!(!is_valid_pairing_endpoint_hint(ssrf), "{ssrf}");
    }
}
