//! Adversarial fault-injection and end-to-end Sans-I/O test suite (Verification Gates 3 and 4).

use std::collections::VecDeque;

use snow::Builder;
use snow::params::NoiseParams;

use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_encode, pairing_sas};
use tendril_core::error::CoreError;
use tendril_core::grants::{GrantUnsigned, RevocationListUnsigned, sign_crl, sign_grant};
use tendril_core::identity::{EndpointIdentity, sign_rotation};
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
    HostHello, Intent, MAX_READ_BUFFER_LEN, NOISE_PATTERN, PairClaim, Preamble, decode_frame,
    encode_frame,
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
    let uri = PairingUri {
        host_name: "Studio Host".to_string(),
        code: code.clone(),
        host_static_pub: *host_id.static_key().public_bytes(),
        host_signing_pub: *host_id.signing_key().public_bytes(),
        endpoints: vec!["direct:192.168.1.50:7000".to_string()],
    };
    let parsed_uri = PairingUri::parse(&uri.encode()).unwrap();
    assert_eq!(parsed_uri, uri);

    let mut p_init = PairingInitiator::new(
        &client_id,
        "Workstation",
        "linux",
        &parsed_uri.code,
        Some(PinnedHost {
            host_id: None,
            static_pub: parsed_uri.host_static_pub,
            signing_pub: parsed_uri.host_signing_pub,
            rotation_seq: 0,
        }),
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
            Some(*del_identity.signing_key().public_bytes()),
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
        &del_identity.signing_key().signing_key(),
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
        &host_id.signing_key().signing_key(),
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
        .confirm_peer(&client_id.device_id(), None)
        .unwrap();

    let mut cli_roster = Roster::new();
    cli_roster
        .insert_pinned_host(
            host_id.host_id().to_string(),
            "Host".into(),
            *host_id.static_key().public_bytes(),
            Some(*host_id.signing_key().public_bytes()),
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
        let expected_err = if attempt < 5 {
            "unauthorized"
        } else {
            "code_burned"
        };
        assert!(init_ev.iter().any(|a| matches!(a, PairAction::Completed(PairOutcome::Rejected { error }) if error == expected_err)));
    }
    assert_eq!(mgr.live_code_count(NOW_UNIX + 6), 0);

    // Even the real code now fails with code_burned.
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
    assert!(ev_b.iter().any(|a| matches!(a, PairAction::Completed(PairOutcome::Rejected { error }) if error == "code_burned")));

    // Expired code -> code_expired; 2-group LAN code over Remote -> path_disallowed.
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
    assert!(ev_exp.iter().any(|a| matches!(a, PairAction::Completed(PairOutcome::Rejected { error }) if error == "code_expired")));

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

    let params: NoiseParams = NOISE_PATTERN.parse().unwrap();
    let pair_preamble = Preamble::v1(Intent::Pair).encode();
    let mut mitm_to_client = Builder::new(params.clone())
        .local_private_key(mitm_id.static_key().secret_bytes())
        .unwrap()
        .prologue(&pair_preamble)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut mitm_to_host = Builder::new(params.clone())
        .local_private_key(mitm_id.static_key().secret_bytes())
        .unwrap()
        .prologue(&pair_preamble)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut h_resp = PairingResponder::new(&host_id, PairingPathKind::Remote, None).unwrap();

    let c_m1 = collect_pair_writes(&c_init.start().unwrap());
    let mut pt_buf = vec![0u8; MAX_FRAME_LEN];
    let mut ct_buf = vec![0u8; MAX_FRAME_LEN];
    // MITM completes msg1/msg2 toward Client AND msg1/msg2 toward Host independently.
    mitm_to_client
        .read_message(decode_frame(&c_m1[6..]).unwrap().0, &mut pt_buf)
        .unwrap();
    let mitm_hello = serde_json::to_vec(&HostHello {
        host_id: mitm_id.host_id().to_string(),
        proto_version: 1,
        rotation: vec![],
    })
    .unwrap();
    let nm2_c = mitm_to_client
        .write_message(&mitm_hello, &mut ct_buf)
        .unwrap();
    let c_ev2 = c_init
        .feed_bytes(&encode_frame(&ct_buf[..nm2_c]).unwrap())
        .unwrap();
    let c_sas = c_ev2
        .iter()
        .find_map(|a| match a {
            PairAction::SasReady { pairing_sas, .. } => Some(pairing_sas.clone()),
            _ => None,
        })
        .unwrap();
    let c_m3_wire = collect_pair_writes(&c_ev2);
    let n_claim = mitm_to_client
        .read_message(decode_frame(&c_m3_wire).unwrap().0, &mut pt_buf)
        .unwrap();
    let relayed_claim: PairClaim = serde_json::from_slice(&pt_buf[..n_claim]).unwrap();

    // MITM dials real Host and forwards Client's PairClaim (containing code_mac bound to h_client).
    let nm1_h = mitm_to_host.write_message(&[], &mut ct_buf).unwrap();
    let mut to_h = pair_preamble.to_vec();
    to_h.extend_from_slice(&encode_frame(&ct_buf[..nm1_h]).unwrap());
    let h_m2 = collect_pair_writes(
        &h_resp
            .feed_bytes(&to_h, NOW_UNIX, &mut mgr_mitm, &mut host_roster)
            .unwrap(),
    );
    mitm_to_host
        .read_message(decode_frame(&h_m2).unwrap().0, &mut pt_buf)
        .unwrap();
    let h_hash: [u8; 32] = mitm_to_host.get_handshake_hash().try_into().unwrap();
    assert_ne!(c_sas, pairing_sas(&h_hash));
    let claim_bytes = serde_json::to_vec(&relayed_claim).unwrap();
    let nm3_h = mitm_to_host
        .write_message(&claim_bytes, &mut ct_buf)
        .unwrap();
    let splice_ev = h_resp
        .feed_bytes(
            &encode_frame(&ct_buf[..nm3_h]).unwrap(),
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
        Some(PinnedHost {
            host_id: Some(host_id.host_id().to_string()),
            static_pub: *rogue_id.static_key().public_bytes(),
            signing_pub: *rogue_id.signing_key().public_bytes(),
            rotation_seq: 0,
        }),
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
            Some(*rogue_id.signing_key().public_bytes()),
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
                Some(*peer.signing_key().public_bytes()),
                peer.host_id().to_string(),
                "cli".into(),
                "abcd".into(),
            )
            .unwrap();
        host_roster.confirm_peer(&peer.device_id(), None).unwrap();
    }
    client_roster
        .insert_pinned_host(
            host_id.host_id().to_string(),
            "Host".into(),
            *host_id.static_key().public_bytes(),
            Some(*host_id.signing_key().public_bytes()),
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
        &delegate_id.signing_key().signing_key(),
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
        &attacker_id.signing_key().signing_key(),
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
        &host_id.signing_key().signing_key(),
    )
    .unwrap();
    host_roster
        .ingest_crl(
            crl1,
            host_id.host_id(),
            host_id.signing_key().public_bytes(),
        )
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
        &host_id.signing_key().signing_key(),
    )
    .unwrap();
    assert_eq!(
        host_roster.ingest_crl(
            stale_crl,
            host_id.host_id(),
            host_id.signing_key().public_bytes()
        ),
        Err(CoreError::CrlStaleSeq { current: 2, got: 1 })
    );

    // 5. Unanchored MITM fork in HostHello fails handshake WITHOUT revoking legitimate host entry.
    let rogue_rot = sign_rotation(
        1,
        &attacker_id.signing_key().signing_key(),
        StaticKeypair::from_scalar([0xC1; 32]).public_bytes(),
        StaticKeypair::from_scalar([0xC2; 32]).public_bytes(),
        NOW_UNIX + 50,
    )
    .unwrap();
    let unanch_res = client_roster.apply_verified_rotation(
        host_id.host_id(),
        &[rogue_rot],
        host_id.static_key().public_bytes(),
        host_id.signing_key().public_bytes(),
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
        &host_id.signing_key().signing_key(),
        next_sig_b.public_bytes(),
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
    let params: NoiseParams = NOISE_PATTERN.parse().unwrap();
    let sess_pre = Preamble::v1(Intent::Session).encode();
    let mut evil_resp = Builder::new(params)
        .local_private_key(host_id.static_key().secret_bytes())
        .unwrap()
        .prologue(&sess_pre)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut pt_buf = vec![0u8; MAX_FRAME_LEN];
    let mut ct_buf = vec![0u8; MAX_FRAME_LEN];
    evil_resp
        .read_message(decode_frame(&fork_m1[6..]).unwrap().0, &mut pt_buf)
        .unwrap();
    let forked_hello = serde_json::to_vec(&HostHello {
        host_id: host_id.host_id().to_string(),
        proto_version: 1,
        rotation: forked_chain,
    })
    .unwrap();
    let n_fm2 = evil_resp.write_message(&forked_hello, &mut ct_buf).unwrap();
    let fork_err = s_fork_init
        .feed_bytes(
            &encode_frame(&ct_buf[..n_fm2]).unwrap(),
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
