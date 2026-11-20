//! Verifies all canonical v1 vectors under `spec/vectors/*.json` and negative cases.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use snow::Builder;
use snow::params::NoiseParams;

use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{
    argon2id_pairing_key, b64url_decode_array, b64url_encode, compute_code_mac, device_id,
    fingerprint_device, fingerprint_host, normalize_code, pairing_sas, verify_code_mac,
    x25519_public_from_scalar,
};
use tendril_core::error::CoreError;
use tendril_core::grants::{
    Capability, Grant, GrantUnsigned, RevocationList, canonical_json, crl_signed_bytes,
    grant_allows, grant_signed_bytes, sign_grant, verify_crl_signature, verify_delegation_subset,
    verify_grant_signature, verify_grant_with_chain,
};
use tendril_core::identity::{
    RotationRecord, detect_rotation_fork, rotation_signed_bytes, sign_rotation,
    verify_rotation_chain, verify_rotation_record,
};
use tendril_core::wire::{
    HostHello, InnerFrameType, Intent, NOISE_PATTERN, Preamble, decode_frame, decode_inner_frame,
    encode_frame,
};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn decode_hex_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes = hex::decode(s).expect("valid hex");
    bytes.try_into().expect("exact length")
}

#[derive(Deserialize)]
struct FingerprintsVector {
    host_static_scalar_hex: String,
    host_static_pub_hex: String,
    host_device_id: String,
    host_fingerprint: String,
    device_static_scalar_hex: String,
    device_static_pub_hex: String,
    device_id: String,
    device_fingerprint: String,
    raw_pubkey_hex: String,
    raw_host_fingerprint: String,
    raw_device_fingerprint: String,
    raw_device_id: String,
    handshake_hash_hex: String,
    pairing_sas: String,
}

#[derive(Deserialize)]
struct PairingMacCase {
    code: String,
    code_normalized: String,
    kdf_hex: String,
    code_mac_hex: String,
    code_mac_b64url: String,
}

#[derive(Deserialize)]
struct PairingMacVector {
    handshake_hash_hex: String,
    salt_hex: String,
    remote_3group: PairingMacCase,
    lan_2group: PairingMacCase,
}

#[derive(Deserialize)]
struct RotationStep {
    signed_bytes_hex: String,
    record: RotationRecord,
}

#[derive(Deserialize)]
struct RotationVector {
    pinned_signing_pub_hex: String,
    pinned_static_pub_hex: String,
    step2_signing_seed_hex: String,
    step2_static_scalar_hex: String,
    chain: Vec<RotationStep>,
    fork_record: RotationStep,
}

#[derive(Deserialize)]
struct GrantsVector {
    root_issuer_id: String,
    root_signing_pub_hex: String,
    delegate_id: String,
    delegate_signing_pub_hex: String,
    leaf_id: String,
    root_unsorted_json: String,
    root_jcs_json: String,
    root_signed_bytes_hex: String,
    root_grant: Grant,
    delegated_valid: Grant,
    delegated_widened: Grant,
    crl_jcs_json: String,
    crl_signed_bytes_hex: String,
    revocation_list: RevocationList,
}

#[derive(Deserialize)]
struct PairTranscriptVector {
    preamble_hex: String,
    initiator_static_scalar_hex: String,
    initiator_static_pub_hex: String,
    initiator_ephem_scalar_hex: String,
    responder_static_scalar_hex: String,
    responder_static_pub_hex: String,
    responder_ephem_scalar_hex: String,
    host_hello_json: String,
    msg1_frame_hex: String,
    msg2_frame_hex: String,
    post_msg2_handshake_hash_hex: String,
    pairing_code: String,
    pairing_sas: String,
    code_mac_b64url: String,
    pair_claim_json: String,
    msg3_frame_hex: String,
    final_handshake_hash_hex: String,
    pair_response_json: String,
    pair_response_frame_hex: String,
}

#[derive(Deserialize)]
struct SessionTranscriptVector {
    preamble_hex: String,
    initiator_static_scalar_hex: String,
    initiator_ephem_scalar_hex: String,
    responder_static_scalar_hex: String,
    responder_ephem_scalar_hex: String,
    host_hello_json: String,
    msg1_frame_hex: String,
    msg2_frame_hex: String,
    post_msg2_handshake_hash_hex: String,
    session_hello_json: String,
    msg3_frame_hex: String,
    final_handshake_hash_hex: String,
    data_inner_hex: String,
    data_frame_hex: String,
    rekey_inner_hex: String,
    rekey_frame_hex: String,
    post_rekey_data_inner_hex: String,
    post_rekey_data_frame_hex: String,
}

#[derive(Deserialize)]
struct HandshakeVector {
    noise_pattern: String,
    pair_transcript: PairTranscriptVector,
    session_transcript: SessionTranscriptVector,
}

#[test]
fn fingerprints_vector_matches() {
    let raw = fs::read_to_string(vectors_dir().join("fingerprints.json")).unwrap();
    let v: FingerprintsVector = serde_json::from_str(&raw).unwrap();

    let host_scalar: [u8; 32] = decode_hex_array(&v.host_static_scalar_hex);
    let host_pub = x25519_public_from_scalar(&host_scalar);
    assert_eq!(hex::encode(host_pub), v.host_static_pub_hex);
    assert_eq!(device_id(&host_pub), v.host_device_id);
    assert_eq!(fingerprint_host(&host_pub), v.host_fingerprint);

    let dev_scalar: [u8; 32] = decode_hex_array(&v.device_static_scalar_hex);
    let dev_pub = x25519_public_from_scalar(&dev_scalar);
    assert_eq!(hex::encode(dev_pub), v.device_static_pub_hex);
    assert_eq!(device_id(&dev_pub), v.device_id);
    assert_eq!(fingerprint_device(&dev_pub), v.device_fingerprint);

    let raw_pub: [u8; 32] = decode_hex_array(&v.raw_pubkey_hex);
    assert_eq!(fingerprint_host(&raw_pub), v.raw_host_fingerprint);
    assert_eq!(fingerprint_device(&raw_pub), v.raw_device_fingerprint);
    assert_eq!(device_id(&raw_pub), v.raw_device_id);

    let h: [u8; 32] = decode_hex_array(&v.handshake_hash_hex);
    assert_eq!(pairing_sas(&h), v.pairing_sas);

    assert_eq!(
        b64url_decode_array::<32>(&b64url_encode(&[0u8; 31])),
        Err(CoreError::InvalidLength {
            expected: 32,
            actual: 31
        })
    );
}

#[test]
fn pairing_mac_vectors_match() {
    let raw = fs::read_to_string(vectors_dir().join("pairing_mac.json")).unwrap();
    let v: PairingMacVector = serde_json::from_str(&raw).unwrap();
    let h: [u8; 32] = decode_hex_array(&v.handshake_hash_hex);
    assert_eq!(hex::encode(&h[..16]), v.salt_hex);

    for case in [&v.remote_3group, &v.lan_2group] {
        assert_eq!(normalize_code(&case.code), case.code_normalized);
        let kdf = argon2id_pairing_key(&case.code, &h).unwrap();
        assert_eq!(hex::encode(*kdf), case.kdf_hex);
        let mac = compute_code_mac(&case.code, &h).unwrap();
        assert_eq!(hex::encode(mac), case.code_mac_hex);
        let decoded: [u8; 32] = b64url_decode_array(&case.code_mac_b64url).unwrap();
        assert!(verify_code_mac(&case.code, &h, &decoded).unwrap());
        assert!(!verify_code_mac("TND-WRONG-CODE", &h, &decoded).unwrap());
    }
}

#[test]
fn rotation_chain_and_fork_detection_match() {
    let raw = fs::read_to_string(vectors_dir().join("rotation.json")).unwrap();
    let v: RotationVector = serde_json::from_str(&raw).unwrap();

    for step in &v.chain {
        let verified = verify_rotation_record(&step.record).unwrap();
        let bytes = rotation_signed_bytes(
            verified.seq,
            &verified.prev_signing_pub,
            &verified.new_signing_pub,
            &verified.new_static_pub,
            verified.ts_unix,
        );
        assert_eq!(hex::encode(bytes), step.signed_bytes_hex);
    }

    let pinned_signing: [u8; 32] = decode_hex_array(&v.pinned_signing_pub_hex);
    let pinned_static: [u8; 32] = decode_hex_array(&v.pinned_static_pub_hex);
    let step2_seed: [u8; 32] = decode_hex_array(&v.step2_signing_seed_hex);
    let step2_signing_pub = ed25519_dalek::SigningKey::from_bytes(&step2_seed)
        .verifying_key()
        .to_bytes();
    let step2_static_pub = x25519_public_from_scalar(&decode_hex_array(&v.step2_static_scalar_hex));

    let records: Vec<RotationRecord> = v.chain.iter().map(|s| s.record.clone()).collect();
    let seq = verify_rotation_chain(
        &pinned_signing,
        &pinned_static,
        0,
        &records,
        &step2_static_pub,
        &step2_signing_pub,
    )
    .unwrap();
    assert_eq!(seq, 2);

    // Fork at seq 2 must be detected immediately by both helpers.
    verify_rotation_record(&v.fork_record.record).unwrap();
    let mut forked = records.clone();
    forked.push(v.fork_record.record);
    assert_eq!(
        detect_rotation_fork(&forked),
        Err(CoreError::RotationForkDetected { seq: 2 })
    );
    assert_eq!(
        verify_rotation_chain(
            &pinned_signing,
            &pinned_static,
            0,
            &forked,
            &step2_static_pub,
            &step2_signing_pub,
        ),
        Err(CoreError::RotationForkDetected { seq: 2 })
    );

    // Unanchored colliding seq signed by an unrelated key must fail without fork revocation.
    let rogue_sk = ed25519_dalek::SigningKey::from_bytes(&[0xAB; 32]);
    let rogue_rec = sign_rotation(
        2,
        &rogue_sk,
        &step2_signing_pub,
        &step2_static_pub,
        1_795_219_300,
    )
    .unwrap();
    let mut with_unanchored = records;
    with_unanchored.push(rogue_rec);
    let unanchored_res = verify_rotation_chain(
        &pinned_signing,
        &pinned_static,
        0,
        &with_unanchored,
        &step2_static_pub,
        &step2_signing_pub,
    );
    assert!(!matches!(
        unanchored_res,
        Err(CoreError::RotationForkDetected { .. })
    ));
    assert!(unanchored_res.is_err());
}

#[test]
fn grants_and_crl_vectors_match() {
    let raw = fs::read_to_string(vectors_dir().join("grants.json")).unwrap();
    let v: GrantsVector = serde_json::from_str(&raw).unwrap();

    let unsorted: GrantUnsigned = serde_json::from_str(&v.root_unsorted_json).unwrap();
    let jcs = canonical_json(&unsorted).unwrap();
    assert_eq!(jcs, v.root_jcs_json);
    assert_eq!(
        hex::encode(grant_signed_bytes(&unsorted).unwrap()),
        v.root_signed_bytes_hex
    );

    let root_pub: [u8; 32] = decode_hex_array(&v.root_signing_pub_hex);
    let del_pub: [u8; 32] = decode_hex_array(&v.delegate_signing_pub_hex);
    verify_grant_signature(&v.root_grant, &root_pub).unwrap();
    verify_grant_signature(&v.delegated_valid, &del_pub).unwrap();
    verify_delegation_subset(&v.delegated_valid, &v.root_grant).unwrap();

    // Valid delegated grant passes chain evaluation at 2026-11-25T00:00:00Z (1795564800)
    verify_crl_signature(&v.revocation_list, &root_pub).unwrap();
    assert_eq!(
        canonical_json(&v.revocation_list.unsigned()).unwrap(),
        v.crl_jcs_json
    );
    assert_eq!(
        hex::encode(crl_signed_bytes(&v.revocation_list.unsigned()).unwrap()),
        v.crl_signed_bytes_hex
    );

    let lookup = |issuer: &str| -> Option<[u8; 32]> {
        if issuer == v.root_issuer_id {
            Some(root_pub)
        } else if issuer == v.delegate_id {
            Some(del_pub)
        } else {
            None
        }
    };

    verify_grant_with_chain(
        &v.delegated_valid,
        &v.leaf_id,
        &v.root_issuer_id,
        1_795_564_800,
        Some(&v.revocation_list),
        lookup,
    )
    .unwrap();

    assert!(
        grant_allows(
            &v.delegated_valid,
            &Capability::parse("fs.read:/photos/2026/a.jpg").unwrap()
        )
        .unwrap()
    );
    assert!(
        !grant_allows(
            &v.delegated_valid,
            &Capability::parse("fs.read:/photos/2025/a.jpg").unwrap()
        )
        .unwrap()
    );
    assert!(
        !grant_allows(
            &v.delegated_valid,
            &Capability::parse("fs.write:/photos/2026/a.jpg").unwrap()
        )
        .unwrap()
    );

    // Widened child grant must fail both subset check and chain evaluation.
    assert!(matches!(
        verify_delegation_subset(&v.delegated_widened, &v.root_grant),
        Err(CoreError::DelegationDenied(_))
    ));
    assert!(matches!(
        verify_grant_with_chain(
            &v.delegated_widened,
            &v.leaf_id,
            &v.root_issuer_id,
            1_795_564_800,
            Some(&v.revocation_list),
            lookup
        ),
        Err(CoreError::DelegationDenied(_))
    ));

    // Active non-root peer cannot self-sign a forged root grant.
    let rogue_sk = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let rogue_pub = rogue_sk.verifying_key().to_bytes();
    let rogue_id = "dev_eeeeeeeeeeeeeeee";
    let rogue_grant = sign_grant(
        GrantUnsigned {
            v: 1,
            issuer: rogue_id.to_string(),
            subject: rogue_id.to_string(),
            caps: vec!["fs.read:/photos/*".to_string()],
            not_before: "2026-11-20T00:00:00Z".to_string(),
            not_after: "2026-12-20T00:00:00Z".to_string(),
            nonce: "rogue_nonce_0000000001".to_string(),
            delegated_from: vec![],
            uses: None,
            machine: None,
        },
        &rogue_sk,
    )
    .unwrap();
    let lookup_with_rogue = |issuer: &str| -> Option<[u8; 32]> {
        if issuer == rogue_id {
            Some(rogue_pub)
        } else {
            lookup(issuer)
        }
    };
    assert!(matches!(
        verify_grant_with_chain(
            &rogue_grant,
            rogue_id,
            &v.root_issuer_id,
            1_795_564_800,
            Some(&v.revocation_list),
            lookup_with_rogue,
        ),
        Err(CoreError::GrantDenied(_))
    ));
}

#[test]
fn handshake_transcript_vectors_match() {
    let raw = fs::read_to_string(vectors_dir().join("handshake.json")).unwrap();
    let v: HandshakeVector = serde_json::from_str(&raw).unwrap();
    assert_eq!(v.noise_pattern, NOISE_PATTERN);

    let params: NoiseParams = v.noise_pattern.parse().unwrap();
    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let mut pt = vec![0u8; MAX_FRAME_LEN];

    // Pair transcript
    let p = &v.pair_transcript;
    let preamble = hex::decode(&p.preamble_hex).unwrap();
    assert_eq!(
        Preamble::decode(&preamble).unwrap(),
        Preamble::v1(Intent::Pair)
    );

    let init_s = decode_hex_array::<32>(&p.initiator_static_scalar_hex);
    let init_e = decode_hex_array::<32>(&p.initiator_ephem_scalar_hex);
    let resp_s = decode_hex_array::<32>(&p.responder_static_scalar_hex);
    let resp_e = decode_hex_array::<32>(&p.responder_ephem_scalar_hex);

    let mut init = Builder::new(params.clone())
        .local_private_key(&init_s)
        .unwrap()
        .prologue(&preamble)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&init_e)
        .build_initiator()
        .unwrap();
    let mut resp = Builder::new(params.clone())
        .local_private_key(&resp_s)
        .unwrap()
        .prologue(&preamble)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&resp_e)
        .build_responder()
        .unwrap();

    let n1 = init.write_message(&[], &mut buf).unwrap();
    let f1 = encode_frame(&buf[..n1]).unwrap();
    assert_eq!(hex::encode(&f1), p.msg1_frame_hex);
    let (b1, _) = decode_frame(&f1).unwrap();
    resp.read_message(b1, &mut pt).unwrap();

    let n2 = resp
        .write_message(p.host_hello_json.as_bytes(), &mut buf)
        .unwrap();
    let f2 = encode_frame(&buf[..n2]).unwrap();
    assert_eq!(hex::encode(&f2), p.msg2_frame_hex);
    let (b2, _) = decode_frame(&f2).unwrap();
    let n_pt2 = init.read_message(b2, &mut pt).unwrap();
    assert_eq!(&pt[..n_pt2], p.host_hello_json.as_bytes());
    assert_eq!(
        hex::encode(init.get_remote_static().unwrap()),
        p.responder_static_pub_hex
    );

    let h: [u8; 32] = init.get_handshake_hash().try_into().unwrap();
    assert_eq!(hex::encode(h), p.post_msg2_handshake_hash_hex);
    assert_eq!(pairing_sas(&h), p.pairing_sas);
    let mac = b64url_decode_array::<32>(&p.code_mac_b64url).unwrap();
    assert!(verify_code_mac(&p.pairing_code, &h, &mac).unwrap());

    let n3 = init
        .write_message(p.pair_claim_json.as_bytes(), &mut buf)
        .unwrap();
    let f3 = encode_frame(&buf[..n3]).unwrap();
    assert_eq!(hex::encode(&f3), p.msg3_frame_hex);
    let (b3, _) = decode_frame(&f3).unwrap();
    let n_pt3 = resp.read_message(b3, &mut pt).unwrap();
    assert_eq!(&pt[..n_pt3], p.pair_claim_json.as_bytes());
    assert_eq!(
        hex::encode(resp.get_remote_static().unwrap()),
        p.initiator_static_pub_hex
    );
    assert_eq!(
        hex::encode(init.get_handshake_hash()),
        p.final_handshake_hash_hex
    );

    let mut init_tx = init.into_transport_mode().unwrap();
    let mut resp_tx = resp.into_transport_mode().unwrap();
    let n4 = resp_tx
        .write_message(p.pair_response_json.as_bytes(), &mut buf)
        .unwrap();
    let f4 = encode_frame(&buf[..n4]).unwrap();
    assert_eq!(hex::encode(&f4), p.pair_response_frame_hex);
    let (b4, _) = decode_frame(&f4).unwrap();
    let n_pt4 = init_tx.read_message(b4, &mut pt).unwrap();
    assert_eq!(&pt[..n_pt4], p.pair_response_json.as_bytes());

    // Session transcript + REKEY
    let s = &v.session_transcript;
    let s_pre = hex::decode(&s.preamble_hex).unwrap();
    assert_eq!(
        Preamble::decode(&s_pre).unwrap(),
        Preamble::v1(Intent::Session)
    );

    let mut s_init = Builder::new(params.clone())
        .local_private_key(&decode_hex_array::<32>(&s.initiator_static_scalar_hex))
        .unwrap()
        .prologue(&s_pre)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&decode_hex_array::<32>(
            &s.initiator_ephem_scalar_hex,
        ))
        .build_initiator()
        .unwrap();
    let mut s_resp = Builder::new(params)
        .local_private_key(&decode_hex_array::<32>(&s.responder_static_scalar_hex))
        .unwrap()
        .prologue(&s_pre)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&decode_hex_array::<32>(
            &s.responder_ephem_scalar_hex,
        ))
        .build_responder()
        .unwrap();

    let sn1 = s_init.write_message(&[], &mut buf).unwrap();
    let sf1 = encode_frame(&buf[..sn1]).unwrap();
    assert_eq!(hex::encode(&sf1), s.msg1_frame_hex);
    s_resp
        .read_message(decode_frame(&sf1).unwrap().0, &mut pt)
        .unwrap();

    let sn2 = s_resp
        .write_message(s.host_hello_json.as_bytes(), &mut buf)
        .unwrap();
    let sf2 = encode_frame(&buf[..sn2]).unwrap();
    assert_eq!(hex::encode(&sf2), s.msg2_frame_hex);
    let sn_pt2 = s_init
        .read_message(decode_frame(&sf2).unwrap().0, &mut pt)
        .unwrap();
    let s_host_hello: HostHello = serde_json::from_slice(&pt[..sn_pt2]).unwrap();
    let presented_static: [u8; 32] = s_init.get_remote_static().unwrap().try_into().unwrap();
    // Initiator must verify host static pin or rotation before writing msg3.
    let mismatched_pin = [0xFF; 32];
    assert_eq!(
        verify_rotation_chain(
            &mismatched_pin,
            &mismatched_pin,
            0,
            &s_host_hello.rotation,
            &presented_static,
            &mismatched_pin,
        ),
        Err(CoreError::RotationEmptyChain)
    );
    assert_eq!(
        hex::encode(s_init.get_handshake_hash()),
        s.post_msg2_handshake_hash_hex
    );

    let sn3 = s_init
        .write_message(s.session_hello_json.as_bytes(), &mut buf)
        .unwrap();
    let sf3 = encode_frame(&buf[..sn3]).unwrap();
    assert_eq!(hex::encode(&sf3), s.msg3_frame_hex);
    s_resp
        .read_message(decode_frame(&sf3).unwrap().0, &mut pt)
        .unwrap();
    assert_eq!(
        hex::encode(s_init.get_handshake_hash()),
        s.final_handshake_hash_hex
    );

    let mut s_init_tx = s_init.into_transport_mode().unwrap();
    let mut s_resp_tx = s_resp.into_transport_mode().unwrap();

    let data_pt = hex::decode(&s.data_inner_hex).unwrap();
    let nd = s_init_tx.write_message(&data_pt, &mut buf).unwrap();
    let df = encode_frame(&buf[..nd]).unwrap();
    assert_eq!(hex::encode(&df), s.data_frame_hex);
    let nd_pt = s_resp_tx
        .read_message(decode_frame(&df).unwrap().0, &mut pt)
        .unwrap();
    assert_eq!(
        decode_inner_frame(&pt[..nd_pt]).unwrap(),
        (InnerFrameType::Data, b"hello tendril".as_slice())
    );

    let rekey_pt = hex::decode(&s.rekey_inner_hex).unwrap();
    let nr = s_init_tx.write_message(&rekey_pt, &mut buf).unwrap();
    let rf = encode_frame(&buf[..nr]).unwrap();
    assert_eq!(hex::encode(&rf), s.rekey_frame_hex);
    s_init_tx.rekey_outgoing();
    let nr_pt = s_resp_tx
        .read_message(decode_frame(&rf).unwrap().0, &mut pt)
        .unwrap();
    assert_eq!(
        decode_inner_frame(&pt[..nr_pt]).unwrap(),
        (InnerFrameType::Rekey, [].as_slice())
    );
    s_resp_tx.rekey_incoming();

    let post_pt = hex::decode(&s.post_rekey_data_inner_hex).unwrap();
    let np = s_init_tx.write_message(&post_pt, &mut buf).unwrap();
    let pf = encode_frame(&buf[..np]).unwrap();
    assert_eq!(hex::encode(&pf), s.post_rekey_data_frame_hex);
    let np_pt = s_resp_tx
        .read_message(decode_frame(&pf).unwrap().0, &mut pt)
        .unwrap();
    assert_eq!(
        decode_inner_frame(&pt[..np_pt]).unwrap(),
        (InnerFrameType::Data, b"after rekey".as_slice())
    );
}
