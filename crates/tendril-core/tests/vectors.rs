//! Verifies all canonical v1 vectors under `spec/vectors/*.json` and negative cases.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{
    HYBRID_SIG_LEN, HybridSigningPublicKey, SigningKeypair, argon2id_pairing_key, b64url_decode,
    b64url_decode_array, b64url_encode, compute_code_mac, device_id, fingerprint_device,
    fingerprint_host, normalize_code, pairing_sas, verify_code_mac, x25519_public_from_scalar,
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
use tendril_core::noise::{NoiseHfsHandshakeBuilder, NoiseHfsSeeds};
use tendril_core::pairing::{
    ENROLL_PROOF_DOMAIN, EnrollmentPolicy, enroll_proof_bytes, sign_enroll_proof_deterministic,
    verify_enroll_proof, verify_enrollment_token,
};
use tendril_core::relay_auth::{
    RelayAuthProof, RelayAuthRole, RelayTicket, compute_relay_auth_hmac,
    compute_relay_auth_hmac_b64, relay_auth_hmac_input, relay_ticket_jcs,
    relay_ticket_signed_bytes, verify_relay_auth_hmac, verify_relay_ticket,
};
use tendril_core::roster::Roster;
use tendril_core::v2::{
    PAKE_ARGON2_MEMORY_KIB, PAKE_ARGON2_PARALLELISM, PAKE_ARGON2_TIME, PaddingPolicy,
    PakeArgon2Params, V2_PAKE_SALT_LEN, V2InnerFrame, canonical_relay_host, compute_pake_init_mac,
    compute_pake_msg1_mac, compute_pake_resp_mac, compute_rendezvous_mac, decode_v2_inner_frame,
    derive_epoch_mailbox, derive_pake_keys, derive_pake_master, encode_dummy_cover_frame,
    epoch_for_unix, pad_inner_frame, pad_msg3_payload, pad_pake_msg3_payload,
    pake_msg2_bucket_for_hello_len, pake_noise_prologue, seal_pake_host_hello,
    seal_v2_hello_envelope, sign_v2_relay_accept, sign_v2_relay_dial, sign_v2_relay_register,
    unpad_inner_frame, unpad_msg3_payload, unpad_pake_msg3_payload, unseal_pake_host_hello,
    unseal_v2_hello_envelope, v2_relay_accept_signed_bytes, v2_relay_dial_signed_bytes,
    v2_relay_register_signed_bytes, verify_rendezvous_mac, verify_v2_relay_accept,
    verify_v2_relay_dial, verify_v2_relay_register,
};
use tendril_core::wire::{
    HostHello, InnerFrameType, Intent, NOISE_PATTERN, PREAMBLE_FLAG_NONE, PairResponse, Preamble,
    WIRE_VERSION_V2, decode_frame, decode_inner_frame, encode_frame,
};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn decode_hex_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes = hex::decode(s).expect("valid hex");
    bytes.try_into().expect("exact length")
}

fn decode_hybrid_pub(s: &str) -> HybridSigningPublicKey {
    let bytes = hex::decode(s).expect("valid hex");
    HybridSigningPublicKey::from_bytes(&bytes).expect("valid hybrid signing public key")
}

fn init_hfs_seeds(ephem_hex: &str, keygen_seed_hex: &str) -> NoiseHfsSeeds {
    let keygen = decode_hex_array::<64>(keygen_seed_hex);
    NoiseHfsSeeds {
        x25519: decode_hex_array::<32>(ephem_hex),
        mlkem_d: keygen[..32].try_into().unwrap(),
        mlkem_z: keygen[32..].try_into().unwrap(),
        mlkem_m: [0u8; 32],
    }
}

fn resp_hfs_seeds(ephem_hex: &str, encaps_seed_hex: &str) -> NoiseHfsSeeds {
    NoiseHfsSeeds {
        x25519: decode_hex_array::<32>(ephem_hex),
        mlkem_d: [0u8; 32],
        mlkem_z: [0u8; 32],
        mlkem_m: decode_hex_array::<32>(encaps_seed_hex),
    }
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
    step2_signing_mldsa_seed_hex: String,
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
    initiator_mlkem768_keygen_seed_hex: String,
    responder_static_scalar_hex: String,
    responder_static_pub_hex: String,
    responder_ephem_scalar_hex: String,
    responder_mlkem768_encaps_seed_hex: String,
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
    initiator_mlkem768_keygen_seed_hex: String,
    responder_static_scalar_hex: String,
    responder_ephem_scalar_hex: String,
    responder_mlkem768_encaps_seed_hex: String,
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

    let pinned_signing = decode_hybrid_pub(&v.pinned_signing_pub_hex);
    let pinned_static: [u8; 32] = decode_hex_array(&v.pinned_static_pub_hex);
    let step2_signing_pub = SigningKeypair::from_seeds(
        decode_hex_array::<32>(&v.step2_signing_seed_hex),
        decode_hex_array::<32>(&v.step2_signing_mldsa_seed_hex),
    )
    .public_key()
    .clone();
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
    let rogue_sk = SigningKeypair::from_seed([0xAB; 32]);
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

    let root_pub = decode_hybrid_pub(&v.root_signing_pub_hex);
    let del_pub = decode_hybrid_pub(&v.delegate_signing_pub_hex);
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

    let lookup = |issuer: &str| -> Option<HybridSigningPublicKey> {
        if issuer == v.root_issuer_id {
            Some(root_pub.clone())
        } else if issuer == v.delegate_id {
            Some(del_pub.clone())
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
    let rogue_sk = SigningKeypair::from_seed([0xEE; 32]);
    let rogue_pub = rogue_sk.public_key().clone();
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
    let lookup_with_rogue = |issuer: &str| -> Option<HybridSigningPublicKey> {
        if issuer == rogue_id {
            Some(rogue_pub.clone())
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
    let resp_s = decode_hex_array::<32>(&p.responder_static_scalar_hex);

    let mut init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&init_s)
        .prologue(&preamble)
        .fixed_hfs_seeds_for_testing_only(init_hfs_seeds(
            &p.initiator_ephem_scalar_hex,
            &p.initiator_mlkem768_keygen_seed_hex,
        ))
        .build_initiator()
        .unwrap();
    let mut resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&resp_s)
        .prologue(&preamble)
        .fixed_hfs_seeds_for_testing_only(resp_hfs_seeds(
            &p.responder_ephem_scalar_hex,
            &p.responder_mlkem768_encaps_seed_hex,
        ))
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

    let h: [u8; 32] = *init.get_handshake_hash();
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

    let mut s_init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&decode_hex_array::<32>(&s.initiator_static_scalar_hex))
        .prologue(&s_pre)
        .fixed_hfs_seeds_for_testing_only(init_hfs_seeds(
            &s.initiator_ephem_scalar_hex,
            &s.initiator_mlkem768_keygen_seed_hex,
        ))
        .build_initiator()
        .unwrap();
    let mut s_resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&decode_hex_array::<32>(&s.responder_static_scalar_hex))
        .prologue(&s_pre)
        .fixed_hfs_seeds_for_testing_only(resp_hfs_seeds(
            &s.responder_ephem_scalar_hex,
            &s.responder_mlkem768_encaps_seed_hex,
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
    let presented_static: [u8; 32] = *s_init.get_remote_static().unwrap();
    // Initiator must verify host static pin or rotation before writing msg3.
    let mismatched_static = [0xFF; 32];
    let mismatched_signing = SigningKeypair::from_seed([0xFF; 32]).public_key().clone();
    assert_eq!(
        verify_rotation_chain(
            &mismatched_signing,
            &mismatched_static,
            0,
            &s_host_hello.rotation,
            &presented_static,
            &mismatched_signing,
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
    s_init_tx.rekey_outgoing().unwrap();
    let nr_pt = s_resp_tx
        .read_message(decode_frame(&rf).unwrap().0, &mut pt)
        .unwrap();
    assert_eq!(
        decode_inner_frame(&pt[..nr_pt]).unwrap(),
        (InnerFrameType::Rekey, [].as_slice())
    );
    s_resp_tx.rekey_incoming().unwrap();

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

#[derive(Deserialize)]
struct M2mEnrollmentVector {
    noise_pattern: String,
    preamble_hex: String,
    now_unix: u64,
    anchor_id: String,
    anchor_signing_pub_hex: String,
    responder_host_id: String,
    responder_static_scalar_hex: String,
    responder_static_pub_hex: String,
    responder_ephem_scalar_hex: String,
    responder_mlkem768_encaps_seed_hex: String,
    responder_signing_pub_hex: String,
    initiator_static_scalar_hex: String,
    initiator_static_pub_hex: String,
    initiator_device_id: String,
    initiator_ephem_scalar_hex: String,
    initiator_mlkem768_keygen_seed_hex: String,
    initiator_signing_seed_hex: String,
    initiator_signing_mldsa_seed_hex: String,
    initiator_signing_pub_hex: String,
    token_jcs_json: String,
    token_signed_bytes_hex: String,
    enrollment_token: Grant,
    host_hello_json: String,
    msg1_frame_hex: String,
    msg2_frame_hex: String,
    post_msg2_handshake_hash_hex: String,
    enroll_proof_domain_hex: String,
    enroll_proof_bytes_hex: String,
    enroll_proof_b64url: String,
    pair_claim_json: String,
    msg3_frame_hex: String,
    final_handshake_hash_hex: String,
    pair_response_json: String,
    pair_response_frame_hex: String,
    replayed_response_json: String,
}

#[test]
fn m2m_enrollment_vectors_match() {
    let raw = fs::read_to_string(vectors_dir().join("m2m_enrollment.json")).unwrap();
    let v: M2mEnrollmentVector = serde_json::from_str(&raw).unwrap();
    assert_eq!(v.noise_pattern, NOISE_PATTERN);

    let pre = hex::decode(&v.preamble_hex).unwrap();
    assert_eq!(Preamble::decode(&pre).unwrap(), Preamble::v1(Intent::Pair));

    let anchor_pub = decode_hybrid_pub(&v.anchor_signing_pub_hex);
    let resp_static_pub = decode_hex_array::<32>(&v.responder_static_pub_hex);
    let resp_signing_pub = decode_hybrid_pub(&v.responder_signing_pub_hex);
    let init_static_pub = decode_hex_array::<32>(&v.initiator_static_pub_hex);
    let init_signing_pub = decode_hybrid_pub(&v.initiator_signing_pub_hex);
    assert_eq!(device_id(&init_static_pub), v.initiator_device_id);
    assert_eq!(device_id(&resp_static_pub), v.responder_host_id);

    let unsigned = v.enrollment_token.unsigned();
    assert_eq!(canonical_json(&unsigned).unwrap(), v.token_jcs_json);
    assert_eq!(
        hex::encode(grant_signed_bytes(&unsigned).unwrap()),
        v.token_signed_bytes_hex
    );
    verify_grant_signature(&v.enrollment_token, &anchor_pub).unwrap();

    // Purpose separation: enrollment tokens must NEVER verify as regular session grants.
    let err = verify_grant_with_chain(
        &v.enrollment_token,
        &v.initiator_device_id,
        &v.anchor_id,
        v.now_unix,
        None,
        |id| (id == v.anchor_id).then(|| anchor_pub.clone()),
    );
    assert!(matches!(err, Err(CoreError::GrantDenied(_))));

    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let mut pt = vec![0u8; MAX_FRAME_LEN];
    let mut init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&decode_hex_array::<32>(&v.initiator_static_scalar_hex))
        .prologue(&pre)
        .fixed_hfs_seeds_for_testing_only(init_hfs_seeds(
            &v.initiator_ephem_scalar_hex,
            &v.initiator_mlkem768_keygen_seed_hex,
        ))
        .build_initiator()
        .unwrap();
    let mut resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&decode_hex_array::<32>(&v.responder_static_scalar_hex))
        .prologue(&pre)
        .fixed_hfs_seeds_for_testing_only(resp_hfs_seeds(
            &v.responder_ephem_scalar_hex,
            &v.responder_mlkem768_encaps_seed_hex,
        ))
        .build_responder()
        .unwrap();

    let n1 = init.write_message(&[], &mut buf).unwrap();
    let f1 = encode_frame(&buf[..n1]).unwrap();
    assert_eq!(hex::encode(&f1), v.msg1_frame_hex);
    resp.read_message(decode_frame(&f1).unwrap().0, &mut pt)
        .unwrap();

    let n2 = resp
        .write_message(v.host_hello_json.as_bytes(), &mut buf)
        .unwrap();
    let f2 = encode_frame(&buf[..n2]).unwrap();
    assert_eq!(hex::encode(&f2), v.msg2_frame_hex);
    let npt2 = init
        .read_message(decode_frame(&f2).unwrap().0, &mut pt)
        .unwrap();
    assert_eq!(&pt[..npt2], v.host_hello_json.as_bytes());

    let h: [u8; 32] = *init.get_handshake_hash();
    assert_eq!(hex::encode(h), v.post_msg2_handshake_hash_hex);
    assert_eq!(hex::encode(ENROLL_PROOF_DOMAIN), v.enroll_proof_domain_hex);
    let expected_proof_bytes = enroll_proof_bytes(&h, &init_static_pub, &v.enrollment_token.nonce);
    assert_eq!(hex::encode(&expected_proof_bytes), v.enroll_proof_bytes_hex);
    let proof_sig = b64url_decode(&v.enroll_proof_b64url).unwrap();
    assert_eq!(proof_sig.len(), HYBRID_SIG_LEN);
    verify_enroll_proof(
        &init_signing_pub,
        &h,
        &init_static_pub,
        &v.enrollment_token.nonce,
        &proof_sig,
    )
    .unwrap();

    let n3 = init
        .write_message(v.pair_claim_json.as_bytes(), &mut buf)
        .unwrap();
    let f3 = encode_frame(&buf[..n3]).unwrap();
    assert_eq!(hex::encode(&f3), v.msg3_frame_hex);
    let npt3 = resp
        .read_message(decode_frame(&f3).unwrap().0, &mut pt)
        .unwrap();
    assert_eq!(&pt[..npt3], v.pair_claim_json.as_bytes());
    assert_eq!(
        hex::encode(init.get_handshake_hash()),
        v.final_handshake_hash_hex
    );

    let mut init_tx = init.into_transport_mode().unwrap();
    let mut resp_tx = resp.into_transport_mode().unwrap();
    let n4 = resp_tx
        .write_message(v.pair_response_json.as_bytes(), &mut buf)
        .unwrap();
    let f4 = encode_frame(&buf[..n4]).unwrap();
    assert_eq!(hex::encode(&f4), v.pair_response_frame_hex);
    let npt4 = init_tx
        .read_message(decode_frame(&f4).unwrap().0, &mut pt)
        .unwrap();
    assert_eq!(&pt[..npt4], v.pair_response_json.as_bytes());
    let parsed_resp: PairResponse = serde_json::from_slice(&pt[..npt4]).unwrap();
    assert!(matches!(
        parsed_resp,
        PairResponse::Success { ref status, .. } if status == "active"
    ));

    // Also run the state machines end-to-end with the vector keys to verify replay rejection.
    let mut roster = Roster::new();
    roster
        .add_trust_anchor(v.anchor_id.clone(), anchor_pub)
        .unwrap();
    verify_enrollment_token(
        &v.enrollment_token,
        &v.responder_host_id,
        &resp_signing_pub,
        &v.initiator_device_id,
        v.now_unix,
        &EnrollmentPolicy::enabled_default(),
        &roster,
    )
    .unwrap();

    let init_signing = SigningKeypair::from_seeds(
        decode_hex_array::<32>(&v.initiator_signing_seed_hex),
        decode_hex_array::<32>(&v.initiator_signing_mldsa_seed_hex),
    );
    assert_eq!(init_signing.public_key(), &init_signing_pub);
    let expected_sig = sign_enroll_proof_deterministic(
        &init_signing,
        &h,
        &init_static_pub,
        &v.enrollment_token.nonce,
    )
    .unwrap();
    assert_eq!(b64url_encode(&expected_sig), v.enroll_proof_b64url);

    let (_, na) = verify_enrollment_token(
        &v.enrollment_token,
        &v.responder_host_id,
        &resp_signing_pub,
        &v.initiator_device_id,
        v.now_unix,
        &EnrollmentPolicy::enabled_default(),
        &roster,
    )
    .unwrap();
    roster
        .burn_enrollment_nonce(&v.enrollment_token.nonce, na, v.now_unix)
        .unwrap();
    assert_eq!(
        verify_enrollment_token(
            &v.enrollment_token,
            &v.responder_host_id,
            &resp_signing_pub,
            &v.initiator_device_id,
            v.now_unix,
            &EnrollmentPolicy::enabled_default(),
            &roster,
        ),
        Err(CoreError::EnrollmentTokenReplayed)
    );
    assert_eq!(
        serde_json::from_str::<PairResponse>(&v.replayed_response_json).unwrap(),
        PairResponse::Error {
            error: "token_replayed".to_string(),
        }
    );
}

#[derive(Deserialize)]
struct BlindedRelayVector {
    mailbox_secret_hex: String,
    unix_secs: u64,
    epoch: u64,
    epoch_signing_seed_hex: String,
    dial_auth_key_hex: String,
    mailbox_id_hex: String,
    mailbox_id_b64url: String,
    relay_host_raw: String,
    relay_host_canonical: String,
    challenge_nonce_hex: String,
    conn_id_hex: String,
    register_signed_bytes_hex: String,
    register_sig_hex: String,
    register_sig_b64url: String,
    dial_mac_input_hex: String,
    dial_token_hex: String,
    dial_token_b64url: String,
    accept_signed_bytes_hex: String,
    accept_sig_hex: String,
    accept_sig_b64url: String,
}

#[derive(Deserialize)]
struct RelayAdmissionVector {
    shared_secret_hex: String,
    op: String,
    dial_op: String,
    accept_op: String,
    relay_host_raw: String,
    relay_host_canonical: String,
    challenge_nonce_hex: String,
    pub_or_target_hex: String,
    hmac_input_hex: String,
    hmac_mac_hex: String,
    hmac_mac_b64url: String,
    dial_hmac_input_hex: String,
    dial_hmac_mac_hex: String,
    accept_hmac_input_hex: String,
    accept_hmac_mac_hex: String,
    ticket_issuer_pub_hex: String,
    ticket_now_unix: u64,
    ticket_jcs_json: String,
    ticket_signed_bytes_hex: String,
    ticket_sig_hex: String,
    ticket: RelayTicket,
    ticket_proof_json: String,
    hmac_proof_json: String,
}

#[derive(Deserialize)]
struct V2ReconnectVector {
    preamble_hex: String,
    initiator_static_scalar_hex: String,
    initiator_static_pub_hex: String,
    initiator_ephem_scalar_hex: String,
    initiator_mlkem768_keygen_seed_hex: String,
    responder_static_scalar_hex: String,
    responder_static_pub_hex: String,
    responder_ephem_scalar_hex: String,
    responder_mlkem768_encaps_seed_hex: String,
    responder_signing_pub_hex: String,
    reconnect_secret_hex: String,
    rendezvous_nonce_hex: String,
    ts_unix: u64,
    ekem_i_hash_hex: String,
    rendezvous_mac_hex: String,
    msg1_payload_hex: String,
    msg1_frame_hex: String,
    host_hello_json: String,
    bucket_len: usize,
    hello_seal_key_hex: String,
    pre_msg2_handshake_hash_hex: String,
    sealed_hello_envelope_hex: String,
    msg2_frame_hex: String,
    post_msg2_handshake_hash_hex: String,
    session_hello_json: String,
    msg3_padded_payload_hex: String,
    msg3_frame_hex: String,
    final_handshake_hash_hex: String,
    padded_data_payload_hex: String,
    padded_inner_hex: String,
    padded_frame_hex: String,
    cover_bucket_len: usize,
    cover_inner_hex: String,
    cover_frame_hex: String,
    exported_reconnect_secret_hex: String,
    exported_mailbox_secret_hex: String,
}

#[derive(Deserialize)]
struct V2PakeArgon2Spec {
    t: u32,
    m_kib: u32,
    p: u32,
    key_len: usize,
}

#[derive(Deserialize)]
struct V2PakeVector {
    preamble_hex: String,
    code: String,
    code_normalized: String,
    channel_salt_hex: String,
    argon2id: V2PakeArgon2Spec,
    master_pake_hex: String,
    pake_prologue_key_hex: String,
    pake_init_key_hex: String,
    pake_hello_key_hex: String,
    pake_confirm_key_hex: String,
    pake_context_tag_hex: String,
    noise_prologue_hex: String,
    initiator_static_scalar_hex: String,
    initiator_static_pub_hex: String,
    initiator_ephem_scalar_hex: String,
    initiator_mlkem768_keygen_seed_hex: String,
    responder_static_scalar_hex: String,
    responder_static_pub_hex: String,
    responder_ephem_scalar_hex: String,
    responder_mlkem768_encaps_seed_hex: String,
    responder_signing_pub_hex: String,
    ekem_i_hash_hex: String,
    init_mac_hex: String,
    msg1_payload_hex: String,
    msg1_frame_hex: String,
    host_hello_json: String,
    msg2_bucket_len: usize,
    pre_msg2_handshake_hash_hex: String,
    sealed_host_hello_hex: String,
    resp_confirm_mac_hex: String,
    msg2_payload_hex: String,
    msg2_frame_hex: String,
    post_msg2_handshake_hash_hex: String,
    pairing_sas: String,
    pair_claim_json: String,
    init_confirm_mac_hex: String,
    msg3_payload_hex: String,
    msg3_frame_hex: String,
    final_handshake_hash_hex: String,
    pair_response_json: String,
    pair_response_payload_hex: String,
    pair_response_frame_hex: String,
    exported_reconnect_secret_hex: String,
    exported_mailbox_secret_hex: String,
}

#[derive(Deserialize)]
struct WireV2Vector {
    noise_pattern: String,
    v2_session_preamble_hex: String,
    v2_pake_pair_preamble_hex: String,
    blinded_relay: BlindedRelayVector,
    relay_admission: RelayAdmissionVector,
    v2_reconnect: V2ReconnectVector,
    pake_pairing: V2PakeVector,
}

#[test]
fn wire_v2_vectors_match_byte_for_byte() {
    use sha2::{Digest, Sha256};
    use tendril_core::crypto::hkdf_sha256_32;

    let raw = fs::read_to_string(vectors_dir().join("wire_v2.json")).unwrap();
    let v: WireV2Vector = serde_json::from_str(&raw).unwrap();
    assert_eq!(v.noise_pattern, NOISE_PATTERN);

    let expected_session_pre = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    let expected_pake_pre = Preamble::v2_pake_pair().encode();
    assert_eq!(hex::encode(expected_session_pre), v.v2_session_preamble_hex);
    assert_eq!(hex::encode(expected_pake_pre), v.v2_pake_pair_preamble_hex);

    // 1. Blinded /v2/relay hourly epoch
    let br = &v.blinded_relay;
    let mailbox_secret = decode_hex_array::<32>(&br.mailbox_secret_hex);
    let epoch = epoch_for_unix(br.unix_secs);
    assert_eq!(epoch, br.epoch);
    let mailbox = derive_epoch_mailbox(&mailbox_secret, epoch);
    assert_eq!(
        hex::encode(mailbox.signing_key().to_bytes()),
        br.epoch_signing_seed_hex
    );
    assert_eq!(hex::encode(mailbox.dial_auth_key()), br.dial_auth_key_hex);
    assert_eq!(hex::encode(mailbox.mailbox_id), br.mailbox_id_hex);
    assert_eq!(b64url_encode(&mailbox.mailbox_id), br.mailbox_id_b64url);
    assert_eq!(
        canonical_relay_host(&br.relay_host_raw).unwrap(),
        br.relay_host_canonical
    );

    let challenge_nonce = decode_hex_array::<32>(&br.challenge_nonce_hex);
    let conn_id = decode_hex_array::<16>(&br.conn_id_hex);
    let reg_bytes =
        v2_relay_register_signed_bytes(&br.relay_host_raw, &challenge_nonce, epoch).unwrap();
    assert_eq!(hex::encode(&reg_bytes), br.register_signed_bytes_hex);
    let reg_sig = sign_v2_relay_register(&mailbox, &br.relay_host_raw, &challenge_nonce).unwrap();
    assert_eq!(hex::encode(reg_sig), br.register_sig_hex);
    assert_eq!(b64url_encode(&reg_sig), br.register_sig_b64url);
    verify_v2_relay_register(
        &mailbox.mailbox_id,
        epoch,
        &br.relay_host_canonical,
        &challenge_nonce,
        &reg_sig,
    )
    .unwrap();

    // Tamper register signature
    let mut bad_reg_sig = reg_sig;
    bad_reg_sig[0] ^= 0x01;
    assert_eq!(
        verify_v2_relay_register(
            &mailbox.mailbox_id,
            epoch,
            &br.relay_host_canonical,
            &challenge_nonce,
            &bad_reg_sig
        ),
        Err(CoreError::InvalidSignature)
    );

    let dial_bytes = v2_relay_dial_signed_bytes(
        &br.relay_host_raw,
        &challenge_nonce,
        &mailbox.mailbox_id,
        &conn_id,
        epoch,
    )
    .unwrap();
    assert_eq!(hex::encode(&dial_bytes), br.dial_mac_input_hex);
    let dial_token =
        sign_v2_relay_dial(&mailbox, &br.relay_host_raw, &challenge_nonce, &conn_id).unwrap();
    assert_eq!(hex::encode(dial_token), br.dial_token_hex);
    assert_eq!(b64url_encode(&dial_token), br.dial_token_b64url);
    verify_v2_relay_dial(
        &mailbox,
        &br.relay_host_canonical,
        &challenge_nonce,
        &conn_id,
        &dial_token,
    )
    .unwrap();
    assert_eq!(
        verify_v2_relay_dial(
            &mailbox,
            "wrong.relay.test",
            &challenge_nonce,
            &conn_id,
            &dial_token
        ),
        Err(CoreError::InvalidSignature)
    );

    let accept_bytes =
        v2_relay_accept_signed_bytes(&br.relay_host_raw, &challenge_nonce, &conn_id, epoch)
            .unwrap();
    assert_eq!(hex::encode(&accept_bytes), br.accept_signed_bytes_hex);
    let accept_sig =
        sign_v2_relay_accept(&mailbox, &br.relay_host_raw, &challenge_nonce, &conn_id).unwrap();
    assert_eq!(hex::encode(accept_sig), br.accept_sig_hex);
    assert_eq!(b64url_encode(&accept_sig), br.accept_sig_b64url);
    verify_v2_relay_accept(
        &mailbox.mailbox_id,
        epoch,
        &br.relay_host_canonical,
        &challenge_nonce,
        &conn_id,
        &accept_sig,
    )
    .unwrap();

    // 2. Relay admission (Tier 2 + Tier 3)
    let ra = &v.relay_admission;
    let shared_secret = hex::decode(&ra.shared_secret_hex).unwrap();
    let adm_nonce = decode_hex_array::<32>(&ra.challenge_nonce_hex);
    let pub_or_target = decode_hex_array::<32>(&ra.pub_or_target_hex);
    assert_eq!(
        canonical_relay_host(&ra.relay_host_raw).unwrap(),
        ra.relay_host_canonical
    );

    let hmac_in =
        relay_auth_hmac_input(&ra.op, &ra.relay_host_raw, &adm_nonce, &pub_or_target).unwrap();
    assert_eq!(hex::encode(&hmac_in), ra.hmac_input_hex);
    let mac = compute_relay_auth_hmac(
        &shared_secret,
        &ra.op,
        &ra.relay_host_raw,
        &adm_nonce,
        &pub_or_target,
    )
    .unwrap();
    assert_eq!(hex::encode(mac), ra.hmac_mac_hex);
    assert_eq!(
        compute_relay_auth_hmac_b64(
            &shared_secret,
            &ra.op,
            &ra.relay_host_raw,
            &adm_nonce,
            &pub_or_target
        )
        .unwrap(),
        ra.hmac_mac_b64url
    );
    verify_relay_auth_hmac(
        &shared_secret,
        &ra.op,
        &ra.relay_host_canonical,
        &adm_nonce,
        &pub_or_target,
        &ra.hmac_mac_b64url,
    )
    .unwrap();
    assert!(
        verify_relay_auth_hmac(
            &shared_secret,
            &ra.dial_op,
            &ra.relay_host_canonical,
            &adm_nonce,
            &pub_or_target,
            &ra.hmac_mac_b64url
        )
        .is_err()
    );

    let dial_hmac_in =
        relay_auth_hmac_input(&ra.dial_op, &ra.relay_host_raw, &adm_nonce, &pub_or_target).unwrap();
    assert_eq!(hex::encode(&dial_hmac_in), ra.dial_hmac_input_hex);
    assert_eq!(
        hex::encode(
            compute_relay_auth_hmac(
                &shared_secret,
                &ra.dial_op,
                &ra.relay_host_raw,
                &adm_nonce,
                &pub_or_target
            )
            .unwrap()
        ),
        ra.dial_hmac_mac_hex
    );
    let accept_hmac_in = relay_auth_hmac_input(
        &ra.accept_op,
        &ra.relay_host_raw,
        &adm_nonce,
        &pub_or_target,
    )
    .unwrap();
    assert_eq!(hex::encode(&accept_hmac_in), ra.accept_hmac_input_hex);
    assert_eq!(
        hex::encode(
            compute_relay_auth_hmac(
                &shared_secret,
                &ra.accept_op,
                &ra.relay_host_raw,
                &adm_nonce,
                &pub_or_target
            )
            .unwrap()
        ),
        ra.accept_hmac_mac_hex
    );

    assert_eq!(relay_ticket_jcs(&ra.ticket).unwrap(), ra.ticket_jcs_json);
    assert_eq!(
        hex::encode(relay_ticket_signed_bytes(&ra.ticket).unwrap()),
        ra.ticket_signed_bytes_hex
    );
    assert_eq!(
        hex::encode(b64url_decode(&ra.ticket.sig).unwrap()),
        ra.ticket_sig_hex
    );
    let issuer_pub = decode_hex_array::<32>(&ra.ticket_issuer_pub_hex);
    assert_eq!(
        verify_relay_ticket(
            &ra.ticket,
            &[issuer_pub],
            &ra.relay_host_canonical,
            RelayAuthRole::Dial,
            &pub_or_target,
            ra.ticket_now_unix + 60
        ),
        Ok(issuer_pub)
    );
    assert!(
        verify_relay_ticket(
            &ra.ticket,
            &[issuer_pub],
            &ra.relay_host_canonical,
            RelayAuthRole::Register,
            &pub_or_target,
            ra.ticket_now_unix + 60
        )
        .is_err()
    );
    let mut bad_ticket = ra.ticket.clone();
    bad_ticket.relay_host = "other.example.com".to_string();
    assert!(
        verify_relay_ticket(
            &bad_ticket,
            &[issuer_pub],
            "other.example.com",
            RelayAuthRole::Dial,
            &pub_or_target,
            ra.ticket_now_unix + 60
        )
        .is_err()
    );
    assert_eq!(
        serde_json::from_str::<RelayAuthProof>(&ra.hmac_proof_json).unwrap(),
        RelayAuthProof::Hmac {
            mac: ra.hmac_mac_b64url.clone()
        }
    );
    assert_eq!(
        serde_json::from_str::<RelayAuthProof>(&ra.ticket_proof_json).unwrap(),
        RelayAuthProof::Ticket {
            ticket: ra.ticket.clone()
        }
    );

    // 3. Pseudonymous v2 Reconnect
    let rc = &v.v2_reconnect;
    let r_pre = decode_hex_array::<6>(&rc.preamble_hex);
    assert_eq!(r_pre, expected_session_pre);
    let init_static = decode_hex_array::<32>(&rc.initiator_static_scalar_hex);
    let resp_static = decode_hex_array::<32>(&rc.responder_static_scalar_hex);
    assert_eq!(
        hex::encode(x25519_public_from_scalar(&init_static)),
        rc.initiator_static_pub_hex
    );
    let resp_static_pub = x25519_public_from_scalar(&resp_static);
    assert_eq!(hex::encode(resp_static_pub), rc.responder_static_pub_hex);
    assert_eq!(
        hex::encode(
            decode_hybrid_pub(&rc.responder_signing_pub_hex)
                .as_bytes()
                .as_slice()
        ),
        rc.responder_signing_pub_hex
    );

    let reconnect_secret = decode_hex_array::<32>(&rc.reconnect_secret_hex);
    let rendezvous_nonce = decode_hex_array::<16>(&rc.rendezvous_nonce_hex);

    let mut r_init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&init_static)
        .prologue(&r_pre)
        .fixed_hfs_seeds_for_testing_only(init_hfs_seeds(
            &rc.initiator_ephem_scalar_hex,
            &rc.initiator_mlkem768_keygen_seed_hex,
        ))
        .build_initiator()
        .unwrap();
    let mut r_resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&resp_static)
        .prologue(&r_pre)
        .fixed_hfs_seeds_for_testing_only(resp_hfs_seeds(
            &rc.responder_ephem_scalar_hex,
            &rc.responder_mlkem768_encaps_seed_hex,
        ))
        .build_responder()
        .unwrap();

    let mut r_payload1 = Vec::new();
    let m1 = r_init
        .write_msg1_with_payload(|e_i_pub, ek_bytes| {
            let ek_hash: [u8; 32] = Sha256::digest(ek_bytes).into();
            assert_eq!(hex::encode(ek_hash), rc.ekem_i_hash_hex);
            let mac = compute_rendezvous_mac(
                &reconnect_secret,
                &r_pre,
                e_i_pub,
                &ek_hash,
                &rendezvous_nonce,
                rc.ts_unix,
            );
            assert_eq!(hex::encode(mac), rc.rendezvous_mac_hex);
            assert!(verify_rendezvous_mac(
                &reconnect_secret,
                &r_pre,
                e_i_pub,
                &ek_hash,
                &rendezvous_nonce,
                rc.ts_unix,
                &mac
            ));
            let mut p = Vec::with_capacity(56);
            p.extend_from_slice(&rendezvous_nonce);
            p.extend_from_slice(&rc.ts_unix.to_be_bytes());
            p.extend_from_slice(&mac);
            r_payload1 = p.clone();
            Ok(p)
        })
        .unwrap();
    assert_eq!(hex::encode(&r_payload1), rc.msg1_payload_hex);
    let f1 = encode_frame(&m1).unwrap();
    assert_eq!(hex::encode(&f1), rc.msg1_frame_hex);
    let dec1 = r_resp
        .read_message_vec(decode_frame(&f1).unwrap().0)
        .unwrap();
    assert_eq!(&*dec1, r_payload1.as_slice());

    let parsed_hello: HostHello = serde_json::from_str(&rc.host_hello_json).unwrap();
    assert_eq!(parsed_hello.proto_version, WIRE_VERSION_V2);
    let expected_seal_key = hkdf_sha256_32(
        &reconnect_secret,
        &rendezvous_nonce,
        b"tendril-v2-hello-seal",
    );
    assert_eq!(hex::encode(*expected_seal_key), rc.hello_seal_key_hex);
    let m2 = r_resp
        .write_msg2_with_hash(|h_pre| {
            assert_eq!(hex::encode(h_pre), rc.pre_msg2_handshake_hash_hex);
            let env = seal_v2_hello_envelope(
                &reconnect_secret,
                &rendezvous_nonce,
                h_pre,
                rc.host_hello_json.as_bytes(),
            )?;
            assert_eq!(env.len(), rc.bucket_len);
            assert_eq!(hex::encode(&env), rc.sealed_hello_envelope_hex);
            Ok(env)
        })
        .unwrap();
    let f2 = encode_frame(&m2).unwrap();
    assert_eq!(hex::encode(&f2), rc.msg2_frame_hex);
    let (dec2, init_h_pre) = r_init
        .read_msg2_with_pre_payload_hash(decode_frame(&f2).unwrap().0)
        .unwrap();
    assert_eq!(hex::encode(init_h_pre), rc.pre_msg2_handshake_hash_hex);
    let unsealed_hello =
        unseal_v2_hello_envelope(&reconnect_secret, &rendezvous_nonce, &init_h_pre, &dec2).unwrap();
    assert_eq!(&*unsealed_hello, rc.host_hello_json.as_bytes());
    assert_eq!(
        hex::encode(r_init.get_handshake_hash()),
        rc.post_msg2_handshake_hash_hex
    );

    // Tamper sealed envelope must fail closed
    let mut bad_env = hex::decode(&rc.sealed_hello_envelope_hex).unwrap();
    bad_env[0] ^= 0x01;
    assert_eq!(
        unseal_v2_hello_envelope(&reconnect_secret, &rendezvous_nonce, &init_h_pre, &bad_env),
        Err(CoreError::HostKeyUnverified)
    );

    let msg3_padded = pad_msg3_payload(rc.session_hello_json.as_bytes()).unwrap();
    assert_eq!(hex::encode(&msg3_padded), rc.msg3_padded_payload_hex);
    let m3 = r_init.write_message_vec(&msg3_padded).unwrap();
    let f3 = encode_frame(&m3).unwrap();
    assert_eq!(hex::encode(&f3), rc.msg3_frame_hex);
    let dec3 = r_resp
        .read_message_vec(decode_frame(&f3).unwrap().0)
        .unwrap();
    assert_eq!(
        unpad_msg3_payload(&dec3).unwrap(),
        rc.session_hello_json.as_bytes()
    );
    assert_eq!(
        hex::encode(r_init.get_handshake_hash()),
        rc.final_handshake_hash_hex
    );

    let mut r_init_tx = r_init.into_transport_mode().unwrap();
    let mut r_resp_tx = r_resp.into_transport_mode().unwrap();
    let (exp_reconn, exp_mbox) = r_init_tx.export_v2_secrets(&resp_static_pub);
    assert_eq!(hex::encode(*exp_reconn), rc.exported_reconnect_secret_hex);
    assert_eq!(hex::encode(*exp_mbox), rc.exported_mailbox_secret_hex);

    let raw_data = hex::decode(&rc.padded_data_payload_hex).unwrap();
    let padded_inner = pad_inner_frame(
        InnerFrameType::Data,
        &raw_data,
        &PaddingPolicy::v2_default(),
    )
    .unwrap();
    assert_eq!(hex::encode(&padded_inner), rc.padded_inner_hex);
    let padded_ct = r_init_tx.write_message_vec(&padded_inner).unwrap();
    let padded_frame = encode_frame(&padded_ct).unwrap();
    assert_eq!(hex::encode(&padded_frame), rc.padded_frame_hex);
    let dec_padded = r_resp_tx
        .read_message_vec(decode_frame(&padded_frame).unwrap().0)
        .unwrap();
    assert_eq!(
        unpad_inner_frame(&dec_padded).unwrap(),
        (InnerFrameType::Data, raw_data)
    );

    let cover_inner = encode_dummy_cover_frame(rc.cover_bucket_len).unwrap();
    assert_eq!(hex::encode(&cover_inner), rc.cover_inner_hex);
    let cover_ct = r_init_tx.write_message_vec(&cover_inner).unwrap();
    let cover_frame = encode_frame(&cover_ct).unwrap();
    assert_eq!(hex::encode(&cover_frame), rc.cover_frame_hex);
    let dec_cover = r_resp_tx
        .read_message_vec(decode_frame(&cover_frame).unwrap().0)
        .unwrap();
    assert_eq!(
        decode_v2_inner_frame(&dec_cover, false).unwrap(),
        V2InnerFrame::DummyCover {
            plaintext_len: rc.cover_bucket_len
        }
    );

    // 4. Hybrid Argon2id PAKE + ML-KEM-768 Pairing
    let pk = &v.pake_pairing;
    let p_pre = decode_hex_array::<6>(&pk.preamble_hex);
    assert_eq!(p_pre, expected_pake_pre);
    assert_eq!(normalize_code(&pk.code), pk.code_normalized);
    assert_eq!(pk.argon2id.m_kib, PAKE_ARGON2_MEMORY_KIB);
    assert_eq!(pk.argon2id.t, PAKE_ARGON2_TIME);
    assert_eq!(pk.argon2id.p, PAKE_ARGON2_PARALLELISM);
    assert_eq!(pk.argon2id.key_len, 32);

    let salt = decode_hex_array::<V2_PAKE_SALT_LEN>(&pk.channel_salt_hex);
    let prod_params = PakeArgon2Params::production();
    let master = derive_pake_master(&pk.code, &salt, prod_params).unwrap();
    assert_eq!(hex::encode(*master), pk.master_pake_hex);
    let pake_keys = derive_pake_keys(&pk.code, &salt, prod_params).unwrap();
    assert_eq!(
        hex::encode(pake_keys.pake_prologue_key),
        pk.pake_prologue_key_hex
    );
    assert_eq!(hex::encode(pake_keys.pake_init_key), pk.pake_init_key_hex);
    assert_eq!(hex::encode(pake_keys.pake_hello_key), pk.pake_hello_key_hex);
    assert_eq!(
        hex::encode(pake_keys.pake_confirm_key),
        pk.pake_confirm_key_hex
    );
    assert_eq!(
        hex::encode(pake_keys.pake_context_tag),
        pk.pake_context_tag_hex
    );
    let prologue = pake_noise_prologue(&pake_keys.pake_context_tag);
    assert_eq!(hex::encode(prologue), pk.noise_prologue_hex);

    let p_init_static = decode_hex_array::<32>(&pk.initiator_static_scalar_hex);
    let p_resp_static = decode_hex_array::<32>(&pk.responder_static_scalar_hex);
    assert_eq!(
        hex::encode(x25519_public_from_scalar(&p_init_static)),
        pk.initiator_static_pub_hex
    );
    let p_resp_static_pub = x25519_public_from_scalar(&p_resp_static);
    assert_eq!(hex::encode(p_resp_static_pub), pk.responder_static_pub_hex);

    let mut p_init = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&p_init_static)
        .prologue(&prologue)
        .fixed_hfs_seeds_for_testing_only(init_hfs_seeds(
            &pk.initiator_ephem_scalar_hex,
            &pk.initiator_mlkem768_keygen_seed_hex,
        ))
        .build_initiator()
        .unwrap();
    let mut p_resp = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&p_resp_static)
        .prologue(&prologue)
        .fixed_hfs_seeds_for_testing_only(resp_hfs_seeds(
            &pk.responder_ephem_scalar_hex,
            &pk.responder_mlkem768_encaps_seed_hex,
        ))
        .build_responder()
        .unwrap();

    let pm1 = p_init
        .write_msg1_with_payload(|e_i_pub, ek_bytes| {
            let ek_hash: [u8; 32] = Sha256::digest(ek_bytes).into();
            assert_eq!(hex::encode(ek_hash), pk.ekem_i_hash_hex);
            let mac =
                compute_pake_msg1_mac(&pake_keys.pake_init_key, &p_pre, e_i_pub, &ek_hash, &salt);
            assert_eq!(hex::encode(mac), pk.init_mac_hex);
            let mut out = Vec::with_capacity(48);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&mac);
            assert_eq!(hex::encode(&out), pk.msg1_payload_hex);
            Ok(out)
        })
        .unwrap();
    let pf1 = encode_frame(&pm1).unwrap();
    assert_eq!(hex::encode(&pf1), pk.msg1_frame_hex);
    let pdec1 = p_resp
        .read_message_vec(decode_frame(&pf1).unwrap().0)
        .unwrap();
    assert_eq!(hex::encode(&*pdec1), pk.msg1_payload_hex);

    let msg2_bucket = pake_msg2_bucket_for_hello_len(pk.host_hello_json.len()).unwrap();
    assert_eq!(msg2_bucket, pk.msg2_bucket_len);
    let pm2 = p_resp
        .write_msg2_with_hash(|h_pre| {
            assert_eq!(hex::encode(h_pre), pk.pre_msg2_handshake_hash_hex);
            let sealed = seal_pake_host_hello(
                &pake_keys.pake_hello_key,
                h_pre,
                pk.host_hello_json.as_bytes(),
            )?;
            assert_eq!(hex::encode(&sealed), pk.sealed_host_hello_hex);
            let rmac = compute_pake_resp_mac(&pake_keys.pake_confirm_key, h_pre, &sealed);
            assert_eq!(hex::encode(rmac), pk.resp_confirm_mac_hex);
            let mut out = vec![0u8; msg2_bucket];
            let slen = u16::try_from(sealed.len()).unwrap();
            out[..2].copy_from_slice(&slen.to_be_bytes());
            out[2..2 + sealed.len()].copy_from_slice(&sealed);
            out[2 + sealed.len()..2 + sealed.len() + 32].copy_from_slice(&rmac);
            assert_eq!(hex::encode(&out), pk.msg2_payload_hex);
            Ok(out)
        })
        .unwrap();
    let pf2 = encode_frame(&pm2).unwrap();
    assert_eq!(hex::encode(&pf2), pk.msg2_frame_hex);
    let (pdec2, p_init_h_pre) = p_init
        .read_msg2_with_pre_payload_hash(decode_frame(&pf2).unwrap().0)
        .unwrap();
    assert_eq!(hex::encode(&*pdec2), pk.msg2_payload_hex);
    assert_eq!(hex::encode(p_init_h_pre), pk.pre_msg2_handshake_hash_hex);
    let sealed_slice = hex::decode(&pk.sealed_host_hello_hex).unwrap();
    let unsealed_pake_hello =
        unseal_pake_host_hello(&pake_keys.pake_hello_key, &p_init_h_pre, &sealed_slice).unwrap();
    assert_eq!(&*unsealed_pake_hello, pk.host_hello_json.as_bytes());
    let post_msg2 = *p_init.get_handshake_hash();
    assert_eq!(hex::encode(post_msg2), pk.post_msg2_handshake_hash_hex);
    assert_eq!(pairing_sas(&post_msg2), pk.pairing_sas);

    // Wrong key fails unseal
    assert_eq!(
        unseal_pake_host_hello(&[0xFF; 32], &p_init_h_pre, &sealed_slice),
        Err(CoreError::PairingAuthFailed)
    );

    let init_confirm_mac = compute_pake_init_mac(
        &pake_keys.pake_confirm_key,
        &post_msg2,
        pk.pair_claim_json.as_bytes(),
    );
    assert_eq!(hex::encode(init_confirm_mac), pk.init_confirm_mac_hex);
    let msg3_payload =
        pad_pake_msg3_payload(&init_confirm_mac, pk.pair_claim_json.as_bytes()).unwrap();
    assert_eq!(hex::encode(&msg3_payload), pk.msg3_payload_hex);
    let (unpadded_mac, unpadded_claim) = unpad_pake_msg3_payload(&msg3_payload).unwrap();
    assert_eq!(unpadded_mac, init_confirm_mac);
    assert_eq!(unpadded_claim, pk.pair_claim_json.as_bytes());

    let pm3 = p_init.write_message_vec(&msg3_payload).unwrap();
    let pf3 = encode_frame(&pm3).unwrap();
    assert_eq!(hex::encode(&pf3), pk.msg3_frame_hex);
    let pdec3 = p_resp
        .read_message_vec(decode_frame(&pf3).unwrap().0)
        .unwrap();
    assert_eq!(&*pdec3, msg3_payload.as_slice());
    assert_eq!(
        hex::encode(p_init.get_handshake_hash()),
        pk.final_handshake_hash_hex
    );

    let mut p_init_tx = p_init.into_transport_mode().unwrap();
    let mut p_resp_tx = p_resp.into_transport_mode().unwrap();
    let (p_exp_reconn, p_exp_mbox) = p_init_tx.export_v2_secrets(&p_resp_static_pub);
    assert_eq!(hex::encode(*p_exp_reconn), pk.exported_reconnect_secret_hex);
    assert_eq!(hex::encode(*p_exp_mbox), pk.exported_mailbox_secret_hex);

    let pr_payload = pad_msg3_payload(pk.pair_response_json.as_bytes()).unwrap();
    assert_eq!(hex::encode(&pr_payload), pk.pair_response_payload_hex);
    let pr_ct = p_resp_tx.write_message_vec(&pr_payload).unwrap();
    let pr_frame = encode_frame(&pr_ct).unwrap();
    assert_eq!(hex::encode(&pr_frame), pk.pair_response_frame_hex);
    let pdec4 = p_init_tx
        .read_message_vec(decode_frame(&pr_frame).unwrap().0)
        .unwrap();
    assert_eq!(&*pdec4, pr_payload.as_slice());
    assert_eq!(
        unpad_msg3_payload(&pdec4).unwrap(),
        pk.pair_response_json.as_bytes()
    );
    assert_eq!(
        decode_hybrid_pub(&pk.responder_signing_pub_hex).to_b64url(),
        serde_json::from_str::<HostHello>(&pk.host_hello_json)
            .unwrap()
            .signing_pub
    );
}
