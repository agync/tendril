//! Generates canonical v1 JSON test vectors under `spec/vectors/` using real crypto.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use snow::Builder;
use snow::params::NoiseParams;

use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{
    ARGON2_KEY_LEN, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME, PAIR_MAC_LABEL, SAS_LABEL,
    SigningKeypair, StaticKeypair, argon2id_pairing_key, b64url_encode, compute_code_mac,
    device_id, fingerprint_device, fingerprint_host, normalize_code, pairing_sas,
    x25519_public_from_scalar,
};
use tendril_core::grants::{
    CRL_DOMAIN, GRANT_DOMAIN, Grant, GrantUnsigned, RevocationList, RevocationListUnsigned,
    canonical_json, crl_signed_bytes, grant_signed_bytes, sign_crl, sign_grant,
};
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, rotation_signed_bytes, sign_rotation,
};
use tendril_core::pairing::{
    ENROLL_PROOF_DOMAIN, EnrollmentPolicy, enroll_proof_bytes, mint_enrollment_token,
    sign_enroll_proof, verify_enrollment_token,
};
use tendril_core::roster::Roster;
use tendril_core::wire::{
    HostHello, InnerFrameType, Intent, NOISE_PATTERN, PairClaim, PairResponse, Preamble,
    SessionHello, decode_frame, encode_frame, encode_inner_frame,
};

#[derive(Serialize)]
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
    sas_label: String,
    sas_digest_hex: String,
    pairing_sas: String,
}

#[derive(Serialize)]
struct PairingMacCase {
    code: String,
    code_normalized: String,
    kdf_hex: String,
    code_mac_hex: String,
    code_mac_b64url: String,
}

#[derive(Serialize)]
struct Argon2ParamsSpec {
    t: u32,
    m_kib: u32,
    p: u32,
    key_len: usize,
    version: String,
}

#[derive(Serialize)]
struct PairingMacVector {
    handshake_hash_hex: String,
    salt_hex: String,
    mac_label: String,
    argon2id: Argon2ParamsSpec,
    remote_3group: PairingMacCase,
    lan_2group: PairingMacCase,
}

#[derive(Serialize)]
struct RotationStep {
    signed_bytes_hex: String,
    record: RotationRecord,
}

#[derive(Serialize)]
struct RotationVector {
    pinned_signing_seed_hex: String,
    pinned_signing_pub_hex: String,
    pinned_static_scalar_hex: String,
    pinned_static_pub_hex: String,
    step1_signing_seed_hex: String,
    step1_static_scalar_hex: String,
    step2_signing_seed_hex: String,
    step2_static_scalar_hex: String,
    fork_signing_seed_hex: String,
    fork_static_scalar_hex: String,
    chain: Vec<RotationStep>,
    fork_record: RotationStep,
}

#[derive(Serialize)]
struct GrantsVector {
    root_issuer_id: String,
    root_signing_seed_hex: String,
    root_signing_pub_hex: String,
    delegate_id: String,
    delegate_signing_seed_hex: String,
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

#[derive(Serialize)]
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

#[derive(Serialize)]
struct SessionTranscriptVector {
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

#[derive(Serialize)]
struct HandshakeVector {
    noise_pattern: String,
    pair_transcript: PairTranscriptVector,
    session_transcript: SessionTranscriptVector,
}

#[derive(Serialize)]
struct M2mEnrollmentVector {
    noise_pattern: String,
    preamble_hex: String,
    now_unix: u64,
    anchor_id: String,
    anchor_signing_seed_hex: String,
    anchor_signing_pub_hex: String,
    responder_host_id: String,
    responder_static_scalar_hex: String,
    responder_static_pub_hex: String,
    responder_ephem_scalar_hex: String,
    responder_signing_pub_hex: String,
    initiator_static_scalar_hex: String,
    initiator_static_pub_hex: String,
    initiator_device_id: String,
    initiator_ephem_scalar_hex: String,
    initiator_signing_seed_hex: String,
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

fn seq_bytes(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(idx as u8);
    }
    out
}

fn write_json<T: Serialize>(
    dir: &Path,
    name: &str,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    fs::write(dir.join(name), text)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vectors_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    fs::create_dir_all(&vectors_dir)?;

    // 1. fingerprints.json
    let host_scalar = seq_bytes(0x00);
    let host_pub = x25519_public_from_scalar(&host_scalar);
    let dev_scalar = seq_bytes(0x20);
    let dev_pub = x25519_public_from_scalar(&dev_scalar);
    let raw_pubkey = seq_bytes(0x00);
    let h = seq_bytes(0x40);
    let mut sas_hasher = Sha256::new();
    sas_hasher.update(SAS_LABEL);
    sas_hasher.update(h);
    let sas_digest: [u8; 32] = sas_hasher.finalize().into();

    let fingerprints = FingerprintsVector {
        host_static_scalar_hex: hex::encode(host_scalar),
        host_static_pub_hex: hex::encode(host_pub),
        host_device_id: device_id(&host_pub),
        host_fingerprint: fingerprint_host(&host_pub),
        device_static_scalar_hex: hex::encode(dev_scalar),
        device_static_pub_hex: hex::encode(dev_pub),
        device_id: device_id(&dev_pub),
        device_fingerprint: fingerprint_device(&dev_pub),
        raw_pubkey_hex: hex::encode(raw_pubkey),
        raw_host_fingerprint: fingerprint_host(&raw_pubkey),
        raw_device_fingerprint: fingerprint_device(&raw_pubkey),
        raw_device_id: device_id(&raw_pubkey),
        handshake_hash_hex: hex::encode(h),
        sas_label: String::from_utf8(SAS_LABEL.to_vec())?,
        sas_digest_hex: hex::encode(sas_digest),
        pairing_sas: pairing_sas(&h),
    };
    write_json(&vectors_dir, "fingerprints.json", &fingerprints)?;

    // 2. pairing_mac.json
    let remote_code = "tnd-4f9k-22xq-8n3p";
    let remote_kdf = argon2id_pairing_key(remote_code, &h)?;
    let remote_mac = compute_code_mac(remote_code, &h)?;
    let lan_code = "TND-4F9K-22XQ";
    let lan_kdf = argon2id_pairing_key(lan_code, &h)?;
    let lan_mac = compute_code_mac(lan_code, &h)?;

    let pairing_mac = PairingMacVector {
        handshake_hash_hex: hex::encode(h),
        salt_hex: hex::encode(&h[..16]),
        mac_label: String::from_utf8(PAIR_MAC_LABEL.to_vec())?,
        argon2id: Argon2ParamsSpec {
            t: ARGON2_TIME,
            m_kib: ARGON2_MEMORY_KIB,
            p: ARGON2_PARALLELISM,
            key_len: ARGON2_KEY_LEN,
            version: "0x13".to_string(),
        },
        remote_3group: PairingMacCase {
            code: remote_code.to_string(),
            code_normalized: normalize_code(remote_code),
            kdf_hex: hex::encode(*remote_kdf),
            code_mac_hex: hex::encode(remote_mac),
            code_mac_b64url: b64url_encode(&remote_mac),
        },
        lan_2group: PairingMacCase {
            code: lan_code.to_string(),
            code_normalized: normalize_code(lan_code),
            kdf_hex: hex::encode(*lan_kdf),
            code_mac_hex: hex::encode(lan_mac),
            code_mac_b64url: b64url_encode(&lan_mac),
        },
    };
    write_json(&vectors_dir, "pairing_mac.json", &pairing_mac)?;

    // 3. rotation.json
    let seed0 = seq_bytes(0x00);
    let key0 = SigningKey::from_bytes(&seed0);
    let static0 = seq_bytes(0x40);
    let static0_pub = x25519_public_from_scalar(&static0);

    let seed1 = seq_bytes(0x10);
    let key1 = SigningKey::from_bytes(&seed1);
    let static1 = seq_bytes(0x50);
    let static1_pub = x25519_public_from_scalar(&static1);

    let seed2 = seq_bytes(0x20);
    let key2 = SigningKey::from_bytes(&seed2);
    let static2 = seq_bytes(0x60);
    let static2_pub = x25519_public_from_scalar(&static2);

    let fork_seed = seq_bytes(0x30);
    let fork_key = SigningKey::from_bytes(&fork_seed);
    let fork_static = seq_bytes(0x70);
    let fork_static_pub = x25519_public_from_scalar(&fork_static);

    let ts1 = 1_795_132_800; // 2026-11-20T00:00:00Z
    let ts2 = 1_795_219_200; // 2026-11-21T00:00:00Z
    let ts_fork = 1_795_219_260; // 2026-11-21T00:01:00Z

    let rec1 = sign_rotation(
        1,
        &key0,
        &key1.verifying_key().to_bytes(),
        &static1_pub,
        ts1,
    )?;
    let bytes1 = rotation_signed_bytes(
        1,
        &key0.verifying_key().to_bytes(),
        &key1.verifying_key().to_bytes(),
        &static1_pub,
        ts1,
    );
    let rec2 = sign_rotation(
        2,
        &key1,
        &key2.verifying_key().to_bytes(),
        &static2_pub,
        ts2,
    )?;
    let bytes2 = rotation_signed_bytes(
        2,
        &key1.verifying_key().to_bytes(),
        &key2.verifying_key().to_bytes(),
        &static2_pub,
        ts2,
    );
    let rec_fork = sign_rotation(
        2,
        &key1,
        &fork_key.verifying_key().to_bytes(),
        &fork_static_pub,
        ts_fork,
    )?;
    let bytes_fork = rotation_signed_bytes(
        2,
        &key1.verifying_key().to_bytes(),
        &fork_key.verifying_key().to_bytes(),
        &fork_static_pub,
        ts_fork,
    );

    let rotation = RotationVector {
        pinned_signing_seed_hex: hex::encode(seed0),
        pinned_signing_pub_hex: hex::encode(key0.verifying_key().to_bytes()),
        pinned_static_scalar_hex: hex::encode(static0),
        pinned_static_pub_hex: hex::encode(static0_pub),
        step1_signing_seed_hex: hex::encode(seed1),
        step1_static_scalar_hex: hex::encode(static1),
        step2_signing_seed_hex: hex::encode(seed2),
        step2_static_scalar_hex: hex::encode(static2),
        fork_signing_seed_hex: hex::encode(fork_seed),
        fork_static_scalar_hex: hex::encode(fork_static),
        chain: vec![
            RotationStep {
                signed_bytes_hex: hex::encode(bytes1),
                record: rec1,
            },
            RotationStep {
                signed_bytes_hex: hex::encode(bytes2),
                record: rec2,
            },
        ],
        fork_record: RotationStep {
            signed_bytes_hex: hex::encode(bytes_fork),
            record: rec_fork,
        },
    };
    write_json(&vectors_dir, "rotation.json", &rotation)?;

    // 4. grants.json
    let root_seed = seq_bytes(0x80);
    let root_signing = SigningKey::from_bytes(&root_seed);
    let root_static = x25519_public_from_scalar(&seq_bytes(0x90));
    let root_id = device_id(&root_static);

    let del_seed = seq_bytes(0xa0);
    let del_signing = SigningKey::from_bytes(&del_seed);
    let del_static = x25519_public_from_scalar(&seq_bytes(0xb0));
    let del_id = device_id(&del_static);

    let leaf_static = x25519_public_from_scalar(&seq_bytes(0xd0));
    let leaf_id = device_id(&leaf_static);

    let root_nonce = b64url_encode(&[1u8; 16]);
    let root_unsorted_json = format!(
        "{{\"nonce\":\"{root_nonce}\",\"v\":1,\"caps\":[\"session.open\",\"pair.mint\",\"fs.read:/photos/*\"],\"not_after\":\"2026-12-20T00:00:00Z\",\"subject\":\"{del_id}\",\"issuer\":\"{root_id}\",\"not_before\":\"2026-11-20T00:00:00Z\"}}"
    );
    let root_unsigned: GrantUnsigned = serde_json::from_str(&root_unsorted_json)?;
    let root_jcs_json = canonical_json(&root_unsigned)?;
    let root_signed_bytes = grant_signed_bytes(&root_unsigned)?;
    let root_grant = sign_grant(root_unsigned, &root_signing)?;

    let valid_child_unsigned = GrantUnsigned {
        v: 1,
        issuer: del_id.clone(),
        subject: leaf_id.clone(),
        caps: vec![
            "session.open".to_string(),
            "fs.read:/photos/2026/*".to_string(),
        ],
        not_before: "2026-11-21T00:00:00Z".to_string(),
        not_after: "2026-12-01T00:00:00Z".to_string(),
        nonce: b64url_encode(&[2u8; 16]),
        delegated_from: vec![root_grant.clone()],
        uses: None,
        machine: None,
    };
    let delegated_valid = sign_grant(valid_child_unsigned, &del_signing)?;

    let widened_child_unsigned = GrantUnsigned {
        v: 1,
        issuer: del_id.clone(),
        subject: leaf_id.clone(),
        caps: vec!["session.open".to_string(), "fs.read:/*".to_string()],
        not_before: "2026-11-21T00:00:00Z".to_string(),
        not_after: "2026-12-01T00:00:00Z".to_string(),
        nonce: b64url_encode(&[3u8; 16]),
        delegated_from: vec![root_grant.clone()],
        uses: None,
        machine: None,
    };
    let delegated_widened = sign_grant(widened_child_unsigned, &del_signing)?;

    let crl_unsigned = RevocationListUnsigned {
        v: 1,
        issuer: root_id.clone(),
        seq: 1,
        revoked_devices: vec!["dev_deadbeefcafebabe".to_string()],
        revoked_nonces: vec![b64url_encode(&[9u8; 16])],
        ts: "2026-11-22T00:00:00Z".to_string(),
    };
    let crl_jcs_json = canonical_json(&crl_unsigned)?;
    let crl_signed_bytes = crl_signed_bytes(&crl_unsigned)?;
    let revocation_list = sign_crl(crl_unsigned, &root_signing)?;

    assert!(root_signed_bytes.starts_with(GRANT_DOMAIN));
    assert!(crl_signed_bytes.starts_with(CRL_DOMAIN));

    let grants_vec = GrantsVector {
        root_issuer_id: root_id,
        root_signing_seed_hex: hex::encode(root_seed),
        root_signing_pub_hex: hex::encode(root_signing.verifying_key().to_bytes()),
        delegate_id: del_id,
        delegate_signing_seed_hex: hex::encode(del_seed),
        delegate_signing_pub_hex: hex::encode(del_signing.verifying_key().to_bytes()),
        leaf_id,
        root_unsorted_json,
        root_jcs_json,
        root_signed_bytes_hex: hex::encode(root_signed_bytes),
        root_grant,
        delegated_valid,
        delegated_widened,
        crl_jcs_json,
        crl_signed_bytes_hex: hex::encode(crl_signed_bytes),
        revocation_list,
    };
    write_json(&vectors_dir, "grants.json", &grants_vec)?;

    // 5. handshake.json
    let pair_transcript = build_pair_transcript(&host_scalar, &host_pub, &dev_scalar, &dev_pub)?;
    let session_transcript =
        build_session_transcript(&host_scalar, &host_pub, &dev_scalar, &dev_pub)?;
    let handshake = HandshakeVector {
        noise_pattern: NOISE_PATTERN.to_string(),
        pair_transcript,
        session_transcript,
    };
    write_json(&vectors_dir, "handshake.json", &handshake)?;

    // 6. m2m_enrollment.json
    let m2m_vec = build_m2m_enrollment_vector()?;
    write_json(&vectors_dir, "m2m_enrollment.json", &m2m_vec)?;

    println!(
        "Generated 6 canonical vector files under {}",
        vectors_dir.display()
    );
    Ok(())
}

fn build_pair_transcript(
    resp_static: &[u8; 32],
    resp_static_pub: &[u8; 32],
    init_static: &[u8; 32],
    init_static_pub: &[u8; 32],
) -> Result<PairTranscriptVector, Box<dyn std::error::Error>> {
    let init_ephem = seq_bytes(0x51);
    let resp_ephem = seq_bytes(0x61);
    let preamble = Preamble::v1(Intent::Pair).encode();
    let params: NoiseParams = NOISE_PATTERN.parse()?;

    let mut initiator = Builder::new(params.clone())
        .local_private_key(init_static)?
        .prologue(&preamble)?
        .fixed_ephemeral_key_for_testing_only(&init_ephem)
        .build_initiator()?;
    let mut responder = Builder::new(params)
        .local_private_key(resp_static)?
        .prologue(&preamble)?
        .fixed_ephemeral_key_for_testing_only(&resp_ephem)
        .build_responder()?;

    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let mut pt = vec![0u8; MAX_FRAME_LEN];

    let n1 = initiator.write_message(&[], &mut buf)?;
    let msg1_frame = encode_frame(&buf[..n1])?;
    let (body1, _) = decode_frame(&msg1_frame)?;
    let _ = responder.read_message(body1, &mut pt)?;

    let host_hello = HostHello {
        host_id: device_id(resp_static_pub),
        proto_version: 1,
        rotation: vec![],
    };
    let host_hello_json = serde_json::to_string(&host_hello)?;
    let n2 = responder.write_message(host_hello_json.as_bytes(), &mut buf)?;
    let msg2_frame = encode_frame(&buf[..n2])?;
    let (body2, _) = decode_frame(&msg2_frame)?;
    let n_pt2 = initiator.read_message(body2, &mut pt)?;
    assert_eq!(&pt[..n_pt2], host_hello_json.as_bytes());

    let post_msg2_hash: [u8; 32] = initiator.get_handshake_hash().try_into()?;
    let resp_hash: [u8; 32] = responder.get_handshake_hash().try_into()?;
    assert_eq!(post_msg2_hash, resp_hash);

    let pairing_code = "TND-4F9K-22XQ-8N3P".to_string();
    let sas = pairing_sas(&post_msg2_hash);
    let mac = compute_code_mac(&pairing_code, &post_msg2_hash)?;
    let mac_b64 = b64url_encode(&mac);

    let claim = PairClaim {
        name: "Phone".to_string(),
        kind: "ios".to_string(),
        code_mac: Some(mac_b64.clone()),
        enrollment_token: None,
        signing_pub: None,
        enroll_proof: None,
    };
    let pair_claim_json = serde_json::to_string(&claim)?;
    let n3 = initiator.write_message(pair_claim_json.as_bytes(), &mut buf)?;
    let msg3_frame = encode_frame(&buf[..n3])?;
    let (body3, _) = decode_frame(&msg3_frame)?;
    let n_pt3 = responder.read_message(body3, &mut pt)?;
    assert_eq!(&pt[..n_pt3], pair_claim_json.as_bytes());
    assert_eq!(
        responder.get_remote_static(),
        Some(init_static_pub.as_slice())
    );

    let final_hash: [u8; 32] = initiator.get_handshake_hash().try_into()?;
    assert_eq!(final_hash, responder.get_handshake_hash());

    let mut init_tx = initiator.into_transport_mode()?;
    let mut resp_tx = responder.into_transport_mode()?;

    let host_signing = SigningKey::from_bytes(&seq_bytes(0x71));
    let pair_resp = PairResponse::Success {
        device_id: device_id(init_static_pub),
        status: "pending".to_string(),
        host_signing_pub: b64url_encode(&host_signing.verifying_key().to_bytes()),
    };
    let pair_response_json = serde_json::to_string(&pair_resp)?;
    let n4 = resp_tx.write_message(pair_response_json.as_bytes(), &mut buf)?;
    let pair_response_frame = encode_frame(&buf[..n4])?;
    let (body4, _) = decode_frame(&pair_response_frame)?;
    let n_pt4 = init_tx.read_message(body4, &mut pt)?;
    assert_eq!(&pt[..n_pt4], pair_response_json.as_bytes());

    Ok(PairTranscriptVector {
        preamble_hex: hex::encode(preamble),
        initiator_static_scalar_hex: hex::encode(init_static),
        initiator_static_pub_hex: hex::encode(init_static_pub),
        initiator_ephem_scalar_hex: hex::encode(init_ephem),
        responder_static_scalar_hex: hex::encode(resp_static),
        responder_static_pub_hex: hex::encode(resp_static_pub),
        responder_ephem_scalar_hex: hex::encode(resp_ephem),
        host_hello_json,
        msg1_frame_hex: hex::encode(msg1_frame),
        msg2_frame_hex: hex::encode(msg2_frame),
        post_msg2_handshake_hash_hex: hex::encode(post_msg2_hash),
        pairing_code,
        pairing_sas: sas,
        code_mac_b64url: mac_b64,
        pair_claim_json,
        msg3_frame_hex: hex::encode(msg3_frame),
        final_handshake_hash_hex: hex::encode(final_hash),
        pair_response_json,
        pair_response_frame_hex: hex::encode(pair_response_frame),
    })
}

fn build_session_transcript(
    resp_static: &[u8; 32],
    resp_static_pub: &[u8; 32],
    init_static: &[u8; 32],
    init_static_pub: &[u8; 32],
) -> Result<SessionTranscriptVector, Box<dyn std::error::Error>> {
    let init_ephem = seq_bytes(0x81);
    let resp_ephem = seq_bytes(0x91);
    let preamble = Preamble::v1(Intent::Session).encode();
    let params: NoiseParams = NOISE_PATTERN.parse()?;

    let mut initiator = Builder::new(params.clone())
        .local_private_key(init_static)?
        .prologue(&preamble)?
        .fixed_ephemeral_key_for_testing_only(&init_ephem)
        .build_initiator()?;
    let mut responder = Builder::new(params)
        .local_private_key(resp_static)?
        .prologue(&preamble)?
        .fixed_ephemeral_key_for_testing_only(&resp_ephem)
        .build_responder()?;

    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let mut pt = vec![0u8; MAX_FRAME_LEN];

    let n1 = initiator.write_message(&[], &mut buf)?;
    let msg1_frame = encode_frame(&buf[..n1])?;
    let (body1, _) = decode_frame(&msg1_frame)?;
    let _ = responder.read_message(body1, &mut pt)?;

    let host_hello = HostHello {
        host_id: device_id(resp_static_pub),
        proto_version: 1,
        rotation: vec![],
    };
    let host_hello_json = serde_json::to_string(&host_hello)?;
    let n2 = responder.write_message(host_hello_json.as_bytes(), &mut buf)?;
    let msg2_frame = encode_frame(&buf[..n2])?;
    let (body2, _) = decode_frame(&msg2_frame)?;
    let _ = initiator.read_message(body2, &mut pt)?;

    let post_msg2_hash: [u8; 32] = initiator.get_handshake_hash().try_into()?;

    let session_hello = SessionHello {
        device_id: device_id(init_static_pub),
        grant: None,
        crl_seq: Some(1),
    };
    let session_hello_json = serde_json::to_string(&session_hello)?;
    let n3 = initiator.write_message(session_hello_json.as_bytes(), &mut buf)?;
    let msg3_frame = encode_frame(&buf[..n3])?;
    let (body3, _) = decode_frame(&msg3_frame)?;
    let _ = responder.read_message(body3, &mut pt)?;

    let final_hash: [u8; 32] = initiator.get_handshake_hash().try_into()?;

    let mut init_tx = initiator.into_transport_mode()?;
    let mut resp_tx = responder.into_transport_mode()?;

    let data_inner = encode_inner_frame(InnerFrameType::Data, b"hello tendril")?;
    let nd = init_tx.write_message(&data_inner, &mut buf)?;
    let data_frame = encode_frame(&buf[..nd])?;
    let (dbody, _) = decode_frame(&data_frame)?;
    let nd_pt = resp_tx.read_message(dbody, &mut pt)?;
    assert_eq!(&pt[..nd_pt], data_inner.as_slice());

    let rekey_inner = encode_inner_frame(InnerFrameType::Rekey, &[])?;
    let nr = init_tx.write_message(&rekey_inner, &mut buf)?;
    let rekey_frame = encode_frame(&buf[..nr])?;
    init_tx.rekey_outgoing();
    let (rbody, _) = decode_frame(&rekey_frame)?;
    let nr_pt = resp_tx.read_message(rbody, &mut pt)?;
    assert_eq!(&pt[..nr_pt], rekey_inner.as_slice());
    resp_tx.rekey_incoming();

    let post_rekey_inner = encode_inner_frame(InnerFrameType::Data, b"after rekey")?;
    let np = init_tx.write_message(&post_rekey_inner, &mut buf)?;
    let post_rekey_frame = encode_frame(&buf[..np])?;
    let (pbody, _) = decode_frame(&post_rekey_frame)?;
    let np_pt = resp_tx.read_message(pbody, &mut pt)?;
    assert_eq!(&pt[..np_pt], post_rekey_inner.as_slice());

    Ok(SessionTranscriptVector {
        preamble_hex: hex::encode(preamble),
        initiator_static_scalar_hex: hex::encode(init_static),
        initiator_static_pub_hex: hex::encode(init_static_pub),
        initiator_ephem_scalar_hex: hex::encode(init_ephem),
        responder_static_scalar_hex: hex::encode(resp_static),
        responder_static_pub_hex: hex::encode(resp_static_pub),
        responder_ephem_scalar_hex: hex::encode(resp_ephem),
        host_hello_json,
        msg1_frame_hex: hex::encode(msg1_frame),
        msg2_frame_hex: hex::encode(msg2_frame),
        post_msg2_handshake_hash_hex: hex::encode(post_msg2_hash),
        session_hello_json,
        msg3_frame_hex: hex::encode(msg3_frame),
        final_handshake_hash_hex: hex::encode(final_hash),
        data_inner_hex: hex::encode(data_inner),
        data_frame_hex: hex::encode(data_frame),
        rekey_inner_hex: hex::encode(rekey_inner),
        rekey_frame_hex: hex::encode(rekey_frame),
        post_rekey_data_inner_hex: hex::encode(post_rekey_inner),
        post_rekey_data_frame_hex: hex::encode(post_rekey_frame),
    })
}

fn build_m2m_enrollment_vector() -> Result<M2mEnrollmentVector, Box<dyn std::error::Error>> {
    let now_unix = 1_795_132_800u64;
    let resp_static_scalar = seq_bytes(0x71);
    let resp_signing_seed = seq_bytes(0x72);
    let resp_ephem_scalar = seq_bytes(0x73);
    let resp_id = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(resp_static_scalar),
        SigningKeypair::from_seed(resp_signing_seed),
    );
    let resp_static_pub = *resp_id.static_key().public_bytes();
    let resp_signing_pub = *resp_id.signing_key().public_bytes();
    let responder_host_id = resp_id.host_id().to_string();

    let init_static_scalar = seq_bytes(0x81);
    let init_signing_seed = seq_bytes(0x82);
    let init_ephem_scalar = seq_bytes(0x83);
    let init_id = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(init_static_scalar),
        SigningKeypair::from_seed(init_signing_seed),
    );
    let init_static_pub = *init_id.static_key().public_bytes();
    let init_signing_pub = *init_id.signing_key().public_bytes();
    let initiator_device_id = init_id.device_id();

    let anchor_id = "anchor-ci".to_string();
    let anchor_signing_seed = seq_bytes(0x91);
    let anchor_identity = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(seq_bytes(0x92)),
        SigningKeypair::from_seed(anchor_signing_seed),
    )
    .with_host_id(&anchor_id);
    let anchor_signing_pub = *anchor_identity.signing_key().public_bytes();

    let nonce = [0x5Au8; 16];
    let enrollment_token = mint_enrollment_token(
        &anchor_identity,
        &responder_host_id,
        Some(&initiator_device_id),
        now_unix,
        900,
        nonce,
    )?;
    let token_unsigned = enrollment_token.unsigned();
    let token_jcs_json = canonical_json(&token_unsigned)?;
    let token_signed_bytes = grant_signed_bytes(&token_unsigned)?;

    let params: NoiseParams = NOISE_PATTERN.parse()?;
    let preamble = Preamble::v1(Intent::Pair).encode();
    let mut initiator = Builder::new(params.clone())
        .local_private_key(&init_static_scalar)?
        .prologue(&preamble)?
        .fixed_ephemeral_key_for_testing_only(&init_ephem_scalar)
        .build_initiator()?;
    let mut responder = Builder::new(params)
        .local_private_key(&resp_static_scalar)?
        .prologue(&preamble)?
        .fixed_ephemeral_key_for_testing_only(&resp_ephem_scalar)
        .build_responder()?;

    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let mut pt = vec![0u8; MAX_FRAME_LEN];

    let n1 = initiator.write_message(&[], &mut buf)?;
    let msg1_frame = encode_frame(&buf[..n1])?;
    let (body1, _) = decode_frame(&msg1_frame)?;
    let _ = responder.read_message(body1, &mut pt)?;

    let host_hello = HostHello {
        host_id: responder_host_id.clone(),
        proto_version: 1,
        rotation: vec![],
    };
    let host_hello_json = serde_json::to_string(&host_hello)?;
    let n2 = responder.write_message(host_hello_json.as_bytes(), &mut buf)?;
    let msg2_frame = encode_frame(&buf[..n2])?;
    let (body2, _) = decode_frame(&msg2_frame)?;
    let n_pt2 = initiator.read_message(body2, &mut pt)?;
    assert_eq!(&pt[..n_pt2], host_hello_json.as_bytes());

    let post_msg2_hash: [u8; 32] = initiator.get_handshake_hash().try_into()?;
    assert_eq!(post_msg2_hash, responder.get_handshake_hash());

    let proof_bytes =
        enroll_proof_bytes(&post_msg2_hash, &init_static_pub, &enrollment_token.nonce);
    let proof_sig = sign_enroll_proof(
        &init_id.signing_key().signing_key(),
        &post_msg2_hash,
        &init_static_pub,
        &enrollment_token.nonce,
    );
    let enroll_proof_b64url = b64url_encode(&proof_sig);

    let claim = PairClaim {
        name: "build-runner-01".to_string(),
        kind: "machine".to_string(),
        code_mac: None,
        enrollment_token: Some(enrollment_token.clone()),
        signing_pub: Some(b64url_encode(&init_signing_pub)),
        enroll_proof: Some(enroll_proof_b64url.clone()),
    };
    let pair_claim_json = serde_json::to_string(&claim)?;
    let n3 = initiator.write_message(pair_claim_json.as_bytes(), &mut buf)?;
    let msg3_frame = encode_frame(&buf[..n3])?;
    let (body3, _) = decode_frame(&msg3_frame)?;
    let n_pt3 = responder.read_message(body3, &mut pt)?;
    assert_eq!(&pt[..n_pt3], pair_claim_json.as_bytes());

    let final_hash: [u8; 32] = initiator.get_handshake_hash().try_into()?;
    assert_eq!(final_hash, responder.get_handshake_hash());

    let mut roster = Roster::new();
    roster.add_trust_anchor(anchor_id.clone(), anchor_signing_pub)?;
    let policy = EnrollmentPolicy::enabled_default();
    let (_, na) = verify_enrollment_token(
        &enrollment_token,
        &responder_host_id,
        &resp_signing_pub,
        &initiator_device_id,
        now_unix,
        &policy,
        &roster,
    )?;
    roster.burn_enrollment_nonce(&enrollment_token.nonce, na, now_unix)?;
    roster.record_enrolled_machine(init_static_pub, init_signing_pub, claim.name, claim.kind)?;

    let mut init_tx = initiator.into_transport_mode()?;
    let mut resp_tx = responder.into_transport_mode()?;
    let pair_resp = PairResponse::Success {
        device_id: initiator_device_id.clone(),
        status: "active".to_string(),
        host_signing_pub: b64url_encode(&resp_signing_pub),
    };
    let pair_response_json = serde_json::to_string(&pair_resp)?;
    let n4 = resp_tx.write_message(pair_response_json.as_bytes(), &mut buf)?;
    let pair_response_frame = encode_frame(&buf[..n4])?;
    let (body4, _) = decode_frame(&pair_response_frame)?;
    let n_pt4 = init_tx.read_message(body4, &mut pt)?;
    assert_eq!(&pt[..n_pt4], pair_response_json.as_bytes());

    let replayed_resp = PairResponse::Error {
        error: "token_replayed".to_string(),
    };
    let replayed_response_json = serde_json::to_string(&replayed_resp)?;

    Ok(M2mEnrollmentVector {
        noise_pattern: NOISE_PATTERN.to_string(),
        preamble_hex: hex::encode(preamble),
        now_unix,
        anchor_id,
        anchor_signing_seed_hex: hex::encode(anchor_signing_seed),
        anchor_signing_pub_hex: hex::encode(anchor_signing_pub),
        responder_host_id,
        responder_static_scalar_hex: hex::encode(resp_static_scalar),
        responder_static_pub_hex: hex::encode(resp_static_pub),
        responder_ephem_scalar_hex: hex::encode(resp_ephem_scalar),
        responder_signing_pub_hex: hex::encode(resp_signing_pub),
        initiator_static_scalar_hex: hex::encode(init_static_scalar),
        initiator_static_pub_hex: hex::encode(init_static_pub),
        initiator_device_id,
        initiator_ephem_scalar_hex: hex::encode(init_ephem_scalar),
        initiator_signing_seed_hex: hex::encode(init_signing_seed),
        initiator_signing_pub_hex: hex::encode(init_signing_pub),
        token_jcs_json,
        token_signed_bytes_hex: hex::encode(token_signed_bytes),
        enrollment_token,
        host_hello_json,
        msg1_frame_hex: hex::encode(msg1_frame),
        msg2_frame_hex: hex::encode(msg2_frame),
        post_msg2_handshake_hash_hex: hex::encode(post_msg2_hash),
        enroll_proof_domain_hex: hex::encode(ENROLL_PROOF_DOMAIN),
        enroll_proof_bytes_hex: hex::encode(proof_bytes),
        enroll_proof_b64url,
        pair_claim_json,
        msg3_frame_hex: hex::encode(msg3_frame),
        final_handshake_hash_hex: hex::encode(final_hash),
        pair_response_json,
        pair_response_frame_hex: hex::encode(pair_response_frame),
        replayed_response_json,
    })
}
