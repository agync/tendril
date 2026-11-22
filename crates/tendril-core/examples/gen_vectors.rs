//! Generates canonical v1 JSON test vectors under `spec/vectors/` using real crypto.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{
    ARGON2_KEY_LEN, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME, PAIR_MAC_LABEL, SAS_LABEL,
    SigningKeypair, StaticKeypair, argon2id_pairing_key, b64url_encode, compute_code_mac,
    device_id, fingerprint_device, fingerprint_host, normalize_code, pairing_sas,
    x25519_public_from_scalar,
};
use tendril_core::grants::{
    CRL_DOMAIN, GRANT_DOMAIN, Grant, GrantUnsigned, RevocationList, RevocationListUnsigned,
    canonical_json, crl_signed_bytes, grant_signed_bytes, sign_crl_deterministic,
    sign_grant_deterministic,
};
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, rotation_signed_bytes, sign_rotation_deterministic,
};
use tendril_core::noise::{NoiseHfsHandshakeBuilder, NoiseHfsSeeds};
use tendril_core::pairing::{
    ENROLL_PROOF_DOMAIN, EnrollmentPolicy, enroll_proof_bytes, mint_enrollment_token_deterministic,
    sign_enroll_proof_deterministic, verify_enrollment_token,
};
use tendril_core::relay_auth::{
    RelayAuthProof, RelayAuthRole, RelayTicket, compute_relay_auth_hmac,
    compute_relay_auth_hmac_b64, mint_relay_ticket, relay_auth_hmac_input, relay_ticket_jcs,
    relay_ticket_signed_bytes, verify_relay_auth_hmac, verify_relay_ticket,
};
use tendril_core::roster::Roster;
use tendril_core::v2::{
    PAKE_ARGON2_MEMORY_KIB, PAKE_ARGON2_PARALLELISM, PAKE_ARGON2_TIME, PaddingPolicy,
    PakeArgon2Params, V2_PAKE_SALT_LEN, canonical_relay_host, compute_pake_init_mac,
    compute_pake_msg1_mac, compute_pake_resp_mac, compute_rendezvous_mac, decode_v2_inner_frame,
    derive_epoch_mailbox, derive_pake_keys, derive_pake_master, encode_dummy_cover_frame,
    epoch_for_unix, pad_inner_frame, pad_msg3_payload, pad_pake_msg3_payload, pad_v2_pair_response,
    pake_msg2_bucket_for_hello_len, pake_noise_prologue, seal_pake_host_hello,
    seal_v2_hello_envelope, sign_v2_relay_accept, sign_v2_relay_dial, sign_v2_relay_register,
    unpad_inner_frame, unpad_msg3_payload, unpad_pake_msg3_payload, unpad_v2_pair_response,
    unseal_pake_host_hello, unseal_v2_hello_envelope, v2_relay_accept_signed_bytes,
    v2_relay_dial_signed_bytes, v2_relay_register_signed_bytes, verify_v2_relay_accept,
    verify_v2_relay_dial, verify_v2_relay_register,
};
use tendril_core::wire::{
    HostHello, InnerFrameType, Intent, NOISE_PATTERN, PREAMBLE_FLAG_NONE, PairClaim, PairResponse,
    Preamble, SessionHello, WIRE_VERSION_V2, decode_frame, encode_frame, encode_inner_frame,
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
    pinned_signing_mldsa_seed_hex: String,
    pinned_signing_pub_hex: String,
    pinned_static_scalar_hex: String,
    pinned_static_pub_hex: String,
    step1_signing_seed_hex: String,
    step1_signing_mldsa_seed_hex: String,
    step1_static_scalar_hex: String,
    step2_signing_seed_hex: String,
    step2_signing_mldsa_seed_hex: String,
    step2_static_scalar_hex: String,
    fork_signing_seed_hex: String,
    fork_signing_mldsa_seed_hex: String,
    fork_static_scalar_hex: String,
    chain: Vec<RotationStep>,
    fork_record: RotationStep,
}

#[derive(Serialize)]
struct GrantsVector {
    root_issuer_id: String,
    root_signing_seed_hex: String,
    root_signing_mldsa_seed_hex: String,
    root_signing_pub_hex: String,
    delegate_id: String,
    delegate_signing_seed_hex: String,
    delegate_signing_mldsa_seed_hex: String,
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

#[derive(Serialize)]
struct SessionTranscriptVector {
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
    anchor_signing_mldsa_seed_hex: String,
    anchor_signing_pub_hex: String,
    responder_host_id: String,
    responder_static_scalar_hex: String,
    responder_static_pub_hex: String,
    responder_ephem_scalar_hex: String,
    responder_mlkem768_encaps_seed_hex: String,
    responder_signing_seed_hex: String,
    responder_signing_mldsa_seed_hex: String,
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

#[derive(Serialize)]
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

#[derive(Serialize)]
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
    ticket_issuer_seed_hex: String,
    ticket_issuer_pub_hex: String,
    ticket_now_unix: u64,
    ticket_ttl_secs: u64,
    ticket_jcs_json: String,
    ticket_signed_bytes_hex: String,
    ticket_sig_hex: String,
    ticket: RelayTicket,
    ticket_proof_json: String,
    hmac_proof_json: String,
}

#[derive(Serialize)]
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
    responder_signing_seed_hex: String,
    responder_signing_mldsa_seed_hex: String,
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

#[derive(Serialize)]
struct V2PakeVector {
    preamble_hex: String,
    code: String,
    code_normalized: String,
    channel_salt_hex: String,
    argon2id: Argon2ParamsSpec,
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
    responder_signing_seed_hex: String,
    responder_signing_mldsa_seed_hex: String,
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

#[derive(Serialize)]
struct WireV2Vector {
    noise_pattern: String,
    v2_session_preamble_hex: String,
    v2_pake_pair_preamble_hex: String,
    blinded_relay: BlindedRelayVector,
    relay_admission: RelayAdmissionVector,
    v2_reconnect: V2ReconnectVector,
    pake_pairing: V2PakeVector,
}

fn concat64(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(a);
    out[32..].copy_from_slice(b);
    out
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
    let mldsa_seed0 = seq_bytes(0x80);
    let key0 = SigningKeypair::from_seeds(seed0, mldsa_seed0);
    let static0 = seq_bytes(0x40);
    let static0_pub = x25519_public_from_scalar(&static0);

    let seed1 = seq_bytes(0x10);
    let mldsa_seed1 = seq_bytes(0x90);
    let key1 = SigningKeypair::from_seeds(seed1, mldsa_seed1);
    let static1 = seq_bytes(0x50);
    let static1_pub = x25519_public_from_scalar(&static1);

    let seed2 = seq_bytes(0x20);
    let mldsa_seed2 = seq_bytes(0xA0);
    let key2 = SigningKeypair::from_seeds(seed2, mldsa_seed2);
    let static2 = seq_bytes(0x60);
    let static2_pub = x25519_public_from_scalar(&static2);

    let fork_seed = seq_bytes(0x30);
    let fork_mldsa_seed = seq_bytes(0xB0);
    let fork_key = SigningKeypair::from_seeds(fork_seed, fork_mldsa_seed);
    let fork_static = seq_bytes(0x70);
    let fork_static_pub = x25519_public_from_scalar(&fork_static);

    let ts1 = 1_795_132_800; // 2026-11-20T00:00:00Z
    let ts2 = 1_795_219_200; // 2026-11-21T00:00:00Z
    let ts_fork = 1_795_219_260; // 2026-11-21T00:01:00Z

    let rec1 = sign_rotation_deterministic(1, &key0, key1.public_key(), &static1_pub, ts1)?;
    let bytes1 = rotation_signed_bytes(1, key0.public_key(), key1.public_key(), &static1_pub, ts1);
    let rec2 = sign_rotation_deterministic(2, &key1, key2.public_key(), &static2_pub, ts2)?;
    let bytes2 = rotation_signed_bytes(2, key1.public_key(), key2.public_key(), &static2_pub, ts2);
    let rec_fork =
        sign_rotation_deterministic(2, &key1, fork_key.public_key(), &fork_static_pub, ts_fork)?;
    let bytes_fork = rotation_signed_bytes(
        2,
        key1.public_key(),
        fork_key.public_key(),
        &fork_static_pub,
        ts_fork,
    );

    let rotation = RotationVector {
        pinned_signing_seed_hex: hex::encode(seed0),
        pinned_signing_mldsa_seed_hex: hex::encode(mldsa_seed0),
        pinned_signing_pub_hex: hex::encode(key0.public_bytes()),
        pinned_static_scalar_hex: hex::encode(static0),
        pinned_static_pub_hex: hex::encode(static0_pub),
        step1_signing_seed_hex: hex::encode(seed1),
        step1_signing_mldsa_seed_hex: hex::encode(mldsa_seed1),
        step1_static_scalar_hex: hex::encode(static1),
        step2_signing_seed_hex: hex::encode(seed2),
        step2_signing_mldsa_seed_hex: hex::encode(mldsa_seed2),
        step2_static_scalar_hex: hex::encode(static2),
        fork_signing_seed_hex: hex::encode(fork_seed),
        fork_signing_mldsa_seed_hex: hex::encode(fork_mldsa_seed),
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
    let root_mldsa_seed = seq_bytes(0xC0);
    let root_signing = SigningKeypair::from_seeds(root_seed, root_mldsa_seed);
    let root_static = x25519_public_from_scalar(&seq_bytes(0x90));
    let root_id = device_id(&root_static);

    let del_seed = seq_bytes(0xa0);
    let del_mldsa_seed = seq_bytes(0xE0);
    let del_signing = SigningKeypair::from_seeds(del_seed, del_mldsa_seed);
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
    let root_grant = sign_grant_deterministic(root_unsigned, &root_signing)?;

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
    let delegated_valid = sign_grant_deterministic(valid_child_unsigned, &del_signing)?;

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
    let delegated_widened = sign_grant_deterministic(widened_child_unsigned, &del_signing)?;

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
    let revocation_list = sign_crl_deterministic(crl_unsigned, &root_signing)?;

    assert!(root_signed_bytes.starts_with(GRANT_DOMAIN));
    assert!(crl_signed_bytes.starts_with(CRL_DOMAIN));

    let grants_vec = GrantsVector {
        root_issuer_id: root_id,
        root_signing_seed_hex: hex::encode(root_seed),
        root_signing_mldsa_seed_hex: hex::encode(root_mldsa_seed),
        root_signing_pub_hex: hex::encode(root_signing.public_bytes()),
        delegate_id: del_id,
        delegate_signing_seed_hex: hex::encode(del_seed),
        delegate_signing_mldsa_seed_hex: hex::encode(del_mldsa_seed),
        delegate_signing_pub_hex: hex::encode(del_signing.public_bytes()),
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

    // 7. wire_v2.json
    let wire_v2_vec = generate_wire_v2_vector()?;
    write_json(&vectors_dir, "wire_v2.json", &wire_v2_vec)?;

    println!(
        "Generated 7 canonical vector files under {}",
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
    let init_d = seq_bytes(0x52);
    let init_z = seq_bytes(0x53);
    let resp_ephem = seq_bytes(0x61);
    let resp_m = seq_bytes(0x62);
    let preamble = Preamble::v1(Intent::Pair).encode();

    let mut initiator = NoiseHfsHandshakeBuilder::new()
        .local_private_key(init_static)
        .prologue(&preamble)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: init_ephem,
            mlkem_d: init_d,
            mlkem_z: init_z,
            mlkem_m: [0u8; 32],
        })
        .build_initiator()?;
    let mut responder = NoiseHfsHandshakeBuilder::new()
        .local_private_key(resp_static)
        .prologue(&preamble)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: resp_ephem,
            mlkem_d: [0u8; 32],
            mlkem_z: [0u8; 32],
            mlkem_m: resp_m,
        })
        .build_responder()?;

    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let mut pt = vec![0u8; MAX_FRAME_LEN];

    let n1 = initiator.write_message(&[], &mut buf)?;
    let msg1_frame = encode_frame(&buf[..n1])?;
    let (body1, _) = decode_frame(&msg1_frame)?;
    let _ = responder.read_message(body1, &mut pt)?;

    let host_signing = SigningKeypair::from_seeds(seq_bytes(0x71), seq_bytes(0x75));
    let host_signing_pub_b64 = host_signing.public_key().to_b64url();
    let host_hello = HostHello {
        host_id: device_id(resp_static_pub),
        proto_version: 1,
        signing_pub: host_signing_pub_b64.clone(),
        rotation: vec![],
    };
    let host_hello_json = serde_json::to_string(&host_hello)?;
    let n2 = responder.write_message(host_hello_json.as_bytes(), &mut buf)?;
    let msg2_frame = encode_frame(&buf[..n2])?;
    let (body2, _) = decode_frame(&msg2_frame)?;
    let n_pt2 = initiator.read_message(body2, &mut pt)?;
    assert_eq!(&pt[..n_pt2], host_hello_json.as_bytes());

    let post_msg2_hash: [u8; 32] = *initiator.get_handshake_hash();
    let resp_hash: [u8; 32] = *responder.get_handshake_hash();
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
    assert_eq!(responder.get_remote_static(), Some(init_static_pub));

    let final_hash: [u8; 32] = *initiator.get_handshake_hash();
    assert_eq!(final_hash, *responder.get_handshake_hash());

    let mut init_tx = initiator.into_transport_mode()?;
    let mut resp_tx = responder.into_transport_mode()?;

    let pair_resp = PairResponse::Success {
        device_id: device_id(init_static_pub),
        status: "pending".to_string(),
        host_signing_pub: host_signing_pub_b64,
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
        initiator_mlkem768_keygen_seed_hex: hex::encode(concat64(&init_d, &init_z)),
        responder_static_scalar_hex: hex::encode(resp_static),
        responder_static_pub_hex: hex::encode(resp_static_pub),
        responder_ephem_scalar_hex: hex::encode(resp_ephem),
        responder_mlkem768_encaps_seed_hex: hex::encode(resp_m),
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
    let init_d = seq_bytes(0x82);
    let init_z = seq_bytes(0x83);
    let resp_ephem = seq_bytes(0x91);
    let resp_m = seq_bytes(0x92);
    let preamble = Preamble::v1(Intent::Session).encode();

    let mut initiator = NoiseHfsHandshakeBuilder::new()
        .local_private_key(init_static)
        .prologue(&preamble)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: init_ephem,
            mlkem_d: init_d,
            mlkem_z: init_z,
            mlkem_m: [0u8; 32],
        })
        .build_initiator()?;
    let mut responder = NoiseHfsHandshakeBuilder::new()
        .local_private_key(resp_static)
        .prologue(&preamble)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: resp_ephem,
            mlkem_d: [0u8; 32],
            mlkem_z: [0u8; 32],
            mlkem_m: resp_m,
        })
        .build_responder()?;

    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let mut pt = vec![0u8; MAX_FRAME_LEN];

    let n1 = initiator.write_message(&[], &mut buf)?;
    let msg1_frame = encode_frame(&buf[..n1])?;
    let (body1, _) = decode_frame(&msg1_frame)?;
    let _ = responder.read_message(body1, &mut pt)?;

    let host_signing = SigningKeypair::from_seeds(seq_bytes(0x71), seq_bytes(0x75));
    let host_hello = HostHello {
        host_id: device_id(resp_static_pub),
        proto_version: 1,
        signing_pub: host_signing.public_key().to_b64url(),
        rotation: vec![],
    };
    let host_hello_json = serde_json::to_string(&host_hello)?;
    let n2 = responder.write_message(host_hello_json.as_bytes(), &mut buf)?;
    let msg2_frame = encode_frame(&buf[..n2])?;
    let (body2, _) = decode_frame(&msg2_frame)?;
    let _ = initiator.read_message(body2, &mut pt)?;

    let post_msg2_hash: [u8; 32] = *initiator.get_handshake_hash();

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

    let final_hash: [u8; 32] = *initiator.get_handshake_hash();

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
    init_tx.rekey_outgoing()?;
    let (rbody, _) = decode_frame(&rekey_frame)?;
    let nr_pt = resp_tx.read_message(rbody, &mut pt)?;
    assert_eq!(&pt[..nr_pt], rekey_inner.as_slice());
    resp_tx.rekey_incoming()?;

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
        initiator_mlkem768_keygen_seed_hex: hex::encode(concat64(&init_d, &init_z)),
        responder_static_scalar_hex: hex::encode(resp_static),
        responder_static_pub_hex: hex::encode(resp_static_pub),
        responder_ephem_scalar_hex: hex::encode(resp_ephem),
        responder_mlkem768_encaps_seed_hex: hex::encode(resp_m),
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
    let resp_signing_mldsa_seed = seq_bytes(0x76);
    let resp_ephem_scalar = seq_bytes(0x73);
    let resp_m = seq_bytes(0x74);
    let resp_id = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(resp_static_scalar),
        SigningKeypair::from_seeds(resp_signing_seed, resp_signing_mldsa_seed),
    );
    let resp_static_pub = *resp_id.static_key().public_bytes();
    let resp_signing_pub = resp_id.signing_key().public_key().clone();
    let responder_host_id = resp_id.host_id().to_string();

    let init_static_scalar = seq_bytes(0x81);
    let init_signing_seed = seq_bytes(0x82);
    let init_signing_mldsa_seed = seq_bytes(0x86);
    let init_ephem_scalar = seq_bytes(0x83);
    let init_d = seq_bytes(0x84);
    let init_z = seq_bytes(0x85);
    let init_id = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(init_static_scalar),
        SigningKeypair::from_seeds(init_signing_seed, init_signing_mldsa_seed),
    );
    let init_static_pub = *init_id.static_key().public_bytes();
    let init_signing_pub = init_id.signing_key().public_key().clone();
    let initiator_device_id = init_id.device_id();

    let anchor_id = "anchor-ci".to_string();
    let anchor_signing_seed = seq_bytes(0x91);
    let anchor_signing_mldsa_seed = seq_bytes(0x95);
    let anchor_identity = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(seq_bytes(0x92)),
        SigningKeypair::from_seeds(anchor_signing_seed, anchor_signing_mldsa_seed),
    )
    .with_host_id(&anchor_id);
    let anchor_signing_pub = anchor_identity.signing_key().public_key().clone();

    let nonce = [0x5Au8; 16];
    let enrollment_token = mint_enrollment_token_deterministic(
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

    let preamble = Preamble::v1(Intent::Pair).encode();
    let mut initiator = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&init_static_scalar)
        .prologue(&preamble)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: init_ephem_scalar,
            mlkem_d: init_d,
            mlkem_z: init_z,
            mlkem_m: [0u8; 32],
        })
        .build_initiator()?;
    let mut responder = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&resp_static_scalar)
        .prologue(&preamble)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: resp_ephem_scalar,
            mlkem_d: [0u8; 32],
            mlkem_z: [0u8; 32],
            mlkem_m: resp_m,
        })
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
        signing_pub: resp_signing_pub.to_b64url(),
        rotation: vec![],
    };
    let host_hello_json = serde_json::to_string(&host_hello)?;
    let n2 = responder.write_message(host_hello_json.as_bytes(), &mut buf)?;
    let msg2_frame = encode_frame(&buf[..n2])?;
    let (body2, _) = decode_frame(&msg2_frame)?;
    let n_pt2 = initiator.read_message(body2, &mut pt)?;
    assert_eq!(&pt[..n_pt2], host_hello_json.as_bytes());

    let post_msg2_hash: [u8; 32] = *initiator.get_handshake_hash();
    assert_eq!(post_msg2_hash, *responder.get_handshake_hash());

    let proof_bytes =
        enroll_proof_bytes(&post_msg2_hash, &init_static_pub, &enrollment_token.nonce);
    let proof_sig = sign_enroll_proof_deterministic(
        init_id.signing_key(),
        &post_msg2_hash,
        &init_static_pub,
        &enrollment_token.nonce,
    )?;
    let enroll_proof_b64url = b64url_encode(&proof_sig);

    let claim = PairClaim {
        name: "build-runner-01".to_string(),
        kind: "machine".to_string(),
        code_mac: None,
        enrollment_token: Some(enrollment_token.clone()),
        signing_pub: Some(init_signing_pub.to_b64url()),
        enroll_proof: Some(enroll_proof_b64url.clone()),
    };
    let pair_claim_json = serde_json::to_string(&claim)?;
    let n3 = initiator.write_message(pair_claim_json.as_bytes(), &mut buf)?;
    let msg3_frame = encode_frame(&buf[..n3])?;
    let (body3, _) = decode_frame(&msg3_frame)?;
    let n_pt3 = responder.read_message(body3, &mut pt)?;
    assert_eq!(&pt[..n_pt3], pair_claim_json.as_bytes());

    let final_hash: [u8; 32] = *initiator.get_handshake_hash();
    assert_eq!(final_hash, *responder.get_handshake_hash());

    let mut roster = Roster::new();
    roster.add_trust_anchor(anchor_id.clone(), anchor_signing_pub.clone())?;
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
    roster.record_enrolled_machine(
        init_static_pub,
        init_signing_pub.clone(),
        claim.name,
        claim.kind,
    )?;

    let mut init_tx = initiator.into_transport_mode()?;
    let mut resp_tx = responder.into_transport_mode()?;
    let pair_resp = PairResponse::Success {
        device_id: initiator_device_id.clone(),
        status: "active".to_string(),
        host_signing_pub: resp_signing_pub.to_b64url(),
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
        anchor_signing_mldsa_seed_hex: hex::encode(anchor_signing_mldsa_seed),
        anchor_signing_pub_hex: hex::encode(anchor_signing_pub.as_bytes()),
        responder_host_id,
        responder_static_scalar_hex: hex::encode(resp_static_scalar),
        responder_static_pub_hex: hex::encode(resp_static_pub),
        responder_ephem_scalar_hex: hex::encode(resp_ephem_scalar),
        responder_mlkem768_encaps_seed_hex: hex::encode(resp_m),
        responder_signing_seed_hex: hex::encode(resp_signing_seed),
        responder_signing_mldsa_seed_hex: hex::encode(resp_signing_mldsa_seed),
        responder_signing_pub_hex: hex::encode(resp_signing_pub.as_bytes()),
        initiator_static_scalar_hex: hex::encode(init_static_scalar),
        initiator_static_pub_hex: hex::encode(init_static_pub),
        initiator_device_id,
        initiator_ephem_scalar_hex: hex::encode(init_ephem_scalar),
        initiator_mlkem768_keygen_seed_hex: hex::encode(concat64(&init_d, &init_z)),
        initiator_signing_seed_hex: hex::encode(init_signing_seed),
        initiator_signing_mldsa_seed_hex: hex::encode(init_signing_mldsa_seed),
        initiator_signing_pub_hex: hex::encode(init_signing_pub.as_bytes()),
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

fn generate_wire_v2_vector() -> Result<WireV2Vector, Box<dyn std::error::Error>> {
    use ed25519_dalek::SigningKey;

    let v2_session_preamble = Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE).encode();
    let v2_pake_pair_preamble = Preamble::v2_pake_pair().encode();

    // 1. Blinded /v2/relay hourly epoch
    let mailbox_secret = seq_bytes(0x90);
    let unix_secs = 1_795_134_200u64;
    let epoch = epoch_for_unix(unix_secs);
    let mailbox = derive_epoch_mailbox(&mailbox_secret, epoch);
    let relay_host_raw = "RELAY.Tendril.Test.".to_string();
    let relay_host_canonical = canonical_relay_host(&relay_host_raw)?;
    let challenge_nonce = seq_bytes(0xA0);
    let conn_id: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F,
    ];
    let register_signed_bytes =
        v2_relay_register_signed_bytes(&relay_host_raw, &challenge_nonce, epoch)?;
    let register_sig = sign_v2_relay_register(&mailbox, &relay_host_raw, &challenge_nonce)?;
    verify_v2_relay_register(
        &mailbox.mailbox_id,
        epoch,
        &relay_host_canonical,
        &challenge_nonce,
        &register_sig,
    )?;

    let dial_mac_input = v2_relay_dial_signed_bytes(
        &relay_host_raw,
        &challenge_nonce,
        &mailbox.mailbox_id,
        &conn_id,
        epoch,
    )?;
    let dial_token = sign_v2_relay_dial(&mailbox, &relay_host_raw, &challenge_nonce, &conn_id)?;
    verify_v2_relay_dial(
        &mailbox,
        &relay_host_canonical,
        &challenge_nonce,
        &conn_id,
        &dial_token,
    )?;

    let accept_signed_bytes =
        v2_relay_accept_signed_bytes(&relay_host_raw, &challenge_nonce, &conn_id, epoch)?;
    let accept_sig = sign_v2_relay_accept(&mailbox, &relay_host_raw, &challenge_nonce, &conn_id)?;
    verify_v2_relay_accept(
        &mailbox.mailbox_id,
        epoch,
        &relay_host_canonical,
        &challenge_nonce,
        &conn_id,
        &accept_sig,
    )?;

    let blinded_relay = BlindedRelayVector {
        mailbox_secret_hex: hex::encode(mailbox_secret),
        unix_secs,
        epoch,
        epoch_signing_seed_hex: hex::encode(mailbox.signing_key().to_bytes()),
        dial_auth_key_hex: hex::encode(mailbox.dial_auth_key()),
        mailbox_id_hex: hex::encode(mailbox.mailbox_id),
        mailbox_id_b64url: b64url_encode(&mailbox.mailbox_id),
        relay_host_raw,
        relay_host_canonical,
        challenge_nonce_hex: hex::encode(challenge_nonce),
        conn_id_hex: hex::encode(conn_id),
        register_signed_bytes_hex: hex::encode(register_signed_bytes),
        register_sig_hex: hex::encode(register_sig),
        register_sig_b64url: b64url_encode(&register_sig),
        dial_mac_input_hex: hex::encode(dial_mac_input),
        dial_token_hex: hex::encode(dial_token),
        dial_token_b64url: b64url_encode(&dial_token),
        accept_signed_bytes_hex: hex::encode(accept_signed_bytes),
        accept_sig_hex: hex::encode(accept_sig),
        accept_sig_b64url: b64url_encode(&accept_sig),
    };

    // 2. Relay Admission (Tier 2 HMAC + Tier 3 Ed25519 JCS RelayTicket)
    let shared_secret = seq_bytes(0xB0);
    let adm_host_raw = "Relay.Example.COM.".to_string();
    let adm_host_canon = canonical_relay_host(&adm_host_raw)?;
    let adm_nonce = seq_bytes(0xC0);
    let pub_or_target = SigningKey::from_bytes(&seq_bytes(0xD0))
        .verifying_key()
        .to_bytes();

    let hmac_input = relay_auth_hmac_input("register", &adm_host_raw, &adm_nonce, &pub_or_target)?;
    let hmac_mac = compute_relay_auth_hmac(
        &shared_secret,
        "register",
        &adm_host_raw,
        &adm_nonce,
        &pub_or_target,
    )?;
    let hmac_mac_b64url = compute_relay_auth_hmac_b64(
        &shared_secret,
        "register",
        &adm_host_raw,
        &adm_nonce,
        &pub_or_target,
    )?;
    verify_relay_auth_hmac(
        &shared_secret,
        "register",
        &adm_host_canon,
        &adm_nonce,
        &pub_or_target,
        &hmac_mac_b64url,
    )?;

    let dial_hmac_input = relay_auth_hmac_input("dial", &adm_host_raw, &adm_nonce, &pub_or_target)?;
    let dial_hmac_mac = compute_relay_auth_hmac(
        &shared_secret,
        "dial",
        &adm_host_raw,
        &adm_nonce,
        &pub_or_target,
    )?;
    let accept_hmac_input =
        relay_auth_hmac_input("accept", &adm_host_raw, &adm_nonce, &pub_or_target)?;
    let accept_hmac_mac = compute_relay_auth_hmac(
        &shared_secret,
        "accept",
        &adm_host_raw,
        &adm_nonce,
        &pub_or_target,
    )?;

    let ticket_issuer_seed = seq_bytes(0xE0);
    let ticket_issuer_sk = SigningKey::from_bytes(&ticket_issuer_seed);
    let ticket_issuer_pub = ticket_issuer_sk.verifying_key().to_bytes();
    let ticket_now_unix = 1_795_132_800u64;
    let ticket_ttl_secs = 3_600u64;
    let ticket = mint_relay_ticket(
        &ticket_issuer_sk,
        &adm_host_raw,
        RelayAuthRole::Dial,
        &b64url_encode(&pub_or_target),
        ticket_now_unix,
        ticket_ttl_secs,
    )?;
    let ticket_jcs_json = relay_ticket_jcs(&ticket)?;
    let ticket_signed_bytes = relay_ticket_signed_bytes(&ticket)?;
    let ticket_sig = tendril_core::crypto::b64url_decode_array::<64>(&ticket.sig)?;
    verify_relay_ticket(
        &ticket,
        &[ticket_issuer_pub],
        &adm_host_canon,
        RelayAuthRole::Dial,
        &pub_or_target,
        ticket_now_unix + 60,
    )?;

    let hmac_proof_json = serde_json::to_string(&RelayAuthProof::Hmac {
        mac: hmac_mac_b64url.clone(),
    })?;
    let ticket_proof_json = serde_json::to_string(&RelayAuthProof::Ticket {
        ticket: ticket.clone(),
    })?;

    let relay_admission = RelayAdmissionVector {
        shared_secret_hex: hex::encode(shared_secret),
        op: "register".to_string(),
        dial_op: "dial".to_string(),
        accept_op: "accept".to_string(),
        relay_host_raw: adm_host_raw,
        relay_host_canonical: adm_host_canon,
        challenge_nonce_hex: hex::encode(adm_nonce),
        pub_or_target_hex: hex::encode(pub_or_target),
        hmac_input_hex: hex::encode(hmac_input),
        hmac_mac_hex: hex::encode(hmac_mac),
        hmac_mac_b64url,
        dial_hmac_input_hex: hex::encode(dial_hmac_input),
        dial_hmac_mac_hex: hex::encode(dial_hmac_mac),
        accept_hmac_input_hex: hex::encode(accept_hmac_input),
        accept_hmac_mac_hex: hex::encode(accept_hmac_mac),
        ticket_issuer_seed_hex: hex::encode(ticket_issuer_seed),
        ticket_issuer_pub_hex: hex::encode(ticket_issuer_pub),
        ticket_now_unix,
        ticket_ttl_secs,
        ticket_jcs_json,
        ticket_signed_bytes_hex: hex::encode(ticket_signed_bytes),
        ticket_sig_hex: hex::encode(ticket_sig),
        ticket,
        ticket_proof_json,
        hmac_proof_json,
    };

    // 3. Pseudonymous v2 Reconnect
    let v2_reconnect = build_v2_reconnect_vector(&v2_session_preamble)?;

    // 4. Hybrid Argon2id PAKE + ML-KEM-768 Pairing
    let pake_pairing = build_v2_pake_vector(&v2_pake_pair_preamble)?;

    Ok(WireV2Vector {
        noise_pattern: NOISE_PATTERN.to_string(),
        v2_session_preamble_hex: hex::encode(v2_session_preamble),
        v2_pake_pair_preamble_hex: hex::encode(v2_pake_pair_preamble),
        blinded_relay,
        relay_admission,
        v2_reconnect,
        pake_pairing,
    })
}

fn build_v2_reconnect_vector(
    preamble: &[u8; 6],
) -> Result<V2ReconnectVector, Box<dyn std::error::Error>> {
    use tendril_core::crypto::hkdf_sha256_32;

    let init_static = seq_bytes(0x31);
    let init_static_pub = x25519_public_from_scalar(&init_static);
    let init_ephem = seq_bytes(0x32);
    let init_d = seq_bytes(0x33);
    let init_z = seq_bytes(0x34);

    let resp_static = seq_bytes(0x41);
    let resp_static_pub = x25519_public_from_scalar(&resp_static);
    let resp_ephem = seq_bytes(0x42);
    let resp_m = seq_bytes(0x43);
    let resp_signing_seed = seq_bytes(0x44);
    let resp_signing_mldsa_seed = seq_bytes(0x45);
    let resp_signing = SigningKeypair::from_seeds(resp_signing_seed, resp_signing_mldsa_seed);

    let reconnect_secret = seq_bytes(0x55);
    let rendezvous_nonce: [u8; 16] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        0xB8,
    ];
    let ts_unix = 1_795_134_200u64;

    let mut initiator = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&init_static)
        .prologue(preamble)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: init_ephem,
            mlkem_d: init_d,
            mlkem_z: init_z,
            mlkem_m: [0u8; 32],
        })
        .build_initiator()?;
    let mut responder = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&resp_static)
        .prologue(preamble)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: resp_ephem,
            mlkem_d: [0u8; 32],
            mlkem_z: [0u8; 32],
            mlkem_m: resp_m,
        })
        .build_responder()?;

    let mut ekem_i_hash = [0u8; 32];
    let mut rendezvous_mac = [0u8; 32];
    let mut msg1_payload = Vec::new();
    let msg1_body = initiator.write_msg1_with_payload(|e_i_pub, ek_bytes| {
        ekem_i_hash = Sha256::digest(ek_bytes).into();
        rendezvous_mac = compute_rendezvous_mac(
            &reconnect_secret,
            preamble,
            e_i_pub,
            &ekem_i_hash,
            &rendezvous_nonce,
            ts_unix,
        );
        let mut p = Vec::with_capacity(56);
        p.extend_from_slice(&rendezvous_nonce);
        p.extend_from_slice(&ts_unix.to_be_bytes());
        p.extend_from_slice(&rendezvous_mac);
        msg1_payload = p.clone();
        Ok(p)
    })?;
    let msg1_frame = encode_frame(&msg1_body)?;
    let (body1, _) = decode_frame(&msg1_frame)?;
    let dec1 = responder.read_message_vec(body1)?;
    assert_eq!(&*dec1, msg1_payload.as_slice());

    let host_hello = HostHello {
        host_id: device_id(&resp_static_pub),
        proto_version: WIRE_VERSION_V2,
        signing_pub: resp_signing.public_key().to_b64url(),
        rotation: vec![],
    };
    let host_hello_json = serde_json::to_string(&host_hello)?;

    let hello_seal_key = hkdf_sha256_32(
        &reconnect_secret,
        &rendezvous_nonce,
        b"tendril-v2-hello-seal",
    );
    let mut pre_msg2_hash = [0u8; 32];
    let mut sealed_hello_envelope = Vec::new();
    let msg2_body = responder.write_msg2_with_hash(|h_pre| {
        pre_msg2_hash = *h_pre;
        let env = seal_v2_hello_envelope(
            &reconnect_secret,
            &rendezvous_nonce,
            h_pre,
            host_hello_json.as_bytes(),
        )?;
        sealed_hello_envelope = env.clone();
        Ok(env)
    })?;
    let bucket_len = sealed_hello_envelope.len();
    let msg2_frame = encode_frame(&msg2_body)?;
    let (body2, _) = decode_frame(&msg2_frame)?;
    let (dec2, init_h_pre) = initiator.read_msg2_with_pre_payload_hash(body2)?;
    assert_eq!(init_h_pre, pre_msg2_hash);
    let unsealed_hello =
        unseal_v2_hello_envelope(&reconnect_secret, &rendezvous_nonce, &init_h_pre, &dec2)?;
    assert_eq!(&*unsealed_hello, host_hello_json.as_bytes());

    let post_msg2_hash = *initiator.get_handshake_hash();
    assert_eq!(post_msg2_hash, *responder.get_handshake_hash());

    let session_hello = SessionHello {
        device_id: device_id(&init_static_pub),
        grant: None,
        crl_seq: Some(0),
    };
    let session_hello_json = serde_json::to_string(&session_hello)?;
    let msg3_padded_payload = pad_msg3_payload(session_hello_json.as_bytes())?;
    let msg3_body = initiator.write_message_vec(&msg3_padded_payload)?;
    let msg3_frame = encode_frame(&msg3_body)?;
    let (body3, _) = decode_frame(&msg3_frame)?;
    let dec3 = responder.read_message_vec(body3)?;
    assert_eq!(unpad_msg3_payload(&dec3)?, session_hello_json.as_bytes());

    let final_hash = *initiator.get_handshake_hash();
    assert_eq!(final_hash, *responder.get_handshake_hash());

    let mut init_tx = initiator.into_transport_mode()?;
    let mut resp_tx = responder.into_transport_mode()?;
    let (exported_reconnect, exported_mailbox) = init_tx.export_v2_secrets(&resp_static_pub);
    assert_eq!(
        resp_tx.export_v2_secrets(&resp_static_pub),
        (exported_reconnect.clone(), exported_mailbox.clone())
    );

    let policy = PaddingPolicy::v2_default();
    let padded_data_payload = b"hello-v2-padded".to_vec();
    let padded_inner = pad_inner_frame(InnerFrameType::Data, &padded_data_payload, &policy)?;
    let padded_ct = init_tx.write_message_vec(&padded_inner)?;
    let padded_frame = encode_frame(&padded_ct)?;
    let (pbody, _) = decode_frame(&padded_frame)?;
    let dec_padded = resp_tx.read_message_vec(pbody)?;
    assert_eq!(
        unpad_inner_frame(&dec_padded)?,
        (InnerFrameType::Data, padded_data_payload.clone())
    );

    let cover_bucket_len = 256usize;
    let cover_inner = encode_dummy_cover_frame(cover_bucket_len)?;
    let cover_ct = init_tx.write_message_vec(&cover_inner)?;
    let cover_frame = encode_frame(&cover_ct)?;
    let (cbody, _) = decode_frame(&cover_frame)?;
    let dec_cover = resp_tx.read_message_vec(cbody)?;
    assert!(matches!(
        decode_v2_inner_frame(&dec_cover, false)?,
        tendril_core::v2::V2InnerFrame::DummyCover { plaintext_len: 256 }
    ));

    Ok(V2ReconnectVector {
        preamble_hex: hex::encode(preamble),
        initiator_static_scalar_hex: hex::encode(init_static),
        initiator_static_pub_hex: hex::encode(init_static_pub),
        initiator_ephem_scalar_hex: hex::encode(init_ephem),
        initiator_mlkem768_keygen_seed_hex: hex::encode(concat64(&init_d, &init_z)),
        responder_static_scalar_hex: hex::encode(resp_static),
        responder_static_pub_hex: hex::encode(resp_static_pub),
        responder_ephem_scalar_hex: hex::encode(resp_ephem),
        responder_mlkem768_encaps_seed_hex: hex::encode(resp_m),
        responder_signing_seed_hex: hex::encode(resp_signing_seed),
        responder_signing_mldsa_seed_hex: hex::encode(resp_signing_mldsa_seed),
        responder_signing_pub_hex: hex::encode(resp_signing.public_bytes()),
        reconnect_secret_hex: hex::encode(reconnect_secret),
        rendezvous_nonce_hex: hex::encode(rendezvous_nonce),
        ts_unix,
        ekem_i_hash_hex: hex::encode(ekem_i_hash),
        rendezvous_mac_hex: hex::encode(rendezvous_mac),
        msg1_payload_hex: hex::encode(msg1_payload),
        msg1_frame_hex: hex::encode(msg1_frame),
        host_hello_json,
        bucket_len,
        hello_seal_key_hex: hex::encode(*hello_seal_key),
        pre_msg2_handshake_hash_hex: hex::encode(pre_msg2_hash),
        sealed_hello_envelope_hex: hex::encode(sealed_hello_envelope),
        msg2_frame_hex: hex::encode(msg2_frame),
        post_msg2_handshake_hash_hex: hex::encode(post_msg2_hash),
        session_hello_json,
        msg3_padded_payload_hex: hex::encode(msg3_padded_payload),
        msg3_frame_hex: hex::encode(msg3_frame),
        final_handshake_hash_hex: hex::encode(final_hash),
        padded_data_payload_hex: hex::encode(padded_data_payload),
        padded_inner_hex: hex::encode(padded_inner),
        padded_frame_hex: hex::encode(padded_frame),
        cover_bucket_len,
        cover_inner_hex: hex::encode(cover_inner),
        cover_frame_hex: hex::encode(cover_frame),
        exported_reconnect_secret_hex: hex::encode(*exported_reconnect),
        exported_mailbox_secret_hex: hex::encode(*exported_mailbox),
    })
}

fn build_v2_pake_vector(preamble: &[u8; 6]) -> Result<V2PakeVector, Box<dyn std::error::Error>> {
    let code = "TND-4F9K-22XQ-7M3P".to_string();
    let code_normalized = normalize_code(&code);
    let channel_salt: [u8; V2_PAKE_SALT_LEN] = [
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F,
    ];
    let params = PakeArgon2Params::production();
    let master_pake = derive_pake_master(&code, &channel_salt, params)?;
    let keys = derive_pake_keys(&code, &channel_salt, params)?;
    let noise_prologue = pake_noise_prologue(&keys.pake_context_tag);

    let init_static = seq_bytes(0x51);
    let init_static_pub = x25519_public_from_scalar(&init_static);
    let init_ephem = seq_bytes(0x52);
    let init_d = seq_bytes(0x53);
    let init_z = seq_bytes(0x54);

    let resp_static = seq_bytes(0x61);
    let resp_static_pub = x25519_public_from_scalar(&resp_static);
    let resp_ephem = seq_bytes(0x62);
    let resp_m = seq_bytes(0x63);
    let resp_signing_seed = seq_bytes(0x64);
    let resp_signing_mldsa_seed = seq_bytes(0x65);
    let resp_signing = SigningKeypair::from_seeds(resp_signing_seed, resp_signing_mldsa_seed);

    let mut initiator = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&init_static)
        .prologue(&noise_prologue)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: init_ephem,
            mlkem_d: init_d,
            mlkem_z: init_z,
            mlkem_m: [0u8; 32],
        })
        .build_initiator()?;
    let mut responder = NoiseHfsHandshakeBuilder::new()
        .local_private_key(&resp_static)
        .prologue(&noise_prologue)
        .fixed_hfs_seeds_for_testing_only(NoiseHfsSeeds {
            x25519: resp_ephem,
            mlkem_d: [0u8; 32],
            mlkem_z: [0u8; 32],
            mlkem_m: resp_m,
        })
        .build_responder()?;

    let mut ekem_i_hash = [0u8; 32];
    let mut init_mac = [0u8; 32];
    let mut msg1_payload = Vec::new();
    let msg1_body = initiator.write_msg1_with_payload(|e_i_pub, ek_bytes| {
        ekem_i_hash = Sha256::digest(ek_bytes).into();
        init_mac = compute_pake_msg1_mac(
            &keys.pake_init_key,
            preamble,
            e_i_pub,
            &ekem_i_hash,
            &channel_salt,
        );
        let mut p = Vec::with_capacity(48);
        p.extend_from_slice(&channel_salt);
        p.extend_from_slice(&init_mac);
        msg1_payload = p.clone();
        Ok(p)
    })?;
    let msg1_frame = encode_frame(&msg1_body)?;
    let (body1, _) = decode_frame(&msg1_frame)?;
    let dec1 = responder.read_message_vec(body1)?;
    assert_eq!(&*dec1, msg1_payload.as_slice());

    let host_hello = HostHello {
        host_id: device_id(&resp_static_pub),
        proto_version: WIRE_VERSION_V2,
        signing_pub: resp_signing.public_key().to_b64url(),
        rotation: vec![],
    };
    let host_hello_json = serde_json::to_string(&host_hello)?;
    let msg2_bucket_len = pake_msg2_bucket_for_hello_len(host_hello_json.len())?;

    let mut pre_msg2_hash = [0u8; 32];
    let mut sealed_host_hello = Vec::new();
    let mut resp_confirm_mac = [0u8; 32];
    let mut msg2_payload = Vec::new();
    let msg2_body = responder.write_msg2_with_hash(|h_pre| {
        pre_msg2_hash = *h_pre;
        sealed_host_hello =
            seal_pake_host_hello(&keys.pake_hello_key, h_pre, host_hello_json.as_bytes())?;
        resp_confirm_mac = compute_pake_resp_mac(&keys.pake_confirm_key, h_pre, &sealed_host_hello);
        let sealed_len = u16::try_from(sealed_host_hello.len()).map_err(|_| {
            tendril_core::error::CoreError::FrameTooLarge {
                len: sealed_host_hello.len(),
                max: MAX_FRAME_LEN,
            }
        })?;
        let mut out = vec![0u8; msg2_bucket_len];
        out[..2].copy_from_slice(&sealed_len.to_be_bytes());
        out[2..2 + sealed_host_hello.len()].copy_from_slice(&sealed_host_hello);
        out[2 + sealed_host_hello.len()..2 + sealed_host_hello.len() + 32]
            .copy_from_slice(&resp_confirm_mac);
        msg2_payload = out.clone();
        Ok(out)
    })?;
    let msg2_frame = encode_frame(&msg2_body)?;
    let (body2, _) = decode_frame(&msg2_frame)?;
    let (dec2, init_h_pre) = initiator.read_msg2_with_pre_payload_hash(body2)?;
    assert_eq!(init_h_pre, pre_msg2_hash);
    assert_eq!(&*dec2, msg2_payload.as_slice());
    let unsealed = unseal_pake_host_hello(&keys.pake_hello_key, &init_h_pre, &sealed_host_hello)?;
    assert_eq!(&*unsealed, host_hello_json.as_bytes());

    let post_msg2_hash = *initiator.get_handshake_hash();
    assert_eq!(post_msg2_hash, *responder.get_handshake_hash());
    let sas = pairing_sas(&post_msg2_hash);

    let claim = PairClaim {
        name: "Laptop".to_string(),
        kind: "linux".to_string(),
        code_mac: None,
        enrollment_token: None,
        signing_pub: None,
        enroll_proof: None,
    };
    let pair_claim_json = serde_json::to_string(&claim)?;
    let init_confirm_mac = compute_pake_init_mac(
        &keys.pake_confirm_key,
        &post_msg2_hash,
        pair_claim_json.as_bytes(),
    );
    let msg3_payload = pad_pake_msg3_payload(&init_confirm_mac, pair_claim_json.as_bytes())?;

    let msg3_body = initiator.write_message_vec(&msg3_payload)?;
    let msg3_frame = encode_frame(&msg3_body)?;
    let (body3, _) = decode_frame(&msg3_frame)?;
    let dec3 = responder.read_message_vec(body3)?;
    assert_eq!(&*dec3, msg3_payload.as_slice());
    let (unpadded_mac, unpadded_claim) = unpad_pake_msg3_payload(&dec3)?;
    assert_eq!(unpadded_mac, init_confirm_mac);
    assert_eq!(unpadded_claim, pair_claim_json.as_bytes());

    let final_hash = *initiator.get_handshake_hash();
    assert_eq!(final_hash, *responder.get_handshake_hash());

    let mut init_tx = initiator.into_transport_mode()?;
    let mut resp_tx = responder.into_transport_mode()?;
    let (exported_reconnect, exported_mailbox) = init_tx.export_v2_secrets(&resp_static_pub);
    assert_eq!(
        resp_tx.export_v2_secrets(&resp_static_pub),
        (exported_reconnect.clone(), exported_mailbox.clone())
    );

    let pair_resp = PairResponse::Success {
        device_id: device_id(&init_static_pub),
        status: "pending".to_string(),
        host_signing_pub: resp_signing.public_key().to_b64url(),
    };
    let pair_response_json = serde_json::to_string(&pair_resp)?;
    let pair_response_payload = pad_v2_pair_response(pair_response_json.as_bytes())?;
    let resp_ct = resp_tx.write_message_vec(&pair_response_payload)?;
    let pair_response_frame = encode_frame(&resp_ct)?;
    let (body4, _) = decode_frame(&pair_response_frame)?;
    let dec4 = init_tx.read_message_vec(body4)?;
    assert_eq!(&*dec4, pair_response_payload.as_slice());
    assert_eq!(
        unpad_v2_pair_response(&dec4)?,
        pair_response_json.as_bytes()
    );

    Ok(V2PakeVector {
        preamble_hex: hex::encode(preamble),
        code,
        code_normalized,
        channel_salt_hex: hex::encode(channel_salt),
        argon2id: Argon2ParamsSpec {
            t: PAKE_ARGON2_TIME,
            m_kib: PAKE_ARGON2_MEMORY_KIB,
            p: PAKE_ARGON2_PARALLELISM,
            key_len: ARGON2_KEY_LEN,
            version: "0x13".to_string(),
        },
        master_pake_hex: hex::encode(*master_pake),
        pake_prologue_key_hex: hex::encode(keys.pake_prologue_key),
        pake_init_key_hex: hex::encode(keys.pake_init_key),
        pake_hello_key_hex: hex::encode(keys.pake_hello_key),
        pake_confirm_key_hex: hex::encode(keys.pake_confirm_key),
        pake_context_tag_hex: hex::encode(keys.pake_context_tag),
        noise_prologue_hex: hex::encode(noise_prologue),
        initiator_static_scalar_hex: hex::encode(init_static),
        initiator_static_pub_hex: hex::encode(init_static_pub),
        initiator_ephem_scalar_hex: hex::encode(init_ephem),
        initiator_mlkem768_keygen_seed_hex: hex::encode(concat64(&init_d, &init_z)),
        responder_static_scalar_hex: hex::encode(resp_static),
        responder_static_pub_hex: hex::encode(resp_static_pub),
        responder_ephem_scalar_hex: hex::encode(resp_ephem),
        responder_mlkem768_encaps_seed_hex: hex::encode(resp_m),
        responder_signing_seed_hex: hex::encode(resp_signing_seed),
        responder_signing_mldsa_seed_hex: hex::encode(resp_signing_mldsa_seed),
        responder_signing_pub_hex: hex::encode(resp_signing.public_bytes()),
        ekem_i_hash_hex: hex::encode(ekem_i_hash),
        init_mac_hex: hex::encode(init_mac),
        msg1_payload_hex: hex::encode(msg1_payload),
        msg1_frame_hex: hex::encode(msg1_frame),
        host_hello_json,
        msg2_bucket_len,
        pre_msg2_handshake_hash_hex: hex::encode(pre_msg2_hash),
        sealed_host_hello_hex: hex::encode(sealed_host_hello),
        resp_confirm_mac_hex: hex::encode(resp_confirm_mac),
        msg2_payload_hex: hex::encode(msg2_payload),
        msg2_frame_hex: hex::encode(msg2_frame),
        post_msg2_handshake_hash_hex: hex::encode(post_msg2_hash),
        pairing_sas: sas,
        pair_claim_json,
        init_confirm_mac_hex: hex::encode(init_confirm_mac),
        msg3_payload_hex: hex::encode(msg3_payload),
        msg3_frame_hex: hex::encode(msg3_frame),
        final_handshake_hash_hex: hex::encode(final_hash),
        pair_response_json,
        pair_response_payload_hex: hex::encode(&pair_response_payload),
        pair_response_frame_hex: hex::encode(pair_response_frame),
        exported_reconnect_secret_hex: hex::encode(*exported_reconnect),
        exported_mailbox_secret_hex: hex::encode(*exported_mailbox),
    })
}
