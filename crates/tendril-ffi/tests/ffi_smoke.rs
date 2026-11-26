use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tempfile::TempDir;
use tendril_core::MAX_FRAME_LEN;
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::{
    ED25519_SIG_LEN, HYBRID_MLDSA_CTX, HYBRID_SIGNING_PUB_LEN, SigningKeypair, StaticKeypair,
    b64url_decode, b64url_encode,
};
use tendril_core::grants::{Grant, RevocationListUnsigned, sign_crl};
use tendril_core::identity::sign_rotation;
use tendril_core::noise::NoiseHfsHandshakeBuilder;
use tendril_core::roster::PeerState;
use tendril_core::wire::{HostHello, Intent, Preamble, ResumableFrameReader, encode_frame};
use tendril_ffi::{
    TENDRIL_EOF, TENDRIL_ERR_INVALID_ARG, TENDRIL_ERR_NOT_FOUND, TENDRIL_ERR_PROTOCOL,
    TENDRIL_MLDSA65_PUB_LEN, TENDRIL_MLDSA65_SIG_LEN, TENDRIL_OK, TENDRIL_WOULD_BLOCK,
    TendrilGroup, TendrilMlDsa65Signer, tendril_compute_code_mac, tendril_device_id,
    tendril_endpoint_add_trust_anchor, tendril_endpoint_close,
    tendril_endpoint_configure_transports_json, tendril_endpoint_confirm_peer,
    tendril_endpoint_enroll_initiate, tendril_endpoint_export_identity_json,
    tendril_endpoint_export_roster_json, tendril_endpoint_free, tendril_endpoint_info_json,
    tendril_endpoint_issue_code, tendril_endpoint_issue_pairing_uri,
    tendril_endpoint_mint_enrollment_token, tendril_endpoint_mint_grant,
    tendril_endpoint_mint_relay_ticket, tendril_endpoint_new, tendril_endpoint_new_from_state,
    tendril_endpoint_new_sealed, tendril_endpoint_new_sealed_with_options,
    tendril_endpoint_pair_accept, tendril_endpoint_pair_initiate, tendril_endpoint_pair_v2_accept,
    tendril_endpoint_pair_v2_initiate, tendril_endpoint_refresh_routes,
    tendril_endpoint_revoke_peer, tendril_endpoint_revoke_trust_anchor,
    tendril_endpoint_serve_direct, tendril_endpoint_serve_p2p, tendril_endpoint_serve_relay,
    tendril_endpoint_serve_relay_v2, tendril_fingerprint_device, tendril_fingerprint_host,
    tendril_group_close, tendril_group_create, tendril_group_free, tendril_group_open,
    tendril_last_error, tendril_pairing_sas, tendril_session_accept, tendril_session_accept_v2,
    tendril_session_authorize, tendril_session_close, tendril_session_connect,
    tendril_session_connect_v2, tendril_session_export_roster_json, tendril_session_free,
    tendril_session_peer_id, tendril_session_poll_event, tendril_session_rekey,
    tendril_session_send_data, tendril_session_shutdown, tendril_string_free,
    tendril_verify_grant_json, tendril_verify_rotation_chain_json, tendril_verify_wake_tag,
};
use tendril_runtime::{
    DirectListener, PathListener, PathStream, PrefixedPathStream, SessionDriver, StateStore,
    derive_epoch_wake_tag, peek_exact, recv_tendril_frame,
};

unsafe fn take_cstr(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null());
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("utf8")
        .to_owned();
    unsafe { tendril_string_free(ptr) };
    s
}

fn read_last_err() -> String {
    let mut buf = vec![0i8; 256];
    let needed = unsafe { tendril_last_error(buf.as_mut_ptr().cast::<c_char>(), buf.len()) };
    assert!(needed >= 1);
    unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) }
        .to_str()
        .expect("utf8")
        .to_owned()
}

fn hex_bytes(hex_str: &str) -> Vec<u8> {
    assert_eq!(hex_str.len() % 2, 0);
    (0..hex_str.len() / 2)
        .map(|i| u8::from_str_radix(&hex_str[2 * i..2 * i + 2], 16).expect("hex byte"))
        .collect()
}

fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex byte");
    }
    out
}

#[test]
fn ffi_verifies_all_spec_vectors_and_error_paths() {
    // 1. Null-pointer error paths populate thread-local last_error.
    let mut out_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe { tendril_endpoint_info_json(ptr::null(), &raw mut out_ptr) };
    assert_eq!(rc, TENDRIL_ERR_INVALID_ARG);
    assert!(read_last_err().contains("null endpoint"));

    // 2. Fingerprints and SAS vectors.
    let fp: Value = serde_json::from_str(include_str!("../../../spec/vectors/fingerprints.json"))
        .expect("fingerprints json");
    let raw_pub = hex32(fp["raw_pubkey_hex"].as_str().unwrap());
    let hh = hex32(fp["handshake_hash_hex"].as_str().unwrap());

    assert_eq!(
        unsafe { tendril_device_id(raw_pub.as_ptr(), &raw mut out_ptr) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { take_cstr(out_ptr) },
        fp["raw_device_id"].as_str().unwrap()
    );

    assert_eq!(
        unsafe { tendril_fingerprint_host(raw_pub.as_ptr(), &raw mut out_ptr) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { take_cstr(out_ptr) },
        fp["raw_host_fingerprint"].as_str().unwrap()
    );

    assert_eq!(
        unsafe { tendril_fingerprint_device(raw_pub.as_ptr(), &raw mut out_ptr) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { take_cstr(out_ptr) },
        fp["raw_device_fingerprint"].as_str().unwrap()
    );

    assert_eq!(
        unsafe { tendril_pairing_sas(hh.as_ptr(), &raw mut out_ptr) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { take_cstr(out_ptr) },
        fp["pairing_sas"].as_str().unwrap()
    );

    // 3. Pairing MAC vector (3-group & 2-group).
    let pm: Value = serde_json::from_str(include_str!("../../../spec/vectors/pairing_mac.json"))
        .expect("pairing_mac json");
    let pm_hh = hex32(pm["handshake_hash_hex"].as_str().unwrap());
    let code_c = CString::new(pm["remote_3group"]["code"].as_str().unwrap()).unwrap();
    let mut mac_out = [0u8; 32];
    assert_eq!(
        unsafe { tendril_compute_code_mac(code_c.as_ptr(), pm_hh.as_ptr(), mac_out.as_mut_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        mac_out,
        hex32(pm["remote_3group"]["code_mac_hex"].as_str().unwrap())
    );

    // 4. Rotation chain vector & fork rejection.
    let rot: Value = serde_json::from_str(include_str!("../../../spec/vectors/rotation.json"))
        .expect("rotation json");
    let psig = b64url_encode(&hex_bytes(rot["pinned_signing_pub_hex"].as_str().unwrap()));
    let pstat = b64url_encode(&hex32(rot["pinned_static_pub_hex"].as_str().unwrap()));
    let records: Vec<Value> = rot["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["record"].clone())
        .collect();
    let chain_json = serde_json::to_string(&records).unwrap();
    let cur_stat_b64 = records[1]["new_static_pub"].as_str().unwrap();
    let cur_sig_b64 = records[1]["new_signing_pub"].as_str().unwrap();

    let psig_c = CString::new(psig).unwrap();
    let pstat_c = CString::new(pstat).unwrap();
    let chain_c = CString::new(chain_json).unwrap();
    let cstat_c = CString::new(cur_stat_b64).unwrap();
    let csig_c = CString::new(cur_sig_b64).unwrap();
    let mut final_seq = 0u64;
    assert_eq!(
        unsafe {
            tendril_verify_rotation_chain_json(
                psig_c.as_ptr(),
                pstat_c.as_ptr(),
                0,
                chain_c.as_ptr(),
                cstat_c.as_ptr(),
                csig_c.as_ptr(),
                &raw mut final_seq,
            )
        },
        TENDRIL_OK
    );
    assert_eq!(final_seq, 2);

    let mut fork_records = records.clone();
    fork_records.push(rot["fork_record"]["record"].clone());
    let fork_c = CString::new(serde_json::to_string(&fork_records).unwrap()).unwrap();
    assert_eq!(
        unsafe {
            tendril_verify_rotation_chain_json(
                psig_c.as_ptr(),
                pstat_c.as_ptr(),
                0,
                fork_c.as_ptr(),
                cstat_c.as_ptr(),
                csig_c.as_ptr(),
                &raw mut final_seq,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );

    // 5. Grant delegation vector.
    let gv: Value =
        serde_json::from_str(include_str!("../../../spec/vectors/grants.json")).expect("grants");
    let mut keys = HashMap::new();
    keys.insert(
        gv["root_issuer_id"].as_str().unwrap(),
        b64url_encode(&hex_bytes(gv["root_signing_pub_hex"].as_str().unwrap())),
    );
    keys.insert(
        gv["delegate_id"].as_str().unwrap(),
        b64url_encode(&hex_bytes(gv["delegate_signing_pub_hex"].as_str().unwrap())),
    );
    let keys_c = CString::new(serde_json::to_string(&keys).unwrap()).unwrap();
    let valid_grant_c =
        CString::new(serde_json::to_string(&gv["delegated_valid"]).unwrap()).unwrap();
    let widened_grant_c =
        CString::new(serde_json::to_string(&gv["delegated_widened"]).unwrap()).unwrap();
    let subj_c = CString::new(gv["leaf_id"].as_str().unwrap()).unwrap();
    let root_c = CString::new(gv["root_issuer_id"].as_str().unwrap()).unwrap();
    let cap_c = CString::new("fs.read:/photos/2026/a.jpg").unwrap();
    let now = 1_795_564_800u64; // 2026-11-25T00:00:00Z

    let mut allowed = 0u8;
    assert_eq!(
        unsafe {
            tendril_verify_grant_json(
                valid_grant_c.as_ptr(),
                keys_c.as_ptr(),
                subj_c.as_ptr(),
                root_c.as_ptr(),
                cap_c.as_ptr(),
                now,
                ptr::null(),
                &raw mut allowed,
            )
        },
        TENDRIL_OK
    );
    assert_eq!(allowed, 1);

    assert_eq!(
        unsafe {
            tendril_verify_grant_json(
                widened_grant_c.as_ptr(),
                keys_c.as_ptr(),
                subj_c.as_ptr(),
                root_c.as_ptr(),
                cap_c.as_ptr(),
                now,
                ptr::null(),
                &raw mut allowed,
            )
        },
        TENDRIL_OK
    );
    assert_eq!(allowed, 0);

    // Valid CRL passes; tampered/forged CRL must be denied fail-closed.
    let valid_crl_c = CString::new(serde_json::to_string(&gv["revocation_list"]).unwrap()).unwrap();
    assert_eq!(
        unsafe {
            tendril_verify_grant_json(
                valid_grant_c.as_ptr(),
                keys_c.as_ptr(),
                subj_c.as_ptr(),
                root_c.as_ptr(),
                cap_c.as_ptr(),
                now,
                valid_crl_c.as_ptr(),
                &raw mut allowed,
            )
        },
        TENDRIL_OK
    );
    assert_eq!(allowed, 1);

    let mut forged_crl = gv["revocation_list"].clone();
    forged_crl["revoked_devices"] = serde_json::json!([]);
    let forged_crl_c = CString::new(serde_json::to_string(&forged_crl).unwrap()).unwrap();
    assert_eq!(
        unsafe {
            tendril_verify_grant_json(
                valid_grant_c.as_ptr(),
                keys_c.as_ptr(),
                subj_c.as_ptr(),
                root_c.as_ptr(),
                cap_c.as_ptr(),
                now,
                forged_crl_c.as_ptr(),
                &raw mut allowed,
            )
        },
        TENDRIL_OK
    );
    assert_eq!(allowed, 0, "forged CRL must fail closed");
}

#[test]
fn ffi_full_lifecycle_and_session_outlives_endpoint() {
    let host_name = CString::new("ffi-host").unwrap();
    let host_ep = unsafe { tendril_endpoint_new(ptr::null(), host_name.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(ptr::null(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let mut info_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(host_ep, &raw mut info_ptr) },
        TENDRIL_OK
    );
    let info: Value = serde_json::from_str(&unsafe { take_cstr(info_ptr) }).unwrap();
    assert_eq!(info["host_id"], "ffi-host");
    assert!(info["device_id"].as_str().unwrap().starts_with("dev_"));
    assert!(!info["static_pub"].as_str().unwrap().is_empty());
    assert!(!info["signing_pub"].as_str().unwrap().is_empty());

    let bad_kind = CString::new("bluetooth").unwrap();
    let mut bad_code_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, bad_kind.as_ptr(), &raw mut bad_code_ptr) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(bad_code_ptr.is_null());

    let mut listen_ep_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, ptr::null(), &raw mut listen_ep_ptr) },
        TENDRIL_OK
    );
    let endpoint_str = unsafe { take_cstr(listen_ep_ptr) };

    let mut code_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, ptr::null(), &raw mut code_ptr) },
        TENDRIL_OK
    );
    let code_str = unsafe { take_cstr(code_ptr) };

    let ep_usize = host_ep as usize;
    let accept_pair_thr = thread::spawn(move || {
        let mut out_ptr: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(
                ep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out_ptr,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "pair accept failed: {}", read_last_err());
        unsafe { take_cstr(out_ptr) }
    });

    let ep_c = CString::new(endpoint_str.clone()).unwrap();
    let code_c = CString::new(code_str).unwrap();
    let mut cli_pair_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_initiate(
                cli_ep,
                ep_c.as_ptr(),
                ptr::null(),
                code_c.as_ptr(),
                ptr::null(),
                ptr::null(),
                &raw mut cli_pair_ptr,
            )
        },
        TENDRIL_OK
    );
    let cli_pair: Value = serde_json::from_str(&unsafe { take_cstr(cli_pair_ptr) }).unwrap();
    let host_pair: Value = serde_json::from_str(&accept_pair_thr.join().unwrap()).unwrap();
    assert_eq!(cli_pair["sas"], host_pair["sas"]);
    assert_eq!(cli_pair["status"], "pending");

    let peer_dev_c = CString::new(host_pair["device_id"].as_str().unwrap()).unwrap();
    let sas_c = CString::new(host_pair["sas"].as_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, peer_dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );

    let caps_c = CString::new("[\"fs.read\"]").unwrap();
    let mut grant_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                peer_dev_c.as_ptr(),
                caps_c.as_ptr(),
                3600,
                &raw mut grant_ptr,
            )
        },
        TENDRIL_OK
    );
    let grant_str = unsafe { take_cstr(grant_ptr) };

    // Connecting before client-side confirm_peer must fail closed (PeerPending).
    let grant_c = CString::new(grant_str).unwrap();
    let ep_pre = ep_usize;
    let pre_acc = thread::spawn(move || {
        let s =
            unsafe { tendril_session_accept(ep_pre as *mut tendril_ffi::TendrilEndpoint, 2_000) };
        assert!(s.is_null(), "pre-confirm session must not establish");
    });
    let pre_sess = unsafe {
        tendril_session_connect(
            cli_ep,
            ep_c.as_ptr(),
            ptr::null(),
            host_name.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(
        pre_sess.is_null(),
        "client must reject session before confirm"
    );
    assert!(read_last_err().contains("pending"));
    pre_acc.join().unwrap();

    // Confirm host pin on client with matching SAS, then connect cleanly.
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(cli_ep, host_name.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );

    let accept_sess_thr = thread::spawn(move || {
        let sess =
            unsafe { tendril_session_accept(ep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) };
        assert!(
            !sess.is_null(),
            "session accept failed: {}",
            read_last_err()
        );
        sess as usize
    });

    let cli_sess = unsafe {
        tendril_session_connect(
            cli_ep,
            ep_c.as_ptr(),
            ptr::null(),
            host_name.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(
        !cli_sess.is_null(),
        "session connect failed: {}",
        read_last_err()
    );
    let host_sess = accept_sess_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;

    // Poll when empty returns TENDRIL_WOULD_BLOCK.
    let mut ev_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 25, &raw mut ev_ptr) },
        TENDRIL_WOULD_BLOCK
    );

    // Drop client endpoint handle BEFORE using cli_sess to prove lifetime independence.
    unsafe { tendril_endpoint_free(cli_ep) };

    // Null-pointer guards and authenticated peer identity accessors on both sides.
    let sentinel_byte: c_char = 1;
    let mut sentinel_buf: *mut c_char = (&raw const sentinel_byte).cast_mut();
    assert_eq!(
        unsafe { tendril_session_peer_id(ptr::null(), &raw mut sentinel_buf) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(sentinel_buf.is_null());
    assert_eq!(
        unsafe { tendril_session_peer_id(host_sess, ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );
    let mut peer_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_peer_id(host_sess, &raw mut peer_ptr) },
        TENDRIL_OK,
        "host_sess peer_id failed: {}",
        read_last_err()
    );
    assert_eq!(
        unsafe { take_cstr(peer_ptr) },
        host_pair["device_id"].as_str().unwrap()
    );
    assert_eq!(
        unsafe { tendril_session_peer_id(cli_sess, &raw mut peer_ptr) },
        TENDRIL_OK,
        "cli_sess peer_id failed: {}",
        read_last_err()
    );
    assert_eq!(unsafe { take_cstr(peer_ptr) }, "ffi-host");

    let cap_ok = CString::new("fs.read").unwrap();
    let cap_deny = CString::new("shell.exec").unwrap();
    let mut allowed = 0u8;
    assert_eq!(
        unsafe { tendril_session_authorize(host_sess, cap_ok.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 1);
    assert_eq!(
        unsafe { tendril_session_authorize(host_sess, cap_deny.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 0);

    let msg = b"hello-over-ffi";
    assert_eq!(
        unsafe { tendril_session_send_data(cli_sess, msg.as_ptr(), msg.len()) },
        TENDRIL_OK
    );
    // Null out_event_json must fail immediately without losing the queued event.
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 500, ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 2_000, &raw mut ev_ptr) },
        TENDRIL_OK
    );
    let ev: Value = serde_json::from_str(&unsafe { take_cstr(ev_ptr) }).unwrap();
    assert_eq!(ev["event"], "data");
    assert_eq!(ev["data_b64"], b64url_encode(msg));

    assert_eq!(unsafe { tendril_session_rekey(cli_sess) }, TENDRIL_OK);
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 2_000, &raw mut ev_ptr) },
        TENDRIL_OK
    );
    let ev_rekey: Value = serde_json::from_str(&unsafe { take_cstr(ev_ptr) }).unwrap();
    assert_eq!(ev_rekey["event"], "rekeyed");

    // Revoking peer immediately fails authorize closed via shared roster Arc.
    assert_eq!(
        unsafe { tendril_endpoint_revoke_peer(host_ep, peer_dev_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_session_authorize(host_sess, cap_ok.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 0);
    // Revocation strips authority while preserving authenticated session peer identity.
    assert_eq!(
        unsafe { tendril_session_peer_id(host_sess, &raw mut peer_ptr) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { take_cstr(peer_ptr) },
        host_pair["device_id"].as_str().unwrap()
    );

    assert_eq!(
        unsafe { tendril_session_close(cli_sess, 1000, ptr::null()) },
        TENDRIL_OK
    );
    unsafe {
        tendril_session_free(cli_sess);
        tendril_session_free(host_sess);
        tendril_endpoint_free(host_ep);
    }
}

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parses the `YYYY-MM-DDTHH:MM:SSZ` timestamps that minted grants carry.
fn rfc3339_utc_to_unix(ts: &str) -> u64 {
    let b = ts.as_bytes();
    assert!(
        b.len() == 20
            && b[19] == b'Z'
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':',
        "unexpected timestamp shape: {ts}"
    );
    let num = |r: std::ops::Range<usize>| -> i64 { ts[r].parse().expect("timestamp digits") };
    let (y, m, d) = (num(0..4), num(5..7), num(8..10));
    let (hh, mm, ss) = (num(11..13), num(14..16), num(17..19));
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3_600 + mm * 60 + ss).expect("timestamp before epoch")
}

fn pair_and_mint_c(host_dir: &str, cli_dir: &str, host_name_str: &str, caps_json: &str) -> String {
    let hd = CString::new(host_dir).unwrap();
    let cd = CString::new(cli_dir).unwrap();
    let hn = CString::new(host_name_str).unwrap();

    let host_ep = unsafe { tendril_endpoint_new(hd.as_ptr(), hn.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(cd.as_ptr(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let mut ep_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, ptr::null(), &raw mut ep_ptr) },
        TENDRIL_OK
    );
    let endpoint_str = unsafe { take_cstr(ep_ptr) };

    let mut code_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, ptr::null(), &raw mut code_ptr) },
        TENDRIL_OK
    );
    let code_str = unsafe { take_cstr(code_ptr) };

    let ep_usize = host_ep as usize;
    let accept_thr = thread::spawn(move || {
        let mut out_ptr: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(
                ep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out_ptr,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "pair accept failed: {}", read_last_err());
        unsafe { take_cstr(out_ptr) }
    });

    let ep_c = CString::new(endpoint_str).unwrap();
    let code_c = CString::new(code_str).unwrap();
    let mut cli_pair_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_initiate(
                cli_ep,
                ep_c.as_ptr(),
                ptr::null(),
                code_c.as_ptr(),
                ptr::null(),
                ptr::null(),
                &raw mut cli_pair_ptr,
            )
        },
        TENDRIL_OK
    );
    let cli_pair: Value = serde_json::from_str(&unsafe { take_cstr(cli_pair_ptr) }).unwrap();
    let host_pair: Value = serde_json::from_str(&accept_thr.join().unwrap()).unwrap();
    assert_eq!(cli_pair["sas"], host_pair["sas"]);

    let peer_c = CString::new(host_pair["device_id"].as_str().unwrap()).unwrap();
    let sas_c = CString::new(host_pair["sas"].as_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, peer_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(cli_ep, hn.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );

    let caps_c = CString::new(caps_json).unwrap();
    let mut grant_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                peer_c.as_ptr(),
                caps_c.as_ptr(),
                3600,
                &raw mut grant_ptr,
            )
        },
        TENDRIL_OK
    );
    let grant_str = unsafe { take_cstr(grant_ptr) };

    unsafe {
        tendril_endpoint_free(cli_ep);
        tendril_endpoint_free(host_ep);
    }
    grant_str
}

#[test]
fn ffi_persists_host_rotation_and_fork_revocation_across_restart() {
    let host_dir = TempDir::new().unwrap();
    let cli_dir = TempDir::new().unwrap();

    let host_path = host_dir.path().to_str().unwrap().to_owned();
    let cli_path = cli_dir.path().to_str().unwrap().to_owned();

    let _ = pair_and_mint_c(&host_path, &cli_path, "rot-host", "[\"fs.read\"]");

    let host_store = StateStore::open_or_create(host_dir.path()).unwrap();
    let mut host_id = host_store.load_or_generate_identity(None).unwrap();

    let now = current_unix();
    host_id
        .rotate(
            StaticKeypair::generate().unwrap(),
            SigningKeypair::generate().unwrap(),
            now,
        )
        .unwrap();
    host_store.save_identity(&host_id).unwrap();
    drop(host_store);

    // 1. Client connects to legitimately rotated host (no grant needed) -> seq=1 persists.
    let hd_c = CString::new(host_path).unwrap();
    let cd_c = CString::new(cli_path).unwrap();
    let host_name_c = CString::new("rot-host").unwrap();

    let host_ep2 = unsafe { tendril_endpoint_new(hd_c.as_ptr(), ptr::null()) };
    let cli_ep2 = unsafe { tendril_endpoint_new(cd_c.as_ptr(), ptr::null()) };
    assert!(!host_ep2.is_null() && !cli_ep2.is_null());

    let mut ep2_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep2, ptr::null(), &raw mut ep2_ptr) },
        TENDRIL_OK
    );
    let ep2_str = unsafe { take_cstr(ep2_ptr) };
    let ep2_c = CString::new(ep2_str).unwrap();

    let host_ep2_usize = host_ep2 as usize;
    let accept_thr2 = thread::spawn(move || unsafe {
        let sess =
            tendril_session_accept(host_ep2_usize as *mut tendril_ffi::TendrilEndpoint, 5_000);
        assert!(
            !sess.is_null(),
            "rotated session accept failed: {}",
            read_last_err()
        );
        sess as usize
    });
    let cli_sess2 = unsafe {
        tendril_session_connect(
            cli_ep2,
            ep2_c.as_ptr(),
            ptr::null(),
            host_name_c.as_ptr(),
            ptr::null(),
        )
    };
    assert!(
        !cli_sess2.is_null(),
        "rotated connect failed: {}",
        read_last_err()
    );
    let host_sess2 = accept_thr2.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess2.is_null());

    unsafe {
        tendril_session_close(cli_sess2, 1000, ptr::null());
        tendril_session_free(cli_sess2);
        tendril_session_free(host_sess2);
        tendril_endpoint_free(cli_ep2);
        tendril_endpoint_free(host_ep2);
    }

    let persisted_after_rot = StateStore::open_or_create(cli_dir.path())
        .unwrap()
        .load_roster()
        .unwrap();
    let rot_entry = persisted_after_rot.get("rot-host").expect("rot-host entry");
    assert_eq!(rot_entry.rotation_seq, 1);
    assert_eq!(rot_entry.state, PeerState::Active);

    // 2. Host key at seq=1 signs two diverging seq=2 rotation records -> client detects fork & persists Revoked.
    let key_a_stat = StaticKeypair::generate().unwrap();
    let key_a_sig = SigningKeypair::generate().unwrap();
    let key_b_stat = StaticKeypair::generate().unwrap();
    let key_b_sig = SigningKeypair::generate().unwrap();
    let seq1_signing = host_id.signing_key();
    let rec_2a = sign_rotation(
        2,
        seq1_signing,
        key_a_sig.public_key(),
        key_a_stat.public_bytes(),
        now + 10,
    )
    .unwrap();
    let rec_2b = sign_rotation(
        2,
        seq1_signing,
        key_b_sig.public_key(),
        key_b_stat.public_bytes(),
        now + 11,
    )
    .unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (fep_str, fork_srv) = rt.block_on(async {
        let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let ep = listener.local_endpoint();
        let handle = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let peeked = peek_exact(stream.as_mut(), PREAMBLE_LEN).await.unwrap();
            let mut wrapped = PrefixedPathStream::new(stream, peeked[PREAMBLE_LEN..].to_vec());
            let mut reader = ResumableFrameReader::new();
            let msg1 = recv_tendril_frame(&mut wrapped, &mut reader).await.unwrap();
            let mut hs = NoiseHfsHandshakeBuilder::new()
                .local_private_key(key_a_stat.secret_bytes())
                .prologue(&Preamble::v1(Intent::Session).encode())
                .build_responder()
                .unwrap();
            let mut pt = vec![0u8; MAX_FRAME_LEN];
            hs.read_message(&msg1, &mut pt).unwrap();
            let hello = serde_json::to_vec(&HostHello {
                host_id: "rot-host".to_owned(),
                proto_version: 1,
                signing_pub: key_a_sig.public_key().to_b64url(),
                rotation: vec![rec_2a, rec_2b],
                upgrade: Vec::new(),
            })
            .unwrap();
            let mut ct = vec![0u8; MAX_FRAME_LEN];
            let n2 = hs.write_message(&hello, &mut ct).unwrap();
            wrapped
                .send_chunk(&encode_frame(&ct[..n2]).unwrap())
                .await
                .unwrap();
            let _ = wrapped.close().await;
        });
        (ep, handle)
    });

    let fep_c = CString::new(fep_str).unwrap();
    let cd_c2 = cd_c.clone();
    let hname_c2 = host_name_c.clone();
    let cli_thr = thread::spawn(move || {
        let cli_ep3 = unsafe { tendril_endpoint_new(cd_c2.as_ptr(), ptr::null()) };
        assert!(!cli_ep3.is_null());
        let cli_sess_fork = unsafe {
            tendril_session_connect(
                cli_ep3,
                fep_c.as_ptr(),
                ptr::null(),
                hname_c2.as_ptr(),
                ptr::null(),
            )
        };
        assert!(cli_sess_fork.is_null(), "forked host must be rejected");
        assert!(read_last_err().contains("fork"));
        unsafe { tendril_endpoint_free(cli_ep3) };
    });
    rt.block_on(fork_srv).unwrap();
    cli_thr.join().unwrap();

    let persisted_after_fork = StateStore::open_or_create(cli_dir.path())
        .unwrap()
        .load_roster()
        .unwrap();
    assert_eq!(
        persisted_after_fork.get("rot-host").unwrap().state,
        PeerState::Revoked
    );
}

#[test]
fn ffi_persists_session_terminating_crl_across_restart() {
    let host_dir = TempDir::new().unwrap();
    let cli_dir = TempDir::new().unwrap();
    let host_path = host_dir.path().to_str().unwrap().to_owned();
    let cli_path = cli_dir.path().to_str().unwrap().to_owned();

    let grant_str = pair_and_mint_c(&host_path, &cli_path, "crl-host", "[\"fs.read\"]");
    let grant: Grant = serde_json::from_str(&grant_str).unwrap();
    let host_store = StateStore::open_or_create(host_dir.path()).unwrap();
    let host_id = host_store.load_or_generate_identity(None).unwrap();
    let mut host_roster = host_store.load_roster().unwrap();

    let crl_ts = grant.not_before.clone();
    let revoked_nonce = grant.nonce.clone();
    let expected_nonce = revoked_nonce.clone();
    // Bring up raw runtime host listener so we can push a signed 0x03 REVOCATION revoking the active grant.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (ep_str, accept_handle) = rt.block_on(async {
        let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let ep = listener.local_endpoint();
        let h_id = host_id.clone();
        let handle = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            let now = current_unix();
            let mut drv = SessionDriver::accept(stream, &h_id, &mut host_roster, now, None)
                .await
                .unwrap();
            let crl = sign_crl(
                RevocationListUnsigned {
                    v: 1,
                    issuer: h_id.host_id().to_owned(),
                    seq: 1,
                    revoked_devices: Vec::new(),
                    revoked_nonces: vec![revoked_nonce],
                    ts: crl_ts,
                },
                h_id.signing_key(),
            )
            .unwrap();
            drv.send_revocation(&crl).await.unwrap();
            drv
        });
        (ep, handle)
    });

    let cd_c = CString::new(cli_path).unwrap();
    let ep_c = CString::new(ep_str).unwrap();
    let host_name_c = CString::new("crl-host").unwrap();
    let grant_c = CString::new(grant_str).unwrap();

    let ep_c2 = ep_c.clone();
    let hname_c2 = host_name_c.clone();
    let g_c2 = grant_c.clone();
    let cd_c2 = cd_c.clone();
    let cli_thr = thread::spawn(move || {
        let cli_ep = unsafe { tendril_endpoint_new(cd_c2.as_ptr(), ptr::null()) };
        assert!(!cli_ep.is_null());
        let sess = unsafe {
            tendril_session_connect(
                cli_ep,
                ep_c2.as_ptr(),
                ptr::null(),
                hname_c2.as_ptr(),
                g_c2.as_ptr(),
            )
        };
        assert!(!sess.is_null(), "connect failed: {}", read_last_err());
        let mut out_ptr: *mut c_char = ptr::null_mut();
        let rc = unsafe { tendril_session_poll_event(sess, 2_000, &raw mut out_ptr) };
        assert_eq!(rc, TENDRIL_ERR_PROTOCOL);
        assert!(out_ptr.is_null());
        unsafe {
            tendril_session_free(sess);
            tendril_endpoint_free(cli_ep);
        }
    });

    let _srv_drv = rt.block_on(accept_handle).unwrap();
    cli_thr.join().unwrap();

    let persisted = StateStore::open_or_create(cli_dir.path())
        .unwrap()
        .load_roster()
        .unwrap();
    let crl = persisted.crl("crl-host").expect("persisted CRL on error");
    assert_eq!(crl.seq, 1);
    assert_eq!(crl.revoked_nonces, vec![expected_nonce]);
}

#[test]
fn sealed_endpoint_persists_crl_and_v2_floor_without_binding_save() {
    use tendril_core::roster::Roster;
    use tendril_runtime::V2SessionDriver;

    let host_dir = TempDir::new().unwrap();
    let cli_dir = TempDir::new().unwrap();
    let hd_c = CString::new(host_dir.path().to_str().unwrap()).unwrap();
    let cd_c = CString::new(cli_dir.path().to_str().unwrap()).unwrap();
    let hname_c = CString::new("sealed-v2-host").unwrap();

    // The client pairs as a pre-sealed binding endpoint did: in memory, roster exported.
    let host_ep = unsafe { tendril_endpoint_new(hd_c.as_ptr(), hname_c.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new_from_state(ptr::null(), ptr::null(), ptr::null()) };
    assert!(!host_ep.is_null(), "{}", read_last_err());
    assert!(!cli_ep.is_null(), "{}", read_last_err());

    let mut id_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_identity_json(cli_ep, &raw mut id_p) },
        TENDRIL_OK
    );
    let cli_identity_c = CString::new(unsafe { take_cstr(id_p) }).unwrap();

    let mut info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(host_ep, &raw mut info_p) },
        TENDRIL_OK
    );
    let host_info: Value = serde_json::from_str(&unsafe { take_cstr(info_p) }).unwrap();
    let mut info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(cli_ep, &raw mut info_p) },
        TENDRIL_OK
    );
    let cli_info: Value = serde_json::from_str(&unsafe { take_cstr(info_p) }).unwrap();
    let cli_dev_c = CString::new(cli_info["device_id"].as_str().unwrap()).unwrap();

    let mut dep_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, ptr::null(), &raw mut dep_p) },
        TENDRIL_OK
    );
    let dep_c = CString::new(unsafe { take_cstr(dep_p) }).unwrap();
    let mut code_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, ptr::null(), &raw mut code_p) },
        TENDRIL_OK
    );
    let code_c = CString::new(unsafe { take_cstr(code_p) }).unwrap();
    let pinned_c = CString::new(
        serde_json::json!({
            "host_id": "sealed-v2-host",
            "static_pub_b64": host_info["static_pub"],
            "signing_pin_b64": host_info["signing_pub"],
            "rotation_seq": 0,
            "min_wire_version": 2
        })
        .to_string(),
    )
    .unwrap();
    let hep_usize = host_ep.addr();
    let accept = thread::spawn(move || {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_v2_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK);
        serde_json::from_str::<Value>(&unsafe { take_cstr(out) }).unwrap()
    });
    let name_c = CString::new("sealed-cli").unwrap();
    let kind_c = CString::new("cli").unwrap();
    let mut out_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                cli_ep,
                dep_c.as_ptr(),
                ptr::null(),
                code_c.as_ptr(),
                name_c.as_ptr(),
                kind_c.as_ptr(),
                pinned_c.as_ptr(),
                &raw mut out_p,
            )
        },
        TENDRIL_OK,
        "{}",
        read_last_err()
    );
    unsafe { take_cstr(out_p) };
    let sas_c = CString::new(accept.join().unwrap()["sas"].as_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, cli_dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    let caps_c = CString::new("[\"fs.read:/sealed/*\"]").unwrap();
    let mut grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli_dev_c.as_ptr(),
                caps_c.as_ptr(),
                300,
                &raw mut grant_p,
            )
        },
        TENDRIL_OK
    );
    let grant_str = unsafe { take_cstr(grant_p) };
    let grant: Grant = serde_json::from_str(&grant_str).unwrap();
    let grant_c = CString::new(grant_str).unwrap();
    unsafe { tendril_endpoint_free(host_ep) };

    // Legacy fixture: the paired roster with its v2 floor still at 1, so only a session can
    // raise it.
    let mut roster_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_roster_json(cli_ep, &raw mut roster_p) },
        TENDRIL_OK
    );
    let mut legacy: Value = serde_json::from_str(&unsafe { take_cstr(roster_p) }).unwrap();
    unsafe { tendril_endpoint_free(cli_ep) };
    assert!(
        legacy["entries"]["sealed-v2-host"]["v2_secrets"].is_object(),
        "{legacy}"
    );
    legacy["entries"]["sealed-v2-host"]["min_wire_version"] = 1.into();
    let stale_c = CString::new(legacy.to_string()).unwrap();

    let refused = unsafe {
        tendril_endpoint_new_sealed(cd_c.as_ptr(), ptr::null(), stale_c.as_ptr(), ptr::null())
    };
    assert!(refused.is_null());
    assert!(read_last_err().contains("a roster seed requires the saved identity"));
    assert!(!cli_dir.path().join("rt-roster.sealed").exists());

    let cli_ep = unsafe {
        tendril_endpoint_new_sealed(
            cd_c.as_ptr(),
            cli_identity_c.as_ptr(),
            stale_c.as_ptr(),
            ptr::null(),
        )
    };
    assert!(!cli_ep.is_null(), "{}", read_last_err());
    assert!(cli_dir.path().join("rt-roster.sealed").exists());
    assert!(!cli_dir.path().join("roster.json").exists());
    let mut roster_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_roster_json(cli_ep, &raw mut roster_p) },
        TENDRIL_OK
    );
    let migrated: Value = serde_json::from_str(&unsafe { take_cstr(roster_p) }).unwrap();
    assert_eq!(
        migrated["entries"]["sealed-v2-host"]["min_wire_version"], 1,
        "{migrated}"
    );
    assert!(migrated["crls"]["sealed-v2-host"].is_null(), "{migrated}");

    // A raw host pushes a 0x03 CRL over an established v2 session.
    let host_store = StateStore::open_or_create(host_dir.path()).unwrap();
    let host_id = host_store.load_or_generate_identity(None).unwrap();
    let mut host_roster: Roster = host_store.load_roster().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (v2_ep, accept_handle) = rt.block_on(async {
        let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let ep = listener.local_endpoint();
        let handle = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            let mut drv = V2SessionDriver::accept(
                stream,
                &host_id,
                &mut host_roster,
                current_unix(),
                &Default::default(),
                None,
            )
            .await
            .unwrap();
            let crl = sign_crl(
                RevocationListUnsigned {
                    v: 1,
                    issuer: host_id.host_id().to_owned(),
                    seq: 1,
                    revoked_devices: Vec::new(),
                    revoked_nonces: vec![grant.nonce.clone()],
                    ts: grant.not_before.clone(),
                },
                host_id.signing_key(),
            )
            .unwrap();
            drv.send_revocation(&crl).await.unwrap();
            drv
        });
        (ep, handle)
    });
    let v2_ep_c = CString::new(v2_ep).unwrap();
    let sess = unsafe {
        tendril_session_connect_v2(
            cli_ep,
            v2_ep_c.as_ptr(),
            ptr::null(),
            hname_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(!sess.is_null(), "{}", read_last_err());
    let drv_host = rt.block_on(accept_handle).unwrap();
    let mut ev_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(sess, 2_000, &raw mut ev_p) },
        TENDRIL_ERR_PROTOCOL
    );
    unsafe {
        tendril_session_free(sess);
        tendril_endpoint_free(cli_ep);
    }
    drop(drv_host);

    // No export or binding save happened: reopening with the stale legacy roster still sees both.
    let reopened = unsafe {
        tendril_endpoint_new_sealed(
            cd_c.as_ptr(),
            cli_identity_c.as_ptr(),
            stale_c.as_ptr(),
            ptr::null(),
        )
    };
    assert!(!reopened.is_null(), "{}", read_last_err());
    let mut roster_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_roster_json(reopened, &raw mut roster_p) },
        TENDRIL_OK
    );
    let roster: Value = serde_json::from_str(&unsafe { take_cstr(roster_p) }).unwrap();
    assert_eq!(
        roster["entries"]["sealed-v2-host"]["min_wire_version"], 2,
        "{roster}"
    );
    assert_eq!(roster["crls"]["sealed-v2-host"]["seq"], 1, "{roster}");
    unsafe { tendril_endpoint_free(reopened) };
}

#[test]
fn sealed_concurrent_first_opens_seed_once() {
    use std::sync::{Arc, Barrier};
    use tendril_core::crypto::StaticKeypair;
    use tendril_core::roster::Roster;

    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("state");
    let dir_c = Arc::new(CString::new(dir.to_str().unwrap()).unwrap());
    let open_all = |identity: Option<Arc<CString>>, seed: Option<Arc<CString>>| {
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (barrier, dir_c) = (barrier.clone(), dir_c.clone());
                let (identity, seed) = (identity.clone(), seed.clone());
                thread::spawn(move || {
                    barrier.wait();
                    let ep = unsafe {
                        tendril_endpoint_new_sealed(
                            dir_c.as_ptr(),
                            identity.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                            seed.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                            ptr::null(),
                        )
                    };
                    assert!(!ep.is_null(), "{}", read_last_err());
                    let mut roster_p: *mut c_char = ptr::null_mut();
                    assert_eq!(
                        unsafe { tendril_endpoint_export_roster_json(ep, &raw mut roster_p) },
                        TENDRIL_OK
                    );
                    unsafe { tendril_endpoint_free(ep) };
                    serde_json::from_str::<Value>(&unsafe { take_cstr(roster_p) }).unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    };

    // Opens that generate an identity write no runtime state, so none can strand another.
    open_all(None, None);
    assert!(!dir.join("rt-roster.sealed").exists());
    assert!(!dir.join("rt-groups.sealed").exists());

    let ep = unsafe { tendril_endpoint_new_from_state(ptr::null(), ptr::null(), ptr::null()) };
    let mut id_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_identity_json(ep, &raw mut id_p) },
        TENDRIL_OK
    );
    unsafe { tendril_endpoint_free(ep) };
    let identity = Arc::new(CString::new(unsafe { take_cstr(id_p) }).unwrap());
    let peer = StaticKeypair::from_scalar([0x5a; 32]);
    let mut seed = Roster::new();
    seed.insert_pinned_host(
        peer.device_id(),
        "seeded".to_owned(),
        *peer.public_bytes(),
        None,
        0,
        Vec::new(),
    )
    .unwrap();
    let seed = Arc::new(CString::new(serde_json::to_string(&seed).unwrap()).unwrap());

    let rosters = open_all(Some(identity.clone()), Some(seed));
    assert!(
        rosters[0]["entries"][peer.device_id()].is_object(),
        "{}",
        rosters[0]
    );
    assert!(rosters.iter().all(|r| *r == rosters[0]));

    // A later stale seed never replaces the runtime roster.
    let empty = Arc::new(CString::new(serde_json::to_string(&Roster::new()).unwrap()).unwrap());
    let rosters = open_all(Some(identity), Some(empty));
    assert!(
        rosters
            .iter()
            .all(|r| r["entries"][peer.device_id()].is_object())
    );
}

#[test]
fn sealed_malformed_seed_fails_only_when_used() {
    use tendril_core::crypto::StaticKeypair;
    use tendril_core::roster::Roster;

    let ep = unsafe { tendril_endpoint_new_from_state(ptr::null(), ptr::null(), ptr::null()) };
    let mut id_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_identity_json(ep, &raw mut id_p) },
        TENDRIL_OK
    );
    unsafe { tendril_endpoint_free(ep) };
    let identity = CString::new(unsafe { take_cstr(id_p) }).unwrap();
    let malformed = CString::new("{not a roster").unwrap();
    let open = |dir: &CString, seed: &CString| unsafe {
        tendril_endpoint_new_sealed(dir.as_ptr(), identity.as_ptr(), seed.as_ptr(), ptr::null())
    };

    // A seed that would be used must parse.
    let tmp = TempDir::new().unwrap();
    let fresh = tmp.path().join("fresh");
    let fresh_c = CString::new(fresh.to_str().unwrap()).unwrap();
    assert!(open(&fresh_c, &malformed).is_null());
    assert!(read_last_err().contains("invalid roster json"));
    assert!(!fresh.join("rt-roster.sealed").exists());

    // Initialized state ignores the seed without parsing it.
    let peer = StaticKeypair::from_scalar([0x5b; 32]);
    let mut seed = Roster::new();
    seed.insert_pinned_host(
        peer.device_id(),
        "seeded".to_owned(),
        *peer.public_bytes(),
        None,
        0,
        Vec::new(),
    )
    .unwrap();
    let seed_c = CString::new(serde_json::to_string(&seed).unwrap()).unwrap();
    let ep = open(&fresh_c, &seed_c);
    assert!(!ep.is_null(), "{}", read_last_err());
    unsafe { tendril_endpoint_free(ep) };
    let ep = open(&fresh_c, &malformed);
    assert!(!ep.is_null(), "{}", read_last_err());
    let mut roster_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_roster_json(ep, &raw mut roster_p) },
        TENDRIL_OK
    );
    unsafe { tendril_endpoint_free(ep) };
    let roster: Value = serde_json::from_str(&unsafe { take_cstr(roster_p) }).unwrap();
    assert!(roster["entries"][peer.device_id()].is_object(), "{roster}");
}

#[cfg(feature = "p2p-iroh")]
#[test]
fn ffi_serve_p2p_deterministic_pair_mint_session_roundtrip() {
    let host_dir = TempDir::new().unwrap();
    let cli_dir = TempDir::new().unwrap();
    let host_path = host_dir.path().to_str().unwrap().to_owned();
    let cli_path = cli_dir.path().to_str().unwrap().to_owned();

    let hd_c = CString::new(host_path.clone()).unwrap();
    let cd_c = CString::new(cli_path).unwrap();
    let hname_c = CString::new("ffi-p2p-host").unwrap();
    let disabled_c = CString::new("disabled").unwrap();
    let remote_c = CString::new("remote").unwrap();

    let host_ep = unsafe { tendril_endpoint_new(hd_c.as_ptr(), hname_c.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(cd_c.as_ptr(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let mut p2p_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_p2p(host_ep, disabled_c.as_ptr(), &raw mut p2p_ptr) },
        TENDRIL_OK,
        "serve_p2p failed: {}",
        read_last_err()
    );
    let p2p_ep = unsafe { take_cstr(p2p_ptr) };
    assert!(p2p_ep.starts_with("iroh://"), "got: {p2p_ep}");

    let mut code_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, remote_c.as_ptr(), &raw mut code_ptr) },
        TENDRIL_OK
    );
    let code = unsafe { take_cstr(code_ptr) };

    let host_ep_usize = host_ep as usize;
    let accept_pair = thread::spawn(move || unsafe {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = tendril_endpoint_pair_accept(
            host_ep_usize as *mut tendril_ffi::TendrilEndpoint,
            8_000,
            &raw mut out,
        );
        assert_eq!(rc, TENDRIL_OK, "pair accept failed: {}", read_last_err());
        take_cstr(out)
    });

    let p2p_c = CString::new(p2p_ep.clone()).unwrap();
    let code_c = CString::new(code).unwrap();
    let mut pair_out_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_initiate(
                cli_ep,
                p2p_c.as_ptr(),
                disabled_c.as_ptr(),
                code_c.as_ptr(),
                ptr::null(),
                ptr::null(),
                &raw mut pair_out_ptr,
            )
        },
        TENDRIL_OK,
        "pair initiate over p2p failed: {}",
        read_last_err()
    );
    let pair_cli: Value = serde_json::from_str(&unsafe { take_cstr(pair_out_ptr) }).unwrap();
    let pair_srv: Value = serde_json::from_str(&accept_pair.join().unwrap()).unwrap();
    assert_eq!(pair_cli["sas"], pair_srv["sas"]);

    let dev_id = pair_srv["device_id"].as_str().unwrap();
    let dev_c = CString::new(dev_id).unwrap();
    let sas_c = CString::new(pair_cli["sas"].as_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(cli_ep, hname_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );

    let caps_c = CString::new("[\"fs.read\"]").unwrap();
    let mut grant_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                dev_c.as_ptr(),
                caps_c.as_ptr(),
                3600,
                &raw mut grant_ptr,
            )
        },
        TENDRIL_OK
    );
    let grant_c = CString::new(unsafe { take_cstr(grant_ptr) }).unwrap();

    let host_ep_usize2 = host_ep as usize;
    let accept_sess = thread::spawn(move || unsafe {
        let s = tendril_session_accept(host_ep_usize2 as *mut tendril_ffi::TendrilEndpoint, 8_000);
        assert!(!s.is_null(), "session accept failed: {}", read_last_err());
        s as usize
    });

    let cli_sess = unsafe {
        tendril_session_connect(
            cli_ep,
            p2p_c.as_ptr(),
            disabled_c.as_ptr(),
            hname_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(
        !cli_sess.is_null(),
        "p2p session connect failed: {}",
        read_last_err()
    );
    let host_sess = accept_sess.join().unwrap() as *mut tendril_ffi::TendrilSession;

    let msg = b"hello-ffi-p2p";
    assert_eq!(
        unsafe { tendril_session_send_data(cli_sess, msg.as_ptr(), msg.len()) },
        TENDRIL_OK
    );
    let mut ev_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 2_000, &raw mut ev_ptr) },
        TENDRIL_OK
    );
    let ev: Value = serde_json::from_str(&unsafe { take_cstr(ev_ptr) }).unwrap();
    assert_eq!(ev["event"], "data");
    assert_eq!(ev["data_b64"], b64url_encode(msg));

    unsafe {
        tendril_session_close(cli_sess, 1000, ptr::null());
        tendril_session_free(cli_sess);
        tendril_session_free(host_sess);
        tendril_endpoint_free(cli_ep);
        tendril_endpoint_free(host_ep);
    }

    // Reopen host endpoint from same state_dir and confirm P2P EndpointId stays identical.
    let host_ep_reopened = unsafe { tendril_endpoint_new(hd_c.as_ptr(), ptr::null()) };
    assert!(!host_ep_reopened.is_null());
    let mut p2p_ptr2: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_p2p(host_ep_reopened, disabled_c.as_ptr(), &raw mut p2p_ptr2)
        },
        TENDRIL_OK
    );
    let p2p_ep2 = unsafe { take_cstr(p2p_ptr2) };
    assert_eq!(p2p_ep.split('?').next(), p2p_ep2.split('?').next());
    unsafe { tendril_endpoint_free(host_ep_reopened) };
}

#[cfg(feature = "p2p-iroh")]
#[test]
fn ffi_serve_p2p_rejects_lan_code() {
    let host_ep = unsafe { tendril_endpoint_new(ptr::null(), ptr::null()) };
    let cli_ep = unsafe { tendril_endpoint_new(ptr::null(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let disabled_c = CString::new("disabled").unwrap();
    let mut p2p_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_p2p(host_ep, disabled_c.as_ptr(), &raw mut p2p_ptr) },
        TENDRIL_OK
    );
    let p2p_ep = unsafe { take_cstr(p2p_ptr) };

    let mut code_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, ptr::null(), &raw mut code_ptr) },
        TENDRIL_OK
    );
    let lan_code_c = CString::new(unsafe { take_cstr(code_ptr) }).unwrap();
    let p2p_c = CString::new(p2p_ep).unwrap();

    let host_ep_usize = host_ep as usize;
    let accept_pair = thread::spawn(move || unsafe {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = tendril_endpoint_pair_accept(
            host_ep_usize as *mut tendril_ffi::TendrilEndpoint,
            8_000,
            &raw mut out,
        );
        assert_eq!(rc, TENDRIL_ERR_PROTOCOL);
        assert!(out.is_null());
    });

    let mut pair_out_ptr: *mut c_char = ptr::null_mut();
    let cli_rc = unsafe {
        tendril_endpoint_pair_initiate(
            cli_ep,
            p2p_c.as_ptr(),
            disabled_c.as_ptr(),
            lan_code_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            &raw mut pair_out_ptr,
        )
    };
    assert_ne!(cli_rc, TENDRIL_OK);
    assert!(pair_out_ptr.is_null());
    accept_pair.join().unwrap();

    unsafe {
        tendril_endpoint_free(cli_ep);
        tendril_endpoint_free(host_ep);
    }
}

#[cfg(not(feature = "p2p-iroh"))]
#[test]
fn ffi_serve_p2p_without_feature_returns_protocol_error() {
    let host_ep = unsafe { tendril_endpoint_new(ptr::null(), ptr::null()) };
    assert!(!host_ep.is_null());
    let mut p2p_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe { tendril_endpoint_serve_p2p(host_ep, ptr::null(), &raw mut p2p_ptr) };
    assert_eq!(rc, TENDRIL_ERR_PROTOCOL);
    assert!(p2p_ptr.is_null());
    assert!(read_last_err().contains("p2p-iroh"));
    unsafe { tendril_endpoint_free(host_ep) };
}

#[test]
fn batch1_sec03_ffi_pair_flood_does_not_starve_accept_session() {
    use std::io::Write;
    use std::net::TcpStream;

    let tmp = TempDir::new().unwrap();
    let host_dir = tmp.path().join("host");
    let cli_dir = tmp.path().join("cli");
    let grant_str = pair_and_mint_c(
        host_dir.to_str().unwrap(),
        cli_dir.to_str().unwrap(),
        "ffi-sec03-host",
        "[\"fs.read\"]",
    );

    let hd_c = CString::new(host_dir.to_str().unwrap()).unwrap();
    let cd_c = CString::new(cli_dir.to_str().unwrap()).unwrap();
    let hn_c = CString::new("ffi-sec03-host").unwrap();
    let host_ep = unsafe { tendril_endpoint_new(hd_c.as_ptr(), hn_c.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(cd_c.as_ptr(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let mut ep_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, ptr::null(), &raw mut ep_ptr) },
        TENDRIL_OK
    );
    let ep_str = unsafe { take_cstr(ep_ptr) };
    let addr = ep_str.strip_prefix("direct:").unwrap_or(&ep_str);

    // Park 32 unconsumed Intent::Pair streams across two IP bursts while pair_accept is unpolled.
    let mut floods = Vec::new();
    for i in 0..32usize {
        if i == 24 {
            thread::sleep(Duration::from_millis(1_500));
        }
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"TND\x01\x02\x00").unwrap();
        floods.push(s);
    }
    thread::sleep(Duration::from_millis(300));

    let ep_usize = host_ep as usize;
    let accept_thr = thread::spawn(move || {
        let s =
            unsafe { tendril_session_accept(ep_usize as *mut tendril_ffi::TendrilEndpoint, 4_000) };
        assert!(!s.is_null(), "session accept starved: {}", read_last_err());
        s as usize
    });

    let ep_c = CString::new(ep_str).unwrap();
    let grant_c = CString::new(grant_str).unwrap();
    let cli_sess = unsafe {
        tendril_session_connect(
            cli_ep,
            ep_c.as_ptr(),
            ptr::null(),
            hn_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(
        !cli_sess.is_null(),
        "session connect failed after pair flood: {}",
        read_last_err()
    );
    let host_sess = accept_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;

    drop(floods);
    unsafe {
        tendril_session_close(cli_sess, 1000, ptr::null());
        tendril_session_free(cli_sess);
        tendril_session_free(host_sess);
        tendril_endpoint_free(cli_ep);
        tendril_endpoint_free(host_ep);
    }
}

#[test]
fn batch2b_sec08_sec17_sec32_sec37_ffi_hardening() {
    use std::time::Instant;

    // SEC-08: in-memory state creation + export with zero filesystem state.
    let hn = CString::new("mem-host").unwrap();
    let mem_ep = unsafe { tendril_endpoint_new_from_state(ptr::null(), ptr::null(), hn.as_ptr()) };
    assert!(!mem_ep.is_null());

    let mut id_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_identity_json(mem_ep, &raw mut id_ptr) },
        TENDRIL_OK
    );
    let id_json = unsafe { take_cstr(id_ptr) };

    let mut rst_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_roster_json(mem_ep, &raw mut rst_ptr) },
        TENDRIL_OK
    );
    let rst_json = unsafe { take_cstr(rst_ptr) };

    let mut info_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(mem_ep, &raw mut info_ptr) },
        TENDRIL_OK
    );
    let info_orig = unsafe { take_cstr(info_ptr) };
    unsafe { tendril_endpoint_free(mem_ep) };

    let id_c = CString::new(id_json).unwrap();
    let rst_c = CString::new(rst_json).unwrap();
    let restored =
        unsafe { tendril_endpoint_new_from_state(id_c.as_ptr(), rst_c.as_ptr(), ptr::null()) };
    assert!(!restored.is_null(), "restore failed: {}", read_last_err());
    let mut info2_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(restored, &raw mut info2_ptr) },
        TENDRIL_OK
    );
    assert_eq!(unsafe { take_cstr(info2_ptr) }, info_orig);

    // SEC-17 (Endpoint): tendril_endpoint_close wakes blocked tendril_session_accept immediately.
    let ep_usize = restored as usize;
    let accept_t0 = Instant::now();
    let acc_thr = thread::spawn(move || {
        unsafe { tendril_session_accept(ep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) }
            .is_null()
    });
    thread::sleep(Duration::from_millis(60));
    assert_eq!(unsafe { tendril_endpoint_close(restored) }, TENDRIL_OK);
    assert!(acc_thr.join().unwrap());
    assert!(accept_t0.elapsed() < Duration::from_secs(1));
    unsafe { tendril_endpoint_free(restored) };

    // Pair + establish session to test SEC-17 full-duplex, SEC-32 len guard, SEC-37 UTF-8 error alignment.
    let tmp = TempDir::new().unwrap();
    let host_dir = tmp.path().join("host");
    let cli_dir = tmp.path().join("cli");
    let grant_str = pair_and_mint_c(
        host_dir.to_str().unwrap(),
        cli_dir.to_str().unwrap(),
        "ffi-sec17-host",
        "[\"fs.read\"]",
    );

    let hd_c = CString::new(host_dir.to_str().unwrap()).unwrap();
    let cd_c = CString::new(cli_dir.to_str().unwrap()).unwrap();
    let hn_c = CString::new("ffi-sec17-host").unwrap();
    let host_ep = unsafe { tendril_endpoint_new(hd_c.as_ptr(), hn_c.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(cd_c.as_ptr(), ptr::null()) };

    let mut ep_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, ptr::null(), &raw mut ep_ptr) },
        TENDRIL_OK
    );
    let ep_str = unsafe { take_cstr(ep_ptr) };

    let hep_usize = host_ep as usize;
    let acc_sess_thr = thread::spawn(move || {
        unsafe { tendril_session_accept(hep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) }
            .addr()
    });
    let ep_c = CString::new(ep_str).unwrap();
    let grant_c = CString::new(grant_str).unwrap();
    let cli_sess = unsafe {
        tendril_session_connect(
            cli_ep,
            ep_c.as_ptr(),
            ptr::null(),
            hn_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(!cli_sess.is_null());
    let host_sess = acc_sess_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess.is_null());

    // SEC-32: len > isize::MAX and len > MAX_APP_DATA_LEN return TENDRIL_ERR_PROTOCOL without panic/abort.
    let dummy = 1u8;
    assert_eq!(
        unsafe { tendril_session_send_data(cli_sess, &raw const dummy, usize::MAX) },
        TENDRIL_ERR_PROTOCOL
    );
    assert_eq!(
        unsafe {
            tendril_session_send_data(
                cli_sess,
                &raw const dummy,
                tendril_core::MAX_APP_DATA_LEN + 1,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );

    // SEC-37: tendril_last_error backs down to valid UTF-8 char boundary when cap splits 4-byte emoji.
    let mut emoji_peer = String::from("dev_missing_");
    emoji_peer.push('\u{1F600}');
    let emoji_c = CString::new(emoji_peer).unwrap();
    let mut small = vec![0u8; 41];
    assert_eq!(
        unsafe { tendril_endpoint_revoke_peer(host_ep, emoji_c.as_ptr()) },
        TENDRIL_ERR_NOT_FOUND
    );
    unsafe {
        let needed = tendril_last_error(small.as_mut_ptr().cast::<c_char>(), small.len());
        assert!(needed > small.len() as i32);
        let cstr = CStr::from_ptr(small.as_ptr().cast::<c_char>());
        assert_eq!(
            cstr.to_str().unwrap(),
            "peer not found in roster: dev_missing_"
        );
    }

    // Export session roster JSON cleanly.
    let mut sr_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_export_roster_json(host_sess, &raw mut sr_ptr) },
        TENDRIL_OK
    );
    let _ = unsafe { take_cstr(sr_ptr) };

    // SEC-17 (Session): poll_event(5000) does NOT block authorize, send_data, or shutdown.
    let hs_usize = host_sess as usize;
    let poll_thr = thread::spawn(move || {
        let mut ev_ptr: *mut c_char = ptr::null_mut();
        unsafe {
            tendril_session_poll_event(
                hs_usize as *mut tendril_ffi::TendrilSession,
                5_000,
                &raw mut ev_ptr,
            )
        }
    });
    thread::sleep(Duration::from_millis(60));

    let conc_t0 = Instant::now();
    let mut conc_peer_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_peer_id(host_sess, &raw mut conc_peer_ptr) },
        TENDRIL_OK
    );
    let conc_peer = unsafe { take_cstr(conc_peer_ptr) };
    assert!(
        conc_peer.starts_with("dev_"),
        "unexpected peer id: {conc_peer}"
    );
    assert_eq!(
        unsafe { tendril_session_peer_id(cli_sess, &raw mut conc_peer_ptr) },
        TENDRIL_OK
    );
    assert_eq!(unsafe { take_cstr(conc_peer_ptr) }, "ffi-sec17-host");
    let cap_ok = CString::new("fs.read").unwrap();
    let mut allowed = 0u8;
    assert_eq!(
        unsafe { tendril_session_authorize(host_sess, cap_ok.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 1);
    assert_eq!(
        unsafe { tendril_session_send_data(host_sess, b"host-to-cli".as_ptr(), 11) },
        TENDRIL_OK
    );
    assert!(conc_t0.elapsed() < Duration::from_millis(500));

    let mut cli_ev_ptr: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(cli_sess, 2_000, &raw mut cli_ev_ptr) },
        TENDRIL_OK
    );
    let cli_ev: Value = serde_json::from_str(&unsafe { take_cstr(cli_ev_ptr) }).unwrap();
    assert_eq!(cli_ev["event"], "data");

    assert_eq!(unsafe { tendril_session_shutdown(host_sess) }, TENDRIL_OK);
    assert_eq!(poll_thr.join().unwrap(), TENDRIL_EOF);
    assert!(conc_t0.elapsed() < Duration::from_secs(1));

    // SEC-31: grant expiring while tendril_session_poll_event is parked must reject incoming REKEY.
    let exp_host_info: Value = {
        let mut info_p: *mut c_char = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_info_json(host_ep, &raw mut info_p) },
            TENDRIL_OK
        );
        serde_json::from_str(&unsafe { take_cstr(info_p) }).unwrap()
    };
    let cli_id_info: Value = {
        let mut info_p: *mut c_char = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_info_json(cli_ep, &raw mut info_p) },
            TENDRIL_OK
        );
        serde_json::from_str(&unsafe { take_cstr(info_p) }).unwrap()
    };
    let cli_dev_c = CString::new(cli_id_info["device_id"].as_str().unwrap()).unwrap();
    const GRANT_TTL_SECS: u64 = 3;
    const EXPIRY_WAIT_MAX: Duration = Duration::from_secs(GRANT_TTL_SECS + 5);
    // Longer than EXPIRY_WAIT_MAX so the parked poll ends by expiry, not WOULD_BLOCK.
    const POLL_TIMEOUT_MS: u64 = 15_000;
    let short_caps_c = CString::new("[\"fs.read\"]").unwrap();
    let mut short_grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli_dev_c.as_ptr(),
                short_caps_c.as_ptr(),
                GRANT_TTL_SECS,
                &raw mut short_grant_p,
            )
        },
        TENDRIL_OK
    );
    let minted_unix = current_unix();
    let t_mint = Instant::now();
    let short_grant = unsafe { take_cstr(short_grant_p) };
    let not_after = rfc3339_utc_to_unix(
        serde_json::from_str::<Value>(&short_grant).unwrap()["not_after"]
            .as_str()
            .unwrap(),
    );
    let short_grant_c = CString::new(short_grant).unwrap();
    let hep2_usize = host_ep as usize;
    let acc2_thr = thread::spawn(move || {
        let sess = unsafe {
            tendril_session_accept(hep2_usize as *mut tendril_ffi::TendrilEndpoint, 5_000)
        };
        let err = if sess.is_null() {
            read_last_err()
        } else {
            String::new()
        };
        (sess.addr(), err, current_unix(), t_mint.elapsed())
    });
    let hn2_c = CString::new(exp_host_info["host_id"].as_str().unwrap()).unwrap();
    let cli_sess2 = unsafe {
        tendril_session_connect(
            cli_ep,
            ep_c.as_ptr(),
            ptr::null(),
            hn2_c.as_ptr(),
            short_grant_c.as_ptr(),
        )
    };
    assert!(!cli_sess2.is_null(), "connect2 failed: {}", read_last_err());
    let (host_sess2_addr, accept_err, accept_unix, accept_elapsed) = acc2_thr.join().unwrap();
    let host_sess2 = host_sess2_addr as *mut tendril_ffi::TendrilSession;
    assert!(
        !host_sess2.is_null(),
        "host accept failed: {accept_err} (not_after={not_after} minted_unix={minted_unix} \
         accept_unix={accept_unix} mint_to_accept={accept_elapsed:?})"
    );

    let hs2_usize = host_sess2 as usize;
    let poll2_thr = thread::spawn(move || {
        let entered = current_unix();
        let mut ev_p: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_session_poll_event(
                hs2_usize as *mut tendril_ffi::TendrilSession,
                POLL_TIMEOUT_MS,
                &raw mut ev_p,
            )
        };
        let err = read_last_err();
        if !ev_p.is_null() {
            unsafe { tendril_string_free(ev_p) };
        }
        (rc, err, entered)
    });
    let give_up = Instant::now() + EXPIRY_WAIT_MAX;
    while current_unix() < not_after {
        assert!(
            Instant::now() < give_up,
            "wall clock did not reach not_after={not_after}: minted_unix={minted_unix} now={} \
             monotonic_elapsed={:?} (clock stepped back?)",
            current_unix(),
            t_mint.elapsed()
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !poll2_thr.is_finished(),
        "poll returned before the rekey: minted_unix={minted_unix} not_after={not_after}"
    );
    assert_eq!(unsafe { tendril_session_rekey(cli_sess2) }, TENDRIL_OK);
    let (rc, err, entered) = poll2_thr.join().unwrap();
    assert_eq!(rc, TENDRIL_ERR_PROTOCOL, "poll error: {err}");
    assert!(
        err.contains("grant outside validity window"),
        "poll failed for another reason: {err}"
    );
    assert!(
        entered < not_after,
        "poll entered after expiry: entered={entered} not_after={not_after}"
    );

    unsafe {
        tendril_session_close(cli_sess2, 1000, ptr::null());
        tendril_session_free(cli_sess2);
        tendril_session_free(host_sess2);
        tendril_session_close(cli_sess, 1000, ptr::null());
        tendril_session_free(cli_sess);
        tendril_session_free(host_sess);
        tendril_endpoint_free(cli_ep);
        tendril_endpoint_free(host_ep);
    }
}

#[test]
fn phase6_m2m_enrollment_and_replay_rejection() {
    use tendril_core::crypto::b64url_decode_array;

    let host_dir = TempDir::new().unwrap();
    let cli1_dir = TempDir::new().unwrap();
    let cli2_dir = TempDir::new().unwrap();
    let host_dir_c = CString::new(host_dir.path().to_str().unwrap()).unwrap();
    let cli1_dir_c = CString::new(cli1_dir.path().to_str().unwrap()).unwrap();
    let cli2_dir_c = CString::new(cli2_dir.path().to_str().unwrap()).unwrap();
    let host_name_c = CString::new("ffi-m2m-host").unwrap();

    let host_ep = unsafe { tendril_endpoint_new(host_dir_c.as_ptr(), host_name_c.as_ptr()) };
    let cli1_ep = unsafe { tendril_endpoint_new(cli1_dir_c.as_ptr(), ptr::null()) };
    let cli2_ep = unsafe { tendril_endpoint_new(cli2_dir_c.as_ptr(), ptr::null()) };
    let anchor_ep =
        unsafe { tendril_endpoint_new(ptr::null(), CString::new("ffi-anchor").unwrap().as_ptr()) };
    assert!(!host_ep.is_null() && !cli1_ep.is_null() && !cli2_ep.is_null() && !anchor_ep.is_null());

    let mut host_info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(host_ep, &raw mut host_info_p) },
        TENDRIL_OK
    );
    let host_info: Value = serde_json::from_str(&unsafe { take_cstr(host_info_p) }).unwrap();
    let host_id = host_info["host_id"].as_str().unwrap().to_owned();
    let host_static_pub: [u8; 32] =
        b64url_decode_array(host_info["static_pub"].as_str().unwrap()).unwrap();
    let host_signing_pub = b64url_decode(host_info["signing_pub"].as_str().unwrap()).unwrap();
    assert_eq!(host_signing_pub.len(), HYBRID_SIGNING_PUB_LEN);
    let host_signing_hash: [u8; 32] =
        b64url_decode_array(host_info["signing_pub_hash"].as_str().unwrap()).unwrap();

    let mut anchor_info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(anchor_ep, &raw mut anchor_info_p) },
        TENDRIL_OK
    );
    let anchor_info: Value = serde_json::from_str(&unsafe { take_cstr(anchor_info_p) }).unwrap();
    let anchor_id = anchor_info["host_id"].as_str().unwrap().to_owned();
    let anchor_signing_pub = b64url_decode(anchor_info["signing_pub"].as_str().unwrap()).unwrap();
    assert_eq!(anchor_signing_pub.len(), HYBRID_SIGNING_PUB_LEN);

    let mut cli1_info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(cli1_ep, &raw mut cli1_info_p) },
        TENDRIL_OK
    );
    let cli1_info: Value = serde_json::from_str(&unsafe { take_cstr(cli1_info_p) }).unwrap();
    let cli1_dev_id = cli1_info["device_id"].as_str().unwrap().to_owned();

    let mut cli2_info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(cli2_ep, &raw mut cli2_info_p) },
        TENDRIL_OK
    );
    let cli2_info: Value = serde_json::from_str(&unsafe { take_cstr(cli2_info_p) }).unwrap();
    let cli2_dev_id = cli2_info["device_id"].as_str().unwrap().to_owned();

    let listen_c = CString::new("127.0.0.1:0").unwrap();
    let mut ep_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, listen_c.as_ptr(), &raw mut ep_p) },
        TENDRIL_OK
    );
    let ep_str = unsafe { take_cstr(ep_p) };
    let ep_c = CString::new(ep_str).unwrap();
    let host_id_c = CString::new(host_id.as_str()).unwrap();
    let cli1_dev_c = CString::new(cli1_dev_id.as_str()).unwrap();

    // 1. Self-issued token enrolls cli1 directly to Active with zero app grants.
    let mut tok1_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_enrollment_token(
                host_ep,
                host_id_c.as_ptr(),
                cli1_dev_c.as_ptr(),
                900,
                &raw mut tok1_p,
            )
        },
        TENDRIL_OK
    );
    let tok1_str = unsafe { take_cstr(tok1_p) };
    let tok1_c = CString::new(tok1_str.as_str()).unwrap();
    let name1_c = CString::new("m2m-1").unwrap();
    let kind_c = CString::new("machine").unwrap();

    let hep_usize = host_ep as usize;
    let accept_thr1 = thread::spawn(move || {
        let mut out_p: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out_p,
            )
        };
        (
            rc,
            if out_p.is_null() {
                String::new()
            } else {
                unsafe { take_cstr(out_p) }
            },
        )
    });

    let mut enroll1_p: *mut c_char = ptr::null_mut();
    let rc1 = unsafe {
        tendril_endpoint_enroll_initiate(
            cli1_ep,
            ep_c.as_ptr(),
            ptr::null(),
            host_id_c.as_ptr(),
            host_static_pub.as_ptr(),
            host_signing_pub.as_ptr(),
            host_signing_pub.len(),
            0,
            tok1_c.as_ptr(),
            name1_c.as_ptr(),
            kind_c.as_ptr(),
            &raw mut enroll1_p,
        )
    };
    assert_eq!(rc1, TENDRIL_OK, "enroll1 err: {}", read_last_err());
    let enroll1_json: Value = serde_json::from_str(&unsafe { take_cstr(enroll1_p) }).unwrap();
    assert_eq!(enroll1_json["status"], "active");
    let (acc_rc1, acc_json1) = accept_thr1.join().unwrap();
    assert_eq!(acc_rc1, TENDRIL_OK);
    let acc1: Value = serde_json::from_str(&acc_json1).unwrap();
    assert_eq!(acc1["status"], "active");
    assert_eq!(acc1["device_id"], cli1_dev_id);

    // 2. Single-use burn rejects immediate replay.
    let accept_thr_rep = thread::spawn(move || {
        let mut out_p: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out_p,
            )
        };
        if !out_p.is_null() {
            unsafe { tendril_string_free(out_p) };
        }
        rc
    });
    let mut rep_p: *mut c_char = ptr::null_mut();
    let rep_rc = unsafe {
        tendril_endpoint_enroll_initiate(
            cli1_ep,
            ep_c.as_ptr(),
            ptr::null(),
            host_id_c.as_ptr(),
            host_static_pub.as_ptr(),
            host_signing_hash.as_ptr(),
            host_signing_hash.len(),
            0,
            tok1_c.as_ptr(),
            name1_c.as_ptr(),
            kind_c.as_ptr(),
            &raw mut rep_p,
        )
    };
    assert_eq!(rep_rc, TENDRIL_ERR_PROTOCOL);
    assert!(read_last_err().contains("token_replayed"));
    assert_eq!(accept_thr_rep.join().unwrap(), TENDRIL_ERR_PROTOCOL);

    // 3. Trust anchor enrollment works, then revoking the anchor blocks fresh tokens.
    let anchor_id_c = CString::new(anchor_id.as_str()).unwrap();
    assert_eq!(
        unsafe {
            tendril_endpoint_add_trust_anchor(
                host_ep,
                anchor_id_c.as_ptr(),
                anchor_signing_pub.as_ptr(),
                anchor_signing_pub.len(),
            )
        },
        TENDRIL_OK
    );
    let cli2_dev_c = CString::new(cli2_dev_id.as_str()).unwrap();
    let mut tok2_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_enrollment_token(
                anchor_ep,
                host_id_c.as_ptr(),
                cli2_dev_c.as_ptr(),
                900,
                &raw mut tok2_p,
            )
        },
        TENDRIL_OK
    );
    let tok2_c = CString::new(unsafe { take_cstr(tok2_p) }).unwrap();
    let accept_thr2 = thread::spawn(move || {
        let mut out_p: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out_p,
            )
        };
        if !out_p.is_null() {
            unsafe { tendril_string_free(out_p) };
        }
        rc
    });
    let mut enroll2_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_enroll_initiate(
                cli2_ep,
                ep_c.as_ptr(),
                ptr::null(),
                host_id_c.as_ptr(),
                host_static_pub.as_ptr(),
                host_signing_hash.as_ptr(),
                host_signing_hash.len(),
                0,
                tok2_c.as_ptr(),
                name1_c.as_ptr(),
                kind_c.as_ptr(),
                &raw mut enroll2_p,
            )
        },
        TENDRIL_OK
    );
    unsafe { tendril_string_free(enroll2_p) };
    assert_eq!(accept_thr2.join().unwrap(), TENDRIL_OK);

    assert_eq!(
        unsafe { tendril_endpoint_revoke_trust_anchor(host_ep, anchor_id_c.as_ptr()) },
        TENDRIL_OK
    );
    let mut tok3_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_enrollment_token(
                anchor_ep,
                host_id_c.as_ptr(),
                ptr::null(),
                900,
                &raw mut tok3_p,
            )
        },
        TENDRIL_OK
    );
    let tok3_c = CString::new(unsafe { take_cstr(tok3_p) }).unwrap();
    let accept_thr3 = thread::spawn(move || {
        let mut out_p: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out_p,
            )
        };
        if !out_p.is_null() {
            unsafe { tendril_string_free(out_p) };
        }
        rc
    });
    let mut enroll3_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_enroll_initiate(
                cli2_ep,
                ep_c.as_ptr(),
                ptr::null(),
                host_id_c.as_ptr(),
                host_static_pub.as_ptr(),
                host_signing_pub.as_ptr(),
                host_signing_pub.len(),
                0,
                tok3_c.as_ptr(),
                name1_c.as_ptr(),
                kind_c.as_ptr(),
                &raw mut enroll3_p,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(read_last_err().contains("untrusted_anchor"));
    assert_eq!(accept_thr3.join().unwrap(), TENDRIL_ERR_PROTOCOL);

    // 4. Default deny holds on enrolled peer until mint_grant is called.
    let acc_sess_thr = thread::spawn(move || {
        unsafe { tendril_session_accept(hep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) }
            .addr()
    });
    let sess1 = unsafe {
        tendril_session_connect(
            cli1_ep,
            ep_c.as_ptr(),
            ptr::null(),
            host_id_c.as_ptr(),
            ptr::null(),
        )
    };
    assert!(!sess1.is_null(), "connect failed: {}", read_last_err());
    let host_sess1 = acc_sess_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess1.is_null());
    let cap_c = CString::new("fs.read:/m2m/doc.txt").unwrap();
    let mut allowed: u8 = 9;
    assert_eq!(
        unsafe { tendril_session_authorize(host_sess1, cap_c.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 0);

    let caps_c = CString::new("[\"fs.read:/m2m/*\"]").unwrap();
    let mut grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli1_dev_c.as_ptr(),
                caps_c.as_ptr(),
                300,
                &raw mut grant_p,
            )
        },
        TENDRIL_OK
    );
    let grant_c = CString::new(unsafe { take_cstr(grant_p) }).unwrap();
    let acc_sess2_thr = thread::spawn(move || {
        unsafe { tendril_session_accept(hep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) }
            .addr()
    });
    let sess2 = unsafe {
        tendril_session_connect(
            cli1_ep,
            ep_c.as_ptr(),
            ptr::null(),
            host_id_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(!sess2.is_null());
    let host_sess2 = acc_sess2_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess2.is_null());
    assert_eq!(
        unsafe { tendril_session_authorize(host_sess2, cap_c.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 1);
    let mut m2m_peer_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_peer_id(sess2, &raw mut m2m_peer_p) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { take_cstr(m2m_peer_p) },
        host_id_c.to_str().unwrap()
    );
    assert_eq!(
        unsafe { tendril_session_peer_id(host_sess2, &raw mut m2m_peer_p) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { take_cstr(m2m_peer_p) },
        cli1_dev_c.to_str().unwrap()
    );

    // Invalid pin/key lengths must fail closed before reading beyond caller buffer.
    let short_buf = [0x11u8; 32];
    for bad_len in [0usize, 1, 31, 33, 1983, 1985, usize::MAX] {
        let rc_anchor = unsafe {
            tendril_endpoint_add_trust_anchor(host_ep, ep_c.as_ptr(), short_buf.as_ptr(), bad_len)
        };
        assert_eq!(rc_anchor, TENDRIL_ERR_INVALID_ARG);

        let mut bad_enroll_p: *mut c_char = ptr::null_mut();
        let rc_enroll = unsafe {
            tendril_endpoint_enroll_initiate(
                cli1_ep,
                ep_c.as_ptr(),
                ptr::null(),
                host_id_c.as_ptr(),
                host_static_pub.as_ptr(),
                short_buf.as_ptr(),
                bad_len,
                0,
                tok3_c.as_ptr(),
                name1_c.as_ptr(),
                kind_c.as_ptr(),
                &raw mut bad_enroll_p,
            )
        };
        assert_eq!(rc_enroll, TENDRIL_ERR_INVALID_ARG);
        assert!(bad_enroll_p.is_null());
    }

    unsafe {
        tendril_session_close(sess1, 1000, ptr::null());
        tendril_session_free(sess1);
        tendril_session_free(host_sess1);
        tendril_session_close(sess2, 1000, ptr::null());
        tendril_session_free(sess2);
        tendril_session_free(host_sess2);
        tendril_endpoint_free(anchor_ep);
        tendril_endpoint_free(cli2_ep);
        tendril_endpoint_free(cli1_ep);
        tendril_endpoint_free(host_ep);
    }
}

#[test]
fn ffi_configure_transports_json_validation_and_feature_gates() {
    let ep = unsafe { tendril_endpoint_new(ptr::null(), ptr::null()) };
    assert!(!ep.is_null());

    // NULL pointer safety checks across all 7 new C ABI symbols.
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ptr::null_mut(), ptr::null()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, ptr::null()) },
        TENDRIL_ERR_INVALID_ARG
    );
    let mut null_out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_relay_ticket(
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                &raw mut null_out,
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_relay_ticket(
                ep,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay_v2(
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                &raw mut null_out,
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                &raw mut null_out,
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_endpoint_pair_v2_accept(ptr::null_mut(), 10, &raw mut null_out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_endpoint_pair_v2_accept(ep, 10, ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(
        unsafe {
            tendril_session_connect_v2(
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        }
        .is_null()
    );
    assert!(unsafe { tendril_session_accept_v2(ptr::null_mut(), 10) }.is_null());

    // Strict deny_unknown_fields (must not echo unexpected keys or scalar values).
    let bad_unknown = CString::new("{\"unknown_field\":1}").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, bad_unknown.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    let err_unknown = read_last_err();
    assert!(
        err_unknown.contains("invalid transport_config_json"),
        "unexpected err: {err_unknown}"
    );
    assert!(!err_unknown.contains("unknown_field"));

    // Non-string scalar type error on secret field must NEVER echo the scalar value.
    let bad_scalar_secret = CString::new("{\"relay_auth_secret\":123456}").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, bad_scalar_secret.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    let err_scalar = read_last_err();
    assert!(err_scalar.contains("invalid transport_config_json"));
    assert!(
        !err_scalar.contains("123456"),
        "last_error leaked scalar secret value: {err_scalar}"
    );

    // Mutually exclusive relay auth fields.
    let bad_relay_mutex = CString::new(
        r#"{"relay_auth_secret":"sec","relay_ticket":{"v":1,"issuer_pub":"AA","relay_host":"h","role":"any","target_pub":"*","not_before":1,"not_after":2,"sig":"AA"}}"#,
    )
    .unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, bad_relay_mutex.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("mutually exclusive"));

    // Empty relay_ticket fields rejected.
    let bad_empty_ticket = CString::new(
        r#"{"relay_ticket":{"v":1,"issuer_pub":"","relay_host":"h","role":"any","target_pub":"*","not_before":1,"not_after":2,"sig":""}}"#,
    )
    .unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, bad_empty_ticket.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );

    // Mutually exclusive P2P auth and P2P relay mode fields.
    let bad_p2p_auth_mutex =
        CString::new(r#"{"p2p_relay_auth_token":"tok","p2p_api_secret":"sec"}"#).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, bad_p2p_auth_mutex.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("mutually exclusive"));

    let bad_p2p_mode_mutex =
        CString::new(r#"{"p2p_relay_mode":"default","p2p_relay_urls":["https://relay.example"]}"#)
            .unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, bad_p2p_mode_mutex.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("mutually exclusive"));

    // Control character in secret fails closed and does not echo secret in error message.
    let secret_with_ctrl =
        CString::new("{\"relay_auth_secret\":\"leaked-secret\\u0007\"}").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, secret_with_ctrl.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(!read_last_err().contains("leaked-secret"));

    // Wake options validation: require wake_url, wake_secret_b64, and valid base64url 32 bytes.
    let wake_no_url = CString::new("{\"wake_pre_wake\":true}").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, wake_no_url.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    let wake_no_secret = CString::new("{\"wake_url\":\"http://127.0.0.1:9/wake\"}").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, wake_no_secret.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    let wake_bad_secret =
        CString::new("{\"wake_url\":\"http://127.0.0.1:9/wake\",\"wake_secret_b64\":\"not-32\"}")
            .unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(ep, wake_bad_secret.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("wake_secret_b64"));

    // Invalid P2P auth with disabled relay mode.
    let p2p_disabled_auth =
        CString::new("{\"p2p_relay_mode\":\"disabled\",\"p2p_relay_auth_token\":\"tok\"}").unwrap();
    let rc_dis =
        unsafe { tendril_endpoint_configure_transports_json(ep, p2p_disabled_auth.as_ptr()) };
    #[cfg(feature = "p2p-iroh")]
    assert_eq!(rc_dis, TENDRIL_ERR_INVALID_ARG);
    #[cfg(not(feature = "p2p-iroh"))]
    assert_eq!(rc_dis, TENDRIL_ERR_PROTOCOL);

    // p2p_api_secret requires p2p-iroh-services (and p2p-iroh).
    let api_sec = CString::new(
        "{\"p2p_relay_mode\":\"https://relay.example\",\"p2p_api_secret\":\"api-sec\"}",
    )
    .unwrap();
    let rc_api = unsafe { tendril_endpoint_configure_transports_json(ep, api_sec.as_ptr()) };
    #[cfg(feature = "p2p-iroh-services")]
    assert_eq!(
        rc_api,
        TENDRIL_OK,
        "p2p_api_secret err: {}",
        read_last_err()
    );
    #[cfg(not(feature = "p2p-iroh-services"))]
    assert_eq!(rc_api, TENDRIL_ERR_PROTOCOL);

    unsafe { tendril_endpoint_free(ep) };
}

#[test]
fn ffi_relay_auth_mint_ticket_and_gated_v1_relay() {
    use tendril_core::crypto::b64url_decode_array;
    use tendril_core::relay_auth::RelayAuthScope;
    use tendril_relay::RelayConfig;
    use tendril_runtime::EmbeddedRelay;
    use zeroize::Zeroizing;

    let host_dir = TempDir::new().unwrap();
    let cli_dir = TempDir::new().unwrap();
    let hd_c = CString::new(host_dir.path().to_str().unwrap()).unwrap();
    let cd_c = CString::new(cli_dir.path().to_str().unwrap()).unwrap();
    let hname_c = CString::new("ffi-gated-host").unwrap();

    let host_ep = unsafe { tendril_endpoint_new(hd_c.as_ptr(), hname_c.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(cd_c.as_ptr(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let mut host_id_json_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(host_ep, &raw mut host_id_json_p) },
        TENDRIL_OK
    );
    let host_id_val: Value = serde_json::from_str(&unsafe { take_cstr(host_id_json_p) }).unwrap();
    let host_relay_pub_b64 = host_id_val["relay_pub"].as_str().unwrap().to_owned();
    let host_relay_pub: [u8; 32] = b64url_decode_array(&host_relay_pub_b64).unwrap();

    let mut cli_id_json_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(cli_ep, &raw mut cli_id_json_p) },
        TENDRIL_OK
    );
    let cli_id_val: Value = serde_json::from_str(&unsafe { take_cstr(cli_id_json_p) }).unwrap();
    let cli_dev_id = cli_id_val["device_id"].as_str().unwrap().to_owned();

    // Mint relay ticket using FFI (also check invalid role rejection).
    let rhost_c = CString::new("localhost").unwrap();
    let bad_role_c = CString::new("bogus").unwrap();
    let star_c = CString::new("*").unwrap();
    let mut bad_tkt_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_relay_ticket(
                host_ep,
                rhost_c.as_ptr(),
                bad_role_c.as_ptr(),
                star_c.as_ptr(),
                300,
                &raw mut bad_tkt_p,
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(bad_tkt_p.is_null());

    let role_any_c = CString::new("any").unwrap();
    let host_rpub_c = CString::new(host_relay_pub_b64).unwrap();
    let mut ticket_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_relay_ticket(
                host_ep,
                rhost_c.as_ptr(),
                role_any_c.as_ptr(),
                host_rpub_c.as_ptr(),
                300,
                &raw mut ticket_p,
            )
        },
        TENDRIL_OK
    );
    let ticket_json_str = unsafe { take_cstr(ticket_p) };
    let ticket_val: Value = serde_json::from_str(&ticket_json_str).unwrap();

    // Test NULL role + NULL target_pub defaulting to "any" + "*".
    let mut default_ticket_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_relay_ticket(
                host_ep,
                rhost_c.as_ptr(),
                ptr::null(),
                ptr::null(),
                300,
                &raw mut default_ticket_p,
            )
        },
        TENDRIL_OK
    );
    let default_ticket_val: Value =
        serde_json::from_str(&unsafe { take_cstr(default_ticket_p) }).unwrap();
    assert_eq!(default_ticket_val["role"], "any");
    assert_eq!(default_ticket_val["target_pub"], "*");

    // Mint dial-only and register-only tickets for negative admission tests.
    let role_dial_c = CString::new("dial").unwrap();
    let mut dial_only_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_relay_ticket(
                host_ep,
                rhost_c.as_ptr(),
                role_dial_c.as_ptr(),
                ptr::null(),
                300,
                &raw mut dial_only_p,
            )
        },
        TENDRIL_OK
    );
    let dial_only_val: Value = serde_json::from_str(&unsafe { take_cstr(dial_only_p) }).unwrap();

    let role_reg_c = CString::new("register").unwrap();
    let mut reg_only_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_relay_ticket(
                host_ep,
                rhost_c.as_ptr(),
                role_reg_c.as_ptr(),
                ptr::null(),
                300,
                &raw mut reg_only_p,
            )
        },
        TENDRIL_OK
    );
    let reg_only_val: Value = serde_json::from_str(&unsafe { take_cstr(reg_only_p) }).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay_handle = rt.block_on(async {
        EmbeddedRelay::start(RelayConfig {
            host: "localhost".to_owned(),
            auth_secret: Some(Zeroizing::new(b"ffi-gated-secret".to_vec())),
            trusted_issuers: vec![host_relay_pub],
            auth_scope: RelayAuthScope::All,
            ..RelayConfig::default()
        })
        .await
        .expect("bind gated relay")
    });
    let ws_v1_url = relay_handle.ws_url();
    let ws_v1_c = CString::new(ws_v1_url).unwrap();

    // Negative 1: unauthenticated serve_relay must fail when RelayAuthScope::All is enabled.
    let mut bad_ep_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay(
                host_ep,
                ws_v1_c.as_ptr(),
                rhost_c.as_ptr(),
                &raw mut bad_ep_p,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(bad_ep_p.is_null());

    // Negative 2: wrong HMAC secret must fail.
    let wrong_hmac_c = CString::new("{\"relay_auth_secret\":\"wrong-hmac-secret\"}").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(host_ep, wrong_hmac_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay(
                host_ep,
                ws_v1_c.as_ptr(),
                rhost_c.as_ptr(),
                &raw mut bad_ep_p,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(bad_ep_p.is_null());

    // Negative 3: dial-only ticket cannot register.
    let dial_only_cfg_c =
        CString::new(serde_json::json!({ "relay_ticket": dial_only_val }).to_string()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(host_ep, dial_only_cfg_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay(
                host_ep,
                ws_v1_c.as_ptr(),
                rhost_c.as_ptr(),
                &raw mut bad_ep_p,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(bad_ep_p.is_null());

    // Configure host with valid HMAC secret and register host listener.
    let host_cfg_c = CString::new("{\"relay_auth_secret\":\"ffi-gated-secret\"}").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(host_ep, host_cfg_c.as_ptr()) },
        TENDRIL_OK
    );
    let cli_cfg_c =
        CString::new(serde_json::json!({ "relay_ticket": ticket_val }).to_string()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(cli_ep, cli_cfg_c.as_ptr()) },
        TENDRIL_OK
    );

    let mut relay_ep_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay(
                host_ep,
                ws_v1_c.as_ptr(),
                rhost_c.as_ptr(),
                &raw mut relay_ep_p,
            )
        },
        TENDRIL_OK,
        "serve_relay failed: {}",
        read_last_err()
    );
    let relay_ep = unsafe { take_cstr(relay_ep_p) };
    let relay_ep_c = CString::new(relay_ep).unwrap();

    let kind_c = CString::new("remote").unwrap();
    let mut code_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, kind_c.as_ptr(), &raw mut code_p) },
        TENDRIL_OK
    );
    let code_c = CString::new(unsafe { take_cstr(code_p) }).unwrap();

    // Negative 4: register-only ticket cannot dial gated relay on pair_initiate.
    let reg_only_cfg_c =
        CString::new(serde_json::json!({ "relay_ticket": reg_only_val }).to_string()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(cli_ep, reg_only_cfg_c.as_ptr()) },
        TENDRIL_OK
    );
    let name_c = CString::new("ffi-cli").unwrap();
    let dev_kind_c = CString::new("desktop").unwrap();
    let mut rejected_pair_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_initiate(
                cli_ep,
                relay_ep_c.as_ptr(),
                rhost_c.as_ptr(),
                code_c.as_ptr(),
                name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                &raw mut rejected_pair_p,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(rejected_pair_p.is_null());

    // Reconfigure client with valid "any" ticket and complete pairing + session.
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(cli_ep, cli_cfg_c.as_ptr()) },
        TENDRIL_OK
    );

    let hep_usize = host_ep.addr();
    let acc_pair_thr = thread::spawn(move || {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "pair_accept failed");
        unsafe { take_cstr(out) };
    });

    let mut pair_out_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_initiate(
                cli_ep,
                relay_ep_c.as_ptr(),
                rhost_c.as_ptr(),
                code_c.as_ptr(),
                name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                &raw mut pair_out_p,
            )
        },
        TENDRIL_OK,
        "pair_initiate over gated v1 relay failed: {}",
        read_last_err()
    );
    let pair_out_val: Value = serde_json::from_str(&unsafe { take_cstr(pair_out_p) }).unwrap();
    let sas_c = CString::new(pair_out_val["sas"].as_str().unwrap()).unwrap();
    acc_pair_thr.join().unwrap();

    let cli_dev_c = CString::new(cli_dev_id).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(cli_ep, hname_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, cli_dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    let caps_c = CString::new("[\"fs.read\"]").unwrap();
    let mut grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli_dev_c.as_ptr(),
                caps_c.as_ptr(),
                300,
                &raw mut grant_p,
            )
        },
        TENDRIL_OK
    );
    let grant_c = CString::new(unsafe { take_cstr(grant_p) }).unwrap();

    let acc_sess_thr = thread::spawn(move || {
        unsafe { tendril_session_accept(hep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) }
            .addr()
    });
    let cli_sess = unsafe {
        tendril_session_connect(
            cli_ep,
            relay_ep_c.as_ptr(),
            rhost_c.as_ptr(),
            hname_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(
        !cli_sess.is_null(),
        "gated v1 connect failed: {}",
        read_last_err()
    );
    let host_sess = acc_sess_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess.is_null());

    let msg = b"hello-ffi-gated-v1";
    assert_eq!(
        unsafe { tendril_session_send_data(cli_sess, msg.as_ptr(), msg.len()) },
        TENDRIL_OK
    );
    let mut ev_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 2_000, &raw mut ev_p) },
        TENDRIL_OK
    );
    let ev: Value = serde_json::from_str(&unsafe { take_cstr(ev_p) }).unwrap();
    assert_eq!(ev["event"], "data");
    assert_eq!(ev["data_b64"], b64url_encode(msg));

    unsafe {
        tendril_session_close(cli_sess, 1000, ptr::null());
        tendril_session_free(cli_sess);
        tendril_session_free(host_sess);
        tendril_endpoint_free(cli_ep);
        tendril_endpoint_free(host_ep);
    }
    drop(relay_handle);
}

#[test]
fn ffi_wire_v2_pair_relay_v2_downgrade_guard_wake_rekey_and_revoke() {
    use tendril_core::crypto::b64url_decode_array;
    use tendril_core::relay_auth::RelayAuthScope;
    use tendril_relay::RelayConfig;
    use tendril_runtime::{EmbeddedRelay, WakeTag, verify_epoch_wake_tag_window};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    let host_dir = TempDir::new().unwrap();
    let cli_dir = TempDir::new().unwrap();
    let hd_c = CString::new(host_dir.path().to_str().unwrap()).unwrap();
    let cd_c = CString::new(cli_dir.path().to_str().unwrap()).unwrap();
    let hname_c = CString::new("ffi-v2-host").unwrap();

    let host_ep = unsafe { tendril_endpoint_new(hd_c.as_ptr(), hname_c.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(cd_c.as_ptr(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let mut host_id_json_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(host_ep, &raw mut host_id_json_p) },
        TENDRIL_OK
    );
    let host_id_val: Value = serde_json::from_str(&unsafe { take_cstr(host_id_json_p) }).unwrap();
    let host_relay_pub: [u8; 32] =
        b64url_decode_array(host_id_val["relay_pub"].as_str().unwrap()).unwrap();

    let mut cli_id_json_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(cli_ep, &raw mut cli_id_json_p) },
        TENDRIL_OK
    );
    let cli_id_val: Value = serde_json::from_str(&unsafe { take_cstr(cli_id_json_p) }).unwrap();
    let cli_dev_id = cli_id_val["device_id"].as_str().unwrap().to_owned();

    let rhost_c = CString::new("localhost").unwrap();
    let role_any_c = CString::new("any").unwrap();
    let star_c = CString::new("*").unwrap();
    let mut ticket_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_relay_ticket(
                host_ep,
                rhost_c.as_ptr(),
                role_any_c.as_ptr(),
                star_c.as_ptr(),
                300,
                &raw mut ticket_p,
            )
        },
        TENDRIL_OK
    );
    let ticket_val: Value = serde_json::from_str(&unsafe { take_cstr(ticket_p) }).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let wake_secret = [0x6Bu8; 32];
    let (relay_handle, wake_addr, wake_task) = rt.block_on(async {
        let relay_handle = EmbeddedRelay::start(RelayConfig {
            host: "localhost".to_owned(),
            auth_secret: Some(Zeroizing::new(b"ffi-v2-hmac".to_vec())),
            trusted_issuers: vec![host_relay_pub],
            auth_scope: RelayAuthScope::All,
            ..RelayConfig::default()
        })
        .await
        .expect("bind gated v2 relay");

        let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wake_addr = sink.local_addr().unwrap();
        let wake_task = tokio::spawn(async move {
            loop {
                let (mut sock, _) = sink.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                let mut header_end = None;
                loop {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        break;
                    }
                }
                let Some(header_end) = header_end else {
                    continue;
                };
                let headers = std::str::from_utf8(&buf[..header_end]).unwrap().to_owned();
                if !headers.starts_with("POST ") {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    continue;
                }
                let clen = headers
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap();
                while buf.len() < header_end + clen {
                    let n = sock.read(&mut tmp).await.unwrap();
                    assert!(n > 0);
                    buf.extend_from_slice(&tmp[..n]);
                }
                let json: Value =
                    serde_json::from_slice(&buf[header_end..header_end + clen]).unwrap();
                let tag = WakeTag::from_b64url(json["wake_tag"].as_str().unwrap()).unwrap();
                let now_s = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                assert!(verify_epoch_wake_tag_window(&wake_secret, &tag, now_s));
                sock.write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
                break;
            }
        });
        (relay_handle, wake_addr, wake_task)
    });

    let host_cfg_c = CString::new("{\"relay_auth_secret\":\"ffi-v2-hmac\"}").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(host_ep, host_cfg_c.as_ptr()) },
        TENDRIL_OK
    );
    let cli_cfg_c = CString::new(
        serde_json::json!({
            "relay_ticket": &ticket_val,
            "wake_url": format!("http://{wake_addr}/wake"),
            "wake_adapter": "webhook",
            "wake_secret_b64": b64url_encode(&wake_secret),
            "wake_pre_wake": true,
            "wake_retry_delay_ms": 50,
            "wake_max_attempts": 25
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(cli_ep, cli_cfg_c.as_ptr()) },
        TENDRIL_OK
    );

    let ws_v1_c = CString::new(relay_handle.ws_url()).unwrap();
    let ws_v2_c = CString::new(relay_handle.ws_v2_url()).unwrap();

    let mut ep1_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay(
                host_ep,
                ws_v1_c.as_ptr(),
                rhost_c.as_ptr(),
                &raw mut ep1_p,
            )
        },
        TENDRIL_OK,
        "serve_relay v1 failed: {}",
        read_last_err()
    );
    let ep1 = unsafe { take_cstr(ep1_p) };
    let ep1_c = CString::new(ep1).unwrap();

    // Before pairing any v2 peer, serve_relay_v2 with NULL peer_id must fail NOT_FOUND.
    let mut empty_v2_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay_v2(
                host_ep,
                ws_v2_c.as_ptr(),
                rhost_c.as_ptr(),
                ptr::null(),
                &raw mut empty_v2_p,
            )
        },
        TENDRIL_ERR_NOT_FOUND
    );
    assert!(empty_v2_p.is_null());

    let kind_c = CString::new("remote").unwrap();
    let mut code_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, kind_c.as_ptr(), &raw mut code_p) },
        TENDRIL_OK
    );
    let code_c = CString::new(unsafe { take_cstr(code_p) }).unwrap();

    let hep_usize = host_ep.addr();
    let acc_v2_thr = thread::spawn(move || {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_v2_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                10_000,
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "pair_v2_accept failed");
        serde_json::from_str::<Value>(&unsafe { take_cstr(out) }).unwrap()
    });

    let name_c = CString::new("ffi-v2-cli").unwrap();
    let dev_kind_c = CString::new("cli").unwrap();
    let mut pair_v2_out_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                cli_ep,
                ep1_c.as_ptr(),
                rhost_c.as_ptr(),
                code_c.as_ptr(),
                name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                ptr::null(),
                &raw mut pair_v2_out_p,
            )
        },
        TENDRIL_OK,
        "pair_v2_initiate failed: {}",
        read_last_err()
    );
    let pair_v2_val: Value = serde_json::from_str(&unsafe { take_cstr(pair_v2_out_p) }).unwrap();
    assert_eq!(pair_v2_val["host_id"], "ffi-v2-host");
    assert_eq!(pair_v2_val["wire_version"], 2);
    let host_acc_val = acc_v2_thr.join().unwrap();
    assert_eq!(host_acc_val["wire_version"], 2);

    let sas_c = CString::new(pair_v2_val["sas"].as_str().unwrap()).unwrap();
    let cli_dev_c = CString::new(cli_dev_id).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(cli_ep, hname_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, cli_dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    let caps_c = CString::new("[\"fs.read:/v2/*\"]").unwrap();
    let mut grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli_dev_c.as_ptr(),
                caps_c.as_ptr(),
                300,
                &raw mut grant_p,
            )
        },
        TENDRIL_OK
    );
    let grant_c = CString::new(unsafe { take_cstr(grant_p) }).unwrap();

    // Anti-downgrade: v1 tendril_session_connect against a v2-pinned host must fail closed.
    let downgraded = unsafe {
        tendril_session_connect(
            cli_ep,
            ep1_c.as_ptr(),
            rhost_c.as_ptr(),
            hname_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(
        downgraded.is_null(),
        "v1 session connect must not downgrade v2 peer"
    );

    // Bind /v2/relay listener for the paired peer.
    let mut ep2_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay_v2(
                host_ep,
                ws_v2_c.as_ptr(),
                rhost_c.as_ptr(),
                cli_dev_c.as_ptr(),
                &raw mut ep2_p,
            )
        },
        TENDRIL_OK,
        "serve_relay_v2 failed: {}",
        read_last_err()
    );
    let ep2 = unsafe { take_cstr(ep2_p) };
    assert!(ep2.contains("/v2/relay"), "unexpected ep2: {ep2}");
    let ep2_c = CString::new(ep2).unwrap();

    // Also test serve_relay_v2 with NULL peer_id_opt binding active v2 peers.
    let mut ep2_null_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay_v2(
                host_ep,
                ws_v2_c.as_ptr(),
                rhost_c.as_ptr(),
                ptr::null(),
                &raw mut ep2_null_p,
            )
        },
        TENDRIL_OK,
        "serve_relay_v2(NULL) failed: {}",
        read_last_err()
    );
    let ep2_null = unsafe { take_cstr(ep2_null_p) };
    assert!(ep2_null.contains("/v2/relay"));

    // Short-timeout accept negatives on v2 pairing and v2 session.
    let mut timeout_out_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_pair_v2_accept(host_ep, 20, &raw mut timeout_out_p) },
        TENDRIL_WOULD_BLOCK
    );
    assert!(timeout_out_p.is_null());
    assert!(unsafe { tendril_session_accept_v2(host_ep, 20) }.is_null());

    let acc_sess_v2_thr = thread::spawn(move || {
        unsafe { tendril_session_accept_v2(hep_usize as *mut tendril_ffi::TendrilEndpoint, 10_000) }
            .addr()
    });
    let cli_sess_v2 = unsafe {
        tendril_session_connect_v2(
            cli_ep,
            ep2_c.as_ptr(),
            rhost_c.as_ptr(),
            hname_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(
        !cli_sess_v2.is_null(),
        "session_connect_v2 failed: {}",
        read_last_err()
    );
    let host_sess_v2 = acc_sess_v2_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess_v2.is_null(), "session_accept_v2 returned null");

    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), wake_task)
            .await
            .expect("wake webhook timed out")
            .unwrap();
    });

    let msg = b"hello-ffi-v2-relay";
    assert_eq!(
        unsafe { tendril_session_send_data(cli_sess_v2, msg.as_ptr(), msg.len()) },
        TENDRIL_OK
    );
    let mut ev_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess_v2, 2_000, &raw mut ev_p) },
        TENDRIL_OK
    );
    let ev: Value = serde_json::from_str(&unsafe { take_cstr(ev_p) }).unwrap();
    assert_eq!(ev["event"], "data");
    assert_eq!(ev["data_b64"], b64url_encode(msg));

    // Authorize check (allowed + denied), rekey, and roster export over v2 session.
    let mut allowed = 0u8;
    let mut v2_peer_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_peer_id(cli_sess_v2, &raw mut v2_peer_p) },
        TENDRIL_OK,
        "v2 cli peer_id failed: {}",
        read_last_err()
    );
    assert_eq!(unsafe { take_cstr(v2_peer_p) }, "ffi-v2-host");
    assert_eq!(
        unsafe { tendril_session_peer_id(host_sess_v2, &raw mut v2_peer_p) },
        TENDRIL_OK,
        "v2 host peer_id failed: {}",
        read_last_err()
    );
    assert_eq!(unsafe { take_cstr(v2_peer_p) }, cli_dev_c.to_str().unwrap());
    let ok_cap_c = CString::new("fs.read:/v2/note").unwrap();
    assert_eq!(
        unsafe { tendril_session_authorize(host_sess_v2, ok_cap_c.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 1);

    let denied_cap_c = CString::new("fs.write:/v2/note").unwrap();
    assert_eq!(
        unsafe { tendril_session_authorize(host_sess_v2, denied_cap_c.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 0);

    assert_eq!(unsafe { tendril_session_rekey(cli_sess_v2) }, TENDRIL_OK);
    let mut sess_roster_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_export_roster_json(cli_sess_v2, &raw mut sess_roster_p) },
        TENDRIL_OK
    );
    let sess_roster_val: Value =
        serde_json::from_str(&unsafe { take_cstr(sess_roster_p) }).unwrap();
    assert_eq!(sess_roster_val["entries"]["ffi-v2-host"]["state"], "active");
    assert_eq!(
        sess_roster_val["entries"]["ffi-v2-host"]["min_wire_version"],
        2
    );

    assert_eq!(
        unsafe { tendril_session_close(cli_sess_v2, 1000, ptr::null()) },
        TENDRIL_OK
    );

    // Reconfigure client without wake sink (since single-shot wake sink finished) and test revoke fail-closed.
    let cli_cfg_nowake_c =
        CString::new(serde_json::json!({ "relay_ticket": &ticket_val }).to_string()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(cli_ep, cli_cfg_nowake_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_revoke_peer(host_ep, cli_dev_c.as_ptr()) },
        TENDRIL_OK
    );
    let acc_revoked_thr = thread::spawn(move || {
        unsafe { tendril_session_accept_v2(hep_usize as *mut tendril_ffi::TendrilEndpoint, 2_000) }
            .addr()
    });
    let rev_sess = unsafe {
        tendril_session_connect_v2(
            cli_ep,
            ep2_c.as_ptr(),
            rhost_c.as_ptr(),
            hname_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    let rev_host_sess = acc_revoked_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(rev_sess.is_null() && rev_host_sess.is_null());

    unsafe {
        tendril_session_free(cli_sess_v2);
        tendril_session_free(host_sess_v2);
        tendril_endpoint_free(cli_ep);
        tendril_endpoint_free(host_ep);
    }
    drop(relay_handle);
}

#[test]
fn ffi_v2_pinned_pair_wrong_code_and_mid_session_crl_revocation() {
    use tendril_core::roster::Roster;
    use tendril_runtime::V2SessionDriver;

    let host_dir = TempDir::new().unwrap();
    let cli_dir = TempDir::new().unwrap();
    let hd_c = CString::new(host_dir.path().to_str().unwrap()).unwrap();
    let cd_c = CString::new(cli_dir.path().to_str().unwrap()).unwrap();
    let hname_c = CString::new("ffi-pin-host").unwrap();

    let host_ep = unsafe { tendril_endpoint_new(hd_c.as_ptr(), hname_c.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(cd_c.as_ptr(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let mut host_info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(host_ep, &raw mut host_info_p) },
        TENDRIL_OK
    );
    let host_info: Value = serde_json::from_str(&unsafe { take_cstr(host_info_p) }).unwrap();

    let mut cli_info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(cli_ep, &raw mut cli_info_p) },
        TENDRIL_OK
    );
    let cli_info: Value = serde_json::from_str(&unsafe { take_cstr(cli_info_p) }).unwrap();
    let cli_dev_id = cli_info["device_id"].as_str().unwrap().to_owned();

    let bind_c = CString::new("127.0.0.1:0").unwrap();
    let mut dep_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, bind_c.as_ptr(), &raw mut dep_p) },
        TENDRIL_OK
    );
    let dep = unsafe { take_cstr(dep_p) };
    let dep_c = CString::new(dep.clone()).unwrap();

    let kind_c = CString::new("lan").unwrap();
    let mut code_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, kind_c.as_ptr(), &raw mut code_p) },
        TENDRIL_OK
    );
    let code_c = CString::new(unsafe { take_cstr(code_p) }).unwrap();

    // Negative 1: unknown field in pinned_host_json_opt must fail with TENDRIL_ERR_INVALID_ARG.
    let bad_pin_c = CString::new("{\"unknown_pin_field\":true}").unwrap();
    let name_c = CString::new("pin-cli").unwrap();
    let dev_kind_c = CString::new("cli").unwrap();
    let mut out_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                cli_ep,
                dep_c.as_ptr(),
                ptr::null(),
                code_c.as_ptr(),
                name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                bad_pin_c.as_ptr(),
                &raw mut out_p,
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(out_p.is_null());
    assert!(read_last_err().contains("invalid pinned_host_json_opt"));

    // Negative 2: wrong PAKE pairing code fails closed without adding peer.
    let hep_usize = host_ep.addr();
    let acc_wrong_thr = thread::spawn(move || {
        let mut out: *mut c_char = ptr::null_mut();
        unsafe {
            tendril_endpoint_pair_v2_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out,
            )
        }
    });
    let wrong_code_c = CString::new("0000-0000").unwrap();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                cli_ep,
                dep_c.as_ptr(),
                ptr::null(),
                wrong_code_c.as_ptr(),
                name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                ptr::null(),
                &raw mut out_p,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(out_p.is_null());
    assert_eq!(acc_wrong_thr.join().unwrap(), TENDRIL_ERR_PROTOCOL);

    // Positive: valid pinned_host_json_opt pairs immediately into Active (host_confirmed = true).
    let mut code2_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, kind_c.as_ptr(), &raw mut code2_p) },
        TENDRIL_OK
    );
    let code2_c = CString::new(unsafe { take_cstr(code2_p) }).unwrap();
    let pinned_c = CString::new(
        serde_json::json!({
            "host_id": "ffi-pin-host",
            "static_pub_b64": host_info["static_pub"],
            "signing_pin_b64": host_info["signing_pub"],
            "rotation_seq": 0,
            "min_wire_version": 2
        })
        .to_string(),
    )
    .unwrap();
    let acc_ok_thr = thread::spawn(move || {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_v2_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK);
        serde_json::from_str::<Value>(&unsafe { take_cstr(out) }).unwrap()
    });
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                cli_ep,
                dep_c.as_ptr(),
                ptr::null(),
                code2_c.as_ptr(),
                name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                pinned_c.as_ptr(),
                &raw mut out_p,
            )
        },
        TENDRIL_OK,
        "pinned pair_v2_initiate failed: {}",
        read_last_err()
    );
    let init_val: Value = serde_json::from_str(&unsafe { take_cstr(out_p) }).unwrap();
    assert_eq!(init_val["status"], "active");
    assert_eq!(init_val["host_confirmed"], true);
    let acc_val = acc_ok_thr.join().unwrap();
    let sas_c = CString::new(acc_val["sas"].as_str().unwrap()).unwrap();

    let cli_dev_c = CString::new(cli_dev_id).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, cli_dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    let caps_c = CString::new("[\"fs.read:/crl/*\"]").unwrap();
    let mut grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli_dev_c.as_ptr(),
                caps_c.as_ptr(),
                300,
                &raw mut grant_p,
            )
        },
        TENDRIL_OK
    );
    let grant_str = unsafe { take_cstr(grant_p) };
    let grant: Grant = serde_json::from_str(&grant_str).unwrap();
    let grant_c = CString::new(grant_str).unwrap();
    let crl_ts = grant.not_before.clone();
    let revoked_nonce = grant.nonce.clone();
    let expected_nonce = revoked_nonce.clone();

    // Free host_ep so we can drive a raw V2SessionDriver host pushing a live 0x03 CRL revocation frame.
    unsafe { tendril_endpoint_free(host_ep) };

    let host_store = StateStore::open_or_create(host_dir.path()).unwrap();
    let host_id = host_store.load_or_generate_identity(None).unwrap();
    let mut host_roster: Roster = host_store.load_roster().unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (v2_ep_str, accept_handle) = rt.block_on(async {
        let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let ep = listener.local_endpoint();
        let h_id = host_id.clone();
        let handle = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut drv = V2SessionDriver::accept(
                stream,
                &h_id,
                &mut host_roster,
                now,
                &Default::default(),
                None,
            )
            .await
            .unwrap();
            let crl = sign_crl(
                RevocationListUnsigned {
                    v: 1,
                    issuer: h_id.host_id().to_owned(),
                    seq: 1,
                    revoked_devices: Vec::new(),
                    revoked_nonces: vec![revoked_nonce],
                    ts: crl_ts,
                },
                h_id.signing_key(),
            )
            .unwrap();
            drv.send_revocation(&crl).await.unwrap();
            drv
        });
        (ep, handle)
    });
    let v2_ep_c = CString::new(v2_ep_str.clone()).unwrap();

    let cli_sess = unsafe {
        tendril_session_connect_v2(
            cli_ep,
            v2_ep_c.as_ptr(),
            ptr::null(),
            hname_c.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(
        !cli_sess.is_null(),
        "v2 connect failed: {}",
        read_last_err()
    );
    let drv_host = rt.block_on(accept_handle).unwrap();

    let mut ev_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(cli_sess, 2_000, &raw mut ev_p) },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(ev_p.is_null());

    // Reopen cli_ep from disk and verify the CRL persisted across restart and rejects the revoked nonce.
    unsafe {
        tendril_session_free(cli_sess);
        tendril_endpoint_free(cli_ep);
    }
    drop(drv_host);

    let cli_ep2 = unsafe { tendril_endpoint_new(cd_c.as_ptr(), ptr::null()) };
    assert!(!cli_ep2.is_null());
    let mut persisted_roster_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_roster_json(cli_ep2, &raw mut persisted_roster_p) },
        TENDRIL_OK
    );
    let persisted_roster: Value =
        serde_json::from_str(&unsafe { take_cstr(persisted_roster_p) }).unwrap();
    let crl_nonces = persisted_roster["crls"]["ffi-pin-host"]["revoked_nonces"]
        .as_array()
        .expect("persisted CRL nonces");
    assert!(crl_nonces.iter().any(|v| v == &expected_nonce));

    unsafe { tendril_endpoint_free(cli_ep2) };
}

struct MockMlDsaCtx {
    inner: SigningKeypair,
    sign_calls: AtomicUsize,
    drop_calls: AtomicUsize,
    fail_sign: bool,
}

unsafe extern "C" fn mock_mldsa_sign(
    ctx: *mut c_void,
    msg: *const u8,
    msg_len: usize,
    mldsa_ctx: *const u8,
    mldsa_ctx_len: usize,
    out_sig: *mut u8,
    out_sig_len: usize,
) -> i32 {
    if ctx.is_null() || out_sig.is_null() || out_sig_len != TENDRIL_MLDSA65_SIG_LEN {
        return TENDRIL_ERR_INVALID_ARG;
    }
    let state = unsafe { &*(ctx as *const MockMlDsaCtx) };
    state.sign_calls.fetch_add(1, Ordering::SeqCst);
    if state.fail_sign {
        return TENDRIL_ERR_PROTOCOL;
    }
    let msg_slice = if msg_len == 0 {
        &[]
    } else if msg.is_null() {
        return TENDRIL_ERR_INVALID_ARG;
    } else {
        unsafe { std::slice::from_raw_parts(msg, msg_len) }
    };
    let ctx_slice = if mldsa_ctx_len == 0 {
        &[]
    } else if mldsa_ctx.is_null() {
        return TENDRIL_ERR_INVALID_ARG;
    } else {
        unsafe { std::slice::from_raw_parts(mldsa_ctx, mldsa_ctx_len) }
    };
    if ctx_slice != HYBRID_MLDSA_CTX {
        return TENDRIL_ERR_INVALID_ARG;
    }
    let Ok(hybrid) = state.inner.sign(msg_slice) else {
        return TENDRIL_ERR_PROTOCOL;
    };
    let out = unsafe { std::slice::from_raw_parts_mut(out_sig, out_sig_len) };
    out.copy_from_slice(&hybrid[ED25519_SIG_LEN..]);
    TENDRIL_OK
}

unsafe extern "C" fn mock_mldsa_drop(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let state = unsafe { Arc::from_raw(ctx as *const MockMlDsaCtx) };
    state.drop_calls.fetch_add(1, Ordering::SeqCst);
}

fn build_c_signer(
    state: &Arc<MockMlDsaCtx>,
    pub_buf: &mut [u8; TENDRIL_MLDSA65_PUB_LEN],
) -> TendrilMlDsa65Signer {
    pub_buf.copy_from_slice(&state.inner.public_bytes()[32..]);
    TendrilMlDsa65Signer {
        ctx: Arc::into_raw(Arc::clone(state)).cast_mut().cast(),
        public_key: pub_buf.as_ptr(),
        public_key_len: pub_buf.len(),
        sign: Some(mock_mldsa_sign),
        drop_ctx: Some(mock_mldsa_drop),
    }
}

#[test]
fn sealed_external_mldsa_drop_ctx_runs_once_on_errors_and_free() {
    let tmp = TempDir::new().unwrap();
    let dir_c = CString::new(tmp.path().join("state").to_str().unwrap()).unwrap();
    let kp = SigningKeypair::from_seeds([0x31; 32], [0x41; 32]);

    let make_state = || {
        Arc::new(MockMlDsaCtx {
            inner: kp.clone(),
            sign_calls: AtomicUsize::new(0),
            drop_calls: AtomicUsize::new(0),
            fail_sign: false,
        })
    };

    let mut pub_buf = [0u8; TENDRIL_MLDSA65_PUB_LEN];

    // 1. Null state_dir: drop_ctx still runs exactly once.
    let s1 = make_state();
    let c1 = build_c_signer(&s1, &mut pub_buf);
    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c1,
        )
    };
    assert!(ep.is_null());
    assert_eq!(s1.drop_calls.load(Ordering::SeqCst), 1);

    // 2. Malformed / unknown / invalid runtime_profile options_json_opt: drop_ctx runs once.
    for bad_opts in [
        "{not json",
        r#"{"unknown":true}"#,
        r#"{"runtime_profile":"tiny"}"#,
    ] {
        let s = make_state();
        let c = build_c_signer(&s, &mut pub_buf);
        let opts_c = CString::new(bad_opts).unwrap();
        let ep = unsafe {
            tendril_endpoint_new_sealed_with_options(
                dir_c.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                opts_c.as_ptr(),
                &raw const c,
            )
        };
        assert!(ep.is_null(), "bad_opts={bad_opts}");
        assert_eq!(
            s.drop_calls.load(Ordering::SeqCst),
            1,
            "bad_opts={bad_opts}"
        );
    }

    // 3. Missing sign function pointer: drop_ctx runs once.
    let s3 = make_state();
    let mut c3 = build_c_signer(&s3, &mut pub_buf);
    c3.sign = None;
    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c3,
        )
    };
    assert!(ep.is_null());
    assert_eq!(s3.drop_calls.load(Ordering::SeqCst), 1);

    // 4. Null public_key and wrong public_key_len: drop_ctx runs once.
    let s4 = make_state();
    let mut c4 = build_c_signer(&s4, &mut pub_buf);
    c4.public_key = ptr::null();
    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c4,
        )
    };
    assert!(ep.is_null());
    assert_eq!(s4.drop_calls.load(Ordering::SeqCst), 1);

    let s5 = make_state();
    let mut c5 = build_c_signer(&s5, &mut pub_buf);
    c5.public_key_len = TENDRIL_MLDSA65_PUB_LEN - 1;
    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c5,
        )
    };
    assert!(ep.is_null());
    assert_eq!(s5.drop_calls.load(Ordering::SeqCst), 1);

    // 5. v1 software identity JSON paired with external signer fails and runs drop_ctx once.
    let v1_json = serde_json::json!({
        "version": 1,
        "static_secret_b64": b64url_encode(&[0x10; 32]),
        "signing_seed_b64": b64url_encode(&[0x20; 32]),
        "host_id": "v1-host"
    })
    .to_string();
    let v1_c = CString::new(v1_json).unwrap();
    let s6 = make_state();
    let c6 = build_c_signer(&s6, &mut pub_buf);
    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            dir_c.as_ptr(),
            v1_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c6,
        )
    };
    assert!(ep.is_null());
    assert_eq!(s6.drop_calls.load(Ordering::SeqCst), 1);

    // 6. Null ctx guard: drop_ctx must NOT be invoked when ctx == NULL (on error or free).
    static NULL_CTX_DROPS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn record_null_ctx_drop(_ctx: *mut c_void) {
        NULL_CTX_DROPS.fetch_add(1, Ordering::SeqCst);
    }
    let bad_null_opts = CString::new("{\"unknown\":1}").unwrap();
    let null_ctx_bad = TendrilMlDsa65Signer {
        ctx: ptr::null_mut(),
        public_key: pub_buf.as_ptr(),
        public_key_len: pub_buf.len(),
        sign: Some(mock_mldsa_sign),
        drop_ctx: Some(record_null_ctx_drop),
    };
    let ep_null_bad = unsafe {
        tendril_endpoint_new_sealed_with_options(
            dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            bad_null_opts.as_ptr(),
            &raw const null_ctx_bad,
        )
    };
    assert!(ep_null_bad.is_null());
    assert_eq!(NULL_CTX_DROPS.load(Ordering::SeqCst), 0);

    let null_dir_c = CString::new(tmp.path().join("null_ctx_state").to_str().unwrap()).unwrap();
    let null_ctx_ok = TendrilMlDsa65Signer {
        ctx: ptr::null_mut(),
        public_key: pub_buf.as_ptr(),
        public_key_len: pub_buf.len(),
        sign: Some(mock_mldsa_sign),
        drop_ctx: Some(record_null_ctx_drop),
    };
    let ep_null_ok = unsafe {
        tendril_endpoint_new_sealed_with_options(
            null_dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const null_ctx_ok,
        )
    };
    assert!(!ep_null_ok.is_null(), "{}", read_last_err());
    unsafe { tendril_endpoint_free(ep_null_ok) };
    assert_eq!(NULL_CTX_DROPS.load(Ordering::SeqCst), 0);

    // 7. Keystore / sealed-state failure (regular file path instead of directory): drop_ctx runs once.
    let bad_store_path = tmp.path().join("not_a_dir");
    std::fs::write(&bad_store_path, b"not-a-directory").unwrap();
    let bad_store_c = CString::new(bad_store_path.to_str().unwrap()).unwrap();
    let s7 = make_state();
    let c7 = build_c_signer(&s7, &mut pub_buf);
    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            bad_store_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c7,
        )
    };
    assert!(ep.is_null());
    assert_eq!(s7.drop_calls.load(Ordering::SeqCst), 1);

    // 8. Forged 1952-byte ML-DSA public key (all 0xFF): fails post-sign verify and drops once.
    let s8 = make_state();
    let mut forged_pub = [0xffu8; TENDRIL_MLDSA65_PUB_LEN];
    let mut c8 = build_c_signer(&s8, &mut pub_buf);
    c8.public_key = forged_pub.as_ptr();
    c8.public_key_len = forged_pub.len();
    let forged_dir_c = CString::new(tmp.path().join("forged_pub_state").to_str().unwrap()).unwrap();
    let ep_forged = unsafe {
        tendril_endpoint_new_sealed_with_options(
            forged_dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c8,
        )
    };
    assert!(!ep_forged.is_null(), "{}", read_last_err());
    let mut uri_p: *mut c_char = ptr::null_mut();
    assert_ne!(
        unsafe { tendril_endpoint_issue_pairing_uri(ep_forged, ptr::null(), &raw mut uri_p) },
        TENDRIL_OK
    );
    assert!(uri_p.is_null());
    assert_eq!(s8.drop_calls.load(Ordering::SeqCst), 0);
    unsafe { tendril_endpoint_free(ep_forged) };
    assert_eq!(s8.drop_calls.load(Ordering::SeqCst), 1);

    // Also test wrong all-zero 1952-byte key against an exported v2 identity JSON: drops once.
    forged_pub.fill(0);

    // 9. Success path (creating initialized sealed state) + reopening existing sealed state without
    // identity (sealed-state mismatch failure): drop_ctx runs once in both cases.
    let s_ok = make_state();
    let c_ok = build_c_signer(&s_ok, &mut pub_buf);
    let ok_dir_c = CString::new(tmp.path().join("ok_state").to_str().unwrap()).unwrap();
    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            ok_dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c_ok,
        )
    };
    assert!(!ep.is_null(), "{}", read_last_err());
    let mut saved_id_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_identity_json(ep, &raw mut saved_id_p) },
        TENDRIL_OK
    );
    let saved_id_c = CString::new(unsafe { take_cstr(saved_id_p) }).unwrap();
    assert_eq!(s_ok.drop_calls.load(Ordering::SeqCst), 0);
    unsafe { tendril_endpoint_free(ep) };
    assert_eq!(s_ok.drop_calls.load(Ordering::SeqCst), 1);

    // Seed sealed state once, then reopening without identity_json_opt fails and runs drop_ctx once.
    let empty_roster_c =
        CString::new(serde_json::to_string(&tendril_core::roster::Roster::new()).unwrap()).unwrap();
    let s_seed = make_state();
    let c_seed = build_c_signer(&s_seed, &mut pub_buf);
    let ep_seed = unsafe {
        tendril_endpoint_new_sealed_with_options(
            ok_dir_c.as_ptr(),
            saved_id_c.as_ptr(),
            empty_roster_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            &raw const c_seed,
        )
    };
    assert!(!ep_seed.is_null(), "{}", read_last_err());
    unsafe { tendril_endpoint_free(ep_seed) };
    assert_eq!(s_seed.drop_calls.load(Ordering::SeqCst), 1);

    let s_reopen_no_id = make_state();
    let c_reopen_no_id = build_c_signer(&s_reopen_no_id, &mut pub_buf);
    let ep_no_id = unsafe {
        tendril_endpoint_new_sealed_with_options(
            ok_dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c_reopen_no_id,
        )
    };
    assert!(ep_no_id.is_null());
    assert_eq!(s_reopen_no_id.drop_calls.load(Ordering::SeqCst), 1);

    let s_zero_key = make_state();
    let mut c_zero_key = build_c_signer(&s_zero_key, &mut pub_buf);
    c_zero_key.public_key = forged_pub.as_ptr();
    c_zero_key.public_key_len = forged_pub.len();
    let ep_zero_key = unsafe {
        tendril_endpoint_new_sealed_with_options(
            ok_dir_c.as_ptr(),
            saved_id_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c_zero_key,
        )
    };
    assert!(ep_zero_key.is_null());
    assert_eq!(s_zero_key.drop_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn sealed_external_mldsa_drop_ctx_waits_for_live_session_and_group() {
    let tmp = TempDir::new().unwrap();
    let host_dir = CString::new(tmp.path().join("host_state").to_str().unwrap()).unwrap();
    let cli_dir = CString::new(tmp.path().join("cli_state").to_str().unwrap()).unwrap();

    let kp = SigningKeypair::from_seeds([0x81; 32], [0x91; 32]);
    let host_state = Arc::new(MockMlDsaCtx {
        inner: kp,
        sign_calls: AtomicUsize::new(0),
        drop_calls: AtomicUsize::new(0),
        fail_sign: false,
    });
    let mut pub_buf = [0u8; TENDRIL_MLDSA65_PUB_LEN];
    let c_signer = build_c_signer(&host_state, &mut pub_buf);
    let host_ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            host_dir.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c_signer,
        )
    };
    assert!(!host_ep.is_null(), "{}", read_last_err());
    let mut info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(host_ep, &raw mut info_p) },
        TENDRIL_OK
    );
    let host_info: Value = serde_json::from_str(&unsafe { take_cstr(info_p) }).unwrap();
    let host_name = CString::new(host_info["host_id"].as_str().unwrap()).unwrap();

    let cli_ep = unsafe {
        tendril_endpoint_new_sealed(cli_dir.as_ptr(), ptr::null(), ptr::null(), ptr::null())
    };
    assert!(!cli_ep.is_null(), "{}", read_last_err());

    let bind_c = CString::new("127.0.0.1:0").unwrap();
    let mut ep_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, bind_c.as_ptr(), &raw mut ep_p) },
        TENDRIL_OK
    );
    let listen_ep = unsafe { take_cstr(ep_p) };

    let kind_c = CString::new("lan").unwrap();
    let mut code_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, kind_c.as_ptr(), &raw mut code_p) },
        TENDRIL_OK
    );
    let code_c = CString::new(unsafe { take_cstr(code_p) }).unwrap();

    let hep_usize = host_ep as usize;
    let acc_thr = thread::spawn(move || {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_v2_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "{}", read_last_err());
        serde_json::from_str::<Value>(&unsafe { take_cstr(out) }).unwrap()
    });
    let dep_c = CString::new(listen_ep).unwrap();
    let cli_name_c = CString::new("group-cli").unwrap();
    let dev_kind_c = CString::new("desktop").unwrap();
    let mut pair_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                cli_ep,
                dep_c.as_ptr(),
                ptr::null(),
                code_c.as_ptr(),
                cli_name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                ptr::null(),
                &raw mut pair_p,
            )
        },
        TENDRIL_OK,
        "{}",
        read_last_err()
    );
    drop(unsafe { take_cstr(pair_p) });
    let acc_val = acc_thr.join().unwrap();
    let cli_dev_c = CString::new(acc_val["device_id"].as_str().unwrap()).unwrap();
    let sas_c = CString::new(acc_val["sas"].as_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, cli_dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(cli_ep, host_name.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );

    let caps_c = CString::new("[\"fs.read\"]").unwrap();
    let mut grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli_dev_c.as_ptr(),
                caps_c.as_ptr(),
                300,
                &raw mut grant_p,
            )
        },
        TENDRIL_OK
    );
    let grant_c = CString::new(unsafe { take_cstr(grant_p) }).unwrap();

    // Create and open a group on host_ep so GroupPool also retains Arc<EndpointIdentity>.
    let grp_name_c = CString::new("custody-grp").unwrap();
    let mut manifest_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_group_create(
                host_ep,
                grp_name_c.as_ptr(),
                2,
                ptr::null(),
                &raw mut manifest_p,
            )
        },
        TENDRIL_OK,
        "{}",
        read_last_err()
    );
    let manifest: Value = serde_json::from_str(&unsafe { take_cstr(manifest_p) }).unwrap();
    let group_id_c = CString::new(manifest["group_id"].as_str().unwrap()).unwrap();
    let mut host_grp: *mut TendrilGroup = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_open(host_ep, group_id_c.as_ptr(), ptr::null(), &raw mut host_grp) },
        TENDRIL_OK,
        "{}",
        read_last_err()
    );
    assert!(!host_grp.is_null());

    // Open a live session before freeing host_ep.
    let sess_acc = thread::spawn(move || unsafe {
        tendril_session_accept_v2(hep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) as usize
    });
    let cli_sess = unsafe {
        tendril_session_connect_v2(
            cli_ep,
            dep_c.as_ptr(),
            ptr::null(),
            host_name.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(!cli_sess.is_null(), "{}", read_last_err());
    let host_sess = sess_acc.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess.is_null());
    assert_eq!(host_state.drop_calls.load(Ordering::SeqCst), 0);

    // Freeing host_ep while host_sess and host_grp remain live must NOT drop_ctx yet.
    unsafe { tendril_endpoint_free(host_ep) };
    assert_eq!(host_state.drop_calls.load(Ordering::SeqCst), 0);

    // Live session continues exchanging data independently of freed endpoint.
    let msg = b"still-alive-after-ep-free";
    assert_eq!(
        unsafe { tendril_session_send_data(cli_sess, msg.as_ptr(), msg.len()) },
        TENDRIL_OK
    );
    let mut ev_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 2_000, &raw mut ev_p) },
        TENDRIL_OK
    );
    let ev: Value = serde_json::from_str(&unsafe { take_cstr(ev_p) }).unwrap();
    assert_eq!(ev["event"], "data");
    assert_eq!(
        b64url_decode(ev["data_b64"].as_str().unwrap()).unwrap(),
        msg
    );

    // Closing/freeing sessions while host_grp is open still leaves GroupPool holding identity Arc.
    unsafe {
        tendril_session_free(cli_sess);
        tendril_session_free(host_sess);
        tendril_endpoint_free(cli_ep);
    }
    assert_eq!(host_state.drop_calls.load(Ordering::SeqCst), 0);

    // Closing and freeing the last group handle drops the final Arc and invokes drop_ctx once.
    assert_eq!(unsafe { tendril_group_close(host_grp) }, TENDRIL_OK);
    unsafe { tendril_group_free(host_grp) };
    assert_eq!(host_state.drop_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn sealed_external_mldsa_round_trip_and_signing() {
    let tmp = TempDir::new().unwrap();
    let host_dir = CString::new(tmp.path().join("host_state").to_str().unwrap()).unwrap();
    let cli_dir = CString::new(tmp.path().join("cli_state").to_str().unwrap()).unwrap();
    let host_name = CString::new("enclave-host").unwrap();

    let kp = SigningKeypair::from_seeds([0x51; 32], [0x61; 32]);
    let state1 = Arc::new(MockMlDsaCtx {
        inner: kp.clone(),
        sign_calls: AtomicUsize::new(0),
        drop_calls: AtomicUsize::new(0),
        fail_sign: false,
    });
    let mut pub_buf = [0u8; TENDRIL_MLDSA65_PUB_LEN];
    let c_signer1 = build_c_signer(&state1, &mut pub_buf);
    let opts_default =
        CString::new(r#"{"runtime_profile":"default","client_only":false}"#).unwrap();

    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            host_dir.as_ptr(),
            ptr::null(),
            ptr::null(),
            host_name.as_ptr(),
            opts_default.as_ptr(),
            &raw const c_signer1,
        )
    };
    assert!(!ep.is_null(), "{}", read_last_err());

    let mut id_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_identity_json(ep, &raw mut id_p) },
        TENDRIL_OK
    );
    let id_json = unsafe { take_cstr(id_p) };
    let id_val: Value = serde_json::from_str(&id_json).unwrap();
    assert_eq!(id_val["version"], 2);
    assert_eq!(id_val["pq_signing_custody"], "external_mldsa65");
    assert!(id_val.get("pq_signing_seed_b64").is_none());

    let mut info_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(ep, &raw mut info_p) },
        TENDRIL_OK
    );
    let host_info: Value = serde_json::from_str(&unsafe { take_cstr(info_p) }).unwrap();
    let host_dev_id = host_info["device_id"].as_str().unwrap().to_owned();

    // Serve direct and issue pairing URI (signs route set via external ML-DSA-65 signer).
    let bind_c = CString::new("127.0.0.1:0").unwrap();
    let mut ep_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(ep, bind_c.as_ptr(), &raw mut ep_p) },
        TENDRIL_OK
    );
    drop(unsafe { take_cstr(ep_p) });

    let mut uri_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_pairing_uri(ep, ptr::null(), &raw mut uri_p) },
        TENDRIL_OK
    );
    drop(unsafe { take_cstr(uri_p) });
    assert!(state1.sign_calls.load(Ordering::SeqCst) >= 1);

    unsafe { tendril_endpoint_free(ep) };
    assert_eq!(state1.drop_calls.load(Ordering::SeqCst), 1);

    // Reopen without signer must fail closed.
    let id_c = CString::new(id_json.clone()).unwrap();
    let missing_signer_ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            host_dir.as_ptr(),
            id_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    assert!(missing_signer_ep.is_null());

    // Reopen with mismatched external public key must fail closed and drop ctx once.
    let wrong_kp = SigningKeypair::from_seeds([0x51; 32], [0x77; 32]);
    let wrong_state = Arc::new(MockMlDsaCtx {
        inner: wrong_kp,
        sign_calls: AtomicUsize::new(0),
        drop_calls: AtomicUsize::new(0),
        fail_sign: false,
    });
    let c_wrong = build_c_signer(&wrong_state, &mut pub_buf);
    let wrong_ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            host_dir.as_ptr(),
            id_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c_wrong,
        )
    };
    assert!(wrong_ep.is_null());
    assert_eq!(wrong_state.drop_calls.load(Ordering::SeqCst), 1);

    // Reopen with matching external signer: grant mint, v2 pair + session connect all succeed.
    let state2 = Arc::new(MockMlDsaCtx {
        inner: kp,
        sign_calls: AtomicUsize::new(0),
        drop_calls: AtomicUsize::new(0),
        fail_sign: false,
    });
    let c_signer2 = build_c_signer(&state2, &mut pub_buf);
    let host_ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            host_dir.as_ptr(),
            id_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw const c_signer2,
        )
    };
    assert!(!host_ep.is_null(), "{}", read_last_err());

    let mut info2_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_info_json(host_ep, &raw mut info2_p) },
        TENDRIL_OK
    );
    let info2: Value = serde_json::from_str(&unsafe { take_cstr(info2_p) }).unwrap();
    assert_eq!(info2["device_id"], host_dev_id);

    let mut listen_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, bind_c.as_ptr(), &raw mut listen_p) },
        TENDRIL_OK
    );
    let listen_ep = unsafe { take_cstr(listen_p) };
    let kind_c = CString::new("lan").unwrap();
    let mut code_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, kind_c.as_ptr(), &raw mut code_p) },
        TENDRIL_OK
    );
    let code_c = CString::new(unsafe { take_cstr(code_p) }).unwrap();

    // Client runs with extension profile + client_only: true.
    let cli_opts = CString::new(r#"{"runtime_profile":"extension","client_only":true}"#).unwrap();
    let cli_ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            cli_dir.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            cli_opts.as_ptr(),
            ptr::null(),
        )
    };
    assert!(!cli_ep.is_null(), "{}", read_last_err());

    let cli_dev_id: String = {
        let mut ci_p: *mut c_char = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_info_json(cli_ep, &raw mut ci_p) },
            TENDRIL_OK
        );
        let ci: Value = serde_json::from_str(&unsafe { take_cstr(ci_p) }).unwrap();
        ci["device_id"].as_str().unwrap().to_owned()
    };

    let hep_usize = host_ep as usize;
    let acc_thr = thread::spawn(move || {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_v2_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "{}", read_last_err());
        serde_json::from_str::<Value>(&unsafe { take_cstr(out) }).unwrap()
    });
    let dep_c = CString::new(listen_ep.clone()).unwrap();
    let cli_name_c = CString::new("ext-client").unwrap();
    let dev_kind_c = CString::new("phone").unwrap();
    let mut pair_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                cli_ep,
                dep_c.as_ptr(),
                ptr::null(),
                code_c.as_ptr(),
                cli_name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                ptr::null(),
                &raw mut pair_p,
            )
        },
        TENDRIL_OK,
        "{}",
        read_last_err()
    );
    drop(unsafe { take_cstr(pair_p) });
    let acc_val = acc_thr.join().unwrap();

    let cli_dev_c = CString::new(cli_dev_id.clone()).unwrap();
    let sas_c = CString::new(acc_val["sas"].as_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, cli_dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(cli_ep, host_name.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );

    let sign_before_grant = state2.sign_calls.load(Ordering::SeqCst);
    let caps_c = CString::new("[\"fs.read\"]").unwrap();
    let mut grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli_dev_c.as_ptr(),
                caps_c.as_ptr(),
                300,
                &raw mut grant_p,
            )
        },
        TENDRIL_OK
    );
    let grant_str = unsafe { take_cstr(grant_p) };
    assert!(state2.sign_calls.load(Ordering::SeqCst) > sign_before_grant);

    let issuer_keys_c = CString::new(
        serde_json::json!({
            "enclave-host": info2["signing_pub"],
        })
        .to_string(),
    )
    .unwrap();
    let grant_c = CString::new(grant_str).unwrap();
    let cap_c = CString::new("fs.read").unwrap();
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut allowed = 0u8;
    assert_eq!(
        unsafe {
            tendril_verify_grant_json(
                grant_c.as_ptr(),
                issuer_keys_c.as_ptr(),
                cli_dev_c.as_ptr(),
                host_name.as_ptr(),
                cap_c.as_ptr(),
                now_unix,
                ptr::null(),
                &raw mut allowed,
            )
        },
        TENDRIL_OK,
        "{}",
        read_last_err()
    );
    assert_eq!(allowed, 1);

    // Connect v2 session from extension client to external-custody host.
    let sess_acc_thr = thread::spawn(move || unsafe {
        tendril_session_accept_v2(hep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) as usize
    });
    let cli_sess = unsafe {
        tendril_session_connect_v2(
            cli_ep,
            dep_c.as_ptr(),
            ptr::null(),
            host_name.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(!cli_sess.is_null(), "{}", read_last_err());
    let host_sess = sess_acc_thr.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess.is_null());

    let payload = b"hello-enclave";
    assert_eq!(
        unsafe { tendril_session_send_data(cli_sess, payload.as_ptr(), payload.len()) },
        TENDRIL_OK
    );
    let mut ev_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 2_000, &raw mut ev_p) },
        TENDRIL_OK
    );
    let ev: Value = serde_json::from_str(&unsafe { take_cstr(ev_p) }).unwrap();
    assert_eq!(ev["event"], "data");
    assert_eq!(
        b64url_decode(ev["data_b64"].as_str().unwrap()).unwrap(),
        payload
    );

    unsafe {
        tendril_session_free(cli_sess);
        tendril_session_free(host_sess);
        tendril_endpoint_free(cli_ep);
        tendril_endpoint_free(host_ep);
    }
    assert_eq!(state2.drop_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn extension_client_only_rejects_listeners_and_allows_outbound() {
    let tmp = TempDir::new().unwrap();
    let dir_c = CString::new(tmp.path().join("ext_state").to_str().unwrap()).unwrap();
    let opts_c = CString::new(r#"{"runtime_profile":"extension","client_only":true}"#).unwrap();

    let ep = unsafe {
        tendril_endpoint_new_sealed_with_options(
            dir_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            opts_c.as_ptr(),
            ptr::null(),
        )
    };
    assert!(!ep.is_null(), "{}", read_last_err());

    let mut out: *mut c_char = ptr::null_mut();
    let addr_c = CString::new("127.0.0.1:0").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(ep, addr_c.as_ptr(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("client_only"));

    let relay_c = CString::new("wss://relay.example/v1/relay").unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_serve_relay(ep, relay_c.as_ptr(), ptr::null(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("client_only"));

    assert_eq!(
        unsafe {
            tendril_endpoint_serve_relay_v2(
                ep,
                relay_c.as_ptr(),
                ptr::null(),
                ptr::null(),
                &raw mut out,
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("client_only"));

    assert_eq!(
        unsafe { tendril_endpoint_serve_p2p(ep, ptr::null(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("client_only"));

    assert_eq!(
        unsafe { tendril_endpoint_issue_pairing_uri(ep, ptr::null(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("client_only"));

    assert_eq!(
        unsafe { tendril_endpoint_refresh_routes(ep, ptr::null(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(read_last_err().contains("client_only"));

    let grp_c = CString::new("grp-ext").unwrap();
    let mut grp: *mut TendrilGroup = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_open(ep, grp_c.as_ptr(), addr_c.as_ptr(), &raw mut grp) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(grp.is_null());
    assert!(read_last_err().contains("client_only"));

    // NULL listen_addr does not fail client_only (reaches missing group check).
    assert_eq!(
        unsafe { tendril_group_open(ep, grp_c.as_ptr(), ptr::null(), &raw mut grp) },
        TENDRIL_ERR_NOT_FOUND
    );

    // Outbound v2 pairing and session connect succeed under extension + client_only.
    let host_name = CString::new("ext-outbound-host").unwrap();
    let host_ep =
        unsafe { tendril_endpoint_new_from_state(ptr::null(), ptr::null(), host_name.as_ptr()) };
    assert!(!host_ep.is_null(), "{}", read_last_err());
    let mut listen_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, addr_c.as_ptr(), &raw mut listen_p) },
        TENDRIL_OK
    );
    let listen_ep = unsafe { take_cstr(listen_p) };
    let kind_c = CString::new("lan").unwrap();
    let mut code_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, kind_c.as_ptr(), &raw mut code_p) },
        TENDRIL_OK
    );
    let code_c = CString::new(unsafe { take_cstr(code_p) }).unwrap();

    let hep_usize = host_ep as usize;
    let pair_acc = thread::spawn(move || {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_v2_accept(
                hep_usize as *mut tendril_ffi::TendrilEndpoint,
                5_000,
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "{}", read_last_err());
        serde_json::from_str::<Value>(&unsafe { take_cstr(out) }).unwrap()
    });
    let dep_c = CString::new(listen_ep).unwrap();
    let cli_name_c = CString::new("ext-cli").unwrap();
    let dev_kind_c = CString::new("ios").unwrap();
    let mut pair_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_v2_initiate(
                ep,
                dep_c.as_ptr(),
                ptr::null(),
                code_c.as_ptr(),
                cli_name_c.as_ptr(),
                dev_kind_c.as_ptr(),
                ptr::null(),
                &raw mut pair_p,
            )
        },
        TENDRIL_OK,
        "{}",
        read_last_err()
    );
    drop(unsafe { take_cstr(pair_p) });
    let acc_val = pair_acc.join().unwrap();
    let cli_dev_c = CString::new(acc_val["device_id"].as_str().unwrap()).unwrap();
    let sas_c = CString::new(acc_val["sas"].as_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, cli_dev_c.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(ep, host_name.as_ptr(), sas_c.as_ptr()) },
        TENDRIL_OK
    );
    let caps_c = CString::new("[\"fs.read\"]").unwrap();
    let mut grant_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                cli_dev_c.as_ptr(),
                caps_c.as_ptr(),
                300,
                &raw mut grant_p,
            )
        },
        TENDRIL_OK
    );
    let grant_c = CString::new(unsafe { take_cstr(grant_p) }).unwrap();

    let sess_acc = thread::spawn(move || unsafe {
        tendril_session_accept_v2(hep_usize as *mut tendril_ffi::TendrilEndpoint, 5_000) as usize
    });
    let cli_sess = unsafe {
        tendril_session_connect_v2(
            ep,
            dep_c.as_ptr(),
            ptr::null(),
            host_name.as_ptr(),
            grant_c.as_ptr(),
        )
    };
    assert!(!cli_sess.is_null(), "{}", read_last_err());
    let host_sess = sess_acc.join().unwrap() as *mut tendril_ffi::TendrilSession;
    assert!(!host_sess.is_null());
    let msg = b"ext-outbound-ok";
    assert_eq!(
        unsafe { tendril_session_send_data(cli_sess, msg.as_ptr(), msg.len()) },
        TENDRIL_OK
    );
    let mut ev_p: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_poll_event(host_sess, 2_000, &raw mut ev_p) },
        TENDRIL_OK
    );
    let ev: Value = serde_json::from_str(&unsafe { take_cstr(ev_p) }).unwrap();
    assert_eq!(ev["event"], "data");
    assert_eq!(
        b64url_decode(ev["data_b64"].as_str().unwrap()).unwrap(),
        msg
    );

    unsafe {
        tendril_session_free(cli_sess);
        tendril_session_free(host_sess);
        tendril_endpoint_free(host_ep);
        tendril_endpoint_free(ep);
    }
}

#[test]
fn verify_wake_tag_c_abi_checks_window_and_args() {
    let secret = [0x42u8; 32];
    let other_secret = [0x99u8; 32];
    let now = 1_764_115_200u64;
    let tag_b64 = derive_epoch_wake_tag(&secret, now).to_b64url();
    let tag_c = CString::new(tag_b64).unwrap();

    for delta in [-3600i64, 0, 3600] {
        let check_now = (now as i64 + delta) as u64;
        let mut matched = 0u8;
        assert_eq!(
            unsafe {
                tendril_verify_wake_tag(
                    secret.as_ptr(),
                    tag_c.as_ptr(),
                    check_now,
                    &raw mut matched,
                )
            },
            TENDRIL_OK
        );
        assert_eq!(matched, 1, "delta={delta}");
    }

    for delta in [-7200i64, 7200] {
        let check_now = (now as i64 + delta) as u64;
        let mut matched = 1u8;
        assert_eq!(
            unsafe {
                tendril_verify_wake_tag(
                    secret.as_ptr(),
                    tag_c.as_ptr(),
                    check_now,
                    &raw mut matched,
                )
            },
            TENDRIL_OK
        );
        assert_eq!(matched, 0, "delta={delta}");
    }

    let mut wrong_matched = 1u8;
    assert_eq!(
        unsafe {
            tendril_verify_wake_tag(
                other_secret.as_ptr(),
                tag_c.as_ptr(),
                now,
                &raw mut wrong_matched,
            )
        },
        TENDRIL_OK
    );
    assert_eq!(wrong_matched, 0);

    let bad_tag_c = CString::new("not-valid-b64").unwrap();
    let mut matched = 0u8;
    assert_eq!(
        unsafe {
            tendril_verify_wake_tag(secret.as_ptr(), bad_tag_c.as_ptr(), now, &raw mut matched)
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_verify_wake_tag(ptr::null(), tag_c.as_ptr(), now, &raw mut matched) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_verify_wake_tag(secret.as_ptr(), ptr::null(), now, &raw mut matched) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_verify_wake_tag(secret.as_ptr(), tag_c.as_ptr(), now, ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );
}
