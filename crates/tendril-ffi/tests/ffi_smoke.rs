use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::thread;

use serde_json::Value;
use tendril_core::crypto::b64url_encode;
use tendril_ffi::{
    TENDRIL_ERR_INVALID_ARG, TENDRIL_ERR_PROTOCOL, TENDRIL_OK, TENDRIL_WOULD_BLOCK,
    tendril_compute_code_mac, tendril_device_id, tendril_endpoint_confirm_peer,
    tendril_endpoint_free, tendril_endpoint_info_json, tendril_endpoint_issue_code,
    tendril_endpoint_mint_grant, tendril_endpoint_new, tendril_endpoint_pair_accept,
    tendril_endpoint_pair_initiate, tendril_endpoint_revoke_peer, tendril_endpoint_serve_direct,
    tendril_fingerprint_device, tendril_fingerprint_host, tendril_last_error, tendril_pairing_sas,
    tendril_session_accept, tendril_session_authorize, tendril_session_close,
    tendril_session_connect, tendril_session_free, tendril_session_poll_event,
    tendril_session_rekey, tendril_session_send_data, tendril_string_free,
    tendril_verify_grant_json, tendril_verify_rotation_chain_json,
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
    let psig = b64url_encode(&hex32(rot["pinned_signing_pub_hex"].as_str().unwrap()));
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
        b64url_encode(&hex32(gv["root_signing_pub_hex"].as_str().unwrap())),
    );
    keys.insert(
        gv["delegate_id"].as_str().unwrap(),
        b64url_encode(&hex32(gv["delegate_signing_pub_hex"].as_str().unwrap())),
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
}

#[test]
fn ffi_full_lifecycle_and_session_outlives_endpoint() {
    let host_name = CString::new("ffi-host").unwrap();
    let host_ep = unsafe { tendril_endpoint_new(ptr::null(), host_name.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(ptr::null(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

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

    let grant_c = CString::new(grant_str).unwrap();
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
