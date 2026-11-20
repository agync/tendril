use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tempfile::TempDir;
use tendril_core::MAX_FRAME_LEN;
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::grants::{Grant, RevocationListUnsigned, sign_crl};
use tendril_core::identity::sign_rotation;
use tendril_core::roster::PeerState;
use tendril_core::wire::{
    HostHello, Intent, NOISE_PATTERN, Preamble, ResumableFrameReader, encode_frame,
};
#[cfg(feature = "p2p-iroh")]
use tendril_ffi::tendril_endpoint_serve_p2p;
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
use tendril_runtime::{
    DirectListener, PathListener, PathStream, PrefixedPathStream, SessionDriver, StateStore,
    peek_exact, recv_tendril_frame,
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
    let seq1_signing = host_id.signing_key().signing_key();
    let rec_2a = sign_rotation(
        2,
        &seq1_signing,
        key_a_sig.public_bytes(),
        key_a_stat.public_bytes(),
        now + 10,
    )
    .unwrap();
    let rec_2b = sign_rotation(
        2,
        &seq1_signing,
        key_b_sig.public_bytes(),
        key_b_stat.public_bytes(),
        now + 11,
    )
    .unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
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
            let mut hs = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
                .local_private_key(key_a_stat.secret_bytes())
                .unwrap()
                .prologue(&Preamble::v1(Intent::Session).encode())
                .unwrap()
                .build_responder()
                .unwrap();
            let mut pt = vec![0u8; MAX_FRAME_LEN];
            hs.read_message(&msg1, &mut pt).unwrap();
            let hello = serde_json::to_vec(&HostHello {
                host_id: "rot-host".to_owned(),
                proto_version: 1,
                rotation: vec![rec_2a, rec_2b],
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
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
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
                &h_id.signing_key().signing_key(),
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
