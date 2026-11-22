//! Regression tests for the FFI roster lock order (`store_lock` then `roster`), the v2 revocation
//! sync, the Wire v1 downgrade pre-check, and roster serialization hygiene.

use std::ffi::{CStr, CString, c_char};
use std::net::TcpListener;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::roster::{PeerState, Roster};
use tendril_ffi::{
    TENDRIL_OK, TendrilEndpoint, TendrilSession, tendril_endpoint_confirm_peer,
    tendril_endpoint_export_roster_json, tendril_endpoint_free, tendril_endpoint_issue_code,
    tendril_endpoint_mint_grant, tendril_endpoint_new, tendril_endpoint_pair_accept,
    tendril_endpoint_pair_initiate, tendril_endpoint_revoke_peer, tendril_endpoint_serve_direct,
    tendril_last_error, tendril_session_accept, tendril_session_authorize, tendril_session_close,
    tendril_session_connect, tendril_session_connect_v2, tendril_session_export_roster_json,
    tendril_session_free, tendril_session_poll_event, tendril_session_rekey,
    tendril_session_send_data, tendril_session_shutdown, tendril_string_free,
};
use tendril_runtime::StateStore;

const DEAD_ENDPOINT: &str = "127.0.0.1:1";

unsafe fn take_cstr(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null());
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
    unsafe { tendril_string_free(ptr) };
    s
}

fn last_err() -> String {
    let mut buf = vec![0i8; 512];
    let needed = unsafe { tendril_last_error(buf.as_mut_ptr().cast::<c_char>(), buf.len()) };
    assert!(needed >= 1);
    unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) }
        .to_str()
        .unwrap()
        .to_owned()
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn seed_roster(dir: &TempDir, ids: &[String], min_wire_version: u8) {
    let store = StateStore::open_or_create(dir.path()).unwrap();
    let mut roster = Roster::new();
    for id in ids {
        roster
            .insert_pinned_host(
                id.clone(),
                id.clone(),
                *StaticKeypair::generate().unwrap().public_bytes(),
                Some(SigningKeypair::generate().unwrap().public_key().clone()),
                0,
                Vec::new(),
            )
            .unwrap();
        if min_wire_version > 1 {
            roster
                .set_peer_min_wire_version(id, min_wire_version)
                .unwrap();
        }
    }
    store.save_roster(&roster).unwrap();
}

fn disk_roster(dir: &TempDir) -> Roster {
    StateStore::open_or_create(dir.path())
        .unwrap()
        .load_roster()
        .unwrap()
}

fn endpoint_at(dir: &TempDir) -> *mut TendrilEndpoint {
    let d = cstr(dir.path().to_str().unwrap());
    let ep = unsafe { tendril_endpoint_new(d.as_ptr(), ptr::null()) };
    assert!(!ep.is_null(), "endpoint_new failed: {}", last_err());
    ep
}

fn endpoint_roster_json(ep: *mut TendrilEndpoint) -> Value {
    let mut out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_roster_json(ep, &raw mut out) },
        TENDRIL_OK
    );
    serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()
}

fn session_roster_json(sess: *mut TendrilSession) -> Value {
    let mut out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_session_export_roster_json(sess, &raw mut out) },
        TENDRIL_OK
    );
    serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()
}

fn peer_state(roster: &Value, id: &str) -> String {
    roster["entries"][id]["state"]
        .as_str()
        .unwrap_or("missing")
        .to_owned()
}

#[test]
fn sec04_endpoint_revoke_races_sync_paths_without_resurrection() {
    const PEERS: usize = 24;
    let dir = TempDir::new().unwrap();
    let ids: Vec<String> = (0..PEERS).map(|i| format!("peer-{i:02}")).collect();
    seed_roster(&dir, &ids, 1);
    let ep = endpoint_at(&dir) as usize;

    let stop = Arc::new(AtomicBool::new(false));
    let start = Arc::new(Barrier::new(5));
    let mut workers = Vec::new();
    for worker in 0..4usize {
        let stop = Arc::clone(&stop);
        let start = Arc::clone(&start);
        let ids = ids.clone();
        workers.push(thread::spawn(move || {
            let ep = ep as *mut TendrilEndpoint;
            let dead = cstr(DEAD_ENDPOINT);
            let target = cstr("nobody");
            let caps = cstr("[\"fs.read\"]");
            start.wait();
            let mut i = 0usize;
            while !stop.load(Ordering::Acquire) {
                match worker {
                    0 => {
                        let s = unsafe {
                            tendril_session_connect_v2(
                                ep,
                                dead.as_ptr(),
                                ptr::null(),
                                target.as_ptr(),
                                ptr::null(),
                            )
                        };
                        assert!(s.is_null());
                    }
                    1 => {
                        let s = unsafe {
                            tendril_session_connect(
                                ep,
                                dead.as_ptr(),
                                ptr::null(),
                                target.as_ptr(),
                                ptr::null(),
                            )
                        };
                        assert!(s.is_null());
                    }
                    2 => {
                        let id = cstr(&ids[i % ids.len()]);
                        let mut out: *mut c_char = ptr::null_mut();
                        let rc = unsafe {
                            tendril_endpoint_mint_grant(
                                ep,
                                id.as_ptr(),
                                caps.as_ptr(),
                                60,
                                &raw mut out,
                            )
                        };
                        if rc == TENDRIL_OK {
                            drop(unsafe { take_cstr(out) });
                        }
                    }
                    _ => {
                        let id = cstr(&ids[i % ids.len()]);
                        let _ =
                            unsafe { tendril_endpoint_confirm_peer(ep, id.as_ptr(), ptr::null()) };
                    }
                }
                i += 1;
            }
        }));
    }

    start.wait();
    for id in &ids {
        let c = cstr(id);
        assert_eq!(
            unsafe { tendril_endpoint_revoke_peer(ep as *mut TendrilEndpoint, c.as_ptr()) },
            TENDRIL_OK,
            "revoke {id}: {}",
            last_err()
        );
        thread::yield_now();
    }
    stop.store(true, Ordering::Release);
    for w in workers {
        w.join().unwrap();
    }

    // One more sync round after all writers quiesced must still not resurrect anything.
    let dead = cstr(DEAD_ENDPOINT);
    let target = cstr("nobody");
    let s = unsafe {
        tendril_session_connect_v2(
            ep as *mut TendrilEndpoint,
            dead.as_ptr(),
            ptr::null(),
            target.as_ptr(),
            ptr::null(),
        )
    };
    assert!(s.is_null());

    let mem = endpoint_roster_json(ep as *mut TendrilEndpoint);
    let disk = disk_roster(&dir);
    for id in &ids {
        assert_eq!(peer_state(&mem, id), "revoked", "memory resurrected {id}");
        assert_eq!(
            disk.get(id).unwrap().state,
            PeerState::Revoked,
            "disk resurrected {id}"
        );
        assert!(disk.get(id).unwrap().grants.is_empty());
    }
    unsafe { tendril_endpoint_free(ep as *mut TendrilEndpoint) };
}

#[test]
fn sec03_disk_revocation_propagates_into_endpoint_roster_on_v2_connect_error() {
    let dir = TempDir::new().unwrap();
    let ids = vec!["peer-a".to_owned(), "peer-b".to_owned()];
    seed_roster(&dir, &ids, 1);
    let ep = endpoint_at(&dir);
    assert_eq!(peer_state(&endpoint_roster_json(ep), "peer-a"), "active");

    // Simulates the runtime v2 driver committing a revocation straight to disk.
    StateStore::open_or_create(dir.path())
        .unwrap()
        .update_roster(|r| {
            r.revoke_peer("peer-a")
                .map_err(|e| tendril_runtime::RuntimeError::Protocol(e.to_string()))
        })
        .unwrap();

    let dead = cstr(DEAD_ENDPOINT);
    let target = cstr("peer-a");
    let s = unsafe {
        tendril_session_connect_v2(ep, dead.as_ptr(), ptr::null(), target.as_ptr(), ptr::null())
    };
    assert!(s.is_null());

    let json = endpoint_roster_json(ep);
    assert_eq!(peer_state(&json, "peer-a"), "revoked");
    assert_eq!(peer_state(&json, "peer-b"), "active");

    // A later in-memory mutation must not write the stale pre-revocation state back.
    let b = cstr("peer-b");
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(ep, b.as_ptr(), ptr::null()) },
        TENDRIL_OK
    );
    assert_eq!(
        disk_roster(&dir).get("peer-a").unwrap().state,
        PeerState::Revoked
    );
    unsafe { tendril_endpoint_free(ep) };
}

#[test]
fn priv04_v1_connect_fails_closed_before_any_dial_when_floor_requires_v2() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = {
        let accepted = Arc::clone(&accepted);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if listener.accept().is_ok() {
                    accepted.fetch_add(1, Ordering::AcqRel);
                }
                thread::sleep(Duration::from_millis(5));
            }
        })
    };

    let dir = TempDir::new().unwrap();
    seed_roster(&dir, &["v2-only".to_owned(), "v1-ok".to_owned()], 1);
    StateStore::open_or_create(dir.path())
        .unwrap()
        .update_roster(|r| {
            r.set_peer_min_wire_version("v2-only", 2)
                .map_err(|e| tendril_runtime::RuntimeError::Protocol(e.to_string()))
        })
        .unwrap();
    let ep = endpoint_at(&dir);

    let ep_c = cstr(&addr);
    let target = cstr("v2-only");
    let s = unsafe {
        tendril_session_connect(ep, ep_c.as_ptr(), ptr::null(), target.as_ptr(), ptr::null())
    };
    assert!(s.is_null());
    assert!(
        last_err().to_ascii_lowercase().contains("downgrade"),
        "unexpected error: {}",
        last_err()
    );

    // The floor is raised on disk after the endpoint was opened: it must still be honored.
    StateStore::open_or_create(dir.path())
        .unwrap()
        .update_roster(|r| {
            r.set_peer_min_wire_version("v1-ok", 2)
                .map_err(|e| tendril_runtime::RuntimeError::Protocol(e.to_string()))
        })
        .unwrap();
    let target = cstr("v1-ok");
    let s = unsafe {
        tendril_session_connect(ep, ep_c.as_ptr(), ptr::null(), target.as_ptr(), ptr::null())
    };
    assert!(s.is_null());
    assert!(last_err().to_ascii_lowercase().contains("downgrade"));

    thread::sleep(Duration::from_millis(100));
    stop.store(true, Ordering::Release);
    watcher.join().unwrap();
    assert_eq!(
        accepted.load(Ordering::Acquire),
        0,
        "no dial may reach the listener"
    );
    unsafe { tendril_endpoint_free(ep) };
}

struct PairedSessions {
    host_dir: TempDir,
    _cli_dir: TempDir,
    host_ep: *mut TendrilEndpoint,
    cli_ep: *mut TendrilEndpoint,
    host_sess: *mut TendrilSession,
    cli_sess: *mut TendrilSession,
    cli_device_id: String,
}

fn paired_sessions() -> PairedSessions {
    let host_dir = TempDir::new().unwrap();
    let cli_dir = TempDir::new().unwrap();
    let hd = cstr(host_dir.path().to_str().unwrap());
    let cd = cstr(cli_dir.path().to_str().unwrap());
    let hn = cstr("race-host");
    let host_ep = unsafe { tendril_endpoint_new(hd.as_ptr(), hn.as_ptr()) };
    let cli_ep = unsafe { tendril_endpoint_new(cd.as_ptr(), ptr::null()) };
    assert!(!host_ep.is_null() && !cli_ep.is_null());

    let mut out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host_ep, ptr::null(), &raw mut out) },
        TENDRIL_OK
    );
    let endpoint = unsafe { take_cstr(out) };
    let mut code_out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_code(host_ep, ptr::null(), &raw mut code_out) },
        TENDRIL_OK
    );
    let code = unsafe { take_cstr(code_out) };

    let host_addr = host_ep as usize;
    let accept = thread::spawn(move || {
        let mut o: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(host_addr as *mut TendrilEndpoint, 5_000, &raw mut o)
        };
        assert_eq!(rc, TENDRIL_OK, "pair accept: {}", last_err());
        unsafe { take_cstr(o) }
    });
    let ep_c = cstr(&endpoint);
    let code_c = cstr(&code);
    let mut pair_out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_initiate(
                cli_ep,
                ep_c.as_ptr(),
                ptr::null(),
                code_c.as_ptr(),
                ptr::null(),
                ptr::null(),
                &raw mut pair_out,
            )
        },
        TENDRIL_OK,
        "pair initiate: {}",
        last_err()
    );
    let cli_pair: Value = serde_json::from_str(&unsafe { take_cstr(pair_out) }).unwrap();
    let host_pair: Value = serde_json::from_str(&accept.join().unwrap()).unwrap();
    let sas = cstr(host_pair["sas"].as_str().unwrap());
    let cli_device_id = host_pair["device_id"].as_str().unwrap().to_owned();
    let peer_c = cstr(&cli_device_id);
    assert_eq!(cli_pair["sas"], host_pair["sas"]);
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host_ep, peer_c.as_ptr(), sas.as_ptr()) },
        TENDRIL_OK
    );
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(cli_ep, hn.as_ptr(), sas.as_ptr()) },
        TENDRIL_OK
    );
    let caps = cstr("[\"fs.read\"]");
    let mut grant_out: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(
                host_ep,
                peer_c.as_ptr(),
                caps.as_ptr(),
                3600,
                &raw mut grant_out,
            )
        },
        TENDRIL_OK
    );
    let grant = cstr(&unsafe { take_cstr(grant_out) });

    let accept_sess = thread::spawn(move || {
        let s = unsafe { tendril_session_accept(host_addr as *mut TendrilEndpoint, 5_000) };
        assert!(!s.is_null(), "session accept: {}", last_err());
        s as usize
    });
    let cli_sess = unsafe {
        tendril_session_connect(
            cli_ep,
            ep_c.as_ptr(),
            ptr::null(),
            hn.as_ptr(),
            grant.as_ptr(),
        )
    };
    assert!(!cli_sess.is_null(), "session connect: {}", last_err());
    let host_sess = accept_sess.join().unwrap() as *mut TendrilSession;

    PairedSessions {
        host_dir,
        _cli_dir: cli_dir,
        host_ep,
        cli_ep,
        host_sess,
        cli_sess,
        cli_device_id,
    }
}

#[test]
fn sec04_revoke_peer_races_session_poll_event_and_authorize() {
    let p = paired_sessions();
    let cap = cstr("fs.read");
    let mut allowed = 0u8;
    assert_eq!(
        unsafe { tendril_session_authorize(p.host_sess, cap.as_ptr(), &raw mut allowed) },
        TENDRIL_OK
    );
    assert_eq!(allowed, 1, "grant must authorize before revocation");

    let stop = Arc::new(AtomicBool::new(false));
    let start = Arc::new(Barrier::new(5));
    let host_sess = p.host_sess as usize;
    let cli_sess = p.cli_sess as usize;
    let mut workers = Vec::new();
    {
        let stop = Arc::clone(&stop);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            start.wait();
            while !stop.load(Ordering::Acquire) {
                let mut out: *mut c_char = ptr::null_mut();
                let rc = unsafe {
                    tendril_session_poll_event(host_sess as *mut TendrilSession, 5, &raw mut out)
                };
                if rc == TENDRIL_OK && !out.is_null() {
                    drop(unsafe { take_cstr(out) });
                }
            }
        }));
    }
    {
        let stop = Arc::clone(&stop);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            let cap = cstr("fs.read");
            start.wait();
            while !stop.load(Ordering::Acquire) {
                let mut a = 0u8;
                let rc = unsafe {
                    tendril_session_authorize(
                        host_sess as *const TendrilSession,
                        cap.as_ptr(),
                        &raw mut a,
                    )
                };
                assert_eq!(rc, TENDRIL_OK);
            }
        }));
    }
    {
        let stop = Arc::clone(&stop);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            start.wait();
            while !stop.load(Ordering::Acquire) {
                let _ = unsafe {
                    tendril_session_send_data(cli_sess as *mut TendrilSession, b"x".as_ptr(), 1)
                };
                let _ = unsafe { tendril_session_rekey(cli_sess as *mut TendrilSession) };
                thread::sleep(Duration::from_millis(1));
            }
        }));
    }
    {
        let stop = Arc::clone(&stop);
        let start = Arc::clone(&start);
        let host_ep = p.host_ep as usize;
        workers.push(thread::spawn(move || {
            let dead = cstr(DEAD_ENDPOINT);
            let target = cstr("nobody");
            start.wait();
            while !stop.load(Ordering::Acquire) {
                let s = unsafe {
                    tendril_session_connect(
                        host_ep as *mut TendrilEndpoint,
                        dead.as_ptr(),
                        ptr::null(),
                        target.as_ptr(),
                        ptr::null(),
                    )
                };
                assert!(s.is_null());
            }
        }));
    }

    start.wait();
    thread::sleep(Duration::from_millis(30));
    let peer_c = cstr(&p.cli_device_id);
    assert_eq!(
        unsafe { tendril_endpoint_revoke_peer(p.host_ep, peer_c.as_ptr()) },
        TENDRIL_OK,
        "revoke: {}",
        last_err()
    );
    // Revocation is visible to authorize immediately, with no stale overwrite possible.
    for _ in 0..200 {
        let mut a = 1u8;
        assert_eq!(
            unsafe { tendril_session_authorize(p.host_sess, cap.as_ptr(), &raw mut a) },
            TENDRIL_OK
        );
        assert_eq!(a, 0, "authorize must deny immediately after revoke_peer");
        thread::sleep(Duration::from_millis(1));
    }
    stop.store(true, Ordering::Release);
    for w in workers {
        w.join().unwrap();
    }

    assert_eq!(
        peer_state(&session_roster_json(p.host_sess), &p.cli_device_id),
        "revoked"
    );
    assert_eq!(
        peer_state(&endpoint_roster_json(p.host_ep), &p.cli_device_id),
        "revoked"
    );
    let disk = disk_roster(&p.host_dir);
    let entry = disk.get(&p.cli_device_id).unwrap();
    assert_eq!(entry.state, PeerState::Revoked, "disk resurrected the peer");
    assert!(entry.grants.is_empty());

    unsafe {
        tendril_session_shutdown(p.host_sess);
        tendril_session_close(p.cli_sess, 1000, ptr::null());
        tendril_session_free(p.cli_sess);
        tendril_session_free(p.host_sess);
        tendril_endpoint_free(p.cli_ep);
        tendril_endpoint_free(p.host_ep);
    }
}
