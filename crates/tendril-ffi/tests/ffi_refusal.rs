//! Authenticated refusal through the C ABI: typed last-error code, `TENDRIL_ERR_REFUSED`,
//! the closed-event `refusal` field and the refusal endpoint calls.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;
use tendril_ffi::{
    TENDRIL_ERR_INVALID_ARG, TENDRIL_ERR_NOT_FOUND, TENDRIL_ERR_REFUSED, TENDRIL_OK,
    TENDRIL_WOULD_BLOCK, TendrilEndpoint, TendrilSession, tendril_endpoint_clear_refusal_notice,
    tendril_endpoint_confirm_peer, tendril_endpoint_export_roster_json, tendril_endpoint_free,
    tendril_endpoint_info_json, tendril_endpoint_issue_pairing_uri, tendril_endpoint_mint_grant,
    tendril_endpoint_new, tendril_endpoint_pair_accept, tendril_endpoint_pair_uri,
    tendril_endpoint_pair_v2_accept, tendril_endpoint_pair_v2_uri, tendril_endpoint_revoke_peer,
    tendril_endpoint_revoke_peer_with_options, tendril_endpoint_serve_direct,
    tendril_endpoint_set_refusal_policy_json, tendril_last_error, tendril_last_error_code,
    tendril_session_accept, tendril_session_accept_v2, tendril_session_close,
    tendril_session_connect, tendril_session_connect_v2, tendril_session_free,
    tendril_session_poll_event, tendril_session_rekey, tendril_session_send_data,
    tendril_string_free,
};

fn cs(s: &str) -> CString {
    CString::new(s).expect("no interior NUL")
}

unsafe fn take_cstr(p: *mut c_char) -> String {
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) }
        .to_str()
        .expect("utf8")
        .to_owned();
    unsafe { tendril_string_free(p) };
    s
}

fn read_buf(f: impl FnOnce(*mut c_char, usize) -> i32) -> String {
    let mut buf = vec![0u8; 4096];
    f(buf.as_mut_ptr().cast::<c_char>(), buf.len());
    unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) }
        .to_string_lossy()
        .into_owned()
}

fn last_err() -> String {
    read_buf(|b, n| unsafe { tendril_last_error(b, n) })
}

fn last_code() -> String {
    read_buf(|b, n| unsafe { tendril_last_error_code(b, n) })
}

struct Ep(*mut TendrilEndpoint);

impl Ep {
    fn open(dir: &std::path::Path, host_id: Option<&str>) -> Ep {
        let d = cs(dir.to_str().unwrap());
        let h = host_id.map(cs);
        let ep = unsafe {
            tendril_endpoint_new(d.as_ptr(), h.as_ref().map_or(ptr::null(), |c| c.as_ptr()))
        };
        assert!(!ep.is_null(), "{}", last_err());
        Ep(ep)
    }

    fn info(&self) -> Value {
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_info_json(self.0, &raw mut out) },
            TENDRIL_OK
        );
        serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()
    }

    fn roster(&self) -> Value {
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_export_roster_json(self.0, &raw mut out) },
            TENDRIL_OK,
            "{}",
            last_err()
        );
        serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()
    }

    fn revoke(&self, peer: &str) -> i32 {
        let p = cs(peer);
        unsafe { tendril_endpoint_revoke_peer(self.0, p.as_ptr()) }
    }

    fn revoke_with(&self, peer: &str, options: Option<&str>) -> i32 {
        let p = cs(peer);
        let o = options.map(cs);
        unsafe {
            tendril_endpoint_revoke_peer_with_options(
                self.0,
                p.as_ptr(),
                o.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            )
        }
    }

    fn set_policy(&self, policy: &str) -> i32 {
        let p = cs(policy);
        unsafe { tendril_endpoint_set_refusal_policy_json(self.0, p.as_ptr()) }
    }

    fn clear_notice(&self, peer: &str) -> i32 {
        let p = cs(peer);
        unsafe { tendril_endpoint_clear_refusal_notice(self.0, p.as_ptr()) }
    }
}

impl Drop for Ep {
    fn drop(&mut self) {
        unsafe { tendril_endpoint_free(self.0) };
    }
}

struct Sess(*mut TendrilSession);

impl Sess {
    fn poll(&self, timeout_ms: u64) -> (i32, Option<Value>) {
        let mut out = ptr::null_mut();
        let rc = unsafe { tendril_session_poll_event(self.0, timeout_ms, &raw mut out) };
        if rc == TENDRIL_OK {
            (
                rc,
                Some(serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()),
            )
        } else {
            (rc, None)
        }
    }

    /// Polls until a `closed` event arrives.
    fn expect_closed(&self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let (rc, ev) = self.poll(500);
            if let Some(ev) = ev {
                if ev["event"] == "closed" {
                    return ev;
                }
                continue;
            }
            assert_eq!(rc, TENDRIL_WOULD_BLOCK, "poll failed: {}", last_err());
        }
        panic!("no closed event");
    }

    fn send(&self, data: &[u8]) -> i32 {
        unsafe { tendril_session_send_data(self.0, data.as_ptr(), data.len()) }
    }
}

impl Drop for Sess {
    fn drop(&mut self) {
        unsafe { tendril_session_free(self.0) };
    }
}

struct World {
    tmp: TempDir,
    host: Ep,
    client: Ep,
    host_id: String,
    client_id: String,
    grant: String,
    wire: u8,
}

fn world(wire: u8) -> World {
    let tmp = TempDir::new().unwrap();
    let host = Ep::open(&tmp.path().join("host"), Some("refusal-host"));
    let client = Ep::open(&tmp.path().join("client"), None);
    let listen = cs("127.0.0.1:0");
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_direct(host.0, listen.as_ptr(), &raw mut out) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    unsafe { tendril_string_free(out) };
    let mut issued = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_pairing_uri(host.0, ptr::null(), &raw mut issued) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let uri = serde_json::from_str::<Value>(&unsafe { take_cstr(issued) }).unwrap()["uri"]
        .as_str()
        .unwrap()
        .to_owned();
    let host_addr = host.0 as usize;
    let acceptor = thread::spawn(move || {
        let mut out = ptr::null_mut();
        let ep = host_addr as *mut TendrilEndpoint;
        let rc = if wire == 2 {
            unsafe { tendril_endpoint_pair_v2_accept(ep, 15_000, &raw mut out) }
        } else {
            unsafe { tendril_endpoint_pair_accept(ep, 15_000, &raw mut out) }
        };
        assert_eq!(rc, TENDRIL_OK, "pair accept failed: {}", last_err());
        serde_json::from_str::<Value>(&unsafe { take_cstr(out) }).unwrap()
    });
    let u = cs(&uri);
    let mut out = ptr::null_mut();
    let rc = unsafe {
        let f = if wire == 2 {
            tendril_endpoint_pair_v2_uri
        } else {
            tendril_endpoint_pair_uri
        };
        f(
            client.0,
            u.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &raw mut out,
        )
    };
    assert_eq!(rc, TENDRIL_OK, "pair failed: {}", last_err());
    unsafe { tendril_string_free(out) };
    let host_res = acceptor.join().unwrap();
    let dev = cs(host_res["device_id"].as_str().unwrap());
    let sas = cs(host_res["sas"].as_str().unwrap());
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host.0, dev.as_ptr(), sas.as_ptr()) },
        TENDRIL_OK
    );
    let host_id = host.info()["host_id"].as_str().unwrap().to_owned();
    let client_id = client.info()["device_id"].as_str().unwrap().to_owned();
    let grant = mint_grant(&host, &client_id);
    World {
        tmp,
        host,
        client,
        host_id,
        client_id,
        grant,
        wire,
    }
}

fn mint_grant(host: &Ep, peer: &str) -> String {
    let p = cs(peer);
    let caps = cs("[\"fs.read\"]");
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_grant(host.0, p.as_ptr(), caps.as_ptr(), 3600, &raw mut out)
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    unsafe { take_cstr(out) }
}

impl World {
    /// Connects the client while the host accepts for a short window. Returns the client and
    /// host sessions, or the failing message and typed code read right after the call.
    fn connect(&self) -> Result<(Sess, Option<Sess>), (String, String)> {
        let host_addr = self.host.0 as usize;
        let wire = self.wire;
        let acceptor = thread::spawn(move || {
            let ep = host_addr as *mut TendrilEndpoint;
            let s = if wire == 2 {
                unsafe { tendril_session_accept_v2(ep, 3_000) }
            } else {
                unsafe { tendril_session_accept(ep, 3_000) }
            };
            s as usize
        });
        let target = cs(&self.host_id);
        let grant = cs(&self.grant);
        let s = unsafe {
            if wire == 2 {
                tendril_session_connect_v2(
                    self.client.0,
                    ptr::null(),
                    ptr::null(),
                    target.as_ptr(),
                    grant.as_ptr(),
                )
            } else {
                tendril_session_connect(
                    self.client.0,
                    ptr::null(),
                    ptr::null(),
                    target.as_ptr(),
                    grant.as_ptr(),
                )
            }
        };
        let (err, code) = (last_err(), last_code());
        let host_sess = acceptor.join().unwrap() as *mut TendrilSession;
        let host_sess = (!host_sess.is_null()).then(|| Sess(host_sess));
        if s.is_null() {
            Err((err, code))
        } else {
            Ok((Sess(s), host_sess))
        }
    }
}

#[test]
fn refused_v2_connect_sets_the_typed_code_and_is_stable() {
    let w = world(2);
    assert_eq!(w.host.revoke(&w.client_id), TENDRIL_OK, "{}", last_err());
    let Err((err, code)) = w.connect() else {
        panic!("a revoked peer must not connect");
    };
    assert_eq!(code, "refused_revoked", "error: {err}");

    // The typed code is readable before and after the message, and any number of times.
    let before = last_code();
    let msg = last_err();
    let after = last_code();
    assert_eq!(before, "refused_revoked");
    assert_eq!(after, "refused_revoked");
    assert_eq!(
        last_err(),
        msg,
        "reading the code never mutates the message"
    );
}

#[test]
fn last_error_code_is_empty_for_untyped_errors_and_reports_needed_length() {
    let w = world(2);
    // An untyped failure (null target) leaves an empty code.
    let s = unsafe {
        tendril_session_connect_v2(
            w.client.0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    assert!(s.is_null());
    assert_eq!(last_code(), "");

    // A typed one reports the bytes needed, NUL included, without a buffer.
    assert_eq!(w.host.revoke(&w.client_id), TENDRIL_OK);
    assert!(w.connect().is_err());
    let needed = unsafe { tendril_last_error_code(ptr::null_mut(), 0) };
    assert_eq!(needed, i32::try_from("refused_revoked".len() + 1).unwrap());
    let mut small = [0xffu8; 8];
    let n = unsafe { tendril_last_error_code(small.as_mut_ptr().cast::<c_char>(), small.len()) };
    assert_eq!(n, needed);
    assert_eq!(small[7], 0, "truncated output stays NUL-terminated");
    assert_eq!(last_code(), "refused_revoked");
}

#[test]
fn v1_refusal_after_connect_surfaces_in_event_send_and_rekey() {
    let w = world(1);
    assert_eq!(w.host.revoke(&w.client_id), TENDRIL_OK, "{}", last_err());
    let (sess, _host) = w
        .connect()
        .unwrap_or_else(|(err, _)| panic!("v1 connect returns before the refusal: {err}"));
    let ev = sess.expect_closed();
    assert_eq!(ev["code"], 4001);
    assert_eq!(ev["refusal"], "revoked");

    assert_eq!(sess.send(b"x"), TENDRIL_ERR_REFUSED, "{}", last_err());
    assert_eq!(last_code(), "refused_revoked");
    assert_eq!(
        unsafe { tendril_session_rekey(sess.0) },
        TENDRIL_ERR_REFUSED
    );
    assert_eq!(last_code(), "refused_revoked");
}

#[test]
fn closed_event_refusal_is_null_for_responders_and_plain_closes() {
    let w = world(2);
    let (client, host) = w
        .connect()
        .unwrap_or_else(|(err, _)| panic!("healthy connect failed: {err}"));
    let host = host.expect("host session");
    // A responder that receives a refusal-looking code keeps the raw code and reports no refusal.
    assert_eq!(
        unsafe { tendril_session_close(client.0, 4001, ptr::null()) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let ev = host.expect_closed();
    assert_eq!(ev["code"], 4001);
    assert!(
        ev.get("refusal").is_some_and(Value::is_null),
        "responder closed event carries refusal: null, got {ev}"
    );

    // An initiator that receives a non-refusal close reports null too.
    let w = world(2);
    let (client, host) = w.connect().unwrap_or_else(|(err, _)| panic!("{err}"));
    let host = host.expect("host session");
    assert_eq!(
        unsafe { tendril_session_close(host.0, 1000, ptr::null()) },
        TENDRIL_OK
    );
    let ev = client.expect_closed();
    assert_eq!(ev["code"], 1000);
    assert!(ev.get("refusal").is_some_and(Value::is_null), "{ev}");
}

#[test]
fn silent_revoke_options_leave_no_notice() {
    let w = world(2);
    let rc = w
        .host
        .revoke_with(&w.client_id, Some(r#"{"notify": false}"#));
    assert_eq!(rc, TENDRIL_OK, "{}", last_err());
    let Err((_, code)) = w.connect() else {
        panic!("a revoked peer must not connect");
    };
    assert!(
        !code.starts_with("refused"),
        "a silent revoke must not refuse: {code}"
    );
}

#[test]
fn null_options_follow_the_policy_and_persist() {
    let w = world(2);
    assert_eq!(
        w.host
            .set_policy(r#"{"pending": false, "revoked_notice_ttl_secs": 0}"#),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let policy = w.host.roster()["refusal_policy"].clone();
    assert_eq!(policy["revoked_notice_ttl_secs"], 0);
    assert_eq!(policy["pending"], false);
    assert_eq!(w.host.revoke_with(&w.client_id, None), TENDRIL_OK);
    let Err((_, code)) = w.connect() else {
        panic!("a revoked peer must not connect");
    };
    assert!(
        !code.starts_with("refused"),
        "ttl 0 records no notice: {code}"
    );

    // The policy survives a reopen of the state directory.
    let dir = w.tmp.path().join("host");
    let World { host, tmp, .. } = w;
    drop(host);
    let reopened = Ep::open(&dir, Some("refusal-host"));
    assert_eq!(reopened.roster()["refusal_policy"], policy);
    drop(tmp);
}

#[test]
fn explicit_notify_records_a_notice() {
    let w = world(2);
    assert_eq!(
        w.host
            .revoke_with(&w.client_id, Some(r#"{"notify": true}"#)),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let Err((_, code)) = w.connect() else {
        panic!("a revoked peer must not connect");
    };
    assert_eq!(code, "refused_revoked");
}

#[test]
fn clearing_a_notice_keeps_the_peer_revoked() {
    let w = world(2);
    assert_eq!(w.host.revoke(&w.client_id), TENDRIL_OK);
    assert_eq!(
        w.host.clear_notice(&w.client_id),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let Err((_, code)) = w.connect() else {
        panic!("the peer stays revoked");
    };
    assert!(!code.starts_with("refused"), "notice dropped: {code}");
    assert_eq!(w.host.clear_notice("no-such-peer"), TENDRIL_ERR_NOT_FOUND);
}

#[test]
fn endpoint_calls_reject_bad_arguments() {
    let w = world(2);
    assert_eq!(w.host.set_policy("not json"), TENDRIL_ERR_INVALID_ARG);
    assert_eq!(
        w.host.set_policy(r#"{"bogus": 1}"#),
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        w.host.revoke_with(&w.client_id, Some("not json")),
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        w.host.revoke_with("no-such-peer", None),
        TENDRIL_ERR_NOT_FOUND
    );
    assert_eq!(
        unsafe { tendril_endpoint_set_refusal_policy_json(ptr::null_mut(), ptr::null()) },
        TENDRIL_ERR_INVALID_ARG
    );
}
