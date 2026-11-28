//! Pairing URIs, stored routes and signed route announcements through the C ABI.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tendril_ffi::{
    TENDRIL_ERR_CLOSED, TENDRIL_ERR_INVALID_ARG, TENDRIL_ERR_NOT_FOUND, TENDRIL_OK,
    TENDRIL_WOULD_BLOCK, TendrilEndpoint, TendrilSession, tendril_endpoint_apply_route_uri,
    tendril_endpoint_clear_peer_routes, tendril_endpoint_close,
    tendril_endpoint_configure_transports_json, tendril_endpoint_confirm_peer,
    tendril_endpoint_export_identity_json, tendril_endpoint_free, tendril_endpoint_info_json,
    tendril_endpoint_issue_pairing_uri, tendril_endpoint_mint_grant, tendril_endpoint_new,
    tendril_endpoint_new_from_state, tendril_endpoint_new_sealed, tendril_endpoint_pair_accept,
    tendril_endpoint_pair_uri, tendril_endpoint_pair_v2_accept, tendril_endpoint_pair_v2_uri,
    tendril_endpoint_peer_routes, tendril_endpoint_refresh_routes, tendril_endpoint_serve_direct,
    tendril_endpoint_set_peer_routes, tendril_last_error, tendril_session_accept,
    tendril_session_accept_v2, tendril_session_connect, tendril_session_connect_v2,
    tendril_session_connect_with_options, tendril_session_free, tendril_session_poll_event,
    tendril_session_send_data, tendril_string_free, tendril_verify_wake_tag,
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

fn last_err() -> String {
    let mut buf = vec![0u8; 4096];
    unsafe { tendril_last_error(buf.as_mut_ptr().cast::<c_char>(), buf.len()) };
    unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) }
        .to_string_lossy()
        .into_owned()
}

/// Owned endpoint handle, freed on drop.
struct Ep(*mut TendrilEndpoint);

impl Ep {
    fn raw(&self) -> *mut TendrilEndpoint {
        self.0
    }

    fn addr(&self) -> usize {
        self.0 as usize
    }

    fn host_id(&self) -> String {
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_info_json(self.0, &raw mut out) },
            TENDRIL_OK
        );
        let info: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
        info["host_id"].as_str().unwrap().to_owned()
    }

    fn configure(&self, cfg: &Value) -> i32 {
        let c = cs(&cfg.to_string());
        unsafe { tendril_endpoint_configure_transports_json(self.0, c.as_ptr()) }
    }

    fn serve_direct(&self, addr: &str) -> String {
        let a = cs(addr);
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_serve_direct(self.0, a.as_ptr(), &raw mut out) },
            TENDRIL_OK,
            "{}",
            last_err()
        );
        unsafe { take_cstr(out) }
    }

    fn issue(&self, opts: Option<&Value>) -> Value {
        let o = opts.map(|v| cs(&v.to_string()));
        let mut out = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_issue_pairing_uri(
                self.0,
                o.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "issue failed: {}", last_err());
        serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()
    }

    fn peer_routes(&self, peer: &str) -> Value {
        let p = cs(peer);
        let mut out = ptr::null_mut();
        let rc = unsafe { tendril_endpoint_peer_routes(self.0, p.as_ptr(), &raw mut out) };
        assert_eq!(rc, TENDRIL_OK, "peer_routes failed: {}", last_err());
        serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()
    }

    fn routes_of(&self, peer: &str, source: &str) -> Vec<String> {
        self.peer_routes(peer)["routes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["source"] == source)
            .map(|r| r["hint"].as_str().unwrap().to_owned())
            .collect()
    }

    fn set_routes(&self, peer: &str, routes: &Value) -> i32 {
        let p = cs(peer);
        let r = cs(&routes.to_string());
        unsafe { tendril_endpoint_set_peer_routes(self.0, p.as_ptr(), r.as_ptr()) }
    }

    fn clear_routes(&self, peer: &str, source: Option<&str>) -> i32 {
        let p = cs(peer);
        let s = source.map(cs);
        unsafe {
            tendril_endpoint_clear_peer_routes(
                self.0,
                p.as_ptr(),
                s.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            )
        }
    }

    fn apply(&self, uri: &str, opts: Option<&Value>) -> Result<Value, (i32, String)> {
        let u = cs(uri);
        let o = opts.map(|v| cs(&v.to_string()));
        let mut out = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_apply_route_uri(
                self.0,
                u.as_ptr(),
                o.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &raw mut out,
            )
        };
        if rc == TENDRIL_OK {
            Ok(serde_json::from_str(&unsafe { take_cstr(out) }).unwrap())
        } else {
            Err((rc, last_err()))
        }
    }

    fn refresh(&self, snapshot: Option<&Value>) -> Value {
        let s = snapshot.map(|v| cs(&v.to_string()));
        let mut out = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_refresh_routes(
                self.0,
                s.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &raw mut out,
            )
        };
        assert_eq!(rc, TENDRIL_OK, "refresh failed: {}", last_err());
        serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()
    }

    fn mint_grant(&self, peer: &str) -> String {
        let p = cs(peer);
        let caps = cs("[\"fs.read\"]");
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe {
                tendril_endpoint_mint_grant(self.0, p.as_ptr(), caps.as_ptr(), 3600, &raw mut out)
            },
            TENDRIL_OK,
            "{}",
            last_err()
        );
        unsafe { take_cstr(out) }
    }
}

impl Drop for Ep {
    fn drop(&mut self) {
        unsafe { tendril_endpoint_free(self.0) };
    }
}

/// Owned session handle, freed on drop.
#[derive(Debug)]
struct Sess(*mut TendrilSession);

impl Sess {
    fn send(&self, data: &[u8]) {
        assert_eq!(
            unsafe { tendril_session_send_data(self.0, data.as_ptr(), data.len()) },
            TENDRIL_OK,
            "{}",
            last_err()
        );
    }

    fn poll(&self, timeout_ms: u64) -> Option<Value> {
        let mut out = ptr::null_mut();
        let rc = unsafe { tendril_session_poll_event(self.0, timeout_ms, &raw mut out) };
        if rc == TENDRIL_WOULD_BLOCK {
            return None;
        }
        assert_eq!(rc, TENDRIL_OK, "poll failed: {}", last_err());
        Some(serde_json::from_str(&unsafe { take_cstr(out) }).unwrap())
    }

    fn expect_data(&self, want: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(ev) = self.poll(500)
                && ev["event"] == "data"
            {
                let got =
                    tendril_core::crypto::b64url_decode(ev["data_b64"].as_str().unwrap()).unwrap();
                assert_eq!(got, want);
                return;
            }
        }
        panic!("no data event");
    }
}

impl Drop for Sess {
    fn drop(&mut self) {
        unsafe { tendril_session_free(self.0) };
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    StateDir,
    Sealed,
    StoreLess,
}

fn sealed_identity(dir: &str, host_id: Option<&str>) -> String {
    let d = cs(dir);
    let h = host_id.map(cs);
    let ep = Ep(unsafe {
        tendril_endpoint_new_sealed(
            d.as_ptr(),
            ptr::null(),
            ptr::null(),
            h.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
        )
    });
    assert!(!ep.raw().is_null(), "{}", last_err());
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_export_identity_json(ep.raw(), &raw mut out) },
        TENDRIL_OK
    );
    unsafe { take_cstr(out) }
}

fn open_sealed(dir: &str, identity: &str) -> Ep {
    let d = cs(dir);
    let i = cs(identity);
    let ep = Ep(unsafe {
        tendril_endpoint_new_sealed(d.as_ptr(), i.as_ptr(), ptr::null(), ptr::null())
    });
    assert!(!ep.raw().is_null(), "{}", last_err());
    ep
}

fn new_ep(kind: Kind, tmp: &TempDir, name: &str, host_id: Option<&str>) -> Ep {
    let dir = tmp.path().join(name);
    let dir_s = dir.to_str().unwrap().to_owned();
    let h = host_id.map(cs);
    let hp = h.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    let ep = match kind {
        Kind::StateDir => {
            let d = cs(&dir_s);
            Ep(unsafe { tendril_endpoint_new(d.as_ptr(), hp) })
        }
        Kind::Sealed => {
            let identity = sealed_identity(&dir_s, host_id);
            return open_sealed(&dir_s, &identity);
        }
        Kind::StoreLess => {
            Ep(unsafe { tendril_endpoint_new_from_state(ptr::null(), ptr::null(), hp) })
        }
    };
    assert!(!ep.raw().is_null(), "{}", last_err());
    ep
}

/// Pairs `client` with `host` through `uri` (Wire v1 or v2), confirms on the host, and returns
/// the client's pair result.
fn pair(host: &Ep, client: &Ep, uri: &str, wire: u8, options: Option<&Value>) -> Value {
    let host_addr = host.addr();
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
    let u = cs(uri);
    let o = options.map(|v| cs(&v.to_string()));
    let mut out = ptr::null_mut();
    let rc = unsafe {
        let f = if wire == 2 {
            tendril_endpoint_pair_v2_uri
        } else {
            tendril_endpoint_pair_uri
        };
        f(
            client.raw(),
            u.as_ptr(),
            ptr::null(),
            ptr::null(),
            o.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            &raw mut out,
        )
    };
    assert_eq!(rc, TENDRIL_OK, "pair_uri failed: {}", last_err());
    let res: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
    let host_res = acceptor.join().unwrap();
    assert_eq!(res["sas"], host_res["sas"]);
    let dev = cs(host_res["device_id"].as_str().unwrap());
    let sas = cs(host_res["sas"].as_str().unwrap());
    assert_eq!(
        unsafe { tendril_endpoint_confirm_peer(host.raw(), dev.as_ptr(), sas.as_ptr()) },
        TENDRIL_OK
    );
    res
}

/// Connects `client` to `host` with `connect` on the calling thread while the host accepts.
fn connect_pair(
    host: &Ep,
    wire: u8,
    connect: impl FnOnce() -> *mut TendrilSession,
) -> Result<(Sess, Sess), String> {
    let host_addr = host.addr();
    let acceptor = thread::spawn(move || {
        let ep = host_addr as *mut TendrilEndpoint;
        let s = if wire == 2 {
            unsafe { tendril_session_accept_v2(ep, 8_000) }
        } else {
            unsafe { tendril_session_accept(ep, 8_000) }
        };
        s as usize
    });
    let client = connect();
    let err = client.is_null().then(last_err);
    let host_sess = acceptor.join().unwrap() as *mut TendrilSession;
    if let Some(err) = err {
        if !host_sess.is_null() {
            drop(Sess(host_sess));
        }
        return Err(err);
    }
    assert!(!host_sess.is_null(), "host accept failed");
    Ok((Sess(client), Sess(host_sess)))
}

fn connect_stored(client: &Ep, host: &Ep, wire: u8, grant: &str) -> Result<(Sess, Sess), String> {
    let target = cs(&host.host_id());
    let g = cs(grant);
    connect_pair(host, wire, || unsafe {
        if wire == 2 {
            tendril_session_connect_v2(
                client.raw(),
                ptr::null(),
                ptr::null(),
                target.as_ptr(),
                g.as_ptr(),
            )
        } else {
            tendril_session_connect(
                client.raw(),
                ptr::null(),
                ptr::null(),
                target.as_ptr(),
                g.as_ptr(),
            )
        }
    })
}

fn connect_opts(client: &Ep, host: &Ep, opts: &Value) -> Result<(Sess, Sess), String> {
    let target = cs(&host.host_id());
    let o = cs(&opts.to_string());
    let wire = u8::try_from(opts["wire"].as_u64().unwrap_or(1)).unwrap();
    connect_pair(host, wire, || unsafe {
        tendril_session_connect_with_options(client.raw(), target.as_ptr(), o.as_ptr())
    })
}

fn direct(endpoint: &str) -> String {
    format!("direct:{endpoint}")
}

fn port_of(endpoint: &str) -> u16 {
    endpoint.rsplit(':').next().unwrap().parse().unwrap()
}

/// Host with one loopback listener, paired with a fresh client over a signed URI.
struct Paired {
    _tmp: TempDir,
    host: Ep,
    client: Ep,
    host_id: String,
    listen: String,
    grant: String,
}

fn paired(kind: Kind, wire: u8) -> Paired {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(kind, &tmp, "host", Some("routes-host"));
    let client = new_ep(kind, &tmp, "client", None);
    let listen = host.serve_direct("127.0.0.1:0");
    let issued = host.issue(None);
    let uri = issued["uri"].as_str().unwrap().to_owned();
    assert!(uri.contains("&rs="), "issued URI is host-signed by default");
    let res = pair(&host, &client, &uri, wire, None);
    let host_id = host.host_id();
    assert_eq!(res["host_id"], host_id.as_str());
    let device_id = {
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_info_json(client.raw(), &raw mut out) },
            TENDRIL_OK
        );
        let info: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
        info["device_id"].as_str().unwrap().to_owned()
    };
    let grant = host.mint_grant(&device_id);
    Paired {
        _tmp: tmp,
        host,
        client,
        host_id,
        listen,
        grant,
    }
}

#[test]
fn uri_pairing_persists_signed_routes_and_connects_without_endpoint() {
    for kind in [Kind::StateDir, Kind::Sealed, Kind::StoreLess] {
        let tmp = TempDir::new().unwrap();
        let host = new_ep(kind, &tmp, "host", Some("routes-host"));
        let client = new_ep(kind, &tmp, "client", None);
        let listen = host.serve_direct("127.0.0.1:0");
        let issued = host.issue(None);
        let uri = issued["uri"].as_str().unwrap().to_owned();
        assert!(uri.contains("&rq=") && uri.contains("&rs="), "{kind:?}");
        assert_eq!(issued["code_kind"], "lan");
        assert!(issued["route_seq"].as_u64().unwrap() >= 1);
        assert_eq!(issued["uri_len"].as_u64().unwrap(), uri.len() as u64);
        assert!(issued["qr_version_m"].as_u64().unwrap() >= 1);
        assert!(issued["dropped"].is_array());

        let res = pair(&host, &client, &uri, 1, None);
        assert_eq!(res["status"], "active", "{kind:?}");
        assert_eq!(res["host_confirmed"], true);
        assert_eq!(res["committed"], true);
        assert_eq!(res["route_check"], "verified");
        assert!(
            res.as_object().unwrap().contains_key("routes_reason"),
            "routes_reason is always present: {res}"
        );
        assert_eq!(res["routes_reason"], Value::Null);
        assert_eq!(res["provider"], "direct");
        assert_eq!(res["endpoint"], direct(&listen));
        assert_eq!(
            res["routes_persisted"],
            json!([{"hint": direct(&listen), "source": "signed"}])
        );
        assert!(res["skipped"].as_array().unwrap().is_empty());

        let host_id = host.host_id();
        let view = client.peer_routes(&host_id);
        assert_eq!(view["routes"], res["routes_persisted"]);
        assert_eq!(view["route_meta"]["seq"], issued["route_seq"]);
        assert_eq!(view["route_meta"]["origin"], "uri");
        assert_eq!(view["last_route_set"], Value::Null);

        let device_id = res["device_id"].as_str().unwrap().to_owned();
        let grant = host.mint_grant(&device_id);
        let (c, h) = connect_stored(&client, &host, 1, &grant)
            .unwrap_or_else(|e| panic!("{kind:?} endpoint-free connect: {e}"));
        c.send(b"over stored route");
        h.expect_data(b"over stored route");
    }
}

#[test]
fn v2_uri_pairing_and_endpoint_free_v2_connect() {
    let p = paired(Kind::StateDir, 2);
    assert_eq!(
        p.client.routes_of(&p.host_id, "signed"),
        [direct(&p.listen)]
    );
    let (c, h) = connect_stored(&p.client, &p.host, 2, &p.grant).expect("v2 connect");
    c.send(b"v2 stored");
    h.expect_data(b"v2 stored");
}

#[test]
fn issue_and_pair_options() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", Some("opt-host"));
    let listen = host.serve_direct("127.0.0.1:0");

    let remote = host.issue(Some(&json!({"kind": "remote", "host_name": "Studio"})));
    assert_eq!(remote["code_kind"], "remote");
    assert!(remote["uri"].as_str().unwrap().contains("Studio"));

    for bad in [json!({"kind": "bluetooth"}), json!({"extra": 1})] {
        let o = cs(&bad.to_string());
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_issue_pairing_uri(host.raw(), o.as_ptr(), &raw mut out) },
            TENDRIL_ERR_INVALID_ARG
        );
        assert!(out.is_null());
    }

    // Unsigned issuance: nothing persists under all_signed unless save_route opts in.
    let unsigned = host.issue(Some(&json!({"sign_routes": false})));
    let uri = unsigned["uri"].as_str().unwrap().to_owned();
    assert!(!uri.contains("&rs="));
    let client = new_ep(Kind::StateDir, &tmp, "client", None);
    let res = pair(&host, &client, &uri, 1, None);
    assert_eq!(res["route_check"], "unsigned");
    assert_eq!(res["routes_persisted"], json!([]));
    assert_eq!(res["routes_reason"], "unsigned_uri");

    let unsigned = host.issue(Some(&json!({"sign_routes": false})));
    let uri = unsigned["uri"].as_str().unwrap().to_owned();
    let client2 = new_ep(Kind::StateDir, &tmp, "client2", None);
    let res = pair(&host, &client2, &uri, 1, Some(&json!({"save_route": true})));
    assert_eq!(
        res["routes_persisted"],
        json!([{"hint": direct(&listen), "source": "committed"}])
    );

    // An explicit endpoint option is dialed alone and stored as an operator route.
    let signed = host.issue(None);
    let uri = signed["uri"].as_str().unwrap().to_owned();
    let client3 = new_ep(Kind::StateDir, &tmp, "client3", None);
    let res = pair(
        &host,
        &client3,
        &uri,
        1,
        Some(&json!({"endpoint": listen, "route_policy": "none"})),
    );
    assert_eq!(
        res["routes_persisted"],
        json!([{"hint": direct(&listen), "source": "operator"}])
    );

    // Bad URI and bad options fail before any dial.
    let u = cs("tendril://nope");
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_uri(
                client.raw(),
                u.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                &raw mut out,
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
    let u = cs(&uri);
    let o = cs(r#"{"route_policy": "sometimes"}"#);
    assert_eq!(
        unsafe {
            tendril_endpoint_pair_uri(
                client.raw(),
                u.as_ptr(),
                ptr::null(),
                ptr::null(),
                o.as_ptr(),
                &raw mut out,
            )
        },
        TENDRIL_ERR_INVALID_ARG
    );
}

#[test]
fn transport_config_route_keys() {
    let tmp = TempDir::new().unwrap();
    let ep = new_ep(Kind::StoreLess, &tmp, "ep", None);
    assert_eq!(
        ep.configure(&json!({
            "relay_auth_origins": ["wss://relay.example", "ws://127.0.0.1:8080/"],
            "advertised_endpoints": ["192.168.1.5:7000"],
            "advertise": "explicit",
            "route_policy": "committed_only",
            "sign_routes": false,
        })),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    for bad in [
        json!({"relay_auth_origins": ["relay.example"]}),
        json!({"relay_auth_origins": ["wss://relay.example/path"]}),
        json!({"relay_auth_origins": ["wss://user@relay.example"]}),
        json!({"route_policy": "sometimes"}),
        json!({"advertise": "loud"}),
    ] {
        assert_eq!(ep.configure(&bad), TENDRIL_ERR_INVALID_ARG, "{bad}");
    }
}

#[test]
fn explicit_advertising_and_unsigned_default() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", None);
    assert_eq!(
        host.configure(&json!({
            "advertise": "explicit",
            "advertised_endpoints": ["192.168.1.5:7000"],
            "sign_routes": false,
        })),
        TENDRIL_OK
    );
    host.serve_direct("0.0.0.0:0");
    let issued = host.issue(None);
    let uri = issued["uri"].as_str().unwrap();
    assert!(
        !uri.contains("&rs="),
        "sign_routes: false is the endpoint default"
    );
    assert!(uri.contains("192.168.1.5"));
    let dropped = issued["dropped"].as_array().unwrap();
    assert!(
        dropped.iter().any(|d| d["reason"] == "unspecified_bind"),
        "explicit mode keeps the unspecified bind and drops it: {dropped:?}"
    );
}

#[test]
fn peer_route_setter_replaces_operator_routes_atomically() {
    let p = paired(Kind::StateDir, 1);
    let (client, host_id) = (&p.client, p.host_id.as_str());
    let signed = vec![direct(&p.listen)];

    assert_eq!(
        client.set_routes(host_id, &json!(["127.0.0.1:1", "127.0.0.1:2"])),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    assert_eq!(
        client.set_routes(host_id, &json!(["127.0.0.1:3"])),
        TENDRIL_OK
    );
    assert_eq!(
        client.routes_of(host_id, "operator"),
        ["direct:127.0.0.1:3"]
    );
    assert_eq!(client.routes_of(host_id, "signed"), signed);

    for bad in [
        json!(["127.0.0.1:4", "host#frag"]),
        json!(["a:1", "a:2", "a:3", "a:4", "a:5", "a:6", "a:7"]),
        json!([1]),
    ] {
        assert_eq!(client.set_routes(host_id, &bad), -1, "{bad}");
        assert!(!last_err().is_empty());
    }
    assert_eq!(
        client.routes_of(host_id, "operator"),
        ["direct:127.0.0.1:3"]
    );
    assert_eq!(
        client.set_routes("dev_unknown", &json!(["127.0.0.1:5"])),
        TENDRIL_ERR_NOT_FOUND,
        "an unknown peer maps like the sibling route calls"
    );
    assert!(last_err().contains("dev_unknown"), "{}", last_err());

    assert_eq!(client.clear_routes(host_id, None), TENDRIL_OK);
    assert!(client.routes_of(host_id, "operator").is_empty());
    assert_eq!(client.routes_of(host_id, "signed"), signed);
    assert_eq!(
        client.clear_routes(host_id, Some("bogus")),
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(client.clear_routes(host_id, Some("signed")), TENDRIL_OK);
    let view = client.peer_routes(host_id);
    assert_eq!(view["routes"], json!([]));
    assert!(
        view["route_meta"]["seq"].as_u64().is_some(),
        "route_meta kept"
    );

    let err = connect_stored(client, &p.host, 1, &p.grant).expect_err("no routes left");
    assert!(err.contains("no dialable stored routes"), "{err}");

    assert_eq!(client.set_routes(host_id, &json!([p.listen])), TENDRIL_OK);
    let (c, h) = connect_stored(client, &p.host, 1, &p.grant).expect("operator route connect");
    c.send(b"operator");
    h.expect_data(b"operator");

    let mut out = ptr::null_mut();
    let unknown = cs("dev_unknown");
    assert_eq!(
        unsafe { tendril_endpoint_peer_routes(client.raw(), unknown.as_ptr(), &raw mut out) },
        TENDRIL_ERR_NOT_FOUND
    );
}

#[test]
fn apply_route_uri_offline() {
    let p = paired(Kind::Sealed, 1);
    let (host, client, host_id) = (&p.host, &p.client, p.host_id.as_str());
    let first = client.peer_routes(host_id)["route_meta"]["seq"]
        .as_u64()
        .unwrap();
    let stale = host.issue(None)["uri"].as_str().unwrap().to_owned();

    let second = host.serve_direct("127.0.0.1:0");
    let fresh = host.issue(None);
    assert_eq!(fresh["route_seq"].as_u64().unwrap(), first + 1);
    let fresh_uri = fresh["uri"].as_str().unwrap();

    let res = client.apply(fresh_uri, None).expect("apply fresh");
    assert_eq!(res["peer_id"], host_id);
    assert_eq!(res["applied"], true);
    assert_eq!(res["reason"], Value::Null);
    assert_eq!(res["route_seq"].as_u64().unwrap(), first + 1);
    let mut signed = client.routes_of(host_id, "signed");
    signed.sort();
    let mut want = vec![direct(&p.listen), direct(&second)];
    want.sort();
    assert_eq!(signed, want);

    let res = client.apply(&stale, None).expect("apply stale");
    assert_eq!(res["applied"], false);
    assert_eq!(res["reason"], "stale_route_seq");
    assert_eq!(client.routes_of(host_id, "signed").len(), 2);

    let res = client
        .apply(&stale, Some(&json!({"replace_routes": true})))
        .expect("approved");
    assert_eq!(res["applied"], true);
    assert_eq!(client.routes_of(host_id, "signed"), [direct(&p.listen)]);
    assert_eq!(
        client.peer_routes(host_id)["route_meta"]["origin"],
        "approved"
    );

    let res = client
        .apply(fresh_uri, Some(&json!({"route_policy": "committed_only"})))
        .expect("policy");
    assert_eq!(res["applied"], false);
    assert_eq!(res["reason"], "route_policy");

    let unsigned = host.issue(Some(&json!({"sign_routes": false})));
    let (rc, msg) = client
        .apply(unsigned["uri"].as_str().unwrap(), None)
        .expect_err("unsigned");
    assert_eq!(rc, TENDRIL_ERR_INVALID_ARG);
    assert!(msg.contains("not host-signed"), "{msg}");

    let tmp = TempDir::new().unwrap();
    let stranger = new_ep(Kind::StoreLess, &tmp, "stranger", None);
    stranger.serve_direct("127.0.0.1:0");
    let foreign = stranger.issue(None);
    let (rc, _) = client
        .apply(foreign["uri"].as_str().unwrap(), None)
        .expect_err("unknown host");
    assert_eq!(rc, TENDRIL_ERR_NOT_FOUND);
    let (rc, _) = client.apply("not a uri", None).expect_err("garbage");
    assert_eq!(rc, TENDRIL_ERR_INVALID_ARG);
}

#[test]
fn connect_with_options_uses_and_applies_recovery_uri() {
    let p = paired(Kind::StateDir, 1);
    let (host, client, host_id) = (&p.host, &p.client, p.host_id.as_str());
    assert_eq!(client.clear_routes(host_id, Some("all")), TENDRIL_OK);
    connect_stored(client, host, 1, &p.grant).expect_err("no stored routes");

    // Equal rq: the URI's hints are dialed but the stored routes stay untouched.
    let same = host.issue(None);
    let grant: Value = serde_json::from_str(&p.grant).unwrap();
    let (c, h) = connect_opts(
        client,
        host,
        &json!({"wire": 1, "grant": grant, "recovery_uri": same["uri"]}),
    )
    .expect("recovery connect");
    c.send(b"recovered");
    h.expect_data(b"recovered");
    drop((c, h));
    assert_eq!(client.peer_routes(host_id)["routes"], json!([]));

    // Newer rq under all_signed: the signed routes are replaced.
    host.serve_direct("127.0.0.1:0");
    let newer = host.issue(None);
    let (c, h) = connect_opts(
        client,
        host,
        &json!({"grant": grant, "recovery_uri": newer["uri"]}),
    )
    .expect("recovery connect");
    drop((c, h));
    assert_eq!(client.routes_of(host_id, "signed").len(), 2);
    assert_eq!(
        client.peer_routes(host_id)["route_meta"]["seq"],
        newer["route_seq"]
    );

    // An explicit endpoint with a recovery URI still checks the URI's keys.
    let (c, h) = connect_opts(
        client,
        host,
        &json!({"grant": grant, "endpoint": p.listen, "recovery_uri": newer["uri"]}),
    )
    .expect("explicit endpoint with recovery URI");
    drop((c, h));

    let tmp = TempDir::new().unwrap();
    let stranger = new_ep(Kind::StoreLess, &tmp, "stranger", None);
    stranger.serve_direct("127.0.0.1:0");
    let foreign = stranger.issue(None);
    let target = cs(host_id);
    let o = cs(&json!({"grant": grant, "recovery_uri": foreign["uri"]}).to_string());
    let s =
        unsafe { tendril_session_connect_with_options(client.raw(), target.as_ptr(), o.as_ptr()) };
    assert!(s.is_null(), "a recovery URI of another host is refused");

    for bad in [json!({"wire": 3}), json!({"wires": 1})] {
        let o = cs(&bad.to_string());
        let s = unsafe {
            tendril_session_connect_with_options(client.raw(), target.as_ptr(), o.as_ptr())
        };
        assert!(s.is_null(), "{bad}");
    }
}

fn snapshot(addr: &str) -> Value {
    json!({"networks": [{
        "id": "net-1",
        "iface": "wlan0",
        "if_index": 3,
        "transports": ["wifi"],
        "addrs": [addr],
    }]})
}

/// Polls `sess` (route sets never reach its event stream) until `client` records an applied
/// route set with `seq` from `host_id`.
fn wait_route_set(client: &Ep, sess: &Sess, host_id: &str, seq: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let ev = sess.poll(250);
        assert!(
            ev.is_none(),
            "route sets never reach the event stream: {ev:?}"
        );
        let view = client.peer_routes(host_id);
        if view["last_route_set"] == json!({"outcome": "applied", "seq": seq}) {
            assert_eq!(view["route_meta"]["origin"], "session");
            assert_eq!(view["route_meta"]["seq"], seq);
            return;
        }
        assert!(
            Instant::now() < deadline,
            "route set {seq} not applied: {view}"
        );
    }
}

#[test]
fn refresh_routes_delivers_a_route_set_to_live_sessions() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", Some("refresh-host"));
    let client = new_ep(Kind::StateDir, &tmp, "client", None);
    let loopback = host.serve_direct("127.0.0.1:0");
    let any = host.serve_direct("0.0.0.0:0");
    let lan_port = port_of(&any);

    let first = host.refresh(Some(&snapshot("10.255.77.20")));
    let seq0 = first["route_seq"].as_u64().unwrap();
    let issued = host.issue(None);
    assert_eq!(issued["route_seq"].as_u64().unwrap(), seq0);
    let uri = issued["uri"].as_str().unwrap();
    let lan_a = format!("direct:10.255.77.20:{lan_port}");
    assert!(uri.contains("10.255.77.20"), "{uri}");

    let res = pair(&host, &client, uri, 1, None);
    let host_id = host.host_id();
    let mut signed = client.routes_of(&host_id, "signed");
    signed.sort();
    let mut want = vec![direct(&loopback), lan_a.clone()];
    want.sort();
    assert_eq!(signed, want);
    let grant = host.mint_grant(res["device_id"].as_str().unwrap());

    // A client that learned its routes from a URI sends route_seq 0, so the host's current set
    // is the first host-initiated frame of its first session.
    let (c, h) = connect_stored(&client, &host, 1, &grant).expect("first connect");
    wait_route_set(&client, &c, &host_id, seq0);
    drop((c, h));

    let (c, h) = connect_stored(&client, &host, 1, &grant).expect("second connect");

    let again = host.refresh(Some(&snapshot("10.255.77.20")));
    assert_eq!(again["changed"], false);
    assert_eq!(again["route_seq"].as_u64().unwrap(), seq0);

    let moved = host.refresh(Some(&snapshot("10.255.77.30")));
    assert_eq!(moved["changed"], true);
    let seq1 = moved["route_seq"].as_u64().unwrap();
    assert_eq!(seq1, seq0 + 1);

    let lan_b = format!("direct:10.255.77.30:{lan_port}");
    wait_route_set(&client, &c, &host_id, seq1);
    let signed = client.routes_of(&host_id, "signed");
    assert!(signed.contains(&lan_b), "{signed:?}");
    assert!(!signed.contains(&lan_a), "{signed:?}");
    assert!(signed.contains(&direct(&loopback)), "{signed:?}");

    h.send(b"still open");
    c.expect_data(b"still open");

    let bad = cs("{\"networks\": 1}");
    assert_eq!(
        unsafe { tendril_endpoint_refresh_routes(host.raw(), bad.as_ptr(), ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_endpoint_refresh_routes(host.raw(), ptr::null(), ptr::null_mut()) },
        TENDRIL_OK
    );
}

#[test]
fn sealed_host_keeps_route_seq_across_close_and_reopen() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("host");
    let dir_s = dir.to_str().unwrap();
    let identity = sealed_identity(dir_s, Some("sealed-host"));
    let explicit = |hint: &str| json!({"advertise": "explicit", "advertised_endpoints": [hint]});

    let seq_b = {
        let host = open_sealed(dir_s, &identity);
        assert_eq!(host.configure(&explicit("192.168.40.1:4100")), TENDRIL_OK);
        let a = host.issue(None)["route_seq"].as_u64().unwrap();
        assert_eq!(host.configure(&explicit("192.168.40.1:4101")), TENDRIL_OK);
        let b = host.issue(None)["route_seq"].as_u64().unwrap();
        assert_eq!(b, a + 1);
        b
    };

    let host = open_sealed(dir_s, &identity);
    assert_eq!(host.configure(&explicit("192.168.40.1:4101")), TENDRIL_OK);
    assert_eq!(host.issue(None)["route_seq"].as_u64().unwrap(), seq_b);
    assert_eq!(host.configure(&explicit("192.168.40.1:4102")), TENDRIL_OK);
    assert_eq!(
        host.issue(None)["route_seq"].as_u64().unwrap(),
        seq_b + 1,
        "a changed set after reopen bumps from the persisted sequence"
    );
}

/// Runs `tendril_endpoint_pair_uri` and returns its result code and last error.
fn pair_uri_rc(client: &Ep, uri: &str, options: Option<&Value>) -> (i32, String) {
    let u = cs(uri);
    let o = options.map(|v| cs(&v.to_string()));
    let mut out = ptr::null_mut();
    let rc = unsafe {
        tendril_endpoint_pair_uri(
            client.raw(),
            u.as_ptr(),
            ptr::null(),
            ptr::null(),
            o.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            &raw mut out,
        )
    };
    if rc == TENDRIL_OK {
        drop(unsafe { take_cstr(out) });
    }
    (rc, last_err())
}

#[test]
fn empty_code_override_is_rejected_before_dialing() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", None);
    let client = new_ep(Kind::StateDir, &tmp, "client", None);
    host.serve_direct("127.0.0.1:0");
    let uri = host.issue(None)["uri"].as_str().unwrap().to_owned();
    for code in ["", "   "] {
        let started = Instant::now();
        let (rc, err) = pair_uri_rc(&client, &uri, Some(&json!({ "code": code })));
        assert_eq!(rc, TENDRIL_ERR_INVALID_ARG, "{code:?}: {err}");
        assert!(err.contains("pairing code invalid"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "rejected before any dial"
        );
    }
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_pair_accept(host.raw(), 200, &raw mut out) },
        TENDRIL_WOULD_BLOCK,
        "the host never saw a pairing attempt"
    );
}

/// Asserts that `err` is non-empty and contains none of `secrets`.
fn assert_redacted(what: &str, err: &str, secrets: &[&str]) {
    assert!(!err.is_empty(), "{what}: no error");
    for secret in secrets {
        assert!(!err.contains(secret), "{what} leaked {secret:?}: {err}");
    }
}

#[test]
fn last_error_never_echoes_raw_input() {
    const SECRETS: [&str; 4] = ["hunter2", "s3cr3t", "AB12", "CD34"];
    let p = paired(Kind::StateDir, 1);
    let (client, host_id) = (&p.client, p.host_id.as_str());

    for origin in [
        "wss://user:hunter2@relay.example/p?t=s3cr3t",
        "opaque-s3cr3t",
    ] {
        let rc = client.configure(&json!({ "relay_auth_origins": [origin] }));
        assert_eq!(rc, TENDRIL_ERR_INVALID_ARG);
        assert_redacted("relay_auth_origins", &last_err(), &SECRETS);
    }

    let uri = p.host.issue(None)["uri"].as_str().unwrap().to_owned();
    let bad_uris = [
        "tendril://pair?v=1&host=a&code=TND-AB12-CD34&s3cr3t=1&k=AA&sh=AA".to_owned(),
        format!("{uri}&s3cr3t=TND-AB12-CD34"),
    ];
    for bad in &bad_uris {
        let (rc, err) = pair_uri_rc(client, bad, None);
        assert_eq!(rc, TENDRIL_ERR_INVALID_ARG);
        assert_redacted("pair_uri", &err, &SECRETS);
        let (rc, err) = client.apply(bad, None).expect_err("bad URI");
        assert_eq!(rc, TENDRIL_ERR_INVALID_ARG);
        assert_redacted("apply_route_uri", &err, &SECRETS);
    }
    for opts in [
        json!({"code": 12_345, "endpoint": "s3cr3t"}),
        json!({"code": "TND-AB12-CD34", "endpoint": ["hunter2"]}),
        json!({"route_policy": "s3cr3t"}),
    ] {
        let (rc, err) = pair_uri_rc(client, &uri, Some(&opts));
        assert_eq!(rc, TENDRIL_ERR_INVALID_ARG, "{opts}");
        assert_redacted("pair_uri options", &err, &SECRETS);
    }
    let (rc, err) = pair_uri_rc(
        client,
        &uri,
        Some(&json!({
            "code": "TND-AB12-CD34",
            "endpoint": "ws://user:hunter2@127.0.0.1:1/v1/relay?token=s3cr3t",
        })),
    );
    assert_ne!(rc, TENDRIL_OK);
    assert_redacted("pair_uri dial failure", &err, &SECRETS);

    for routes in [
        json!(["127.0.0.1:4?token=s3cr3t"]),
        json!(["ws://user:hunter2@127.0.0.1:1/v1/relay?token=s3cr3t"]),
    ] {
        if client.set_routes(host_id, &routes) != TENDRIL_OK {
            assert_redacted("set_peer_routes", &last_err(), &SECRETS);
        }
    }

    let grant: Value = serde_json::from_str(&p.grant).unwrap();
    let target = cs(host_id);
    for opts in [
        json!({"grant": grant, "endpoint": "ws://user:hunter2@127.0.0.1:1/v1/relay?token=s3cr3t"}),
        json!({"grant": grant, "recovery_uri": bad_uris[0]}),
        json!({"grant": grant, "recovery_uri": "s3cr3t"}),
        json!({"grant": grant}),
    ] {
        let o = cs(&opts.to_string());
        let s = unsafe {
            tendril_session_connect_with_options(client.raw(), target.as_ptr(), o.as_ptr())
        };
        if s.is_null() {
            assert_redacted("connect_with_options", &last_err(), &SECRETS);
        } else {
            drop(Sess(s));
        }
    }
}

#[test]
fn last_error_redacts_quoted_kind_and_json_input() {
    const SECRETS: [&str; 4] = ["hunter2", "s3cr3t", "123456", "AB12"];
    let p = paired(Kind::StateDir, 1);
    let (host, client, host_id) = (&p.host, &p.client, p.host_id.as_str());

    // A pairing code kind is never echoed, quoted or not, in any case.
    for kind in ["s3cr3t", "x's3cr3t", "TND-AB12-CD34"] {
        let o = cs(&json!({ "kind": kind }).to_string());
        let mut out = ptr::null_mut();
        let rc =
            unsafe { tendril_endpoint_issue_pairing_uri(host.raw(), o.as_ptr(), &raw mut out) };
        assert_eq!(rc, TENDRIL_ERR_INVALID_ARG, "{kind}");
        assert_redacted("issue kind", &last_err(), &SECRETS);
    }
    assert_eq!(
        host.issue(Some(&json!({"kind": "REMOTE"})))["code_kind"],
        "remote"
    );

    // An apostrophe in an endpoint never ends a redacted value early.
    let uri = host.issue(None)["uri"].as_str().unwrap().to_owned();
    for endpoint in [
        "x'y hunter2@relay?t=s3cr3t",
        "ws://h:1/'/hunter2?t=s3cr3t",
        "endpoint 'a' hunter2 s3cr3t",
    ] {
        let (rc, err) = pair_uri_rc(client, &uri, Some(&json!({ "endpoint": endpoint })));
        assert_ne!(rc, TENDRIL_OK, "{endpoint}");
        assert_redacted("pair_uri endpoint", &err, &SECRETS);
        let o = cs(
            &json!({ "grant": serde_json::from_str::<Value>(&p.grant).unwrap(),
                            "endpoint": endpoint })
            .to_string(),
        );
        let target = cs(host_id);
        let s = unsafe {
            tendril_session_connect_with_options(client.raw(), target.as_ptr(), o.as_ptr())
        };
        if s.is_null() {
            assert_redacted("connect endpoint", &last_err(), &SECRETS);
        } else {
            drop(Sess(s));
        }
    }

    // JSON string lists and network snapshots report only the JSON error's position.
    for routes in [
        json!([123_456]),
        json!(["127.0.0.1:1", {"s3cr3t": "hunter2"}]),
    ] {
        assert_eq!(client.set_routes(host_id, &routes), TENDRIL_ERR_INVALID_ARG);
        let err = last_err();
        assert!(err.contains("line 1 column"), "{err}");
        assert_redacted("routes_json", &err, &SECRETS);
    }
    for snapshot in [
        json!({"networks": 123_456}),
        json!({"networks": [{"s3cr3t": "hunter2"}]}),
        json!({"networks": [{"iface": 123_456, "transports": [], "addrs": []}]}),
    ] {
        let s = cs(&snapshot.to_string());
        let mut out = ptr::null_mut();
        let rc = unsafe { tendril_endpoint_refresh_routes(host.raw(), s.as_ptr(), &raw mut out) };
        assert_eq!(rc, TENDRIL_ERR_INVALID_ARG, "{snapshot}");
        assert_redacted("snapshot_json_opt", &last_err(), &SECRETS);
    }
}

/// Lock order: a pairing claim takes the
/// roster file lock, then the pairing manager; URI issuance must publish before it takes the
/// manager. Issuing URIs in a loop while Wire v1 and v2 pairings complete on a state-dir host
/// must not deadlock.
#[test]
fn issuing_uris_while_pair_accept_runs_on_a_state_dir_host_completes() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let (tx, rx) = std::sync::mpsc::channel();
    // A deadlock leaves this thread blocked; the test fails on the timeout instead of hanging.
    thread::spawn(move || {
        let tmp = TempDir::new().unwrap();
        let host = new_ep(Kind::StateDir, &tmp, "host", Some("lock-order-host"));
        host.serve_direct("127.0.0.1:0");
        let uris: Vec<String> = (0..4)
            .map(|_| host.issue(None)["uri"].as_str().unwrap().to_owned())
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicUsize::new(0));
        let issuer = {
            let (stop, attempts, host_addr) =
                (Arc::clone(&stop), Arc::clone(&attempts), host.addr());
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let mut out = ptr::null_mut();
                    let rc = unsafe {
                        tendril_endpoint_issue_pairing_uri(
                            host_addr as *mut TendrilEndpoint,
                            ptr::null(),
                            &raw mut out,
                        )
                    };
                    // Every live code slot may be taken; the refusal still publishes first.
                    if rc == TENDRIL_OK {
                        drop(unsafe { take_cstr(out) });
                    }
                    attempts.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        for (i, uri) in uris.iter().enumerate() {
            let client = new_ep(Kind::StateDir, &tmp, &format!("client{i}"), None);
            let wire = if i % 2 == 0 { 1 } else { 2 };
            pair(&host, &client, uri, wire, None);
        }
        stop.store(true, Ordering::Release);
        issuer.join().unwrap();
        let _ = tx.send(attempts.load(Ordering::Relaxed));
    });
    let attempts = rx
        .recv_timeout(Duration::from_secs(120))
        .expect("pairing and URI issuance finish without a lock-order deadlock");
    assert!(attempts > 0, "the issuer ran during the pairings");
}

/// A loopback webhook that counts `POST /wake` requests and answers `202`. Other requests (a
/// host service probes new loopback listeners with `GET /`) are ignored.
fn wake_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            if buf[..n].starts_with(b"POST /wake") {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        }
    });
    (format!("http://{addr}/wake"), hits)
}

#[test]
fn explicit_v2_wake_connect_negotiates_routes() {
    use std::sync::atomic::Ordering;
    let p = paired(Kind::StateDir, 2);
    let (host, client, host_id) = (&p.host, &p.client, p.host_id.as_str());
    let (wake_url, wakes) = wake_server();
    assert_eq!(
        client.configure(&json!({
            "wake_url": wake_url,
            "wake_secret_b64": tendril_core::crypto::b64url_encode(&[7u8; 32]),
            "wake_pre_wake": true,
            "wake_retry_delay_ms": 50,
            "wake_max_attempts": 3,
        })),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let seq0 = client.peer_routes(host_id)["route_meta"]["seq"]
        .as_u64()
        .unwrap();

    // A new listener publishes a newer set; the woken session must receive it.
    host.serve_direct("127.0.0.1:0");
    let target = cs(host_id);
    let endpoint = cs(&p.listen);
    let g = cs(&p.grant);
    let (c, h) = connect_pair(host, 2, || unsafe {
        tendril_session_connect_v2(
            client.raw(),
            endpoint.as_ptr(),
            ptr::null(),
            target.as_ptr(),
            g.as_ptr(),
        )
    })
    .expect("woken explicit v2 connect");
    assert!(wakes.load(Ordering::SeqCst) >= 1, "pre_wake sent the hint");
    wait_route_set(client, &c, host_id, seq0 + 1);
    c.send(b"woken");
    h.expect_data(b"woken");
    drop((c, h));

    // A woken connect also takes a recovery URI.
    host.serve_direct("127.0.0.1:0");
    let newer = host.issue(None);
    let before = wakes.load(Ordering::SeqCst);
    let grant: Value = serde_json::from_str(&p.grant).unwrap();
    let (c, h) = connect_opts(
        client,
        host,
        &json!({"wire": 2, "grant": grant, "endpoint": p.listen, "recovery_uri": newer["uri"]}),
    )
    .expect("woken recovery connect");
    drop((c, h));
    assert!(wakes.load(Ordering::SeqCst) > before, "the wake ran again");
    assert_eq!(
        client.peer_routes(host_id)["route_meta"]["seq"],
        newer["route_seq"]
    );
}

#[test]
fn issue_reports_dropped_hints_redacted() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", Some("drop-host"));
    assert_eq!(
        host.configure(&json!({
            "advertise": "explicit",
            "advertised_endpoints": ["ws://user:SECRETPW@relay.example/v1/relay?t=SECRETTOKEN"],
        })),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    host.serve_direct("127.0.0.1:0");
    let o = cs("{}");
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_issue_pairing_uri(host.raw(), o.as_ptr(), &raw mut out) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let raw = unsafe { take_cstr(out) };
    assert!(!raw.contains("SECRETPW"), "{raw}");
    assert!(!raw.contains("SECRETTOKEN"), "{raw}");
    let issued: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        issued["dropped"],
        json!([{"hint": "ws://relay.example", "reason": "invalid"}])
    );
}

#[test]
fn connect_with_options_accepts_relay_host() {
    let p = paired(Kind::StateDir, 1);
    let target = cs(&p.host_id);

    // `relay_host` selects the relay mode of an explicit iroh endpoint, as in the legacy call;
    // an unparsable value is rejected before any dial, by the same parser.
    let legacy_ep = cs("iroh://peer");
    let legacy_rh = cs("not-a-relay-mode");
    let legacy = unsafe {
        tendril_session_connect(
            p.client.raw(),
            legacy_ep.as_ptr(),
            legacy_rh.as_ptr(),
            target.as_ptr(),
            ptr::null(),
        )
    };
    assert!(legacy.is_null());
    let legacy_err = last_err();
    assert!(!legacy_err.contains("unknown field"), "{legacy_err}");

    let opts = cs(r#"{"endpoint":"iroh://peer","relay_host":"not-a-relay-mode"}"#);
    let sess = unsafe {
        tendril_session_connect_with_options(p.client.raw(), target.as_ptr(), opts.as_ptr())
    };
    assert!(sess.is_null());
    let err = last_err();
    assert!(!err.contains("unknown field"), "{err}");
    assert_eq!(
        err, legacy_err,
        "same relay_host semantics as the legacy call"
    );

    // An empty value is ignored: the stored routes still connect.
    let grant: Value = serde_json::from_str(&p.grant).unwrap();
    let (c, h) = connect_opts(
        &p.client,
        &p.host,
        &json!({"grant": grant, "relay_host": ""}),
    )
    .expect("connect with an empty relay_host");
    c.send(b"relay host ok");
    h.expect_data(b"relay host ok");
}

fn close(ep: &Ep) {
    assert_eq!(unsafe { tendril_endpoint_close(ep.raw()) }, TENDRIL_OK);
}

fn issue_rc(ep: &Ep) -> (i32, bool, String) {
    let mut out = ptr::null_mut();
    let rc = unsafe { tendril_endpoint_issue_pairing_uri(ep.raw(), ptr::null(), &raw mut out) };
    let null = out.is_null();
    if !null {
        drop(unsafe { take_cstr(out) });
    }
    (rc, null, last_err())
}

fn refresh_rc(ep: &Ep, snapshot: Option<&Value>) -> (i32, bool, String) {
    let s = snapshot.map(|v| cs(&v.to_string()));
    let mut out = ptr::null_mut();
    let rc = unsafe {
        tendril_endpoint_refresh_routes(
            ep.raw(),
            s.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            &raw mut out,
        )
    };
    let null = out.is_null();
    if !null {
        drop(unsafe { take_cstr(out) });
    }
    (rc, null, last_err())
}

#[test]
fn issue_pairing_uri_after_close_is_refused() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", Some("closed-host"));
    host.serve_direct("127.0.0.1:0");
    close(&host);
    let (rc, null, err) = issue_rc(&host);
    assert_eq!(rc, TENDRIL_ERR_CLOSED, "{err}");
    assert!(null, "no output on a closed endpoint");
    assert!(err.contains("closed"), "{err}");

    let idle = new_ep(Kind::StateDir, &tmp, "idle", Some("closed-idle"));
    close(&idle);
    let (rc, null, err) = issue_rc(&idle);
    assert_eq!(rc, TENDRIL_ERR_CLOSED, "{err}");
    assert!(null);
    assert!(err.contains("closed"), "{err}");
}

#[test]
fn refresh_routes_after_close_is_refused() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", Some("closed-host"));
    let endpoint = host.serve_direct("127.0.0.1:0");
    close(&host);
    let (rc, null, err) = refresh_rc(&host, None);
    assert_eq!(rc, TENDRIL_ERR_CLOSED, "{err}");
    assert!(null);
    assert!(err.contains("closed"), "{err}");

    let snap = snapshot(&endpoint);
    let (rc, null, err) = refresh_rc(&host, Some(&snap));
    assert_eq!(rc, TENDRIL_ERR_CLOSED, "{err}");
    assert!(null);
    assert!(err.contains("closed"), "{err}");

    let idle = new_ep(Kind::StateDir, &tmp, "idle", Some("closed-idle"));
    close(&idle);
    assert_eq!(refresh_rc(&idle, None).0, TENDRIL_ERR_CLOSED);
}

#[test]
fn close_is_idempotent_and_free_after_close_is_clean() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", Some("closed-host"));
    host.serve_direct("127.0.0.1:0");
    close(&host);
    close(&host);
    drop(host);
}

#[test]
fn serve_after_close_does_not_start_hosting() {
    let tmp = TempDir::new().unwrap();
    let host = new_ep(Kind::StateDir, &tmp, "host", Some("closed-host"));
    close(&host);
    host.serve_direct("127.0.0.1:0");
    let (rc, null, err) = issue_rc(&host);
    assert_eq!(rc, TENDRIL_ERR_CLOSED, "{err}");
    assert!(null);
}

#[derive(Debug)]
struct CapturedApnsReq {
    request_line: String,
    headers: HashMap<String, String>,
    body: Value,
}

fn apns_capture_server() -> (String, Arc<Mutex<Vec<CapturedApnsReq>>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_bg = Arc::clone(&captured);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let mut header_end = None;
            let mut content_len = 0usize;
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if header_end.is_none()
                    && let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let end = pos + 4;
                    header_end = Some(end);
                    let hdr_str = String::from_utf8_lossy(&raw[..pos]);
                    for line in hdr_str.split("\r\n").skip(1) {
                        if let Some((k, v)) = line.split_once(':')
                            && k.trim().eq_ignore_ascii_case("content-length")
                        {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if let Some(end) = header_end
                    && raw.len() >= end + content_len
                {
                    break;
                }
            }
            let Some(end) = header_end else { continue };
            let head = String::from_utf8_lossy(&raw[..end - 4]);
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or_default().to_owned();
            let mut headers = HashMap::new();
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
                }
            }
            if request_line.starts_with("POST /3/device/") {
                let body_bytes = &raw[end..(end + content_len).min(raw.len())];
                let body: Value = serde_json::from_slice(body_bytes).unwrap();
                captured_bg.lock().unwrap().push(CapturedApnsReq {
                    request_line,
                    headers,
                    body,
                });
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        }
    });
    (format!("http://{addr}/3/device/deadbeef"), captured)
}

#[test]
fn apns_mutable_alert_and_coalesce_persist_across_dials() {
    let p = paired(Kind::StateDir, 2);
    let (host, client) = (&p.host, &p.client);
    let (wake_url, captured) = apns_capture_server();
    let secret = [0x29u8; 32];
    let secret_b64 = tendril_core::crypto::b64url_encode(&secret);
    assert_eq!(
        client.configure(&json!({
            "wake_url": wake_url,
            "wake_adapter": "apns",
            "wake_secret_b64": secret_b64,
            "wake_auth_token": "dev-bearer-token",
            "wake_pre_wake": true,
            "wake_retry_delay_ms": 20,
            "wake_max_attempts": 2,
            "wake_coalesce_secs": 60,
            "wake_apns_mode": "mutable_alert",
            "wake_apns_topic": "app.tendril.test",
            "wake_apns_loc_key": "TENDRIL_WAKE_TEST",
        })),
        TENDRIL_OK,
        "{}",
        last_err()
    );

    let target = cs(p.host_id.as_str());
    let endpoint = cs(&p.listen);
    let g = cs(&p.grant);
    let (c1, h1) = connect_pair(host, 2, || unsafe {
        tendril_session_connect_v2(
            client.raw(),
            endpoint.as_ptr(),
            ptr::null(),
            target.as_ptr(),
            g.as_ptr(),
        )
    })
    .expect("first dial");
    drop((c1, h1));
    // Rapid second dial must be coalesced by the cached WakeProvider cooldown.
    let (c2, h2) = connect_pair(host, 2, || unsafe {
        tendril_session_connect_v2(
            client.raw(),
            endpoint.as_ptr(),
            ptr::null(),
            target.as_ptr(),
            g.as_ptr(),
        )
    })
    .expect("second dial");
    drop((c2, h2));

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 1, "expected second wake to coalesce");
    let req = &reqs[0];
    assert!(req.request_line.starts_with("POST /3/device/deadbeef "));
    assert_eq!(
        req.headers.get("authorization").map(String::as_str),
        Some("Bearer dev-bearer-token")
    );
    assert_eq!(
        req.headers.get("apns-push-type").map(String::as_str),
        Some("alert")
    );
    assert_eq!(
        req.headers.get("apns-priority").map(String::as_str),
        Some("10")
    );
    assert_eq!(
        req.headers.get("apns-topic").map(String::as_str),
        Some("app.tendril.test")
    );
    assert_eq!(req.body["aps"]["mutable-content"], 1);
    assert!(req.body["aps"].get("content-available").is_none());
    assert_eq!(req.body["aps"]["alert"]["loc-key"], "TENDRIL_WAKE_TEST");
    let tag_c = cs(req.body["wake_tag"].as_str().unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut matched = 0u8;
    assert_eq!(
        unsafe { tendril_verify_wake_tag(secret.as_ptr(), tag_c.as_ptr(), now, &raw mut matched) },
        TENDRIL_OK
    );
    assert_eq!(matched, 1);
}

fn generate_ephemeral_ec_p8_and_mtls_pem() -> (String, String, String) {
    let p8_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate p256 key");
    let p8_pem = p8_key.serialize_pem();

    let mut params =
        CertificateParams::new(vec!["tendril-apns-test".to_owned()]).expect("cert params");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let mtls_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate mtls key");
    let cert = params.self_signed(&mtls_key).expect("self-signed cert");
    (p8_pem, cert.pem(), mtls_key.serialize_pem())
}

#[test]
fn apns_h2_config_validation_and_tls_attempt() {
    let (p8_pem, cert_pem, key_pem) = generate_ephemeral_ec_p8_and_mtls_pem();
    let p = paired(Kind::StateDir, 2);
    let (host, client) = (&p.host, &p.client);
    let device_token = "0".repeat(64);
    let secret_b64 = tendril_core::crypto::b64url_encode(&[0x55u8; 32]);

    // Valid APNs HTTP/2 provider token (.p8) + mutable_alert configuration succeeds.
    assert_eq!(
        client.configure(&json!({
            "wake_url": format!("https://api.sandbox.push.apple.com/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_apns_mode": "mutable_alert",
            "wake_apns_topic": "app.tendril.ios",
            "wake_apns_loc_key": "TENDRIL_WAKE_CALL",
            "wake_apns_team_id": "TEAM123456",
            "wake_apns_key_id": "KEY1234567",
            "wake_apns_p8_pem": p8_pem,
            "wake_coalesce_secs": 15,
        })),
        TENDRIL_OK,
        "{}",
        last_err()
    );

    // Valid APNs HTTP/2 client mTLS certificate/key configuration succeeds.
    assert_eq!(
        client.configure(&json!({
            "wake_url": format!("https://api.push.apple.com/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_apns_mode": "background",
            "wake_apns_topic": "app.tendril.ios",
            "wake_apns_client_cert_pem": cert_pem,
            "wake_apns_client_key_pem": key_pem,
        })),
        TENDRIL_OK,
        "{}",
        last_err()
    );

    // Fail-closed rejections and error redaction checks.
    let bad_configs = [
        json!({
            "wake_url": format!("http://127.0.0.1:8080/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_auth_token": "tok",
            "wake_apns_topic": "app.tendril.ios",
        }),
        json!({
            "wake_url": format!("https://evil.example/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_auth_token": "tok",
            "wake_apns_topic": "app.tendril.ios",
        }),
        json!({
            "wake_url": format!("https://api.push.apple.com/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_auth_token": "tok",
        }),
        json!({
            "wake_url": format!("https://api.push.apple.com/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_auth_token": "tok",
            "wake_apns_topic": "app.tendril.ios",
            "wake_apns_team_id": "TEAM123456",
            "wake_apns_key_id": "KEY1234567",
            "wake_apns_p8_pem": p8_pem,
        }),
        json!({
            "wake_url": format!("https://api.push.apple.com/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_auth_token": "tok",
            "wake_apns_topic": "app.tendril.ios",
            "wake_apns_mode": "mutable_alert",
            "wake_apns_loc_key": "BAD KEY WITH SPACES",
        }),
        json!({
            "wake_url": format!("https://api.push.apple.com/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_apns_topic": "app.tendril.ios",
            "wake_apns_team_id": "TEAM123456",
            "wake_apns_key_id": "KEY1234567",
            "wake_apns_p8_pem": "TOPSECRET_INVALID_P8",
        }),
    ];
    for cfg in bad_configs {
        assert_eq!(client.configure(&cfg), TENDRIL_ERR_INVALID_ARG, "{cfg}");
        let err = last_err();
        assert!(!err.contains("TOPSECRET_INVALID_P8"), "{err}");
        assert!(!err.contains(&secret_b64), "{err}");
    }

    // Loopback TLS listener proves ApnsH2WakeProvider connects cleanly and fails closed on untrusted TLS,
    // without blocking best-effort tendril_session_connect_v2.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tls_addr = listener.local_addr().unwrap();
    let tls_hits = Arc::new(AtomicUsize::new(0));
    let tls_hits_bg = Arc::clone(&tls_hits);
    thread::spawn(move || {
        for s in listener.incoming().flatten() {
            tls_hits_bg.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    });
    assert_eq!(
        client.configure(&json!({
            "wake_url": format!("https://{tls_addr}/3/device/{device_token}"),
            "wake_adapter": "apns_h2",
            "wake_secret_b64": secret_b64,
            "wake_auth_token": "TOPSECRET_BEARER",
            "wake_pre_wake": true,
            "wake_max_attempts": 1,
            "wake_timeout_ms": 500,
            "wake_apns_mode": "mutable_alert",
            "wake_apns_topic": "app.tendril.ios",
            "wake_apns_loc_key": "TENDRIL_WAKE_CALL",
        })),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let target = cs(p.host_id.as_str());
    let endpoint = cs(&p.listen);
    let g = cs(&p.grant);
    let (c, h) = connect_pair(host, 2, || unsafe {
        tendril_session_connect_v2(
            client.raw(),
            endpoint.as_ptr(),
            ptr::null(),
            target.as_ptr(),
            g.as_ptr(),
        )
    })
    .expect("connect continues best-effort");
    drop((c, h));
    assert!(tls_hits.load(Ordering::SeqCst) >= 1);
}

#[test]
fn low_power_stored_v2_wake_idle_timeout_and_external_monitor() {
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let p = paired(Kind::StateDir, 2);
    let (host, client, host_id) = (&p.host, &p.client, p.host_id.as_str());

    // Pick a currently closed loopback port so the initial stored-route dial hits connection refused.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let sleeping_port = probe.local_addr().unwrap().port();
    drop(probe);
    let sleeping_addr = format!("127.0.0.1:{sleeping_port}");

    let host_c = cs(host_id);
    let source_all = cs("all");
    assert_eq!(
        unsafe {
            tendril_ffi::tendril_endpoint_clear_peer_routes(
                client.raw(),
                host_c.as_ptr(),
                source_all.as_ptr(),
            )
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let routes_c = cs(&json!([sleeping_addr]).to_string());
    assert_eq!(
        unsafe {
            tendril_ffi::tendril_endpoint_set_peer_routes(
                client.raw(),
                host_c.as_ptr(),
                routes_c.as_ptr(),
            )
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );

    // `idle_timeout_ms: 0` must fail closed before dialing.
    let target = cs(host_id);
    let bad_opts = cs(&json!({"wire": 2, "idle_timeout_ms": 0}).to_string());
    assert!(
        unsafe {
            tendril_session_connect_with_options(client.raw(), target.as_ptr(), bad_opts.as_ptr())
        }
        .is_null(),
        "idle_timeout_ms=0 must be rejected"
    );

    // Start a wake server that binds the sleeping host listener before replying 202.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let wake_addr = listener.local_addr().unwrap();
    let wake_hits = Arc::new(AtomicUsize::new(0));
    let hits_ref = Arc::clone(&wake_hits);
    let host_addr = host.addr();
    let sleep_c = CString::new(sleeping_addr.clone()).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            if buf[..n].starts_with(b"POST /wake") {
                if hits_ref.fetch_add(1, Ordering::SeqCst) == 0 {
                    let ep = host_addr as *mut TendrilEndpoint;
                    let mut out = ptr::null_mut();
                    let rc = unsafe {
                        tendril_ffi::tendril_endpoint_serve_direct(
                            ep,
                            sleep_c.as_ptr(),
                            &raw mut out,
                        )
                    };
                    assert_eq!(rc, TENDRIL_OK, "deferred serve_direct failed");
                    if !out.is_null() {
                        unsafe { drop(take_cstr(out)) };
                    }
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        }
    });
    let wake_url = format!("http://{wake_addr}/wake");

    assert_eq!(
        host.configure(&json!({ "power_profile": "low_power" })),
        TENDRIL_OK,
        "{}",
        last_err()
    );
    assert_eq!(
        client.configure(&json!({
            "power_profile": "low_power",
            "wake_url": wake_url,
            "wake_secret_b64": tendril_core::crypto::b64url_encode(&[9u8; 32]),
            "wake_pre_wake": false,
            "wake_retry_delay_ms": 50,
            "wake_retry_max_delay_ms": 200,
            "wake_max_attempts": 3,
        })),
        TENDRIL_OK,
        "{}",
        last_err()
    );

    assert_eq!(
        unsafe { tendril_ffi::tendril_endpoint_set_external_path_monitor(host.raw(), 1) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let _ = host.refresh(None);
    assert_eq!(
        unsafe { tendril_ffi::tendril_endpoint_set_external_path_monitor(host.raw(), 0) },
        TENDRIL_OK,
        "{}",
        last_err()
    );

    // Stored-route (`endpoint` omitted) Wire v2 connect must fire the wake provider on initial miss.
    let grant: Value = serde_json::from_str(&p.grant).unwrap();
    let (c, h) = connect_opts(
        client,
        host,
        &json!({"wire": 2, "grant": grant, "idle_timeout_ms": 5000}),
    )
    .expect("stored-route v2 wake connect");
    assert_eq!(wake_hits.load(Ordering::SeqCst), 1);
    c.send(b"ffi-low-power");
    h.expect_data(b"ffi-low-power");
    drop((c, h));

    // Subsequent stored-route reconnect finds the live listener via LKG without waking again.
    let (c2, h2) = connect_opts(
        client,
        host,
        &json!({"wire": 2, "grant": grant, "idle_timeout_ms": 5000}),
    )
    .expect("stored-route v2 LKG reconnect");
    assert_eq!(wake_hits.load(Ordering::SeqCst), 1);
    c2.send(b"ffi-lkg");
    h2.expect_data(b"ffi-lkg");
    drop((c2, h2));
}
