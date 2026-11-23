//! Group mesh C ABI: admin calls, manifest ingestion, open, broadcast, poll, authorize, close.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tendril_core::crypto::{b64url_decode, b64url_decode_array};
use tendril_core::group::GroupManifest;
use tendril_ffi::{
    TENDRIL_ERR_CLOSED, TENDRIL_ERR_INVALID_ARG, TENDRIL_ERR_NOT_FOUND, TENDRIL_ERR_PROTOCOL,
    TENDRIL_OK, TENDRIL_WOULD_BLOCK, TendrilEndpoint, TendrilGroup, tendril_endpoint_close,
    tendril_endpoint_configure_transports_json, tendril_endpoint_enroll_initiate,
    tendril_endpoint_export_identity_json, tendril_endpoint_free, tendril_endpoint_info_json,
    tendril_endpoint_mint_enrollment_token, tendril_endpoint_new, tendril_endpoint_new_from_state,
    tendril_endpoint_new_sealed, tendril_endpoint_pair_accept, tendril_endpoint_serve_direct,
    tendril_endpoint_serve_relay, tendril_group_add_member, tendril_group_authorize_peer,
    tendril_group_broadcast, tendril_group_close, tendril_group_create, tendril_group_free,
    tendril_group_ingest_manifest, tendril_group_local_endpoint, tendril_group_open,
    tendril_group_poll_event, tendril_group_remove_member, tendril_group_sync, tendril_last_error,
    tendril_session_accept, tendril_session_accept_v2, tendril_session_connect,
    tendril_session_free, tendril_session_poll_event, tendril_session_shutdown,
    tendril_string_free,
};
use tendril_runtime::{
    DirectDialer, EmbeddedRelay, PathDialer, RelayClientAuth, RelayDialer, RelayV2Dialer,
    SessionDriver, StateStore, deserialize_identity_json,
};

unsafe fn take_cstr(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null());
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
    unsafe { tendril_string_free(ptr) };
    s
}

fn last_err() -> String {
    let mut buf = vec![0i8; 512];
    let needed = unsafe { tendril_last_error(buf.as_mut_ptr().cast::<c_char>(), buf.len()) };
    assert!(needed >= 1, "expected a last error");
    unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) }
        .to_str()
        .unwrap()
        .to_owned()
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

struct Node {
    dir: TempDir,
    ep: *mut TendrilEndpoint,
    id: String,
    addr: String,
    static_pub: [u8; 32],
    signing_pub: Vec<u8>,
}

impl Node {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let path = cstr(dir.path().to_str().unwrap());
        let ep = unsafe { tendril_endpoint_new(path.as_ptr(), ptr::null()) };
        assert!(!ep.is_null(), "{}", last_err());
        Self::from_ep(dir, ep)
    }

    /// A store-less mobile-style endpoint: identity stays with the caller, the runtime seals
    /// roster and group state in the directory.
    fn sealed() -> Self {
        let dir = TempDir::new().unwrap();
        let ep = open_sealed(dir.path(), None).unwrap();
        Self::from_ep(dir, ep)
    }

    fn identity_json(&self) -> String {
        let mut out = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_export_identity_json(self.ep, &raw mut out) },
            TENDRIL_OK
        );
        unsafe { take_cstr(out) }
    }

    /// Frees the endpoint and reopens the sealed directory with the exported identity.
    fn restart_sealed(&mut self) {
        let identity = self.identity_json();
        unsafe {
            tendril_endpoint_close(self.ep);
            tendril_endpoint_free(self.ep);
        }
        self.ep = open_sealed(self.dir.path(), Some(&identity)).unwrap();
        let mut addr = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_serve_direct(self.ep, ptr::null(), &raw mut addr) },
            TENDRIL_OK
        );
        self.addr = unsafe { take_cstr(addr) };
    }

    fn from_ep(dir: TempDir, ep: *mut TendrilEndpoint) -> Self {
        let mut info = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_info_json(ep, &raw mut info) },
            TENDRIL_OK
        );
        let info: Value = serde_json::from_str(&unsafe { take_cstr(info) }).unwrap();
        let id = info["device_id"].as_str().unwrap().to_owned();
        let static_pub = b64url_decode_array::<32>(info["static_pub"].as_str().unwrap()).unwrap();
        let signing_pub = b64url_decode(info["signing_pub"].as_str().unwrap()).unwrap();
        assert_eq!(info["host_id"].as_str().unwrap(), id);
        let mut addr = ptr::null_mut();
        assert_eq!(
            unsafe { tendril_endpoint_serve_direct(ep, ptr::null(), &raw mut addr) },
            TENDRIL_OK
        );
        Self {
            dir,
            ep,
            id,
            addr: unsafe { take_cstr(addr) },
            static_pub,
            signing_pub,
        }
    }
}

fn open_sealed(
    dir: &std::path::Path,
    identity: Option<&str>,
) -> Result<*mut TendrilEndpoint, String> {
    let dir = cstr(dir.to_str().unwrap());
    let identity = identity.map(cstr);
    let ep = unsafe {
        tendril_endpoint_new_sealed(
            dir.as_ptr(),
            identity.as_ref().map_or(ptr::null(), |i| i.as_ptr()),
            ptr::null(),
            ptr::null(),
        )
    };
    if ep.is_null() {
        Err(last_err())
    } else {
        Ok(ep)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.ep.is_null() {
            return;
        }
        unsafe {
            tendril_endpoint_close(self.ep);
            tendril_endpoint_free(self.ep);
        }
    }
}

/// Enrolls `peer` with `host` over the M2M flow, which pins both full signing keys.
fn pair(host: &Node, peer: &Node) {
    let host_id = cstr(&host.id);
    let peer_id = cstr(&peer.id);
    let mut token = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_mint_enrollment_token(
                host.ep,
                host_id.as_ptr(),
                peer_id.as_ptr(),
                900,
                &raw mut token,
            )
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let token = cstr(&unsafe { take_cstr(token) });
    let host_ep = host.ep as usize;
    let accept = thread::spawn(move || {
        let mut out = ptr::null_mut();
        let rc = unsafe {
            tendril_endpoint_pair_accept(host_ep as *mut TendrilEndpoint, 10_000, &raw mut out)
        };
        assert_eq!(rc, TENDRIL_OK, "enroll accept: {}", last_err());
        unsafe { take_cstr(out) };
    });
    let addr = cstr(&host.addr);
    let name = cstr("peer");
    let kind = cstr("machine");
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_endpoint_enroll_initiate(
                peer.ep,
                addr.as_ptr(),
                ptr::null(),
                host_id.as_ptr(),
                host.static_pub.as_ptr(),
                host.signing_pub.as_ptr(),
                host.signing_pub.len(),
                0,
                token.as_ptr(),
                name.as_ptr(),
                kind.as_ptr(),
                &raw mut out,
            )
        },
        TENDRIL_OK,
        "enroll initiate: {}",
        last_err()
    );
    let enrolled: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
    assert_eq!(enrolled["status"], "active");
    accept.join().unwrap();
}

fn create_group(root: &Node, name: &str) -> (String, Value) {
    let name = cstr(name);
    let endpoints = cstr(&serde_json::to_string(&[&root.addr]).unwrap());
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_group_create(root.ep, name.as_ptr(), 1, endpoints.as_ptr(), &raw mut out)
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let manifest: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
    (manifest["group_id"].as_str().unwrap().to_owned(), manifest)
}

fn add_member(root: &Node, gid: &str, member: &Node) -> String {
    add_member_at(root, gid, member, &member.addr)
}

fn add_member_at(root: &Node, gid: &str, member: &Node, addr: &str) -> String {
    let gid = cstr(gid);
    let peer = cstr(&member.id);
    let endpoints = cstr(&serde_json::to_string(&[addr]).unwrap());
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_group_add_member(
                root.ep,
                gid.as_ptr(),
                peer.as_ptr(),
                ptr::null(),
                endpoints.as_ptr(),
                &raw mut out,
            )
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    unsafe { take_cstr(out) }
}

fn ingest(node: &Node, manifest: &str, sender: &str) -> Result<String, (i32, String)> {
    let manifest = cstr(manifest);
    let sender = cstr(sender);
    let mut out = ptr::null_mut();
    let rc = unsafe {
        tendril_group_ingest_manifest(node.ep, manifest.as_ptr(), sender.as_ptr(), &raw mut out)
    };
    if rc == TENDRIL_OK {
        Ok(unsafe { take_cstr(out) })
    } else {
        assert!(out.is_null());
        Err((rc, last_err()))
    }
}

fn free_addr() -> String {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().to_string()
}

fn open(node: &Node, gid: &str) -> *mut TendrilGroup {
    open_at(node, gid, None)
}

fn open_at(node: &Node, gid: &str, listen: Option<&str>) -> *mut TendrilGroup {
    let gid = cstr(gid);
    let listen = listen.map(cstr);
    let mut group = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_group_open(
                node.ep,
                gid.as_ptr(),
                listen.as_ref().map_or(ptr::null(), |l| l.as_ptr()),
                &raw mut group,
            )
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    assert!(!group.is_null());
    group
}

fn wait_event(group: *mut TendrilGroup, want: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(Instant::now() < deadline, "no {want} event in time");
        let mut out = ptr::null_mut();
        match unsafe { tendril_group_poll_event(group, 500, &raw mut out) } {
            TENDRIL_OK => {
                let ev: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
                if ev["event"] == want {
                    return ev;
                }
            }
            TENDRIL_WOULD_BLOCK => {}
            rc => panic!("poll rc {rc}: {}", last_err()),
        }
    }
}

fn broadcast(group: *mut TendrilGroup, data: &[u8]) -> Value {
    let mut out = ptr::null_mut();
    let rc = unsafe {
        tendril_group_broadcast(group, ptr::null(), data.as_ptr(), data.len(), &raw mut out)
    };
    assert_eq!(rc, TENDRIL_OK, "{}", last_err());
    serde_json::from_str(&unsafe { take_cstr(out) }).unwrap()
}

#[test]
fn group_mesh_create_add_open_broadcast_and_revoke() {
    let a = Node::new();
    let b = Node::new();
    let c = Node::new();
    pair(&a, &b);
    pair(&a, &c);

    let (gid, m1) = create_group(&a, "ffi-mesh");
    assert_eq!(m1["seq"], 1);
    assert!(m1.get("group_rendezvous_key").is_none());
    add_member(&a, &gid, &b);
    let manifest = add_member(&a, &gid, &c);
    assert!(!manifest.contains("rendezvous_key"));
    assert_eq!(ingest(&b, &manifest, &a.id).unwrap(), gid);
    assert_eq!(ingest(&c, &manifest, &a.id).unwrap(), gid);

    let ga = open(&a, &gid);
    let gb = open(&b, &gid);
    let gc = open(&c, &gid);

    let report = broadcast(ga, b"hello-mesh");
    let mut delivered: Vec<&str> = report["delivered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    delivered.sort_unstable();
    let mut want = vec![b.id.as_str(), c.id.as_str()];
    want.sort_unstable();
    assert_eq!(delivered, want, "{report}");
    assert!(report["failed"].as_array().unwrap().is_empty(), "{report}");

    for g in [gb, gc] {
        let ev = wait_event(g, "app_data");
        assert!(ev.get("group_id").is_none());
        assert_eq!(ev["sender_device_id"], a.id.as_str());
        let payload = b64url_decode(ev["payload_b64"].as_str().unwrap()).unwrap();
        assert_eq!(payload, b"hello-mesh");
    }

    // Sibling traffic needs only the manifest: B reaches C and A directly.
    let report = broadcast(gb, b"from-b");
    assert_eq!(report["delivered"].as_array().unwrap().len(), 2, "{report}");
    let ev = wait_event(gc, "app_data");
    assert_eq!(ev["sender_device_id"], b.id.as_str());

    let gid_c = cstr(&gid);
    let peer_b = cstr(&b.id);
    let send_cap = cstr(&format!("group.send:{gid}"));
    assert_eq!(
        unsafe { tendril_group_authorize_peer(ga, peer_b.as_ptr(), send_cap.as_ptr()) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let admin_cap = cstr(&format!("group.admin:{gid}"));
    assert_eq!(
        unsafe { tendril_group_authorize_peer(ga, peer_b.as_ptr(), admin_cap.as_ptr()) },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(!last_err().is_empty());

    // Revoke C at the root, then push the manifest to B: B's pool reports it.
    let peer_c = cstr(&c.id);
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_remove_member(a.ep, gid_c.as_ptr(), peer_c.as_ptr(), &raw mut out) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let revoked = unsafe { take_cstr(out) };
    assert_eq!(ingest(&b, &revoked, &a.id).unwrap(), gid);
    let ev = wait_event(gb, "member_revoked");
    assert_eq!(ev["device_id"], c.id.as_str());
    assert_eq!(
        unsafe { tendril_group_authorize_peer(gb, peer_c.as_ptr(), send_cap.as_ptr()) },
        TENDRIL_ERR_PROTOCOL
    );

    for g in [ga, gb, gc] {
        assert_eq!(unsafe { tendril_group_close(g) }, TENDRIL_OK);
        unsafe { tendril_group_free(g) };
    }
}

#[test]
fn group_ingest_refuses_non_signer_and_malformed_input() {
    let a = Node::new();
    let b = Node::new();
    let d = Node::new();
    pair(&a, &b);
    pair(&b, &d);
    let (gid, _) = create_group(&a, "refusals");
    let manifest = add_member(&a, &gid, &b);

    // D is paired with B only; first contact from a peer that is not the root is refused.
    let (rc, msg) = ingest(&d, &manifest, &b.id).unwrap_err();
    assert_eq!(rc, TENDRIL_ERR_PROTOCOL, "{msg}");
    assert!(!msg.is_empty());
    // An unknown sender is refused too.
    let (rc, _) = ingest(&d, &manifest, "not-a-paired-peer").unwrap_err();
    assert_ne!(rc, TENDRIL_OK);
    // Neither refusal stored the group.
    let gid_c = cstr(&gid);
    let mut group = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_open(d.ep, gid_c.as_ptr(), ptr::null(), &raw mut group) },
        TENDRIL_ERR_NOT_FOUND
    );
    assert!(group.is_null());
    // Malformed and unknown-field JSON never reach the book.
    let (rc, _) = ingest(&b, "{not json", &a.id).unwrap_err();
    assert_ne!(rc, TENDRIL_OK);
    let mut tampered: Value = serde_json::from_str(&manifest).unwrap();
    tampered["surprise"] = Value::Bool(true);
    let (rc, _) = ingest(&b, &tampered.to_string(), &a.id).unwrap_err();
    assert_ne!(rc, TENDRIL_OK);
    // The honest push from the root still works.
    assert_eq!(ingest(&b, &manifest, &a.id).unwrap(), gid);

    // Only the root may change membership.
    let peer = cstr(&d.id);
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_group_add_member(
                b.ep,
                gid_c.as_ptr(),
                peer.as_ptr(),
                ptr::null(),
                ptr::null(),
                &raw mut out,
            )
        },
        TENDRIL_ERR_PROTOCOL
    );
    assert!(out.is_null());
}

#[test]
fn group_handle_null_closed_and_free_ordering() {
    let a = Node::new();
    let (gid, _) = create_group(&a, "handles");
    let gid_c = cstr(&gid);
    let name = cstr("x");
    let mut out = ptr::null_mut();

    // Null arguments.
    assert_eq!(
        unsafe {
            tendril_group_create(ptr::null_mut(), name.as_ptr(), 1, ptr::null(), &raw mut out)
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_group_create(a.ep, ptr::null(), 1, ptr::null(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_group_create(a.ep, name.as_ptr(), 1, ptr::null(), ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );
    let bad_json = cstr("{\"not\":\"an array\"}");
    assert_eq!(
        unsafe { tendril_group_create(a.ep, name.as_ptr(), 1, bad_json.as_ptr(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_group_open(a.ep, gid_c.as_ptr(), ptr::null(), ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );
    let mut group: *mut TendrilGroup = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_open(ptr::null_mut(), gid_c.as_ptr(), ptr::null(), &raw mut group) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_group_close(ptr::null_mut()) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe {
            tendril_group_broadcast(ptr::null_mut(), ptr::null(), ptr::null(), 0, &raw mut out)
        },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_group_poll_event(ptr::null_mut(), 0, &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_group_authorize_peer(ptr::null(), name.as_ptr(), name.as_ptr()) },
        TENDRIL_ERR_INVALID_ARG
    );
    unsafe { tendril_group_free(ptr::null_mut()) };

    // Unknown group.
    let missing = cstr("no-such-group");
    assert_eq!(
        unsafe { tendril_group_open(a.ep, missing.as_ptr(), ptr::null(), &raw mut group) },
        TENDRIL_ERR_NOT_FOUND
    );
    assert!(group.is_null());
    assert!(!last_err().is_empty());

    // An in-memory endpoint has no state directory for groups.
    let mem = unsafe { tendril_endpoint_new_from_state(ptr::null(), ptr::null(), ptr::null()) };
    assert!(!mem.is_null());
    assert_eq!(
        unsafe { tendril_group_create(mem, name.as_ptr(), 1, ptr::null(), &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert!(last_err().contains("state directory"));
    unsafe { tendril_endpoint_free(mem) };

    // Close is idempotent, every use after close errors, and free after close is safe.
    let group = open(&a, &gid);
    let data = b"x";
    assert_eq!(
        unsafe { tendril_group_broadcast(group, ptr::null(), ptr::null(), 1, &raw mut out) },
        TENDRIL_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { tendril_group_poll_event(group, 0, &raw mut out) },
        TENDRIL_WOULD_BLOCK
    );
    assert_eq!(unsafe { tendril_group_close(group) }, TENDRIL_OK);
    assert_eq!(unsafe { tendril_group_close(group) }, TENDRIL_OK);
    assert_eq!(
        unsafe { tendril_group_broadcast(group, ptr::null(), data.as_ptr(), 1, &raw mut out) },
        TENDRIL_ERR_CLOSED
    );
    assert_eq!(
        unsafe { tendril_group_poll_event(group, 0, &raw mut out) },
        TENDRIL_ERR_CLOSED
    );
    assert_eq!(
        unsafe { tendril_group_authorize_peer(group, name.as_ptr(), name.as_ptr()) },
        TENDRIL_ERR_CLOSED
    );
    assert!(last_err().contains("closed"));
    unsafe { tendril_group_free(group) };

    // Reopening after close works, and free without close is safe.
    let again = open(&a, &gid);
    unsafe { tendril_group_free(again) };

    // A handle outlives its endpoint's close: the pool is shut down and reports EOF.
    let last = open(&a, &gid);
    assert_eq!(unsafe { tendril_endpoint_close(a.ep) }, TENDRIL_OK);
    assert_eq!(
        unsafe { tendril_group_poll_event(last, 10, &raw mut out) },
        tendril_ffi::TENDRIL_EOF
    );
    unsafe { tendril_group_free(last) };
}

#[test]
fn ordinary_sessions_still_arrive_while_groups_are_open() {
    let a = Node::new();
    let b = Node::new();
    pair(&a, &b);
    let (gid, _) = create_group(&a, "coexist");
    let group = open(&a, &gid);

    let a_ep = a.ep as usize;
    let accept = thread::spawn(move || {
        let sess = unsafe { tendril_session_accept(a_ep as *mut TendrilEndpoint, 10_000) };
        assert!(!sess.is_null(), "accept: {}", last_err());
        sess as usize
    });
    let addr = cstr(&a.addr);
    let target = cstr(&a.id);
    let client = unsafe {
        tendril_session_connect(
            b.ep,
            addr.as_ptr(),
            ptr::null(),
            target.as_ptr(),
            ptr::null(),
        )
    };
    assert!(!client.is_null(), "connect: {}", last_err());
    let server = accept.join().unwrap() as *mut tendril_ffi::TendrilSession;
    unsafe {
        tendril_session_shutdown(client);
        tendril_session_shutdown(server);
        tendril_session_free(client);
        tendril_session_free(server);
        tendril_group_free(group);
    }
}

#[test]
fn wire_v2_group_needs_sync_then_siblings_broadcast() {
    let a = Node::new();
    let b = Node::new();
    let c = Node::new();
    pair(&a, &b);
    pair(&a, &c);

    let name = cstr("v2-mesh");
    let endpoints = cstr(&serde_json::to_string(&[&a.addr]).unwrap());
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_create(a.ep, name.as_ptr(), 2, endpoints.as_ptr(), &raw mut out) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let created: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
    let gid = created["group_id"].as_str().unwrap().to_owned();
    assert_eq!(created["min_wire_version"], 2);
    let (addr_b, addr_c) = (free_addr(), free_addr());
    add_member_at(&a, &gid, &b, &addr_b);
    let manifest = add_member_at(&a, &gid, &c, &addr_c);
    assert_eq!(ingest(&b, &manifest, &a.id).unwrap(), gid);
    assert_eq!(ingest(&c, &manifest, &a.id).unwrap(), gid);

    let ga = open(&a, &gid);
    let gb = open_at(&b, &gid, Some(&addr_b));
    let gc = open_at(&c, &gid, Some(&addr_c));

    // Root sync pushes the manifest and rendezvous key to each member over its ordinary paired
    // session; the members only run a pool listener.
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_sync(ga, &raw mut out) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let report: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
    assert_eq!(report["delivered"].as_array().unwrap().len(), 2, "{report}");

    // The members' open pools pick the pushed key up through the book watcher.
    let deadline = Instant::now() + Duration::from_secs(15);
    let report = loop {
        let report = broadcast(gb, b"v2-from-b");
        if report["delivered"].as_array().unwrap().len() == 2 || Instant::now() > deadline {
            break report;
        }
        thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(report["delivered"].as_array().unwrap().len(), 2, "{report}");
    for g in [ga, gc] {
        let ev = wait_event(g, "app_data");
        assert_eq!(ev["sender_device_id"], b.id.as_str());
        let payload = b64url_decode(ev["payload_b64"].as_str().unwrap()).unwrap();
        assert_eq!(payload, b"v2-from-b");
    }
    for g in [ga, gb, gc] {
        unsafe { tendril_group_free(g) };
    }
}

#[test]
fn group_open_with_listener_reports_bound_endpoint() {
    let a = Node::new();
    let (gid, _) = create_group(&a, "listener");
    let gid_c = cstr(&gid);
    let listen = cstr("127.0.0.1:0");
    let mut group = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_open(a.ep, gid_c.as_ptr(), listen.as_ptr(), &raw mut group) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let mut ep = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_local_endpoint(group, &raw mut ep) },
        TENDRIL_OK
    );
    let bound = unsafe { take_cstr(ep) };
    assert!(bound.contains("127.0.0.1:"), "{bound}");

    let plain = open(&a, &gid);
    let mut ep = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_local_endpoint(plain, &raw mut ep) },
        TENDRIL_OK
    );
    assert!(ep.is_null());

    let bad = cstr("not-an-addr");
    let mut rejected = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_open(a.ep, gid_c.as_ptr(), bad.as_ptr(), &raw mut rejected) },
        TENDRIL_ERR_INVALID_ARG
    );
    unsafe {
        tendril_group_free(group);
        tendril_group_free(plain);
    }
}

/// Pushes a fresh group's manifest and rendezvous key from root `a` to `b` over an ordinary
/// session and returns the group id, the manifest, and the `group_*` events `b` reported.
fn push_group_over_session(a: &Node, b: &Node) -> (String, GroupManifest, Vec<Value>) {
    let (gid, _) = create_group(a, "unverified");
    let manifest_json = add_member(a, &gid, b);
    let secrets = StateStore::open_or_create(a.dir.path())
        .unwrap()
        .load_group_book()
        .unwrap()
        .secrets(&gid)
        .cloned()
        .unwrap();
    let manifest = GroupManifest::from_wire_bytes(manifest_json.as_bytes()).unwrap();

    let b_ep = b.ep as usize;
    let accept = thread::spawn(move || {
        let sess = unsafe { tendril_session_accept(b_ep as *mut TendrilEndpoint, 10_000) };
        assert!(!sess.is_null(), "accept: {}", last_err());
        let mut events = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        while events.len() < 2 && Instant::now() < deadline {
            let mut out = ptr::null_mut();
            match unsafe { tendril_session_poll_event(sess, 500, &raw mut out) } {
                TENDRIL_OK => {
                    let ev: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
                    if ev["event"].as_str().unwrap().starts_with("group_") {
                        events.push(ev);
                    }
                }
                TENDRIL_WOULD_BLOCK => {}
                rc => panic!("poll rc {rc}: {}", last_err()),
            }
        }
        unsafe {
            tendril_session_shutdown(sess);
            tendril_session_free(sess);
        }
        events
    });

    let store = StateStore::open_or_create(a.dir.path()).unwrap();
    let identity = store.load_or_generate_identity(None).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let stream = DirectDialer::new().dial(&b.addr).await.unwrap();
        let mut roster = store.load_roster().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut session = SessionDriver::connect(stream, &identity, &b.id, None, &mut roster, now)
            .await
            .unwrap();
        session.send_group_manifest(&manifest).await.unwrap();
        session.send_group_rendezvous(&secrets, &gid).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    (gid, manifest, accept.join().unwrap())
}

#[test]
fn session_group_frames_are_ingested_by_the_runtime_and_report_a_redacted_outcome() {
    let a = Node::new();
    let b = Node::new();
    pair(&a, &b);
    let (gid, manifest, events) = push_group_over_session(&a, &b);
    assert_eq!(events.len(), 2, "{events:?}");
    let manifest_ev = &events[0];
    assert_eq!(manifest_ev["event"], "group_manifest_ingested");
    assert_eq!(manifest_ev["group_id"], gid.as_str());
    assert_eq!(manifest_ev["seq"], manifest.seq);
    assert!(manifest_ev.get("manifest_json").is_none(), "{manifest_ev}");
    let stored = StateStore::open_or_create(b.dir.path())
        .unwrap()
        .load_group_book()
        .unwrap();
    assert_eq!(stored.manifest(&gid).unwrap().seq, manifest.seq);
    let key_ev = &events[1];
    assert_eq!(key_ev["event"], "group_rendezvous_ingested", "{key_ev}");
    assert_eq!(key_ev["group_id"], gid.as_str());
    let mut keys: Vec<&str> = key_ev
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["event", "group_id", "seq"]);
}

fn sealed_store(node: &Node) -> StateStore {
    let identity = deserialize_identity_json(&node.identity_json()).unwrap();
    StateStore::open_sealed(node.dir.path(), &identity).unwrap()
}

#[test]
fn sealed_endpoint_hosts_group_across_restart() {
    let a = Node::new();
    let mut b = Node::sealed();
    pair(&a, &b);
    let (gid, _) = create_group(&a, "sealed-mesh");
    let addr_b = free_addr();
    let manifest = add_member_at(&a, &gid, &b, &addr_b);
    assert_eq!(ingest(&b, &manifest, &a.id).unwrap(), gid);

    let ga = open(&a, &gid);
    let gb = open_at(&b, &gid, Some(&addr_b));
    let report = broadcast(ga, b"before-restart");
    assert_eq!(report["delivered"][0], b.id.as_str(), "{report}");
    let ev = wait_event(gb, "app_data");
    assert_eq!(
        b64url_decode(ev["payload_b64"].as_str().unwrap()).unwrap(),
        b"before-restart"
    );
    unsafe { tendril_group_free(gb) };

    let names: Vec<String> = std::fs::read_dir(b.dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(names.iter().any(|n| n == "rt-groups.sealed"), "{names:?}");
    assert!(names.iter().any(|n| n == "rt-roster.sealed"), "{names:?}");
    for plain in ["identity.json", "roster.json", "groups.json"] {
        assert!(!names.iter().any(|n| n == plain), "{names:?}");
    }
    let sealed = std::fs::read(b.dir.path().join("rt-groups.sealed")).unwrap();
    let contains = |needle: &[u8]| sealed.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(gid.as_bytes()));
    assert!(!contains(b"group_rendezvous_key"));
    let root_book = StateStore::open_or_create(a.dir.path())
        .unwrap()
        .load_group_book()
        .unwrap();
    let key = root_book.secrets(&gid).unwrap().group_rendezvous_key();
    assert!(!contains(key));
    assert!(!contains(
        tendril_core::crypto::b64url_encode(key).as_bytes()
    ));
    let persisted = StateStore::open_sealed(
        b.dir.path(),
        &tendril_runtime::deserialize_identity_json(&b.identity_json()).unwrap(),
    )
    .unwrap()
    .load_group_book()
    .unwrap();
    assert!(
        tendril_core::group::is_active_member(persisted.manifest(&gid).unwrap(), &b.id),
        "the ingested manifest is durable before the restart"
    );

    b.restart_sealed();
    let gb = open_at(&b, &gid, Some(&addr_b));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let report = broadcast(ga, b"after-restart");
        if report["delivered"].as_array().unwrap().len() == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "{report}");
        thread::sleep(Duration::from_millis(200));
    }
    let ev = wait_event(gb, "app_data");
    assert_eq!(
        b64url_decode(ev["payload_b64"].as_str().unwrap()).unwrap(),
        b"after-restart"
    );
    unsafe {
        tendril_group_free(gb);
        tendril_group_free(ga);
    }

    // Fail closed: another identity, no identity, or a tampered file never open the state.
    let identity = b.identity_json();
    unsafe {
        tendril_endpoint_close(b.ep);
        tendril_endpoint_free(b.ep);
    }
    b.ep = ptr::null_mut();
    let other = Node::sealed().identity_json();
    let err = open_sealed(b.dir.path(), Some(&other)).unwrap_err();
    assert!(
        err.contains("sealed roster state cannot be opened"),
        "{err}"
    );
    let err = open_sealed(b.dir.path(), None).unwrap_err();
    assert!(
        err.contains("sealed runtime state exists but no identity was supplied"),
        "{err}"
    );
    let path = b.dir.path().join("rt-groups.sealed");
    let mut tampered = std::fs::read(&path).unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    std::fs::write(&path, &tampered).unwrap();
    let err = open_sealed(b.dir.path(), Some(&identity)).unwrap_err();
    assert!(
        err.contains("sealed groups state cannot be opened"),
        "{err}"
    );
    tampered[0] = 0x07;
    std::fs::write(&path, &tampered).unwrap();
    let err = open_sealed(b.dir.path(), Some(&identity)).unwrap_err();
    assert!(err.contains("unsupported sealed state version 7"), "{err}");
    let err = unsafe {
        let ep = tendril_endpoint_new_sealed(ptr::null(), ptr::null(), ptr::null(), ptr::null());
        assert!(ep.is_null());
        last_err()
    };
    assert!(err.contains("state_dir"), "{err}");
}

#[test]
fn sealed_endpoints_independent_handles() {
    let root = Node::sealed();
    let c = Node::new();
    let d = Node::new();
    pair(&root, &c);
    pair(&root, &d);
    let (gid, _) = create_group(&root, "two-handles");
    add_member(&root, &gid, &c);

    let second = open_sealed(root.dir.path(), Some(&root.identity_json())).unwrap();
    let gid_c = cstr(&gid);
    let peer_c = cstr(&c.id);
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_group_remove_member(root.ep, gid_c.as_ptr(), peer_c.as_ptr(), &raw mut out)
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    unsafe { take_cstr(out) };

    let peer_d = cstr(&d.id);
    let endpoints = cstr(&serde_json::to_string(&[&d.addr]).unwrap());
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            tendril_group_add_member(
                second,
                gid_c.as_ptr(),
                peer_d.as_ptr(),
                ptr::null(),
                endpoints.as_ptr(),
                &raw mut out,
            )
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let latest = GroupManifest::from_wire_bytes(unsafe { take_cstr(out) }.as_bytes()).unwrap();
    assert!(latest.revoked_members.contains(&c.id), "removal undone");
    unsafe { tendril_endpoint_free(second) };

    let book = sealed_store(&root).load_group_book().unwrap();
    let stored = book.manifest(&gid).unwrap();
    assert_eq!(stored.seq, latest.seq);
    assert!(!tendril_core::group::is_active_member(stored, &c.id));
    assert!(tendril_core::group::is_active_member(stored, &d.id));
}

#[test]
fn sealed_endpoint_ingests_session_group_frames() {
    let a = Node::new();
    let b = Node::sealed();
    pair(&a, &b);
    let (gid, manifest, events) = push_group_over_session(&a, &b);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["event"], "group_manifest_ingested", "{events:?}");
    assert_eq!(
        events[1]["event"], "group_rendezvous_ingested",
        "{events:?}"
    );
    let book = sealed_store(&b).load_group_book().unwrap();
    assert_eq!(book.manifest(&gid).unwrap().seq, manifest.seq);
    assert!(book.secrets(&gid).is_some());
}

#[test]
fn group_close_wakes_a_parked_poll_promptly() {
    let a = Node::new();
    let (gid, _) = create_group(&a, "close-wake");
    let group = open(&a, &gid);

    let handle = group as usize;
    let poller = thread::spawn(move || {
        let started = Instant::now();
        let mut out = ptr::null_mut();
        let rc =
            unsafe { tendril_group_poll_event(handle as *mut TendrilGroup, 30_000, &raw mut out) };
        (rc, started.elapsed())
    });
    thread::sleep(Duration::from_millis(300));
    assert_eq!(unsafe { tendril_group_close(group) }, TENDRIL_OK);
    let (rc, elapsed) = poller.join().unwrap();
    assert_eq!(rc, tendril_ffi::TENDRIL_EOF);
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");

    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_poll_event(group, 30_000, &raw mut out) },
        TENDRIL_ERR_CLOSED
    );
    unsafe { tendril_group_free(group) };
}

#[test]
fn group_listener_port_is_reusable_after_close_and_free() {
    let a = Node::new();
    let (gid, _) = create_group(&a, "port-reuse");
    let addr = free_addr();

    let first = open_at(&a, &gid, Some(&addr));
    assert_eq!(unsafe { tendril_group_close(first) }, TENDRIL_OK);
    unsafe { tendril_group_free(first) };

    let second = open_at(&a, &gid, Some(&addr));
    unsafe { tendril_group_free(second) };

    let third = open_at(&a, &gid, Some(&addr));
    unsafe { tendril_group_free(third) };
}

#[test]
fn parked_session_accept_does_not_steal_group_streams() {
    let a = Node::new();
    let b = Node::new();
    pair(&a, &b);
    let (gid, _) = create_group(&a, "no-steal");
    let manifest = add_member(&a, &gid, &b);
    assert_eq!(ingest(&b, &manifest, &a.id).unwrap(), gid);

    let a_ep = a.ep as usize;
    let parked = thread::spawn(move || {
        let sess = unsafe { tendril_session_accept(a_ep as *mut TendrilEndpoint, 20_000) };
        if !sess.is_null() {
            unsafe { tendril_session_free(sess) };
        }
    });
    thread::sleep(Duration::from_millis(300));

    let ga = open(&a, &gid);
    let gb = open(&b, &gid);
    let report = broadcast(gb, b"through-the-pump");
    assert_eq!(report["delivered"].as_array().unwrap().len(), 1, "{report}");
    let ev = wait_event(ga, "app_data");
    assert_eq!(ev["sender_device_id"], b.id.as_str());

    assert_eq!(unsafe { tendril_endpoint_close(a.ep) }, TENDRIL_OK);
    parked.join().unwrap();
    unsafe {
        tendril_group_free(ga);
        tendril_group_free(gb);
    }
}

#[test]
fn parked_accept_switches_to_group_channels_when_the_runtime_starts() {
    let a = Node::new();
    let b = Node::new();
    pair(&a, &b);
    let (gid, _) = create_group(&a, "parked-switch");

    let a_ep = a.ep as usize;
    let started = Instant::now();
    let parked = thread::spawn(move || {
        let sess = unsafe { tendril_session_accept(a_ep as *mut TendrilEndpoint, 30_000) };
        assert!(!sess.is_null(), "parked accept: {}", last_err());
        (sess as usize, started.elapsed())
    });
    thread::sleep(Duration::from_millis(300));

    let group = open(&a, &gid);
    let addr = cstr(&a.addr);
    let target = cstr(&a.id);
    let client = unsafe {
        tendril_session_connect(
            b.ep,
            addr.as_ptr(),
            ptr::null(),
            target.as_ptr(),
            ptr::null(),
        )
    };
    assert!(!client.is_null(), "connect: {}", last_err());
    let (server, elapsed) = parked.join().unwrap();
    assert!(
        elapsed < Duration::from_secs(10),
        "parked accept waited {elapsed:?}"
    );
    let server = server as *mut tendril_ffi::TendrilSession;
    unsafe {
        tendril_session_shutdown(client);
        tendril_session_shutdown(server);
        tendril_session_free(client);
        tendril_session_free(server);
        tendril_group_free(group);
    }
}

#[test]
fn sibling_stream_queued_before_group_open_is_not_refused() {
    let a = Node::new();
    let b = Node::new();
    pair(&a, &b);
    let (gid, _) = create_group(&a, "queued-sibling");
    let manifest = add_member(&a, &gid, &b);
    assert_eq!(ingest(&b, &manifest, &a.id).unwrap(), gid);

    let gb = open(&b, &gid) as usize;
    let sender = thread::spawn(move || broadcast(gb as *mut TendrilGroup, b"queued-first"));
    thread::sleep(Duration::from_millis(500));

    let ga = open(&a, &gid);
    let report = sender.join().unwrap();
    assert_eq!(report["delivered"].as_array().unwrap().len(), 1, "{report}");
    let ev = wait_event(ga, "app_data");
    assert_eq!(ev["sender_device_id"], b.id.as_str());
    unsafe {
        tendril_group_free(ga);
        tendril_group_free(gb as *mut TendrilGroup);
    }
}

/// A parked accept on its own thread. Dropping it closes the endpoint, which wakes the accept, and
/// joins the thread; declare it after the `Node`s so an unwinding assertion cannot free the
/// endpoint under the parked call.
struct AcceptThread {
    ep: usize,
    handle: Option<thread::JoinHandle<(usize, Option<String>)>>,
}

impl AcceptThread {
    fn spawn(ep: *mut TendrilEndpoint, v2: bool, timeout_ms: u64) -> Self {
        let ep = ep as usize;
        let handle = thread::spawn(move || {
            let ep = ep as *mut TendrilEndpoint;
            let sess = if v2 {
                unsafe { tendril_session_accept_v2(ep, timeout_ms) }
            } else {
                unsafe { tendril_session_accept(ep, timeout_ms) }
            };
            let err = sess.is_null().then(last_err);
            (sess as usize, err)
        });
        Self {
            ep,
            handle: Some(handle),
        }
    }

    fn join_with_err(mut self) -> (*mut tendril_ffi::TendrilSession, Option<String>) {
        let (sess, err) = self.handle.take().unwrap().join().unwrap();
        (sess as *mut tendril_ffi::TendrilSession, err)
    }

    fn join(self) -> *mut tendril_ffi::TendrilSession {
        self.join_with_err().0
    }

    fn close_and_join(self) -> (*mut tendril_ffi::TendrilSession, Option<String>) {
        unsafe { tendril_endpoint_close(self.ep as *mut TendrilEndpoint) };
        self.join_with_err()
    }
}

impl Drop for AcceptThread {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            unsafe { tendril_endpoint_close(self.ep as *mut TendrilEndpoint) };
            let sess = handle.join().map_or(0, |(s, _)| s) as *mut tendril_ffi::TendrilSession;
            if !sess.is_null() {
                unsafe { tendril_session_free(sess) };
            }
        }
    }
}

fn assert_second_accept_times_out(ep: *mut TendrilEndpoint, v2: bool, expected_err: &str) {
    let started = Instant::now();
    let sess = if v2 {
        unsafe { tendril_session_accept_v2(ep, 100) }
    } else {
        unsafe { tendril_session_accept(ep, 100) }
    };
    let elapsed = started.elapsed();
    assert!(sess.is_null(), "second accept unexpectedly got a session");
    assert_eq!(last_err(), expected_err);
    assert!(
        elapsed >= Duration::from_millis(90) && elapsed < Duration::from_secs(5),
        "second accept took {elapsed:?}"
    );
}

#[test]
fn concurrent_group_accepts_honour_each_callers_deadline() {
    let a = Node::new();
    let b = Node::new();
    pair(&a, &b);
    let (gid, _) = create_group(&a, "accept-deadline");
    let group = open(&a, &gid);

    let first = AcceptThread::spawn(a.ep, false, 20_000);
    thread::sleep(Duration::from_millis(300));
    assert_second_accept_times_out(a.ep, false, "timed out accepting session");

    let addr = cstr(&a.addr);
    let target = cstr(&a.id);
    let client = unsafe {
        tendril_session_connect(
            b.ep,
            addr.as_ptr(),
            ptr::null(),
            target.as_ptr(),
            ptr::null(),
        )
    };
    assert!(!client.is_null(), "connect: {}", last_err());
    let server = first.join();
    assert!(!server.is_null(), "first accept: {}", last_err());
    unsafe {
        tendril_session_shutdown(client);
        tendril_session_shutdown(server);
        tendril_session_free(client);
        tendril_session_free(server);
        tendril_group_free(group);
    }
}

#[test]
fn concurrent_group_accepts_honour_each_callers_deadline_v2() {
    let a = Node::new();
    let b = Node::new();
    pair(&a, &b);
    let (gid, _) = create_group(&a, "accept-deadline-v2");
    let group = open(&a, &gid);

    let first = AcceptThread::spawn(a.ep, true, 20_000);
    thread::sleep(Duration::from_millis(300));
    assert_second_accept_times_out(a.ep, true, "timed out accepting v2 session");

    let (sess, err) = first.close_and_join();
    assert!(sess.is_null());
    assert_eq!(err.as_deref(), Some("listener closed"));
    unsafe { tendril_group_free(group) };
}

const RELAY_SECRET: &str = "tendril-group-relay-hmac-secret-32";

fn configure_relay_auth(node: &Node) {
    let cfg = cstr(&format!(r#"{{"relay_auth_secret":"{RELAY_SECRET}"}}"#));
    assert_eq!(
        unsafe { tendril_endpoint_configure_transports_json(node.ep, cfg.as_ptr()) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
}

/// The group mailbox `node` registers on a relay, once its store holds the group key.
fn group_mailbox(node: &Node, gid: &str) -> Option<[u8; 32]> {
    let book = StateStore::open_or_create(node.dir.path())
        .unwrap()
        .load_group_book()
        .unwrap();
    let secrets = book.secrets(gid)?;
    Some(*tendril_core::group::derive_group_mailbox_secret(
        secrets.group_rendezvous_key(),
        secrets.seq(),
        &node.id,
    ))
}

/// Dials `mailbox` on the auth-required relay the way a sibling does: it answers once the
/// mailbox has a registration.
fn mailbox_registered(rt: &tokio::runtime::Runtime, url: &str, mailbox: [u8; 32]) -> bool {
    let secret =
        tendril_core::relay_auth::RelayAuthSecret::from_bytes(RELAY_SECRET.as_bytes()).unwrap();
    let epoch = tendril_core::v2::epoch_for_unix(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    rt.block_on(
        RelayV2Dialer::new(mailbox)
            .with_auth(RelayClientAuth::HmacSecret(secret))
            .connect_for_epoch(url, epoch),
    )
    .is_ok()
}

fn wait_mailbox_registered(rt: &tokio::runtime::Runtime, url: &str, node: &Node, gid: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(mailbox) = group_mailbox(node, gid)
            && mailbox_registered(rt, url, mailbox)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "group mailbox of {} never registered on the relay",
            node.id
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn ffi_group_hub_serves_and_dials_v2_relay_with_relay_auth() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt
        .block_on(EmbeddedRelay::start(tendril_relay::RelayConfig {
            host: "127.0.0.1".to_owned(),
            auth_secret: Some(zeroize::Zeroizing::new(RELAY_SECRET.as_bytes().to_vec())),
            auth_scope: tendril_core::relay_auth::RelayAuthScope::All,
            ..tendril_relay::RelayConfig::default()
        }))
        .unwrap();
    let url = relay.ws_v2_url();

    let a = Node::new();
    let b = Node::new();
    configure_relay_auth(&a);
    configure_relay_auth(&b);
    pair(&a, &b);

    // `a` is reachable only through the relay. `b` also runs a pool listener, so the root can push
    // the group key to it; `b` dials `a` over the relay alone.
    let addr_b = free_addr();
    let name = cstr("relay-auth");
    let endpoints = cstr(&serde_json::to_string(&[&url]).unwrap());
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_create(a.ep, name.as_ptr(), 2, endpoints.as_ptr(), &raw mut out) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let created: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
    let gid = created["group_id"].as_str().unwrap().to_owned();
    let hints = cstr(&serde_json::to_string(&[addr_b.as_str(), url.as_str()]).unwrap());
    let gid_c = cstr(&gid);
    let peer = cstr(&b.id);
    assert_eq!(
        unsafe {
            tendril_group_add_member(
                a.ep,
                gid_c.as_ptr(),
                peer.as_ptr(),
                ptr::null(),
                hints.as_ptr(),
                &raw mut out,
            )
        },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let manifest = unsafe { take_cstr(out) };
    assert_eq!(ingest(&b, &manifest, &a.id).unwrap(), gid);

    // No stream has reached either endpoint: opening the group starts the hub, and the pool's
    // book watcher registers the root's group mailbox by itself, with the relay auth.
    let ga = open(&a, &gid);
    let gb = open_at(&b, &gid, Some(&addr_b));
    wait_mailbox_registered(&rt, &url, &a, &gid);

    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_sync(ga, &raw mut out) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let report: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
    assert_eq!(report["delivered"], serde_json::json!([b.id]), "{report}");

    // With the key pushed, the member registers its own group mailbox as well.
    wait_mailbox_registered(&rt, &url, &b, &gid);

    let deadline = Instant::now() + Duration::from_secs(15);
    let report = loop {
        let report = broadcast(gb, b"over the relay");
        if report["delivered"] == serde_json::json!([a.id]) || Instant::now() > deadline {
            break report;
        }
        thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(report["delivered"], serde_json::json!([a.id]), "{report}");
    let ev = wait_event(ga, "app_data");
    assert_eq!(ev["sender_device_id"], b.id.as_str());
    assert_eq!(
        b64url_decode(ev["payload_b64"].as_str().unwrap()).unwrap(),
        b"over the relay"
    );
    for g in [ga, gb] {
        unsafe { tendril_group_free(g) };
    }
}

/// Dials the identity mailbox `relay_pub` on a `/v1/relay` URL the way a peer does: `Ok(true)`
/// once something is registered there, `Ok(false)` while the relay answers `offline`.
fn v1_mailbox_registered(
    rt: &tokio::runtime::Runtime,
    url: &str,
    relay_pub: &[u8; 32],
) -> Result<bool, String> {
    match rt.block_on(RelayDialer::new().connect(url, relay_pub)) {
        Ok(_) => Ok(true),
        Err(e) if e.to_string().contains("offline") => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

#[test]
fn ffi_group_hub_leaves_a_served_v1_relay_mailbox_to_the_app() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt
        .block_on(EmbeddedRelay::start(tendril_relay::RelayConfig {
            host: "127.0.0.1".to_owned(),
            ..tendril_relay::RelayConfig::default()
        }))
        .unwrap();
    // A second relay addressed as `localhost` is the control: its canonical host differs from the
    // served `127.0.0.1` while both bind plain 127.0.0.1 (the only loopback address every CI
    // host configures). The app does not serve it, so the pool registers the identity there, and
    // that registration is the observable proof that the pool's mailbox plan ran.
    let control = rt
        .block_on(EmbeddedRelay::start(tendril_relay::RelayConfig {
            host: "localhost".to_owned(),
            ..tendril_relay::RelayConfig::default()
        }))
        .unwrap();
    let v1_url = relay.ws_url();
    let control_url = format!("ws://localhost:{}/v1/relay", control.local_addr().port());

    let a = Node::new();
    let b = Node::new();
    pair(&a, &b);
    let url_c = cstr(&v1_url);
    let mut served = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_endpoint_serve_relay(a.ep, url_c.as_ptr(), ptr::null(), &raw mut served) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let served = unsafe { take_cstr(served) };
    let relay_pub = b64url_decode_array::<32>(served.rsplit('#').next().unwrap()).unwrap();
    let served = cstr(&served);

    // The root's own entry names both relays, the served one first. The app serves the first
    // mailbox, so the hub must not register a pool on it: ordinary sessions keep arriving
    // through the app. The second relay is not served, so the hub registers the identity there.
    let name = cstr("served-v1");
    let endpoints = cstr(&serde_json::to_string(&[&v1_url, &control_url]).unwrap());
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { tendril_group_create(a.ep, name.as_ptr(), 1, endpoints.as_ptr(), &raw mut out) },
        TENDRIL_OK,
        "{}",
        last_err()
    );
    let created: Value = serde_json::from_str(&unsafe { take_cstr(out) }).unwrap();
    let group = open(&a, created["group_id"].as_str().unwrap());

    // Both mailbox tasks of the plan start in one watcher pass, so once the control is
    // registered the pool has already had its chance at the served host.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !v1_mailbox_registered(&rt, &control_url, &relay_pub).unwrap() {
        assert!(
            Instant::now() < deadline,
            "the pool never registered the identity on the unserved relay"
        );
        thread::sleep(Duration::from_millis(100));
    }

    // The accept runs in a scoped thread that always joins before any assertion, so no failure
    // can free the endpoint while the thread still uses it.
    let a_ep = a.ep as usize;
    let b_ep = b.ep as usize;
    let (client, server) = thread::scope(|scope| {
        let accept = scope.spawn(move || {
            (unsafe { tendril_session_accept(a_ep as *mut TendrilEndpoint, 10_000) }) as usize
        });
        let target = cstr(&a.id);
        let client = unsafe {
            tendril_session_connect(
                b_ep as *mut TendrilEndpoint,
                served.as_ptr(),
                ptr::null(),
                target.as_ptr(),
                ptr::null(),
            )
        };
        (
            client,
            accept.join().unwrap() as *mut tendril_ffi::TendrilSession,
        )
    });
    let outcome = format!(
        "connect null: {}, accept null: {}",
        client.is_null(),
        server.is_null()
    );
    unsafe {
        for s in [client, server] {
            if !s.is_null() {
                tendril_session_shutdown(s);
                tendril_session_free(s);
            }
        }
        tendril_group_free(group);
    }
    assert!(
        !client.is_null() && !server.is_null(),
        "the app's served mailbox was displaced: {outcome}"
    );
}
