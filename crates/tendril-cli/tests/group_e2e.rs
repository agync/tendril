//! Hermetic three-node `tendril group` flow over loopback: A roots, B and C pair only with A.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const EVENT_TIMEOUT: Duration = Duration::from_secs(20);

fn tendril_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tendril")
}

fn run(state_dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .output()
        .expect("run tendril bin")
}

fn run_ok(state_dir: &Path, args: &[&str]) -> serde_json::Value {
    let out = run(state_dir, args);
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?} stdout not json ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe");
    listener.local_addr().expect("probe addr").to_string()
}

struct Serve {
    child: Child,
    events: Receiver<serde_json::Value>,
    listening: serde_json::Value,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Serve {
    fn start(state_dir: &Path, listen: &str, extra: &[&str]) -> Self {
        let mut child = Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(state_dir)
            .args(["serve", "--listen", listen])
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn serve");
        let stdout = child.stdout.take().expect("serve stdout");
        let (tx, events) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value) = serde_json::from_str(&line)
                    && tx.send(value).is_err()
                {
                    break;
                }
            }
        });
        let mut serve = Self {
            child,
            events,
            listening: serde_json::Value::Null,
        };
        serve.listening = serve.wait_event("listening");
        assert_eq!(serve.listening["direct_endpoint"], listen);
        serve
    }

    fn wait_event(&self, name: &str) -> serde_json::Value {
        self.wait_matching(name, |_| true)
    }

    fn wait_matching(
        &self,
        name: &str,
        pred: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        let deadline = Instant::now() + EVENT_TIMEOUT;
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            let ev = self
                .events
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("timed out waiting for event {name}"));
            if ev["event"] == name && pred(&ev) {
                return ev;
            }
        }
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn device_id(dir: &Path) -> String {
    run_ok(dir, &["init"])["device_id"]
        .as_str()
        .expect("device_id")
        .to_owned()
}

/// Enrolls `peer_dir` with the root over the M2M flow, which records the peer's signing key.
fn enroll_with_root(root_dir: &Path, root: &serde_json::Value, serve: &Serve, peer_dir: &Path) {
    let root_id = root["device_id"].as_str().expect("root id");
    let peer_id = device_id(peer_dir);
    let token = root_dir.join(format!("enroll-{peer_id}.json"));
    let minted = run(
        root_dir,
        &[
            "enroll-token",
            "--target-host",
            root_id,
            "--subject",
            &peer_id,
            "--out",
            token.to_str().expect("token path"),
        ],
    );
    assert!(
        minted.status.success(),
        "enroll-token: {}",
        String::from_utf8_lossy(&minted.stderr)
    );
    let enrolled = run(
        peer_dir,
        &[
            "enroll",
            "--endpoint",
            serve.listening["direct_endpoint"].as_str().expect("ep"),
            "--host-id",
            root_id,
            "--host-static-pub",
            root["static_pub"].as_str().expect("static"),
            "--host-signing-pub",
            root["signing_pub"].as_str().expect("signing"),
            "--token-file",
            token.to_str().expect("token path"),
        ],
    );
    assert!(
        enrolled.status.success(),
        "enroll: {}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    serve.wait_event("enrolled");
}

fn names(report: &serde_json::Value, key: &str) -> Vec<String> {
    report[key]
        .as_array()
        .expect("report array")
        .iter()
        .map(|v| {
            v.as_str()
                .or_else(|| v[0].as_str())
                .expect("device id entry")
                .to_owned()
        })
        .collect()
}

#[test]
fn group_e2e_create_add_sync_broadcast_remove() {
    let a_dir = TempDir::new().expect("a dir");
    let b_dir = TempDir::new().expect("b dir");
    let c_dir = TempDir::new().expect("c dir");
    let (a_dir, b_dir, c_dir) = (a_dir.path(), b_dir.path(), c_dir.path());
    let (a_addr, b_addr, c_addr) = (free_addr(), free_addr(), free_addr());

    let a_info = run_ok(a_dir, &["init"]);
    let a_id = a_info["device_id"].as_str().expect("a id").to_owned();
    let b_id = device_id(b_dir);
    let c_id = device_id(c_dir);
    let enroll_serve = Serve::start(a_dir, &a_addr, &["--allow-enroll"]);
    enroll_with_root(a_dir, &a_info, &enroll_serve, b_dir);
    enroll_with_root(a_dir, &a_info, &enroll_serve, c_dir);
    enroll_serve.stop();

    let created = run_ok(
        a_dir,
        &[
            "group",
            "create",
            "--name",
            "trio",
            "--endpoint",
            &format!("direct:{a_addr}"),
        ],
    );
    let gid = created["group_id"].as_str().expect("group id").to_owned();
    assert_eq!(created["seq"], 1);

    let stranger = run(
        a_dir,
        &["group", "add", &gid, "--peer", "dev_0000000000000000"],
    );
    assert!(!stranger.status.success(), "unknown peer must fail closed");

    let added_b = run_ok(
        a_dir,
        &[
            "group",
            "add",
            &gid,
            "--peer",
            &b_id,
            "--endpoint",
            &format!("direct:{b_addr}"),
        ],
    );
    assert_eq!(added_b["seq"], 2);
    let added_c = run_ok(
        a_dir,
        &["group", "add", &gid, "--peer", &c_id, "--endpoint", &c_addr],
    );
    assert_eq!(added_c["seq"], 3);
    assert_eq!(added_c["members"].as_array().expect("members").len(), 3);

    let listed = run(a_dir, &["group", "list"]);
    let shown = run(a_dir, &["group", "show", &gid]);
    for out in [&listed, &shown] {
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("rendezvous_key"), "secret leaked: {text}");
    }
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("list json");
    assert_eq!(listed["groups"][0]["role"], "root");
    assert_eq!(listed["groups"][0]["seq"], 3);

    let b_serve = Serve::start(b_dir, &b_addr, &[]);
    let c_serve = Serve::start(c_dir, &c_addr, &["--p2p-local"]);

    let synced = run_ok(a_dir, &["group", "sync", &gid, "--p2p-local"]);
    assert_eq!(synced["seq"], 3);
    let mut delivered = names(&synced, "delivered");
    delivered.sort();
    let mut expect = vec![b_id.clone(), c_id.clone()];
    expect.sort();
    assert_eq!(delivered, expect, "{synced}");
    for serve in [&b_serve, &c_serve] {
        serve.wait_matching("group_manifest_ingested", |e| e["seq"] == 3);
        serve.wait_event("group_rendezvous_ingested");
    }
    let b_view = run_ok(b_dir, &["group", "show", &gid]);
    assert_eq!(b_view["role"], "member");
    assert_eq!(b_view["manifest"]["seq"], 3);

    let broadcast = run_ok(
        b_dir,
        &[
            "group",
            "broadcast",
            &gid,
            "--message",
            "hello-mesh",
            "--p2p-local",
        ],
    );
    assert_eq!(
        names(&broadcast, "delivered"),
        vec![c_id.clone()],
        "{broadcast}"
    );
    assert_eq!(
        names(&broadcast, "offline"),
        vec![a_id.clone()],
        "{broadcast}"
    );
    let member_remove = run(b_dir, &["group", "remove", &gid, "--peer", &c_id]);
    assert!(
        !member_remove.status.success(),
        "a non-root member must not remove members"
    );
    let data = c_serve.wait_event("group_data");
    assert_eq!(data["utf8"], "hello-mesh");
    assert_eq!(data["sender_device_id"], b_id);
    assert_eq!(data["group_id"], gid);

    let a_serve = Serve::start(a_dir, &a_addr, &[]);
    let removed = run_ok(a_dir, &["group", "remove", &gid, "--peer", &c_id]);
    assert_eq!(removed["seq"], 4);
    assert_eq!(removed["revoked_members"], serde_json::json!([c_id]));
    let resync = run_ok(a_dir, &["group", "sync", &gid]);
    assert_eq!(names(&resync, "delivered"), vec![b_id.clone()], "{resync}");
    b_serve.wait_matching("group_member_revoked", |e| e["device_id"] == c_id);

    assert_eq!(
        run_ok(b_dir, &["group", "show", &gid])["manifest"]["seq"],
        4
    );
    let after = run_ok(
        b_dir,
        &["group", "broadcast", &gid, "--message", "after-removal"],
    );
    for key in ["delivered", "offline", "failed"] {
        assert!(
            !names(&after, key).contains(&c_id),
            "removed member still targeted in {key}: {after}"
        );
    }
    assert!(
        c_serve
            .events
            .recv_timeout(Duration::from_millis(500))
            .map_or(true, |e| e["utf8"] != "after-removal")
    );
    drop(a_serve);
}

#[test]
fn group_e2e_wire_v2_members_are_onboarded_by_sync() {
    let a_dir = TempDir::new().expect("a dir");
    let b_dir = TempDir::new().expect("b dir");
    let c_dir = TempDir::new().expect("c dir");
    let (a_dir, b_dir, c_dir) = (a_dir.path(), b_dir.path(), c_dir.path());
    let (a_addr, b_addr, c_addr) = (free_addr(), free_addr(), free_addr());

    let a_info = run_ok(a_dir, &["init"]);
    let a_id = a_info["device_id"].as_str().expect("a id").to_owned();
    let b_id = device_id(b_dir);
    let c_id = device_id(c_dir);
    let enroll_serve = Serve::start(a_dir, &a_addr, &["--allow-enroll"]);
    enroll_with_root(a_dir, &a_info, &enroll_serve, b_dir);
    enroll_with_root(a_dir, &a_info, &enroll_serve, c_dir);
    enroll_serve.stop();

    let created = run_ok(
        a_dir,
        &[
            "group",
            "create",
            "--name",
            "trio-v2",
            "--wire-v2",
            "--endpoint",
            &format!("direct:{a_addr}"),
        ],
    );
    let gid = created["group_id"].as_str().expect("group id").to_owned();
    assert_eq!(created["manifest"]["min_wire_version"], 2);
    for (peer, addr) in [(&b_id, &b_addr), (&c_id, &c_addr)] {
        run_ok(
            a_dir,
            &["group", "add", &gid, "--peer", peer, "--endpoint", addr],
        );
    }

    let b_serve = Serve::start(b_dir, &b_addr, &["--wire-v2"]);
    let c_serve = Serve::start(c_dir, &c_addr, &["--wire-v2"]);
    let synced = run_ok(a_dir, &["group", "sync", &gid]);
    assert_eq!(synced["seq"], 3);
    let mut delivered = names(&synced, "delivered");
    delivered.sort();
    let mut expect = vec![b_id.clone(), c_id.clone()];
    expect.sort();
    assert_eq!(delivered, expect, "{synced}");
    for serve in [&b_serve, &c_serve] {
        serve.wait_matching("group_manifest_ingested", |e| e["seq"] == 3);
        serve.wait_matching("group_rendezvous_ingested", |e| e["seq"] == 3);
    }
    for dir in [b_dir, c_dir] {
        let view = run_ok(dir, &["group", "show", &gid]);
        assert_eq!(view["role"], "member");
        assert_eq!(view["rendezvous_seq"], 3);
    }

    let broadcast = run_ok(
        b_dir,
        &["group", "broadcast", &gid, "--message", "hello-v2-mesh"],
    );
    assert_eq!(
        names(&broadcast, "delivered"),
        vec![c_id.clone()],
        "{broadcast}"
    );
    assert_eq!(names(&broadcast, "offline"), vec![a_id], "{broadcast}");
    let data = c_serve.wait_event("group_data");
    assert_eq!(data["utf8"], "hello-v2-mesh");
    assert_eq!(data["sender_device_id"], b_id);
    assert_eq!(data["group_id"], gid);
}

/// Copies the root's stored manifest and rendezvous key into `dir`'s group book.
fn copy_group(root_dir: &Path, dir: &Path, gid: &str) {
    let root = tendril_runtime::StateStore::open_or_create(root_dir).expect("root store");
    let book = root.load_group_book().expect("root book");
    let manifest = book.manifest(gid).expect("manifest").clone();
    let secrets = book.secrets(gid).expect("key").clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    tendril_runtime::StateStore::open_or_create(dir)
        .expect("member store")
        .update_group_book(|b| {
            b.ingest_group_manifest(&manifest, now, None)?;
            b.install_secrets(gid, secrets.clone())?;
            Ok(())
        })
        .expect("seed member book");
}

/// A `serve` member whose manifest entry has only a `/v2/relay` hint registers its group
/// mailbox on its own, with no inbound stream ever arriving, and a sibling then reaches it.
#[test]
fn group_e2e_relay_only_serve_member_registers_its_group_mailbox() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let relay = rt
        .block_on(tendril_runtime::EmbeddedRelay::bind_local("127.0.0.1"))
        .expect("relay");
    let relay_url = relay.ws_v2_url();
    let a_dir = TempDir::new().expect("a dir");
    let b_dir = TempDir::new().expect("b dir");
    let c_dir = TempDir::new().expect("c dir");
    let (a_dir, b_dir, c_dir) = (a_dir.path(), b_dir.path(), c_dir.path());
    let (a_addr, b_addr, c_addr) = (free_addr(), free_addr(), free_addr());

    let a_info = run_ok(a_dir, &["init"]);
    let b_id = device_id(b_dir);
    let c_id = device_id(c_dir);
    let enroll_serve = Serve::start(a_dir, &a_addr, &["--allow-enroll"]);
    enroll_with_root(a_dir, &a_info, &enroll_serve, b_dir);
    enroll_with_root(a_dir, &a_info, &enroll_serve, c_dir);
    enroll_serve.stop();

    let created = run_ok(
        a_dir,
        &[
            "group",
            "create",
            "--name",
            "relay-only",
            "--wire-v2",
            "--endpoint",
            &format!("direct:{a_addr}"),
        ],
    );
    let gid = created["group_id"].as_str().expect("group id").to_owned();
    run_ok(
        a_dir,
        &[
            "group",
            "add",
            &gid,
            "--peer",
            &b_id,
            "--endpoint",
            &format!("direct:{b_addr}"),
        ],
    );
    run_ok(
        a_dir,
        &[
            "group",
            "add",
            &gid,
            "--peer",
            &c_id,
            "--endpoint",
            &relay_url,
        ],
    );
    copy_group(a_dir, b_dir, &gid);
    copy_group(a_dir, c_dir, &gid);

    let mailbox = {
        let store = tendril_runtime::StateStore::open_or_create(c_dir).expect("c store");
        let book = store.load_group_book().expect("c book");
        let secrets = book.secrets(&gid).expect("c key");
        *tendril_core::group::derive_group_mailbox_secret(
            secrets.group_rendezvous_key(),
            secrets.seq(),
            &c_id,
        )
    };
    let epoch = tendril_core::v2::epoch_for_unix(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    );
    let probe = || {
        rt.block_on(
            tendril_runtime::RelayV2Dialer::new(mailbox).connect_for_epoch(&relay_url, epoch),
        )
        .map(drop)
    };
    assert!(probe().is_err(), "mailbox registered before serve started");

    let c_serve = Serve::start(c_dir, &c_addr, &["--wire-v2"]);
    let deadline = Instant::now() + EVENT_TIMEOUT;
    while let Err(err) = probe() {
        assert!(
            Instant::now() < deadline,
            "serve never registered its group mailbox: {err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let broadcast = run_ok(
        b_dir,
        &["group", "broadcast", &gid, "--message", "over-the-relay"],
    );
    assert!(
        names(&broadcast, "delivered").contains(&c_id),
        "{broadcast}"
    );
    let data = c_serve.wait_event("group_data");
    assert_eq!(data["utf8"], "over-the-relay");
    c_serve.stop();
    drop(relay);
}
