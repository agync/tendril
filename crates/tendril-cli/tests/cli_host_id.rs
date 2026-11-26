//! An invalid local `host_id` cannot be configured or served.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use tempfile::TempDir;

fn tendril(state_dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tendril"))
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .output()
        .expect("run tendril bin")
}

#[test]
fn init_refuses_an_invalid_host_id_and_writes_nothing() {
    for bad in ["has#hash", "ctl\u{7}char", &"x".repeat(257)] {
        let dir = TempDir::new().expect("dir");
        let out = tendril(dir.path(), &["init", "--host-id", bad]);
        assert!(!out.status.success(), "{bad:?} was accepted");
        assert!(!dir.path().join("identity.json").exists(), "{bad:?}");
    }
}

#[test]
fn serve_refuses_an_invalid_stored_host_id() {
    let dir = TempDir::new().expect("dir");
    assert!(tendril(dir.path(), &["init"]).status.success());
    let path = dir.path().join("identity.json");
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("identity")).expect("json");
    doc["host_id"] = "has#hash".into();
    std::fs::write(&path, doc.to_string()).expect("rewrite");
    let out = tendril(dir.path(), &["serve", "--listen", "127.0.0.1:0"]);
    assert!(
        !out.status.success(),
        "serve started with an invalid host_id"
    );
}

#[test]
fn conformance_peer_refuses_an_invalid_host_id() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tendril-conformance-peer"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn peer");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut call = |req: serde_json::Value| -> serde_json::Value {
        writeln!(stdin, "{req}").expect("write");
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read");
        serde_json::from_str(&line).expect("json")
    };
    let bad = call(serde_json::json!({"op": "init", "host_id": "has#hash"}));
    assert_eq!(bad["ok"], false, "{bad}");
    let good = call(serde_json::json!({"op": "init", "host_id": "peer-ok"}));
    assert_eq!(good["ok"], true, "{good}");
    assert_eq!(good["host_id"], "peer-ok");
    drop(stdin);
    let _ = child.wait();
}
