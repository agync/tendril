use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use tempfile::TempDir;
use tendril_relay::{RelayConfig, RelayServer};

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn tendril_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tendril")
}

fn peer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tendril-conformance-peer")
}

fn run_tendril(state_dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .output()
        .expect("run tendril bin")
}

fn read_json_line(reader: &mut BufReader<std::process::ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read stdout line");
    assert!(n > 0, "unexpected EOF waiting for subprocess JSON line");
    serde_json::from_str(&line).expect("parse subprocess json line")
}

#[test]
fn cli_e2e_direct_pair_confirm_mint_dial_and_revoke() {
    let host_dir = TempDir::new().expect("host dir");
    let client_dir = TempDir::new().expect("client dir");

    let init_host = run_tendril(host_dir.path(), &["init", "--host-id", "host-direct"]);
    assert!(init_host.status.success());
    let init_cli = run_tendril(client_dir.path(), &["init"]);
    assert!(init_cli.status.success());
    let cli_info: serde_json::Value =
        serde_json::from_slice(&init_cli.stdout).expect("parse cli init");
    let cli_dev_id = cli_info["device_id"]
        .as_str()
        .expect("cli dev id")
        .to_owned();

    let mut serve = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(host_dir.path())
            .args(["serve", "--listen", "127.0.0.1:0", "--issue-code", "lan"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve"),
    );

    let mut stdout = BufReader::new(serve.0.stdout.take().expect("serve stdout"));
    let listening = read_json_line(&mut stdout);
    assert_eq!(listening["event"], "listening");
    let direct_ep = listening["direct_endpoint"]
        .as_str()
        .expect("direct_endpoint")
        .to_owned();
    let code = listening["pairing_code"]
        .as_str()
        .expect("pairing_code")
        .to_owned();

    let pair_out = run_tendril(
        client_dir.path(),
        &[
            "pair",
            "--endpoint",
            &direct_ep,
            "--code",
            &code,
            "--name",
            "cli-laptop",
        ],
    );
    assert!(
        pair_out.status.success(),
        "pair stderr: {}",
        String::from_utf8_lossy(&pair_out.stderr)
    );
    let paired_info: serde_json::Value =
        serde_json::from_slice(&pair_out.stdout).expect("pair json");
    let sas = paired_info["sas"].as_str().expect("sas");

    let paired_event = read_json_line(&mut stdout);
    assert_eq!(paired_event["event"], "paired");
    assert_eq!(paired_event["device_id"], cli_dev_id);
    assert_eq!(paired_event["sas"], sas);

    let confirm_cli = run_tendril(client_dir.path(), &["confirm", "host-direct", "--sas", sas]);
    assert!(
        confirm_cli.status.success(),
        "client confirm stderr: {}",
        String::from_utf8_lossy(&confirm_cli.stderr)
    );
    let confirm_out = run_tendril(host_dir.path(), &["confirm", &cli_dev_id, "--sas", sas]);
    assert!(confirm_out.status.success());

    let mint_out = run_tendril(host_dir.path(), &["mint", &cli_dev_id, "--cap", "fs.read"]);
    assert!(mint_out.status.success());
    let grant_json = String::from_utf8(mint_out.stdout).expect("grant utf8");

    let dial_out = run_tendril(
        client_dir.path(),
        &[
            "dial",
            "--target",
            "host-direct",
            "--endpoint",
            &direct_ep,
            "--grant",
            grant_json.trim(),
            "--message",
            "hello-cli-direct",
        ],
    );
    assert!(
        dial_out.status.success(),
        "dial stderr: {}",
        String::from_utf8_lossy(&dial_out.stderr)
    );

    let established_ev = read_json_line(&mut stdout);
    assert_eq!(established_ev["event"], "session_established");
    let data_ev = read_json_line(&mut stdout);
    assert_eq!(data_ev["event"], "data");
    assert_eq!(data_ev["utf8"], "hello-cli-direct");

    let revoke_out = run_tendril(host_dir.path(), &["revoke", &cli_dev_id]);
    assert!(revoke_out.status.success());

    let post_revoke = run_tendril(
        client_dir.path(),
        &[
            "dial",
            "--target",
            "host-direct",
            "--endpoint",
            &direct_ep,
            "--message",
            "must-fail",
        ],
    );
    assert!(
        !post_revoke.status.success(),
        "dial after revoke must fail closed"
    );
}

#[tokio::test]
async fn cli_e2e_relay_pair_confirm_mint_dial_and_revoke() {
    let relay = RelayServer::bind(RelayConfig::default())
        .await
        .expect("bind relay");
    let relay_handle = relay.spawn();
    let relay_url = relay_handle.ws_url();

    let host_dir = TempDir::new().expect("host dir");
    let client_dir = TempDir::new().expect("client dir");

    tokio::task::spawn_blocking(move || {
        let init_host = run_tendril(host_dir.path(), &["init", "--host-id", "host-relayed"]);
        assert!(init_host.status.success());
        let init_cli = run_tendril(client_dir.path(), &["init"]);
        assert!(init_cli.status.success());
        let cli_info: serde_json::Value =
            serde_json::from_slice(&init_cli.stdout).expect("parse cli init");
        let cli_dev_id = cli_info["device_id"]
            .as_str()
            .expect("cli dev id")
            .to_owned();

        let mut serve = KillOnDrop(
            Command::new(tendril_bin())
                .arg("--state-dir")
                .arg(host_dir.path())
                .args([
                    "serve",
                    "--listen",
                    "127.0.0.1:0",
                    "--relay",
                    &relay_url,
                    "--relay-host",
                    "localhost",
                    "--issue-code",
                    "remote",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn serve"),
        );

        let mut stdout = BufReader::new(serve.0.stdout.take().expect("serve stdout"));
        let listening = read_json_line(&mut stdout);
        let relay_ep = listening["relay_endpoint"]
            .as_str()
            .expect("relay_endpoint")
            .to_owned();
        let code = listening["pairing_code"]
            .as_str()
            .expect("pairing_code")
            .to_owned();

        let pair_out = run_tendril(
            client_dir.path(),
            &[
                "pair",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
                "--code",
                &code,
            ],
        );
        assert!(
            pair_out.status.success(),
            "pair stderr: {}",
            String::from_utf8_lossy(&pair_out.stderr)
        );
        let paired_info: serde_json::Value =
            serde_json::from_slice(&pair_out.stdout).expect("pair json");
        let sas = paired_info["sas"].as_str().expect("sas");

        let paired_ev = read_json_line(&mut stdout);
        assert_eq!(paired_ev["event"], "paired");

        let pre_confirm_dial = run_tendril(
            client_dir.path(),
            &[
                "dial",
                "--target",
                "host-relayed",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
            ],
        );
        assert!(
            !pre_confirm_dial.status.success(),
            "dial before client confirm must fail closed"
        );
        assert!(
            run_tendril(
                client_dir.path(),
                &["confirm", "host-relayed", "--sas", sas]
            )
            .status
            .success()
        );
        assert!(
            run_tendril(host_dir.path(), &["confirm", &cli_dev_id, "--sas", sas])
                .status
                .success()
        );
        let mint_out = run_tendril(host_dir.path(), &["mint", &cli_dev_id, "--cap", "fs.read"]);
        assert!(mint_out.status.success());
        let grant_json = String::from_utf8(mint_out.stdout).expect("grant utf8");

        let dial_out = run_tendril(
            client_dir.path(),
            &[
                "dial",
                "--target",
                "host-relayed",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
                "--grant",
                grant_json.trim(),
                "--message",
                "hello-cli-relay",
            ],
        );
        assert!(dial_out.status.success());

        let est_ev = read_json_line(&mut stdout);
        assert_eq!(est_ev["event"], "session_established");
        assert_eq!(est_ev["provider"], "Relay");
        let data_ev = read_json_line(&mut stdout);
        assert_eq!(data_ev["utf8"], "hello-cli-relay");

        assert!(
            run_tendril(host_dir.path(), &["revoke", &cli_dev_id])
                .status
                .success()
        );
        let post_revoke = run_tendril(
            client_dir.path(),
            &[
                "dial",
                "--target",
                "host-relayed",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
            ],
        );
        assert!(!post_revoke.status.success());
    })
    .await
    .expect("blocking relay e2e");

    relay_handle.stop().await.expect("stop relay");
}

struct PeerProc {
    child: KillOnDrop,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl PeerProc {
    fn spawn() -> Self {
        let mut child = Command::new(peer_bin())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn conformance peer");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child: KillOnDrop(child),
            stdin,
            stdout,
        }
    }

    fn send_cmd(&mut self, val: &serde_json::Value) {
        let line = serde_json::to_string(val).expect("serialize cmd");
        writeln!(self.stdin, "{line}").expect("write stdin");
        self.stdin.flush().expect("flush stdin");
    }

    fn recv_resp(&mut self) -> serde_json::Value {
        read_json_line(&mut self.stdout)
    }

    fn call(&mut self, val: serde_json::Value) -> serde_json::Value {
        self.send_cmd(&val);
        let resp = self.recv_resp();
        assert_eq!(resp["ok"], true, "peer op failed: {resp:?}");
        resp
    }
}

#[test]
fn conformance_peer_drives_full_json_stdio_session() {
    let mut host = PeerProc::spawn();
    let mut client = PeerProc::spawn();

    let host_init = host.call(serde_json::json!({ "op": "init", "host_id": "conf-host" }));
    let client_init = client.call(serde_json::json!({ "op": "init" }));
    let client_dev_id = client_init["device_id"]
        .as_str()
        .expect("cli dev id")
        .to_owned();
    assert_eq!(host_init["host_id"], "conf-host");

    let srv = host.call(serde_json::json!({ "op": "serve_direct" }));
    let ep = srv["endpoint"].as_str().expect("endpoint").to_owned();
    let code_resp = host.call(serde_json::json!({ "op": "issue_code", "kind": "lan" }));
    let code = code_resp["code"].as_str().expect("code").to_owned();

    // Start pair concurrently across both JSON peers.
    host.send_cmd(&serde_json::json!({ "op": "pair" }));
    client.send_cmd(&serde_json::json!({
        "op": "pair",
        "endpoint": ep,
        "code": code,
        "name": "conf-cli",
        "kind": "test"
    }));
    let host_pair = host.recv_resp();
    let cli_pair = client.recv_resp();
    assert_eq!(host_pair["ok"], true);
    assert_eq!(cli_pair["ok"], true);
    assert_eq!(host_pair["sas"], cli_pair["sas"]);
    let sas = host_pair["sas"].as_str().expect("sas").to_owned();

    host.call(serde_json::json!({ "op": "confirm", "peer_id": client_dev_id, "sas": sas }));
    client.call(serde_json::json!({ "op": "confirm", "peer_id": "conf-host", "sas": sas }));
    let mint = host.call(serde_json::json!({
        "op": "mint",
        "peer_id": client_dev_id,
        "caps": ["fs.read"]
    }));
    let grant = mint["grant"].clone();

    host.send_cmd(&serde_json::json!({ "op": "connect" }));
    client.send_cmd(&serde_json::json!({
        "op": "connect",
        "endpoint": ep,
        "target_host_id": "conf-host",
        "grant": grant
    }));
    assert_eq!(host.recv_resp()["ok"], true);
    assert_eq!(client.recv_resp()["ok"], true);

    let auth_ok = host.call(serde_json::json!({ "op": "authorize", "cap": "fs.read" }));
    assert_eq!(auth_ok["allowed"], true);
    let auth_deny = host.call(serde_json::json!({ "op": "authorize", "cap": "shell.exec" }));
    assert_eq!(auth_deny["allowed"], false);

    client.call(serde_json::json!({ "op": "send", "data_utf8": "conformance-hello" }));
    let recv_data = host.call(serde_json::json!({ "op": "recv", "timeout_ms": 2000 }));
    assert_eq!(recv_data["event"], "data");
    assert_eq!(recv_data["data_utf8"], "conformance-hello");

    client.call(serde_json::json!({ "op": "rekey" }));
    let recv_rekey = host.call(serde_json::json!({ "op": "recv", "timeout_ms": 2000 }));
    assert_eq!(recv_rekey["event"], "rekeyed");

    host.call(serde_json::json!({ "op": "revoke", "peer_id": client_dev_id }));
    let auth_revoked = host.call(serde_json::json!({ "op": "authorize", "cap": "fs.read" }));
    assert_eq!(auth_revoked["allowed"], false);

    client.call(serde_json::json!({ "op": "close" }));
    host.call(serde_json::json!({ "op": "shutdown" }));
    client.call(serde_json::json!({ "op": "shutdown" }));
    let status = host.child.0.wait().expect("wait host");
    assert!(status.success());
    let status_cli = client.child.0.wait().expect("wait cli");
    assert!(status_cli.success());
}

#[test]
fn cli_e2e_embedded_relay_p2p_overlay_and_broker() {
    let host_dir = TempDir::new().expect("host dir");
    let client_dir = TempDir::new().expect("client dir");

    assert!(
        run_tendril(host_dir.path(), &["init", "--host-id", "host-multi"])
            .status
            .success()
    );
    let init_cli = run_tendril(client_dir.path(), &["init"]);
    assert!(init_cli.status.success());
    let cli_info: serde_json::Value =
        serde_json::from_slice(&init_cli.stdout).expect("parse cli init");
    let cli_dev_id = cli_info["device_id"]
        .as_str()
        .expect("cli dev id")
        .to_owned();

    let mut serve = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(host_dir.path())
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--embedded-relay",
                "--p2p-local",
                "--overlay",
                "127.0.0.1:0",
                "--broker",
                "127.0.0.1:0",
                "--issue-code",
                "remote",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve"),
    );

    let mut stdout = BufReader::new(serve.0.stdout.take().expect("serve stdout"));
    let listening = read_json_line(&mut stdout);
    assert_eq!(listening["event"], "listening");
    let relay_ep = listening["relay_endpoint"]
        .as_str()
        .expect("relay_endpoint")
        .to_owned();
    let p2p_ep = listening["p2p_endpoint"]
        .as_str()
        .expect("p2p_endpoint")
        .to_owned();
    let overlay_ep = listening["overlay_endpoint"]
        .as_str()
        .expect("overlay_endpoint")
        .to_owned();
    let broker_ep = listening["broker_endpoint"]
        .as_str()
        .expect("broker_endpoint")
        .to_owned();
    assert!(listening["embedded_relay_url"].as_str().is_some());
    let code = listening["pairing_code"]
        .as_str()
        .expect("pairing_code")
        .to_owned();

    // Pair over P2P (iroh) locally.
    let pair_out = run_tendril(
        client_dir.path(),
        &[
            "pair",
            "--p2p-local",
            "--endpoint",
            &p2p_ep,
            "--code",
            &code,
            "--name",
            "cli-p2p",
        ],
    );
    assert!(
        pair_out.status.success(),
        "pair stderr: {}",
        String::from_utf8_lossy(&pair_out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&pair_out.stderr).contains("Endpoint dropped without calling"),
        "unexpected ungraceful iroh drop warning on pair stderr: {}",
        String::from_utf8_lossy(&pair_out.stderr)
    );
    let paired_info: serde_json::Value =
        serde_json::from_slice(&pair_out.stdout).expect("pair json");
    let sas = paired_info["sas"].as_str().expect("sas");

    let paired_ev = read_json_line(&mut stdout);
    assert_eq!(paired_ev["event"], "paired");
    assert_eq!(paired_ev["device_id"], cli_dev_id);
    assert_eq!(paired_ev["sas"], sas);

    assert!(
        run_tendril(client_dir.path(), &["confirm", "host-multi", "--sas", sas])
            .status
            .success()
    );
    assert!(
        run_tendril(host_dir.path(), &["confirm", &cli_dev_id, "--sas", sas])
            .status
            .success()
    );
    let mint_out = run_tendril(host_dir.path(), &["mint", &cli_dev_id, "--cap", "fs.read"]);
    assert!(mint_out.status.success());
    let grant_json = String::from_utf8(mint_out.stdout).expect("grant utf8");

    for (ep, expected_provider, msg) in [
        (&p2p_ep, "P2p", "hello-cli-p2p"),
        (&overlay_ep, "Overlay", "hello-cli-overlay"),
        (&broker_ep, "Broker", "hello-cli-broker"),
        (&relay_ep, "Relay", "hello-cli-embedded-relay"),
    ] {
        let mut args = vec![
            "dial",
            "--target",
            "host-multi",
            "--endpoint",
            ep.as_str(),
            "--grant",
            grant_json.trim(),
            "--message",
            msg,
        ];
        if expected_provider == "Relay" {
            args.extend(["--relay-host", "localhost"]);
        } else if expected_provider == "P2p" {
            args.push("--p2p-local");
        }
        let dial_out = run_tendril(client_dir.path(), &args);
        assert!(
            dial_out.status.success(),
            "dial {expected_provider} stderr: {}",
            String::from_utf8_lossy(&dial_out.stderr)
        );
        let dial_json: serde_json::Value =
            serde_json::from_slice(&dial_out.stdout).expect("dial json");
        assert_eq!(dial_json["provider"], expected_provider);
        if expected_provider == "P2p" {
            assert!(
                !String::from_utf8_lossy(&dial_out.stderr)
                    .contains("Endpoint dropped without calling"),
                "unexpected ungraceful iroh drop warning on dial stderr: {}",
                String::from_utf8_lossy(&dial_out.stderr)
            );
        }

        let est = read_json_line(&mut stdout);
        assert_eq!(est["event"], "session_established");
        assert_eq!(est["provider"], expected_provider);
        let data = read_json_line(&mut stdout);
        assert_eq!(data["event"], "data");
        assert_eq!(data["utf8"], msg);
        let closed = read_json_line(&mut stdout);
        assert_eq!(closed["event"], "closed");
    }

    drop(stdout);
    drop(serve);

    // Restarting serve from the same state_dir preserves the HKDF-derived P2P EndpointId.
    let mut serve2 = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(host_dir.path())
            .args(["serve", "--listen", "127.0.0.1:0", "--p2p-local"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve restart"),
    );
    let mut stdout2 = BufReader::new(serve2.0.stdout.take().expect("serve2 stdout"));
    let listening2 = read_json_line(&mut stdout2);
    let p2p_ep2 = listening2["p2p_endpoint"]
        .as_str()
        .expect("p2p_endpoint2")
        .to_owned();
    assert_eq!(p2p_ep.split('?').next(), p2p_ep2.split('?').next());
}
