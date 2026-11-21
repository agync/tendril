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
                "--overlay-allow-non-tailnet",
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

#[tokio::test]
async fn batch1_sec04_cli_serve_enforces_live_revoke_and_flock_pair_safety() {
    let host_dir = TempDir::new().expect("host dir");
    let client_dir = TempDir::new().expect("client dir");

    assert!(
        run_tendril(host_dir.path(), &["init", "--host-id", "host-live-rev"])
            .status
            .success()
    );
    let init_cli = run_tendril(client_dir.path(), &["init"]);
    assert!(init_cli.status.success());
    let cli_info: serde_json::Value = serde_json::from_slice(&init_cli.stdout).expect("cli init");
    let cli_dev_id = cli_info["device_id"].as_str().expect("dev id").to_owned();

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
    let direct_ep = listening["direct_endpoint"]
        .as_str()
        .expect("direct_ep")
        .to_owned();
    let code = listening["pairing_code"]
        .as_str()
        .expect("pairing_code")
        .to_owned();

    let pair_out = run_tendril(
        client_dir.path(),
        &["pair", "--endpoint", &direct_ep, "--code", &code],
    );
    assert!(pair_out.status.success());
    let paired_info: serde_json::Value =
        serde_json::from_slice(&pair_out.stdout).expect("pair json");
    let sas = paired_info["sas"].as_str().expect("sas").to_owned();
    let paired_ev = read_json_line(&mut stdout);
    assert_eq!(paired_ev["event"], "paired");

    assert!(
        run_tendril(
            client_dir.path(),
            &["confirm", "host-live-rev", "--sas", &sas]
        )
        .status
        .success()
    );
    assert!(
        run_tendril(host_dir.path(), &["confirm", &cli_dev_id, "--sas", &sas])
            .status
            .success()
    );
    let mint_out = run_tendril(host_dir.path(), &["mint", &cli_dev_id, "--cap", "fs.read"]);
    assert!(mint_out.status.success());
    let grant: tendril_core::grants::Grant =
        serde_json::from_slice(&mint_out.stdout).expect("grant json");

    let cli_store = tendril_runtime::StateStore::open_or_create(client_dir.path()).unwrap();
    let cli_id = cli_store.load_identity().unwrap();
    let mut cli_roster = cli_store.load_roster().unwrap();

    // Connect open session, verify live ping, then revoke via CLI while session stays open.
    let stream = tendril_runtime::dial_endpoint(&direct_ep, None)
        .await
        .unwrap();
    let mut driver = tendril_runtime::SessionDriver::connect(
        stream,
        &cli_id,
        "host-live-rev",
        Some(grant),
        &mut cli_roster,
        1_795_564_800,
    )
    .await
    .unwrap();
    let est = read_json_line(&mut stdout);
    assert_eq!(est["event"], "session_established");

    driver.send_ping(99).await.unwrap();
    loop {
        if let Some(tendril_runtime::SessionEvent::PongReceived(99)) = driver
            .next_event(1_795_564_800, &mut cli_roster)
            .await
            .unwrap()
        {
            break;
        }
    }

    // Revoke client in external CLI process while session is active; serve MUST terminate
    // promptly via roster reload and refuse subsequent REKEY / DATA frames.
    assert!(
        run_tendril(host_dir.path(), &["revoke", &cli_dev_id])
            .status
            .success()
    );
    let _ = driver.send_rekey().await;
    let _ = driver.send_data(b"must-not-deliver").await;

    let closed = read_json_line(&mut stdout);
    assert_eq!(
        closed["event"], "closed",
        "expected serve to close revoked session immediately instead of emitting data: {closed:?}"
    );
    let _ = driver.next_event(1_795_564_800, &mut cli_roster).await;

    // Concurrent CLI pair against another host must not clobber pre-existing revocations.
    let second_dir = TempDir::new().expect("second host");
    assert!(
        run_tendril(second_dir.path(), &["init", "--host-id", "host-second"])
            .status
            .success()
    );
    let mut serve2 = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(second_dir.path())
            .args(["serve", "--listen", "127.0.0.1:0", "--issue-code", "lan"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve2"),
    );
    let mut stdout2 = BufReader::new(serve2.0.stdout.take().expect("serve2 stdout"));
    let l2 = read_json_line(&mut stdout2);
    let ep2 = l2["direct_endpoint"].as_str().unwrap().to_owned();
    let code2 = l2["pairing_code"].as_str().unwrap().to_owned();

    // Seed an active host + revoke it on client_dir, verify pair + update_roster retains Revoked state.
    cli_store
        .update_roster(|r| {
            let dummy = tendril_core::identity::EndpointIdentity::generate()?;
            r.insert_pinned_host(
                "revoked-keep".into(),
                "Revoked".into(),
                *dummy.static_key().public_bytes(),
                Some(dummy.signing_key().public_key().clone()),
                0,
                vec![],
            )?;
            r.revoke_peer("revoked-keep")?;
            Ok(())
        })
        .unwrap();
    let pair2 = run_tendril(
        client_dir.path(),
        &["pair", "--endpoint", &ep2, "--code", &code2],
    );
    assert!(pair2.status.success());
    let after_pair = cli_store.load_roster().unwrap();
    assert_eq!(
        after_pair.get("revoked-keep").unwrap().state,
        tendril_core::roster::PeerState::Revoked
    );
    assert!(after_pair.get("host-second").is_some());
}

#[test]
fn cli_e2e_pair_non_argv_code_inputs() {
    let host_dir = TempDir::new().expect("host dir");
    let client_dir = TempDir::new().expect("client dir");
    assert!(
        run_tendril(host_dir.path(), &["init", "--host-id", "host-sec25"])
            .status
            .success()
    );
    assert!(run_tendril(client_dir.path(), &["init"]).status.success());

    let spawn_pair_server = || {
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
        let mut stdout = BufReader::new(serve.0.stdout.take().expect("stdout"));
        let listening = read_json_line(&mut stdout);
        let ep = listening["direct_endpoint"]
            .as_str()
            .expect("ep")
            .to_owned();
        let code = listening["pairing_code"].as_str().expect("code").to_owned();
        (serve, ep, code)
    };

    // 1. --code-stdin
    let (_s1, ep1, code1) = spawn_pair_server();
    let mut child = Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(client_dir.path())
        .args(["pair", "--endpoint", &ep1, "--code-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pair stdin");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{code1}\n").as_bytes())
        .expect("write code stdin");
    let out1 = child.wait_with_output().expect("wait stdin");
    assert!(
        out1.status.success(),
        "pair --code-stdin failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );

    // 2. --code-file
    let (_s2, ep2, code2) = spawn_pair_server();
    let code_file = client_dir.path().join("pair.code");
    std::fs::write(&code_file, format!("{code2}\r\n")).expect("write code file");
    let out2 = run_tendril(
        client_dir.path(),
        &[
            "pair",
            "--endpoint",
            &ep2,
            "--code-file",
            code_file.to_str().expect("utf8 path"),
        ],
    );
    assert!(
        out2.status.success(),
        "pair --code-file failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );

    // 3. TENDRIL_PAIR_CODE env var, plus conflict rejection when combined with --code.
    let (_s3, ep3, code3) = spawn_pair_server();
    let conflict = Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(client_dir.path())
        .env("TENDRIL_PAIR_CODE", &code3)
        .args(["pair", "--endpoint", &ep3, "--code", &code3])
        .output()
        .expect("run conflict pair");
    assert!(
        !conflict.status.success(),
        "conflicting code sources must fail"
    );

    let out3 = Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(client_dir.path())
        .env("TENDRIL_PAIR_CODE", &code3)
        .args(["pair", "--endpoint", &ep3])
        .output()
        .expect("run env pair");
    assert!(
        out3.status.success(),
        "TENDRIL_PAIR_CODE pair failed: {}",
        String::from_utf8_lossy(&out3.stderr)
    );
}

#[test]
fn cli_e2e_p2p_ephemeral_and_local_env() {
    let host_dir = TempDir::new().expect("host dir");
    assert!(
        run_tendril(host_dir.path(), &["init", "--host-id", "host-priv01"])
            .status
            .success()
    );

    let start_ephemeral = || {
        let mut serve = KillOnDrop(
            Command::new(tendril_bin())
                .arg("--state-dir")
                .arg(host_dir.path())
                .env("TENDRIL_P2P_LOCAL", "1")
                .args([
                    "serve",
                    "--listen",
                    "127.0.0.1:0",
                    "--p2p",
                    "--ephemeral-p2p",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn ephemeral serve"),
        );
        let mut stdout = BufReader::new(serve.0.stdout.take().expect("stdout"));
        let listening = read_json_line(&mut stdout);
        listening["p2p_endpoint"]
            .as_str()
            .expect("p2p_endpoint")
            .to_owned()
    };

    let ep1 = start_ephemeral();
    let ep2 = start_ephemeral();
    assert!(ep1.starts_with("iroh://"));
    assert!(
        ep1.contains("addr="),
        "TENDRIL_P2P_LOCAL=1 on serve --p2p selects offline Disabled mode with local addr: {ep1}"
    );
    let id1 = ep1
        .strip_prefix("iroh://")
        .unwrap()
        .split('?')
        .next()
        .unwrap();
    let id2 = ep2
        .strip_prefix("iroh://")
        .unwrap()
        .split('?')
        .next()
        .unwrap();
    assert_ne!(
        id1, id2,
        "--ephemeral-p2p must rotate EndpointId per invocation"
    );
}

#[test]
fn cli_e2e_m2m_enrollment_replay_anchor_and_rotation() {
    let host_dir = TempDir::new().expect("host dir");
    let anchor_dir = TempDir::new().expect("anchor dir");
    let rogue_dir = TempDir::new().expect("rogue dir");
    let client1_dir = TempDir::new().expect("client1 dir");
    let client2_dir = TempDir::new().expect("client2 dir");
    let client3_dir = TempDir::new().expect("client3 dir");

    let init_host: serde_json::Value = serde_json::from_slice(
        &run_tendril(host_dir.path(), &["init", "--host-id", "host-m2m"]).stdout,
    )
    .expect("host init");
    let host_static_0 = init_host["static_pub"].as_str().unwrap().to_owned();
    let host_signing_0 = init_host["signing_pub"].as_str().unwrap().to_owned();

    let init_anchor: serde_json::Value = serde_json::from_slice(
        &run_tendril(anchor_dir.path(), &["init", "--host-id", "anchor-ci"]).stdout,
    )
    .expect("anchor init");
    let anchor_signing = init_anchor["signing_pub"].as_str().unwrap().to_owned();

    assert!(
        run_tendril(rogue_dir.path(), &["init", "--host-id", "anchor-rogue"])
            .status
            .success()
    );
    let c1_info: serde_json::Value =
        serde_json::from_slice(&run_tendril(client1_dir.path(), &["init"]).stdout)
            .expect("c1 init");
    let c1_dev_id = c1_info["device_id"].as_str().unwrap().to_owned();
    assert!(run_tendril(client2_dir.path(), &["init"]).status.success());
    assert!(run_tendril(client3_dir.path(), &["init"]).status.success());

    // Register admin_anchor and verify list.
    assert!(
        run_tendril(
            host_dir.path(),
            &[
                "anchor",
                "add",
                "anchor-ci",
                "--signing-pub",
                &anchor_signing
            ]
        )
        .status
        .success()
    );
    let anchor_list: serde_json::Value =
        serde_json::from_slice(&run_tendril(host_dir.path(), &["anchor", "list"]).stdout)
            .expect("anchor list");
    assert_eq!(anchor_list["anchors"][0]["anchor_id"], "anchor-ci");
    assert_eq!(anchor_list["anchors"][0]["state"], "active");

    // 1. Mint self-issued token to a 0o600 file.
    let self_tok_path = host_dir.path().join("self-enroll.json");
    let mint_self = run_tendril(
        host_dir.path(),
        &[
            "enroll-token",
            "--target-host",
            "host-m2m",
            "--subject",
            &c1_dev_id,
            "--ttl-secs",
            "900",
            "--out",
            self_tok_path.to_str().unwrap(),
        ],
    );
    assert!(
        mint_self.status.success(),
        "enroll-token stderr: {}",
        String::from_utf8_lossy(&mint_self.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&self_tok_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "token --out must enforce 0o600 permissions");
    }

    // Start serve with --allow-enroll --issue-code lan --redact-logs.
    let mut serve = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(host_dir.path())
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--issue-code",
                "lan",
                "--allow-enroll",
                "--redact-logs",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve"),
    );
    let mut stdout = BufReader::new(serve.0.stdout.take().expect("stdout"));
    let listening = read_json_line(&mut stdout);
    assert_eq!(listening["event"], "listening");
    assert_eq!(listening["allow_enroll"], true);
    assert_eq!(
        listening["pairing_code"], "<redacted>",
        "--redact-logs must redact pairing_code"
    );
    let ep = listening["direct_endpoint"].as_str().unwrap().to_owned();

    // 2. Concurrent replay race with identical self-issued token: exactly one wins, one fails token_replayed.
    let c1_dir_a = client1_dir.path().to_path_buf();
    let c1_dir_b = client1_dir.path().to_path_buf();
    let ep_a = ep.clone();
    let ep_b = ep.clone();
    let hs0_a = host_static_0.clone();
    let hs0_b = host_static_0.clone();
    let hk0_a = host_signing_0.clone();
    let hk0_b = host_signing_0.clone();
    let tok_a = self_tok_path.clone();
    let tok_b = self_tok_path.clone();

    let h1 = std::thread::spawn(move || {
        run_tendril(
            &c1_dir_a,
            &[
                "enroll",
                "--endpoint",
                &ep_a,
                "--host-id",
                "host-m2m",
                "--host-static-pub",
                &hs0_a,
                "--host-signing-pub",
                &hk0_a,
                "--token-file",
                tok_a.to_str().unwrap(),
            ],
        )
    });
    let h2 = std::thread::spawn(move || {
        run_tendril(
            &c1_dir_b,
            &[
                "enroll",
                "--endpoint",
                &ep_b,
                "--host-id",
                "host-m2m",
                "--host-static-pub",
                &hs0_b,
                "--host-signing-pub",
                &hk0_b,
                "--token-file",
                tok_b.to_str().unwrap(),
            ],
        )
    });
    let out_a = h1.join().unwrap();
    let out_b = h2.join().unwrap();
    let successes = usize::from(out_a.status.success()) + usize::from(out_b.status.success());
    assert_eq!(
        successes,
        1,
        "concurrent M2M replay must allow strictly 1 enrollment; a={} / b={}",
        String::from_utf8_lossy(&out_a.stderr),
        String::from_utf8_lossy(&out_b.stderr)
    );
    let failed_out = if out_a.status.success() {
        &out_b
    } else {
        &out_a
    };
    assert!(
        String::from_utf8_lossy(&failed_out.stderr).contains("token_replayed"),
        "expected token_replayed on losing race, got {}",
        String::from_utf8_lossy(&failed_out.stderr)
    );

    // Confirm serve stdout redacted token_nonce (and saw both enrolled and pair_rejected).
    let ev1 = read_json_line(&mut stdout);
    let ev2 = read_json_line(&mut stdout);
    let enrolled_ev = if ev1["event"] == "enrolled" {
        &ev1
    } else {
        &ev2
    };
    let rejected_ev = if ev1["event"] == "pair_rejected" {
        &ev1
    } else {
        &ev2
    };
    assert_eq!(enrolled_ev["event"], "enrolled");
    assert_eq!(enrolled_ev["token_nonce"], "<redacted>");
    assert_eq!(rejected_ev["event"], "pair_rejected");
    assert_eq!(rejected_ev["error"], "token_replayed");

    // 3. Trust-anchor enrollment via --token-stdin succeeds for client2.
    let anchor_tok_out = run_tendril(
        anchor_dir.path(),
        &["enroll-token", "--target-host", "host-m2m"],
    );
    assert!(anchor_tok_out.status.success());
    let mut enroll_stdin = Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(client2_dir.path())
        .args([
            "enroll",
            "--endpoint",
            &ep,
            "--host-id",
            "host-m2m",
            "--host-static-pub",
            &host_static_0,
            "--host-signing-pub",
            &host_signing_0,
            "--token-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn enroll stdin");
    enroll_stdin
        .stdin
        .take()
        .unwrap()
        .write_all(&anchor_tok_out.stdout)
        .unwrap();
    let enroll2_res = enroll_stdin.wait_with_output().unwrap();
    assert!(
        enroll2_res.status.success(),
        "anchor stdin enroll stderr: {}",
        String::from_utf8_lossy(&enroll2_res.stderr)
    );
    let _ = read_json_line(&mut stdout);

    // 4. Dial + --redact-logs masks payload utf8 on server stdout.
    assert!(
        run_tendril(host_dir.path(), &["mint", &c1_dev_id, "--cap", "chat.send"])
            .status
            .success()
    );
    let dial_res = run_tendril(
        client1_dir.path(),
        &[
            "dial",
            "--target",
            "host-m2m",
            "--endpoint",
            &ep,
            "--message",
            "super-secret-payload",
        ],
    );
    assert!(
        dial_res.status.success(),
        "dial stderr: {}",
        String::from_utf8_lossy(&dial_res.stderr)
    );
    let _sess_ev = read_json_line(&mut stdout);
    let data_ev = read_json_line(&mut stdout);
    assert_eq!(data_ev["event"], "data");
    assert_eq!(
        data_ev["utf8"], "<redacted>",
        "--redact-logs must redact utf8 payload"
    );
    let _closed_ev = read_json_line(&mut stdout);

    // 5. Untrusted anchor & revoked anchor & CRL revoke-token all fail closed cleanly.
    let rogue_tok = String::from_utf8(
        run_tendril(
            rogue_dir.path(),
            &["enroll-token", "--target-host", "host-m2m"],
        )
        .stdout,
    )
    .unwrap();
    let rogue_fail = Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(client3_dir.path())
        .env("TENDRIL_ENROLL_TOKEN", &rogue_tok)
        .args([
            "enroll",
            "--endpoint",
            &ep,
            "--host-id",
            "host-m2m",
            "--host-static-pub",
            &host_static_0,
            "--host-signing-pub",
            &host_signing_0,
        ])
        .output()
        .unwrap();
    assert!(!rogue_fail.status.success());
    assert!(String::from_utf8_lossy(&rogue_fail.stderr).contains("untrusted_anchor"));
    let _ = read_json_line(&mut stdout);

    // Stop server -> revoke anchor + revoke unused token nonce -> restart serve (pre-rotation)
    // to verify persistent post-restart burn log and CRL, then rotate and verify post-rotation.
    drop(serve);

    assert!(
        run_tendril(host_dir.path(), &["anchor", "revoke", "anchor-ci"])
            .status
            .success()
    );
    let to_revoke_tok = host_dir.path().join("to-revoke.json");
    let revoke_mint: serde_json::Value = serde_json::from_slice(
        &run_tendril(
            host_dir.path(),
            &[
                "enroll-token",
                "--target-host",
                "host-m2m",
                "--out",
                to_revoke_tok.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    let revoked_nonce = revoke_mint["nonce"].as_str().unwrap().to_owned();
    assert!(
        run_tendril(host_dir.path(), &["revoke-token", &revoked_nonce])
            .status
            .success()
    );

    let mut serve_restart = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(host_dir.path())
            .args(["serve", "--listen", "127.0.0.1:0", "--allow-enroll"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve_restart"),
    );
    let mut stdout_r = BufReader::new(serve_restart.0.stdout.take().expect("stdout_r"));
    let ep_r = read_json_line(&mut stdout_r)["direct_endpoint"]
        .as_str()
        .unwrap()
        .to_owned();

    // Post-restart replay of self_tok_path -> token_replayed
    let post_restart_rep = run_tendril(
        client1_dir.path(),
        &[
            "enroll",
            "--endpoint",
            &ep_r,
            "--host-id",
            "host-m2m",
            "--host-static-pub",
            &host_static_0,
            "--host-signing-pub",
            &host_signing_0,
            "--token-file",
            self_tok_path.to_str().unwrap(),
        ],
    );
    assert!(!post_restart_rep.status.success());
    assert!(String::from_utf8_lossy(&post_restart_rep.stderr).contains("token_replayed"));
    let _ = read_json_line(&mut stdout_r);

    // CRL-revoked token -> unauthorized
    let crl_fail = run_tendril(
        client3_dir.path(),
        &[
            "enroll",
            "--endpoint",
            &ep_r,
            "--host-id",
            "host-m2m",
            "--host-static-pub",
            &host_static_0,
            "--host-signing-pub",
            &host_signing_0,
            "--token-file",
            to_revoke_tok.to_str().unwrap(),
        ],
    );
    assert!(!crl_fail.status.success());
    assert!(String::from_utf8_lossy(&crl_fail.stderr).contains("unauthorized"));
    let _ = read_json_line(&mut stdout_r);
    drop(serve_restart);

    // Now rotate host keys (which automatically re-signs persisted self-CRL) and restart serve.
    let rot_out: serde_json::Value =
        serde_json::from_slice(&run_tendril(host_dir.path(), &["rotate"]).stdout)
            .expect("rotate output");
    assert_eq!(rot_out["rotation_seq"], 1);

    let mut serve2 = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(host_dir.path())
            .args(["serve", "--listen", "127.0.0.1:0", "--allow-enroll"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve2"),
    );
    let mut stdout2 = BufReader::new(serve2.0.stdout.take().expect("stdout2"));
    let listening2 = read_json_line(&mut stdout2);
    let ep2 = listening2["direct_endpoint"].as_str().unwrap().to_owned();

    // Revoked anchor token -> untrusted_anchor
    let revoked_anc_tok = String::from_utf8(
        run_tendril(
            anchor_dir.path(),
            &["enroll-token", "--target-host", "host-m2m"],
        )
        .stdout,
    )
    .unwrap();
    let rev_anc_fail = Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(client3_dir.path())
        .env("TENDRIL_ENROLL_TOKEN", &revoked_anc_tok)
        .args([
            "enroll",
            "--endpoint",
            &ep2,
            "--host-id",
            "host-m2m",
            "--host-static-pub",
            &host_static_0,
            "--host-signing-pub",
            &host_signing_0,
        ])
        .output()
        .unwrap();
    assert!(!rev_anc_fail.status.success());
    assert!(String::from_utf8_lossy(&rev_anc_fail.stderr).contains("untrusted_anchor"));
    let _ = read_json_line(&mut stdout2);

    // Fresh token issued by rotated host enrolls client3 using PRE-rotation pin!
    let rot_tok_path = host_dir.path().join("rot-enroll.json");
    assert!(
        run_tendril(
            host_dir.path(),
            &[
                "enroll-token",
                "--target-host",
                "host-m2m",
                "--out",
                rot_tok_path.to_str().unwrap(),
            ]
        )
        .status
        .success()
    );
    let rot_enroll = run_tendril(
        client3_dir.path(),
        &[
            "enroll",
            "--endpoint",
            &ep2,
            "--host-id",
            "host-m2m",
            "--host-static-pub",
            &host_static_0,
            "--host-signing-pub",
            &host_signing_0,
            "--token-file",
            rot_tok_path.to_str().unwrap(),
        ],
    );
    assert!(
        rot_enroll.status.success(),
        "post-rotation enroll stderr: {}",
        String::from_utf8_lossy(&rot_enroll.stderr)
    );
    let rot_enroll_json: serde_json::Value = serde_json::from_slice(&rot_enroll.stdout).unwrap();
    assert_eq!(rot_enroll_json["status"], "active");
    assert_eq!(rot_enroll_json["host_rotation_seq"], 1);
    let _ = read_json_line(&mut stdout2);
    drop(serve2);

    // 6. confirm without --sas fails closed, --allow-no-sas succeeds.
    let human_host_dir = TempDir::new().unwrap();
    let human_cli_dir = TempDir::new().unwrap();
    assert!(
        run_tendril(
            human_host_dir.path(),
            &["init", "--host-id", "human-sas-host"]
        )
        .status
        .success()
    );
    let h_cli_init: serde_json::Value =
        serde_json::from_slice(&run_tendril(human_cli_dir.path(), &["init"]).stdout).unwrap();
    let h_cli_dev_id = h_cli_init["device_id"].as_str().unwrap().to_owned();
    let mut h_serve = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(human_host_dir.path())
            .args(["serve", "--listen", "127.0.0.1:0", "--issue-code", "lan"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut h_out = BufReader::new(h_serve.0.stdout.take().unwrap());
    let h_list = read_json_line(&mut h_out);
    let h_ep = h_list["direct_endpoint"].as_str().unwrap().to_owned();
    let h_code = h_list["pairing_code"].as_str().unwrap().to_owned();
    assert!(
        run_tendril(
            human_cli_dir.path(),
            &["pair", "--endpoint", &h_ep, "--code", &h_code]
        )
        .status
        .success()
    );
    let _ = read_json_line(&mut h_out);
    assert!(
        !run_tendril(human_host_dir.path(), &["confirm", &h_cli_dev_id])
            .status
            .success(),
        "confirm without --sas must fail closed"
    );
    assert!(
        run_tendril(
            human_host_dir.path(),
            &["confirm", &h_cli_dev_id, "--allow-no-sas"]
        )
        .status
        .success(),
        "confirm --allow-no-sas must explicitly opt in"
    );
}

#[test]
fn cli_v1_pairing_rejects_v2_floored_host_with_zero_wire_bytes_sent() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::time::Duration;

    use tendril_core::identity::EndpointIdentity;
    use tendril_core::pairing::PairingUri;
    use tendril_core::roster::V2PeerSecrets;
    use tendril_runtime::StateStore;

    let cli_dir = TempDir::new().unwrap();
    assert!(run_tendril(cli_dir.path(), &["init"]).status.success());

    let host_identity = EndpointIdentity::generate().unwrap();
    let store = StateStore::open_or_create(cli_dir.path()).unwrap();
    store
        .update_roster(|rst| {
            rst.insert_pinned_host(
                host_identity.host_id().to_owned(),
                "v2-floored-host".to_owned(),
                *host_identity.static_key().public_bytes(),
                Some(host_identity.signing_key().public_key().clone()),
                host_identity.rotation_seq(),
                vec![],
            )?;
            rst.upgrade_peer_to_v2(
                host_identity.host_id(),
                V2PeerSecrets::new([0x11; 32], [0x22; 32]),
            )?;
            assert_eq!(
                rst.pairing_floor(host_identity.static_key().public_bytes()),
                2
            );
            Ok(())
        })
        .unwrap();

    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let accept_thread = std::thread::spawn(move || {
        let (mut sock, _) = tcp.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut received = Vec::new();
        let _ = sock.read_to_end(&mut received);
        received
    });

    let uri = PairingUri {
        host_name: "v2-floored-host".to_owned(),
        code: "TND-1234-5678".to_owned(),
        host_static_pub: *host_identity.static_key().public_bytes(),
        host_signing_pub_hash: host_identity.signing_key().public_key().sha256_hash(),
        endpoints: vec![format!("direct:{addr}")],
        host_id: Some(host_identity.host_id().to_owned()),
        rotation_seq: Some(host_identity.rotation_seq()),
    }
    .encode();

    let pair_out = run_tendril(cli_dir.path(), &["pair", "--pairing-uri", &uri]);
    assert!(
        !pair_out.status.success(),
        "v1 pair against min_wire_version=2 host must fail closed"
    );
    let stderr = String::from_utf8_lossy(&pair_out.stderr);
    assert!(
        stderr.contains("VersionDowngrade"),
        "unexpected stderr: {stderr}"
    );

    let wire_bytes = accept_thread.join().unwrap();
    assert!(
        wire_bytes.is_empty(),
        "CLI v1 downgrade guard must reject before writing wire bytes, got {} bytes",
        wire_bytes.len()
    );
}

#[test]
fn cli_accepts_leading_hyphen_b64url_args() {
    use tendril_core::crypto::b64url_encode;

    let cli_dir = TempDir::new().unwrap();
    assert!(run_tendril(cli_dir.path(), &["init"]).status.success());

    // 0xf9, 0xc0 encodes to "-c..." in unpadded base64url.
    let leading_hyphen_nonce =
        b64url_encode(&[0xf9, 0xc0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    assert!(
        leading_hyphen_nonce.starts_with("-c"),
        "expected -c prefix, got {leading_hyphen_nonce}"
    );

    let revoke_out = run_tendril(cli_dir.path(), &["revoke-token", &leading_hyphen_nonce]);
    assert!(
        revoke_out.status.success(),
        "revoke-token should accept leading-hyphen b64url nonce, stderr: {}",
        String::from_utf8_lossy(&revoke_out.stderr)
    );

    let anchor_out = run_tendril(
        cli_dir.path(),
        &[
            "anchor",
            "add",
            "hyphen-anchor",
            "--signing-pub",
            &leading_hyphen_nonce,
        ],
    );
    let anchor_stderr = String::from_utf8_lossy(&anchor_out.stderr);
    assert!(
        !anchor_out.status.success() && !anchor_stderr.contains("unexpected argument"),
        "anchor add must parse leading-hyphen --signing-pub instead of failing in clap: {anchor_stderr}"
    );

    let enroll_out = run_tendril(
        cli_dir.path(),
        &[
            "enroll",
            "--endpoint",
            "127.0.0.1:1",
            "--host-id",
            "host-1",
            "--host-static-pub",
            &leading_hyphen_nonce,
            "--host-signing-pub",
            &leading_hyphen_nonce,
        ],
    );
    let enroll_stderr = String::from_utf8_lossy(&enroll_out.stderr);
    assert!(
        !enroll_out.status.success() && !enroll_stderr.contains("unexpected argument"),
        "enroll must parse leading-hyphen host keys instead of failing in clap: {enroll_stderr}"
    );

    let dial_out = run_tendril(
        cli_dir.path(),
        &[
            "dial",
            "--target",
            "host-1",
            "--endpoint",
            "127.0.0.1:1",
            "--grant",
            &leading_hyphen_nonce,
            "--message",
            "-c-message",
        ],
    );
    let dial_stderr = String::from_utf8_lossy(&dial_out.stderr);
    assert!(
        !dial_out.status.success() && !dial_stderr.contains("unexpected argument"),
        "dial must parse leading-hyphen --grant and --message instead of failing in clap: {dial_stderr}"
    );

    let pair_out = run_tendril(
        cli_dir.path(),
        &[
            "pair",
            "--endpoint",
            "127.0.0.1:1",
            "--code",
            "-c-pair-code",
        ],
    );
    let pair_stderr = String::from_utf8_lossy(&pair_out.stderr);
    assert!(
        !pair_out.status.success() && !pair_stderr.contains("unexpected argument"),
        "pair must parse leading-hyphen --code instead of failing in clap: {pair_stderr}"
    );
}

#[tokio::test]
async fn cli_e2e_relay_auth_ticket_and_hmac_gate() {
    use tendril_core::crypto::{b64url_decode_array, b64url_encode};
    use tendril_core::relay_auth::{RelayAuthScope, RelayTicket};
    use zeroize::Zeroizing;

    let host_dir = TempDir::new().expect("host dir");
    let client_dir = TempDir::new().expect("client dir");

    let init_host = run_tendril(host_dir.path(), &["init", "--host-id", "host-gated"]);
    assert!(init_host.status.success());
    let host_info: serde_json::Value =
        serde_json::from_slice(&init_host.stdout).expect("parse host init");
    let host_relay_pub_b64 = host_info["relay_pub"]
        .as_str()
        .expect("host relay_pub")
        .to_owned();
    let host_relay_pub: [u8; 32] =
        b64url_decode_array(&host_relay_pub_b64).expect("decode host relay_pub");

    let init_cli = run_tendril(client_dir.path(), &["init"]);
    assert!(init_cli.status.success());
    let cli_info: serde_json::Value =
        serde_json::from_slice(&init_cli.stdout).expect("parse cli init");
    let cli_dev_id = cli_info["device_id"]
        .as_str()
        .expect("cli dev id")
        .to_owned();

    // Exercise relay-ticket subcommand targeting host_relay_pub and leading-hyphen target parsing.
    let ticket_out = run_tendril(
        host_dir.path(),
        &[
            "relay-ticket",
            "--relay-host",
            "localhost",
            "--role",
            "any",
            "--target-pub",
            &host_relay_pub_b64,
            "--ttl-secs",
            "300",
        ],
    );
    assert!(
        ticket_out.status.success(),
        "relay-ticket failed: {}",
        String::from_utf8_lossy(&ticket_out.stderr)
    );
    let ticket: RelayTicket =
        serde_json::from_slice(&ticket_out.stdout).expect("parse relay ticket");
    assert_eq!(ticket.target_pub, host_relay_pub_b64);
    assert_eq!(ticket.relay_host, "localhost");

    let hyphen_target = b64url_encode(&[0xFB; 32]);
    assert!(hyphen_target.starts_with('-'));
    let hyphen_ticket_out = run_tendril(
        host_dir.path(),
        &[
            "relay-ticket",
            "--relay-host",
            "localhost",
            "--role",
            "dial",
            "--target-pub",
            &hyphen_target,
        ],
    );
    assert!(
        hyphen_ticket_out.status.success(),
        "relay-ticket should accept leading-hyphen --target-pub: {}",
        String::from_utf8_lossy(&hyphen_ticket_out.stderr)
    );

    let secret_file = host_dir.path().join("relay-secret.txt");
    std::fs::write(&secret_file, "cli-gated-hmac-secret\n").expect("write relay secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let world_readable_secret = host_dir.path().join("insecure-secret.txt");
    std::fs::write(&world_readable_secret, "cli-gated-hmac-secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &world_readable_secret,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    let wrong_secret_file = client_dir.path().join("wrong-secret.txt");
    std::fs::write(&wrong_secret_file, "wrong-hmac-secret\n").expect("write wrong secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrong_secret_file, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let ticket_file = client_dir.path().join("relay-ticket.json");
    std::fs::write(&ticket_file, &ticket_out.stdout).expect("write ticket file");

    let relay = RelayServer::bind(RelayConfig {
        host: "localhost".to_owned(),
        auth_secret: Some(Zeroizing::new(b"cli-gated-hmac-secret".to_vec())),
        trusted_issuers: vec![host_relay_pub],
        auth_scope: RelayAuthScope::All,
        ..RelayConfig::default()
    })
    .await
    .expect("bind gated relay");
    let relay_handle = relay.spawn();
    let relay_url = relay_handle.ws_url();

    tokio::task::spawn_blocking(move || {
        // Negative: insecure 0644 secret file must fail closed on Unix.
        #[cfg(unix)]
        {
            let bad_perm_serve = Command::new(tendril_bin())
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
                    "--relay-auth-secret-file",
                ])
                .arg(&world_readable_secret)
                .output()
                .expect("run bad perm serve");
            assert!(
                !bad_perm_serve.status.success(),
                "0644 secret file must be rejected"
            );
            assert!(
                String::from_utf8_lossy(&bad_perm_serve.stderr).contains("0600"),
                "stderr should recommend 0600: {}",
                String::from_utf8_lossy(&bad_perm_serve.stderr)
            );
        }

        // Negative: --relay-v2 without --wire-v2 must fail fast.
        let bad_v2_combo = run_tendril(
            host_dir.path(),
            &[
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--relay",
                &relay_url,
                "--relay-v2",
            ],
        );
        assert!(
            !bad_v2_combo.status.success(),
            "--relay-v2 without --wire-v2 must fail"
        );

        // Negative: unauthenticated serve fails when RelayAuthScope::All is enabled.
        let bad_serve = run_tendril(
            host_dir.path(),
            &[
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--relay",
                &relay_url,
                "--relay-host",
                "localhost",
            ],
        );
        assert!(
            !bad_serve.status.success(),
            "serve without auth must fail against gated relay"
        );

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
                    "--relay-auth-secret-file",
                ])
                .arg(&secret_file)
                .args(["--issue-code", "remote"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn gated serve"),
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

        // Negative: pair with wrong HMAC secret fails.
        let bad_pair = Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(client_dir.path())
            .args([
                "pair",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
                "--code",
                &code,
                "--relay-auth-secret-file",
            ])
            .arg(&wrong_secret_file)
            .output()
            .expect("run bad pair");
        assert!(
            !bad_pair.status.success(),
            "pair with wrong secret must fail against gated relay"
        );

        // Positive: client authenticates using Ed25519 relay ticket file.
        let ok_pair = Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(client_dir.path())
            .args([
                "pair",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
                "--code",
                &code,
                "--relay-ticket-file",
            ])
            .arg(&ticket_file)
            .output()
            .expect("run ticket pair");
        assert!(
            ok_pair.status.success(),
            "ticket pair failed: {}",
            String::from_utf8_lossy(&ok_pair.stderr)
        );
        let paired_info: serde_json::Value =
            serde_json::from_slice(&ok_pair.stdout).expect("pair json");
        let sas = paired_info["sas"].as_str().expect("sas");
        let paired_ev = read_json_line(&mut stdout);
        assert_eq!(paired_ev["event"], "paired");
        assert_eq!(paired_ev["sas"], sas);

        assert!(
            run_tendril(client_dir.path(), &["confirm", "host-gated", "--sas", sas])
                .status
                .success()
        );
        assert!(
            run_tendril(host_dir.path(), &["confirm", &cli_dev_id, "--sas", sas])
                .status
                .success()
        );
        let mint = run_tendril(host_dir.path(), &["mint", &cli_dev_id, "--cap", "fs.read"]);
        assert!(mint.status.success());
        let grant = String::from_utf8(mint.stdout).unwrap();

        let dial_out = Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(client_dir.path())
            .args([
                "dial",
                "--target",
                "host-gated",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
                "--relay-ticket-file",
            ])
            .arg(&ticket_file)
            .args(["--grant", &grant, "--message", "hello-gated-v1"])
            .output()
            .expect("run ticket dial");
        assert!(
            dial_out.status.success(),
            "ticket dial failed: {}",
            String::from_utf8_lossy(&dial_out.stderr)
        );
        let est = read_json_line(&mut stdout);
        assert_eq!(est["event"], "session_established");
        let ev = read_json_line(&mut stdout);
        assert_eq!(ev["event"], "data");
        assert_eq!(ev["utf8"], "hello-gated-v1");
    })
    .await
    .expect("spawn_blocking");
}

async fn accept_wake_post(listener: &tokio::net::TcpListener, wake_secret: &[u8; 32]) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    use tendril_runtime::{WakeTag, verify_epoch_wake_tag_window};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let (mut sock, _) = listener.accept().await.unwrap();
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
        let json: serde_json::Value =
            serde_json::from_slice(&buf[header_end..header_end + clen]).unwrap();
        let tag = WakeTag::from_b64url(json["wake_tag"].as_str().unwrap()).unwrap();
        let now_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(verify_epoch_wake_tag_window(wake_secret, &tag, now_s));
        sock.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let _ = sock.flush().await;
        return headers;
    }
}

#[tokio::test]
async fn cli_e2e_wire_v2_pair_relay_v2_downgrade_guard_and_http_wake() {
    use std::sync::Arc;
    use tendril_core::crypto::b64url_decode_array;
    use tendril_core::relay_auth::RelayAuthScope;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;
    use zeroize::Zeroizing;

    let host_dir = TempDir::new().expect("host dir");
    let client_dir = TempDir::new().expect("client dir");

    let init_host = run_tendril(host_dir.path(), &["init", "--host-id", "host-v2"]);
    assert!(init_host.status.success());
    let host_info: serde_json::Value = serde_json::from_slice(&init_host.stdout).unwrap();
    let host_relay_pub: [u8; 32] =
        b64url_decode_array(host_info["relay_pub"].as_str().unwrap()).unwrap();

    let init_cli = run_tendril(client_dir.path(), &["init"]);
    assert!(init_cli.status.success());
    let cli_info: serde_json::Value = serde_json::from_slice(&init_cli.stdout).unwrap();
    let cli_dev_id = cli_info["device_id"].as_str().unwrap().to_owned();

    let ticket_out = run_tendril(
        host_dir.path(),
        &["relay-ticket", "--relay-host", "localhost", "--role", "any"],
    );
    assert!(ticket_out.status.success());
    let ticket_file = client_dir.path().join("v2-ticket.json");
    std::fs::write(&ticket_file, &ticket_out.stdout).unwrap();

    let secret_file = host_dir.path().join("v2-hmac.txt");
    std::fs::write(&secret_file, "v2-cli-hmac-secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let wake_secret = [0x42u8; 32];
    let wake_secret_file = client_dir.path().join("wake-secret.txt");
    std::fs::write(
        &wake_secret_file,
        tendril_core::crypto::b64url_encode(&wake_secret),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wake_secret_file, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let wake_auth_file = client_dir.path().join("wake-auth.txt");
    std::fs::write(&wake_auth_file, "wake-bearer-tok\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wake_auth_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let relay = RelayServer::bind(RelayConfig {
        host: "localhost".to_owned(),
        auth_secret: Some(Zeroizing::new(b"v2-cli-hmac-secret".to_vec())),
        trusted_issuers: vec![host_relay_pub],
        auth_scope: RelayAuthScope::All,
        ..RelayConfig::default()
    })
    .await
    .expect("bind v2 relay");
    let relay_handle = relay.spawn();
    let relay_v1_url = relay_handle.ws_url();
    let relay_v2_url = relay_handle.ws_v2_url();

    // Loopback HTTP wake sink #1 (pre-wake with bearer token verification).
    let sink1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink1_addr = sink1.local_addr().unwrap();
    let sink1_task = tokio::spawn(async move {
        let headers = accept_wake_post(&sink1, &wake_secret).await;
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("authorization: bearer wake-bearer-tok"),
            "missing wake auth header: {headers}"
        );
    });

    // Loopback HTTP wake sink #2 (wake-on-demand when host serve is sleeping).
    let sink2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink2_addr = sink2.local_addr().unwrap();
    let woken_notify = Arc::new(Notify::new());
    let woken_notify_c = Arc::clone(&woken_notify);
    let sink2_task = tokio::spawn(async move {
        let _ = accept_wake_post(&sink2, &wake_secret).await;
        woken_notify_c.notify_one();
    });

    let host_dir_path = host_dir.path().to_path_buf();
    let client_dir_path = client_dir.path().to_path_buf();
    let secret_file_c = secret_file.clone();
    let ticket_file_c = ticket_file.clone();
    let wake_secret_c = wake_secret_file.clone();
    let wake_auth_c = wake_auth_file.clone();
    let v1_c = relay_v1_url.clone();
    let v2_c = relay_v2_url.clone();

    let grant = tokio::task::spawn_blocking(move || {
        let mut serve1 = KillOnDrop(
            Command::new(tendril_bin())
                .arg("--state-dir")
                .arg(&host_dir_path)
                .args([
                    "serve",
                    "--listen",
                    "127.0.0.1:0",
                    "--relay",
                    &v1_c,
                    "--relay-host",
                    "localhost",
                    "--wire-v2",
                    "--relay-v2",
                    "--relay-auth-secret-file",
                ])
                .arg(&secret_file_c)
                .args(["--issue-code", "remote"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn serve1"),
        );

        let mut stdout1 = BufReader::new(serve1.0.stdout.take().expect("serve1 stdout"));
        let listening1 = read_json_line(&mut stdout1);
        assert_eq!(listening1["wire_v2"], true);
        let relay_ep = listening1["relay_endpoint"]
            .as_str()
            .expect("relay_endpoint")
            .to_owned();
        let code = listening1["pairing_code"]
            .as_str()
            .expect("pairing_code")
            .to_owned();

        // Pair with --wire-v2 over gated /v1/relay.
        let pair_v2 = Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(&client_dir_path)
            .args([
                "pair",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
                "--wire-v2",
                "--code",
                &code,
                "--relay-ticket-file",
            ])
            .arg(&ticket_file_c)
            .output()
            .expect("pair --wire-v2");
        assert!(
            pair_v2.status.success(),
            "pair --wire-v2 failed: {}",
            String::from_utf8_lossy(&pair_v2.stderr)
        );
        let paired_info: serde_json::Value =
            serde_json::from_slice(&pair_v2.stdout).expect("pair v2 json");
        let sas = paired_info["sas"].as_str().expect("sas");
        let paired_ev = read_json_line(&mut stdout1);
        assert_eq!(paired_ev["event"], "paired");
        assert_eq!(paired_ev["sas"], sas);

        assert!(
            run_tendril(&client_dir_path, &["confirm", "host-v2", "--sas", sas])
                .status
                .success()
        );
        assert!(
            run_tendril(&host_dir_path, &["confirm", &cli_dev_id, "--sas", sas])
                .status
                .success()
        );
        let mint = run_tendril(&host_dir_path, &["mint", &cli_dev_id, "--cap", "fs.read"]);
        assert!(mint.status.success());
        let grant = String::from_utf8(mint.stdout).unwrap();

        // Anti-downgrade: dialing a v2-pinned host without --wire-v2 must fail closed.
        let downgraded = Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(&client_dir_path)
            .args([
                "dial",
                "--target",
                "host-v2",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "localhost",
                "--relay-ticket-file",
            ])
            .arg(&ticket_file_c)
            .args(["--grant", &grant, "--message", "must-not-downgrade"])
            .output()
            .expect("run downgraded dial");
        assert!(
            !downgraded.status.success(),
            "dial without --wire-v2 against v2-pinned host must fail closed"
        );

        // Wait briefly for dynamic RelayV2Listener sync inside running serve1, then dial /v2/relay with --wake-pre-wake.
        std::thread::sleep(std::time::Duration::from_millis(400));
        let wake_url1 = format!("http://{sink1_addr}/wake");
        let dial_v2 = Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(&client_dir_path)
            .args([
                "dial",
                "--target",
                "host-v2",
                "--endpoint",
                &v2_c,
                "--relay-host",
                "localhost",
                "--wire-v2",
                "--relay-v2",
                "--wake-url",
                &wake_url1,
                "--wake-adapter",
                "webhook",
                "--wake-secret-file",
            ])
            .arg(&wake_secret_c)
            .arg("--wake-auth-header-file")
            .arg(&wake_auth_c)
            .arg("--wake-pre-wake")
            .arg("--relay-ticket-file")
            .arg(&ticket_file_c)
            .args(["--grant", &grant, "--message", "hello-v2-dynamic"])
            .output()
            .expect("run v2 dial");
        assert!(
            dial_v2.status.success(),
            "v2 dial failed: {}",
            String::from_utf8_lossy(&dial_v2.stderr)
        );
        let est1 = read_json_line(&mut stdout1);
        assert_eq!(est1["event"], "session_established");
        let ev1 = read_json_line(&mut stdout1);
        assert_eq!(ev1["event"], "data");
        assert_eq!(ev1["utf8"], "hello-v2-dynamic");

        drop(serve1);
        grant
    })
    .await
    .unwrap();

    sink1_task.await.unwrap();

    // Phase 2: host sleeps until HTTP wake sink2 fires, then starts serve --relay-v2 and accepts client dial.
    let v2_ep2 = relay_v2_url.clone();
    let wake_url2 = format!("http://{sink2_addr}/wake");
    let c_dir2 = client_dir.path().to_path_buf();
    let w_sec2 = wake_secret_file.clone();
    let t_file2 = ticket_file.clone();
    let grant_c = grant.clone();
    let dial_task = tokio::task::spawn_blocking(move || {
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(&c_dir2)
            .args([
                "dial",
                "--target",
                "host-v2",
                "--endpoint",
                &v2_ep2,
                "--relay-host",
                "localhost",
                "--wire-v2",
                "--relay-v2",
                "--wake-url",
                &wake_url2,
                "--wake-secret-file",
            ])
            .arg(&w_sec2)
            .arg("--relay-ticket-file")
            .arg(&t_file2)
            .args(["--grant", &grant_c, "--message", "woken-by-cli-http"])
            .output()
            .expect("run sleeping-host v2 dial")
    });

    woken_notify.notified().await;
    sink2_task.await.unwrap();

    let h_dir2 = host_dir.path().to_path_buf();
    let v1_u2 = relay_v1_url.clone();
    let sec_f2 = secret_file.clone();
    let serve2_task = tokio::task::spawn_blocking(move || {
        let mut serve2 = KillOnDrop(
            Command::new(tendril_bin())
                .arg("--state-dir")
                .arg(&h_dir2)
                .args([
                    "serve",
                    "--listen",
                    "127.0.0.1:0",
                    "--relay",
                    &v1_u2,
                    "--relay-host",
                    "localhost",
                    "--wire-v2",
                    "--relay-v2",
                    "--relay-auth-secret-file",
                ])
                .arg(&sec_f2)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn serve2"),
        );
        let mut stdout2 = BufReader::new(serve2.0.stdout.take().expect("serve2 stdout"));
        let listening2 = read_json_line(&mut stdout2);
        let v2_eps = listening2["relay_v2_endpoints"]
            .as_array()
            .expect("relay_v2_endpoints array");
        assert!(
            !v2_eps.is_empty(),
            "pre-paired v2 host serve must report relay_v2_endpoints: {listening2:?}"
        );
        let est2 = read_json_line(&mut stdout2);
        assert_eq!(est2["event"], "session_established");
        let ev2 = read_json_line(&mut stdout2);
        assert_eq!(ev2["event"], "data");
        assert_eq!(ev2["utf8"], "woken-by-cli-http");
        serve2
    });

    let (dial_res, serve2_res) = tokio::join!(dial_task, serve2_task);
    let dial_out2 = dial_res.unwrap();
    assert!(
        dial_out2.status.success(),
        "woken dial failed: {}",
        String::from_utf8_lossy(&dial_out2.stderr)
    );
    let _serve2_guard = serve2_res.unwrap();
}

#[tokio::test]
async fn cli_e2e_conformance_peer_v2_relay_auth_and_wake() {
    use tendril_core::crypto::{b64url_decode_array, b64url_encode};
    use tendril_core::relay_auth::RelayAuthScope;
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    let mut host = PeerProc::spawn();
    let mut client = PeerProc::spawn();

    let host_init = host.call(serde_json::json!({ "op": "init", "host_id": "peer-v2-host" }));
    let host_relay_pub: [u8; 32] =
        b64url_decode_array(host_init["relay_pub"].as_str().unwrap()).unwrap();
    let client_init = client.call(serde_json::json!({ "op": "init" }));
    let client_dev_id = client_init["device_id"].as_str().unwrap().to_owned();

    let relay = RelayServer::bind(RelayConfig {
        host: "localhost".to_owned(),
        auth_secret: Some(Zeroizing::new(b"peer-hmac-secret".to_vec())),
        trusted_issuers: vec![host_relay_pub],
        auth_scope: RelayAuthScope::All,
        ..RelayConfig::default()
    })
    .await
    .expect("bind gated relay");
    let relay_handle = relay.spawn();
    let relay_v1_url = relay_handle.ws_url();
    let relay_v2_url = relay_handle.ws_v2_url();

    // Unknown transport config field must fail closed.
    host.send_cmd(&serde_json::json!({
        "op": "configure_transports",
        "unknown_field": true
    }));
    let bad_cfg = host.recv_resp();
    assert_eq!(bad_cfg["ok"], false);

    host.call(serde_json::json!({
        "op": "configure_transports",
        "relay_auth_secret": "peer-hmac-secret",
        "p2p_relay_mode": "disabled"
    }));
    let ticket_resp = host.call(serde_json::json!({
        "op": "mint_relay_ticket",
        "relay_host": "localhost",
        "role": "any",
        "target_pub": "*",
        "ttl_secs": 300
    }));
    let ticket_val = ticket_resp["ticket"].clone();

    let wake_secret = [0x5Au8; 32];
    let wake_sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wake_addr = wake_sink.local_addr().unwrap();
    let wake_task = tokio::spawn(async move {
        let _ = accept_wake_post(&wake_sink, &wake_secret).await;
    });

    client.call(serde_json::json!({
        "op": "configure_transports",
        "relay_ticket": ticket_val,
        "p2p_relay_mode": "disabled",
        "wake_url": format!("http://{wake_addr}/wake"),
        "wake_adapter": "webhook",
        "wake_secret_b64": b64url_encode(&wake_secret),
        "wake_pre_wake": true,
        "wake_retry_delay_ms": 50,
        "wake_max_attempts": 25
    }));

    tokio::task::spawn_blocking(move || {
        let srv = host.call(serde_json::json!({
            "op": "serve_relay",
            "relay_url": relay_v1_url,
            "expected_host": "localhost"
        }));
        let ep1 = srv["endpoint"].as_str().unwrap().to_owned();
        let issued = host.call(serde_json::json!({ "op": "issue_code", "kind": "remote" }));
        let code = issued["code"].as_str().unwrap().to_owned();

        host.send_cmd(&serde_json::json!({ "op": "pair_v2_accept", "timeout_ms": 10000 }));
        let init_v2 = client.call(serde_json::json!({
            "op": "pair_v2_initiate",
            "endpoint": ep1,
            "relay_host": "localhost",
            "code": code,
            "name": "peer-cli",
            "kind": "cli"
        }));
        let acc_v2 = host.recv_resp();
        assert_eq!(acc_v2["ok"], true, "pair_v2_accept failed: {acc_v2:?}");
        assert_eq!(init_v2["host_id"], "peer-v2-host");
        assert_eq!(init_v2["wire_version"], 2);
        let sas = init_v2["sas"].as_str().unwrap().to_owned();

        client.call(serde_json::json!({ "op": "confirm", "peer_id": "peer-v2-host", "sas": sas }));
        host.call(serde_json::json!({ "op": "confirm", "peer_id": client_dev_id, "sas": sas }));
        let grant_resp = host.call(serde_json::json!({
            "op": "mint",
            "peer_id": client_dev_id,
            "caps": ["fs.read"]
        }));
        let grant = grant_resp["grant"].clone();

        let srv2 = host.call(serde_json::json!({
            "op": "serve_relay_v2",
            "relay_url": relay_v2_url,
            "expected_host": "localhost"
        }));
        let ep2 = srv2["endpoint"].as_str().unwrap().to_owned();

        host.send_cmd(&serde_json::json!({ "op": "accept_v2", "timeout_ms": 10000 }));
        client.call(serde_json::json!({
            "op": "connect_v2",
            "endpoint": ep2,
            "relay_host": "localhost",
            "target_host_id": "peer-v2-host",
            "grant": grant
        }));
        let acc_sess = host.recv_resp();
        assert_eq!(acc_sess["ok"], true, "accept_v2 failed: {acc_sess:?}");

        client.call(serde_json::json!({ "op": "send", "data_utf8": "hello-peer-v2" }));
        let recv_ev = host.call(serde_json::json!({ "op": "recv", "timeout_ms": 5000 }));
        assert_eq!(recv_ev["data_utf8"], "hello-peer-v2");

        let auth = host.call(serde_json::json!({ "op": "authorize", "cap": "fs.read" }));
        assert_eq!(auth["allowed"], true);
        client.call(serde_json::json!({ "op": "rekey" }));
        client.call(serde_json::json!({ "op": "close" }));
    })
    .await
    .expect("spawn_blocking peer test");

    wake_task.await.unwrap();
}
