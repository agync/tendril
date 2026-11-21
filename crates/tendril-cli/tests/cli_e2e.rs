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
