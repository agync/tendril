//! CLI route management and the seamless Day-2 acceptance flows.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use tendril_relay::{RelayConfig, RelayServer};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

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

fn run_tendril(state_dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(tendril_bin())
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .output()
        .expect("run tendril bin")
}

fn json_out(out: &std::process::Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout json")
}

fn read_json_line(reader: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read stdout line");
    assert!(n > 0, "unexpected EOF waiting for subprocess JSON line");
    serde_json::from_str(&line).expect("parse subprocess json line")
}

/// Reads host lines up to the next established session and its data frame.
fn expect_session(stdout: &mut BufReader<ChildStdout>, provider: &str, message: &str) {
    loop {
        let line = read_json_line(stdout);
        if line["event"] == "session_established" {
            assert_eq!(line["provider"], provider, "{line}");
            break;
        }
    }
    loop {
        let line = read_json_line(stdout);
        if line["event"] == "data" {
            assert_eq!(line["utf8"], message, "{line}");
            break;
        }
    }
}

struct Serve {
    _child: KillOnDrop,
    stdout: BufReader<ChildStdout>,
    listening: serde_json::Value,
}

fn serve(state_dir: &std::path::Path, args: &[&str]) -> Serve {
    let mut child = KillOnDrop(
        Command::new(tendril_bin())
            .arg("--state-dir")
            .arg(state_dir)
            .arg("serve")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve"),
    );
    let mut stdout = BufReader::new(child.0.stdout.take().expect("serve stdout"));
    let listening = read_json_line(&mut stdout);
    assert_eq!(listening["event"], "listening", "{listening}");
    Serve {
        _child: child,
        stdout,
        listening,
    }
}

struct Peers {
    host: TempDir,
    client: TempDir,
    client_id: String,
}

fn init_peers(host_id: &str) -> Peers {
    let host = TempDir::new().expect("host dir");
    let client = TempDir::new().expect("client dir");
    assert!(
        run_tendril(host.path(), &["init", "--host-id", host_id])
            .status
            .success()
    );
    let init = json_out(&run_tendril(client.path(), &["init"]));
    Peers {
        host,
        client,
        client_id: init["device_id"].as_str().expect("device id").to_owned(),
    }
}

/// Pairs over the host's signed URI, confirms on the host and returns a grant.
fn pair_uri_and_grant(peers: &Peers, host: &mut Serve) -> (serde_json::Value, String) {
    let uri = host.listening["pairing_uri"].as_str().expect("pairing_uri");
    let paired = json_out(&run_tendril(
        peers.client.path(),
        &["pair", "--pairing-uri", uri],
    ));
    assert_eq!(paired["route_check"], "verified", "{paired}");
    assert_eq!(paired["status"], "active");
    assert_eq!(read_json_line(&mut host.stdout)["event"], "paired");
    let sas = paired["sas"].as_str().expect("sas");
    assert!(
        run_tendril(
            peers.host.path(),
            &["confirm", &peers.client_id, "--sas", sas]
        )
        .status
        .success()
    );
    let mint = run_tendril(
        peers.host.path(),
        &["mint", &peers.client_id, "--cap", "fs.read"],
    );
    assert!(mint.status.success());
    (
        paired,
        String::from_utf8(mint.stdout).unwrap().trim().to_owned(),
    )
}

fn dial(peers: &Peers, target: &str, grant: &str, message: &str) -> serde_json::Value {
    json_out(&run_tendril(
        peers.client.path(),
        &[
            "dial",
            "--target",
            target,
            "--grant",
            grant,
            "--message",
            message,
        ],
    ))
}

fn route_list(peers: &Peers, target: &str) -> serde_json::Value {
    json_out(&run_tendril(
        peers.client.path(),
        &["route", "list", "--target", target],
    ))
}

fn hints(routes: &serde_json::Value, source: &str) -> Vec<String> {
    routes["routes"]
        .as_array()
        .expect("routes")
        .iter()
        .filter(|r| r["source"] == source)
        .map(|r| r["hint"].as_str().unwrap().to_owned())
        .collect()
}

/// A loopback TCP forwarder standing in for one host listener; stopping it refuses new dials.
struct Forwarder {
    port: u16,
    target: Arc<Mutex<Option<SocketAddr>>>,
    task: JoinHandle<()>,
}

impl Forwarder {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind forwarder");
        let port = listener.local_addr().unwrap().port();
        let target: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
        let target_c = Arc::clone(&target);
        let task = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            while let Ok((mut inbound, _)) = listener.accept().await {
                let Some(addr) = *target_c.lock().unwrap() else {
                    continue;
                };
                conns.spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(addr).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        Self { port, target, task }
    }

    fn forward_to(&self, endpoint: &str) {
        let port = endpoint
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .expect("listener port");
        *self.target.lock().unwrap() = Some(SocketAddr::from(([127, 0, 0, 1], port)));
    }

    fn stop(&self) {
        self.task.abort();
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("blocking task")
}

#[test]
fn route_set_list_clear_and_apply() {
    let peers = init_peers("host-routes");
    let host_args = [
        "--listen",
        "127.0.0.1:0",
        "--embedded-relay",
        "--relay-host",
        "127.0.0.1",
        "--issue-code",
        "auto",
    ];
    let mut host = serve(peers.host.path(), &host_args);
    let uri1 = host.listening["pairing_uri"].as_str().unwrap().to_owned();
    let seq1 = host.listening["route_seq"].as_u64().unwrap();
    let (paired, _grant) = pair_uri_and_grant(&peers, &mut host);
    let signed1: Vec<String> = paired["routes_persisted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["hint"].as_str().unwrap().to_owned())
        .collect();
    drop(host);

    let listed = route_list(&peers, "host-routes");
    assert_eq!(hints(&listed, "signed"), signed1);
    assert_eq!(listed["route_meta"]["seq"], seq1);
    assert_eq!(listed["route_meta"]["origin"], "uri");
    assert!(listed["last_route_set"].is_null());

    let set = |eps: &[&str]| {
        let mut args = vec!["route", "set", "--target", "host-routes"];
        for ep in eps {
            args.extend(["--endpoint", ep]);
        }
        json_out(&run_tendril(peers.client.path(), &args))
    };
    let first = set(&["127.0.0.1:1111", "127.0.0.1:2222"]);
    assert_eq!(
        hints(&first, "operator"),
        ["direct:127.0.0.1:1111", "direct:127.0.0.1:2222"]
    );
    let replaced = set(&["127.0.0.1:3333"]);
    assert_eq!(hints(&replaced, "operator"), ["direct:127.0.0.1:3333"]);
    assert_eq!(hints(&replaced, "signed"), signed1);
    assert!(
        !run_tendril(
            peers.client.path(),
            &["route", "set", "--target", "host-routes"]
        )
        .status
        .success(),
        "route set without --endpoint needs --clear"
    );

    let cleared_signed = json_out(&run_tendril(
        peers.client.path(),
        &[
            "route",
            "clear",
            "--target",
            "host-routes",
            "--source",
            "signed",
        ],
    ));
    assert!(hints(&cleared_signed, "signed").is_empty());
    assert_eq!(
        hints(&cleared_signed, "operator"),
        ["direct:127.0.0.1:3333"]
    );
    assert_eq!(cleared_signed["route_meta"]["seq"], seq1);

    let cleared = json_out(&run_tendril(
        peers.client.path(),
        &["route", "clear", "--target", "host-routes"],
    ));
    assert!(hints(&cleared, "operator").is_empty());
    set(&["127.0.0.1:4444"]);
    let emptied = json_out(&run_tendril(
        peers.client.path(),
        &["route", "set", "--target", "host-routes", "--clear"],
    ));
    assert!(emptied["routes"].as_array().unwrap().is_empty());

    // A restarted host serves a new relay port, so it issues a newer route sequence.
    let host2 = serve(peers.host.path(), &host_args);
    let uri2 = host2.listening["pairing_uri"].as_str().unwrap().to_owned();
    let seq2 = host2.listening["route_seq"].as_u64().unwrap();
    assert!(seq2 > seq1);
    let advertised2: Vec<String> = host2.listening["advertised_endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    drop(host2);

    let apply = |uri: &str, extra: &[&str]| {
        let mut args = vec!["route", "apply", "--pairing-uri", uri];
        args.extend(extra);
        json_out(&run_tendril(peers.client.path(), &args))
    };
    let fresh = apply(&uri2, &[]);
    assert_eq!(fresh["applied"], true, "{fresh}");
    assert_eq!(fresh["target"], "host-routes");
    assert_eq!(hints(&fresh, "signed"), advertised2);
    assert_eq!(fresh["route_meta"]["seq"], seq2);
    assert_eq!(fresh["route_meta"]["origin"], "uri");

    let stale = apply(&uri1, &[]);
    assert_eq!(stale["applied"], false);
    assert_eq!(stale["reason"], "stale_route_seq");
    assert_eq!(hints(&stale, "signed"), advertised2);

    let approved = apply(&uri1, &["--replace-routes"]);
    assert_eq!(approved["applied"], true);
    assert_eq!(hints(&approved, "signed"), signed1);
    assert_eq!(approved["route_meta"]["origin"], "approved");
    assert_eq!(approved["route_meta"]["seq"], seq2);
}

#[test]
fn errors_never_echo_credential_bearing_origins_or_uris() {
    let client = TempDir::new().expect("client dir");
    assert!(run_tendril(client.path(), &["init"]).status.success());
    let origin = "wss://user:hunter2@relay.example:8443/v1/relay?token=s3cret";
    let bad_uri = "tendril://pair?v=1&host=h&code=TND-ABCD-EFGH&s3cret=hunter2";
    for args in [
        vec![
            "pair",
            "--endpoint",
            "127.0.0.1:1",
            "--code",
            "TND-ABCD-EFGH",
            "--relay-auth-origin",
            origin,
        ],
        vec!["pair", "--pairing-uri", bad_uri],
        vec!["route", "apply", "--pairing-uri", bad_uri],
    ] {
        let out = run_tendril(client.path(), &args);
        assert!(!out.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("invalid --relay-auth-origin 'wss://relay.example:8443'")
                || stderr.contains("invalid pairing URI"),
            "{stderr}"
        );
        for leaked in ["hunter2", "s3cret", "TND-ABCD-EFGH"] {
            assert!(!stderr.contains(leaked), "{leaked} leaked: {stderr}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stored_relay_v2_route_from_route_set_dials_v2_relay() {
    let relay = RelayServer::bind(RelayConfig {
        host: "127.0.0.1".to_owned(),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let relay_handle = relay.spawn();
    let relay_url = relay_handle.ws_url();
    let relay_v2_url = relay_handle.ws_v2_url();

    blocking(move || {
        let peers = init_peers("host-v2-route");
        let mut host = serve(
            peers.host.path(),
            &[
                "--listen",
                "127.0.0.1:0",
                "--relay",
                &relay_url,
                "--relay-host",
                "127.0.0.1",
                "--wire-v2",
                "--relay-v2",
                "--issue-code",
                "remote",
            ],
        );
        let relay_ep = host.listening["relay_endpoint"]
            .as_str()
            .unwrap()
            .to_owned();
        let code = host.listening["pairing_code"].as_str().unwrap().to_owned();
        let paired = json_out(&run_tendril(
            peers.client.path(),
            &[
                "pair",
                "--wire-v2",
                "--endpoint",
                &relay_ep,
                "--relay-host",
                "127.0.0.1",
                "--code",
                &code,
            ],
        ));
        assert_eq!(paired["provider"], "Relay");
        assert_eq!(read_json_line(&mut host.stdout)["event"], "paired");
        let sas = paired["sas"].as_str().unwrap();
        assert!(
            run_tendril(
                peers.client.path(),
                &["confirm", "host-v2-route", "--sas", sas]
            )
            .status
            .success()
        );
        assert!(
            run_tendril(
                peers.host.path(),
                &["confirm", &peers.client_id, "--sas", sas]
            )
            .status
            .success()
        );
        let mint = run_tendril(
            peers.host.path(),
            &["mint", &peers.client_id, "--cap", "fs.read"],
        );
        assert!(mint.status.success());
        let grant = String::from_utf8(mint.stdout).unwrap();

        let set = json_out(&run_tendril(
            peers.client.path(),
            &[
                "route",
                "set",
                "--target",
                "host-v2-route",
                "--endpoint",
                &relay_v2_url,
            ],
        ));
        assert_eq!(hints(&set, "operator"), std::slice::from_ref(&relay_v2_url));

        // The host binds the peer's /v2/relay mailbox once its roster sync sees the confirm.
        std::thread::sleep(std::time::Duration::from_millis(600));
        let dialed = json_out(&run_tendril(
            peers.client.path(),
            &[
                "dial",
                "--wire-v2",
                "--target",
                "host-v2-route",
                "--grant",
                grant.trim(),
                "--message",
                "hello-stored-v2",
            ],
        ));
        assert_eq!(dialed["provider"], "Relay");
        assert_eq!(dialed["endpoint"], relay_v2_url.as_str());
        assert_eq!(dialed["wire_version"], 2);
        expect_session(&mut host.stdout, "Relay", "hello-stored-v2");
    })
    .await;
}

/// A1: one QR, then Day-2 dials walk the ladder (direct, overlay, relay) with no flags.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a1_ladder_pairs_on_lan_then_overlay_then_relay_without_prompts() {
    let direct = Forwarder::start().await;
    let overlay = Forwarder::start().await;
    let direct_hint = format!("direct:127.0.0.1:{}", direct.port);
    let overlay_hint = format!("overlay://127.0.0.1:{}", overlay.port);

    let peers = Arc::new(init_peers("host-ladder"));
    let p = Arc::clone(&peers);
    let (dh, oh) = (direct_hint.clone(), overlay_hint.clone());
    // Unspecified binds are not advertised; the advertised routes are the forwarders.
    let host = blocking(move || {
        serve(
            p.host.path(),
            &[
                "--listen",
                "0.0.0.0:0",
                "--overlay",
                "0.0.0.0:0",
                "--overlay-allow-non-tailnet",
                "--embedded-relay",
                "--relay-host",
                "127.0.0.1",
                "--advertise-endpoint",
                &dh,
                "--advertise-endpoint",
                &oh,
                "--issue-code",
                "auto",
            ],
        )
    })
    .await;
    direct.forward_to(host.listening["direct_endpoint"].as_str().unwrap());
    overlay.forward_to(host.listening["overlay_endpoint"].as_str().unwrap());
    let relay_hint = host.listening["embedded_relay_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let advertised = host.listening["advertised_endpoints"].clone();
    assert_eq!(
        advertised,
        serde_json::json!([direct_hint, overlay_hint, relay_hint])
    );

    let p = Arc::clone(&peers);
    let (mut host, paired, grant) = blocking(move || {
        let mut host = host;
        let (paired, grant) = pair_uri_and_grant(&p, &mut host);
        (host, paired, grant)
    })
    .await;
    assert_eq!(paired["provider"], "Direct");
    let persisted: Vec<&str> = paired["routes_persisted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            assert_eq!(r["source"], "signed");
            r["hint"].as_str().unwrap()
        })
        .collect();
    assert_eq!(persisted, [&direct_hint, &overlay_hint, &relay_hint]);

    let mut ladder = vec![
        ("Direct", direct_hint.clone()),
        ("Overlay", overlay_hint.clone()),
        ("Relay", relay_hint.clone()),
    ];
    for step in 0..3 {
        if step == 1 {
            direct.stop();
        } else if step == 2 {
            overlay.stop();
        }
        let (provider, hint) = ladder.remove(0);
        let p = Arc::clone(&peers);
        let g = grant.clone();
        let msg = format!("ladder-{step}");
        let (h, dialed) = blocking(move || {
            let dialed = dial(&p, "host-ladder", &g, &msg);
            expect_session(&mut host.stdout, provider, &msg);
            (host, dialed)
        })
        .await;
        host = h;
        assert_eq!(dialed["provider"], provider, "{dialed}");
        assert_eq!(dialed["endpoint"], hint.as_str(), "{dialed}");
    }
}

/// A2: the host's direct address changes; the next connect learns it from `0x0C` and the one
/// after goes straight to the new address. Operator routes survive the announcement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2_host_address_change_propagates_to_next_dial() {
    let relay = RelayServer::bind(RelayConfig {
        host: "127.0.0.1".to_owned(),
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let relay_handle = relay.spawn();
    let relay_url = relay_handle.ws_url();

    blocking(move || {
        let peers = init_peers("host-moves");
        let host_args = |extra: &[&'static str]| {
            let mut args = vec![
                "--listen".to_owned(),
                "127.0.0.1:0".to_owned(),
                "--relay".to_owned(),
                relay_url.clone(),
                "--relay-host".to_owned(),
                "127.0.0.1".to_owned(),
            ];
            args.extend(extra.iter().map(|s| (*s).to_owned()));
            args
        };
        let args1 = host_args(&["--issue-code", "auto"]);
        let mut host1 = serve(
            peers.host.path(),
            &args1.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let p1 = format!(
            "direct:{}",
            host1.listening["direct_endpoint"].as_str().unwrap()
        );
        let seq1 = host1.listening["route_seq"].as_u64().unwrap();
        let (paired, grant) = pair_uri_and_grant(&peers, &mut host1);
        let signed: Vec<&str> = paired["routes_persisted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["hint"].as_str().unwrap())
            .collect();
        assert_eq!(signed, [p1.as_str(), relay_url.as_str()]);
        json_out(&run_tendril(
            peers.client.path(),
            &[
                "route",
                "set",
                "--target",
                "host-moves",
                "--endpoint",
                &relay_url,
            ],
        ));
        drop(host1);

        // The host comes back on a new direct port and publishes seq + 1 at startup.
        let args2 = host_args(&[]);
        let mut host2 = serve(
            peers.host.path(),
            &args2.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let p3 = format!(
            "direct:{}",
            host2.listening["direct_endpoint"].as_str().unwrap()
        );
        assert_ne!(p3, p1);
        let seq2 = host2.listening["route_seq"].as_u64().unwrap();
        assert!(seq2 > seq1);

        let first = dial(&peers, "host-moves", &grant, "after-move-1");
        expect_session(&mut host2.stdout, "Relay", "after-move-1");
        assert_eq!(first["provider"], "Relay", "{first}");
        assert!(
            first["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["hint"] == p1.as_str()),
            "the stale address is tried and fails: {first}"
        );
        assert_eq!(
            first["route_set"],
            serde_json::json!({"outcome": "applied", "seq": seq2}),
            "{first}"
        );

        let listed = route_list(&peers, "host-moves");
        assert_eq!(hints(&listed, "signed"), [p3.clone(), relay_url.clone()]);
        assert_eq!(hints(&listed, "operator"), std::slice::from_ref(&relay_url));
        assert_eq!(listed["route_meta"]["seq"], seq2);
        assert_eq!(listed["route_meta"]["origin"], "session");
        assert_eq!(listed["last_route_set"]["outcome"], "applied");

        let second = dial(&peers, "host-moves", &grant, "after-move-2");
        expect_session(&mut host2.stdout, "Direct", "after-move-2");
        assert_eq!(second["provider"], "Direct", "{second}");
        assert_eq!(second["endpoint"], p3.as_str());
        assert_eq!(second["failures"], serde_json::json!([]), "{second}");
    })
    .await;
}

/// A loopback HTTP wake sink that answers every request and counts wake POSTs.
async fn wake_sink() -> (String, Arc<std::sync::atomic::AtomicUsize>, JoinHandle<()>) {
    wake_sink_with(|| {}).await
}

/// [`wake_sink`] that also runs `on_post` for each counted wake POST, before answering it.
async fn wake_sink_with(
    on_post: impl Fn() + Send + Sync + 'static,
) -> (String, Arc<std::sync::atomic::AtomicUsize>, JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sink");
    let url = format!("http://{}/wake", listener.local_addr().unwrap());
    let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let posts_c = Arc::clone(&posts);
    let on_post = Arc::new(on_post);
    let task = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let posts = Arc::clone(&posts_c);
            let on_post = Arc::clone(&on_post);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                let header_end = loop {
                    let Ok(n) = sock.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                // Foreign loopback probes are answered but never counted.
                if !headers.starts_with("POST /wake ") {
                    let _ = sock
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
                let clen = headers
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + clen {
                    match sock.read(&mut tmp).await {
                        Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
                        _ => return,
                    }
                }
                on_post();
                posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = sock
                    .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    (url, posts, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_dial_takes_a_recovery_uri_and_ingests_route_sets() {
    let (wake_url, posts, sink_task) = wake_sink().await;

    blocking(move || {
        let peers = init_peers("host-wakes");
        let wake_secret_file = peers.client.path().join("wake-secret.txt");
        std::fs::write(
            &wake_secret_file,
            tendril_core::crypto::b64url_encode(&[0x42u8; 32]),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wake_secret_file, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let host_args = [
            "--listen",
            "127.0.0.1:0",
            "--wire-v2",
            "--issue-code",
            "auto",
        ];
        let mut host1 = serve(peers.host.path(), &host_args);
        let uri1 = host1.listening["pairing_uri"].as_str().unwrap().to_owned();
        let paired = json_out(&run_tendril(
            peers.client.path(),
            &["pair", "--wire-v2", "--pairing-uri", &uri1],
        ));
        assert_eq!(paired["route_check"], "verified", "{paired}");
        assert_eq!(read_json_line(&mut host1.stdout)["event"], "paired");
        let sas = paired["sas"].as_str().expect("sas");
        assert!(
            run_tendril(
                peers.host.path(),
                &["confirm", &peers.client_id, "--sas", sas]
            )
            .status
            .success()
        );
        let mint = run_tendril(
            peers.host.path(),
            &["mint", &peers.client_id, "--cap", "fs.read"],
        );
        assert!(mint.status.success());
        let grant = String::from_utf8(mint.stdout).unwrap().trim().to_owned();
        drop(host1);

        // The host restarts on a new port; the client recovers with its fresh URI over a wake.
        let mut host2 = serve(peers.host.path(), &host_args);
        let ep2 = host2.listening["direct_endpoint"]
            .as_str()
            .unwrap()
            .to_owned();
        let uri2 = host2.listening["pairing_uri"].as_str().unwrap().to_owned();
        let seq2 = host2.listening["route_seq"].as_u64().unwrap();
        let secret = wake_secret_file.to_str().unwrap();
        let out = json_out(&run_tendril(
            peers.client.path(),
            &[
                "dial",
                "--target",
                "host-wakes",
                "--wire-v2",
                "--endpoint",
                &ep2,
                "--pairing-uri",
                &uri2,
                "--wake-url",
                &wake_url,
                "--wake-secret-file",
                secret,
                "--wake-pre-wake",
                "--grant",
                &grant,
                "--message",
                "woken-recovery",
            ],
        ));
        expect_session(&mut host2.stdout, "Direct", "woken-recovery");
        assert!(!out["wake_outcome"].is_null(), "{out}");
        assert_eq!(out["recovery_routes"], "replaced", "{out}");
        assert_eq!(
            out["route_set"]["seq"], seq2,
            "a route set was ingested: {out}"
        );
        let listed = route_list(&peers, "host-wakes");
        assert_eq!(hints(&listed, "signed"), [format!("direct:{ep2}")]);
    })
    .await;
    assert!(posts.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    sink_task.abort();
}

/// Writes a `0600` wake secret file into the client state directory.
fn wake_secret_file(peers: &Peers) -> std::path::PathBuf {
    let path = peers.client.path().join("wake-secret.txt");
    std::fs::write(&path, tendril_core::crypto::b64url_encode(&[0x42u8; 32])).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// Pairs over Wire v2 with the host's URI, confirms on the host and returns a grant.
fn pair_v2_and_grant(peers: &Peers, host: &mut Serve) -> String {
    let uri = host.listening["pairing_uri"].as_str().expect("pairing_uri");
    let paired = json_out(&run_tendril(
        peers.client.path(),
        &["pair", "--wire-v2", "--pairing-uri", uri],
    ));
    assert_eq!(paired["route_check"], "verified", "{paired}");
    assert_eq!(read_json_line(&mut host.stdout)["event"], "paired");
    let sas = paired["sas"].as_str().expect("sas");
    assert!(
        run_tendril(
            peers.host.path(),
            &["confirm", &peers.client_id, "--sas", sas]
        )
        .status
        .success()
    );
    let mint = run_tendril(
        peers.host.path(),
        &["mint", &peers.client_id, "--cap", "fs.read"],
    );
    assert!(mint.status.success());
    String::from_utf8(mint.stdout).unwrap().trim().to_owned()
}

/// Without `--wake-pre-wake`, a dial whose first connect misses on the transport sends the
/// wake hint and retries; the woken host then answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_dial_retries_a_transport_miss_after_waking() {
    // The forwarder stands in for the sleeping host: until the wake it closes every dial.
    let sleeping = Forwarder::start().await;
    let peers = Arc::new(init_peers("host-sleeps"));
    let p = Arc::clone(&peers);
    let (host, grant) = blocking(move || {
        let mut host = serve(
            p.host.path(),
            &[
                "--listen",
                "127.0.0.1:0",
                "--wire-v2",
                "--issue-code",
                "auto",
            ],
        );
        let grant = pair_v2_and_grant(&p, &mut host);
        (host, grant)
    })
    .await;
    let host_addr: SocketAddr = host.listening["direct_endpoint"]
        .as_str()
        .unwrap()
        .parse()
        .expect("direct endpoint");
    let wake_target = Arc::clone(&sleeping.target);
    let (wake_url, posts, sink_task) = wake_sink_with(move || {
        *wake_target.lock().unwrap() = Some(host_addr);
    })
    .await;
    let endpoint = format!("127.0.0.1:{}", sleeping.port);

    let out = blocking(move || {
        let mut host = host;
        let secret = wake_secret_file(&peers);
        let out = json_out(&run_tendril(
            peers.client.path(),
            &[
                "dial",
                "--target",
                "host-sleeps",
                "--wire-v2",
                "--endpoint",
                &endpoint,
                "--wake-url",
                &wake_url,
                "--wake-secret-file",
                secret.to_str().unwrap(),
                "--grant",
                &grant,
                "--message",
                "woken-after-miss",
            ],
        ));
        expect_session(&mut host.stdout, "Direct", "woken-after-miss");
        out
    })
    .await;
    assert!(
        !out["wake_outcome"].is_null(),
        "the miss sent a wake: {out}"
    );
    assert_eq!(posts.load(std::sync::atomic::Ordering::SeqCst), 1);
    sleeping.stop();
    sink_task.abort();
}

/// A message never echoes the secrets or codes planted in operator input.
fn assert_no_leak(text: &str) {
    let lower = text.to_ascii_lowercase();
    for leaked in ["s3cret", "abcd-efgh", "tok="] {
        assert!(!lower.contains(leaked), "{leaked} leaked: {text}");
    }
}

#[test]
fn serve_reports_dropped_endpoints_redacted() {
    let host = TempDir::new().expect("host dir");
    assert!(
        run_tendril(host.path(), &["init", "--host-id", "host-drops"])
            .status
            .success()
    );
    for issue in [&["--issue-code", "auto"][..], &[][..]] {
        let mut args = vec![
            "--listen",
            "127.0.0.1:0",
            "--advertise-endpoint",
            "ws://user:s3cret@relay.example/v1/relay?tok=s3cret",
            "--advertise-endpoint",
            "direct:TND-ABCD-EFGH:1",
        ];
        args.extend_from_slice(issue);
        let served = serve(host.path(), &args);
        let dropped = served.listening["dropped_endpoints"]
            .as_array()
            .unwrap_or_else(|| panic!("dropped_endpoints: {}", served.listening))
            .clone();
        let shown: Vec<&str> = dropped
            .iter()
            .map(|d| d["hint"].as_str().expect("hint"))
            .collect();
        assert!(shown.contains(&"ws://relay.example"), "{shown:?}");
        assert_eq!(dropped.len(), 2, "{dropped:?}");
        assert_no_leak(&served.listening["dropped_endpoints"].to_string());
        assert_no_leak(&served.listening["advertised_endpoints"].to_string());
    }
}

#[test]
fn p2p_relay_and_relay_host_errors_never_echo_the_url() {
    let client = TempDir::new().expect("client dir");
    assert!(run_tendril(client.path(), &["init"]).status.success());
    let secret_url = "https://u:s3cret@relay.example/x y?tok=s3cret TND-ABCD-EFGH";
    let iroh = "iroh://ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";
    for args in [
        vec![
            "dial",
            "--target",
            "nobody",
            "--endpoint",
            iroh,
            "--p2p-relay",
            secret_url,
            "--p2p-no-port-mapping",
        ],
        vec![
            "dial",
            "--target",
            "nobody",
            "--endpoint",
            iroh,
            "--relay-host",
            secret_url,
        ],
        vec![
            "pair",
            "--endpoint",
            iroh,
            "--code",
            "TND-WXYZ-QRST",
            "--p2p-relay",
            secret_url,
            "--p2p-no-port-mapping",
        ],
    ] {
        let out = run_tendril(client.path(), &args);
        assert!(!out.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("relay"), "{args:?}: {stderr}");
        assert_no_leak(&stderr);
    }
}

/// Without `--wake-pre-wake`, a permanent failure (here the relay refuses an unauthenticated
/// dial) ends the dial at once: no wake hint, no retries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_dial_fails_fast_on_a_permanent_error() {
    use tendril_core::relay_auth::RelayAuthScope;

    let relay = RelayServer::bind(RelayConfig {
        host: "127.0.0.1".to_owned(),
        auth_secret: Some(zeroize::Zeroizing::new(b"wake-fail-fast-secret".to_vec())),
        auth_scope: RelayAuthScope::All,
        ..RelayConfig::default()
    })
    .await
    .expect("bind relay");
    let relay_handle = relay.spawn();
    let v2_relay = relay_handle.ws_v2_url();
    let (wake_url, posts, sink_task) = wake_sink().await;

    let out = blocking(move || {
        let peers = init_peers("host-refused");
        let mut host = serve(
            peers.host.path(),
            &[
                "--listen",
                "127.0.0.1:0",
                "--wire-v2",
                "--issue-code",
                "auto",
            ],
        );
        let grant = pair_v2_and_grant(&peers, &mut host);
        let secret = wake_secret_file(&peers);
        run_tendril(
            peers.client.path(),
            &[
                "dial",
                "--target",
                "host-refused",
                "--wire-v2",
                "--relay-v2",
                "--relay-host",
                "127.0.0.1",
                "--endpoint",
                &v2_relay,
                "--wake-url",
                &wake_url,
                "--wake-secret-file",
                secret.to_str().unwrap(),
                "--grant",
                &grant,
                "--message",
                "never-sent",
            ],
        )
    })
    .await;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let failed = stderr
        .lines()
        .find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .filter(|v| v["event"] == "attempt_failed")
        })
        .unwrap_or_else(|| panic!("no attempt_failed line: {stderr}"));
    assert_eq!(failed["committed"], false, "{failed}");
    assert_eq!(
        posts.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a permanent failure sent a wake: {failed}"
    );
    sink_task.abort();
    let _ = relay_handle.stop().await;
}
