//! Tendril reference CLI (`tendril`) for identity, pairing, grants, serving, and dialing.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::{b64url_encode, random_bytes};
use tendril_core::grants::Grant;
use tendril_core::pairing::{
    PairOutcome, PairingCodeKind, PairingConfig, PairingManager, PairingPathKind,
};
use tendril_core::policy::ProviderId;
use tendril_core::wire::{Intent, Preamble};
use tendril_runtime::{
    DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, LocalDialer, PathDialer, PathListener,
    PathStream, PreAuthConfig, PreAuthRateLimiter, PrefixedPathStream, RelayDialer, RelayListener,
    SessionDriver, SessionEvent, StateStore, drive_pair_initiator, drive_pair_responder,
    peek_exact,
};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Debug, Parser)]
#[command(name = "tendril", about = "Tendril private device-to-device CLI")]
struct Cli {
    #[arg(long, default_value = ".tendril")]
    state_dir: PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PairKindArg {
    Lan,
    Remote,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize or load endpoint identity and roster state directory.
    Init {
        #[arg(long)]
        host_id: Option<String>,
    },
    /// Serve incoming pairing and session connections over direct TCP and optional relay.
    Serve {
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        relay_host: Option<String>,
        #[arg(long, value_enum)]
        issue_code: Option<PairKindArg>,
    },
    /// Pair with a remote host using a one-time pairing code.
    Pair {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        code: String,
        #[arg(long, default_value = "device")]
        name: String,
        #[arg(long, default_value = "cli")]
        kind: String,
        #[arg(long)]
        relay_host: Option<String>,
    },
    /// Confirm a pending paired peer (`pair.confirm`), moving it to Active with zero capabilities.
    Confirm {
        peer_id: String,
        #[arg(long)]
        sas: Option<String>,
    },
    /// Mint a signed capability grant (`pair.mint`) for an Active peer.
    Mint {
        peer_id: String,
        #[arg(long = "cap", required = true)]
        caps: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
    },
    /// Open an authenticated session to a pinned host and optionally send one payload.
    Dial {
        #[arg(long)]
        target: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        relay_host: Option<String>,
        #[arg(long)]
        grant: Option<String>,
        #[arg(long)]
        message: Option<String>,
    },
    /// Revoke an existing peer (`pair.revoke`), failing closed on all future sessions.
    Revoke { peer_id: String },
}

#[derive(Serialize)]
struct InitOut {
    host_id: String,
    device_id: String,
    static_pub: String,
    signing_pub: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn print_json_line<T: Serialize>(value: &T) {
    if let Ok(line) = serde_json::to_string(value) {
        println!("{line}");
    }
}

async fn dial_endpoint(
    endpoint: &str,
    relay_host: Option<&str>,
) -> Result<Box<dyn PathStream>, Box<dyn std::error::Error>> {
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        let mut dialer = RelayDialer::new();
        if let Some(host) = relay_host {
            dialer = dialer.with_expected_host(host);
        }
        Ok(dialer.dial(endpoint).await?)
    } else if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        let dialer = LocalDialer::new();
        Ok(dialer.dial(endpoint).await?)
    } else {
        let dialer = DirectDialer::new();
        Ok(dialer.dial(endpoint).await?)
    }
}

async fn handle_inbound(
    mut stream: Box<dyn PathStream>,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    rate_limiter: PreAuthRateLimiter,
) {
    let Ok(peeked) = peek_exact(stream.as_mut(), PREAMBLE_LEN).await else {
        return;
    };
    let Ok(preamble) = Preamble::decode(&peeked[..PREAMBLE_LEN]) else {
        return;
    };
    let mut wrapped: Box<dyn PathStream> = Box::new(PrefixedPathStream::new(stream, peeked));
    let now = now_unix();

    match preamble.intent {
        Intent::Pair => {
            let path_kind = if wrapped.provider_id() == ProviderId::Relay {
                PairingPathKind::Remote
            } else {
                PairingPathKind::Lan
            };
            let current_roster = {
                let _guard = store_lock.lock().await;
                store.load_roster().unwrap_or_default()
            };
            let roster_sync = StdMutex::new(current_roster);
            match drive_pair_responder(
                wrapped.as_mut(),
                &identity,
                &pair_mgr,
                &roster_sync,
                path_kind,
                now,
                Some(&rate_limiter),
            )
            .await
            {
                Ok(res) => match res.outcome {
                    PairOutcome::ResponderPending {
                        device_id,
                        device_static_pub,
                        pairing_sas,
                        name,
                        kind,
                        ..
                    } => {
                        let _guard = store_lock.lock().await;
                        let mut persisted = store.load_roster().unwrap_or_default();
                        let _ = persisted.record_pending_pair(
                            device_static_pub,
                            None,
                            name,
                            kind,
                            pairing_sas.clone(),
                        );
                        let _ = store.save_roster(&persisted);
                        print_json_line(&serde_json::json!({
                            "event": "paired",
                            "device_id": device_id,
                            "sas": pairing_sas,
                        }));
                    }
                    PairOutcome::Rejected { error } => {
                        print_json_line(&serde_json::json!({
                            "event": "pair_rejected",
                            "error": error,
                        }));
                    }
                    PairOutcome::InitiatorPending { .. } => {}
                },
                Err(err) => {
                    tracing::debug!(error = %err, "pair responder error");
                }
            }
        }
        Intent::Session => {
            let mut roster = {
                let _guard = store_lock.lock().await;
                store.load_roster().unwrap_or_default()
            };
            let Ok(mut driver) =
                SessionDriver::accept(wrapped, &identity, &mut roster, now, Some(&rate_limiter))
                    .await
            else {
                tracing::debug!("inbound session rejected");
                return;
            };
            let peer_id = driver.peer_device_id().unwrap_or_default().to_owned();
            print_json_line(&serde_json::json!({
                "event": "session_established",
                "peer_device_id": peer_id,
                "provider": format!("{:?}", driver.provider_id()),
            }));
            while let Ok(Some(ev)) = driver.next_event(now_unix(), &mut roster).await {
                match ev {
                    SessionEvent::AppData(data) => {
                        print_json_line(&serde_json::json!({
                            "event": "data",
                            "len": data.len(),
                            "utf8": String::from_utf8_lossy(&data),
                        }));
                    }
                    SessionEvent::Closed { code, reason } => {
                        print_json_line(&serde_json::json!({
                            "event": "closed",
                            "code": code,
                            "reason": reason,
                        }));
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn await_pong(
    driver: &mut SessionDriver,
    roster: &mut tendril_core::roster::Roster,
    cookie: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    driver.send_ping(cookie).await?;
    let wait = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match driver.next_event(now_unix(), roster).await? {
                Some(SessionEvent::PongReceived(got)) if got == cookie => {
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
                Some(SessionEvent::Closed { code, reason }) => {
                    return Err(format!("peer closed session ({code}): {reason}").into());
                }
                Some(_) => continue,
                None => return Err("peer closed transport before pong".into()),
            }
        }
    })
    .await;
    match wait {
        Ok(inner) => inner,
        Err(_) => Err("timed out waiting for peer pong".into()),
    }
}

fn load_grant_arg(arg: &str) -> Result<Grant, Box<dyn std::error::Error>> {
    if let Some(path) = arg.strip_prefix('@') {
        let content = std::fs::read_to_string(Path::new(path))?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(serde_json::from_str(arg)?)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let store = Arc::new(StateStore::open_or_create(&cli.state_dir)?);

    match cli.cmd {
        Command::Init { host_id } => {
            let id = store.load_or_generate_identity(host_id.as_deref())?;
            let roster = store.load_roster()?;
            store.save_roster(&roster)?;
            print_json_line(&InitOut {
                host_id: id.host_id().to_owned(),
                device_id: id.device_id(),
                static_pub: b64url_encode(id.static_key().public_bytes()),
                signing_pub: b64url_encode(id.signing_key().public_bytes()),
            });
        }
        Command::Serve {
            listen,
            relay,
            relay_host,
            issue_code,
        } => {
            let identity = Arc::new(store.load_or_generate_identity(None)?);
            let store_lock = Arc::new(AsyncMutex::new(()));
            let pair_mgr = Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default())));
            let rate_limiter = PreAuthRateLimiter::new(PreAuthConfig::default());

            let issued = if let Some(kind_arg) = issue_code {
                let kind = match kind_arg {
                    PairKindArg::Lan => PairingCodeKind::Lan2Group,
                    PairKindArg::Remote => PairingCodeKind::Remote3Group,
                };
                Some(
                    pair_mgr
                        .lock()
                        .expect("lock")
                        .issue_code(kind, now_unix())?,
                )
            } else {
                None
            };

            let mut direct_listener = DirectListener::bind(listen, None).await?;
            let direct_ep = direct_listener.local_endpoint();
            let mut relay_listener = if let Some(relay_url) = relay {
                Some(
                    RelayListener::bind(
                        relay_url,
                        relay_host,
                        identity.signing_key().signing_key(),
                        DEFAULT_WRITE_TIMEOUT,
                    )
                    .await?,
                )
            } else {
                None
            };
            let relay_ep = relay_listener.as_ref().map(PathListener::local_endpoint);

            print_json_line(&serde_json::json!({
                "event": "listening",
                "host_id": identity.host_id(),
                "device_id": identity.device_id(),
                "direct_endpoint": direct_ep,
                "relay_endpoint": relay_ep,
                "pairing_code": issued,
            }));

            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    res = direct_listener.accept() => {
                        if let Ok(stream) = res {
                            tokio::spawn(handle_inbound(
                                stream,
                                Arc::clone(&store),
                                Arc::clone(&store_lock),
                                Arc::clone(&identity),
                                Arc::clone(&pair_mgr),
                                rate_limiter.clone(),
                            ));
                        }
                    }
                    res = async {
                        match relay_listener.as_mut() {
                            Some(rl) => Some(rl.accept().await),
                            None => std::future::pending().await,
                        }
                    } => {
                        if let Some(Ok(stream)) = res {
                            tokio::spawn(handle_inbound(
                                stream,
                                Arc::clone(&store),
                                Arc::clone(&store_lock),
                                Arc::clone(&identity),
                                Arc::clone(&pair_mgr),
                                rate_limiter.clone(),
                            ));
                        }
                    }
                }
            }
        }
        Command::Pair {
            endpoint,
            code,
            name,
            kind,
            relay_host,
        } => {
            let identity = store.load_or_generate_identity(None)?;
            let mut roster = store.load_roster()?;
            let mut stream = dial_endpoint(&endpoint, relay_host.as_deref()).await?;
            let res =
                drive_pair_initiator(stream.as_mut(), &identity, name, kind, code, None).await?;
            match res.outcome {
                PairOutcome::InitiatorPending {
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    pairing_sas,
                    ..
                } => {
                    roster.insert_pinned_host(
                        host_id.clone(),
                        host_id.clone(),
                        host_static_pub,
                        Some(host_signing_pub),
                        host_rotation_seq,
                        Vec::new(),
                    )?;
                    store.save_roster(&roster)?;
                    print_json_line(&serde_json::json!({
                        "paired_host_id": host_id,
                        "sas": pairing_sas,
                        "static_pub": b64url_encode(&host_static_pub),
                        "signing_pub": b64url_encode(&host_signing_pub),
                    }));
                }
                PairOutcome::Rejected { error } => {
                    return Err(format!("pairing rejected: {error}").into());
                }
                PairOutcome::ResponderPending { .. } => {
                    return Err("unexpected responder outcome".into());
                }
            }
        }
        Command::Confirm { peer_id, sas } => {
            let mut roster = store.load_roster()?;
            roster.confirm_peer(&peer_id, sas.as_deref())?;
            store.save_roster(&roster)?;
            print_json_line(&serde_json::json!({ "confirmed": peer_id }));
        }
        Command::Mint {
            peer_id,
            caps,
            ttl_secs,
        } => {
            let identity = store.load_identity()?;
            let mut roster = store.load_roster()?;
            let now = now_unix();
            let nonce = random_bytes::<16>()?;
            let grant = roster.mint_grant(&identity, &peer_id, caps, now, now + ttl_secs, nonce)?;
            store.save_roster(&roster)?;
            print_json_line(&grant);
        }
        Command::Dial {
            target,
            endpoint,
            relay_host,
            grant,
            message,
        } => {
            let identity = store.load_identity()?;
            let mut roster = store.load_roster()?;
            let grant_obj = grant.as_deref().map(load_grant_arg).transpose()?;
            let stream = dial_endpoint(&endpoint, relay_host.as_deref()).await?;
            let mut driver = SessionDriver::connect(
                stream,
                &identity,
                &target,
                grant_obj,
                &mut roster,
                now_unix(),
            )
            .await?;
            let provider = format!("{:?}", driver.provider_id());
            await_pong(&mut driver, &mut roster, 1).await?;
            if let Some(msg) = message {
                driver.send_data(msg.as_bytes()).await?;
                await_pong(&mut driver, &mut roster, 2).await?;
            }
            driver.send_close(1000, "done").await?;
            print_json_line(&serde_json::json!({
                "connected": target,
                "provider": provider,
            }));
        }
        Command::Revoke { peer_id } => {
            let mut roster = store.load_roster()?;
            roster.revoke_peer(&peer_id)?;
            store.save_roster(&roster)?;
            print_json_line(&serde_json::json!({ "revoked": peer_id }));
        }
    }

    Ok(())
}
