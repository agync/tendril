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
    BrokerListener, BrokerServerConfig, DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT,
    DirectListener, EmbeddedRelay, HalfOpenGuard, OverlayListener, P2pListener, P2pRelayMode,
    PathListener, PathStream, PreAuthConfig, PreAuthRateLimiter, PrefixedPathStream, RelayListener,
    SessionDriver, SessionEvent, StateStore, dial_endpoint as runtime_dial_endpoint,
    drive_pair_initiator, drive_pair_responder_with_options, peek_exact,
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
    /// Serve incoming pairing and session connections across configured path providers.
    Serve {
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        #[arg(long, conflicts_with = "embedded_relay")]
        relay: Option<String>,
        #[arg(long)]
        relay_host: Option<String>,
        #[arg(long)]
        embedded_relay: bool,
        #[arg(long, conflicts_with = "p2p_local")]
        p2p: bool,
        #[arg(long)]
        p2p_local: bool,
        #[arg(long)]
        overlay: Option<SocketAddr>,
        #[arg(long)]
        broker: Option<SocketAddr>,
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
        #[arg(long)]
        p2p_local: bool,
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
        p2p_local: bool,
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
    p2p_local: bool,
) -> Result<Box<dyn PathStream>, Box<dyn std::error::Error>> {
    let effective_hint = if endpoint.starts_with("iroh://")
        && (p2p_local || std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1"))
    {
        Some("disabled")
    } else {
        relay_host
    };
    Ok(runtime_dial_endpoint(endpoint, effective_hint).await?)
}

fn spawn_listener_pump(
    mut listener: Box<dyn PathListener>,
    tx: tokio::sync::mpsc::Sender<Box<dyn PathStream>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(stream) => {
                    if tx.send(stream).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "listener terminated");
                    break;
                }
            }
        }
    })
}

async fn handle_inbound(
    mut stream: Box<dyn PathStream>,
    pre_auth_guard: HalfOpenGuard,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    rate_limiter: PreAuthRateLimiter,
) {
    let Ok(Ok(peeked)) = tokio::time::timeout(
        DEFAULT_PRE_AUTH_TIMEOUT,
        peek_exact(stream.as_mut(), PREAMBLE_LEN),
    )
    .await
    else {
        return;
    };
    let Ok(preamble) = Preamble::decode(&peeked[..PREAMBLE_LEN]) else {
        return;
    };
    let mut wrapped: Box<dyn PathStream> = Box::new(PrefixedPathStream::new(stream, peeked));
    let now = now_unix();

    match preamble.intent {
        Intent::Pair => {
            let path_kind = match wrapped.provider_id() {
                ProviderId::Local | ProviderId::Direct => PairingPathKind::Lan,
                ProviderId::Overlay | ProviderId::P2p | ProviderId::Relay | ProviderId::Broker => {
                    PairingPathKind::Remote
                }
            };
            let current_roster = {
                let _guard = store_lock.lock().await;
                match store.load_roster() {
                    Ok(r) => r,
                    Err(err) => {
                        tracing::error!(error = %err, "failed to load roster before pair");
                        return;
                    }
                }
            };
            let roster_sync = StdMutex::new(current_roster);
            match drive_pair_responder_with_options(
                wrapped.as_mut(),
                &identity,
                &pair_mgr,
                &roster_sync,
                path_kind,
                now,
                Some(&rate_limiter),
                Some(pre_auth_guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
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
                        let mut persisted = match store.load_roster() {
                            Ok(r) => r,
                            Err(err) => {
                                tracing::error!(error = %err, "failed to reload roster after pair");
                                return;
                            }
                        };
                        if let Err(err) = persisted.record_pending_pair(
                            device_static_pub,
                            None,
                            name,
                            kind,
                            pairing_sas.clone(),
                        ) {
                            tracing::error!(error = %err, "failed to record paired peer");
                            return;
                        }
                        if let Err(err) = store.save_roster(&persisted) {
                            tracing::error!(error = %err, "failed to persist paired roster");
                            return;
                        }
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
                match store.load_roster() {
                    Ok(r) => r,
                    Err(err) => {
                        tracing::error!(error = %err, "failed to load roster before session");
                        return;
                    }
                }
            };
            let Ok(mut driver) = SessionDriver::accept_with_options(
                wrapped,
                &identity,
                &mut roster,
                now,
                Some(&rate_limiter),
                Some(pre_auth_guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
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
            embedded_relay,
            p2p,
            p2p_local,
            overlay,
            broker,
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

            let direct_listener = DirectListener::bind(listen, None).await?;
            let direct_ep = direct_listener.local_endpoint();
            let mut listeners: Vec<Box<dyn PathListener>> = vec![Box::new(direct_listener)];

            let (embedded_relay_handle, embedded_relay_url, effective_relay_url, effective_host) =
                if embedded_relay {
                    let host_name = relay_host.clone().unwrap_or_else(|| "localhost".to_owned());
                    let emb = EmbeddedRelay::bind_local(host_name.clone()).await?;
                    let ws_url = emb.ws_url();
                    (
                        Some(emb),
                        Some(ws_url.clone()),
                        Some(ws_url),
                        Some(host_name),
                    )
                } else {
                    (None, None, relay, relay_host)
                };

            let relay_ep = if let Some(relay_url) = effective_relay_url {
                let rl = RelayListener::bind(
                    relay_url,
                    effective_host,
                    identity.signing_key().signing_key(),
                    DEFAULT_WRITE_TIMEOUT,
                )
                .await?;
                let ep = rl.local_endpoint();
                listeners.push(Box::new(rl));
                Some(ep)
            } else {
                None
            };

            let p2p_ep = if p2p || p2p_local {
                let mode = if p2p_local {
                    P2pRelayMode::Disabled
                } else {
                    P2pRelayMode::Default
                };
                let seed = identity.derive_p2p_identity_seed();
                let pl = P2pListener::bind_with_secret(mode, *seed).await?;
                let ep = pl.local_endpoint();
                listeners.push(Box::new(pl));
                Some(ep)
            } else {
                None
            };

            let overlay_ep = if let Some(overlay_addr) = overlay {
                let ol = OverlayListener::bind(overlay_addr, None).await?;
                let ep = ol.local_endpoint();
                listeners.push(Box::new(ol));
                Some(ep)
            } else {
                None
            };

            let broker_ep = if let Some(broker_addr) = broker {
                let bl = BrokerListener::bind(BrokerServerConfig {
                    listen_addr: broker_addr,
                    ..BrokerServerConfig::default()
                })
                .await?;
                let ep = bl.local_endpoint();
                listeners.push(Box::new(bl));
                Some(ep)
            } else {
                None
            };

            print_json_line(&serde_json::json!({
                "event": "listening",
                "host_id": identity.host_id(),
                "device_id": identity.device_id(),
                "direct_endpoint": direct_ep,
                "relay_endpoint": relay_ep,
                "embedded_relay_url": embedded_relay_url,
                "p2p_endpoint": p2p_ep,
                "overlay_endpoint": overlay_ep,
                "broker_endpoint": broker_ep,
                "pairing_code": issued,
            }));

            let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel(64);
            let pump_handles: Vec<_> = listeners
                .into_iter()
                .map(|listener| spawn_listener_pump(listener, inbound_tx.clone()))
                .collect();
            drop(inbound_tx);

            let dispatch_stream = |stream: Box<dyn PathStream>| match rate_limiter
                .try_acquire_for_peer(stream.peer_ip(), stream.peer_transport_id().as_deref())
            {
                Ok(guard) => {
                    tokio::spawn(handle_inbound(
                        stream,
                        guard,
                        Arc::clone(&store),
                        Arc::clone(&store_lock),
                        Arc::clone(&identity),
                        Arc::clone(&pair_mgr),
                        rate_limiter.clone(),
                    ));
                }
                Err(err) => {
                    tracing::debug!(error = %err, "rejected inbound stream at pre-auth limit");
                }
            };

            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    maybe_stream = inbound_rx.recv() => {
                        match maybe_stream {
                            Some(stream) => dispatch_stream(stream),
                            None => break,
                        }
                    }
                }
            }

            for handle in pump_handles {
                handle.abort();
            }
            if let Some(emb) = embedded_relay_handle {
                let _ = emb.shutdown().await;
            }
        }
        Command::Pair {
            endpoint,
            code,
            name,
            kind,
            relay_host,
            p2p_local,
        } => {
            let identity = store.load_or_generate_identity(None)?;
            let mut roster = store.load_roster()?;
            let mut stream = dial_endpoint(&endpoint, relay_host.as_deref(), p2p_local).await?;
            let res =
                drive_pair_initiator(stream.as_mut(), &identity, name, kind, code, None).await;
            let _ = stream.close().await;
            let res = res?;
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
            let grant = roster.mint_grant(
                &identity,
                &peer_id,
                caps,
                now,
                now.saturating_add(ttl_secs),
                nonce,
            )?;
            store.save_roster(&roster)?;
            print_json_line(&grant);
        }
        Command::Dial {
            target,
            endpoint,
            relay_host,
            p2p_local,
            grant,
            message,
        } => {
            let identity = store.load_identity()?;
            let mut roster = store.load_roster()?;
            let grant_obj = grant.as_deref().map(load_grant_arg).transpose()?;
            let stream = dial_endpoint(&endpoint, relay_host.as_deref(), p2p_local).await?;
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
