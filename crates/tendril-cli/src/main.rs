//! Tendril reference CLI (`tendril`) for identity, pairing, grants, serving, and dialing.

use std::io::Read;
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
    PairOutcome, PairingCodeKind, PairingConfig, PairingManager, PairingUri,
};
use tendril_core::wire::{Intent, Preamble};
use tendril_runtime::{
    BrokerListener, BrokerServerConfig, DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT,
    DirectListener, EmbeddedRelay, HalfOpenGuard, OverlayListener, P2pDialer, P2pListener,
    P2pOptions, P2pRelayMode, PathDialer, PathListener, PathStream, PreAuthConfig,
    PreAuthRateLimiter, PrefixedPathStream, RelayListener, SessionDriver, SessionEvent, StateStore,
    dial_endpoint as runtime_dial_endpoint, drive_pair_initiator,
    drive_pair_responder_with_options, pairing_path_kind_for_provider, parse_p2p_relay_mode,
    peek_exact,
};
use tokio::sync::Mutex as AsyncMutex;
use zeroize::{Zeroize, Zeroizing};

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
        #[arg(long, conflicts_with = "p2p_local", value_name = "MODE_OR_URL")]
        p2p_relay: Option<String>,
        #[arg(long)]
        no_pkarr: bool,
        #[arg(long)]
        ephemeral_p2p: bool,
        #[arg(long)]
        include_direct_addrs: bool,
        #[arg(long)]
        overlay: Option<SocketAddr>,
        #[arg(long)]
        broker: Option<SocketAddr>,
        #[arg(long, value_enum)]
        issue_code: Option<PairKindArg>,
    },
    /// Pair with a remote host using a one-time pairing code or `tendril://pair?...` URI.
    Pair {
        #[arg(long, required_unless_present = "pairing_uri")]
        endpoint: Option<String>,
        #[arg(long, conflicts_with_all = ["code_stdin", "code_file"])]
        code: Option<String>,
        #[arg(long, conflicts_with_all = ["code", "code_file"])]
        code_stdin: bool,
        #[arg(long, value_name = "PATH", conflicts_with_all = ["code", "code_stdin"])]
        code_file: Option<PathBuf>,
        #[arg(long)]
        pairing_uri: Option<String>,
        #[arg(long, default_value = "device")]
        name: String,
        #[arg(long, default_value = "cli")]
        kind: String,
        #[arg(long)]
        relay_host: Option<String>,
        #[arg(long)]
        p2p_local: bool,
        #[arg(long, conflicts_with = "p2p_local", value_name = "MODE_OR_URL")]
        p2p_relay: Option<String>,
        #[arg(long)]
        no_pkarr: bool,
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
        #[arg(long, conflicts_with = "p2p_local", value_name = "MODE_OR_URL")]
        p2p_relay: Option<String>,
        #[arg(long)]
        no_pkarr: bool,
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
    p2p_relay: Option<&str>,
    no_pkarr: bool,
) -> Result<Box<dyn PathStream>, Box<dyn std::error::Error>> {
    let relay_spec = p2p_relay
        .or(relay_host)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://")
        && (p2p_local
            || relay_spec.is_some()
            || no_pkarr
            || std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1"))
    {
        let mode = if p2p_local
            || (relay_spec.is_none() && std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1"))
        {
            P2pRelayMode::Disabled
        } else if let Some(spec) = relay_spec {
            parse_p2p_relay_mode(Some(spec))?
        } else {
            P2pRelayMode::Default
        };
        let mut opts = P2pOptions::for_dialer(mode);
        if no_pkarr {
            opts = opts.with_resolve_pkarr(false);
        }
        let dialer = P2pDialer::bind_with_options(opts).await?;
        return match dialer.dial(endpoint).await {
            Ok(stream) => Ok(stream),
            Err(err) => {
                dialer.close().await;
                Err(err.into())
            }
        };
    }
    Ok(runtime_dial_endpoint(endpoint, relay_host).await?)
}

fn trim_secret_code(mut raw: String) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let trimmed = raw.trim_end_matches(['\r', '\n']).trim().to_owned();
    raw.zeroize();
    if trimmed.is_empty() {
        return Err("pairing code input is empty".into());
    }
    Ok(Zeroizing::new(trimmed))
}

fn resolve_pair_code(
    code: Option<String>,
    code_stdin: bool,
    code_file: Option<PathBuf>,
    uri_code: Option<&str>,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let env_raw = match std::env::var("TENDRIL_PAIR_CODE") {
        Ok(val) if !val.is_empty() => Some(Zeroizing::new(val)),
        Ok(_) | Err(_) => None,
    };
    let explicit_count = usize::from(code.is_some())
        + usize::from(code_stdin)
        + usize::from(code_file.is_some())
        + usize::from(env_raw.is_some());
    if explicit_count > 1 {
        return Err(
            "conflicting pairing code sources: supply only one of --code, --code-stdin, --code-file, or TENDRIL_PAIR_CODE"
                .into(),
        );
    }
    if let Some(c) = code {
        return trim_secret_code(c);
    }
    if code_stdin {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut buf)?;
        let out = trim_secret_code(std::mem::take(&mut *buf))?;
        return Ok(out);
    }
    if let Some(path) = code_file {
        let content = Zeroizing::new(std::fs::read_to_string(&path)?);
        return trim_secret_code(content.as_str().to_owned());
    }
    if let Some(env_val) = env_raw {
        return trim_secret_code(env_val.as_str().to_owned());
    }
    if let Some(u_code) = uri_code {
        return trim_secret_code(u_code.to_owned());
    }
    Err("pairing code (--code, --code-stdin, --code-file, TENDRIL_PAIR_CODE, or --pairing-uri) is required".into())
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
            let path_kind = pairing_path_kind_for_provider(wrapped.provider_id());
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
                        if let Err(err) = store.update_roster(|persisted| {
                            persisted
                                .record_pending_pair(
                                    device_static_pub,
                                    None,
                                    name,
                                    kind,
                                    pairing_sas.clone(),
                                )
                                .map(|_| ())
                                .map_err(Into::into)
                        }) {
                            tracing::error!(error = %err, "failed to record paired peer");
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
            let (mut roster, initial_stamp) = {
                let _guard = store_lock.lock().await;
                match store.load_roster_with_stamp() {
                    Ok(pair) => pair,
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
            let mut last_stamp = initial_stamp;
            loop {
                let ev_res = driver
                    .next_event_with_refresh(&mut roster, Duration::from_millis(250), |mem| {
                        let current_stamp = store.roster_stamp()?;
                        if current_stamp != last_stamp {
                            let (disk, fresh_stamp) = store.load_roster_with_stamp()?;
                            *mem = disk;
                            last_stamp = fresh_stamp;
                            return Ok(true);
                        }
                        Ok(false)
                    })
                    .await;
                match ev_res {
                    Ok(Some(SessionEvent::AppData(data))) => {
                        print_json_line(&serde_json::json!({
                            "event": "data",
                            "len": data.len(),
                            "utf8": String::from_utf8_lossy(&data),
                        }));
                    }
                    Ok(Some(SessionEvent::RevocationUpdated { issuer, seq })) => {
                        persist_session_crl(
                            store.as_ref(),
                            store_lock.as_ref(),
                            identity.as_ref(),
                            &mut roster,
                            &issuer,
                            &mut last_stamp,
                        )
                        .await;
                        print_json_line(&serde_json::json!({
                            "event": "revocation_updated",
                            "issuer": issuer,
                            "seq": seq,
                        }));
                        if let Err(err) = driver.tick(now_unix(), &roster).await {
                            print_json_line(&serde_json::json!({
                                "event": "closed",
                                "code": 1000,
                                "reason": err.to_string(),
                            }));
                            break;
                        }
                    }
                    Ok(Some(SessionEvent::Closed { code, reason })) => {
                        print_json_line(&serde_json::json!({
                            "event": "closed",
                            "code": code,
                            "reason": reason,
                        }));
                        break;
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(err) => {
                        for issuer in [identity.host_id(), peer_id.as_str()] {
                            persist_session_crl(
                                store.as_ref(),
                                store_lock.as_ref(),
                                identity.as_ref(),
                                &mut roster,
                                issuer,
                                &mut last_stamp,
                            )
                            .await;
                        }
                        print_json_line(&serde_json::json!({
                            "event": "closed",
                            "code": 1000,
                            "reason": err.to_string(),
                        }));
                        break;
                    }
                }
            }
        }
    }
}

fn persist_crl_for_issuer(
    store: &StateStore,
    identity: &tendril_core::identity::EndpointIdentity,
    roster: &tendril_core::roster::Roster,
    issuer: &str,
) -> Result<
    Option<(
        tendril_core::roster::Roster,
        Option<tendril_runtime::RosterStamp>,
    )>,
    tendril_runtime::RuntimeError,
> {
    let Some(crl) = roster.crl(issuer).cloned() else {
        return Ok(None);
    };
    let ((), disk, stamp) = store.update_roster_with_state(|disk| {
        let issuer_pub = if issuer == identity.host_id() {
            Some(*identity.signing_key().public_bytes())
        } else {
            disk.lookup_active_signing_key(issuer).or_else(|| {
                disk.get(issuer)
                    .filter(|e| e.state != tendril_core::roster::PeerState::Pending)
                    .and_then(|e| e.signing_pub)
            })
        };
        let Some(pk) = issuer_pub else {
            return Ok(());
        };
        if let Err(err) = disk.ingest_crl(crl, issuer, &pk)
            && !matches!(err, tendril_core::error::CoreError::CrlStaleSeq { .. })
        {
            return Err(err.into());
        }
        Ok(())
    })?;
    Ok(Some((disk, stamp)))
}

async fn persist_session_crl(
    store: &StateStore,
    store_lock: &AsyncMutex<()>,
    identity: &tendril_core::identity::EndpointIdentity,
    roster: &mut tendril_core::roster::Roster,
    issuer: &str,
    last_stamp: &mut Option<tendril_runtime::RosterStamp>,
) {
    let _guard = store_lock.lock().await;
    match persist_crl_for_issuer(store, identity, roster, issuer) {
        Ok(Some((disk, stamp))) => {
            *roster = disk;
            *last_stamp = stamp;
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = %err, "failed to persist session CRL update");
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
            p2p_relay,
            no_pkarr,
            ephemeral_p2p,
            include_direct_addrs,
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

            let p2p_ep = if p2p || p2p_local || p2p_relay.is_some() {
                let mode = if p2p_local {
                    P2pRelayMode::Disabled
                } else if let Some(spec) = p2p_relay.as_deref() {
                    parse_p2p_relay_mode(Some(spec))?
                } else if std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1") {
                    P2pRelayMode::Disabled
                } else {
                    P2pRelayMode::Default
                };
                let mut opts = P2pOptions::for_listener(mode);
                if no_pkarr {
                    opts = opts.with_publish_pkarr(false).with_resolve_pkarr(false);
                }
                if include_direct_addrs {
                    opts = opts.with_advertise_direct_addrs(true);
                }
                let seed = if ephemeral_p2p {
                    None
                } else {
                    Some(identity.derive_p2p_identity_seed())
                };
                let pl = P2pListener::bind_with_options(opts, seed).await?;
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
                .try_acquire_for_stream(
                    stream.provider_id(),
                    stream.peer_ip(),
                    stream.peer_transport_id().as_deref(),
                ) {
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
            code_stdin,
            code_file,
            pairing_uri,
            name,
            kind,
            relay_host,
            p2p_local,
            p2p_relay,
            no_pkarr,
        } => {
            let parsed_uri = pairing_uri.as_deref().map(PairingUri::parse).transpose()?;
            let pinned_host = parsed_uri.as_ref().map(PairingUri::to_pinned_host);
            let effective_code = resolve_pair_code(
                code,
                code_stdin,
                code_file,
                parsed_uri.as_ref().map(|u| u.code.as_str()),
            )?;
            let effective_endpoint = match endpoint {
                Some(ep) => ep,
                None => parsed_uri
                    .as_ref()
                    .and_then(|u| u.endpoints.first())
                    .map(|hint| {
                        for prefix in ["direct:", "relay:", "overlay:", "broker:", "local:", "p2p:"]
                        {
                            if let Some(rest) = hint.strip_prefix(prefix) {
                                return rest.to_owned();
                            }
                        }
                        hint.clone()
                    })
                    .ok_or("endpoint or URI ep hint is required")?,
            };
            let identity = store.load_or_generate_identity(None)?;
            let mut stream = dial_endpoint(
                &effective_endpoint,
                relay_host.as_deref(),
                p2p_local,
                p2p_relay.as_deref(),
                no_pkarr,
            )
            .await?;
            let res = drive_pair_initiator(
                stream.as_mut(),
                &identity,
                name,
                kind,
                effective_code.as_str().to_owned(),
                pinned_host,
            )
            .await;
            let _ = stream.close().await;
            let res = res?;
            match res.outcome {
                PairOutcome::InitiatorPending {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    pairing_sas,
                    host_pin_verified,
                } => {
                    let display_name = parsed_uri
                        .as_ref()
                        .map(|u| u.host_name.clone())
                        .unwrap_or_else(|| host_id.clone());
                    let hints = parsed_uri
                        .as_ref()
                        .map(|u| u.endpoints.clone())
                        .unwrap_or_default();
                    let host_id_out = host_id.clone();
                    let sas_out = pairing_sas.clone();
                    store.update_roster(|roster| {
                        if host_pin_verified {
                            roster
                                .insert_pinned_host(
                                    host_id,
                                    display_name,
                                    host_static_pub,
                                    Some(host_signing_pub),
                                    host_rotation_seq,
                                    hints,
                                )
                                .map(|_| ())
                                .map_err(Into::into)
                        } else {
                            roster
                                .record_pending_host(
                                    host_id,
                                    display_name,
                                    host_static_pub,
                                    host_signing_pub,
                                    host_rotation_seq,
                                    pairing_sas,
                                    hints,
                                )
                                .map(|_| ())
                                .map_err(Into::into)
                        }
                    })?;
                    print_json_line(&serde_json::json!({
                        "device_id": device_id,
                        "paired_host_id": host_id_out,
                        "sas": sas_out,
                        "status": if host_pin_verified { "active" } else { "pending" },
                        "host_confirmed": host_pin_verified,
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
            store.update_roster(|roster| {
                roster
                    .confirm_peer(&peer_id, sas.as_deref())
                    .map(|_| ())
                    .map_err(Into::into)
            })?;
            print_json_line(&serde_json::json!({ "confirmed": peer_id }));
        }
        Command::Mint {
            peer_id,
            caps,
            ttl_secs,
        } => {
            let identity = store.load_identity()?;
            let now = now_unix();
            let nonce = random_bytes::<16>()?;
            let grant = store.update_roster(|roster| {
                roster
                    .mint_grant(
                        &identity,
                        &peer_id,
                        caps,
                        now,
                        now.saturating_add(ttl_secs),
                        nonce,
                    )
                    .map_err(Into::into)
            })?;
            print_json_line(&grant);
        }
        Command::Dial {
            target,
            endpoint,
            relay_host,
            p2p_local,
            p2p_relay,
            no_pkarr,
            grant,
            message,
        } => {
            let identity = store.load_identity()?;
            let mut roster = store.load_roster()?;
            let initial_seq = roster.get(&target).map(|e| e.rotation_seq);
            let grant_obj = grant.as_deref().map(load_grant_arg).transpose()?;
            let stream = dial_endpoint(
                &endpoint,
                relay_host.as_deref(),
                p2p_local,
                p2p_relay.as_deref(),
                no_pkarr,
            )
            .await?;
            let connect_res = SessionDriver::connect(
                stream,
                &identity,
                &target,
                grant_obj,
                &mut roster,
                now_unix(),
            )
            .await;
            if let Err(err) = &connect_res
                && roster
                    .get(&target)
                    .is_some_and(|e| e.state == tendril_core::roster::PeerState::Revoked)
            {
                let _ = store.update_roster(|disk| {
                    let _ = disk.revoke_peer(&target);
                    Ok(())
                });
                return Err(err.to_string().into());
            }
            let mut driver = connect_res?;
            let chain = driver.applied_rotation().to_vec();
            if !chain.is_empty()
                && let Some(rotated) = roster.get(&target).cloned()
                && rotated.rotation_seq > initial_seq.unwrap_or(0)
                && let Some(signing_pub) = rotated.signing_pub
            {
                store.update_roster(|disk| {
                    if let Some(entry) = disk.get(&target)
                        && entry.state == tendril_core::roster::PeerState::Active
                        && entry.rotation_seq < rotated.rotation_seq
                    {
                        disk.apply_verified_rotation(
                            &target,
                            &chain,
                            &rotated.static_pub,
                            &signing_pub,
                        )?;
                    }
                    Ok(())
                })?;
            }
            let provider = format!("{:?}", driver.provider_id());
            let session_res: Result<(), Box<dyn std::error::Error>> = async {
                await_pong(&mut driver, &mut roster, 1).await?;
                if let Some(msg) = message {
                    driver.send_data(msg.as_bytes()).await?;
                    await_pong(&mut driver, &mut roster, 2).await?;
                }
                driver.send_close(1000, "done").await?;
                Ok(())
            }
            .await;
            let persist_res = persist_crl_for_issuer(&store, &identity, &roster, &target);
            if let Err(err) = &persist_res {
                tracing::error!(error = %err, "failed to persist dial session CRL update");
            }
            session_res?;
            let _ = persist_res?;
            print_json_line(&serde_json::json!({
                "connected": target,
                "provider": provider,
            }));
        }
        Command::Revoke { peer_id } => {
            store.update_roster(|roster| roster.revoke_peer(&peer_id).map_err(Into::into))?;
            print_json_line(&serde_json::json!({ "revoked": peer_id }));
        }
    }

    Ok(())
}
