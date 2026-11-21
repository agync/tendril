//! Tendril reference CLI (`tendril`) for identity, pairing, grants, serving, and dialing.

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::{
    SigningKeypair, StaticKeypair, b64url_decode_array, b64url_encode, random_bytes,
};
use tendril_core::grants::Grant;
use tendril_core::pairing::{
    DEFAULT_ENROLLMENT_TTL_SECS, EnrollmentPolicy, PairOutcome, PairingCodeKind, PairingConfig,
    PairingManager, PairingUri, PinnedHost, mint_enrollment_token,
};
use tendril_core::roster::AnchorState;
use tendril_core::wire::{Intent, Preamble};
use tendril_runtime::{
    BrokerListener, BrokerServerConfig, DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT,
    DirectListener, EmbeddedRelay, HalfOpenGuard, OverlayListener, P2pDialer, P2pListener,
    P2pOptions, P2pRelayMode, PathDialer, PathListener, PathStream, PreAuthConfig,
    PreAuthRateLimiter, PrefixedPathStream, RelayListener, SessionDriver, SessionEvent, StateStore,
    dial_endpoint as runtime_dial_endpoint, drive_m2m_enroll_initiator, drive_pair_initiator,
    drive_pair_responder_with_store, pairing_path_kind_for_provider, parse_p2p_relay_mode,
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
enum AnchorCommand {
    /// Register an active external Ed25519 trust anchor for M2M enrollment.
    Add {
        anchor_id: String,
        #[arg(long)]
        signing_pub: String,
    },
    /// Revoke an external trust anchor (and sibling anchors sharing its signing key).
    Revoke { anchor_id: String },
    /// List configured M2M trust anchors.
    List,
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
        #[arg(long)]
        allow_enroll: bool,
        #[arg(long)]
        redact_logs: bool,
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
    /// Manage external Ed25519 trust anchors for M2M enrollment.
    Anchor {
        #[command(subcommand)]
        cmd: AnchorCommand,
    },
    /// Mint a short-lived, single-use M2M enrollment token (`pair.enroll:<target_host>`).
    EnrollToken {
        #[arg(long)]
        target_host: String,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long, default_value_t = DEFAULT_ENROLLMENT_TTL_SECS)]
        ttl_secs: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Autonomously enroll with a pinned host using a single-use M2M enrollment token.
    Enroll {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        host_id: String,
        #[arg(long)]
        host_static_pub: String,
        #[arg(long)]
        host_signing_pub: String,
        #[arg(long, default_value_t = 0)]
        host_rotation_seq: u64,
        #[arg(long, value_name = "PATH", conflicts_with = "token_stdin")]
        token_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "token_file")]
        token_stdin: bool,
        #[arg(long, default_value = "machine")]
        name: String,
        #[arg(long, default_value = "machine")]
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
        #[arg(long, conflicts_with = "sas")]
        allow_no_sas: bool,
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
    /// Revoke an unused grant or enrollment token nonce on the signed local CRL.
    RevokeToken { nonce: String },
    /// Rotate local static and signing identity keys and re-sign any persisted self-CRL.
    Rotate,
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
        let line = Zeroizing::new(line);
        println!("{}", *line);
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

fn write_private_token_file(path: &Path, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            return Err(format!(
                "refusing to overwrite non-regular file or symlink '{}'",
                path.display()
            )
            .into());
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("token");
        let nonce = random_bytes::<8>()?;
        let tmp_path = parent.join(format!(".{file_name}.tmp.{}", b64url_encode(&nonce)));
        let res = (|| -> Result<(), Box<dyn std::error::Error>> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp_path, path)?;
            Ok(())
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        res
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
        Ok(())
    }
}

fn resolve_enroll_token(
    token_file: Option<PathBuf>,
    token_stdin: bool,
) -> Result<Grant, Box<dyn std::error::Error>> {
    let env_raw = match std::env::var("TENDRIL_ENROLL_TOKEN") {
        Ok(val) if !val.trim().is_empty() => Some(Zeroizing::new(val)),
        Ok(_) | Err(_) => None,
    };
    let sources = usize::from(token_file.is_some())
        + usize::from(token_stdin)
        + usize::from(env_raw.is_some());
    if sources > 1 {
        return Err(
            "conflicting enrollment token sources: supply only one of --token-file, --token-stdin, or TENDRIL_ENROLL_TOKEN"
                .into(),
        );
    }
    let raw = if let Some(path) = token_file {
        Zeroizing::new(std::fs::read_to_string(path)?)
    } else if token_stdin {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else if let Some(env_val) = env_raw {
        env_val
    } else {
        return Err(
            "enrollment token (--token-file, --token-stdin, or TENDRIL_ENROLL_TOKEN) is required"
                .into(),
        );
    };
    Ok(serde_json::from_str(raw.trim())?)
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

#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    mut stream: Box<dyn PathStream>,
    pre_auth_guard: HalfOpenGuard,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    rate_limiter: PreAuthRateLimiter,
    pair_enabled: bool,
    allow_enroll: bool,
    redact_logs: bool,
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
            if !pair_enabled {
                let _ = wrapped.close().await;
                return;
            }
            let path_kind = pairing_path_kind_for_provider(wrapped.provider_id());
            let policy = if allow_enroll {
                EnrollmentPolicy::enabled_default()
            } else {
                EnrollmentPolicy::default()
            };
            match drive_pair_responder_with_store(
                wrapped.as_mut(),
                &identity,
                &pair_mgr,
                &store,
                &store_lock,
                path_kind,
                now,
                policy,
                Some(&rate_limiter),
                Some(pre_auth_guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            {
                Ok(res) => match res.outcome {
                    PairOutcome::ResponderPending {
                        device_id,
                        pairing_sas,
                        ..
                    } => {
                        print_json_line(&serde_json::json!({
                            "event": "paired",
                            "device_id": device_id,
                            "sas": pairing_sas,
                        }));
                    }
                    PairOutcome::ResponderEnrolled {
                        device_id,
                        token_nonce,
                        name,
                        kind,
                        ..
                    } => {
                        let shown_nonce = if redact_logs {
                            "<redacted>"
                        } else {
                            token_nonce.as_str()
                        };
                        print_json_line(&serde_json::json!({
                            "event": "enrolled",
                            "device_id": device_id,
                            "name": name,
                            "kind": kind,
                            "token_nonce": shown_nonce,
                        }));
                    }
                    PairOutcome::Rejected { error } => {
                        print_json_line(&serde_json::json!({
                            "event": "pair_rejected",
                            "error": error,
                        }));
                    }
                    PairOutcome::InitiatorPending { .. }
                    | PairOutcome::InitiatorEnrolled { .. } => {}
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
                        let shown_utf8 = if redact_logs {
                            "<redacted>".to_owned()
                        } else {
                            String::from_utf8_lossy(&data).into_owned()
                        };
                        print_json_line(&serde_json::json!({
                            "event": "data",
                            "len": data.len(),
                            "utf8": shown_utf8,
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
            match driver.next_event_now(roster).await? {
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
            allow_enroll,
            redact_logs,
        } => {
            let identity = Arc::new(store.load_or_generate_identity(None)?);
            let store_lock = Arc::new(AsyncMutex::new(()));
            let pair_mgr = Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default())));
            let rate_limiter = PreAuthRateLimiter::new(PreAuthConfig::default());
            let pair_enabled = issue_code.is_some() || allow_enroll;

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

            let shown_code = if redact_logs {
                issued.as_deref().map(|_| "<redacted>")
            } else {
                issued.as_deref()
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
                "pairing_code": shown_code,
                "allow_enroll": allow_enroll,
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
                        pair_enabled,
                        allow_enroll,
                        redact_logs,
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
                PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                    return Err("unexpected responder outcome".into());
                }
                PairOutcome::InitiatorEnrolled { .. } => {
                    return Err("unexpected m2m enrollment outcome".into());
                }
            }
        }
        Command::Anchor { cmd } => match cmd {
            AnchorCommand::Add {
                anchor_id,
                signing_pub,
            } => {
                let signing_pub_bytes: [u8; 32] = b64url_decode_array(&signing_pub)?;
                let id_clone = anchor_id.clone();
                store.update_roster(|roster| {
                    roster
                        .add_trust_anchor(id_clone, signing_pub_bytes)
                        .map(|_| ())
                        .map_err(Into::into)
                })?;
                print_json_line(&serde_json::json!({
                    "added_anchor": anchor_id,
                    "signing_pub": signing_pub,
                }));
            }
            AnchorCommand::Revoke { anchor_id } => {
                store.update_roster(|roster| {
                    roster.revoke_trust_anchor(&anchor_id).map_err(Into::into)
                })?;
                print_json_line(&serde_json::json!({ "revoked_anchor": anchor_id }));
            }
            AnchorCommand::List => {
                let roster = store.load_roster()?;
                let anchors: Vec<_> = roster
                    .trust_anchors()
                    .map(|(id, anchor)| {
                        serde_json::json!({
                            "anchor_id": id,
                            "signing_pub": b64url_encode(&anchor.signing_pub),
                            "state": match anchor.state {
                                AnchorState::Active => "active",
                                AnchorState::Revoked => "revoked",
                            },
                        })
                    })
                    .collect();
                print_json_line(&serde_json::json!({ "anchors": anchors }));
            }
        },
        Command::EnrollToken {
            target_host,
            subject,
            ttl_secs,
            out,
        } => {
            let identity = store.load_identity()?;
            let now = now_unix();
            let nonce = random_bytes::<16>()?;
            let token = mint_enrollment_token(
                &identity,
                &target_host,
                subject.as_deref(),
                now,
                ttl_secs,
                nonce,
            )?;
            if let Some(out_path) = out {
                let mut json = Zeroizing::new(serde_json::to_string_pretty(&token)?);
                json.push('\n');
                write_private_token_file(&out_path, &json)?;
                print_json_line(&serde_json::json!({
                    "wrote": out_path.display().to_string(),
                    "issuer": token.issuer,
                    "subject": token.subject,
                    "nonce": token.nonce,
                    "not_after": token.not_after,
                }));
            } else {
                print_json_line(&token);
            }
        }
        Command::Enroll {
            endpoint,
            host_id,
            host_static_pub,
            host_signing_pub,
            host_rotation_seq,
            token_file,
            token_stdin,
            name,
            kind,
            relay_host,
            p2p_local,
            p2p_relay,
            no_pkarr,
        } => {
            let token = resolve_enroll_token(token_file, token_stdin)?;
            let pinned_host = PinnedHost {
                host_id: Some(host_id),
                static_pub: b64url_decode_array(&host_static_pub)?,
                signing_pub: b64url_decode_array(&host_signing_pub)?,
                rotation_seq: host_rotation_seq,
            };
            let identity = store.load_or_generate_identity(None)?;
            let mut stream = dial_endpoint(
                &endpoint,
                relay_host.as_deref(),
                p2p_local,
                p2p_relay.as_deref(),
                no_pkarr,
            )
            .await?;
            let res = drive_m2m_enroll_initiator(
                stream.as_mut(),
                &identity,
                name,
                kind,
                token,
                pinned_host,
            )
            .await;
            let _ = stream.close().await;
            let res = res?;
            match res.outcome {
                PairOutcome::InitiatorEnrolled {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    token_nonce,
                } => {
                    let host_id_out = host_id.clone();
                    store.update_roster(|roster| {
                        roster
                            .insert_pinned_host(
                                host_id,
                                host_id_out.clone(),
                                host_static_pub,
                                Some(host_signing_pub),
                                host_rotation_seq,
                                Vec::new(),
                            )
                            .map(|_| ())
                            .map_err(Into::into)
                    })?;
                    print_json_line(&serde_json::json!({
                        "device_id": device_id,
                        "enrolled_host_id": host_id_out,
                        "status": "active",
                        "host_rotation_seq": host_rotation_seq,
                        "token_nonce": token_nonce,
                        "static_pub": b64url_encode(&host_static_pub),
                        "signing_pub": b64url_encode(&host_signing_pub),
                    }));
                }
                PairOutcome::Rejected { error } => {
                    return Err(format!("m2m enrollment rejected: {error}").into());
                }
                PairOutcome::InitiatorPending { .. } => {
                    return Err("unexpected human pending outcome during m2m enrollment".into());
                }
                PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                    return Err("unexpected responder outcome".into());
                }
            }
        }
        Command::Confirm {
            peer_id,
            sas,
            allow_no_sas,
        } => {
            store.update_roster(|roster| {
                if allow_no_sas {
                    roster.confirm_peer_without_sas(&peer_id)
                } else {
                    roster.confirm_peer(&peer_id, sas.as_deref())
                }
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
        Command::RevokeToken { nonce } => {
            let identity = store.load_identity()?;
            let now = now_unix();
            let crl = store.update_roster(|roster| {
                roster
                    .revoke_nonce(&identity, &nonce, now)
                    .map_err(Into::into)
            })?;
            print_json_line(&serde_json::json!({
                "revoked_nonce": nonce,
                "crl_seq": crl.seq,
            }));
        }
        Command::Rotate => {
            let mut identity = store.load_identity()?;
            let new_static = StaticKeypair::generate()?;
            let new_signing = SigningKeypair::generate()?;
            let now = now_unix();
            identity.rotate(new_static, new_signing, now)?;
            store.save_identity(&identity)?;
            store.update_roster(|roster| {
                roster
                    .resign_crl(&identity, now)
                    .map(|_| ())
                    .map_err(Into::into)
            })?;
            print_json_line(&serde_json::json!({
                "host_id": identity.host_id(),
                "rotation_seq": identity.rotation_seq(),
                "static_pub": b64url_encode(identity.static_key().public_bytes()),
                "signing_pub": b64url_encode(identity.signing_key().public_bytes()),
            }));
        }
    }

    Ok(())
}
