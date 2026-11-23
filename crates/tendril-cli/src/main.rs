//! Tendril reference CLI (`tendril`) for identity, pairing, grants, serving, and dialing.

mod group;

use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, SigningKeypair,
    StaticKeypair, b64url_decode, b64url_decode_array, b64url_encode, random_bytes,
};
use tendril_core::grants::{Grant, canonical_json};
use tendril_core::identity::SigningKeyPin;
use tendril_core::pairing::{
    DEFAULT_ENROLLMENT_TTL_SECS, EnrollmentPolicy, PairOutcome, PairingCodeKind, PairingConfig,
    PairingManager, PairingUri, PinnedHost, mint_enrollment_token,
};
use tendril_core::relay_auth::{RelayAuthRole, RelayAuthSecret, RelayTicket};
use tendril_core::roster::{AnchorState, PeerState, Roster};
use tendril_core::v2::{
    V2PairOutcome, V2PinnedHost, canonical_relay_host, derive_epoch_mailbox_window,
};
use tendril_runtime::{
    BrokerDialer, BrokerListener, BrokerServerConfig, DEFAULT_PRE_AUTH_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, EmbeddedRelay, HalfOpenGuard,
    HttpWakeProvider, InboundQueue, InboundRouter, InboundSession, LocalDialer, OverlayDialer,
    OverlayListener, P2pDialer, P2pListener, P2pOptions, P2pRelayAuth, P2pRelayMode, PathDialer,
    PathListener, PathStream, PreAuthRateLimiter, RelayClientAuth, RelayDialer, RelayListener,
    RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig, SessionDriver, SessionEvent, StateStore,
    V2ResponderState, V2SessionDriver, WakeAdapterKind, WakeDialOptions, WakeSecret, WakeTarget,
    dial_endpoint_with_auth as runtime_dial_endpoint_with_auth,
    drive_m2m_enroll_initiator_with_store, drive_pair_initiator_with_store,
    drive_pair_responder_with_store, drive_v2_pake_pair_initiator_with_store,
    drive_v2_pake_pair_responder_with_store, pairing_path_kind_for_provider, parse_p2p_relay_mode,
    parse_p2p_relay_modes, pinned_pairing_floor, recv_routed, wake_and_connect_v2_session,
};
use tokio::sync::{Mutex as AsyncMutex, watch};
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RelayRoleArg {
    Register,
    Dial,
    Any,
}

impl From<RelayRoleArg> for RelayAuthRole {
    fn from(role: RelayRoleArg) -> Self {
        match role {
            RelayRoleArg::Register => Self::Register,
            RelayRoleArg::Dial => Self::Dial,
            RelayRoleArg::Any => Self::Any,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WakeAdapterArg {
    UnifiedPush,
    Webhook,
    Apns,
    Fcm,
}

impl From<WakeAdapterArg> for WakeAdapterKind {
    fn from(adapter: WakeAdapterArg) -> Self {
        match adapter {
            WakeAdapterArg::UnifiedPush => Self::UnifiedPush,
            WakeAdapterArg::Webhook => Self::Webhook,
            WakeAdapterArg::Apns => Self::Apns,
            WakeAdapterArg::Fcm => Self::Fcm,
        }
    }
}

#[derive(Debug, Clone, Args)]
struct RelayAuthArgs {
    #[arg(long, value_name = "PATH", conflicts_with = "relay_ticket_file")]
    relay_auth_secret_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH", conflicts_with = "relay_auth_secret_file")]
    relay_ticket_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct P2pTransportArgs {
    #[arg(long)]
    p2p_local: bool,
    #[arg(
        long = "p2p-relay",
        value_name = "MODE_OR_URL",
        conflicts_with = "p2p_local"
    )]
    p2p_relay: Vec<String>,
    #[arg(long, value_name = "PATH", conflicts_with = "p2p_api_secret_file")]
    p2p_relay_token_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH", conflicts_with = "p2p_relay_token_file")]
    p2p_api_secret_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "no_pkarr")]
    p2p_pkarr: bool,
    #[arg(long, conflicts_with = "p2p_pkarr")]
    no_pkarr: bool,
}

#[derive(Debug, Subcommand)]
enum AnchorCommand {
    /// Register an active external hybrid signing trust anchor for M2M enrollment.
    Add {
        anchor_id: String,
        #[arg(long, allow_hyphen_values = true)]
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
        #[arg(long)]
        wire_v2: bool,
        #[arg(long)]
        relay_v2: bool,
        #[arg(long, conflicts_with = "p2p_local")]
        p2p: bool,
        #[command(flatten)]
        p2p_args: P2pTransportArgs,
        #[command(flatten)]
        relay_auth: RelayAuthArgs,
        #[arg(long)]
        ephemeral_p2p: bool,
        #[arg(long)]
        include_direct_addrs: bool,
        #[arg(long)]
        overlay: Option<SocketAddr>,
        #[arg(long)]
        overlay_allow_non_tailnet: bool,
        #[arg(long)]
        broker: Option<SocketAddr>,
        #[arg(long, value_enum)]
        issue_code: Option<PairKindArg>,
        #[arg(long)]
        allow_enroll: bool,
        #[arg(long)]
        redact_logs: bool,
    },
    /// Mint a signed stateless Ed25519 relay admission ticket (`RelayTicket`).
    RelayTicket {
        #[arg(long)]
        relay_host: String,
        #[arg(long, value_enum, default_value_t = RelayRoleArg::Any)]
        role: RelayRoleArg,
        #[arg(long, allow_hyphen_values = true)]
        target_pub: Option<String>,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
    },
    /// Pair with a remote host using a one-time pairing code or `tendril://pair?...` URI.
    Pair {
        #[arg(long, required_unless_present = "pairing_uri")]
        endpoint: Option<String>,
        #[arg(long, allow_hyphen_values = true, conflicts_with_all = ["code_stdin", "code_file"])]
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
        wire_v2: bool,
        #[arg(long)]
        relay_v2: bool,
        #[command(flatten)]
        p2p_args: P2pTransportArgs,
        #[command(flatten)]
        relay_auth: RelayAuthArgs,
    },
    /// Manage external hybrid signing trust anchors for M2M enrollment.
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
        #[arg(long, allow_hyphen_values = true)]
        host_static_pub: String,
        #[arg(long, allow_hyphen_values = true)]
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
        #[command(flatten)]
        p2p_args: P2pTransportArgs,
        #[command(flatten)]
        relay_auth: RelayAuthArgs,
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
        wire_v2: bool,
        #[arg(long)]
        relay_v2: bool,
        #[arg(long, value_name = "URL")]
        wake_url: Option<String>,
        #[arg(long, value_enum, default_value_t = WakeAdapterArg::Webhook)]
        wake_adapter: WakeAdapterArg,
        #[arg(long, value_name = "PATH")]
        wake_secret_file: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        wake_auth_header_file: Option<PathBuf>,
        #[arg(long)]
        wake_pre_wake: bool,
        #[command(flatten)]
        p2p_args: P2pTransportArgs,
        #[command(flatten)]
        relay_auth: RelayAuthArgs,
        #[arg(long, allow_hyphen_values = true)]
        grant: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        message: Option<String>,
    },
    /// Revoke an existing peer (`pair.revoke`), failing closed on all future sessions.
    Revoke { peer_id: String },
    /// Create and operate small peer mesh groups.
    Group {
        #[command(subcommand)]
        cmd: group::GroupCommand,
    },
    /// Revoke an unused grant or enrollment token nonce on the signed local CRL.
    RevokeToken {
        #[arg(allow_hyphen_values = true)]
        nonce: String,
    },
    /// Rotate local static and signing identity keys and re-sign any persisted self-CRL.
    Rotate,
}

#[derive(Serialize)]
struct InitOut {
    host_id: String,
    device_id: String,
    static_pub: String,
    signing_pub: String,
    signing_pub_hash: String,
    relay_pub: String,
}

fn parse_signing_pin_b64(encoded: &str) -> Result<SigningKeyPin, tendril_core::error::CoreError> {
    let bytes = b64url_decode(encoded)?;
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        Ok(SigningKeyPin::Full(HybridSigningPublicKey::from_bytes(
            &bytes,
        )?))
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let hash: [u8; 32] = bytes
            .try_into()
            .map_err(|_| tendril_core::error::CoreError::InvalidSignature)?;
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(tendril_core::error::CoreError::InvalidLength {
            expected: HYBRID_SIGNING_PUB_LEN,
            actual: bytes.len(),
        })
    }
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

const MAX_CREDENTIAL_FILE_BYTES: u64 = 16 * 1024;

fn read_private_secret_bytes(
    path: &Path,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(format!(
            "{label} file '{}' must be a regular non-symlink file",
            path.display()
        )
        .into());
    }
    if meta.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(format!(
            "{label} file '{}' exceeds {MAX_CREDENTIAL_FILE_BYTES} bytes",
            path.display()
        )
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{label} file '{}' has insecure permissions {mode:04o}; use chmod 0600",
                path.display()
            )
            .into());
        }
    }
    Ok(Zeroizing::new(std::fs::read(path)?))
}

fn read_trimmed_secret_line(
    path: &Path,
    label: &str,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let raw_bytes = read_private_secret_bytes(path, label)?;
    let raw = Zeroizing::new(
        String::from_utf8(raw_bytes.to_vec())
            .map_err(|_| format!("{label} file must be valid UTF-8"))?,
    );
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(
            format!("{label} must be a non-empty single line without control characters").into(),
        );
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

fn trim_secret_value(
    raw: Zeroizing<String>,
    label: &str,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(
            format!("{label} must be a non-empty single line without control characters").into(),
        );
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

fn resolve_relay_auth(args: &RelayAuthArgs) -> Result<RelayClientAuth, Box<dyn std::error::Error>> {
    if let Some(path) = &args.relay_auth_secret_file {
        let trimmed = read_trimmed_secret_line(path, "relay auth secret")?;
        let secret = RelayAuthSecret::from_bytes(trimmed.as_bytes())?;
        return Ok(RelayClientAuth::HmacSecret(secret));
    }
    if let Some(path) = &args.relay_ticket_file {
        let raw_bytes = read_private_secret_bytes(path, "relay ticket")?;
        let raw = Zeroizing::new(
            String::from_utf8(raw_bytes.to_vec())
                .map_err(|_| "relay ticket file must be valid UTF-8")?,
        );
        let ticket: RelayTicket = serde_json::from_str(raw.trim())?;
        let _ = canonical_relay_host(&ticket.relay_host)?;
        if ticket.issuer_pub.is_empty() || ticket.target_pub.is_empty() || ticket.sig.is_empty() {
            return Err("relay ticket has empty required fields".into());
        }
        if ticket.spans_multiple_v2_epochs() {
            tracing::warn!(
                "relay ticket spans multiple /v2/relay epochs, allowing cross-epoch mailbox linkability; prefer Tier 2 HMAC admission or single-epoch scoped tickets"
            );
        }
        return Ok(RelayClientAuth::Ticket(ticket));
    }
    if let Ok(val) = std::env::var("TENDRIL_RELAY_AUTH_SECRET") {
        let val = Zeroizing::new(val);
        if !val.is_empty() {
            let trimmed = trim_secret_value(val, "TENDRIL_RELAY_AUTH_SECRET")?;
            let secret = RelayAuthSecret::from_bytes(trimmed.as_bytes())?;
            return Ok(RelayClientAuth::HmacSecret(secret));
        }
    }
    Ok(RelayClientAuth::None)
}

fn resolve_p2p_relay_auth(
    args: &P2pTransportArgs,
) -> Result<Option<P2pRelayAuth>, Box<dyn std::error::Error>> {
    if let Some(path) = &args.p2p_relay_token_file {
        let tok = read_trimmed_secret_line(path, "p2p relay token")?;
        return Ok(Some(P2pRelayAuth::BearerToken(tok)));
    }
    if let Some(path) = &args.p2p_api_secret_file {
        #[cfg(feature = "p2p-iroh-services")]
        {
            let sec = read_trimmed_secret_line(path, "p2p api secret")?;
            return Ok(Some(P2pRelayAuth::IrohServicesSecret(sec)));
        }
        #[cfg(not(feature = "p2p-iroh-services"))]
        {
            let _ = path;
            return Err(
                "--p2p-api-secret-file requires tendril-cli built with p2p-iroh-services feature"
                    .into(),
            );
        }
    }
    let env_tok = std::env::var("TENDRIL_P2P_RELAY_TOKEN")
        .ok()
        .map(Zeroizing::new)
        .filter(|s| !s.is_empty());
    let env_api = std::env::var("TENDRIL_P2P_API_SECRET")
        .ok()
        .map(Zeroizing::new)
        .filter(|s| !s.is_empty());
    if env_tok.is_some() && env_api.is_some() {
        return Err(
            "conflicting TENDRIL_P2P_RELAY_TOKEN and TENDRIL_P2P_API_SECRET env vars".into(),
        );
    }
    if let Some(raw) = env_tok {
        let tok = trim_secret_value(raw, "TENDRIL_P2P_RELAY_TOKEN")?;
        return Ok(Some(P2pRelayAuth::BearerToken(tok)));
    }
    if let Some(raw) = env_api {
        #[cfg(feature = "p2p-iroh-services")]
        {
            let sec = trim_secret_value(raw, "TENDRIL_P2P_API_SECRET")?;
            return Ok(Some(P2pRelayAuth::IrohServicesSecret(sec)));
        }
        #[cfg(not(feature = "p2p-iroh-services"))]
        {
            let _ = raw;
            return Err(
                "TENDRIL_P2P_API_SECRET requires tendril-cli built with p2p-iroh-services feature"
                    .into(),
            );
        }
    }
    Ok(None)
}

fn validate_explicit_p2p_args(args: &P2pTransportArgs) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ref path) = args.p2p_relay_token_file {
        let _ = read_trimmed_secret_line(path, "p2p relay token")?;
    }
    if let Some(ref path) = args.p2p_api_secret_file {
        #[cfg(feature = "p2p-iroh-services")]
        {
            let _ = read_trimmed_secret_line(path, "p2p api secret")?;
        }
        #[cfg(not(feature = "p2p-iroh-services"))]
        {
            let _ = path;
            return Err(
                "--p2p-api-secret-file requires tendril-cli built with p2p-iroh-services feature"
                    .into(),
            );
        }
    }
    Ok(())
}

fn resolve_pkarr_enabled(mode: &P2pRelayMode, p2p_pkarr: bool, no_pkarr: bool) -> bool {
    if matches!(mode, P2pRelayMode::Default) {
        !no_pkarr
    } else {
        p2p_pkarr && !no_pkarr
    }
}

fn build_p2p_listener_options(
    args: &P2pTransportArgs,
    resolved_p2p_auth: Option<P2pRelayAuth>,
    include_direct_addrs: bool,
) -> Result<P2pOptions, Box<dyn std::error::Error>> {
    let mode = resolve_p2p_relay_mode(args, None)?;
    let pkarr = resolve_pkarr_enabled(&mode, args.p2p_pkarr, args.no_pkarr);
    let mut opts = P2pOptions::for_listener(mode)
        .with_publish_pkarr(pkarr)
        .with_resolve_pkarr(pkarr)
        .with_relay_auth(resolved_p2p_auth);
    if include_direct_addrs {
        opts = opts.with_advertise_direct_addrs(true);
    }
    Ok(opts)
}

fn resolve_explicit_p2p_relay_mode(
    args: &P2pTransportArgs,
    relay_host_fallback: Option<&str>,
) -> Result<Option<P2pRelayMode>, Box<dyn std::error::Error>> {
    if !args.p2p_relay.is_empty() {
        if args.p2p_relay.len() == 1 {
            return Ok(Some(parse_p2p_relay_mode(Some(&args.p2p_relay[0]))?));
        }
        return Ok(Some(parse_p2p_relay_modes(&args.p2p_relay)?));
    }
    if let Some(spec) = relay_host_fallback.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(Some(parse_p2p_relay_mode(Some(spec))?));
    }
    if args.p2p_local || std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1") {
        return Ok(Some(P2pRelayMode::Disabled));
    }
    Ok(None)
}

fn resolve_p2p_relay_mode(
    args: &P2pTransportArgs,
    relay_host_fallback: Option<&str>,
) -> Result<P2pRelayMode, Box<dyn std::error::Error>> {
    Ok(
        resolve_explicit_p2p_relay_mode(args, relay_host_fallback)?
            .unwrap_or(P2pRelayMode::Default),
    )
}

fn ws_path(endpoint: &str) -> &str {
    let without_frag = endpoint.split_once('#').map_or(endpoint, |(u, _)| u);
    let without_query = without_frag
        .split_once('?')
        .map_or(without_frag, |(u, _)| u);
    if let Some(rest) = without_query
        .strip_prefix("ws://")
        .or_else(|| without_query.strip_prefix("wss://"))
    {
        rest.split_once('/').map_or("", |(_, path)| path)
    } else {
        ""
    }
}

fn is_v2_relay_endpoint(endpoint: &str) -> bool {
    (endpoint.starts_with("ws://") || endpoint.starts_with("wss://"))
        && ws_path(endpoint) == "v2/relay"
}

fn derive_v2_relay_url(url: &str) -> String {
    let (base, frag) = url
        .split_once('#')
        .map_or((url, None), |(u, f)| (u, Some(f)));
    let (no_q, query) = base
        .split_once('?')
        .map_or((base, None), |(u, q)| (u, Some(q)));
    let updated = if let Some(prefix) = no_q.strip_suffix("/v1/relay") {
        format!("{prefix}/v2/relay")
    } else if no_q.ends_with("/v2/relay") {
        no_q.to_owned()
    } else {
        format!("{}/v2/relay", no_q.trim_end_matches('/'))
    };
    match (query, frag) {
        (Some(q), Some(f)) => format!("{updated}?{q}#{f}"),
        (Some(q), None) => format!("{updated}?{q}"),
        (None, Some(f)) => format!("{updated}#{f}"),
        (None, None) => updated,
    }
}

fn lookup_v2_mailbox_secret_for_target(
    roster: &Roster,
    target_host_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let entry = roster
        .get(target_host_id)
        .ok_or_else(|| format!("target '{target_host_id}' not found in roster"))?;
    if entry.state == PeerState::Revoked {
        return Err(format!("target '{target_host_id}' is revoked").into());
    }
    let secrets = entry
        .v2_secrets
        .as_ref()
        .ok_or_else(|| format!("target '{target_host_id}' has no v2 mailbox_secret in roster"))?;
    Ok(*secrets.mailbox_secret())
}

fn lookup_v2_mailbox_secret_for_pair(
    roster: &Roster,
    pinned: Option<&PinnedHost>,
    endpoint: &str,
    now_unix: u64,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if let Some(pin) = pinned {
        if let Some(ref hid) = pin.host_id
            && let Some(entry) = roster.get(hid)
            && entry.state != PeerState::Revoked
            && let Some(ref secrets) = entry.v2_secrets
        {
            return Ok(*secrets.mailbox_secret());
        }
        for (_, entry) in roster.entries() {
            if entry.state != PeerState::Revoked
                && entry.static_pub == pin.static_pub
                && let Some(ref secrets) = entry.v2_secrets
            {
                return Ok(*secrets.mailbox_secret());
            }
        }
    }
    if let Some((_, frag)) = endpoint.split_once('#')
        && !frag.is_empty()
    {
        for (_, entry) in roster.entries() {
            if entry.state != PeerState::Revoked
                && let Some(ref secrets) = entry.v2_secrets
            {
                let win = derive_epoch_mailbox_window(secrets.mailbox_secret(), now_unix);
                if win
                    .mailboxes()
                    .iter()
                    .any(|mb| mb.mailbox_id_b64url() == frag)
                {
                    return Ok(*secrets.mailbox_secret());
                }
            }
        }
    }
    Err("no matching v2 mailbox_secret in roster for /v2/relay endpoint; pair over direct, p2p, or /v1/relay first".into())
}

fn build_p2p_dialer_options(
    p2p_args: &P2pTransportArgs,
    endpoint: &str,
    relay_host: Option<&str>,
) -> Result<P2pOptions, Box<dyn std::error::Error>> {
    let explicit_mode = resolve_explicit_p2p_relay_mode(p2p_args, relay_host)?;
    let p2p_auth = resolve_p2p_relay_auth(p2p_args)?;
    let allow_private_addrs = matches!(explicit_mode, Some(P2pRelayMode::Disabled));
    let mut opts = if endpoint.starts_with("iroh://") || endpoint.starts_with("p2p:iroh://") {
        P2pOptions::for_endpoint(endpoint, explicit_mode, allow_private_addrs)?
    } else {
        let mode = explicit_mode.unwrap_or(P2pRelayMode::Default);
        let is_disabled = matches!(mode, P2pRelayMode::Disabled);
        P2pOptions::for_dialer(mode).with_allow_private_addrs(allow_private_addrs || is_disabled)
    };
    let pkarr = resolve_pkarr_enabled(&opts.relay_mode, p2p_args.p2p_pkarr, p2p_args.no_pkarr);
    opts = opts.with_resolve_pkarr(pkarr).with_relay_auth(p2p_auth);
    Ok(opts)
}

async fn dial_endpoint_cli(
    endpoint: &str,
    relay_host: Option<&str>,
    p2p_args: &P2pTransportArgs,
    relay_auth: &RelayClientAuth,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathStream>, Box<dyn std::error::Error>> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        let opts = build_p2p_dialer_options(p2p_args, endpoint, normalized_host)?;
        let dialer = P2pDialer::bind_with_options(opts).await?;
        return match dialer.dial(endpoint).await {
            Ok(stream) => Ok(stream),
            Err(err) => {
                dialer.close().await;
                Err(err.into())
            }
        };
    }
    if let Some(secret) = v2_mailbox_secret {
        let mut dialer = RelayV2Dialer::new(secret).with_auth(relay_auth.clone());
        if let Some(host) = normalized_host {
            dialer = dialer.with_expected_host(host);
        }
        return Ok(dialer.dial(endpoint).await?);
    }
    Ok(runtime_dial_endpoint_with_auth(endpoint, normalized_host, relay_auth.clone()).await?)
}

async fn build_path_dialer(
    endpoint: &str,
    relay_host: Option<&str>,
    p2p_args: &P2pTransportArgs,
    relay_auth: &RelayClientAuth,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathDialer>, Box<dyn std::error::Error>> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        let opts = build_p2p_dialer_options(p2p_args, endpoint, normalized_host)?;
        return Ok(Box::new(P2pDialer::bind_with_options(opts).await?));
    }
    if endpoint.starts_with("overlay://") {
        return Ok(Box::new(OverlayDialer::new()));
    }
    if endpoint.starts_with("broker+ws://") || endpoint.starts_with("broker+wss://") {
        return Ok(Box::new(BrokerDialer::new()));
    }
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        if let Some(secret) = v2_mailbox_secret {
            let mut dialer = RelayV2Dialer::new(secret).with_auth(relay_auth.clone());
            if let Some(host) = normalized_host {
                dialer = dialer.with_expected_host(host);
            }
            return Ok(Box::new(dialer));
        }
        let mut dialer = RelayDialer::new().with_auth(relay_auth.clone());
        if let Some(host) = normalized_host {
            dialer = dialer.with_expected_host(host);
        }
        return Ok(Box::new(dialer));
    }
    if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        return Ok(Box::new(LocalDialer::new()));
    }
    Ok(Box::new(DirectDialer::new()))
}

fn resolve_wake_secret(path: Option<&Path>) -> Result<WakeSecret, Box<dyn std::error::Error>> {
    let bytes = if let Some(p) = path {
        read_private_secret_bytes(p, "wake secret")?
    } else if let Ok(val) = std::env::var("TENDRIL_WAKE_SECRET") {
        let val = Zeroizing::new(val);
        if val.is_empty() {
            return Err(
                "--wake-secret-file or TENDRIL_WAKE_SECRET is required with --wake-url".into(),
            );
        }
        Zeroizing::new(val.as_bytes().to_vec())
    } else {
        return Err("--wake-secret-file or TENDRIL_WAKE_SECRET is required with --wake-url".into());
    };
    if bytes.len() == 32 {
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&bytes);
        return Ok(WakeSecret::from_bytes(*arr));
    }
    if let Ok(text) = std::str::from_utf8(&bytes) {
        let trimmed = text.trim_end_matches(['\r', '\n']).trim();
        if let Ok(arr) = b64url_decode_array::<32>(trimmed) {
            let arr = Zeroizing::new(arr);
            return Ok(WakeSecret::from_bytes(*arr));
        }
        if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut arr = Zeroizing::new([0u8; 32]);
            for (i, slot) in arr.iter_mut().enumerate() {
                *slot = u8::from_str_radix(&trimmed[2 * i..2 * i + 2], 16)?;
            }
            return Ok(WakeSecret::from_bytes(*arr));
        }
    }
    Err("wake secret must be 32 raw bytes, 32-byte b64url, or 64-char hex".into())
}

fn resolve_wake_auth_token(path: &Path) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let line = read_trimmed_secret_line(path, "wake auth header")?;
    let trimmed = line.trim();
    let after_header = trimmed
        .strip_prefix("Authorization:")
        .or_else(|| trimmed.strip_prefix("authorization:"))
        .map_or(trimmed, str::trim);
    let token = after_header
        .strip_prefix("Bearer ")
        .or_else(|| after_header.strip_prefix("bearer "))
        .map_or(after_header, str::trim);
    if token.is_empty() {
        return Err("wake auth header token must not be empty".into());
    }
    Ok(Zeroizing::new(token.to_owned()))
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
        let raw_bytes = read_private_secret_bytes(&path, "pairing code")?;
        let text =
            std::str::from_utf8(&raw_bytes).map_err(|_| "pairing code file must be valid UTF-8")?;
        return trim_secret_code(text.to_owned());
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
        let raw_bytes = read_private_secret_bytes(&path, "enrollment token")?;
        let text = std::str::from_utf8(&raw_bytes)
            .map_err(|_| "enrollment token file must be valid UTF-8")?;
        Zeroizing::new(text.to_owned())
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

struct CancelableListener {
    inner: Box<dyn PathListener>,
    stop_rx: watch::Receiver<bool>,
}

impl PathListener for CancelableListener {
    fn accept<'life0, 'async_trait>(
        &'life0 mut self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Box<dyn PathStream>, tendril_runtime::RuntimeError>,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if *self.stop_rx.borrow() {
                return Err(tendril_runtime::RuntimeError::Closed);
            }
            tokio::select! {
                biased;
                _ = self.stop_rx.changed() => Err(tendril_runtime::RuntimeError::Closed),
                res = self.inner.accept() => res,
            }
        })
    }

    fn local_endpoint(&self) -> String {
        self.inner.local_endpoint()
    }
}

fn spawn_routed_worker<F, Fut>(queue: InboundQueue, handler: F) -> tokio::task::JoinHandle<()>
where
    F: Fn(Box<dyn PathStream>, HalfOpenGuard) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            match recv_routed(&queue, Duration::from_secs(3600)).await {
                Ok(Some((stream, guard))) => {
                    tokio::spawn(handler(stream, guard));
                }
                Ok(None) => break,
                Err(()) => continue,
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_v1_pair(
    mut stream: Box<dyn PathStream>,
    pre_auth_guard: HalfOpenGuard,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    rate_limiter: PreAuthRateLimiter,
    allow_enroll: bool,
    redact_logs: bool,
) {
    let now = now_unix();
    let path_kind = pairing_path_kind_for_provider(stream.provider_id());
    let policy = if allow_enroll {
        EnrollmentPolicy::enabled_default()
    } else {
        EnrollmentPolicy::default()
    };
    match drive_pair_responder_with_store(
        stream.as_mut(),
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
            PairOutcome::InitiatorPending { .. } | PairOutcome::InitiatorEnrolled { .. } => {}
        },
        Err(err) => {
            tracing::debug!(error = %err, "pair responder error");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_pair(
    mut stream: Box<dyn PathStream>,
    pre_auth_guard: HalfOpenGuard,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    v2_state: Arc<V2ResponderState>,
    rate_limiter: PreAuthRateLimiter,
) {
    let now = now_unix();
    let path_kind = pairing_path_kind_for_provider(stream.provider_id());
    match drive_v2_pake_pair_responder_with_store(
        stream.as_mut(),
        &identity,
        &pair_mgr,
        &store,
        &store_lock,
        path_kind,
        now,
        &v2_state,
        Some(&rate_limiter),
        Some(pre_auth_guard),
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
    {
        Ok(res) => match res.outcome {
            V2PairOutcome::ResponderPending {
                device_id,
                pairing_sas,
                ..
            } => {
                print_json_line(&serde_json::json!({
                    "event": "paired",
                    "device_id": device_id,
                    "sas": pairing_sas,
                    "wire_version": 2,
                }));
            }
            V2PairOutcome::Rejected { error } => {
                print_json_line(&serde_json::json!({
                    "event": "pair_rejected",
                    "error": error,
                    "wire_version": 2,
                }));
            }
            V2PairOutcome::InitiatorPending { .. } => {}
        },
        Err(err) => {
            tracing::debug!(error = %err, "v2 pair responder error");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_v1_session(
    stream: Box<dyn PathStream>,
    pre_auth_guard: HalfOpenGuard,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    rate_limiter: PreAuthRateLimiter,
    redact_logs: bool,
    groups: Arc<group::ServeGroups>,
) {
    let now = now_unix();
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
    let Ok(driver) = SessionDriver::accept_with_options(
        stream,
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
    run_v1_session(
        driver,
        roster,
        initial_stamp,
        store,
        store_lock,
        identity,
        redact_logs,
        groups,
    )
    .await;
}

/// Runs an accepted ordinary Wire v1 session admitted against `roster` at `initial_stamp`.
/// An ingested group frame re-syncs the serving group pools in `groups`.
#[allow(clippy::too_many_arguments)]
async fn run_v1_session(
    mut driver: SessionDriver,
    mut roster: tendril_core::roster::Roster,
    initial_stamp: Option<tendril_runtime::RosterStamp>,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    redact_logs: bool,
    groups: Arc<group::ServeGroups>,
) {
    let peer_id = driver.peer_device_id().unwrap_or_default().to_owned();
    let mut last_stamp = initial_stamp;
    {
        let _guard = store_lock.lock().await;
        match store.roster_stamp() {
            Ok(curr_stamp) if curr_stamp != last_stamp => match store.load_roster_with_stamp() {
                Ok((disk, fresh_stamp)) => {
                    roster = disk;
                    last_stamp = fresh_stamp;
                }
                Err(err) => {
                    tracing::error!(error = %err, "failed to reload roster after v1 accept");
                    let _ = driver.send_close(1000, "roster error").await;
                    return;
                }
            },
            Ok(_) => {}
            Err(err) => {
                tracing::error!(error = %err, "failed to check roster stamp after v1 accept");
                let _ = driver.send_close(1000, "roster error").await;
                return;
            }
        }
    }
    if !roster
        .get(&peer_id)
        .is_some_and(|entry| entry.state == PeerState::Active)
    {
        let _ = driver.send_close(1000, "peer revoked").await;
        return;
    }
    print_json_line(&serde_json::json!({
        "event": "session_established",
        "peer_device_id": peer_id,
        "provider": format!("{:?}", driver.provider_id()),
    }));
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
                match store.roster_stamp() {
                    Ok(curr_stamp) if curr_stamp != last_stamp => {
                        let loaded = {
                            let _guard = store_lock.lock().await;
                            store.load_roster_with_stamp()
                        };
                        match loaded {
                            Ok((disk, fresh_stamp)) => {
                                roster = disk;
                                last_stamp = fresh_stamp;
                            }
                            Err(err) => {
                                tracing::error!(error = %err, "failed to reload roster during v1 session");
                                let _ = driver.send_close(1000, "roster error").await;
                                print_json_line(&serde_json::json!({
                                    "event": "closed",
                                    "code": 1000,
                                    "reason": "roster error",
                                }));
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::error!(error = %err, "failed to check roster stamp during v1 session");
                        let _ = driver.send_close(1000, "roster error").await;
                        print_json_line(&serde_json::json!({
                            "event": "closed",
                            "code": 1000,
                            "reason": "roster error",
                        }));
                        break;
                    }
                }
                if !roster
                    .get(&peer_id)
                    .is_some_and(|entry| entry.state == PeerState::Active)
                {
                    let _ = driver.send_close(1000, "peer revoked").await;
                    print_json_line(&serde_json::json!({
                        "event": "closed",
                        "code": 1000,
                        "reason": "peer revoked",
                    }));
                    break;
                }
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
            Ok(Some(
                event @ (SessionEvent::GroupManifestReceived(_)
                | SessionEvent::GroupRendezvousReceived(_)),
            )) => {
                if group::handle_group_frame(
                    store.as_ref(),
                    &identity.device_id(),
                    &peer_id,
                    &event,
                ) {
                    groups.refresh();
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

async fn refresh_v2_roster_if_changed(
    store: &StateStore,
    store_lock: &AsyncMutex<()>,
    roster_arc: &StdMutex<tendril_core::roster::Roster>,
    last_stamp_arc: &StdMutex<Option<tendril_runtime::RosterStamp>>,
) -> Result<(), tendril_runtime::RuntimeError> {
    let prev_stamp = last_stamp_arc.lock().expect("stamp lock").clone();
    let curr_stamp = match store.roster_stamp() {
        Ok(stamp) => stamp,
        Err(err) => return Err(err),
    };
    if curr_stamp != prev_stamp {
        let loaded = {
            let _g = store_lock.lock().await;
            store.load_roster_with_stamp()
        };
        match loaded {
            Ok((disk, fresh_stamp)) => {
                *roster_arc.lock().expect("roster lock") = disk;
                *last_stamp_arc.lock().expect("stamp lock") = fresh_stamp;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_v2_session(
    stream: Box<dyn PathStream>,
    pre_auth_guard: HalfOpenGuard,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    v2_state: Arc<V2ResponderState>,
    rate_limiter: PreAuthRateLimiter,
    redact_logs: bool,
    groups: Arc<group::ServeGroups>,
) {
    let Ok(driver) = V2SessionDriver::accept_with_store(
        stream,
        &identity,
        &store,
        &store_lock,
        now_unix(),
        &v2_state,
        Some(&rate_limiter),
        Some(pre_auth_guard),
        DEFAULT_PRE_AUTH_TIMEOUT,
    )
    .await
    else {
        tracing::debug!("inbound v2 session rejected");
        return;
    };
    run_v2_session(driver, store, store_lock, identity, redact_logs, groups).await;
}

/// Runs an accepted, store-backed ordinary Wire v2 session. An ingested group frame re-syncs
/// the serving group pools in `groups`.
async fn run_v2_session(
    driver: V2SessionDriver,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    redact_logs: bool,
    groups: Arc<group::ServeGroups>,
) {
    let peer_id = driver.peer_device_id().to_owned();
    let provider = format!("{:?}", driver.provider_id());
    let (initial_roster, initial_stamp) = {
        let _guard = store_lock.lock().await;
        match store.load_roster_with_stamp() {
            Ok(pair) => pair,
            Err(err) => {
                tracing::error!(error = %err, "failed to load roster after v2 session accept");
                return;
            }
        }
    };
    if !initial_roster
        .get(&peer_id)
        .is_some_and(|entry| entry.state == PeerState::Active)
    {
        let mut driver = driver;
        let _ = driver.send_close(1000, "peer revoked").await;
        return;
    }
    print_json_line(&serde_json::json!({
        "event": "session_established",
        "peer_device_id": peer_id,
        "provider": provider,
        "wire_version": 2,
    }));
    let session = Arc::new(driver.into_concurrent());
    let roster_arc = Arc::new(StdMutex::new(initial_roster));
    let last_stamp_arc = Arc::new(StdMutex::new(initial_stamp));

    let session_tick = Arc::clone(&session);
    let roster_tick = Arc::clone(&roster_arc);
    let last_stamp_tick = Arc::clone(&last_stamp_arc);
    let store_tick = Arc::clone(&store);
    let store_lock_tick = Arc::clone(&store_lock);
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let tick_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = stop_rx.changed() => break,
                _ = interval.tick() => {
                    match refresh_v2_roster_if_changed(
                        &store_tick,
                        &store_lock_tick,
                        &roster_tick,
                        &last_stamp_tick,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(err) => {
                            tracing::error!(error = %err, "failed to refresh roster during v2 tick");
                            let _ = session_tick.send_close(1000, "roster error").await;
                            print_json_line(&serde_json::json!({
                                "event": "closed",
                                "code": 1000,
                                "reason": "roster error",
                            }));
                            session_tick.shutdown();
                            break;
                        }
                    }
                    if let Err(err) = session_tick.tick_locked(now_unix(), &roster_tick).await {
                        print_json_line(&serde_json::json!({
                            "event": "closed",
                            "code": 1000,
                            "reason": err.to_string(),
                        }));
                        session_tick.shutdown();
                        break;
                    }
                }
            }
        }
    });

    loop {
        match session.next_event_locked_now(&roster_arc).await {
            Ok(Some(SessionEvent::AppData(data))) => {
                match refresh_v2_roster_if_changed(
                    &store,
                    &store_lock,
                    &roster_arc,
                    &last_stamp_arc,
                )
                .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        tracing::error!(error = %err, "failed to refresh roster during v2 app data");
                        let _ = session.send_close(1000, "roster error").await;
                        print_json_line(&serde_json::json!({
                            "event": "closed",
                            "code": 1000,
                            "reason": "roster error",
                        }));
                        break;
                    }
                }
                let still_active = roster_arc
                    .lock()
                    .expect("roster lock")
                    .get(&peer_id)
                    .is_some_and(|entry| entry.state == PeerState::Active);
                if !still_active {
                    let _ = session.send_close(1000, "peer revoked").await;
                    print_json_line(&serde_json::json!({
                        "event": "closed",
                        "code": 1000,
                        "reason": "peer revoked",
                    }));
                    break;
                }
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
                let loaded = {
                    let _g = store_lock.lock().await;
                    store.load_roster_with_stamp()
                };
                match loaded {
                    Ok((disk, fresh_stamp)) => {
                        *roster_arc.lock().expect("roster lock") = disk;
                        *last_stamp_arc.lock().expect("stamp lock") = fresh_stamp;
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "failed to reload roster after v2 revocation update");
                        let _ = session.send_close(1000, "roster error").await;
                        print_json_line(&serde_json::json!({
                            "event": "closed",
                            "code": 1000,
                            "reason": "roster error",
                        }));
                        break;
                    }
                }
                print_json_line(&serde_json::json!({
                    "event": "revocation_updated",
                    "issuer": issuer,
                    "seq": seq,
                }));
                if let Err(err) = session.tick_locked(now_unix(), &roster_arc).await {
                    print_json_line(&serde_json::json!({
                        "event": "closed",
                        "code": 1000,
                        "reason": err.to_string(),
                    }));
                    break;
                }
            }
            Ok(Some(
                event @ (SessionEvent::GroupManifestReceived(_)
                | SessionEvent::GroupRendezvousReceived(_)),
            )) => {
                if group::handle_group_frame(
                    store.as_ref(),
                    &identity.device_id(),
                    &peer_id,
                    &event,
                ) {
                    groups.refresh();
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
                print_json_line(&serde_json::json!({
                    "event": "closed",
                    "code": 1000,
                    "reason": err.to_string(),
                }));
                break;
            }
        }
    }
    let _ = stop_tx.send(true);
    let _ = tick_task.await;
    session.shutdown();
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
            Some(identity.signing_key().public_key().clone())
        } else {
            disk.lookup_active_signing_key(issuer).or_else(|| {
                disk.get(issuer)
                    .filter(|e| e.state != tendril_core::roster::PeerState::Pending)
                    .and_then(|e| e.signing_pub.clone())
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

async fn await_pong_v2(
    driver: &mut V2SessionDriver,
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

async fn sync_v2_relay_listeners(
    router: &InboundRouter,
    v2_relay_url: &str,
    expected_host: Option<&str>,
    relay_auth: &RelayClientAuth,
    roster: &Roster,
    active: &mut HashMap<String, ([u8; 32], watch::Sender<bool>)>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut desired: HashMap<String, [u8; 32]> = HashMap::new();
    for (peer_id, entry) in roster.entries() {
        if entry.state == PeerState::Active
            && let Some(ref secrets) = entry.v2_secrets
        {
            desired.insert(peer_id.clone(), *secrets.mailbox_secret());
        }
    }
    let to_remove: Vec<String> = active
        .iter()
        .filter(|(pid, (sec, _))| desired.get(*pid) != Some(sec))
        .map(|(pid, _)| pid.clone())
        .collect();
    for pid in to_remove {
        if let Some((_, stop_tx)) = active.remove(&pid) {
            let _ = stop_tx.send(true);
        }
    }
    let mut newly_bound = Vec::new();
    let handle = tokio::runtime::Handle::current();
    for (pid, secret) in desired {
        if active.contains_key(&pid) {
            continue;
        }
        if !newly_bound.is_empty() {
            let jitter_byte = random_bytes::<1>()?[0];
            let delay_ms = 25 + u64::from(jitter_byte) % 126;
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let cfg = RelayV2ListenerConfig {
            expected_host: expected_host.map(ToOwned::to_owned),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            allow_insecure_ws: false,
            replay_cache: None,
            unix_secs: None,
            auth: relay_auth.clone(),
        };
        let listener = RelayV2Listener::bind_with_config(v2_relay_url, secret, cfg).await?;
        newly_bound.push(listener.local_endpoint());
        let (stop_tx, stop_rx) = watch::channel(false);
        let cancelable = CancelableListener {
            inner: Box::new(listener),
            stop_rx,
        };
        router.spawn_listener(&handle, Box::new(cancelable));
        active.insert(pid, (secret, stop_tx));
    }
    Ok(newly_bound)
}

fn load_grant_arg(arg: &str) -> Result<Grant, Box<dyn std::error::Error>> {
    if let Some(path) = arg.strip_prefix('@') {
        let raw_bytes = read_private_secret_bytes(Path::new(path), "grant")?;
        let text = std::str::from_utf8(&raw_bytes).map_err(|_| "grant file must be valid UTF-8")?;
        Ok(serde_json::from_str(text.trim())?)
    } else {
        Ok(serde_json::from_str(arg)?)
    }
}

fn persist_dial_roster_updates(
    store: &StateStore,
    target: &str,
    initial_seq: Option<u64>,
    roster: &Roster,
    applied_rotation: &[tendril_core::identity::RotationRecord],
    upgrade_v2: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !applied_rotation.is_empty()
        && let Some(rotated) = roster.get(target).cloned()
        && rotated.rotation_seq > initial_seq.unwrap_or(0)
        && let Some(signing_pub) = rotated.signing_pub
    {
        store.update_roster(|disk| {
            if let Some(entry) = disk.get(target)
                && entry.state == PeerState::Active
                && entry.rotation_seq < rotated.rotation_seq
            {
                disk.apply_verified_rotation(
                    target,
                    applied_rotation,
                    &rotated.static_pub,
                    &signing_pub,
                )?;
            }
            Ok(())
        })?;
    }
    if upgrade_v2 {
        store.update_roster(|disk| {
            if let Some(entry) = disk.get(target)
                && entry.state == PeerState::Active
                && entry.v2_secrets.is_some()
                && entry.min_wire_version < tendril_core::wire::WIRE_VERSION_V2
            {
                disk.set_peer_min_wire_version(target, tendril_core::wire::WIRE_VERSION_V2)?;
            }
            Ok(())
        })?;
    }
    Ok(())
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
                signing_pub: id.signing_key().public_key().to_b64url(),
                signing_pub_hash: b64url_encode(&id.signing_key().signing_pub_hash()),
                relay_pub: b64url_encode(id.signing_key().ed25519_public_bytes()),
            });
        }
        Command::RelayTicket {
            relay_host,
            role,
            target_pub,
            ttl_secs,
        } => {
            let identity = store.load_identity()?;
            let ticket = identity.mint_relay_ticket(
                &relay_host,
                role.into(),
                target_pub.as_deref().unwrap_or("*"),
                now_unix(),
                ttl_secs,
            )?;
            if ticket.spans_multiple_v2_epochs() {
                tracing::warn!(
                    "minted relay ticket spans multiple /v2/relay epochs, allowing cross-epoch mailbox linkability; prefer Tier 2 HMAC admission or single-epoch scoped tickets"
                );
            }
            let json = Zeroizing::new(canonical_json(&ticket)?);
            println!("{}", *json);
        }
        Command::Serve {
            listen,
            relay,
            relay_host,
            embedded_relay,
            wire_v2,
            relay_v2,
            p2p,
            p2p_args,
            relay_auth,
            ephemeral_p2p,
            include_direct_addrs,
            overlay,
            overlay_allow_non_tailnet,
            broker,
            issue_code,
            allow_enroll,
            redact_logs,
        } => {
            let identity = Arc::new(store.load_or_generate_identity(None)?);
            let store_lock = Arc::new(AsyncMutex::new(()));
            let pair_mgr = Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default())));
            let router = Arc::new(InboundRouter::new());
            let v2_state = Arc::new(V2ResponderState::new());
            let pair_enabled = issue_code.is_some() || allow_enroll;
            router.set_pair_enabled(pair_enabled);
            router.set_v2_pair_enabled(wire_v2 && pair_enabled);

            let resolved_relay_auth = resolve_relay_auth(&relay_auth)?;
            let want_p2p = p2p
                || p2p_args.p2p_local
                || !p2p_args.p2p_relay.is_empty()
                || p2p_args.p2p_pkarr
                || p2p_args.p2p_relay_token_file.is_some()
                || p2p_args.p2p_api_secret_file.is_some();
            validate_explicit_p2p_args(&p2p_args)?;
            let resolved_p2p_auth = if want_p2p {
                resolve_p2p_relay_auth(&p2p_args)?
            } else {
                None
            };

            if relay_v2 && !wire_v2 {
                return Err("--relay-v2 requires --wire-v2".into());
            }
            if relay_v2 && !embedded_relay && relay.is_none() {
                return Err("--relay-v2 requires --relay or --embedded-relay".into());
            }

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
            let handle = tokio::runtime::Handle::current();
            router.spawn_listener(&handle, Box::new(direct_listener));

            let (
                embedded_relay_handle,
                embedded_relay_url,
                v1_relay_url,
                v2_relay_url,
                effective_host,
            ) = if embedded_relay {
                let host_name = relay_host.clone().unwrap_or_else(|| "localhost".to_owned());
                let emb = EmbeddedRelay::bind_local(host_name.clone()).await?;
                let ws_url = emb.ws_url();
                let ws_v2_url = relay_v2.then(|| emb.ws_v2_url());
                (
                    Some(emb),
                    Some(ws_url.clone()),
                    Some(ws_url),
                    ws_v2_url,
                    Some(host_name),
                )
            } else if let Some(r_url) = relay {
                if is_v2_relay_endpoint(&r_url) {
                    (None, None, None, Some(r_url), relay_host)
                } else if relay_v2 {
                    let v2_u = derive_v2_relay_url(&r_url);
                    (None, None, Some(r_url), Some(v2_u), relay_host)
                } else {
                    (None, None, Some(r_url), None, relay_host)
                }
            } else {
                (None, None, None, None, relay_host)
            };

            let served_v1_relay = v1_relay_url.clone();
            let relay_ep = if let Some(relay_url) = v1_relay_url {
                let rl = RelayListener::bind_with_auth(
                    relay_url,
                    effective_host.clone(),
                    identity.signing_key().ed25519_signing_key(),
                    DEFAULT_WRITE_TIMEOUT,
                    resolved_relay_auth.clone(),
                )
                .await?;
                let ep = rl.local_endpoint();
                router.spawn_listener(&handle, Box::new(rl));
                Some(ep)
            } else {
                None
            };

            let mut active_v2_relays: HashMap<String, ([u8; 32], watch::Sender<bool>)> =
                HashMap::new();
            let mut last_v2_roster_stamp = None;
            let relay_v2_endpoints = if let Some(ref v2_url) = v2_relay_url {
                let (roster_now, stamp_now) = store.load_roster_with_stamp()?;
                last_v2_roster_stamp = stamp_now;
                sync_v2_relay_listeners(
                    &router,
                    v2_url,
                    effective_host.as_deref(),
                    &resolved_relay_auth,
                    &roster_now,
                    &mut active_v2_relays,
                )
                .await?
            } else {
                Vec::new()
            };
            let relay_v2_endpoint = relay_v2_endpoints.first().cloned();

            let p2p_ep = if want_p2p {
                let opts =
                    build_p2p_listener_options(&p2p_args, resolved_p2p_auth, include_direct_addrs)?;
                let seed = if ephemeral_p2p {
                    None
                } else {
                    Some(identity.derive_p2p_identity_seed())
                };
                let pl = P2pListener::bind_with_options(opts, seed).await?;
                let ep = pl.local_endpoint();
                router.spawn_listener(&handle, Box::new(pl));
                Some(ep)
            } else {
                None
            };

            let overlay_ep = if let Some(overlay_addr) = overlay {
                let ol = OverlayListener::bind(overlay_addr, None)
                    .await?
                    .with_allow_non_tailnet(overlay_allow_non_tailnet);
                let ep = ol.local_endpoint();
                router.spawn_listener(&handle, Box::new(ol));
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
                router.spawn_listener(&handle, Box::new(bl));
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
                "relay_v2_endpoint": relay_v2_endpoint,
                "relay_v2_endpoints": relay_v2_endpoints,
                "embedded_relay_url": embedded_relay_url,
                "p2p_endpoint": p2p_ep,
                "overlay_endpoint": overlay_ep,
                "broker_endpoint": broker_ep,
                "pairing_code": shown_code,
                "allow_enroll": allow_enroll,
                "wire_v2": wire_v2,
            }));

            let group_dialers =
                group::build_dialers(resolved_relay_auth.clone(), want_p2p.then_some(&p2p_args))
                    .await?;
            let group_hub = group::ServeGroups::new(
                Arc::clone(&store),
                Arc::clone(&identity),
                group_dialers,
                resolved_relay_auth.clone(),
                served_v1_relay,
                redact_logs,
            );
            group_hub.refresh();

            let (v1_pair_q, v1_sess_q) = router.split_queues();
            let (v2_pair_q, v2_sess_q) = router.split_v2_queues();

            let mut worker_handles = Vec::new();
            {
                let store_c = Arc::clone(&store);
                let lock_c = Arc::clone(&store_lock);
                let id_c = Arc::clone(&identity);
                let mgr_c = Arc::clone(&pair_mgr);
                let rl_c = router.pair_rate_limiter().clone();
                worker_handles.push(spawn_routed_worker(v1_pair_q, move |mut stream, guard| {
                    let s = Arc::clone(&store_c);
                    let l = Arc::clone(&lock_c);
                    let id = Arc::clone(&id_c);
                    let m = Arc::clone(&mgr_c);
                    let r = rl_c.clone();
                    async move {
                        if !pair_enabled {
                            let _ = stream.close().await;
                            return;
                        }
                        handle_v1_pair(stream, guard, s, l, id, m, r, allow_enroll, redact_logs)
                            .await;
                    }
                }));
            }
            {
                let store_c = Arc::clone(&store);
                let lock_c = Arc::clone(&store_lock);
                let id_c = Arc::clone(&identity);
                let rl_c = router.session_rate_limiter().clone();
                let hub_c = Arc::clone(&group_hub);
                let v2_c = Arc::clone(&v2_state);
                worker_handles.push(spawn_routed_worker(v1_sess_q, move |stream, guard| {
                    let s = Arc::clone(&store_c);
                    let l = Arc::clone(&lock_c);
                    let id = Arc::clone(&id_c);
                    let r = rl_c.clone();
                    let hub = Arc::clone(&hub_c);
                    let v2 = Arc::clone(&v2_c);
                    async move {
                        if !hub.refresh() {
                            handle_v1_session(stream, guard, s, l, id, r, redact_logs, hub).await;
                            return;
                        }
                        match hub.accept(stream, &v2, &r, guard).await {
                            Some(InboundSession::OrdinaryV1 {
                                session,
                                roster,
                                stamp,
                            }) => {
                                run_v1_session(
                                    session,
                                    roster,
                                    stamp,
                                    s,
                                    l,
                                    id,
                                    redact_logs,
                                    Arc::clone(&hub),
                                )
                                .await;
                            }
                            Some(InboundSession::OrdinaryV2 { session }) => {
                                run_v2_session(session, s, l, id, redact_logs, Arc::clone(&hub))
                                    .await;
                            }
                            Some(InboundSession::Group { .. }) | None => {}
                        }
                    }
                }));
            }
            {
                let store_c = Arc::clone(&store);
                let lock_c = Arc::clone(&store_lock);
                let id_c = Arc::clone(&identity);
                let mgr_c = Arc::clone(&pair_mgr);
                let v2_c = Arc::clone(&v2_state);
                let rl_c = router.v2_pair_rate_limiter().clone();
                worker_handles.push(spawn_routed_worker(v2_pair_q, move |mut stream, guard| {
                    let s = Arc::clone(&store_c);
                    let l = Arc::clone(&lock_c);
                    let id = Arc::clone(&id_c);
                    let m = Arc::clone(&mgr_c);
                    let v2 = Arc::clone(&v2_c);
                    let r = rl_c.clone();
                    async move {
                        if !wire_v2 || !pair_enabled {
                            let _ = stream.close().await;
                            return;
                        }
                        handle_v2_pair(stream, guard, s, l, id, m, v2, r).await;
                    }
                }));
            }
            {
                let store_c = Arc::clone(&store);
                let lock_c = Arc::clone(&store_lock);
                let id_c = Arc::clone(&identity);
                let v2_c = Arc::clone(&v2_state);
                let rl_c = router.v2_session_rate_limiter().clone();
                let hub_c = Arc::clone(&group_hub);
                worker_handles.push(spawn_routed_worker(v2_sess_q, move |mut stream, guard| {
                    let s = Arc::clone(&store_c);
                    let l = Arc::clone(&lock_c);
                    let id = Arc::clone(&id_c);
                    let v2 = Arc::clone(&v2_c);
                    let r = rl_c.clone();
                    let hub = Arc::clone(&hub_c);
                    async move {
                        if !wire_v2 {
                            let _ = stream.close().await;
                            return;
                        }
                        if !hub.refresh() {
                            handle_v2_session(stream, guard, s, l, id, v2, r, redact_logs, hub)
                                .await;
                            return;
                        }
                        match hub.accept(stream, &v2, &r, guard).await {
                            Some(InboundSession::OrdinaryV2 { session }) => {
                                run_v2_session(session, s, l, id, redact_logs, Arc::clone(&hub))
                                    .await;
                            }
                            Some(InboundSession::OrdinaryV1 {
                                session,
                                roster,
                                stamp,
                            }) => {
                                run_v1_session(
                                    session,
                                    roster,
                                    stamp,
                                    s,
                                    l,
                                    id,
                                    redact_logs,
                                    Arc::clone(&hub),
                                )
                                .await;
                            }
                            Some(InboundSession::Group { .. }) | None => {}
                        }
                    }
                }));
            }

            let mut relay_sync_interval = tokio::time::interval(Duration::from_millis(250));
            relay_sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = relay_sync_interval.tick() => {
                        group_hub.refresh();
                        if let Some(ref v2_url) = v2_relay_url
                            && let Ok(curr_stamp) = store.roster_stamp()
                            && curr_stamp != last_v2_roster_stamp
                            && let Ok((roster_now, fresh_stamp)) = store.load_roster_with_stamp()
                        {
                            last_v2_roster_stamp = fresh_stamp;
                            if let Err(err) = sync_v2_relay_listeners(
                                &router,
                                v2_url,
                                effective_host.as_deref(),
                                &resolved_relay_auth,
                                &roster_now,
                                &mut active_v2_relays,
                            )
                            .await
                            {
                                tracing::warn!(error = %err, "failed to sync v2 relay listeners");
                            }
                        }
                    }
                }
            }

            for (_, stop_tx) in active_v2_relays.into_values() {
                let _ = stop_tx.send(true);
            }
            router.close();
            group_hub.shutdown();
            for handle in worker_handles {
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
            wire_v2,
            relay_v2,
            p2p_args,
            relay_auth,
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
            let roster = store.load_roster()?;
            let resolved_relay_auth = resolve_relay_auth(&relay_auth)?;
            validate_explicit_p2p_args(&p2p_args)?;
            if relay_v2 && !wire_v2 {
                return Err("--relay-v2 requires --wire-v2".into());
            }
            let use_relay_v2 = relay_v2 || is_v2_relay_endpoint(&effective_endpoint);
            let v2_mailbox_secret = if use_relay_v2 {
                Some(lookup_v2_mailbox_secret_for_pair(
                    &roster,
                    pinned_host.as_ref(),
                    &effective_endpoint,
                    now_unix(),
                )?)
            } else {
                None
            };
            let mut stream = dial_endpoint_cli(
                &effective_endpoint,
                relay_host.as_deref(),
                &p2p_args,
                &resolved_relay_auth,
                v2_mailbox_secret,
            )
            .await?;

            if wire_v2 {
                let v2_pinned = pinned_host
                    .map(|pin| {
                        let floor = pinned_pairing_floor(&roster, &pin);
                        V2PinnedHost::new(pin, floor)
                    })
                    .transpose()?;
                let display_name = parsed_uri
                    .as_ref()
                    .map_or_else(|| "paired-host".to_owned(), |u| u.host_name.clone());
                let hints = parsed_uri
                    .as_ref()
                    .map(|u| u.endpoints.clone())
                    .unwrap_or_default();
                let res = drive_v2_pake_pair_initiator_with_store(
                    stream.as_mut(),
                    &identity,
                    name,
                    kind,
                    effective_code.as_str().to_owned(),
                    v2_pinned,
                    display_name,
                    hints,
                    &store,
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await;
                let _ = stream.close().await;
                let res = res?;
                match res.outcome {
                    V2PairOutcome::InitiatorPending {
                        device_id,
                        host_id,
                        host_static_pub,
                        host_signing_pub,
                        pairing_sas,
                        host_pin_verified,
                        ..
                    } => {
                        print_json_line(&serde_json::json!({
                            "device_id": device_id,
                            "paired_host_id": host_id,
                            "sas": pairing_sas,
                            "status": if host_pin_verified { "active" } else { "pending" },
                            "host_confirmed": host_pin_verified,
                            "static_pub": b64url_encode(&host_static_pub),
                            "signing_pub": host_signing_pub.to_b64url(),
                            "signing_pub_hash": b64url_encode(&host_signing_pub.sha256_hash()),
                            "wire_version": 2,
                        }));
                    }
                    V2PairOutcome::Rejected { error } => {
                        return Err(format!("pairing rejected: {error}").into());
                    }
                    V2PairOutcome::ResponderPending { .. } => {
                        return Err("unexpected responder outcome".into());
                    }
                }
            } else {
                let res = drive_pair_initiator_with_store(
                    stream.as_mut(),
                    &identity,
                    name,
                    kind,
                    effective_code.as_str().to_owned(),
                    pinned_host,
                    &store,
                    DEFAULT_PRE_AUTH_TIMEOUT,
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
                                        Some(host_signing_pub.clone()),
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
                                        host_signing_pub.clone(),
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
                            "signing_pub": host_signing_pub.to_b64url(),
                            "signing_pub_hash": b64url_encode(&host_signing_pub.sha256_hash()),
                        }));
                    }
                    PairOutcome::Rejected { error } => {
                        return Err(format!("pairing rejected: {error}").into());
                    }
                    PairOutcome::ResponderPending { .. }
                    | PairOutcome::ResponderEnrolled { .. } => {
                        return Err("unexpected responder outcome".into());
                    }
                    PairOutcome::InitiatorEnrolled { .. } => {
                        return Err("unexpected m2m enrollment outcome".into());
                    }
                }
            }
        }
        Command::Anchor { cmd } => match cmd {
            AnchorCommand::Add {
                anchor_id,
                signing_pub,
            } => {
                let signing_pub_key = HybridSigningPublicKey::from_b64url(&signing_pub)?;
                let id_clone = anchor_id.clone();
                store.update_roster(|roster| {
                    roster
                        .add_trust_anchor(id_clone, signing_pub_key)
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
                            "signing_pub": anchor.signing_pub.to_b64url(),
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
            p2p_args,
            relay_auth,
        } => {
            validate_explicit_p2p_args(&p2p_args)?;
            let token = resolve_enroll_token(token_file, token_stdin)?;
            let pinned_host = PinnedHost {
                host_id: Some(host_id),
                static_pub: b64url_decode_array(&host_static_pub)?,
                signing_pin: parse_signing_pin_b64(&host_signing_pub)?,
                rotation_seq: host_rotation_seq,
            };
            let identity = store.load_or_generate_identity(None)?;
            let resolved_relay_auth = resolve_relay_auth(&relay_auth)?;
            let mut stream = dial_endpoint_cli(
                &endpoint,
                relay_host.as_deref(),
                &p2p_args,
                &resolved_relay_auth,
                None,
            )
            .await?;
            let res = drive_m2m_enroll_initiator_with_store(
                stream.as_mut(),
                &identity,
                name,
                kind,
                token,
                pinned_host,
                &store,
                DEFAULT_PRE_AUTH_TIMEOUT,
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
                                Some(host_signing_pub.clone()),
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
                        "signing_pub": host_signing_pub.to_b64url(),
                        "signing_pub_hash": b64url_encode(&host_signing_pub.sha256_hash()),
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
            wire_v2,
            relay_v2,
            wake_url,
            wake_adapter,
            wake_secret_file,
            wake_auth_header_file,
            wake_pre_wake,
            p2p_args,
            relay_auth,
            grant,
            message,
        } => {
            validate_explicit_p2p_args(&p2p_args)?;
            if relay_v2 && !wire_v2 {
                return Err("--relay-v2 requires --wire-v2".into());
            }
            if wake_url.is_some() && !wire_v2 {
                return Err("--wake-url requires --wire-v2".into());
            }
            if wake_url.is_none()
                && (wake_secret_file.is_some() || wake_auth_header_file.is_some() || wake_pre_wake)
            {
                return Err(
                    "--wake-secret-file, --wake-auth-header-file, and --wake-pre-wake require --wake-url"
                        .into(),
                );
            }

            let identity = store.load_identity()?;
            let mut roster = store.load_roster()?;
            let initial_seq = roster.get(&target).map(|e| e.rotation_seq);
            let grant_obj = grant.as_deref().map(load_grant_arg).transpose()?;
            let resolved_relay_auth = resolve_relay_auth(&relay_auth)?;
            let use_relay_v2 = relay_v2 || is_v2_relay_endpoint(&endpoint);
            let v2_mailbox_secret = if use_relay_v2 {
                Some(lookup_v2_mailbox_secret_for_target(&roster, &target)?)
            } else {
                None
            };

            if wire_v2 {
                let store_lock = AsyncMutex::new(());
                let (mut driver, wake_outcome) = if let Some(wurl) = wake_url {
                    let wake_secret = resolve_wake_secret(wake_secret_file.as_deref())?;
                    let mut wake_target = WakeTarget::new(wake_adapter.into(), &wurl)?;
                    if let Some(auth_path) = wake_auth_header_file.as_deref() {
                        let tok = resolve_wake_auth_token(auth_path)?;
                        wake_target = wake_target.with_auth_token(tok.as_str())?;
                    }
                    let wake_provider = Arc::new(HttpWakeProvider::new().with_cooldown_secs(0));
                    let wake_opts = WakeDialOptions::new(wake_provider, wake_target, wake_secret)
                        .with_pre_wake(wake_pre_wake);
                    let dialer = build_path_dialer(
                        &endpoint,
                        relay_host.as_deref(),
                        &p2p_args,
                        &resolved_relay_auth,
                        v2_mailbox_secret,
                    )
                    .await?;
                    let res = wake_and_connect_v2_session(
                        &*dialer,
                        &endpoint,
                        &wake_opts,
                        &identity,
                        &target,
                        grant_obj,
                        &mut roster,
                        now_unix(),
                    )
                    .await;
                    if let Err(err) = &res
                        && roster
                            .get(&target)
                            .is_some_and(|e| e.state == PeerState::Revoked)
                    {
                        let _ = store.update_roster(|disk| {
                            let _ = disk.revoke_peer(&target);
                            Ok(())
                        });
                        return Err(err.to_string().into());
                    }
                    let (drv, outcome) = res?;
                    persist_dial_roster_updates(
                        &store,
                        &target,
                        initial_seq,
                        &roster,
                        drv.applied_rotation(),
                        drv.exported_v2_secrets().is_some(),
                    )?;
                    (drv, outcome)
                } else {
                    let stream = dial_endpoint_cli(
                        &endpoint,
                        relay_host.as_deref(),
                        &p2p_args,
                        &resolved_relay_auth,
                        v2_mailbox_secret,
                    )
                    .await?;
                    let drv = V2SessionDriver::connect_with_store(
                        stream,
                        &identity,
                        &target,
                        grant_obj,
                        &store,
                        &store_lock,
                        now_unix(),
                    )
                    .await?;
                    roster = store.load_roster()?;
                    (drv, None)
                };

                let provider = format!("{:?}", driver.provider_id());
                let session_res: Result<(), Box<dyn std::error::Error>> = async {
                    await_pong_v2(&mut driver, &mut roster, 1).await?;
                    if let Some(msg) = message {
                        driver.send_data(msg.as_bytes()).await?;
                        await_pong_v2(&mut driver, &mut roster, 2).await?;
                    }
                    driver.send_close(1000, "done").await?;
                    Ok(())
                }
                .await;
                let persist_res = persist_crl_for_issuer(&store, &identity, &roster, &target);
                if let Err(err) = &persist_res {
                    tracing::error!(error = %err, "failed to persist v2 dial session CRL update");
                }
                session_res?;
                let _ = persist_res?;
                let wake_str = wake_outcome.map(|o| format!("{o:?}"));
                print_json_line(&serde_json::json!({
                    "connected": target,
                    "provider": provider,
                    "wire_version": 2,
                    "wake_outcome": wake_str,
                }));
            } else {
                tendril_core::session::check_peer_allows_wire_v1(&roster, &target)?;
                let stream = dial_endpoint_cli(
                    &endpoint,
                    relay_host.as_deref(),
                    &p2p_args,
                    &resolved_relay_auth,
                    v2_mailbox_secret,
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
                        .is_some_and(|e| e.state == PeerState::Revoked)
                {
                    let _ = store.update_roster(|disk| {
                        let _ = disk.revoke_peer(&target);
                        Ok(())
                    });
                    return Err(err.to_string().into());
                }
                let mut driver = connect_res?;
                persist_dial_roster_updates(
                    &store,
                    &target,
                    initial_seq,
                    &roster,
                    driver.applied_rotation(),
                    false,
                )?;
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
        }
        Command::Group { cmd } => group::run(Arc::clone(&store), cmd).await?,
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
                "signing_pub": identity.signing_key().public_key().to_b64url(),
                "signing_pub_hash": b64url_encode(&identity.signing_key().signing_pub_hash()),
                "relay_pub": b64url_encode(identity.signing_key().ed25519_public_bytes()),
            }));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkarr_default_enabled_only_for_default_relay_mode() {
        let default_args = P2pTransportArgs {
            p2p_local: false,
            p2p_relay: Vec::new(),
            p2p_relay_token_file: None,
            p2p_api_secret_file: None,
            p2p_pkarr: false,
            no_pkarr: false,
        };
        let listener_default =
            build_p2p_listener_options(&default_args, None, false).expect("default listener");
        assert!(listener_default.publish_pkarr);
        assert!(listener_default.resolve_pkarr);
        let dialer_default = build_p2p_dialer_options(&default_args, "direct://127.0.0.1:1", None)
            .expect("default dialer");
        assert!(dialer_default.resolve_pkarr);

        let no_pkarr_args = P2pTransportArgs {
            no_pkarr: true,
            ..default_args.clone()
        };
        let listener_no_pkarr =
            build_p2p_listener_options(&no_pkarr_args, None, false).expect("no-pkarr listener");
        assert!(!listener_no_pkarr.publish_pkarr);
        assert!(!listener_no_pkarr.resolve_pkarr);

        let custom_args = P2pTransportArgs {
            p2p_relay: vec!["https://relay.example".to_owned()],
            ..default_args.clone()
        };
        let listener_custom =
            build_p2p_listener_options(&custom_args, None, false).expect("custom listener");
        assert!(!listener_custom.publish_pkarr);
        assert!(!listener_custom.resolve_pkarr);
        let dialer_custom = build_p2p_dialer_options(&custom_args, "direct://127.0.0.1:1", None)
            .expect("custom dialer");
        assert!(!dialer_custom.resolve_pkarr);

        let custom_opt_in = P2pTransportArgs {
            p2p_pkarr: true,
            ..custom_args
        };
        let listener_custom_pkarr =
            build_p2p_listener_options(&custom_opt_in, None, false).expect("custom opt-in");
        assert!(listener_custom_pkarr.publish_pkarr);
        assert!(listener_custom_pkarr.resolve_pkarr);
        let dialer_custom_pkarr =
            build_p2p_dialer_options(&custom_opt_in, "direct://127.0.0.1:1", None)
                .expect("custom dialer opt-in");
        assert!(dialer_custom_pkarr.resolve_pkarr);
    }

    #[test]
    fn priv01_p2p_dialer_options_derives_uri_relays_and_disables_pkarr() {
        let default_args = P2pTransportArgs {
            p2p_local: false,
            p2p_relay: Vec::new(),
            p2p_relay_token_file: None,
            p2p_api_secret_file: None,
            p2p_pkarr: false,
            no_pkarr: false,
        };
        // Valid 32-byte Ed25519 hex iroh endpoint ID.
        let ep_id: String = SigningKeypair::generate()
            .expect("gen signing key")
            .ed25519_public_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let uri = format!("iroh://{ep_id}?relay=https://relay.example:8443");
        let opts = build_p2p_dialer_options(&default_args, &uri, None).expect("uri relay opts");
        assert_eq!(
            opts.relay_mode,
            P2pRelayMode::Custom("https://relay.example:8443/".to_owned())
        );
        assert!(!opts.resolve_pkarr);

        let pkarr_opt_in = P2pTransportArgs {
            p2p_pkarr: true,
            ..default_args.clone()
        };
        let opts_pkarr = build_p2p_dialer_options(&pkarr_opt_in, &uri, None).expect("pkarr opt-in");
        assert!(opts_pkarr.resolve_pkarr);

        // Private/loopback URI relay fails closed when private addrs are not enabled.
        let private_uri = format!("iroh://{ep_id}?relay=https://127.0.0.1:8443");
        assert!(build_p2p_dialer_options(&default_args, &private_uri, None).is_err());
    }

    #[test]
    fn lookup_v2_mailbox_secret_for_pair_fails_closed_without_match() {
        let mut roster = Roster::new();
        let peer_id = tendril_core::identity::EndpointIdentity::generate().unwrap();
        let secrets = tendril_core::roster::V2PeerSecrets::new([0x11; 32], [0x22; 32]);
        roster
            .apply_v2_pair_initiator_outcome(
                &V2PairOutcome::InitiatorPending {
                    device_id: peer_id.device_id(),
                    host_id: "unrelated-host".to_owned(),
                    host_static_pub: *peer_id.static_key().public_bytes(),
                    host_signing_pub: peer_id.signing_key().public_key().clone(),
                    pairing_sas: "123456".to_owned(),
                    host_rotation_seq: 0,
                    v2_secrets: secrets,
                    host_pin_verified: false,
                },
                "unrelated".to_owned(),
                Vec::new(),
            )
            .unwrap();
        // Single active v2 peer in roster must NOT be guessed when unpinned and no fragment matches.
        assert!(
            lookup_v2_mailbox_secret_for_pair(
                &roster,
                None,
                "ws://127.0.0.1:8080/v2/relay",
                1_795_564_800,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn priv06_sync_v2_relay_listeners_skips_pending_and_binds_active() {
        let relay = tendril_relay::RelayServer::bind(tendril_relay::RelayConfig::default())
            .await
            .expect("bind relay");
        let relay_handle = relay.spawn();
        let v2_relay_url = derive_v2_relay_url(&relay_handle.ws_url());

        let mut roster = Roster::new();
        let pending_id = tendril_core::identity::EndpointIdentity::generate().unwrap();
        let pending_secrets = tendril_core::roster::V2PeerSecrets::new([0x31; 32], [0x32; 32]);
        roster
            .apply_v2_pair_initiator_outcome(
                &V2PairOutcome::InitiatorPending {
                    device_id: pending_id.device_id(),
                    host_id: "pending-v2-peer".to_owned(),
                    host_static_pub: *pending_id.static_key().public_bytes(),
                    host_signing_pub: pending_id.signing_key().public_key().clone(),
                    pairing_sas: "111111".to_owned(),
                    host_rotation_seq: 0,
                    v2_secrets: pending_secrets,
                    host_pin_verified: false,
                },
                "pending".to_owned(),
                Vec::new(),
            )
            .unwrap();

        let active_id = tendril_core::identity::EndpointIdentity::generate().unwrap();
        let active_secrets = tendril_core::roster::V2PeerSecrets::new([0x41; 32], [0x42; 32]);
        roster
            .apply_v2_pair_initiator_outcome(
                &V2PairOutcome::InitiatorPending {
                    device_id: active_id.device_id(),
                    host_id: "active-v2-peer".to_owned(),
                    host_static_pub: *active_id.static_key().public_bytes(),
                    host_signing_pub: active_id.signing_key().public_key().clone(),
                    pairing_sas: "222222".to_owned(),
                    host_rotation_seq: 0,
                    v2_secrets: active_secrets,
                    host_pin_verified: false,
                },
                "active".to_owned(),
                Vec::new(),
            )
            .unwrap();
        roster
            .confirm_peer("active-v2-peer", Some("222222"))
            .unwrap();

        let router = InboundRouter::new();
        let mut active = HashMap::new();
        let bound = sync_v2_relay_listeners(
            &router,
            &v2_relay_url,
            Some("localhost"),
            &RelayClientAuth::None,
            &roster,
            &mut active,
        )
        .await
        .expect("sync v2 relay listeners");

        assert_eq!(bound.len(), 1, "only Active peer must bind a v2 mailbox");
        assert!(active.contains_key("active-v2-peer"));
        assert!(!active.contains_key("pending-v2-peer"));

        for (_, (_, stop_tx)) in active.drain() {
            let _ = stop_tx.send(true);
        }
        relay_handle.stop().await.expect("stop relay");
    }
}
