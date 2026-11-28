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
use tendril_core::UPGRADE_CAP_WEBRTC_V1;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, SigningKeypair,
    StaticKeypair, b64url_decode, b64url_decode_array, b64url_encode, random_bytes,
};
use tendril_core::grants::{Grant, canonical_json};
use tendril_core::identity::SigningKeyPin;
use tendril_core::pairing::{
    DEFAULT_ENROLLMENT_TTL_SECS, EnrollmentPolicy, IssueOptions, PairOutcome, PairingCodeKind,
    PairingConfig, PairingManager, PairingPathKind, PairingUri, PersistOpts, PinnedHost,
    RoutePolicy, mint_enrollment_token,
};
use tendril_core::policy::ProviderId;
use tendril_core::relay_auth::{RelayAuthRole, RelayAuthSecret, RelayTicket, origin_allowed};
use tendril_core::roster::{AnchorState, PeerState, Roster, RouteSource, StoredRoute};
use tendril_core::v2::{V2PairOutcome, canonical_relay_host};
use tendril_runtime::providers::egress::{DestClass, classify_destination};
use tendril_runtime::providers::hints::{
    HintDialerConfig, HintDialers, RouteApplyOpts, apply_signed_route_uri, clear_peer_routes,
    peer_routes, set_peer_routes,
};
use tendril_runtime::redact::{redact_error, redact_hint, redact_text, redact_url_str};
use tendril_runtime::{
    AddressSource, AdvertiseInputs, AdvertiseMode, ApnsPushMode, AttemptError, BrokerListener,
    BrokerServerConfig, CandidateFailure, ConnectOpts, ConnectResult, DEFAULT_PRE_AUTH_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT, DirectListener, EmbeddedRelay, EnrollRouteWarning, HalfOpenGuard,
    InboundQueue, InboundRouter, InboundSession, LastRouteSet, ListAddrSource, M2mEnrollOptions,
    OverlayListener, P2pDialer, P2pListener, P2pOptions, P2pRelayAuth, P2pRelayMode,
    PairPolicyOptions, PathDialer, PathListener, PathStream, PowerProfile, PreAuthRateLimiter,
    RecoveryRoutes, RefusalState, RelayClientAuth, RelayListener, RelayListenerConfig,
    RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig, RosterAccess, RouteAnnouncer,
    RouteSetSink, RuntimeError, SessionDriver, SessionEvent, StateStore, V2ResponderState,
    V2SessionDriver, WakeAdapterKind, WakeConfigSpec, WakeDialOptions, WakeOutcome, WakeSecret,
    WebRtcUpgradeEndpoint, WebRtcUpgradeHandle, WtListener, build_wake_provider,
    connect_with_wake_policy, dial_endpoint_with_auth as runtime_dial_endpoint_with_auth,
    drive_m2m_enroll_initiator_with_routes, drive_pair_initiator_with_policy,
    drive_pair_responder_with_store, drive_v2_pair_initiator_with_policy,
    drive_v2_pake_pair_responder_with_store, parse_p2p_bind_addrs, parse_p2p_relay_mode,
    parse_p2p_relay_modes, recv_routed,
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
    /// `remote` whenever a remote-class hint survives, else `lan`.
    Auto,
}

impl PairKindArg {
    const fn requested_kind(self) -> Option<PairingCodeKind> {
        match self {
            Self::Lan => Some(PairingCodeKind::Lan2Group),
            Self::Remote => Some(PairingCodeKind::Remote3Group),
            Self::Auto => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum PowerProfileArg {
    #[default]
    Standard,
    #[value(alias = "low_power")]
    LowPower,
}

impl From<PowerProfileArg> for PowerProfile {
    fn from(profile: PowerProfileArg) -> Self {
        match profile {
            PowerProfileArg::Standard => Self::Standard,
            PowerProfileArg::LowPower => Self::LowPower,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum RoutePolicyArg {
    /// Persist every route of a host-signed pairing URI or route set.
    #[default]
    AllSigned,
    /// Persist only the route that carried the pairing commit.
    CommittedOnly,
    /// Persist no route from a pairing URI, announcement or recovery URI.
    #[value(name = "none")]
    NoRoutes,
}

impl From<RoutePolicyArg> for RoutePolicy {
    fn from(arg: RoutePolicyArg) -> Self {
        match arg {
            RoutePolicyArg::AllSigned => Self::AllSigned,
            RoutePolicyArg::CommittedOnly => Self::CommittedOnly,
            RoutePolicyArg::NoRoutes => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RouteSourceArg {
    Operator,
    Signed,
    Committed,
    All,
}

impl RouteSourceArg {
    const fn source(self) -> Option<RouteSource> {
        match self {
            Self::Operator => Some(RouteSource::Operator),
            Self::Signed => Some(RouteSource::Signed),
            Self::Committed => Some(RouteSource::Committed),
            Self::All => None,
        }
    }
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
    #[value(alias = "apns_h2")]
    ApnsH2,
    Fcm,
}

impl From<WakeAdapterArg> for WakeAdapterKind {
    fn from(adapter: WakeAdapterArg) -> Self {
        match adapter {
            WakeAdapterArg::UnifiedPush => Self::UnifiedPush,
            WakeAdapterArg::Webhook => Self::Webhook,
            WakeAdapterArg::Apns => Self::Apns,
            WakeAdapterArg::ApnsH2 => Self::ApnsH2,
            WakeAdapterArg::Fcm => Self::Fcm,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ApnsPushModeArg {
    Background,
    #[value(alias = "mutable_alert")]
    MutableAlert,
}

impl From<ApnsPushModeArg> for ApnsPushMode {
    fn from(mode: ApnsPushModeArg) -> Self {
        match mode {
            ApnsPushModeArg::Background => Self::Background,
            ApnsPushModeArg::MutableAlert => Self::MutableAlert,
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
struct RelayOriginArgs {
    /// Relay origin (`scheme://host:port`) that may receive relay admission material
    /// (repeatable). An explicit `--endpoint` is always allowed.
    #[arg(long = "relay-auth-origin", value_name = "ORIGIN")]
    relay_auth_origins: Vec<String>,
}

#[derive(Debug, Clone, Default, Args)]
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
    /// Do not probe the local router for a UPnP, NAT-PMP or PCP port mapping.
    #[arg(long)]
    p2p_no_port_mapping: bool,
    /// Local UDP address the P2P endpoint binds for QUIC (repeatable, at most one IPv4 and one
    /// IPv6, for example `0.0.0.0:0` or `[::]:0`). A family left out gets no socket.
    #[arg(long = "p2p-bind", value_name = "ADDR")]
    p2p_bind: Vec<String>,
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
enum PendingCommand {
    /// List the unconfirmed host claims left by unpinned pairing, oldest first.
    List,
    /// Drop every claim naming `host_id`; revokes nothing.
    Remove { host_id: String },
    /// Revoke the keys of the claims whose handshake-derived `device_id` matches (never a `host_id`).
    Revoke { device_id: String },
}

#[derive(Debug, Subcommand)]
enum RouteCommand {
    /// Replace the peer's operator routes (`--endpoint` repeatable; `--clear` with none).
    Set {
        #[arg(long)]
        target: String,
        #[arg(long = "endpoint", value_name = "HINT")]
        endpoints: Vec<String>,
        #[arg(long, conflicts_with = "endpoints")]
        clear: bool,
    },
    /// Show the peer's stored routes, route metadata and last route set outcome.
    #[command(alias = "show")]
    List {
        #[arg(long)]
        target: String,
    },
    /// Remove the peer's routes of one source (default `operator`) or all of them.
    Clear {
        #[arg(long)]
        target: String,
        #[arg(long, value_enum, default_value_t = RouteSourceArg::Operator)]
        source: RouteSourceArg,
    },
    /// Apply a fresh host-signed pairing URI to the matching paired host offline.
    Apply {
        #[arg(long)]
        pairing_uri: String,
        #[arg(long)]
        replace_routes: bool,
        #[arg(long, value_enum, default_value_t)]
        route_policy: RoutePolicyArg,
    },
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
        #[arg(long)]
        webtransport: Option<SocketAddr>,
        #[arg(long, value_name = "SOCKET_ADDR")]
        webrtc_upgrade: Option<SocketAddr>,
        #[arg(long, value_enum)]
        issue_code: Option<PairKindArg>,
        /// Extra route to advertise in pairing URIs and route sets (repeatable).
        #[arg(long = "advertise-endpoint", value_name = "HINT")]
        advertise_endpoints: Vec<String>,
        /// Issue pairing URIs without `rq` and `rs` (interop tests only).
        #[arg(long)]
        no_route_signature: bool,
        #[arg(long)]
        allow_enroll: bool,
        #[arg(long)]
        redact_logs: bool,
        #[arg(long, value_enum, default_value_t)]
        power_profile: PowerProfileArg,
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
        /// Rejected: `/v2/relay` is never used for pairing.
        #[arg(long)]
        relay_v2: bool,
        #[arg(long, value_enum, default_value_t)]
        route_policy: RoutePolicyArg,
        /// Persist the route that carried an unsigned pairing.
        #[arg(long)]
        save_route: bool,
        #[command(flatten)]
        relay_auth: RelayAuthArgs,
        #[command(flatten)]
        origins: RelayOriginArgs,
        #[command(flatten)]
        p2p_args: P2pTransportArgs,
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
        /// Which of the host's routes to keep: the host's signed set and the endpoint dialed
        /// (`all-signed`, the default), only the endpoint dialed (`committed-only`), or no
        /// route (`none`: no route set is requested and nothing is stored). `all-signed`
        /// asks the host for its route set, which a host that predates route sets rejects
        /// as a protocol error before it spends the token: enrol against such a host with
        /// `committed-only` or `none`, or upgrade it.
        #[arg(long, value_enum, default_value_t)]
        route_policy: RoutePolicyArg,
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
        /// Dial only this endpoint; without it the stored routes are raced.
        #[arg(long)]
        endpoint: Option<String>,
        /// Fresh pairing URI of this peer, used as a recovery URI (its code is never sent).
        #[arg(long)]
        pairing_uri: Option<String>,
        /// Approve replacing the signed routes with the recovery URI's routes.
        #[arg(long, requires = "pairing_uri")]
        replace_routes: bool,
        #[arg(long, value_enum, default_value_t)]
        route_policy: RoutePolicyArg,
        #[command(flatten)]
        origins: RelayOriginArgs,
        #[arg(long)]
        relay_host: Option<String>,
        #[arg(long)]
        wire_v2: bool,
        #[arg(long)]
        relay_v2: bool,
        #[arg(long, value_name = "URL")]
        wake_url: Option<String>,
        #[arg(long, value_enum)]
        wake_adapter: Option<WakeAdapterArg>,
        #[arg(long, value_name = "PATH")]
        wake_secret_file: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        wake_auth_header_file: Option<PathBuf>,
        #[arg(long)]
        wake_pre_wake: bool,
        #[arg(long, value_name = "MS")]
        wake_retry_max_delay_ms: Option<u64>,
        #[arg(long, value_enum)]
        wake_apns_mode: Option<ApnsPushModeArg>,
        #[arg(long, value_name = "TOPIC")]
        wake_apns_topic: Option<String>,
        #[arg(long, value_name = "KEY")]
        wake_apns_loc_key: Option<String>,
        #[arg(long, value_name = "TEAM_ID")]
        wake_apns_team_id: Option<String>,
        #[arg(long, value_name = "KEY_ID")]
        wake_apns_key_id: Option<String>,
        #[arg(long, value_name = "PATH")]
        wake_apns_p8_file: Option<PathBuf>,
        #[command(flatten)]
        p2p_args: P2pTransportArgs,
        #[command(flatten)]
        relay_auth: RelayAuthArgs,
        #[arg(long, value_enum, default_value_t)]
        power_profile: PowerProfileArg,
        #[arg(long, value_name = "MS")]
        idle_timeout_ms: Option<u64>,
        #[arg(long, allow_hyphen_values = true)]
        grant: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        message: Option<String>,
    },
    /// Revoke an existing peer (`pair.revoke`), failing closed on all future sessions.
    ///
    /// Unless `--no-notify` is given, the roster's refusal policy decides whether the peer is
    /// told it is revoked when it next connects (a zero notice TTL tells it nothing).
    Revoke {
        peer_id: String,
        /// Revoke silently: record no refusal notice for this peer.
        #[arg(long)]
        no_notify: bool,
    },
    /// Show or set the host refusal policy (`spec/pairing-v1.md` Section 5.1).
    ///
    /// With no flag it prints the stored policy. Each flag given replaces that field and the
    /// resulting policy is persisted and printed. Notices already recorded keep their expiry.
    RefusalPolicy {
        /// Refuse unconfirmed (`Pending`) peers with `4004 peer_pending`.
        #[arg(long)]
        pending: Option<bool>,
        /// Lifetime in seconds of a notice recorded at revocation; `0` records none.
        #[arg(long)]
        revoked_ttl_secs: Option<u64>,
    },
    /// Drop the recorded refusal notice of a peer, which stays revoked.
    ClearRefusalNotice { peer_id: String },
    /// List, remove or revoke unconfirmed host claims from unpinned pairing.
    Pending {
        #[command(subcommand)]
        cmd: PendingCommand,
    },
    /// Inspect and manage a paired peer's stored Day-2 routes.
    Route {
        #[command(subcommand)]
        cmd: RouteCommand,
    },
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
    let link_meta = std::fs::symlink_metadata(path)?;
    if link_meta.file_type().is_symlink() || !link_meta.is_file() {
        return Err(format!(
            "{label} file '{}' must be a regular non-symlink file",
            path.display()
        )
        .into());
    }
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
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
    let cap = usize::try_from(meta.len().min(MAX_CREDENTIAL_FILE_BYTES))
        .unwrap_or(0)
        .saturating_add(1);
    let mut buf = Zeroizing::new(Vec::with_capacity(cap));
    file.take(MAX_CREDENTIAL_FILE_BYTES + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_CREDENTIAL_FILE_BYTES {
        return Err(format!(
            "{label} file '{}' exceeds {MAX_CREDENTIAL_FILE_BYTES} bytes",
            path.display()
        )
        .into());
    }
    Ok(buf)
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
    parse_p2p_bind_addrs("--p2p-bind", &args.p2p_bind)?;
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
    if matches!(mode, P2pRelayMode::N0Public) {
        !no_pkarr
    } else {
        p2p_pkarr && !no_pkarr
    }
}

/// The explicit `--p2p-pkarr` / `--no-pkarr` choice; `None` keeps the per-endpoint default.
/// The hint dialer set applies it to operator `iroh://` dials only.
const fn pkarr_override(args: &P2pTransportArgs) -> Option<bool> {
    if args.no_pkarr {
        Some(false)
    } else if args.p2p_pkarr {
        Some(true)
    } else {
        None
    }
}

/// Applies `--p2p-no-port-mapping`, `--p2p-bind`, and `profile` defaults to `opts`.
fn apply_p2p_net_args_with_profile(
    opts: P2pOptions,
    args: &P2pTransportArgs,
    profile: PowerProfile,
) -> Result<P2pOptions, Box<dyn std::error::Error>> {
    let port_mapping = !args.p2p_no_port_mapping && profile.p2p_port_mapping_default();
    Ok(opts
        .with_port_mapping(port_mapping)
        .with_bind_addrs(parse_p2p_bind_addrs("--p2p-bind", &args.p2p_bind)?))
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_p2p_listener_options(
    args: &P2pTransportArgs,
    resolved_p2p_auth: Option<P2pRelayAuth>,
    include_direct_addrs: bool,
) -> Result<P2pOptions, Box<dyn std::error::Error>> {
    build_p2p_listener_options_with_profile(
        args,
        resolved_p2p_auth,
        include_direct_addrs,
        PowerProfile::Standard,
    )
}

fn build_p2p_listener_options_with_profile(
    args: &P2pTransportArgs,
    resolved_p2p_auth: Option<P2pRelayAuth>,
    include_direct_addrs: bool,
    power_profile: PowerProfile,
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
    apply_p2p_net_args_with_profile(opts, args, power_profile)
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
    Ok(resolve_explicit_p2p_relay_mode(args, relay_host_fallback)?
        .unwrap_or(P2pRelayMode::N0Public))
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

/// A boxed error whose text went through the shared [`redact_text`]; the typed error is kept
/// when redaction changes nothing.
fn redacted_error<E: std::error::Error + 'static>(err: E) -> Box<dyn std::error::Error> {
    let shown = err.to_string();
    let safe = redact_text(&shown);
    if safe == shown {
        Box::new(err)
    } else {
        safe.into()
    }
}

fn validate_relay_auth_origins(origins: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    for origin in origins {
        if !origin_allowed(origin, std::slice::from_ref(origin)) {
            return Err(format!(
                "invalid --relay-auth-origin '{}': expected scheme://host[:port] with scheme ws, wss, http or https",
                redact_url_str(origin)
            )
            .into());
        }
    }
    Ok(())
}

/// The shared pairing and Day-2 dialer set. The `--relay-host` fallback for the Iroh relay mode
/// applies only to an explicit operator `iroh://` endpoint, as before.
fn build_hint_dialers(
    relay_auth: RelayClientAuth,
    relay_host: Option<&str>,
    p2p_args: &P2pTransportArgs,
    operator_endpoint: Option<&str>,
) -> Result<Arc<HintDialers>, Box<dyn std::error::Error>> {
    build_hint_dialers_with_profile(
        relay_auth,
        relay_host,
        p2p_args,
        operator_endpoint,
        PowerProfile::Standard,
    )
}

fn build_hint_dialers_with_profile(
    relay_auth: RelayClientAuth,
    relay_host: Option<&str>,
    p2p_args: &P2pTransportArgs,
    operator_endpoint: Option<&str>,
    power_profile: PowerProfile,
) -> Result<Arc<HintDialers>, Box<dyn std::error::Error>> {
    let relay_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    let operator_iroh = operator_endpoint
        .is_some_and(|ep| ep.starts_with("iroh://") || ep.starts_with("p2p:iroh://"));
    let p2p_relay_mode =
        resolve_explicit_p2p_relay_mode(p2p_args, relay_host.filter(|_| operator_iroh))?;
    let p2p_allow_private_addrs = matches!(p2p_relay_mode, Some(P2pRelayMode::Disabled));
    let port_mapping = if p2p_args.p2p_no_port_mapping {
        false
    } else {
        power_profile.p2p_port_mapping_default()
    };
    Ok(Arc::new(HintDialers::new(HintDialerConfig {
        relay_auth,
        relay_expected_host: relay_host.map(ToOwned::to_owned),
        p2p_relay_mode: p2p_relay_mode.unwrap_or(P2pRelayMode::N0Public),
        p2p_relay_auth: resolve_p2p_relay_auth(p2p_args)?,
        p2p_allow_private_addrs,
        p2p_pkarr: pkarr_override(p2p_args),
        p2p_port_mapping: port_mapping,
        p2p_bind_addrs: parse_p2p_bind_addrs("--p2p-bind", &p2p_args.p2p_bind)?,
        ..HintDialerConfig::default().with_power_profile(power_profile)
    })))
}

/// Parses a scanned pairing URI; the error is its redacted display text (`invalid pairing
/// URI: ...`), never the URI or its parameters.
fn parse_pairing_uri(raw: &str) -> Result<PairingUri, Box<dyn std::error::Error>> {
    PairingUri::parse(raw).map_err(|err| redact_text(&err.to_string()).into())
}

/// Skipped hints for diagnostics, with [`redact_hint`] applied.
fn skipped_json(skipped: &[tendril_runtime::providers::SkippedHint]) -> serde_json::Value {
    skipped
        .iter()
        .map(|s| serde_json::json!({ "hint": redact_hint(&s.hint), "reason": s.reason }))
        .collect()
}

/// Dropped advertised hints for the listening line, each only as
/// [`tendril_core::pairing::DroppedHint::redacted_hint`]: an operator hint may carry
/// credentials or a code.
fn dropped_json(dropped: &[tendril_core::pairing::DroppedHint]) -> serde_json::Value {
    dropped
        .iter()
        .map(|d| serde_json::json!({ "hint": d.redacted_hint(), "reason": d.reason }))
        .collect()
}

/// Candidates that were dialed and failed, in the order they failed.
fn candidate_failures_json(failures: &[CandidateFailure]) -> Vec<serde_json::Value> {
    failures
        .iter()
        .map(|f| {
            serde_json::json!({
                "hint": redact_hint(&f.hint),
                "provider": format!("{:?}", f.provider),
                "error": redact_error(&f.error),
            })
        })
        .collect()
}

/// The `error_code` of an `attempt_failed` line: the stable [`RuntimeError::code`] of an
/// authenticated refusal (`refused_revoked`, `refused_pending`, `refused`), otherwise the
/// bounded pairing code or egress reason.
fn attempt_error_code(error: &RuntimeError) -> Option<&'static str> {
    if error.refusal().is_some() {
        return Some(error.code());
    }
    match error {
        RuntimeError::Core(core) => Some(core.pair_error_code()),
        RuntimeError::Egress { reason, .. } => Some(reason.as_str()),
        _ => None,
    }
}

/// Reports a failed pairing or connect attempt as one JSON line on stderr and returns its error.
fn attempt_failed(err: AttemptError) -> Box<dyn std::error::Error> {
    let error_code = attempt_error_code(&err.error);
    let failures = candidate_failures_json(&err.failures);
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "attempt_failed",
            "error": redact_error(&err.error),
            "error_code": error_code,
            "committed": err.committed,
            "skipped": skipped_json(&err.skipped),
            "failures": failures,
        })
    );
    redacted_error(err.error)
}

/// Wakes the peer and runs the Wire v2 policy connect. With `pre_wake` the wake
/// hint goes first, then the connect runs with retries; otherwise the connect runs first and
/// only a miss a wake can fix ([`AttemptError::is_wakeable_miss`]) sends the wake hint and
/// retries. Any other failure ends the dial at once, without a wake.
async fn wake_connect_v2(
    identity: &Arc<tendril_core::identity::EndpointIdentity>,
    target: &str,
    access: &RosterAccess,
    make_opts: impl Fn() -> ConnectOpts,
    wake: &WakeDialOptions,
) -> Result<(ConnectResult<V2SessionDriver>, Option<WakeOutcome>), AttemptError> {
    let connect = || {
        V2SessionDriver::connect_with_policy_and_store(
            Arc::clone(identity),
            target,
            access,
            make_opts(),
        )
    };
    connect_with_wake_policy(wake, connect).await
}

const ROUTE_STATUS_FILE: &str = "route-status.json";

/// The last route set outcome per peer, recorded by `dial` for `route list`.
fn load_route_status(state_dir: &Path) -> serde_json::Map<String, serde_json::Value> {
    std::fs::read(state_dir.join(ROUTE_STATUS_FILE))
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}

fn record_route_status(
    state_dir: &Path,
    peer_id: &str,
    last: LastRouteSet,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut status = load_route_status(state_dir);
    status.insert(peer_id.to_owned(), serde_json::to_value(last)?);
    let body = serde_json::to_vec(&status)?;
    let tmp = state_dir.join(format!(
        ".{ROUTE_STATUS_FILE}.tmp.{}",
        b64url_encode(&random_bytes::<8>()?)
    ));
    let res = std::fs::write(&tmp, body)
        .and_then(|()| std::fs::rename(&tmp, state_dir.join(ROUTE_STATUS_FILE)));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(res?)
}

fn peer_routes_json(
    roster: &Roster,
    state_dir: &Path,
    peer_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let last = load_route_status(state_dir).remove(peer_id);
    let view = peer_routes(roster, peer_id, last)?;
    Ok(serde_json::json!({
        "target": peer_id,
        "routes": view.routes,
        "route_meta": view.route_meta,
        "last_route_set": view.last_route_set,
    }))
}

/// Adds the multi-route pairing fields to a `pair` result line.
fn add_pair_route_fields(
    out: &mut serde_json::Value,
    route: &tendril_core::policy::CandidateEndpoint,
    committed: bool,
    route_check: &str,
    routes_persisted: &[StoredRoute],
    routes_reason: Option<&str>,
    skipped: &[tendril_runtime::providers::SkippedHint],
) {
    if let Some(obj) = out.as_object_mut() {
        obj.insert("provider".into(), format!("{:?}", route.provider).into());
        obj.insert("endpoint".into(), route.addr.clone().into());
        obj.insert("committed".into(), committed.into());
        obj.insert("route_check".into(), route_check.into());
        obj.insert(
            "routes_persisted".into(),
            serde_json::to_value(routes_persisted).unwrap_or_default(),
        );
        obj.insert("routes_reason".into(), routes_reason.into());
        obj.insert("skipped".into(), skipped_json(skipped));
    }
}

const fn recovery_routes_str(outcome: RecoveryRoutes) -> &'static str {
    match outcome {
        RecoveryRoutes::Replaced => "replaced",
        RecoveryRoutes::Approved => "approved",
        RecoveryRoutes::Unchanged(reason) => reason,
    }
}

pub(crate) fn build_p2p_dialer_options_with_profile(
    p2p_args: &P2pTransportArgs,
    endpoint: &str,
    relay_host: Option<&str>,
    power_profile: PowerProfile,
) -> Result<P2pOptions, Box<dyn std::error::Error>> {
    let explicit_mode = resolve_explicit_p2p_relay_mode(p2p_args, relay_host)?;
    let p2p_auth = resolve_p2p_relay_auth(p2p_args)?;
    let allow_private_addrs = matches!(explicit_mode, Some(P2pRelayMode::Disabled));
    let mut opts = if endpoint.starts_with("iroh://") || endpoint.starts_with("p2p:iroh://") {
        P2pOptions::for_endpoint(endpoint, explicit_mode, allow_private_addrs)?
    } else {
        let mode = explicit_mode.unwrap_or(P2pRelayMode::N0Public);
        let is_disabled = matches!(mode, P2pRelayMode::Disabled);
        P2pOptions::for_dialer(mode).with_allow_private_addrs(allow_private_addrs || is_disabled)
    };
    let pkarr = resolve_pkarr_enabled(&opts.relay_mode, p2p_args.p2p_pkarr, p2p_args.no_pkarr);
    opts = opts.with_resolve_pkarr(pkarr).with_relay_auth(p2p_auth);
    apply_p2p_net_args_with_profile(opts, p2p_args, power_profile)
}

fn build_p2p_dialer_options(
    p2p_args: &P2pTransportArgs,
    endpoint: &str,
    relay_host: Option<&str>,
) -> Result<P2pOptions, Box<dyn std::error::Error>> {
    build_p2p_dialer_options_with_profile(p2p_args, endpoint, relay_host, PowerProfile::Standard)
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

fn resolve_wake_p8_pem(path: &Path) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let raw = read_private_secret_bytes(path, "wake apns p8")?;
    let text = Zeroizing::new(
        String::from_utf8(raw.to_vec()).map_err(|_| "wake apns p8 file must be valid UTF-8")?,
    );
    if text.trim().is_empty() {
        return Err("wake apns p8 file must not be empty".into());
    }
    Ok(text)
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

fn responder_path_kind(stream: &dyn PathStream) -> PairingPathKind {
    match stream.provider_id() {
        ProviderId::Local => PairingPathKind::Lan,
        ProviderId::Direct => {
            if stream.peer_ip().is_some_and(|ip| {
                matches!(
                    classify_destination(ip),
                    DestClass::Loopback | DestClass::Lan
                )
            }) {
                PairingPathKind::Lan
            } else {
                PairingPathKind::Remote
            }
        }
        _ => PairingPathKind::Remote,
    }
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
    let path_kind = responder_path_kind(stream.as_ref());
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
    let path_kind = responder_path_kind(stream.as_ref());
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
    announcer: Arc<RouteAnnouncer>,
    webrtc_handle: Option<WebRtcUpgradeHandle>,
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
    let allow_upgrade = stream.provider_id() != ProviderId::P2p && webrtc_handle.is_some();
    let upgrade_caps = if allow_upgrade {
        vec![UPGRADE_CAP_WEBRTC_V1.to_owned()]
    } else {
        Vec::new()
    };
    let Ok(mut driver) = SessionDriver::accept_with_upgrade_caps(
        stream,
        &identity,
        &mut roster,
        now,
        Some(&rate_limiter),
        Some(pre_auth_guard),
        DEFAULT_PRE_AUTH_TIMEOUT,
        upgrade_caps,
    )
    .await
    else {
        tracing::debug!("inbound session rejected");
        return;
    };
    if allow_upgrade {
        driver.set_webrtc_upgrade_handle(webrtc_handle);
    }
    run_v1_session(
        driver,
        roster,
        initial_stamp,
        store,
        store_lock,
        identity,
        redact_logs,
        groups,
        announcer,
    )
    .await;
}

/// Registers a responder session with the route announcer before any other host-initiated
/// frame; a client that sent `route_seq` receives the current signed route set if it is newer.
/// A failed registration (the initial set could not be sent) fails the session:
/// the caller closes it rather than run a session that missed its route set.
async fn register_route_sink(
    announcer: &RouteAnnouncer,
    sink: Arc<dyn RouteSetSink>,
    peer_route_seq: Option<u64>,
) -> Result<(), RuntimeError> {
    announcer
        .on_session_established(&sink, peer_route_seq, tendril_runtime::announce::unix_ms())
        .await
        .inspect_err(|err| {
            tracing::warn!(error = %redact_error(err), "route announcer registration failed");
        })
}

/// The `closed` line of a session whose route announcer registration failed.
const ROUTE_REGISTRATION_FAILED: &str = "route set delivery failed";

/// Persists the session CRL of `issuer` held by the shared session roster.
///
/// The written roster replaces the shared one only by compare-and-swap on the stamp it was
/// cloned at: when the tick reloaded the shared roster meanwhile, the newer copy stays (the
/// next reload picks up this write). CRLs the shared copy accepted after the clone are carried
/// into the swapped-in roster, so the swap never rolls revocation state back.
async fn persist_shared_session_crl(
    store: &StateStore,
    store_lock: &AsyncMutex<()>,
    identity: &tendril_core::identity::EndpointIdentity,
    roster_arc: &StdMutex<Roster>,
    last_stamp_arc: &StdMutex<Option<tendril_runtime::RosterStamp>>,
    issuer: &str,
) {
    let (mut roster, before) = {
        let memory = roster_arc.lock().expect("roster lock");
        let stamp = last_stamp_arc.lock().expect("stamp lock").clone();
        (memory.clone(), stamp)
    };
    let mut stamp = before.clone();
    persist_session_crl(store, store_lock, identity, &mut roster, issuer, &mut stamp).await;
    if stamp != before {
        swap_if_stamp_unchanged(identity, roster_arc, last_stamp_arc, &before, roster, stamp);
    }
}

/// Replaces the shared roster and stamp with `written` / `stamp` only while the shared stamp
/// is still `expected`; CRLs the shared roster holds beyond `written` are carried over first.
/// Returns whether the swap happened.
fn swap_if_stamp_unchanged(
    identity: &tendril_core::identity::EndpointIdentity,
    roster_arc: &StdMutex<Roster>,
    last_stamp_arc: &StdMutex<Option<tendril_runtime::RosterStamp>>,
    expected: &Option<tendril_runtime::RosterStamp>,
    mut written: Roster,
    stamp: Option<tendril_runtime::RosterStamp>,
) -> bool {
    let mut memory = roster_arc.lock().expect("roster lock");
    let mut current = last_stamp_arc.lock().expect("stamp lock");
    if *current != *expected {
        return false;
    }
    carry_held_revocations(&memory, &mut written, identity);
    *memory = written;
    *current = stamp;
    true
}

/// Runs an accepted ordinary Wire v1 session admitted against `roster` at `initial_stamp`.
/// An ingested group frame re-syncs the serving group pools in `groups`. The session is
/// registered with `announcer` for route set delivery.
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
    announcer: Arc<RouteAnnouncer>,
) {
    let peer_id = driver.peer_device_id().unwrap_or_default().to_owned();
    let mut last_stamp = initial_stamp;
    {
        let _guard = store_lock.lock().await;
        match store.roster_stamp() {
            Ok(curr_stamp) if curr_stamp != last_stamp => match store.load_roster_with_stamp() {
                Ok((mut disk, fresh_stamp)) => {
                    // Disk wins for everything but the revocation state the accept added.
                    carry_held_revocations(&roster, &mut disk, &identity);
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
    let session = Arc::new(driver.into_concurrent());
    if register_route_sink(&announcer, session.clone(), session.peer_route_seq())
        .await
        .is_err()
    {
        let _ = session.send_close(1000, ROUTE_REGISTRATION_FAILED).await;
        print_json_line(&serde_json::json!({
            "event": "closed",
            "code": 1000,
            "reason": ROUTE_REGISTRATION_FAILED,
        }));
        session.shutdown();
        return;
    }
    let roster_arc = Arc::new(StdMutex::new(roster));
    let last_stamp_arc = Arc::new(StdMutex::new(last_stamp));

    let session_tick = Arc::clone(&session);
    let roster_tick = Arc::clone(&roster_arc);
    let last_stamp_tick = Arc::clone(&last_stamp_arc);
    let store_tick = Arc::clone(&store);
    let store_lock_tick = Arc::clone(&store_lock);
    let identity_tick = Arc::clone(&identity);
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let tick_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = stop_rx.changed() => break,
                _ = interval.tick() => {
                    if let Err(err) = refresh_roster_if_changed(
                        &store_tick,
                        &store_lock_tick,
                        &identity_tick,
                        &roster_tick,
                        &last_stamp_tick,
                    )
                    .await
                    {
                        tracing::error!(error = %err, "failed to refresh roster during v1 tick");
                        let _ = session_tick.send_close(1000, "roster error").await;
                        print_json_line(&serde_json::json!({
                            "event": "closed",
                            "code": 1000,
                            "reason": "roster error",
                        }));
                        session_tick.shutdown();
                        break;
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
                if let Err(err) = refresh_roster_if_changed(
                    &store,
                    &store_lock,
                    &identity,
                    &roster_arc,
                    &last_stamp_arc,
                )
                .await
                {
                    tracing::error!(error = %err, "failed to reload roster during v1 session");
                    let _ = session.send_close(1000, "roster error").await;
                    print_json_line(&serde_json::json!({
                        "event": "closed",
                        "code": 1000,
                        "reason": "roster error",
                    }));
                    break;
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
                persist_shared_session_crl(
                    store.as_ref(),
                    store_lock.as_ref(),
                    identity.as_ref(),
                    &roster_arc,
                    &last_stamp_arc,
                    &issuer,
                )
                .await;
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
                for issuer in [identity.host_id(), peer_id.as_str()] {
                    persist_shared_session_crl(
                        store.as_ref(),
                        store_lock.as_ref(),
                        identity.as_ref(),
                        &roster_arc,
                        &last_stamp_arc,
                        issuer,
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
    let _ = stop_tx.send(true);
    let _ = tick_task.await;
    session.shutdown();
}

async fn refresh_roster_if_changed(
    store: &StateStore,
    store_lock: &AsyncMutex<()>,
    identity: &tendril_core::identity::EndpointIdentity,
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
            Ok((mut disk, fresh_stamp)) => {
                // One lock for carry and swap: a CRL the session ingested but has not yet
                // persisted survives the reload, and the reader persists it afterwards. The
                // stamp moves under the same lock (roster, then stamp), so a concurrent CRL
                // persist's compare-and-swap sees roster and stamp change together.
                let mut memory = roster_arc.lock().expect("roster lock");
                carry_held_revocations(&memory, &mut disk, identity);
                *memory = disk;
                *last_stamp_arc.lock().expect("stamp lock") = fresh_stamp;
                drop(memory);
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
    announcer: Arc<RouteAnnouncer>,
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
    run_v2_session(
        driver,
        store,
        store_lock,
        identity,
        redact_logs,
        groups,
        announcer,
    )
    .await;
}

/// Runs an accepted, store-backed ordinary Wire v2 session. An ingested group frame re-syncs
/// the serving group pools in `groups`. The session is registered with `announcer` for route
/// set delivery.
async fn run_v2_session(
    driver: V2SessionDriver,
    store: Arc<StateStore>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<tendril_core::identity::EndpointIdentity>,
    redact_logs: bool,
    groups: Arc<group::ServeGroups>,
    announcer: Arc<RouteAnnouncer>,
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
    if register_route_sink(&announcer, session.clone(), session.peer_route_seq())
        .await
        .is_err()
    {
        let _ = session.send_close(1000, ROUTE_REGISTRATION_FAILED).await;
        print_json_line(&serde_json::json!({
            "event": "closed",
            "code": 1000,
            "reason": ROUTE_REGISTRATION_FAILED,
        }));
        session.shutdown();
        return;
    }
    let roster_arc = Arc::new(StdMutex::new(initial_roster));
    let last_stamp_arc = Arc::new(StdMutex::new(initial_stamp));

    let session_tick = Arc::clone(&session);
    let roster_tick = Arc::clone(&roster_arc);
    let last_stamp_tick = Arc::clone(&last_stamp_arc);
    let store_tick = Arc::clone(&store);
    let store_lock_tick = Arc::clone(&store_lock);
    let identity_tick = Arc::clone(&identity);
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let tick_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = stop_rx.changed() => break,
                _ = interval.tick() => {
                    match refresh_roster_if_changed(
                        &store_tick,
                        &store_lock_tick,
                        &identity_tick,
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
                match refresh_roster_if_changed(
                    &store,
                    &store_lock,
                    &identity,
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
                    Ok((mut disk, fresh_stamp)) => {
                        let mut memory = roster_arc.lock().expect("roster lock");
                        carry_held_revocations(&memory, &mut disk, &identity);
                        *memory = disk;
                        *last_stamp_arc.lock().expect("stamp lock") = fresh_stamp;
                        drop(memory);
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

/// Folds into `disk` the revocation state `memory` holds (CRLs, revoked entries and anchors a
/// session accepted but the store lacks), so a roster reload never drops it. Verification keys
/// and notice rules are those of `Roster::absorb_held_revocations`, with this host's own key
/// for its own CRL.
fn carry_held_revocations(
    memory: &Roster,
    disk: &mut Roster,
    identity: &tendril_core::identity::EndpointIdentity,
) {
    disk.absorb_held_revocations(
        memory,
        Some((identity.host_id(), identity.signing_key().public_key())),
    );
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
    if roster.crl(issuer).is_none() {
        return Ok(None);
    }
    let ((), disk, stamp) = store.update_roster_with_state(|disk| {
        // Every held revocation goes in the same write as the CRL of `issuer`, so swapping the
        // session roster for the written one never drops any.
        carry_held_revocations(roster, disk, identity);
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

async fn sync_v2_relay_listeners_with_profile(
    router: &InboundRouter,
    v2_relay_url: &str,
    expected_host: Option<&str>,
    relay_auth: &RelayClientAuth,
    roster: &Roster,
    active: &mut HashMap<String, ([u8; 32], watch::Sender<bool>)>,
    power_profile: PowerProfile,
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
            power_profile,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let store = Arc::new(StateStore::open_or_create(&cli.state_dir)?);

    match cli.cmd {
        Command::Init { host_id } => {
            if host_id.as_deref() == Some("") {
                return Err("--host-id must not be empty".into());
            }
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
            webtransport,
            webrtc_upgrade,
            issue_code,
            advertise_endpoints,
            no_route_signature,
            allow_enroll,
            redact_logs,
            power_profile,
        } => {
            let serve_power_profile: PowerProfile = power_profile.into();
            let identity = Arc::new(store.load_or_generate_identity(None)?);
            let store_lock = Arc::new(AsyncMutex::new(()));
            let pair_mgr = Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default())));
            let router = Arc::new(InboundRouter::new().with_refusal_state(
                RefusalState::with_audit_sink(|audit| {
                    print_json_line(&serde_json::json!({
                        "event": "session_refused",
                        "peer_device_id": audit.peer_id,
                        "code": audit.code,
                    }));
                }),
            ));
            let (webrtc_handle, webrtc_listener, webrtc_addr) = if let Some(addr) = webrtc_upgrade {
                let (wh, wl) = WebRtcUpgradeEndpoint::bind(addr).await?;
                let bound = wl.local_addr();
                (Some(wh), Some(wl), Some(bound))
            } else {
                (None, None, None)
            };
            let v2_state = Arc::new(
                V2ResponderState::with_config(tendril_runtime::V2ResponderConfig {
                    jitter: serve_power_profile.v2_jitter(),
                    webrtc_upgrade_handle: webrtc_handle.clone(),
                    ..Default::default()
                })
                .with_refusal_state(router.refusal_state().clone()),
            );
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
                let rl = RelayListener::bind_with_config(
                    relay_url,
                    effective_host.clone(),
                    identity.signing_key().ed25519_signing_key(),
                    resolved_relay_auth.clone(),
                    RelayListenerConfig::new()
                        .with_write_timeout(DEFAULT_WRITE_TIMEOUT)
                        .with_power_profile(serve_power_profile),
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
                sync_v2_relay_listeners_with_profile(
                    &router,
                    v2_url,
                    effective_host.as_deref(),
                    &resolved_relay_auth,
                    &roster_now,
                    &mut active_v2_relays,
                    serve_power_profile,
                )
                .await?
            } else {
                Vec::new()
            };
            let relay_v2_endpoint = relay_v2_endpoints.first().cloned();

            let p2p_ep = if want_p2p {
                let opts = build_p2p_listener_options_with_profile(
                    &p2p_args,
                    resolved_p2p_auth,
                    include_direct_addrs,
                    serve_power_profile,
                )?;
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

            let wt_ep = if let Some(wt_addr) = webtransport {
                let wtl = WtListener::bind(wt_addr).await?;
                let ep = if wtl.local_addr().ip().is_unspecified() {
                    tracing::warn!(
                        addr = %wtl.local_addr(),
                        "webtransport bound to unspecified address; bind a concrete address or pass --advertise-endpoint to advertise wt://"
                    );
                    None
                } else {
                    Some(wtl.local_endpoint())
                };
                router.spawn_listener(&handle, Box::new(wtl));
                ep
            } else {
                None
            };
            if let Some(wul) = webrtc_listener {
                router.spawn_listener(&handle, Box::new(wul));
            }

            // Explicit advertising only: concrete listener binds and
            // `--advertise-endpoint`; unspecified binds are dropped, never enumerated.
            let served_endpoints: Vec<String> = [
                Some(direct_ep.clone()),
                wt_ep.clone(),
                relay_ep.clone(),
                v2_relay_url.clone(),
                p2p_ep.clone(),
                overlay_ep.clone(),
                broker_ep.clone(),
            ]
            .into_iter()
            .flatten()
            .collect();
            let announcer = Arc::new(RouteAnnouncer::new(
                (*identity).clone(),
                RosterAccess::from_store(Arc::clone(&store))?.with_local_signer(
                    identity.host_id(),
                    identity.signing_key().public_key().clone(),
                ),
                AdvertiseInputs {
                    mode: AdvertiseMode::Explicit,
                    served_endpoints,
                    listeners: Vec::new(),
                    advertised_endpoints: advertise_endpoints,
                },
                AddressSource::Custom(Arc::new(ListAddrSource::new(Vec::new()))),
            ));
            let now_ms = tendril_runtime::announce::unix_ms();
            let mut issued = None;
            let mut advertised = None;
            let mut dropped = None;
            let mut route_seq = None;
            if let Some(kind_arg) = issue_code {
                let opts = IssueOptions {
                    requested_kind: kind_arg.requested_kind(),
                    sign_routes: !no_route_signature,
                };
                // The announcer takes the manager itself, after its store I/O (lock order).
                let uri =
                    announcer.issue_pairing_uri(&pair_mgr, identity.host_id(), opts, now_ms)?;
                advertised = Some(uri.parsed.endpoints.clone());
                dropped = Some(dropped_json(&uri.dropped));
                route_seq = uri.route_seq;
                issued = Some(uri);
            } else {
                match announcer.publish(now_ms) {
                    Ok(state) => {
                        advertised = Some(state.routes().to_vec());
                        dropped = Some(dropped_json(&announcer.last_dropped()));
                        route_seq = Some(state.seq());
                    }
                    Err(err) => tracing::warn!(error = %err, "route publication failed"),
                }
            }
            let announcer_timer = announcer.spawn(None);

            let shown = |v: &str| -> String {
                if redact_logs {
                    "<redacted>".to_owned()
                } else {
                    v.to_owned()
                }
            };
            let pairing_code = issued
                .as_ref()
                .map(|i| Zeroizing::new(shown(i.parsed.code.as_str())));
            let pairing_uri = issued.as_ref().map(|i| Zeroizing::new(shown(&i.uri)));
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
                "wt_endpoint": wt_ep,
                "webrtc_upgrade": webrtc_addr.map(|a| a.to_string()),
                "pairing_code": pairing_code.as_deref(),
                "pairing_uri": pairing_uri.as_deref(),
                "advertised_endpoints": advertised,
                "dropped_endpoints": dropped,
                "uri_len": issued.as_ref().map(|i| i.uri_len),
                "qr_version_m": issued.as_ref().map(|i| i.qr_version_m),
                "route_seq": route_seq,
                "allow_enroll": allow_enroll,
                "wire_v2": wire_v2,
            }));
            drop(pairing_uri);
            drop(pairing_code);
            if let Some(mut i) = issued {
                i.uri.zeroize();
            }

            let group_dialers = group::build_dialers(
                resolved_relay_auth.clone(),
                want_p2p.then_some(&p2p_args),
                serve_power_profile,
            )
            .await?;
            let group_hub = group::ServeGroups::new(
                Arc::clone(&store),
                Arc::clone(&identity),
                group_dialers,
                resolved_relay_auth.clone(),
                served_v1_relay,
                redact_logs,
                serve_power_profile,
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
                let ann_c = Arc::clone(&announcer);
                let webrtc_c = webrtc_handle.clone();
                worker_handles.push(spawn_routed_worker(v1_sess_q, move |stream, guard| {
                    let s = Arc::clone(&store_c);
                    let l = Arc::clone(&lock_c);
                    let id = Arc::clone(&id_c);
                    let r = rl_c.clone();
                    let hub = Arc::clone(&hub_c);
                    let v2 = Arc::clone(&v2_c);
                    let ann = Arc::clone(&ann_c);
                    let webrtc = webrtc_c.clone();
                    async move {
                        if !hub.refresh() {
                            handle_v1_session(
                                stream,
                                guard,
                                s,
                                l,
                                id,
                                r,
                                redact_logs,
                                hub,
                                ann,
                                webrtc,
                            )
                            .await;
                            return;
                        }
                        match hub.accept(stream, &v2, &r, guard).await {
                            Some(InboundSession::OrdinaryV1 {
                                mut session,
                                roster,
                                stamp,
                            }) => {
                                if session.provider_id() == ProviderId::P2p {
                                    session.set_webrtc_upgrade_handle(None);
                                } else if let Some(ref wh) = webrtc {
                                    session.set_webrtc_upgrade_handle(Some(wh.clone()));
                                }
                                run_v1_session(
                                    session,
                                    roster,
                                    stamp,
                                    s,
                                    l,
                                    id,
                                    redact_logs,
                                    Arc::clone(&hub),
                                    ann,
                                )
                                .await;
                            }
                            Some(InboundSession::OrdinaryV2 { session }) => {
                                run_v2_session(
                                    session,
                                    s,
                                    l,
                                    id,
                                    redact_logs,
                                    Arc::clone(&hub),
                                    ann,
                                )
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
                let ann_c = Arc::clone(&announcer);
                let webrtc_c = webrtc_handle.clone();
                worker_handles.push(spawn_routed_worker(v2_sess_q, move |mut stream, guard| {
                    let s = Arc::clone(&store_c);
                    let l = Arc::clone(&lock_c);
                    let id = Arc::clone(&id_c);
                    let v2 = Arc::clone(&v2_c);
                    let r = rl_c.clone();
                    let hub = Arc::clone(&hub_c);
                    let ann = Arc::clone(&ann_c);
                    let webrtc = webrtc_c.clone();
                    async move {
                        if !wire_v2 {
                            let _ = stream.close().await;
                            return;
                        }
                        if !hub.refresh() {
                            handle_v2_session(
                                stream,
                                guard,
                                s,
                                l,
                                id,
                                v2,
                                r,
                                redact_logs,
                                hub,
                                ann,
                            )
                            .await;
                            return;
                        }
                        match hub.accept(stream, &v2, &r, guard).await {
                            Some(InboundSession::OrdinaryV2 { session }) => {
                                run_v2_session(
                                    session,
                                    s,
                                    l,
                                    id,
                                    redact_logs,
                                    Arc::clone(&hub),
                                    ann,
                                )
                                .await;
                            }
                            Some(InboundSession::OrdinaryV1 {
                                mut session,
                                roster,
                                stamp,
                            }) => {
                                if session.provider_id() == ProviderId::P2p {
                                    session.set_webrtc_upgrade_handle(None);
                                } else if let Some(ref wh) = webrtc {
                                    session.set_webrtc_upgrade_handle(Some(wh.clone()));
                                }
                                run_v1_session(
                                    session,
                                    roster,
                                    stamp,
                                    s,
                                    l,
                                    id,
                                    redact_logs,
                                    Arc::clone(&hub),
                                    ann,
                                )
                                .await;
                            }
                            Some(InboundSession::Group { .. }) | None => {}
                        }
                    }
                }));
            }

            let store_notify = tendril_runtime::store_change_notifier();
            let mut last_store_seq = tendril_runtime::store_change_seq();
            let fallback_interval = match serve_power_profile {
                PowerProfile::Standard => Duration::from_millis(250),
                PowerProfile::LowPower => tendril_runtime::HOST_BOOK_WATCH_FALLBACK,
            };
            let mut relay_sync_interval = tokio::time::interval(fallback_interval);
            relay_sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let notified = store_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let store_changed = tendril_runtime::store_change_seq() != last_store_seq;
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    () = async {
                        if store_changed {
                            return;
                        }
                        tokio::select! {
                            () = &mut notified => {}
                            _ = relay_sync_interval.tick() => {}
                        }
                    } => {
                        last_store_seq = tendril_runtime::store_change_seq();
                        group_hub.refresh();
                        if let Some(ref v2_url) = v2_relay_url
                            && let Ok(curr_stamp) = store.roster_stamp()
                            && curr_stamp != last_v2_roster_stamp
                            && let Ok((roster_now, fresh_stamp)) = store.load_roster_with_stamp()
                        {
                            last_v2_roster_stamp = fresh_stamp;
                            if let Err(err) = sync_v2_relay_listeners_with_profile(
                                &router,
                                v2_url,
                                effective_host.as_deref(),
                                &resolved_relay_auth,
                                &roster_now,
                                &mut active_v2_relays,
                                serve_power_profile,
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
            announcer_timer.abort();
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
            route_policy,
            save_route,
            relay_auth,
            origins,
            p2p_args,
        } => {
            const NO_V2_RELAY_PAIRING: &str = "/v2/relay is not used for pairing; pair over another route, then use dial --relay-v2";
            if relay_v2
                || endpoint
                    .as_deref()
                    .is_some_and(|ep| is_v2_relay_endpoint(ep.strip_prefix("relay:").unwrap_or(ep)))
            {
                return Err(NO_V2_RELAY_PAIRING.into());
            }
            let persist = PersistOpts {
                operator_endpoint: None,
                policy: route_policy.into(),
                save_committed: save_route,
            };
            persist.validate()?;
            validate_relay_auth_origins(&origins.relay_auth_origins)?;
            let parsed_uri = pairing_uri.as_deref().map(parse_pairing_uri).transpose()?;
            let effective_code = resolve_pair_code(
                code,
                code_stdin,
                code_file,
                parsed_uri.as_ref().map(|u| u.code.as_str()),
            )?;
            let identity = Arc::new(store.load_or_generate_identity(None)?);
            let resolved_relay_auth = resolve_relay_auth(&relay_auth)?;
            validate_explicit_p2p_args(&p2p_args)?;
            let dialers = build_hint_dialers(
                resolved_relay_auth,
                relay_host.as_deref(),
                &p2p_args,
                endpoint.as_deref(),
            )?;
            let mut opts =
                PairPolicyOptions::new(name, kind, effective_code.as_str().to_owned(), dialers);
            opts.uri = parsed_uri;
            opts.operator_endpoint = endpoint;
            opts.persist = persist;
            opts.relay_auth_origins = origins.relay_auth_origins;
            let access = RosterAccess::from_store(Arc::clone(&store))?.with_local_signer(
                identity.host_id(),
                identity.signing_key().public_key().clone(),
            );

            if wire_v2 {
                let res = drive_v2_pair_initiator_with_policy(identity, &access, opts)
                    .await
                    .map_err(attempt_failed)?;
                match &res.drive.outcome {
                    V2PairOutcome::InitiatorPending {
                        device_id,
                        host_id,
                        host_static_pub,
                        host_signing_pub,
                        pairing_sas,
                        host_pin_verified,
                        ..
                    } => {
                        let mut out = serde_json::json!({
                            "device_id": device_id,
                            "paired_host_id": host_id,
                            "sas": pairing_sas,
                            "status": if *host_pin_verified { "active" } else { "pending" },
                            "host_confirmed": host_pin_verified,
                            "static_pub": b64url_encode(host_static_pub),
                            "signing_pub": host_signing_pub.to_b64url(),
                            "signing_pub_hash": b64url_encode(&host_signing_pub.sha256_hash()),
                            "wire_version": 2,
                        });
                        add_pair_route_fields(
                            &mut out,
                            &res.route,
                            res.committed,
                            res.route_check.as_str(),
                            &res.routes_persisted,
                            res.routes_reason,
                            &res.skipped,
                        );
                        print_json_line(&out);
                    }
                    V2PairOutcome::Rejected { error } => {
                        return Err(format!("pairing rejected: {error}").into());
                    }
                    V2PairOutcome::ResponderPending { .. } => {
                        return Err("unexpected responder outcome".into());
                    }
                }
            } else {
                let res = drive_pair_initiator_with_policy(identity, &access, opts)
                    .await
                    .map_err(attempt_failed)?;
                match &res.drive.outcome {
                    PairOutcome::InitiatorPending {
                        device_id,
                        host_id,
                        host_static_pub,
                        host_signing_pub,
                        pairing_sas,
                        host_pin_verified,
                        ..
                    } => {
                        let mut out = serde_json::json!({
                            "device_id": device_id,
                            "paired_host_id": host_id,
                            "sas": pairing_sas,
                            "status": if *host_pin_verified { "active" } else { "pending" },
                            "host_confirmed": host_pin_verified,
                            "static_pub": b64url_encode(host_static_pub),
                            "signing_pub": host_signing_pub.to_b64url(),
                            "signing_pub_hash": b64url_encode(&host_signing_pub.sha256_hash()),
                        });
                        add_pair_route_fields(
                            &mut out,
                            &res.route,
                            res.committed,
                            res.route_check.as_str(),
                            &res.routes_persisted,
                            res.routes_reason,
                            &res.skipped,
                        );
                        print_json_line(&out);
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
            route_policy,
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
            let opts = M2mEnrollOptions {
                operator_endpoint: Some(endpoint.clone()),
                policy: route_policy.into(),
                handshake_timeout: DEFAULT_PRE_AUTH_TIMEOUT,
            };
            let res = drive_m2m_enroll_initiator_with_routes(
                stream.as_mut(),
                &identity,
                name,
                kind,
                token,
                pinned_host,
                &store,
                opts,
            )
            .await;
            let _ = stream.close().await;
            let res = res?;
            let routes_persisted = res.routes_persisted;
            let route_warnings: Vec<&str> = res
                .route_warnings
                .iter()
                .map(EnrollRouteWarning::as_str)
                .collect();
            for warning in &res.route_warnings {
                tracing::warn!(reason = warning.as_str(), %warning, "m2m enrolment route not stored");
            }
            match res.drive.outcome {
                PairOutcome::InitiatorEnrolled {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    token_nonce,
                } => {
                    print_json_line(&serde_json::json!({
                        "device_id": device_id,
                        "enrolled_host_id": host_id,
                        "routes_persisted": routes_persisted,
                        "route_warnings": route_warnings,
                        "routes_reason": serde_json::Value::Null,
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
            pairing_uri,
            replace_routes,
            route_policy,
            origins,
            relay_host,
            wire_v2,
            relay_v2,
            wake_url,
            wake_adapter,
            wake_secret_file,
            wake_auth_header_file,
            wake_pre_wake,
            wake_retry_max_delay_ms,
            wake_apns_mode,
            wake_apns_topic,
            wake_apns_loc_key,
            wake_apns_team_id,
            wake_apns_key_id,
            wake_apns_p8_file,
            p2p_args,
            relay_auth,
            power_profile,
            idle_timeout_ms,
            grant,
            message,
        } => {
            validate_explicit_p2p_args(&p2p_args)?;
            if idle_timeout_ms == Some(0) {
                return Err("--idle-timeout-ms must be >= 1".into());
            }
            let dial_power_profile: PowerProfile = power_profile.into();
            let idle_timeout = idle_timeout_ms.map(Duration::from_millis);
            if relay_v2 && !wire_v2 {
                return Err("--relay-v2 requires --wire-v2".into());
            }
            if wake_url.is_some() && !wire_v2 {
                return Err("--wake-url requires --wire-v2".into());
            }
            if wake_url.is_none()
                && (wake_adapter.is_some()
                    || wake_secret_file.is_some()
                    || wake_auth_header_file.is_some()
                    || wake_pre_wake
                    || wake_retry_max_delay_ms.is_some()
                    || wake_apns_mode.is_some()
                    || wake_apns_topic.is_some()
                    || wake_apns_loc_key.is_some()
                    || wake_apns_team_id.is_some()
                    || wake_apns_key_id.is_some()
                    || wake_apns_p8_file.is_some())
            {
                return Err(
                    "--wake-adapter, --wake-secret-file, --wake-auth-header-file, --wake-pre-wake, --wake-retry-max-delay-ms, and --wake-apns-* require --wake-url"
                        .into(),
                );
            }
            validate_relay_auth_origins(&origins.relay_auth_origins)?;

            let identity = store.load_identity()?;
            let grant_obj = grant.as_deref().map(load_grant_arg).transpose()?;
            let resolved_relay_auth = resolve_relay_auth(&relay_auth)?;

            // Wake applies to both explicit `--endpoint` dials and stored-route multi-address dials.
            let wake = match wake_url {
                Some(wurl) => {
                    let wake_secret = resolve_wake_secret(wake_secret_file.as_deref())?;
                    let mut auth_token = wake_auth_header_file
                        .as_deref()
                        .map(resolve_wake_auth_token)
                        .transpose()?;
                    let mut p8_pem = wake_apns_p8_file
                        .as_deref()
                        .map(resolve_wake_p8_pem)
                        .transpose()?;
                    let mut secret_b64 = Zeroizing::new(b64url_encode(wake_secret.as_bytes()));
                    let spec = WakeConfigSpec {
                        wake_url: Some(wurl),
                        wake_adapter: Some(wake_adapter.unwrap_or(WakeAdapterArg::Webhook).into()),
                        wake_secret_b64: Some(std::mem::take(&mut *secret_b64)),
                        wake_auth_token: auth_token.as_mut().map(|t| std::mem::take(&mut **t)),
                        wake_pre_wake: Some(wake_pre_wake),
                        wake_retry_delay_ms: None,
                        wake_retry_max_delay_ms,
                        wake_max_attempts: None,
                        wake_timeout_ms: None,
                        wake_coalesce_secs: None,
                        wake_apns_mode: wake_apns_mode.map(Into::into),
                        wake_apns_topic,
                        wake_apns_loc_key,
                        wake_apns_team_id,
                        wake_apns_key_id,
                        wake_apns_p8_pem: p8_pem.as_mut().map(|p| std::mem::take(&mut **p)),
                        wake_apns_client_cert_pem: None,
                        wake_apns_client_key_pem: None,
                    };
                    let settings = build_wake_provider(spec)
                        .map_err(redacted_error)?
                        .ok_or("wake configuration missing")?;
                    Some(settings.to_dial_options())
                }
                None => None,
            };

            if relay_v2
                && !endpoint
                    .as_deref()
                    .is_some_and(|ep| is_v2_relay_endpoint(ep.strip_prefix("relay:").unwrap_or(ep)))
            {
                return Err("--relay-v2 requires a /v2/relay --endpoint".into());
            }
            let dialers = build_hint_dialers_with_profile(
                resolved_relay_auth,
                relay_host.as_deref(),
                &p2p_args,
                endpoint.as_deref(),
                dial_power_profile,
            )?;
            let route_policy: RoutePolicy = route_policy.into();
            let make_opts = || {
                let mut opts = ConnectOpts::new(Arc::clone(&dialers))
                    .with_power_profile(dial_power_profile)
                    .with_idle_timeout(idle_timeout);
                opts.grant.clone_from(&grant_obj);
                opts.recovery_uri.clone_from(&pairing_uri);
                opts.replace_routes = replace_routes;
                opts.policy = route_policy;
                opts.operator_endpoint.clone_from(&endpoint);
                opts.relay_auth_origins
                    .clone_from(&origins.relay_auth_origins);
                opts
            };
            let access = RosterAccess::from_store(Arc::clone(&store))?.with_local_signer(
                identity.host_id(),
                identity.signing_key().public_key().clone(),
            );
            let identity = Arc::new(identity);

            let mut out = if wire_v2 {
                let (res, wake_outcome) = match &wake {
                    Some(wake) => {
                        wake_connect_v2(&identity, &target, &access, make_opts, wake).await
                    }
                    None => V2SessionDriver::connect_with_policy_and_store(
                        Arc::clone(&identity),
                        &target,
                        &access,
                        make_opts(),
                    )
                    .await
                    .map(|res| (res, None)),
                }
                .map_err(attempt_failed)?;
                let mut roster = store.load_roster()?;
                let mut driver = res.session;
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
                serde_json::json!({
                    "connected": target,
                    "provider": provider,
                    "endpoint": res.route.addr,
                    "wire_version": 2,
                    "wake_outcome": wake_outcome.map(|o| format!("{o:?}")),
                    "skipped": skipped_json(&res.skipped),
                    "failures": candidate_failures_json(&res.failures),
                    "recovery_routes": res.recovery_routes.map(recovery_routes_str),
                })
            } else {
                let res = SessionDriver::connect_with_policy_and_store(
                    Arc::clone(&identity),
                    &target,
                    &access,
                    make_opts(),
                )
                .await
                .map_err(attempt_failed)?;
                let mut roster = store.load_roster()?;
                let mut driver = res.session;
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
                serde_json::json!({
                    "connected": target,
                    "provider": provider,
                    "endpoint": res.route.addr,
                    "skipped": skipped_json(&res.skipped),
                    "failures": candidate_failures_json(&res.failures),
                    "recovery_routes": res.recovery_routes.map(recovery_routes_str),
                })
            };
            let last = access.last_route_set(&target);
            if let Some(last) = last
                && let Err(err) = record_route_status(store.dir(), &target, last)
            {
                tracing::warn!(error = %err, "failed to record route set status");
            }
            if let Some(obj) = out.as_object_mut() {
                obj.insert("route_set".into(), serde_json::to_value(last)?);
            }
            print_json_line(&out);
        }
        Command::Group { cmd } => group::run(Arc::clone(&store), cmd).await?,
        Command::Revoke { peer_id, no_notify } => {
            let now = now_unix();
            let notice = store.update_roster(|roster| {
                roster.revoke_peer_at(&peer_id, !no_notify, now)?;
                Ok(roster
                    .get(&peer_id)
                    .is_some_and(|e| roster.refusal_for_static(&e.static_pub, now).is_some()))
            })?;
            print_json_line(&serde_json::json!({ "revoked": peer_id, "notice": notice }));
        }
        Command::RefusalPolicy {
            pending,
            revoked_ttl_secs,
        } => {
            let policy = if pending.is_none() && revoked_ttl_secs.is_none() {
                store.load_roster()?.refusal_policy()
            } else {
                store.update_roster(|roster| {
                    let mut policy = roster.refusal_policy();
                    if let Some(pending) = pending {
                        policy.pending = pending;
                    }
                    if let Some(ttl) = revoked_ttl_secs {
                        policy.revoked_notice_ttl_secs = ttl;
                    }
                    roster.set_refusal_policy(policy);
                    Ok(policy)
                })?
            };
            print_json_line(&policy);
        }
        Command::ClearRefusalNotice { peer_id } => {
            store.update_roster(|roster| {
                roster.clear_refusal_notice(&peer_id)?;
                Ok(())
            })?;
            print_json_line(&serde_json::json!({ "cleared": peer_id }));
        }
        Command::Pending { cmd } => match cmd {
            PendingCommand::List => {
                let roster = store.load_roster()?;
                let claims = roster.pending_hosts_json();
                print_json_line(&serde_json::json!({ "pending_hosts": claims }));
            }
            PendingCommand::Remove { host_id } => {
                store.update_roster(|roster| {
                    roster
                        .remove_pending_host_claims(&host_id)
                        .map_err(Into::into)
                })?;
                print_json_line(&serde_json::json!({ "removed_pending": host_id }));
            }
            PendingCommand::Revoke { device_id } => {
                store.update_roster(|roster| {
                    roster.revoke_pending_host(&device_id).map_err(Into::into)
                })?;
                print_json_line(&serde_json::json!({ "revoked_pending": device_id }));
            }
        },
        Command::Route { cmd } => {
            let access = RosterAccess::from_store(Arc::clone(&store))?;
            // A store without a readable identity has no host CRL of its own to keep.
            let access = match store.load_identity() {
                Ok(identity) => access.with_local_signer(
                    identity.host_id(),
                    identity.signing_key().public_key().clone(),
                ),
                Err(_) => access,
            };
            match cmd {
                RouteCommand::Set {
                    target,
                    endpoints,
                    clear,
                } => {
                    if endpoints.is_empty() && !clear {
                        return Err(
                            "route set needs at least one --endpoint, or --clear to remove the operator routes"
                                .into(),
                        );
                    }
                    access
                        .update(|roster| set_peer_routes(roster, &target, &endpoints))
                        .map_err(redacted_error)?;
                    let roster = access.load()?;
                    print_json_line(&peer_routes_json(&roster, store.dir(), &target)?);
                }
                RouteCommand::List { target } => {
                    let roster = access.load()?;
                    print_json_line(&peer_routes_json(&roster, store.dir(), &target)?);
                }
                RouteCommand::Clear { target, source } => {
                    access.update(|roster| clear_peer_routes(roster, &target, source.source()))?;
                    let roster = access.load()?;
                    print_json_line(&peer_routes_json(&roster, store.dir(), &target)?);
                }
                RouteCommand::Apply {
                    pairing_uri,
                    replace_routes,
                    route_policy,
                } => {
                    let uri = Zeroizing::new(pairing_uri);
                    let parsed = parse_pairing_uri(&uri)?;
                    let opts = RouteApplyOpts {
                        policy: route_policy.into(),
                        replace_routes,
                    };
                    let res = access
                        .update(|roster| apply_signed_route_uri(roster, &parsed, opts))
                        .map_err(redacted_error)?;
                    print_json_line(&serde_json::json!({
                        "target": res.peer_id,
                        "applied": res.applied,
                        "reason": res.reason,
                        "routes": res.routes,
                        "route_meta": res.route_meta,
                    }));
                }
            }
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
    fn attempt_error_code_reports_refusals_by_their_stable_code() {
        use tendril_core::RefusalReason;
        use tendril_core::error::CoreError;
        let refused = |reason| RuntimeError::Core(CoreError::PeerRefused { reason });
        assert_eq!(
            attempt_error_code(&refused(RefusalReason::Revoked)),
            Some("refused_revoked")
        );
        assert_eq!(
            attempt_error_code(&refused(RefusalReason::Pending)),
            Some("refused_pending")
        );
        let closed = |code| RuntimeError::InitiatorClosed {
            code,
            reason: String::new(),
        };
        assert_eq!(attempt_error_code(&closed(4001)), Some("refused_revoked"));
        assert_eq!(attempt_error_code(&closed(4450)), Some("refused"));
        // A close that is not a refusal and other errors keep their bounded pairing codes.
        assert_eq!(attempt_error_code(&closed(1000)), None);
        assert_eq!(
            attempt_error_code(&RuntimeError::Core(CoreError::PairingCodeExpired)),
            Some("code_expired")
        );
    }

    #[test]
    fn pkarr_default_enabled_only_for_default_relay_mode() {
        let default_args = P2pTransportArgs {
            p2p_local: false,
            p2p_relay: Vec::new(),
            p2p_relay_token_file: None,
            p2p_api_secret_file: None,
            p2p_pkarr: false,
            no_pkarr: false,
            p2p_no_port_mapping: false,
            p2p_bind: Vec::new(),
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
    fn p2p_net_flags_parse_and_reach_every_option_set() {
        let cli = Cli::try_parse_from([
            "tendril",
            "dial",
            "--target",
            "peer",
            "--p2p-no-port-mapping",
            "--p2p-bind",
            "127.0.0.1:0",
            "--p2p-bind",
            "[::1]:0",
        ])
        .expect("flags parse");
        let Command::Dial { p2p_args, .. } = cli.cmd else {
            panic!("expected dial");
        };
        assert!(p2p_args.p2p_no_port_mapping);
        assert_eq!(p2p_args.p2p_bind, ["127.0.0.1:0", "[::1]:0"]);
        let only = tendril_runtime::P2pBindAddrs::Only {
            v4: Some("127.0.0.1:0".parse().expect("v4")),
            v6: Some("[::1]:0".parse().expect("v6")),
        };

        let listener = build_p2p_listener_options(&p2p_args, None, false).expect("listener");
        assert!(!listener.port_mapping);
        assert_eq!(listener.bind_addrs, only);
        let dialer =
            build_p2p_dialer_options(&p2p_args, "direct://127.0.0.1:1", None).expect("dialer");
        assert!(!dialer.port_mapping);
        assert_eq!(dialer.bind_addrs, only);
        let ep_id: String = SigningKeypair::generate()
            .expect("gen signing key")
            .ed25519_public_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let endpoint = format!("iroh://{ep_id}");
        let endpoint_dialer =
            build_p2p_dialer_options(&p2p_args, &endpoint, None).expect("endpoint dialer");
        assert!(!endpoint_dialer.port_mapping);
        assert_eq!(endpoint_dialer.bind_addrs, only);
        let hints = build_hint_dialers(RelayClientAuth::None, None, &p2p_args, Some(&endpoint))
            .expect("hint dialers");
        assert!(!hints.config().p2p_port_mapping);
        assert_eq!(hints.config().p2p_bind_addrs, only);
        let operator = hints.operator_p2p_options(&endpoint).expect("operator");
        assert!(!operator.port_mapping);
        assert_eq!(operator.bind_addrs, only);
    }

    #[test]
    fn p2p_net_defaults_map_and_bind_everywhere() {
        let args = P2pTransportArgs::default();
        let listener = build_p2p_listener_options(&args, None, false).expect("listener");
        assert!(listener.port_mapping);
        assert_eq!(
            listener.bind_addrs,
            tendril_runtime::P2pBindAddrs::AllInterfaces
        );
        let hints = build_hint_dialers(RelayClientAuth::None, None, &args, None).expect("hints");
        assert!(hints.config().p2p_port_mapping);
    }

    #[test]
    fn invalid_p2p_bind_is_an_error_naming_the_flag() {
        let args = P2pTransportArgs {
            p2p_bind: vec!["not-an-addr".to_owned()],
            ..P2pTransportArgs::default()
        };
        for err in [
            build_p2p_listener_options(&args, None, false)
                .expect_err("listener")
                .to_string(),
            build_p2p_dialer_options(&args, "direct://127.0.0.1:1", None)
                .expect_err("dialer")
                .to_string(),
            build_hint_dialers(RelayClientAuth::None, None, &args, None)
                .map(|_| ())
                .expect_err("hints")
                .to_string(),
            validate_explicit_p2p_args(&args)
                .expect_err("validate")
                .to_string(),
        ] {
            assert!(err.contains("--p2p-bind"), "{err}");
        }
    }

    #[test]
    fn n0_alias_is_accepted_as_the_relay_mode() {
        let args = P2pTransportArgs {
            p2p_relay: vec!["n0".to_owned()],
            ..P2pTransportArgs::default()
        };
        let opts = build_p2p_listener_options(&args, None, false).expect("listener");
        assert_eq!(opts.relay_mode, P2pRelayMode::N0Public);
    }

    #[test]
    fn low_power_profile_disables_default_p2p_port_mapping_for_serve_and_groups() {
        let args = P2pTransportArgs::default();
        let listener_std =
            build_p2p_listener_options_with_profile(&args, None, false, PowerProfile::Standard)
                .expect("standard listener");
        let listener_lp =
            build_p2p_listener_options_with_profile(&args, None, false, PowerProfile::LowPower)
                .expect("low-power listener");
        assert!(listener_std.port_mapping);
        assert!(!listener_lp.port_mapping);

        let dialer_lp = build_p2p_dialer_options_with_profile(
            &args,
            "direct://127.0.0.1:1",
            None,
            PowerProfile::LowPower,
        )
        .expect("low-power dialer");
        assert!(!dialer_lp.port_mapping);
    }

    fn test_crl(
        issuer: &tendril_core::identity::EndpointIdentity,
        seq: u64,
    ) -> tendril_core::grants::RevocationList {
        tendril_core::grants::sign_crl(
            tendril_core::grants::RevocationListUnsigned {
                v: 1,
                issuer: issuer.host_id().to_owned(),
                seq,
                revoked_devices: vec!["unrelated-device".to_owned()],
                revoked_nonces: Vec::new(),
                ts: "2026-11-23T00:00:00Z".to_owned(),
            },
            issuer.signing_key(),
        )
        .expect("crl")
    }

    #[tokio::test]
    async fn session_crl_survives_a_tick_reload_before_it_is_persisted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = StateStore::open_or_create(dir.path()).expect("store");
        let identity = tendril_core::identity::EndpointIdentity::generate().expect("identity");
        let peer = tendril_core::identity::EndpointIdentity::generate().expect("peer");
        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                peer.host_id().to_owned(),
                "peer".to_owned(),
                *peer.static_key().public_bytes(),
                Some(peer.signing_key().public_key().clone()),
                0,
                Vec::new(),
            )
            .expect("pin peer");
        store.save_roster(&roster).expect("save");
        let (mut memory, stamp) = store.load_roster_with_stamp().expect("load");

        // The session reader ingests a peer CRL and a host CRL into the shared roster.
        memory
            .ingest_crl(
                test_crl(&peer, 4),
                peer.host_id(),
                peer.signing_key().public_key(),
            )
            .expect("peer crl");
        memory
            .ingest_crl(
                test_crl(&identity, 2),
                identity.host_id(),
                identity.signing_key().public_key(),
            )
            .expect("host crl");
        let roster_arc = StdMutex::new(memory);
        let stamp_arc = StdMutex::new(stamp);
        let store_lock = AsyncMutex::new(());

        // An unrelated roster write lands, and the tick reloads before the reader persists.
        let other = tendril_core::identity::EndpointIdentity::generate().expect("other");
        store
            .update_roster_with_state(|disk| {
                disk.insert_pinned_host(
                    other.host_id().to_owned(),
                    "other".to_owned(),
                    *other.static_key().public_bytes(),
                    None,
                    0,
                    Vec::new(),
                )
                .map_err(RuntimeError::Core)?;
                Ok(())
            })
            .expect("unrelated write");
        refresh_roster_if_changed(&store, &store_lock, &identity, &roster_arc, &stamp_arc)
            .await
            .expect("reload");
        {
            let reloaded = roster_arc.lock().expect("roster lock");
            assert!(reloaded.get(other.host_id()).is_some(), "reload took disk");
            assert_eq!(reloaded.crl(peer.host_id()).map(|c| c.seq), Some(4));
            assert_eq!(reloaded.crl(identity.host_id()).map(|c| c.seq), Some(2));
        }

        // The reader then handles RevocationUpdated and persists both CRLs.
        for issuer in [peer.host_id(), identity.host_id()] {
            persist_shared_session_crl(
                &store,
                &store_lock,
                &identity,
                &roster_arc,
                &stamp_arc,
                issuer,
            )
            .await;
        }
        let disk = store.load_roster().expect("disk");
        assert_eq!(disk.crl(peer.host_id()).map(|c| c.seq), Some(4));
        assert_eq!(disk.crl(identity.host_id()).map(|c| c.seq), Some(2));
        assert!(disk.get(other.host_id()).is_some());
    }

    #[test]
    fn diagnostics_never_echo_credential_bearing_input() {
        let secret_origin = "wss://user:hunter2@relay.example:8443/v1/relay?token=s3cret#frag";
        let err = validate_relay_auth_origins(&[secret_origin.to_owned()])
            .expect_err("a path is not an origin")
            .to_string();
        assert!(err.contains("invalid --relay-auth-origin"), "{err}");
        for leaked in ["hunter2", "s3cret", "user", "/v1/relay", "frag"] {
            assert!(!err.contains(leaked), "{leaked} leaked: {err}");
        }

        let uri_err = parse_pairing_uri("tendril://pair?v=1&host=h&code=TND-ABCD-EFGH&s3cret=1")
            .expect_err("unknown parameter")
            .to_string();
        assert!(uri_err.contains("invalid pairing URI"), "{uri_err}");
        assert!(!uri_err.contains("s3cret"), "{uri_err}");
        assert!(!uri_err.contains("TND-ABCD-EFGH"), "{uri_err}");

        let failure = CandidateFailure {
            hint: secret_origin.to_owned(),
            provider: tendril_core::policy::ProviderId::Relay,
            error: RuntimeError::Protocol(format!("relay refused '{secret_origin}': closed")),
        };
        let skipped = tendril_runtime::providers::SkippedHint::new(
            "https://user:hunter2@broker.example/x?k=s3cret".to_owned(),
            tendril_runtime::providers::SkipReason::BlockedAddress,
        );
        let shown = serde_json::json!({
            "failures": candidate_failures_json(std::slice::from_ref(&failure)),
            "skipped": skipped_json(std::slice::from_ref(&skipped)),
        })
        .to_string();
        assert!(shown.contains("wss://relay.example:8443"), "{shown}");
        assert!(shown.contains("https://broker.example"), "{shown}");
        assert!(shown.contains("blocked_address"), "{shown}");
        for leaked in ["hunter2", "s3cret", "user", "/v1/relay", "frag"] {
            assert!(!shown.contains(leaked), "{leaked} leaked: {shown}");
        }

        let returned = attempt_failed(AttemptError::from(failure.error)).to_string();
        assert!(
            !returned.contains("hunter2") && !returned.contains("s3cret"),
            "{returned}"
        );
    }

    #[test]
    fn wake_retries_only_misses_a_wake_can_fix() {
        let attempt =
            |error: RuntimeError, committed: bool, failures: Vec<RuntimeError>| AttemptError {
                error,
                committed,
                skipped: Vec::new(),
                failures: failures
                    .into_iter()
                    .map(|error| CandidateFailure {
                        hint: "ws://127.0.0.1:1/v2/relay".to_owned(),
                        provider: tendril_core::policy::ProviderId::Relay,
                        error,
                    })
                    .collect(),
            };
        let offline = || RuntimeError::RelayOffline(tendril_runtime::RelayOffline::V2Dial);
        let pinned_offline =
            || RuntimeError::RelayOffline(tendril_runtime::RelayOffline::PinnedKey);
        let refused =
            || RuntimeError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert!(attempt(refused(), false, vec![refused()]).is_wakeable_miss());
        assert!(attempt(RuntimeError::Closed, false, Vec::new()).is_wakeable_miss());
        assert!(attempt(pinned_offline(), false, vec![offline()]).is_wakeable_miss());
        assert!(attempt(offline(), false, vec![refused()]).is_wakeable_miss());
        assert!(!attempt(offline(), true, vec![offline()]).is_wakeable_miss());
        assert!(!attempt(refused(), true, Vec::new()).is_wakeable_miss());
        for permanent in [
            RuntimeError::Protocol("relay_auth_unconfigured: relay requires credentials".into()),
            RuntimeError::Protocol("v2 relay dial rejected: unauthorized".into()),
            RuntimeError::Protocol("no dialable stored routes for p".into()),
            RuntimeError::Policy("all candidates exhausted"),
            RuntimeError::Core(tendril_core::error::CoreError::PeerRevoked("p".into())),
        ] {
            assert!(!attempt(permanent, false, Vec::new()).is_wakeable_miss());
        }
        let unauthorized = || RuntimeError::Protocol("v2 relay dial rejected: unauthorized".into());
        assert!(
            !attempt(offline(), false, vec![offline(), unauthorized()]).is_wakeable_miss(),
            "one permanent candidate failure"
        );
        // A look-alike untyped message is no longer an offline refusal.
        assert!(
            !attempt(
                RuntimeError::Protocol("v2 relay dial rejected: offline".into()),
                false,
                Vec::new()
            )
            .is_wakeable_miss()
        );
    }

    #[test]
    fn redacting_runtime_text_again_changes_nothing() {
        // Runtime messages already print redact_host / redact_hint output; the CLI's own
        // pass over them must not mangle it.
        for already in [
            "egress refused (blocked_address): 10.0.0.1".to_owned(),
            format!(
                "egress refused (invalid): {}",
                tendril_runtime::redact::redact_host("bad host!")
            ),
            format!(
                "no dialable route: {}",
                tendril_runtime::redact::redact_hint("wss://u:p@relay.example:8443/v2/relay?t=1")
            ),
            format!(
                "dial failed: {}",
                tendril_runtime::redact::redact_hint("direct:[::1]:4433")
            ),
        ] {
            assert_eq!(
                redact_text(&already),
                already,
                "double redaction changed {already}"
            );
            let boxed = redacted_error(std::io::Error::other(already.clone()));
            assert_eq!(boxed.to_string(), already);
        }
    }

    #[test]
    fn diagnostics_redact_pairing_codes_and_url_tails() {
        let failure = CandidateFailure {
            hint: "direct:TND-ABCD-EFGH:1".to_owned(),
            provider: tendril_core::policy::ProviderId::Direct,
            error: RuntimeError::Protocol(
                "dial https://relay.example/x y?tok=s3cret then tnd-abcd-efgh failed".to_owned(),
            ),
        };
        let dropped = [
            tendril_core::pairing::DroppedHint {
                hint: "local:tnd-wxyz-qrst".to_owned(),
                reason: tendril_core::pairing::DropReason::Invalid,
            },
            tendril_core::pairing::DroppedHint {
                hint: "ws://user:s3cret@relay.example/v1/relay?tok=s3cret".to_owned(),
                reason: tendril_core::pairing::DropReason::InsecureWs,
            },
        ];
        let shown = serde_json::json!({
            "failures": candidate_failures_json(std::slice::from_ref(&failure)),
            "dropped": dropped_json(&dropped),
        })
        .to_string();
        assert!(shown.contains("ws://relay.example"), "{shown}");
        assert!(shown.contains("insecure_ws"), "{shown}");
        let lower = shown.to_ascii_lowercase();
        for leaked in ["abcd-efgh", "wxyz-qrst", "s3cret", "tok=", "/v1/relay"] {
            assert!(!lower.contains(leaked), "{leaked} leaked: {shown}");
        }
        let returned = attempt_failed(AttemptError::from(failure.error))
            .to_string()
            .to_ascii_lowercase();
        assert!(
            !returned.contains("s3cret") && !returned.contains("abcd-efgh"),
            "{returned}"
        );
    }

    #[test]
    fn crl_persist_swap_never_rolls_back_a_newer_reload() {
        let identity = tendril_core::identity::EndpointIdentity::generate().expect("identity");
        let peer = tendril_core::identity::EndpointIdentity::generate().expect("peer");
        let mut base = Roster::new();
        base.insert_pinned_host(
            peer.host_id().to_owned(),
            "peer".to_owned(),
            *peer.static_key().public_bytes(),
            Some(peer.signing_key().public_key().clone()),
            0,
            Vec::new(),
        )
        .expect("pin peer");
        let dir = tempfile::tempdir().expect("tempdir");
        let store = StateStore::open_or_create(dir.path()).expect("store");
        store.save_roster(&base).expect("save");
        let cloned_at = store.roster_stamp().expect("stamp");
        let ingest = |roster: &mut Roster, seq| {
            roster
                .ingest_crl(
                    test_crl(&peer, seq),
                    peer.host_id(),
                    peer.signing_key().public_key(),
                )
                .expect("crl");
        };
        // The persist wrote seq 4; the shared roster accepted seq 5 meanwhile.
        let mut written = base.clone();
        ingest(&mut written, 4);
        let mut shared = base.clone();
        ingest(&mut shared, 5);
        let roster_arc = StdMutex::new(shared);
        let stamp_arc = StdMutex::new(cloned_at.clone());
        assert!(swap_if_stamp_unchanged(
            &identity,
            &roster_arc,
            &stamp_arc,
            &cloned_at,
            written.clone(),
            None,
        ));
        assert_eq!(
            roster_arc
                .lock()
                .unwrap()
                .crl(peer.host_id())
                .map(|c| c.seq),
            Some(5),
            "the swap carries the newer in-memory CRL"
        );

        // A tick reloaded a newer roster after the clone: the written copy does not replace it.
        let reloaded_marker = tendril_core::identity::EndpointIdentity::generate().expect("id");
        let mut reloaded = base;
        reloaded
            .insert_pinned_host(
                reloaded_marker.host_id().to_owned(),
                "newer".to_owned(),
                *reloaded_marker.static_key().public_bytes(),
                None,
                0,
                Vec::new(),
            )
            .expect("pin");
        let roster_arc = StdMutex::new(reloaded);
        let stamp_arc = StdMutex::new(None);
        assert!(!swap_if_stamp_unchanged(
            &identity,
            &roster_arc,
            &stamp_arc,
            &cloned_at,
            written,
            cloned_at.clone(),
        ));
        assert!(
            roster_arc
                .lock()
                .unwrap()
                .get(reloaded_marker.host_id())
                .is_some(),
            "the newer reload stays"
        );
        assert!(stamp_arc.lock().unwrap().is_none());
    }

    #[test]
    fn trust_anchor_crls_survive_a_reload() {
        let identity = tendril_core::identity::EndpointIdentity::generate().expect("identity");
        let anchor = tendril_core::identity::EndpointIdentity::generate().expect("anchor");
        let mut disk = Roster::new();
        disk.add_trust_anchor(
            anchor.host_id().to_owned(),
            anchor.signing_key().public_key().clone(),
        )
        .expect("anchor");
        let mut memory = disk.clone();
        memory
            .ingest_crl(
                test_crl(&anchor, 3),
                anchor.host_id(),
                anchor.signing_key().public_key(),
            )
            .expect("anchor crl");
        carry_held_revocations(&memory, &mut disk, &identity);
        assert_eq!(disk.crl(anchor.host_id()).map(|c| c.seq), Some(3));
    }

    #[test]
    fn a_reload_keeps_the_hosts_own_crl_and_revoked_state() {
        let identity = tendril_core::identity::EndpointIdentity::generate().expect("identity");
        let anchor = tendril_core::identity::EndpointIdentity::generate().expect("anchor");
        let peer = tendril_core::identity::EndpointIdentity::generate().expect("peer");
        let mut disk = Roster::new();
        disk.add_trust_anchor(
            anchor.host_id().to_owned(),
            anchor.signing_key().public_key().clone(),
        )
        .expect("anchor");
        disk.insert_pinned_host(
            peer.host_id().to_owned(),
            "peer".to_owned(),
            *peer.static_key().public_bytes(),
            Some(peer.signing_key().public_key().clone()),
            0,
            Vec::new(),
        )
        .expect("pin peer");
        let mut memory = disk.clone();
        memory
            .ingest_crl(
                test_crl(&anchor, 2),
                anchor.host_id(),
                anchor.signing_key().public_key(),
            )
            .expect("anchor crl");
        memory
            .ingest_crl(
                test_crl(&identity, 1),
                identity.host_id(),
                identity.signing_key().public_key(),
            )
            .expect("own crl");
        // The anchor and the peer are revoked in memory and the anchor also on disk.
        memory
            .revoke_trust_anchor(anchor.host_id())
            .expect("revoke anchor");
        memory.revoke_peer(peer.host_id()).expect("revoke peer");
        disk.revoke_trust_anchor(anchor.host_id())
            .expect("revoke anchor");

        carry_held_revocations(&memory, &mut disk, &identity);
        assert_eq!(disk.crl(anchor.host_id()).map(|c| c.seq), Some(2));
        assert_eq!(disk.crl(identity.host_id()).map(|c| c.seq), Some(1));
        assert_eq!(
            disk.get(peer.host_id()).map(|e| e.state),
            Some(PeerState::Revoked)
        );
    }

    #[test]
    fn operator_iroh_hint_dialers_honour_pkarr_flags() {
        let args = P2pTransportArgs {
            p2p_local: false,
            p2p_relay: Vec::new(),
            p2p_relay_token_file: None,
            p2p_api_secret_file: None,
            p2p_pkarr: false,
            no_pkarr: false,
            p2p_no_port_mapping: false,
            p2p_bind: Vec::new(),
        };
        let ep_id: String = SigningKeypair::generate()
            .expect("gen signing key")
            .ed25519_public_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let endpoint = format!("iroh://{ep_id}");
        let resolves = |args: &P2pTransportArgs| {
            build_hint_dialers(RelayClientAuth::None, None, args, Some(&endpoint))
                .expect("dialers")
                .operator_p2p_options(&endpoint)
                .expect("options")
                .resolve_pkarr
        };
        assert!(resolves(&args), "default relays look up");
        assert!(
            !resolves(&P2pTransportArgs {
                no_pkarr: true,
                ..args.clone()
            }),
            "--no-pkarr turns lookup off in default relay mode"
        );
        let custom = P2pTransportArgs {
            p2p_relay: vec!["https://relay.example".to_owned()],
            ..args
        };
        assert!(!resolves(&custom), "custom relays do not look up");
        assert!(
            resolves(&P2pTransportArgs {
                p2p_pkarr: true,
                ..custom
            }),
            "--p2p-pkarr opts in on custom relays"
        );
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
            p2p_no_port_mapping: false,
            p2p_bind: Vec::new(),
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
        let bound = sync_v2_relay_listeners_with_profile(
            &router,
            &v2_relay_url,
            Some("localhost"),
            &RelayClientAuth::None,
            &roster,
            &mut active,
            PowerProfile::Standard,
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
