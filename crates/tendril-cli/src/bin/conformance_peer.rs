//! Line-delimited JSON stdin/stdout conformance peer driving `tendril-runtime`.

use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tendril_core::PREAMBLE_LEN;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, b64url_decode,
    b64url_decode_array, b64url_encode, random_bytes,
};
use tendril_core::grants::{Grant, canonical_json};
use tendril_core::identity::{EndpointIdentity, SigningKeyPin};
use tendril_core::pairing::{
    EnrollmentPolicy, PairAction, PairOutcome, PairingCodeKind, PairingConfig, PairingInitiator,
    PairingManager, PairingPathKind, PinnedHost,
    mint_enrollment_token as core_mint_enrollment_token,
};
use tendril_core::policy::ProviderId;
use tendril_core::relay_auth::{RelayAuthRole, RelayAuthSecret, RelayTicket};
use tendril_core::roster::{AnchorState, Roster};
use tendril_core::v2::{
    V2PairOutcome, V2PinnedHost, canonical_relay_host, derive_epoch_mailbox_window,
};
use tendril_core::wire::{FLAG_PAKE_PAIR, Intent, Preamble, WIRE_VERSION, WIRE_VERSION_V2};
use tendril_runtime::{
    BrokerDialer, DEFAULT_PRE_AUTH_TIMEOUT, DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener,
    HttpWakeProvider, LocalDialer, MAX_OUTER_FRAME_LEN, OverlayDialer, P2pDialer, P2pOptions,
    P2pRelayAuth, P2pRelayMode, PathDialer, PathListener, PathStream, PrefixedPathStream,
    RelayClientAuth, RelayDialer, RelayListener, RelayV2Dialer, RelayV2Listener,
    RelayV2ListenerConfig, SessionDriver, SessionEvent, StateStore, V2ResponderState,
    V2SessionDriver, WakeAdapterKind, WakeDialOptions, WakeSecret, WakeTarget,
    drive_pair_responder_with_policy, drive_v2_pake_pair_initiator, drive_v2_pake_pair_responder,
    parse_p2p_relay_mode, parse_p2p_relay_modes, peek_exact, pinned_pairing_floor,
    wake_and_connect_v2_session,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct TransportConfigInput {
    relay_auth_secret: Option<String>,
    #[zeroize(skip)]
    relay_ticket: Option<RelayTicket>,
    #[zeroize(skip)]
    p2p_relay_mode: Option<String>,
    #[zeroize(skip)]
    p2p_relay_urls: Option<Vec<String>>,
    #[zeroize(skip)]
    p2p_pkarr: Option<bool>,
    #[zeroize(skip)]
    p2p_advertise_direct_addrs: Option<bool>,
    #[zeroize(skip)]
    p2p_allow_private_addrs: Option<bool>,
    p2p_relay_auth_token: Option<String>,
    p2p_api_secret: Option<String>,
    #[zeroize(skip)]
    wake_url: Option<String>,
    #[zeroize(skip)]
    wake_adapter: Option<WakeAdapterKind>,
    wake_secret_b64: Option<String>,
    wake_auth_token: Option<String>,
    #[zeroize(skip)]
    wake_pre_wake: Option<bool>,
    #[zeroize(skip)]
    wake_retry_delay_ms: Option<u64>,
    #[zeroize(skip)]
    wake_max_attempts: Option<usize>,
    #[zeroize(skip)]
    wake_timeout_ms: Option<u64>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct WakeConfig {
    #[zeroize(skip)]
    target: WakeTarget,
    #[zeroize(skip)]
    secret: WakeSecret,
    pre_wake: bool,
    retry_delay_ms: u64,
    max_attempts: usize,
    timeout_ms: u64,
}

#[derive(Clone, Default)]
struct PeerTransportConfig {
    relay_auth: RelayClientAuth,
    p2p_relay_mode: Option<P2pRelayMode>,
    p2p_pkarr: Option<bool>,
    p2p_allow_private_addrs: Option<bool>,
    p2p_relay_auth: Option<P2pRelayAuth>,
    wake: Option<WakeConfig>,
}

impl PeerTransportConfig {
    fn from_input(mut input: TransportConfigInput) -> Result<Self, String> {
        if input.relay_auth_secret.is_some() && input.relay_ticket.is_some() {
            return Err("relay_auth_secret and relay_ticket are mutually exclusive".to_owned());
        }
        if input.p2p_relay_auth_token.is_some() && input.p2p_api_secret.is_some() {
            return Err(
                "p2p_relay_auth_token and p2p_api_secret are mutually exclusive".to_owned(),
            );
        }
        if input.p2p_relay_mode.is_some() && input.p2p_relay_urls.is_some() {
            return Err("p2p_relay_mode and p2p_relay_urls are mutually exclusive".to_owned());
        }

        let relay_auth = if let Some(sec) = input.relay_auth_secret.take().map(Zeroizing::new) {
            let trimmed = sec.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
                return Err("invalid relay_auth_secret".to_owned());
            }
            let parsed = RelayAuthSecret::from_bytes(trimmed.as_bytes())
                .map_err(|_| "invalid relay_auth_secret".to_owned())?;
            RelayClientAuth::HmacSecret(parsed)
        } else if let Some(ticket) = input.relay_ticket.take() {
            canonical_relay_host(&ticket.relay_host).map_err(|e| e.to_string())?;
            if ticket.issuer_pub.is_empty() || ticket.target_pub.is_empty() || ticket.sig.is_empty()
            {
                return Err("relay_ticket has empty required fields".to_owned());
            }
            RelayClientAuth::Ticket(ticket)
        } else {
            RelayClientAuth::None
        };

        let p2p_relay_mode = if let Some(ref mode) = input.p2p_relay_mode {
            Some(parse_p2p_relay_mode(Some(mode)).map_err(|e| e.to_string())?)
        } else if let Some(ref urls) = input.p2p_relay_urls {
            Some(parse_p2p_relay_modes(urls).map_err(|e| e.to_string())?)
        } else {
            None
        };

        let p2p_relay_auth =
            if let Some(tok) = input.p2p_relay_auth_token.take().map(Zeroizing::new) {
                if tok.is_empty() || tok.chars().any(char::is_control) {
                    return Err("invalid p2p_relay_auth_token".to_owned());
                }
                Some(P2pRelayAuth::BearerToken(tok))
            } else if let Some(sec) = input.p2p_api_secret.take().map(Zeroizing::new) {
                #[cfg(feature = "p2p-iroh-services")]
                {
                    if sec.is_empty() || sec.chars().any(char::is_control) {
                        return Err("invalid p2p_api_secret".to_owned());
                    }
                    Some(P2pRelayAuth::IrohServicesSecret(sec))
                }
                #[cfg(not(feature = "p2p-iroh-services"))]
                {
                    let _ = sec;
                    return Err(
                        "p2p_api_secret requires tendril-cli built with p2p-iroh-services feature"
                            .to_owned(),
                    );
                }
            } else {
                None
            };

        if p2p_relay_auth.is_some() && matches!(p2p_relay_mode, Some(P2pRelayMode::Disabled)) {
            return Err("p2p relay auth is invalid when p2p_relay_mode is disabled".to_owned());
        }

        let wake = if let Some(url) = input.wake_url.take() {
            let adapter = input.wake_adapter.unwrap_or(WakeAdapterKind::Webhook);
            let mut target = WakeTarget::new(adapter, &url).map_err(|e| e.to_string())?;
            if let Some(tok) = input.wake_auth_token.take().map(Zeroizing::new) {
                target = target
                    .with_auth_token(tok.as_str())
                    .map_err(|_| "invalid wake_auth_token".to_owned())?;
            }
            let secret_b64 = input
                .wake_secret_b64
                .take()
                .map(Zeroizing::new)
                .ok_or_else(|| "wake_secret_b64 is required when wake_url is set".to_owned())?;
            let secret_bytes = Zeroizing::new(
                b64url_decode_array::<32>(secret_b64.trim())
                    .map_err(|_| "invalid wake_secret_b64".to_owned())?,
            );
            Some(WakeConfig {
                target,
                secret: WakeSecret::from_bytes(*secret_bytes),
                pre_wake: input.wake_pre_wake.unwrap_or(false),
                retry_delay_ms: input.wake_retry_delay_ms.unwrap_or(100),
                max_attempts: input.wake_max_attempts.unwrap_or(10).max(1),
                timeout_ms: input.wake_timeout_ms.unwrap_or(3_000),
            })
        } else if input.wake_adapter.is_some()
            || input.wake_secret_b64.is_some()
            || input.wake_auth_token.is_some()
            || input.wake_pre_wake.is_some()
            || input.wake_retry_delay_ms.is_some()
            || input.wake_max_attempts.is_some()
            || input.wake_timeout_ms.is_some()
        {
            return Err("wake_* options require wake_url".to_owned());
        } else {
            None
        };

        let _ = input.p2p_advertise_direct_addrs;
        Ok(Self {
            relay_auth,
            p2p_relay_mode,
            p2p_pkarr: input.p2p_pkarr,
            p2p_allow_private_addrs: input.p2p_allow_private_addrs,
            p2p_relay_auth,
            wake,
        })
    }

    fn build_p2p_dialer_options(&self, relay_host: Option<&str>) -> Result<P2pOptions, String> {
        let mode = if let Some(ref m) = self.p2p_relay_mode {
            m.clone()
        } else if let Some(spec) = relay_host.map(str::trim).filter(|s| !s.is_empty()) {
            parse_p2p_relay_mode(Some(spec)).map_err(|e| e.to_string())?
        } else if std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1") {
            P2pRelayMode::Disabled
        } else {
            P2pRelayMode::Default
        };
        let mut opts = P2pOptions::for_dialer(mode)
            .with_resolve_pkarr(self.p2p_pkarr.unwrap_or(false))
            .with_relay_auth(self.p2p_relay_auth.clone());
        if let Some(allow_priv) = self.p2p_allow_private_addrs {
            opts = opts.with_allow_private_addrs(allow_priv);
        } else if matches!(opts.relay_mode, P2pRelayMode::Disabled) {
            opts = opts.with_allow_private_addrs(true);
        }
        Ok(opts)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedHostInput {
    host_id: Option<String>,
    #[serde(alias = "static_pub")]
    static_pub_b64: String,
    #[serde(alias = "signing_pub", alias = "signing_pin")]
    signing_pin_b64: String,
    #[serde(default)]
    rotation_seq: u64,
    #[serde(default)]
    min_wire_version: Option<u8>,
}

fn parse_signing_pin(encoded: &str) -> Result<SigningKeyPin, String> {
    let bytes = b64url_decode(encoded).map_err(|e| e.to_string())?;
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        HybridSigningPublicKey::from_bytes(&bytes)
            .map(SigningKeyPin::Full)
            .map_err(|e| e.to_string())
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let hash: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "invalid signing key hash length".to_owned())?;
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(format!("invalid signing pin length {}", bytes.len()))
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum PeerCmd {
    Init {
        state_dir: Option<PathBuf>,
        host_id: Option<String>,
    },
    ConfigureTransports {
        config: Option<serde_json::Value>,
        #[serde(flatten)]
        flat: serde_json::Map<String, serde_json::Value>,
    },
    MintRelayTicket {
        relay_host: String,
        role: Option<String>,
        target_pub: Option<String>,
        ttl_secs: Option<u64>,
    },
    ServeDirect {
        listen: Option<SocketAddr>,
    },
    ServeRelay {
        relay_url: String,
        expected_host: Option<String>,
    },
    ServeRelayV2 {
        relay_url: String,
        expected_host: Option<String>,
        peer_id: Option<String>,
    },
    IssueCode {
        kind: Option<String>,
    },
    AddTrustAnchor {
        anchor_id: String,
        signing_pub: String,
    },
    RevokeTrustAnchor {
        anchor_id: String,
    },
    MintEnrollmentToken {
        target_host_id: String,
        subject: Option<String>,
        ttl_secs: Option<u64>,
    },
    Pair {
        endpoint: Option<String>,
        relay_host: Option<String>,
        code: Option<String>,
        name: Option<String>,
        kind: Option<String>,
    },
    PairV2Initiate {
        endpoint: String,
        relay_host: Option<String>,
        code: String,
        name: Option<String>,
        kind: Option<String>,
        pinned_host: Option<PinnedHostInput>,
    },
    PairV2Accept {
        timeout_ms: Option<u64>,
    },
    Confirm {
        peer_id: String,
        sas: Option<String>,
    },
    Mint {
        peer_id: String,
        caps: Vec<String>,
        ttl_secs: Option<u64>,
    },
    Connect {
        endpoint: Option<String>,
        relay_host: Option<String>,
        target_host_id: Option<String>,
        grant: Option<Grant>,
    },
    ConnectV2 {
        endpoint: String,
        relay_host: Option<String>,
        target_host_id: String,
        grant: Option<Grant>,
    },
    AcceptV2 {
        timeout_ms: Option<u64>,
    },
    Send {
        data_b64: Option<String>,
        data_utf8: Option<String>,
    },
    Recv {
        timeout_ms: Option<u64>,
    },
    Authorize {
        cap: String,
    },
    Rekey,
    Revoke {
        peer_id: String,
    },
    Close {
        code: Option<u16>,
        reason: Option<String>,
    },
    Shutdown,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

enum SessionBackend {
    V1(SessionDriver),
    V2(V2SessionDriver),
}

impl SessionBackend {
    async fn send_data(&mut self, payload: &[u8]) -> Result<(), String> {
        match self {
            Self::V1(s) => s.send_data(payload).await.map_err(|e| e.to_string()),
            Self::V2(s) => s.send_data(payload).await.map_err(|e| e.to_string()),
        }
    }

    async fn next_event_now(
        &mut self,
        roster: &mut Roster,
    ) -> Result<Option<SessionEvent>, String> {
        match self {
            Self::V1(s) => s.next_event_now(roster).await.map_err(|e| e.to_string()),
            Self::V2(s) => s.next_event_now(roster).await.map_err(|e| e.to_string()),
        }
    }

    fn authorize(
        &self,
        cap: &str,
        now_unix: u64,
        roster: &Roster,
    ) -> (
        Result<(), tendril_core::error::CoreError>,
        tendril_core::grants::AuditEvent,
    ) {
        match self {
            Self::V1(s) => s.authorize(cap, now_unix, roster),
            Self::V2(s) => s.authorize(cap, now_unix, roster),
        }
    }

    async fn send_rekey(&mut self) -> Result<(), String> {
        match self {
            Self::V1(s) => s.send_rekey().await.map_err(|e| e.to_string()),
            Self::V2(s) => s.send_rekey().await.map_err(|e| e.to_string()),
        }
    }

    async fn send_close(&mut self, code: u16, reason: &str) -> Result<(), String> {
        match self {
            Self::V1(s) => s.send_close(code, reason).await.map_err(|e| e.to_string()),
            Self::V2(s) => s.send_close(code, reason).await.map_err(|e| e.to_string()),
        }
    }
}

struct PeerState {
    store: Option<StateStore>,
    identity: Option<EndpointIdentity>,
    roster: Roster,
    pair_mgr: PairingManager,
    v2_state: Arc<V2ResponderState>,
    transport_cfg: PeerTransportConfig,
    self_m2m_enabled: bool,
    accepted_tx: mpsc::Sender<Box<dyn PathStream>>,
    accepted_rx: mpsc::Receiver<Box<dyn PathStream>>,
    listener_tasks: Vec<JoinHandle<()>>,
    session: Option<SessionBackend>,
}

impl PeerState {
    fn new() -> Self {
        let (accepted_tx, accepted_rx) = mpsc::channel(32);
        Self {
            store: None,
            identity: None,
            roster: Roster::new(),
            pair_mgr: PairingManager::new(PairingConfig::default()),
            v2_state: Arc::new(V2ResponderState::new()),
            transport_cfg: PeerTransportConfig::default(),
            self_m2m_enabled: false,
            accepted_tx,
            accepted_rx,
            listener_tasks: Vec::new(),
            session: None,
        }
    }

    fn persist_roster(&self) -> Result<(), String> {
        if let Some(store) = &self.store {
            store.save_roster(&self.roster).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn spawn_listener(&self, mut listener: Box<dyn PathListener>) -> JoinHandle<()> {
        let tx = self.accepted_tx.clone();
        tokio::spawn(async move {
            while let Ok(stream) = listener.accept().await {
                if tx.send(stream).await.is_err() {
                    break;
                }
            }
        })
    }

    fn shutdown_listeners(&mut self) {
        for handle in self.listener_tasks.drain(..) {
            handle.abort();
        }
    }
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

fn lookup_v2_mailbox_secret_for_target(
    roster: &Roster,
    target_host_id: &str,
) -> Result<[u8; 32], String> {
    let entry = roster
        .get(target_host_id)
        .ok_or_else(|| format!("target '{target_host_id}' not found in roster"))?;
    if entry.state == PeerStateEnum::Revoked {
        return Err(format!("target '{target_host_id}' is revoked"));
    }
    entry
        .v2_secrets
        .as_ref()
        .map(|s| *s.mailbox_secret())
        .ok_or_else(|| format!("target '{target_host_id}' has no v2 mailbox_secret"))
}

use tendril_core::roster::PeerState as PeerStateEnum;

fn lookup_v2_mailbox_secret_for_pair(
    roster: &Roster,
    pinned: Option<&PinnedHost>,
    endpoint: &str,
    now_unix: u64,
) -> Result<[u8; 32], String> {
    if let Some(pin) = pinned {
        if let Some(ref hid) = pin.host_id
            && let Some(entry) = roster.get(hid)
            && entry.state != PeerStateEnum::Revoked
            && let Some(ref secrets) = entry.v2_secrets
        {
            return Ok(*secrets.mailbox_secret());
        }
        for (_, entry) in roster.entries() {
            if entry.state != PeerStateEnum::Revoked
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
            if entry.state != PeerStateEnum::Revoked
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
    Err("no matching v2 mailbox_secret in roster for /v2/relay endpoint".to_owned())
}

async fn dial_endpoint_with_cfg(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &PeerTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathStream>, String> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        let opts = cfg.build_p2p_dialer_options(normalized_host)?;
        let dialer = P2pDialer::bind_with_options(opts)
            .await
            .map_err(|e| e.to_string())?;
        return match dialer.dial(endpoint).await {
            Ok(stream) => Ok(stream),
            Err(err) => {
                dialer.close().await;
                Err(err.to_string())
            }
        };
    }
    if endpoint.starts_with("overlay://") {
        return OverlayDialer::new()
            .dial(endpoint)
            .await
            .map_err(|e| e.to_string());
    }
    if endpoint.starts_with("broker+ws://") || endpoint.starts_with("broker+wss://") {
        return BrokerDialer::new()
            .dial(endpoint)
            .await
            .map_err(|e| e.to_string());
    }
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        if let Some(secret) = v2_mailbox_secret {
            let mut dialer = RelayV2Dialer::new(secret).with_auth(cfg.relay_auth.clone());
            if let Some(host) = normalized_host {
                dialer = dialer.with_expected_host(host);
            }
            return dialer.dial(endpoint).await.map_err(|e| e.to_string());
        }
        let mut dialer = RelayDialer::new().with_auth(cfg.relay_auth.clone());
        if let Some(host) = normalized_host {
            dialer = dialer.with_expected_host(host);
        }
        return dialer.dial(endpoint).await.map_err(|e| e.to_string());
    }
    if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        return LocalDialer::new()
            .dial(endpoint)
            .await
            .map_err(|e| e.to_string());
    }
    DirectDialer::new()
        .dial(endpoint)
        .await
        .map_err(|e| e.to_string())
}

async fn build_dialer_with_cfg(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &PeerTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathDialer>, String> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        let opts = cfg.build_p2p_dialer_options(normalized_host)?;
        return Ok(Box::new(
            P2pDialer::bind_with_options(opts)
                .await
                .map_err(|e| e.to_string())?,
        ));
    }
    if endpoint.starts_with("overlay://") {
        return Ok(Box::new(OverlayDialer::new()));
    }
    if endpoint.starts_with("broker+ws://") || endpoint.starts_with("broker+wss://") {
        return Ok(Box::new(BrokerDialer::new()));
    }
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        if let Some(secret) = v2_mailbox_secret {
            let mut dialer = RelayV2Dialer::new(secret).with_auth(cfg.relay_auth.clone());
            if let Some(host) = normalized_host {
                dialer = dialer.with_expected_host(host);
            }
            return Ok(Box::new(dialer));
        }
        let mut dialer = RelayDialer::new().with_auth(cfg.relay_auth.clone());
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

async fn drive_v1_pair_initiator_with_roster(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    roster: &Roster,
) -> Result<(PairOutcome, Option<String>), String> {
    let mut machine = PairingInitiator::new_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        code,
        None,
        WIRE_VERSION,
        None,
    )
    .map_err(|e| e.to_string())?
    .with_roster_floors(roster);
    let mut observed_sas = None;
    let init_actions = machine.start().map_err(|e| e.to_string())?;
    let mut should_close = false;
    for action in init_actions {
        match action {
            PairAction::WriteBytes(bytes) => {
                for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
                    stream.send_chunk(chunk).await.map_err(|e| e.to_string())?;
                }
            }
            PairAction::SasReady { pairing_sas, .. } => {
                observed_sas = Some(pairing_sas);
            }
            PairAction::Completed(outcome) => return Ok((outcome, observed_sas)),
            PairAction::CloseTransport(_) => {
                should_close = true;
            }
        }
    }
    if should_close {
        let _ = stream.close().await;
    }
    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
    loop {
        let n = timeout(DEFAULT_PRE_AUTH_TIMEOUT, stream.recv_chunk(&mut buf))
            .await
            .map_err(|_| "pairing handshake timed out".to_owned())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("pairing transport closed".to_owned());
        }
        let actions = machine.feed_bytes(&buf[..n]).map_err(|e| e.to_string())?;
        let mut completed = None;
        let mut close_now = false;
        for action in actions {
            match action {
                PairAction::WriteBytes(bytes) => {
                    for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
                        stream.send_chunk(chunk).await.map_err(|e| e.to_string())?;
                    }
                }
                PairAction::SasReady { pairing_sas, .. } => {
                    observed_sas = Some(pairing_sas);
                }
                PairAction::Completed(outcome) => completed = Some(outcome),
                PairAction::CloseTransport(_) => close_now = true,
            }
        }
        if close_now {
            let _ = stream.close().await;
        }
        if let Some(outcome) = completed {
            return Ok((outcome, observed_sas));
        }
    }
}

fn ok_json<T: Serialize>(v: T) -> serde_json::Value {
    serde_json::to_value(v)
        .unwrap_or_else(|e| serde_json::json!({ "ok": false, "error": e.to_string() }))
}

fn err_json(msg: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "ok": false, "error": msg.into() })
}

async fn dispatch_cmd(state: &mut PeerState, cmd: PeerCmd) -> (serde_json::Value, bool) {
    match cmd {
        PeerCmd::Init { state_dir, host_id } => {
            let identity_res = if let Some(dir) = state_dir {
                match StateStore::open_or_create(&dir) {
                    Ok(store) => {
                        let id = store.load_or_generate_identity(host_id.as_deref());
                        match id {
                            Ok(id) => {
                                state.roster = store.load_roster().unwrap_or_default();
                                state.store = Some(store);
                                Ok(id)
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            } else {
                EndpointIdentity::generate()
                    .map(|id| match host_id {
                        Some(h) if !h.is_empty() => id.with_host_id(h),
                        _ => id,
                    })
                    .map_err(|e| e.to_string())
            };
            match identity_res {
                Ok(id) => {
                    let resp = serde_json::json!({
                        "ok": true,
                        "host_id": id.host_id(),
                        "device_id": id.device_id(),
                        "static_pub": b64url_encode(id.static_key().public_bytes()),
                        "signing_pub": id.signing_key().public_key().to_b64url(),
                        "signing_pub_hash": b64url_encode(&id.signing_key().signing_pub_hash()),
                        "relay_pub": b64url_encode(id.signing_key().ed25519_public_bytes()),
                    });
                    state.identity = Some(id);
                    (resp, false)
                }
                Err(e) => (err_json(e), false),
            }
        }
        PeerCmd::ConfigureTransports { config, flat } => {
            let input_res: Result<TransportConfigInput, serde_json::Error> =
                if let Some(cfg_val) = config {
                    if !flat.is_empty() {
                        return (
                            err_json("configure_transports cannot mix 'config' with flat fields"),
                            false,
                        );
                    }
                    serde_json::from_value(cfg_val)
                } else {
                    serde_json::from_value(serde_json::Value::Object(flat))
                };
            let input = match input_res {
                Ok(v) => v,
                Err(e) => return (err_json(format!("invalid transport config: {e}")), false),
            };
            match PeerTransportConfig::from_input(input) {
                Ok(cfg) => {
                    state.transport_cfg = cfg;
                    (serde_json::json!({ "ok": true }), false)
                }
                Err(e) => (err_json(e), false),
            }
        }
        PeerCmd::MintRelayTicket {
            relay_host,
            role,
            target_pub,
            ttl_secs,
        } => {
            let Some(id) = state.identity.as_ref() else {
                return (err_json("init required before mint_relay_ticket"), false);
            };
            let role_enum = match role.as_deref() {
                None | Some("" | "any") => RelayAuthRole::Any,
                Some("register") => RelayAuthRole::Register,
                Some("dial") => RelayAuthRole::Dial,
                Some(other) => return (err_json(format!("invalid relay role '{other}'")), false),
            };
            let target = target_pub
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("*");
            let ticket = match id.mint_relay_ticket(
                &relay_host,
                role_enum,
                target,
                now_unix(),
                ttl_secs.unwrap_or(3600),
            ) {
                Ok(t) => t,
                Err(e) => return (err_json(e.to_string()), false),
            };
            let ticket_json = match canonical_json(&ticket) {
                Ok(j) => Zeroizing::new(j),
                Err(e) => return (err_json(e.to_string()), false),
            };
            (
                serde_json::json!({
                    "ok": true,
                    "ticket": ok_json(ticket),
                    "ticket_json": *ticket_json,
                }),
                false,
            )
        }
        PeerCmd::ServeDirect { listen } => {
            let addr = listen.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
            match DirectListener::bind(addr, None).await {
                Ok(listener) => {
                    let ep = listener.local_endpoint();
                    let task = state.spawn_listener(Box::new(listener));
                    state.listener_tasks.push(task);
                    (serde_json::json!({ "ok": true, "endpoint": ep }), false)
                }
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::ServeRelay {
            relay_url,
            expected_host,
        } => {
            let Some(id) = state.identity.as_ref() else {
                return (err_json("init required before serve_relay"), false);
            };
            match RelayListener::bind_with_auth(
                relay_url,
                expected_host,
                id.signing_key().ed25519_signing_key(),
                DEFAULT_WRITE_TIMEOUT,
                state.transport_cfg.relay_auth.clone(),
            )
            .await
            {
                Ok(listener) => {
                    let ep = listener.local_endpoint();
                    let task = state.spawn_listener(Box::new(listener));
                    state.listener_tasks.push(task);
                    (serde_json::json!({ "ok": true, "endpoint": ep }), false)
                }
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::ServeRelayV2 {
            relay_url,
            expected_host,
            peer_id,
        } => {
            let Some(_) = state.identity.as_ref() else {
                return (err_json("init required before serve_relay_v2"), false);
            };
            let secrets: Vec<[u8; 32]> = if let Some(ref pid) = peer_id.filter(|s| !s.is_empty()) {
                match lookup_v2_mailbox_secret_for_target(&state.roster, pid) {
                    Ok(sec) => vec![sec],
                    Err(e) => return (err_json(e), false),
                }
            } else {
                let list: Vec<[u8; 32]> = state
                    .roster
                    .entries()
                    .filter(|(_, e)| e.state != PeerStateEnum::Revoked)
                    .filter_map(|(_, e)| e.v2_secrets.as_ref().map(|s| *s.mailbox_secret()))
                    .collect();
                if list.is_empty() {
                    return (
                        err_json("no paired v2 peers with mailbox_secret in roster"),
                        false,
                    );
                }
                list
            };
            let mut first_ep = None;
            for secret in secrets {
                let cfg = RelayV2ListenerConfig {
                    expected_host: expected_host.clone(),
                    write_timeout: DEFAULT_WRITE_TIMEOUT,
                    allow_insecure_ws: false,
                    replay_cache: None,
                    unix_secs: None,
                    auth: state.transport_cfg.relay_auth.clone(),
                };
                match RelayV2Listener::bind_with_config(relay_url.clone(), secret, cfg).await {
                    Ok(listener) => {
                        if first_ep.is_none() {
                            first_ep = Some(listener.local_endpoint());
                        }
                        let task = state.spawn_listener(Box::new(listener));
                        state.listener_tasks.push(task);
                    }
                    Err(e) => return (err_json(e.to_string()), false),
                }
            }
            (
                serde_json::json!({ "ok": true, "endpoint": first_ep }),
                false,
            )
        }
        PeerCmd::IssueCode { kind } => {
            let pk = match kind.as_deref() {
                Some("remote") => PairingCodeKind::Remote3Group,
                _ => PairingCodeKind::Lan2Group,
            };
            match state.pair_mgr.issue_code(pk, now_unix()) {
                Ok(code) => (serde_json::json!({ "ok": true, "code": code }), false),
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::AddTrustAnchor {
            anchor_id,
            signing_pub,
        } => {
            let signing_key = match HybridSigningPublicKey::from_b64url(&signing_pub) {
                Ok(k) => k,
                Err(e) => return (err_json(e.to_string()), false),
            };
            if let Err(e) = state.roster.add_trust_anchor(anchor_id, signing_key) {
                return (err_json(e.to_string()), false);
            }
            if let Err(e) = state.persist_roster() {
                return (err_json(e), false);
            }
            (serde_json::json!({ "ok": true }), false)
        }
        PeerCmd::RevokeTrustAnchor { anchor_id } => {
            if let Err(e) = state.roster.revoke_trust_anchor(&anchor_id) {
                return (err_json(e.to_string()), false);
            }
            if let Err(e) = state.persist_roster() {
                return (err_json(e), false);
            }
            (serde_json::json!({ "ok": true }), false)
        }
        PeerCmd::MintEnrollmentToken {
            target_host_id,
            subject,
            ttl_secs,
        } => {
            let Some(id) = state.identity.as_ref() else {
                return (
                    err_json("init required before mint_enrollment_token"),
                    false,
                );
            };
            let nonce = match random_bytes::<16>() {
                Ok(n) => n,
                Err(e) => return (err_json(e.to_string()), false),
            };
            let token = match core_mint_enrollment_token(
                id,
                &target_host_id,
                subject.as_deref(),
                now_unix(),
                ttl_secs.unwrap_or(900),
                nonce,
            ) {
                Ok(t) => t,
                Err(e) => return (err_json(e.to_string()), false),
            };
            if target_host_id == id.host_id() {
                state.self_m2m_enabled = true;
            }
            let json = Zeroizing::new(serde_json::to_string(&token).expect("serialize token"));
            (
                serde_json::json!({ "ok": true, "token_json": *json }),
                false,
            )
        }
        PeerCmd::Pair {
            endpoint,
            relay_host,
            code,
            name,
            kind,
        } => {
            let Some(id) = state.identity.clone() else {
                return (err_json("init required before pair"), false);
            };
            if let Some(ep) = endpoint {
                let Some(code_str) = code else {
                    return (err_json("initiator pair requires 'code'"), false);
                };
                let v2_sec = if is_v2_relay_endpoint(&ep) {
                    match lookup_v2_mailbox_secret_for_pair(&state.roster, None, &ep, now_unix()) {
                        Ok(s) => Some(s),
                        Err(e) => return (err_json(e), false),
                    }
                } else {
                    None
                };
                let mut stream = match dial_endpoint_with_cfg(
                    &ep,
                    relay_host.as_deref(),
                    &state.transport_cfg,
                    v2_sec,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => return (err_json(e), false),
                };
                let res = drive_v1_pair_initiator_with_roster(
                    stream.as_mut(),
                    &id,
                    name.unwrap_or_else(|| "peer-client".to_owned()),
                    kind.unwrap_or_else(|| "cli".to_owned()),
                    code_str,
                    &state.roster,
                )
                .await;
                let _ = stream.close().await;
                match res {
                    Ok((outcome, _)) => match outcome {
                        PairOutcome::InitiatorPending {
                            device_id,
                            host_id,
                            host_static_pub,
                            host_signing_pub,
                            host_rotation_seq,
                            pairing_sas,
                            host_pin_verified,
                        } => {
                            let pin_res = if host_pin_verified {
                                state.roster.insert_pinned_host(
                                    host_id.clone(),
                                    host_id.clone(),
                                    host_static_pub,
                                    Some(host_signing_pub),
                                    host_rotation_seq,
                                    Vec::new(),
                                )
                            } else {
                                state.roster.record_pending_host(
                                    host_id.clone(),
                                    host_id.clone(),
                                    host_static_pub,
                                    host_signing_pub,
                                    host_rotation_seq,
                                    pairing_sas.clone(),
                                    Vec::new(),
                                )
                            };
                            if let Err(e) = pin_res {
                                return (err_json(e.to_string()), false);
                            }
                            if let Err(e) = state.persist_roster() {
                                return (err_json(e), false);
                            }
                            (
                                serde_json::json!({
                                    "ok": true,
                                    "role": "initiator",
                                    "device_id": device_id,
                                    "host_id": host_id,
                                    "sas": pairing_sas,
                                    "host_confirmed": host_pin_verified,
                                }),
                                false,
                            )
                        }
                        PairOutcome::Rejected { error } => (err_json(error), false),
                        PairOutcome::ResponderPending { .. }
                        | PairOutcome::ResponderEnrolled { .. } => {
                            (err_json("unexpected responder outcome"), false)
                        }
                        PairOutcome::InitiatorEnrolled { .. } => {
                            (err_json("unexpected m2m enrollment outcome"), false)
                        }
                    },
                    Err(e) => (err_json(e), false),
                }
            } else {
                let Ok(Some(mut stream)) =
                    timeout(Duration::from_secs(10), state.accepted_rx.recv()).await
                else {
                    return (err_json("timed out accepting pairing connection"), false);
                };
                let Ok(Ok(peeked)) = timeout(
                    Duration::from_secs(10),
                    peek_exact(stream.as_mut(), PREAMBLE_LEN),
                )
                .await
                else {
                    return (err_json("timed out reading pairing preamble"), false);
                };
                if let Err(e) = Preamble::decode(&peeked[..PREAMBLE_LEN])
                    .map_err(|e| e.to_string())
                    .and_then(|p| {
                        (p.intent == Intent::Pair)
                            .then_some(())
                            .ok_or_else(|| "expected pair preamble".to_owned())
                    })
                {
                    return (err_json(e), false);
                }
                let mut wrapped = PrefixedPathStream::new(stream, peeked);
                let path_kind = if wrapped.provider_id() == ProviderId::Relay {
                    PairingPathKind::Remote
                } else {
                    PairingPathKind::Lan
                };
                let policy = if state.self_m2m_enabled
                    || state
                        .roster
                        .trust_anchors()
                        .any(|(_, a)| a.state == AnchorState::Active)
                {
                    EnrollmentPolicy::enabled_default()
                } else {
                    EnrollmentPolicy::default()
                };
                let mgr_lock = StdMutex::new(std::mem::replace(
                    &mut state.pair_mgr,
                    PairingManager::new(PairingConfig::default()),
                ));
                let roster_lock = StdMutex::new(std::mem::take(&mut state.roster));
                let pair_res = drive_pair_responder_with_policy(
                    &mut wrapped,
                    &id,
                    &mgr_lock,
                    &roster_lock,
                    path_kind,
                    now_unix(),
                    policy,
                    None,
                    None,
                    tendril_runtime::DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await;
                state.pair_mgr = mgr_lock.into_inner().expect("lock");
                state.roster = roster_lock.into_inner().expect("lock");
                match pair_res {
                    Ok(res) => match res.outcome {
                        PairOutcome::ResponderPending {
                            device_id,
                            pairing_sas,
                            name,
                            kind,
                            ..
                        } => {
                            if let Err(e) = state.persist_roster() {
                                return (err_json(e), false);
                            }
                            (
                                serde_json::json!({
                                    "ok": true,
                                    "role": "responder",
                                    "device_id": device_id,
                                    "sas": pairing_sas,
                                    "name": name,
                                    "kind": kind,
                                }),
                                false,
                            )
                        }
                        PairOutcome::ResponderEnrolled {
                            device_id,
                            token_nonce,
                            name,
                            kind,
                            ..
                        } => {
                            if let Err(e) = state.persist_roster() {
                                return (err_json(e), false);
                            }
                            (
                                serde_json::json!({
                                    "ok": true,
                                    "role": "responder",
                                    "status": "active",
                                    "device_id": device_id,
                                    "token_nonce": token_nonce,
                                    "name": name,
                                    "kind": kind,
                                }),
                                false,
                            )
                        }
                        PairOutcome::Rejected { error } => (err_json(error), false),
                        PairOutcome::InitiatorPending { .. }
                        | PairOutcome::InitiatorEnrolled { .. } => {
                            (err_json("unexpected initiator outcome"), false)
                        }
                    },
                    Err(e) => (err_json(e.to_string()), false),
                }
            }
        }
        PeerCmd::PairV2Initiate {
            endpoint,
            relay_host,
            code,
            name,
            kind,
            pinned_host,
        } => {
            let Some(id) = state.identity.clone() else {
                return (err_json("init required before pair_v2_initiate"), false);
            };
            let v2_pinned = match pinned_host {
                Some(pin_in) => {
                    let static_pub = match b64url_decode_array::<32>(&pin_in.static_pub_b64) {
                        Ok(k) => k,
                        Err(e) => return (err_json(e.to_string()), false),
                    };
                    let signing_pin = match parse_signing_pin(&pin_in.signing_pin_b64) {
                        Ok(p) => p,
                        Err(e) => return (err_json(e), false),
                    };
                    let pinned = PinnedHost {
                        host_id: pin_in.host_id,
                        static_pub,
                        signing_pin,
                        rotation_seq: pin_in.rotation_seq,
                    };
                    let base = pinned_pairing_floor(&state.roster, &pinned);
                    let floor = pin_in.min_wire_version.map_or(base, |v| base.max(v));
                    match V2PinnedHost::new(pinned, floor) {
                        Ok(v) => Some(v),
                        Err(e) => return (err_json(e.to_string()), false),
                    }
                }
                None => None,
            };
            let v2_sec = if is_v2_relay_endpoint(&endpoint) {
                match lookup_v2_mailbox_secret_for_pair(
                    &state.roster,
                    v2_pinned.as_ref().map(|p| &p.pinned),
                    &endpoint,
                    now_unix(),
                ) {
                    Ok(s) => Some(s),
                    Err(e) => return (err_json(e), false),
                }
            } else {
                None
            };
            let mut stream = match dial_endpoint_with_cfg(
                &endpoint,
                relay_host.as_deref(),
                &state.transport_cfg,
                v2_sec,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => return (err_json(e), false),
            };
            let res = drive_v2_pake_pair_initiator(
                stream.as_mut(),
                &id,
                name.unwrap_or_else(|| "peer-client".to_owned()),
                kind.unwrap_or_else(|| "cli".to_owned()),
                code,
                v2_pinned,
            )
            .await;
            let _ = stream.close().await;
            match res {
                Ok(res) => match res.outcome {
                    V2PairOutcome::InitiatorPending {
                        ref device_id,
                        ref host_id,
                        ref pairing_sas,
                        host_pin_verified,
                        ..
                    } => {
                        let dev_id = device_id.clone();
                        let h_id = host_id.clone();
                        let sas = pairing_sas.clone();
                        if let Err(e) = state.roster.apply_v2_pair_initiator_outcome(
                            &res.outcome,
                            h_id.clone(),
                            Vec::new(),
                        ) {
                            return (err_json(e.to_string()), false);
                        }
                        if let Err(e) = state.persist_roster() {
                            return (err_json(e), false);
                        }
                        (
                            serde_json::json!({
                                "ok": true,
                                "role": "initiator",
                                "device_id": dev_id,
                                "host_id": h_id,
                                "sas": sas,
                                "host_confirmed": host_pin_verified,
                                "wire_version": 2,
                            }),
                            false,
                        )
                    }
                    V2PairOutcome::Rejected { error } => (err_json(error), false),
                    V2PairOutcome::ResponderPending { .. } => {
                        (err_json("unexpected responder outcome"), false)
                    }
                },
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::PairV2Accept { timeout_ms } => {
            let Some(id) = state.identity.clone() else {
                return (err_json("init required before pair_v2_accept"), false);
            };
            let wait = Duration::from_millis(timeout_ms.unwrap_or(10_000));
            let Ok(Some(mut stream)) = timeout(wait, state.accepted_rx.recv()).await else {
                return (err_json("timed out accepting v2 pairing connection"), false);
            };
            let Ok(Ok(peeked)) = timeout(
                DEFAULT_PRE_AUTH_TIMEOUT,
                peek_exact(stream.as_mut(), PREAMBLE_LEN),
            )
            .await
            else {
                return (err_json("timed out reading v2 pairing preamble"), false);
            };
            if let Err(e) = Preamble::decode(&peeked[..PREAMBLE_LEN])
                .map_err(|e| e.to_string())
                .and_then(|p| {
                    (p.version == WIRE_VERSION_V2
                        && p.intent == Intent::Pair
                        && p.flags == FLAG_PAKE_PAIR)
                        .then_some(())
                        .ok_or_else(|| "expected v2 PAKE pair preamble".to_owned())
                })
            {
                return (err_json(e), false);
            }
            let mut wrapped = PrefixedPathStream::new(stream, peeked);
            let path_kind = if wrapped.provider_id() == ProviderId::Relay {
                PairingPathKind::Remote
            } else {
                PairingPathKind::Lan
            };
            let mgr_arc = Arc::new(StdMutex::new(std::mem::replace(
                &mut state.pair_mgr,
                PairingManager::new(PairingConfig::default()),
            )));
            let roster_lock = StdMutex::new(std::mem::take(&mut state.roster));
            let pair_res = drive_v2_pake_pair_responder(
                &mut wrapped,
                &id,
                &mgr_arc,
                &roster_lock,
                path_kind,
                now_unix(),
                &state.v2_state,
                None,
            )
            .await;
            state.pair_mgr = match Arc::try_unwrap(mgr_arc) {
                Ok(m) => m.into_inner().expect("lock"),
                Err(a) => std::mem::replace(
                    &mut *a.lock().expect("lock"),
                    PairingManager::new(PairingConfig::default()),
                ),
            };
            state.roster = roster_lock.into_inner().expect("lock");
            match pair_res {
                Ok(res) => match res.outcome {
                    V2PairOutcome::ResponderPending {
                        device_id,
                        pairing_sas,
                        name,
                        kind,
                        ..
                    } => {
                        if let Err(e) = state.persist_roster() {
                            return (err_json(e), false);
                        }
                        (
                            serde_json::json!({
                                "ok": true,
                                "role": "responder",
                                "device_id": device_id,
                                "sas": pairing_sas,
                                "name": name,
                                "kind": kind,
                                "wire_version": 2,
                            }),
                            false,
                        )
                    }
                    V2PairOutcome::Rejected { error } => (err_json(error), false),
                    V2PairOutcome::InitiatorPending { .. } => {
                        (err_json("unexpected initiator outcome"), false)
                    }
                },
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::Confirm { peer_id, sas } => {
            if let Err(e) = state.roster.confirm_peer(&peer_id, sas.as_deref()) {
                return (err_json(e.to_string()), false);
            }
            if let Err(e) = state.persist_roster() {
                return (err_json(e), false);
            }
            (serde_json::json!({ "ok": true, "peer_id": peer_id }), false)
        }
        PeerCmd::Mint {
            peer_id,
            caps,
            ttl_secs,
        } => {
            let Some(id) = state.identity.as_ref() else {
                return (err_json("init required before mint"), false);
            };
            let nonce = match random_bytes::<16>() {
                Ok(n) => n,
                Err(e) => return (err_json(e.to_string()), false),
            };
            let now = now_unix();
            match state.roster.mint_grant(
                id,
                &peer_id,
                caps,
                now,
                now.saturating_add(ttl_secs.unwrap_or(3600)),
                nonce,
            ) {
                Ok(grant) => {
                    if let Err(e) = state.persist_roster() {
                        return (err_json(e), false);
                    }
                    (
                        serde_json::json!({ "ok": true, "grant": ok_json(grant) }),
                        false,
                    )
                }
                Err(e) => (err_json(e.to_string()), false),
            }
        }
        PeerCmd::Connect {
            endpoint,
            relay_host,
            target_host_id,
            grant,
        } => {
            let Some(id) = state.identity.clone() else {
                return (err_json("init required before connect"), false);
            };
            let driver_res = if let Some(ep) = endpoint {
                let Some(target) = target_host_id else {
                    return (
                        err_json("initiator connect requires 'target_host_id'"),
                        false,
                    );
                };
                let v2_sec = if is_v2_relay_endpoint(&ep) {
                    match lookup_v2_mailbox_secret_for_target(&state.roster, &target) {
                        Ok(s) => Some(s),
                        Err(e) => return (err_json(e), false),
                    }
                } else {
                    None
                };
                let stream = match dial_endpoint_with_cfg(
                    &ep,
                    relay_host.as_deref(),
                    &state.transport_cfg,
                    v2_sec,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => return (err_json(e), false),
                };
                SessionDriver::connect(stream, &id, &target, grant, &mut state.roster, now_unix())
                    .await
            } else {
                let Ok(Some(stream)) =
                    timeout(Duration::from_secs(10), state.accepted_rx.recv()).await
                else {
                    return (err_json("timed out accepting session connection"), false);
                };
                SessionDriver::accept(stream, &id, &mut state.roster, now_unix(), None).await
            };
            match driver_res {
                Ok(driver) => {
                    let peer_device_id = driver.peer_device_id().map(ToOwned::to_owned);
                    let peer_crl_seq = driver.peer_crl_seq();
                    let provider = format!("{:?}", driver.provider_id());
                    state.session = Some(SessionBackend::V1(driver));
                    let _ = state.persist_roster();
                    (
                        serde_json::json!({
                            "ok": true,
                            "peer_device_id": peer_device_id,
                            "peer_crl_seq": peer_crl_seq,
                            "provider": provider,
                        }),
                        false,
                    )
                }
                Err(e) => {
                    let _ = state.persist_roster();
                    (err_json(e.to_string()), false)
                }
            }
        }
        PeerCmd::ConnectV2 {
            endpoint,
            relay_host,
            target_host_id,
            grant,
        } => {
            let Some(id) = state.identity.clone() else {
                return (err_json("init required before connect_v2"), false);
            };
            let v2_sec = if is_v2_relay_endpoint(&endpoint) {
                match lookup_v2_mailbox_secret_for_target(&state.roster, &target_host_id) {
                    Ok(s) => Some(s),
                    Err(e) => return (err_json(e), false),
                }
            } else {
                None
            };
            let driver_res = if let Some(ref wake_cfg) = state.transport_cfg.wake {
                let dialer = match build_dialer_with_cfg(
                    &endpoint,
                    relay_host.as_deref(),
                    &state.transport_cfg,
                    v2_sec,
                )
                .await
                {
                    Ok(d) => d,
                    Err(e) => return (err_json(e), false),
                };
                let http_wake = Arc::new(
                    HttpWakeProvider::new()
                        .with_cooldown_secs(0)
                        .with_timeout(Duration::from_millis(wake_cfg.timeout_ms)),
                );
                let wake_opts = WakeDialOptions::new(
                    http_wake,
                    wake_cfg.target.clone(),
                    wake_cfg.secret.clone(),
                )
                .with_pre_wake(wake_cfg.pre_wake)
                .with_retry_delay(Duration::from_millis(wake_cfg.retry_delay_ms))
                .with_max_attempts(wake_cfg.max_attempts)
                .with_wake_timeout(Duration::from_millis(wake_cfg.timeout_ms));
                wake_and_connect_v2_session(
                    &*dialer,
                    &endpoint,
                    &wake_opts,
                    &id,
                    &target_host_id,
                    grant,
                    &mut state.roster,
                    now_unix(),
                )
                .await
                .map(|(drv, _)| drv)
            } else {
                let stream = match dial_endpoint_with_cfg(
                    &endpoint,
                    relay_host.as_deref(),
                    &state.transport_cfg,
                    v2_sec,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => return (err_json(e), false),
                };
                V2SessionDriver::connect(
                    stream,
                    &id,
                    &target_host_id,
                    grant,
                    &mut state.roster,
                    now_unix(),
                )
                .await
            };
            match driver_res {
                Ok(driver) => {
                    let peer_device_id = driver.peer_device_id().to_owned();
                    let peer_crl_seq = driver.peer_crl_seq();
                    let provider = format!("{:?}", driver.provider_id());
                    if driver.exported_v2_secrets().is_some() {
                        let _ = state
                            .roster
                            .set_peer_min_wire_version(&target_host_id, WIRE_VERSION_V2);
                    }
                    let _ = state.persist_roster();
                    state.session = Some(SessionBackend::V2(driver));
                    (
                        serde_json::json!({
                            "ok": true,
                            "peer_device_id": peer_device_id,
                            "peer_crl_seq": peer_crl_seq,
                            "provider": provider,
                            "wire_version": 2,
                        }),
                        false,
                    )
                }
                Err(e) => {
                    let _ = state.persist_roster();
                    (err_json(e.to_string()), false)
                }
            }
        }
        PeerCmd::AcceptV2 { timeout_ms } => {
            let Some(id) = state.identity.clone() else {
                return (err_json("init required before accept_v2"), false);
            };
            let wait = Duration::from_millis(timeout_ms.unwrap_or(10_000));
            let Ok(Some(stream)) = timeout(wait, state.accepted_rx.recv()).await else {
                return (err_json("timed out accepting v2 session connection"), false);
            };
            match V2SessionDriver::accept(
                stream,
                &id,
                &mut state.roster,
                now_unix(),
                &state.v2_state,
                None,
            )
            .await
            {
                Ok(driver) => {
                    let peer_device_id = driver.peer_device_id().to_owned();
                    let peer_crl_seq = driver.peer_crl_seq();
                    let provider = format!("{:?}", driver.provider_id());
                    if driver.exported_v2_secrets().is_some() {
                        let _ = state
                            .roster
                            .set_peer_min_wire_version(&peer_device_id, WIRE_VERSION_V2);
                    }
                    let _ = state.persist_roster();
                    state.session = Some(SessionBackend::V2(driver));
                    (
                        serde_json::json!({
                            "ok": true,
                            "peer_device_id": peer_device_id,
                            "peer_crl_seq": peer_crl_seq,
                            "provider": provider,
                            "wire_version": 2,
                        }),
                        false,
                    )
                }
                Err(e) => {
                    let _ = state.persist_roster();
                    (err_json(e.to_string()), false)
                }
            }
        }
        PeerCmd::Send {
            data_b64,
            data_utf8,
        } => {
            let Some(session) = state.session.as_mut() else {
                return (err_json("no active session"), false);
            };
            let payload = if let Some(b64) = data_b64 {
                match b64url_decode(&b64) {
                    Ok(bytes) => bytes,
                    Err(e) => return (err_json(e.to_string()), false),
                }
            } else if let Some(text) = data_utf8 {
                text.into_bytes()
            } else {
                return (err_json("send requires 'data_b64' or 'data_utf8'"), false);
            };
            match session.send_data(&payload).await {
                Ok(()) => (
                    serde_json::json!({ "ok": true, "sent_bytes": payload.len() }),
                    false,
                ),
                Err(e) => (err_json(e), false),
            }
        }
        PeerCmd::Recv { timeout_ms } => {
            let Some(session) = state.session.as_mut() else {
                return (err_json("no active session"), false);
            };
            let wait = Duration::from_millis(timeout_ms.unwrap_or(5_000));
            match timeout(wait, session.next_event_now(&mut state.roster)).await {
                Ok(Ok(Some(SessionEvent::AppData(data)))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "data",
                        "data_b64": b64url_encode(&data),
                        "data_utf8": String::from_utf8_lossy(&data),
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::Rekeyed { direction }))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "rekeyed",
                        "direction": format!("{direction:?}"),
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::GrantUpdated(grant)))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "grant_updated",
                        "grant": ok_json(grant),
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::RevocationUpdated { issuer, seq }))) => {
                    let _ = state.persist_roster();
                    (
                        serde_json::json!({
                            "ok": true,
                            "event": "revocation_updated",
                            "issuer": issuer,
                            "seq": seq,
                        }),
                        false,
                    )
                }
                Ok(Ok(Some(SessionEvent::PongReceived(cookie)))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "pong",
                        "cookie": cookie,
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::Audit(audit)))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "audit",
                        "audit": ok_json(audit),
                    }),
                    false,
                ),
                Ok(Ok(Some(SessionEvent::Closed { code, reason }))) => (
                    serde_json::json!({
                        "ok": true,
                        "event": "closed",
                        "code": code,
                        "reason": reason,
                    }),
                    false,
                ),
                Ok(Ok(None)) => (serde_json::json!({ "ok": true, "event": "eof" }), false),
                Ok(Err(e)) => (err_json(e), false),
                Err(_) => (err_json("recv timed out"), false),
            }
        }
        PeerCmd::Authorize { cap } => {
            let Some(session) = state.session.as_ref() else {
                return (err_json("no active session"), false);
            };
            let (res, audit) = session.authorize(&cap, now_unix(), &state.roster);
            (
                serde_json::json!({
                    "ok": true,
                    "allowed": res.is_ok(),
                    "audit": ok_json(audit),
                }),
                false,
            )
        }
        PeerCmd::Rekey => {
            let Some(session) = state.session.as_mut() else {
                return (err_json("no active session"), false);
            };
            match session.send_rekey().await {
                Ok(()) => (serde_json::json!({ "ok": true }), false),
                Err(e) => (err_json(e), false),
            }
        }
        PeerCmd::Revoke { peer_id } => {
            if let Err(e) = state.roster.revoke_peer(&peer_id) {
                return (err_json(e.to_string()), false);
            }
            if let Err(e) = state.persist_roster() {
                return (err_json(e), false);
            }
            (serde_json::json!({ "ok": true, "revoked": peer_id }), false)
        }
        PeerCmd::Close { code, reason } => {
            if let Some(mut session) = state.session.take() {
                match session
                    .send_close(code.unwrap_or(1000), reason.as_deref().unwrap_or("normal"))
                    .await
                {
                    Ok(()) => (serde_json::json!({ "ok": true }), false),
                    Err(e) => (err_json(e), false),
                }
            } else {
                (serde_json::json!({ "ok": true }), false)
            }
        }
        PeerCmd::Shutdown => {
            if let Some(mut session) = state.session.take() {
                let _ = session.send_close(1000, "shutdown").await;
            }
            state.shutdown_listeners();
            (serde_json::json!({ "ok": true }), true)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (line_tx, mut line_rx) = mpsc::channel::<String>(32);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(text) => {
                    if line_tx.blocking_send(text).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut state = PeerState::new();
    let stdout = std::io::stdout();

    while let Some(line) = line_rx.recv().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (resp, should_exit) = match serde_json::from_str::<PeerCmd>(trimmed) {
            Ok(cmd) => dispatch_cmd(&mut state, cmd).await,
            Err(err) => (err_json(format!("invalid command json: {err}")), false),
        };
        let encoded = serde_json::to_string(&resp)?;
        {
            let mut out = stdout.lock();
            out.write_all(encoded.as_bytes())?;
            out.write_all(b"\n")?;
            out.flush()?;
        }
        if should_exit {
            break;
        }
    }

    state.shutdown_listeners();
    Ok(())
}
