//! Python PyO3 bindings over `tendril-core` and `tendril-runtime` with GIL release.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde::Deserialize;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, b64url_decode,
    b64url_decode_array, b64url_encode, compute_code_mac as core_compute_code_mac,
    device_id as core_device_id, fingerprint_device as core_fingerprint_device,
    fingerprint_host as core_fingerprint_host, pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::error::CoreError;
use tendril_core::grants::{AuditEvent, Grant, RevocationList, authorize_grant, canonical_json};
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, verify_rotation_chain,
};
use tendril_core::pairing::{
    EnrollmentPolicy, PairAction, PairOutcome, PairingCodeKind, PairingConfig, PairingManager,
    PinnedHost, mint_enrollment_token as core_mint_enrollment_token,
};
use tendril_core::relay_auth::{RelayAuthRole, RelayAuthSecret, RelayTicket};
use tendril_core::roster::{AnchorState, PeerState, Roster};
use tendril_core::v2::{
    V2PairOutcome, V2PinnedHost, canonical_relay_host, derive_epoch_mailbox_window,
};
use tendril_runtime::{
    BrokerDialer, ConcurrentSession, ConcurrentV2Session, DEFAULT_PRE_AUTH_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT, DirectDialer, DirectListener, HttpWakeProvider, InboundRouter,
    LocalDialer, MAX_OUTER_FRAME_LEN, OverlayDialer, P2pDialer, P2pListener, P2pOptions,
    P2pRelayAuth, P2pRelayMode, PathDialer, PathListener, PathStream, RelayClientAuth, RelayDialer,
    RelayListener, RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig, RuntimeError,
    SessionDriver, SessionEvent, StateStore, V2ResponderState, V2SessionDriver, WakeAdapterKind,
    WakeDialOptions, WakeSecret, WakeTarget, dial_endpoint_with_auth,
    drive_m2m_enroll_initiator_with_floor, drive_m2m_enroll_initiator_with_store,
    drive_pair_initiator_with_store, drive_pair_responder_with_policy_and_store,
    drive_v2_pake_pair_initiator_with_store, drive_v2_pake_pair_initiator_with_timeout,
    drive_v2_pake_pair_responder_with_options, drive_v2_pake_pair_responder_with_store,
    pairing_path_kind_for_provider, parse_p2p_relay_mode, parse_p2p_relay_modes,
    pinned_pairing_floor, wake_and_dial_v2,
};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn persist_roster_guard(store: Option<&Arc<StateStore>>, roster: &Roster) -> PyResult<()> {
    if let Some(s) = store {
        s.save_roster(roster)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    }
    Ok(())
}

fn persist_store_roster(
    store: Option<&Arc<StateStore>>,
    roster: &Arc<StdMutex<Roster>>,
) -> PyResult<()> {
    if store.is_some() {
        let guard = roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        persist_roster_guard(store, &guard)?;
    }
    Ok(())
}

fn sync_roster_from_store_opt(
    store: Option<&Arc<StateStore>>,
    roster: &Arc<StdMutex<Roster>>,
) -> PyResult<()> {
    if let Some(s) = store {
        let disk = s
            .load_roster()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let mut guard = roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = disk;
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn as_32(bytes: &[u8], name: &str) -> PyResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{name} must be exactly 32 bytes")))
}

fn parse_hybrid_signing_pub(bytes: &[u8], name: &str) -> PyResult<HybridSigningPublicKey> {
    if bytes.len() != HYBRID_SIGNING_PUB_LEN {
        return Err(PyValueError::new_err(format!(
            "{name} must be exactly {HYBRID_SIGNING_PUB_LEN} bytes"
        )));
    }
    HybridSigningPublicKey::from_bytes(bytes)
        .map_err(|e| PyValueError::new_err(format!("invalid {name}: {e}")))
}

fn parse_signing_pin(bytes: &[u8], name: &str) -> PyResult<SigningKeyPin> {
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        parse_hybrid_signing_pub(bytes, name).map(SigningKeyPin::Full)
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let mut hash = [0u8; HYBRID_SIGNING_HASH_LEN];
        hash.copy_from_slice(bytes);
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(PyValueError::new_err(format!(
            "{name} must be {HYBRID_SIGNING_PUB_LEN} or {HYBRID_SIGNING_HASH_LEN} bytes"
        )))
    }
}

fn parse_signing_pin_b64(encoded: &str) -> Result<SigningKeyPin, String> {
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
struct WakeTransportConfig {
    #[zeroize(skip)]
    target: WakeTarget,
    #[zeroize(skip)]
    secret: WakeSecret,
    pre_wake: bool,
    retry_delay_ms: u64,
    max_attempts: usize,
    timeout_ms: u64,
}

impl fmt::Debug for WakeTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakeTransportConfig")
            .field("target", &self.target)
            .field("secret", &"<redacted>")
            .field("pre_wake", &self.pre_wake)
            .field("retry_delay_ms", &self.retry_delay_ms)
            .field("max_attempts", &self.max_attempts)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

#[derive(Clone, Default)]
struct EndpointTransportConfig {
    relay_auth: RelayClientAuth,
    p2p_relay_mode: Option<P2pRelayMode>,
    p2p_pkarr: Option<bool>,
    p2p_advertise_direct_addrs: Option<bool>,
    p2p_allow_private_addrs: Option<bool>,
    p2p_relay_auth: Option<P2pRelayAuth>,
    wake: Option<WakeTransportConfig>,
}

impl fmt::Debug for EndpointTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointTransportConfig")
            .field("relay_auth", &self.relay_auth)
            .field("p2p_relay_mode", &self.p2p_relay_mode)
            .field("p2p_pkarr", &self.p2p_pkarr)
            .field(
                "p2p_advertise_direct_addrs",
                &self.p2p_advertise_direct_addrs,
            )
            .field("p2p_allow_private_addrs", &self.p2p_allow_private_addrs)
            .field("p2p_relay_auth", &self.p2p_relay_auth)
            .field("wake", &self.wake)
            .finish()
    }
}

impl Drop for EndpointTransportConfig {
    fn drop(&mut self) {
        self.relay_auth = RelayClientAuth::None;
        self.p2p_relay_auth = None;
        self.wake = None;
    }
}

impl EndpointTransportConfig {
    fn from_input(mut input: TransportConfigInput) -> PyResult<Self> {
        if input.relay_auth_secret.is_some() && input.relay_ticket.is_some() {
            return Err(PyValueError::new_err(
                "relay_auth_secret and relay_ticket are mutually exclusive",
            ));
        }
        if input.p2p_relay_auth_token.is_some() && input.p2p_api_secret.is_some() {
            return Err(PyValueError::new_err(
                "p2p_relay_auth_token and p2p_api_secret are mutually exclusive",
            ));
        }
        if input.p2p_relay_mode.is_some() && input.p2p_relay_urls.is_some() {
            return Err(PyValueError::new_err(
                "p2p_relay_mode and p2p_relay_urls are mutually exclusive",
            ));
        }

        let relay_auth = if let Some(sec) = input.relay_auth_secret.take().map(Zeroizing::new) {
            let trimmed = sec.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
                return Err(PyValueError::new_err("invalid relay_auth_secret"));
            }
            let parsed = RelayAuthSecret::from_bytes(trimmed.as_bytes())
                .map_err(|_| PyValueError::new_err("invalid relay_auth_secret"))?;
            RelayClientAuth::HmacSecret(parsed)
        } else if let Some(ticket) = input.relay_ticket.take() {
            canonical_relay_host(&ticket.relay_host)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            if ticket.issuer_pub.is_empty() || ticket.target_pub.is_empty() || ticket.sig.is_empty()
            {
                return Err(PyValueError::new_err(
                    "relay_ticket has empty required fields",
                ));
            }
            RelayClientAuth::Ticket(ticket)
        } else {
            RelayClientAuth::None
        };

        let p2p_relay_mode = if let Some(ref mode_s) = input.p2p_relay_mode {
            Some(
                parse_p2p_relay_mode(Some(mode_s))
                    .map_err(|e| PyValueError::new_err(e.to_string()))?,
            )
        } else if let Some(ref urls) = input.p2p_relay_urls {
            Some(parse_p2p_relay_modes(urls).map_err(|e| PyValueError::new_err(e.to_string()))?)
        } else {
            None
        };

        let p2p_relay_auth =
            if let Some(tok) = input.p2p_relay_auth_token.take().map(Zeroizing::new) {
                if tok.is_empty() || tok.chars().any(char::is_control) {
                    return Err(PyValueError::new_err("invalid p2p_relay_auth_token"));
                }
                Some(P2pRelayAuth::BearerToken(tok))
            } else if let Some(sec) = input.p2p_api_secret.take().map(Zeroizing::new) {
                #[cfg(feature = "p2p-iroh-services")]
                {
                    if sec.is_empty() || sec.chars().any(char::is_control) {
                        return Err(PyValueError::new_err("invalid p2p_api_secret"));
                    }
                    Some(P2pRelayAuth::IrohServicesSecret(sec))
                }
                #[cfg(not(feature = "p2p-iroh-services"))]
                {
                    let _ = sec;
                    return Err(PyRuntimeError::new_err(
                        "tendril-py built without p2p-iroh-services feature",
                    ));
                }
            } else {
                None
            };

        if p2p_relay_auth.is_some() && matches!(p2p_relay_mode, Some(P2pRelayMode::Disabled)) {
            return Err(PyValueError::new_err(
                "p2p relay auth is invalid when p2p_relay_mode is disabled",
            ));
        }

        let wake = if let Some(url) = input.wake_url.take() {
            let adapter = input.wake_adapter.unwrap_or(WakeAdapterKind::Webhook);
            let mut target =
                WakeTarget::new(adapter, &url).map_err(|e| PyValueError::new_err(e.to_string()))?;
            if let Some(tok) = input.wake_auth_token.take().map(Zeroizing::new) {
                target = target
                    .with_auth_token(tok.as_str())
                    .map_err(|_| PyValueError::new_err("invalid wake_auth_token"))?;
            }
            let secret_b64 = input
                .wake_secret_b64
                .take()
                .map(Zeroizing::new)
                .ok_or_else(|| {
                    PyValueError::new_err("wake_secret_b64 is required when wake_url is set")
                })?;
            let secret_bytes = Zeroizing::new(
                b64url_decode_array::<32>(secret_b64.trim())
                    .map_err(|_| PyValueError::new_err("invalid wake_secret_b64"))?,
            );
            Some(WakeTransportConfig {
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
            return Err(PyValueError::new_err("wake_* options require wake_url"));
        } else {
            None
        };

        Ok(Self {
            relay_auth,
            p2p_relay_mode,
            p2p_pkarr: input.p2p_pkarr,
            p2p_advertise_direct_addrs: input.p2p_advertise_direct_addrs,
            p2p_allow_private_addrs: input.p2p_allow_private_addrs,
            p2p_relay_auth,
            wake,
        })
    }

    fn build_p2p_listener_options(
        &self,
        relay_mode_override: Option<&str>,
    ) -> Result<P2pOptions, RuntimeError> {
        let mode = match relay_mode_override.map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => parse_p2p_relay_mode(Some(raw))?,
            None => self.p2p_relay_mode.clone().unwrap_or(P2pRelayMode::Default),
        };
        let mut opts = P2pOptions::for_listener(mode);
        if let Some(pkarr) = self.p2p_pkarr {
            opts = opts.with_publish_pkarr(pkarr).with_resolve_pkarr(pkarr);
        }
        if let Some(adv) = self.p2p_advertise_direct_addrs {
            opts = opts.with_advertise_direct_addrs(adv);
        }
        if let Some(allow_priv) = self.p2p_allow_private_addrs {
            opts = opts.with_allow_private_addrs(allow_priv);
        }
        opts = opts.with_relay_auth(self.p2p_relay_auth.clone());
        Ok(opts)
    }

    fn build_p2p_dialer_options(
        &self,
        relay_host: Option<&str>,
    ) -> Result<P2pOptions, RuntimeError> {
        let mode = if let Some(ref m) = self.p2p_relay_mode {
            m.clone()
        } else if let Some(spec) = relay_host.map(str::trim).filter(|s| !s.is_empty()) {
            parse_p2p_relay_mode(Some(spec))?
        } else if std::env::var("TENDRIL_P2P_LOCAL").as_deref() == Ok("1") {
            P2pRelayMode::Disabled
        } else {
            P2pRelayMode::Default
        };
        let mut opts = P2pOptions::for_dialer(mode);
        if let Some(pkarr) = self.p2p_pkarr {
            opts = opts.with_resolve_pkarr(pkarr);
        }
        if let Some(allow_priv) = self.p2p_allow_private_addrs {
            opts = opts.with_allow_private_addrs(allow_priv);
        } else if matches!(opts.relay_mode, P2pRelayMode::Disabled) {
            opts = opts.with_allow_private_addrs(true);
        }
        opts = opts.with_relay_auth(self.p2p_relay_auth.clone());
        Ok(opts)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PyPinnedHostInput {
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
) -> PyResult<[u8; 32]> {
    let entry = roster.get(target_host_id).ok_or_else(|| {
        PyRuntimeError::new_err(format!("target '{target_host_id}' not found in roster"))
    })?;
    if entry.state == PeerState::Revoked {
        return Err(PyRuntimeError::new_err(format!(
            "target '{target_host_id}' is revoked"
        )));
    }
    entry
        .v2_secrets
        .as_ref()
        .map(|s| *s.mailbox_secret())
        .ok_or_else(|| {
            PyRuntimeError::new_err(format!(
                "target '{target_host_id}' has no v2 mailbox_secret"
            ))
        })
}

fn lookup_v2_mailbox_secret_for_pair(
    roster: &Roster,
    pinned: Option<&PinnedHost>,
    endpoint: &str,
    now_unix: u64,
) -> Result<[u8; 32], RuntimeError> {
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
    Err(RuntimeError::Protocol(
        "no matching v2 mailbox_secret in roster for /v2/relay endpoint".to_owned(),
    ))
}

async fn dial_endpoint_v2_with_options(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &EndpointTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathStream>, RuntimeError> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        let opts = cfg.build_p2p_dialer_options(normalized_host)?;
        let dialer = P2pDialer::bind_with_options(opts).await?;
        return match dialer.dial(endpoint).await {
            Ok(stream) => Ok(stream),
            Err(err) => {
                dialer.close().await;
                Err(err)
            }
        };
    }
    if let Some(secret) = v2_mailbox_secret {
        let mut dialer = RelayV2Dialer::new(secret).with_auth(cfg.relay_auth.clone());
        if let Some(host) = normalized_host {
            dialer = dialer.with_expected_host(host);
        }
        return dialer.dial(endpoint).await;
    }
    dial_endpoint_with_auth(endpoint, normalized_host, cfg.relay_auth.clone()).await
}

async fn build_dialer_with_options(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &EndpointTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathDialer>, RuntimeError> {
    let normalized_host = relay_host.map(str::trim).filter(|s| !s.is_empty());
    if endpoint.starts_with("iroh://") {
        let opts = cfg.build_p2p_dialer_options(normalized_host)?;
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

async fn drive_v1_pair_initiator_with_roster_floors(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    roster: &Roster,
) -> Result<PairOutcome, RuntimeError> {
    let mut machine = tendril_core::pairing::PairingInitiator::new_with_min_wire_version(
        identity,
        device_name,
        device_kind,
        code,
        None,
        tendril_core::WIRE_VERSION,
        None,
    )?
    .with_roster_floors(roster);
    timeout(DEFAULT_PRE_AUTH_TIMEOUT, async {
        let init_actions = machine.start()?;
        let mut should_close = false;
        for action in init_actions {
            match action {
                PairAction::WriteBytes(bytes) => {
                    for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
                        stream.send_chunk(chunk).await?;
                    }
                }
                PairAction::SasReady { .. } => {}
                PairAction::Completed(outcome) => return Ok(outcome),
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
            let n = stream.recv_chunk(&mut buf).await?;
            if n == 0 {
                return Err(RuntimeError::Closed);
            }
            let actions = machine.feed_bytes(&buf[..n])?;
            let mut completed = None;
            let mut close_now = false;
            for action in actions {
                match action {
                    PairAction::WriteBytes(bytes) => {
                        for chunk in bytes.chunks(MAX_OUTER_FRAME_LEN) {
                            stream.send_chunk(chunk).await?;
                        }
                    }
                    PairAction::SasReady { .. } => {}
                    PairAction::Completed(outcome) => completed = Some(outcome),
                    PairAction::CloseTransport(_) => close_now = true,
                }
            }
            if close_now {
                let _ = stream.close().await;
            }
            if let Some(outcome) = completed {
                return Ok(outcome);
            }
        }
    })
    .await
    .map_err(|_| RuntimeError::Timeout("pre-auth pairing handshake timed out"))?
}

#[pyfunction]
fn device_id(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_device_id(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn fingerprint_host(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_fingerprint_host(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn fingerprint_device(static_pub: &[u8]) -> PyResult<String> {
    Ok(core_fingerprint_device(&as_32(static_pub, "static_pub")?))
}

#[pyfunction]
fn pairing_sas(handshake_hash: &[u8]) -> PyResult<String> {
    Ok(core_pairing_sas(&as_32(handshake_hash, "handshake_hash")?))
}

#[pyfunction]
fn compute_code_mac(py: Python<'_>, code: &str, handshake_hash: &[u8]) -> PyResult<Py<PyBytes>> {
    let hh = as_32(handshake_hash, "handshake_hash")?;
    let code_owned = code.to_owned();
    let mac = py
        .detach(move || core_compute_code_mac(&code_owned, &hh))
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &mac).unbind())
}

#[pyfunction]
fn verify_rotation_chain_json(
    pinned_signing_b64: &str,
    pinned_static_b64: &str,
    pinned_seq: u64,
    chain_json: &str,
    cur_static_b64: &str,
    cur_signing_b64: &str,
) -> PyResult<u64> {
    let psig = HybridSigningPublicKey::from_b64url(pinned_signing_b64)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let pstat = b64url_decode_array::<32>(pinned_static_b64)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let cstat = b64url_decode_array::<32>(cur_static_b64)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let csig = HybridSigningPublicKey::from_b64url(cur_signing_b64)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let chain: Vec<RotationRecord> =
        serde_json::from_str(chain_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    verify_rotation_chain(&psig, &pstat, pinned_seq, &chain, &cstat, &csig)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (grant_json, issuer_keys_json, expected_subject, expected_root_issuer, requested_cap, now_unix_secs, crl_json=None))]
fn verify_grant_json(
    grant_json: &str,
    issuer_keys_json: &str,
    expected_subject: &str,
    expected_root_issuer: &str,
    requested_cap: &str,
    now_unix_secs: u64,
    crl_json: Option<&str>,
) -> PyResult<bool> {
    let grant: Grant =
        serde_json::from_str(grant_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let key_map_raw: HashMap<String, String> =
        serde_json::from_str(issuer_keys_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let mut key_map = HashMap::with_capacity(key_map_raw.len());
    for (id, b64) in key_map_raw {
        let k = HybridSigningPublicKey::from_b64url(&b64)
            .map_err(|e| PyValueError::new_err(format!("invalid key for {id}: {e}")))?;
        key_map.insert(id, k);
    }
    let crl: Option<RevocationList> = match crl_json {
        Some(s) if !s.is_empty() => {
            Some(serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?)
        }
        _ => None,
    };
    let (res, _) = authorize_grant(
        Some(&grant),
        expected_subject,
        expected_root_issuer,
        requested_cap,
        now_unix_secs,
        crl.as_ref(),
        |id| key_map.get(id).cloned(),
    );
    Ok(res.is_ok())
}

fn refresh_m2m_flags(self_m2m: &AtomicBool, m2m: &AtomicBool, roster: &Roster) {
    let enabled = self_m2m.load(Ordering::Acquire)
        || roster
            .trust_anchors()
            .any(|(_, a)| a.state == AnchorState::Active);
    m2m.store(enabled, Ordering::Release);
}

#[pyclass(frozen)]
struct Endpoint {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    router: Arc<InboundRouter>,
    v2_state: Arc<V2ResponderState>,
    transport_cfg: Arc<StdMutex<EndpointTransportConfig>>,
    self_m2m_enabled: Arc<AtomicBool>,
    m2m_enabled: Arc<AtomicBool>,
}

impl Endpoint {
    fn snapshot_transport_cfg(&self) -> EndpointTransportConfig {
        self.transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[pymethods]
impl Endpoint {
    #[new]
    #[pyo3(signature = (state_dir=None, host_id=None))]
    fn new(py: Python<'_>, state_dir: Option<&str>, host_id: Option<&str>) -> PyResult<Self> {
        let dir_owned = state_dir.filter(|s| !s.is_empty()).map(ToOwned::to_owned);
        let host_owned = host_id.map(ToOwned::to_owned);
        py.detach(move || {
            let rt = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
            );
            let (store, identity, roster) = if let Some(dir) = dir_owned {
                let store = Arc::new(
                    StateStore::open_or_create(dir)
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
                );
                let identity = store
                    .load_or_generate_identity(host_owned.as_deref())
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                let roster = store
                    .load_roster()
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                (Some(store), identity, roster)
            } else {
                let mut identity = EndpointIdentity::generate()
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                if let Some(h) = host_owned.as_deref()
                    && !h.is_empty()
                {
                    identity = identity.with_host_id(h);
                }
                (None, identity, Roster::new())
            };

            let has_active_anchor = roster
                .trust_anchors()
                .any(|(_, a)| a.state == AnchorState::Active);
            Ok(Self {
                rt,
                store,
                store_lock: Arc::new(AsyncMutex::new(())),
                identity: Arc::new(identity),
                roster: Arc::new(StdMutex::new(roster)),
                pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
                router: Arc::new(InboundRouter::new()),
                v2_state: Arc::new(V2ResponderState::default()),
                transport_cfg: Arc::new(StdMutex::new(EndpointTransportConfig::default())),
                self_m2m_enabled: Arc::new(AtomicBool::new(false)),
                m2m_enabled: Arc::new(AtomicBool::new(has_active_anchor)),
            })
        })
    }

    fn info_json(&self) -> String {
        serde_json::json!({
            "host_id": self.identity.host_id(),
            "device_id": self.identity.device_id(),
            "static_pub": b64url_encode(self.identity.static_key().public_bytes()),
            "signing_pub": self.identity.signing_key().public_key().to_b64url(),
            "signing_pub_hash": b64url_encode(&self.identity.signing_key().signing_pub_hash()),
            "relay_pub": b64url_encode(self.identity.signing_key().ed25519_public_bytes()),
        })
        .to_string()
    }

    fn configure_transports_json(&self, transport_config_json: &str) -> PyResult<()> {
        let input: TransportConfigInput =
            serde_json::from_str(transport_config_json).map_err(|e| {
                PyValueError::new_err(format!(
                    "invalid transport_config_json: {:?} at line {} column {}",
                    e.classify(),
                    e.line(),
                    e.column()
                ))
            })?;
        let parsed = EndpointTransportConfig::from_input(input)?;
        let mut guard = self
            .transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = parsed;
        Ok(())
    }

    #[pyo3(signature = (relay_host, role=None, target_pub_or_wildcard=None, ttl_secs=None))]
    fn mint_relay_ticket(
        &self,
        py: Python<'_>,
        relay_host: &str,
        role: Option<&str>,
        target_pub_or_wildcard: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> PyResult<String> {
        let role_enum = match role.map(str::trim) {
            None | Some("" | "any") => RelayAuthRole::Any,
            Some("register") => RelayAuthRole::Register,
            Some("dial") => RelayAuthRole::Dial,
            Some(other) => {
                return Err(PyValueError::new_err(format!(
                    "invalid relay ticket role '{other}'"
                )));
            }
        };
        let host_s = relay_host.to_owned();
        let target_s = target_pub_or_wildcard
            .filter(|s| !s.is_empty())
            .unwrap_or("*")
            .to_owned();
        let ttl = ttl_secs.unwrap_or(300);
        let identity = Arc::clone(&self.identity);
        py.detach(move || {
            let ticket = identity
                .mint_relay_ticket(&host_s, role_enum, &target_s, now_unix(), ttl)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let json = Zeroizing::new(
                canonical_json(&ticket).map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
            );
            Ok((*json).clone())
        })
    }

    #[pyo3(signature = (listen_addr="127.0.0.1:0"))]
    fn serve_direct(&self, py: Python<'_>, listen_addr: &str) -> PyResult<String> {
        let addr: SocketAddr = listen_addr
            .parse()
            .map_err(|e| PyValueError::new_err(format!("invalid address: {e}")))?;
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        py.detach(move || {
            let listener = rt
                .block_on(DirectListener::bind(addr, None))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let ep = listener.local_endpoint();
            router.spawn_listener(rt.handle(), Box::new(listener));
            Ok(ep)
        })
    }

    #[pyo3(signature = (relay_url, expected_host=None))]
    fn serve_relay(
        &self,
        py: Python<'_>,
        relay_url: &str,
        expected_host: Option<&str>,
    ) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let url = relay_url.to_owned();
        let exp = expected_host.map(ToOwned::to_owned);
        let key = self.identity.signing_key().ed25519_signing_key();
        let cfg = self.snapshot_transport_cfg();
        py.detach(move || {
            let listener = rt
                .block_on(RelayListener::bind_with_auth(
                    url,
                    exp,
                    key,
                    DEFAULT_WRITE_TIMEOUT,
                    cfg.relay_auth.clone(),
                ))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let ep = listener.local_endpoint();
            router.spawn_listener(rt.handle(), Box::new(listener));
            Ok(ep)
        })
    }

    #[pyo3(signature = (relay_url, expected_host=None, peer_id=None))]
    fn serve_relay_v2(
        &self,
        py: Python<'_>,
        relay_url: &str,
        expected_host: Option<&str>,
        peer_id: Option<&str>,
    ) -> PyResult<String> {
        let cfg = self.snapshot_transport_cfg();
        let secrets: Vec<[u8; 32]> = {
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(pid) = peer_id.filter(|s| !s.is_empty()) {
                vec![lookup_v2_mailbox_secret_for_target(&roster, pid)?]
            } else {
                let list: Vec<[u8; 32]> = roster
                    .entries()
                    .filter(|(_, e)| e.state == PeerState::Active)
                    .filter_map(|(_, e)| e.v2_secrets.as_ref().map(|s| *s.mailbox_secret()))
                    .collect();
                if list.is_empty() {
                    return Err(PyRuntimeError::new_err(
                        "no active v2 peers with mailbox_secret in roster",
                    ));
                }
                list
            }
        };

        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let url_s = relay_url.to_owned();
        let exp_host = expected_host.map(ToOwned::to_owned);
        py.detach(move || {
            let mut bound_listeners = Vec::with_capacity(secrets.len());
            for secret in secrets {
                let lcfg = RelayV2ListenerConfig {
                    expected_host: exp_host.clone(),
                    write_timeout: DEFAULT_WRITE_TIMEOUT,
                    allow_insecure_ws: false,
                    replay_cache: None,
                    unix_secs: None,
                    auth: cfg.relay_auth.clone(),
                };
                let listener = rt
                    .block_on(RelayV2Listener::bind_with_config(
                        url_s.clone(),
                        secret,
                        lcfg,
                    ))
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                bound_listeners.push(listener);
            }
            let first_ep = bound_listeners.first().map(|l| l.local_endpoint());
            for listener in bound_listeners {
                router.spawn_listener(rt.handle(), Box::new(listener));
            }
            Ok(first_ep.unwrap_or(url_s))
        })
    }

    #[pyo3(signature = (relay_mode=None))]
    fn serve_p2p(&self, py: Python<'_>, relay_mode: Option<&str>) -> PyResult<String> {
        let cfg = self.snapshot_transport_cfg();
        let opts = cfg
            .build_p2p_listener_options(relay_mode)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let seed = self.identity.derive_p2p_identity_seed();
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        py.detach(move || {
            let listener = rt
                .block_on(P2pListener::bind_with_options(opts, Some(seed)))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let ep = listener.local_endpoint();
            router.spawn_listener(rt.handle(), Box::new(listener));
            Ok(ep)
        })
    }

    #[pyo3(signature = (kind="lan"))]
    fn issue_code(&self, py: Python<'_>, kind: &str) -> PyResult<String> {
        let pk = match kind {
            "" | "lan" => PairingCodeKind::Lan2Group,
            "remote" => PairingCodeKind::Remote3Group,
            other => {
                return Err(PyValueError::new_err(format!(
                    "invalid pairing code kind '{other}'"
                )));
            }
        };
        let mgr = Arc::clone(&self.pair_mgr);
        py.detach(move || {
            let mut guard = mgr.lock().expect("pair_mgr mutex poisoned");
            guard
                .issue_code(pk, now_unix())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }

    #[pyo3(signature = (endpoint, code, relay_host=None, name="py-device", kind="python"))]
    fn pair_initiate(
        &self,
        py: Python<'_>,
        endpoint: &str,
        code: &str,
        relay_host: Option<&str>,
        name: &str,
        kind: &str,
    ) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let cfg = self.snapshot_transport_cfg();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let code_s = code.to_owned();
        let name_s = name.to_owned();
        let kind_s = kind.to_owned();

        py.detach(move || {
            let roster_snapshot = roster_arc
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let v2_secret = if is_v2_relay_endpoint(&ep_s) {
                Some(
                    lookup_v2_mailbox_secret_for_pair(&roster_snapshot, None, &ep_s, now_unix())
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
                )
            } else {
                None
            };
            let store_for_pair = store.clone();
            let outcome = rt.block_on(async move {
                let mut stream =
                    dial_endpoint_v2_with_options(&ep_s, rh_s.as_deref(), &cfg, v2_secret)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                let pair_res = if let Some(ref s) = store_for_pair {
                    drive_pair_initiator_with_store(
                        stream.as_mut(),
                        &identity,
                        name_s,
                        kind_s,
                        code_s,
                        None,
                        s,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                    .map(|r| r.outcome)
                } else {
                    drive_v1_pair_initiator_with_roster_floors(
                        stream.as_mut(),
                        &identity,
                        name_s,
                        kind_s,
                        code_s,
                        &roster_snapshot,
                    )
                    .await
                }
                .map_err(|e| PyRuntimeError::new_err(e.to_string()));
                let _ = stream.close().await;
                pair_res
            })?;

            match outcome {
                PairOutcome::InitiatorPending {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    pairing_sas,
                    host_pin_verified,
                } => {
                    {
                        let mut roster = roster_arc.lock().expect("roster mutex poisoned");
                        let pin_res = if host_pin_verified {
                            roster.insert_pinned_host(
                                host_id.clone(),
                                host_id.clone(),
                                host_static_pub,
                                Some(host_signing_pub),
                                host_rotation_seq,
                                Vec::new(),
                            )
                        } else {
                            roster.record_pending_host(
                                host_id.clone(),
                                host_id.clone(),
                                host_static_pub,
                                host_signing_pub,
                                host_rotation_seq,
                                pairing_sas.clone(),
                                Vec::new(),
                            )
                        };
                        pin_res.map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                    }
                    persist_store_roster(store.as_ref(), &roster_arc)?;
                    Ok(serde_json::json!({
                        "device_id": device_id,
                        "host_id": host_id,
                        "sas": pairing_sas,
                        "status": if host_pin_verified { "active" } else { "pending" },
                        "host_confirmed": host_pin_verified,
                    })
                    .to_string())
                }
                PairOutcome::Rejected { error } => Err(PyRuntimeError::new_err(error)),
                PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                    Err(PyRuntimeError::new_err("unexpected responder outcome"))
                }
                PairOutcome::InitiatorEnrolled { .. } => {
                    Err(PyRuntimeError::new_err("unexpected m2m enrollment outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn pair_accept(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let pair_mgr = Arc::clone(&self.pair_mgr);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let wait = Duration::from_millis(timeout_ms);
        let policy = if self.m2m_enabled.load(Ordering::Acquire) {
            EnrollmentPolicy::enabled_default()
        } else {
            EnrollmentPolicy::default()
        };

        py.detach(move || {
            let roster_in = Arc::clone(&roster_arc);
            let res = rt.block_on(async move {
                let (mut stream, guard) = match router.recv_pair(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => return Err(PyRuntimeError::new_err("timed out accepting pair")),
                };

                let path_kind = pairing_path_kind_for_provider(stream.provider_id());
                drive_pair_responder_with_policy_and_store(
                    stream.as_mut(),
                    &identity,
                    &pair_mgr,
                    &roster_in,
                    store.as_deref(),
                    path_kind,
                    now_unix(),
                    policy,
                    Some(router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })?;

            match res.outcome {
                PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => Ok(serde_json::json!({
                    "device_id": device_id,
                    "sas": pairing_sas,
                    "name": name,
                    "kind": kind,
                })
                .to_string()),
                PairOutcome::ResponderEnrolled {
                    device_id,
                    token_nonce,
                    name,
                    kind,
                    ..
                } => Ok(serde_json::json!({
                    "device_id": device_id,
                    "status": "active",
                    "token_nonce": token_nonce,
                    "name": name,
                    "kind": kind,
                })
                .to_string()),
                PairOutcome::Rejected { error } => Err(PyRuntimeError::new_err(error)),
                PairOutcome::InitiatorPending { .. } | PairOutcome::InitiatorEnrolled { .. } => {
                    Err(PyRuntimeError::new_err("unexpected initiator outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (peer_id, sas=None))]
    fn confirm_peer(&self, py: Python<'_>, peer_id: &str, sas: Option<&str>) -> PyResult<()> {
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let pid = peer_id.to_owned();
        let sas_owned = sas.map(ToOwned::to_owned);
        py.detach(move || {
            {
                let mut roster = roster_arc.lock().expect("roster mutex poisoned");
                roster
                    .confirm_peer(&pid, sas_owned.as_deref())
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            }
            persist_store_roster(store.as_ref(), &roster_arc)
        })
    }

    #[pyo3(signature = (peer_id, caps, ttl_secs=3600))]
    fn mint_grant(
        &self,
        py: Python<'_>,
        peer_id: &str,
        caps: Vec<String>,
        ttl_secs: u64,
    ) -> PyResult<String> {
        let roster_arc = Arc::clone(&self.roster);
        let identity = Arc::clone(&self.identity);
        let store = self.store.clone();
        let pid = peer_id.to_owned();
        py.detach(move || {
            let nonce = random_bytes::<16>().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let grant = {
                let mut roster = roster_arc.lock().expect("roster mutex poisoned");
                let now = now_unix();
                roster
                    .mint_grant(
                        &identity,
                        &pid,
                        caps,
                        now,
                        now.saturating_add(ttl_secs),
                        nonce,
                    )
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            };
            persist_store_roster(store.as_ref(), &roster_arc)?;
            serde_json::to_string(&grant).map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }

    fn revoke_peer(&self, py: Python<'_>, peer_id: &str) -> PyResult<()> {
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let pid = peer_id.to_owned();
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        py.detach(move || {
            let mut roster = roster_arc.lock().expect("roster mutex poisoned");
            roster
                .revoke_peer(&pid)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            persist_roster_guard(store.as_ref(), &roster)?;
            refresh_m2m_flags(&self_m2m, &m2m, &roster);
            Ok(())
        })
    }

    fn add_trust_anchor(
        &self,
        py: Python<'_>,
        anchor_id: &str,
        signing_pub: &[u8],
    ) -> PyResult<()> {
        let key = parse_hybrid_signing_pub(signing_pub, "signing_pub")?;
        let aid = anchor_id.to_owned();
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        let router = Arc::clone(&self.router);
        py.detach(move || {
            let mut roster = roster_arc.lock().expect("roster mutex poisoned");
            roster
                .add_trust_anchor(aid, key)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            persist_roster_guard(store.as_ref(), &roster)?;
            refresh_m2m_flags(&self_m2m, &m2m, &roster);
            router.set_pair_enabled(true);
            Ok(())
        })
    }

    fn revoke_trust_anchor(&self, py: Python<'_>, anchor_id: &str) -> PyResult<()> {
        let aid = anchor_id.to_owned();
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        py.detach(move || {
            let mut roster = roster_arc.lock().expect("roster mutex poisoned");
            roster
                .revoke_trust_anchor(&aid)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            persist_roster_guard(store.as_ref(), &roster)?;
            refresh_m2m_flags(&self_m2m, &m2m, &roster);
            Ok(())
        })
    }

    #[pyo3(signature = (target_host_id, subject=None, ttl_secs=900))]
    fn mint_enrollment_token(
        &self,
        py: Python<'_>,
        target_host_id: &str,
        subject: Option<&str>,
        ttl_secs: u64,
    ) -> PyResult<String> {
        let target_s = target_host_id.to_owned();
        let subject_s = subject.map(ToOwned::to_owned);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let self_m2m = Arc::clone(&self.self_m2m_enabled);
        let m2m = Arc::clone(&self.m2m_enabled);
        let router = Arc::clone(&self.router);
        py.detach(move || {
            let nonce = random_bytes::<16>().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let token = core_mint_enrollment_token(
                &identity,
                &target_s,
                subject_s.as_deref(),
                now_unix(),
                ttl_secs,
                nonce,
            )
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
            if target_s == identity.host_id() {
                let roster = roster_arc.lock().expect("roster mutex poisoned");
                self_m2m.store(true, Ordering::Release);
                refresh_m2m_flags(&self_m2m, &m2m, &roster);
                router.set_pair_enabled(true);
            }
            serde_json::to_string(&token).map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }

    #[pyo3(signature = (endpoint, host_id, host_static_pub, host_signing_pub, token_json, relay_host=None, host_rotation_seq=0, name="py-machine", kind="machine"))]
    #[allow(clippy::too_many_arguments)]
    fn enroll_initiate(
        &self,
        py: Python<'_>,
        endpoint: &str,
        host_id: &str,
        host_static_pub: &[u8],
        host_signing_pub: &[u8],
        token_json: &str,
        relay_host: Option<&str>,
        host_rotation_seq: u64,
        name: &str,
        kind: &str,
    ) -> PyResult<String> {
        let static_pub = as_32(host_static_pub, "host_static_pub")?;
        let signing_pin = parse_signing_pin(host_signing_pub, "host_signing_pub")?;
        let token: Grant = serde_json::from_str(token_json)
            .map_err(|e| PyValueError::new_err(format!("invalid token_json: {e}")))?;
        let pinned_host = PinnedHost {
            host_id: Some(host_id.to_owned()),
            static_pub,
            signing_pin,
            rotation_seq: host_rotation_seq,
        };
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let name_s = name.to_owned();
        let kind_s = kind.to_owned();

        let cfg = self.snapshot_transport_cfg();
        let fallback_floor = {
            let roster = roster_arc
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pinned_pairing_floor(&roster, &pinned_host)
        };
        py.detach(move || {
            let store_for_enroll = store.clone();
            let res = rt.block_on(async move {
                let mut stream = dial_endpoint_v2_with_options(&ep_s, rh_s.as_deref(), &cfg, None)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                let pair_res = if let Some(ref s) = store_for_enroll {
                    drive_m2m_enroll_initiator_with_store(
                        stream.as_mut(),
                        &identity,
                        name_s,
                        kind_s,
                        token,
                        pinned_host,
                        s,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                } else {
                    drive_m2m_enroll_initiator_with_floor(
                        stream.as_mut(),
                        &identity,
                        name_s,
                        kind_s,
                        token,
                        pinned_host,
                        fallback_floor,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                }
                .map_err(|e| PyRuntimeError::new_err(e.to_string()));
                let _ = stream.close().await;
                pair_res
            })?;

            match res.outcome {
                PairOutcome::InitiatorEnrolled {
                    device_id,
                    host_id,
                    host_static_pub,
                    host_signing_pub,
                    host_rotation_seq,
                    token_nonce,
                } => {
                    {
                        let mut roster = roster_arc.lock().expect("roster mutex poisoned");
                        roster
                            .insert_pinned_host(
                                host_id.clone(),
                                host_id.clone(),
                                host_static_pub,
                                Some(host_signing_pub),
                                host_rotation_seq,
                                Vec::new(),
                            )
                            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                    }
                    persist_store_roster(store.as_ref(), &roster_arc)?;
                    Ok(serde_json::json!({
                        "device_id": device_id,
                        "host_id": host_id,
                        "status": "active",
                        "host_rotation_seq": host_rotation_seq,
                        "token_nonce": token_nonce,
                    })
                    .to_string())
                }
                PairOutcome::Rejected { error } => Err(PyRuntimeError::new_err(error)),
                PairOutcome::InitiatorPending { .. } => {
                    Err(PyRuntimeError::new_err("unexpected human pending outcome"))
                }
                PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                    Err(PyRuntimeError::new_err("unexpected responder outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (endpoint, code, relay_host=None, name=None, kind=None, pinned_host_json=None))]
    #[allow(clippy::too_many_arguments)]
    fn pair_v2_initiate(
        &self,
        py: Python<'_>,
        endpoint: &str,
        code: &str,
        relay_host: Option<&str>,
        name: Option<&str>,
        kind: Option<&str>,
        pinned_host_json: Option<&str>,
    ) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let cfg = self.snapshot_transport_cfg();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let code_s = code.to_owned();
        let device_name = name.unwrap_or("py-device").to_owned();
        let device_kind = kind.unwrap_or("python").to_owned();
        let pinned_opt = pinned_host_json
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        py.detach(move || {
            let roster_snapshot = roster_arc
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();

            let v2_pinned = match pinned_opt {
                Some(raw) => {
                    let pin_in: PyPinnedHostInput = serde_json::from_str(&raw).map_err(|e| {
                        PyValueError::new_err(format!(
                            "invalid pinned_host_json: {:?} at line {} column {}",
                            e.classify(),
                            e.line(),
                            e.column()
                        ))
                    })?;
                    let static_pub = b64url_decode_array::<32>(&pin_in.static_pub_b64)
                        .map_err(|e| PyValueError::new_err(e.to_string()))?;
                    let signing_pin = parse_signing_pin_b64(&pin_in.signing_pin_b64)
                        .map_err(PyValueError::new_err)?;
                    let pinned = PinnedHost {
                        host_id: pin_in.host_id,
                        static_pub,
                        signing_pin,
                        rotation_seq: pin_in.rotation_seq,
                    };
                    let base_floor = pinned_pairing_floor(&roster_snapshot, &pinned);
                    let floor = pin_in
                        .min_wire_version
                        .map_or(base_floor, |v| base_floor.max(v));
                    Some(
                        V2PinnedHost::new(pinned, floor)
                            .map_err(|e| PyValueError::new_err(e.to_string()))?,
                    )
                }
                None => None,
            };

            let v2_secret = if is_v2_relay_endpoint(&ep_s) {
                Some(
                    lookup_v2_mailbox_secret_for_pair(
                        &roster_snapshot,
                        v2_pinned.as_ref().map(|p| &p.pinned),
                        &ep_s,
                        now_unix(),
                    )
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
                )
            } else {
                None
            };

            let store_for_pair = store.clone();
            let pair_res = rt.block_on(async move {
                let mut stream =
                    dial_endpoint_v2_with_options(&ep_s, rh_s.as_deref(), &cfg, v2_secret)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                let res = if let Some(ref s) = store_for_pair {
                    drive_v2_pake_pair_initiator_with_store(
                        stream.as_mut(),
                        &identity,
                        device_name,
                        device_kind,
                        code_s,
                        v2_pinned,
                        "paired-host".to_owned(),
                        Vec::new(),
                        s,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                } else {
                    drive_v2_pake_pair_initiator_with_timeout(
                        stream.as_mut(),
                        &identity,
                        device_name,
                        device_kind,
                        code_s,
                        v2_pinned,
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                }
                .map_err(|e| PyRuntimeError::new_err(e.to_string()));
                let _ = stream.close().await;
                res
            })?;

            match pair_res.outcome {
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
                    if store.is_some() {
                        sync_roster_from_store_opt(store.as_ref(), &roster_arc)?;
                    } else {
                        let mut roster = roster_arc
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        roster
                            .apply_v2_pair_initiator_outcome(
                                &pair_res.outcome,
                                h_id.clone(),
                                Vec::new(),
                            )
                            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                    }
                    Ok(serde_json::json!({
                        "device_id": dev_id,
                        "host_id": h_id,
                        "sas": sas,
                        "status": if host_pin_verified { "active" } else { "pending" },
                        "host_confirmed": host_pin_verified,
                        "wire_version": 2,
                    })
                    .to_string())
                }
                V2PairOutcome::Rejected { error } => Err(PyRuntimeError::new_err(error)),
                V2PairOutcome::ResponderPending { .. } => {
                    Err(PyRuntimeError::new_err("unexpected responder outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn pair_v2_accept(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let pair_mgr = Arc::clone(&self.pair_mgr);
        let roster_arc = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let v2_state = Arc::clone(&self.v2_state);
        let wait = Duration::from_millis(timeout_ms);

        py.detach(move || {
            let roster_in = Arc::clone(&roster_arc);
            let store_in = store.clone();
            let res = rt.block_on(async move {
                let (mut stream, guard) = match router.recv_v2_pair(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => return Err(PyRuntimeError::new_err("timed out accepting v2 pair")),
                };
                let path_kind = pairing_path_kind_for_provider(stream.provider_id());
                if let Some(ref s) = store_in {
                    drive_v2_pake_pair_responder_with_store(
                        stream.as_mut(),
                        &identity,
                        &pair_mgr,
                        s,
                        &store_lock,
                        path_kind,
                        now_unix(),
                        &v2_state,
                        Some(router.v2_pair_rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                } else {
                    drive_v2_pake_pair_responder_with_options(
                        stream.as_mut(),
                        &identity,
                        &pair_mgr,
                        &roster_in,
                        path_kind,
                        now_unix(),
                        &v2_state,
                        Some(router.v2_pair_rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                }
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })?;

            match res.outcome {
                V2PairOutcome::ResponderPending {
                    device_id,
                    pairing_sas,
                    name,
                    kind,
                    ..
                } => {
                    sync_roster_from_store_opt(store.as_ref(), &roster_arc)?;
                    Ok(serde_json::json!({
                        "device_id": device_id,
                        "sas": pairing_sas,
                        "name": name,
                        "kind": kind,
                        "wire_version": 2,
                    })
                    .to_string())
                }
                V2PairOutcome::Rejected { error } => Err(PyRuntimeError::new_err(error)),
                V2PairOutcome::InitiatorPending { .. } => {
                    Err(PyRuntimeError::new_err("unexpected initiator outcome"))
                }
            }
        })
    }

    #[pyo3(signature = (endpoint, target_host_id, grant_json=None, relay_host=None))]
    fn connect(
        &self,
        py: Python<'_>,
        endpoint: &str,
        target_host_id: &str,
        grant_json: Option<&str>,
        relay_host: Option<&str>,
    ) -> PyResult<Session> {
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.is_empty() => {
                Some(serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?)
            }
            _ => None,
        };
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let cfg = self.snapshot_transport_cfg();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let target_s = target_host_id.to_owned();

        let driver = py.detach(move || {
            let v2_secret = if is_v2_relay_endpoint(&ep_s) {
                let guard = roster
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                Some(lookup_v2_mailbox_secret_for_target(&guard, &target_s)?)
            } else {
                None
            };
            let roster_in = Arc::clone(&roster);
            let res = rt.block_on(async move {
                let stream = dial_endpoint_v2_with_options(&ep_s, rh_s.as_deref(), &cfg, v2_secret)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                SessionDriver::connect_locked(
                    stream,
                    &identity,
                    &target_s,
                    grant,
                    &roster_in,
                    now_unix(),
                )
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            });
            match res {
                Ok(drv) => {
                    persist_store_roster(store.as_ref(), &roster)?;
                    Ok(drv)
                }
                Err(err) => {
                    if let Err(pe) = persist_store_roster(store.as_ref(), &roster) {
                        Err(PyRuntimeError::new_err(format!(
                            "{err} (roster persist error: {pe})"
                        )))
                    } else {
                        Err(err)
                    }
                }
            }
        })?;

        Ok(Session {
            rt: Arc::clone(&self.rt),
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(SessionBackend::V1(driver.into_concurrent())),
        })
    }

    #[pyo3(signature = (endpoint, target_host_id, grant_json=None, relay_host=None))]
    fn connect_v2(
        &self,
        py: Python<'_>,
        endpoint: &str,
        target_host_id: &str,
        grant_json: Option<&str>,
        relay_host: Option<&str>,
    ) -> PyResult<Session> {
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.is_empty() => {
                Some(serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?)
            }
            _ => None,
        };
        let rt = Arc::clone(&self.rt);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let cfg = self.snapshot_transport_cfg();
        let ep_s = endpoint.to_owned();
        let rh_s = relay_host.map(ToOwned::to_owned);
        let target_s = target_host_id.to_owned();

        let driver = py.detach(move || {
            let v2_secret = if is_v2_relay_endpoint(&ep_s) {
                let guard = roster
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                Some(lookup_v2_mailbox_secret_for_target(&guard, &target_s)?)
            } else {
                None
            };
            let roster_in = Arc::clone(&roster);
            let store_in = store.clone();
            let res = rt.block_on(async move {
                let stream = if let Some(ref wake_cfg) = cfg.wake {
                    let dialer = build_dialer_with_options(&ep_s, rh_s.as_deref(), &cfg, v2_secret)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
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
                    wake_and_dial_v2(&*dialer, &ep_s, &wake_opts, now_unix())
                        .await
                        .map(|(stream, _)| stream)
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
                } else {
                    dial_endpoint_v2_with_options(&ep_s, rh_s.as_deref(), &cfg, v2_secret)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
                };
                if let Some(ref s) = store_in {
                    V2SessionDriver::connect_with_store(
                        stream,
                        &identity,
                        &target_s,
                        grant,
                        s,
                        &store_lock,
                        now_unix(),
                    )
                    .await
                } else {
                    V2SessionDriver::connect_locked(
                        stream,
                        &identity,
                        &target_s,
                        grant,
                        &roster_in,
                        now_unix(),
                    )
                    .await
                }
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            });
            match res {
                Ok(drv) => {
                    sync_roster_from_store_opt(store.as_ref(), &roster)?;
                    Ok(drv)
                }
                Err(err) => {
                    if store.is_some() {
                        let _ = sync_roster_from_store_opt(store.as_ref(), &roster);
                    }
                    Err(err)
                }
            }
        })?;

        Ok(Session {
            rt: Arc::clone(&self.rt),
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(SessionBackend::V2(driver.into_concurrent())),
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn accept_session(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Session> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let wait = Duration::from_millis(timeout_ms);

        let driver = py.detach(move || {
            rt.block_on(async move {
                let (stream, guard) = match router.recv_session(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => return Err(PyRuntimeError::new_err("timed out accepting session")),
                };

                SessionDriver::accept_locked(
                    stream,
                    &identity,
                    &roster,
                    now_unix(),
                    Some(router.rate_limiter()),
                    Some(guard),
                    DEFAULT_PRE_AUTH_TIMEOUT,
                )
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })
        })?;

        Ok(Session {
            rt: Arc::clone(&self.rt),
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(SessionBackend::V1(driver.into_concurrent())),
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn accept_v2(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<Session> {
        let rt = Arc::clone(&self.rt);
        let router = Arc::clone(&self.router);
        let identity = Arc::clone(&self.identity);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let store_lock = Arc::clone(&self.store_lock);
        let v2_state = Arc::clone(&self.v2_state);
        let wait = Duration::from_millis(timeout_ms);

        let driver = py.detach(move || {
            let roster_in = Arc::clone(&roster);
            let store_in = store.clone();
            let drv = rt.block_on(async move {
                let (stream, guard) = match router.recv_v2_session(wait).await {
                    Ok(Some(pair)) => pair,
                    Ok(None) => return Err(PyRuntimeError::new_err("listener closed")),
                    Err(()) => {
                        return Err(PyRuntimeError::new_err("timed out accepting v2 session"));
                    }
                };
                if let Some(ref s) = store_in {
                    V2SessionDriver::accept_with_store(
                        stream,
                        &identity,
                        s,
                        &store_lock,
                        now_unix(),
                        &v2_state,
                        Some(router.v2_session_rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                } else {
                    V2SessionDriver::accept_locked(
                        stream,
                        &identity,
                        &roster_in,
                        now_unix(),
                        &v2_state,
                        Some(router.v2_session_rate_limiter()),
                        Some(guard),
                        DEFAULT_PRE_AUTH_TIMEOUT,
                    )
                    .await
                }
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })?;
            sync_roster_from_store_opt(store.as_ref(), &roster)?;
            Ok::<_, PyErr>(drv)
        })?;

        Ok(Session {
            rt: Arc::clone(&self.rt),
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(SessionBackend::V2(driver.into_concurrent())),
        })
    }

    fn close(&self, py: Python<'_>) {
        let router = Arc::clone(&self.router);
        py.detach(move || router.close());
    }
}

enum SessionBackend {
    V1(ConcurrentSession),
    V2(ConcurrentV2Session),
}

impl SessionBackend {
    fn is_v2(&self) -> bool {
        matches!(self, Self::V2(_))
    }

    async fn send_data(&self, payload: &[u8]) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_data(payload).await,
            Self::V2(s) => s.send_data(payload).await,
        }
    }

    async fn next_event_locked_now(
        &self,
        roster: &StdMutex<Roster>,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        match self {
            Self::V1(s) => s.next_event_locked_now(roster).await,
            Self::V2(s) => s.next_event_locked_now(roster).await,
        }
    }

    fn authorize_locked(
        &self,
        requested_cap: &str,
        now_unix: u64,
        roster: &StdMutex<Roster>,
    ) -> (Result<(), CoreError>, AuditEvent) {
        match self {
            Self::V1(s) => s.authorize_locked(requested_cap, now_unix, roster),
            Self::V2(s) => s.authorize_locked(requested_cap, now_unix, roster),
        }
    }

    async fn send_rekey(&self) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_rekey().await,
            Self::V2(s) => s.send_rekey().await,
        }
    }

    async fn send_close(&self, code: u16, reason: &str) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_close(code, reason).await,
            Self::V2(s) => s.send_close(code, reason).await,
        }
    }
}

#[pyclass(frozen)]
struct Session {
    rt: Arc<Runtime>,
    store: Option<Arc<StateStore>>,
    roster: Arc<StdMutex<Roster>>,
    session: Arc<SessionBackend>,
}

#[pymethods]
impl Session {
    fn send_data(&self, py: Python<'_>, payload: &[u8]) -> PyResult<()> {
        let data = payload.to_vec();
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        py.detach(move || {
            rt.block_on(async move {
                sess.send_data(&data)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })
        })
    }

    #[pyo3(signature = (timeout_ms=5000))]
    fn poll_event(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<String> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        let roster = Arc::clone(&self.roster);
        let store = self.store.clone();
        let wait = Duration::from_millis(timeout_ms);

        py.detach(move || {
            rt.block_on(async move {
                match timeout(wait, sess.next_event_locked_now(&roster)).await {
                    Ok(Ok(Some(ev))) => {
                        let json = match ev {
                            SessionEvent::AppData(data) => serde_json::json!({
                                "status": "event",
                                "event": "data",
                                "data_b64": b64url_encode(&data),
                            }),
                            SessionEvent::Rekeyed { direction } => serde_json::json!({
                                "status": "event",
                                "event": "rekeyed",
                                "direction": format!("{direction:?}"),
                            }),
                            SessionEvent::GrantUpdated(g) => serde_json::json!({
                                "status": "event",
                                "event": "grant_updated",
                                "grant": g,
                            }),
                            SessionEvent::RevocationUpdated { issuer, seq } => {
                                if sess.is_v2() && store.is_some() {
                                    sync_roster_from_store_opt(store.as_ref(), &roster)?;
                                } else {
                                    persist_store_roster(store.as_ref(), &roster)?;
                                }
                                serde_json::json!({
                                    "status": "event",
                                    "event": "revocation_updated",
                                    "issuer": issuer,
                                    "seq": seq,
                                })
                            }
                            SessionEvent::PongReceived(cookie) => serde_json::json!({
                                "status": "event",
                                "event": "pong",
                                "cookie": cookie,
                            }),
                            SessionEvent::Audit(audit) => serde_json::json!({
                                "status": "event",
                                "event": "audit",
                                "audit": audit,
                            }),
                            SessionEvent::Closed { code, reason } => serde_json::json!({
                                "status": "event",
                                "event": "closed",
                                "code": code,
                                "reason": reason,
                            }),
                        };
                        Ok(json.to_string())
                    }
                    Ok(Ok(None)) => Ok(serde_json::json!({ "status": "eof" }).to_string()),
                    Ok(Err(e)) => {
                        if sess.is_v2() && store.is_some() {
                            let _ = sync_roster_from_store_opt(store.as_ref(), &roster);
                            Err(PyRuntimeError::new_err(e.to_string()))
                        } else if let Err(pe) = persist_store_roster(store.as_ref(), &roster) {
                            Err(PyRuntimeError::new_err(format!("{e} ({pe})")))
                        } else {
                            Err(PyRuntimeError::new_err(e.to_string()))
                        }
                    }
                    Err(_) => Ok(serde_json::json!({ "status": "would_block" }).to_string()),
                }
            })
        })
    }

    fn authorize(&self, py: Python<'_>, requested_cap: &str) -> bool {
        let sess = Arc::clone(&self.session);
        let roster = Arc::clone(&self.roster);
        let cap = requested_cap.to_owned();
        py.detach(move || sess.authorize_locked(&cap, now_unix(), &roster).0.is_ok())
    }

    fn rekey(&self, py: Python<'_>) -> PyResult<()> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        py.detach(move || {
            rt.block_on(async move {
                sess.send_rekey()
                    .await
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })
        })
    }

    #[pyo3(signature = (code=1000, reason="normal"))]
    fn close(&self, py: Python<'_>, code: u16, reason: &str) -> PyResult<()> {
        let rt = Arc::clone(&self.rt);
        let sess = Arc::clone(&self.session);
        let reason_s = reason.to_owned();
        py.detach(move || {
            rt.block_on(async move {
                sess.send_close(code, &reason_s)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            })
        })
    }
}

#[pymodule]
fn _tendril(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(device_id, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_host, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_device, m)?)?;
    m.add_function(wrap_pyfunction!(pairing_sas, m)?)?;
    m.add_function(wrap_pyfunction!(compute_code_mac, m)?)?;
    m.add_function(wrap_pyfunction!(verify_rotation_chain_json, m)?)?;
    m.add_function(wrap_pyfunction!(verify_grant_json, m)?)?;
    m.add_class::<Endpoint>()?;
    m.add_class::<Session>()?;
    Ok(())
}
