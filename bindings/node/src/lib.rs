//! Node.js N-API native addon over `tendril-core` and `tendril-runtime`.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::Deserialize;
use tendril_core::crypto::{
    HYBRID_SIGNING_HASH_LEN, HYBRID_SIGNING_PUB_LEN, HybridSigningPublicKey, b64url_decode,
    b64url_decode_array, b64url_encode, compute_code_mac as core_compute_code_mac,
    device_id as core_device_id, fingerprint_device as core_fingerprint_device,
    fingerprint_host as core_fingerprint_host, pairing_sas as core_pairing_sas, random_bytes,
};
use tendril_core::error::CoreError;
use tendril_core::grants::{Grant, RevocationList, authorize_grant, canonical_json};
use tendril_core::identity::{
    EndpointIdentity, RotationRecord, SigningKeyPin, verify_rotation_chain,
};
use tendril_core::pairing::{
    EnrollmentPolicy, PairAction, PairOutcome, PairingCodeKind, PairingConfig, PairingInitiator,
    PairingManager, PinnedHost, mint_enrollment_token as core_mint_enrollment_token,
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
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_SAFE_INTEGER_F64: f64 = 9_007_199_254_740_991.0;

fn f64_to_u64(v: f64, name: &str) -> Result<u64> {
    if !(0.0..=MAX_SAFE_INTEGER_F64).contains(&v) || v.fract() != 0.0 {
        return Err(Error::new(
            Status::InvalidArg,
            format!("{name} must be a non-negative safe integer"),
        ));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(v as u64)
}

fn f64_to_timeout_ms(v: Option<f64>, default_ms: u64) -> Result<u64> {
    let Some(raw) = v else {
        return Ok(default_ms);
    };
    let ms = f64_to_u64(raw, "timeout_ms")?;
    if ms > u64::from(u32::MAX) {
        return Err(Error::new(
            Status::InvalidArg,
            "timeout_ms exceeds u32 maximum",
        ));
    }
    Ok(ms)
}

fn f64_to_u16(v: Option<f64>, default_val: u16, name: &str) -> Result<u16> {
    let Some(raw) = v else {
        return Ok(default_val);
    };
    let n = f64_to_u64(raw, name)?;
    u16::try_from(n)
        .map_err(|_| Error::new(Status::InvalidArg, format!("{name} must be in 0..=65535")))
}

fn u64_to_f64(v: u64) -> Result<f64> {
    if v > 9_007_199_254_740_991 {
        return Err(Error::new(
            Status::GenericFailure,
            "sequence exceeds JavaScript safe integer range",
        ));
    }
    #[allow(clippy::cast_precision_loss)]
    Ok(v as f64)
}

fn persist_store_roster(
    store: Option<&Arc<StateStore>>,
    roster: &Arc<StdMutex<Roster>>,
) -> Result<()> {
    if let Some(s) = store {
        let guard = roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.save_roster(&guard).map_err(to_generic_err)?;
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn as_32(bytes: &[u8], name: &str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        Error::new(
            Status::InvalidArg,
            format!("{name} must be exactly 32 bytes"),
        )
    })
}

fn parse_hybrid_signing_pub(bytes: &[u8], name: &str) -> Result<HybridSigningPublicKey> {
    if bytes.len() != HYBRID_SIGNING_PUB_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            format!("{name} must be exactly {HYBRID_SIGNING_PUB_LEN} bytes"),
        ));
    }
    HybridSigningPublicKey::from_bytes(bytes)
        .map_err(|e| Error::new(Status::InvalidArg, format!("invalid {name}: {e}")))
}

fn parse_signing_pin(bytes: &[u8], name: &str) -> Result<SigningKeyPin> {
    if bytes.len() == HYBRID_SIGNING_PUB_LEN {
        parse_hybrid_signing_pub(bytes, name).map(SigningKeyPin::Full)
    } else if bytes.len() == HYBRID_SIGNING_HASH_LEN {
        let mut hash = [0u8; HYBRID_SIGNING_HASH_LEN];
        hash.copy_from_slice(bytes);
        Ok(SigningKeyPin::Hash(hash))
    } else {
        Err(Error::new(
            Status::InvalidArg,
            format!("{name} must be {HYBRID_SIGNING_PUB_LEN} or {HYBRID_SIGNING_HASH_LEN} bytes"),
        ))
    }
}

fn to_generic_err(err: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, err.to_string())
}

fn to_invalid_arg(err: impl std::fmt::Display) -> Error {
    Error::new(Status::InvalidArg, err.to_string())
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
    fn from_input(mut input: TransportConfigInput) -> Result<Self> {
        if input.relay_auth_secret.is_some() && input.relay_ticket.is_some() {
            return Err(to_invalid_arg(
                "relay_auth_secret and relay_ticket are mutually exclusive",
            ));
        }
        if input.p2p_relay_auth_token.is_some() && input.p2p_api_secret.is_some() {
            return Err(to_invalid_arg(
                "p2p_relay_auth_token and p2p_api_secret are mutually exclusive",
            ));
        }
        if input.p2p_relay_mode.is_some() && input.p2p_relay_urls.is_some() {
            return Err(to_invalid_arg(
                "p2p_relay_mode and p2p_relay_urls are mutually exclusive",
            ));
        }

        let relay_auth = if let Some(sec) = input.relay_auth_secret.take().map(Zeroizing::new) {
            let trimmed = sec.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
                return Err(to_invalid_arg("invalid relay_auth_secret"));
            }
            let parsed = RelayAuthSecret::from_bytes(trimmed.as_bytes())
                .map_err(|_| to_invalid_arg("invalid relay_auth_secret"))?;
            RelayClientAuth::HmacSecret(parsed)
        } else if let Some(ticket) = input.relay_ticket.take() {
            canonical_relay_host(&ticket.relay_host).map_err(to_invalid_arg)?;
            if ticket.issuer_pub.is_empty() || ticket.target_pub.is_empty() || ticket.sig.is_empty()
            {
                return Err(to_invalid_arg("relay_ticket has empty required fields"));
            }
            RelayClientAuth::Ticket(ticket)
        } else {
            RelayClientAuth::None
        };

        let p2p_relay_mode = if let Some(ref mode_s) = input.p2p_relay_mode {
            Some(parse_p2p_relay_mode(Some(mode_s)).map_err(to_invalid_arg)?)
        } else if let Some(ref urls) = input.p2p_relay_urls {
            Some(parse_p2p_relay_modes(urls).map_err(to_invalid_arg)?)
        } else {
            None
        };

        let p2p_relay_auth =
            if let Some(tok) = input.p2p_relay_auth_token.take().map(Zeroizing::new) {
                if tok.is_empty() || tok.chars().any(char::is_control) {
                    return Err(to_invalid_arg("invalid p2p_relay_auth_token"));
                }
                Some(P2pRelayAuth::BearerToken(tok))
            } else if let Some(sec) = input.p2p_api_secret.take().map(Zeroizing::new) {
                #[cfg(feature = "p2p-iroh-services")]
                {
                    if sec.is_empty() || sec.chars().any(char::is_control) {
                        return Err(to_invalid_arg("invalid p2p_api_secret"));
                    }
                    Some(P2pRelayAuth::IrohServicesSecret(sec))
                }
                #[cfg(not(feature = "p2p-iroh-services"))]
                {
                    let _ = sec;
                    return Err(to_generic_err(
                        "tendril-node built without p2p-iroh-services feature",
                    ));
                }
            } else {
                None
            };

        if p2p_relay_auth.is_some() && matches!(p2p_relay_mode, Some(P2pRelayMode::Disabled)) {
            return Err(to_invalid_arg(
                "p2p relay auth is invalid when p2p_relay_mode is disabled",
            ));
        }

        let wake = if let Some(url) = input.wake_url.take() {
            let adapter = input.wake_adapter.unwrap_or(WakeAdapterKind::Webhook);
            let mut target = WakeTarget::new(adapter, &url).map_err(to_invalid_arg)?;
            if let Some(tok) = input.wake_auth_token.take().map(Zeroizing::new) {
                target = target
                    .with_auth_token(tok.as_str())
                    .map_err(|_| to_invalid_arg("invalid wake_auth_token"))?;
            }
            let secret_b64 = input
                .wake_secret_b64
                .take()
                .map(Zeroizing::new)
                .ok_or_else(|| {
                    to_invalid_arg("wake_secret_b64 is required when wake_url is set")
                })?;
            let secret_bytes = Zeroizing::new(
                b64url_decode_array::<32>(secret_b64.trim())
                    .map_err(|_| to_invalid_arg("invalid wake_secret_b64"))?,
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
            return Err(to_invalid_arg("wake_* options require wake_url"));
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
    ) -> std::result::Result<P2pOptions, RuntimeError> {
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
    ) -> std::result::Result<P2pOptions, RuntimeError> {
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
struct NodePinnedHostInput {
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

fn parse_signing_pin_b64(encoded: &str) -> std::result::Result<SigningKeyPin, String> {
    let bytes = b64url_decode(encoded).map_err(|e| e.to_string())?;
    parse_signing_pin(&bytes, "signing_pin").map_err(|e| e.reason)
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

fn lookup_v2_mailbox_secret_for_target(roster: &Roster, target_host_id: &str) -> Result<[u8; 32]> {
    let entry = roster
        .get(target_host_id)
        .ok_or_else(|| to_generic_err(format!("target '{target_host_id}' not found in roster")))?;
    if entry.state == PeerState::Revoked {
        return Err(to_generic_err(format!(
            "target '{target_host_id}' is revoked"
        )));
    }
    entry
        .v2_secrets
        .as_ref()
        .map(|s| *s.mailbox_secret())
        .ok_or_else(|| {
            to_generic_err(format!(
                "target '{target_host_id}' has no v2 mailbox_secret"
            ))
        })
}

fn lookup_v2_mailbox_secret_for_pair(
    roster: &Roster,
    pinned: Option<&PinnedHost>,
    endpoint: &str,
    now_unix: u64,
) -> Result<[u8; 32]> {
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
    Err(to_generic_err(
        "no matching v2 mailbox_secret in roster for /v2/relay endpoint",
    ))
}

async fn dial_endpoint_v2_with_options(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &EndpointTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> std::result::Result<Box<dyn PathStream>, RuntimeError> {
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
) -> std::result::Result<Box<dyn PathDialer>, RuntimeError> {
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

async fn dial_v2_with_wake_and_options(
    endpoint: &str,
    relay_host: Option<&str>,
    cfg: &EndpointTransportConfig,
    v2_mailbox_secret: Option<[u8; 32]>,
) -> Result<Box<dyn PathStream>> {
    if let Some(ref wake_cfg) = cfg.wake {
        let dialer = build_dialer_with_options(endpoint, relay_host, cfg, v2_mailbox_secret)
            .await
            .map_err(to_generic_err)?;
        let http_wake = Arc::new(
            HttpWakeProvider::new()
                .with_cooldown_secs(0)
                .with_timeout(Duration::from_millis(wake_cfg.timeout_ms)),
        );
        let wake_opts =
            WakeDialOptions::new(http_wake, wake_cfg.target.clone(), wake_cfg.secret.clone())
                .with_pre_wake(wake_cfg.pre_wake)
                .with_retry_delay(Duration::from_millis(wake_cfg.retry_delay_ms))
                .with_max_attempts(wake_cfg.max_attempts)
                .with_wake_timeout(Duration::from_millis(wake_cfg.timeout_ms));
        wake_and_dial_v2(&*dialer, endpoint, &wake_opts, now_unix())
            .await
            .map(|(stream, _)| stream)
            .map_err(to_generic_err)
    } else {
        dial_endpoint_v2_with_options(endpoint, relay_host, cfg, v2_mailbox_secret)
            .await
            .map_err(to_generic_err)
    }
}

async fn drive_v1_pair_initiator_with_roster_floors(
    stream: &mut dyn PathStream,
    identity: &EndpointIdentity,
    device_name: String,
    device_kind: String,
    code: String,
    roster: &Roster,
) -> std::result::Result<PairOutcome, RuntimeError> {
    let mut machine = PairingInitiator::new_with_min_wire_version(
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

#[napi]
pub fn device_id(static_pub: Buffer) -> Result<String> {
    Ok(core_device_id(&as_32(static_pub.as_ref(), "static_pub")?))
}

#[napi]
pub fn fingerprint_host(static_pub: Buffer) -> Result<String> {
    Ok(core_fingerprint_host(&as_32(
        static_pub.as_ref(),
        "static_pub",
    )?))
}

#[napi]
pub fn fingerprint_device(static_pub: Buffer) -> Result<String> {
    Ok(core_fingerprint_device(&as_32(
        static_pub.as_ref(),
        "static_pub",
    )?))
}

#[napi]
pub fn pairing_sas(handshake_hash: Buffer) -> Result<String> {
    Ok(core_pairing_sas(&as_32(
        handshake_hash.as_ref(),
        "handshake_hash",
    )?))
}

#[napi]
pub async fn compute_code_mac(code: String, handshake_hash: Buffer) -> Result<Buffer> {
    let hh = as_32(handshake_hash.as_ref(), "handshake_hash")?;
    let mac = tokio::task::spawn_blocking(move || core_compute_code_mac(&code, &hh))
        .await
        .map_err(to_generic_err)?
        .map_err(to_generic_err)?;
    Ok(Buffer::from(mac.to_vec()))
}

#[napi]
pub fn verify_rotation_chain_json(
    pinned_signing_b64: String,
    pinned_static_b64: String,
    pinned_seq: f64,
    chain_json: String,
    cur_static_b64: String,
    cur_signing_b64: String,
) -> Result<f64> {
    let pinned_seq_u64 = f64_to_u64(pinned_seq, "pinned_seq")?;
    let psig = HybridSigningPublicKey::from_b64url(&pinned_signing_b64).map_err(to_generic_err)?;
    let pstat = b64url_decode_array::<32>(&pinned_static_b64).map_err(to_generic_err)?;
    let cstat = b64url_decode_array::<32>(&cur_static_b64).map_err(to_generic_err)?;
    let csig = HybridSigningPublicKey::from_b64url(&cur_signing_b64).map_err(to_generic_err)?;
    let chain: Vec<RotationRecord> = serde_json::from_str(&chain_json).map_err(to_generic_err)?;
    let seq = verify_rotation_chain(&psig, &pstat, pinned_seq_u64, &chain, &cstat, &csig)
        .map_err(to_generic_err)?;
    u64_to_f64(seq)
}

#[napi]
pub fn verify_grant_json(
    grant_json: String,
    issuer_keys_json: String,
    expected_subject: String,
    expected_root_issuer: String,
    requested_cap: String,
    now_unix_secs: f64,
    crl_json: Option<String>,
) -> Result<bool> {
    let now_u64 = f64_to_u64(now_unix_secs, "now_unix_secs")?;
    let grant: Grant = serde_json::from_str(&grant_json).map_err(to_generic_err)?;
    let key_map_raw: HashMap<String, String> =
        serde_json::from_str(&issuer_keys_json).map_err(to_generic_err)?;
    let mut key_map = HashMap::with_capacity(key_map_raw.len());
    for (id, b64) in key_map_raw {
        let k = HybridSigningPublicKey::from_b64url(&b64).map_err(to_generic_err)?;
        key_map.insert(id, k);
    }
    let crl: Option<RevocationList> = match crl_json {
        Some(s) if !s.is_empty() => Some(serde_json::from_str(&s).map_err(to_generic_err)?),
        _ => None,
    };
    let (res, _) = authorize_grant(
        Some(&grant),
        &expected_subject,
        &expected_root_issuer,
        &requested_cap,
        now_u64,
        crl.as_ref(),
        |id| key_map.get(id).cloned(),
    );
    Ok(res.is_ok())
}

#[napi]
pub struct Endpoint {
    store: Option<Arc<StateStore>>,
    store_lock: Arc<AsyncMutex<()>>,
    identity: Arc<EndpointIdentity>,
    roster: Arc<StdMutex<Roster>>,
    pair_mgr: Arc<StdMutex<PairingManager>>,
    router: InboundRouter,
    v2_state: Arc<V2ResponderState>,
    transport_cfg: StdMutex<EndpointTransportConfig>,
    self_m2m_enabled: AtomicBool,
    m2m_enabled: AtomicBool,
}

impl Endpoint {
    fn persist_roster(&self, roster: &Roster) -> Result<()> {
        if let Some(store) = &self.store {
            store.save_roster(roster).map_err(to_generic_err)?;
        }
        Ok(())
    }

    fn sync_roster_from_store(&self) -> Result<()> {
        if let Some(store) = &self.store {
            let disk = store.load_roster().map_err(to_generic_err)?;
            let mut guard = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = disk;
        }
        Ok(())
    }

    fn snapshot_transport_cfg(&self) -> EndpointTransportConfig {
        self.transport_cfg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn refresh_m2m_enabled(&self, roster: &Roster) {
        let enabled = self.self_m2m_enabled.load(Ordering::Acquire)
            || roster
                .trust_anchors()
                .any(|(_, a)| a.state == AnchorState::Active);
        self.m2m_enabled.store(enabled, Ordering::Release);
    }

    fn spawn_listener(&self, listener: Box<dyn PathListener>) {
        self.router
            .spawn_listener(&tokio::runtime::Handle::current(), listener);
    }
}

#[napi]
impl Endpoint {
    #[napi(constructor)]
    pub fn new(state_dir: Option<String>, host_id: Option<String>) -> Result<Self> {
        let host_opt = host_id.as_deref();
        let (store, identity, roster) = if let Some(dir) = state_dir.filter(|s| !s.is_empty()) {
            let store = Arc::new(StateStore::open_or_create(dir).map_err(to_generic_err)?);
            let identity = store
                .load_or_generate_identity(host_opt)
                .map_err(to_generic_err)?;
            let roster = store.load_roster().map_err(to_generic_err)?;
            (Some(store), identity, roster)
        } else {
            let mut identity = EndpointIdentity::generate().map_err(to_generic_err)?;
            if let Some(h) = host_opt
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
            store,
            store_lock: Arc::new(AsyncMutex::new(())),
            identity: Arc::new(identity),
            roster: Arc::new(StdMutex::new(roster)),
            pair_mgr: Arc::new(StdMutex::new(PairingManager::new(PairingConfig::default()))),
            router: InboundRouter::new(),
            v2_state: Arc::new(V2ResponderState::new()),
            transport_cfg: StdMutex::new(EndpointTransportConfig::default()),
            self_m2m_enabled: AtomicBool::new(false),
            m2m_enabled: AtomicBool::new(has_active_anchor),
        })
    }

    #[napi]
    pub fn info_json(&self) -> String {
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

    #[napi]
    pub async fn serve_direct(&self, listen_addr: Option<String>) -> Result<String> {
        let addr: SocketAddr = listen_addr
            .as_deref()
            .unwrap_or("127.0.0.1:0")
            .parse()
            .map_err(|e| Error::new(Status::InvalidArg, format!("invalid address: {e}")))?;
        let listener = DirectListener::bind(addr, None)
            .await
            .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        Ok(ep)
    }

    #[napi]
    pub async fn serve_relay(
        &self,
        relay_url: String,
        expected_host: Option<String>,
    ) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        let key = self.identity.signing_key().ed25519_signing_key();
        let listener = RelayListener::bind_with_auth(
            relay_url,
            expected_host,
            key,
            DEFAULT_WRITE_TIMEOUT,
            cfg.relay_auth.clone(),
        )
        .await
        .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        Ok(ep)
    }

    #[napi(js_name = "serveP2p")]
    pub async fn serve_p2p(&self, relay_mode: Option<String>) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        let opts = cfg
            .build_p2p_listener_options(relay_mode.as_deref())
            .map_err(to_invalid_arg)?;
        let seed = self.identity.derive_p2p_identity_seed();
        let listener = P2pListener::bind_with_options(opts, Some(seed))
            .await
            .map_err(to_generic_err)?;
        let ep = listener.local_endpoint();
        self.spawn_listener(Box::new(listener));
        Ok(ep)
    }

    #[napi]
    pub fn issue_code(&self, kind: Option<String>) -> Result<String> {
        let pk = match kind.as_deref() {
            None | Some("" | "lan") => PairingCodeKind::Lan2Group,
            Some("remote") => PairingCodeKind::Remote3Group,
            Some(other) => {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!("invalid pairing code kind '{other}'"),
                ));
            }
        };
        let mut mgr = self.pair_mgr.lock().expect("pair_mgr mutex poisoned");
        mgr.issue_code(pk, now_unix()).map_err(to_generic_err)
    }

    #[napi]
    pub async fn pair_initiate(
        &self,
        endpoint: String,
        code: String,
        relay_host: Option<String>,
        name: Option<String>,
        kind: Option<String>,
    ) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        let roster_snapshot = {
            self.roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        let v2_secret = if is_v2_relay_endpoint(&endpoint) {
            Some(lookup_v2_mailbox_secret_for_pair(
                &roster_snapshot,
                None,
                &endpoint,
                now_unix(),
            )?)
        } else {
            None
        };
        let mut stream =
            dial_endpoint_v2_with_options(&endpoint, relay_host.as_deref(), &cfg, v2_secret)
                .await
                .map_err(to_generic_err)?;
        let device_name = name.unwrap_or_else(|| "node-device".to_owned());
        let device_kind = kind.unwrap_or_else(|| "node".to_owned());
        let outcome = if let Some(ref store) = self.store {
            drive_pair_initiator_with_store(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                None,
                store,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
            .map(|r| r.outcome)
        } else {
            drive_v1_pair_initiator_with_roster_floors(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                &roster_snapshot,
            )
            .await
        };
        let _ = stream.close().await;
        let outcome = outcome.map_err(to_generic_err)?;

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
                let mut roster = self
                    .roster
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                pin_res.map_err(to_generic_err)?;
                self.persist_roster(&roster)?;
                Ok(serde_json::json!({
                    "device_id": device_id,
                    "host_id": host_id,
                    "sas": pairing_sas,
                    "status": if host_pin_verified { "active" } else { "pending" },
                    "host_confirmed": host_pin_verified,
                })
                .to_string())
            }
            PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                Err(to_generic_err("unexpected responder outcome"))
            }
            PairOutcome::InitiatorEnrolled { .. } => {
                Err(to_generic_err("unexpected m2m enrollment outcome"))
            }
        }
    }

    #[napi]
    pub async fn pair_accept(&self, timeout_ms: Option<f64>) -> Result<String> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        let policy = if self.m2m_enabled.load(Ordering::Acquire) {
            EnrollmentPolicy::enabled_default()
        } else {
            EnrollmentPolicy::default()
        };
        let (mut stream, guard) = match self.router.recv_pair(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting pair")),
        };

        let path_kind = pairing_path_kind_for_provider(stream.provider_id());
        let res = drive_pair_responder_with_policy_and_store(
            stream.as_mut(),
            &self.identity,
            &self.pair_mgr,
            &self.roster,
            self.store.as_deref(),
            path_kind,
            now_unix(),
            policy,
            Some(self.router.rate_limiter()),
            Some(guard),
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .map_err(to_generic_err)?;

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
            PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            PairOutcome::InitiatorPending { .. } | PairOutcome::InitiatorEnrolled { .. } => {
                Err(to_generic_err("unexpected initiator outcome"))
            }
        }
    }

    #[napi]
    pub fn confirm_peer(&self, peer_id: String, sas: Option<String>) -> Result<()> {
        let mut roster = self
            .roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        roster
            .confirm_peer(&peer_id, sas.as_deref())
            .map_err(to_generic_err)?;
        self.persist_roster(&roster)
    }

    #[napi]
    pub fn mint_grant(
        &self,
        peer_id: String,
        caps: Vec<String>,
        ttl_secs: Option<f64>,
    ) -> Result<String> {
        let ttl = match ttl_secs {
            Some(v) => f64_to_u64(v, "ttl_secs")?,
            None => 3600,
        };
        let nonce = random_bytes::<16>().map_err(to_generic_err)?;
        let mut roster = self
            .roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = now_unix();
        let grant = roster
            .mint_grant(
                &self.identity,
                &peer_id,
                caps,
                now,
                now.saturating_add(ttl),
                nonce,
            )
            .map_err(to_generic_err)?;
        self.persist_roster(&roster)?;
        serde_json::to_string(&grant).map_err(to_generic_err)
    }

    #[napi]
    pub fn revoke_peer(&self, peer_id: String) -> Result<()> {
        let mut roster = self
            .roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        roster.revoke_peer(&peer_id).map_err(to_generic_err)?;
        self.persist_roster(&roster)?;
        self.refresh_m2m_enabled(&roster);
        Ok(())
    }

    #[napi]
    pub fn add_trust_anchor(&self, anchor_id: String, signing_pub: Buffer) -> Result<()> {
        let key = parse_hybrid_signing_pub(signing_pub.as_ref(), "signing_pub")?;
        let mut roster = self
            .roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        roster
            .add_trust_anchor(anchor_id, key)
            .map_err(to_generic_err)?;
        self.persist_roster(&roster)?;
        self.refresh_m2m_enabled(&roster);
        self.router.set_pair_enabled(true);
        Ok(())
    }

    #[napi]
    pub fn revoke_trust_anchor(&self, anchor_id: String) -> Result<()> {
        let mut roster = self
            .roster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        roster
            .revoke_trust_anchor(&anchor_id)
            .map_err(to_generic_err)?;
        self.persist_roster(&roster)?;
        self.refresh_m2m_enabled(&roster);
        Ok(())
    }

    #[napi]
    pub fn mint_enrollment_token(
        &self,
        target_host_id: String,
        subject: Option<String>,
        ttl_secs: Option<f64>,
    ) -> Result<String> {
        let ttl = match ttl_secs {
            Some(v) => f64_to_u64(v, "ttl_secs")?,
            None => 900,
        };
        let nonce = random_bytes::<16>().map_err(to_generic_err)?;
        let token = core_mint_enrollment_token(
            &self.identity,
            &target_host_id,
            subject.as_deref(),
            now_unix(),
            ttl,
            nonce,
        )
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        if target_host_id == self.identity.host_id() {
            self.self_m2m_enabled.store(true, Ordering::Release);
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.refresh_m2m_enabled(&roster);
            self.router.set_pair_enabled(true);
        }
        serde_json::to_string(&token).map_err(to_generic_err)
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_initiate(
        &self,
        endpoint: String,
        host_id: String,
        host_static_pub: Buffer,
        host_signing_pub: Buffer,
        token_json: String,
        relay_host: Option<String>,
        host_rotation_seq: Option<f64>,
        name: Option<String>,
        kind: Option<String>,
    ) -> Result<String> {
        let static_pub = as_32(host_static_pub.as_ref(), "host_static_pub")?;
        let signing_pin = parse_signing_pin(host_signing_pub.as_ref(), "host_signing_pub")?;
        let rot_seq = match host_rotation_seq {
            Some(v) => f64_to_u64(v, "host_rotation_seq")?,
            None => 0,
        };
        let token: Grant = serde_json::from_str(&token_json)
            .map_err(|e| Error::new(Status::InvalidArg, format!("invalid token_json: {e}")))?;
        let pinned_host = PinnedHost {
            host_id: Some(host_id),
            static_pub,
            signing_pin,
            rotation_seq: rot_seq,
        };

        let cfg = self.snapshot_transport_cfg();
        let (fallback_floor, v2_secret) = {
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let floor = pinned_pairing_floor(&roster, &pinned_host);
            let sec = if is_v2_relay_endpoint(&endpoint) {
                Some(lookup_v2_mailbox_secret_for_pair(
                    &roster,
                    Some(&pinned_host),
                    &endpoint,
                    now_unix(),
                )?)
            } else {
                None
            };
            (floor, sec)
        };
        let mut stream =
            dial_endpoint_v2_with_options(&endpoint, relay_host.as_deref(), &cfg, v2_secret)
                .await
                .map_err(to_generic_err)?;
        let device_name = name.unwrap_or_else(|| "node-machine".to_owned());
        let device_kind = kind.unwrap_or_else(|| "machine".to_owned());
        let res = if let Some(ref store) = self.store {
            drive_m2m_enroll_initiator_with_store(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                token,
                pinned_host,
                store,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        } else {
            drive_m2m_enroll_initiator_with_floor(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                token,
                pinned_host,
                fallback_floor,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        let _ = stream.close().await;
        let res = res.map_err(to_generic_err)?;

        match res.outcome {
            PairOutcome::InitiatorEnrolled {
                device_id,
                host_id,
                host_static_pub,
                host_signing_pub,
                host_rotation_seq,
                token_nonce,
            } => {
                let mut roster = self
                    .roster
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                roster
                    .insert_pinned_host(
                        host_id.clone(),
                        host_id.clone(),
                        host_static_pub,
                        Some(host_signing_pub),
                        host_rotation_seq,
                        Vec::new(),
                    )
                    .map_err(to_generic_err)?;
                self.persist_roster(&roster)?;
                Ok(serde_json::json!({
                    "device_id": device_id,
                    "host_id": host_id,
                    "status": "active",
                    "host_rotation_seq": host_rotation_seq,
                    "token_nonce": token_nonce,
                })
                .to_string())
            }
            PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            PairOutcome::InitiatorPending { .. } => {
                Err(to_generic_err("unexpected human pending outcome"))
            }
            PairOutcome::ResponderPending { .. } | PairOutcome::ResponderEnrolled { .. } => {
                Err(to_generic_err("unexpected responder outcome"))
            }
        }
    }

    #[napi]
    pub async fn connect(
        &self,
        endpoint: String,
        target_host_id: String,
        grant_json: Option<String>,
        relay_host: Option<String>,
    ) -> Result<Session> {
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.is_empty() => Some(serde_json::from_str(&s).map_err(to_generic_err)?),
            _ => None,
        };
        let cfg = self.snapshot_transport_cfg();
        let v2_secret = if is_v2_relay_endpoint(&endpoint) {
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Some(lookup_v2_mailbox_secret_for_target(
                &roster,
                &target_host_id,
            )?)
        } else {
            None
        };
        let stream =
            dial_endpoint_v2_with_options(&endpoint, relay_host.as_deref(), &cfg, v2_secret)
                .await
                .map_err(to_generic_err)?;
        let driver = match SessionDriver::connect_locked(
            stream,
            &self.identity,
            &target_host_id,
            grant,
            &self.roster,
            now_unix(),
        )
        .await
        {
            Ok(drv) => {
                persist_store_roster(self.store.as_ref(), &self.roster)?;
                drv
            }
            Err(e) => {
                if let Err(pe) = persist_store_roster(self.store.as_ref(), &self.roster) {
                    return Err(Error::new(Status::GenericFailure, format!("{e} ({pe})")));
                }
                return Err(to_generic_err(e));
            }
        };

        Ok(Session {
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(SessionBackend::V1(driver.into_concurrent())),
        })
    }

    #[napi]
    pub async fn accept_session(&self, timeout_ms: Option<f64>) -> Result<Session> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        let (stream, guard) = match self.router.recv_session(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting session")),
        };

        let driver = SessionDriver::accept_locked(
            stream,
            &self.identity,
            &self.roster,
            now_unix(),
            Some(self.router.rate_limiter()),
            Some(guard),
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .map_err(to_generic_err)?;

        Ok(Session {
            store: self.store.clone(),
            roster: Arc::clone(&self.roster),
            session: Arc::new(SessionBackend::V1(driver.into_concurrent())),
        })
    }

    #[napi(js_name = "configureTransportsJson")]
    pub fn configure_transports_json(&self, transport_config_json: String) -> Result<()> {
        let input: TransportConfigInput =
            serde_json::from_str(&transport_config_json).map_err(|e| {
                to_invalid_arg(format!(
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

    #[napi(js_name = "mintRelayTicket")]
    pub fn mint_relay_ticket(
        &self,
        relay_host: String,
        role: Option<String>,
        target_pub_or_wildcard: Option<String>,
        ttl_secs: Option<f64>,
    ) -> Result<String> {
        let ttl = match ttl_secs {
            Some(v) => f64_to_u64(v, "ttl_secs")?,
            None => 3600,
        };
        let role_enum = match role.as_deref().map(str::trim) {
            None | Some("" | "any") => RelayAuthRole::Any,
            Some("register") => RelayAuthRole::Register,
            Some("dial") => RelayAuthRole::Dial,
            Some(other) => {
                return Err(to_invalid_arg(format!(
                    "invalid relay ticket role '{other}'"
                )));
            }
        };
        let target_s = target_pub_or_wildcard
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("*");
        let ticket = self
            .identity
            .mint_relay_ticket(&relay_host, role_enum, target_s, now_unix(), ttl)
            .map_err(to_invalid_arg)?;
        let json = Zeroizing::new(canonical_json(&ticket).map_err(to_generic_err)?);
        Ok(json.to_string())
    }

    #[napi(js_name = "serveRelayV2")]
    pub async fn serve_relay_v2(
        &self,
        relay_url: String,
        expected_host: Option<String>,
        peer_id: Option<String>,
    ) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        let secrets: Vec<[u8; 32]> = {
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(pid) = peer_id.as_deref().filter(|s| !s.is_empty()) {
                vec![lookup_v2_mailbox_secret_for_target(&roster, pid)?]
            } else {
                let list: Vec<[u8; 32]> = roster
                    .entries()
                    .filter(|(_, e)| e.state == PeerState::Active)
                    .filter_map(|(_, e)| e.v2_secrets.as_ref().map(|s| *s.mailbox_secret()))
                    .collect();
                if list.is_empty() {
                    return Err(to_generic_err(
                        "no active v2 peers with mailbox_secret in roster",
                    ));
                }
                list
            }
        };

        let mut bound_listeners: Vec<RelayV2Listener> = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let lcfg = RelayV2ListenerConfig {
                expected_host: expected_host.clone(),
                write_timeout: DEFAULT_WRITE_TIMEOUT,
                allow_insecure_ws: false,
                replay_cache: None,
                unix_secs: None,
                auth: cfg.relay_auth.clone(),
            };
            let listener = RelayV2Listener::bind_with_config(&relay_url, secret, lcfg)
                .await
                .map_err(to_generic_err)?;
            bound_listeners.push(listener);
        }
        let first_ep = bound_listeners.first().map(|l| l.local_endpoint());
        for listener in bound_listeners {
            self.spawn_listener(Box::new(listener));
        }
        Ok(first_ep.unwrap_or(relay_url))
    }

    #[napi(js_name = "pairV2Initiate")]
    pub async fn pair_v2_initiate(
        &self,
        endpoint: String,
        code: String,
        relay_host: Option<String>,
        name: Option<String>,
        kind: Option<String>,
        pinned_host_json: Option<String>,
    ) -> Result<String> {
        let cfg = self.snapshot_transport_cfg();
        let roster_snapshot = {
            self.roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };

        let v2_pinned = match pinned_host_json.as_deref().filter(|s| !s.is_empty()) {
            Some(raw) => {
                let pin_in: NodePinnedHostInput = serde_json::from_str(raw).map_err(|e| {
                    to_invalid_arg(format!(
                        "invalid pinned_host_json: {:?} at line {} column {}",
                        e.classify(),
                        e.line(),
                        e.column()
                    ))
                })?;
                let static_pub =
                    b64url_decode_array::<32>(&pin_in.static_pub_b64).map_err(to_invalid_arg)?;
                let signing_pin =
                    parse_signing_pin_b64(&pin_in.signing_pin_b64).map_err(to_invalid_arg)?;
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
                Some(V2PinnedHost::new(pinned, floor).map_err(to_invalid_arg)?)
            }
            None => None,
        };

        let v2_secret = if is_v2_relay_endpoint(&endpoint) {
            Some(lookup_v2_mailbox_secret_for_pair(
                &roster_snapshot,
                v2_pinned.as_ref().map(|p| &p.pinned),
                &endpoint,
                now_unix(),
            )?)
        } else {
            None
        };

        let device_name = name.unwrap_or_else(|| "node-device".to_owned());
        let device_kind = kind.unwrap_or_else(|| "node".to_owned());
        let mut stream =
            dial_endpoint_v2_with_options(&endpoint, relay_host.as_deref(), &cfg, v2_secret)
                .await
                .map_err(to_generic_err)?;
        let pair_res = if let Some(ref store) = self.store {
            drive_v2_pake_pair_initiator_with_store(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                v2_pinned,
                "paired-host".to_owned(),
                Vec::new(),
                store,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        } else {
            drive_v2_pake_pair_initiator_with_timeout(
                stream.as_mut(),
                &self.identity,
                device_name,
                device_kind,
                code,
                v2_pinned,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        let _ = stream.close().await;
        let pair_res = pair_res.map_err(to_generic_err)?;

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
                if self.store.is_some() {
                    self.sync_roster_from_store()?;
                } else {
                    let mut roster = self
                        .roster
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    roster
                        .apply_v2_pair_initiator_outcome(
                            &pair_res.outcome,
                            h_id.clone(),
                            Vec::new(),
                        )
                        .map_err(to_generic_err)?;
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
            V2PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            V2PairOutcome::ResponderPending { .. } => {
                Err(to_generic_err("unexpected responder outcome"))
            }
        }
    }

    #[napi(js_name = "pairV2Accept")]
    pub async fn pair_v2_accept(&self, timeout_ms: Option<f64>) -> Result<String> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        let (mut stream, guard) = match self.router.recv_v2_pair(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting v2 pair")),
        };
        let path_kind = pairing_path_kind_for_provider(stream.provider_id());
        let pair_res = if let Some(ref store) = self.store {
            drive_v2_pake_pair_responder_with_store(
                stream.as_mut(),
                &self.identity,
                &self.pair_mgr,
                store,
                &self.store_lock,
                path_kind,
                now_unix(),
                &self.v2_state,
                Some(self.router.v2_pair_rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        } else {
            drive_v2_pake_pair_responder_with_options(
                stream.as_mut(),
                &self.identity,
                &self.pair_mgr,
                &self.roster,
                path_kind,
                now_unix(),
                &self.v2_state,
                Some(self.router.v2_pair_rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        }
        .map_err(to_generic_err)?;

        match pair_res.outcome {
            V2PairOutcome::ResponderPending {
                device_id,
                pairing_sas,
                name,
                kind,
                ..
            } => {
                self.sync_roster_from_store()?;
                Ok(serde_json::json!({
                    "device_id": device_id,
                    "sas": pairing_sas,
                    "name": name,
                    "kind": kind,
                    "wire_version": 2,
                })
                .to_string())
            }
            V2PairOutcome::Rejected { error } => Err(to_generic_err(error)),
            V2PairOutcome::InitiatorPending { .. } => {
                Err(to_generic_err("unexpected initiator outcome"))
            }
        }
    }

    #[napi(js_name = "connectV2")]
    pub async fn connect_v2(
        &self,
        endpoint: String,
        target_host_id: String,
        grant_json: Option<String>,
        relay_host: Option<String>,
    ) -> Result<Session> {
        let grant: Option<Grant> = match grant_json {
            Some(s) if !s.is_empty() => Some(serde_json::from_str(&s).map_err(to_invalid_arg)?),
            _ => None,
        };
        let cfg = self.snapshot_transport_cfg();
        let v2_secret = if is_v2_relay_endpoint(&endpoint) {
            let roster = self
                .roster
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Some(lookup_v2_mailbox_secret_for_target(
                &roster,
                &target_host_id,
            )?)
        } else {
            None
        };
        let stream =
            dial_v2_with_wake_and_options(&endpoint, relay_host.as_deref(), &cfg, v2_secret)
                .await?;
        let driver_res = if let Some(ref store) = self.store {
            V2SessionDriver::connect_with_store(
                stream,
                &self.identity,
                &target_host_id,
                grant,
                store,
                &self.store_lock,
                now_unix(),
            )
            .await
        } else {
            V2SessionDriver::connect_locked(
                stream,
                &self.identity,
                &target_host_id,
                grant,
                &self.roster,
                now_unix(),
            )
            .await
        };
        match driver_res {
            Ok(driver) => {
                if self.store.is_some() {
                    self.sync_roster_from_store()?;
                }
                Ok(Session {
                    store: self.store.clone(),
                    roster: Arc::clone(&self.roster),
                    session: Arc::new(SessionBackend::V2(driver.into_concurrent())),
                })
            }
            Err(e) => {
                if self.store.is_some() {
                    let _ = self.sync_roster_from_store();
                }
                Err(to_generic_err(e))
            }
        }
    }

    #[napi(js_name = "acceptV2")]
    pub async fn accept_v2(&self, timeout_ms: Option<f64>) -> Result<Session> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        let (stream, guard) = match self.router.recv_v2_session(wait).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Err(to_generic_err("listener closed")),
            Err(()) => return Err(to_generic_err("timed out accepting v2 session")),
        };
        let driver_res = if let Some(ref store) = self.store {
            V2SessionDriver::accept_with_store(
                stream,
                &self.identity,
                store,
                &self.store_lock,
                now_unix(),
                &self.v2_state,
                Some(self.router.v2_session_rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        } else {
            V2SessionDriver::accept_locked(
                stream,
                &self.identity,
                &self.roster,
                now_unix(),
                &self.v2_state,
                Some(self.router.v2_session_rate_limiter()),
                Some(guard),
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        };
        match driver_res {
            Ok(driver) => {
                if self.store.is_some() {
                    self.sync_roster_from_store()?;
                }
                Ok(Session {
                    store: self.store.clone(),
                    roster: Arc::clone(&self.roster),
                    session: Arc::new(SessionBackend::V2(driver.into_concurrent())),
                })
            }
            Err(e) => {
                if self.store.is_some() {
                    let _ = self.sync_roster_from_store();
                }
                Err(to_generic_err(e))
            }
        }
    }

    #[napi]
    pub fn close(&self) {
        self.router.close();
    }
}

enum SessionBackend {
    V1(ConcurrentSession),
    V2(ConcurrentV2Session),
}

impl SessionBackend {
    async fn send_data(&self, payload: &[u8]) -> std::result::Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_data(payload).await,
            Self::V2(s) => s.send_data(payload).await,
        }
    }

    async fn next_event_locked_now(
        &self,
        roster: &StdMutex<Roster>,
    ) -> std::result::Result<Option<SessionEvent>, RuntimeError> {
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
    ) -> (
        std::result::Result<(), CoreError>,
        tendril_core::grants::AuditEvent,
    ) {
        match self {
            Self::V1(s) => s.authorize_locked(requested_cap, now_unix, roster),
            Self::V2(s) => s.authorize_locked(requested_cap, now_unix, roster),
        }
    }

    async fn send_rekey(&self) -> std::result::Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_rekey().await,
            Self::V2(s) => s.send_rekey().await,
        }
    }

    async fn send_close(&self, code: u16, reason: &str) -> std::result::Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_close(code, reason).await,
            Self::V2(s) => s.send_close(code, reason).await,
        }
    }
}

#[napi]
pub struct Session {
    store: Option<Arc<StateStore>>,
    roster: Arc<StdMutex<Roster>>,
    session: Arc<SessionBackend>,
}

#[napi]
impl Session {
    #[napi]
    pub async fn send_data(&self, payload: Buffer) -> Result<()> {
        self.session
            .send_data(payload.as_ref())
            .await
            .map_err(to_generic_err)
    }

    #[napi]
    pub async fn poll_event(&self, timeout_ms: Option<f64>) -> Result<String> {
        let wait = Duration::from_millis(f64_to_timeout_ms(timeout_ms, 5000)?);
        match timeout(wait, self.session.next_event_locked_now(&self.roster)).await {
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
                        if matches!(self.session.as_ref(), SessionBackend::V2(_))
                            && let Some(ref store) = self.store
                        {
                            let disk = store.load_roster().map_err(to_generic_err)?;
                            let mut guard = self
                                .roster
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            *guard = disk;
                        } else {
                            persist_store_roster(self.store.as_ref(), &self.roster)?;
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
                if matches!(self.session.as_ref(), SessionBackend::V2(_))
                    && let Some(ref store) = self.store
                {
                    if let Ok(disk) = store.load_roster() {
                        let mut guard = self
                            .roster
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        *guard = disk;
                    }
                    Err(to_generic_err(e))
                } else if let Err(pe) = persist_store_roster(self.store.as_ref(), &self.roster) {
                    Err(Error::new(Status::GenericFailure, format!("{e} ({pe})")))
                } else {
                    Err(to_generic_err(e))
                }
            }
            Err(_) => Ok(serde_json::json!({ "status": "would_block" }).to_string()),
        }
    }

    #[napi]
    pub async fn authorize(&self, requested_cap: String) -> bool {
        self.session
            .authorize_locked(&requested_cap, now_unix(), &self.roster)
            .0
            .is_ok()
    }

    #[napi]
    pub async fn rekey(&self) -> Result<()> {
        self.session.send_rekey().await.map_err(to_generic_err)
    }

    #[napi]
    pub async fn close(&self, code: Option<f64>, reason: Option<String>) -> Result<()> {
        let close_code = f64_to_u16(code, 1000, "code")?;
        self.session
            .send_close(close_code, reason.as_deref().unwrap_or("normal"))
            .await
            .map_err(to_generic_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendril_core::grants::{RevocationListUnsigned, sign_crl};

    #[tokio::test]
    async fn v2_mid_session_crl_revocation_closes_session() {
        let uniq = format!(
            "tendril-node-crl-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base_dir = std::env::temp_dir().join(uniq);
        let host_dir = base_dir.join("host");
        let cli_dir = base_dir.join("cli");
        std::fs::create_dir_all(&host_dir).unwrap();
        std::fs::create_dir_all(&cli_dir).unwrap();

        let host_ep = Endpoint::new(
            Some(host_dir.to_string_lossy().into_owned()),
            Some("crl-host".to_owned()),
        )
        .unwrap();
        let cli_ep = Endpoint::new(
            Some(cli_dir.to_string_lossy().into_owned()),
            Some("crl-cli".to_owned()),
        )
        .unwrap();

        let addr = host_ep
            .serve_direct(Some("127.0.0.1:0".to_owned()))
            .await
            .unwrap();
        let code = host_ep.issue_code(Some("lan".to_owned())).unwrap();
        let (cli_pair_raw, host_acc_raw) = tokio::join!(
            cli_ep.pair_v2_initiate(
                addr.clone(),
                code,
                None,
                Some("crl-cli".to_owned()),
                Some("node".to_owned()),
                None,
            ),
            host_ep.pair_v2_accept(Some(5000.0)),
        );
        let cli_pair: serde_json::Value = serde_json::from_str(&cli_pair_raw.unwrap()).unwrap();
        let host_acc: serde_json::Value = serde_json::from_str(&host_acc_raw.unwrap()).unwrap();
        let sas = cli_pair["sas"].as_str().unwrap().to_owned();
        let dev_id = host_acc["device_id"].as_str().unwrap().to_owned();

        host_ep
            .confirm_peer(dev_id.clone(), Some(sas.clone()))
            .unwrap();
        cli_ep
            .confirm_peer("crl-host".to_owned(), Some(sas))
            .unwrap();
        let grant_json = host_ep
            .mint_grant(dev_id, vec!["fs.read".to_owned()], Some(3600.0))
            .unwrap();
        let grant: Grant = serde_json::from_str(&grant_json).unwrap();
        let crl_ts = grant.not_before.clone();
        let revoked_nonce = grant.nonce.clone();
        host_ep.close();

        let host_store = StateStore::open_or_create(&host_dir).unwrap();
        let host_id = host_store.load_or_generate_identity(None).unwrap();
        let mut host_roster = host_store.load_roster().unwrap();
        let mut listener = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let v2_ep = listener.local_endpoint();
        let accept_handle = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            let mut drv = V2SessionDriver::accept(
                stream,
                &host_id,
                &mut host_roster,
                now_unix(),
                &Default::default(),
                None,
            )
            .await
            .unwrap();
            let crl = sign_crl(
                RevocationListUnsigned {
                    v: 1,
                    issuer: host_id.host_id().to_owned(),
                    seq: 1,
                    revoked_devices: Vec::new(),
                    revoked_nonces: vec![revoked_nonce],
                    ts: crl_ts,
                },
                host_id.signing_key(),
            )
            .unwrap();
            drv.send_revocation(&crl).await.unwrap();
            drv
        });

        let cli_sess = cli_ep
            .connect_v2(v2_ep, "crl-host".to_owned(), Some(grant_json), None)
            .await
            .unwrap();
        let mut closed_or_err = false;
        for _ in 0..4 {
            match cli_sess.poll_event(Some(2000.0)).await {
                Ok(ev_raw) => {
                    let ev: serde_json::Value = serde_json::from_str(&ev_raw).unwrap();
                    if ev["event"] == "closed" || ev["status"] == "eof" {
                        closed_or_err = true;
                        break;
                    }
                }
                Err(_) => {
                    closed_or_err = true;
                    break;
                }
            }
        }
        assert!(
            closed_or_err,
            "expected mid-session CRL revocation to close or error session"
        );
        assert!(!cli_sess.authorize("fs.read".to_owned()).await);
        let _ = accept_handle.await;
        cli_ep.close();

        let reloaded_roster = StateStore::open_or_create(&cli_dir)
            .unwrap()
            .load_roster()
            .unwrap();
        let persisted_crl = reloaded_roster
            .crl("crl-host")
            .expect("persisted CRL across reload");
        assert_eq!(persisted_crl.seq, 1);
        assert_eq!(persisted_crl.revoked_nonces, vec![grant.nonce]);

        let _ = std::fs::remove_dir_all(&base_dir);
    }
}
