//! Optional opaque push wake-hint subsystem (`WakeProvider`).
//!
//! Core remains the trust boundary: wake signals carry only an epoch-blinded
//! [`WakeTag`] and tell a sleeping peer to poll its configured paths. Payloads
//! never carry plaintext, pairing codes, capability grants, `host_id`, or
//! identity keys. Pull-only endpoints use [`NoopWakeProvider`] by default.

pub mod apns_h2;

use std::collections::HashMap;
use std::fmt;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apns_h2::validate_apns_h2_endpoint_host;
pub use apns_h2::{
    APNS_JWT_REFRESH_SECS, ApnsH2Auth, ApnsH2WakeProvider, validate_apns_h2_endpoint_url,
    validate_apns_topic,
};
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tendril_core::crypto::{b64url_decode_array, b64url_encode, hkdf_sha256_32, random_bytes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::RuntimeError;
use crate::providers::egress::{DestClass, classify_destination};
use crate::providers::{
    ensure_rustls_ring_provider, is_loopback_host, is_metadata_or_link_local_ip,
};
use crate::redact::redact_url_str;
use crate::v2_driver::WakeDialOptions;

/// Byte length of an epoch-blinded [`WakeTag`].
pub const WAKE_TAG_LEN: usize = 16;

/// Duration of one wake tag rotation epoch in seconds (1 hour).
pub const WAKE_EPOCH_SECS: u64 = 3_600;

/// Default timeout for outbound HTTP/HTTPS wake-hint delivery.
pub const DEFAULT_WAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// Default per-target cooldown interval in seconds for wake coalescing.
pub const DEFAULT_WAKE_COALESCE_INTERVAL_SECS: u64 = 5;

/// Maximum accepted length for a wake endpoint URL.
pub const MAX_WAKE_ENDPOINT_URL_LEN: usize = 512;

/// Maximum number of distinct targets tracked by [`WakeCoalescer`].
pub const MAX_WAKE_COALESCE_TARGETS: usize = 1_024;

/// Maximum accepted byte size for inline APNs PEM credentials/certificates.
pub const MAX_WAKE_PEM_BYTES: usize = 16 * 1024;

/// Default static localization key for `MutableAlert` APNs wake notifications.
pub const DEFAULT_APNS_LOC_KEY: &str = "TENDRIL_WAKE_FALLBACK";

/// Maximum HTTP response bytes read from a wake endpoint.
pub(crate) const MAX_WAKE_RESPONSE_BYTES: usize = 4_096;

/// HKDF-SHA256 domain separation label for epoch-blinded wake tags.
const WAKE_TAG_HKDF_INFO: &[u8] = b"tendril/wake/epoch-tag/v1";

/// High-entropy 32-byte out-of-band secret used to derive epoch-blinded [`WakeTag`]s.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WakeSecret([u8; 32]);

impl WakeSecret {
    /// Generates a fresh 32-byte random wake secret from the OS CSPRNG.
    pub fn generate() -> Result<Self, RuntimeError> {
        Ok(Self(random_bytes::<32>()?))
    }

    /// Constructs a [`WakeSecret`] from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the epoch-blinded [`WakeTag`] for `unix_secs`.
    #[must_use]
    pub fn derive_tag(&self, unix_secs: u64) -> WakeTag {
        derive_epoch_wake_tag(&self.0, unix_secs)
    }
}

impl fmt::Debug for WakeSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WakeSecret").field(&"[REDACTED]").finish()
    }
}

/// Fixed 16-byte pseudonymous wake tag derived from a [`WakeSecret`] and hour epoch.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WakeTag([u8; WAKE_TAG_LEN]);

impl WakeTag {
    /// Constructs a [`WakeTag`] from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; WAKE_TAG_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw tag bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; WAKE_TAG_LEN] {
        &self.0
    }

    /// Encodes the tag as unpadded URL-safe base64.
    #[must_use]
    pub fn to_b64url(&self) -> String {
        b64url_encode(&self.0)
    }

    /// Decodes a [`WakeTag`] from unpadded URL-safe base64.
    pub fn from_b64url(encoded: &str) -> Result<Self, RuntimeError> {
        let bytes = b64url_decode_array::<WAKE_TAG_LEN>(encoded)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for WakeTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WakeTag").field(&self.to_b64url()).finish()
    }
}

impl fmt::Display for WakeTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_b64url())
    }
}

impl Serialize for WakeTag {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_b64url())
    }
}

impl<'de> Deserialize<'de> for WakeTag {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_b64url(&s).map_err(serde::de::Error::custom)
    }
}

/// Returns the quantized hour epoch index for `unix_secs`.
#[must_use]
pub const fn wake_epoch(unix_secs: u64) -> u64 {
    unix_secs / WAKE_EPOCH_SECS
}

/// Returns the quantized epoch start timestamp in seconds for `unix_secs`.
#[must_use]
pub const fn wake_epoch_start_secs(unix_secs: u64) -> u64 {
    wake_epoch(unix_secs) * WAKE_EPOCH_SECS
}

/// Derives an epoch-blinded [`WakeTag`] from an out-of-band `wake_secret` and `unix_secs`.
///
/// Using HKDF-SHA256 keyed by `wake_secret` with the hour epoch as salt prevents
/// push relays from correlating wake hints to `host_id`, `signing_pub`, or across hours.
#[must_use]
pub fn derive_epoch_wake_tag(wake_secret: &[u8; 32], unix_secs: u64) -> WakeTag {
    derive_tag_for_epoch(wake_secret, wake_epoch(unix_secs))
}

fn derive_tag_for_epoch(wake_secret: &[u8; 32], epoch: u64) -> WakeTag {
    let derived = hkdf_sha256_32(wake_secret, &epoch.to_be_bytes(), WAKE_TAG_HKDF_INFO);
    let mut tag = [0u8; WAKE_TAG_LEN];
    tag.copy_from_slice(&derived[..WAKE_TAG_LEN]);
    WakeTag(tag)
}

/// Verifies `candidate` against `wake_secret` across the `+-1` hour epoch window
/// around `now_unix_secs` to tolerate clock skew across hour boundaries.
#[must_use]
pub fn verify_epoch_wake_tag_window(
    wake_secret: &[u8; 32],
    candidate: &WakeTag,
    now_unix_secs: u64,
) -> bool {
    let current = wake_epoch(now_unix_secs);
    let mut matched = subtle::Choice::from(0u8);
    for epoch in [
        current.saturating_sub(1),
        current,
        current.saturating_add(1),
    ] {
        let expected = derive_tag_for_epoch(wake_secret, epoch);
        matched |= candidate.as_bytes().ct_eq(expected.as_bytes());
    }
    bool::from(matched)
}

/// Supported wake push transport adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeAdapterKind {
    UnifiedPush,
    Webhook,
    Apns,
    ApnsH2,
    Fcm,
}

/// Alias for [`WakeAdapterKind`].
pub type WakeChannel = WakeAdapterKind;

/// APNs notification delivery mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApnsPushMode {
    /// Silent background push (`apns-push-type: background`, `apns-priority: 5`, `content-available: 1`).
    #[default]
    Background,
    /// User-visible NSE-wakeable alert (`apns-push-type: alert`, `apns-priority: 10`,
    /// `mutable-content: 1`, static `alert.loc-key` only).
    MutableAlert,
}

/// Validates a static APNs `loc-key` (`1..=64` ASCII `[A-Za-z0-9_.-]` bytes only).
///
/// Rejects dynamic text, format specifiers, arguments, whitespace, and peer identifiers.
pub fn validate_apns_loc_key(key: &str) -> Result<&str, RuntimeError> {
    if key.is_empty() || key.len() > 64 {
        return Err(RuntimeError::Protocol(
            "APNs loc-key must be 1..=64 ASCII characters".into(),
        ));
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(RuntimeError::Protocol(
            "APNs loc-key must contain only ASCII [A-Za-z0-9_.-]".into(),
        ));
    }
    Ok(key)
}

/// APNs push options attached to a [`WakeTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApnsOptions {
    pub mode: ApnsPushMode,
    pub loc_key: String,
}

impl Default for ApnsOptions {
    fn default() -> Self {
        Self {
            mode: ApnsPushMode::Background,
            loc_key: DEFAULT_APNS_LOC_KEY.to_owned(),
        }
    }
}

impl ApnsOptions {
    /// Constructs silent background APNs options.
    #[must_use]
    pub fn background() -> Self {
        Self::default()
    }

    /// Constructs `MutableAlert` APNs options with a validated static `loc-key`.
    pub fn mutable_alert(loc_key: &str) -> Result<Self, RuntimeError> {
        validate_apns_loc_key(loc_key)?;
        Ok(Self {
            mode: ApnsPushMode::MutableAlert,
            loc_key: loc_key.to_owned(),
        })
    }

    /// Validates the stored `loc_key`.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        validate_apns_loc_key(&self.loc_key)?;
        Ok(())
    }
}

pub(crate) fn strip_host_brackets(host: &str) -> &str {
    let trimmed = host.trim();
    trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed)
}

/// Validates a wake endpoint URL against SSRF, cleartext, and length rules.
///
/// Requires `https://` everywhere except `http://` on loopback hosts
/// (`127.0.0.0/8`, `::1`, `localhost`). Rejects userinfo, fragments, control
/// characters, URLs longer than 512 bytes, and metadata/link-local addresses.
pub fn validate_wake_endpoint_url(url_str: &str) -> Result<Url, RuntimeError> {
    if url_str.chars().any(char::is_control) {
        return Err(RuntimeError::Protocol(
            "wake endpoint URL contains control characters".into(),
        ));
    }
    let trimmed = url_str.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::Protocol(
            "wake endpoint URL must not be empty".into(),
        ));
    }
    if trimmed.len() > MAX_WAKE_ENDPOINT_URL_LEN {
        return Err(RuntimeError::Protocol(format!(
            "wake endpoint URL exceeds maximum length {MAX_WAKE_ENDPOINT_URL_LEN}"
        )));
    }
    let parsed = Url::parse(trimmed)
        .map_err(|err| RuntimeError::Protocol(format!("invalid wake endpoint URL: {err}")))?;
    let is_http = match parsed.scheme() {
        "https" => false,
        "http" => true,
        other => {
            return Err(RuntimeError::Protocol(format!(
                "unsupported wake endpoint URL scheme '{other}'"
            )));
        }
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RuntimeError::Protocol(
            "wake endpoint URL userinfo credentials are not permitted".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(RuntimeError::Protocol(
            "wake endpoint URL fragments are not permitted".into(),
        ));
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| RuntimeError::Protocol("wake endpoint URL is missing a host".into()))?;
    let bare = strip_host_brackets(host).trim_end_matches('.');
    if bare.eq_ignore_ascii_case("metadata.google.internal") {
        return Err(RuntimeError::Protocol(
            "cloud metadata hostname is not permitted".into(),
        ));
    }
    if let Ok(ip) = bare.parse::<IpAddr>()
        && is_metadata_or_link_local_ip(ip)
    {
        return Err(RuntimeError::Protocol(format!(
            "link-local or metadata address '{ip}' is not permitted"
        )));
    }
    if is_http && !is_loopback_host(bare) {
        return Err(RuntimeError::Protocol(
            "cleartext http:// wake endpoint is permitted only for loopback hosts".into(),
        ));
    }
    Ok(parsed)
}

/// Validated wake push destination with optional redacted bearer token and APNs options.
#[derive(Clone)]
pub struct WakeTarget {
    adapter: WakeAdapterKind,
    endpoint: Url,
    auth_token: Option<Zeroizing<String>>,
    apns_mode: ApnsPushMode,
    apns_loc_key: String,
    apns_topic: Option<String>,
}

impl WakeTarget {
    /// Creates a validated [`WakeTarget`] for `adapter` and `endpoint_url`.
    pub fn new(adapter: WakeAdapterKind, endpoint_url: &str) -> Result<Self, RuntimeError> {
        let endpoint = if adapter == WakeAdapterKind::ApnsH2 {
            validate_apns_h2_endpoint_url(endpoint_url)?
        } else {
            validate_wake_endpoint_url(endpoint_url)?
        };
        Ok(Self {
            adapter,
            endpoint,
            auth_token: None,
            apns_mode: ApnsPushMode::Background,
            apns_loc_key: DEFAULT_APNS_LOC_KEY.to_owned(),
            apns_topic: None,
        })
    }

    /// Attaches an optional bearer authorization token, rejecting control characters.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Result<Self, RuntimeError> {
        let token = token.into();
        if token.is_empty() || token.chars().any(char::is_control) {
            return Err(RuntimeError::Protocol(
                "wake auth token must be non-empty without control characters".into(),
            ));
        }
        self.auth_token = Some(Zeroizing::new(token));
        Ok(self)
    }

    /// Sets the APNs delivery mode (`Background` or `MutableAlert`).
    pub fn with_apns_mode(mut self, mode: ApnsPushMode) -> Result<Self, RuntimeError> {
        self.require_apns_adapter("apns_mode")?;
        self.apns_mode = mode;
        Ok(self)
    }

    /// Sets and validates the static APNs `alert.loc-key`.
    pub fn with_apns_loc_key(mut self, loc_key: impl Into<String>) -> Result<Self, RuntimeError> {
        self.require_apns_adapter("apns_loc_key")?;
        let loc_key = loc_key.into();
        validate_apns_loc_key(&loc_key)?;
        self.apns_loc_key = loc_key;
        Ok(self)
    }

    /// Sets and validates the APNs `apns-topic` header.
    pub fn with_apns_topic(mut self, topic: impl Into<String>) -> Result<Self, RuntimeError> {
        self.require_apns_adapter("apns_topic")?;
        let topic = topic.into();
        validate_apns_topic(&topic)?;
        self.apns_topic = Some(topic);
        Ok(self)
    }

    /// Applies validated [`ApnsOptions`] to this target.
    pub fn with_apns_options(mut self, options: ApnsOptions) -> Result<Self, RuntimeError> {
        self.require_apns_adapter("apns_options")?;
        options.validate()?;
        self.apns_mode = options.mode;
        self.apns_loc_key = options.loc_key;
        Ok(self)
    }

    fn require_apns_adapter(&self, field: &str) -> Result<(), RuntimeError> {
        if !matches!(
            self.adapter,
            WakeAdapterKind::Apns | WakeAdapterKind::ApnsH2
        ) {
            return Err(RuntimeError::Protocol(format!(
                "{field} is only valid for apns or apns_h2 wake targets"
            )));
        }
        Ok(())
    }

    /// Returns the adapter kind.
    #[must_use]
    pub fn adapter(&self) -> WakeAdapterKind {
        self.adapter
    }

    /// Returns the validated endpoint URL.
    #[must_use]
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Returns the validated endpoint URL as a string slice.
    #[must_use]
    pub fn endpoint_str(&self) -> &str {
        self.endpoint.as_str()
    }

    /// Returns the optional bearer token.
    #[must_use]
    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref().map(String::as_str)
    }

    /// Returns the configured APNs push mode.
    #[must_use]
    pub fn apns_mode(&self) -> ApnsPushMode {
        self.apns_mode
    }

    /// Returns the configured static APNs `loc-key`.
    #[must_use]
    pub fn apns_loc_key(&self) -> &str {
        &self.apns_loc_key
    }

    /// Returns the optional `apns-topic` override.
    #[must_use]
    pub fn apns_topic(&self) -> Option<&str> {
        self.apns_topic.as_deref()
    }
}

impl fmt::Debug for WakeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakeTarget")
            .field("adapter", &self.adapter)
            .field("endpoint", &redact_url_str(self.endpoint.as_str()))
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("apns_mode", &self.apns_mode)
            .field("apns_loc_key", &self.apns_loc_key)
            .field("apns_topic", &self.apns_topic)
            .finish()
    }
}

/// Opaque JSON wake payload for `UnifiedPush` and generic `Webhook` adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeEnvelope {
    pub v: u8,
    pub wake_tag: WakeTag,
    pub epoch_s: u64,
}

impl WakeEnvelope {
    /// Builds an opaque wake envelope for `tag` at `now_unix_secs`.
    #[must_use]
    pub fn new(tag: &WakeTag, now_unix_secs: u64) -> Self {
        Self {
            v: 1,
            wake_tag: *tag,
            epoch_s: wake_epoch_start_secs(now_unix_secs),
        }
    }

    /// Serializes the envelope to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        serde_json::to_vec(self)
            .map_err(|err| RuntimeError::Protocol(format!("wake envelope serialize failed: {err}")))
    }
}

/// Static localization-key alert block (`{"loc-key": "<KEY>"}`) for `MutableAlert` APNs pushes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApnsAlert {
    #[serde(rename = "loc-key")]
    pub loc_key: String,
}

/// APNs `aps` dictionary supporting silent `Background` and NSE-wakeable `MutableAlert` pushes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApnsAps {
    #[serde(rename = "content-available", skip_serializing_if = "Option::is_none")]
    pub content_available: Option<u8>,
    #[serde(rename = "mutable-content", skip_serializing_if = "Option::is_none")]
    pub mutable_content: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<ApnsAlert>,
}

/// APNs JSON envelope carrying only the opaque wake hint and optional static `loc-key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApnsPayload {
    pub aps: ApnsAps,
    pub v: u8,
    pub wake_tag: WakeTag,
    pub epoch_s: u64,
}

impl ApnsPayload {
    /// Builds a silent background APNs payload for `tag` at `now_unix_secs`.
    #[must_use]
    pub fn new(tag: &WakeTag, now_unix_secs: u64) -> Self {
        Self {
            aps: ApnsAps {
                content_available: Some(1),
                mutable_content: None,
                alert: None,
            },
            v: 1,
            wake_tag: *tag,
            epoch_s: wake_epoch_start_secs(now_unix_secs),
        }
    }

    /// Builds a `MutableAlert` APNs payload (`mutable-content: 1`, static `loc-key` only).
    pub fn mutable_alert(
        tag: &WakeTag,
        now_unix_secs: u64,
        loc_key: &str,
    ) -> Result<Self, RuntimeError> {
        validate_apns_loc_key(loc_key)?;
        Ok(Self {
            aps: ApnsAps {
                content_available: None,
                mutable_content: Some(1),
                alert: Some(ApnsAlert {
                    loc_key: loc_key.to_owned(),
                }),
            },
            v: 1,
            wake_tag: *tag,
            epoch_s: wake_epoch_start_secs(now_unix_secs),
        })
    }

    /// Builds an APNs payload for `mode` and optional `loc_key` (defaults to [`DEFAULT_APNS_LOC_KEY`]).
    pub fn with_mode(
        tag: &WakeTag,
        now_unix_secs: u64,
        mode: ApnsPushMode,
        loc_key: Option<&str>,
    ) -> Result<Self, RuntimeError> {
        if let Some(key) = loc_key {
            validate_apns_loc_key(key)?;
        }
        match mode {
            ApnsPushMode::Background => Ok(Self::new(tag, now_unix_secs)),
            ApnsPushMode::MutableAlert => {
                Self::mutable_alert(tag, now_unix_secs, loc_key.unwrap_or(DEFAULT_APNS_LOC_KEY))
            }
        }
    }

    /// Serializes the APNs payload to JSON bytes after validating any static `loc-key`.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        if let Some(alert) = &self.aps.alert {
            validate_apns_loc_key(&alert.loc_key)?;
        }
        serde_json::to_vec(self)
            .map_err(|err| RuntimeError::Protocol(format!("apns payload serialize failed: {err}")))
    }
}

/// FCM Android transport priority block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcmAndroidConfig {
    pub priority: String,
}

/// FCM HTTP v1 data-only fields (all values are strings per FCM v1 spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcmDataFields {
    pub v: String,
    pub wake_tag: String,
    pub epoch_s: String,
}

/// FCM HTTP v1 message body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcmMessage {
    pub android: FcmAndroidConfig,
    pub data: FcmDataFields,
}

/// FCM HTTP v1 high-priority data-only envelope carrying only the opaque wake hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcmPayload {
    pub message: FcmMessage,
}

impl FcmPayload {
    /// Builds a high-priority data-only FCM v1 payload for `tag` at `now_unix_secs`.
    #[must_use]
    pub fn new(tag: &WakeTag, now_unix_secs: u64) -> Self {
        Self {
            message: FcmMessage {
                android: FcmAndroidConfig {
                    priority: "high".to_owned(),
                },
                data: FcmDataFields {
                    v: "1".to_owned(),
                    wake_tag: tag.to_b64url(),
                    epoch_s: wake_epoch_start_secs(now_unix_secs).to_string(),
                },
            },
        }
    }

    /// Serializes the FCM payload to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        serde_json::to_vec(self)
            .map_err(|err| RuntimeError::Protocol(format!("fcm payload serialize failed: {err}")))
    }
}

/// Formats the adapter-specific JSON payload for `adapter` using default options.
pub fn build_wake_payload(
    adapter: WakeAdapterKind,
    tag: &WakeTag,
    now_unix_secs: u64,
) -> Result<Vec<u8>, RuntimeError> {
    match adapter {
        WakeAdapterKind::UnifiedPush | WakeAdapterKind::Webhook => {
            WakeEnvelope::new(tag, now_unix_secs).to_json_bytes()
        }
        WakeAdapterKind::Apns | WakeAdapterKind::ApnsH2 => {
            ApnsPayload::new(tag, now_unix_secs).to_json_bytes()
        }
        WakeAdapterKind::Fcm => FcmPayload::new(tag, now_unix_secs).to_json_bytes(),
    }
}

/// Formats the adapter-specific JSON payload for `target` (respecting [`ApnsPushMode`] and `loc-key`).
pub fn build_wake_payload_for_target(
    target: &WakeTarget,
    tag: &WakeTag,
    now_unix_secs: u64,
) -> Result<Vec<u8>, RuntimeError> {
    match target.adapter() {
        WakeAdapterKind::UnifiedPush | WakeAdapterKind::Webhook => {
            WakeEnvelope::new(tag, now_unix_secs).to_json_bytes()
        }
        WakeAdapterKind::Apns | WakeAdapterKind::ApnsH2 => ApnsPayload::with_mode(
            tag,
            now_unix_secs,
            target.apns_mode(),
            Some(target.apns_loc_key()),
        )?
        .to_json_bytes(),
        WakeAdapterKind::Fcm => FcmPayload::new(tag, now_unix_secs).to_json_bytes(),
    }
}

/// Outcome of a wake-hint delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    /// Push wake hint was accepted by the configured provider/gateway.
    Delivered,
    /// Wake hint was suppressed locally by per-target coalescing.
    Coalesced,
    /// Pull-only mode (`NoopWakeProvider`); no push was attempted.
    Noop,
    /// Best-effort wake hint failed and was skipped without impacting core flows.
    Skipped,
}

/// Pluggable opaque push wake-hint provider.
#[async_trait]
pub trait WakeProvider: Send + Sync {
    /// Sends an opaque wake hint for `tag` to `target` at `now_unix_secs`.
    async fn notify(
        &self,
        target: &WakeTarget,
        tag: &WakeTag,
        now_unix_secs: u64,
    ) -> Result<WakeOutcome, RuntimeError>;

    /// Best-effort wake hint that catches transport/timeout errors and returns [`WakeOutcome::Skipped`].
    async fn notify_best_effort(
        &self,
        target: &WakeTarget,
        tag: &WakeTag,
        now_unix_secs: u64,
    ) -> WakeOutcome {
        match self.notify(target, tag, now_unix_secs).await {
            Ok(outcome) => outcome,
            Err(err) => {
                tracing::debug!(
                    adapter = ?target.adapter(),
                    error = %err,
                    "best-effort wake hint skipped"
                );
                WakeOutcome::Skipped
            }
        }
    }
}

#[derive(Clone, Copy)]
struct CoalesceEntry {
    last_secs: u64,
    seq: u64,
}

/// Bounded per-target rate limiter / coalescer preventing burst wake-hint spam.
pub struct WakeCoalescer {
    cooldown_secs: u64,
    max_targets: usize,
    state: Mutex<CoalesceState>,
}

#[derive(Default)]
struct CoalesceState {
    next_seq: u64,
    entries: HashMap<(WakeAdapterKind, String), CoalesceEntry>,
}

impl fmt::Debug for WakeCoalescer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entry_count = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .len();
        f.debug_struct("WakeCoalescer")
            .field("cooldown_secs", &self.cooldown_secs)
            .field("max_targets", &self.max_targets)
            .field("entry_count", &entry_count)
            .finish()
    }
}

impl Default for WakeCoalescer {
    fn default() -> Self {
        Self::new(DEFAULT_WAKE_COALESCE_INTERVAL_SECS)
    }
}

impl WakeCoalescer {
    /// Creates a coalescer with `cooldown_secs` per target and [`MAX_WAKE_COALESCE_TARGETS`] capacity.
    #[must_use]
    pub fn new(cooldown_secs: u64) -> Self {
        Self {
            cooldown_secs,
            max_targets: MAX_WAKE_COALESCE_TARGETS,
            state: Mutex::new(CoalesceState::default()),
        }
    }

    /// Returns `true` if a wake hint should be sent now (and records the attempt),
    /// or `false` if suppressed by the cooldown window.
    pub fn check_and_record(&self, target: &WakeTarget, now_unix_secs: u64) -> bool {
        let key = (target.adapter(), target.endpoint_str().to_owned());
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = guard.entries.get(&key)
            && self.cooldown_secs > 0
            && now_unix_secs.saturating_sub(entry.last_secs) < self.cooldown_secs
        {
            return false;
        }
        if !guard.entries.contains_key(&key)
            && guard.entries.len() >= self.max_targets
            && let Some(oldest_key) = guard
                .entries
                .iter()
                .min_by_key(|(_, v)| v.seq)
                .map(|(k, _)| k.clone())
        {
            guard.entries.remove(&oldest_key);
        }
        guard.next_seq = guard.next_seq.wrapping_add(1);
        let seq = guard.next_seq;
        guard.entries.insert(
            key,
            CoalesceEntry {
                last_secs: now_unix_secs,
                seq,
            },
        );
        true
    }
}

/// Default pull-only [`WakeProvider`] that performs no network I/O.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopWakeProvider;

#[async_trait]
impl WakeProvider for NoopWakeProvider {
    async fn notify(
        &self,
        _target: &WakeTarget,
        _tag: &WakeTag,
        _now_unix_secs: u64,
    ) -> Result<WakeOutcome, RuntimeError> {
        Ok(WakeOutcome::Noop)
    }
}

/// Recorded wake event stored by [`MemoryWakeProvider`].
#[derive(Debug, Clone)]
pub struct RecordedWake {
    pub target: WakeTarget,
    pub tag: WakeTag,
    pub epoch_s: u64,
    pub now_unix_secs: u64,
}

/// Deterministic in-memory [`WakeProvider`] test sink.
#[derive(Debug, Default)]
pub struct MemoryWakeProvider {
    coalescer: WakeCoalescer,
    events: Mutex<Vec<RecordedWake>>,
}

impl MemoryWakeProvider {
    /// Creates an in-memory wake provider with the default coalescing cooldown.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an in-memory wake provider with a custom coalescing cooldown in seconds.
    #[must_use]
    pub fn with_cooldown_secs(cooldown_secs: u64) -> Self {
        Self {
            coalescer: WakeCoalescer::new(cooldown_secs),
            events: Mutex::new(Vec::new()),
        }
    }

    /// Returns a snapshot of all delivered wake events.
    #[must_use]
    pub fn recorded(&self) -> Vec<RecordedWake> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Clears all recorded wake events.
    pub fn clear(&self) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

#[async_trait]
impl WakeProvider for MemoryWakeProvider {
    async fn notify(
        &self,
        target: &WakeTarget,
        tag: &WakeTag,
        now_unix_secs: u64,
    ) -> Result<WakeOutcome, RuntimeError> {
        if !self.coalescer.check_and_record(target, now_unix_secs) {
            return Ok(WakeOutcome::Coalesced);
        }
        let mut guard = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(RecordedWake {
            target: target.clone(),
            tag: *tag,
            epoch_s: wake_epoch_start_secs(now_unix_secs),
            now_unix_secs,
        });
        Ok(WakeOutcome::Delivered)
    }
}

/// Builds the default Mozilla/WebPKI TLS root certificate store for HTTPS wake providers.
#[must_use]
pub fn default_wake_root_certs() -> rustls::RootCertStore {
    rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

/// SSRF-safe async HTTP/1.1 + rustls TLS wake-hint provider.
#[derive(Debug)]
pub struct HttpWakeProvider {
    timeout: Duration,
    coalescer: WakeCoalescer,
    root_cert_count: usize,
    tls_config: Arc<rustls::ClientConfig>,
}

impl Default for HttpWakeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpWakeProvider {
    /// Creates an [`HttpWakeProvider`] with default timeout (`3s`), coalescing (`5s`),
    /// and Mozilla/WebPKI root certificates (`webpki-roots`) for HTTPS endpoints.
    #[must_use]
    pub fn new() -> Self {
        Self::with_roots(default_wake_root_certs())
    }

    /// Creates an [`HttpWakeProvider`] with an empty TLS root store (for negative HTTPS tests).
    #[must_use]
    pub fn with_empty_roots() -> Self {
        Self::with_roots(rustls::RootCertStore::empty())
    }

    fn with_roots(root_certs: rustls::RootCertStore) -> Self {
        ensure_rustls_ring_provider();
        let root_cert_count = root_certs.len();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        Self {
            timeout: DEFAULT_WAKE_TIMEOUT,
            coalescer: WakeCoalescer::default(),
            root_cert_count,
            tls_config: Arc::new(tls_config),
        }
    }

    /// Returns the number of loaded TLS root certificates (when configured via `new`,
    /// `with_empty_roots`, or `with_root_certs`).
    #[must_use]
    pub fn root_cert_count(&self) -> usize {
        self.root_cert_count
    }

    /// Overrides the per-request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides the per-target coalescing cooldown in seconds.
    #[must_use]
    pub fn with_cooldown_secs(mut self, cooldown_secs: u64) -> Self {
        self.coalescer = WakeCoalescer::new(cooldown_secs);
        self
    }

    /// Configures the TLS root certificate store for `https://` wake endpoints.
    #[must_use]
    pub fn with_root_certs(mut self, root_certs: rustls::RootCertStore) -> Self {
        ensure_rustls_ring_provider();
        self.root_cert_count = root_certs.len();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        self.tls_config = Arc::new(tls_config);
        self
    }

    /// Configures a custom `rustls::ClientConfig` for `https://` wake endpoints.
    #[must_use]
    pub fn with_tls_config(mut self, tls_config: Arc<rustls::ClientConfig>) -> Self {
        self.root_cert_count = 0;
        self.tls_config = tls_config;
        self
    }
}

#[async_trait]
impl WakeProvider for HttpWakeProvider {
    async fn notify(
        &self,
        target: &WakeTarget,
        tag: &WakeTag,
        now_unix_secs: u64,
    ) -> Result<WakeOutcome, RuntimeError> {
        if target.adapter() == WakeAdapterKind::ApnsH2 {
            return Err(RuntimeError::Protocol(
                "wake adapter 'apns_h2' requires ApnsH2WakeProvider (HTTP/2)".into(),
            ));
        }
        let parsed = validate_wake_endpoint_url(target.endpoint_str())?;
        let body = build_wake_payload_for_target(target, tag, now_unix_secs)?;
        let req_bytes = build_http_post_request(&parsed, target, &body)?;
        if !self.coalescer.check_and_record(target, now_unix_secs) {
            return Ok(WakeOutcome::Coalesced);
        }
        let tls_config = Arc::clone(&self.tls_config);

        let status = timeout(
            self.timeout,
            send_wake_http(&parsed, &req_bytes, tls_config),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("wake HTTP delivery timed out"))??;

        if (200..300).contains(&status) {
            Ok(WakeOutcome::Delivered)
        } else {
            Err(RuntimeError::Protocol(format!(
                "wake endpoint returned HTTP status {status}"
            )))
        }
    }
}

/// Shared wake transport configuration specification across runtime, CLI, FFI, and bindings.
#[derive(Clone, Default, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WakeConfigSpec {
    pub wake_url: Option<String>,
    #[zeroize(skip)]
    pub wake_adapter: Option<WakeAdapterKind>,
    pub wake_secret_b64: Option<String>,
    pub wake_auth_token: Option<String>,
    #[zeroize(skip)]
    pub wake_pre_wake: Option<bool>,
    #[zeroize(skip)]
    pub wake_retry_delay_ms: Option<u64>,
    #[zeroize(skip)]
    pub wake_max_attempts: Option<usize>,
    #[zeroize(skip)]
    pub wake_timeout_ms: Option<u64>,
    #[zeroize(skip)]
    pub wake_coalesce_secs: Option<u64>,
    #[zeroize(skip)]
    pub wake_apns_mode: Option<ApnsPushMode>,
    pub wake_apns_topic: Option<String>,
    pub wake_apns_loc_key: Option<String>,
    pub wake_apns_team_id: Option<String>,
    pub wake_apns_key_id: Option<String>,
    pub wake_apns_p8_pem: Option<String>,
    pub wake_apns_client_cert_pem: Option<String>,
    pub wake_apns_client_key_pem: Option<String>,
}

impl WakeConfigSpec {
    fn has_any_non_url_field(&self) -> bool {
        self.wake_adapter.is_some()
            || self.wake_secret_b64.is_some()
            || self.wake_auth_token.is_some()
            || self.wake_pre_wake.is_some()
            || self.wake_retry_delay_ms.is_some()
            || self.wake_max_attempts.is_some()
            || self.wake_timeout_ms.is_some()
            || self.wake_coalesce_secs.is_some()
            || self.has_any_apns_field()
    }

    fn has_any_apns_field(&self) -> bool {
        self.wake_apns_mode.is_some()
            || self.wake_apns_topic.is_some()
            || self.wake_apns_loc_key.is_some()
            || self.wake_apns_team_id.is_some()
            || self.wake_apns_key_id.is_some()
            || self.wake_apns_p8_pem.is_some()
            || self.wake_apns_client_cert_pem.is_some()
            || self.wake_apns_client_key_pem.is_some()
    }
}

impl fmt::Debug for WakeConfigSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakeConfigSpec")
            .field("wake_url", &self.wake_url.as_deref().map(redact_url_str))
            .field("wake_adapter", &self.wake_adapter)
            .field(
                "wake_secret_b64",
                &self.wake_secret_b64.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "wake_auth_token",
                &self.wake_auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("wake_pre_wake", &self.wake_pre_wake)
            .field("wake_retry_delay_ms", &self.wake_retry_delay_ms)
            .field("wake_max_attempts", &self.wake_max_attempts)
            .field("wake_timeout_ms", &self.wake_timeout_ms)
            .field("wake_coalesce_secs", &self.wake_coalesce_secs)
            .field("wake_apns_mode", &self.wake_apns_mode)
            .field("wake_apns_topic", &self.wake_apns_topic)
            .field("wake_apns_loc_key", &self.wake_apns_loc_key)
            .field("wake_apns_team_id", &self.wake_apns_team_id)
            .field("wake_apns_key_id", &self.wake_apns_key_id)
            .field(
                "wake_apns_p8_pem",
                &self.wake_apns_p8_pem.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "wake_apns_client_cert_pem",
                &self.wake_apns_client_cert_pem.as_ref().map(|_| "[CERT]"),
            )
            .field(
                "wake_apns_client_key_pem",
                &self.wake_apns_client_key_pem.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Validated, endpoint-owned wake transport configuration with a persistent [`WakeProvider`].
#[derive(Clone)]
pub struct WakeTransportSettings {
    pub provider: Arc<dyn WakeProvider>,
    pub target: WakeTarget,
    pub secret: WakeSecret,
    pub pre_wake: bool,
    pub retry_delay_ms: u64,
    pub max_attempts: usize,
    pub timeout_ms: u64,
    pub coalesce_secs: u64,
}

/// Compatibility alias for [`WakeTransportSettings`].
pub type ParsedWakeConfig = WakeTransportSettings;

impl fmt::Debug for WakeTransportSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakeTransportSettings")
            .field("provider", &"<WakeProvider>")
            .field("target", &self.target)
            .field("secret", &self.secret)
            .field("pre_wake", &self.pre_wake)
            .field("retry_delay_ms", &self.retry_delay_ms)
            .field("max_attempts", &self.max_attempts)
            .field("timeout_ms", &self.timeout_ms)
            .field("coalesce_secs", &self.coalesce_secs)
            .finish()
    }
}

impl WakeTransportSettings {
    /// Parses and validates a [`WakeConfigSpec`], returning `None` when `wake_url` is unset.
    pub fn from_spec(spec: WakeConfigSpec) -> Result<Option<Self>, RuntimeError> {
        build_wake_provider(spec)
    }

    /// Converts these endpoint settings into per-dial [`WakeDialOptions`] sharing the pooled provider.
    #[must_use]
    pub fn to_dial_options(&self) -> WakeDialOptions {
        WakeDialOptions::new(
            Arc::clone(&self.provider),
            self.target.clone(),
            self.secret.clone(),
        )
        .with_pre_wake(self.pre_wake)
        .with_retry_delay(Duration::from_millis(self.retry_delay_ms))
        .with_max_attempts(self.max_attempts)
        .with_wake_timeout(Duration::from_millis(self.timeout_ms))
    }
}

/// Validates a [`WakeConfigSpec`] and builds a persistent [`WakeTransportSettings`] with WebPKI roots.
pub fn build_wake_provider(
    spec: WakeConfigSpec,
) -> Result<Option<WakeTransportSettings>, RuntimeError> {
    build_wake_provider_with_root_certs(spec, None)
}

/// Validates a [`WakeConfigSpec`] and builds a persistent [`WakeTransportSettings`] with an
/// optional custom TLS [`rustls::RootCertStore`].
pub fn build_wake_provider_with_root_certs(
    mut spec: WakeConfigSpec,
    root_certs: Option<rustls::RootCertStore>,
) -> Result<Option<WakeTransportSettings>, RuntimeError> {
    let Some(url) = spec.wake_url.take() else {
        if spec.has_any_non_url_field() {
            return Err(RuntimeError::Protocol(
                "wake_* options require wake_url".into(),
            ));
        }
        return Ok(None);
    };

    let adapter = spec.wake_adapter.unwrap_or(WakeAdapterKind::Webhook);
    let secret_b64 = spec
        .wake_secret_b64
        .take()
        .map(Zeroizing::new)
        .ok_or_else(|| {
            RuntimeError::Protocol("wake_secret_b64 is required when wake_url is set".into())
        })?;
    let secret_bytes = Zeroizing::new(
        b64url_decode_array::<32>(secret_b64.trim())
            .map_err(|_| RuntimeError::Protocol("invalid wake_secret_b64".into()))?,
    );
    let secret = WakeSecret::from_bytes(*secret_bytes);

    if !matches!(adapter, WakeAdapterKind::Apns | WakeAdapterKind::ApnsH2)
        && spec.has_any_apns_field()
    {
        return Err(RuntimeError::Protocol(
            "wake_apns_* options are only valid for apns or apns_h2 adapters".into(),
        ));
    }
    if adapter == WakeAdapterKind::Apns
        && (spec.wake_apns_team_id.is_some()
            || spec.wake_apns_key_id.is_some()
            || spec.wake_apns_p8_pem.is_some()
            || spec.wake_apns_client_cert_pem.is_some()
            || spec.wake_apns_client_key_pem.is_some())
    {
        return Err(RuntimeError::Protocol(
            "APNs provider token and mTLS options require wake_adapter 'apns_h2'".into(),
        ));
    }

    let mut target = WakeTarget::new(adapter, &url)?;
    if adapter == WakeAdapterKind::ApnsH2 {
        validate_apns_h2_endpoint_host(target.endpoint(), false)?;
    }
    let auth_token = spec.wake_auth_token.take().map(Zeroizing::new);
    if let Some(ref tok) = auth_token {
        if tok.is_empty() || tok.chars().any(char::is_control) {
            return Err(RuntimeError::Protocol("invalid wake_auth_token".into()));
        }
        if adapter != WakeAdapterKind::ApnsH2 {
            target = target
                .with_auth_token(tok.as_str())
                .map_err(|_| RuntimeError::Protocol("invalid wake_auth_token".into()))?;
        }
    }

    if let Some(mode) = spec.wake_apns_mode {
        target = target.with_apns_mode(mode)?;
    }
    if let Some(loc_key) = spec.wake_apns_loc_key.take() {
        target = target.with_apns_loc_key(loc_key)?;
    }
    let apns_topic = spec.wake_apns_topic.take();
    if let Some(ref topic) = apns_topic {
        target = target.with_apns_topic(topic.as_str())?;
    }

    let pre_wake = spec.wake_pre_wake.unwrap_or(false);
    let retry_delay_ms = spec.wake_retry_delay_ms.unwrap_or(100);
    let max_attempts = spec.wake_max_attempts.unwrap_or(10).max(1);
    let timeout_ms = spec.wake_timeout_ms.unwrap_or(3_000);
    let coalesce_secs = spec
        .wake_coalesce_secs
        .unwrap_or(DEFAULT_WAKE_COALESCE_INTERVAL_SECS);
    let timeout_dur = Duration::from_millis(timeout_ms);

    let provider: Arc<dyn WakeProvider> = if adapter == WakeAdapterKind::ApnsH2 {
        let topic = apns_topic.ok_or_else(|| {
            RuntimeError::Protocol("wake_apns_topic is required for apns_h2".into())
        })?;
        let p8_pem = spec
            .wake_apns_p8_pem
            .take()
            .map(|s| Zeroizing::new(s.into_bytes()));
        let team_id = spec.wake_apns_team_id.take();
        let key_id = spec.wake_apns_key_id.take();
        let client_cert_pem = spec
            .wake_apns_client_cert_pem
            .take()
            .map(|s| Zeroizing::new(s.into_bytes()));
        let client_key_pem = spec
            .wake_apns_client_key_pem
            .take()
            .map(|s| Zeroizing::new(s.into_bytes()));

        if let Some(ref pem) = p8_pem
            && pem.len() > MAX_WAKE_PEM_BYTES
        {
            return Err(RuntimeError::Protocol(format!(
                "wake_apns_p8_pem exceeds {MAX_WAKE_PEM_BYTES} bytes"
            )));
        }
        if let Some(ref pem) = client_cert_pem
            && pem.len() > MAX_WAKE_PEM_BYTES
        {
            return Err(RuntimeError::Protocol(format!(
                "wake_apns_client_cert_pem exceeds {MAX_WAKE_PEM_BYTES} bytes"
            )));
        }
        if let Some(ref pem) = client_key_pem
            && pem.len() > MAX_WAKE_PEM_BYTES
        {
            return Err(RuntimeError::Protocol(format!(
                "wake_apns_client_key_pem exceeds {MAX_WAKE_PEM_BYTES} bytes"
            )));
        }

        if (team_id.is_some() || key_id.is_some()) && p8_pem.is_none() {
            return Err(RuntimeError::Protocol(
                "wake_apns_team_id and wake_apns_key_id require wake_apns_p8_pem".into(),
            ));
        }
        let has_p8 = p8_pem.is_some();
        let has_bearer = auth_token.is_some();
        let has_mtls = client_cert_pem.is_some() || client_key_pem.is_some();
        let active_modes = u8::from(has_p8) + u8::from(has_bearer) + u8::from(has_mtls);
        if active_modes == 0 {
            return Err(RuntimeError::Protocol(
                "apns_h2 requires wake_apns_p8_pem, wake_auth_token, or client mTLS cert+key"
                    .into(),
            ));
        }
        if active_modes > 1 {
            return Err(RuntimeError::Protocol(
                "apns_h2 auth modes (wake_apns_p8_pem, wake_auth_token, client mTLS) are mutually exclusive"
                    .into(),
            ));
        }

        let auth = if let Some(p8_pem) = p8_pem {
            let team_id = team_id.ok_or_else(|| {
                RuntimeError::Protocol(
                    "wake_apns_team_id is required when wake_apns_p8_pem is set".into(),
                )
            })?;
            let key_id = key_id.ok_or_else(|| {
                RuntimeError::Protocol(
                    "wake_apns_key_id is required when wake_apns_p8_pem is set".into(),
                )
            })?;
            ApnsH2Auth::ProviderToken {
                team_id,
                key_id,
                p8_pem,
            }
        } else if let Some(tok) = auth_token {
            ApnsH2Auth::BearerToken(tok)
        } else {
            let cert_pem = client_cert_pem.ok_or_else(|| {
                RuntimeError::Protocol(
                    "wake_apns_client_cert_pem is required with wake_apns_client_key_pem".into(),
                )
            })?;
            let key_pem = client_key_pem.ok_or_else(|| {
                RuntimeError::Protocol(
                    "wake_apns_client_key_pem is required with wake_apns_client_cert_pem".into(),
                )
            })?;
            ApnsH2Auth::ClientCert { cert_pem, key_pem }
        };

        let mut apns = ApnsH2WakeProvider::new(auth)?;
        if let Some(roots) = root_certs {
            apns = apns.with_root_certs(roots)?;
        }
        apns = apns
            .with_topic(topic)?
            .with_timeout(timeout_dur)
            .with_cooldown_secs(coalesce_secs);
        Arc::new(apns)
    } else {
        let mut http = HttpWakeProvider::new()
            .with_timeout(timeout_dur)
            .with_cooldown_secs(coalesce_secs);
        if let Some(roots) = root_certs {
            http = http.with_root_certs(roots);
        }
        Arc::new(http)
    };

    Ok(Some(WakeTransportSettings {
        provider,
        target,
        secret,
        pre_wake,
        retry_delay_ms,
        max_attempts,
        timeout_ms,
        coalesce_secs,
    }))
}

fn build_http_post_request(
    parsed: &Url,
    target: &WakeTarget,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
    let host = parsed
        .host_str()
        .ok_or_else(|| RuntimeError::Protocol("wake URL missing host".into()))?;
    let host_header = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let path = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_owned(),
    };

    let mut req = Zeroizing::new(Vec::with_capacity(256 + body.len()));
    req.extend_from_slice(
        format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host_header}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n",
            body.len()
        )
        .as_bytes(),
    );
    if target.adapter() == WakeAdapterKind::Apns {
        match target.apns_mode() {
            ApnsPushMode::Background => {
                req.extend_from_slice(b"apns-push-type: background\r\napns-priority: 5\r\n");
            }
            ApnsPushMode::MutableAlert => {
                req.extend_from_slice(b"apns-push-type: alert\r\napns-priority: 10\r\n");
            }
        }
        if let Some(topic) = target.apns_topic() {
            validate_apns_topic(topic)?;
            req.extend_from_slice(format!("apns-topic: {topic}\r\n").as_bytes());
        }
    }
    if let Some(token) = target.auth_token() {
        req.extend_from_slice(format!("Authorization: Bearer {token}\r\n").as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body);
    Ok(req)
}

pub(crate) fn check_resolved_wake_ip(
    ip: IpAddr,
    is_http: bool,
    bare_host: &str,
    require_public_non_loopback: bool,
) -> Result<(), RuntimeError> {
    if is_metadata_or_link_local_ip(ip) {
        return Err(RuntimeError::Protocol(format!(
            "resolved metadata or link-local address '{ip}' is not permitted"
        )));
    }
    if is_http && !ip.is_loopback() {
        return Err(RuntimeError::Protocol(format!(
            "cleartext http:// wake endpoint resolved to non-loopback address '{ip}'"
        )));
    }
    if require_public_non_loopback {
        let class = classify_destination(ip);
        if is_loopback_host(bare_host) {
            if class != DestClass::Loopback {
                return Err(RuntimeError::Protocol(format!(
                    "loopback wake endpoint resolved to non-loopback address '{ip}'"
                )));
            }
        } else if class != DestClass::Public {
            return Err(RuntimeError::Protocol(format!(
                "apns_h2 endpoint resolved to non-public address '{ip}'"
            )));
        }
    }
    Ok(())
}

pub(crate) async fn resolve_and_connect(parsed: &Url) -> Result<TcpStream, RuntimeError> {
    resolve_and_connect_with_policy(parsed, false).await
}

pub(crate) async fn resolve_and_connect_with_policy(
    parsed: &Url,
    require_public_non_loopback: bool,
) -> Result<TcpStream, RuntimeError> {
    let host = parsed
        .host_str()
        .ok_or_else(|| RuntimeError::Protocol("wake URL missing host".into()))?;
    let bare = strip_host_brackets(host).trim_end_matches('.');
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| RuntimeError::Protocol("wake URL missing port".into()))?;
    let is_http = parsed.scheme() == "http";

    let addrs: Vec<SocketAddr> = lookup_host((bare, port)).await?.collect();
    if addrs.is_empty() {
        return Err(RuntimeError::Protocol(format!(
            "wake endpoint host '{bare}' resolved to zero addresses"
        )));
    }

    for addr in &addrs {
        check_resolved_wake_ip(addr.ip(), is_http, bare, require_public_non_loopback)?;
    }

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.map_or_else(
        || RuntimeError::Protocol("failed to connect to wake endpoint".into()),
        RuntimeError::Io,
    ))
}

async fn send_wake_http(
    parsed: &Url,
    req_bytes: &[u8],
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<u16, RuntimeError> {
    let mut tcp = resolve_and_connect(parsed).await?;
    let resp_buf = if parsed.scheme() == "https" {
        let host = parsed
            .host_str()
            .ok_or_else(|| RuntimeError::Protocol("wake URL missing host".into()))?;
        let bare = strip_host_brackets(host).trim_end_matches('.').to_owned();
        let server_name = ServerName::try_from(bare)
            .map_err(|err| RuntimeError::Protocol(format!("invalid TLS server name: {err}")))?;
        send_over_rustls(&mut tcp, tls_config, server_name, req_bytes).await?
    } else {
        tcp.write_all(req_bytes).await?;
        tcp.flush().await?;
        read_bounded_http_response(&mut tcp).await?
    };
    parse_http_status(&resp_buf)
}

async fn flush_rustls_writes(
    tcp: &mut TcpStream,
    conn: &mut rustls::ClientConnection,
) -> Result<(), RuntimeError> {
    while conn.wants_write() {
        let mut out = Vec::new();
        conn.write_tls(&mut out)?;
        if !out.is_empty() {
            tcp.write_all(&out).await?;
        }
    }
    tcp.flush().await?;
    Ok(())
}

async fn read_rustls_packets(
    tcp: &mut TcpStream,
    conn: &mut rustls::ClientConnection,
    buf: &mut [u8],
) -> Result<usize, RuntimeError> {
    let n = tcp.read(buf).await?;
    if n == 0 {
        return Ok(0);
    }
    let mut slice = &buf[..n];
    conn.read_tls(&mut slice)?;
    conn.process_new_packets()
        .map_err(|err| RuntimeError::Protocol(format!("wake TLS error: {err}")))?;
    Ok(n)
}

async fn send_over_rustls(
    tcp: &mut TcpStream,
    tls_config: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
    req_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let mut conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|err| RuntimeError::Protocol(format!("wake TLS init failed: {err}")))?;
    let mut io_buf = [0u8; 4_096];

    while conn.is_handshaking() {
        flush_rustls_writes(tcp, &mut conn).await?;
        if !conn.is_handshaking() {
            break;
        }
        if conn.wants_read() {
            if read_rustls_packets(tcp, &mut conn, &mut io_buf).await? == 0 {
                return Err(RuntimeError::Closed);
            }
        } else if !conn.wants_write() {
            return Err(RuntimeError::Protocol("wake TLS handshake stalled".into()));
        }
    }

    conn.writer().write_all(req_bytes)?;
    conn.writer().flush()?;
    flush_rustls_writes(tcp, &mut conn).await?;

    let mut resp = Vec::new();
    let mut pt_buf = [0u8; 1_024];
    loop {
        match conn.reader().read(&mut pt_buf) {
            Ok(0) => break,
            Ok(n) => {
                let take = n.min(MAX_WAKE_RESPONSE_BYTES.saturating_sub(resp.len()));
                resp.extend_from_slice(&pt_buf[..take]);
                if resp.len() >= MAX_WAKE_RESPONSE_BYTES
                    || resp.windows(4).any(|w| w == b"\r\n\r\n")
                {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if read_rustls_packets(tcp, &mut conn, &mut io_buf).await? == 0 {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(RuntimeError::Io(err)),
        }
    }
    conn.send_close_notify();
    let _ = flush_rustls_writes(tcp, &mut conn).await;
    Ok(resp)
}

async fn read_bounded_http_response(tcp: &mut TcpStream) -> Result<Vec<u8>, RuntimeError> {
    let mut resp = Vec::new();
    let mut chunk = [0u8; 1_024];
    while resp.len() < MAX_WAKE_RESPONSE_BYTES {
        let n = tcp.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        let take = n.min(MAX_WAKE_RESPONSE_BYTES - resp.len());
        resp.extend_from_slice(&chunk[..take]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(resp)
}

fn parse_http_status(resp: &[u8]) -> Result<u16, RuntimeError> {
    let text = std::str::from_utf8(resp)
        .map_err(|_| RuntimeError::Protocol("wake response is not valid UTF-8".into()))?;
    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| RuntimeError::Protocol("empty wake HTTP response".into()))?;
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| RuntimeError::Protocol("missing HTTP version in wake response".into()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(RuntimeError::Protocol(format!(
            "unexpected wake HTTP version '{version}'"
        )));
    }
    let code_str = parts
        .next()
        .ok_or_else(|| RuntimeError::Protocol("missing status code in wake response".into()))?;
    code_str
        .parse::<u16>()
        .map_err(|_| RuntimeError::Protocol(format!("invalid wake HTTP status '{code_str}'")))
}
