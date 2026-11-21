//! Optional opaque push wake-hint subsystem (`WakeProvider`).
//!
//! Core remains the trust boundary: wake signals carry only an epoch-blinded
//! [`WakeTag`] and tell a sleeping peer to poll its configured paths. Payloads
//! never carry plaintext, pairing codes, capability grants, `host_id`, or
//! identity keys. Pull-only endpoints use [`NoopWakeProvider`] by default.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use crate::providers::{
    ensure_rustls_ring_provider, is_loopback_host, is_metadata_or_link_local_ip,
};

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

/// Maximum HTTP response bytes read from a wake endpoint.
const MAX_WAKE_RESPONSE_BYTES: usize = 4_096;

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
    Fcm,
}

/// Alias for [`WakeAdapterKind`].
pub type WakeChannel = WakeAdapterKind;

fn strip_host_brackets(host: &str) -> &str {
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

/// Validated wake push destination with optional redacted bearer token.
#[derive(Clone)]
pub struct WakeTarget {
    adapter: WakeAdapterKind,
    endpoint: Url,
    auth_token: Option<Zeroizing<String>>,
}

impl WakeTarget {
    /// Creates a validated [`WakeTarget`] for `adapter` and `endpoint_url`.
    pub fn new(adapter: WakeAdapterKind, endpoint_url: &str) -> Result<Self, RuntimeError> {
        let endpoint = validate_wake_endpoint_url(endpoint_url)?;
        Ok(Self {
            adapter,
            endpoint,
            auth_token: None,
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
}

impl fmt::Debug for WakeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakeTarget")
            .field("adapter", &self.adapter)
            .field("endpoint", &self.endpoint.as_str())
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
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

/// Silent background APNs payload (`content-available: 1`) with zero user-visible text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApnsAps {
    #[serde(rename = "content-available")]
    pub content_available: u8,
}

/// APNs HTTP/1.1-gateway JSON envelope carrying only the opaque wake hint.
///
/// Note: [`HttpWakeProvider`] uses HTTP/1.1, so APNs targets require an HTTP/1.1
/// push gateway or relay; direct Apple APNs requires HTTP/2 via a custom [`WakeProvider`].
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
                content_available: 1,
            },
            v: 1,
            wake_tag: *tag,
            epoch_s: wake_epoch_start_secs(now_unix_secs),
        }
    }

    /// Serializes the APNs payload to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
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

/// Formats the adapter-specific JSON payload for `target.adapter()`.
pub fn build_wake_payload(
    adapter: WakeAdapterKind,
    tag: &WakeTag,
    now_unix_secs: u64,
) -> Result<Vec<u8>, RuntimeError> {
    match adapter {
        WakeAdapterKind::UnifiedPush | WakeAdapterKind::Webhook => {
            WakeEnvelope::new(tag, now_unix_secs).to_json_bytes()
        }
        WakeAdapterKind::Apns => ApnsPayload::new(tag, now_unix_secs).to_json_bytes(),
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

#[derive(Debug, Clone, Copy)]
struct CoalesceEntry {
    last_secs: u64,
    seq: u64,
}

/// Bounded per-target rate limiter / coalescer preventing burst wake-hint spam.
#[derive(Debug)]
pub struct WakeCoalescer {
    cooldown_secs: u64,
    max_targets: usize,
    state: Mutex<CoalesceState>,
}

#[derive(Debug, Default)]
struct CoalesceState {
    next_seq: u64,
    entries: HashMap<(WakeAdapterKind, String), CoalesceEntry>,
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

/// SSRF-safe async HTTP/1.1 + rustls TLS wake-hint provider.
#[derive(Debug)]
pub struct HttpWakeProvider {
    timeout: Duration,
    coalescer: WakeCoalescer,
    tls_config: Arc<rustls::ClientConfig>,
}

impl Default for HttpWakeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpWakeProvider {
    /// Creates an [`HttpWakeProvider`] with default timeout (`3s`), coalescing (`5s`),
    /// and an empty TLS root store (use [`Self::with_root_certs`] or [`Self::with_tls_config`]
    /// for HTTPS endpoints).
    #[must_use]
    pub fn new() -> Self {
        ensure_rustls_ring_provider();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        Self {
            timeout: DEFAULT_WAKE_TIMEOUT,
            coalescer: WakeCoalescer::default(),
            tls_config: Arc::new(tls_config),
        }
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
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        self.tls_config = Arc::new(tls_config);
        self
    }

    /// Configures a custom `rustls::ClientConfig` for `https://` wake endpoints.
    #[must_use]
    pub fn with_tls_config(mut self, tls_config: Arc<rustls::ClientConfig>) -> Self {
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
        let parsed = validate_wake_endpoint_url(target.endpoint_str())?;
        if !self.coalescer.check_and_record(target, now_unix_secs) {
            return Ok(WakeOutcome::Coalesced);
        }
        let body = build_wake_payload(target.adapter(), tag, now_unix_secs)?;
        let req_bytes = build_http_post_request(&parsed, target, &body)?;
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
        req.extend_from_slice(b"apns-push-type: background\r\napns-priority: 5\r\n");
    }
    if let Some(token) = target.auth_token() {
        req.extend_from_slice(format!("Authorization: Bearer {token}\r\n").as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body);
    Ok(req)
}

async fn resolve_and_connect(parsed: &Url) -> Result<TcpStream, RuntimeError> {
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
        if is_metadata_or_link_local_ip(addr.ip()) {
            return Err(RuntimeError::Protocol(format!(
                "resolved metadata or link-local address '{}' is not permitted",
                addr.ip()
            )));
        }
        if is_http && !addr.ip().is_loopback() {
            return Err(RuntimeError::Protocol(format!(
                "cleartext http:// wake endpoint resolved to non-loopback address '{}'",
                addr.ip()
            )));
        }
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
