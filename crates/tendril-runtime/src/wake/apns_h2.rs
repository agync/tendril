//! Direct HTTP/2 Apple Push Notification service (`ApnsH2WakeProvider`) transport.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderValue, Method, Request, Uri};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::Serialize;
use tendril_core::crypto::b64url_encode;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    ApnsPushMode, DEFAULT_WAKE_COALESCE_INTERVAL_SECS, DEFAULT_WAKE_TIMEOUT, MAX_WAKE_PEM_BYTES,
    MAX_WAKE_RESPONSE_BYTES, WAKE_EPOCH_SECS, WakeAdapterKind, WakeCoalescer, WakeOutcome,
    WakeProvider, WakeTag, WakeTarget, build_wake_payload_for_target, default_wake_root_certs,
    resolve_and_connect_with_policy, strip_host_brackets, validate_wake_endpoint_url,
    wake_epoch_start_secs,
};
use crate::error::RuntimeError;
use crate::providers::{ensure_rustls_ring_provider, is_loopback_host};
use crate::redact::redact_text;

/// Provider JWT refresh interval in seconds (45 minutes; Apple APNs tokens expire at 60 min).
pub const APNS_JWT_REFRESH_SECS: u64 = 2_700;

const MAX_APNS_ERROR_PREVIEW_CHARS: usize = 256;

/// Validates an `apns-topic` header value (`1..=255` non-control, non-whitespace ASCII bytes).
pub fn validate_apns_topic(topic: &str) -> Result<&str, RuntimeError> {
    if topic.is_empty() || topic.len() > 255 {
        return Err(RuntimeError::Protocol(
            "apns-topic must be 1..=255 ASCII characters".into(),
        ));
    }
    if !topic
        .bytes()
        .all(|b| b.is_ascii() && !b.is_ascii_control() && !b.is_ascii_whitespace())
    {
        return Err(RuntimeError::Protocol(
            "apns-topic must contain only printable non-whitespace ASCII characters".into(),
        ));
    }
    Ok(topic)
}

fn validate_apns_identifier<'a>(value: &'a str, label: &str) -> Result<&'a str, RuntimeError> {
    if value.is_empty() || value.len() > 64 {
        return Err(RuntimeError::Protocol(format!(
            "{label} must be 1..=64 ASCII characters"
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii() && !b.is_ascii_control() && !b.is_ascii_whitespace())
    {
        return Err(RuntimeError::Protocol(format!(
            "{label} must contain only printable non-whitespace ASCII characters"
        )));
    }
    Ok(value)
}

fn is_apple_apns_host(bare_host: &str) -> bool {
    let lower = bare_host.trim_end_matches('.').to_ascii_lowercase();
    lower
        .strip_suffix(".push.apple.com")
        .is_some_and(|sub| !sub.is_empty() && !sub.ends_with('.'))
}

pub(crate) fn validate_apns_h2_endpoint_host(
    parsed: &Url,
    allow_custom_host: bool,
) -> Result<(), RuntimeError> {
    if allow_custom_host {
        return Ok(());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| RuntimeError::Protocol("wake URL missing host".into()))?;
    let bare = strip_host_brackets(host).trim_end_matches('.');
    if is_loopback_host(bare) {
        return Ok(());
    }
    if is_apple_apns_host(bare) {
        if !matches!(parsed.port(), None | Some(443)) {
            return Err(RuntimeError::Protocol(
                "Apple APNs endpoint port must be omitted or 443".into(),
            ));
        }
        return Ok(());
    }
    Err(RuntimeError::Protocol(
        "apns_h2 endpoint host must be *.push.apple.com (port 443) or a loopback host".into(),
    ))
}

/// Validates a direct HTTP/2 APNs endpoint URL (`https://` required, no whitespace/control chars,
/// and `/3/device/<64..=200 hex>` with no query string).
pub fn validate_apns_h2_endpoint_url(url_str: &str) -> Result<Url, RuntimeError> {
    if url_str.trim().chars().any(char::is_whitespace) {
        return Err(RuntimeError::Protocol(
            "apns_h2 endpoint URL must not contain whitespace".into(),
        ));
    }
    let parsed = validate_wake_endpoint_url(url_str)?;
    if parsed.scheme() != "https" {
        return Err(RuntimeError::Protocol(
            "apns_h2 requires an https:// endpoint URL".into(),
        ));
    }
    if parsed
        .path()
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(RuntimeError::Protocol(
            "apns_h2 endpoint path contains whitespace or control characters".into(),
        ));
    }
    let Some(token) = parsed.path().strip_prefix("/3/device/") else {
        return Err(RuntimeError::Protocol(
            "apns_h2 endpoint path must be /3/device/<device_token>".into(),
        ));
    };
    if !(64..=200).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RuntimeError::Protocol(
            "APNs device token must be 64..=200 hex characters".into(),
        ));
    }
    if parsed.query().is_some() {
        return Err(RuntimeError::Protocol(
            "apns_h2 endpoint URL must not include a query string".into(),
        ));
    }
    Ok(parsed)
}

/// Mutually exclusive authentication credentials for [`ApnsH2WakeProvider`].
#[derive(Clone)]
pub enum ApnsH2Auth {
    /// ES256 provider JWT minted and cached from an Apple `.p8` PKCS#8 P-256 private key PEM.
    ProviderToken {
        team_id: String,
        key_id: String,
        p8_pem: Zeroizing<Vec<u8>>,
    },
    /// Pre-minted bearer JWT string.
    BearerToken(Zeroizing<String>),
    /// Client mTLS certificate chain and private key PEMs.
    ClientCert {
        cert_pem: Zeroizing<Vec<u8>>,
        key_pem: Zeroizing<Vec<u8>>,
    },
}

impl fmt::Debug for ApnsH2Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderToken {
                team_id, key_id, ..
            } => f
                .debug_struct("ProviderToken")
                .field("team_id", team_id)
                .field("key_id", key_id)
                .field("p8_pem", &"[REDACTED]")
                .finish(),
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"[REDACTED]").finish(),
            Self::ClientCert { .. } => f
                .debug_struct("ClientCert")
                .field("cert_pem", &"[CERT]")
                .field("key_pem", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct CachedJwt {
    token: Zeroizing<String>,
    issued_at_secs: u64,
}

struct Es256TokenSigner {
    team_id: String,
    key_id: String,
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
    cached: StdMutex<Option<CachedJwt>>,
}

impl fmt::Debug for Es256TokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Es256TokenSigner")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("key_pair", &"[REDACTED]")
            .finish()
    }
}

impl Es256TokenSigner {
    fn new(team_id: &str, key_id: &str, p8_pem: &[u8]) -> Result<Self, RuntimeError> {
        if p8_pem.len() > MAX_WAKE_PEM_BYTES {
            return Err(RuntimeError::Protocol(format!(
                "wake_apns_p8_pem exceeds {MAX_WAKE_PEM_BYTES} bytes"
            )));
        }
        let team_id = validate_apns_identifier(team_id, "wake_apns_team_id")?.to_owned();
        let key_id = validate_apns_identifier(key_id, "wake_apns_key_id")?.to_owned();
        let key_der = PrivateKeyDer::from_pem_slice(p8_pem)
            .map_err(|err| RuntimeError::Protocol(format!("invalid APNs .p8 PEM key: {err}")))?;
        let PrivateKeyDer::Pkcs8(pkcs8) = key_der else {
            return Err(RuntimeError::Protocol(
                "APNs .p8 key must be a PKCS#8 private key".into(),
            ));
        };
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.secret_pkcs8_der(),
            &rng,
        )
        .map_err(|err| RuntimeError::Protocol(format!("invalid APNs P-256 PKCS#8 key: {err}")))?;
        Ok(Self {
            team_id,
            key_id,
            key_pair,
            rng,
            cached: StdMutex::new(None),
        })
    }

    fn token_for(&self, now_unix_secs: u64) -> Result<Zeroizing<String>, RuntimeError> {
        let mut guard = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref cached) = *guard
            && now_unix_secs >= cached.issued_at_secs
            && now_unix_secs - cached.issued_at_secs < APNS_JWT_REFRESH_SECS
        {
            return Ok(cached.token.clone());
        }

        #[derive(Serialize)]
        struct JwtHeader<'a> {
            alg: &'a str,
            kid: &'a str,
        }
        #[derive(Serialize)]
        struct JwtClaims<'a> {
            iss: &'a str,
            iat: u64,
        }

        let header = serde_json::to_vec(&JwtHeader {
            alg: "ES256",
            kid: &self.key_id,
        })
        .map_err(|err| RuntimeError::Protocol(format!("JWT header encode failed: {err}")))?;
        let claims = serde_json::to_vec(&JwtClaims {
            iss: &self.team_id,
            iat: now_unix_secs,
        })
        .map_err(|err| RuntimeError::Protocol(format!("JWT claims encode failed: {err}")))?;
        let signing_input = Zeroizing::new(format!(
            "{}.{}",
            b64url_encode(&header),
            b64url_encode(&claims)
        ));
        let sig = self
            .key_pair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| RuntimeError::Protocol("APNs ES256 JWT signing failed".into()))?;
        let token = Zeroizing::new(format!(
            "{}.{}",
            *signing_input,
            b64url_encode(sig.as_ref())
        ));
        *guard = Some(CachedJwt {
            token: token.clone(),
            issued_at_secs: now_unix_secs,
        });
        Ok(token)
    }
}

#[derive(Clone)]
enum ApnsH2AuthRuntime {
    ProviderToken(Arc<Es256TokenSigner>),
    BearerToken(Zeroizing<String>),
    ClientCert {
        cert_pem: Zeroizing<Vec<u8>>,
        key_pem: Zeroizing<Vec<u8>>,
    },
}

impl fmt::Debug for ApnsH2AuthRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderToken(signer) => f.debug_tuple("ProviderToken").field(signer).finish(),
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"[REDACTED]").finish(),
            Self::ClientCert { .. } => f
                .debug_struct("ClientCert")
                .field("cert_pem", &"[CERT]")
                .field("key_pem", &"[REDACTED]")
                .finish(),
        }
    }
}

impl ApnsH2AuthRuntime {
    fn from_auth(auth: ApnsH2Auth) -> Result<Self, RuntimeError> {
        match auth {
            ApnsH2Auth::ProviderToken {
                team_id,
                key_id,
                p8_pem,
            } => Ok(Self::ProviderToken(Arc::new(Es256TokenSigner::new(
                &team_id,
                &key_id,
                p8_pem.as_slice(),
            )?))),
            ApnsH2Auth::BearerToken(token) => {
                if token.is_empty() || token.chars().any(char::is_control) {
                    return Err(RuntimeError::Protocol(
                        "APNs bearer token must be non-empty without control characters".into(),
                    ));
                }
                Ok(Self::BearerToken(token))
            }
            ApnsH2Auth::ClientCert { cert_pem, key_pem } => {
                if cert_pem.len() > MAX_WAKE_PEM_BYTES {
                    return Err(RuntimeError::Protocol(format!(
                        "wake_apns_client_cert_pem exceeds {MAX_WAKE_PEM_BYTES} bytes"
                    )));
                }
                if key_pem.len() > MAX_WAKE_PEM_BYTES {
                    return Err(RuntimeError::Protocol(format!(
                        "wake_apns_client_key_pem exceeds {MAX_WAKE_PEM_BYTES} bytes"
                    )));
                }
                Ok(Self::ClientCert { cert_pem, key_pem })
            }
        }
    }
}

fn build_tls_connector(
    root_certs: &rustls::RootCertStore,
    auth: &ApnsH2AuthRuntime,
) -> Result<TlsConnector, RuntimeError> {
    ensure_rustls_ring_provider();
    let builder = rustls::ClientConfig::builder().with_root_certificates(root_certs.clone());
    let mut tls_config = match auth {
        ApnsH2AuthRuntime::ClientCert { cert_pem, key_pem } => {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|err| {
                        RuntimeError::Protocol(format!(
                            "invalid APNs client certificate PEM: {err}"
                        ))
                    })?;
            if certs.is_empty() {
                return Err(RuntimeError::Protocol(
                    "APNs client certificate PEM contains no certificates".into(),
                ));
            }
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_slice()).map_err(|err| {
                RuntimeError::Protocol(format!("invalid APNs client private key PEM: {err}"))
            })?;
            builder.with_client_auth_cert(certs, key).map_err(|err| {
                RuntimeError::Protocol(format!("invalid APNs client TLS credentials: {err}"))
            })?
        }
        ApnsH2AuthRuntime::ProviderToken(_) | ApnsH2AuthRuntime::BearerToken(_) => {
            builder.with_no_client_auth()
        }
    };
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsConnector::from(Arc::new(tls_config)))
}

struct PooledH2Conn {
    id: u64,
    send_request: h2::client::SendRequest<Bytes>,
    conn_task: JoinHandle<()>,
}

impl Drop for PooledH2Conn {
    fn drop(&mut self) {
        self.conn_task.abort();
    }
}

type PoolSlot = Arc<AsyncMutex<Option<PooledH2Conn>>>;

enum H2AttemptError {
    BeforeHeaders(h2::Error),
    AfterHeaders(h2::Error),
}

fn map_h2_error(context: &str, err: &h2::Error) -> RuntimeError {
    RuntimeError::Protocol(format!("{context}: {}", redact_text(&err.to_string())))
}

fn format_apns_error_body(body_bytes: &[u8], active_token: Option<&str>) -> String {
    if body_bytes.is_empty() {
        return String::new();
    }
    let raw = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body_bytes)
        && let Some(reason) = json.get("reason").and_then(|v| v.as_str())
    {
        reason.to_owned()
    } else {
        String::from_utf8_lossy(body_bytes).into_owned()
    };
    let mut scrubbed = redact_text(raw.trim());
    if let Some(tok) = active_token
        && !tok.is_empty()
    {
        scrubbed = scrubbed.replace(tok, "<redacted>");
    }
    scrubbed
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_APNS_ERROR_PREVIEW_CHARS)
        .collect()
}

/// Direct HTTP/2 APNs [`WakeProvider`] (`WakeAdapterKind::ApnsH2`).
///
/// Enforces `https://`, ALPN `h2`, SSRF-safe DNS/IP checks, pooled `h2` connections
/// per `(host, port)` with automatic `GOAWAY`/disconnect recovery, and zero-PII
/// opaque wake envelopes.
pub struct ApnsH2WakeProvider {
    timeout: Duration,
    coalescer: WakeCoalescer,
    auth: ApnsH2AuthRuntime,
    default_topic: Option<String>,
    allow_custom_host: bool,
    root_cert_count: usize,
    tls_connector: TlsConnector,
    pool: StdMutex<HashMap<(String, u16), PoolSlot>>,
    next_conn_id: AtomicU64,
}

impl fmt::Debug for ApnsH2WakeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApnsH2WakeProvider")
            .field("timeout", &self.timeout)
            .field("coalescer", &self.coalescer)
            .field("auth", &self.auth)
            .field("default_topic", &self.default_topic)
            .field("allow_custom_host", &self.allow_custom_host)
            .field("root_cert_count", &self.root_cert_count)
            .finish_non_exhaustive()
    }
}

impl ApnsH2WakeProvider {
    /// Creates an [`ApnsH2WakeProvider`] verifying endpoints against Mozilla/WebPKI roots.
    pub fn new(auth: ApnsH2Auth) -> Result<Self, RuntimeError> {
        let roots = default_wake_root_certs();
        Self::with_roots(auth, roots)
    }

    /// Creates an [`ApnsH2WakeProvider`] with an empty TLS root store (for negative tests).
    pub fn with_empty_roots(auth: ApnsH2Auth) -> Result<Self, RuntimeError> {
        Self::with_roots(auth, rustls::RootCertStore::empty())
    }

    fn with_roots(
        auth: ApnsH2Auth,
        root_certs: rustls::RootCertStore,
    ) -> Result<Self, RuntimeError> {
        let auth = ApnsH2AuthRuntime::from_auth(auth)?;
        let root_cert_count = root_certs.len();
        let tls_connector = build_tls_connector(&root_certs, &auth)?;
        Ok(Self {
            timeout: DEFAULT_WAKE_TIMEOUT,
            coalescer: WakeCoalescer::new(DEFAULT_WAKE_COALESCE_INTERVAL_SECS),
            auth,
            default_topic: None,
            allow_custom_host: false,
            root_cert_count,
            tls_connector,
            pool: StdMutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(1),
        })
    }

    /// Permits non-Apple, non-loopback APNs endpoints (intended only for local loopback or mock-server tests).
    #[must_use]
    pub fn with_allow_custom_host(mut self, allow: bool) -> Self {
        self.allow_custom_host = allow;
        self
    }

    /// Replaces the TLS root certificate store and clears any pooled connections.
    pub fn with_root_certs(
        mut self,
        root_certs: rustls::RootCertStore,
    ) -> Result<Self, RuntimeError> {
        self.root_cert_count = root_certs.len();
        self.tls_connector = build_tls_connector(&root_certs, &self.auth)?;
        self.pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        Ok(self)
    }

    /// Sets the default `apns-topic` header (overridable on [`WakeTarget`]).
    pub fn with_topic(mut self, topic: impl Into<String>) -> Result<Self, RuntimeError> {
        let topic = topic.into();
        validate_apns_topic(&topic)?;
        self.default_topic = Some(topic);
        Ok(self)
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

    /// Returns the number of loaded TLS root certificates.
    #[must_use]
    pub fn root_cert_count(&self) -> usize {
        self.root_cert_count
    }

    fn pool_slot(&self, host: &str, port: u16) -> PoolSlot {
        let key = (host.to_ascii_lowercase(), port);
        let mut map = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            map.entry(key)
                .or_insert_with(|| Arc::new(AsyncMutex::new(None))),
        )
    }

    async fn dial_h2(&self, parsed: &Url) -> Result<PooledH2Conn, RuntimeError> {
        let tcp = resolve_and_connect_with_policy(parsed, !self.allow_custom_host).await?;
        let host = parsed
            .host_str()
            .ok_or_else(|| RuntimeError::Protocol("wake URL missing host".into()))?;
        let bare = strip_host_brackets(host).trim_end_matches('.').to_owned();
        let server_name = ServerName::try_from(bare)
            .map_err(|err| RuntimeError::Protocol(format!("invalid TLS server name: {err}")))?;
        let tls_stream = self
            .tls_connector
            .connect(server_name, tcp)
            .await
            .map_err(|err| RuntimeError::Protocol(format!("APNs TLS handshake failed: {err}")))?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(RuntimeError::Protocol(
                "APNs endpoint did not negotiate HTTP/2 ALPN".into(),
            ));
        }
        let (send_request, connection) = h2::client::handshake(tls_stream)
            .await
            .map_err(|err| map_h2_error("APNs HTTP/2 handshake failed", &err))?;
        let conn_task = tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(error = %redact_text(&err.to_string()), "APNs HTTP/2 connection closed");
            }
        });
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        Ok(PooledH2Conn {
            id,
            send_request,
            conn_task,
        })
    }

    async fn acquire_conn(
        &self,
        slot: &PoolSlot,
        parsed: &Url,
    ) -> Result<(u64, h2::client::SendRequest<Bytes>, bool), RuntimeError> {
        let mut guard = slot.lock().await;
        if let Some(ref existing) = *guard {
            if existing.conn_task.is_finished() {
                *guard = None;
            } else {
                return Ok((existing.id, existing.send_request.clone(), true));
            }
        }
        let fresh = self.dial_h2(parsed).await?;
        let id = fresh.id;
        let send_req = fresh.send_request.clone();
        *guard = Some(fresh);
        Ok((id, send_req, false))
    }

    async fn invalidate_and_reconnect(
        &self,
        slot: &PoolSlot,
        failed_id: u64,
        parsed: &Url,
    ) -> Result<(u64, h2::client::SendRequest<Bytes>), RuntimeError> {
        let mut guard = slot.lock().await;
        if guard.as_ref().is_some_and(|c| c.id == failed_id) {
            *guard = None;
        } else if let Some(ref existing) = *guard
            && !existing.conn_task.is_finished()
        {
            return Ok((existing.id, existing.send_request.clone()));
        }
        let fresh = self.dial_h2(parsed).await?;
        let id = fresh.id;
        let send_req = fresh.send_request.clone();
        *guard = Some(fresh);
        Ok((id, send_req))
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_with_pool(
        &self,
        parsed: &Url,
        target: &WakeTarget,
        topic: &str,
        tag: &WakeTag,
        now_unix_secs: u64,
        body_vec: Vec<u8>,
        auth_token: Option<&str>,
    ) -> Result<(u16, Vec<u8>), RuntimeError> {
        let host = parsed
            .host_str()
            .ok_or_else(|| RuntimeError::Protocol("wake URL missing host".into()))?;
        let bare = strip_host_brackets(host).trim_end_matches('.');
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| RuntimeError::Protocol("wake URL missing port".into()))?;
        let slot = self.pool_slot(bare, port);
        let body = Bytes::from(body_vec);

        let (conn_id, mut send_req, was_cached) = self.acquire_conn(&slot, parsed).await?;
        let req = build_h2_request(parsed, target, topic, tag, now_unix_secs, auth_token)?;

        match send_once_on_conn(&mut send_req, req, body.clone()).await {
            Ok(resp) => Ok(resp),
            Err(H2AttemptError::BeforeHeaders(err)) if was_cached => {
                tracing::debug!(
                    error = %redact_text(&err.to_string()),
                    "reconnecting pooled APNs HTTP/2 channel after GOAWAY/close"
                );
                let (_new_id, mut fresh_req) = self
                    .invalidate_and_reconnect(&slot, conn_id, parsed)
                    .await?;
                let retry_req =
                    build_h2_request(parsed, target, topic, tag, now_unix_secs, auth_token)?;
                send_once_on_conn(&mut fresh_req, retry_req, body)
                    .await
                    .map_err(|e| match e {
                        H2AttemptError::BeforeHeaders(err) => {
                            map_h2_error("APNs HTTP/2 request failed", &err)
                        }
                        H2AttemptError::AfterHeaders(err) => {
                            map_h2_error("APNs HTTP/2 response failed", &err)
                        }
                    })
            }
            Err(H2AttemptError::BeforeHeaders(err)) => {
                let mut guard = slot.lock().await;
                if guard.as_ref().is_some_and(|c| c.id == conn_id) {
                    *guard = None;
                }
                Err(map_h2_error("APNs HTTP/2 request failed", &err))
            }
            Err(H2AttemptError::AfterHeaders(err)) => {
                Err(map_h2_error("APNs HTTP/2 response failed", &err))
            }
        }
    }
}

fn build_h2_request(
    parsed: &Url,
    target: &WakeTarget,
    topic: &str,
    tag: &WakeTag,
    now_unix_secs: u64,
    auth_token: Option<&str>,
) -> Result<Request<()>, RuntimeError> {
    let host = parsed
        .host_str()
        .ok_or_else(|| RuntimeError::Protocol("wake URL missing host".into()))?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let path_and_query = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_owned(),
    };
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(path_and_query.as_str())
        .build()
        .map_err(|err| RuntimeError::Protocol(format!("invalid APNs HTTP/2 URI: {err}")))?;

    let (push_type, priority) = match target.apns_mode() {
        ApnsPushMode::Background => ("background", "5"),
        ApnsPushMode::MutableAlert => ("alert", "10"),
    };
    let expiration = wake_epoch_start_secs(now_unix_secs)
        .saturating_add(WAKE_EPOCH_SECS)
        .to_string();
    let collapse_id = tag.to_b64url();

    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            "apns-topic",
            HeaderValue::from_str(topic)
                .map_err(|_| RuntimeError::Protocol("invalid apns-topic header value".into()))?,
        )
        .header("apns-push-type", HeaderValue::from_static(push_type))
        .header("apns-priority", HeaderValue::from_static(priority))
        .header(
            "apns-collapse-id",
            HeaderValue::from_str(&collapse_id).map_err(|_| {
                RuntimeError::Protocol("invalid apns-collapse-id header value".into())
            })?,
        )
        .header(
            "apns-expiration",
            HeaderValue::from_str(&expiration).map_err(|_| {
                RuntimeError::Protocol("invalid apns-expiration header value".into())
            })?,
        )
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    if let Some(tok) = auth_token {
        let auth_val = Zeroizing::new(format!("bearer {tok}"));
        let hv = HeaderValue::from_str(&auth_val)
            .map_err(|_| RuntimeError::Protocol("invalid APNs authorization token".into()))?;
        builder = builder.header(AUTHORIZATION, hv);
    }

    builder.body(()).map_err(|err| {
        RuntimeError::Protocol(format!("failed to build APNs HTTP/2 request: {err}"))
    })
}

async fn send_once_on_conn(
    send_req: &mut h2::client::SendRequest<Bytes>,
    req: Request<()>,
    body: Bytes,
) -> Result<(u16, Vec<u8>), H2AttemptError> {
    std::future::poll_fn(|cx| send_req.poll_ready(cx))
        .await
        .map_err(H2AttemptError::BeforeHeaders)?;

    let (resp_fut, mut send_stream) = send_req
        .send_request(req, body.is_empty())
        .map_err(H2AttemptError::BeforeHeaders)?;
    if !body.is_empty() {
        send_stream
            .send_data(body, true)
            .map_err(H2AttemptError::BeforeHeaders)?;
    }
    let (head, mut resp_body) = resp_fut
        .await
        .map_err(H2AttemptError::BeforeHeaders)?
        .into_parts();
    let status = head.status.as_u16();
    let mut out = Vec::new();
    let mut flow = resp_body.flow_control().clone();
    while let Some(chunk_res) = resp_body.data().await {
        let chunk = chunk_res.map_err(H2AttemptError::AfterHeaders)?;
        let take = chunk
            .len()
            .min(MAX_WAKE_RESPONSE_BYTES.saturating_sub(out.len()));
        out.extend_from_slice(&chunk[..take]);
        let _ = flow.release_capacity(chunk.len());
        if out.len() >= MAX_WAKE_RESPONSE_BYTES {
            break;
        }
    }
    Ok((status, out))
}

#[async_trait]
impl WakeProvider for ApnsH2WakeProvider {
    async fn notify(
        &self,
        target: &WakeTarget,
        tag: &WakeTag,
        now_unix_secs: u64,
    ) -> Result<WakeOutcome, RuntimeError> {
        if target.adapter() != WakeAdapterKind::ApnsH2 {
            return Err(RuntimeError::Protocol(
                "ApnsH2WakeProvider requires apns_h2 wake adapter".into(),
            ));
        }
        let parsed = validate_apns_h2_endpoint_url(target.endpoint_str())?;
        validate_apns_h2_endpoint_host(&parsed, self.allow_custom_host)?;
        let topic = target
            .apns_topic()
            .or(self.default_topic.as_deref())
            .ok_or_else(|| RuntimeError::Protocol("apns-topic is required for apns_h2".into()))?;
        validate_apns_topic(topic)?;

        if target.auth_token().is_some() {
            return Err(RuntimeError::Protocol(
                "wake_auth_token must be configured on ApnsH2Auth, not WakeTarget".into(),
            ));
        }
        let auth_token = match &self.auth {
            ApnsH2AuthRuntime::ProviderToken(signer) => Some(signer.token_for(now_unix_secs)?),
            ApnsH2AuthRuntime::BearerToken(tok) => Some(tok.clone()),
            ApnsH2AuthRuntime::ClientCert { .. } => None,
        };

        let body_vec = build_wake_payload_for_target(target, tag, now_unix_secs)?;
        if !self.coalescer.check_and_record(target, now_unix_secs) {
            return Ok(WakeOutcome::Coalesced);
        }

        let (status, resp_body) = timeout(
            self.timeout,
            self.send_with_pool(
                &parsed,
                target,
                topic,
                tag,
                now_unix_secs,
                body_vec,
                auth_token.as_deref().map(String::as_str),
            ),
        )
        .await
        .map_err(|_| RuntimeError::Timeout("APNs HTTP/2 wake delivery timed out"))??;

        if (200..300).contains(&status) {
            Ok(WakeOutcome::Delivered)
        } else {
            let reason =
                format_apns_error_body(&resp_body, auth_token.as_deref().map(String::as_str));
            if reason.is_empty() {
                Err(RuntimeError::Protocol(format!(
                    "APNs endpoint returned HTTP status {status}"
                )))
            } else {
                Err(RuntimeError::Protocol(format!(
                    "APNs endpoint returned HTTP status {status}: {reason}"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::PooledH2Conn;
    use crate::wake::check_resolved_wake_ip;

    #[test]
    fn apns_h2_resolved_ip_rejects_private_rfc1918_ula_and_rebound_loopback() {
        for bad_ip in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 5, 10)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("fd12:3456:789a::1".parse().unwrap()),
            IpAddr::V6("::ffff:10.0.0.1".parse().unwrap()),
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
        ] {
            assert!(
                check_resolved_wake_ip(bad_ip, false, "api.push.apple.com", true).is_err(),
                "expected non-public resolved IP rejection for {bad_ip}"
            );
        }

        // Public IP for Apple host is accepted.
        assert!(
            check_resolved_wake_ip(
                IpAddr::V4(Ipv4Addr::new(17, 188, 128, 1)),
                false,
                "api.push.apple.com",
                true,
            )
            .is_ok()
        );

        // Loopback host allows only loopback IPs and rejects RFC1918.
        assert!(
            check_resolved_wake_ip(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                false,
                "localhost",
                true,
            )
            .is_ok()
        );
        assert!(
            check_resolved_wake_ip(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                false,
                "localhost",
                true,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn pooled_h2_conn_drop_aborts_conn_task() {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let srv_task = tokio::spawn(async move {
            if let Ok(mut conn) = h2::server::handshake(server_io).await {
                while let Some(Ok(_)) = conn.accept().await {}
            }
        });
        let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();

        struct AbortGuard {
            flag: Arc<AtomicBool>,
            done: Arc<Notify>,
        }
        impl Drop for AbortGuard {
            fn drop(&mut self) {
                self.flag.store(true, Ordering::SeqCst);
                self.done.notify_waiters();
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let done = Arc::new(Notify::new());
        let guard = AbortGuard {
            flag: Arc::clone(&dropped),
            done: Arc::clone(&done),
        };
        let conn_task = tokio::spawn(async move {
            let _guard = guard;
            let _ = connection.await;
            std::future::pending::<()>().await;
        });

        let pooled = PooledH2Conn {
            id: 1,
            send_request,
            conn_task,
        };
        assert!(!dropped.load(Ordering::SeqCst));
        let notified = done.notified();
        tokio::pin!(notified);
        drop(pooled);
        tokio::time::timeout(Duration::from_secs(1), notified)
            .await
            .expect("dropping PooledH2Conn must abort conn_task promptly");
        assert!(dropped.load(Ordering::SeqCst));
        srv_task.abort();
    }
}
