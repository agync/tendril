//! Opt-in browser WebAssembly `iroh` P2P stream dialer (`p2p-iroh` feature).

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex};

use futures_util::lock::Mutex as AsyncMutex;
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, TransportAddr,
};
use n0_future::time::{Duration, timeout};
use tendril_core::MAX_FRAME_LEN;
use url::Url;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const TENDRIL_P2P_ALPN: &[u8] = b"tendril/p2p/v1";
const P2P_STREAM_MAGIC: u8 = 0x54;
const MAX_OUTER_FRAME_LEN: usize = 2 + MAX_FRAME_LEN;

fn to_js_err(err: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

fn strip_host_brackets(host: &str) -> &str {
    let trimmed = host.trim();
    trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed)
}

fn is_loopback_host(host: &str) -> bool {
    let bare = strip_host_brackets(host).trim_end_matches('.');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return match canonical_ip(ip) {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        };
    }
    let suffix = b".localhost";
    let bare_bytes = bare.as_bytes();
    bare.eq_ignore_ascii_case("localhost")
        || (bare_bytes.len() > suffix.len()
            && bare_bytes[bare_bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
}

fn is_metadata_or_link_local_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    }
}

fn is_private_or_reserved_ip(ip: IpAddr) -> bool {
    if is_metadata_or_link_local_ip(ip) {
        return true;
    }
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || oct[0] == 0
                || (oct[0] == 100 && (oct[1] & 0xc0) == 64)
                || (oct[0] == 192 && oct[1] == 0 && oct[2] == 0)
                || (oct[0] == 198 && (oct[1] & 0xfe) == 18)
                || oct[0] >= 240
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_multicast()
                || (segs[0] & 0xfe00) == 0xfc00
                || (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] & 0xffc0) == 0xfec0
                || (segs[0] == 0x2001 && segs[1] == 0x0db8)
                || (segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0)
                || segs == [0, 0, 0, 0, 0, 0, 0, 0]
        }
    }
}

fn validate_iroh_relay_url_wasm(url_str: &str) -> Result<Url, String> {
    if url_str.chars().any(char::is_control) {
        return Err("iroh relay URL contains control characters".to_owned());
    }
    let trimmed = url_str.trim();
    let parsed =
        Url::parse(trimmed).map_err(|err| format!("invalid iroh relay URL '{url_str}': {err}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("iroh relay URL userinfo credentials are not permitted".to_owned());
    }
    if parsed.fragment().is_some() || parsed.query().is_some() {
        return Err("iroh relay URL query and fragment are not permitted".to_owned());
    }
    let is_http = match parsed.scheme() {
        "https" => false,
        "http" => true,
        other => return Err(format!("unsupported iroh relay URL scheme '{other}'")),
    };
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "iroh relay URL is missing a host".to_owned())?;
    let bare = strip_host_brackets(host);
    if bare
        .trim_end_matches('.')
        .eq_ignore_ascii_case("metadata.google.internal")
    {
        return Err("cloud metadata hostname is not permitted".to_owned());
    }
    if let Ok(ip) = bare.trim_end_matches('.').parse::<IpAddr>()
        && is_metadata_or_link_local_ip(ip)
    {
        return Err(format!(
            "link-local or metadata address '{ip}' is not permitted"
        ));
    }
    if is_http && !is_loopback_host(bare) {
        return Err(
            "cleartext http:// iroh relay URL is permitted only for loopback hosts".to_owned(),
        );
    }
    Ok(parsed)
}

/// Parses an `iroh://<endpoint_id>[?addr=...&relay=...]` URI into an [`EndpointAddr`].
pub fn parse_p2p_endpoint_uri(endpoint: &str) -> Result<EndpointAddr, String> {
    parse_p2p_endpoint_filtered(endpoint, true)
}

fn parse_p2p_endpoint_filtered(
    endpoint: &str,
    allow_private_addrs: bool,
) -> Result<EndpointAddr, String> {
    if endpoint.chars().any(char::is_control) {
        return Err("iroh endpoint contains control characters".to_owned());
    }
    let raw = endpoint
        .strip_prefix("iroh://")
        .ok_or_else(|| format!("iroh endpoint must use iroh:// scheme: '{endpoint}'"))?;
    let (id_part, query_part) = raw.split_once('?').unwrap_or((raw, ""));
    let id = EndpointId::from_str(id_part)
        .map_err(|err| format!("invalid iroh endpoint id '{id_part}': {err}"))?;

    let mut addrs = Vec::new();
    if !query_part.is_empty() {
        for pair in query_part.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, val) = pair
                .split_once('=')
                .ok_or_else(|| format!("invalid iroh query param '{pair}'"))?;
            match key {
                "addr" => {
                    let sock: SocketAddr = val
                        .parse()
                        .map_err(|err| format!("invalid iroh socket addr '{val}': {err}"))?;
                    if is_metadata_or_link_local_ip(sock.ip())
                        || (!allow_private_addrs && is_private_or_reserved_ip(sock.ip()))
                    {
                        continue;
                    }
                    addrs.push(TransportAddr::Ip(sock));
                }
                "relay" => {
                    let validated = validate_iroh_relay_url_wasm(val)?;
                    let url = RelayUrl::from_str(validated.as_str())
                        .map_err(|err| format!("invalid iroh relay URL '{val}': {err}"))?;
                    addrs.push(TransportAddr::Relay(url));
                }
                other => {
                    return Err(format!("unknown iroh endpoint query parameter '{other}'"));
                }
            }
        }
    }
    Ok(EndpointAddr::from_parts(id, addrs))
}

/// Validates and parses an `iroh://...` URI into JSON metadata for JS callers.
#[wasm_bindgen]
pub fn parse_p2p_endpoint_json(endpoint: &str) -> Result<String, JsValue> {
    let addr = parse_p2p_endpoint_uri(endpoint).map_err(to_js_err)?;
    let addrs: Vec<String> = addr.ip_addrs().map(ToString::to_string).collect();
    let relays: Vec<String> = addr.relay_urls().map(ToString::to_string).collect();
    Ok(serde_json::json!({
        "endpoint_id": addr.id.to_string(),
        "addrs": addrs,
        "relays": relays,
    })
    .to_string())
}

/// Bidirectional QUIC stream over `iroh` inside browser WASM (`ws_stream_wasm` relay transport).
#[wasm_bindgen]
pub struct WasmIrohStream {
    endpoint: Endpoint,
    conn: StdMutex<Option<Connection>>,
    send: Arc<AsyncMutex<Option<SendStream>>>,
    recv: Arc<AsyncMutex<Option<RecvStream>>>,
}

const MAX_P2P_RELAY_URLS: usize = 8;
const MAX_P2P_AUTH_TOKEN_BYTES: usize = 4_096;

fn validate_p2p_auth_token_wasm(raw: String) -> Result<Zeroizing<String>, String> {
    let token = Zeroizing::new(raw);
    if token.is_empty() || token.len() > MAX_P2P_AUTH_TOKEN_BYTES {
        return Err("iroh relay auth token length must be within 1..=4096 bytes".to_owned());
    }
    if token.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return Err("iroh relay auth token contains control characters".to_owned());
    }
    Ok(token)
}

fn build_relay_map_wasm(urls: &[String], auth_token: Option<&str>) -> Result<RelayMap, String> {
    if urls.is_empty() || urls.len() > MAX_P2P_RELAY_URLS {
        return Err(format!(
            "p2pRelayUrls must contain 1..={MAX_P2P_RELAY_URLS} URLs"
        ));
    }
    let mut configs = Vec::with_capacity(urls.len());
    for raw in urls {
        let validated = validate_iroh_relay_url_wasm(raw.trim())?;
        let url = RelayUrl::from_str(validated.as_str())
            .map_err(|e| format!("invalid relay URL '{raw}': {e}"))?;
        configs.push(RelayConfig::from(url));
    }
    let map = RelayMap::from_iter(configs);
    Ok(match auth_token {
        Some(tok) => map.with_auth_token(tok),
        None => map,
    })
}

async fn dial_with_relay_mode(
    addr: EndpointAddr,
    relay_mode: RelayMode,
    allow_n0_dns: bool,
    timeout_ms: Option<u32>,
) -> Result<WasmIrohStream, JsValue> {
    let budget = Duration::from_millis(u64::from(timeout_ms.unwrap_or(15_000).clamp(100, 120_000)));
    let mut builder = Endpoint::builder(presets::Minimal).relay_mode(relay_mode);
    if allow_n0_dns && addr.relay_urls().next().is_none() {
        builder = builder.address_lookup(iroh::address_lookup::PkarrResolver::n0_dns());
    }
    let ep = timeout(budget, builder.bind())
        .await
        .map_err(|_| to_js_err("iroh endpoint bind timed out"))?
        .map_err(|e| to_js_err(format!("iroh endpoint bind failed: {e}")))?;

    let dial_res = timeout(budget, async {
        let conn = ep
            .connect(addr, TENDRIL_P2P_ALPN)
            .await
            .map_err(|e| format!("iroh connect failed: {e}"))?;

        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("iroh open_bi failed: {e}"))?;

        // Write a 1-byte stream marker immediately so the peer's accept_bi() resolves.
        send.write_all(&[P2P_STREAM_MAGIC])
            .await
            .map_err(|e| format!("iroh opener write failed: {e}"))?;

        Ok::<_, String>((conn, send, recv))
    })
    .await;

    match dial_res {
        Ok(Ok((conn, send, recv))) => Ok(WasmIrohStream {
            endpoint: ep,
            conn: StdMutex::new(Some(conn)),
            send: Arc::new(AsyncMutex::new(Some(send))),
            recv: Arc::new(AsyncMutex::new(Some(recv))),
        }),
        Ok(Err(msg)) => {
            ep.close().await;
            Err(to_js_err(msg))
        }
        Err(_) => {
            ep.close().await;
            Err(to_js_err("timed out connecting to iroh endpoint"))
        }
    }
}

fn resolve_dial_relay_mode(
    addr: &EndpointAddr,
    relay_url_override: Option<&str>,
) -> Result<(RelayMode, bool), String> {
    if relay_url_override.is_some_and(|raw| raw.chars().any(char::is_control)) {
        return Err("iroh relay URL contains control characters".to_owned());
    }
    if let Some(url_str) = relay_url_override.map(str::trim).filter(|s| !s.is_empty()) {
        let validated = validate_iroh_relay_url_wasm(url_str)?;
        let url = RelayUrl::from_str(validated.as_str())
            .map_err(|e| format!("invalid relay URL '{url_str}': {e}"))?;
        return Ok((RelayMode::Custom(url.into()), false));
    }
    let addr_relays: Vec<RelayConfig> = addr.relay_urls().cloned().map(RelayConfig::from).collect();
    if addr_relays.len() > MAX_P2P_RELAY_URLS {
        return Err(format!(
            "iroh endpoint URI must contain at most {MAX_P2P_RELAY_URLS} relay URLs"
        ));
    }
    if !addr_relays.is_empty() {
        return Ok((RelayMode::Custom(RelayMap::from_iter(addr_relays)), false));
    }
    Ok((RelayMode::Default, true))
}

fn resolve_dial_with_options_relay_mode(
    addr: &EndpointAddr,
    relay_urls_json_opt: Option<&str>,
    auth_token: Option<&str>,
) -> Result<(RelayMode, bool), String> {
    if let Some(json_str) = relay_urls_json_opt {
        let urls: Vec<String> =
            serde_json::from_str(json_str).map_err(|e| format!("invalid relay_urls_json: {e}"))?;
        let map = build_relay_map_wasm(&urls, auth_token)?;
        return Ok((RelayMode::Custom(map), false));
    }
    let addr_relays: Vec<RelayConfig> = addr.relay_urls().cloned().map(RelayConfig::from).collect();
    if addr_relays.len() > MAX_P2P_RELAY_URLS {
        return Err(format!(
            "iroh endpoint URI must contain at most {MAX_P2P_RELAY_URLS} relay URLs"
        ));
    }
    if !addr_relays.is_empty() {
        let map = RelayMap::from_iter(addr_relays);
        let map = match auth_token {
            Some(tok) => map.with_auth_token(tok),
            None => map,
        };
        return Ok((RelayMode::Custom(map), false));
    }
    if auth_token.is_some() {
        return Err(
            "p2pRelayAuthToken requires explicit p2pRelayUrls, relayUrlOverride, or ?relay= in endpoint URI; refusing to attach bearer token to default public n0 relays"
                .to_owned(),
        );
    }
    Ok((RelayMode::Default, true))
}

#[wasm_bindgen]
impl WasmIrohStream {
    /// Connects a fresh ephemeral `iroh` endpoint to `endpoint` and opens a Tendril tunnel stream.
    #[wasm_bindgen]
    pub async fn dial(
        endpoint: String,
        relay_url_override: Option<String>,
        timeout_ms: Option<u32>,
    ) -> Result<WasmIrohStream, JsValue> {
        let addr = parse_p2p_endpoint_filtered(&endpoint, false).map_err(to_js_err)?;
        let (relay_mode, allow_n0_dns) =
            resolve_dial_relay_mode(&addr, relay_url_override.as_deref()).map_err(to_js_err)?;
        dial_with_relay_mode(addr, relay_mode, allow_n0_dns, timeout_ms).await
    }

    /// Connects an ephemeral `iroh` endpoint with multi-relay `RelayMap` and optional bearer auth token.
    #[wasm_bindgen]
    pub async fn dial_with_options(
        endpoint: String,
        relay_urls_json_opt: Option<String>,
        auth_token_opt: Option<String>,
        timeout_ms: Option<u32>,
    ) -> Result<WasmIrohStream, JsValue> {
        let addr = parse_p2p_endpoint_filtered(&endpoint, false).map_err(to_js_err)?;
        let token = auth_token_opt
            .map(validate_p2p_auth_token_wasm)
            .transpose()
            .map_err(to_js_err)?;
        let (relay_mode, allow_n0_dns) = resolve_dial_with_options_relay_mode(
            &addr,
            relay_urls_json_opt.as_deref(),
            token.as_deref().map(String::as_str),
        )
        .map_err(to_js_err)?;
        dial_with_relay_mode(addr, relay_mode, allow_n0_dns, timeout_ms).await
    }

    /// Sends one bounded chunk over the open QUIC stream.
    #[wasm_bindgen]
    pub async fn send_chunk(&self, bytes: Vec<u8>) -> Result<(), JsValue> {
        if bytes.len() > MAX_OUTER_FRAME_LEN {
            return Err(to_js_err(format!(
                "frame length {} exceeds {}",
                bytes.len(),
                MAX_OUTER_FRAME_LEN
            )));
        }
        let mut guard = self.send.lock().await;
        let Some(send) = guard.as_mut() else {
            return Err(to_js_err("iroh stream is closed"));
        };
        send.write_all(&bytes)
            .await
            .map_err(|e| to_js_err(format!("iroh write failed: {e}")))
    }

    /// Reads the next chunk from the QUIC stream, or returns `None` on EOF.
    #[wasm_bindgen]
    pub async fn recv_chunk(&self) -> Result<Option<Vec<u8>>, JsValue> {
        let mut guard = self.recv.lock().await;
        let Some(recv) = guard.as_mut() else {
            return Ok(None);
        };
        let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
        match recv.read(&mut buf).await {
            Ok(Some(0)) | Ok(None) => Ok(None),
            Ok(Some(n)) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(e) => Err(to_js_err(format!("iroh read failed: {e}"))),
        }
    }

    /// Gracefully finishes the stream when idle and closes the ephemeral `iroh` endpoint.
    #[wasm_bindgen]
    pub async fn close(&self) {
        if let Some(mut sg) = self.send.try_lock()
            && let Some(mut s) = sg.take()
        {
            let _ = s.finish();
            let _ = timeout(Duration::from_millis(200), s.stopped()).await;
        }
        if let Some(conn) = self.conn.lock().ok().and_then(|mut cg| cg.take()) {
            conn.close(0u32.into(), b"closed");
        }
        // Close the endpoint before awaiting send/recv locks so parked I/O futures unblock immediately.
        self.endpoint.close().await;
        if let Some(mut s) = self.send.lock().await.take() {
            let _ = s.finish();
        }
        self.recv.lock().await.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_p2p_endpoint_uri_validates_scheme_and_query() {
        let ep_id = iroh::SecretKey::from_bytes(&[9u8; 32]).public();
        let bare = parse_p2p_endpoint_uri(&format!("iroh://{ep_id}")).expect("bare");
        assert_eq!(bare.id, ep_id);
        assert_eq!(bare.ip_addrs().count(), 0);
        assert_eq!(bare.relay_urls().count(), 0);

        let full = parse_p2p_endpoint_uri(&format!(
            "iroh://{ep_id}?addr=[::1]:4433&relay=https://relay.example/"
        ))
        .expect("full");
        assert_eq!(full.id, ep_id);
        assert_eq!(full.ip_addrs().count(), 1);
        assert_eq!(full.relay_urls().count(), 1);

        assert!(parse_p2p_endpoint_uri(&format!("{ep_id}")).is_err());
        assert!(parse_p2p_endpoint_uri(&format!("iroh://{ep_id}?bad=1")).is_err());
    }

    #[test]
    fn validate_iroh_relay_url_and_filtered_endpoint_wasm() {
        assert!(is_loopback_host("my-\u{00e9}.localhost"));
        assert!(!is_loopback_host("my-\u{00e9}-host.org"));
        assert!(validate_iroh_relay_url_wasm("https://relay.example/").is_ok());
        assert!(validate_iroh_relay_url_wasm("http://127.0.0.1:8080/").is_ok());
        assert!(validate_iroh_relay_url_wasm("http://[::1]:8080/").is_ok());
        assert!(validate_iroh_relay_url_wasm("http://evil.example/").is_err());
        assert!(validate_iroh_relay_url_wasm("https://169.254.169.254/").is_err());
        assert!(validate_iroh_relay_url_wasm("https://169.254.169.254./").is_err());
        assert!(validate_iroh_relay_url_wasm("https://169.254.169.254../").is_err());
        assert!(validate_iroh_relay_url_wasm("https://metadata.google.internal./").is_err());
        assert!(validate_iroh_relay_url_wasm("javascript:alert(1)").is_err());
        assert!(validate_iroh_relay_url_wasm("https://user@relay.example/").is_err());
        assert!(validate_iroh_relay_url_wasm("https://relay.example/\n").is_err());

        let ep_id = iroh::SecretKey::from_bytes(&[12u8; 32]).public();
        let uri = format!(
            "iroh://{ep_id}?addr=[::1]:4433&addr=192.168.1.5:4433&addr=169.254.169.254:80&addr=93.184.216.34:4433&relay=https://relay.example/"
        );
        let filtered = parse_p2p_endpoint_filtered(&uri, false).expect("filtered");
        let addrs: Vec<String> = filtered.ip_addrs().map(ToString::to_string).collect();
        assert_eq!(addrs, vec!["93.184.216.34:4433"]);
        assert_eq!(filtered.relay_urls().count(), 1);

        let priv_allowed = parse_p2p_endpoint_filtered(&uri, true).expect("priv allowed");
        let priv_addrs: Vec<String> = priv_allowed.ip_addrs().map(ToString::to_string).collect();
        assert!(!priv_addrs.iter().any(|a| a.starts_with("169.254.")));
        assert!(priv_addrs.contains(&"[::1]:4433".to_owned()));
        assert!(priv_addrs.contains(&"192.168.1.5:4433".to_owned()));
    }

    #[test]
    fn priv01_custom_relay_extraction_and_auth_token_fail_closed() {
        let ep_id = iroh::SecretKey::from_bytes(&[21u8; 32]).public();
        let with_relay = parse_p2p_endpoint_filtered(
            &format!("iroh://{ep_id}?relay=https://custom.relay.example/"),
            false,
        )
        .expect("with relay");
        let bare = parse_p2p_endpoint_filtered(&format!("iroh://{ep_id}"), false).expect("bare");

        let expected_url = RelayUrl::from_str("https://custom.relay.example/").unwrap();
        // dial() with ?relay= uses RelayMode::Custom and disables n0 DNS
        let (mode, allow_n0) = resolve_dial_relay_mode(&with_relay, None).expect("custom");
        assert!(!allow_n0);
        match mode {
            RelayMode::Custom(map) => {
                assert_eq!(map.len(), 1);
                assert!(map.get(&expected_url).is_some());
            }
            other => panic!("expected RelayMode::Custom, got {other:?}"),
        }

        // dial() without ?relay= or override uses RelayMode::Default
        let (mode_def, allow_n0_def) = resolve_dial_relay_mode(&bare, None).expect("default");
        assert!(allow_n0_def);
        assert!(matches!(mode_def, RelayMode::Default));

        // dial_with_options() with auth_token and NO explicit relay URLs and NO ?relay= MUST fail closed
        let err = resolve_dial_with_options_relay_mode(&bare, None, Some("secret-bearer"))
            .expect_err("must fail closed");
        assert!(err.contains("refusing to attach bearer token"));

        // dial_with_options() with auth_token and ?relay= builds Custom RelayMap and disables n0 DNS
        let (mode_tok, allow_n0_tok) =
            resolve_dial_with_options_relay_mode(&with_relay, None, Some("secret-bearer"))
                .expect("token with ?relay=");
        assert!(!allow_n0_tok);
        match mode_tok {
            RelayMode::Custom(map) => {
                assert_eq!(map.len(), 1);
                assert!(map.get(&expected_url).is_some());
            }
            other => panic!("expected RelayMode::Custom, got {other:?}"),
        }

        // dial_with_options() without auth_token and with ?relay= builds Custom RelayMap and disables n0 DNS
        let (mode_no_tok, allow_n0_no_tok) =
            resolve_dial_with_options_relay_mode(&with_relay, None, None).expect("no token");
        assert!(!allow_n0_no_tok);
        assert!(matches!(mode_no_tok, RelayMode::Custom(_)));
    }
}
