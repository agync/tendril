//! Opt-in browser WebAssembly `iroh` P2P stream dialer (`p2p-iroh` feature).

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use futures_util::lock::Mutex as AsyncMutex;
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, TransportAddr};
use tendril_core::MAX_FRAME_LEN;
use wasm_bindgen::prelude::*;

const TENDRIL_P2P_ALPN: &[u8] = b"tendril/p2p/v1";
const P2P_STREAM_MAGIC: u8 = 0x54;
const MAX_OUTER_FRAME_LEN: usize = 2 + MAX_FRAME_LEN;

fn to_js_err(err: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}

/// Parses an `iroh://<endpoint_id>[?addr=...&relay=...]` URI into an [`EndpointAddr`].
pub fn parse_p2p_endpoint_uri(endpoint: &str) -> Result<EndpointAddr, String> {
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
                    addrs.push(TransportAddr::Ip(sock));
                }
                "relay" => {
                    let url = RelayUrl::from_str(val)
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
    conn: Arc<AsyncMutex<Option<Connection>>>,
    send: Arc<AsyncMutex<Option<SendStream>>>,
    recv: Arc<AsyncMutex<Option<RecvStream>>>,
}

#[wasm_bindgen]
impl WasmIrohStream {
    /// Connects a fresh ephemeral `iroh` endpoint to `endpoint` and opens a Tendril tunnel stream.
    #[wasm_bindgen]
    pub async fn dial(
        endpoint: String,
        relay_url_override: Option<String>,
    ) -> Result<WasmIrohStream, JsValue> {
        let addr = parse_p2p_endpoint_uri(&endpoint).map_err(to_js_err)?;
        let builder = match relay_url_override
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(url_str) => {
                let url = RelayUrl::from_str(url_str)
                    .map_err(|e| to_js_err(format!("invalid relay URL '{url_str}': {e}")))?;
                Endpoint::builder(presets::N0).relay_mode(RelayMode::Custom(url.into()))
            }
            None => Endpoint::builder(presets::N0).relay_mode(RelayMode::Default),
        };
        let ep = builder
            .bind()
            .await
            .map_err(|e| to_js_err(format!("iroh endpoint bind failed: {e}")))?;

        let conn = match ep.connect(addr, TENDRIL_P2P_ALPN).await {
            Ok(c) => c,
            Err(e) => {
                ep.close().await;
                return Err(to_js_err(format!("iroh connect failed: {e}")));
            }
        };

        let (mut send, recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                drop(conn);
                ep.close().await;
                return Err(to_js_err(format!("iroh open_bi failed: {e}")));
            }
        };

        // Write a 1-byte stream marker immediately so the peer's accept_bi() resolves.
        if let Err(e) = send.write_all(&[P2P_STREAM_MAGIC]).await {
            drop(send);
            drop(recv);
            drop(conn);
            ep.close().await;
            return Err(to_js_err(format!("iroh opener write failed: {e}")));
        }

        Ok(Self {
            endpoint: ep,
            conn: Arc::new(AsyncMutex::new(Some(conn))),
            send: Arc::new(AsyncMutex::new(Some(send))),
            recv: Arc::new(AsyncMutex::new(Some(recv))),
        })
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

    /// Gracefully finishes the stream and closes the ephemeral `iroh` endpoint.
    #[wasm_bindgen]
    pub async fn close(&self) {
        {
            let mut sg = self.send.lock().await;
            if let Some(mut s) = sg.take() {
                let _ = s.finish();
            }
        }
        {
            let mut rg = self.recv.lock().await;
            rg.take();
        }
        {
            let mut cg = self.conn.lock().await;
            cg.take();
        }
        self.endpoint.close().await;
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
}
