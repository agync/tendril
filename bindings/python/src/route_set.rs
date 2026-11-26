//! Verify-and-decode entry point for host-signed `0x0C ROUTE_SET` payloads.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use tendril_core::crypto::HybridSigningPublicKey;
use tendril_core::routes::RouteSet;

/// Decodes a route set payload and verifies its hybrid signature against `signing_pub`.
///
/// Returns `{"seq", "issued_at", "routes"}` as JSON only when both the structure and the
/// signature are valid. Raises `ValueError` naming the failed step: `signing key invalid`,
/// `route set decode failed`, or `route set signature invalid`. There is no unverified decode.
#[pyfunction]
pub fn verify_route_set(payload: &[u8], signing_pub: &[u8]) -> PyResult<String> {
    let key = HybridSigningPublicKey::from_bytes(signing_pub)
        .map_err(|_| PyValueError::new_err("signing key invalid"))?;
    let set =
        RouteSet::decode(payload).map_err(|_| PyValueError::new_err("route set decode failed"))?;
    set.verify(&key)
        .map_err(|_| PyValueError::new_err("route set signature invalid"))?;
    Ok(serde_json::json!({
        "seq": set.seq,
        "issued_at": set.issued_at,
        "routes": set.routes,
    })
    .to_string())
}
