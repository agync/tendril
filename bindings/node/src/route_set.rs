//! Verify-and-decode entry point for host-signed `0x0C ROUTE_SET` payloads.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tendril_core::crypto::HybridSigningPublicKey;
use tendril_core::routes::RouteSet;

/// Decodes a route set payload and verifies its hybrid signature against `signing_pub`.
///
/// Returns `{"seq","issued_at","routes"}` as JSON only when both the structure and the
/// signature are valid. Throws an `Error` naming the failed step: `signing key invalid`,
/// `route set decode failed`, or `route set signature invalid`. There is no unverified decode.
#[napi]
pub fn verify_route_set(payload: Buffer, signing_pub: Buffer) -> Result<String> {
    let fail = |msg: &str| Error::new(Status::GenericFailure, msg);
    let key = HybridSigningPublicKey::from_bytes(signing_pub.as_ref())
        .map_err(|_| fail("signing key invalid"))?;
    let set = RouteSet::decode(payload.as_ref()).map_err(|_| fail("route set decode failed"))?;
    set.verify(&key)
        .map_err(|_| fail("route set signature invalid"))?;
    Ok(serde_json::json!({
        "seq": set.seq,
        "issued_at": set.issued_at,
        "routes": set.routes,
    })
    .to_string())
}
