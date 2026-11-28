//! Generates `spec/vectors/routes.json` from deterministic keys using real hybrid signatures.

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

use tendril_core::crypto::{HYBRID_SIG_LEN, SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    PAIRING_ROUTES_DOMAIN, PairRouteBinding, PairingUri, route_statement_input,
    sign_route_statement,
};
use tendril_core::routes::{MAX_ROUTE_SEQ, ROUTE_SET_DOMAIN, RouteSet};
use tendril_core::wire::SessionHello;

const STATIC_SCALAR: [u8; 32] = [0x61; 32];
const SIGNING_SEED: [u8; 32] = [0x62; 32];
const SIGNING_MLDSA_SEED: [u8; 32] = [0x63; 32];
const ISSUED_AT: u64 = 1_795_564_800;

fn sign_case(
    id: &EndpointIdentity,
    name: &str,
    seq: u64,
    routes: &[&str],
) -> Result<Value, Box<dyn std::error::Error>> {
    let routes: Vec<String> = routes.iter().map(|r| (*r).to_owned()).collect();
    let set = RouteSet::sign_deterministic(id, seq, ISSUED_AT, routes.clone())?;
    let payload = set.encode();
    let (body, sig) = payload.split_at(payload.len() - HYBRID_SIG_LEN);
    Ok(json!({
        "name": name,
        "seq": seq,
        "issued_at": ISSUED_AT,
        "routes": routes,
        "body_hex": hex::encode(body),
        "signed_bytes_hex": hex::encode(set.signed_bytes()),
        "sig_hex": hex::encode(sig),
    }))
}

/// Re-encodes the body of `set` with its fields replaced.
fn mutated(set: &RouteSet, f: impl FnOnce(&mut RouteSet)) -> Vec<u8> {
    let mut m = set.clone();
    f(&mut m);
    body_of(&m.encode())
}

fn body_of(payload: &[u8]) -> Vec<u8> {
    payload[..payload.len() - HYBRID_SIG_LEN].to_vec()
}

const RS_ROUTE_SEQ: u64 = 7;

/// A fixed signed pairing URI: the exact `rs` input bytes and the Ed25519 signature over them.
fn pairing_route_statement(id: &EndpointIdentity) -> Result<Value, Box<dyn std::error::Error>> {
    let hints = vec![
        "direct:192.168.1.20:9100".to_owned(),
        "overlay://100.64.0.10:9100".to_owned(),
        "wss://relay.example.com/v1/relay".to_owned(),
    ];
    let mut uri = PairingUri::new(
        "Studio Host",
        "TND-ABCD-EFGH-JKLM",
        *id.static_key().public_bytes(),
        id.signing_key().signing_pub_hash(),
        hints.clone(),
        Some(id.host_id().to_owned()),
        Some(0),
    );
    uri.relay_pub = Some(*id.signing_key().ed25519_public_bytes());
    let prefix = format!("{}&rq={RS_ROUTE_SEQ}", uri.try_encode()?);
    let sig = sign_route_statement(id, &prefix);
    let full = format!("{prefix}&rs={}", b64url_encode(&sig));
    PairingUri::parse(&full)?;
    Ok(json!({
        "domain_hex": hex::encode(PAIRING_ROUTES_DOMAIN),
        "ed25519_pub_hex": hex::encode(id.signing_key().ed25519_public_bytes()),
        "route_seq": RS_ROUTE_SEQ,
        "hints": hints,
        "uri_bytes_before_rs": prefix,
        "rs_input_hex": hex::encode(route_statement_input(&prefix)),
        "rs_hex": hex::encode(sig),
        "uri": full,
    }))
}

fn signed_uri(signer: &EndpointIdentity, uri: &PairingUri) -> Result<String, CoreError> {
    let prefix = format!("{}&rq={RS_ROUTE_SEQ}", uri.try_encode()?);
    let sig = sign_route_statement(signer, &prefix);
    Ok(format!("{prefix}&rs={}", b64url_encode(&sig)))
}

const URI_STATIC_SCALAR: [u8; 32] = [0x64; 32];
const URI_SIGNING_SEED: [u8; 32] = [0x65; 32];
const URI_SIGNING_MLDSA_SEED: [u8; 32] = [0x66; 32];

/// Pre-`msg3` checks of a URI-bound initiator (spec 6.5 steps 1-3). The responder always
/// presents the fixed host key: as the URI's own key, as a key rotated once from the URI's key
/// (`URI_*` seeds, rotated at `ISSUED_AT`), or as an unrelated key with no chain to it.
fn pairing_route_check(id: &EndpointIdentity) -> Result<Value, Box<dyn std::error::Error>> {
    let old = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(URI_STATIC_SCALAR),
        SigningKeypair::from_seeds(URI_SIGNING_SEED, URI_SIGNING_MLDSA_SEED),
    );
    let uri_of = |key: &EndpointIdentity, hints: &[&str], rp: Option<&EndpointIdentity>| {
        let mut uri = PairingUri::new(
            "Studio Host",
            "TND-ABCD-EFGH-JKLM",
            *key.static_key().public_bytes(),
            key.signing_key().signing_pub_hash(),
            hints.iter().map(|h| (*h).to_owned()).collect(),
            Some(key.host_id().to_owned()),
            Some(0),
        );
        uri.relay_pub = rp.map(|r| *r.signing_key().ed25519_public_bytes());
        uri
    };
    let tamper = |uri: &str| uri.replacen("192.168.1.20", "192.168.1.21", 1);
    let relayed = [
        "direct:192.168.1.20:9100",
        "wss://relay.example.com/v1/relay",
    ];
    let direct = ["direct:192.168.1.20:9100"];
    let verified = signed_uri(id, &uri_of(id, &relayed, Some(id)))?;
    let rp_mismatch = signed_uri(id, &uri_of(id, &relayed, Some(&old)))?;
    let by_old = signed_uri(&old, &uri_of(&old, &direct, None))?;
    let old_ed = *old.signing_key().ed25519_public_bytes();
    let (own, rotated, unrelated) = ("uri_key", "rotated_from_uri_key", "unrelated_key");
    let cases: Vec<(&str, String, &str, Option<[u8; 32]>)> = vec![
        ("verified", verified.clone(), own, None),
        (
            "unsigned",
            uri_of(id, &relayed, Some(id)).try_encode()?,
            own,
            None,
        ),
        ("route_key_rotated", by_old.clone(), rotated, None),
        ("route_key_rotated_stale_rs", tamper(&by_old), rotated, None),
        ("invalid_rs", tamper(&verified), own, None),
        ("rp_mismatch", rp_mismatch.clone(), own, None),
        (
            "rp_mismatch_and_invalid_rs",
            tamper(&rp_mismatch),
            own,
            None,
        ),
        (
            "operator_key_mismatch",
            signed_uri(id, &uri_of(id, &direct, None))?,
            own,
            Some(old_ed),
        ),
        ("unchained_key", by_old, unrelated, None),
    ];
    let key = id.signing_key().public_key();
    let mut out = Vec::new();
    for (name, uri, responder, operator) in cases {
        let binding = PairRouteBinding::new(Some(PairingUri::parse(&uri)?), operator)?;
        let pin_ok = responder != unrelated;
        let verdict = pin_ok.then(|| binding.verdict(key));
        let commit_error = match verdict.as_ref().map(|v| v.committable()) {
            Some(Ok(_)) => Value::Null,
            None | Some(Err(CoreError::HostKeyUnverified)) => json!("host_key_unverified"),
            Some(Err(CoreError::InvalidPairingUri(_))) => json!("invalid_pairing_uri"),
            Some(Err(other)) => return Err(other.into()),
        };
        let mut case = json!({
            "name": name,
            "uri": uri,
            "responder": responder,
            "presented_static_pub_hex": hex::encode(id.static_key().public_bytes()),
            "presented_ed25519_pub_hex": hex::encode(key.ed25519_bytes()),
            "presented_signing_pub_sha256_hex": hex::encode(key.sha256_hash()),
            "presented_rotation_seq": u64::from(responder == rotated),
            "pin_ok": pin_ok,
            "relay_pub_ok": verdict.as_ref().map(|v| v.relay_pub_ok()),
            "route_check": verdict.as_ref().map(|v| v.route_check().as_str()),
            "commit_error": commit_error,
            "wires": ["v1", "v2"],
        });
        if let Some(op) = operator {
            case["operator_relay_key_hex"] = json!(hex::encode(op));
        }
        out.push(case);
    }
    Ok(json!({
        "uri_identity": {
            "static_scalar_hex": hex::encode(URI_STATIC_SCALAR),
            "signing_seed_hex": hex::encode(URI_SIGNING_SEED),
            "signing_mldsa_seed_hex": hex::encode(URI_SIGNING_MLDSA_SEED),
            "rotated_at": ISSUED_AT,
        },
        "cases": out,
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    let id = EndpointIdentity::from_keys(
        StaticKeypair::from_scalar(STATIC_SCALAR),
        SigningKeypair::from_seeds(SIGNING_SEED, SIGNING_MLDSA_SEED),
    );
    let signing = id.signing_key();

    let cases = vec![
        sign_case(
            &id,
            "six_routes",
            42,
            &[
                "direct:192.168.1.20:9100",
                "direct:[fd00::20]:9100",
                "overlay://100.64.0.10:9100",
                "iroh://k51qzi5uqu5dl",
                "wss://relay.example.com/v1/relay",
                "broker+wss://broker.example.com/v1/broker",
            ],
        )?,
        sign_case(&id, "empty", 1, &[])?,
        sign_case(&id, "max_seq", MAX_ROUTE_SEQ, &["direct:10.0.0.5:9100"])?,
        sign_case(
            &id,
            "iroh_v2",
            7,
            &["iroh://v2?relay=https://relay.example.com"],
        )?,
    ];

    let base =
        RouteSet::sign_deterministic(&id, 3, ISSUED_AT, vec!["direct:192.168.1.20:9100".into()])?;
    let base_body = body_of(&base.encode());
    let count_at = 1 + 32 + 32 + 8 + 8;
    let mut count7 = base_body.clone();
    count7[count_at] = 7;
    let mut zero_len = base_body.clone();
    zero_len[count_at + 1..count_at + 3].copy_from_slice(&0u16.to_be_bytes());
    let mut bad_version = base_body.clone();
    bad_version[0] = 0x02;
    let empty_body = body_of(&RouteSet::sign_deterministic(&id, 1, ISSUED_AT, vec![])?.encode());
    let rejections = [
        ("trailing_byte", base_body.clone(), HYBRID_SIG_LEN + 1),
        ("truncated_3454", empty_body, HYBRID_SIG_LEN - 1),
        ("bad_version", bad_version, HYBRID_SIG_LEN),
        ("count_7", count7, HYBRID_SIG_LEN),
        ("hint_len_0", zero_len, HYBRID_SIG_LEN),
        ("seq_0", mutated(&base, |m| m.seq = 0), HYBRID_SIG_LEN),
        (
            "seq_2_53",
            mutated(&base, |m| m.seq = MAX_ROUTE_SEQ + 1),
            HYBRID_SIG_LEN,
        ),
        (
            "duplicate_hint",
            mutated(&base, |m| m.routes.push(m.routes[0].clone())),
            HYBRID_SIG_LEN,
        ),
        (
            "hint_with_fragment",
            mutated(&base, |m| {
                m.routes = vec!["wss://relay.example.com/v1/relay#key".into()];
            }),
            HYBRID_SIG_LEN,
        ),
        (
            "ipc_hint",
            mutated(&base, |m| m.routes = vec!["local:/run/tendril.sock".into()]),
            HYBRID_SIG_LEN,
        ),
        (
            "iroh_v2_addr",
            mutated(&base, |m| {
                m.routes = vec!["iroh://v2?addr=192.0.2.10:11204".into()];
            }),
            HYBRID_SIG_LEN,
        ),
    ];
    let rejections: Vec<Value> = rejections
        .iter()
        .map(|(name, body, filler)| {
            json!({ "name": name, "body_hex": hex::encode(body), "zero_filler_len": filler })
        })
        .collect();

    let hello = SessionHello {
        device_id: id.device_id(),
        grant: None,
        crl_seq: None,
        groups: None,
        route_seq: Some(42),
        upgrade: Vec::new(),
    };

    let doc = json!({
        "route_set": {
            "domain_hex": hex::encode(ROUTE_SET_DOMAIN),
            "static_scalar_hex": hex::encode(STATIC_SCALAR),
            "static_pub_hex": hex::encode(id.static_key().public_bytes()),
            "signing_seed_hex": hex::encode(SIGNING_SEED),
            "signing_mldsa_seed_hex": hex::encode(SIGNING_MLDSA_SEED),
            "signing_pub_hex": hex::encode(signing.public_bytes()),
            "sh_hex": hex::encode(signing.signing_pub_hash()),
            "sign_deterministic": cases,
            "decode_rejections": rejections,
        },
        "session_hello_route_seq": {
            "route_seq": 42,
            "json": serde_json::to_string(&hello)?,
        },
        "pairing_route_statement": pairing_route_statement(&id)?,
        "pairing_route_check": pairing_route_check(&id)?,
    });

    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    fs::write(dir.join("routes.json"), text)?;
    Ok(())
}
