//! Generates `spec/vectors/routes.json` from deterministic keys using real hybrid signatures.

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

use tendril_core::crypto::{HYBRID_SIG_LEN, SigningKeypair, StaticKeypair, b64url_encode};
use tendril_core::identity::EndpointIdentity;
use tendril_core::pairing::{
    PAIRING_ROUTES_DOMAIN, PairingUri, route_statement_input, sign_route_statement,
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
    });

    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    fs::write(dir.join("routes.json"), text)?;
    Ok(())
}
