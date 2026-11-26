//! Host-signed route sets carried in the `0x0C ROUTE_SET` inner frame.
//!
//! A route set binds the host's current Noise static key, the hash of its hybrid signing key, a
//! persistent sequence, an issue time, and up to six endpoint hints under one hybrid
//! `Ed25519 || ML-DSA-65` signature. This module is the codec only: decoding enforces structure,
//! and verification checks the signature. Key binding, sequence and policy rules belong to the
//! roster.

use std::collections::BTreeSet;
use std::fmt;

use crate::crypto::{
    HYBRID_SIG_LEN, HYBRID_SIGNING_HASH_LEN, HybridSigningPublicKey, SigningKeypair,
};
use crate::error::CoreError;
use crate::identity::EndpointIdentity;
use crate::pairing::is_valid_pairing_endpoint_hint;

/// Domain prefix prepended to the route set body before signing (`21` bytes).
pub const ROUTE_SET_DOMAIN: &[u8] = b"tendril-route-set-v1\0";

/// Route set body version byte.
pub const ROUTE_SET_VERSION: u8 = 0x01;

/// Largest `seq` a route set may carry (`2^53 - 1`).
pub const MAX_ROUTE_SEQ: u64 = (1 << 53) - 1;

/// Maximum number of routes in one set.
pub const MAX_ROUTE_SET_ROUTES: usize = 6;

/// Maximum byte length of one route hint.
pub const MAX_ROUTE_HINT_LEN: usize = 256;

/// Byte length of a route set body with zero routes.
pub const MIN_ROUTE_SET_BODY: usize = 1 + 32 + HYBRID_SIGNING_HASH_LEN + 8 + 8 + 1;

/// Smallest valid `0x0C` payload (`body || sig` with zero routes).
pub const MIN_ROUTE_SET_PAYLOAD: usize = MIN_ROUTE_SET_BODY + HYBRID_SIG_LEN;

/// Largest valid `0x0C` payload (six routes of 256 bytes each).
pub const MAX_ROUTE_SET_PAYLOAD: usize = 5_003;

const _: () = assert!(MIN_ROUTE_SET_PAYLOAD == 3_455);
const _: () = assert!(
    MAX_ROUTE_SET_PAYLOAD
        == MIN_ROUTE_SET_PAYLOAD + MAX_ROUTE_SET_ROUTES * (2 + MAX_ROUTE_HINT_LEN)
);

const STRUCTURE_ERR: CoreError = CoreError::InvalidInnerFramePayload("route set");

/// One host-signed route set (`0x0C ROUTE_SET` payload).
#[derive(Clone, PartialEq, Eq)]
pub struct RouteSet {
    /// Host Noise static public key the set was signed for.
    pub static_pub: [u8; 32],
    /// `SHA-256` of the host's 1984-byte hybrid signing public key.
    pub sh: [u8; HYBRID_SIGNING_HASH_LEN],
    /// Persistent monotonic sequence, `1..=2^53-1`.
    pub seq: u64,
    /// Unix seconds at which the host recorded this set.
    pub issued_at: u64,
    /// Endpoint hints in builder order.
    pub routes: Vec<String>,
    sig: Box<[u8; HYBRID_SIG_LEN]>,
}

impl RouteSet {
    /// Signs a route set for `identity` with hedged ML-DSA randomness.
    pub fn sign(
        identity: &EndpointIdentity,
        seq: u64,
        issued_at: u64,
        routes: Vec<String>,
    ) -> Result<Self, CoreError> {
        Self::sign_with(identity, seq, issued_at, routes, false)
    }

    /// Signs a route set deterministically (zero ML-DSA hedging seed); for test vectors only.
    pub fn sign_deterministic(
        identity: &EndpointIdentity,
        seq: u64,
        issued_at: u64,
        routes: Vec<String>,
    ) -> Result<Self, CoreError> {
        Self::sign_with(identity, seq, issued_at, routes, true)
    }

    fn sign_with(
        identity: &EndpointIdentity,
        seq: u64,
        issued_at: u64,
        routes: Vec<String>,
        deterministic: bool,
    ) -> Result<Self, CoreError> {
        Self::sign_for(
            identity.static_key().public_bytes(),
            identity.signing_key(),
            seq,
            issued_at,
            routes,
            deterministic,
        )
    }

    /// Signs a set for the host whose Noise static key is `static_pub` and whose current
    /// signing key is `signing`.
    pub(crate) fn sign_for(
        static_pub: &[u8; 32],
        signing: &SigningKeypair,
        seq: u64,
        issued_at: u64,
        routes: Vec<String>,
        deterministic: bool,
    ) -> Result<Self, CoreError> {
        validate_seq(seq)?;
        validate_routes(&routes)?;
        let mut set = Self {
            static_pub: *static_pub,
            sh: signing.signing_pub_hash(),
            seq,
            issued_at,
            routes,
            sig: Box::new([0u8; HYBRID_SIG_LEN]),
        };
        let message = set.signed_bytes();
        let sig = if deterministic {
            signing.sign_deterministic(&message)?
        } else {
            signing.sign(&message)?
        };
        set.sig = Box::new(sig.try_into().map_err(|_| CoreError::InvalidSignature)?);
        Ok(set)
    }

    /// Encodes the `0x0C` payload: `route_set_body || sig`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.sig[..]);
        out
    }

    /// Strictly decodes a `0x0C` payload, checking structure only (not the signature).
    ///
    /// Every failure is `InvalidInnerFramePayload("route set")`, which closes the session.
    pub fn decode(payload: &[u8]) -> Result<Self, CoreError> {
        if !(MIN_ROUTE_SET_PAYLOAD..=MAX_ROUTE_SET_PAYLOAD).contains(&payload.len()) {
            return Err(STRUCTURE_ERR);
        }
        let mut cur = Cursor(payload);
        if cur.take_array::<1>()? != [ROUTE_SET_VERSION] {
            return Err(STRUCTURE_ERR);
        }
        let static_pub = cur.take_array::<32>()?;
        let sh = cur.take_array::<HYBRID_SIGNING_HASH_LEN>()?;
        let seq = u64::from_be_bytes(cur.take_array::<8>()?);
        let issued_at = u64::from_be_bytes(cur.take_array::<8>()?);
        let [count] = cur.take_array::<1>()?;
        let count = usize::from(count);
        if count > MAX_ROUTE_SET_ROUTES {
            return Err(STRUCTURE_ERR);
        }
        let mut routes = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::from(u16::from_be_bytes(cur.take_array::<2>()?));
            if len == 0 || len > MAX_ROUTE_HINT_LEN {
                return Err(STRUCTURE_ERR);
            }
            let hint = std::str::from_utf8(cur.take(len)?).map_err(|_| STRUCTURE_ERR)?;
            routes.push(hint.to_owned());
        }
        let sig = cur.take_array::<HYBRID_SIG_LEN>()?;
        if !cur.0.is_empty() {
            return Err(STRUCTURE_ERR);
        }
        validate_seq(seq)?;
        validate_routes(&routes)?;
        Ok(Self {
            static_pub,
            sh,
            seq,
            issued_at,
            routes,
            sig: Box::new(sig),
        })
    }

    /// Returns `ROUTE_SET_DOMAIN || route_set_body`, the exact bytes the signature covers.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let body = self.body();
        let mut out = Vec::with_capacity(ROUTE_SET_DOMAIN.len() + body.len());
        out.extend_from_slice(ROUTE_SET_DOMAIN);
        out.extend_from_slice(&body);
        out
    }

    /// Verifies the hybrid signature over [`Self::signed_bytes`]; both halves must pass.
    ///
    /// Fails with `InvalidSignature`. Binding `static_pub` and `sh` to a pinned peer is the
    /// caller's check.
    pub fn verify(&self, key: &HybridSigningPublicKey) -> Result<(), CoreError> {
        key.verify(&self.signed_bytes(), &self.sig[..])
    }

    fn body(&self) -> Vec<u8> {
        let routes_len: usize = self.routes.iter().map(|r| 2 + r.len()).sum();
        let mut out = Vec::with_capacity(MIN_ROUTE_SET_BODY + routes_len);
        out.push(ROUTE_SET_VERSION);
        out.extend_from_slice(&self.static_pub);
        out.extend_from_slice(&self.sh);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.push(u8::try_from(self.routes.len()).unwrap_or(u8::MAX));
        for route in &self.routes {
            let len = u16::try_from(route.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(route.as_bytes());
        }
        out
    }
}

impl fmt::Debug for RouteSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteSet")
            .field("static_pub", &hex::encode(self.static_pub))
            .field("sh", &hex::encode(self.sh))
            .field("seq", &self.seq)
            .field("issued_at", &self.issued_at)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

fn validate_seq(seq: u64) -> Result<(), CoreError> {
    if seq == 0 || seq > MAX_ROUTE_SEQ {
        return Err(STRUCTURE_ERR);
    }
    Ok(())
}

fn validate_routes(routes: &[String]) -> Result<(), CoreError> {
    if routes.len() > MAX_ROUTE_SET_ROUTES {
        return Err(STRUCTURE_ERR);
    }
    let mut seen = BTreeSet::new();
    for route in routes {
        if route.is_empty()
            || route.len() > MAX_ROUTE_HINT_LEN
            || route.contains('#')
            || route.starts_with("local:")
            || route.starts_with("unix://")
            || !is_valid_pairing_endpoint_hint(route)
            || !seen.insert(route.as_str())
        {
            return Err(STRUCTURE_ERR);
        }
    }
    Ok(())
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CoreError> {
        if self.0.len() < n {
            return Err(STRUCTURE_ERR);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CoreError> {
        self.take(N)?.try_into().map_err(|_| STRUCTURE_ERR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ED25519_SIG_LEN, SigningKeypair, StaticKeypair};

    fn identity() -> EndpointIdentity {
        EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x11; 32]),
            SigningKeypair::from_seeds([0x22; 32], [0x33; 32]),
        )
    }

    fn six_routes() -> Vec<String> {
        vec![
            "direct:192.168.1.20:9100".into(),
            "direct:127.0.0.1:9100".into(),
            "overlay://100.64.0.10:9100".into(),
            "iroh://abc123".into(),
            "wss://relay.example.com/v1/relay".into(),
            "broker+wss://broker.example.com/v1/broker".into(),
        ]
    }

    fn long_hint(tag: char, len: usize) -> String {
        let prefix = format!("wss://relay.example.com/{tag}");
        let mut hint = prefix.clone();
        hint.extend(std::iter::repeat_n('a', len - prefix.len()));
        hint
    }

    fn signed(routes: Vec<String>) -> RouteSet {
        RouteSet::sign_deterministic(&identity(), 7, 1_795_219_200, routes).unwrap()
    }

    fn assert_structure_err<T: fmt::Debug>(res: Result<T, CoreError>) {
        assert_eq!(
            res.unwrap_err(),
            CoreError::InvalidInnerFramePayload("route set")
        );
    }

    #[test]
    fn round_trip_and_verify() {
        let id = identity();
        let set = RouteSet::sign(&id, 1, 1_795_219_200, six_routes()).unwrap();
        assert_eq!(set.static_pub, *id.static_key().public_bytes());
        assert_eq!(set.sh, id.signing_key().public_key().sha256_hash());
        let payload = set.encode();
        let decoded = RouteSet::decode(&payload).unwrap();
        assert_eq!(decoded, set);
        decoded.verify(id.signing_key().public_key()).unwrap();
        assert_eq!(
            &set.signed_bytes()[..ROUTE_SET_DOMAIN.len()],
            ROUTE_SET_DOMAIN
        );
        assert_eq!(
            set.signed_bytes()[ROUTE_SET_DOMAIN.len()..],
            payload[..payload.len() - HYBRID_SIG_LEN]
        );
    }

    #[test]
    fn deterministic_signing_is_stable() {
        assert_eq!(signed(six_routes()).encode(), signed(six_routes()).encode());
    }

    #[test]
    fn verify_rejects_tampering_and_wrong_key() {
        let id = identity();
        let mut set = signed(six_routes());
        set.verify(id.signing_key().public_key()).unwrap();

        let other = SigningKeypair::from_seeds([0x44; 32], [0x55; 32]);
        assert_eq!(
            set.verify(other.public_key()),
            Err(CoreError::InvalidSignature)
        );

        let mut tampered = set.clone();
        tampered.routes.pop();
        assert_eq!(
            tampered.verify(id.signing_key().public_key()),
            Err(CoreError::InvalidSignature)
        );

        set.seq += 1;
        assert_eq!(
            set.verify(id.signing_key().public_key()),
            Err(CoreError::InvalidSignature)
        );

        let mut payload = signed(six_routes()).encode();
        let last = payload.len() - 1;
        payload[last] ^= 1;
        let flipped = RouteSet::decode(&payload).unwrap();
        assert_eq!(
            flipped.verify(id.signing_key().public_key()),
            Err(CoreError::InvalidSignature)
        );
    }

    #[test]
    fn verify_requires_both_signature_halves() {
        let id = identity();
        let payload = signed(six_routes()).encode();
        let sig_at = payload.len() - HYBRID_SIG_LEN;
        let mldsa_at = sig_at + ED25519_SIG_LEN;
        for (half, at) in [
            ("Ed25519 first", sig_at),
            ("Ed25519 last", mldsa_at - 1),
            ("ML-DSA first", mldsa_at),
            ("ML-DSA last", payload.len() - 1),
        ] {
            let mut flipped = payload.clone();
            flipped[at] ^= 1;
            assert_eq!(
                RouteSet::decode(&flipped)
                    .unwrap()
                    .verify(id.signing_key().public_key()),
                Err(CoreError::InvalidSignature),
                "{half}"
            );
        }
    }

    #[test]
    fn payload_bounds() {
        let empty = signed(vec![]).encode();
        assert_eq!(empty.len(), MIN_ROUTE_SET_PAYLOAD);
        assert!(RouteSet::decode(&empty).is_ok());
        assert_structure_err(RouteSet::decode(&empty[..empty.len() - 1]));

        let max_routes: Vec<String> = ('a'..='f')
            .map(|c| long_hint(c, MAX_ROUTE_HINT_LEN))
            .collect();
        let max = signed(max_routes).encode();
        assert_eq!(max.len(), MAX_ROUTE_SET_PAYLOAD);
        assert!(RouteSet::decode(&max).is_ok());
        let mut over = max;
        over.push(0);
        assert_eq!(over.len(), MAX_ROUTE_SET_PAYLOAD + 1);
        assert_structure_err(RouteSet::decode(&over));
    }

    #[test]
    fn decode_rejects_trailing_byte() {
        let mut payload = signed(six_routes()).encode();
        payload.push(0);
        assert_structure_err(RouteSet::decode(&payload));
    }

    #[test]
    fn decode_rejects_bad_structure() {
        let base = signed(vec!["direct:192.168.1.20:9100".into()]).encode();
        let count_at = MIN_ROUTE_SET_BODY - 1;

        let mut version = base.clone();
        version[0] = 0x02;
        assert_structure_err(RouteSet::decode(&version));

        let mut count7 = base.clone();
        count7[count_at] = 7;
        assert_structure_err(RouteSet::decode(&count7));

        let mut count_short = base.clone();
        count_short[count_at] = 2;
        assert_structure_err(RouteSet::decode(&count_short));

        let mut zero_len = base.clone();
        zero_len[count_at + 1..count_at + 3].copy_from_slice(&0u16.to_be_bytes());
        assert_structure_err(RouteSet::decode(&zero_len));

        let mut over_len = base.clone();
        over_len[count_at + 1..count_at + 3].copy_from_slice(&257u16.to_be_bytes());
        assert_structure_err(RouteSet::decode(&over_len));

        let mut bad_utf8 = base.clone();
        bad_utf8[count_at + 3] = 0xFF;
        assert_structure_err(RouteSet::decode(&bad_utf8));

        let seq_at = 1 + 32 + 32;
        for bad_seq in [0, MAX_ROUTE_SEQ + 1] {
            let mut payload = base.clone();
            payload[seq_at..seq_at + 8].copy_from_slice(&u64::to_be_bytes(bad_seq));
            assert_structure_err(RouteSet::decode(&payload));
        }
        let mut max_seq = base;
        max_seq[seq_at..seq_at + 8].copy_from_slice(&MAX_ROUTE_SEQ.to_be_bytes());
        assert_eq!(RouteSet::decode(&max_seq).unwrap().seq, MAX_ROUTE_SEQ);
    }

    /// Builds a payload around `routes` with a zero signature, bypassing sign-side validation.
    fn raw_payload(routes: &[&str]) -> Vec<u8> {
        let mut set = signed(vec![]);
        set.routes = routes.iter().map(|r| (*r).to_owned()).collect();
        set.encode()
    }

    #[test]
    fn decode_rejects_invalid_hints() {
        let hint_257 = long_hint('a', MAX_ROUTE_HINT_LEN + 1);
        let cases: [&[&str]; 7] = [
            &["direct:192.168.1.20:9100", "direct:192.168.1.20:9100"],
            &["wss://relay.example.com/v1/relay#key"],
            &["local:/tmp/tendril.sock"],
            &["unix:///tmp/tendril.sock"],
            &["direct:0.0.0.0:9100"],
            &["not a hint"],
            &[hint_257.as_str()],
        ];
        for routes in cases {
            assert_structure_err(RouteSet::decode(&raw_payload(routes)));
        }
        let seven: Vec<String> = (0..7)
            .map(|i| format!("direct:192.168.1.{i}:9100"))
            .collect();
        let seven: Vec<&str> = seven.iter().map(String::as_str).collect();
        assert_structure_err(RouteSet::decode(&raw_payload(&seven)));
        assert!(RouteSet::decode(&raw_payload(&seven[..6])).is_ok());
    }

    #[test]
    fn sign_enforces_the_same_rules() {
        let id = identity();
        let sign = |seq: u64, routes: Vec<String>| RouteSet::sign(&id, seq, 0, routes);
        assert_structure_err(sign(0, vec![]));
        assert_structure_err(sign(MAX_ROUTE_SEQ + 1, vec![]));
        assert!(sign(MAX_ROUTE_SEQ, vec![]).is_ok());
        let seven = (0..7)
            .map(|i| format!("direct:192.168.1.{i}:9100"))
            .collect();
        assert_structure_err(sign(1, seven));
        assert_structure_err(sign(1, vec!["direct:192.168.1.20:9100".into(); 2]));
        assert_structure_err(sign(1, vec!["local:/tmp/tendril.sock".into()]));
        assert_structure_err(sign(1, vec![long_hint('a', MAX_ROUTE_HINT_LEN + 1)]));
        assert_structure_err(sign(1, vec![String::new()]));
    }
}
