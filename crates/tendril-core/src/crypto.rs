//! Deterministic cryptographic primitives, key encodings, SAS, and pairing MACs.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::error::CoreError;

type HmacSha256 = Hmac<Sha256>;

/// Unambiguous 31-character alphabet used to generate pairing codes.
pub const CODE_ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// ASCII domain separation label for pairing `code_mac`.
pub const PAIR_MAC_LABEL: &[u8] = b"tendril-pair-v1";

/// ASCII domain separation label for post-`msg2` pairing SAS.
pub const SAS_LABEL: &[u8] = b"tendril-sas-v1";

/// Argon2id memory cost in KiB (64 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 65_536;

/// Argon2id time cost (iterations).
pub const ARGON2_TIME: u32 = 3;

/// Argon2id lane count (parallelism).
pub const ARGON2_PARALLELISM: u32 = 1;

/// Argon2id output key length in bytes.
pub const ARGON2_KEY_LEN: usize = 32;

/// Number of leading handshake-hash bytes used as the Argon2id salt.
pub const SALT_LEN: usize = 16;

/// Encodes arbitrary bytes as unpadded URL-safe base64 (RFC 4648 Section 5).
#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes unpadded URL-safe base64 into raw bytes.
pub fn b64url_decode(encoded: &str) -> Result<Vec<u8>, CoreError> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| CoreError::Base64Decode(err.to_string()))
}

/// Decodes unpadded URL-safe base64 expecting an exact fixed byte array length.
pub fn b64url_decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], CoreError> {
    let bytes = b64url_decode(encoded)?;
    let actual = bytes.len();
    bytes.try_into().map_err(|_| CoreError::InvalidLength {
        expected: N,
        actual,
    })
}

/// Derives the X25519 public key from a raw 32-byte private scalar.
#[must_use]
pub fn x25519_public_from_scalar(scalar: &[u8; 32]) -> [u8; 32] {
    let secret = X25519StaticSecret::from(*scalar);
    X25519PublicKey::from(&secret).to_bytes()
}

/// Derives the canonical `device_id` (`"dev_" + hex_lower(SHA-256(static_pub)[..8])`).
#[must_use]
pub fn device_id(static_pub: &[u8; 32]) -> String {
    let sum = Sha256::digest(static_pub);
    format!("dev_{}", hex::encode(&sum[..8]))
}

/// Renders the host static public key fingerprint (`xxxx xxxx xxxx xxxx`, lowercase base32).
#[must_use]
pub fn fingerprint_host(static_pub: &[u8; 32]) -> String {
    let sum = Sha256::digest(static_pub);
    let encoded = BASE32_NOPAD.encode(&sum).to_ascii_lowercase();
    group4_first16(&encoded)
}

/// Renders the device static public key fingerprint (`XXXX XXXX XXXX XXXX`, uppercase hex).
#[must_use]
pub fn fingerprint_device(static_pub: &[u8; 32]) -> String {
    let sum = Sha256::digest(static_pub);
    let encoded = hex::encode_upper(sum);
    group4_first16(&encoded)
}

/// Derives the canonical post-`msg2` transcript SAS (`xxxx xxxx xxxx xxxx`, lowercase base32).
#[must_use]
pub fn pairing_sas(handshake_hash: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SAS_LABEL);
    hasher.update(handshake_hash);
    let sum = hasher.finalize();
    let encoded = BASE32_NOPAD.encode(&sum).to_ascii_lowercase();
    group4_first16(&encoded)
}

fn group4_first16(s: &str) -> String {
    let chars = &s.as_bytes()[..16];
    let mut out = String::with_capacity(19);
    for (idx, chunk) in chars.chunks_exact(4).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out
}

/// Normalizes a user-entered pairing code: ASCII uppercase with all hyphens stripped.
#[must_use]
pub fn normalize_code(code: &str) -> String {
    code.to_ascii_uppercase().replace('-', "")
}

/// Derives the 32-byte pairing HMAC key using Argon2id v1.3 salted by `handshake_hash[..16]`.
pub fn argon2id_pairing_key(
    code: &str,
    handshake_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; ARGON2_KEY_LEN]>, CoreError> {
    let normalized = Zeroizing::new(normalize_code(code));
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME,
        ARGON2_PARALLELISM,
        Some(ARGON2_KEY_LEN),
    )
    .map_err(|err| CoreError::Argon2(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; ARGON2_KEY_LEN]);
    argon2
        .hash_password_into(
            normalized.as_bytes(),
            &handshake_hash[..SALT_LEN],
            &mut *out,
        )
        .map_err(|err| CoreError::Argon2(err.to_string()))?;
    Ok(out)
}

/// Computes `HMAC-SHA256(argon2id(code, h[..16]), "tendril-pair-v1" || h)`.
pub fn compute_code_mac(code: &str, handshake_hash: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    let key = argon2id_pairing_key(code, handshake_hash)?;
    let mut mac =
        HmacSha256::new_from_slice(&*key).map_err(|err| CoreError::Argon2(err.to_string()))?;
    mac.update(PAIR_MAC_LABEL);
    mac.update(handshake_hash);
    Ok(mac.finalize().into_bytes().into())
}

/// Verifies `candidate` against the expected `code_mac` in constant time.
pub fn verify_code_mac(
    code: &str,
    handshake_hash: &[u8; 32],
    candidate: &[u8; 32],
) -> Result<bool, CoreError> {
    let expected = compute_code_mac(code, handshake_hash)?;
    Ok(bool::from(expected.ct_eq(candidate)))
}
