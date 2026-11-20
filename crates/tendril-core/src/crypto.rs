//! Deterministic cryptographic primitives, key encodings, SAS, and pairing MACs.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use snow::Builder;
use snow::params::{CipherChoice, DHChoice, HashChoice, NoiseParams};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CoreError;

type HmacSha256 = Hmac<Sha256>;

/// Unambiguous 31-character alphabet used to generate pairing codes.
pub const CODE_ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// ASCII domain separation label for pairing `code_mac`.
pub const PAIR_MAC_LABEL: &[u8] = b"tendril-pair-v1";

/// ASCII domain separation label for post-`msg2` pairing SAS.
pub const SAS_LABEL: &[u8] = b"tendril-sas-v1";

/// HKDF-SHA256 domain separation label for deriving the host P2P routing seed.
pub const P2P_IDENTITY_HKDF_LABEL: &[u8] = b"tendril/p2p/iroh-identity/v1";

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

/// Validates that `pub_bytes` is a full-order Curve25519 public key (not in any small-order subgroup).
#[must_use]
pub fn is_valid_x25519_public_key(pub_bytes: &[u8; 32]) -> bool {
    let zero_scalar = X25519StaticSecret::from([0u8; 32]);
    let peer_pub = X25519PublicKey::from(*pub_bytes);
    zero_scalar.diffie_hellman(&peer_pub).was_contributory()
}

/// Validates that `pub_bytes` decodes as a non-zero, non-weak Ed25519 verifying key.
#[must_use]
pub fn is_valid_ed25519_public_key(pub_bytes: &[u8; 32]) -> bool {
    !bool::from(pub_bytes.ct_eq(&[0u8; 32]))
        && VerifyingKey::from_bytes(pub_bytes).is_ok_and(|vk| !vk.is_weak())
}

struct ContributoryDh {
    inner: Box<dyn Dh>,
}

impl Dh for ContributoryDh {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn pub_len(&self) -> usize {
        self.inner.pub_len()
    }

    fn priv_len(&self) -> usize {
        self.inner.priv_len()
    }

    fn set(&mut self, privkey: &[u8]) {
        self.inner.set(privkey);
    }

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        self.inner.generate(rng)
    }

    fn pubkey(&self) -> &[u8] {
        self.inner.pubkey()
    }

    fn privkey(&self) -> &[u8] {
        self.inner.privkey()
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        if pubkey.len() < 32 || out.len() < 32 {
            return Err(snow::Error::Input);
        }
        self.inner.dh(pubkey, out)?;
        if bool::from(out[..32].ct_eq(&[0u8; 32])) {
            out[..32].zeroize();
            return Err(snow::Error::Dh);
        }
        Ok(())
    }

    fn dh_len(&self) -> usize {
        self.inner.dh_len()
    }
}

pub(crate) struct TendrilCryptoResolver;

impl CryptoResolver for TendrilCryptoResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        DefaultResolver.resolve_rng()
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        let inner = DefaultResolver.resolve_dh(choice)?;
        match choice {
            DHChoice::Curve25519 => Some(Box::new(ContributoryDh { inner })),
            _ => Some(inner),
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}

/// Builds a `snow` handshake builder enforcing RFC 7748 contributory X25519 DH checks.
#[must_use]
pub(crate) fn new_noise_builder(params: NoiseParams) -> Builder<'static> {
    Builder::with_resolver(params, Box::new(TendrilCryptoResolver))
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

fn normalize_code_into(code: &str, out: &mut String) {
    for ch in code.chars() {
        if ch != '-' {
            out.push(ch.to_ascii_uppercase());
        }
    }
}

/// Normalizes a user-entered pairing code: ASCII uppercase with all hyphens stripped.
#[must_use]
pub fn normalize_code(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    normalize_code_into(code, &mut out);
    out
}

/// Derives the 32-byte pairing HMAC key using Argon2id v1.3 salted by `handshake_hash[..16]`.
pub fn argon2id_pairing_key(
    code: &str,
    handshake_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; ARGON2_KEY_LEN]>, CoreError> {
    let mut normalized = Zeroizing::new(String::with_capacity(code.len()));
    normalize_code_into(code, &mut normalized);
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

/// Fills a fixed-size buffer using the platform CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|err| CoreError::Rng(err.to_string()))?;
    Ok(out)
}

/// X25519 static keypair whose private scalar is zeroized on drop and redacted from `Debug`.
#[derive(Clone)]
pub struct StaticKeypair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl StaticKeypair {
    /// Generates a fresh X25519 static keypair using the platform CSPRNG.
    pub fn generate() -> Result<Self, CoreError> {
        let mut scalar = Zeroizing::new(random_bytes::<32>()?);
        let secret = X25519StaticSecret::from(*scalar);
        let public = X25519PublicKey::from(&secret).to_bytes();
        // Zeroize intermediate copy; `secret` wrapper holds the final clamped or raw scalar.
        scalar.as_mut().copy_from_slice(&secret.to_bytes());
        Ok(Self {
            secret: scalar,
            public,
        })
    }

    /// Constructs a static keypair from an existing 32-byte private scalar.
    #[must_use]
    pub fn from_scalar(scalar: [u8; 32]) -> Self {
        let public = x25519_public_from_scalar(&scalar);
        Self {
            secret: Zeroizing::new(scalar),
            public,
        }
    }

    /// Returns the raw 32-byte private scalar.
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Returns the 32-byte X25519 public key.
    #[must_use]
    pub const fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    /// Returns the canonical `device_id` derived from this public key.
    #[must_use]
    pub fn device_id(&self) -> String {
        device_id(&self.public)
    }

    /// Returns the `4x4` lowercase base32 host fingerprint for this static key.
    #[must_use]
    pub fn host_fingerprint(&self) -> String {
        fingerprint_host(&self.public)
    }

    /// Returns the `4x4` uppercase hex device fingerprint for this static key.
    #[must_use]
    pub fn device_fingerprint(&self) -> String {
        fingerprint_device(&self.public)
    }
}

impl fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("device_id", &self.device_id())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Ed25519 signing keypair whose seed is zeroized on drop and redacted from `Debug`.
#[derive(Clone)]
pub struct SigningKeypair {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl SigningKeypair {
    /// Generates a fresh Ed25519 signing keypair using the platform CSPRNG.
    pub fn generate() -> Result<Self, CoreError> {
        let seed = random_bytes::<32>()?;
        Ok(Self::from_seed(seed))
    }

    /// Constructs a signing keypair from an existing 32-byte Ed25519 seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&seed);
        let public = sk.verifying_key().to_bytes();
        Self {
            seed: Zeroizing::new(seed),
            public,
        }
    }

    /// Builds an `ed25519_dalek::SigningKey` from the zeroizing seed.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    /// Returns the 32-byte Ed25519 signing seed.
    #[must_use]
    pub fn seed_bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Returns the 32-byte Ed25519 verifying public key.
    #[must_use]
    pub const fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

impl fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeypair")
            .field("public", &b64url_encode(&self.public))
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// Derives a 32-byte subkey using single-block RFC 5869 HKDF-SHA256.
#[must_use]
pub fn hkdf_sha256_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let zero_salt = [0u8; 32];
    let effective_salt = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    let mut extract =
        HmacSha256::new_from_slice(effective_salt).expect("HMAC-SHA256 accepts any salt length");
    extract.update(ikm);
    let prk: Zeroizing<[u8; 32]> = Zeroizing::new(extract.finalize().into_bytes().into());

    let mut expand =
        HmacSha256::new_from_slice(&*prk).expect("HMAC-SHA256 accepts 32-byte PRK key");
    expand.update(info);
    expand.update(&[0x01u8]);
    Zeroizing::new(expand.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha256_32_matches_rfc5869_vectors() {
        // RFC 5869 Appendix A.1 (first 32 bytes of 42-byte OKM).
        let ikm1 = [0x0bu8; 22];
        let salt1 = hex::decode("000102030405060708090a0b0c").unwrap();
        let info1 = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm1 = hkdf_sha256_32(&ikm1, &salt1, &info1);
        assert_eq!(
            hex::encode(*okm1),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );

        // RFC 5869 Appendix A.3 (empty salt, empty info, first 32 bytes of OKM).
        let ikm3 = [0x0bu8; 22];
        let okm3 = hkdf_sha256_32(&ikm3, &[], &[]);
        assert_eq!(
            hex::encode(*okm3),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
    }
}
