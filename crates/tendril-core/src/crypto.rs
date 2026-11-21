//! Deterministic cryptographic primitives, key encodings, SAS, and pairing MACs.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use fips203::ml_kem_768;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as MlDsaKeyGen, SerDes as MlDsaSerDes, Signer as _, Verifier as _};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

/// Byte length of an Ed25519 verifying public key.
pub const ED25519_PUBLIC_LEN: usize = 32;

/// Byte length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;

/// Byte length of an ML-DSA-65 public key.
pub const MLDSA65_PUBLIC_LEN: usize = ml_dsa_65::PK_LEN;

/// Byte length of an ML-DSA-65 signature.
pub const MLDSA65_SIG_LEN: usize = ml_dsa_65::SIG_LEN;

/// Byte length of a concatenated `Ed25519 || ML-DSA-65` hybrid signing public key (`1984`).
pub const HYBRID_SIGNING_PUB_LEN: usize = ED25519_PUBLIC_LEN + MLDSA65_PUBLIC_LEN;

/// Byte length of a concatenated `Ed25519 || ML-DSA-65` hybrid signature (`3373`).
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN;

/// Byte length of the SHA-256 hash of a [`HybridSigningPublicKey`].
pub const HYBRID_SIGNING_HASH_LEN: usize = 32;

/// Byte length of an ML-KEM-768 encapsulation key (`1184`).
pub const MLKEM768_EK_LEN: usize = ml_kem_768::EK_LEN;

/// Byte length of an ML-KEM-768 ciphertext (`1088`).
pub const MLKEM768_CT_LEN: usize = ml_kem_768::CT_LEN;

/// FIPS 204 ML-DSA-65 context string binding all Tendril hybrid signatures.
pub const HYBRID_MLDSA_CTX: &[u8] = b"tendril-hybrid-v1";

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

/// Decodes unpadded URL-safe base64 into a heap-boxed fixed byte array.
pub fn b64url_decode_boxed<const N: usize>(encoded: &str) -> Result<Box<[u8; N]>, CoreError> {
    let bytes = b64url_decode(encoded)?;
    let actual = bytes.len();
    bytes
        .into_boxed_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidLength {
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

/// Concatenated `Ed25519 (32 B) || ML-DSA-65 (1952 B)` hybrid signing public key (`1984` B).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HybridSigningPublicKey(Box<[u8; HYBRID_SIGNING_PUB_LEN]>);

impl HybridSigningPublicKey {
    /// Parses and validates a 1984-byte `Ed25519 || ML-DSA-65` public key slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        let actual = bytes.len();
        let boxed: Box<[u8; HYBRID_SIGNING_PUB_LEN]> = bytes
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidLength {
                expected: HYBRID_SIGNING_PUB_LEN,
                actual,
            })?;
        Self::from_boxed(boxed)
    }

    /// Parses and validates a heap-boxed `1984`-byte `Ed25519 || ML-DSA-65` public key.
    pub fn from_boxed(bytes: Box<[u8; HYBRID_SIGNING_PUB_LEN]>) -> Result<Self, CoreError> {
        let mut ed = [0u8; ED25519_PUBLIC_LEN];
        ed.copy_from_slice(&bytes[..ED25519_PUBLIC_LEN]);
        if !is_valid_ed25519_public_key(&ed) {
            return Err(CoreError::InvalidSignature);
        }
        let mut mldsa = [0u8; MLDSA65_PUBLIC_LEN];
        mldsa.copy_from_slice(&bytes[ED25519_PUBLIC_LEN..]);
        ml_dsa_65::PublicKey::try_from_bytes(mldsa).map_err(|_| CoreError::InvalidSignature)?;
        Ok(Self(bytes))
    }

    /// Parses and validates a URL-safe unpadded base64 hybrid signing public key.
    pub fn from_b64url(encoded: &str) -> Result<Self, CoreError> {
        let boxed = b64url_decode_boxed::<HYBRID_SIGNING_PUB_LEN>(encoded)?;
        Self::from_boxed(boxed)
    }

    /// Encodes the full 1984-byte hybrid public key as URL-safe unpadded base64.
    #[must_use]
    pub fn to_b64url(&self) -> String {
        b64url_encode(&self.0[..])
    }

    /// Returns the raw 1984-byte `Ed25519 || ML-DSA-65` slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HYBRID_SIGNING_PUB_LEN] {
        &self.0
    }

    /// Returns the 32-byte Ed25519 verifying key prefix (also used as relay control `relay_pub`).
    #[must_use]
    pub fn ed25519_bytes(&self) -> &[u8; ED25519_PUBLIC_LEN] {
        self.0[..ED25519_PUBLIC_LEN]
            .try_into()
            .expect("32-byte Ed25519 prefix")
    }

    /// Returns the 1952-byte ML-DSA-65 public key suffix.
    #[must_use]
    pub fn mldsa65_bytes(&self) -> &[u8; MLDSA65_PUBLIC_LEN] {
        self.0[ED25519_PUBLIC_LEN..]
            .try_into()
            .expect("1952-byte ML-DSA-65 suffix")
    }

    /// Computes `SHA-256(Ed25519 || ML-DSA-65)` used for QR `sh=` hash pinning.
    #[must_use]
    pub fn sha256_hash(&self) -> [u8; HYBRID_SIGNING_HASH_LEN] {
        Sha256::digest(&self.0[..]).into()
    }

    /// Verifies a `3373`-byte `Ed25519 || ML-DSA-65` hybrid signature; BOTH components must pass.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        if signature.len() != HYBRID_SIG_LEN {
            return Err(CoreError::InvalidSignature);
        }
        let ed_vk = VerifyingKey::from_bytes(self.ed25519_bytes())
            .map_err(|_| CoreError::InvalidSignature)?;
        let ed_sig = Ed25519Signature::from_slice(&signature[..ED25519_SIG_LEN])
            .map_err(|_| CoreError::InvalidSignature)?;
        ed_vk
            .verify_strict(message, &ed_sig)
            .map_err(|_| CoreError::InvalidSignature)?;

        let mldsa_pk = ml_dsa_65::PublicKey::try_from_bytes(*self.mldsa65_bytes())
            .map_err(|_| CoreError::InvalidSignature)?;
        let mldsa_sig: [u8; MLDSA65_SIG_LEN] = signature[ED25519_SIG_LEN..]
            .try_into()
            .map_err(|_| CoreError::InvalidSignature)?;
        if !mldsa_pk.verify(message, &mldsa_sig, HYBRID_MLDSA_CTX) {
            return Err(CoreError::InvalidSignature);
        }
        Ok(())
    }
}

impl fmt::Debug for HybridSigningPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSigningPublicKey")
            .field("hash", &b64url_encode(&self.sha256_hash()))
            .finish()
    }
}

impl Serialize for HybridSigningPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_b64url())
    }
}

impl<'de> Deserialize<'de> for HybridSigningPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        Self::from_b64url(&encoded).map_err(serde::de::Error::custom)
    }
}

/// Validates and decodes a raw byte slice as a [`HybridSigningPublicKey`].
#[must_use]
pub fn is_valid_hybrid_signing_public_key(bytes: &[u8]) -> bool {
    HybridSigningPublicKey::from_bytes(bytes).is_ok()
}

/// Computes `SHA-256` of a 1984-byte [`HybridSigningPublicKey`].
#[must_use]
pub fn signing_key_hash(key: &HybridSigningPublicKey) -> [u8; HYBRID_SIGNING_HASH_LEN] {
    key.sha256_hash()
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

/// Hybrid `Ed25519 + ML-DSA-65` signing keypair whose seeds are zeroized on drop.
#[derive(Clone)]
pub struct SigningKeypair {
    ed25519_seed: Zeroizing<[u8; 32]>,
    mldsa_seed: Zeroizing<[u8; 32]>,
    public: HybridSigningPublicKey,
}

impl SigningKeypair {
    /// Generates a fresh hybrid signing keypair using independent OS CSPRNG entropy.
    pub fn generate() -> Result<Self, CoreError> {
        let ed_seed = Zeroizing::new(random_bytes::<32>()?);
        let mldsa_seed = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self::from_seeds(*ed_seed, *mldsa_seed))
    }

    /// Constructs a hybrid signing keypair from independent 32-byte Ed25519 and ML-DSA-65 seeds.
    #[must_use]
    pub fn from_seeds(ed25519_seed: [u8; 32], mldsa_seed: [u8; 32]) -> Self {
        let ed_sk = SigningKey::from_bytes(&ed25519_seed);
        let ed_pub = ed_sk.verifying_key().to_bytes();
        let (mldsa_pk, _mldsa_sk) = ml_dsa_65::KG::keygen_from_seed(&mldsa_seed);
        let mldsa_pub = mldsa_pk.into_bytes();

        let mut combined = Box::new([0u8; HYBRID_SIGNING_PUB_LEN]);
        combined[..ED25519_PUBLIC_LEN].copy_from_slice(&ed_pub);
        combined[ED25519_PUBLIC_LEN..].copy_from_slice(&mldsa_pub);
        Self {
            ed25519_seed: Zeroizing::new(ed25519_seed),
            mldsa_seed: Zeroizing::new(mldsa_seed),
            public: HybridSigningPublicKey(combined),
        }
    }

    /// Deterministic single-seed constructor for tests and fixtures.
    ///
    /// Production identities MUST use [`SigningKeypair::generate`] or [`SigningKeypair::from_seeds`].
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"tendril-test-mldsa65-seed-v1");
        hasher.update(seed);
        let mldsa_seed: [u8; 32] = hasher.finalize().into();
        Self::from_seeds(seed, mldsa_seed)
    }

    /// Builds the `ed25519_dalek::SigningKey` strictly for untrusted relay control authentication.
    #[must_use]
    pub fn ed25519_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed25519_seed)
    }

    /// Returns the 32-byte Ed25519 signing seed.
    #[must_use]
    pub fn seed_bytes(&self) -> &[u8; 32] {
        &self.ed25519_seed
    }

    /// Returns the 32-byte ML-DSA-65 seed `xi`.
    #[must_use]
    pub fn mldsa_seed_bytes(&self) -> &[u8; 32] {
        &self.mldsa_seed
    }

    /// Returns the full 1984-byte [`HybridSigningPublicKey`].
    #[must_use]
    pub const fn public_key(&self) -> &HybridSigningPublicKey {
        &self.public
    }

    /// Returns the full 1984-byte `Ed25519 || ML-DSA-65` public key bytes.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8; HYBRID_SIGNING_PUB_LEN] {
        self.public.as_bytes()
    }

    /// Returns the 32-byte Ed25519 verifying key prefix (used as relay control `relay_pub`).
    #[must_use]
    pub fn ed25519_public_bytes(&self) -> &[u8; ED25519_PUBLIC_LEN] {
        self.public.ed25519_bytes()
    }

    /// Returns the SHA-256 hash of the 1984-byte [`HybridSigningPublicKey`].
    #[must_use]
    pub fn signing_pub_hash(&self) -> [u8; HYBRID_SIGNING_HASH_LEN] {
        self.public.sha256_hash()
    }

    /// Signs `message` with hedged randomness (`Ed25519 || ML-DSA-65`, `3373` bytes).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        let hedging = Zeroizing::new(random_bytes::<32>()?);
        self.sign_with_mldsa_rnd(message, &hedging)
    }

    /// Deterministically signs `message` (`Ed25519 || ML-DSA-65` with zero ML-DSA hedging seed).
    pub fn sign_deterministic(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.sign_with_mldsa_rnd(message, &[0u8; 32])
    }

    fn sign_with_mldsa_rnd(&self, message: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
        let ed_sk = SigningKey::from_bytes(&self.ed25519_seed);
        let ed_sig = ed_sk.sign(message);

        let (_pk, mldsa_sk) = ml_dsa_65::KG::keygen_from_seed(&self.mldsa_seed);
        let mldsa_sig = mldsa_sk
            .try_sign_with_seed(rnd, message, HYBRID_MLDSA_CTX)
            .map_err(|_| CoreError::InvalidSignature)?;

        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&ed_sig.to_bytes());
        out.extend_from_slice(&mldsa_sig);
        Ok(out)
    }
}

impl fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeypair")
            .field("public_hash", &b64url_encode(&self.signing_pub_hash()))
            .field("seeds", &"<redacted>")
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

/// Reports whether `s` contains ASCII control bytes (`0x00..=0x1F` or `0x7F`).
#[must_use]
pub(crate) fn has_control_chars(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
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

    #[test]
    fn hybrid_signing_and_half_tamper_rejection() {
        let kp = SigningKeypair::from_seeds([0x11; 32], [0x22; 32]);
        assert_eq!(kp.public_bytes().len(), HYBRID_SIGNING_PUB_LEN);
        assert_eq!(kp.ed25519_public_bytes(), &kp.public_bytes()[..32]);

        let sig = kp.sign_deterministic(b"tendril-hybrid-msg").unwrap();
        assert_eq!(sig.len(), HYBRID_SIG_LEN);
        kp.public_key().verify(b"tendril-hybrid-msg", &sig).unwrap();

        let mut bad_ed = sig.clone();
        bad_ed[0] ^= 0x01;
        assert_eq!(
            kp.public_key().verify(b"tendril-hybrid-msg", &bad_ed),
            Err(CoreError::InvalidSignature)
        );

        let mut bad_mldsa = sig.clone();
        bad_mldsa[ED25519_SIG_LEN + 10] ^= 0x01;
        assert_eq!(
            kp.public_key().verify(b"tendril-hybrid-msg", &bad_mldsa),
            Err(CoreError::InvalidSignature)
        );

        let json = serde_json::to_string(kp.public_key()).unwrap();
        let parsed: HybridSigningPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(&parsed, kp.public_key());
    }
}
