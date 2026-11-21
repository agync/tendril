//! Pure-Rust zeroizing `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` handshake and transport.
//!
//! Implements the Noise Hybrid Forward Secrecy (`XXhfs`) pattern:
//! ```text
//!   -> e, e1
//!   <- e, ee, ekem1, s, es
//!   -> s, se
//! ```
//! Combining ephemeral X25519 (`e`) and ephemeral ML-KEM-768 (`e1`, `ekem1`) ensures session
//! confidentiality remains secure against harvest-now-decrypt-later quantum adversaries even
//! without pre-shared keys.

use std::fmt;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{hkdf_sha256_32, random_bytes, x25519_public_from_scalar};
use crate::error::CoreError;
use crate::wire::{AEAD_TAG_LEN, MAX_FRAME_LEN, NOISE_PATTERN};

type HmacSha256 = Hmac<Sha256>;
type HkdfPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Byte length of an X25519 public key or shared secret.
pub const DH_LEN: usize = 32;

/// Byte length of an ML-KEM-768 encapsulation key (`e1`).
pub const KEM_PK_LEN: usize = ml_kem_768::EK_LEN;

/// Byte length of a raw ML-KEM-768 ciphertext (`ekem1`).
pub const KEM_CT_LEN: usize = ml_kem_768::CT_LEN;

/// Fixed byte length of `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` message 1 (`e || e1`).
pub const MSG1_LEN: usize = DH_LEN + KEM_PK_LEN;

const ENC_CT_LEN: usize = KEM_CT_LEN + AEAD_TAG_LEN;
const ENC_STATIC_LEN: usize = DH_LEN + AEAD_TAG_LEN;
const MIN_MSG2_LEN: usize = DH_LEN + ENC_CT_LEN + ENC_STATIC_LEN + AEAD_TAG_LEN;
const MIN_MSG3_LEN: usize = ENC_STATIC_LEN + AEAD_TAG_LEN;

/// Deterministic test-only randomness for X25519 ephemeral + ML-KEM-768 operations.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NoiseHfsSeeds {
    pub x25519: [u8; 32],
    pub mlkem_d: [u8; 32],
    pub mlkem_z: [u8; 32],
    pub mlkem_m: [u8; 32],
}

impl NoiseHfsSeeds {
    /// Expands a single 32-byte test seed into deterministic X25519 and ML-KEM-768 seeds.
    #[must_use]
    pub fn from_ephemeral_seed(seed: [u8; 32]) -> Self {
        Self {
            x25519: seed,
            mlkem_d: labeled_sha256(b"tendril-hfs-test-mlkem-d-v1", &seed),
            mlkem_z: labeled_sha256(b"tendril-hfs-test-mlkem-z-v1", &seed),
            mlkem_m: labeled_sha256(b"tendril-hfs-test-mlkem-m-v1", &seed),
        }
    }
}

impl fmt::Debug for NoiseHfsSeeds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseHfsSeeds")
            .field("secrets", &"<redacted>")
            .finish()
    }
}

fn labeled_sha256(label: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(input);
    hasher.finalize().into()
}

fn x25519_dh(
    priv_bytes: &[u8; 32],
    pub_bytes: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let secret = X25519StaticSecret::from(*priv_bytes);
    let remote = X25519PublicKey::from(*pub_bytes);
    let shared = secret.diffie_hellman(&remote);
    if !shared.was_contributory() || bool::from(shared.as_bytes().ct_eq(&[0u8; 32])) {
        return Err(CoreError::Noise("non-contributory X25519 DH".into()));
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

fn noise_hkdf(chaining_key: &[u8; 32], ikm: &[u8]) -> Result<HkdfPair, CoreError> {
    let mut mac0 = HmacSha256::new_from_slice(chaining_key)
        .map_err(|err| CoreError::Noise(format!("hmac init: {err}")))?;
    mac0.update(ikm);
    let temp_key = Zeroizing::new(<[u8; 32]>::from(mac0.finalize().into_bytes()));

    let mut mac1 = HmacSha256::new_from_slice(&*temp_key)
        .map_err(|err| CoreError::Noise(format!("hmac init: {err}")))?;
    mac1.update(&[0x01]);
    let out1 = Zeroizing::new(<[u8; 32]>::from(mac1.finalize().into_bytes()));

    let mut mac2 = HmacSha256::new_from_slice(&*temp_key)
        .map_err(|err| CoreError::Noise(format!("hmac init: {err}")))?;
    mac2.update(&*out1);
    mac2.update(&[0x02]);
    let out2 = Zeroizing::new(<[u8; 32]>::from(mac2.finalize().into_bytes()));

    Ok((out1, out2))
}

fn make_nonce(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

fn aead_encrypt(key: &[u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|err| CoreError::Noise(format!("cipher init: {err}")))?;
    let nonce_bytes = make_nonce(n);
    let mut buf = Vec::with_capacity(
        plaintext
            .len()
            .checked_add(AEAD_TAG_LEN)
            .ok_or_else(|| CoreError::Noise("plaintext length overflow".into()))?,
    );
    buf.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place(&Nonce::from(nonce_bytes), ad, &mut buf)
        .map_err(|_| CoreError::Noise("AEAD encryption failed".into()))?;
    Ok(buf)
}

fn aead_decrypt(
    key: &[u8; 32],
    n: u64,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    if ciphertext.len() < AEAD_TAG_LEN {
        return Err(CoreError::Noise("truncated AEAD ciphertext".into()));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|err| CoreError::Noise(format!("cipher init: {err}")))?;
    let nonce_bytes = make_nonce(n);
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(&Nonce::from(nonce_bytes), ad, &mut *buf)
        .map_err(|_| CoreError::Noise("AEAD decryption failed".into()))?;
    Ok(buf)
}

#[derive(Clone, Default)]
struct CipherState {
    key: Option<Zeroizing<[u8; 32]>>,
    n: u64,
}

impl CipherState {
    fn from_key(key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            key: Some(key),
            n: 0,
        }
    }

    fn initialize_key(&mut self, key: Zeroizing<[u8; 32]>) {
        self.key = Some(key);
        self.n = 0;
    }

    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let Some(ref key) = self.key else {
            return Ok(plaintext.to_vec());
        };
        if self.n == u64::MAX {
            return Err(CoreError::Noise("noise nonce exhausted".into()));
        }
        let ct = aead_encrypt(key, self.n, ad, plaintext)?;
        self.n += 1;
        Ok(ct)
    }

    fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let Some(ref key) = self.key else {
            return Ok(Zeroizing::new(ciphertext.to_vec()));
        };
        if self.n == u64::MAX {
            return Err(CoreError::Noise("noise nonce exhausted".into()));
        }
        let pt = aead_decrypt(key, self.n, ad, ciphertext)?;
        self.n += 1;
        Ok(pt)
    }

    fn rekey(&mut self) -> Result<(), CoreError> {
        let Some(ref key) = self.key else {
            return Err(CoreError::Noise("cannot rekey uninitialized cipher".into()));
        };
        let ct = Zeroizing::new(aead_encrypt(key, u64::MAX, &[], &[0u8; 32])?);
        let mut next = Zeroizing::new([0u8; 32]);
        next.copy_from_slice(&ct[..32]);
        self.key = Some(next);
        Ok(())
    }
}

impl fmt::Debug for CipherState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherState")
            .field("has_key", &self.has_key())
            .field("n", &self.n)
            .finish()
    }
}

struct SymmetricState {
    cipher: CipherState,
    ck: Zeroizing<[u8; 32]>,
    h: [u8; 32],
}

impl SymmetricState {
    fn initialize(protocol_name: &[u8]) -> Self {
        let mut h = [0u8; 32];
        if protocol_name.len() <= 32 {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            h = Sha256::digest(protocol_name).into();
        }
        Self {
            cipher: CipherState::default(),
            ck: Zeroizing::new(h),
            h,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    fn mix_key(&mut self, ikm: &[u8]) -> Result<(), CoreError> {
        let (next_ck, temp_k) = noise_hkdf(&self.ck, ikm)?;
        self.ck = next_ck;
        self.cipher.initialize_key(temp_k);
        Ok(())
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let ct = self.cipher.encrypt_with_ad(&self.h, plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let pt = self.cipher.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn split(self) -> Result<(CipherState, CipherState), CoreError> {
        let (k1, k2) = noise_hkdf(&self.ck, &[])?;
        Ok((CipherState::from_key(k1), CipherState::from_key(k2)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeStep {
    InitiatorWriteMsg1,
    InitiatorReadMsg2,
    InitiatorWriteMsg3,
    ResponderReadMsg1,
    ResponderWriteMsg2,
    ResponderReadMsg3,
    Completed,
    Failed,
}

/// Builder for [`NoiseHfsHandshake`].
#[derive(Default)]
pub struct NoiseHfsHandshakeBuilder {
    local_static: Option<Zeroizing<[u8; 32]>>,
    prologue: Vec<u8>,
    fixed_seeds: Option<NoiseHfsSeeds>,
}

impl NoiseHfsHandshakeBuilder {
    /// Creates a new builder for `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the local static X25519 private scalar.
    #[must_use]
    pub fn local_private_key(mut self, key: &[u8; 32]) -> Self {
        self.local_static = Some(Zeroizing::new(*key));
        self
    }

    /// Sets the cleartext Noise prologue mixed into the initial handshake transcript hash.
    #[must_use]
    pub fn prologue(mut self, prologue: &[u8]) -> Self {
        self.prologue = prologue.to_vec();
        self
    }

    /// Deterministically seeds ephemeral X25519 and ML-KEM-768 randomness for test vectors.
    #[must_use]
    pub fn fixed_ephemeral_for_testing_only(mut self, eph_seed: [u8; 32]) -> Self {
        self.fixed_seeds = Some(NoiseHfsSeeds::from_ephemeral_seed(eph_seed));
        self
    }

    /// Explicitly supplies separate test seeds for X25519 and ML-KEM-768 keygen/encaps.
    #[must_use]
    pub fn fixed_hfs_seeds_for_testing_only(mut self, seeds: NoiseHfsSeeds) -> Self {
        self.fixed_seeds = Some(seeds);
        self
    }

    /// Builds an initiator [`NoiseHfsHandshake`].
    pub fn build_initiator(self) -> Result<NoiseHfsHandshake, CoreError> {
        self.build(Role::Initiator)
    }

    /// Builds a responder [`NoiseHfsHandshake`].
    pub fn build_responder(self) -> Result<NoiseHfsHandshake, CoreError> {
        self.build(Role::Responder)
    }

    fn build(self, role: Role) -> Result<NoiseHfsHandshake, CoreError> {
        let local_static_priv = self
            .local_static
            .ok_or_else(|| CoreError::Noise("missing local static private key".into()))?;
        let local_static_pub = x25519_public_from_scalar(&local_static_priv);
        let mut sym = SymmetricState::initialize(NOISE_PATTERN.as_bytes());
        sym.mix_hash(&self.prologue);

        let step = match role {
            Role::Initiator => HandshakeStep::InitiatorWriteMsg1,
            Role::Responder => HandshakeStep::ResponderReadMsg1,
        };

        Ok(NoiseHfsHandshake {
            role,
            step,
            sym,
            local_static_priv,
            local_static_pub,
            local_ephemeral_priv: None,
            remote_ephemeral: None,
            remote_static: None,
            local_kem_dk: None,
            remote_kem_ek: None,
            remote_kem_ek_hash: None,
            fixed_seeds: self.fixed_seeds,
        })
    }
}

/// Stateful `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256` handshake machine.
pub struct NoiseHfsHandshake {
    role: Role,
    step: HandshakeStep,
    sym: SymmetricState,
    local_static_priv: Zeroizing<[u8; 32]>,
    local_static_pub: [u8; 32],
    local_ephemeral_priv: Option<Zeroizing<[u8; 32]>>,
    remote_ephemeral: Option<[u8; 32]>,
    remote_static: Option<[u8; 32]>,
    local_kem_dk: Option<Box<ml_kem_768::DecapsKey>>,
    remote_kem_ek: Option<Box<ml_kem_768::EncapsKey>>,
    remote_kem_ek_hash: Option<[u8; 32]>,
    fixed_seeds: Option<NoiseHfsSeeds>,
}

impl NoiseHfsHandshake {
    /// Returns the current 32-byte Noise handshake hash `h`.
    #[must_use]
    pub fn get_handshake_hash(&self) -> &[u8; 32] {
        &self.sym.h
    }

    /// Returns the authenticated remote X25519 static public key once received.
    #[must_use]
    pub fn get_remote_static(&self) -> Option<&[u8; 32]> {
        self.remote_static.as_ref()
    }

    /// Returns `(remote_ephemeral_pub, SHA-256(remote_mlkem_ek))` once `msg1` has been read.
    #[must_use]
    pub fn remote_ephemeral_and_kem_hash(&self) -> Option<([u8; 32], [u8; 32])> {
        Some((self.remote_ephemeral?, self.remote_kem_ek_hash?))
    }

    /// Returns `true` when all 3 handshake messages have completed.
    #[must_use]
    pub fn is_handshake_finished(&self) -> bool {
        self.step == HandshakeStep::Completed
    }

    fn fail_and_wipe_secrets(&mut self) {
        self.step = HandshakeStep::Failed;
        self.local_ephemeral_priv = None;
        self.remote_ephemeral = None;
        self.local_kem_dk = None;
        self.remote_kem_ek = None;
        self.remote_kem_ek_hash = None;
    }

    /// Generates `msg1` (`-> e, e1`), calling `build_payload(&e_pub, &ek_bytes)` to construct the payload.
    pub fn write_msg1_with_payload<F>(&mut self, build_payload: F) -> Result<Vec<u8>, CoreError>
    where
        F: FnOnce(&[u8; 32], &[u8]) -> Result<Vec<u8>, CoreError>,
    {
        let step = std::mem::replace(&mut self.step, HandshakeStep::Failed);
        if step != HandshakeStep::InitiatorWriteMsg1 {
            self.fail_and_wipe_secrets();
            return Err(CoreError::Noise(
                "write_msg1_with_payload called out of handshake turn".into(),
            ));
        }
        let res = self.write_msg1_step(build_payload);
        if res.is_err() {
            self.fail_and_wipe_secrets();
        }
        res
    }

    /// Generates `msg2` (`<- e, ee, ekem1, s, es`), calling `build_payload(&h_pre)` right before encrypting payload.
    pub fn write_msg2_with_hash<F>(&mut self, build_payload: F) -> Result<Vec<u8>, CoreError>
    where
        F: FnOnce(&[u8; 32]) -> Result<Vec<u8>, CoreError>,
    {
        let step = std::mem::replace(&mut self.step, HandshakeStep::Failed);
        if step != HandshakeStep::ResponderWriteMsg2 {
            self.fail_and_wipe_secrets();
            return Err(CoreError::Noise(
                "write_msg2_with_hash called out of handshake turn".into(),
            ));
        }
        let res = self.write_msg2_step(build_payload);
        if res.is_err() {
            self.fail_and_wipe_secrets();
        }
        res
    }

    /// Generates the next handshake message into a freshly sized `Vec<u8>`.
    pub fn write_message_vec(&mut self, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
        let step = std::mem::replace(&mut self.step, HandshakeStep::Failed);
        let res = match step {
            HandshakeStep::InitiatorWriteMsg1 => self.write_msg1_step(|_, _| Ok(payload.to_vec())),
            HandshakeStep::ResponderWriteMsg2 => self.write_msg2_step(|_| Ok(payload.to_vec())),
            _ => self.write_message_step(step, payload),
        };
        if res.is_err() {
            self.fail_and_wipe_secrets();
        }
        res
    }

    fn write_msg1_step<F>(&mut self, build_payload: F) -> Result<Vec<u8>, CoreError>
    where
        F: FnOnce(&[u8; 32], &[u8]) -> Result<Vec<u8>, CoreError>,
    {
        let mut out = Vec::new();
        let e_priv = match self.fixed_seeds {
            Some(ref seeds) => Zeroizing::new(seeds.x25519),
            None => Zeroizing::new(random_bytes::<32>()?),
        };
        let e_pub = x25519_public_from_scalar(&e_priv);
        out.extend_from_slice(&e_pub);
        self.sym.mix_hash(&e_pub);
        self.local_ephemeral_priv = Some(e_priv);

        let d = match self.fixed_seeds {
            Some(ref seeds) => Zeroizing::new(seeds.mlkem_d),
            None => Zeroizing::new(random_bytes::<32>()?),
        };
        let z = match self.fixed_seeds {
            Some(ref seeds) => Zeroizing::new(seeds.mlkem_z),
            None => Zeroizing::new(random_bytes::<32>()?),
        };
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(*d, *z);
        let ek_bytes = ek.into_bytes();
        out.extend_from_slice(&ek_bytes);
        self.sym.mix_hash(&ek_bytes);
        self.local_kem_dk = Some(Box::new(dk));

        let payload = Zeroizing::new(build_payload(&e_pub, &ek_bytes)?);
        let enc_payload = self.sym.encrypt_and_hash(&payload)?;
        out.extend_from_slice(&enc_payload);
        if out.len() > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: out.len(),
                max: MAX_FRAME_LEN,
            });
        }
        self.step = HandshakeStep::InitiatorReadMsg2;
        Ok(out)
    }

    fn write_msg2_step<F>(&mut self, build_payload: F) -> Result<Vec<u8>, CoreError>
    where
        F: FnOnce(&[u8; 32]) -> Result<Vec<u8>, CoreError>,
    {
        let mut out = Vec::new();
        let re = self
            .remote_ephemeral
            .ok_or_else(|| CoreError::Noise("missing remote ephemeral key".into()))?;
        let ek = self
            .remote_kem_ek
            .take()
            .ok_or_else(|| CoreError::Noise("missing remote encapsulation key".into()))?;

        let e_priv = match self.fixed_seeds {
            Some(ref seeds) => Zeroizing::new(seeds.x25519),
            None => Zeroizing::new(random_bytes::<32>()?),
        };
        let e_pub = x25519_public_from_scalar(&e_priv);
        out.extend_from_slice(&e_pub);
        self.sym.mix_hash(&e_pub);

        let dh_ee = x25519_dh(&e_priv, &re)?;
        self.sym.mix_key(&*dh_ee)?;

        let m = match self.fixed_seeds {
            Some(ref seeds) => Zeroizing::new(seeds.mlkem_m),
            None => Zeroizing::new(random_bytes::<32>()?),
        };
        let (ss, ct) = ek.encaps_from_seed(&m);
        let ct_bytes = ct.into_bytes();
        let ct_enc = self.sym.encrypt_and_hash(&ct_bytes)?;
        out.extend_from_slice(&ct_enc);
        let ss_bytes = Zeroizing::new(ss.into_bytes());
        self.sym.mix_key(&*ss_bytes)?;

        let s_enc = self.sym.encrypt_and_hash(&self.local_static_pub)?;
        out.extend_from_slice(&s_enc);

        let dh_es = x25519_dh(&self.local_static_priv, &re)?;
        self.sym.mix_key(&*dh_es)?;

        let h_pre = self.sym.h;
        let payload = Zeroizing::new(build_payload(&h_pre)?);
        let payload_enc = self.sym.encrypt_and_hash(&payload)?;
        out.extend_from_slice(&payload_enc);

        if out.len() > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: out.len(),
                max: MAX_FRAME_LEN,
            });
        }
        self.local_ephemeral_priv = Some(e_priv);
        self.step = HandshakeStep::ResponderReadMsg3;
        Ok(out)
    }

    fn write_message_step(
        &mut self,
        step: HandshakeStep,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let mut out = Vec::new();
        let next_step = match step {
            HandshakeStep::InitiatorWriteMsg3 => {
                // `-> s, se`
                let re = self
                    .remote_ephemeral
                    .ok_or_else(|| CoreError::Noise("missing remote ephemeral key".into()))?;

                let s_enc = self.sym.encrypt_and_hash(&self.local_static_pub)?;
                out.extend_from_slice(&s_enc);

                let dh_se = x25519_dh(&self.local_static_priv, &re)?;
                self.sym.mix_key(&*dh_se)?;

                let payload_enc = self.sym.encrypt_and_hash(payload)?;
                out.extend_from_slice(&payload_enc);

                self.local_ephemeral_priv = None;
                HandshakeStep::Completed
            }
            _ => {
                return Err(CoreError::Noise(
                    "write_message called out of handshake turn".into(),
                ));
            }
        };
        if out.len() > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: out.len(),
                max: MAX_FRAME_LEN,
            });
        }
        self.step = next_step;
        Ok(out)
    }

    fn expected_write_len(&self, payload_len: usize) -> Result<usize, CoreError> {
        match self.step {
            HandshakeStep::InitiatorWriteMsg1 => Ok(MSG1_LEN.saturating_add(payload_len)),
            HandshakeStep::ResponderWriteMsg2 => Ok(MIN_MSG2_LEN.saturating_add(payload_len)),
            HandshakeStep::InitiatorWriteMsg3 => Ok(MIN_MSG3_LEN.saturating_add(payload_len)),
            _ => Err(CoreError::Noise(
                "write_message called out of handshake turn".into(),
            )),
        }
    }

    /// Generates the next handshake message into `out`, returning bytes written.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, CoreError> {
        let projected_len = self.expected_write_len(payload.len())?;
        if projected_len > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: projected_len,
                max: MAX_FRAME_LEN,
            });
        }
        if out.len() < projected_len {
            return Err(CoreError::Noise("output buffer too small".into()));
        }
        let msg = self.write_message_vec(payload)?;
        out[..msg.len()].copy_from_slice(&msg);
        Ok(msg.len())
    }

    /// Consumes `msg2` and returns `(decrypted_payload, pre_payload_handshake_hash)`.
    pub fn read_msg2_with_pre_payload_hash(
        &mut self,
        message: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), CoreError> {
        let step = std::mem::replace(&mut self.step, HandshakeStep::Failed);
        if step != HandshakeStep::InitiatorReadMsg2 {
            self.fail_and_wipe_secrets();
            return Err(CoreError::Noise(
                "read_msg2_with_pre_payload_hash called out of handshake turn".into(),
            ));
        }
        if message.len() > MAX_FRAME_LEN {
            self.fail_and_wipe_secrets();
            return Err(CoreError::FrameTooLarge {
                len: message.len(),
                max: MAX_FRAME_LEN,
            });
        }
        let res = self.read_msg2_step(message);
        if res.is_err() {
            self.fail_and_wipe_secrets();
        }
        res
    }

    /// Consumes the next incoming handshake message, returning the zeroized decrypted payload.
    pub fn read_message_vec(&mut self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let step = std::mem::replace(&mut self.step, HandshakeStep::Failed);
        let res = self.read_message_step(step, message);
        if res.is_err() {
            self.fail_and_wipe_secrets();
        }
        res
    }

    fn read_msg2_step(
        &mut self,
        message: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), CoreError> {
        // `<- e, ee, ekem1, s, es`
        if message.len() < MIN_MSG2_LEN {
            return Err(CoreError::Noise("truncated XXhfs msg2".into()));
        }

        let e_priv = self
            .local_ephemeral_priv
            .as_ref()
            .ok_or_else(|| CoreError::Noise("missing local ephemeral key".into()))?
            .clone();
        let dk = self
            .local_kem_dk
            .take()
            .ok_or_else(|| CoreError::Noise("missing local ML-KEM decaps key".into()))?;

        let mut pos = 0;
        let mut re = [0u8; DH_LEN];
        re.copy_from_slice(&message[pos..pos + DH_LEN]);
        pos += DH_LEN;
        self.sym.mix_hash(&re);

        let dh_ee = x25519_dh(&e_priv, &re)?;
        self.sym.mix_key(&*dh_ee)?;

        let ct_pt = self.sym.decrypt_and_hash(&message[pos..pos + ENC_CT_LEN])?;
        pos += ENC_CT_LEN;
        let ct_arr: Box<[u8; KEM_CT_LEN]> = ct_pt
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| CoreError::Noise("invalid ML-KEM ciphertext length".into()))?;
        let ct = ml_kem_768::CipherText::try_from_bytes(*ct_arr)
            .map_err(|err| CoreError::Noise(format!("invalid ML-KEM ciphertext: {err}")))?;
        let ss = dk
            .try_decaps(&ct)
            .map_err(|err| CoreError::Noise(format!("ML-KEM decapsulation failed: {err}")))?;
        let ss_bytes = Zeroizing::new(ss.into_bytes());
        self.sym.mix_key(&*ss_bytes)?;

        let rs_pt = self
            .sym
            .decrypt_and_hash(&message[pos..pos + ENC_STATIC_LEN])?;
        pos += ENC_STATIC_LEN;
        let rs: [u8; DH_LEN] = rs_pt
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Noise("invalid remote static key length".into()))?;

        let dh_es = x25519_dh(&e_priv, &rs)?;
        self.sym.mix_key(&*dh_es)?;

        let h_pre = self.sym.h;
        let payload = self.sym.decrypt_and_hash(&message[pos..])?;
        self.remote_ephemeral = Some(re);
        self.remote_static = Some(rs);
        self.step = HandshakeStep::InitiatorWriteMsg3;
        Ok((payload, h_pre))
    }

    fn read_message_step(
        &mut self,
        step: HandshakeStep,
        message: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        if message.len() > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: message.len(),
                max: MAX_FRAME_LEN,
            });
        }
        match step {
            HandshakeStep::ResponderReadMsg1 => {
                // `-> e, e1`
                if message.len() < MSG1_LEN {
                    return Err(CoreError::Noise("truncated XXhfs msg1".into()));
                }
                let mut re = [0u8; DH_LEN];
                re.copy_from_slice(&message[..DH_LEN]);
                self.sym.mix_hash(&re);

                let mut ek_bytes = Box::new([0u8; KEM_PK_LEN]);
                ek_bytes.copy_from_slice(&message[DH_LEN..MSG1_LEN]);
                let ek = ml_kem_768::EncapsKey::try_from_bytes(*ek_bytes).map_err(|err| {
                    CoreError::Noise(format!("invalid ML-KEM-768 encapsulation key: {err}"))
                })?;
                let ek_hash: [u8; 32] = Sha256::digest(*ek_bytes).into();
                self.sym.mix_hash(&*ek_bytes);

                let payload = self.sym.decrypt_and_hash(&message[MSG1_LEN..])?;
                self.remote_ephemeral = Some(re);
                self.remote_kem_ek = Some(Box::new(ek));
                self.remote_kem_ek_hash = Some(ek_hash);
                self.step = HandshakeStep::ResponderWriteMsg2;
                Ok(payload)
            }
            HandshakeStep::InitiatorReadMsg2 => {
                let (payload, _) = self.read_msg2_step(message)?;
                Ok(payload)
            }
            HandshakeStep::ResponderReadMsg3 => {
                // `-> s, se`
                if message.len() < MIN_MSG3_LEN {
                    return Err(CoreError::Noise("truncated XXhfs msg3".into()));
                }
                let e_priv = self
                    .local_ephemeral_priv
                    .take()
                    .ok_or_else(|| CoreError::Noise("missing local ephemeral key".into()))?;

                let rs_pt = self.sym.decrypt_and_hash(&message[..ENC_STATIC_LEN])?;
                let rs: [u8; DH_LEN] = rs_pt
                    .as_slice()
                    .try_into()
                    .map_err(|_| CoreError::Noise("invalid remote static key length".into()))?;

                let dh_se = x25519_dh(&e_priv, &rs)?;
                self.sym.mix_key(&*dh_se)?;

                let payload = self.sym.decrypt_and_hash(&message[ENC_STATIC_LEN..])?;
                self.remote_static = Some(rs);
                self.step = HandshakeStep::Completed;
                Ok(payload)
            }
            _ => Err(CoreError::Noise(
                "read_message called out of handshake turn".into(),
            )),
        }
    }

    /// Consumes the next incoming handshake message, copying decrypted payload into `out`.
    pub fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, CoreError> {
        if message.len() > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: message.len(),
                max: MAX_FRAME_LEN,
            });
        }
        let min_len = match self.step {
            HandshakeStep::ResponderReadMsg1 => MSG1_LEN,
            HandshakeStep::InitiatorReadMsg2 => MIN_MSG2_LEN,
            HandshakeStep::ResponderReadMsg3 => MIN_MSG3_LEN,
            _ => {
                return Err(CoreError::Noise(
                    "read_message called out of handshake turn".into(),
                ));
            }
        };
        if message.len() >= min_len && out.len() < message.len() - min_len {
            return Err(CoreError::Noise("plaintext buffer too small".into()));
        }
        let pt = self.read_message_vec(message)?;
        out[..pt.len()].copy_from_slice(&pt);
        Ok(pt.len())
    }

    /// Transitions a completed handshake into split transport cipher states.
    pub fn into_transport_mode(self) -> Result<NoiseTransport, CoreError> {
        if !self.is_handshake_finished() {
            return Err(CoreError::Noise(
                "cannot enter transport mode before handshake completes".into(),
            ));
        }
        let handshake_hash = self.sym.h;
        let remote_static = self.remote_static;
        let exporter_secret =
            hkdf_sha256_32(&*self.sym.ck, &self.sym.h, b"tendril-v2-session-export");
        let (c1, c2) = self.sym.split()?;
        let (tx, rx) = match self.role {
            Role::Initiator => (c1, c2),
            Role::Responder => (c2, c1),
        };
        Ok(NoiseTransport {
            tx,
            rx,
            handshake_hash,
            remote_static,
            exporter_secret,
        })
    }
}

impl fmt::Debug for NoiseHfsHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseHfsHandshake")
            .field("role", &self.role)
            .field("step", &self.step)
            .field("handshake_hash", &hex::encode(self.sym.h))
            .finish()
    }
}

/// Split Noise transport session state with zeroizing cipher keys and explicit rekeying.
pub struct NoiseTransport {
    tx: CipherState,
    rx: CipherState,
    handshake_hash: [u8; 32],
    remote_static: Option<[u8; 32]>,
    exporter_secret: Zeroizing<[u8; 32]>,
}

impl NoiseTransport {
    /// Returns the final 32-byte Noise handshake hash `h`.
    #[must_use]
    pub fn get_handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Returns the authenticated remote X25519 static public key.
    #[must_use]
    pub fn get_remote_static(&self) -> Option<&[u8; 32]> {
        self.remote_static.as_ref()
    }

    /// Returns the current outgoing AEAD nonce counter.
    #[must_use]
    pub const fn tx_nonce(&self) -> u64 {
        self.tx.n
    }

    /// Returns the current incoming AEAD nonce counter.
    #[must_use]
    pub const fn rx_nonce(&self) -> u64 {
        self.rx.n
    }

    /// Derives `(reconnect_secret, mailbox_secret)` bound to `host_static_pub` from post-handshake secret key material.
    #[must_use]
    pub fn export_v2_secrets(
        &self,
        host_static_pub: &[u8; 32],
    ) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        let reconnect_secret = hkdf_sha256_32(
            &*self.exporter_secret,
            b"tendril-reconnect-v2",
            host_static_pub,
        );
        let mailbox_secret = hkdf_sha256_32(
            &*self.exporter_secret,
            b"tendril-mailbox-v2",
            host_static_pub,
        );
        (reconnect_secret, mailbox_secret)
    }

    /// Encrypts a transport payload under the outgoing cipher state.
    pub fn write_message_vec(&mut self, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
        let projected_len = payload.len().saturating_add(AEAD_TAG_LEN);
        if projected_len > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: projected_len,
                max: MAX_FRAME_LEN,
            });
        }
        self.tx.encrypt_with_ad(&[], payload)
    }

    /// Encrypts a transport payload into `out`, returning bytes written.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, CoreError> {
        let projected_len = payload.len().saturating_add(AEAD_TAG_LEN);
        if projected_len > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: projected_len,
                max: MAX_FRAME_LEN,
            });
        }
        if out.len() < projected_len {
            return Err(CoreError::Noise("output buffer too small".into()));
        }
        let ct = self.write_message_vec(payload)?;
        out[..ct.len()].copy_from_slice(&ct);
        Ok(ct.len())
    }

    /// Decrypts a transport ciphertext frame under the incoming cipher state.
    pub fn read_message_vec(&mut self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        if message.len() > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: message.len(),
                max: MAX_FRAME_LEN,
            });
        }
        self.rx.decrypt_with_ad(&[], message)
    }

    /// Decrypts a transport ciphertext frame into `out`, returning plaintext bytes written.
    pub fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, CoreError> {
        if message.len() > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len: message.len(),
                max: MAX_FRAME_LEN,
            });
        }
        if message.len() >= AEAD_TAG_LEN && out.len() < message.len() - AEAD_TAG_LEN {
            return Err(CoreError::Noise("plaintext buffer too small".into()));
        }
        let pt = self.read_message_vec(message)?;
        out[..pt.len()].copy_from_slice(&pt);
        Ok(pt.len())
    }

    /// Advances the outgoing cipher key using the Noise `REKEY` PRF.
    pub fn rekey_outgoing(&mut self) -> Result<(), CoreError> {
        self.tx.rekey()
    }

    /// Advances the incoming cipher key using the Noise `REKEY` PRF.
    pub fn rekey_incoming(&mut self) -> Result<(), CoreError> {
        self.rx.rekey()
    }
}

impl fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseTransport")
            .field("tx", &self.tx)
            .field("rx", &self.rx)
            .field("handshake_hash", &hex::encode(self.handshake_hash))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::StaticKeypair;

    #[test]
    fn xxhfs_roundtrip_rekey_and_nonce_exhaustion() {
        let init_k = StaticKeypair::from_scalar([0x11; 32]);
        let resp_k = StaticKeypair::from_scalar([0x22; 32]);
        let mut hs_i = NoiseHfsHandshakeBuilder::new()
            .local_private_key(init_k.secret_bytes())
            .prologue(b"TND\x01\x01\x00")
            .fixed_ephemeral_for_testing_only([0x33; 32])
            .build_initiator()
            .unwrap();
        let mut hs_r = NoiseHfsHandshakeBuilder::new()
            .local_private_key(resp_k.secret_bytes())
            .prologue(b"TND\x01\x01\x00")
            .fixed_ephemeral_for_testing_only([0x44; 32])
            .build_responder()
            .unwrap();

        let msg1 = hs_i.write_message_vec(&[]).unwrap();
        assert_eq!(msg1.len(), MSG1_LEN);
        let pt1 = hs_r.read_message_vec(&msg1).unwrap();
        assert!(pt1.is_empty());

        let msg2 = hs_r.write_message_vec(b"host-hello").unwrap();
        let pt2 = hs_i.read_message_vec(&msg2).unwrap();
        assert_eq!(&*pt2, b"host-hello");
        assert_eq!(hs_i.get_handshake_hash(), hs_r.get_handshake_hash());
        assert_eq!(hs_i.get_remote_static(), Some(resp_k.public_bytes()));

        let msg3 = hs_i.write_message_vec(b"session-hello").unwrap();
        let pt3 = hs_r.read_message_vec(&msg3).unwrap();
        assert_eq!(&*pt3, b"session-hello");
        assert_eq!(hs_i.get_handshake_hash(), hs_r.get_handshake_hash());
        assert_eq!(hs_r.get_remote_static(), Some(init_k.public_bytes()));

        let mut tx_i = hs_i.into_transport_mode().unwrap();
        let mut tx_r = hs_r.into_transport_mode().unwrap();

        let f1 = tx_i.write_message_vec(b"alpha").unwrap();
        assert_eq!(&*tx_r.read_message_vec(&f1).unwrap(), b"alpha");

        tx_i.rekey_outgoing().unwrap();
        tx_r.rekey_incoming().unwrap();
        let f2 = tx_i.write_message_vec(b"beta").unwrap();
        assert_eq!(&*tx_r.read_message_vec(&f2).unwrap(), b"beta");

        let mut tampered = f2.clone();
        tampered[0] ^= 0x01;
        assert!(matches!(
            tx_r.read_message_vec(&tampered),
            Err(CoreError::Noise(_))
        ));

        // Exhausted nonce (`u64::MAX`) must fail closed.
        let mut exhausted = CipherState::from_key(Zeroizing::new([0x55; 32]));
        exhausted.n = u64::MAX;
        assert!(matches!(
            exhausted.encrypt_with_ad(&[], b"x"),
            Err(CoreError::Noise(_))
        ));
    }

    #[test]
    fn xxhfs_rejects_invalid_mlkem_modulus_and_tampered_ciphertext() {
        let init_k = StaticKeypair::from_scalar([0x11; 32]);
        let resp_k = StaticKeypair::from_scalar([0x22; 32]);
        let mut hs_i = NoiseHfsHandshakeBuilder::new()
            .local_private_key(init_k.secret_bytes())
            .prologue(b"TND\x01\x01\x00")
            .build_initiator()
            .unwrap();
        let mut hs_r = NoiseHfsHandshakeBuilder::new()
            .local_private_key(resp_k.secret_bytes())
            .prologue(b"TND\x01\x01\x00")
            .build_responder()
            .unwrap();

        let mut bad_msg1 = hs_i.write_message_vec(&[]).unwrap();
        // Force an invalid ML-KEM-768 encoded coefficient (>= q = 3329): 0xFFFF in first 2 bytes of ek.
        bad_msg1[DH_LEN] = 0xFF;
        bad_msg1[DH_LEN + 1] = 0xFF;
        assert!(matches!(
            hs_r.read_message_vec(&bad_msg1),
            Err(CoreError::Noise(_))
        ));

        // Fresh handshake to test bit-flipped `ekem1` in msg2.
        let mut hs_i2 = NoiseHfsHandshakeBuilder::new()
            .local_private_key(init_k.secret_bytes())
            .prologue(b"TND\x01\x01\x00")
            .build_initiator()
            .unwrap();
        let mut hs_r2 = NoiseHfsHandshakeBuilder::new()
            .local_private_key(resp_k.secret_bytes())
            .prologue(b"TND\x01\x01\x00")
            .build_responder()
            .unwrap();
        let m1 = hs_i2.write_message_vec(&[]).unwrap();
        hs_r2.read_message_vec(&m1).unwrap();
        let mut bad_msg2 = hs_r2.write_message_vec(b"hello").unwrap();
        // Flip a bit inside encrypted `ekem1` ciphertext region (bytes 32..32+1104).
        bad_msg2[DH_LEN + 10] ^= 0x80;
        assert!(matches!(
            hs_i2.read_message_vec(&bad_msg2),
            Err(CoreError::Noise(_))
        ));
        // Failed handshake must fail closed on subsequent read/write calls.
        assert!(matches!(
            hs_i2.read_message_vec(&bad_msg2),
            Err(CoreError::Noise(_))
        ));
        assert!(matches!(
            hs_i2.write_message_vec(b"retry"),
            Err(CoreError::Noise(_))
        ));
    }

    #[test]
    fn undersized_slice_buffers_do_not_advance_handshake_or_nonces() {
        let init_k = StaticKeypair::from_scalar([0x11; 32]);
        let resp_k = StaticKeypair::from_scalar([0x22; 32]);
        let mut hs_i = NoiseHfsHandshakeBuilder::new()
            .local_private_key(init_k.secret_bytes())
            .prologue(b"TND\x01\x01\x00")
            .build_initiator()
            .unwrap();
        let mut hs_r = NoiseHfsHandshakeBuilder::new()
            .local_private_key(resp_k.secret_bytes())
            .prologue(b"TND\x01\x01\x00")
            .build_responder()
            .unwrap();

        let mut tiny = [0u8; 4];
        assert!(matches!(
            hs_i.write_message(b"", &mut tiny),
            Err(CoreError::Noise(_))
        ));
        let mut msg1_buf = vec![0u8; MSG1_LEN];
        let n1 = hs_i.write_message(b"", &mut msg1_buf).unwrap();
        assert_eq!(n1, MSG1_LEN);

        let pt1 = hs_r.read_message_vec(&msg1_buf).unwrap();
        assert!(pt1.is_empty());
        assert!(matches!(
            hs_r.write_message(b"host-hello", &mut tiny),
            Err(CoreError::Noise(_))
        ));
        let mut msg2_buf = vec![0u8; MIN_MSG2_LEN + 10];
        let n2 = hs_r.write_message(b"host-hello", &mut msg2_buf).unwrap();
        assert_eq!(n2, msg2_buf.len());

        assert!(matches!(
            hs_i.read_message(&msg2_buf, &mut tiny),
            Err(CoreError::Noise(_))
        ));
        let mut pt2_buf = [0u8; 10];
        let p2_len = hs_i.read_message(&msg2_buf, &mut pt2_buf).unwrap();
        assert_eq!(&pt2_buf[..p2_len], b"host-hello");

        let msg3 = hs_i.write_message_vec(b"cli").unwrap();
        hs_r.read_message_vec(&msg3).unwrap();

        let mut tx_i = hs_i.into_transport_mode().unwrap();
        let mut tx_r = hs_r.into_transport_mode().unwrap();

        assert!(matches!(
            tx_i.write_message(b"hello-world", &mut tiny),
            Err(CoreError::Noise(_))
        ));
        assert_eq!(tx_i.tx.n, 0);

        let mut ct_buf = [0u8; 64];
        let ct_len = tx_i.write_message(b"hello-world", &mut ct_buf).unwrap();
        assert!(matches!(
            tx_r.read_message(&ct_buf[..ct_len], &mut tiny),
            Err(CoreError::Noise(_))
        ));
        assert_eq!(tx_r.rx.n, 0);

        let mut pt_buf = [0u8; 32];
        let pt_len = tx_r.read_message(&ct_buf[..ct_len], &mut pt_buf).unwrap();
        assert_eq!(&pt_buf[..pt_len], b"hello-world");
    }
}
