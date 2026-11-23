//! Sealed local state envelopes for runtime-owned roster and group files.
//!
//! A sealed file is `0x01 || nonce (24 B) || XChaCha20-Poly1305(K, nonce, AAD, plaintext)` with
//! `K = HKDF-SHA256(ikm = X25519 static secret, salt = empty, info = "tendril-local-state-v1")`
//! and `AAD = "tendril-local-state-v1\0" || 0x01 || kind`. The kind is supplied by the caller and
//! authenticated only through the AAD, so a file of one kind never opens as another.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::crypto::{StaticKeypair, hkdf_sha256_32, random_bytes};
use crate::error::CoreError;

/// Envelope format version stored in the first byte of every sealed state file.
pub const STATE_SEAL_VERSION: u8 = 0x01;

const DOMAIN: &[u8] = b"tendril-local-state-v1";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + NONCE_LEN;

/// Message returned when an envelope fails authentication.
pub const OPEN_FAILED: &str =
    "sealed state cannot be opened (corrupt, tampered, wrong kind, or another identity)";

/// Which runtime state a sealed envelope carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateKind {
    /// Peer roster.
    Roster,
    /// Group book.
    Groups,
}

impl StateKind {
    /// Returns the kind byte bound into the AAD.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Roster => 0x01,
            Self::Groups => 0x02,
        }
    }

    /// Returns the lowercase label used in error messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Roster => "roster",
            Self::Groups => "groups",
        }
    }
}

/// Symmetric key for sealed local state, zeroized on drop and redacted from `Debug`.
pub struct StateKey(Zeroizing<[u8; 32]>);

impl StateKey {
    /// Derives the local state key from the endpoint's X25519 static secret.
    #[must_use]
    pub fn derive(static_key: &StaticKeypair) -> Self {
        Self(hkdf_sha256_32(static_key.secret_bytes(), &[], DOMAIN))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&(*self.0).into())
    }
}

impl core::fmt::Debug for StateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StateKey(<redacted>)")
    }
}

fn aad(kind: StateKind) -> [u8; 25] {
    let mut out = [0u8; 25];
    out[..DOMAIN.len()].copy_from_slice(DOMAIN);
    out[DOMAIN.len()] = 0;
    out[DOMAIN.len() + 1] = STATE_SEAL_VERSION;
    out[DOMAIN.len() + 2] = kind.byte();
    out
}

/// Seals `plaintext` as a `kind` state file under a fresh random nonce.
pub fn seal_state(key: &StateKey, kind: StateKind, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    seal_state_with_nonce(key, kind, &nonce, plaintext)
}

pub(crate) fn seal_state_with_nonce(
    key: &StateKey,
    kind: StateKind,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut body = Zeroizing::new(plaintext.to_vec());
    key.cipher()
        .encrypt_in_place(&XNonce::from(*nonce), &aad(kind), &mut *body)
        .map_err(|_| CoreError::ProtocolViolation("sealed state encryption failed"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(STATE_SEAL_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens a `kind` state file sealed by [`seal_state`].
///
/// Returns [`CoreError::UnsupportedVersion`] for an unknown version byte and
/// [`CoreError::ProtocolViolation`] with [`OPEN_FAILED`] for any other failure.
pub fn open_state(
    key: &StateKey,
    kind: StateKind,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let Some((&version, rest)) = sealed.split_first() else {
        return Err(CoreError::ProtocolViolation(OPEN_FAILED));
    };
    if version != STATE_SEAL_VERSION {
        return Err(CoreError::UnsupportedVersion(version));
    }
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(CoreError::ProtocolViolation(OPEN_FAILED));
    }
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CoreError::ProtocolViolation(OPEN_FAILED))?;
    let mut buf = Zeroizing::new(ct.to_vec());
    key.cipher()
        .decrypt_in_place(&XNonce::from(nonce), &aad(kind), &mut *buf)
        .map_err(|_| CoreError::ProtocolViolation(OPEN_FAILED))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR_HEX: &str =
        "01222222222222222222222222222222222222222222222222dbc2e73009c82e1568c7829f9442206179c6";

    fn fixed_key() -> StateKey {
        StateKey::derive(&StaticKeypair::from_scalar([0x11; 32]))
    }

    #[test]
    fn state_seal_fixed_vector() {
        let key = fixed_key();
        let sealed = seal_state_with_nonce(&key, StateKind::Groups, &[0x22; 24], b"{}").unwrap();
        assert_eq!(hex::encode(&sealed), VECTOR_HEX);

        let raw = hex::decode(VECTOR_HEX).unwrap();
        assert_eq!(raw[0], 0x01);
        let nonce: [u8; 24] = raw[1..25].try_into().unwrap();
        let mut buf = raw[25..].to_vec();
        XChaCha20Poly1305::new(&(*key.0).into())
            .decrypt_in_place(
                &XNonce::from(nonce),
                b"tendril-local-state-v1\0\x01\x02",
                &mut buf,
            )
            .unwrap();
        assert_eq!(buf, b"{}");
        assert_eq!(&*open_state(&key, StateKind::Groups, &raw).unwrap(), b"{}");
    }

    fn assert_cannot_open(res: Result<Zeroizing<Vec<u8>>, CoreError>) {
        let err = res.expect_err("must not open");
        assert!(err.to_string().contains("cannot be opened"), "{err}");
    }

    #[test]
    fn state_seal_rejections() {
        let key = fixed_key();
        let roster = seal_state(&key, StateKind::Roster, b"{\"peers\":{}}").unwrap();
        assert_eq!(
            &*open_state(&key, StateKind::Roster, &roster).unwrap(),
            b"{\"peers\":{}}"
        );
        assert_cannot_open(open_state(&key, StateKind::Groups, &roster));

        let last = roster.len() - 1;
        for idx in [1usize, 24, 25, last - 16, last] {
            let mut bad = roster.clone();
            bad[idx] ^= 0x01;
            assert_cannot_open(open_state(&key, StateKind::Roster, &bad));
        }

        let other = StateKey::derive(&StaticKeypair::from_scalar([0x33; 32]));
        assert_cannot_open(open_state(&other, StateKind::Roster, &roster));

        for len in [0usize, 1, 25, 40, roster.len() - 1] {
            assert_cannot_open(open_state(&key, StateKind::Roster, &roster[..len]));
        }

        let mut future = roster.clone();
        future[0] = 0x02;
        let err = open_state(&key, StateKind::Roster, &future).unwrap_err();
        assert!(matches!(err, CoreError::UnsupportedVersion(2)), "{err}");
        assert!(err.to_string().contains("unsupported"));

        let a = seal_state(&key, StateKind::Roster, b"x").unwrap();
        let b = seal_state(&key, StateKind::Roster, b"x").unwrap();
        assert_ne!(a[1..25], b[1..25], "nonces must be fresh");
        assert!(!format!("{key:?}").contains("17"));
    }
}
