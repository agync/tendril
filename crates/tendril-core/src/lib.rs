//! Core protocol primitives for Tendril.
//!
//! This crate owns device identity, pairing verification, the sealed Noise
//! session, capability grants, and path selection policy without direct OS I/O.

pub mod crypto;
pub mod error;
pub mod grants;
pub mod identity;
pub mod pairing;
pub mod policy;
pub mod roster;
pub mod session;
pub mod wire;

pub use grants::{
    authorize_path_capability, canonicalize_capability_path, verify_enrollment_grant_chain,
};
pub use pairing::{
    DEFAULT_ENROLLMENT_TTL_SECS, ENROLL_PROOF_DOMAIN, EnrollmentPolicy, MAX_ENROLLMENT_TTL_SECS,
};
pub use roster::{AnchorState, MAX_BURNED_ENROLLMENT_NONCES, TrustAnchor};
pub use wire::{
    AEAD_TAG_LEN, MAX_APP_DATA_LEN, MAX_FRAME_LEN, MAX_TRANSPORT_PLAINTEXT, NOISE_PATTERN,
    PREAMBLE_LEN, PREAMBLE_MAGIC, WIRE_VERSION,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_ceiling_fits_within_u16_with_aead_tag() {
        assert_eq!(MAX_FRAME_LEN + AEAD_TAG_LEN, usize::from(u16::MAX));
    }

    #[test]
    fn capability_prefix_and_exact_coverage() {
        let wild = grants::Capability::parse("fs.read:/photos/*").unwrap();
        let exact_child = grants::Capability::parse("fs.read:/photos/2026/a.jpg").unwrap();
        let narrow_wild = grants::Capability::parse("fs.read:/photos/2026/*").unwrap();
        let sibling = grants::Capability::parse("fs.read:/docs/a.txt").unwrap();
        assert!(wild.covers(&exact_child));
        assert!(wild.covers(&narrow_wild));
        assert!(!wild.covers(&sibling));

        let exact = grants::Capability::parse("fs.read:/photos").unwrap();
        assert!(exact.covers(&grants::Capability::parse("fs.read:/photos").unwrap()));
        assert!(!exact.covers(&exact_child));
    }
}
