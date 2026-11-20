//! Core protocol primitives for Tendril.
//!
//! This crate owns device identity, pairing verification, the sealed Noise
//! session, capability grants, and path selection policy without direct OS I/O.

/// Wire protocol version encoded in the cleartext preamble.
pub const WIRE_VERSION: u8 = 1;

/// Length in bytes of the Noise AEAD authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Maximum length in bytes of a single framed payload body.
///
/// Leaves headroom for the 16-byte AEAD tag beneath the 64 KiB Noise message ceiling.
pub const MAX_FRAME_LEN: usize = 65_519;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_ceiling_fits_within_u16_with_aead_tag() {
        assert_eq!(MAX_FRAME_LEN + AEAD_TAG_LEN, usize::from(u16::MAX));
    }
}
