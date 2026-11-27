//! Core protocol primitives for Tendril.
//!
//! This crate owns device identity, pairing verification, the sealed Noise
//! session, capability grants, and path selection policy without direct OS I/O.

use poly1305 as _;

pub mod crypto;
pub mod error;
pub mod grants;
pub mod group;
pub mod identity;
pub mod noise;
pub mod pairing;
pub mod policy;
pub mod redact;
pub mod refusal;
pub mod relay_auth;
pub mod roster;
pub mod routes;
pub mod session;
pub mod state_seal;
pub mod v2;
pub mod wire;

pub use crypto::ExternalMlDsaSigner;
pub use error::{AdmissionRefusalCode, RefusalReason};
pub use grants::{
    authorize_path_capability, canonicalize_capability_path, verify_enrollment_grant_chain,
};
pub use pairing::{
    DEFAULT_ENROLLMENT_TTL_SECS, ENROLL_PROOF_DOMAIN, EnrollmentPolicy, MAX_ENROLLMENT_TTL_SECS,
    MAX_LIVE_PAIRING_CODES, PAIR_KEY_PROOF_DOMAIN,
};
pub use refusal::{
    MAX_REFUSAL_LIMITER_PEERS, MAX_REFUSAL_REPLAY_ENTRIES, REFUSAL_LIMIT_WINDOW_SECS,
    RefusalLimiter, RefusalMode, RefusalReplayCache,
};
pub use relay_auth::{
    MAX_RELAY_AUTH_SECRET_BYTES, MAX_RELAY_FRAME_LEN, MAX_RELAY_TICKET_TTL_SECS,
    MAX_STANDBY_PER_MAILBOX, RELAY_ACCEPT_DOMAIN, RELAY_AUTH_HMAC_DOMAIN, RELAY_HEALTH_PATH,
    RELAY_PATH, RELAY_REG_DOMAIN, RELAY_TICKET_CLOCK_SKEW_SECS, RELAY_TICKET_DOMAIN, RELAY_V2_PATH,
    RelayAuthProof, RelayAuthRole, RelayAuthScope, RelayAuthSecret, RelayTicket,
    compute_relay_auth_hmac, compute_relay_auth_hmac_b64, decode_init_frame, mint_relay_ticket,
    mint_v2_epoch_relay_ticket, relay_accept_signed_bytes, relay_auth_hmac_input,
    relay_register_signed_bytes, relay_ticket_signed_bytes, sign_relay_accept, sign_relay_register,
    validate_relay_auth_op, validate_relay_auth_secret, verify_relay_accept,
    verify_relay_auth_hmac, verify_relay_register, verify_relay_ticket,
};
pub use roster::{AnchorState, MAX_BURNED_ENROLLMENT_NONCES, TrustAnchor, V2PeerSecrets};
pub use routes::{
    MAX_ROUTE_SEQ, MAX_ROUTE_SET_PAYLOAD, MIN_ROUTE_SET_PAYLOAD, ROUTE_SET_DOMAIN, RouteSet,
};
pub use wire::{
    AEAD_TAG_LEN, FLAG_PAKE_PAIR, MAX_APP_DATA_LEN, MAX_FRAME_LEN, MAX_PATH_UPGRADE_LEN,
    MAX_PATH_UPGRADE_OFFERS_PER_SESSION, MAX_TRANSPORT_PLAINTEXT, MAX_UPGRADE_CAP_LEN,
    MAX_UPGRADE_CAPS, NOISE_PATTERN, PREAMBLE_FLAG_NONE, PREAMBLE_LEN, PREAMBLE_MAGIC,
    PathUpgradeMsg, PathUpgradeState, UPGRADE_CAP_WEBRTC_V1, WEBRTC_DATACHANNEL_LABEL,
    WIRE_VERSION, WIRE_VERSION_V2, validate_upgrade_caps,
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
