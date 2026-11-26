//! Stateless Tendril v1 and v2 WebSocket ciphertext relay server and wire helpers.

pub mod protocol;
pub mod rate_limit;
pub mod server;

pub use protocol::{
    MAX_RELAY_FRAME_LEN, MAX_STANDBY_PER_MAILBOX, RELAY_ACCEPT_DOMAIN, RELAY_HEALTH_PATH,
    RELAY_PATH, RELAY_REG_DOMAIN, RELAY_V2_PATH, RelayClientMsg, RelayServerMsg, RelayV2ClientMsg,
    RelayV2ServerMsg, decode_init_frame, relay_accept_signed_bytes, relay_register_signed_bytes,
    sign_relay_accept, sign_relay_register, verify_relay_accept, verify_relay_register,
};
pub use rate_limit::{IpTokenLimiter, normalize_rate_limit_ip};
pub use server::{IpCidr, RelayConfig, RelayError, RelayHandle, RelayServer, TrustedProxyHeader};
#[cfg(feature = "test-hooks")]
pub use server::{RelayTestHook, RelayTestPoint};
pub use tendril_core::relay_auth::{RelayAuthProof, RelayAuthScope};
