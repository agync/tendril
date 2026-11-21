//! Stateless Tendril v1 and v2 WebSocket ciphertext relay server and wire helpers.

pub mod protocol;
pub mod rate_limit;
pub mod server;

pub use protocol::{
    MAX_RELAY_FRAME_LEN, RELAY_ACCEPT_DOMAIN, RELAY_PATH, RELAY_REG_DOMAIN, RELAY_V2_PATH,
    RelayClientMsg, RelayServerMsg, RelayV2ClientMsg, RelayV2ServerMsg, relay_accept_signed_bytes,
    relay_register_signed_bytes, sign_relay_accept, sign_relay_register, verify_relay_accept,
    verify_relay_register,
};
pub use rate_limit::{IpTokenLimiter, normalize_rate_limit_ip};
pub use server::{IpCidr, RelayConfig, RelayError, RelayHandle, RelayServer};
