//! Stateless Tendril v1 WebSocket ciphertext relay server and wire helpers.

pub mod protocol;
pub mod rate_limit;
pub mod server;

pub use protocol::{
    MAX_RELAY_FRAME_LEN, RELAY_ACCEPT_DOMAIN, RELAY_PATH, RELAY_REG_DOMAIN, RelayClientMsg,
    RelayServerMsg, relay_accept_signed_bytes, relay_register_signed_bytes, sign_relay_accept,
    sign_relay_register, verify_relay_accept, verify_relay_register,
};
pub use server::{RelayConfig, RelayError, RelayHandle, RelayServer};
