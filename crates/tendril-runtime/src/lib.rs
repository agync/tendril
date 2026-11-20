//! Async Tokio runtime, pluggable untrusted path providers, rate limiters, and persistence.

pub mod driver;
pub mod error;
pub mod provider;
pub mod providers;
pub mod rate_limit;
pub mod router;
pub mod store;

pub use driver::{
    DEFAULT_PRE_AUTH_TIMEOUT, SessionDriver, SessionEvent, dial_with_policy, drive_pair_initiator,
    drive_pair_responder, drive_pair_responder_with_options, pairing_path_kind_for_provider,
};
pub use error::RuntimeError;
pub use provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathStream,
    PrefixedPathStream, peek_exact, recv_tendril_frame, send_tendril_frame,
};
pub use providers::{
    BrokerDialer, BrokerListener, BrokerServerConfig, DirectDialer, DirectListener, EmbeddedRelay,
    LocalDialer, LocalListener, OverlayConfig, OverlayDialer, OverlayHelperDialer,
    OverlayHelperListener, OverlayListener, OverlayMode, OverlayResolvedMode, RelayDialer,
    RelayListener, dial_endpoint, is_loopback_host, is_metadata_or_link_local_ip, is_tailnet_ip,
    select_overlay_mode,
};
#[cfg(feature = "p2p-iroh")]
pub use providers::{
    P2pDialer, P2pListener, P2pRelayMode, TENDRIL_P2P_ALPN, format_p2p_endpoint,
    parse_p2p_endpoint, parse_p2p_endpoint_filtered, parse_p2p_relay_mode,
};
pub use rate_limit::{HalfOpenGuard, PreAuthConfig, PreAuthRateLimiter};
pub use router::{InboundQueue, InboundRouter, RoutedInbound, recv_routed};
pub use store::{RosterStamp, StateStore};
