//! Async Tokio runtime, pluggable untrusted path providers, rate limiters, and persistence.

pub mod driver;
pub mod error;
pub mod provider;
pub mod providers;
pub mod rate_limit;
pub mod router;
pub mod store;
pub mod v2_driver;
pub mod wake;

pub use driver::{
    ConcurrentSession, DEFAULT_PRE_AUTH_TIMEOUT, PairDriveResult, SessionDriver, SessionEvent,
    dial_with_policy, dial_with_policy_verified, drive_m2m_enroll_initiator_with_floor,
    drive_m2m_enroll_initiator_with_store, drive_pair_initiator_with_floor,
    drive_pair_initiator_with_store, drive_pair_responder, drive_pair_responder_with_options,
    drive_pair_responder_with_policy, drive_pair_responder_with_policy_and_store,
    drive_pair_responder_with_store, pairing_path_kind_for_provider, pinned_pairing_floor,
};
#[allow(deprecated)]
pub use driver::{
    drive_m2m_enroll_initiator, drive_m2m_enroll_initiator_with_timeout, drive_pair_initiator,
    drive_pair_initiator_with_timeout,
};
pub use error::RuntimeError;
pub use provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathReader, PathStream,
    PathWriter, PrefixedPathStream, peek_exact, recv_tendril_frame, send_tendril_frame,
    split_path_stream_fallback,
};
pub use providers::{
    BrokerDialer, BrokerListener, BrokerServerConfig, DirectDialer, DirectListener, EmbeddedRelay,
    LocalDialer, LocalListener, OverlayConfig, OverlayDialer, OverlayHelperDialer,
    OverlayHelperListener, OverlayListener, OverlayMode, OverlayResolvedMode, RelayDialer,
    RelayListener, RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig, dial_endpoint,
    is_loopback_host, is_metadata_or_link_local_ip, is_tailnet_ip, select_overlay_mode,
};
#[cfg(feature = "p2p-iroh")]
pub use providers::{
    P2pDialer, P2pListener, P2pOptions, P2pRelayMode, TENDRIL_P2P_ALPN, format_p2p_endpoint,
    format_p2p_endpoint_with_addrs, parse_p2p_endpoint, parse_p2p_endpoint_filtered,
    parse_p2p_relay_mode,
};
pub use rate_limit::{HalfOpenGuard, PreAuthConfig, PreAuthRateLimiter};
pub use router::{InboundQueue, InboundRouter, RoutedInbound, recv_routed};
pub use store::{RosterStamp, StateStore, deserialize_identity_json, serialize_identity_json};
pub use v2_driver::{
    ConcurrentV2Session, DEFAULT_ARGON2_ACQUIRE_TIMEOUT, DEFAULT_ARGON2_CONCURRENCY,
    V2PairDriveResult, V2ResponderConfig, V2ResponderState, V2SessionDriver, WakeDialOptions,
    drive_v2_pake_pair_initiator, drive_v2_pake_pair_initiator_with_store,
    drive_v2_pake_pair_initiator_with_timeout, drive_v2_pake_pair_responder,
    drive_v2_pake_pair_responder_with_options, drive_v2_pake_pair_responder_with_store,
    drive_v2_session_initiator, drive_v2_session_responder, wake_and_connect_v2_session,
    wake_and_dial_v2,
};
pub use wake::{
    ApnsAps, ApnsPayload, DEFAULT_WAKE_COALESCE_INTERVAL_SECS, DEFAULT_WAKE_TIMEOUT,
    FcmAndroidConfig, FcmDataFields, FcmMessage, FcmPayload, HttpWakeProvider,
    MAX_WAKE_COALESCE_TARGETS, MAX_WAKE_ENDPOINT_URL_LEN, MemoryWakeProvider, NoopWakeProvider,
    RecordedWake, WAKE_EPOCH_SECS, WAKE_TAG_LEN, WakeAdapterKind, WakeChannel, WakeCoalescer,
    WakeEnvelope, WakeOutcome, WakeProvider, WakeSecret, WakeTag, WakeTarget, build_wake_payload,
    derive_epoch_wake_tag, validate_wake_endpoint_url, verify_epoch_wake_tag_window, wake_epoch,
    wake_epoch_start_secs,
};
