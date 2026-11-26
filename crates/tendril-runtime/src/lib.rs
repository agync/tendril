//! Async Tokio runtime, pluggable untrusted path providers, rate limiters, and persistence.

pub mod advertise;
pub mod announce;
pub mod driver;
pub mod error;
pub mod group;
pub mod provider;
pub mod providers;
pub mod rate_limit;
pub mod redact;
pub mod router;
pub mod store;
pub mod v2_driver;
pub mod wake;
pub mod wake_retry;

pub use advertise::{
    AdvertiseInputs, AdvertiseMode, ListAddrSource, LocalAddr, LocalAddrSource, NativeAddrSource,
    NetworkSnapshot, ServedListener, SnapshotNetwork, Transport, auto_endpoints,
};
pub use announce::{
    AddressSource, AnnounceEvent, CLIENT_ROUTE_SET_INTERVAL_MS, DEFAULT_ROUTE_REFRESH_INTERVAL,
    EMPTY_SNAPSHOT_DEBOUNCE_MS, HOST_ROUTE_SET_DEBOUNCE_MS, HOST_ROUTE_SET_INTERVAL_MS,
    IngestIgnored, IngestOutcome, LastRouteSet, RefreshOutcome, RosterAccess, RouteAnnouncer,
    RouteSetLimiter, RouteSetSink, ingest_route_sets,
};
pub use driver::{
    AttemptError, CandidateFailure, ConcurrentSession, ConnectOpts, ConnectResult,
    DEFAULT_PRE_AUTH_TIMEOUT, EnrollRouteWarning, M2mEnrollOptions, M2mEnrollResult,
    PairDriveResult, PairPolicyOptions, PairPolicyResult, RecoveryRoutes, SessionDriver,
    SessionEvent, dial_with_policy, dial_with_policy_verified,
    drive_m2m_enroll_initiator_with_floor, drive_m2m_enroll_initiator_with_routes,
    drive_m2m_enroll_initiator_with_store, drive_pair_initiator_with_floor,
    drive_pair_initiator_with_policy, drive_pair_initiator_with_store, drive_pair_responder,
    drive_pair_responder_with_options, drive_pair_responder_with_policy,
    drive_pair_responder_with_policy_and_store, drive_pair_responder_with_store,
    pairing_path_kind_for_provider, pinned_pairing_floor,
};
#[allow(deprecated)]
pub use driver::{
    drive_m2m_enroll_initiator, drive_m2m_enroll_initiator_with_timeout, drive_pair_initiator,
    drive_pair_initiator_with_timeout,
};
pub use error::{RelayOffline, RuntimeError};
pub use group::{
    ADMIN_SESSION_IDLE_TIMEOUT, BOOTSTRAP_COMMIT_TIMEOUT, BroadcastReport,
    DEFAULT_GROUP_DIAL_BUDGET, GroupEvent, GroupFrameKind, GroupFrameOutcome, GroupHub, GroupPool,
    GroupPoolConfig, InboundSession, MAX_ADMIN_SESSIONS, MAX_CONCURRENT_GROUP_DIALS,
    MAX_GROUPS_PER_SIGNER, MAX_LOCAL_GROUPS, MAX_PENDING_BOOTSTRAP_COMMITS, MAX_STORED_GROUPS,
    check_group_capacity, default_group_caps, group_add_member, group_create, group_forget,
    group_ingest_manifest, group_remove_member, handle_session_group_frame, ingest_pushed_manifest,
    ingest_pushed_rendezvous, normalize_endpoint_hint,
};
pub use provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathDialer, PathListener, PathReader, PathStream,
    PathWriter, PrefixedPathStream, peek_exact, recv_tendril_frame, send_tendril_frame,
    split_path_stream_fallback,
};
pub use providers::{
    BrokerDialer, BrokerListener, BrokerServerConfig, DirectDialer, DirectListener, EmbeddedRelay,
    LocalDialer, LocalListener, OverlayConfig, OverlayDialer, OverlayHelperDialer,
    OverlayHelperListener, OverlayListener, OverlayMode, OverlayResolvedMode, RelayClientAuth,
    RelayDialer, RelayListener, RelayV2Dialer, RelayV2Listener, RelayV2ListenerConfig,
    dial_endpoint, dial_endpoint_with_auth, is_loopback_host, is_metadata_or_link_local_ip,
    is_tailnet_ip, select_overlay_mode,
};
#[cfg(feature = "p2p-iroh")]
pub use providers::{
    MAX_P2P_CUSTOM_RELAYS, P2pBindAddrs, P2pDialer, P2pListener, P2pOptions, P2pRelayAuth,
    P2pRelayMode, TENDRIL_P2P_ALPN, format_p2p_endpoint, format_p2p_endpoint_with_addrs,
    parse_p2p_endpoint, parse_p2p_endpoint_filtered, parse_p2p_relay_mode, parse_p2p_relay_modes,
};
#[cfg(feature = "webrtc")]
pub use providers::{
    MAX_WEBRTC_QUEUED_BYTES, MAX_WEBRTC_SESSIONS, WEBRTC_HANDSHAKE_TIMEOUT, WebRtcActiveDialer,
    WebRtcReadHalf, WebRtcStream, WebRtcUpgradeEndpoint, WebRtcUpgradeHandle,
    WebRtcUpgradeListener, WebRtcWriteHalf,
};
#[cfg(feature = "webtransport")]
pub use providers::{WtDialer, WtListener};
pub use rate_limit::{HalfOpenGuard, PreAuthConfig, PreAuthRateLimiter};
pub use router::{InboundQueue, InboundRouter, RoutedInbound, recv_routed};
pub use store::{
    RosterStamp, StateStore, deserialize_identity_json, deserialize_identity_json_with_signer,
    serialize_identity_json,
};
pub use v2_driver::{
    ConcurrentV2Session, DEFAULT_ARGON2_ACQUIRE_TIMEOUT, DEFAULT_ARGON2_CONCURRENCY,
    DEFAULT_INITIATOR_ARGON2_PERMITS, V2_RUNG_BUDGET_FAR, V2_RUNG_BUDGET_NEAR, V2PairDriveResult,
    V2ResponderConfig, V2ResponderState, V2SessionDriver, WakeDialOptions,
    drive_v2_pair_initiator_with_policy, drive_v2_pake_pair_initiator,
    drive_v2_pake_pair_initiator_with_store, drive_v2_pake_pair_initiator_with_timeout,
    drive_v2_pake_pair_responder, drive_v2_pake_pair_responder_with_options,
    drive_v2_pake_pair_responder_with_store, drive_v2_session_initiator,
    drive_v2_session_responder, initiator_argon2_available, initiator_argon2_peak,
    set_initiator_argon2_permits, wake_and_connect_v2_session, wake_and_dial_v2,
};
pub use wake::{
    APNS_JWT_REFRESH_SECS, ApnsAlert, ApnsAps, ApnsH2Auth, ApnsH2WakeProvider, ApnsOptions,
    ApnsPayload, ApnsPushMode, DEFAULT_APNS_LOC_KEY, DEFAULT_WAKE_COALESCE_INTERVAL_SECS,
    DEFAULT_WAKE_TIMEOUT, FcmAndroidConfig, FcmDataFields, FcmMessage, FcmPayload,
    HttpWakeProvider, MAX_WAKE_COALESCE_TARGETS, MAX_WAKE_ENDPOINT_URL_LEN, MAX_WAKE_PEM_BYTES,
    MemoryWakeProvider, NoopWakeProvider, ParsedWakeConfig, RecordedWake, WAKE_EPOCH_SECS,
    WAKE_TAG_LEN, WakeAdapterKind, WakeChannel, WakeCoalescer, WakeConfigSpec, WakeEnvelope,
    WakeOutcome, WakeProvider, WakeSecret, WakeTag, WakeTarget, WakeTransportSettings,
    build_wake_payload, build_wake_payload_for_target, build_wake_provider,
    build_wake_provider_with_root_certs, default_wake_root_certs, derive_epoch_wake_tag,
    validate_apns_h2_endpoint_url, validate_apns_loc_key, validate_apns_topic,
    validate_wake_endpoint_url, verify_epoch_wake_tag_window, wake_epoch, wake_epoch_start_secs,
};
pub use wake_retry::{connect_with_wake, connect_with_wake_policy};
