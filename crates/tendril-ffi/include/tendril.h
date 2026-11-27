/* Manually maintained C ABI header kept in lockstep with crates/tendril-ffi/src/lib.rs. */
#ifndef TENDRIL_H
#define TENDRIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TENDRIL_KEY_LEN 32
#define TENDRIL_SIGNING_PUB_LEN 1984
#define TENDRIL_SIGNING_HASH_LEN 32
#define TENDRIL_MLDSA65_PUB_LEN 1952
#define TENDRIL_MLDSA65_SIG_LEN 3309

typedef struct TendrilEndpoint TendrilEndpoint;
typedef struct TendrilSession TendrilSession;
typedef struct TendrilGroup TendrilGroup;

enum TendrilResult {
    TENDRIL_OK = 0,
    TENDRIL_WOULD_BLOCK = 1,
    TENDRIL_EOF = 2,
    TENDRIL_ERR_INVALID_ARG = -1,
    TENDRIL_ERR_NOT_FOUND = -2,
    TENDRIL_ERR_CLOSED = -5,
    TENDRIL_ERR_PROTOCOL = -6,
    TENDRIL_ERR_INTERNAL = -7,
    /* The peer authenticated a refusal: its host revoked or has not confirmed this device.
     * tendril_last_error_code holds refused_revoked, refused_pending or refused. */
    TENDRIL_ERR_REFUSED = -8
};

/* Close codes a host sends to refuse a known peer (closed event "code"). */
#define TENDRIL_CLOSE_PEER_REVOKED 4001
#define TENDRIL_CLOSE_PEER_PENDING 4004

/* Copies the last thread-local error message into buf (NUL-terminated). Returns bytes needed. */
int32_t tendril_last_error(char *buf, size_t cap);

/* Copies the stable machine code of the last error on this thread into buf, "" when untyped
 * (refused_revoked, refused_pending, refused, host_key_unverified, ...). Same contract as
 * tendril_last_error: no allocation, NUL-terminated, returns bytes needed, never changes the
 * stored error. Read both on the thread of the failing call, before its next FFI call. */
int32_t tendril_last_error_code(char *buf, size_t cap);

/* Frees a NUL-terminated UTF-8 string allocated by tendril-ffi. */
void tendril_string_free(char *ptr);

/* Vector and pure-core helpers delegating to tendril-core. */
int32_t tendril_device_id(const uint8_t *static_pub_32, char **out_str);
int32_t tendril_fingerprint_host(const uint8_t *static_pub_32, char **out_str);
int32_t tendril_fingerprint_device(const uint8_t *static_pub_32, char **out_str);
int32_t tendril_pairing_sas(const uint8_t *handshake_hash_32, char **out_str);
int32_t tendril_compute_code_mac(
    const char *code,
    const uint8_t *handshake_hash_32,
    uint8_t *out_mac_32
);
int32_t tendril_verify_rotation_chain_json(
    const char *pinned_signing_b64,
    const char *pinned_static_b64,
    uint64_t pinned_seq,
    const char *chain_json,
    const char *cur_static_b64,
    const char *cur_signing_b64,
    uint64_t *out_final_seq
);
int32_t tendril_verify_grant_json(
    const char *grant_json,
    const char *issuer_keys_json,
    const char *expected_subject,
    const char *expected_root_issuer,
    const char *requested_cap,
    uint64_t now_unix,
    const char *crl_json_opt,
    uint8_t *out_allowed
);
int32_t tendril_verify_wake_tag(
    const uint8_t *wake_secret_32,
    const char *wake_tag_b64,
    uint64_t now_unix_secs,
    uint8_t *out_matched
);

/* Endpoint lifecycle and operations. */
TendrilEndpoint *tendril_endpoint_new(const char *state_dir, const char *host_id);
TendrilEndpoint *tendril_endpoint_new_from_state(
    const char *identity_json_opt,
    const char *roster_json_opt,
    const char *host_id_opt
);

/*
 * External ML-DSA-65 signing custody descriptor.
 * - `public_key` (`public_key_len == TENDRIL_MLDSA65_PUB_LEN`) is copied synchronously before
 *   `tendril_endpoint_new_sealed_with_options` returns.
 * - `sign` and `drop_ctx` may be called concurrently from arbitrary worker threads and must not
 *   unwind across the C ABI.
 * - Ownership of `ctx` transfers on entry to `tendril_endpoint_new_sealed_with_options`, and
 *   `drop_ctx(ctx)` executes once iff both `drop_ctx != NULL` and `ctx != NULL` (on failure return
 *   or final internal `Arc` drop).
 */
typedef struct TendrilMlDsa65Signer {
    void *ctx;
    const uint8_t *public_key;
    size_t public_key_len;
    int32_t (*sign)(
        void *ctx,
        const uint8_t *msg,
        size_t msg_len,
        const uint8_t *mldsa_ctx,
        size_t mldsa_ctx_len,
        uint8_t *out_sig,
        size_t out_sig_len
    );
    void (*drop_ctx)(void *ctx);
} TendrilMlDsa65Signer;

/* Like tendril_endpoint_new_from_state, but the runtime persists roster and group state itself in
 * state_dir (rt-roster.sealed, rt-groups.sealed), sealed under a key derived from the identity.
 * Group secrets never cross this boundary. Without identity_json_opt an identity is generated and
 * no runtime state is written: save it, then reopen with it. roster_json_opt needs
 * identity_json_opt and is parsed and written only for a directory with no runtime state (ignored
 * otherwise). Callers that generate and save an identity must serialize that per state_dir across
 * threads and processes (the bindings hold an exclusive lock on state_dir/.identity.lock). NULL
 * (last error set) when state_dir is NULL or empty or the state cannot be opened. */
TendrilEndpoint *tendril_endpoint_new_sealed(const char *state_dir, const char *identity_json_opt,
                                             const char *roster_json_opt, const char *host_id_opt);
/* Like tendril_endpoint_new_sealed with optional JSON runtime/role options and external ML-DSA-65
 * signer custody. options_json_opt may be NULL or {"runtime_profile": "default"|"extension",
 * "client_only": bool}. When mldsa_signer_opt is non-NULL, ownership of mldsa_signer_opt->ctx
 * transfers immediately on entry so drop_ctx(ctx) (if both drop_ctx and ctx are non-NULL) runs
 * once on any failure (NULL return) or when the endpoint and all internal handles drop. */
TendrilEndpoint *tendril_endpoint_new_sealed_with_options(
    const char *state_dir,
    const char *identity_json_opt,
    const char *roster_json_opt,
    const char *host_id_opt,
    const char *options_json_opt,
    const TendrilMlDsa65Signer *mldsa_signer_opt
);
int32_t tendril_endpoint_close(TendrilEndpoint *ep);
/* Frees ep after closing its inbound router, stopping hosting and the route announcer, and
 * shutting down the group hub. Any already-opened sessions remain valid independently. */
void tendril_endpoint_free(TendrilEndpoint *ep);

int32_t tendril_endpoint_export_identity_json(const TendrilEndpoint *ep, char **out_json);
int32_t tendril_endpoint_export_roster_json(const TendrilEndpoint *ep, char **out_json);
int32_t tendril_endpoint_info_json(const TendrilEndpoint *ep, char **out_json);
int32_t tendril_endpoint_serve_direct(TendrilEndpoint *ep, const char *listen_addr, char **out_endpoint);
int32_t tendril_endpoint_serve_relay(
    TendrilEndpoint *ep,
    const char *relay_url,
    const char *expected_host,
    char **out_endpoint
);
int32_t tendril_endpoint_serve_p2p(
    TendrilEndpoint *ep,
    const char *relay_mode_opt,
    char **out_endpoint
);
int32_t tendril_endpoint_issue_code(TendrilEndpoint *ep, const char *kind, char **out_code);

int32_t tendril_endpoint_pair_initiate(
    TendrilEndpoint *ep,
    const char *endpoint,
    const char *relay_host,
    const char *code,
    const char *name,
    const char *kind,
    char **out_json
);
int32_t tendril_endpoint_pair_accept(
    TendrilEndpoint *ep,
    uint64_t timeout_ms,
    char **out_json
);

int32_t tendril_endpoint_confirm_peer(TendrilEndpoint *ep, const char *peer_id, const char *sas);
int32_t tendril_endpoint_mint_grant(
    TendrilEndpoint *ep,
    const char *peer_id,
    const char *caps_json,
    uint64_t ttl_secs,
    char **out_grant_json
);
/* Revokes peer_id; records a refusal notice under the endpoint refusal policy. */
int32_t tendril_endpoint_revoke_peer(TendrilEndpoint *ep, const char *peer_id);
/* options_json: NULL or {"notify": bool}. NULL and an absent notify follow the policy;
 * {"notify": false} revokes silently. TENDRIL_ERR_NOT_FOUND for an unknown peer. */
int32_t tendril_endpoint_revoke_peer_with_options(
    TendrilEndpoint *ep,
    const char *peer_id,
    const char *options_json
);
/* policy_json: {"pending": bool, "revoked_notice_ttl_secs": u64}, absent fields default to
 * (true, 30 days); 0 records no notice. Persisted with the roster. */
int32_t tendril_endpoint_set_refusal_policy_json(TendrilEndpoint *ep, const char *policy_json);
/* Drops the refusal notice of peer_id, which stays revoked. TENDRIL_ERR_NOT_FOUND if unknown. */
int32_t tendril_endpoint_clear_refusal_notice(TendrilEndpoint *ep, const char *peer_id);
/* Unconfirmed host claims left by unpinned pairing. out_json: array, oldest first, of
 * {"host_id", "device_id", "name", "static_pub", "signing_pub_hash", "rotation_seq",
 * "min_wire_version", "pairing_sas"}; host_id is the unauthenticated label a claim names and
 * device_id the id derived from its static key in the handshake. Free out_json with
 * tendril_string_free. */
int32_t tendril_endpoint_pending_hosts(TendrilEndpoint *ep, char **out_json);
/* Drops every claim naming host_id and revokes nothing. TENDRIL_ERR_NOT_FOUND when none. */
int32_t tendril_endpoint_remove_pending_host(TendrilEndpoint *ep, const char *host_id);
/* Revokes the keys of the claims whose device_id matches, never a claimed host_id.
 * TENDRIL_ERR_NOT_FOUND when no claim has that device_id. */
int32_t tendril_endpoint_revoke_pending_host(TendrilEndpoint *ep, const char *device_id);

int32_t tendril_endpoint_add_trust_anchor(
    TendrilEndpoint *ep,
    const char *anchor_id,
    const uint8_t *signing_pub,
    size_t signing_pub_len
);
int32_t tendril_endpoint_revoke_trust_anchor(TendrilEndpoint *ep, const char *anchor_id);
int32_t tendril_endpoint_mint_enrollment_token(
    TendrilEndpoint *ep,
    const char *target_host_id,
    const char *subject_opt,
    uint64_t ttl_secs,
    char **out_token_json
);
/* Enrols under the endpoint's route_policy. out_json gains routes_persisted, route_warnings and
 * routes_reason: routes_reason is null with a state directory and "no_state_dir" on a memory-only
 * endpoint, which requests and stores no route. The default all_signed asks the host for its route
 * set; a host that predates route sets rejects that as a protocol error before it spends the
 * token, so configure route_policy "committed_only" or "none" to enrol against it. */
int32_t tendril_endpoint_enroll_initiate(
    TendrilEndpoint *ep,
    const char *endpoint,
    const char *relay_host_opt,
    const char *host_id,
    const uint8_t *host_static_pub_32,
    const uint8_t *host_signing_pin,
    size_t host_signing_pin_len,
    uint64_t host_rotation_seq,
    const char *token_json,
    const char *name,
    const char *kind,
    char **out_json
);

/*
 * Pairing URIs and routes. Every out_json string is freed with tendril_string_free.
 *
 * tendril_endpoint_configure_transports_json accepts p2p_port_mapping (bool, default true; false
 * keeps a P2P endpoint from probing the router for a UPnP, NAT-PMP or PCP mapping) and
 * p2p_bind_addrs (array of at most one IPv4 and one IPv6 "host:port" such as "0.0.0.0:0" and
 * "[::]:0"; default every interface; an invalid entry is an error naming p2p_bind_addrs).
 * p2p_relay_mode accepts "n0" as an alias of "default".
 *
 * tendril_endpoint_configure_transports_json also accepts wake_* keys (wake_url, wake_adapter,
 * wake_secret_b64, wake_auth_token, wake_pre_wake, wake_retry_delay_ms, wake_max_attempts,
 * wake_timeout_ms, wake_coalesce_secs, wake_apns_mode, wake_apns_topic, wake_apns_loc_key,
 * wake_apns_team_id, wake_apns_key_id, wake_apns_p8_pem, wake_apns_client_cert_pem,
 * wake_apns_client_key_pem), advertised_endpoints (array of strings), relay_auth_origins
 * (array of "scheme://host[:port]"; relay admission material is attached only to these origins
 * or to the explicit endpoint of a call), advertise ("auto", default, or "explicit"), route_policy
 * ("all_signed", default, "committed_only" or "none") and sign_routes (default true).
 */
/* options_json_opt: NULL or {"kind": "auto"|"lan"|"remote", "host_name": str, "sign_routes": bool}.
 * out_json: {"uri", "code_kind", "dropped", "uri_len", "qr_version_m", "route_seq"}.
 * Returns TENDRIL_ERR_CLOSED after tendril_endpoint_close. */
int32_t tendril_endpoint_issue_pairing_uri(
    TendrilEndpoint *ep,
    const char *options_json_opt,
    char **out_json
);
/* options_json_opt: NULL or {"route_policy", "save_route", "endpoint", "code"}; an empty "code"
 * is rejected before any dial.
 * out_json: {"device_id", "host_id", "sas", "status", "host_confirmed", "provider", "endpoint",
 * "committed", "route_check", "routes_persisted", "routes_reason", "skipped"}. "routes_reason" is
 * null, or "unsigned_uri", "route_key_rotated" or "stale_route_seq" when no routes were written. */
int32_t tendril_endpoint_pair_uri(
    TendrilEndpoint *ep,
    const char *pairing_uri,
    const char *name_opt,
    const char *device_kind_opt,
    const char *options_json_opt,
    char **out_json
);
int32_t tendril_endpoint_pair_v2_uri(
    TendrilEndpoint *ep,
    const char *pairing_uri,
    const char *name_opt,
    const char *device_kind_opt,
    const char *options_json_opt,
    char **out_json
);
/* routes_json: JSON array of endpoint strings replacing the operator routes. Returns 0,
 * TENDRIL_ERR_INVALID_ARG for a bad list (nothing is written), TENDRIL_ERR_NOT_FOUND for an
 * unknown peer, or TENDRIL_ERR_PROTOCOL for a pending or revoked one. */
int32_t tendril_endpoint_set_peer_routes(
    TendrilEndpoint *ep,
    const char *peer_id,
    const char *routes_json
);
/* out_json: {"routes": [{"hint", "source"}], "route_meta": {"seq", "issued_at", "origin"} | null,
 * "last_route_set": {"outcome", "seq"} | null}. */
int32_t tendril_endpoint_peer_routes(TendrilEndpoint *ep, const char *peer_id, char **out_json);
/* source_opt: NULL or "operator", "signed", "committed", "all". */
int32_t tendril_endpoint_clear_peer_routes(
    TendrilEndpoint *ep,
    const char *peer_id,
    const char *source_opt
);
/* Offline application of a fresh signed pairing URI. options_json_opt: NULL or
 * {"replace_routes", "route_policy"}. out_json: {"peer_id", "applied", "reason", "route_seq"}. */
int32_t tendril_endpoint_apply_route_uri(
    TendrilEndpoint *ep,
    const char *pairing_uri,
    const char *options_json_opt,
    char **out_json
);
/* Host re-scan. snapshot_json_opt: NULL or the complete network snapshot
 * {"networks": [{"id", "iface", "if_index", "transports", "addrs"}]}. out_json may be NULL;
 * otherwise {"route_seq", "changed"}. Returns TENDRIL_ERR_CLOSED after tendril_endpoint_close. */
int32_t tendril_endpoint_refresh_routes(
    TendrilEndpoint *ep,
    const char *snapshot_json_opt,
    char **out_json
);

/* Session lifecycle and polled queue API (independent of TendrilEndpoint lifetime once opened).
 * A NULL or "" endpoint connects over the peer's stored routes. */
TendrilSession *tendril_session_connect(
    TendrilEndpoint *ep,
    const char *endpoint,
    const char *relay_host,
    const char *target_host_id,
    const char *grant_json
);
TendrilSession *tendril_session_accept(TendrilEndpoint *ep, uint64_t timeout_ms);
/* options_json: NULL or {"wire": 1|2, "grant": obj, "endpoint": str, "relay_host": str,
 * "recovery_uri": str, "replace_routes": bool, "route_policy": str}. "relay_host" is the expected
 * relay host of an explicit "endpoint" (the Iroh relay mode for iroh://), as in
 * tendril_session_connect. */
TendrilSession *tendril_session_connect_with_options(
    TendrilEndpoint *ep,
    const char *target_host_id,
    const char *options_json
);
int32_t tendril_session_shutdown(TendrilSession *sess);
int32_t tendril_session_export_roster_json(const TendrilSession *sess, char **out_json);
int32_t tendril_session_peer_id(const TendrilSession *sess, char **out_peer_id);
void tendril_session_free(TendrilSession *sess);

int32_t tendril_session_send_data(TendrilSession *sess, const uint8_t *data, size_t len);
int32_t tendril_session_poll_event(
    TendrilSession *sess,
    uint64_t timeout_ms,
    char **out_event_json
);
int32_t tendril_session_authorize(
    const TendrilSession *sess,
    const char *cap,
    uint8_t *out_allowed
);
int32_t tendril_session_rekey(TendrilSession *sess);
int32_t tendril_session_close(TendrilSession *sess, uint16_t code, const char *reason);

int32_t tendril_endpoint_configure_transports_json(TendrilEndpoint *ep, const char *transport_config_json);
int32_t tendril_endpoint_mint_relay_ticket(TendrilEndpoint *ep, const char *relay_host, const char *role, const char *target_pub_b64_or_wildcard, uint64_t ttl_secs, char **out_ticket_json);
int32_t tendril_endpoint_serve_relay_v2(TendrilEndpoint *ep, const char *relay_url, const char *expected_host, const char *peer_id_opt, char **out_endpoint);
int32_t tendril_endpoint_pair_v2_initiate(TendrilEndpoint *ep, const char *endpoint, const char *relay_host_opt, const char *code, const char *name, const char *kind, const char *pinned_host_json_opt, char **out_json);
int32_t tendril_endpoint_pair_v2_accept(TendrilEndpoint *ep, uint64_t timeout_ms, char **out_json);
TendrilSession *tendril_session_connect_v2(TendrilEndpoint *ep, const char *endpoint, const char *relay_host_opt, const char *target_host_id, const char *grant_json_opt);
TendrilSession *tendril_session_accept_v2(TendrilEndpoint *ep, uint64_t timeout_ms);

/*
 * Group mesh. Admin calls need a state-directory or sealed endpoint and return manifest JSON
 * (public; rendezvous keys and pairwise secrets never cross this boundary). Free every out string
 * with tendril_string_free. caps_json and endpoints_json are null or a JSON array of strings.
 *
 * Ordinary-session 0x0A/0x0B frames: tendril_session_poll_event hands them to the runtime on
 * state-directory or sealed endpoints and reports group_manifest_ingested, group_manifest_rejected,
 * group_rendezvous_ingested or group_rendezvous_rejected ({group_id, seq, error?}). Store-less
 * endpoints keep reporting group_manifest_unverified and group_rendezvous_unverified.
 */
int32_t tendril_group_create(
    TendrilEndpoint *ep,
    const char *name,
    uint8_t min_wire_version,
    const char *endpoints_json,
    char **out_manifest_json
);
int32_t tendril_group_add_member(
    TendrilEndpoint *ep,
    const char *group_id,
    const char *peer_id,
    const char *caps_json,
    const char *endpoints_json,
    char **out_manifest_json
);
int32_t tendril_group_remove_member(
    TendrilEndpoint *ep,
    const char *group_id,
    const char *peer_id,
    char **out_manifest_json
);
/* sender_peer_id must be the authenticated peer that delivered the manifest. */
int32_t tendril_group_ingest_manifest(
    TendrilEndpoint *ep,
    const char *manifest_json,
    const char *sender_peer_id,
    char **out_group_id
);

/*
 * Opens a group handle (listen_addr may be NULL). The first open on an endpoint routes its inbound session streams through
 * the group hub; configure transports before it. Ordinary sessions still arrive via
 * tendril_session_accept and tendril_session_accept_v2. The hub reads the URLs served with
 * tendril_endpoint_serve_relay once, at the first open, and leaves their relay hosts to the app:
 * let every tendril_endpoint_serve_relay call return before the first open, or the group's
 * mailbox registration competes with a later call on a relay host named in its own entry.
 */
int32_t tendril_group_open(
    TendrilEndpoint *ep,
    const char *group_id,
    const char *listen_addr,
    TendrilGroup **out_group
);
/* Endpoint bound by listen_addr at open time; *out_endpoint is NULL when none (free otherwise). */
int32_t tendril_group_local_endpoint(const TendrilGroup *group, char **out_endpoint);
/* Pushes the manifest (and, for an admin, the rendezvous key) to members. Needed for wire v2 groups. */
int32_t tendril_group_sync(TendrilGroup *group, char **out_report_json);
/* required_cap may be null (default send capability). Report JSON: {delivered, offline, failed}. */
int32_t tendril_group_broadcast(
    TendrilGroup *group,
    const char *required_cap,
    const uint8_t *data_ptr,
    size_t data_len,
    char **out_report_json
);
/* Returns TENDRIL_OK with an event, TENDRIL_WOULD_BLOCK on timeout, TENDRIL_EOF when the pool is closed. */
int32_t tendril_group_poll_event(TendrilGroup *group, uint64_t timeout_ms, char **out_event_json);
/* TENDRIL_OK when peer_id holds cap; any refusal sets the last error. */
int32_t tendril_group_authorize_peer(const TendrilGroup *group, const char *peer_id, const char *cap);
/* Idempotent. Later calls on the handle return TENDRIL_ERR_CLOSED; tendril_group_free is safe after close. */
int32_t tendril_group_close(TendrilGroup *group);
void tendril_group_free(TendrilGroup *group);

#ifdef __cplusplus
}
#endif

#endif /* TENDRIL_H */
