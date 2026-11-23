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
    TENDRIL_ERR_INTERNAL = -7
};

/* Copies the last thread-local error message into buf (NUL-terminated). Returns bytes needed. */
int32_t tendril_last_error(char *buf, size_t cap);

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

/* Endpoint lifecycle and operations. */
TendrilEndpoint *tendril_endpoint_new(const char *state_dir, const char *host_id);
TendrilEndpoint *tendril_endpoint_new_from_state(
    const char *identity_json_opt,
    const char *roster_json_opt,
    const char *host_id_opt
);
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
int32_t tendril_endpoint_close(TendrilEndpoint *ep);
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
int32_t tendril_endpoint_revoke_peer(TendrilEndpoint *ep, const char *peer_id);

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

/* Session lifecycle and polled queue API (independent of TendrilEndpoint lifetime once opened). */
TendrilSession *tendril_session_connect(
    TendrilEndpoint *ep,
    const char *endpoint,
    const char *relay_host,
    const char *target_host_id,
    const char *grant_json
);
TendrilSession *tendril_session_accept(TendrilEndpoint *ep, uint64_t timeout_ms);
int32_t tendril_session_shutdown(TendrilSession *sess);
int32_t tendril_session_export_roster_json(const TendrilSession *sess, char **out_json);
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
 * tendril_session_accept and tendril_session_accept_v2.
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
