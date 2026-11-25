import {
  canonical_relay_host,
  decode_b64url_exact,
  decode_relay_init_frame_b64,
  initSync,
  relay_protocol_constants_json,
  v2_epoch_for_unix,
  v2_epoch_within_skew,
  validate_ed25519_pub_b64,
  validate_relay_auth_secret_bytes,
  validate_relay_ticket_schema_json,
  verify_relay_accept_v1,
  verify_relay_auth_hmac_b64,
  verify_relay_register_v1,
  verify_relay_ticket_json,
  verify_v2_relay_accept_b64,
  verify_v2_relay_register_b64,
} from "../pkg/tendril_wasm.js";

let initialized = false;
let cachedConstants = null;

/** Initializes the compiled `tendril-wasm` module once per isolate. */
export function initWasm(moduleOrBytes) {
  if (!initialized) {
    initSync({ module: moduleOrBytes });
    initialized = true;
  }
}

/** Returns immutable protocol constants sourced directly from `tendril-core`. */
export function getProtocolConstants() {
  if (!cachedConstants) {
    cachedConstants = Object.freeze(JSON.parse(relay_protocol_constants_json()));
  }
  return cachedConstants;
}

export function canonicalRelayHost(host) {
  return canonical_relay_host(host);
}

export function v2EpochForUnix(unixSecs) {
  return v2_epoch_for_unix(unixSecs);
}

export function v2EpochWithinSkew(serverEpoch, claimedEpoch) {
  return v2_epoch_within_skew(serverEpoch, claimedEpoch);
}

/** Validates an HMAC secret copy without mutating the caller's buffer. */
export function validateRelayAuthSecretBytes(secretBytes) {
  const copy = new Uint8Array(secretBytes);
  validate_relay_auth_secret_bytes(copy);
}

export function decodeB64UrlExact(raw, expectedLen) {
  return decode_b64url_exact(raw, expectedLen);
}

export function validateEd25519PubB64(raw) {
  return validate_ed25519_pub_b64(raw);
}

export function decodeRelayInitFrameB64(raw) {
  return decode_relay_init_frame_b64(raw);
}

export function verifyRelayRegisterV1(pubB64, sigB64, relayHost, nonce) {
  return verify_relay_register_v1(pubB64, sigB64, relayHost, nonce);
}

export function verifyRelayAcceptV1(pubB64, connIdB64, sigB64, relayHost, nonce) {
  return verify_relay_accept_v1(pubB64, connIdB64, sigB64, relayHost, nonce);
}

export function verifyV2RelayRegisterB64(mailboxIdB64, epoch, relayHost, nonce, sigB64) {
  return verify_v2_relay_register_b64(mailboxIdB64, epoch, relayHost, nonce, sigB64);
}

export function verifyV2RelayAcceptB64(mailboxIdB64, epoch, relayHost, nonce, connIdB64, sigB64) {
  return verify_v2_relay_accept_b64(mailboxIdB64, epoch, relayHost, nonce, connIdB64, sigB64);
}

/** Verifies an HMAC admission tag against a fresh copy of `secretBytes`. */
export function verifyRelayAuthHmacB64(secretBytes, op, relayHost, nonce, pubOrTarget, macB64) {
  const copy = new Uint8Array(secretBytes);
  return verify_relay_auth_hmac_b64(copy, op, relayHost, nonce, pubOrTarget, macB64);
}

export function validateRelayTicketSchemaJson(ticketJson) {
  return validate_relay_ticket_schema_json(ticketJson);
}

export function verifyRelayTicketJson(ticketJson, issuersJson, expectedHost, requiredOp, targetPub, nowUnixSecs) {
  return verify_relay_ticket_json(ticketJson, issuersJson, expectedHost, requiredOp, targetPub, nowUnixSecs);
}
