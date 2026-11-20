#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tendril.h"

static void throw_ex(JNIEnv *env, const char *class_name, const char *msg) {
  jclass cls = (*env)->FindClass(env, class_name);
  if (cls != NULL) {
    (*env)->ThrowNew(env, cls, msg);
  }
}

static void throw_ffi_error(JNIEnv *env, int32_t rc, const char *fallback) {
  char errbuf[512];
  errbuf[0] = '\0';
  size_t needed = tendril_last_error(errbuf, sizeof(errbuf));
  char full[640];
  if (needed > 1) {
    snprintf(full, sizeof(full), "tendril ffi error (%d): %s", (int)rc, errbuf);
  } else {
    snprintf(full, sizeof(full), "%s (code %d)", fallback, (int)rc);
  }
  throw_ex(env, "java/lang/IllegalStateException", full);
}

static jstring take_out_string(JNIEnv *env, char *ptr) {
  if (ptr == NULL) {
    return (*env)->NewStringUTF(env, "");
  }
  jstring out = (*env)->NewStringUTF(env, ptr);
  tendril_string_free(ptr);
  return out;
}

static const char *get_opt_utf(JNIEnv *env, jstring s) {
  if (s == NULL) {
    return NULL;
  }
  return (*env)->GetStringUTFChars(env, s, NULL);
}

static void release_opt_utf(JNIEnv *env, jstring s, const char *cstr) {
  if (s != NULL && cstr != NULL) {
    (*env)->ReleaseStringUTFChars(env, s, cstr);
  }
}

static int read_bytes32(JNIEnv *env, jbyteArray arr, uint8_t out[32]) {
  if (arr == NULL || (*env)->GetArrayLength(env, arr) != 32) {
    throw_ex(env, "java/lang/IllegalArgumentException", "expected 32-byte array");
    return 0;
  }
  (*env)->GetByteArrayRegion(env, arr, 0, 32, (jbyte *)out);
  return 1;
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_deviceId(
    JNIEnv *env, jclass cls, jbyteArray static_pub) {
  (void)cls;
  uint8_t key[32];
  if (!read_bytes32(env, static_pub, key)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_device_id(key, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_device_id failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_fingerprintHost(
    JNIEnv *env, jclass cls, jbyteArray static_pub) {
  (void)cls;
  uint8_t key[32];
  if (!read_bytes32(env, static_pub, key)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_fingerprint_host(key, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_fingerprint_host failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_fingerprintDevice(
    JNIEnv *env, jclass cls, jbyteArray static_pub) {
  (void)cls;
  uint8_t key[32];
  if (!read_bytes32(env, static_pub, key)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_fingerprint_device(key, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_fingerprint_device failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_pairingSas(
    JNIEnv *env, jclass cls, jbyteArray handshake_hash) {
  (void)cls;
  uint8_t hh[32];
  if (!read_bytes32(env, handshake_hash, hh)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_pairing_sas(hh, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_pairing_sas failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jbyteArray JNICALL Java_dev_tendril_TendrilNative_computeCodeMac(
    JNIEnv *env, jclass cls, jstring code, jbyteArray handshake_hash) {
  (void)cls;
  if (code == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "code must not be null");
    return NULL;
  }
  uint8_t hh[32];
  if (!read_bytes32(env, handshake_hash, hh)) {
    return NULL;
  }
  const char *c_code = get_opt_utf(env, code);
  if (c_code == NULL) {
    return NULL;
  }
  uint8_t mac[32];
  int32_t rc = tendril_compute_code_mac(c_code, hh, mac);
  release_opt_utf(env, code, c_code);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_compute_code_mac failed");
    return NULL;
  }
  jbyteArray res = (*env)->NewByteArray(env, 32);
  if (res != NULL) {
    (*env)->SetByteArrayRegion(env, res, 0, 32, (const jbyte *)mac);
  }
  return res;
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_verifyRotationChainJson(
    JNIEnv *env, jclass cls, jstring pinned_signing_b64, jstring pinned_static_b64,
    jlong pinned_seq, jstring chain_json, jstring cur_static_b64, jstring cur_signing_b64) {
  (void)cls;
  if (pinned_signing_b64 == NULL || pinned_static_b64 == NULL || chain_json == NULL ||
      cur_static_b64 == NULL || cur_signing_b64 == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "rotation inputs must not be null");
    return 0;
  }
  const char *c_psig = get_opt_utf(env, pinned_signing_b64);
  const char *c_pstat = get_opt_utf(env, pinned_static_b64);
  const char *c_chain = get_opt_utf(env, chain_json);
  const char *c_cstat = get_opt_utf(env, cur_static_b64);
  const char *c_csig = get_opt_utf(env, cur_signing_b64);
  uint64_t final_seq = 0;
  int32_t rc = tendril_verify_rotation_chain_json(
      c_psig, c_pstat, (uint64_t)pinned_seq, c_chain, c_cstat, c_csig, &final_seq);
  release_opt_utf(env, pinned_signing_b64, c_psig);
  release_opt_utf(env, pinned_static_b64, c_pstat);
  release_opt_utf(env, chain_json, c_chain);
  release_opt_utf(env, cur_static_b64, c_cstat);
  release_opt_utf(env, cur_signing_b64, c_csig);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_verify_rotation_chain_json failed");
    return 0;
  }
  return (jlong)final_seq;
}

JNIEXPORT jboolean JNICALL Java_dev_tendril_TendrilNative_verifyGrantJson(
    JNIEnv *env, jclass cls, jstring grant_json, jstring issuer_keys_json,
    jstring expected_subject, jstring expected_root_issuer, jstring requested_cap,
    jlong now_unix, jstring crl_json) {
  (void)cls;
  if (grant_json == NULL || issuer_keys_json == NULL || expected_subject == NULL ||
      expected_root_issuer == NULL || requested_cap == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "required grant inputs must not be null");
    return JNI_FALSE;
  }
  const char *c_grant = get_opt_utf(env, grant_json);
  const char *c_keys = get_opt_utf(env, issuer_keys_json);
  const char *c_subj = get_opt_utf(env, expected_subject);
  const char *c_root = get_opt_utf(env, expected_root_issuer);
  const char *c_cap = get_opt_utf(env, requested_cap);
  const char *c_crl = get_opt_utf(env, crl_json);
  uint8_t allowed = 0;
  int32_t rc = tendril_verify_grant_json(
      c_grant, c_keys, c_subj, c_root, c_cap, (uint64_t)now_unix, c_crl, &allowed);
  release_opt_utf(env, grant_json, c_grant);
  release_opt_utf(env, issuer_keys_json, c_keys);
  release_opt_utf(env, expected_subject, c_subj);
  release_opt_utf(env, expected_root_issuer, c_root);
  release_opt_utf(env, requested_cap, c_cap);
  release_opt_utf(env, crl_json, c_crl);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_verify_grant_json failed");
    return JNI_FALSE;
  }
  return allowed == 1 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_endpointNew(
    JNIEnv *env, jclass cls, jstring state_dir, jstring host_id) {
  (void)cls;
  const char *c_dir = get_opt_utf(env, state_dir);
  const char *c_host = get_opt_utf(env, host_id);
  TendrilEndpoint *ep = tendril_endpoint_new(c_dir, c_host);
  release_opt_utf(env, state_dir, c_dir);
  release_opt_utf(env, host_id, c_host);
  if (ep == NULL) {
    throw_ffi_error(env, TENDRIL_ERR_INTERNAL, "tendril_endpoint_new failed");
    return 0;
  }
  return (jlong)(uintptr_t)ep;
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointFree(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)env;
  (void)cls;
  if (ptr != 0) {
    tendril_endpoint_free((TendrilEndpoint *)(uintptr_t)ptr);
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointInfoJson(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_info_json((TendrilEndpoint *)(uintptr_t)ptr, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_info_json failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointServeDirect(
    JNIEnv *env, jclass cls, jlong ptr, jstring listen_addr) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  const char *c_addr = get_opt_utf(env, listen_addr);
  char *out = NULL;
  int32_t rc = tendril_endpoint_serve_direct((TendrilEndpoint *)(uintptr_t)ptr, c_addr, &out);
  release_opt_utf(env, listen_addr, c_addr);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_serve_direct failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointServeRelay(
    JNIEnv *env, jclass cls, jlong ptr, jstring relay_url, jstring expected_host) {
  (void)cls;
  if (ptr == 0 || relay_url == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid endpoint or relay_url");
    return NULL;
  }
  const char *c_url = get_opt_utf(env, relay_url);
  const char *c_host = get_opt_utf(env, expected_host);
  char *out = NULL;
  int32_t rc = tendril_endpoint_serve_relay((TendrilEndpoint *)(uintptr_t)ptr, c_url, c_host, &out);
  release_opt_utf(env, relay_url, c_url);
  release_opt_utf(env, expected_host, c_host);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_serve_relay failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointIssueCode(
    JNIEnv *env, jclass cls, jlong ptr, jstring kind) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  const char *c_kind = get_opt_utf(env, kind);
  char *out = NULL;
  int32_t rc = tendril_endpoint_issue_code((TendrilEndpoint *)(uintptr_t)ptr, c_kind, &out);
  release_opt_utf(env, kind, c_kind);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_issue_code failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointPairInitiate(
    JNIEnv *env, jclass cls, jlong ptr, jstring endpoint, jstring relay_host,
    jstring code, jstring name, jstring kind) {
  (void)cls;
  if (ptr == 0 || endpoint == NULL || code == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid pair initiate arguments");
    return NULL;
  }
  const char *c_ep = get_opt_utf(env, endpoint);
  const char *c_rh = get_opt_utf(env, relay_host);
  const char *c_code = get_opt_utf(env, code);
  const char *c_name = get_opt_utf(env, name);
  const char *c_kind = get_opt_utf(env, kind);
  char *out = NULL;
  int32_t rc = tendril_endpoint_pair_initiate(
      (TendrilEndpoint *)(uintptr_t)ptr, c_ep, c_rh, c_code, c_name, c_kind, &out);
  release_opt_utf(env, endpoint, c_ep);
  release_opt_utf(env, relay_host, c_rh);
  release_opt_utf(env, code, c_code);
  release_opt_utf(env, name, c_name);
  release_opt_utf(env, kind, c_kind);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_pair_initiate failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointPairAccept(
    JNIEnv *env, jclass cls, jlong ptr, jlong timeout_ms) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_pair_accept(
      (TendrilEndpoint *)(uintptr_t)ptr, (uint64_t)timeout_ms, &out);
  if (rc == TENDRIL_WOULD_BLOCK) {
    return (*env)->NewStringUTF(env, "{\"status\":\"would_block\"}");
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_pair_accept failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointConfirmPeer(
    JNIEnv *env, jclass cls, jlong ptr, jstring peer_id, jstring sas) {
  (void)cls;
  if (ptr == 0 || peer_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid confirm arguments");
    return;
  }
  const char *c_peer = get_opt_utf(env, peer_id);
  const char *c_sas = get_opt_utf(env, sas);
  int32_t rc = tendril_endpoint_confirm_peer((TendrilEndpoint *)(uintptr_t)ptr, c_peer, c_sas);
  release_opt_utf(env, peer_id, c_peer);
  release_opt_utf(env, sas, c_sas);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_confirm_peer failed");
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointMintGrant(
    JNIEnv *env, jclass cls, jlong ptr, jstring peer_id, jstring caps_json, jlong ttl_secs) {
  (void)cls;
  if (ptr == 0 || peer_id == NULL || caps_json == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid mint grant arguments");
    return NULL;
  }
  const char *c_peer = get_opt_utf(env, peer_id);
  const char *c_caps = get_opt_utf(env, caps_json);
  char *out = NULL;
  int32_t rc = tendril_endpoint_mint_grant(
      (TendrilEndpoint *)(uintptr_t)ptr, c_peer, c_caps, (uint64_t)ttl_secs, &out);
  release_opt_utf(env, peer_id, c_peer);
  release_opt_utf(env, caps_json, c_caps);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_mint_grant failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointRevokePeer(
    JNIEnv *env, jclass cls, jlong ptr, jstring peer_id) {
  (void)cls;
  if (ptr == 0 || peer_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid revoke arguments");
    return;
  }
  const char *c_peer = get_opt_utf(env, peer_id);
  int32_t rc = tendril_endpoint_revoke_peer((TendrilEndpoint *)(uintptr_t)ptr, c_peer);
  release_opt_utf(env, peer_id, c_peer);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_revoke_peer failed");
  }
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_sessionConnect(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring endpoint, jstring relay_host,
    jstring target_host_id, jstring grant_json) {
  (void)cls;
  if (ep_ptr == 0 || endpoint == NULL || target_host_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid sessionConnect arguments");
    return 0;
  }
  const char *c_ep = get_opt_utf(env, endpoint);
  const char *c_rh = get_opt_utf(env, relay_host);
  const char *c_target = get_opt_utf(env, target_host_id);
  const char *c_grant = get_opt_utf(env, grant_json);
  TendrilSession *sess = tendril_session_connect(
      (TendrilEndpoint *)(uintptr_t)ep_ptr, c_ep, c_rh, c_target, c_grant);
  release_opt_utf(env, endpoint, c_ep);
  release_opt_utf(env, relay_host, c_rh);
  release_opt_utf(env, target_host_id, c_target);
  release_opt_utf(env, grant_json, c_grant);
  if (sess == NULL) {
    throw_ffi_error(env, TENDRIL_ERR_INTERNAL, "tendril_session_connect failed");
    return 0;
  }
  return (jlong)(uintptr_t)sess;
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_sessionAccept(
    JNIEnv *env, jclass cls, jlong ep_ptr, jlong timeout_ms) {
  (void)cls;
  if (ep_ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return 0;
  }
  TendrilSession *sess = tendril_session_accept(
      (TendrilEndpoint *)(uintptr_t)ep_ptr, (uint64_t)timeout_ms);
  if (sess == NULL) {
    throw_ffi_error(env, TENDRIL_ERR_INTERNAL, "tendril_session_accept failed");
    return 0;
  }
  return (jlong)(uintptr_t)sess;
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_sessionFree(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)env;
  (void)cls;
  if (ptr != 0) {
    tendril_session_free((TendrilSession *)(uintptr_t)ptr);
  }
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_sessionSendData(
    JNIEnv *env, jclass cls, jlong ptr, jbyteArray data) {
  (void)cls;
  if (ptr == 0 || data == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid sessionSendData arguments");
    return;
  }
  jsize len = (*env)->GetArrayLength(env, data);
  jbyte *bytes = len > 0 ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
  int32_t rc = tendril_session_send_data(
      (TendrilSession *)(uintptr_t)ptr, (const uint8_t *)bytes, (size_t)len);
  if (bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_session_send_data failed");
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_sessionPollEvent(
    JNIEnv *env, jclass cls, jlong ptr, jlong timeout_ms) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "session freed");
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_session_poll_event(
      (TendrilSession *)(uintptr_t)ptr, (uint64_t)timeout_ms, &out);
  if (rc == TENDRIL_WOULD_BLOCK) {
    return (*env)->NewStringUTF(env, "{\"status\":\"would_block\"}");
  }
  if (rc == TENDRIL_EOF) {
    return (*env)->NewStringUTF(env, "{\"status\":\"eof\"}");
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_session_poll_event failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jboolean JNICALL Java_dev_tendril_TendrilNative_sessionAuthorize(
    JNIEnv *env, jclass cls, jlong ptr, jstring cap) {
  (void)cls;
  if (ptr == 0 || cap == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid sessionAuthorize arguments");
    return JNI_FALSE;
  }
  const char *c_cap = get_opt_utf(env, cap);
  uint8_t allowed = 0;
  int32_t rc = tendril_session_authorize((TendrilSession *)(uintptr_t)ptr, c_cap, &allowed);
  release_opt_utf(env, cap, c_cap);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_session_authorize failed");
    return JNI_FALSE;
  }
  return allowed == 1 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_sessionRekey(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "session freed");
    return;
  }
  int32_t rc = tendril_session_rekey((TendrilSession *)(uintptr_t)ptr);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_session_rekey failed");
  }
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_sessionClose(
    JNIEnv *env, jclass cls, jlong ptr, jint code, jstring reason) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "session freed");
    return;
  }
  const char *c_reason = get_opt_utf(env, reason);
  int32_t rc = tendril_session_close((TendrilSession *)(uintptr_t)ptr, (uint16_t)code, c_reason);
  release_opt_utf(env, reason, c_reason);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_session_close failed");
  }
}
