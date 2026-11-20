#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tendril.h"

static void throw_ex(JNIEnv *env, const char *class_name, const char *msg) {
  if ((*env)->ExceptionCheck(env)) {
    return;
  }
  jclass cls = (*env)->FindClass(env, class_name);
  if (cls != NULL) {
    (*env)->ThrowNew(env, cls, msg);
  }
}

static void throw_ffi_error(JNIEnv *env, int32_t rc, const char *fallback) {
  if ((*env)->ExceptionCheck(env)) {
    return;
  }
  char errbuf[512];
  errbuf[0] = '\0';
  int32_t needed = tendril_last_error(errbuf, sizeof(errbuf));
  char full[640];
  if (needed > 1) {
    snprintf(full, sizeof(full), "tendril ffi error (%d): %s", (int)rc, errbuf);
  } else {
    snprintf(full, sizeof(full), "%s (code %d)", fallback, (int)rc);
  }
  throw_ex(env, "java/lang/IllegalStateException", full);
}

static int dup_opt_utf8(JNIEnv *env, jstring s, char **out_buf) {
  *out_buf = NULL;
  if (s == NULL) {
    return 1;
  }
  jsize len16 = (*env)->GetStringLength(env, s);
  if (len16 < 0) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid string length");
    return 0;
  }
  const jchar *u16 = len16 > 0 ? (*env)->GetStringChars(env, s, NULL) : NULL;
  if (len16 > 0 && u16 == NULL) {
    throw_ex(env, "java/lang/OutOfMemoryError", "GetStringChars failed");
    return 0;
  }

  size_t byte_len = 0;
  for (jsize i = 0; i < len16; i++) {
    uint16_t c = u16[i];
    if (c < 0x80) {
      byte_len += 1;
    } else if (c < 0x800) {
      byte_len += 2;
    } else if (c >= 0xD800 && c <= 0xDBFF) {
      if (i + 1 >= len16 || u16[i + 1] < 0xDC00 || u16[i + 1] > 0xDFFF) {
        if (u16 != NULL) (*env)->ReleaseStringChars(env, s, u16);
        throw_ex(env, "java/lang/IllegalArgumentException", "unpaired UTF-16 high surrogate");
        return 0;
      }
      i++;
      byte_len += 4;
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      if (u16 != NULL) (*env)->ReleaseStringChars(env, s, u16);
      throw_ex(env, "java/lang/IllegalArgumentException", "unpaired UTF-16 low surrogate");
      return 0;
    } else {
      byte_len += 3;
    }
  }

  char *utf8 = (char *)malloc(byte_len + 1);
  if (utf8 == NULL) {
    if (u16 != NULL) (*env)->ReleaseStringChars(env, s, u16);
    throw_ex(env, "java/lang/OutOfMemoryError", "malloc failed encoding UTF-8");
    return 0;
  }

  size_t w = 0;
  for (jsize i = 0; i < len16; i++) {
    uint32_t c = u16[i];
    if (c < 0x80) {
      utf8[w++] = (char)c;
    } else if (c < 0x800) {
      utf8[w++] = (char)(0xC0 | (c >> 6));
      utf8[w++] = (char)(0x80 | (c & 0x3F));
    } else if (c >= 0xD800 && c <= 0xDBFF) {
      uint32_t lo = u16[++i];
      uint32_t cp = 0x10000 + (((c - 0xD800) << 10) | (lo - 0xDC00));
      utf8[w++] = (char)(0xF0 | (cp >> 18));
      utf8[w++] = (char)(0x80 | ((cp >> 12) & 0x3F));
      utf8[w++] = (char)(0x80 | ((cp >> 6) & 0x3F));
      utf8[w++] = (char)(0x80 | (cp & 0x3F));
    } else {
      utf8[w++] = (char)(0xE0 | (c >> 12));
      utf8[w++] = (char)(0x80 | ((c >> 6) & 0x3F));
      utf8[w++] = (char)(0x80 | (c & 0x3F));
    }
  }
  utf8[w] = '\0';
  if (u16 != NULL) {
    (*env)->ReleaseStringChars(env, s, u16);
  }
  *out_buf = utf8;
  return 1;
}

static jstring utf8_to_jstring(JNIEnv *env, const char *s) {
  if (s == NULL) {
    jchar empty = 0;
    return (*env)->NewString(env, &empty, 0);
  }
  const uint8_t *p = (const uint8_t *)s;
  size_t len16 = 0;
  while (*p != 0) {
    uint8_t b0 = p[0];
    if (b0 < 0x80) {
      p += 1;
      len16 += 1;
    } else if ((b0 & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
      p += 2;
      len16 += 1;
    } else if ((b0 & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
      p += 3;
      len16 += 1;
    } else if ((b0 & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 &&
               (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
      p += 4;
      len16 += 2;
    } else {
      p += 1;
      len16 += 1;
    }
  }
  jchar *u16 = (jchar *)malloc((len16 > 0 ? len16 : 1) * sizeof(jchar));
  if (u16 == NULL) {
    throw_ex(env, "java/lang/OutOfMemoryError", "malloc failed decoding UTF-8");
    return NULL;
  }

  p = (const uint8_t *)s;
  size_t idx = 0;
  while (*p != 0 && idx < len16) {
    uint8_t b0 = p[0];
    if (b0 < 0x80) {
      u16[idx++] = (jchar)b0;
      p += 1;
    } else if ((b0 & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
      uint32_t cp = ((uint32_t)(b0 & 0x1F) << 6) | (uint32_t)(p[1] & 0x3F);
      u16[idx++] = (jchar)cp;
      p += 2;
    } else if ((b0 & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
      uint32_t cp = ((uint32_t)(b0 & 0x0F) << 12) | ((uint32_t)(p[1] & 0x3F) << 6) |
                    (uint32_t)(p[2] & 0x3F);
      u16[idx++] = (jchar)cp;
      p += 3;
    } else if ((b0 & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 &&
               (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
      uint32_t cp = ((uint32_t)(b0 & 0x07) << 18) | ((uint32_t)(p[1] & 0x3F) << 12) |
                    ((uint32_t)(p[2] & 0x3F) << 6) | (uint32_t)(p[3] & 0x3F);
      cp -= 0x10000;
      u16[idx++] = (jchar)(0xD800 + (cp >> 10));
      u16[idx++] = (jchar)(0xDC00 + (cp & 0x3FF));
      p += 4;
    } else {
      u16[idx++] = (jchar)0xFFFD;
      p += 1;
    }
  }
  jstring out = (*env)->NewString(env, u16, (jsize)idx);
  free(u16);
  return out;
}

static jstring take_out_string(JNIEnv *env, char *ptr) {
  if (ptr == NULL) {
    return utf8_to_jstring(env, "");
  }
  jstring out = utf8_to_jstring(env, ptr);
  tendril_string_free(ptr);
  return out;
}

static int read_bytes32(JNIEnv *env, jbyteArray arr, uint8_t out[32]) {
  if (arr == NULL || (*env)->GetArrayLength(env, arr) != 32) {
    throw_ex(env, "java/lang/IllegalArgumentException", "expected 32-byte array");
    return 0;
  }
  (*env)->GetByteArrayRegion(env, arr, 0, 32, (jbyte *)out);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
  return 1;
}

static int require_non_negative_jlong(JNIEnv *env, jlong val, const char *name) {
  if (val < 0) {
    char msg[128];
    snprintf(msg, sizeof(msg), "%s must be non-negative", name);
    throw_ex(env, "java/lang/IllegalArgumentException", msg);
    return 0;
  }
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
  char *c_code = NULL;
  if (!dup_opt_utf8(env, code, &c_code)) {
    return NULL;
  }
  uint8_t mac[32];
  int32_t rc = tendril_compute_code_mac(c_code, hh, mac);
  free(c_code);
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
  if (!require_non_negative_jlong(env, pinned_seq, "pinned_seq")) {
    return 0;
  }
  char *c_psig = NULL;
  char *c_pstat = NULL;
  char *c_chain = NULL;
  char *c_cstat = NULL;
  char *c_csig = NULL;
  uint64_t final_seq = 0;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, pinned_signing_b64, &c_psig) &&
      dup_opt_utf8(env, pinned_static_b64, &c_pstat) &&
      dup_opt_utf8(env, chain_json, &c_chain) &&
      dup_opt_utf8(env, cur_static_b64, &c_cstat) &&
      dup_opt_utf8(env, cur_signing_b64, &c_csig)) {
    rc = tendril_verify_rotation_chain_json(
        c_psig, c_pstat, (uint64_t)pinned_seq, c_chain, c_cstat, c_csig, &final_seq);
  }
  free(c_psig);
  free(c_pstat);
  free(c_chain);
  free(c_cstat);
  free(c_csig);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
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
  if (!require_non_negative_jlong(env, now_unix, "now_unix")) {
    return JNI_FALSE;
  }
  char *c_grant = NULL;
  char *c_keys = NULL;
  char *c_subj = NULL;
  char *c_root = NULL;
  char *c_cap = NULL;
  char *c_crl = NULL;
  uint8_t allowed = 0;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, grant_json, &c_grant) &&
      dup_opt_utf8(env, issuer_keys_json, &c_keys) &&
      dup_opt_utf8(env, expected_subject, &c_subj) &&
      dup_opt_utf8(env, expected_root_issuer, &c_root) &&
      dup_opt_utf8(env, requested_cap, &c_cap) &&
      dup_opt_utf8(env, crl_json, &c_crl)) {
    rc = tendril_verify_grant_json(
        c_grant, c_keys, c_subj, c_root, c_cap, (uint64_t)now_unix, c_crl, &allowed);
  }
  free(c_grant);
  free(c_keys);
  free(c_subj);
  free(c_root);
  free(c_cap);
  free(c_crl);
  if ((*env)->ExceptionCheck(env)) {
    return JNI_FALSE;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_verify_grant_json failed");
    return JNI_FALSE;
  }
  return allowed == 1 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_endpointNew(
    JNIEnv *env, jclass cls, jstring state_dir, jstring host_id) {
  (void)cls;
  char *c_dir = NULL;
  char *c_host = NULL;
  TendrilEndpoint *ep = NULL;
  if (dup_opt_utf8(env, state_dir, &c_dir) && dup_opt_utf8(env, host_id, &c_host)) {
    ep = tendril_endpoint_new(c_dir, c_host);
  }
  free(c_dir);
  free(c_host);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
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
  char *c_addr = NULL;
  if (!dup_opt_utf8(env, listen_addr, &c_addr)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_serve_direct((TendrilEndpoint *)(uintptr_t)ptr, c_addr, &out);
  free(c_addr);
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
  char *c_url = NULL;
  char *c_host = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, relay_url, &c_url) && dup_opt_utf8(env, expected_host, &c_host)) {
    rc = tendril_endpoint_serve_relay((TendrilEndpoint *)(uintptr_t)ptr, c_url, c_host, &out);
  }
  free(c_url);
  free(c_host);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
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
  char *c_kind = NULL;
  if (!dup_opt_utf8(env, kind, &c_kind)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_issue_code((TendrilEndpoint *)(uintptr_t)ptr, c_kind, &out);
  free(c_kind);
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
  char *c_ep = NULL;
  char *c_rh = NULL;
  char *c_code = NULL;
  char *c_name = NULL;
  char *c_kind = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, endpoint, &c_ep) &&
      dup_opt_utf8(env, relay_host, &c_rh) &&
      dup_opt_utf8(env, code, &c_code) &&
      dup_opt_utf8(env, name, &c_name) &&
      dup_opt_utf8(env, kind, &c_kind)) {
    rc = tendril_endpoint_pair_initiate(
        (TendrilEndpoint *)(uintptr_t)ptr, c_ep, c_rh, c_code, c_name, c_kind, &out);
  }
  free(c_ep);
  free(c_rh);
  free(c_code);
  free(c_name);
  free(c_kind);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
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
  if (!require_non_negative_jlong(env, timeout_ms, "timeout_ms")) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_pair_accept(
      (TendrilEndpoint *)(uintptr_t)ptr, (uint64_t)timeout_ms, &out);
  if (rc == TENDRIL_WOULD_BLOCK) {
    return utf8_to_jstring(env, "{\"status\":\"would_block\"}");
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
  char *c_peer = NULL;
  char *c_sas = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, peer_id, &c_peer) && dup_opt_utf8(env, sas, &c_sas)) {
    rc = tendril_endpoint_confirm_peer((TendrilEndpoint *)(uintptr_t)ptr, c_peer, c_sas);
  }
  free(c_peer);
  free(c_sas);
  if ((*env)->ExceptionCheck(env)) {
    return;
  }
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
  if (!require_non_negative_jlong(env, ttl_secs, "ttl_secs")) {
    return NULL;
  }
  char *c_peer = NULL;
  char *c_caps = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, peer_id, &c_peer) && dup_opt_utf8(env, caps_json, &c_caps)) {
    rc = tendril_endpoint_mint_grant(
        (TendrilEndpoint *)(uintptr_t)ptr, c_peer, c_caps, (uint64_t)ttl_secs, &out);
  }
  free(c_peer);
  free(c_caps);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
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
  char *c_peer = NULL;
  if (!dup_opt_utf8(env, peer_id, &c_peer)) {
    return;
  }
  int32_t rc = tendril_endpoint_revoke_peer((TendrilEndpoint *)(uintptr_t)ptr, c_peer);
  free(c_peer);
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
  char *c_ep = NULL;
  char *c_rh = NULL;
  char *c_target = NULL;
  char *c_grant = NULL;
  TendrilSession *sess = NULL;
  if (dup_opt_utf8(env, endpoint, &c_ep) &&
      dup_opt_utf8(env, relay_host, &c_rh) &&
      dup_opt_utf8(env, target_host_id, &c_target) &&
      dup_opt_utf8(env, grant_json, &c_grant)) {
    sess = tendril_session_connect(
        (TendrilEndpoint *)(uintptr_t)ep_ptr, c_ep, c_rh, c_target, c_grant);
  }
  free(c_ep);
  free(c_rh);
  free(c_target);
  free(c_grant);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
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
  if (!require_non_negative_jlong(env, timeout_ms, "timeout_ms")) {
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
  if (len > 0 && bytes == NULL) {
    throw_ex(env, "java/lang/OutOfMemoryError", "GetByteArrayElements failed");
    return;
  }
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
  if (!require_non_negative_jlong(env, timeout_ms, "timeout_ms")) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_session_poll_event(
      (TendrilSession *)(uintptr_t)ptr, (uint64_t)timeout_ms, &out);
  if (rc == TENDRIL_WOULD_BLOCK) {
    return utf8_to_jstring(env, "{\"status\":\"would_block\"}");
  }
  if (rc == TENDRIL_EOF) {
    return utf8_to_jstring(env, "{\"status\":\"eof\"}");
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
  char *c_cap = NULL;
  if (!dup_opt_utf8(env, cap, &c_cap)) {
    return JNI_FALSE;
  }
  uint8_t allowed = 0;
  int32_t rc = tendril_session_authorize((TendrilSession *)(uintptr_t)ptr, c_cap, &allowed);
  free(c_cap);
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
  if (code < 0 || code > 65535) {
    throw_ex(env, "java/lang/IllegalArgumentException", "close code must be 0..=65535");
    return;
  }
  char *c_reason = NULL;
  if (!dup_opt_utf8(env, reason, &c_reason)) {
    return;
  }
  int32_t rc = tendril_session_close((TendrilSession *)(uintptr_t)ptr, (uint16_t)code, c_reason);
  free(c_reason);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_session_close failed");
  }
}
