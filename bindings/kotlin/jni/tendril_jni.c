#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tendril.h"

static void zeroize_cstr_free(char *p) {
  if (p == NULL) {
    return;
  }
  volatile unsigned char *vp = (volatile unsigned char *)p;
  while (*vp != 0) {
    *vp++ = 0;
  }
  free(p);
}

static void zeroize_bytes(void *p, size_t len) {
  if (p == NULL || len == 0) {
    return;
  }
  volatile unsigned char *vp = (volatile unsigned char *)p;
  for (size_t i = 0; i < len; i++) {
    vp[i] = 0;
  }
}

static void zeroize_bytes_free(void *p, size_t len) {
  if (p == NULL) {
    return;
  }
  zeroize_bytes(p, len);
  free(p);
}

static jstring utf8_to_jstring(JNIEnv *env, const char *s);

static void throw_ex(JNIEnv *env, const char *class_name, const char *msg) {
  if ((*env)->ExceptionCheck(env)) {
    return;
  }
  jclass cls = (*env)->FindClass(env, class_name);
  if (cls == NULL) {
    return;
  }
  jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(Ljava/lang/String;)V");
  jstring jmsg = ctor != NULL ? utf8_to_jstring(env, msg) : NULL;
  jthrowable ex = NULL;
  if (jmsg != NULL && !(*env)->ExceptionCheck(env)) {
    ex = (jthrowable)(*env)->NewObject(env, cls, ctor, jmsg);
  }
  if (jmsg != NULL) {
    (*env)->DeleteLocalRef(env, jmsg);
  }
  if (ex != NULL && !(*env)->ExceptionCheck(env)) {
    (*env)->Throw(env, ex);
    (*env)->DeleteLocalRef(env, ex);
  } else {
    if ((*env)->ExceptionCheck(env)) {
      (*env)->ExceptionClear(env);
    }
    (*env)->ThrowNew(env, cls, msg != NULL ? msg : "");
  }
  (*env)->DeleteLocalRef(env, cls);
}

static void throw_ffi_error(JNIEnv *env, int32_t rc, const char *fallback) {
  if ((*env)->ExceptionCheck(env)) {
    return;
  }
  char errbuf[512];
  errbuf[0] = '\0';
  int32_t needed = tendril_last_error(errbuf, sizeof(errbuf));
  const char *err_msg = errbuf;
  char *dyn_err = NULL;
  if (needed > (int32_t)sizeof(errbuf)) {
    dyn_err = (char *)malloc((size_t)needed);
    if (dyn_err != NULL) {
      dyn_err[0] = '\0';
      tendril_last_error(dyn_err, (size_t)needed);
      err_msg = dyn_err;
    }
  }
  if (needed > 1) {
    size_t full_cap = strlen(err_msg) + 48;
    char *full = (char *)malloc(full_cap);
    if (full != NULL) {
      snprintf(full, full_cap, "tendril ffi error (%d): %s", (int)rc, err_msg);
      throw_ex(env, "java/lang/IllegalStateException", full);
      free(full);
    } else {
      throw_ex(env, "java/lang/IllegalStateException", err_msg);
    }
  } else {
    char full[128];
    snprintf(full, sizeof(full), "%s (code %d)", fallback, (int)rc);
    throw_ex(env, "java/lang/IllegalStateException", full);
  }
  free(dyn_err);
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
    if (c == 0) {
      if (u16 != NULL) (*env)->ReleaseStringChars(env, s, u16);
      throw_ex(env, "java/lang/IllegalArgumentException", "string contains interior NUL byte");
      return 0;
    } else if (c < 0x80) {
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
  size_t u16_bytes = (len16 > 0 ? len16 : 1) * sizeof(jchar);
  jchar *u16 = (jchar *)malloc(u16_bytes);
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
  zeroize_bytes_free(u16, u16_bytes);
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

static int read_hybrid_signing_pub(JNIEnv *env, jbyteArray arr, uint8_t out[TENDRIL_SIGNING_PUB_LEN]) {
  if (arr == NULL || (*env)->GetArrayLength(env, arr) != TENDRIL_SIGNING_PUB_LEN) {
    throw_ex(env, "java/lang/IllegalArgumentException", "expected 1984-byte hybrid signing key");
    return 0;
  }
  (*env)->GetByteArrayRegion(env, arr, 0, TENDRIL_SIGNING_PUB_LEN, (jbyte *)out);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
  return 1;
}

static int read_signing_pin(JNIEnv *env, jbyteArray arr, uint8_t out[TENDRIL_SIGNING_PUB_LEN], size_t *out_len) {
  if (arr == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "expected 1984-byte or 32-byte signing pin");
    return 0;
  }
  jsize len = (*env)->GetArrayLength(env, arr);
  if (len != TENDRIL_SIGNING_PUB_LEN && len != TENDRIL_SIGNING_HASH_LEN) {
    throw_ex(env, "java/lang/IllegalArgumentException", "expected 1984-byte or 32-byte signing pin");
    return 0;
  }
  (*env)->GetByteArrayRegion(env, arr, 0, len, (jbyte *)out);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
  *out_len = (size_t)len;
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
  zeroize_cstr_free(c_code);
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
  zeroize_cstr_free(c_grant);
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

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_endpointNewFromState(
    JNIEnv *env, jclass cls, jstring identity_json, jstring roster_json, jstring host_id) {
  (void)cls;
  char *c_id = NULL;
  char *c_roster = NULL;
  char *c_host = NULL;
  TendrilEndpoint *ep = NULL;
  if (dup_opt_utf8(env, identity_json, &c_id) &&
      dup_opt_utf8(env, roster_json, &c_roster) &&
      dup_opt_utf8(env, host_id, &c_host)) {
    ep = tendril_endpoint_new_from_state(c_id, c_roster, c_host);
  }
  zeroize_cstr_free(c_id);
  zeroize_cstr_free(c_roster);
  free(c_host);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
  if (ep == NULL) {
    throw_ffi_error(env, TENDRIL_ERR_INTERNAL, "tendril_endpoint_new_from_state failed");
    return 0;
  }
  return (jlong)(uintptr_t)ep;
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_endpointNewSealed(
    JNIEnv *env, jclass cls, jstring state_dir, jstring identity_json, jstring roster_json,
    jstring host_id) {
  (void)cls;
  char *c_dir = NULL;
  char *c_id = NULL;
  char *c_roster = NULL;
  char *c_host = NULL;
  TendrilEndpoint *ep = NULL;
  if (dup_opt_utf8(env, state_dir, &c_dir) &&
      dup_opt_utf8(env, identity_json, &c_id) &&
      dup_opt_utf8(env, roster_json, &c_roster) &&
      dup_opt_utf8(env, host_id, &c_host)) {
    ep = tendril_endpoint_new_sealed(c_dir, c_id, c_roster, c_host);
  }
  free(c_dir);
  zeroize_cstr_free(c_id);
  zeroize_cstr_free(c_roster);
  free(c_host);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
  if (ep == NULL) {
    throw_ffi_error(env, TENDRIL_ERR_INTERNAL, "tendril_endpoint_new_sealed failed");
    return 0;
  }
  return (jlong)(uintptr_t)ep;
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointClose(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)env;
  (void)cls;
  if (ptr != 0) {
    tendril_endpoint_close((TendrilEndpoint *)(uintptr_t)ptr);
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointExportIdentityJson(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_export_identity_json((TendrilEndpoint *)(uintptr_t)ptr, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_export_identity_json failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointExportRosterJson(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_export_roster_json((TendrilEndpoint *)(uintptr_t)ptr, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_export_roster_json failed");
    return NULL;
  }
  return take_out_string(env, out);
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

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointConfigureTransportsJson(
    JNIEnv *env, jclass cls, jlong ptr, jstring transport_config_json) {
  (void)cls;
  if (ptr == 0 || transport_config_json == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid endpoint or transport_config_json");
    return;
  }
  char *c_cfg = NULL;
  if (!dup_opt_utf8(env, transport_config_json, &c_cfg)) {
    return;
  }
  int32_t rc = tendril_endpoint_configure_transports_json(
      (TendrilEndpoint *)(uintptr_t)ptr, c_cfg);
  zeroize_cstr_free(c_cfg);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_configure_transports_json failed");
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointMintRelayTicket(
    JNIEnv *env, jclass cls, jlong ptr, jstring relay_host, jstring role,
    jstring target_pub_or_wildcard, jlong ttl_secs) {
  (void)cls;
  if (ptr == 0 || relay_host == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid endpoint or relay_host");
    return NULL;
  }
  if (!require_non_negative_jlong(env, ttl_secs, "ttl_secs")) {
    return NULL;
  }
  char *c_host = NULL;
  char *c_role = NULL;
  char *c_target = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, relay_host, &c_host) &&
      dup_opt_utf8(env, role, &c_role) &&
      dup_opt_utf8(env, target_pub_or_wildcard, &c_target)) {
    rc = tendril_endpoint_mint_relay_ticket(
        (TendrilEndpoint *)(uintptr_t)ptr, c_host, c_role, c_target, (uint64_t)ttl_secs, &out);
  }
  free(c_host);
  free(c_role);
  free(c_target);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_mint_relay_ticket failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointServeRelayV2(
    JNIEnv *env, jclass cls, jlong ptr, jstring relay_url, jstring expected_host,
    jstring peer_id_opt) {
  (void)cls;
  if (ptr == 0 || relay_url == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid endpoint or relay_url");
    return NULL;
  }
  char *c_url = NULL;
  char *c_host = NULL;
  char *c_peer = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, relay_url, &c_url) &&
      dup_opt_utf8(env, expected_host, &c_host) &&
      dup_opt_utf8(env, peer_id_opt, &c_peer)) {
    rc = tendril_endpoint_serve_relay_v2(
        (TendrilEndpoint *)(uintptr_t)ptr, c_url, c_host, c_peer, &out);
  }
  free(c_url);
  free(c_host);
  free(c_peer);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_serve_relay_v2 failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointServeP2p(
    JNIEnv *env, jclass cls, jlong ptr, jstring relay_mode) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  char *c_mode = NULL;
  if (!dup_opt_utf8(env, relay_mode, &c_mode)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_serve_p2p((TendrilEndpoint *)(uintptr_t)ptr, c_mode, &out);
  free(c_mode);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_serve_p2p failed");
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
  zeroize_cstr_free(c_code);
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

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointPairV2Initiate(
    JNIEnv *env, jclass cls, jlong ptr, jstring endpoint, jstring relay_host,
    jstring code, jstring name, jstring kind, jstring pinned_host_json) {
  (void)cls;
  if (ptr == 0 || endpoint == NULL || code == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid pair v2 initiate arguments");
    return NULL;
  }
  char *c_ep = NULL;
  char *c_rh = NULL;
  char *c_code = NULL;
  char *c_name = NULL;
  char *c_kind = NULL;
  char *c_pinned = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, endpoint, &c_ep) &&
      dup_opt_utf8(env, relay_host, &c_rh) &&
      dup_opt_utf8(env, code, &c_code) &&
      dup_opt_utf8(env, name, &c_name) &&
      dup_opt_utf8(env, kind, &c_kind) &&
      dup_opt_utf8(env, pinned_host_json, &c_pinned)) {
    rc = tendril_endpoint_pair_v2_initiate(
        (TendrilEndpoint *)(uintptr_t)ptr, c_ep, c_rh, c_code, c_name, c_kind, c_pinned, &out);
  }
  free(c_ep);
  free(c_rh);
  zeroize_cstr_free(c_code);
  free(c_name);
  free(c_kind);
  free(c_pinned);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_pair_v2_initiate failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointPairV2Accept(
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
  int32_t rc = tendril_endpoint_pair_v2_accept(
      (TendrilEndpoint *)(uintptr_t)ptr, (uint64_t)timeout_ms, &out);
  if (rc == TENDRIL_WOULD_BLOCK) {
    return utf8_to_jstring(env, "{\"status\":\"would_block\"}");
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_pair_v2_accept failed");
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
  zeroize_cstr_free(c_sas);
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
  zeroize_cstr_free(c_caps);
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

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointAddTrustAnchor(
    JNIEnv *env, jclass cls, jlong ptr, jstring anchor_id, jbyteArray signing_pub) {
  (void)cls;
  if (ptr == 0 || anchor_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid trust anchor arguments");
    return;
  }
  uint8_t key[TENDRIL_SIGNING_PUB_LEN];
  if (!read_hybrid_signing_pub(env, signing_pub, key)) {
    return;
  }
  char *c_anchor = NULL;
  if (!dup_opt_utf8(env, anchor_id, &c_anchor)) {
    return;
  }
  int32_t rc = tendril_endpoint_add_trust_anchor(
      (TendrilEndpoint *)(uintptr_t)ptr, c_anchor, key, (size_t)TENDRIL_SIGNING_PUB_LEN);
  free(c_anchor);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_add_trust_anchor failed");
  }
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointRevokeTrustAnchor(
    JNIEnv *env, jclass cls, jlong ptr, jstring anchor_id) {
  (void)cls;
  if (ptr == 0 || anchor_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid revoke trust anchor arguments");
    return;
  }
  char *c_anchor = NULL;
  if (!dup_opt_utf8(env, anchor_id, &c_anchor)) {
    return;
  }
  int32_t rc = tendril_endpoint_revoke_trust_anchor(
      (TendrilEndpoint *)(uintptr_t)ptr, c_anchor);
  free(c_anchor);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_revoke_trust_anchor failed");
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointMintEnrollmentToken(
    JNIEnv *env, jclass cls, jlong ptr, jstring target_host_id, jstring subject, jlong ttl_secs) {
  (void)cls;
  if (ptr == 0 || target_host_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid mint enrollment token arguments");
    return NULL;
  }
  if (!require_non_negative_jlong(env, ttl_secs, "ttl_secs")) {
    return NULL;
  }
  char *c_target = NULL;
  char *c_subject = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, target_host_id, &c_target) &&
      dup_opt_utf8(env, subject, &c_subject)) {
    rc = tendril_endpoint_mint_enrollment_token(
        (TendrilEndpoint *)(uintptr_t)ptr, c_target, c_subject, (uint64_t)ttl_secs, &out);
  }
  free(c_target);
  free(c_subject);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_mint_enrollment_token failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointEnrollInitiate(
    JNIEnv *env, jclass cls, jlong ptr, jstring endpoint, jstring relay_host,
    jstring host_id, jbyteArray host_static_pub, jbyteArray host_signing_pub,
    jlong host_rotation_seq, jstring token_json, jstring name, jstring kind) {
  (void)cls;
  if (ptr == 0 || endpoint == NULL || host_id == NULL || token_json == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid enroll initiate arguments");
    return NULL;
  }
  if (!require_non_negative_jlong(env, host_rotation_seq, "host_rotation_seq")) {
    return NULL;
  }
  uint8_t static_pub[TENDRIL_KEY_LEN];
  uint8_t signing_pin[TENDRIL_SIGNING_PUB_LEN];
  size_t signing_pin_len = 0;
  if (!read_bytes32(env, host_static_pub, static_pub) ||
      !read_signing_pin(env, host_signing_pub, signing_pin, &signing_pin_len)) {
    return NULL;
  }
  char *c_ep = NULL;
  char *c_rh = NULL;
  char *c_host = NULL;
  char *c_token = NULL;
  char *c_name = NULL;
  char *c_kind = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, endpoint, &c_ep) &&
      dup_opt_utf8(env, relay_host, &c_rh) &&
      dup_opt_utf8(env, host_id, &c_host) &&
      dup_opt_utf8(env, token_json, &c_token) &&
      dup_opt_utf8(env, name, &c_name) &&
      dup_opt_utf8(env, kind, &c_kind)) {
    rc = tendril_endpoint_enroll_initiate(
        (TendrilEndpoint *)(uintptr_t)ptr,
        c_ep,
        c_rh,
        c_host,
        static_pub,
        signing_pin,
        signing_pin_len,
        (uint64_t)host_rotation_seq,
        c_token,
        c_name,
        c_kind,
        &out);
  }
  free(c_ep);
  free(c_rh);
  free(c_host);
  zeroize_cstr_free(c_token);
  free(c_name);
  free(c_kind);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_enroll_initiate failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointIssuePairingUri(
    JNIEnv *env, jclass cls, jlong ptr, jstring options_json) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  char *c_opts = NULL;
  if (!dup_opt_utf8(env, options_json, &c_opts)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_issue_pairing_uri((TendrilEndpoint *)(uintptr_t)ptr, c_opts, &out);
  free(c_opts);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_issue_pairing_uri failed");
    return NULL;
  }
  return take_out_string(env, out);
}

typedef int32_t (*pair_uri_fn)(
    TendrilEndpoint *, const char *, const char *, const char *, const char *, char **);

static jstring pair_uri_common(
    JNIEnv *env, jlong ptr, jstring pairing_uri, jstring name, jstring kind, jstring options_json,
    pair_uri_fn fn, const char *what) {
  if (ptr == 0 || pairing_uri == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid pairing uri arguments");
    return NULL;
  }
  char *c_uri = NULL;
  char *c_name = NULL;
  char *c_kind = NULL;
  char *c_opts = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, pairing_uri, &c_uri) &&
      dup_opt_utf8(env, name, &c_name) &&
      dup_opt_utf8(env, kind, &c_kind) &&
      dup_opt_utf8(env, options_json, &c_opts)) {
    rc = fn((TendrilEndpoint *)(uintptr_t)ptr, c_uri, c_name, c_kind, c_opts, &out);
  }
  zeroize_cstr_free(c_uri);
  free(c_name);
  free(c_kind);
  zeroize_cstr_free(c_opts);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, what);
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointPairUri(
    JNIEnv *env, jclass cls, jlong ptr, jstring pairing_uri, jstring name, jstring kind,
    jstring options_json) {
  (void)cls;
  return pair_uri_common(
      env, ptr, pairing_uri, name, kind, options_json, tendril_endpoint_pair_uri,
      "tendril_endpoint_pair_uri failed");
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointPairV2Uri(
    JNIEnv *env, jclass cls, jlong ptr, jstring pairing_uri, jstring name, jstring kind,
    jstring options_json) {
  (void)cls;
  return pair_uri_common(
      env, ptr, pairing_uri, name, kind, options_json, tendril_endpoint_pair_v2_uri,
      "tendril_endpoint_pair_v2_uri failed");
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointSetPeerRoutes(
    JNIEnv *env, jclass cls, jlong ptr, jstring peer_id, jstring routes_json) {
  (void)cls;
  if (ptr == 0 || peer_id == NULL || routes_json == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid setPeerRoutes arguments");
    return;
  }
  char *c_peer = NULL;
  char *c_routes = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, peer_id, &c_peer) && dup_opt_utf8(env, routes_json, &c_routes)) {
    rc = tendril_endpoint_set_peer_routes((TendrilEndpoint *)(uintptr_t)ptr, c_peer, c_routes);
  }
  free(c_peer);
  free(c_routes);
  if ((*env)->ExceptionCheck(env)) {
    return;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_set_peer_routes failed");
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointPeerRoutes(
    JNIEnv *env, jclass cls, jlong ptr, jstring peer_id) {
  (void)cls;
  if (ptr == 0 || peer_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid peerRoutes arguments");
    return NULL;
  }
  char *c_peer = NULL;
  if (!dup_opt_utf8(env, peer_id, &c_peer)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_peer_routes((TendrilEndpoint *)(uintptr_t)ptr, c_peer, &out);
  free(c_peer);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_peer_routes failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_endpointClearPeerRoutes(
    JNIEnv *env, jclass cls, jlong ptr, jstring peer_id, jstring source) {
  (void)cls;
  if (ptr == 0 || peer_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid clearPeerRoutes arguments");
    return;
  }
  char *c_peer = NULL;
  char *c_source = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, peer_id, &c_peer) && dup_opt_utf8(env, source, &c_source)) {
    rc = tendril_endpoint_clear_peer_routes((TendrilEndpoint *)(uintptr_t)ptr, c_peer, c_source);
  }
  free(c_peer);
  free(c_source);
  if ((*env)->ExceptionCheck(env)) {
    return;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_clear_peer_routes failed");
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointApplyRouteUri(
    JNIEnv *env, jclass cls, jlong ptr, jstring pairing_uri, jstring options_json) {
  (void)cls;
  if (ptr == 0 || pairing_uri == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid applyRouteUri arguments");
    return NULL;
  }
  char *c_uri = NULL;
  char *c_opts = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, pairing_uri, &c_uri) && dup_opt_utf8(env, options_json, &c_opts)) {
    rc = tendril_endpoint_apply_route_uri((TendrilEndpoint *)(uintptr_t)ptr, c_uri, c_opts, &out);
  }
  zeroize_cstr_free(c_uri);
  free(c_opts);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_apply_route_uri failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_endpointRefreshRoutes(
    JNIEnv *env, jclass cls, jlong ptr, jstring snapshot_json) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return NULL;
  }
  char *c_snap = NULL;
  if (!dup_opt_utf8(env, snapshot_json, &c_snap)) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_endpoint_refresh_routes((TendrilEndpoint *)(uintptr_t)ptr, c_snap, &out);
  free(c_snap);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_endpoint_refresh_routes failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_sessionConnectWithOptions(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring target_host_id, jstring options_json) {
  (void)cls;
  if (ep_ptr == 0 || target_host_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid sessionConnectWithOptions arguments");
    return 0;
  }
  char *c_target = NULL;
  char *c_opts = NULL;
  TendrilSession *sess = NULL;
  if (dup_opt_utf8(env, target_host_id, &c_target) && dup_opt_utf8(env, options_json, &c_opts)) {
    sess = tendril_session_connect_with_options(
        (TendrilEndpoint *)(uintptr_t)ep_ptr, c_target, c_opts);
  }
  free(c_target);
  zeroize_cstr_free(c_opts);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
  if (sess == NULL) {
    throw_ffi_error(env, TENDRIL_ERR_INTERNAL, "tendril_session_connect_with_options failed");
    return 0;
  }
  return (jlong)(uintptr_t)sess;
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_sessionConnect(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring endpoint, jstring relay_host,
    jstring target_host_id, jstring grant_json) {
  (void)cls;
  if (ep_ptr == 0 || target_host_id == NULL) {
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
  zeroize_cstr_free(c_grant);
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

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_sessionConnectV2(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring endpoint, jstring relay_host,
    jstring target_host_id, jstring grant_json) {
  (void)cls;
  if (ep_ptr == 0 || target_host_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid sessionConnectV2 arguments");
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
    sess = tendril_session_connect_v2(
        (TendrilEndpoint *)(uintptr_t)ep_ptr, c_ep, c_rh, c_target, c_grant);
  }
  free(c_ep);
  free(c_rh);
  free(c_target);
  zeroize_cstr_free(c_grant);
  if ((*env)->ExceptionCheck(env)) {
    return 0;
  }
  if (sess == NULL) {
    throw_ffi_error(env, TENDRIL_ERR_INTERNAL, "tendril_session_connect_v2 failed");
    return 0;
  }
  return (jlong)(uintptr_t)sess;
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_sessionAcceptV2(
    JNIEnv *env, jclass cls, jlong ep_ptr, jlong timeout_ms) {
  (void)cls;
  if (ep_ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "endpoint closed");
    return 0;
  }
  if (!require_non_negative_jlong(env, timeout_ms, "timeout_ms")) {
    return 0;
  }
  TendrilSession *sess = tendril_session_accept_v2(
      (TendrilEndpoint *)(uintptr_t)ep_ptr, (uint64_t)timeout_ms);
  if (sess == NULL) {
    throw_ffi_error(env, TENDRIL_ERR_INTERNAL, "tendril_session_accept_v2 failed");
    return 0;
  }
  return (jlong)(uintptr_t)sess;
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_sessionShutdown(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)env;
  (void)cls;
  if (ptr != 0) {
    tendril_session_shutdown((TendrilSession *)(uintptr_t)ptr);
  }
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_sessionExportRosterJson(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "session freed");
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_session_export_roster_json((TendrilSession *)(uintptr_t)ptr, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_session_export_roster_json failed");
    return NULL;
  }
  return take_out_string(env, out);
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
  if (len < 0) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid data length");
    return;
  }
  uint8_t stack_buf[4096];
  uint8_t *heap_buf = NULL;
  uint8_t *buf = stack_buf;
  if (len > (jsize)sizeof(stack_buf)) {
    heap_buf = (uint8_t *)malloc((size_t)len);
    if (heap_buf == NULL) {
      throw_ex(env, "java/lang/OutOfMemoryError", "malloc failed");
      return;
    }
    buf = heap_buf;
  }
  if (len > 0) {
    (*env)->GetByteArrayRegion(env, data, 0, len, (jbyte *)buf);
    if ((*env)->ExceptionCheck(env)) {
      zeroize_bytes(buf, (size_t)len);
      free(heap_buf);
      return;
    }
  }
  int32_t rc = tendril_session_send_data(
      (TendrilSession *)(uintptr_t)ptr, len > 0 ? buf : NULL, (size_t)len);
  if (len > 0) {
    zeroize_bytes(buf, (size_t)len);
  }
  free(heap_buf);
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

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_groupCreate(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring name, jint min_wire_version,
    jstring endpoints_json) {
  (void)cls;
  if (ep_ptr == 0 || name == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid groupCreate arguments");
    return NULL;
  }
  if (min_wire_version < 0 || min_wire_version > 255) {
    throw_ex(env, "java/lang/IllegalArgumentException", "min_wire_version must be 0..=255");
    return NULL;
  }
  char *c_name = NULL;
  char *c_endpoints = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, name, &c_name) && dup_opt_utf8(env, endpoints_json, &c_endpoints)) {
    rc = tendril_group_create(
        (TendrilEndpoint *)(uintptr_t)ep_ptr, c_name, (uint8_t)min_wire_version, c_endpoints, &out);
  }
  free(c_name);
  free(c_endpoints);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_create failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_groupAddMember(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring group_id, jstring peer_id, jstring caps_json,
    jstring endpoints_json) {
  (void)cls;
  if (ep_ptr == 0 || group_id == NULL || peer_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid groupAddMember arguments");
    return NULL;
  }
  char *c_gid = NULL;
  char *c_peer = NULL;
  char *c_caps = NULL;
  char *c_endpoints = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, group_id, &c_gid) && dup_opt_utf8(env, peer_id, &c_peer) &&
      dup_opt_utf8(env, caps_json, &c_caps) && dup_opt_utf8(env, endpoints_json, &c_endpoints)) {
    rc = tendril_group_add_member(
        (TendrilEndpoint *)(uintptr_t)ep_ptr, c_gid, c_peer, c_caps, c_endpoints, &out);
  }
  free(c_gid);
  free(c_peer);
  free(c_caps);
  free(c_endpoints);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_add_member failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_groupRemoveMember(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring group_id, jstring peer_id) {
  (void)cls;
  if (ep_ptr == 0 || group_id == NULL || peer_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid groupRemoveMember arguments");
    return NULL;
  }
  char *c_gid = NULL;
  char *c_peer = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, group_id, &c_gid) && dup_opt_utf8(env, peer_id, &c_peer)) {
    rc = tendril_group_remove_member((TendrilEndpoint *)(uintptr_t)ep_ptr, c_gid, c_peer, &out);
  }
  free(c_gid);
  free(c_peer);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_remove_member failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_groupIngestManifest(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring manifest_json, jstring sender_peer_id) {
  (void)cls;
  if (ep_ptr == 0 || manifest_json == NULL || sender_peer_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid groupIngestManifest arguments");
    return NULL;
  }
  char *c_manifest = NULL;
  char *c_sender = NULL;
  char *out = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, manifest_json, &c_manifest) &&
      dup_opt_utf8(env, sender_peer_id, &c_sender)) {
    rc = tendril_group_ingest_manifest(
        (TendrilEndpoint *)(uintptr_t)ep_ptr, c_manifest, c_sender, &out);
  }
  free(c_manifest);
  free(c_sender);
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_ingest_manifest failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jlong JNICALL Java_dev_tendril_TendrilNative_groupOpen(
    JNIEnv *env, jclass cls, jlong ep_ptr, jstring group_id, jstring listen_addr) {
  (void)cls;
  if (ep_ptr == 0 || group_id == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid groupOpen arguments");
    return 0;
  }
  char *c_gid = NULL;
  char *c_listen = NULL;
  TendrilGroup *group = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, group_id, &c_gid) && dup_opt_utf8(env, listen_addr, &c_listen)) {
    rc = tendril_group_open((TendrilEndpoint *)(uintptr_t)ep_ptr, c_gid, c_listen, &group);
  }
  free(c_gid);
  free(c_listen);
  if ((*env)->ExceptionCheck(env)) {
    if (group != NULL) {
      tendril_group_free(group);
    }
    return 0;
  }
  if (rc != TENDRIL_OK || group == NULL) {
    throw_ffi_error(env, rc, "tendril_group_open failed");
    return 0;
  }
  return (jlong)(uintptr_t)group;
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_groupLocalEndpoint(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "group closed");
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_group_local_endpoint((TendrilGroup *)(uintptr_t)ptr, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_local_endpoint failed");
    return NULL;
  }
  if (out == NULL) {
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_groupSync(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "group closed");
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_group_sync((TendrilGroup *)(uintptr_t)ptr, &out);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_sync failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_groupBroadcast(
    JNIEnv *env, jclass cls, jlong ptr, jstring required_cap, jbyteArray data) {
  (void)cls;
  if (ptr == 0 || data == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid groupBroadcast arguments");
    return NULL;
  }
  jsize len = (*env)->GetArrayLength(env, data);
  if (len < 0) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid data length");
    return NULL;
  }
  char *c_cap = NULL;
  if (!dup_opt_utf8(env, required_cap, &c_cap)) {
    return NULL;
  }
  uint8_t stack_buf[4096];
  uint8_t *heap_buf = NULL;
  uint8_t *buf = stack_buf;
  if (len > (jsize)sizeof(stack_buf)) {
    heap_buf = (uint8_t *)malloc((size_t)len);
    if (heap_buf == NULL) {
      free(c_cap);
      throw_ex(env, "java/lang/OutOfMemoryError", "malloc failed");
      return NULL;
    }
    buf = heap_buf;
  }
  if (len > 0) {
    (*env)->GetByteArrayRegion(env, data, 0, len, (jbyte *)buf);
    if ((*env)->ExceptionCheck(env)) {
      zeroize_bytes(buf, (size_t)len);
      free(heap_buf);
      free(c_cap);
      return NULL;
    }
  }
  char *out = NULL;
  int32_t rc = tendril_group_broadcast(
      (TendrilGroup *)(uintptr_t)ptr, c_cap, len > 0 ? buf : NULL, (size_t)len, &out);
  if (len > 0) {
    zeroize_bytes(buf, (size_t)len);
  }
  free(heap_buf);
  free(c_cap);
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_broadcast failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT jstring JNICALL Java_dev_tendril_TendrilNative_groupPollEvent(
    JNIEnv *env, jclass cls, jlong ptr, jlong timeout_ms) {
  (void)cls;
  if (ptr == 0) {
    throw_ex(env, "java/lang/IllegalStateException", "group closed");
    return NULL;
  }
  if (!require_non_negative_jlong(env, timeout_ms, "timeout_ms")) {
    return NULL;
  }
  char *out = NULL;
  int32_t rc = tendril_group_poll_event(
      (TendrilGroup *)(uintptr_t)ptr, (uint64_t)timeout_ms, &out);
  if (rc == TENDRIL_WOULD_BLOCK) {
    return NULL;
  }
  if (rc == TENDRIL_EOF) {
    throw_ex(env, "java/lang/IllegalStateException", "group pool closed");
    return NULL;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_poll_event failed");
    return NULL;
  }
  return take_out_string(env, out);
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_groupAuthorizePeer(
    JNIEnv *env, jclass cls, jlong ptr, jstring peer_id, jstring cap) {
  (void)cls;
  if (ptr == 0 || peer_id == NULL || cap == NULL) {
    throw_ex(env, "java/lang/IllegalArgumentException", "invalid groupAuthorizePeer arguments");
    return;
  }
  char *c_peer = NULL;
  char *c_cap = NULL;
  int32_t rc = TENDRIL_ERR_INTERNAL;
  if (dup_opt_utf8(env, peer_id, &c_peer) && dup_opt_utf8(env, cap, &c_cap)) {
    rc = tendril_group_authorize_peer((TendrilGroup *)(uintptr_t)ptr, c_peer, c_cap);
  }
  free(c_peer);
  free(c_cap);
  if ((*env)->ExceptionCheck(env)) {
    return;
  }
  if (rc != TENDRIL_OK) {
    throw_ffi_error(env, rc, "tendril_group_authorize_peer failed");
  }
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_groupClose(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)env;
  (void)cls;
  if (ptr != 0) {
    tendril_group_close((TendrilGroup *)(uintptr_t)ptr);
  }
}

JNIEXPORT void JNICALL Java_dev_tendril_TendrilNative_groupFree(
    JNIEnv *env, jclass cls, jlong ptr) {
  (void)env;
  (void)cls;
  if (ptr != 0) {
    tendril_group_free((TendrilGroup *)(uintptr_t)ptr);
  }
}
