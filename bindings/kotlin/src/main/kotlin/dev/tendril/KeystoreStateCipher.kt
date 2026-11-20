package dev.tendril

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeystoreStateCipher(private val alias: String = DEFAULT_ALIAS) {
  companion object {
    const val DEFAULT_ALIAS = "tendril.state.master.v1"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val FORMAT_VERSION: Byte = 1
    private const val IV_LEN_BYTES = 12
    private const val TAG_BITS = 128
    private val DOMAIN_AAD = "tendril.state.v1\u0000".toByteArray(Charsets.UTF_8)
  }

  @Synchronized
  private fun getOrCreateKey(): SecretKey {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    if (ks.containsAlias(alias)) {
      return ks.getKey(alias, null) as? SecretKey
        ?: throw IllegalStateException("keystore entry '$alias' is not a SecretKey")
    }
    val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    val spec =
      KeyGenParameterSpec.Builder(
          alias,
          KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setRandomizedEncryptionRequired(true)
        .build()
    gen.init(spec)
    return gen.generateKey()
  }

  private fun buildAad(associatedData: ByteArray?): ByteArray {
    if (associatedData == null || associatedData.isEmpty()) {
      return DOMAIN_AAD
    }
    val out = ByteArray(DOMAIN_AAD.size + associatedData.size)
    System.arraycopy(DOMAIN_AAD, 0, out, 0, DOMAIN_AAD.size)
    System.arraycopy(associatedData, 0, out, DOMAIN_AAD.size, associatedData.size)
    return out
  }

  fun encrypt(plaintext: ByteArray, associatedData: ByteArray? = null): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
    cipher.updateAAD(buildAad(associatedData))
    val iv = cipher.iv
    require(iv.size == IV_LEN_BYTES) { "unexpected GCM IV length: ${iv.size}" }
    val ciphertext = cipher.doFinal(plaintext)
    val out = ByteArray(1 + IV_LEN_BYTES + ciphertext.size)
    out[0] = FORMAT_VERSION
    System.arraycopy(iv, 0, out, 1, IV_LEN_BYTES)
    System.arraycopy(ciphertext, 0, out, 1 + IV_LEN_BYTES, ciphertext.size)
    iv.fill(0)
    ciphertext.fill(0)
    return out
  }

  fun decrypt(sealed: ByteArray, associatedData: ByteArray? = null): ByteArray {
    require(sealed.size > 1 + IV_LEN_BYTES) { "sealed payload too short" }
    require(sealed[0] == FORMAT_VERSION) { "unsupported sealed version: ${sealed[0]}" }
    val iv = sealed.copyOfRange(1, 1 + IV_LEN_BYTES)
    val body = sealed.copyOfRange(1 + IV_LEN_BYTES, sealed.size)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    try {
      cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_BITS, iv))
      cipher.updateAAD(buildAad(associatedData))
      return cipher.doFinal(body)
    } finally {
      iv.fill(0)
      body.fill(0)
    }
  }
}
