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
    private const val IV_LEN_BYTES = 12
    private const val TAG_BITS = 128
  }

  @Synchronized
  private fun getOrCreateKey(): SecretKey {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val existing = ks.getKey(alias, null) as? SecretKey
    if (existing != null) {
      return existing
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

  fun encrypt(plaintext: ByteArray, associatedData: ByteArray? = null): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
    if (associatedData != null && associatedData.isNotEmpty()) {
      cipher.updateAAD(associatedData)
    }
    val iv = cipher.iv
    require(iv.size == IV_LEN_BYTES) { "unexpected GCM IV length: ${iv.size}" }
    val ciphertext = cipher.doFinal(plaintext)
    val out = ByteArray(IV_LEN_BYTES + ciphertext.size)
    System.arraycopy(iv, 0, out, 0, IV_LEN_BYTES)
    System.arraycopy(ciphertext, 0, out, IV_LEN_BYTES, ciphertext.size)
    return out
  }

  fun decrypt(sealed: ByteArray, associatedData: ByteArray? = null): ByteArray {
    require(sealed.size > IV_LEN_BYTES) { "sealed payload too short" }
    val iv = sealed.copyOfRange(0, IV_LEN_BYTES)
    val body = sealed.copyOfRange(IV_LEN_BYTES, sealed.size)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_BITS, iv))
    if (associatedData != null && associatedData.isNotEmpty()) {
      cipher.updateAAD(associatedData)
    }
    return cipher.doFinal(body)
  }
}
