package dev.tendril

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TendrilAndroidSmokeTest {
  private fun deleteKeystoreAlias(alias: String) {
    runCatching {
      val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
      if (ks.containsAlias(alias)) {
        ks.deleteEntry(alias)
      }
    }
  }

  @Test
  fun keystoreRoundTripAndAadBinding() {
    val alias = "tendril.smoke.test.${UUID.randomUUID()}"
    try {
      val cipher = KeystoreStateCipher(alias)
      val plaintext = "tendril-keystore-smoke-payload".toByteArray(Charsets.UTF_8)
      val aad = "tendril.smoke.aad.v1".toByteArray(Charsets.UTF_8)

      val sealed = cipher.encrypt(plaintext, aad)
      assertFalse(sealed.contentEquals(plaintext))

      val opened = cipher.decrypt(sealed, aad)
      assertArrayEquals(plaintext, opened)

      val wrongAadResult = runCatching { cipher.decrypt(sealed, "wrong.aad".toByteArray(Charsets.UTF_8)) }
      assertTrue(wrongAadResult.isFailure)
    } finally {
      deleteKeystoreAlias(alias)
    }
  }

  @Test
  fun endpointIdentityPersistenceAndEnrollmentToken() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val stateDir = File(context.noBackupFilesDir, "tendril-smoke-${UUID.randomUUID()}")
    val alias = "tendril.smoke.ep.${UUID.randomUUID()}"
    val cipher = KeystoreStateCipher(alias)

    try {
      val info1: JSONObject
      TendrilEndpoint.create(
          stateDir = stateDir.absolutePath,
          hostId = "android-smoke-host",
          stateCipher = cipher,
        )
        .use { ep ->
          info1 = JSONObject(ep.infoJson())
          val deviceId = info1.getString("device_id")
          assertFalse(deviceId.isEmpty())
          assertEquals("android-smoke-host", info1.getString("host_id"))

          val tokenJson =
            ep.mintEnrollmentToken(
              targetHostId = "android-smoke-host",
              subject = "smoke-peer",
              ttlSecs = 300,
            )
          val tokenObj = JSONObject(tokenJson)
          assertEquals("android-smoke-host", tokenObj.getString("target_host_id"))
        }

      TendrilEndpoint.create(
          stateDir = stateDir.absolutePath,
          hostId = "android-smoke-host",
          stateCipher = cipher,
        )
        .use { ep2 ->
          val info2 = JSONObject(ep2.infoJson())
          assertEquals(info1.getString("device_id"), info2.getString("device_id"))
          assertEquals(info1.getString("static_pub_b64"), info2.getString("static_pub_b64"))
          assertEquals(info1.getString("signing_pub_b64"), info2.getString("signing_pub_b64"))
          assertNotEquals("", info2.getString("device_id"))
        }
    } finally {
      stateDir.deleteRecursively()
      deleteKeystoreAlias(alias)
    }
  }
}
