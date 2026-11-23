package dev.tendril

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
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
          assertEquals(1, tokenObj.getInt("v"))
          assertEquals("android-smoke-host", tokenObj.getString("issuer"))
          assertEquals("smoke-peer", tokenObj.getString("subject"))
          val caps = tokenObj.getJSONArray("caps")
          assertEquals(1, caps.length())
          assertEquals("pair.enroll:android-smoke-host", caps.getString(0))
          assertEquals(1, tokenObj.getInt("uses"))
          assertTrue(tokenObj.getBoolean("machine"))
          assertFalse(tokenObj.getString("sig").isEmpty())
        }

      TendrilEndpoint.create(
          stateDir = stateDir.absolutePath,
          hostId = "android-smoke-host",
          stateCipher = cipher,
        )
        .use { ep2 ->
          val info2 = JSONObject(ep2.infoJson())
          assertEquals(info1.getString("device_id"), info2.getString("device_id"))
          assertEquals(info1.getString("static_pub"), info2.getString("static_pub"))
          assertEquals(info1.getString("signing_pub"), info2.getString("signing_pub"))
          assertNotEquals("", info2.getString("device_id"))
        }
    } finally {
      stateDir.deleteRecursively()
      deleteKeystoreAlias(alias)
    }
  }

  @Test
  fun configureTransportsAndMintRelayTicket() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val stateDir = File(context.noBackupFilesDir, "tendril-smoke-cfg-${UUID.randomUUID()}")
    val alias = "tendril.smoke.cfg.${UUID.randomUUID()}"
    val cipher = KeystoreStateCipher(alias)

    try {
      TendrilEndpoint.create(
          stateDir = stateDir.absolutePath,
          hostId = "android-smoke-cfg-host",
          stateCipher = cipher,
        )
        .use { ep ->
          val ticketJson =
            ep.mintRelayTicket(
              relayHost = "relay.example",
              role = "dial",
              targetPubOrWildcard = "*",
              ttlSecs = 300,
            )
          val ticketObj = JSONObject(ticketJson)
          assertEquals("relay.example", ticketObj.getString("relay_host"))
          assertEquals("dial", ticketObj.getString("role"))
          assertEquals("*", ticketObj.getString("target_pub"))
          assertFalse(ticketObj.getString("issuer_pub").isEmpty())
          assertFalse(ticketObj.getString("sig").isEmpty())

          val unknownResult =
            runCatching { ep.configureTransportsJson("""{"unknown_field":true}""") }
          assertTrue(unknownResult.isFailure)

          val scalarResult =
            runCatching { ep.configureTransportsJson("""{"relay_auth_secret":123456}""") }
          assertTrue(scalarResult.isFailure)
          val scalarMsg = scalarResult.exceptionOrNull()?.message.orEmpty()
          assertFalse(scalarMsg.contains("123456"))

          ep.configureTransportsJson("""{"relay_ticket":$ticketJson}""")
        }
    } finally {
      stateDir.deleteRecursively()
      deleteKeystoreAlias(alias)
    }
  }

  private fun freeLoopbackAddr(): String =
    java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress()).use {
      "127.0.0.1:${it.localPort}"
    }

  private fun b64(value: String): ByteArray = java.util.Base64.getUrlDecoder().decode(value)

  private fun waitAppData(group: TendrilGroup): JSONObject {
    val deadline = System.nanoTime() + 15_000_000_000L
    while (System.nanoTime() < deadline) {
      val raw = group.pollEvent(500) ?: continue
      val ev = JSONObject(raw)
      if (ev.getString("event") == "app_data") {
        return ev
      }
    }
    throw AssertionError("no app_data event in time")
  }

  private fun broadcastUntilDelivered(group: TendrilGroup, payload: ByteArray): JSONObject {
    val deadline = System.nanoTime() + 15_000_000_000L
    while (true) {
      val report = JSONObject(group.broadcast(payload))
      if (report.getJSONArray("delivered").length() == 1 || System.nanoTime() > deadline) {
        return report
      }
      Thread.sleep(200)
    }
  }

  /** Enrolls [peer] with [host] over the M2M flow, which pins both full signing keys. */
  private fun enroll(host: TendrilEndpoint, hostAddr: String, peer: TendrilEndpoint) {
    val hostInfo = JSONObject(host.infoJson())
    val hostId = hostInfo.getString("host_id")
    val peerId = JSONObject(peer.infoJson()).getString("device_id")
    val token = host.mintEnrollmentToken(targetHostId = hostId, subject = peerId, ttlSecs = 300)
    var acceptError: Throwable? = null
    val accept = Thread { runCatching { host.pairAccept(10_000) }.onFailure { acceptError = it } }
    accept.start()
    peer.enrollInitiate(
      endpoint = hostAddr,
      hostId = hostId,
      hostStaticPub = b64(hostInfo.getString("static_pub")),
      hostSigningPub = b64(hostInfo.getString("signing_pub")),
      tokenJson = token,
    )
    accept.join()
    acceptError?.let { throw it }
  }

  @Test
  fun sealedEndpointHostsGroupAcrossRestart() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val rootDir = File(context.noBackupFilesDir, "tendril-smoke-grp-a-${UUID.randomUUID()}")
    val memberDir = File(context.noBackupFilesDir, "tendril-smoke-grp-b-${UUID.randomUUID()}")
    val rootAlias = "tendril.smoke.grp.a.${UUID.randomUUID()}"
    val memberAlias = "tendril.smoke.grp.b.${UUID.randomUUID()}"
    val memberCipher = KeystoreStateCipher(memberAlias)

    try {
      TendrilEndpoint.create(
          stateDir = rootDir.absolutePath,
          stateCipher = KeystoreStateCipher(rootAlias),
        )
        .use { root ->
          val rootId = JSONObject(root.infoJson()).getString("device_id")
          val rootAddr = root.serveDirect()
          val memberAddr = freeLoopbackAddr()
          val gid =
            TendrilEndpoint.create(stateDir = memberDir.absolutePath, stateCipher = memberCipher)
            .use { member ->
              val memberId = JSONObject(member.infoJson()).getString("device_id")
              enroll(root, rootAddr, member)
              val gid =
                JSONObject(root.groupCreate("smoke-group", 1, "[\"$rootAddr\"]"))
                  .getString("group_id")
              val manifest = root.groupAddMember(gid, memberId, null, "[\"$memberAddr\"]")
              assertEquals(gid, member.groupIngestManifest(manifest, rootId))
              root.openGroup(gid).use { rootGroup ->
                member.openGroup(gid, memberAddr).use { memberGroup ->
                  val report = broadcastUntilDelivered(rootGroup, "before".toByteArray())
                  assertEquals(1, report.getJSONArray("delivered").length())
                  waitAppData(memberGroup)
                }
              }
              gid
            }

          assertTrue(File(memberDir, "rt-groups.sealed").isFile)
          assertTrue(File(memberDir, "rt-roster.sealed").isFile)
          assertTrue(File(memberDir, "identity.sealed").isFile)
          assertFalse(File(memberDir, "groups.json").exists())
          assertFalse(File(memberDir, "roster.sealed").exists())

          TendrilEndpoint.create(stateDir = memberDir.absolutePath, stateCipher = memberCipher)
            .use { member ->
              root.openGroup(gid).use { rootGroup ->
                member.openGroup(gid, memberAddr).use { memberGroup ->
                  val report = broadcastUntilDelivered(rootGroup, "after".toByteArray())
                  assertEquals(1, report.getJSONArray("delivered").length())
                  val ev = waitAppData(memberGroup)
                  assertEquals(rootId, ev.getString("sender_device_id"))
                  assertArrayEquals("after".toByteArray(), b64(ev.getString("payload_b64")))
                }
              }
            }

          val groups = File(memberDir, "rt-groups.sealed")
          val bytes = groups.readBytes()
          bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
          groups.writeBytes(bytes)
          val reopen =
            runCatching {
              TendrilEndpoint.create(stateDir = memberDir.absolutePath, stateCipher = memberCipher)
                .close()
            }
          assertTrue(reopen.isFailure)
          assertTrue(
            reopen.exceptionOrNull()?.message.orEmpty().contains("cannot be opened")
          )
        }
    } finally {
      rootDir.deleteRecursively()
      memberDir.deleteRecursively()
      deleteKeystoreAlias(rootAlias)
      deleteKeystoreAlias(memberAlias)
    }
  }

  private fun nativeRosterJson(dir: File, identityJson: String): String {
    val ptr = TendrilNative.endpointNewSealed(dir.absolutePath, identityJson, null, null)
    try {
      return TendrilNative.endpointExportRosterJson(ptr)
    } finally {
      TendrilNative.endpointFree(ptr)
    }
  }

  @Test
  fun sealedEndpointMigratesLegacyRosterOnce() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val rootDir = File(context.noBackupFilesDir, "tendril-smoke-mig-a-${UUID.randomUUID()}")
    val memberDir = File(context.noBackupFilesDir, "tendril-smoke-mig-b-${UUID.randomUUID()}")
    val legacyDir = File(context.noBackupFilesDir, "tendril-smoke-mig-c-${UUID.randomUUID()}")
    val rootAlias = "tendril.smoke.mig.a.${UUID.randomUUID()}"
    val memberAlias = "tendril.smoke.mig.b.${UUID.randomUUID()}"
    val memberCipher = KeystoreStateCipher(memberAlias)

    try {
      val (rootHostId, memberId) =
        TendrilEndpoint.create(stateDir = rootDir.absolutePath, stateCipher = KeystoreStateCipher(rootAlias))
          .use { root ->
            val rootAddr = root.serveDirect()
            val memberId =
              TendrilEndpoint.create(stateDir = memberDir.absolutePath, stateCipher = memberCipher).use { member ->
                enroll(root, rootAddr, member)
                JSONObject(member.infoJson()).getString("device_id")
              }
            JSONObject(root.infoJson()).getString("host_id") to memberId
          }
      val identityJson = SealedStateStore(memberDir.absolutePath, memberCipher).loadIdentityJson()!!
      val rosterJson = nativeRosterJson(memberDir, identityJson)
      assertTrue(JSONObject(rosterJson).getJSONObject("entries").has(rootHostId))

      // A pre-runtime binding directory: identity plus a nonempty binding-sealed roster.
      SealedStateStore(legacyDir.absolutePath, memberCipher).saveIdentityJson(identityJson)
      val legacy = File(legacyDir, "roster.sealed")
      legacy.writeBytes(
        memberCipher.encrypt(rosterJson.toByteArray(), "tendril.roster.v1".toByteArray())
      )
      TendrilEndpoint.create(stateDir = legacyDir.absolutePath, stateCipher = memberCipher).use { ep ->
        assertEquals(memberId, JSONObject(ep.infoJson()).getString("device_id"))
      }
      assertFalse(legacy.exists())
      assertTrue(File(legacyDir, "rt-roster.sealed").isFile)
      assertTrue(
        JSONObject(nativeRosterJson(legacyDir, identityJson)).getJSONObject("entries").has(rootHostId)
      )

      // Cleanup interrupted after migration: the leftover is deleted unread, even if corrupt.
      legacy.writeBytes(byteArrayOf(1, 2, 3))
      TendrilEndpoint.create(stateDir = legacyDir.absolutePath, stateCipher = memberCipher).close()
      assertFalse(legacy.exists())
      assertTrue(
        JSONObject(nativeRosterJson(legacyDir, identityJson)).getJSONObject("entries").has(rootHostId)
      )
    } finally {
      rootDir.deleteRecursively()
      memberDir.deleteRecursively()
      legacyDir.deleteRecursively()
      deleteKeystoreAlias(rootAlias)
      deleteKeystoreAlias(memberAlias)
    }
  }

  @Test
  fun concurrentFirstOpensShareOneIdentity() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val stateDir = File(context.noBackupFilesDir, "tendril-smoke-race-${UUID.randomUUID()}")
    val alias = "tendril.smoke.race.${UUID.randomUUID()}"
    val cipher = KeystoreStateCipher(alias)
    val threads = 4
    val pool = Executors.newFixedThreadPool(threads)

    try {
      val barrier = CyclicBarrier(threads)
      val ids =
        (0 until threads)
          .map {
            pool.submit<String> {
              barrier.await(10, TimeUnit.SECONDS)
              TendrilEndpoint.create(stateDir = stateDir.absolutePath, stateCipher = cipher).use {
                JSONObject(it.infoJson()).getString("device_id")
              }
            }
          }
          .map { it.get(30, TimeUnit.SECONDS) }
      assertEquals(ids.toString(), 1, ids.toSet().size)
      TendrilEndpoint.create(stateDir = stateDir.absolutePath, stateCipher = cipher).use {
        assertEquals(ids[0], JSONObject(it.infoJson()).getString("device_id"))
      }
    } finally {
      pool.shutdownNow()
      stateDir.deleteRecursively()
      deleteKeystoreAlias(alias)
    }
  }

  @Test
  fun groupApiRefusesWithoutStateDir() {
    TendrilEndpoint.create(stateDir = null).use { ep ->
      val createResult = runCatching { ep.groupCreate("smoke-group") }
      assertTrue(createResult.isFailure)
      assertTrue(
        createResult.exceptionOrNull()?.message.orEmpty().contains("groups require a state directory endpoint")
      )
      val ingestResult = runCatching { ep.groupIngestManifest("{}", "peer") }
      assertTrue(ingestResult.isFailure)
    }
  }
}
