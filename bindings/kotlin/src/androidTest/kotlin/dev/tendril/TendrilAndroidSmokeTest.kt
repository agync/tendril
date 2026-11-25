package dev.tendril

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.net.ConnectivityManager
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.ServiceTestRule
import com.google.android.gms.tasks.Tasks
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.net.InetAddress
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
import org.junit.Assume.assumeTrue
import org.junit.Rule
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

  // ---- Pairing URIs, routes and the multi-network snapshot --------------------------------

  @get:Rule val serviceRule = ServiceTestRule()

  /** A sealed endpoint that can be closed and reopened over the same state. */
  private inner class Node(name: String, private val hostId: String?) {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val dir = File(context.noBackupFilesDir, "tendril-smoke-$name-${UUID.randomUUID()}")
    val alias = "tendril.smoke.$name.${UUID.randomUUID()}"
    private val cipher = KeystoreStateCipher(alias)
    private val opened = mutableListOf<TendrilEndpoint>()

    fun open(): TendrilEndpoint =
      TendrilEndpoint.create(stateDir = dir.absolutePath, hostId = hostId, stateCipher = cipher)
        .also { opened += it }

    fun cleanUp() {
      opened.forEach { runCatching { it.close() } }
      dir.deleteRecursively()
      deleteKeystoreAlias(alias)
    }
  }

  private fun withNodes(vararg names: String, body: (List<Node>) -> Unit) {
    val nodes = names.map { Node(it, if (it.startsWith("host")) "smoke-$it" else null) }
    try {
      body(nodes)
    } finally {
      nodes.forEach { it.cleanUp() }
    }
  }

  private fun pairViaUri(
    host: TendrilEndpoint,
    client: TendrilEndpoint,
    uri: String,
    v2: Boolean = false,
  ): JSONObject {
    var hostResult: String? = null
    var failure: Throwable? = null
    val accept = Thread {
      try {
        hostResult = if (v2) host.pairV2Accept(15_000) else host.pairAccept(15_000)
      } catch (t: Throwable) {
        failure = t
      }
    }
    accept.start()
    val result =
      try {
        JSONObject(
          if (v2) client.pairV2Uri(uri, deviceName = "smoke-client")
          else client.pairUri(uri, deviceName = "smoke-client")
        )
      } finally {
        accept.join(20_000)
      }
    failure?.let { throw it }
    val hostJson = JSONObject(hostResult!!)
    assertEquals(result.getString("sas"), hostJson.getString("sas"))
    host.confirmPeer(hostJson.getString("device_id"), hostJson.getString("sas"))
    return result
  }

  private fun grantFor(host: TendrilEndpoint, peerId: String): String =
    host.mintGrant(peerId, "[\"fs.read\"]")

  /** Connects over stored routes (no endpoint) while [host] accepts; returns client and host sessions. */
  private fun connectStored(
    host: TendrilEndpoint,
    client: TendrilEndpoint,
    grant: String,
  ): Pair<TendrilSession, TendrilSession> {
    var accepted: TendrilSession? = null
    var failure: Throwable? = null
    val accept = Thread {
      try {
        accepted = host.acceptSession(10_000)
      } catch (t: Throwable) {
        failure = t
      }
    }
    accept.start()
    val hostId = JSONObject(host.infoJson()).getString("host_id")
    val session =
      try {
        client.connect(targetHostId = hostId, grantJson = grant)
      } finally {
        accept.join(15_000)
      }
    failure?.let { throw it }
    return session to accepted!!
  }

  private fun expectData(session: TendrilSession, text: String) {
    val deadline = System.nanoTime() + 10_000_000_000L
    while (System.nanoTime() < deadline) {
      val ev = JSONObject(session.pollEvent(500))
      if (ev.optString("event") == "data") {
        assertEquals(text, String(b64(ev.getString("data_b64"))))
        return
      }
    }
    throw AssertionError("no data event for '$text'")
  }

  private fun roundTrip(from: TendrilSession, to: TendrilSession, text: String) {
    from.sendData(text.toByteArray())
    expectData(to, text)
  }

  private fun routesOf(ep: TendrilEndpoint, peerId: String, source: String): List<String> {
    val routes = JSONObject(ep.peerRoutes(peerId)).getJSONArray("routes")
    return (0 until routes.length())
      .map { routes.getJSONObject(it) }
      .filter { it.getString("source") == source }
      .map { it.getString("hint") }
      .sorted()
  }

  private fun waitRouteSet(client: TendrilEndpoint, session: TendrilSession, hostId: String, seq: Long) {
    val deadline = System.nanoTime() + 15_000_000_000L
    while (System.nanoTime() < deadline) {
      val ev = JSONObject(session.pollEvent(250))
      assertEquals("route sets never reach the event stream: $ev", "would_block", ev.optString("status"))
      val last = JSONObject(client.peerRoutes(hostId)).opt("last_route_set")
      if (last is JSONObject && last.getString("outcome") == "applied" && last.getLong("seq") == seq) {
        return
      }
    }
    throw AssertionError("route set $seq not applied")
  }

  private fun net(
    id: String,
    iface: String,
    transports: List<String>,
    vararg addrs: String,
  ): SnapshotNetwork =
    NetworkSnapshots.fromAddresses(
      id,
      iface,
      addrs.map { InetAddress.getByName(it) },
      transports,
    )!!

  private fun hintsOf(uri: String): List<String> =
    Uri.parse(uri).getQueryParameter("ep").orEmpty().split(",").filter { it.isNotEmpty() }

  private fun portOf(endpoint: String): String = endpoint.substringAfterLast(':')

  @Test
  fun signedPairingPersistsAllRoutes() {
    withNodes("host", "client") { (hostNode, clientNode) ->
      val host = hostNode.open()
      val client = clientNode.open()
      val first = host.serveDirect("127.0.0.1:0")
      val second = host.serveDirect("127.0.0.1:0")
      val issued = JSONObject(host.issuePairingUri())
      val uri = issued.getString("uri")
      assertTrue(uri, uri.contains("&rq=") && uri.contains("&rs="))
      assertEquals(uri.length, issued.getInt("uri_len"))
      assertTrue(issued.getJSONArray("dropped").length() == 0)

      val res = pairViaUri(host, client, uri)
      assertEquals("active", res.getString("status"))
      assertEquals("verified", res.getString("route_check"))
      val hostId = JSONObject(host.infoJson()).getString("host_id")
      assertEquals(listOf("direct:$first", "direct:$second").sorted(), routesOf(client, hostId, "signed"))

      val grant = grantFor(host, res.getString("device_id"))
      val (c, h) = connectStored(host, client, grant)
      c.use { cs ->
        h.use { hs ->
          assertEquals(hostId, cs.peerId())
          assertEquals(res.getString("device_id"), hs.peerId())
          roundTrip(cs, hs, "over stored routes")
        }
      }
    }
  }

  @Test
  fun networkCallbackRefreshesRoutes() {
    withNodes("host") { (hostNode) ->
      val host = hostNode.open()
      host.serveDirect("127.0.0.1:0")
      host.serveDirect("0.0.0.0:0")
      val wifiA = NetworkSnapshots.toJson(listOf(net("n1", "wlan0", listOf("wifi"), "10.255.77.20")))
      val wifiB = NetworkSnapshots.toJson(listOf(net("n1", "wlan0", listOf("wifi"), "10.255.77.30")))

      val first = JSONObject(host.refreshRoutes(wifiA))
      val seq0 = first.getLong("route_seq")
      val same = JSONObject(host.refreshRoutes(wifiA))
      assertFalse(same.getBoolean("changed"))
      assertEquals(seq0, same.getLong("route_seq"))

      val moved = JSONObject(host.refreshRoutes(wifiB))
      assertTrue(moved.getBoolean("changed"))
      assertEquals(seq0 + 1, moved.getLong("route_seq"))
      val uri = JSONObject(host.issuePairingUri()).getString("uri")
      assertTrue(uri, uri.contains("10.255.77.30") && !uri.contains("10.255.77.20"))

      val timer = JSONObject(host.refreshRoutes(null))
      assertFalse("timer refresh reuses the retained snapshot", timer.getBoolean("changed"))
      assertEquals(seq0 + 1, timer.getLong("route_seq"))
      assertTrue(runCatching { host.refreshRoutes("{\"networks\":1}") }.isFailure)
    }
  }

  @Test
  fun multiNetworkSnapshot() {
    withNodes("host") { (hostNode) ->
      val host = hostNode.open()
      val listen = host.serveDirect("0.0.0.0:0")
      val port = portOf(listen)
      val wifi = net("n1", "wlan0", listOf("wifi"), "192.168.1.20")
      val vpn = net("n2", "tun0", listOf("vpn"), "100.101.1.2")
      val cell = net("n3", "rmnet0", listOf("cellular"), "100.70.3.4", "203.0.113.7")

      host.refreshRoutes(NetworkSnapshots.toJson(listOf(wifi, vpn, cell)))
      val uri = JSONObject(host.issuePairingUri()).getString("uri")
      val hints = hintsOf(uri)
      assertTrue(hints.toString(), "direct:192.168.1.20:$port" in hints)
      assertTrue(hints.toString(), "overlay://100.101.1.2:$port" in hints)
      assertTrue(uri, !uri.contains("100.70.3.4") && !uri.contains("203.0.113.7"))
      val seq0 = JSONObject(host.refreshRoutes(null)).getLong("route_seq")

      val lost = JSONObject(host.refreshRoutes(NetworkSnapshots.toJson(listOf(vpn, cell))))
      assertTrue(lost.getBoolean("changed"))
      assertEquals(seq0 + 1, lost.getLong("route_seq"))
      val after = hintsOf(JSONObject(host.issuePairingUri()).getString("uri"))
      assertFalse(after.toString(), "direct:192.168.1.20:$port" in after)
      assertTrue(after.toString(), "overlay://100.101.1.2:$port" in after)

      // A snapshot with zero networks is not applied until it persists past the debounce.
      val empty = JSONObject(host.refreshRoutes(NetworkSnapshots.toJson(emptyList())))
      assertFalse(empty.getBoolean("changed"))
      assertEquals(seq0 + 1, empty.getLong("route_seq"))
    }
  }

  @Test
  fun addressChangePropagatesAndReconnects() {
    withNodes("host", "client") { (hostNode, clientNode) ->
      var host = hostNode.open()
      val client = clientNode.open()
      val oldAddr = host.serveDirect("127.0.0.1:0")
      val newAddr = freeLoopbackAddr()
      val hostId = JSONObject(host.infoJson()).getString("host_id")
      val res = pairViaUri(host, client, JSONObject(host.issuePairingUri()).getString("uri"))
      val grant = grantFor(host, res.getString("device_id"))
      val seq0 = JSONObject(client.peerRoutes(hostId)).getJSONObject("route_meta").getLong("seq")

      // The first session carries the host's current set (the client learned routes from a URI).
      connectStored(host, client, grant).let { (c, h) ->
        c.use { cs -> h.use { waitRouteSet(client, cs, hostId, seq0) } }
      }

      // The host starts serving a second address while the client is connected.
      val (c, h) = connectStored(host, client, grant)
      host.serveDirect(newAddr)
      waitRouteSet(client, c, hostId, seq0 + 1)
      assertEquals(
        listOf("direct:$oldAddr", "direct:$newAddr").sorted(),
        routesOf(client, hostId, "signed"),
      )
      c.close()
      h.close()

      // The host restarts and serves only the new address: the stored list still names the old
      // one first, the client falls through to the new one with no prompt.
      host.close()
      host = hostNode.open()
      host.serveDirect(newAddr)
      val (c2, h2) = connectStored(host, client, grant)
      c2.use { cs -> h2.use { hs -> roundTrip(cs, hs, "after the address change") } }
    }
  }

  @Test
  fun sealedSeqSurvivesRestart() {
    withNodes("host") { (node) ->
      fun explicit(hint: String, ep: TendrilEndpoint) =
        ep.configureRoutes(advertise = Advertise.EXPLICIT, advertisedEndpoints = listOf(hint))
      fun seq(ep: TendrilEndpoint) = JSONObject(ep.issuePairingUri()).getLong("route_seq")

      val seqB: Long
      node.open().let { ep ->
        explicit("192.168.40.1:4100", ep)
        val a = seq(ep)
        explicit("192.168.40.1:4101", ep)
        seqB = seq(ep)
        assertEquals(a + 1, seqB)
        ep.close()
      }
      node.open().let { ep ->
        explicit("192.168.40.1:4101", ep)
        assertEquals("unchanged set keeps the persisted sequence", seqB, seq(ep))
        explicit("192.168.40.1:4102", ep)
        assertEquals("a changed set bumps from the persisted sequence", seqB + 1, seq(ep))
      }
    }
  }

  @Test
  fun builderUriIsUriParseFixpoint() {
    withNodes("host") { (node) ->
      val host = node.open()
      host.configureRoutes(
        advertise = Advertise.EXPLICIT,
        advertisedEndpoints = listOf("direct:192.168.40.1:4100", "overlay://100.101.1.2:4100"),
      )
      // The host keeps at most four live pairing codes, so the cases are limited to four.
      val cases =
        listOf(
          "laptop" to true,
          "laptop" to false,
          "Pixel's phone & more/ü" to true,
          "say \"hi\" \\ back" to true,
        )
      for ((name, sign) in cases) {
        val uri = JSONObject(host.issuePairingUri(hostName = name, signRoutes = sign)).getString("uri")
        assertEquals("signed=$sign host=$name", uri, Uri.parse(uri).toString())
        assertEquals(sign, uri.contains("&rs="))
      }
    }
  }

  private fun qrBitmap(content: String, scale: Int = 8): Pair<Bitmap, Int> {
    val hints =
      mapOf(
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        EncodeHintType.CHARACTER_SET to "UTF-8",
        EncodeHintType.MARGIN to 4,
      )
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 0, 0, hints)
    val bitmap = Bitmap.createBitmap(matrix.width * scale, matrix.height * scale, Bitmap.Config.ARGB_8888)
    for (y in 0 until bitmap.height) {
      for (x in 0 until bitmap.width) {
        bitmap.setPixel(x, y, if (matrix.get(x / scale, y / scale)) Color.BLACK else Color.WHITE)
      }
    }
    return bitmap to (matrix.width - 8 - 17) / 4
  }

  private fun scan(bitmap: Bitmap): String? {
    val scanner =
      BarcodeScanning.getClient(
        BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
      )
    try {
      val codes = Tasks.await(scanner.process(InputImage.fromBitmap(bitmap, 0)), 60, TimeUnit.SECONDS)
      return codes.singleOrNull()?.rawValue
    } finally {
      scanner.close()
    }
  }

  @Test
  fun scannerPassthrough() {
    withNodes("host", "client") { (hostNode, clientNode) ->
      val host = hostNode.open()
      val client = clientNode.open()
      host.serveDirect("127.0.0.1:0")
      for (sign in listOf(false, true)) {
        val issued = JSONObject(host.issuePairingUri(signRoutes = sign))
        val uri = issued.getString("uri")
        val (bitmap, version) = qrBitmap(uri)
        assertEquals("QR version of $uri", issued.getInt("qr_version_m"), version)
        val decoded = scan(bitmap)
        assertEquals("signed=$sign decoded string is byte-equal to the builder output", uri, decoded)
        if (sign) {
          val res = pairViaUri(host, client, decoded!!)
          assertEquals("verified", res.getString("route_check"))
        }
      }
    }
  }

  @Test
  fun serviceSeedsHostFromRealNetworks() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val cm = context.getSystemService(ConnectivityManager::class.java)
    @Suppress("DEPRECATION")
    val privateV4 =
      cm.allNetworks
        .flatMap { cm.getLinkProperties(it)?.linkAddresses.orEmpty() }
        .mapNotNull { it.address }
        .filter { it.address.size == 4 && it.isSiteLocalAddress }
        .mapNotNull { it.hostAddress }
    assumeTrue("no private IPv4 network on this device", privateV4.isNotEmpty())
    withNodes("host") { (hostNode) ->
      val host = hostNode.open()
      val port = portOf(host.serveDirect("0.0.0.0:0"))
      val binder =
        serviceRule.bindService(Intent(context, TendrilForegroundService::class.java))
          as TendrilForegroundService.LocalBinder
      binder.attachEndpoint(host)
      val snapshot = JSONObject(binder.currentSnapshotJson()).getJSONArray("networks")
      assertTrue(snapshot.toString(), snapshot.length() >= 1)
      val uri = JSONObject(host.issuePairingUri()).getString("uri")
      val hints = hintsOf(uri)
      assertTrue("$privateV4 not advertised: $hints", privateV4.any { "direct:$it:$port" in hints })
      binder.attachEndpoint(null)
    }
  }

  @Test
  fun grantOptionRejectsInjectionAndBlank() {
    val grant = """{"v":1,"caps":["fs.read"],"sig":"abc"}"""
    // A valid object embeds as is, so signed numbers and field order are untouched.
    assertEquals(grant, grantOption("  $grant\n")?.json)
    assertEquals("""{"grant":$grant}""", optionsJson("grant" to grantOption(grant)))
    val nested = """{"a":[1,-2.5e+3,true,false,null,{"b":"\u00e9\n"}],"c":{}}"""
    assertEquals(nested, grantOption(nested)?.json)
    // Blank is no grant at all, never `"grant":` with an empty value.
    assertEquals(null, grantOption(null))
    assertEquals(null, grantOption(""))
    assertEquals(null, grantOption("  \n\t"))
    assertEquals(null, optionsJson("grant" to grantOption("")))
    val bad =
      listOf(
        // sibling keys smuggled after a complete object
        """{"v":1},"endpoint":"tcp://evil.example:1","replace_routes":true""",
        """{"v":1}"endpoint":"x"""",
        """{"v":1} {"endpoint":"x"}""",
        """{"v":1}}""",
        """{"v":1} // trailing""",
        // not one object
        "[{}]",
        "\"text\"",
        "123",
        "null",
        "{",
        """{"v":1""",
        "{}x",
        // lenient forms the native parser rejects
        """{"a":1,}""",
        """{a:1}""",
        """{'a':1}""",
        """{"a":1 /* c */}""",
        """{"a":1}\u0000}""",
        """{"a":[1,]}""",
        "{\"a\":\"x\ty\"}",
        """{"a":01}""",
        """{"a":"\x"}""",
        """{"a":tru}""",
      )
    for (payload in bad) {
      val err = runCatching { grantOption(payload) }.exceptionOrNull()
      assertTrue("accepted: $payload", err is IllegalArgumentException)
      assertFalse(err?.message.orEmpty().contains("evil"))
    }
    TendrilEndpoint.create().use { ep ->
      val err =
        runCatching { ep.connectWithOptions("peer", grantJson = bad[0], routePolicy = RoutePolicy.NONE) }
          .exceptionOrNull()
      assertTrue(err is IllegalArgumentException)
    }
  }

  @Test
  fun transportConfigCacheMergesAndCachesOnlyAfterSuccess() {
    val cache = TransportConfigCache()
    val sent = mutableListOf<String>()
    cache.replace("""{"relay_ticket":{"sig":"t1"},"route_policy":"none"}""") { sent += it }
    cache.merge(mapOf("route_policy" to "committed_only", "advertised_endpoints" to listOf("a:1"))) {
      sent += it
    }
    val merged = JSONObject(sent.last())
    assertEquals("t1", merged.getJSONObject("relay_ticket").getString("sig"))
    assertEquals("committed_only", merged.getString("route_policy"))
    assertEquals("a:1", merged.getJSONArray("advertised_endpoints").getString(0))
    assertEquals(merged.toString(), cache.current())

    val before = cache.current()
    val failed = runCatching { cache.merge(mapOf("route_policy" to "all_signed")) { error("rejected") } }
    assertTrue(failed.isFailure)
    assertEquals("a failed merge leaves the cache", before, cache.current())
    val failedReplace = runCatching { cache.replace("""{"x":1}""") { error("rejected") } }
    assertTrue(failedReplace.isFailure)
    assertEquals("a failed replace leaves the cache", before, cache.current())

    // A full replacement drops the ticket for good.
    cache.replace("{}") { sent += it }
    cache.merge(mapOf("route_policy" to "all_signed")) { sent += it }
    assertFalse(JSONObject(sent.last()).has("relay_ticket"))
    assertEquals("all_signed", JSONObject(sent.last()).getString("route_policy"))
  }

  @Test
  fun transportConfigCacheFailsLoudlyAndClears() {
    val cache = TransportConfigCache()
    val sent = mutableListOf<String>()
    cache.replace("""{"relay_auth_secret":"s"}""") { sent += it }
    val err = runCatching { cache.replace("[1]") { sent += it } }.exceptionOrNull()
    assertTrue(err is IllegalArgumentException)
    assertEquals("unparseable text is never sent", 1, sent.size)
    assertTrue(cache.current()!!.contains("relay_auth_secret"))
    cache.clear()
    assertEquals(null, cache.current())
  }

  @Test
  fun networkMapUnknownUntilFilledAndLossDuringSeedSticks() {
    val map = NetworkMap<String, String, String>()
    assertFalse(map.isKnown())
    assertFalse(map.seed(callbacksLive = false) { throw SecurityException("denied") })
    assertFalse("a denied seed leaves the map unknown", map.isKnown())
    // A network lost while the seed read ran is not re-added by the stale read.
    assertTrue(
      map.seed(callbacksLive = true) {
        map.remove("a")
        listOf(Triple("a", "l", "c"), Triple("b", "l", "c"))
      }
    )
    assertTrue(map.isKnown())
    assertEquals(listOf("b"), map.complete().map { it.first })
    val empty = NetworkMap<String, String, String>()
    assertTrue(empty.seed(callbacksLive = false) { emptyList() })
    assertTrue("an empty successful seed is a known zero", empty.isKnown())
  }

  @Test
  fun configureRoutesKeepsRelayTicket() {
    TendrilEndpoint.create(hostId = "android-cfg-routes").use { ep ->
      val ticket = ep.mintRelayTicket(relayHost = "relay.example", role = "register", targetPubOrWildcard = "*")
      ep.configureTransportsJson("""{"relay_ticket":$ticket}""")
      ep.configureRoutes(routePolicy = RoutePolicy.COMMITTED_ONLY)
      val kept = JSONObject(ep.transportConfigJson()!!)
      assertEquals(JSONObject(ticket).getString("sig"), kept.getJSONObject("relay_ticket").getString("sig"))
      assertEquals("committed_only", kept.getString("route_policy"))

      // A rejected route key writes nothing and keeps the cache.
      val before = ep.transportConfigJson()
      assertTrue(runCatching { ep.configureRoutes(relayAuthOrigins = listOf("relay.example")) }.isFailure)
      assertTrue(runCatching { ep.configureTransportsJson("""{"unknown_field":true}""") }.isFailure)
      assertEquals(before, ep.transportConfigJson())

      // A full replacement updates the cache, so the replaced ticket is not resurrected.
      ep.configureTransportsJson("{}")
      ep.configureRoutes(routePolicy = RoutePolicy.ALL_SIGNED)
      val reset = JSONObject(ep.transportConfigJson()!!)
      assertFalse(reset.has("relay_ticket"))
      assertEquals("all_signed", reset.getString("route_policy"))
    }
  }

  @Test
  fun networkMapSeedingKeepsCallbackStateAndSurvivesDeniedEnumeration() {
    val map = NetworkMap<String, String, String>()
    map.update("a") { it.link = "link-a"; it.caps = "caps-a" }
    map.update("b") { it.link = "link-b"; it.caps = "caps-b" }

    // A denied enumeration keeps what the callbacks delivered.
    map.seed(callbacksLive = true) { throw SecurityException("no ACCESS_NETWORK_STATE") }
    assertEquals(listOf("a", "b"), map.complete().map { it.first })

    // A seed read earlier than the callbacks must not clobber fresher callback values; lost
    // networks (not in the seed) drop, new ones are added.
    map.seed(callbacksLive = true) {
      listOf(Triple("a", "stale-link", "stale-caps"), Triple("c", "link-c", "caps-c"))
    }
    assertEquals(
      listOf(Triple("a", "link-a", "caps-a"), Triple("c", "link-c", "caps-c")),
      map.complete(),
    )

    // Without callbacks the seed is the only source and overwrites.
    map.seed(callbacksLive = false) { listOf(Triple("a", "fresh-link", "fresh-caps")) }
    assertEquals(listOf(Triple("a", "fresh-link", "fresh-caps")), map.complete())

    // A network still missing data is left out.
    map.update("d") { it.link = "link-d" }
    assertEquals(listOf("a"), map.complete().map { it.first })
  }

  @Test
  fun runAllGuardedRunsEveryStep() {
    val ran = mutableListOf<Int>()
    val err =
      runCatching {
          runAllGuarded(
            { ran += 1; throw IllegalArgumentException("not registered") },
            { ran += 2; throw SecurityException("denied") },
            { ran += 3 },
          )
        }
        .exceptionOrNull()
    assertEquals(listOf(1, 2, 3), ran)
    assertTrue(err is IllegalArgumentException)
    assertEquals(1, err?.suppressed?.size)
    val same = IllegalStateException("same")
    val rethrown = runCatching { runAllGuarded({ throw same }, { throw same }) }.exceptionOrNull()
    assertTrue(rethrown === same)
    runAllGuarded({ ran += 4 })
    assertEquals(4, ran.last())
  }
}
