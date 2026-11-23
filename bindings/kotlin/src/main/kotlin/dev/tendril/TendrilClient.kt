package dev.tendril

import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

internal class SealedStateStore(dirPath: String, private val cipher: KeystoreStateCipher) {
  companion object {
    private const val IDENTITY_FILE = "identity.sealed"
    private const val ROSTER_FILE = "roster.sealed"
    private const val BOOTSTRAP_LOCK_FILE = ".identity.lock"
    private val RUNTIME_FILES = listOf("rt-roster.sealed", "rt-groups.sealed")
    private val bootstrapMonitors = ConcurrentHashMap<String, Any>()
    private val IDENTITY_AAD = "tendril.identity.v1".toByteArray(Charsets.UTF_8)
    private val ROSTER_AAD = "tendril.roster.v1".toByteArray(Charsets.UTF_8)
    private val DIR_PERMS = PosixFilePermissions.fromString("rwx------")
    private val FILE_PERMS = PosixFilePermissions.fromString("rw-------")
  }

  private val ioLock = Any()
  private val root = File(dirPath)

  init {
    val rootPath = root.toPath()
    if (Files.exists(rootPath)) {
      require(!Files.isSymbolicLink(rootPath) && Files.isDirectory(rootPath)) {
        "stateDir must be a private directory"
      }
    } else {
      Files.createDirectories(rootPath)
    }
    try {
      Files.setPosixFilePermissions(rootPath, DIR_PERMS)
    } catch (_: UnsupportedOperationException) {}
  }

  private fun readSealed(name: String, aad: ByteArray): String? {
    val file = File(root, name)
    val path = file.toPath()
    if (!Files.exists(path)) {
      return null
    }
    require(!Files.isSymbolicLink(path) && Files.isRegularFile(path)) {
      "sealed state file '$name' must be a regular file"
    }
    val sealed = Files.readAllBytes(path)
    val plain = cipher.decrypt(sealed, aad)
    return try {
      String(plain, Charsets.UTF_8)
    } finally {
      plain.fill(0)
    }
  }

  private fun writeSealed(name: String, json: String, aad: ByteArray) {
    val plain = json.toByteArray(Charsets.UTF_8)
    val sealed =
      try {
        cipher.encrypt(plain, aad)
      } finally {
        plain.fill(0)
      }
    val target = File(root, name).toPath()
    val tmp = Files.createTempFile(root.toPath(), ".tmp-", ".sealed")
    try {
      try {
        Files.setPosixFilePermissions(tmp, FILE_PERMS)
      } catch (_: UnsupportedOperationException) {}
      FileOutputStream(tmp.toFile()).use { out ->
        out.write(sealed)
        out.fd.sync()
      }
      try {
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
      } catch (_: AtomicMoveNotSupportedException) {
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)
      }
    } finally {
      sealed.fill(0)
      try {
        Files.deleteIfExists(tmp)
      } catch (_: Throwable) {}
    }
  }

  fun loadIdentityJson(): String? = synchronized(ioLock) { readSealed(IDENTITY_FILE, IDENTITY_AAD) }

  fun saveIdentityJson(json: String) =
    synchronized(ioLock) { writeSealed(IDENTITY_FILE, json, IDENTITY_AAD) }

  /**
   * Runs [block] holding the directory's identity bootstrap lock: a JVM monitor per directory
   * (a second `FileChannel.lock` in one JVM throws instead of waiting) plus an exclusive file lock
   * on `.identity.lock` for other processes.
   */
  fun <T> withBootstrapLock(block: () -> T): T {
    val monitor = bootstrapMonitors.computeIfAbsent(root.canonicalPath) { Any() }
    synchronized(monitor) {
      val path = File(root, BOOTSTRAP_LOCK_FILE).toPath()
      FileChannel.open(
          path,
          StandardOpenOption.CREATE,
          StandardOpenOption.WRITE,
          LinkOption.NOFOLLOW_LINKS,
        )
        .use { channel ->
          try {
            Files.setPosixFilePermissions(path, FILE_PERMS)
          } catch (_: UnsupportedOperationException) {}
          val lock = channel.lock()
          try {
            return block()
          } finally {
            lock.release()
          }
        }
    }
  }

  /** Whether the legacy roster still needs migrating: it exists and the runtime has no state. */
  fun legacyRosterNeedsMigration(): Boolean =
    File(root, ROSTER_FILE).exists() && RUNTIME_FILES.none { File(root, it).exists() }

  /** Reads the pre-runtime binding roster, kept only to seed a directory once. */
  fun loadRosterJson(): String? = synchronized(ioLock) { readSealed(ROSTER_FILE, ROSTER_AAD) }

  /** Deletes the pre-runtime binding roster, if any, without reading it. */
  fun deleteLegacyRoster() =
    synchronized(ioLock) { Files.deleteIfExists(File(root, ROSTER_FILE).toPath()) }
}

/**
 * A Tendril endpoint. With a [stateDir], the identity is sealed by [KeystoreStateCipher] in
 * `identity.sealed` and the runtime persists roster and group state itself in `rt-roster.sealed`
 * and `rt-groups.sealed`, sealed under a key derived from that identity.
 */
class TendrilEndpoint private constructor(handle: Long) : Closeable {
  private val lock = ReentrantReadWriteLock()
  private var handleValue: Long = handle

  companion object {
    @JvmStatic
    @JvmOverloads
    fun create(
      stateDir: String? = null,
      hostId: String? = null,
      stateCipher: KeystoreStateCipher? = null,
    ): TendrilEndpoint {
      val dir = stateDir?.takeIf { it.isNotEmpty() }
      if (dir == null) {
        return TendrilEndpoint(TendrilNative.endpointNewFromState(null, null, hostId))
      }
      val store = SealedStateStore(dir, stateCipher ?: KeystoreStateCipher())
      return store.withBootstrapLock { TendrilEndpoint(openSealed(store, dir, hostId)) }
    }

    /**
     * Saves a generated identity before any runtime state exists under it, then opens with it.
     * The reopen syncs the directory, so `identity.sealed` is durable before the first runtime
     * write, and seeds the runtime roster from a legacy `roster.sealed` only when needed.
     */
    private fun openSealed(store: SealedStateStore, dir: String, hostId: String?): Long {
      val identity =
        store.loadIdentityJson()
          ?: run {
            val fresh = TendrilNative.endpointNewSealed(dir, null, null, hostId)
            val generated =
              try {
                TendrilNative.endpointExportIdentityJson(fresh)
              } finally {
                TendrilNative.endpointFree(fresh)
              }
            store.saveIdentityJson(generated)
            generated
          }
      val seed = if (store.legacyRosterNeedsMigration()) store.loadRosterJson() else null
      val ptr = TendrilNative.endpointNewSealed(dir, identity, seed, hostId)
      try {
        store.deleteLegacyRoster()
      } catch (t: Throwable) {
        TendrilNative.endpointFree(ptr)
        throw t
      }
      return ptr
    }

    @JvmStatic fun deviceId(staticPub: ByteArray): String = TendrilNative.deviceId(staticPub)

    @JvmStatic
    fun fingerprintHost(staticPub: ByteArray): String = TendrilNative.fingerprintHost(staticPub)

    @JvmStatic
    fun fingerprintDevice(staticPub: ByteArray): String = TendrilNative.fingerprintDevice(staticPub)

    @JvmStatic
    fun pairingSas(handshakeHash: ByteArray): String = TendrilNative.pairingSas(handshakeHash)

    @JvmStatic
    fun computeCodeMac(code: String, handshakeHash: ByteArray): ByteArray =
      TendrilNative.computeCodeMac(code, handshakeHash)

    @JvmStatic
    fun verifyRotationChainJson(
      pinnedSigningB64: String,
      pinnedStaticB64: String,
      pinnedSeq: Long,
      chainJson: String,
      curStaticB64: String,
      curSigningB64: String,
    ): Long =
      TendrilNative.verifyRotationChainJson(
        pinnedSigningB64,
        pinnedStaticB64,
        pinnedSeq,
        chainJson,
        curStaticB64,
        curSigningB64,
      )

    @JvmStatic
    fun verifyGrantJson(
      grantJson: String,
      issuerKeysJson: String,
      expectedSubject: String,
      expectedRootIssuer: String,
      requestedCap: String,
      nowUnix: Long,
      crlJson: String? = null,
    ): Boolean =
      TendrilNative.verifyGrantJson(
        grantJson,
        issuerKeysJson,
        expectedSubject,
        expectedRootIssuer,
        requestedCap,
        nowUnix,
        crlJson,
      )
  }

  private inline fun <T> withHandle(fn: (Long) -> T): T =
    lock.read {
      val ptr = handleValue
      check(ptr != 0L) { "TendrilEndpoint is closed" }
      fn(ptr)
    }

  fun infoJson(): String = withHandle { TendrilNative.endpointInfoJson(it) }

  fun serveDirect(listenAddr: String = "127.0.0.1:0"): String =
    withHandle { TendrilNative.endpointServeDirect(it, listenAddr) }

  fun serveRelay(relayUrl: String, expectedHost: String? = null): String =
    withHandle { TendrilNative.endpointServeRelay(it, relayUrl, expectedHost) }

  fun configureTransportsJson(transportConfigJson: String) =
    withHandle { TendrilNative.endpointConfigureTransportsJson(it, transportConfigJson) }

  fun mintRelayTicket(
    relayHost: String,
    role: String? = null,
    targetPubOrWildcard: String? = null,
    ttlSecs: Long = 300,
  ): String =
    withHandle {
      TendrilNative.endpointMintRelayTicket(it, relayHost, role, targetPubOrWildcard, ttlSecs)
    }

  fun serveRelayV2(
    relayUrl: String,
    expectedHost: String? = null,
    peerIdOpt: String? = null,
  ): String =
    withHandle { TendrilNative.endpointServeRelayV2(it, relayUrl, expectedHost, peerIdOpt) }

  fun serveP2p(relayMode: String? = null): String =
    withHandle { TendrilNative.endpointServeP2p(it, relayMode) }

  fun issueCode(kind: String = "remote"): String =
    withHandle { TendrilNative.endpointIssueCode(it, kind) }

  fun pairInitiate(
    endpoint: String,
    relayHost: String? = null,
    code: String,
    deviceName: String,
    deviceKind: String = "android",
  ): String =
    withHandle {
      TendrilNative.endpointPairInitiate(it, endpoint, relayHost, code, deviceName, deviceKind)
    }

  fun pairAccept(timeoutMs: Long): String =
    withHandle { TendrilNative.endpointPairAccept(it, timeoutMs) }

  fun pairV2Initiate(
    endpoint: String,
    relayHost: String? = null,
    code: String,
    deviceName: String,
    deviceKind: String = "android",
    pinnedHostJson: String? = null,
  ): String =
    withHandle {
      TendrilNative.endpointPairV2Initiate(
        it,
        endpoint,
        relayHost,
        code,
        deviceName,
        deviceKind,
        pinnedHostJson,
      )
    }

  fun pairV2Accept(timeoutMs: Long): String =
    withHandle { TendrilNative.endpointPairV2Accept(it, timeoutMs) }

  fun confirmPeer(peerId: String, sas: String? = null) =
    withHandle { TendrilNative.endpointConfirmPeer(it, peerId, sas) }

  fun mintGrant(peerId: String, capsJson: String, ttlSecs: Long = 3600): String =
    withHandle { TendrilNative.endpointMintGrant(it, peerId, capsJson, ttlSecs) }

  fun revokePeer(peerId: String) =
    withHandle { TendrilNative.endpointRevokePeer(it, peerId) }

  fun addTrustAnchor(anchorId: String, signingPub: ByteArray) =
    withHandle { TendrilNative.endpointAddTrustAnchor(it, anchorId, signingPub) }

  fun revokeTrustAnchor(anchorId: String) =
    withHandle { TendrilNative.endpointRevokeTrustAnchor(it, anchorId) }

  fun mintEnrollmentToken(
    targetHostId: String,
    subject: String? = null,
    ttlSecs: Long = 900,
  ): String =
    withHandle { TendrilNative.endpointMintEnrollmentToken(it, targetHostId, subject, ttlSecs) }

  fun enrollInitiate(
    endpoint: String,
    relayHost: String? = null,
    hostId: String,
    hostStaticPub: ByteArray,
    hostSigningPub: ByteArray,
    hostRotationSeq: Long = 0,
    tokenJson: String,
    deviceName: String = "android-machine",
    deviceKind: String = "machine",
  ): String =
    withHandle {
      TendrilNative.endpointEnrollInitiate(
        it,
        endpoint,
        relayHost,
        hostId,
        hostStaticPub,
        hostSigningPub,
        hostRotationSeq,
        tokenJson,
        deviceName,
        deviceKind,
      )
    }

  fun connect(
    endpoint: String,
    relayHost: String? = null,
    targetHostId: String,
    grantJson: String? = null,
  ): TendrilSession =
    withHandle {
      TendrilSession(TendrilNative.sessionConnect(it, endpoint, relayHost, targetHostId, grantJson))
    }

  fun acceptSession(timeoutMs: Long): TendrilSession =
    withHandle { TendrilSession(TendrilNative.sessionAccept(it, timeoutMs)) }

  fun connectV2(
    endpoint: String,
    relayHost: String? = null,
    targetHostId: String,
    grantJson: String? = null,
  ): TendrilSession =
    withHandle {
      TendrilSession(
        TendrilNative.sessionConnectV2(it, endpoint, relayHost, targetHostId, grantJson)
      )
    }

  fun acceptV2(timeoutMs: Long): TendrilSession =
    withHandle { TendrilSession(TendrilNative.sessionAcceptV2(it, timeoutMs)) }

  /**
   * Creates a group rooted at this endpoint and returns the signed manifest JSON. Group APIs need
   * a [stateDir]; an endpoint without one fails with an invalid-argument error.
   * [endpointsJson] is null or a JSON array of strings.
   */
  fun groupCreate(name: String, minWireVersion: Int = 1, endpointsJson: String? = null): String =
    withHandle { TendrilNative.groupCreate(it, name, minWireVersion, endpointsJson) }

  fun groupAddMember(
    groupId: String,
    peerId: String,
    capsJson: String? = null,
    endpointsJson: String? = null,
  ): String =
    withHandle { TendrilNative.groupAddMember(it, groupId, peerId, capsJson, endpointsJson) }

  fun groupRemoveMember(groupId: String, peerId: String): String =
    withHandle { TendrilNative.groupRemoveMember(it, groupId, peerId) }

  /** Ingests a manifest received from the authenticated peer [senderPeerId]; returns its group id. */
  fun groupIngestManifest(manifestJson: String, senderPeerId: String): String =
    withHandle { TendrilNative.groupIngestManifest(it, manifestJson, senderPeerId) }

  /**
   * Opens the group pool. A non-null [listenAddr] also binds a direct listener the group serves
   * (see [TendrilGroup.localEndpoint]). Configure transports before the first call; afterwards inbound sessions
   * are routed through the group hub and ordinary sessions still arrive through [acceptSession]. Call
   * [serveRelay] before the first call too: the hub leaves the relay hosts served that way to the endpoint only
   * for calls that returned before it, and a later [serveRelay] on a relay host in the member's own entry
   * competes with the group.
   */
  fun openGroup(groupId: String, listenAddr: String? = null): TendrilGroup =
    withHandle { TendrilGroup(TendrilNative.groupOpen(it, groupId, listenAddr)) }

  override fun close() {
    lock.read {
      val ptr = handleValue
      if (ptr != 0L) {
        TendrilNative.endpointClose(ptr)
      }
    }
    lock.write {
      val ptr = handleValue
      if (ptr != 0L) {
        handleValue = 0L
        TendrilNative.endpointFree(ptr)
      }
    }
  }
}

class TendrilSession internal constructor(handle: Long) : Closeable {
  private val lock = ReentrantReadWriteLock()
  private var handleValue: Long = handle

  private inline fun <T> withHandle(fn: (Long) -> T): T =
    lock.read {
      val ptr = handleValue
      check(ptr != 0L) { "TendrilSession is closed" }
      fn(ptr)
    }

  fun sendData(payload: ByteArray) =
    withHandle { TendrilNative.sessionSendData(it, payload) }

  fun pollEvent(timeoutMs: Long): String =
    withHandle { TendrilNative.sessionPollEvent(it, timeoutMs) }

  fun authorize(requestedCap: String): Boolean =
    withHandle { TendrilNative.sessionAuthorize(it, requestedCap) }

  fun rekey() =
    withHandle { TendrilNative.sessionRekey(it) }

  fun closeSession(code: Int = 1000, reason: String = "") =
    withHandle { TendrilNative.sessionClose(it, code, reason) }

  override fun close() {
    lock.read {
      val ptr = handleValue
      if (ptr != 0L) {
        TendrilNative.sessionShutdown(ptr)
      }
    }
    lock.write {
      val ptr = handleValue
      if (ptr != 0L) {
        handleValue = 0L
        TendrilNative.sessionFree(ptr)
      }
    }
  }
}

class TendrilGroup internal constructor(handle: Long) : Closeable {
  private val lock = ReentrantReadWriteLock()
  private var handleValue: Long = handle

  private inline fun <T> withHandle(fn: (Long) -> T): T =
    lock.read {
      val ptr = handleValue
      check(ptr != 0L) { "TendrilGroup is closed" }
      fn(ptr)
    }

  /** Sends [data] to every reachable member and returns the `{delivered, offline, failed}` JSON. */
  fun broadcast(data: ByteArray, requiredCap: String? = null): String =
    withHandle { TendrilNative.groupBroadcast(it, requiredCap, data) }

  /**
   * Pushes the stored manifest (and, for an admin, the rendezvous key) to members and returns the
   * report JSON. Wire v2 groups need it; the runtime refuses non-admins.
   */
  fun sync(): String = withHandle { TendrilNative.groupSync(it) }

  /** Returns the endpoint bound by `listenAddr` at open time, or null when none was requested. */
  fun localEndpoint(): String? = withHandle { TendrilNative.groupLocalEndpoint(it) }

  /**
   * Waits up to [timeoutMs] for the next event JSON (`app_data`, `manifest_updated`,
   * `member_joined`, `member_revoked`, `audit`) and returns null on timeout. Throws once the pool
   * is closed, and a call parked in the wait throws promptly when [close] is called.
   */
  fun pollEvent(timeoutMs: Long): String? =
    withHandle { TendrilNative.groupPollEvent(it, timeoutMs) }

  /** Throws unless [peerId] currently holds [cap] in the group. */
  fun authorizePeer(peerId: String, cap: String) =
    withHandle { TendrilNative.groupAuthorizePeer(it, peerId, cap) }

  override fun close() {
    lock.read {
      val ptr = handleValue
      if (ptr != 0L) {
        TendrilNative.groupClose(ptr)
      }
    }
    lock.write {
      val ptr = handleValue
      if (ptr != 0L) {
        handleValue = 0L
        TendrilNative.groupFree(ptr)
      }
    }
  }
}
