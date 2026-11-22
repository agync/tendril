package dev.tendril

import java.io.Closeable
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

internal class SealedStateStore(dirPath: String, private val cipher: KeystoreStateCipher) {
  companion object {
    private const val IDENTITY_FILE = "identity.sealed"
    private const val ROSTER_FILE = "roster.sealed"
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
      Files.write(tmp, sealed)
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

  fun loadRosterJson(): String? = synchronized(ioLock) { readSealed(ROSTER_FILE, ROSTER_AAD) }

  fun saveRoster(exportJson: () -> String) =
    synchronized(ioLock) { writeSealed(ROSTER_FILE, exportJson(), ROSTER_AAD) }
}

class TendrilEndpoint private constructor(
  handle: Long,
  private val stateStore: SealedStateStore?,
) : Closeable {
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
        return TendrilEndpoint(TendrilNative.endpointNewFromState(null, null, hostId), null)
      }
      val store = SealedStateStore(dir, stateCipher ?: KeystoreStateCipher())
      val existingIdentity = store.loadIdentityJson()
      val existingRoster = store.loadRosterJson()
      val ptr = TendrilNative.endpointNewFromState(existingIdentity, existingRoster, hostId)
      try {
        if (existingIdentity == null) {
          store.saveIdentityJson(TendrilNative.endpointExportIdentityJson(ptr))
        }
        if (existingRoster == null) {
          store.saveRoster { TendrilNative.endpointExportRosterJson(ptr) }
        }
      } catch (t: Throwable) {
        TendrilNative.endpointFree(ptr)
        throw t
      }
      return TendrilEndpoint(ptr, store)
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

  private fun persistRoster(ptr: Long) {
    val store = stateStore ?: return
    store.saveRoster { TendrilNative.endpointExportRosterJson(ptr) }
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
      val out = TendrilNative.endpointPairInitiate(it, endpoint, relayHost, code, deviceName, deviceKind)
      persistRoster(it)
      out
    }

  fun pairAccept(timeoutMs: Long): String =
    withHandle {
      try {
        val out = TendrilNative.endpointPairAccept(it, timeoutMs)
        persistRoster(it)
        out
      } catch (t: Throwable) {
        try {
          persistRoster(it)
        } catch (pe: Throwable) {
          t.addSuppressed(pe)
        }
        throw t
      }
    }

  fun pairV2Initiate(
    endpoint: String,
    relayHost: String? = null,
    code: String,
    deviceName: String,
    deviceKind: String = "android",
    pinnedHostJson: String? = null,
  ): String =
    withHandle {
      val out =
        TendrilNative.endpointPairV2Initiate(
          it,
          endpoint,
          relayHost,
          code,
          deviceName,
          deviceKind,
          pinnedHostJson,
        )
      persistRoster(it)
      out
    }

  fun pairV2Accept(timeoutMs: Long): String =
    withHandle {
      try {
        val out = TendrilNative.endpointPairV2Accept(it, timeoutMs)
        persistRoster(it)
        out
      } catch (t: Throwable) {
        try {
          persistRoster(it)
        } catch (pe: Throwable) {
          t.addSuppressed(pe)
        }
        throw t
      }
    }

  fun confirmPeer(peerId: String, sas: String? = null) =
    withHandle {
      TendrilNative.endpointConfirmPeer(it, peerId, sas)
      persistRoster(it)
    }

  fun mintGrant(peerId: String, capsJson: String, ttlSecs: Long = 3600): String =
    withHandle {
      val out = TendrilNative.endpointMintGrant(it, peerId, capsJson, ttlSecs)
      persistRoster(it)
      out
    }

  fun revokePeer(peerId: String) =
    withHandle {
      TendrilNative.endpointRevokePeer(it, peerId)
      persistRoster(it)
    }

  fun addTrustAnchor(anchorId: String, signingPub: ByteArray) =
    withHandle {
      TendrilNative.endpointAddTrustAnchor(it, anchorId, signingPub)
      persistRoster(it)
    }

  fun revokeTrustAnchor(anchorId: String) =
    withHandle {
      TendrilNative.endpointRevokeTrustAnchor(it, anchorId)
      persistRoster(it)
    }

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
      val out =
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
      persistRoster(it)
      out
    }

  fun connect(
    endpoint: String,
    relayHost: String? = null,
    targetHostId: String,
    grantJson: String? = null,
  ): TendrilSession =
    withHandle {
      var sessionPtr = 0L
      try {
        sessionPtr = TendrilNative.sessionConnect(it, endpoint, relayHost, targetHostId, grantJson)
        persistRoster(it)
        val ownedPtr = sessionPtr
        sessionPtr = 0L
        TendrilSession(ownedPtr, stateStore)
      } catch (t: Throwable) {
        if (sessionPtr != 0L) {
          try {
            TendrilNative.sessionFree(sessionPtr)
          } catch (freeErr: Throwable) {
            t.addSuppressed(freeErr)
          }
        } else {
          try {
            persistRoster(it)
          } catch (pe: Throwable) {
            t.addSuppressed(pe)
          }
        }
        throw t
      }
    }

  fun acceptSession(timeoutMs: Long): TendrilSession =
    withHandle { TendrilSession(TendrilNative.sessionAccept(it, timeoutMs), stateStore) }

  fun connectV2(
    endpoint: String,
    relayHost: String? = null,
    targetHostId: String,
    grantJson: String? = null,
  ): TendrilSession =
    withHandle {
      var sessionPtr = 0L
      try {
        sessionPtr = TendrilNative.sessionConnectV2(it, endpoint, relayHost, targetHostId, grantJson)
        persistRoster(it)
        val ownedPtr = sessionPtr
        sessionPtr = 0L
        TendrilSession(ownedPtr, stateStore)
      } catch (t: Throwable) {
        if (sessionPtr != 0L) {
          try {
            TendrilNative.sessionFree(sessionPtr)
          } catch (freeErr: Throwable) {
            t.addSuppressed(freeErr)
          }
        } else {
          try {
            persistRoster(it)
          } catch (pe: Throwable) {
            t.addSuppressed(pe)
          }
        }
        throw t
      }
    }

  fun acceptV2(timeoutMs: Long): TendrilSession =
    withHandle {
      var sessionPtr = 0L
      try {
        sessionPtr = TendrilNative.sessionAcceptV2(it, timeoutMs)
        persistRoster(it)
        val ownedPtr = sessionPtr
        sessionPtr = 0L
        TendrilSession(ownedPtr, stateStore)
      } catch (t: Throwable) {
        if (sessionPtr != 0L) {
          try {
            TendrilNative.sessionFree(sessionPtr)
          } catch (freeErr: Throwable) {
            t.addSuppressed(freeErr)
          }
        } else {
          try {
            persistRoster(it)
          } catch (pe: Throwable) {
            t.addSuppressed(pe)
          }
        }
        throw t
      }
    }

  /**
   * Creates a group rooted at this endpoint and returns the signed manifest JSON. Group APIs are
   * not available on sealed mobile endpoints yet: they fail with an invalid-argument error
   * ("groups require a state directory endpoint"). [endpointsJson] is null or a JSON array of
   * strings.
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
   * are routed through the group hub and ordinary sessions still arrive through [acceptSession].
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

class TendrilSession internal constructor(
  handle: Long,
  private val stateStore: SealedStateStore? = null,
) : Closeable {
  private val lock = ReentrantReadWriteLock()
  private var handleValue: Long = handle
  @Volatile private var persistError: Throwable? = null

  private inline fun <T> withHandle(fn: (Long) -> T): T =
    lock.read {
      persistError?.let {
        throw IllegalStateException("TendrilSession locked after roster persistence failure", it)
      }
      val ptr = handleValue
      check(ptr != 0L) { "TendrilSession is closed" }
      fn(ptr)
    }

  private fun persistRoster(ptr: Long) {
    val store = stateStore ?: return
    store.saveRoster { TendrilNative.sessionExportRosterJson(ptr) }
  }

  fun sendData(payload: ByteArray) =
    withHandle { TendrilNative.sessionSendData(it, payload) }

  fun pollEvent(timeoutMs: Long): String {
    var shouldCloseOnPersistFailure = false
    try {
      return withHandle {
        try {
          val ev = TendrilNative.sessionPollEvent(it, timeoutMs)
          if (ev.contains("\"revocation_updated\"")) {
            try {
              persistRoster(it)
            } catch (pe: Throwable) {
              persistError = pe
              shouldCloseOnPersistFailure = true
              throw pe
            }
          }
          ev
        } catch (t: Throwable) {
          if (!shouldCloseOnPersistFailure) {
            try {
              persistRoster(it)
            } catch (pe: Throwable) {
              persistError = pe
              shouldCloseOnPersistFailure = true
              t.addSuppressed(pe)
            }
          }
          throw t
        }
      }
    } finally {
      if (shouldCloseOnPersistFailure) {
        try {
          close()
        } catch (_: Throwable) {}
      }
    }
  }

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
