package dev.tendril

import java.io.Closeable
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.withLock
import kotlin.concurrent.write

class TendrilEndpoint private constructor(handle: Long) : Closeable {
  private val lock = ReentrantReadWriteLock()
  private var handleValue: Long = handle

  companion object {
    @JvmStatic
    fun create(stateDir: String? = null, hostId: String? = null): TendrilEndpoint {
      return TendrilEndpoint(TendrilNative.endpointNew(stateDir, hostId))
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

  fun confirmPeer(peerId: String, sas: String? = null) =
    withHandle { TendrilNative.endpointConfirmPeer(it, peerId, sas) }

  fun mintGrant(peerId: String, capsJson: String, ttlSecs: Long = 3600): String =
    withHandle { TendrilNative.endpointMintGrant(it, peerId, capsJson, ttlSecs) }

  fun revokePeer(peerId: String) =
    withHandle { TendrilNative.endpointRevokePeer(it, peerId) }

  fun connect(
    endpoint: String,
    relayHost: String? = null,
    targetHostId: String,
    grantJson: String? = null,
  ): TendrilSession =
    withHandle {
      val ptr = TendrilNative.sessionConnect(it, endpoint, relayHost, targetHostId, grantJson)
      TendrilSession(ptr)
    }

  fun acceptSession(timeoutMs: Long): TendrilSession =
    withHandle { TendrilSession(TendrilNative.sessionAccept(it, timeoutMs)) }

  override fun close() {
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
  private val lock = ReentrantLock()
  private var handleValue: Long = handle

  private inline fun <T> withHandle(fn: (Long) -> T): T =
    lock.withLock {
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
    lock.withLock {
      val ptr = handleValue
      if (ptr != 0L) {
        handleValue = 0L
        TendrilNative.sessionFree(ptr)
      }
    }
  }
}
