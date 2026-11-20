package dev.tendril

import java.io.Closeable
import java.util.concurrent.atomic.AtomicLong

class TendrilEndpoint private constructor(handle: Long) : Closeable {
  private val handleRef = AtomicLong(handle)

  companion object {
    @JvmStatic
    fun create(stateDir: String? = null, hostId: String? = null): TendrilEndpoint {
      return TendrilEndpoint(TendrilNative.endpointNew(stateDir, hostId))
    }

    @JvmStatic fun deviceId(staticPub: ByteArray): String = TendrilNative.deviceId(staticPub)

    @JvmStatic fun fingerprintHost(staticPub: ByteArray): String = TendrilNative.fingerprintHost(staticPub)

    @JvmStatic fun fingerprintDevice(staticPub: ByteArray): String = TendrilNative.fingerprintDevice(staticPub)

    @JvmStatic fun pairingSas(handshakeHash: ByteArray): String = TendrilNative.pairingSas(handshakeHash)

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

  private fun requireHandle(): Long {
    val ptr = handleRef.get()
    check(ptr != 0L) { "TendrilEndpoint is closed" }
    return ptr
  }

  fun infoJson(): String = TendrilNative.endpointInfoJson(requireHandle())

  fun serveDirect(listenAddr: String = "127.0.0.1:0"): String =
    TendrilNative.endpointServeDirect(requireHandle(), listenAddr)

  fun serveRelay(relayUrl: String, expectedHost: String? = null): String =
    TendrilNative.endpointServeRelay(requireHandle(), relayUrl, expectedHost)

  fun issueCode(kind: String = "remote"): String =
    TendrilNative.endpointIssueCode(requireHandle(), kind)

  fun pairInitiate(
    endpoint: String,
    relayHost: String? = null,
    code: String,
    deviceName: String,
    deviceKind: String = "android",
  ): String =
    TendrilNative.endpointPairInitiate(
      requireHandle(),
      endpoint,
      relayHost,
      code,
      deviceName,
      deviceKind,
    )

  fun pairAccept(timeoutMs: Long): String =
    TendrilNative.endpointPairAccept(requireHandle(), timeoutMs)

  fun confirmPeer(peerId: String, sas: String? = null) {
    TendrilNative.endpointConfirmPeer(requireHandle(), peerId, sas)
  }

  fun mintGrant(peerId: String, capsJson: String, ttlSecs: Long = 3600): String =
    TendrilNative.endpointMintGrant(requireHandle(), peerId, capsJson, ttlSecs)

  fun revokePeer(peerId: String) {
    TendrilNative.endpointRevokePeer(requireHandle(), peerId)
  }

  fun connect(
    endpoint: String,
    relayHost: String? = null,
    targetHostId: String,
    grantJson: String? = null,
  ): TendrilSession {
    val ptr =
      TendrilNative.sessionConnect(
        requireHandle(),
        endpoint,
        relayHost,
        targetHostId,
        grantJson,
      )
    return TendrilSession(ptr)
  }

  fun acceptSession(timeoutMs: Long): TendrilSession {
    return TendrilSession(TendrilNative.sessionAccept(requireHandle(), timeoutMs))
  }

  override fun close() {
    val ptr = handleRef.getAndSet(0L)
    if (ptr != 0L) {
      TendrilNative.endpointFree(ptr)
    }
  }
}

class TendrilSession internal constructor(handle: Long) : Closeable {
  private val handleRef = AtomicLong(handle)

  private fun requireHandle(): Long {
    val ptr = handleRef.get()
    check(ptr != 0L) { "TendrilSession is closed" }
    return ptr
  }

  fun sendData(payload: ByteArray) {
    TendrilNative.sessionSendData(requireHandle(), payload)
  }

  fun pollEvent(timeoutMs: Long): String = TendrilNative.sessionPollEvent(requireHandle(), timeoutMs)

  fun authorize(requestedCap: String): Boolean =
    TendrilNative.sessionAuthorize(requireHandle(), requestedCap)

  fun rekey() {
    TendrilNative.sessionRekey(requireHandle())
  }

  fun closeSession(code: Int = 1000, reason: String = "") {
    TendrilNative.sessionClose(requireHandle(), code, reason)
  }

  override fun close() {
    val ptr = handleRef.getAndSet(0L)
    if (ptr != 0L) {
      TendrilNative.sessionFree(ptr)
    }
  }
}
