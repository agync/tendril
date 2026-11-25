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
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/** Route policy applied to signed route material (`all_signed` is the default). */
enum class RoutePolicy(internal val wire: String) {
  ALL_SIGNED("all_signed"),
  COMMITTED_ONLY("committed_only"),
  NONE("none"),
}

/** Whether a host advertises enumerated LAN and overlay addresses (`auto`, the default). */
enum class Advertise(internal val wire: String) {
  AUTO("auto"),
  EXPLICIT("explicit"),
}

/** Which stored routes [TendrilEndpoint.clearPeerRoutes] removes. */
enum class RouteSource(internal val wire: String) {
  OPERATOR("operator"),
  SIGNED("signed"),
  COMMITTED("committed"),
  ALL("all"),
}

/** A pre-encoded JSON value embedded as is. */
internal class RawJson(val json: String)

private fun jsonQuote(value: String): String {
  val sb = StringBuilder(value.length + 2).append('"')
  for (c in value) {
    when {
      c == '"' -> sb.append("\\\"")
      c == '\\' -> sb.append("\\\\")
      c < ' ' -> sb.append(String.format(Locale.ROOT, "\\u%04x", c.code))
      else -> sb.append(c)
    }
  }
  return sb.append('"').toString()
}

/**
 * The `grant` option for [grantJson]: null for null or blank input, otherwise the text itself when
 * it is exactly one complete, strictly valid JSON object (RFC 8259: no trailing commas, unquoted
 * keys, single quotes, comments, control characters or trailing tokens). Anything else throws
 * [IllegalArgumentException], so a crafted grant cannot add keys to the options object and the
 * native parser never sees text this check would not accept.
 */
internal fun grantOption(grantJson: String?): RawJson? {
  val text = grantJson?.trim()?.takeIf { it.isNotEmpty() } ?: return null
  require(StrictJson(text).isSingleObject()) { "grantJson must be one JSON object" }
  return RawJson(text)
}

/** A strict RFC 8259 validator: accepts exactly one object and nothing else. */
private class StrictJson(private val s: String) {
  private var i = 0

  fun isSingleObject(): Boolean =
    try {
      s.startsWith("{") && value(0) && i == s.length
    } catch (_: IndexOutOfBoundsException) {
      false
    }

  private fun ws() {
    while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
  }

  private fun value(depth: Int): Boolean {
    if (depth > 128) return false
    ws()
    val ok =
      when (s[i]) {
        '{' -> obj(depth)
        '[' -> arr(depth)
        '"' -> str()
        't' -> lit("true")
        'f' -> lit("false")
        'n' -> lit("null")
        else -> num()
      }
    if (ok) ws()
    return ok
  }

  private fun lit(word: String): Boolean {
    if (!s.startsWith(word, i)) return false
    i += word.length
    return true
  }

  private fun obj(depth: Int): Boolean {
    i++
    ws()
    if (s[i] == '}') {
      i++
      return true
    }
    while (true) {
      ws()
      if (s[i] != '"' || !str()) return false
      ws()
      if (s[i++] != ':') return false
      if (!value(depth + 1)) return false
      when (s[i++]) {
        ',' -> continue
        '}' -> return true
        else -> return false
      }
    }
  }

  private fun arr(depth: Int): Boolean {
    i++
    ws()
    if (s[i] == ']') {
      i++
      return true
    }
    while (true) {
      if (!value(depth + 1)) return false
      when (s[i++]) {
        ',' -> continue
        ']' -> return true
        else -> return false
      }
    }
  }

  private fun str(): Boolean {
    i++
    while (true) {
      val c = s[i++]
      when {
        c == '"' -> return true
        c < ' ' -> return false
        c == '\\' ->
          when (s[i++]) {
            '"', '\\', '/', 'b', 'f', 'n', 'r', 't' -> {}
            'u' -> {
              repeat(4) { if (Character.digit(s[i++], 16) < 0) return false }
            }
            else -> return false
          }
      }
    }
  }

  private fun digits(): Boolean {
    val start = i
    while (i < s.length && s[i] in '0'..'9') i++
    return i > start
  }

  private fun num(): Boolean {
    if (s[i] == '-') i++
    if (s[i] == '0') i++ else if (!digits()) return false
    if (i < s.length && s[i] == '.') {
      i++
      if (!digits()) return false
    }
    if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
      i++
      if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
      if (!digits()) return false
    }
    return true
  }
}

/**
 * The last full transport configuration a binding sent. The C ABI replaces the whole
 * configuration on every call, so [merge] layers keys over this cache and sends the result. The
 * cache changes only after the send succeeds.
 *
 * The cache holds the configuration as plain JVM objects, secrets included (`relay_auth_secret`,
 * `p2p_api_secret`, `wake_secret_b64`, `relay_ticket`). The JVM cannot zeroize them, so the
 * endpoint [clear]s the cache on close and the copy lives no longer than the endpoint.
 */
internal class TransportConfigCache {
  private val lock = Any()
  private var config: JSONObject? = null

  /** The cached configuration as JSON, or null when none was sent. */
  fun current(): String? = synchronized(lock) { config?.toString() }

  /** Sends [json] as the whole configuration through [send] and caches it on success. */
  fun replace(json: String, send: (String) -> Unit) =
    synchronized(lock) {
      // Parse before sending: text the cache cannot hold must not reach the native side, or a
      // later merge would silently drop the keys it carried.
      val parsed =
        try {
          JSONObject(json)
        } catch (e: JSONException) {
          throw IllegalArgumentException("transport configuration must be one JSON object", e)
        }
      send(json)
      config = parsed
    }

  /** Drops the cached configuration (and the secrets in it). */
  fun clear() = synchronized(lock) { config = null }

  /** Sends the cached configuration with [keys] set over it, and caches that on success. */
  fun merge(keys: Map<String, Any>, send: (String) -> Unit) =
    synchronized(lock) {
      val merged = JSONObject(config?.toString() ?: "{}")
      for ((k, v) in keys) {
        merged.put(k, if (v is Iterable<*>) JSONArray(v.toList()) else v)
      }
      send(merged.toString())
      config = merged
    }
}

private fun jsonValue(value: Any): String =
  when (value) {
    is String -> jsonQuote(value)
    is Boolean,
    is Number -> value.toString()
    is RawJson -> value.json
    is Iterable<*> -> value.joinToString(",", "[", "]") { jsonValue(requireNotNull(it)) }
    else -> throw IllegalArgumentException("unsupported json value: ${value::class.java.name}")
  }

/** Encodes the non-null [fields] as a JSON object, or null when every field is null. */
internal fun optionsJson(vararg fields: Pair<String, Any?>): String? {
  val present = fields.filter { it.second != null }
  if (present.isEmpty()) return null
  return present.joinToString(",", "{", "}") { (k, v) -> "${jsonQuote(k)}:${jsonValue(v!!)}" }
}

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
  private val transportConfig = TransportConfigCache()

  /** The last full transport configuration sent, as JSON; null before any. */
  internal fun transportConfigJson(): String? = transportConfig.current()

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

  /** Replaces the whole transport configuration; [configureRoutes] merges into what this sets. */
  fun configureTransportsJson(transportConfigJson: String) =
    transportConfig.replace(transportConfigJson) { json ->
      withHandle { TendrilNative.endpointConfigureTransportsJson(it, json) }
    }

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

  /**
   * Connects to [targetHostId] over Wire v1. A null or empty [endpoint] dials the peer's stored
   * routes; a non-empty one is an explicit operator endpoint dialed alone. Route sets from the
   * host are ingested under the endpoint's route policy.
   */
  fun connect(
    endpoint: String? = null,
    relayHost: String? = null,
    targetHostId: String,
    grantJson: String? = null,
  ): TendrilSession =
    withHandle {
      TendrilSession(TendrilNative.sessionConnect(it, endpoint, relayHost, targetHostId, grantJson))
    }

  /**
   * Connects to [targetHostId] with options. [recoveryUri] is a pairing URI whose keys are checked
   * before the session handshake; a signed one replaces the stored `signed` routes when its `rq`
   * is newer, or always with [replaceRoutes]. A null [wire] means Wire v1. [relayHost] is the
   * expected relay host of an explicit [endpoint] (the Iroh relay mode for `iroh://`).
   */
  fun connectWithOptions(
    targetHostId: String,
    wire: Int? = null,
    grantJson: String? = null,
    endpoint: String? = null,
    recoveryUri: String? = null,
    replaceRoutes: Boolean? = null,
    routePolicy: RoutePolicy? = null,
    relayHost: String? = null,
  ): TendrilSession {
    val options =
      optionsJson(
        "wire" to wire,
        "grant" to grantOption(grantJson),
        "endpoint" to endpoint,
        "recovery_uri" to recoveryUri,
        "replace_routes" to replaceRoutes,
        "route_policy" to routePolicy?.wire,
        "relay_host" to relayHost,
      )
    return withHandle {
      TendrilSession(TendrilNative.sessionConnectWithOptions(it, targetHostId, options))
    }
  }

  /**
   * Issues a signed pairing URI from the announced route set and returns
   * `{uri, code_kind, dropped, uri_len, qr_version_m, route_seq}`. [kind] is `auto`, `lan` or
   * `remote`. Add hints through [configureRoutes] `advertisedEndpoints`.
   */
  fun issuePairingUri(
    kind: String? = null,
    hostName: String? = null,
    signRoutes: Boolean? = null,
  ): String {
    val options = optionsJson("kind" to kind, "host_name" to hostName, "sign_routes" to signRoutes)
    return withHandle { TendrilNative.endpointIssuePairingUri(it, options) }
  }

  /**
   * Pairs over Wire v1 from a scanned [pairingUri] (the exact scanned string). An [endpoint] is
   * dialed alone and stored as an `operator` route.
   */
  fun pairUri(
    pairingUri: String,
    deviceName: String? = null,
    deviceKind: String? = "android",
    routePolicy: RoutePolicy? = null,
    saveRoute: Boolean? = null,
    endpoint: String? = null,
    code: String? = null,
  ): String {
    val options =
      optionsJson(
        "route_policy" to routePolicy?.wire,
        "save_route" to saveRoute,
        "endpoint" to endpoint,
        "code" to code,
      )
    return withHandle {
      TendrilNative.endpointPairUri(it, pairingUri, deviceName, deviceKind, options)
    }
  }

  /** As [pairUri] over Wire v2: rungs are tried one at a time. */
  fun pairV2Uri(
    pairingUri: String,
    deviceName: String? = null,
    deviceKind: String? = "android",
    routePolicy: RoutePolicy? = null,
    saveRoute: Boolean? = null,
    endpoint: String? = null,
    code: String? = null,
  ): String {
    val options =
      optionsJson(
        "route_policy" to routePolicy?.wire,
        "save_route" to saveRoute,
        "endpoint" to endpoint,
        "code" to code,
      )
    return withHandle {
      TendrilNative.endpointPairV2Uri(it, pairingUri, deviceName, deviceKind, options)
    }
  }

  /** Replaces the `operator` routes of [peerId] (at most six); one bad entry writes nothing. */
  fun setPeerRoutes(peerId: String, routes: List<String>) =
    withHandle { TendrilNative.endpointSetPeerRoutes(it, peerId, jsonValue(routes)) }

  /** Returns `{routes: [{hint, source}], route_meta, last_route_set}` for [peerId]. */
  fun peerRoutes(peerId: String): String =
    withHandle { TendrilNative.endpointPeerRoutes(it, peerId) }

  /** Clears stored routes of [peerId]; a null [source] clears the `operator` routes. */
  fun clearPeerRoutes(peerId: String, source: RouteSource? = null) =
    withHandle { TendrilNative.endpointClearPeerRoutes(it, peerId, source?.wire) }

  /** Applies a fresh signed pairing URI offline to the paired host it names. */
  fun applyRouteUri(
    pairingUri: String,
    replaceRoutes: Boolean? = null,
    routePolicy: RoutePolicy? = null,
  ): String {
    val options =
      optionsJson("replace_routes" to replaceRoutes, "route_policy" to routePolicy?.wire)
    return withHandle { TendrilNative.endpointApplyRouteUri(it, pairingUri, options) }
  }

  /**
   * Re-scans the host's routes and returns `{route_seq, changed}`. [snapshotJson] is null (the
   * runtime reuses the last snapshot on Android) or the complete network snapshot
   * `{"networks": [{id, iface, if_index, transports, addrs}]}`, never a delta.
   * [TendrilForegroundService] builds and passes it from `ConnectivityManager`.
   */
  fun refreshRoutes(snapshotJson: String? = null): String =
    withHandle { TendrilNative.endpointRefreshRoutes(it, snapshotJson) }

  /**
   * Sets the pairing-URI and route keys of the transport configuration, keeping every other key
   * (relay credentials, P2P, wake) of the last configuration sent.
   */
  fun configureRoutes(
    advertisedEndpoints: List<String>? = null,
    relayAuthOrigins: List<String>? = null,
    advertise: Advertise? = null,
    routePolicy: RoutePolicy? = null,
    signRoutes: Boolean? = null,
  ) {
    val keys =
      listOf(
          "advertised_endpoints" to advertisedEndpoints,
          "relay_auth_origins" to relayAuthOrigins,
          "advertise" to advertise?.wire,
          "route_policy" to routePolicy?.wire,
          "sign_routes" to signRoutes,
        )
        .mapNotNull { (k, v) -> v?.let { k to it } }
        .toMap()
    if (keys.isEmpty()) return
    transportConfig.merge(keys) { json ->
      withHandle { TendrilNative.endpointConfigureTransportsJson(it, json) }
    }
  }

  fun acceptSession(timeoutMs: Long): TendrilSession =
    withHandle { TendrilSession(TendrilNative.sessionAccept(it, timeoutMs)) }

  fun connectV2(
    endpoint: String? = null,
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
    transportConfig.clear()
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

  /** Authenticated roster peer identifier of this session. Evaluate capabilities separately via [authorize]. */
  fun peerId(): String =
    withHandle { TendrilNative.sessionPeerId(it) }

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
