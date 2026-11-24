package dev.tendril

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Log
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** One network of the snapshot passed to [TendrilEndpoint.refreshRoutes]. */
internal data class SnapshotNetwork(
  val id: String,
  val iface: String,
  val ifIndex: Int,
  val transports: List<String>,
  val addrs: List<String>,
)

/** Builds the complete multi-network snapshot JSON the runtime consumes on Android. */
internal object NetworkSnapshots {
  /** Transports of [caps] as the runtime names them; `other` when none is recognized. */
  fun transportsOf(caps: NetworkCapabilities?): List<String> {
    if (caps == null) return emptyList()
    val out = ArrayList<String>(2)
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) out += "wifi"
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) out += "ethernet"
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) out += "cellular"
    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) out += "vpn"
    if (out.isEmpty()) out += "other"
    return out
  }

  /** A network entry from its [link] properties, or null when the link has no interface name. */
  fun fromLink(id: String, link: LinkProperties, transports: List<String>): SnapshotNetwork? =
    fromAddresses(id, link.interfaceName, link.linkAddresses.mapNotNull { it.address }, transports)

  /** A network entry from an interface name and its addresses, or null without a name. */
  fun fromAddresses(
    id: String,
    iface: String?,
    addresses: List<InetAddress>,
    transports: List<String>,
  ): SnapshotNetwork? {
    val name = iface?.takeIf { it.isNotEmpty() } ?: return null
    val index =
      try {
        NetworkInterface.getByName(name)?.index ?: 0
      } catch (_: Exception) {
        0
      }
    return SnapshotNetwork(id, name, index, transports, addresses.mapNotNull { it.hostAddress })
  }

  /** `{"networks": [...]}` for the whole set; an empty set is a valid, complete snapshot. */
  fun toJson(networks: List<SnapshotNetwork>): String =
    networks.joinToString(",", "{\"networks\":[", "]}") { n ->
      optionsJson(
        "id" to n.id,
        "iface" to n.iface,
        "if_index" to n.ifIndex,
        "transports" to n.transports,
        "addrs" to n.addrs,
      )!!
    }
}

/**
 * The live network map. Callbacks and seeding mutate it under one lock, so a seed read cannot
 * overwrite what a callback delivered after it, and a failed seed leaves the map as it was.
 */
internal class NetworkMap<K : Any, L : Any, C : Any> {
  class Entry<L : Any, C : Any>(var link: L? = null, var caps: C? = null)

  private val lock = Any()
  private val entries = LinkedHashMap<K, Entry<L, C>>()
  private val removedDuringSeed = mutableListOf<MutableSet<K>>()
  private var known = false

  /** True once a callback or a successful seed has filled the map, so an empty map means no networks. */
  fun isKnown(): Boolean = synchronized(lock) { known }

  /** Applies a callback [change] to [key]'s entry, creating it when new. */
  fun update(key: K, change: (Entry<L, C>) -> Unit) =
    synchronized(lock) {
      known = true
      change(entries.getOrPut(key) { Entry() })
    }

  fun remove(key: K) =
    synchronized(lock) {
      known = true
      removedDuringSeed.forEach { it.add(key) }
      entries.remove(key)
    }

  /**
   * Seeds from [readAll], which runs outside the lock (it may make binder calls); the result is
   * merged under the lock, so callback updates serialize with the merge. A network a callback
   * reported lost while the read ran stays dropped. With [callbacksLive] a network a callback
   * already filled keeps those fresher values and only missing fields are taken from the seed;
   * without callbacks the seed overwrites. Networks the seed no longer lists are dropped. When
   * [readAll] throws a [SecurityException] the map is left unchanged and this returns false.
   */
  fun seed(callbacksLive: Boolean, readAll: () -> List<Triple<K, L?, C?>>): Boolean {
    val lost = mutableSetOf<K>()
    synchronized(lock) { removedDuringSeed.add(lost) }
    try {
      val seeded =
        try {
          readAll()
        } catch (e: SecurityException) {
          Log.w("TendrilService", "network enumeration not permitted: ${e.message}")
          return false
        }
      synchronized(lock) {
        entries.keys.retainAll(seeded.map { it.first }.toSet())
        for ((key, link, caps) in seeded) {
          if (key in lost) continue
          val entry = entries.getOrPut(key) { Entry() }
          if (link != null && (!callbacksLive || entry.link == null)) entry.link = link
          if (caps != null && (!callbacksLive || entry.caps == null)) entry.caps = caps
        }
        known = true
      }
      return true
    } finally {
      synchronized(lock) { removedDuringSeed.remove(lost) }
    }
  }

  /** The entries that have both link properties and capabilities, copied under the lock. */
  fun complete(): List<Triple<K, L, C>> =
    synchronized(lock) {
      entries.mapNotNull { (key, e) ->
        val link = e.link
        val caps = e.caps
        if (link == null || caps == null) null else Triple(key, link, caps)
      }
    }
}

/** Runs every step even when earlier ones throw; the first failure is rethrown at the end. */
internal fun runAllGuarded(vararg steps: () -> Unit) {
  var first: Throwable? = null
  for (step in steps) {
    try {
      step()
    } catch (t: Throwable) {
      if (first == null) first = t else if (t !== first) first.addSuppressed(t)
    }
  }
  first?.let { throw it }
}

/**
 * Keeps the foreground notification, reports the default network's transport, and feeds a host
 * endpoint the complete multi-network snapshot it needs to advertise LAN and overlay addresses.
 *
 * Attach the host endpoint with [LocalBinder.attachEndpoint] before issuing the first pairing
 * URI. The service seeds its network map from `ConnectivityManager.allNetworks`, then keeps it
 * from an all-networks callback (VPN networks included) and passes the whole map to
 * [TendrilEndpoint.refreshRoutes] after every change. A 60 s timer refreshes with no snapshot,
 * which reuses the retained one.
 */
class TendrilForegroundService : Service() {
  enum class NetworkTransportKind {
    WIFI,
    CELLULAR,
    OTHER,
    NONE,
  }

  fun interface PathTransitionListener {
    fun onPathChanged(transport: NetworkTransportKind)
  }

  inner class LocalBinder : Binder() {
    fun setPathTransitionListener(listener: PathTransitionListener?) {
      transitionListener = listener
    }

    fun currentTransport(): NetworkTransportKind = activeTransport

    /**
     * Makes [endpoint] the route host this service refreshes (null detaches). Seeds the network
     * map and refreshes once before returning, so call it off the main thread.
     */
    fun attachEndpoint(endpoint: TendrilEndpoint?) {
      this@TendrilForegroundService.attachEndpoint(endpoint)
    }

    /** The complete network snapshot JSON the service would pass to the endpoint now. */
    fun currentSnapshotJson(): String = snapshotJson()
  }

  companion object {
    const val CHANNEL_ID = "tendril.session.channel"
    const val NOTIFICATION_ID = 7401
    private const val TAG = "TendrilService"
    private const val TIMER_SECONDS = 60L
  }

  private val binder = LocalBinder()
  private var connectivityManager: ConnectivityManager? = null
  private var callback: ConnectivityManager.NetworkCallback? = null
  @Volatile private var allNetworksCallback: ConnectivityManager.NetworkCallback? = null

  private val networks = NetworkMap<Network, LinkProperties, NetworkCapabilities>()
  private val refreshQueued = AtomicBoolean(false)
  @Volatile private var refresher: ScheduledExecutorService? = null

  @Volatile private var hostEndpoint: TendrilEndpoint? = null

  @Volatile private var transitionListener: PathTransitionListener? = null
  @Volatile private var activeTransport: NetworkTransportKind = NetworkTransportKind.NONE

  override fun onCreate() {
    super.onCreate()
    ensureNotificationChannel()
    val notification = buildForegroundNotification("Tendril encrypted link active")
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      startForeground(
        NOTIFICATION_ID,
        notification,
        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
      )
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }

    val cm = getSystemService(ConnectivityManager::class.java) ?: return
    connectivityManager = cm
    val netCallback =
      object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
          classifyAndNotify(cm.getNetworkCapabilities(network))
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
          classifyAndNotify(caps)
        }

        override fun onLost(network: Network) {
          val active = cm.activeNetwork
          val caps = if (active != null) cm.getNetworkCapabilities(active) else null
          classifyAndNotify(caps)
        }
      }
    callback = netCallback
    cm.registerDefaultNetworkCallback(netCallback)

    val executor =
      Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "tendril-route-refresh").apply { isDaemon = true }
      }
    refresher = executor
    executor.scheduleWithFixedDelay(
      { refreshNow(withSnapshot = false) },
      TIMER_SECONDS,
      TIMER_SECONDS,
      TimeUnit.SECONDS,
    )
    // Register before seeding: a network that appears or is lost during the seed reaches the map
    // through the callback instead of being missed.
    val allCallback =
      object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
          update(network) {}
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
          update(network) { it.caps = caps }
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
          update(network) { it.link = linkProperties }
        }

        override fun onLost(network: Network) {
          networks.remove(network)
          scheduleRefresh()
        }
      }
    allNetworksCallback = allCallback
    try {
      cm.registerNetworkCallback(
        NetworkRequest.Builder().removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),
        allCallback,
      )
    } catch (e: SecurityException) {
      Log.w(TAG, "network callback not permitted: ${e.message}")
      allNetworksCallback = null
    }
    seedNetworks(cm)
  }

  private fun update(
    network: Network,
    change: (NetworkMap.Entry<LinkProperties, NetworkCapabilities>) -> Unit,
  ) {
    networks.update(network, change)
    scheduleRefresh()
  }

  @Suppress("DEPRECATION")
  private fun seedNetworks(cm: ConnectivityManager): Boolean =
    networks.seed(callbacksLive = allNetworksCallback != null) {
      cm.allNetworks.map { n -> Triple(n, cm.getLinkProperties(n), cm.getNetworkCapabilities(n)) }
    }

  /** The whole current network map as the snapshot JSON; networks still missing data are left out. */
  internal fun snapshotJson(): String {
    // Interface index lookups run outside the map lock.
    val list =
      networks.complete().mapNotNull { (network, link, caps) ->
        NetworkSnapshots.fromLink(
          network.networkHandle.toString(),
          link,
          NetworkSnapshots.transportsOf(caps),
        )
      }
    return NetworkSnapshots.toJson(list)
  }

  private fun attachEndpoint(endpoint: TendrilEndpoint?) {
    hostEndpoint = endpoint
    if (endpoint != null) {
      connectivityManager?.let { seedNetworks(it) }
      // An empty map only means "no networks" once enumeration or a callback has filled it. When
      // enumeration was unavailable or denied, or the service is destroyed, a snapshot would
      // claim zero networks and retire every enumerated route, so refresh without one.
      refreshNow(withSnapshot = connectivityManager != null && networks.isKnown())
    }
  }

  private fun scheduleRefresh() {
    val executor = refresher ?: return
    if (hostEndpoint == null || !refreshQueued.compareAndSet(false, true)) return
    try {
      executor.execute {
        refreshQueued.set(false)
        refreshNow(withSnapshot = true)
      }
    } catch (_: java.util.concurrent.RejectedExecutionException) {
      refreshQueued.set(false)
    }
  }

  private fun refreshNow(withSnapshot: Boolean) {
    val endpoint = hostEndpoint ?: return
    try {
      endpoint.refreshRoutes(if (withSnapshot) snapshotJson() else null)
    } catch (e: Throwable) {
      Log.w(TAG, "route refresh failed: ${e.javaClass.simpleName} ${e.message}")
    }
  }

  override fun onBind(intent: Intent?): IBinder = binder

  override fun onDestroy() {
    val cm = connectivityManager
    val cb = callback
    val all = allNetworksCallback
    val executor = refresher
    callback = null
    allNetworksCallback = null
    connectivityManager = null
    hostEndpoint = null
    refresher = null
    try {
      runAllGuarded(
        { if (cm != null && cb != null) cm.unregisterNetworkCallback(cb) },
        { if (cm != null && all != null) cm.unregisterNetworkCallback(all) },
        { executor?.shutdownNow() },
      )
    } catch (e: Exception) {
      Log.w(TAG, "teardown failed: ${e.message}")
    } finally {
      super.onDestroy()
    }
  }

  private fun classifyAndNotify(caps: NetworkCapabilities?) {
    val next =
      when {
        caps == null -> NetworkTransportKind.NONE
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkTransportKind.WIFI
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkTransportKind.CELLULAR
        else -> NetworkTransportKind.OTHER
      }
    updateTransport(next)
  }

  private fun updateTransport(next: NetworkTransportKind) {
    if (activeTransport != next) {
      activeTransport = next
      transitionListener?.onPathChanged(next)
    }
  }

  private fun ensureNotificationChannel() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val mgr = getSystemService(NotificationManager::class.java)
      val channel =
        NotificationChannel(CHANNEL_ID, "Tendril Sessions", NotificationManager.IMPORTANCE_LOW)
      mgr?.createNotificationChannel(channel)
    }
  }

  private fun buildForegroundNotification(content: String): Notification {
    val builder =
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        Notification.Builder(this, CHANNEL_ID)
      } else {
        @Suppress("DEPRECATION") Notification.Builder(this)
      }
    return builder
      .setSmallIcon(android.R.drawable.stat_notify_sync)
      .setContentTitle("Tendril")
      .setContentText(content)
      .setOngoing(true)
      .build()
  }
}
