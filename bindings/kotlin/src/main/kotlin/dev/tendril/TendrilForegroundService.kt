package dev.tendril

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Binder
import android.os.Build
import android.os.IBinder

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
  }

  companion object {
    const val CHANNEL_ID = "tendril.session.channel"
    const val NOTIFICATION_ID = 7401
  }

  private val binder = LocalBinder()
  private var connectivityManager: ConnectivityManager? = null
  private var callback: ConnectivityManager.NetworkCallback? = null

  @Volatile private var transitionListener: PathTransitionListener? = null
  @Volatile private var activeTransport: NetworkTransportKind = NetworkTransportKind.NONE

  override fun onCreate() {
    super.onCreate()
    ensureNotificationChannel()
    val notification = buildForegroundNotification("Tendril encrypted link active")
    startForeground(NOTIFICATION_ID, notification)

    val cm = getSystemService(ConnectivityManager::class.java)
    connectivityManager = cm
    val req =
      NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build()
    val netCallback =
      object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
          classifyAndNotify(cm.getNetworkCapabilities(network))
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
          classifyAndNotify(caps)
        }

        override fun onLost(network: Network) {
          updateTransport(NetworkTransportKind.NONE)
        }
      }
    callback = netCallback
    cm?.registerNetworkCallback(req, netCallback)
  }

  override fun onBind(intent: Intent?): IBinder = binder

  override fun onDestroy() {
    val cm = connectivityManager
    val cb = callback
    if (cm != null && cb != null) {
      cm.unregisterNetworkCallback(cb)
    }
    super.onDestroy()
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
      .setContentTitle("Tendril")
      .setContentText(content)
      .setOngoing(true)
      .build()
  }
}
