// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.system.OsConstants
import android.util.Log
import io.github.malekhasan.sentinel.core.Engine
import io.github.malekhasan.sentinel.core.EngineException
import io.github.malekhasan.sentinel.core.EngineListener
import io.github.malekhasan.sentinel.core.FlowObserver
import io.github.malekhasan.sentinel.core.FlowOwner
import io.github.malekhasan.sentinel.core.FlowProto
import io.github.malekhasan.sentinel.core.FlowRecord
import io.github.malekhasan.sentinel.core.SocketProtector
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * The local VPN: hands every app's traffic to the Rust engine, which relays it over
 * protected sockets. Nothing leaves the phone through Sentinel; there is no server.
 *
 * Runs as a foreground service with a notification that stays visible the whole time
 * (SRS §15.3). If the engine stops without being asked, Android routes traffic outside
 * the tunnel (fail-open, NF-07) and the stop is recorded as a gap (SP-03).
 */
class SentinelVpnService : VpnService() {
    private val main = Handler(Looper.getMainLooper())

    // Main thread only.
    private var engine: Engine? = null
    private var listener: Listener? = null
    private var underlyingDns: UnderlyingDns? = null
    private var networkWatch: NetworkWatch? = null
    private var awayWatcher: AwayWatcher? = null

    override fun onCreate() {
        super.onCreate()
        GapLog.recordUnexpectedExit(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            GapLog.setMonitoringWanted(this, false)
            teardown()
            stopSelf()
        } else {
            // ACTION_START from the app, or Android starting an always-on VPN.
            startMonitoring()
        }
        return START_NOT_STICKY
    }

    private fun startMonitoring() {
        if (engine != null) return
        Monitor.starting()
        try {
            goForeground()
        } catch (e: RuntimeException) {
            // For example, the VPN permission was withdrawn since the user granted it.
            fail(getString(R.string.gap_start_failed, isolate(e.message.orEmpty())))
            return
        }
        GapLog.setMonitoringWanted(this, true)

        val tunnel = try {
            tunnelBuilder().establish()
        } catch (e: RuntimeException) {
            null
        }
        if (tunnel == null) {
            fail(getString(R.string.gap_no_tunnel))
            return
        }
        val listener = Listener()
        // Monitoring without a history is still monitoring: the engine runs either way.
        val history = try {
            History.get(this)
        } catch (e: Exception) {
            Log.w(TAG, "the history is not available; flows will not be stored", e)
            null
        }
        val started = try {
            Engine.start(tunnel.detachFd(), listOf(TUNNEL_DNS), Protector(), listener, Flows(), history)
        } catch (e: EngineException) {
            fail(getString(R.string.gap_start_failed, isolate(e.message.orEmpty())))
            return
        }
        engine = started
        this.listener = listener
        // Changes to DNS, Private DNS and proxies raise alerts (CM-07).
        val watch = history?.let { NetworkWatch(this, it).also(NetworkWatch::start) }
        networkWatch = watch
        underlyingDns = UnderlyingDns(
            this,
            onNetwork = { network, properties ->
                if (engine === started) watch?.networkChanged(network, properties)
            },
        ) { servers ->
            // A callback queued before teardown must not reach a closed engine.
            if (engine === started) started.setUpstreamDns(servers)
        }.also { it.start() }
        // Traffic while the screen is off or locked is counted apart (CM-06).
        awayWatcher = AwayWatcher(this) { away ->
            if (engine === started) started.setAway(away)
        }.also { it.start() }
        GapLog.closeOpen(this, System.currentTimeMillis())
        Monitor.started(started)
        // The network and country (DT-01), company and category (DT-06) of each
        // destination, if a feed brought the data.
        Thread({
            val ip = IpData.open(this)
            val trackers = TrackerData.open(this)
            main.post {
                if (engine === started) {
                    ip?.let {
                        started.setIpDatabase(it)
                        Monitor.ipDataLoaded(it.sources())
                    }
                    trackers?.let {
                        started.setTrackerDatabase(it)
                        Monitor.trackerDataLoaded(it.sources())
                    }
                }
            }
        }, "sentinel-feed-data").start()
        if (history != null) {
            // Roll old flows into daily totals (SRS §13.2), off the main thread.
            Thread({
                try {
                    history.applyRetention(System.currentTimeMillis(), History.KEEP_DAYS)
                } catch (e: Exception) {
                    Log.w(TAG, "retention failed", e)
                }
            }, "sentinel-retention").start()
        }
    }

    private fun tunnelBuilder(): Builder {
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        return Builder()
            .setSession(getString(R.string.app_name))
            .setConfigureIntent(openApp)
            .setMtu(MTU)
            .addAddress(TUNNEL_V4, 32)
            .addAddress(TUNNEL_V6, 128)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // DNS goes to an address inside the tunnel; the engine forwards it to the
            // current network's resolvers, so it keeps working across network changes.
            .addDnsServer(TUNNEL_DNS)
            // Inherit metered or unmetered from the real network instead of always
            // looking metered to apps.
            .setMetered(false)
    }

    /** Monitoring could not start or keep going: record the gap and stop. */
    private fun fail(reason: String) {
        GapLog.open(this, System.currentTimeMillis(), reason)
        teardown()
        stopSelf()
    }

    override fun onRevoke() {
        // Another VPN app took over, or the user switched the VPN off in Settings.
        if (engine != null) {
            GapLog.open(this, System.currentTimeMillis(), getString(R.string.gap_revoked))
        }
        teardown()
        stopSelf()
    }

    override fun onDestroy() {
        if (engine != null) {
            GapLog.open(this, System.currentTimeMillis(), getString(R.string.gap_service_stopped))
        }
        teardown()
        super.onDestroy()
    }

    private fun teardown() {
        listener = null
        underlyingDns?.stop()
        underlyingDns = null
        networkWatch?.stop()
        networkWatch = null
        awayWatcher?.stop()
        awayWatcher = null
        engine?.let {
            it.stop()
            it.close()
        }
        engine = null
        Monitor.stopped()
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun goForeground() {
        val notifications = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.channel_monitoring),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.channel_monitoring_description)
            setShowBadge(false)
        }
        notifications.createNotificationChannel(channel)

        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, SentinelVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_monitoring)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setContentIntent(openApp)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, R.drawable.ic_monitoring),
                    getString(R.string.action_stop),
                    stop,
                ).build(),
            )
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
                }
            }
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /** Lets the engine's own sockets bypass the tunnel. */
    private inner class Protector : SocketProtector {
        override fun protect(fd: Int): Boolean = this@SentinelVpnService.protect(fd)
    }

    /** Called on engine threads. */
    private inner class Flows : FlowObserver {
        private val connectivity = getSystemService(ConnectivityManager::class.java)
        private val appNames = AppNames(this@SentinelVpnService)

        override fun owner(
            proto: FlowProto,
            localIp: String,
            localPort: UShort,
            remoteIp: String,
            remotePort: UShort,
        ): FlowOwner {
            val uid = ownerUid(proto, localIp, localPort, remoteIp, remotePort)
            val app = appNames.packageFor(uid)
            // An app installed since the history began is new to the network (CM-04).
            return FlowOwner(uid, app, app?.let(appNames::installedAt))
        }

        /** Only the active VPN app may ask Android who owns a connection (API 29+). */
        private fun ownerUid(
            proto: FlowProto,
            localIp: String,
            localPort: UShort,
            remoteIp: String,
            remotePort: UShort,
        ): Int = try {
            connectivity.getConnectionOwnerUid(
                if (proto == FlowProto.TCP) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP,
                // Numeric addresses: no lookup happens.
                InetSocketAddress(InetAddress.getByName(localIp), localPort.toInt()),
                InetSocketAddress(InetAddress.getByName(remoteIp), remotePort.toInt()),
            )
        } catch (e: RuntimeException) {
            // SecurityException once this app is no longer the active VPN.
            Process.INVALID_UID
        }

        override fun flows(records: List<FlowRecord>) = Monitor.flowsUpdated(records)
    }

    /** Called on the engine's thread. */
    private inner class Listener : EngineListener {
        override fun engineStopped(error: String?) {
            // `null` means we asked it to stop; teardown() handles that.
            if (error == null) return
            main.post {
                if (listener === this@Listener) {
                    fail(getString(R.string.gap_engine_failed, isolate(error)))
                }
            }
        }
    }

    companion object {
        private const val TAG = "SentinelVpn"
        const val ACTION_START = "io.github.malekhasan.sentinel.action.START"
        const val ACTION_STOP = "io.github.malekhasan.sentinel.action.STOP"
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "monitoring"

        /** Must match the engine's `EngineConfig::mtu` default. */
        const val MTU = 1500
        const val TUNNEL_V4 = "10.215.173.1"
        const val TUNNEL_V6 = "fd00:5e17:173::1"
        /** The resolver address apps see; DNS sent here is forwarded by the engine. */
        const val TUNNEL_DNS = "10.215.173.53"
    }
}
