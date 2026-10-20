// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.KeyguardManager
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
    private var installWatch: InstallWatch? = null
    private var deviceWatch: DeviceWatch? = null
    private var sensorWatch: SensorWatch? = null

    // A new indicator list came into force, or the one in force was removed.
    private val feedChanged: () -> Unit = { main.post { engine?.let(::loadFeedData) } }

    // Checks the indicator list in force again every hour while monitoring runs (SP-04).
    private val recheckFeed = object : Runnable {
        override fun run() {
            Thread({ IndicatorFeed.recheck(this@SentinelVpnService) }, "sentinel-feed-recheck").start()
            main.postDelayed(this, IndicatorFeed.RECHECK_EVERY_MILLIS)
        }
    }

    // Checks that the engine still reports, as often as it does (SP-03). Handler time
    // stands still while the phone sleeps, so this never wakes it. A silent engine takes
    // the phone's traffic and relays none of it: a new one replaces it, and its gap
    // closes when that one runs (NF-07).
    private val checkHeartbeat = object : Runnable {
        override fun run() {
            val running = engine ?: return
            val age = running.snapshot().heartbeatAgeMs.toLong()
            if (Heartbeat.check(this@SentinelVpnService, age, System.currentTimeMillis())) {
                // Still in the foreground: Android may not let it come back from the background.
                teardown(keepForeground = true)
                startMonitoring()
            } else {
                main.postDelayed(this, Heartbeat.EVERY_MILLIS)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        GapLog.recordUnexpectedExit(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // Someone holding a locked phone must not turn monitoring off from the
            // notification: it would leave no gap, as a stop the user asked for is not
            // one (THREAT-MODEL-A T5). From Android 12 the action asks to unlock first.
            if (engine != null && getSystemService(KeyguardManager::class.java)?.isDeviceLocked == true) {
                Log.w(TAG, "not stopping: the phone is locked")
                return START_NOT_STICKY
            }
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
        // Traffic while the screen is off or locked is counted apart (CM-06), and sensor
        // use then raises an alert (SE-04).
        val presence = AwayWatcher(this) { away ->
            if (engine === started) started.setAway(away)
            sensorWatch?.awayChanged(away)
        }.also { it.start() }
        awayWatcher = presence
        // Microphone and camera use (SE-01 basic, SE-03).
        sensorWatch = history?.let { SensorWatch(this, it, presence::isAway).also(SensorWatch::start) }
        GapLog.closeOpen(this, System.currentTimeMillis())
        Monitor.started(started)
        // Only the VPN service itself can ask (SP-03, ADR-0030).
        Monitor.alwaysOn = isAlwaysOn
        main.post(checkHeartbeat)
        loadFeedData(started)
        // Apps installed or updated while monitoring runs are checked at once (ID-13).
        installWatch = InstallWatch(this).also(InstallWatch::start)
        // Apps that hold or gain accessibility, device admin or notification access
        // (ID-12); wireless debugging (ID-03) and trusted certificates (ID-10).
        deviceWatch = DeviceWatch(this).also(DeviceWatch::start)
        IndicatorFeed.addListener(feedChanged)
        main.postDelayed(recheckFeed, IndicatorFeed.RECHECK_EVERY_MILLIS)
        FeedUpdateJob.schedule(this)
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

    /**
     * The indicators every lookup and connection is matched against (ID-13), and the
     * network and country (DT-01), company and category (DT-06) of each destination, from
     * the indicator list in force, if it brought the data. The list is checked when it is
     * first opened (SP-04). The engine follows the feed to each new list, and stops
     * matching a list that fails its check.
     */
    private fun loadFeedData(started: Engine) {
        Thread({
            val feed = IndicatorFeed.get(this)
            val ip = IpData.open(this)
            val trackers = TrackerData.open(this)
            main.post {
                if (engine === started) {
                    started.setFeed(feed)
                    Monitor.feedSet(feed)
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
            // Should a check of the history against this list have been cut short (MS-02).
            History.hunt(this)
            // Apps installed while monitoring was off (ID-13).
            InstalledApps.check(this)
        }, "sentinel-feed-data").start()
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

    private fun teardown(keepForeground: Boolean = false) {
        listener = null
        IndicatorFeed.removeListener(feedChanged)
        main.removeCallbacks(recheckFeed)
        main.removeCallbacks(checkHeartbeat)
        underlyingDns?.stop()
        underlyingDns = null
        networkWatch?.stop()
        networkWatch = null
        awayWatcher?.stop()
        awayWatcher = null
        sensorWatch?.stop()
        sensorWatch = null
        installWatch?.stop()
        installWatch = null
        deviceWatch?.stop()
        deviceWatch = null
        engine?.let {
            it.stop()
            it.close()
        }
        engine = null
        Monitor.stopped()
        if (!keepForeground) stopForeground(STOP_FOREGROUND_REMOVE)
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
                ).apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) setAuthenticationRequired(true)
                }.build(),
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
            // An app installed since the history began is new to the network (CM-04). A
            // system app's regular check-ins are not flagged (DL-04).
            return FlowOwner(uid, app, app?.let(appNames::installedAt), appNames.isSystem(uid, app))
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
