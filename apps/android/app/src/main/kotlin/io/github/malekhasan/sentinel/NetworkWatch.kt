// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.Proxy
import android.net.ProxyInfo
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Log
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.NetworkState
import java.util.concurrent.Executors

/**
 * Reports the settings that decide where the phone's traffic goes (CM-07, ADR-0014)
 * whenever they may have changed. These are the DNS servers and own proxy of the network
 * the phone would use without the VPN, the Private DNS provider, and a proxy set for
 * the whole phone. The history compares each report with the one before, even one from
 * before Sentinel last stopped, and raises an alert for a change.
 *
 * [UnderlyingDns] tells it about that network. Android announces a change of the proxy
 * for the whole phone with a broadcast, which this listens for while monitoring runs.
 * Everything here runs on the main thread except the history writes, which go to one
 * thread of their own, in order.
 */
class NetworkWatch(private val context: Context, private val history: HistoryStore) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val writer = Executors.newSingleThreadExecutor { Thread(it, "sentinel-network-watch") }

    private var network: Network? = null
    private var properties: LinkProperties? = null
    private var reported: NetworkState? = null

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) = report()
    }

    fun start() {
        val filter = IntentFilter(Proxy.PROXY_CHANGE_ACTION)
        // Sent only by the system; no other app may send it here.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
    }

    fun stop() {
        runCatching { context.unregisterReceiver(receiver) }
        writer.shutdown()
    }

    /** The network the phone would use without the VPN, and its settings; none if offline. */
    fun networkChanged(network: Network?, properties: LinkProperties?) {
        this.network = network
        this.properties = properties
        report()
    }

    private fun report() {
        // A broadcast already on its way after stop() finds nothing to do.
        if (writer.isShutdown) return
        val network = network ?: return
        val properties = properties ?: return
        val state = NetworkState(
            // Network ids start again after a restart: the boot count tells them apart.
            network = "${Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, 0)}:$network",
            dnsServers = properties.dnsServers.mapNotNull { it.hostAddress },
            privateDns = properties.privateDnsServerName,
            networkProxy = properties.httpProxy?.let { describe(it) },
            // A proxy for the whole phone, or else the one apps get from their network.
            proxy = connectivity.defaultProxy?.let { describe(it) },
        )
        if (state == reported) return
        reported = state
        writer.execute {
            try {
                history.networkSeen(state)
            } catch (e: Exception) {
                Log.w(TAG, "the network settings cannot be recorded", e)
            }
        }
    }

    /** A proxy as the user would type it: its PAC address, or host and port; none if empty. */
    private fun describe(proxy: ProxyInfo): String? = when {
        proxy.pacFileUrl != Uri.EMPTY -> proxy.pacFileUrl.toString()
        proxy.host.isNullOrEmpty() -> null
        else -> "${proxy.host}:${proxy.port}"
    }

    private companion object {
        const val TAG = "SentinelNetworkWatch"
    }
}
