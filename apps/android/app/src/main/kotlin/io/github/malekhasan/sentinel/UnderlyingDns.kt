// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper

/**
 * Follows the resolvers of the network the phone would use without the VPN, so the
 * engine can forward DNS to them (see `DnsForward` in the Rust engine).
 *
 * Sentinel's own app is inside its tunnel (its connections are monitored like any
 * other app's), so its default network is the VPN itself. This asks for the best
 * network that is *not* a VPN instead.
 */
class UnderlyingDns(context: Context, private val onChange: (List<String>) -> Unit) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val bestMatching = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    // Touched only on the main thread, where the callbacks run.
    private val networks = LinkedHashMap<Network, Pair<NetworkCapabilities?, LinkProperties?>>()
    private var published: List<String>? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            // With a best-matching request, a new network here replaces the old best.
            if (bestMatching) networks.keys.retainAll(setOf(network))
            networks.getOrPut(network) { null to null }
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            networks[network] = capabilities to networks[network]?.second
            publish()
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            networks[network] = networks[network]?.first to properties
            publish()
        }

        override fun onLost(network: Network) {
            networks.remove(network)
            publish()
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val handler = Handler(Looper.getMainLooper())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            connectivity.registerBestMatchingNetworkCallback(request, callback, handler)
        } else {
            // Android 10 and 11: every matching network is reported. Prefer one that is
            // not mobile data, as Android does for its default network.
            connectivity.registerNetworkCallback(request, callback, handler)
        }
    }

    fun stop() {
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }

    private fun publish() {
        val best = networks.values.sortedBy { (capabilities, _) ->
            if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) 1 else 0
        }.firstOrNull { (_, properties) -> properties != null }
        // Scoped link-local resolvers (fe80::1%wlan0) cannot be reached from the engine.
        val servers = best?.second?.dnsServers.orEmpty()
            .filterNot { it.isLinkLocalAddress }
            .mapNotNull { it.hostAddress }
        if (servers != published) {
            published = servers
            onChange(servers)
        }
    }
}
