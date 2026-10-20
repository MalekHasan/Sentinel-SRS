// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.Manifest
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import org.junit.Assert.assertNull
import org.junit.Assert.fail

// Shared by the device tests that run the VPN.

private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
private val context get() = instrumentation.targetContext

/** Grants what the user's "OK" in Android's VPN consent dialog and the notification
 *  prompt grant. */
internal fun grantMonitoringPermissions() {
    shell("appops set ${context.packageName} ACTIVATE_VPN allow")
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        instrumentation.uiAutomation.grantRuntimePermission(
            context.packageName, Manifest.permission.POST_NOTIFICATIONS,
        )
    }
    assertNull("VPN consent should be granted", VpnService.prepare(context))
}

/** Starts the VPN and waits until this app's own traffic goes through it. */
internal fun startMonitoring() {
    context.startForegroundService(serviceIntent(SentinelVpnService.ACTION_START))
    waitFor("monitoring to start") { Monitor.status.value == Monitor.Status.ON }
    // Sentinel's own app is inside the tunnel too, so the tests' sockets use it.
    waitFor("the tunnel to become this app's network") { onTunnel() }
    // Android lists the tunnel as this app's network a moment before it routes the app's
    // traffic into it. Its resolver's address exists only inside the tunnel, so an answer
    // from it proves the traffic goes through.
    waitFor("the tunnel to carry this app's traffic") { dnsAnswered("localhost", tries = 1, timeoutMillis = 500) }
}

/**
 * Whether the tunnel's resolver answers a lookup of [name], in up to [tries] queries.
 * Any answer with the query's id proves the path; the name's existence does not matter.
 */
internal fun dnsAnswered(name: String, tries: Int = 5, timeoutMillis: Int = 2_000): Boolean {
    val resolver = InetAddress.getByName(SentinelVpnService.TUNNEL_DNS)
    repeat(tries) { attempt ->
        val id = 0x5e00 + attempt
        val query = dnsQuery(id, name)
        // A new socket per try: a new source port, like a real resolver.
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMillis
            socket.send(DatagramPacket(query, query.size, resolver, 53))
            val buffer = ByteArray(512)
            val reply = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(reply)
            } catch (timeout: SocketTimeoutException) {
                return@use
            }
            val replyId = (buffer[0].toInt() and 0xFF shl 8) or (buffer[1].toInt() and 0xFF)
            val isResponse = buffer[2].toInt() and 0x80 != 0
            if (reply.length >= 12 && replyId == id && isResponse) return true
        }
    }
    return false
}

/**
 * Stops the VPN the way Sentinel's Stop does, and waits until Android
 * has taken the tunnel away. Otherwise a [startMonitoring] right after would find the
 * old tunnel still in place, and the next connection would go around both: Android
 * routes an app into a new tunnel a moment after the tunnel is created.
 */
internal fun stopMonitoring() {
    context.startService(serviceIntent(SentinelVpnService.ACTION_STOP))
    waitFor("monitoring to stop") { Monitor.status.value == Monitor.Status.OFF }
    waitFor("the tunnel to stop being this app's network") { !onTunnel() }
}

/** Whether this app's traffic goes through a VPN now. */
private fun onTunnel(): Boolean {
    val connectivity = context.getSystemService(ConnectivityManager::class.java)
    return connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
}

private fun serviceIntent(action: String): Intent =
    Intent(context, SentinelVpnService::class.java).setAction(action)

/**
 * The HTTP server the tests reach through the tunnel: by default the test machine's
 * loopback, which the emulator sees as 10.0.2.2. CI starts it; locally run
 * `python3 apps/android/scripts/test-server.py` first, or pass another address with
 * `-Pandroid.testInstrumentationRunnerArguments.sentinelTestServer=host:port`.
 */
internal fun testServer(): Pair<String, Int> {
    val value = InstrumentationRegistry.getArguments()
        .getString("sentinelTestServer", "10.0.2.2:8765")
    val host = value.substringBeforeLast(':')
    val port = value.substringAfterLast(':').toInt()
    return host to port
}

/**
 * The host of the same server on port 53, where DNS is usually served (audit finding
 * A-01): by default the test machine's loopback again. CI starts it; locally run
 * `sudo python3 apps/android/scripts/test-server.py --port 53` first, or pass another
 * host with `-Pandroid.testInstrumentationRunnerArguments.sentinelTestServerOnPort53=host`.
 */
internal fun testServerOnPort53(): String =
    InstrumentationRegistry.getArguments().getString("sentinelTestServerOnPort53", "10.0.2.2")

/** A plain HTTP request the test server answers. */
internal val REQUEST = "GET / HTTP/1.0\r\n\r\n".toByteArray()

/** What the test server sent back, or null if the connection was refused or closed. */
internal fun answer(host: String, port: Int, request: ByteArray = REQUEST): ByteArray? = try {
    Socket().use { socket ->
        socket.connect(InetSocketAddress(InetAddress.getByName(host), port), 5_000)
        socket.soTimeout = 5_000
        socket.getOutputStream().write(request)
        socket.getInputStream().readBytes().takeIf { it.isNotEmpty() }
    }
} catch (e: IOException) {
    null
}

/** Runs [command] as Android's shell user and returns what it printed. */
internal fun shell(command: String): String =
    ParcelFileDescriptor.AutoCloseInputStream(
        instrumentation.uiAutomation.executeShellCommand(command),
    ).use { String(it.readBytes()) }

/** Checks [condition] at once, then every 100 ms until [timeoutMillis] has passed. */
internal fun waitFor(what: String, timeoutMillis: Long = 10_000, condition: () -> Boolean) {
    val deadline = System.currentTimeMillis() + timeoutMillis
    while (!condition()) {
        if (System.currentTimeMillis() >= deadline) fail("timed out waiting for $what")
        Thread.sleep(100)
    }
}

/** A minimal TLS ClientHello carrying one server_name extension. */
internal fun clientHello(name: String): ByteArray {
    fun ByteArrayOutputStream.u16(v: Int) { write(v shr 8 and 0xFF); write(v and 0xFF) }
    val host = name.toByteArray()
    val sni = ByteArrayOutputStream().apply {
        u16(host.size + 3); write(0); u16(host.size); write(host)
    }.toByteArray()
    val ext = ByteArrayOutputStream().apply { u16(0x0000); u16(sni.size); write(sni) }.toByteArray()
    val body = ByteArrayOutputStream().apply {
        write(byteArrayOf(3, 3)); write(ByteArray(32)) // version, random
        write(0) // no session id
        u16(2); u16(0x1301) // one cipher suite
        write(1); write(0) // null compression
        u16(ext.size); write(ext)
    }.toByteArray()
    val handshake = ByteArrayOutputStream().apply {
        write(1); write(0); u16(body.size); write(body)
    }.toByteArray()
    return ByteArrayOutputStream().apply {
        write(0x16); write(3); write(1); u16(handshake.size); write(handshake)
    }.toByteArray()
}

/** A DNS query for the A records of [name], asking for recursion. */
internal fun dnsQuery(id: Int, name: String): ByteArray = ByteArrayOutputStream().apply {
    write(byteArrayOf((id shr 8).toByte(), id.toByte(), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
    name.split('.').forEach { label ->
        write(label.length)
        write(label.toByteArray())
    }
    write(byteArrayOf(0, 0, 1, 0, 1)) // end of name, type A, class IN
}.toByteArray()
