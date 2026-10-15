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
    val connectivity = context.getSystemService(ConnectivityManager::class.java)
    waitFor("the tunnel to become this app's network") {
        connectivity.getNetworkCapabilities(connectivity.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }
}

/** Stops the VPN the way the notification's Stop action does, and waits for it. */
internal fun stopMonitoring() {
    context.startService(serviceIntent(SentinelVpnService.ACTION_STOP))
    waitFor("monitoring to stop") { Monitor.status.value == Monitor.Status.OFF }
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
