// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.NotificationManager
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.FlowProto
import io.github.malekhasan.sentinel.core.FlowRecord
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Connections in the CM-01 acceptance run. */
private const val CONNECTIONS = 20

/**
 * Sprint 1 end to end, on a device: start the VPN, relay real traffic through the Rust
 * engine, forward DNS to the network's resolver, and stop cleanly.
 *
 * Needs the HTTP server described at [testServer].
 */
@RunWith(AndroidJUnit4::class)
class MonitoringTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val notifications = context.getSystemService(NotificationManager::class.java)

    @Before
    fun grantPermissions() = grantMonitoringPermissions()

    @After
    fun stop() = stopMonitoring()

    @Test
    fun relaysTrafficAndDnsThenStopsCleanly() {
        val gapsBefore = GapLog.recent(context, 1_000).size
        startMonitoring()

        // §15.3: monitoring is never hidden.
        assertTrue(
            "the monitoring notification must be showing",
            notifications.activeNotifications.any { it.id == SentinelVpnService.NOTIFICATION_ID },
        )

        // TCP through the engine and its protected upstream socket.
        val (host, port) = testServer()
        val connectedAt = System.currentTimeMillis()
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), 10_000)
            socket.soTimeout = 10_000
            socket.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".toByteArray())
            val status = socket.getInputStream().bufferedReader().readLine()
            assertTrue("unexpected reply: $status", status?.startsWith("HTTP/1.") == true)
        }

        // CM-01: the connection is recorded with its app within 1 s of being opened.
        fun ours(flow: FlowRecord) = flow.proto == FlowProto.TCP &&
            flow.remoteIp == host && flow.remotePort.toInt() == port
        waitFor(
            "the connection to be recorded",
            timeoutMillis = maxOf(0L, connectedAt + 1_000 - System.currentTimeMillis()),
        ) { Monitor.recentFlows().any(::ours) }
        val recorded = Monitor.recentFlows().first(::ours)
        assertEquals("owner of the connection", Process.myUid(), recorded.uid)
        assertEquals(context.packageName, recorded.app)

        // ... and stored in the encrypted history with its app (ADR-0009).
        val history = History.get(context)
        fun stored() = history.recentFlows(50u).filter {
            it.proto == FlowProto.TCP && it.remoteIp == host && it.remotePort.toInt() == port
        }
        waitFor("the connection to be in the history", timeoutMillis = 1_000) {
            stored().any { it.app == context.packageName }
        }

        // DNS to the tunnel's resolver reaches the real network's resolver. Any answer
        // with our query id proves the path; the name's existence does not matter.
        assertTrue("no DNS answer through the tunnel", dnsAnswered("localhost"))

        val snapshot = checkNotNull(Monitor.snapshot()) { "no engine counters while on" }
        assertTrue("flows seen: ${snapshot.flowsTotal}", snapshot.flowsTotal >= 2uL)

        stopMonitoring()
        waitFor("the notification to go") {
            notifications.activeNotifications.none { it.id == SentinelVpnService.NOTIFICATION_ID }
        }
        assertEquals("a stop the user asked for is not a gap", gapsBefore, GapLog.recent(context, 1_000).size)
        // Every recorded flow is closed once the engine has stopped, in the history too.
        assertTrue(
            "flows left open: ${Monitor.recentFlows().filter { it.endedMs == null }}",
            Monitor.recentFlows().all { it.endedMs != null },
        )
        assertTrue("the stored flow is not closed", stored().all { it.endedMs != null })
    }

    /**
     * CM-01 acceptance on a device: every connection in a run is recorded with its app
     * within 1 s of being opened, and every one is in the encrypted history.
     */
    @Test
    fun everyConnectionIsRecordedWithinASecond() {
        History.wipe(context)
        startMonitoring()
        val (host, port) = testServer()
        repeat(CONNECTIONS) { n ->
            Socket().use { socket ->
                val openedAt = System.currentTimeMillis()
                socket.connect(InetSocketAddress(host, port), 10_000)
                socket.soTimeout = 10_000
                socket.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".toByteArray())
                socket.getInputStream().bufferedReader().readLine()
                // The engine sees the app's own address and port inside the tunnel.
                val localPort = socket.localPort
                waitFor(
                    "connection ${n + 1} of $CONNECTIONS to be recorded",
                    timeoutMillis = maxOf(0L, openedAt + 1_000 - System.currentTimeMillis()),
                ) {
                    Monitor.recentFlows().any {
                        it.proto == FlowProto.TCP && it.localPort.toInt() == localPort &&
                            it.uid == Process.myUid()
                    }
                }
            }
        }
        val stored = History.get(context).recentFlows(1_000u).count {
            it.proto == FlowProto.TCP && it.remoteIp == host && it.remotePort.toInt() == port &&
                it.app == context.packageName
        }
        assertEquals("connections in the history", CONNECTIONS, stored)
    }
}
