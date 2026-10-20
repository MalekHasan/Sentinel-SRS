// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.ActivityOptions
import android.app.NotificationManager
import android.os.Build
import android.os.Process
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
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
import org.junit.Rule
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

    /** For the question the notification's Stop opens, in its own activity. */
    @get:Rule
    val compose = createEmptyComposeRule()

    @Before
    fun grantPermissions() = grantMonitoringPermissions()

    @After
    fun stop() = stopMonitoring()

    /**
     * THREAT-MODEL-A T5: the notification's Stop asks to unlock the phone first, so
     * someone holding a locked phone cannot turn monitoring off without leaving a gap.
     */
    @Test
    fun stoppingFromTheNotificationAsksToUnlockFirst() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        startMonitoring()
        val ongoing = notifications.activeNotifications
            .single { it.id == SentinelVpnService.NOTIFICATION_ID }
        val stop = ongoing.notification.actions
            .single { it.title.toString() == context.getString(R.string.action_stop) }
        assertTrue("Stop asks to unlock first", stop.isAuthenticationRequired)
    }

    /**
     * THREAT-MODEL-A E6 (audit finding A-02): an app with notification access can fire the
     * Stop action itself, without a tap. That only asks; monitoring stops when the person
     * holding the phone answers Stop.
     */
    @Test
    fun firingTheNotificationsStopOnlyAsks() {
        startMonitoring()
        val question = context.getString(R.string.stop_title)
        fun asked() = compose.onAllNodesWithText(question).fetchSemanticsNodes().isNotEmpty()

        fireStopAction()
        compose.waitUntil(10_000) { asked() }
        assertEquals("monitoring while asked", Monitor.Status.ON, Monitor.status.value)
        compose.onNodeWithText(context.getString(R.string.stop_keep)).performClick()
        compose.waitUntil(10_000) { !asked() }
        assertEquals("monitoring kept", Monitor.Status.ON, Monitor.status.value)

        fireStopAction()
        compose.waitUntil(10_000) { asked() }
        compose.onNodeWithText(context.getString(R.string.action_stop)).performClick()
        waitFor("monitoring to stop") { Monitor.status.value == Monitor.Status.OFF }
    }

    /** What an app with notification access can do: fire the Stop action as it is. */
    private fun fireStopAction() {
        val stop = notifications.activeNotifications
            .single { it.id == SentinelVpnService.NOTIFICATION_ID }
            .notification.actions
            .single { it.title.toString() == context.getString(R.string.action_stop) }
        // As an app that Android lets start activities, the worst case: it opens the question.
        val options = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            @Suppress("DEPRECATION") // Its successor needs Android 16; the emulator runs 14.
            val allowed = ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED
            ActivityOptions.makeBasic().setPendingIntentBackgroundActivityStartMode(allowed).toBundle()
        } else {
            null
        }
        stop.actionIntent.send(context, 0, null, null, null, null, options)
    }

    @Test
    fun relaysTrafficAndDnsThenStopsCleanly() {
        val gapsBefore = GapLog.recent(context, 1_000).size
        val startedAt = System.currentTimeMillis()
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
        // SP-03: the engine reports, and the service writes down when it heard from it.
        assertTrue("last report ${snapshot.heartbeatAgeMs} ms ago", snapshot.heartbeatAgeMs < 10_000uL)
        val heard = checkNotNull(Heartbeat.lastHeard(context)) { "no report written down" }
        assertTrue("last heard at $heard, started at $startedAt", heard >= startedAt - 1_000)

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
