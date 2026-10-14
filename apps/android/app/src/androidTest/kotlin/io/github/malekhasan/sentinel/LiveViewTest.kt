// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.Process
import android.util.Log
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollToKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.LiveApp
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.system.measureNanoTime
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

private const val TAG = "LiveViewTest"

/** Connections held open at once in the CM-03 acceptance run. */
private const val LIVE_CONNECTIONS = 500

/** Refreshes timed at that load. */
private const val REFRESHES = 50

/** The most a refresh may take at that load: a small share of the 1 s period. */
private const val REFRESH_BUDGET_MILLIS = 50.0

/**
 * CM-03 on a device: the live view groups open connections by app, keeps up with 500
 * of them open at once, and its list handles that many rows.
 *
 * Needs the HTTP server described at [testServer].
 */
@RunWith(AndroidJUnit4::class)
class LiveViewTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun grantPermissions() = grantMonitoringPermissions()

    @After
    fun stop() = stopMonitoring()

    @Test
    fun showsFiveHundredOpenConnectionsUnderTheirAppWithinASecond() {
        startMonitoring()
        val (host, port) = testServer()
        val server = InetAddress.getByName(host)
        val sockets = ArrayList<Socket>(LIVE_CONNECTIONS)
        try {
            repeat(LIVE_CONNECTIONS) {
                sockets += Socket().apply { connect(InetSocketAddress(server, port), 10_000) }
            }
            val openedAt = System.currentTimeMillis()

            fun ours(): LiveApp? = Monitor.liveApps().firstOrNull { it.uid == Process.myUid() }
            waitFor(
                "all $LIVE_CONNECTIONS connections to be in the live view",
                timeoutMillis = maxOf(0L, openedAt + 1_000 - System.currentTimeMillis()),
            ) { (ours()?.openFlows?.toInt() ?: 0) >= LIVE_CONNECTIONS }
            val mine = checkNotNull(ours())
            assertEquals(context.packageName, mine.app)
            assertTrue(
                "destinations: ${mine.topDestinations}",
                server.hostAddress in mine.topDestinations,
            )

            // A refresh takes a small share of the 1 s period at this load.
            val millis = List(REFRESHES) { measureNanoTime { Monitor.liveApps() } / 1e6 }.sorted()
            val p90 = millis[REFRESHES * 9 / 10 - 1]
            Log.i(TAG, "liveApps() with $LIVE_CONNECTIONS open: median ${millis[REFRESHES / 2]} ms, p90 $p90 ms")
            assertTrue("liveApps() p90 $p90 ms", p90 < REFRESH_BUDGET_MILLIS)
        } finally {
            sockets.forEach { runCatching { it.close() } }
        }
    }

    /** The list renders one row per app at that scale and scrolls to the last one. */
    @Test
    fun listsFiveHundredAppsAndScrollsToTheLast() {
        val rows = List(LIVE_CONNECTIONS) { n ->
            LiveRow(
                LiveApp(
                    uid = 10_000 + n,
                    app = "org.example.app$n",
                    openFlows = 1u,
                    bytesUp = (LIVE_CONNECTIONS - n).toULong(),
                    bytesDown = 0u,
                    topDestinations = listOf("192.0.2.1"),
                ),
                label = "App $n",
            )
        }
        compose.setContent {
            SentinelTheme { LiveConnections(Monitor.Status.ON, rows, onBack = {}) }
        }
        compose.onNodeWithText("App 0").assertIsDisplayed()
        compose.onNodeWithTag(LIVE_LIST_TAG).performScrollToKey(liveRowKey(rows.last().app))
        compose.onNodeWithText("App ${LIVE_CONNECTIONS - 1}").assertIsDisplayed()
    }
}
