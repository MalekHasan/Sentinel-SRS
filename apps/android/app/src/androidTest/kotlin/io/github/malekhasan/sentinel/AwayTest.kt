// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.text.format.Formatter
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * CM-06 on a device: traffic while the screen is off is counted apart, per app, and
 * shown on the main screen.
 *
 * Needs the HTTP server described at [testServer].
 */
@RunWith(AndroidJUnit4::class)
class AwayTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val request = "GET / HTTP/1.0\r\n\r\n".toByteArray()

    @Before
    fun grantPermissions() = grantMonitoringPermissions()

    @After
    fun restore() {
        // Other tests need the screen on and unlocked.
        wakeAndUnlock()
        stopMonitoring()
    }

    @Test
    fun trafficWhileTheScreenIsOffIsCountedApart() {
        History.wipe(context)
        wakeAndUnlock()
        startMonitoring()
        waitFor("the engine to see the user present") { Monitor.snapshot()?.away == false }
        sendRequest()

        shell("input keyevent KEYCODE_SLEEP")
        waitFor("the engine to see the user away") { Monitor.snapshot()?.away == true }
        sendRequest()

        wakeAndUnlock()
        waitFor("the engine to see the user back") { Monitor.snapshot()?.away == false }
        sendRequest()
        // Stopping ends every flow, so the history holds their final byte counts.
        stopMonitoring()

        // Only the request sent while the screen was off counts as "while away". Counted
        // at the test server only: starting monitoring also looks a name up through the
        // tunnel to see that it carries this app's traffic.
        val summary = checkNotNull(History.get(context).appSummary(context.packageName, 10u))
        val server = checkNotNull(InetAddress.getByName(testServer().first).hostAddress)
        val app = summary.destinations.single { it.destination == server }
        assertEquals("bytes sent", 3L * request.size, app.bytesUp)
        assertEquals("bytes sent while away", request.size.toLong(), app.bytesUpAway)
        assertTrue("received while away: ${app.bytesDownAway}", app.bytesDownAway > 0)
        assertTrue("all received: ${app.bytesDown}", app.bytesDown > app.bytesDownAway)
        val dayAgo = System.currentTimeMillis() - 24 * 60 * 60 * 1000L
        val ours = History.get(context).awayTotals(dayAgo, 10u)
            .single { it.app == context.packageName }
        assertEquals("connections while away", 1L, ours.flows)

        // The main screen lists the app under "while away".
        val line = context.getString(
            R.string.away_app,
            isolate(AppNames(context).labelFor(context.packageName)),
            Formatter.formatShortFileSize(context, ours.bytesUpAway),
            Formatter.formatShortFileSize(context, ours.bytesDownAway),
        )
        compose.setContent {
            SentinelTheme {
                MonitorScreen(
                    coreVersion = "test",
                    visible = true,
                    onStart = {},
                    onStop = {},
                    onShowLive = {},
                    onOpenApp = {},
                    onOpenAlert = {},
                    onShowJournal = {},
                    onImportFeed = {},
                )
            }
        }
        compose.waitUntil(timeoutMillis = 5_000) {
            compose.onAllNodes(hasText(line)).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText(line).performScrollTo().assertIsDisplayed()
    }

    /** One HTTP request through the tunnel, read to the end. */
    private fun sendRequest() {
        val (host, port) = testServer()
        Socket().use { socket ->
            socket.connect(InetSocketAddress(InetAddress.getByName(host), port), 10_000)
            socket.soTimeout = 10_000
            socket.getOutputStream().write(request)
            assertTrue("no answer", socket.getInputStream().readBytes().isNotEmpty())
        }
    }

    private fun wakeAndUnlock() {
        shell("input keyevent KEYCODE_WAKEUP")
        shell("wm dismiss-keyguard")
    }
}
