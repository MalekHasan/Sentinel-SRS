// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.HistoryApp
import io.github.malekhasan.sentinel.core.HistoryDestination
import io.github.malekhasan.sentinel.core.LiveApp
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

/** Requests this test sends through the tunnel. */
private const val REQUESTS = 3

/**
 * The app detail screen on a device: what the history holds about one app, and how the
 * screen shows it.
 *
 * Needs the HTTP server described at [testServer].
 */
@RunWith(AndroidJUnit4::class)
class AppDetailTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun grantPermissions() = grantMonitoringPermissions()

    @After
    fun stop() = stopMonitoring()

    /** This app's traffic is totalled per destination, to the byte, with its first use. */
    @Test
    fun totalsThisAppsTrafficPerDestination() {
        History.wipe(context)
        val before = System.currentTimeMillis()
        startMonitoring()
        val (host, port) = testServer()
        val server = InetAddress.getByName(host)
        val request = "GET / HTTP/1.0\r\n\r\n".toByteArray()
        repeat(REQUESTS) {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(server, port), 10_000)
                socket.soTimeout = 10_000
                socket.getOutputStream().write(request)
                // An HTTP/1.0 server closes the connection after its answer.
                assertTrue("no answer", socket.getInputStream().readBytes().isNotEmpty())
            }
        }
        // Stopping ends every flow, so the history holds their final byte counts.
        stopMonitoring()

        val summary = checkNotNull(History.get(context).appSummary(context.packageName, 10u)) {
            "this app is not in the history"
        }
        assertTrue(
            "first seen ${summary.firstSeenMs}, test started $before",
            summary.firstSeenMs in before..System.currentTimeMillis(),
        )
        val toServer = summary.destinations.single { it.destination == server.hostAddress }
        assertEquals("connections to the server", REQUESTS.toLong(), toServer.flows)
        assertEquals("bytes sent to the server", REQUESTS.toLong() * request.size, toServer.bytesUp)
        assertTrue("bytes received: ${toServer.bytesDown}", toServer.bytesDown > 0)
    }

    /** The screen lists the destinations, busiest first, and says how many are left out. */
    @Test
    fun showsTheDestinationsAndHowManyAreNotListed() {
        val destinations = List(100) { n ->
            HistoryDestination(
                destination = "host$n.example",
                flows = 1,
                bytesUp = (100 - n) * 1_000L,
                bytesDown = 0,
                firstSeenMs = 0,
                lastSeenMs = System.currentTimeMillis(),
            )
        }
        val history = HistoryApp(
            app = "org.example.video",
            firstSeenMs = System.currentTimeMillis(),
            flows = 100,
            bytesUp = destinations.sumOf { it.bytesUp },
            bytesDown = 0,
            destinationCount = 150u,
            destinations = destinations,
        )
        compose.setContent {
            SentinelTheme {
                AppDetail("org.example.video", AppDetails("Video", history, openFlows = 2), onBack = {})
            }
        }
        compose.onNodeWithText("Video").assertIsDisplayed()
        compose.onNodeWithText("org.example.video").assertIsDisplayed()
        compose.onNodeWithText("host0.example").assertIsDisplayed()

        val list = compose.onNodeWithTag(APP_DETAIL_TAG)
        list.performScrollToNode(hasText("host99.example"))
        compose.onNodeWithText("host99.example").assertIsDisplayed()
        val shown = context.getString(R.string.app_detail_destinations_shown, 100, 150)
        list.performScrollToNode(hasText(shown))
        compose.onNodeWithText(shown).assertIsDisplayed()
    }

    /** Tapping an app in the live view opens its detail. */
    @Test
    fun aLiveRowOpensItsApp() {
        var opened: String? = null
        val row = LiveRow(
            LiveApp(
                uid = 10_001,
                app = "org.example.chat",
                openFlows = 1u,
                bytesUp = 0u,
                bytesDown = 0u,
                topDestinations = emptyList(),
            ),
            label = "Chat",
        )
        compose.setContent {
            SentinelTheme {
                LiveConnections(Monitor.Status.ON, listOf(row), onBack = {}, onOpenApp = { opened = it })
            }
        }
        compose.onNodeWithText("Chat").performClick()
        assertEquals("org.example.chat", opened)
    }
}
