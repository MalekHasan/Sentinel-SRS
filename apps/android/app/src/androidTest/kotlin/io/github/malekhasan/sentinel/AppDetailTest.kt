// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.icu.text.ListFormatter
import android.text.format.Formatter
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.CategoryFact
import io.github.malekhasan.sentinel.core.CompanyFact
import io.github.malekhasan.sentinel.core.HistoryApp
import io.github.malekhasan.sentinel.core.HistoryCompany
import io.github.malekhasan.sentinel.core.HistoryDestination
import io.github.malekhasan.sentinel.core.LiveApp
import io.github.malekhasan.sentinel.core.NameSource
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Locale
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
                bytesUpAway = 0,
                bytesDownAway = 0,
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
            bytesUpAway = 2_048,
            bytesDownAway = 0,
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
        val away = context.getString(
            R.string.app_detail_away,
            Formatter.formatShortFileSize(context, 2_048),
            Formatter.formatShortFileSize(context, 0),
        )
        compose.onNodeWithText(away).assertIsDisplayed()

        val list = compose.onNodeWithTag(APP_DETAIL_TAG)
        list.performScrollToNode(hasText("host99.example"))
        compose.onNodeWithText("host99.example").assertIsDisplayed()
        val shown = context.getString(R.string.app_detail_destinations_shown, 100, 150)
        list.performScrollToNode(hasText(shown))
        compose.onNodeWithText(shown).assertIsDisplayed()
    }

    /** Each destination says what is known about it and why (DT-02). */
    @Test
    fun showsWhyWeBelieveEachFact() {
        val named = HistoryDestination(
            destination = "chat.example.com",
            flows = 1,
            bytesUp = 2_000,
            bytesDown = 0,
            bytesUpAway = 0,
            bytesDownAway = 0,
            firstSeenMs = 0,
            lastSeenMs = System.currentTimeMillis(),
            nameSource = NameSource.SNI,
            asn = 64_500u,
            networkOwner = "EXAMPLE-NET",
            networkSource = "IPtoASN 2026-10-15",
            country = "JO",
            countrySource = "DB-IP Lite 2026-10",
            company = CompanyFact(
                company = "Example Chat Inc",
                listedDomain = "chat.example.com",
                sources = listOf("App tracker list 2023-07-06"),
            ),
            categories = CategoryFact(
                categories = listOf("Analytics", "Session Replay", "Some New Kind"),
                listedDomain = "example.com",
                sources = listOf("Tracker Radar 2026-10-09", "App tracker list 2023-07-06"),
            ),
        )
        val bare = named.copy(
            destination = "192.0.2.7",
            bytesUp = 1_000,
            nameSource = null,
            asn = null,
            networkOwner = null,
            networkSource = null,
            country = null,
            countrySource = null,
            company = null,
            categories = null,
        )
        val history = HistoryApp(
            app = "org.example.chat",
            firstSeenMs = 0,
            flows = 2,
            bytesUp = 3_000,
            bytesDown = 0,
            bytesUpAway = 0,
            bytesDownAway = 0,
            destinationCount = 2u,
            destinations = listOf(named, bare),
        )
        compose.setContent {
            SentinelTheme {
                AppDetail("org.example.chat", AppDetails("Chat", history, openFlows = 0), onBack = {})
            }
        }
        val jordan = Locale.Builder().setRegion("JO").build()
            .getDisplayCountry(context.resources.configuration.locales[0])
        val locale = context.resources.configuration.locales[0]
        val lists = ListFormatter.getInstance(locale)
        val list = compose.onNodeWithTag(APP_DETAIL_TAG)
        for (line in listOf(
            context.getString(R.string.dest_named_sni),
            context.getString(R.string.dest_company, isolate("Example Chat Inc")),
            context.getString(
                R.string.dest_listed_why, isolate("App tracker list 2023-07-06"), isolate("chat.example.com"),
            ),
            // Categories the app knows are in the screen's language; others as listed.
            context.getString(
                R.string.dest_categories,
                lists.format(
                    context.getString(R.string.category_analytics),
                    context.getString(R.string.category_session_replay),
                    isolate("Some New Kind"),
                ),
            ),
            context.getString(
                R.string.dest_listed_why,
                lists.format(isolate("Tracker Radar 2026-10-09"), isolate("App tracker list 2023-07-06")),
                isolate("example.com"),
            ),
            context.getString(R.string.dest_network, isolate("AS64500 EXAMPLE-NET")),
            context.getString(R.string.dest_network_why, isolate("IPtoASN 2026-10-15")),
            context.getString(R.string.dest_country, jordan),
            context.getString(R.string.dest_country_why, isolate("DB-IP Lite 2026-10")),
            context.getString(R.string.dest_address_only),
        )) {
            list.performScrollToNode(hasText(line))
            compose.onNodeWithText(line).assertIsDisplayed()
        }
    }

    /** The companies its destinations belong to, from the tracker lists (DT-06). */
    @Test
    fun showsTheCompaniesItsDestinationsBelongTo() {
        val history = HistoryApp(
            app = "org.example.chat",
            firstSeenMs = 0,
            flows = 3,
            bytesUp = 3_000,
            bytesDown = 0,
            bytesUpAway = 0,
            bytesDownAway = 0,
            destinationCount = 3u,
            destinations = emptyList(),
            companies = listOf(
                HistoryCompany(
                    company = "Example Ads",
                    categories = listOf("Advertising"),
                    destinations = 2u,
                    bytesUp = 2_048,
                    bytesDown = 0,
                ),
                HistoryCompany(
                    company = "Metrics",
                    categories = emptyList(),
                    destinations = 1u,
                    bytesUp = 1_000,
                    bytesDown = 0,
                ),
            ),
        )
        compose.setContent {
            SentinelTheme {
                AppDetail("org.example.chat", AppDetails("Chat", history, openFlows = 0), onBack = {})
            }
        }
        val list = compose.onNodeWithTag(APP_DETAIL_TAG)
        for (line in listOf(
            context.getString(R.string.app_detail_companies_title),
            "Example Ads",
            context.getString(R.string.category_advertising),
            context.resources.getQuantityString(R.plurals.company_destinations, 2, 2),
            context.getString(
                R.string.traffic,
                Formatter.formatShortFileSize(context, 2_048),
                Formatter.formatShortFileSize(context, 0),
            ),
            "Metrics",
            context.getString(R.string.app_detail_companies_note),
        )) {
            list.performScrollToNode(hasText(line))
            compose.onNodeWithText(line).assertIsDisplayed()
        }
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
