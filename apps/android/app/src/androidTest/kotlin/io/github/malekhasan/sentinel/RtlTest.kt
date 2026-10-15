// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.content.res.Configuration
import android.icu.text.ListFormatter
import android.text.format.Formatter
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.getBoundsInRoot
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.style.ResolvedTextDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.CategoryFact
import io.github.malekhasan.sentinel.core.CompanyFact
import io.github.malekhasan.sentinel.core.FlowProto
import io.github.malekhasan.sentinel.core.HistoryApp
import io.github.malekhasan.sentinel.core.HistoryAway
import io.github.malekhasan.sentinel.core.HistoryCompany
import io.github.malekhasan.sentinel.core.HistoryDestination
import io.github.malekhasan.sentinel.core.HistoryFlow
import io.github.malekhasan.sentinel.core.LiveApp
import io.github.malekhasan.sentinel.core.NameSource
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

private const val PACKAGE = "org.example.chat"
private const val LABEL = "Chat"
private const val HOST = "chat.example.com"
private const val ADDRESS = "203.0.113.5"

/**
 * Every screen in Arabic, laid out right to left (S3.4): the Arabic strings are used,
 * each screen starts at the right edge, and sentences stay right to left when they
 * carry Latin names such as package names, hostnames and addresses.
 */
@RunWith(AndroidJUnit4::class)
class RtlTest {
    @get:Rule
    val compose = createComposeRule()

    private val arabic: Context = InstrumentationRegistry.getInstrumentation().targetContext.let {
        val config = Configuration(it.resources.configuration)
        config.setLocale(Locale.forLanguageTag("ar"))
        it.createConfigurationContext(config)
    }
    private val now = System.currentTimeMillis()

    @Test
    fun mainScreen() {
        val flow = HistoryFlow(
            id = 1,
            app = PACKAGE,
            proto = FlowProto.TCP,
            remoteIp = ADDRESS,
            remotePort = 443u,
            hostname = HOST,
            hostnameSource = NameSource.DNS,
            startedMs = now,
            endedMs = null,
            bytesUp = 0,
            bytesDown = 0,
            blocked = false,
        )
        val away = AwayRow(
            HistoryAway(app = PACKAGE, flows = 1, bytesUpAway = 2_048, bytesDownAway = 100),
            label = LABEL,
        )
        compose.setContent {
            InArabic {
                MonitorContent(
                    coreVersion = "0.0.1",
                    status = Monitor.Status.OFF,
                    snapshot = null,
                    flows = listOf(flow),
                    gaps = listOf(GapLog.Gap(now - 60_000, now, "test")),
                    away = listOf(away),
                    onStart = {},
                    onStop = {},
                    onShowLive = {},
                    onOpenApp = {},
                    onWipe = {},
                )
            }
        }
        compose.onNodeWithText(arabic.getString(R.string.tagline)).assertIsDisplayed()
        compose.onNodeWithText(arabic.getString(R.string.action_start)).assertAtTheRight()

        // Both lines start with a Latin name in Arabic, which must not turn them around.
        val flowLine = arabic.getString(
            R.string.flow_open, isolate(PACKAGE), isolate(hostAndPort(HOST, 443)),
        )
        assertRightToLeft(compose.onNodeWithText(flowLine, useUnmergedTree = true))
        val awayLine = arabic.getString(
            R.string.away_app,
            isolate(LABEL),
            Formatter.formatShortFileSize(arabic, 2_048),
            Formatter.formatShortFileSize(arabic, 100),
        )
        assertRightToLeft(compose.onNodeWithText(awayLine, useUnmergedTree = true))
    }

    @Test
    fun liveConnections() {
        val row = LiveRow(
            LiveApp(
                uid = 10_001,
                app = PACKAGE,
                openFlows = 2u,
                bytesUp = 2_048u,
                bytesDown = 100u,
                topDestinations = listOf(HOST, ADDRESS),
            ),
            label = LABEL,
        )
        compose.setContent {
            InArabic { LiveConnections(Monitor.Status.ON, listOf(row), onBack = {}, onOpenApp = {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.back)).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.live_title)).assertIsDisplayed()
        compose.onNodeWithText(LABEL, useUnmergedTree = true).assertAtTheRight()
        // Arabic's own plural for two.
        compose.onNodeWithText(
            arabic.resources.getQuantityString(R.plurals.live_open_flows, 2, 2),
            useUnmergedTree = true,
        ).assertIsDisplayed()
        val destinations = arabic.getString(
            R.string.live_destinations,
            ListFormatter.getInstance(Locale.forLanguageTag("ar"))
                .format(listOf(isolate(HOST), isolate(ADDRESS))),
        )
        assertRightToLeft(compose.onNodeWithText(destinations, useUnmergedTree = true))
    }

    @Test
    fun appDetail() {
        val history = HistoryApp(
            app = PACKAGE,
            firstSeenMs = now,
            flows = 2,
            bytesUp = 2_048,
            bytesDown = 100,
            bytesUpAway = 1_024,
            bytesDownAway = 0,
            destinationCount = 1u,
            destinations = listOf(
                HistoryDestination(
                    destination = HOST,
                    flows = 2,
                    bytesUp = 2_048,
                    bytesDown = 100,
                    bytesUpAway = 512,
                    bytesDownAway = 0,
                    firstSeenMs = now,
                    lastSeenMs = now,
                    nameSource = NameSource.DNS,
                    asn = 64_500u,
                    networkOwner = "EXAMPLE-NET",
                    networkSource = "IPtoASN 2026-10-15",
                    country = "JO",
                    countrySource = "DB-IP Lite 2026-10",
                    company = CompanyFact(
                        company = "Example Chat Inc",
                        listedDomain = "example.com",
                        sources = listOf("Tracker Radar 2026-10-09"),
                    ),
                    categories = CategoryFact(
                        categories = listOf("Analytics"),
                        listedDomain = "example.com",
                        sources = listOf("Tracker Radar 2026-10-09"),
                    ),
                ),
            ),
            companies = listOf(
                HistoryCompany(
                    company = "Example Chat Inc",
                    categories = listOf("Analytics"),
                    destinations = 1u,
                    bytesUp = 2_048,
                    bytesDown = 100,
                ),
            ),
        )
        compose.setContent {
            InArabic { AppDetail(PACKAGE, AppDetails(LABEL, history, openFlows = 2), onBack = {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.back)).assertAtTheRight()
        compose.onNodeWithText(LABEL).assertAtTheRight()
        compose.onNodeWithText(
            arabic.resources.getQuantityString(R.plurals.history_connections, 2, 2),
        ).assertIsDisplayed()
        val away = arabic.getString(
            R.string.app_detail_away,
            Formatter.formatShortFileSize(arabic, 1_024),
            Formatter.formatShortFileSize(arabic, 0),
        )
        assertRightToLeft(compose.onNodeWithText(away))
        // The companies, from the tracker lists (DT-06).
        scrollTo(arabic.getString(R.string.app_detail_companies_title)).assertAtTheRight()
        scrollTo(arabic.getString(R.string.category_analytics)).assertAtTheRight()
        // The destination's facts and their sources: Latin names inside Arabic lines.
        scrollTo(HOST).assertAtTheRight()
        assertRightToLeft(scrollTo(arabic.getString(R.string.dest_company, isolate("Example Chat Inc"))))
        scrollTo(arabic.getString(R.string.dest_categories, arabic.getString(R.string.category_analytics)))
        val listedWhy = arabic.getString(
            R.string.dest_listed_why, isolate("Tracker Radar 2026-10-09"), isolate("example.com"),
        )
        scrollTo(listedWhy, count = 2) // the company and the categories come from that entry
        assertRightToLeft(compose.onAllNodesWithText(listedWhy)[0])
        assertRightToLeft(scrollTo(arabic.getString(R.string.dest_network, isolate("AS64500 EXAMPLE-NET"))))
        assertRightToLeft(scrollTo(arabic.getString(R.string.dest_network_why, isolate("IPtoASN 2026-10-15"))))
        val jordan = Locale.Builder().setRegion("JO").build().getDisplayCountry(Locale.forLanguageTag("ar"))
        scrollTo(arabic.getString(R.string.dest_country, jordan))
    }

    /** Scrolls the app detail list to the line [text]; checks it is there [count] times. */
    private fun scrollTo(text: String, count: Int = 1): SemanticsNodeInteraction {
        compose.onNodeWithTag(APP_DETAIL_TAG).performScrollToNode(hasText(text))
        compose.onAllNodesWithText(text).assertCountEquals(count)
        return compose.onAllNodesWithText(text)[0]
    }

    /** Arabic resources and a right-to-left layout, as on a phone set to Arabic. */
    @Composable
    private fun InArabic(content: @Composable () -> Unit) {
        CompositionLocalProvider(
            LocalContext provides arabic,
            LocalResources provides arabic.resources,
            LocalConfiguration provides arabic.resources.configuration,
            LocalLayoutDirection provides LayoutDirection.Rtl,
        ) {
            SentinelTheme(content)
        }
    }

    /** Closer to the right edge of the screen than to the left. */
    private fun SemanticsNodeInteraction.assertAtTheRight() {
        val root = compose.onRoot().getBoundsInRoot()
        val node = getBoundsInRoot()
        assertTrue(
            "$node should sit at the right of $root",
            root.right - node.right < node.left - root.left,
        )
    }

    private fun assertRightToLeft(text: SemanticsNodeInteraction) {
        val layouts = mutableListOf<TextLayoutResult>()
        val getLayout = text.fetchSemanticsNode().config.getOrNull(SemanticsActions.GetTextLayoutResult)
        checkNotNull(getLayout?.action) { "not a text" }.invoke(layouts)
        assertEquals(ResolvedTextDirection.Rtl, layouts.single().getParagraphDirection(0))
    }
}
