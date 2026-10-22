// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.content.res.Configuration
import android.icu.text.ListFormatter
import android.text.format.Formatter
import androidx.compose.material3.Text
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
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.style.ResolvedTextDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AppAccess
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.AllowedRule
import io.github.malekhasan.sentinel.core.CategoryFact
import io.github.malekhasan.sentinel.core.CompanyFact
import io.github.malekhasan.sentinel.core.ExportFormat
import io.github.malekhasan.sentinel.core.ExportKind
import io.github.malekhasan.sentinel.core.FeedSource
import io.github.malekhasan.sentinel.core.FeedStatus
import io.github.malekhasan.sentinel.core.FirewallMode
import io.github.malekhasan.sentinel.core.FirewallRule
import io.github.malekhasan.sentinel.core.FlowProto
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryApp
import io.github.malekhasan.sentinel.core.HistoryAway
import io.github.malekhasan.sentinel.core.HistoryCompany
import io.github.malekhasan.sentinel.core.HistoryDestination
import io.github.malekhasan.sentinel.core.HardeningItem
import io.github.malekhasan.sentinel.core.HardeningStatus
import io.github.malekhasan.sentinel.core.HardeningStep
import io.github.malekhasan.sentinel.core.HistoryFlow
import io.github.malekhasan.sentinel.core.IndicatorSighting
import io.github.malekhasan.sentinel.core.IndicatorThreat
import io.github.malekhasan.sentinel.core.JournalEntry
import io.github.malekhasan.sentinel.core.KnownTraces
import io.github.malekhasan.sentinel.core.JournalState
import io.github.malekhasan.sentinel.core.LiveApp
import io.github.malekhasan.sentinel.core.NameSource
import io.github.malekhasan.sentinel.core.RuleAction
import io.github.malekhasan.sentinel.core.RuleDestination
import io.github.malekhasan.sentinel.core.SensorKind
import io.github.malekhasan.sentinel.core.SharingSiteKind
import io.github.malekhasan.sentinel.core.SensorUse
import io.github.malekhasan.sentinel.core.SpecialAccess
import java.text.DateFormat
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Date
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
private const val LIST_SOURCE = "Sentinel test indicators"

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
        val alert = alert()
        compose.setContent {
            InArabic {
                MonitorContent(
                    coreVersion = "0.0.1",
                    status = Monitor.Status.OFF,
                    snapshot = null,
                    flows = listOf(flow),
                    gaps = listOf(GapLog.Gap(now - 60_000, now, "test")),
                    away = listOf(away),
                    alerts = listOf(alert),
                    onStart = {},
                    onStop = {},
                    onShowLive = {},
                    onOpenApp = {},
                    onOpenAlert = {},
                    onWipe = {},
                    firewallMode = FirewallMode.BLOCK_UNKNOWN,
                    isolatedSince = now,
                    keepFlowsDays = 30u,
                )
            }
        }
        compose.onNodeWithText(arabic.getString(R.string.tagline)).assertIsDisplayed()
        // Isolation (RA-03), with its time in the Arabic sentence.
        compose.onNodeWithText(arabic.getString(R.string.isolation_title)).assertAtTheRight()
        val format = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.forLanguageTag("ar"))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.isolation_text, format.format(Date(now)))))
        compose.onNodeWithText(arabic.getString(R.string.alerts_title)).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.severity_warning), useUnmergedTree = true).assertAtTheRight()
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

        // A gap in monitoring, how long it lasted, and what a gap means (SP-03).
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.gaps_text)).performScrollTo())
        val gapLine = arabic.getString(
            R.string.gap_closed_length,
            format.format(Date(now - 60_000)),
            format.format(Date(now)),
            duration(60_000, Locale.forLanguageTag("ar")),
            "test",
        )
        assertRightToLeft(compose.onNodeWithText(gapLine))

        // The firewall's modes (CM-08).
        compose.onNodeWithText(arabic.getString(R.string.firewall_title)).performScrollTo().assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.firewall_mode_block_unknown), useUnmergedTree = true)
            .performScrollTo()
            .assertAtTheRight()

        // How long the history keeps connections, and the rest (SRS §13.2).
        compose.onNodeWithText(arabic.getString(R.string.retention_title)).performScrollTo().assertAtTheRight()
        compose.onNodeWithText(
            arabic.resources.getQuantityString(R.plurals.retention_days, 30, 30),
            useUnmergedTree = true,
        ).performScrollTo().assertAtTheRight()
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.retention_text)).performScrollTo())
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
    fun indicatorList() {
        val status = FeedStatus(
            version = 3u,
            createdMs = now - 20 * 24 * 60 * 60 * 1000L,
            expiresMs = now - 24 * 60 * 60 * 1000L,
            sources = listOf(FeedSource("sentinel-test", LIST_SOURCE, "https://example.org", "CC0", 3u)),
            indicators = 3u,
            skipped = 0u,
        )
        val since = now - 30 * 24 * 60 * 60 * 1000L
        compose.setContent {
            InArabic {
                IndicatorList(
                    IndicatorFeed.State(status = status, last = IndicatorFeed.Outcome.UP_TO_DATE),
                    {},
                    {},
                    KnownTraces(alerts = 0u, checkedVersion = 3u, sinceMs = since),
                )
            }
        }
        compose.onNodeWithText(arabic.getString(R.string.feed_title)).assertAtTheRight()
        val dates = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.forLanguageTag("ar"))
        val installed = arabic.getString(R.string.feed_installed, dates.format(Date(status.createdMs)), "3")
        assertRightToLeft(compose.onNodeWithText(installed))
        // Arabic's own plural for three, around a Latin source name.
        val count = arabic.resources.getQuantityString(R.plurals.feed_indicators, 3, 3, isolate(LIST_SOURCE))
        assertRightToLeft(compose.onNodeWithText(count))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.feed_expired, dates.format(Date(status.expiresMs)))))
        compose.onNodeWithText(arabic.getString(R.string.feed_outcome_up_to_date)).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.feed_check)).assertAtTheRight()
        // The result (MS-15), with its dates and limits.
        compose.onNodeWithText(arabic.getString(R.string.feed_result_none)).assertAtTheRight()
        val none = arabic.getString(
            R.string.feed_result_none_text,
            dates.format(Date(since)),
            dates.format(Date(status.createdMs)),
        )
        assertRightToLeft(compose.onNodeWithText(none))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.feed_result_limits)))
    }

    @Test
    fun journalScreen() {
        val rule = FirewallRule(PACKAGE, RuleDestination.Domain(HOST), RuleAction.BLOCK)
        val entry = JournalEntry(
            id = 1,
            atMs = now,
            alertId = 1,
            before = JournalState.Rule(key = "k", rule = null),
            after = JournalState.Rule(key = "k", rule = rule),
            undoneMs = null,
            canUndo = true,
        )
        compose.setContent {
            InArabic { Journal(listOf(JournalRow(entry, LABEL)), onBack = {}, onUndo = {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.back)).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.journal_title)).assertAtTheRight()
        // Latin names inside the sentence must not turn it around.
        val said = arabic.getString(R.string.journal_block_for_app, isolate(HOST), isolate(LABEL))
        compose.onNodeWithText(said).assertAtTheRight()
        assertRightToLeft(compose.onNodeWithText(said))
        compose.onNodeWithText(arabic.getString(R.string.journal_from_alert)).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.journal_undo)).assertAtTheRight()
    }

    /**
     * Audit A-43: a name cannot leave its isolate. One that holds an isolate's end and an
     * override loses both, and the Arabic sentence it starts stays right to left.
     */
    @Test
    fun aNameCannotTurnTheSentenceAround() {
        val hostile = "Bad\u2069\u202Eppa"
        assertEquals("\u2068Badppa\u2069", isolate(hostile))
        val said = arabic.getString(R.string.flow_open, isolate(hostile), isolate(HOST))
        compose.setContent { InArabic { Text(said) } }
        assertRightToLeft(compose.onNodeWithText(said))
    }

    @Test
    fun allowedScreen() {
        val row = AllowedRow(AllowedRule(AlertRule.SPECIAL_ACCESS, PACKAGE, SpecialAccess.ACCESSIBILITY, now), LABEL)
        compose.setContent {
            InArabic { AllowedList(listOf(row), takenBack = LABEL, onBack = {}, onTakeBack = {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.back)).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.allowed_title)).assertAtTheRight()
        // Texts that may fill a line are checked by their direction, not their place.
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.allowed_explainer)))
        // A Latin name inside the sentence must not turn it around.
        val said = arabic.getString(R.string.allowed_taken_back, isolate(LABEL))
        assertRightToLeft(compose.onNodeWithText(said))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_accessibility_title)))
        compose.onNodeWithText(arabic.getString(R.string.allowed_take_back)).assertAtTheRight()
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
            InArabic {
                AppDetail(
                    PACKAGE,
                    AppDetails(LABEL, history, openFlows = 2, access = AppAccess(RuleAction.BLOCK, false)),
                    onBack = {},
                )
            }
        }
        compose.onNodeWithText(arabic.getString(R.string.back)).assertAtTheRight()
        compose.onNodeWithText(LABEL).assertAtTheRight()
        // Whether it may use the internet (RA-01).
        scrollTo(arabic.getString(R.string.app_detail_access_title)).assertAtTheRight()
        assertRightToLeft(scrollTo(arabic.getString(R.string.app_detail_blocked)))
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

    @Test
    fun alertDetail() {
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert(), mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.back)).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.severity_warning), useUnmergedTree = true).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.alert_monitoring_interrupted_title)).assertAtTheRight()
        // Lines that carry Latin names or an English reason stay right to left.
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_monitoring_interrupted_text)))
        val gap = arabic.getString(
            R.string.alert_evidence_gap, arabic.getString(R.string.gap_time_unknown), isolate("Android stopped the VPN"),
        )
        assertRightToLeft(compose.onNodeWithText(gap))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_evidence_app, isolate(LABEL))))
        compose.onNodeWithText(arabic.getString(R.string.alert_action_open_app, isolate(LABEL)), useUnmergedTree = true)
            .assertExists()
        // Feedback (AL-05).
        compose.onNodeWithText(arabic.getString(R.string.alert_feedback_title)).performScrollTo().assertAtTheRight()
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_feedback_note)).performScrollTo())
    }

    /** CM-04: where an app connected, names and the count of the rest, right to left. */
    @Test
    fun newDestinationAlert() {
        val places = listOf("a.example", "b.example")
        val alert = HistoryAlert(
            id = 2,
            rule = AlertRule.NEW_DESTINATION,
            severity = AlertSeverity.INFO,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.Destinations(destinations = places, more = 3u),
            ),
            actions = listOf(AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.alert_new_destination_title)).assertAtTheRight()
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_new_destination_text)))
        val listed = ListFormatter.getInstance(arabic.resources.configuration.locales[0]).format(places.map(::isolate))
        val line = arabic.getString(R.string.alert_evidence_destinations, listed) + " " +
            arabic.resources.getQuantityString(R.plurals.alert_evidence_more_destinations, 3, 3)
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
    }

    /** CM-08: a blocked new app's alert, with its name inside the Arabic action. */
    @Test
    fun newAppBlockedAlert() {
        val alert = HistoryAlert(
            id = 4,
            rule = AlertRule.FIRST_NETWORK_USE,
            severity = AlertSeverity.INFO,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.Destinations(destinations = listOf(HOST), more = 0u),
                AlertEvidence.NewAppBlocked,
            ),
            actions = listOf(AlertAction.AllowApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.alert_first_network_use_blocked_title)).assertAtTheRight()
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_first_network_use_blocked_text)))
        assertRightToLeft(
            compose.onNodeWithText(arabic.getString(R.string.alert_evidence_new_app_blocked)).performScrollTo(),
        )
        val allow = arabic.getString(R.string.alert_action_allow_app, isolate(LABEL))
        compose.onNodeWithText(allow).performScrollTo()
        assertRightToLeft(compose.onNodeWithText(allow, useUnmergedTree = true))
    }

    /** ID-13: a known indicator's alert. What was seen, the family, the source and the
     *  report's link are written left to right inside right-to-left lines. */
    @Test
    fun knownIndicatorAlert() {
        val alert = HistoryAlert(
            id = 5,
            rule = AlertRule.KNOWN_INDICATOR,
            severity = AlertSeverity.CRITICAL,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.Indicator(
                    indicator = "spy.example",
                    seen = "cdn.spy.example",
                    sighting = IndicatorSighting.DNS_QUERY,
                    family = "Pegasus",
                    threat = IndicatorThreat.SPYWARE,
                    source = "Amnesty International Security Lab",
                    date = "2021-07-18",
                    report = "https://example.org/report",
                ),
            ),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.severity_critical), useUnmergedTree = true).assertAtTheRight()
        compose.onNodeWithText(arabic.getString(R.string.alert_known_indicator_title)).assertAtTheRight()
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_known_indicator_text)))
        val date = LocalDate.of(2021, 7, 18).format(
            DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(arabic.resources.configuration.locales[0]),
        )
        val line = listOf(
            arabic.getString(R.string.alert_evidence_indicator_dns, isolate("cdn.spy.example")),
            arabic.getString(
                R.string.alert_evidence_indicator_listed,
                isolate("spy.example"),
                isolate("Pegasus"),
                arabic.getString(R.string.alert_threat_spyware),
            ),
            arabic.getString(
                R.string.alert_evidence_indicator_source,
                isolate("Amnesty International Security Lab"),
                date,
                isolate("https://example.org/report"),
            ),
        ).joinToString(" ")
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
        val block = arabic.getString(R.string.alert_action_block_app, isolate(LABEL))
        compose.onNodeWithText(block).performScrollTo()
        assertRightToLeft(compose.onNodeWithText(block, useUnmergedTree = true))
        // A Critical alert cannot be allowed away (AL-05).
        compose.onNodeWithText(arabic.getString(R.string.alert_feedback_allow)).assertDoesNotExist()
        // MS-13 advice, with a helpline's Latin name inside an Arabic label.
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_advice_keep)).performScrollTo())
        val helpline = arabic.getString(R.string.alert_advice_access_now)
        compose.onNodeWithText(helpline).performScrollTo()
        assertRightToLeft(compose.onNodeWithText(helpline, useUnmergedTree = true))
    }

    /** ID-13: an installed app the list names, with its package name written left to right
     *  inside right-to-left lines. */
    @Test
    fun installedAppAlert() {
        val alert = HistoryAlert(
            id = 8,
            rule = AlertRule.KNOWN_INDICATOR,
            severity = AlertSeverity.CRITICAL,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.Indicator(
                    indicator = PACKAGE,
                    seen = PACKAGE,
                    sighting = IndicatorSighting.INSTALLED_PACKAGE,
                    family = "Example",
                    threat = IndicatorThreat.STALKERWARE,
                    source = "Example lab",
                    date = "2025-01-31",
                    report = "https://example.org/report",
                ),
            ),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_known_indicator_app_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_known_indicator_app_text)))
        val line = compose.onAllNodesWithText(
            arabic.getString(R.string.alert_evidence_indicator_package, isolate(PACKAGE)),
            substring = true,
        )
        line.assertCountEquals(1)
        assertRightToLeft(line[0].performScrollTo())
    }

    /** ID-12: an app that gained notification access, with its name written left to
     *  right inside right-to-left lines. */
    @Test
    fun specialAccessAlert() {
        val alert = HistoryAlert(
            id = 9,
            rule = AlertRule.SPECIAL_ACCESS,
            severity = AlertSeverity.HIGH,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.Access(access = SpecialAccess.NOTIFICATION_LISTENER),
            ),
            actions = listOf(
                AlertAction.OpenAccessSettings(access = SpecialAccess.NOTIFICATION_LISTENER),
                AlertAction.BlockApp(app = PACKAGE),
                AlertAction.OpenApp(app = PACKAGE),
            ),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_notification_access_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_notification_access_text)))
        assertRightToLeft(
            compose.onNodeWithText(arabic.getString(R.string.alert_evidence_notification_access)).performScrollTo(),
        )
        // The action is a button: its label is read from the unmerged tree.
        val settings = arabic.getString(R.string.alert_action_open_access_settings)
        compose.onNodeWithText(settings).performScrollTo()
        assertRightToLeft(compose.onNodeWithText(settings, useUnmergedTree = true))
    }

    /** ID-10: a certificate added to the trusted ones, with its subject and fingerprint
     *  written left to right inside a right-to-left line. */
    @Test
    fun newRootCertificateAlert() {
        val subject = "CN=Proxy CA,O=Example"
        val sha256 = "0d21c5b162bae01a6141f680834a9a89f7a677b6ae988ef60b7389a3a6892c6f"
        val alert = HistoryAlert(
            id = 10,
            rule = AlertRule.NEW_ROOT_CERTIFICATE,
            severity = AlertSeverity.HIGH,
            createdMs = now,
            evidence = listOf(AlertEvidence.Certificate(sha256 = sha256, subject = subject)),
            actions = listOf(AlertAction.OpenCertificateSettings),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, emptyMap()), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_new_root_certificate_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_new_root_certificate_text)))
        val line = arabic.getString(R.string.alert_evidence_certificate, isolate(subject), isolate(sha256))
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
        val settings = arabic.getString(R.string.alert_action_open_certificate_settings)
        compose.onNodeWithText(settings).performScrollTo()
        assertRightToLeft(compose.onNodeWithText(settings, useUnmergedTree = true))
    }

    /** MS-12: the hardening checklist, its steps and where they stand, right to left, with
     *  the security update's date written left to right. */
    @Test
    fun hardeningChecklist() {
        val items = listOf(
            HardeningItem(HardeningStep.ADVANCED_PROTECTION, HardeningStatus.NOT_AVAILABLE),
            HardeningItem(HardeningStep.SECURITY_UPDATE, HardeningStatus.TO_DO),
            HardeningItem(HardeningStep.MESSAGING_APPS, HardeningStatus.CHECK_YOURSELF),
        )
        compose.setContent {
            InArabic { HardeningChecklist(items, "2023-02-05", onBack = {}, onOpen = {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.hardening_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.hardening_explainer)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.hardening_security_update_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.hardening_status_to_do)))
        val patch = arabic.getString(R.string.hardening_security_patch, isolate("2023-02-05"))
        assertRightToLeft(compose.onNodeWithText(patch).performScrollTo())
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.hardening_status_check)).performScrollTo())
    }

    /** THREAT-MODEL-A E6: the question the notification's Stop asks, right to left
     *  although it names Sentinel. */
    @Test
    fun stopQuestion() {
        compose.setContent { InArabic { StopMonitoringQuestion(onStop = {}, onKeep = {}) } }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.stop_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.stop_text)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.action_stop)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.stop_keep)))
    }

    /** SRS §13.2: the question a shorter time to keep connections asks, right to left
     *  although it carries a number. */
    @Test
    fun shorterKeepQuestion() {
        compose.setContent { InArabic { ShorterKeepQuestion(7u, onChange = {}, onCancel = {}) } }
        val days = arabic.resources.getQuantityString(R.plurals.retention_days, 7, 7)
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.retention_shorter_title, days)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.retention_shorter_text)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.retention_shorter_change)))
    }

    /** SP-03: the steps that keep monitoring running, and a maker's own, right to left
     *  although they name Sentinel and the maker's settings. */
    @Test
    fun keepRunning() {
        val items = listOf(
            KeepRunning.Item(KeepRunning.Step.BATTERY, done = false),
            KeepRunning.Item(KeepRunning.Step.ALWAYS_ON, done = null),
        )
        compose.setContent {
            InArabic {
                KeepRunningContent(
                    items, KeepRunning.Maker.SAMSUNG, onBack = {}, onOpen = {}, onOpenAppSettings = {},
                )
            }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.keep_running_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.keep_running_explainer)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.keep_running_battery_title)))
        assertRightToLeft(
            compose.onNodeWithText(arabic.getString(R.string.keep_running_always_on_text)).performScrollTo(),
        )
        assertRightToLeft(
            compose.onNodeWithText(arabic.getString(R.string.keep_running_status_while_monitoring)).performScrollTo(),
        )
        assertRightToLeft(
            compose.onNodeWithText(arabic.getString(R.string.keep_running_maker_samsung)).performScrollTo(),
        )
    }

    /** SRS §12.3: the export screen, how the last export went, and the warning before the
     *  file is chosen, right to left. */
    @Test
    fun export() {
        val choice = HistoryExport.Choice(ExportKind.FLOWS, ExportFormat.CSV, HistoryExport.Range.ALL)
        compose.setContent {
            InArabic {
                ExportContent(choice, HistoryExport.State.Saved(12_345), onChoice = {}, onBack = {}, onSave = {})
            }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.export_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.export_explainer)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.export_kind_flows)).performScrollTo())
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.export_range_note)).performScrollTo())
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.export_format_csv)).performScrollTo())
        val saved = arabic.getString(R.string.export_saved, isolate(Formatter.formatShortFileSize(arabic, 12_345)))
        assertRightToLeft(compose.onNodeWithText(saved).performScrollTo())
        compose.onNodeWithText(arabic.getString(R.string.export_action)).performScrollTo().performClick()
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.export_warning_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.export_warning_text)))
    }

    /** SE-01: the main screen's record of microphone and camera use, right to left, with
     *  the guessed app's name written left to right. */
    @Test
    fun sensorUses() {
        val use = SensorUse(
            id = 1, sensor = SensorKind.MICROPHONE, startedMs = now - 60_000, endedMs = now,
            guess = PACKAGE, userPresent = false,
        )
        compose.setContent {
            InArabic { SensorUses(listOf(use), usageAccess = false, labelFor = { LABEL }, onUsageAccess = {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.sensors_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.sensor_use_guess, isolate(LABEL))))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.sensor_use_away)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.sensors_usage_access)))
    }

    /** SE-04: a use of the microphone with the screen off, right to left. */
    @Test
    fun sensorAlert() {
        val alert = HistoryAlert(
            id = 11,
            rule = AlertRule.SENSOR_WHILE_AWAY,
            severity = AlertSeverity.HIGH,
            createdMs = now,
            evidence = listOf(AlertEvidence.Sensor(sensor = SensorKind.MICROPHONE, startedMs = now, guess = PACKAGE)),
            actions = listOf(AlertAction.OpenPrivacySettings),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_microphone_while_away_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_microphone_while_away_text)))
        val action = arabic.getString(R.string.alert_action_open_privacy_settings)
        compose.onNodeWithText(action).performScrollTo()
        assertRightToLeft(compose.onNodeWithText(action, useUnmergedTree = true))
    }

    /** THREAT-MODEL-A D2: an app at its flow limit, right to left, with the limit's number. */
    @Test
    fun flowLimitAlert() {
        val alert = HistoryAlert(
            id = 12,
            rule = AlertRule.FLOW_LIMIT,
            severity = AlertSeverity.WARNING,
            createdMs = now,
            evidence = listOf(AlertEvidence.App(app = PACKAGE), AlertEvidence.FlowLimit(limit = 512u)),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_flow_limit_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_flow_limit_text)))
        val line = arabic.getString(R.string.alert_evidence_flow_limit, 512)
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
    }

    /** DL-04: check-ins at set times, right to left, with the server's name, the interval
     *  and the size in Arabic. */
    @Test
    fun beaconAlert() {
        val alert = HistoryAlert(
            id = 13,
            rule = AlertRule.BEACON_LIKE,
            severity = AlertSeverity.INFO,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.Beacon(destination = HOST, intervalMs = 60_000, checkIns = 8u, maxBytes = 1_200uL),
            ),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_beacon_like_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_beacon_like_text)))
        val line = arabic.getString(
            R.string.alert_evidence_beacon,
            isolate(HOST),
            8,
            duration(60_000, Locale.forLanguageTag("ar")),
            Formatter.formatShortFileSize(arabic, 1_200),
        )
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
    }

    /** DL-05: lookups that look like data hidden in DNS, right to left, with the domain
     *  and an example written left to right. */
    @Test
    fun dnsTunnelAlert() {
        val example = "6f1d0a9c3b2e4d5f8a7b.t.tunnel.example"
        val alert = HistoryAlert(
            id = 14,
            rule = AlertRule.DNS_TUNNEL,
            severity = AlertSeverity.WARNING,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.DnsNames(domain = "tunnel.example", names = 20u, example = example),
            ),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_dns_tunnel_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_dns_tunnel_text)))
        val line = arabic.getString(R.string.alert_evidence_dns_names, 20, isolate("tunnel.example"), isolate(example))
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
    }

    /** DL-05: an app's own encrypted DNS, right to left, with the service's name. */
    @Test
    fun ownEncryptedDnsAlert() {
        val alert = HistoryAlert(
            id = 15,
            rule = AlertRule.OWN_ENCRYPTED_DNS,
            severity = AlertSeverity.INFO,
            createdMs = now,
            evidence = listOf(AlertEvidence.App(app = PACKAGE), AlertEvidence.EncryptedDns(server = "dns.google")),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_own_encrypted_dns_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_own_encrypted_dns_text)))
        val line = arabic.getString(R.string.alert_evidence_encrypted_dns, isolate("dns.google"))
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
    }

    /** DL-02: an upload surge, right to left, with the sizes in Arabic. */
    @Test
    fun uploadSurgeAlert() {
        val alert = HistoryAlert(
            id = 16,
            rule = AlertRule.UPLOAD_SURGE,
            severity = AlertSeverity.WARNING,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.UploadSurge(lastDay = 52_428_800uL, usualDay = 2_097_152uL, days = 14u),
            ),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_upload_surge_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_upload_surge_text)))
        val line = arabic.getString(
            R.string.alert_evidence_upload_surge,
            Formatter.formatShortFileSize(arabic, 52_428_800),
            14,
            Formatter.formatShortFileSize(arabic, 2_097_152),
        )
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
    }

    /** DL-06: an upload to a sharing site, right to left, with the site's name written
     *  left to right and what the site is for in Arabic. */
    @Test
    fun sharingSiteAlert() {
        val alert = HistoryAlert(
            id = 17,
            rule = AlertRule.SHARING_SITE_UPLOAD,
            severity = AlertSeverity.WARNING,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.SharingSite(
                    destination = "pastebin.com",
                    site = SharingSiteKind.PASTE,
                    bytesUp = 40_000uL,
                ),
            ),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_sharing_site_upload_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_sharing_site_upload_text)))
        val line = arabic.getString(
            R.string.alert_evidence_sharing_site,
            Formatter.formatShortFileSize(arabic, 40_000),
            isolate("pastebin.com"),
            arabic.getString(R.string.sharing_site_paste),
        )
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
    }

    /** SP-02: the alert that monitoring keeps stopping, right to left, with its count and
     *  hours in Arabic and the way to the steps that keep monitoring running. */
    @Test
    fun monitoringKeepsStoppingAlert() {
        val alert = HistoryAlert(
            id = 19,
            rule = AlertRule.MONITORING_KEEPS_STOPPING,
            severity = AlertSeverity.CRITICAL,
            createdMs = now,
            evidence = listOf(AlertEvidence.RepeatedGaps(count = 3u, hours = 24u)),
            actions = listOf(AlertAction.OpenKeepRunning),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf()), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_monitoring_keeps_stopping_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_monitoring_keeps_stopping_text)))
        val line = arabic.resources.getQuantityString(R.plurals.alert_evidence_repeated_gaps, 3, 3, 24)
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
        compose.onNodeWithText(arabic.getString(R.string.keep_running_action)).performScrollTo().assertIsDisplayed()
    }

    /** THREAT-MODEL-A T6: the alert that the history was started anew, right to left,
     *  with no empty "what Sentinel saw" section. */
    @Test
    fun historyStartedAnewAlert() {
        val alert = HistoryAlert(
            id = 18,
            rule = AlertRule.HISTORY_STARTED_ANEW,
            severity = AlertSeverity.WARNING,
            createdMs = now,
            evidence = emptyList(),
            actions = emptyList(),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf()), {}, {}, {}) }
        }
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_history_started_anew_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_history_started_anew_text)))
        compose.onAllNodesWithText(arabic.getString(R.string.alert_evidence_title)).assertCountEquals(0)
    }

    /** MS-02: a match found in the history says how many connections, and on which days,
     *  right to left. */
    @Test
    fun pastIndicatorAlert() {
        val day = 24 * 60 * 60 * 1000L
        val alert = HistoryAlert(
            id = 6,
            rule = AlertRule.KNOWN_INDICATOR,
            severity = AlertSeverity.CRITICAL,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = PACKAGE),
                AlertEvidence.Indicator(
                    indicator = "spy.example",
                    seen = "cdn.spy.example",
                    sighting = IndicatorSighting.CONNECTION_NAME,
                    family = "Pegasus",
                    threat = IndicatorThreat.SPYWARE,
                    source = "Amnesty International Security Lab",
                    date = "2021-07-18",
                    report = "https://example.org/report",
                ),
                AlertEvidence.PastConnections(firstMs = now - 3 * day, lastMs = now - day, connections = 12uL),
            ),
            actions = listOf(AlertAction.BlockApp(app = PACKAGE), AlertAction.OpenApp(app = PACKAGE)),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, mapOf(PACKAGE to LABEL)), {}, {}, {}) }
        }
        // The title wraps across the whole width on a small screen: its direction is checked.
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_known_indicator_past_title)))
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_known_indicator_past_text)))
        val dates = DateFormat.getDateInstance(DateFormat.MEDIUM, arabic.resources.configuration.locales[0])
        val line = arabic.resources.getQuantityString(
            R.plurals.alert_evidence_past_between,
            12,
            12,
            dates.format(Date(now - 3 * day)),
            dates.format(Date(now - day)),
        )
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
    }

    /** CM-07: a changed setting's values, names written left to right, in a right-to-left line. */
    @Test
    fun networkSettingAlert() {
        val alert = HistoryAlert(
            id = 3,
            rule = AlertRule.PRIVATE_DNS_CHANGED,
            severity = AlertSeverity.WARNING,
            createdMs = now,
            evidence = listOf(AlertEvidence.PrivateDns(before = null, after = "dns.example")),
            actions = listOf(AlertAction.OpenNetworkSettings),
            open = true,
        )
        compose.setContent {
            InArabic { AlertDetail(AlertDetails(alert, emptyMap()), {}, {}, {}) }
        }
        compose.onNodeWithText(arabic.getString(R.string.alert_private_dns_changed_title)).assertAtTheRight()
        assertRightToLeft(compose.onNodeWithText(arabic.getString(R.string.alert_private_dns_changed_text)))
        val line = arabic.getString(
            R.string.alert_evidence_private_dns, arabic.getString(R.string.alert_setting_none), isolate("dns.example"),
        )
        assertRightToLeft(compose.onNodeWithText(line).performScrollTo())
        compose.onNodeWithText(arabic.getString(R.string.alert_action_open_network_settings), useUnmergedTree = true)
            .assertExists()
    }

    private fun alert() = HistoryAlert(
        id = 1,
        rule = AlertRule.MONITORING_INTERRUPTED,
        severity = AlertSeverity.WARNING,
        createdMs = now,
        evidence = listOf(
            AlertEvidence.Gap(startedMs = null, reason = "Android stopped the VPN"),
            AlertEvidence.App(app = PACKAGE),
        ),
        actions = listOf(AlertAction.StartMonitoring, AlertAction.OpenApp(app = PACKAGE)),
        open = true,
    )

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
