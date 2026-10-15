// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.icu.text.ListFormatter
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.getBoundsInRoot
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertFeedback
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.HistoryAlert
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** The alert framework (AL-01, AL-02) and its first rule, a monitoring gap (SP-03). */
@RunWith(AndroidJUnit4::class)
class AlertsTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val now = System.currentTimeMillis()

    private fun alert(severity: AlertSeverity = AlertSeverity.WARNING) = HistoryAlert(
        id = 7,
        rule = AlertRule.MONITORING_INTERRUPTED,
        severity = severity,
        createdMs = now,
        evidence = listOf(
            AlertEvidence.Gap(startedMs = null, reason = "Android stopped the VPN"),
            AlertEvidence.App(app = "org.example.vpn"),
        ),
        actions = listOf(AlertAction.StartMonitoring, AlertAction.OpenApp(app = "org.example.vpn")),
        open = true,
    )

    /** A stop nobody asked for raises one Warning alert, which the user can dismiss. */
    @Test
    fun aMonitoringGapRaisesOneAlertThatCanBeDismissed() {
        History.wipe(context)
        GapLog.open(context, 1_000L, "test reason")
        GapLog.open(context, 2_000L, "the first gap is still open")
        val history = History.get(context)
        val raised = history.alerts(true, 10u).single()
        assertEquals(AlertRule.MONITORING_INTERRUPTED, raised.rule)
        assertEquals(AlertSeverity.WARNING, raised.severity)
        assertEquals(listOf(AlertEvidence.Gap(startedMs = 1_000L, reason = "test reason")), raised.evidence)
        assertEquals(listOf<AlertAction>(AlertAction.StartMonitoring), raised.actions)

        GapLog.closeOpen(context, 3_000L)
        assertTrue(history.dismissAlert(raised.id))
        assertTrue("dismissed", history.alerts(true, 10u).isEmpty())
        assertEquals(1, history.alerts(false, 10u).size)
        History.wipe(context)
    }

    /** AL-02: severity, title and one-sentence explanation, then evidence, then actions. */
    @Test
    fun theDetailShowsTitleAndExplanationThenEvidenceThenActions() {
        val chosen = mutableListOf<AlertAction>()
        var dismissed = false
        compose.setContent {
            SentinelTheme {
                AlertDetail(
                    details = AlertDetails(alert(), mapOf("org.example.vpn" to "Example VPN")),
                    onBack = {},
                    onAction = { chosen += it },
                    onDismiss = { dismissed = true },
                )
            }
        }
        val lines = listOf(
            context.getString(R.string.severity_warning),
            context.getString(R.string.alert_monitoring_interrupted_title),
            context.getString(R.string.alert_monitoring_interrupted_text),
            context.getString(R.string.alert_evidence_title),
            context.getString(
                R.string.alert_evidence_gap,
                context.getString(R.string.gap_time_unknown),
                isolate("Android stopped the VPN"),
            ),
            context.getString(R.string.alert_evidence_app, isolate("Example VPN")),
            context.getString(R.string.alert_actions_title),
            context.getString(R.string.alert_action_start_monitoring),
            context.getString(R.string.alert_action_open_app, isolate("Example VPN")),
            context.getString(R.string.alert_dismiss),
        )
        val tops = lines.map { line ->
            compose.onNodeWithText(line).performScrollTo().assertIsDisplayed()
            compose.onNodeWithText(line).getBoundsInRoot().top
        }
        assertEquals("in this order: $lines", tops.sorted(), tops)

        compose.onNodeWithText(context.getString(R.string.alert_action_start_monitoring)).performClick()
        compose.onNodeWithText(context.getString(R.string.alert_action_open_app, isolate("Example VPN")))
            .performClick()
        assertEquals(listOf(AlertAction.StartMonitoring, AlertAction.OpenApp(app = "org.example.vpn")), chosen)
        compose.onNodeWithText(context.getString(R.string.alert_dismiss)).performScrollTo().performClick()
        assertTrue(dismissed)
    }

    /** AL-05: allowing a gap alert stops the next gaps from raising one, until undone. */
    @Test
    fun allowingAnAlertStopsTheNextOnesLikeIt() {
        History.wipe(context)
        val history = History.get(context)
        GapLog.open(context, 1_000L, "first")
        GapLog.closeOpen(context, 2_000L)
        val first = history.alerts(true, 10u).single()
        assertTrue(history.setFeedback(first.id, AlertFeedback.ALLOWED))
        assertTrue("allowing dismisses it", history.alerts(true, 10u).isEmpty())
        GapLog.open(context, 3_000L, "second")
        GapLog.closeOpen(context, 4_000L)
        assertEquals("no alert for an allowed kind", 1, history.alerts(false, 10u).size)

        assertTrue(history.setFeedback(first.id, null))
        GapLog.open(context, 5_000L, "third")
        GapLog.closeOpen(context, 6_000L)
        assertEquals("alerts again once undone", 1, history.alerts(true, 10u).size)
        History.wipe(context)
    }

    /** AL-05: feedback on the screen, its result, and undo; a Critical alert cannot be allowed. */
    @Test
    fun feedbackCanBeGivenAndTakenBack() {
        val given = mutableListOf<AlertFeedback?>()
        var shown by mutableStateOf(alert())
        compose.setContent {
            SentinelTheme {
                AlertDetail(AlertDetails(shown, emptyMap()), {}, {}, {}, onFeedback = { given += it })
            }
        }
        fun tap(text: Int) = compose.onNodeWithText(context.getString(text)).performScrollTo().performClick()
        tap(R.string.alert_feedback_not_useful)
        tap(R.string.alert_feedback_allow)
        assertEquals(listOf(AlertFeedback.NOT_USEFUL, AlertFeedback.ALLOWED), given)

        shown = alert().copy(feedback = AlertFeedback.NOT_USEFUL, open = false)
        compose.waitForIdle()
        compose.onNodeWithText(context.getString(R.string.alert_feedback_was_not_useful))
            .performScrollTo().assertIsDisplayed()
        tap(R.string.alert_feedback_undo)
        assertEquals(null, given.last())

        shown = alert().copy(feedback = AlertFeedback.ALLOWED, open = false)
        compose.waitForIdle()
        compose.onNodeWithText(context.getString(R.string.alert_feedback_was_allowed))
            .performScrollTo().assertIsDisplayed()

        shown = alert(AlertSeverity.CRITICAL)
        compose.waitForIdle()
        compose.onNodeWithText(context.getString(R.string.alert_feedback_not_useful))
            .performScrollTo().assertIsDisplayed()
        compose.onAllNodesWithText(context.getString(R.string.alert_feedback_allow)).assertCountEquals(0)
    }

    /**
     * CM-04: a new app's first connection and an app's new places read as their rule
     * says, list where the app connected, and count the places not listed.
     */
    @Test
    fun firstSeenAlertsSayWhereTheAppConnected() {
        fun firstSeen(rule: AlertRule, destinations: List<String>, more: UInt) = HistoryAlert(
            id = 8,
            rule = rule,
            severity = AlertSeverity.INFO,
            createdMs = now,
            evidence = listOf(
                AlertEvidence.App(app = "org.example.new"),
                AlertEvidence.Destinations(destinations = destinations, more = more),
            ),
            actions = listOf(AlertAction.OpenApp(app = "org.example.new")),
            open = true,
        )
        var shown by mutableStateOf(firstSeen(AlertRule.FIRST_NETWORK_USE, listOf("api.example"), 0u))
        compose.setContent {
            SentinelTheme {
                AlertDetail(AlertDetails(shown, mapOf("org.example.new" to "New App")), {}, {}, {})
            }
        }
        fun shows(text: String) = compose.onNodeWithText(text).performScrollTo().assertIsDisplayed()
        shows(context.getString(R.string.severity_info))
        shows(context.getString(R.string.alert_first_network_use_title))
        shows(context.getString(R.string.alert_first_network_use_text))
        shows(context.getString(R.string.alert_evidence_app, isolate("New App")))
        shows(context.getString(R.string.alert_evidence_destinations, isolate("api.example")))
        shows(context.getString(R.string.alert_action_open_app, isolate("New App")))

        val places = listOf("a.example", "b.example", "c.example")
        shown = firstSeen(AlertRule.NEW_DESTINATION, places, 1u)
        compose.waitForIdle()
        shows(context.getString(R.string.alert_new_destination_title))
        shows(context.getString(R.string.alert_new_destination_text))
        val listed = ListFormatter.getInstance(context.resources.configuration.locales[0])
            .format(places.map(::isolate))
        shows(
            context.getString(R.string.alert_evidence_destinations, listed) + " " +
                context.resources.getQuantityString(R.plurals.alert_evidence_more_destinations, 1, 1),
        )
    }

    /** A dismissed alert says so and offers no Dismiss button. */
    @Test
    fun aDismissedAlertSaysSo() {
        compose.setContent {
            SentinelTheme {
                AlertDetail(AlertDetails(alert().copy(open = false), emptyMap()), {}, {}, {})
            }
        }
        compose.onNodeWithText(context.getString(R.string.alert_dismissed)).performScrollTo().assertIsDisplayed()
        compose.onAllNodesWithText(context.getString(R.string.alert_dismiss)).assertCountEquals(0)
    }

    /** AL-01: the four severities have their own name and their own colour. */
    @Test
    fun eachSeverityLooksDifferent() {
        val severities = AlertSeverity.entries
        compose.setContent {
            SentinelTheme {
                Column { severities.forEach { SeverityBadge(it) } }
            }
        }
        val names = severities.map { severity ->
            val node = compose.onNodeWithTag(severityTag(severity), useUnmergedTree = true)
            node.assertIsDisplayed()
            val bitmap = node.captureToImage().asAndroidBitmap()
            // The badge's own colour, in its top padding, clear of the rounded corners.
            bitmap.getPixel(bitmap.width / 2, 1)
        }
        assertEquals("colours $names", severities.size, names.toSet().size)
        val labels = listOf(
            R.string.severity_info,
            R.string.severity_warning,
            R.string.severity_high,
            R.string.severity_critical,
        ).map(context::getString)
        assertEquals(severities.size, labels.toSet().size)
        labels.forEach { compose.onNodeWithText(it).assertIsDisplayed() }
    }

    /** The main screen lists open alerts first; tapping one opens it. */
    @Test
    fun theMainScreenListsOpenAlerts() {
        var opened: Long? = null
        compose.setContent {
            SentinelTheme {
                MonitorContent(
                    coreVersion = "test",
                    status = Monitor.Status.OFF,
                    snapshot = null,
                    flows = emptyList(),
                    gaps = emptyList(),
                    away = emptyList(),
                    alerts = listOf(alert(AlertSeverity.HIGH)),
                    onStart = {},
                    onStop = {},
                    onShowLive = {},
                    onOpenApp = {},
                    onOpenAlert = { opened = it },
                    onWipe = {},
                )
            }
        }
        compose.onNodeWithText(context.getString(R.string.alerts_title)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.severity_high)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.alert_monitoring_interrupted_title)).performClick()
        assertEquals(7L, opened)
    }
}
