// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.compose.foundation.layout.Column
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
