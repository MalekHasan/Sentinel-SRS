// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.UiModeManager
import android.content.res.Configuration
import android.os.Build
import androidx.compose.material3.ColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isHeading
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.ExportFormat
import io.github.malekhasan.sentinel.core.ExportKind
import io.github.malekhasan.sentinel.core.FlowProto
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryFlow
import io.github.malekhasan.sentinel.core.NameSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

private const val PACKAGE = "org.example.chat"

/**
 * SRS §12.4 on a device (ADR-0037): TalkBack finds each screen's titles and hears what
 * a row opens and when a status changes; rows are large enough to tap; text at twice
 * the size is never cut; and the colours meet WCAG's contrast ratios, in high contrast
 * when the user asks Android for it.
 */
@RunWith(AndroidJUnit4::class)
class AccessibilityTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val now = System.currentTimeMillis()

    @Test
    fun titlesAreHeadings() {
        compose.setContent { SentinelTheme { MainScreen() } }
        val titles = listOf(R.string.app_name, R.string.alerts_title, R.string.recent_title, R.string.gaps_title)
        for (title in titles) {
            compose.onNode(hasText(context.getString(title)) and isHeading()).performScrollTo()
        }
    }

    /** TalkBack says what tapping a row does, and each row is at least 48 dp high. */
    @Test
    fun rowsSayWhatTheyOpenAndAreLargeEnoughToTap() {
        var openedApp: String? = null
        var openedAlert: Long? = null
        compose.setContent {
            SentinelTheme { MainScreen(onOpenApp = { openedApp = it }, onOpenAlert = { openedAlert = it }) }
        }
        compose.onNode(opens(R.string.a11y_open_alert)).performScrollTo()
            .assertHeightIsAtLeast(48.dp)
            .performClick()
        assertEquals(1L, openedAlert)
        compose.onNode(opens(R.string.a11y_open_app)).performScrollTo()
            .assertHeightIsAtLeast(48.dp)
            .performClick()
        assertEquals(PACKAGE, openedApp)
    }

    /** Whether monitoring runs, and how an export went, are read out when they change. */
    @Test
    fun statusChangesAreAnnounced() {
        val announced = SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite)
        compose.setContent { SentinelTheme { MainScreen() } }
        compose.onNode(hasText(context.getString(R.string.status_off)) and announced).assertExists()
    }

    @Test
    fun exportResultsAreAnnounced() {
        val announced = SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite)
        val choice = HistoryExport.Choice(ExportKind.FLOWS, ExportFormat.CSV, HistoryExport.Range.ALL)
        compose.setContent {
            SentinelTheme {
                ExportContent(choice, HistoryExport.State.Failed, onChoice = {}, onBack = {}, onSave = {})
            }
        }
        compose.onNode(hasText(context.getString(R.string.export_failed)) and announced).performScrollTo()
    }

    /** At twice the text size, the largest Android offers, no text is cut or runs off the screen. */
    @Test
    fun largeTextIsNeverCut() {
        compose.setContent { AtTwiceTheTextSize { MainScreen() } }
        assertNoTextCut("main screen")
    }

    @Test
    fun largeTextIsNeverCutOnTheAlert() {
        compose.setContent { AtTwiceTheTextSize { AlertDetail(AlertDetails(alert(), mapOf()), {}, {}, {}) } }
        assertNoTextCut("alert")
    }

    @Test
    fun largeTextIsNeverCutOnTheExport() {
        val choice = HistoryExport.Choice(ExportKind.FLOWS, ExportFormat.CSV, HistoryExport.Range.ALL)
        compose.setContent {
            AtTwiceTheTextSize {
                ExportContent(choice, HistoryExport.State.Saved(12_345), onChoice = {}, onBack = {}, onSave = {})
            }
        }
        assertNoTextCut("export")
    }

    @Test
    fun largeTextIsNeverCutOnKeepRunning() {
        val items = KeepRunning.Step.entries.map { KeepRunning.Item(it, done = false) }
        compose.setContent {
            AtTwiceTheTextSize {
                KeepRunningContent(
                    items,
                    KeepRunning.Maker.HUAWEI,
                    onBack = {},
                    onOpen = {},
                    onOpenAppSettings = {},
                )
            }
        }
        assertNoTextCut("keep running")
    }

    /**
     * WCAG 2.2: text stands out at least 4.5:1 from what is behind it (1.4.3), and the
     * outline of a button 3:1 (1.4.11). In high contrast, text 7:1 and outlines 4.5:1.
     */
    @Test
    fun coloursMeetWcagContrast() {
        val failures = mutableListOf<String>()
        for (dark in listOf(false, true)) {
            for (high in listOf(false, true)) {
                val scheme = sentinelColors(dark, high)
                val text = if (high) 7.0 else 4.5
                val outline = if (high) 4.5 else 3.0
                textPairs(scheme).forEach { (name, pair) ->
                    val ratio = contrast(pair.first, pair.second)
                    if (ratio < text) failures += "dark=$dark high=$high $name: $ratio"
                }
                val ratio = contrast(scheme.outline, scheme.surface)
                if (ratio < outline) failures += "dark=$dark high=$high outline: $ratio"
            }
        }
        assertEquals(emptyList<String>(), failures)
    }

    /**
     * Android 14's contrast setting at "medium" or "high" switches Sentinel to its
     * high-contrast colours. Android may recreate the open screen when the contrast
     * changes, so the screen sets its own content, as Sentinel's do ([ThemeProbeActivity]):
     * one a test set would come back empty, and the test would wait in vain (audit A-50).
     */
    @Test
    fun androidsContrastSettingSwitchesToHighContrast() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
        val modes = checkNotNull(context.getSystemService(UiModeManager::class.java))
        val dark = (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES
        val standard = sentinelColors(dark, highContrast = false).surface
        val high = sentinelColors(dark, highContrast = true).surface
        fun shown() = ThemeProbeActivity.surface
        ThemeProbeActivity.surface = null
        ActivityScenario.launch(ThemeProbeActivity::class.java).use {
            waitFor("the standard colours") { shown() == standard }
            try {
                shell("settings put secure contrast_level 1.0")
                waitFor("Android to report high contrast") { modes.contrast >= HIGH_CONTRAST_LEVEL }
                waitFor("the high-contrast colours") { shown() == high }
            } finally {
                shell("settings put secure contrast_level 0.0")
            }
            waitFor("Android to report standard contrast") { modes.contrast < HIGH_CONTRAST_LEVEL }
            waitFor("the standard colours again") { shown() == standard }
        }
    }

    @Composable
    private fun MainScreen(onOpenApp: (String) -> Unit = {}, onOpenAlert: (Long) -> Unit = {}) {
        MonitorContent(
            coreVersion = "0.0.1",
            status = Monitor.Status.OFF,
            snapshot = null,
            flows = listOf(
                HistoryFlow(
                    id = 1,
                    app = PACKAGE,
                    proto = FlowProto.TCP,
                    remoteIp = "203.0.113.5",
                    remotePort = 443u,
                    hostname = "chat.example.com",
                    hostnameSource = NameSource.DNS,
                    startedMs = now,
                    endedMs = null,
                    bytesUp = 0,
                    bytesDown = 0,
                    blocked = false,
                ),
            ),
            gaps = listOf(GapLog.Gap(now - 60_000, now, "test")),
            away = emptyList(),
            alerts = listOf(alert()),
            onStart = {},
            onStop = {},
            onShowLive = {},
            onOpenApp = onOpenApp,
            onOpenAlert = onOpenAlert,
            onWipe = {},
        )
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

    /** The content with the text twice its usual size, the most Android's settings allow. */
    @Composable
    private fun AtTwiceTheTextSize(content: @Composable () -> Unit) {
        val density = LocalDensity.current
        CompositionLocalProvider(LocalDensity provides Density(density.density, fontScale = 2f)) {
            SentinelTheme(content)
        }
    }

    /** Every text on [screen] is laid out whole and inside the screen's width. */
    private fun assertNoTextCut(screen: String) {
        compose.waitForIdle()
        val width = compose.onRoot().fetchSemanticsNode().size.width
        val texts = compose.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsActions.GetTextLayoutResult), true)
            .fetchSemanticsNodes()
        assertTrue("$screen: texts found", texts.isNotEmpty())
        val cut = texts.mapNotNull { node ->
            val layouts = mutableListOf<TextLayoutResult>()
            node.config.getOrNull(SemanticsActions.GetTextLayoutResult)?.action?.invoke(layouts)
            val layout = layouts.firstOrNull() ?: return@mapNotNull null
            val text = layout.layoutInput.text.text.take(40)
            // This layout is laid out at the full width the text may take, so its
            // hasVisualOverflow is true for any text narrower than that (seen on the
            // emulator for every one-word label). What counts is that all its lines are
            // there, none shortened, within the height the text was given.
            val whole = layout.multiParagraph
            val shortened = (0 until layout.lineCount).any(layout::isLineEllipsized)
            // Where the text is laid out, before any clipping by what holds it.
            val left = node.positionInRoot.x
            when {
                whole.didExceedMaxLines || shortened -> "lines left out: $text"
                whole.height > node.size.height + 1 -> "cut: $text (${whole.height} > ${node.size.height})"
                left < -1 || left + node.size.width > width + 1 -> "off the screen: $text at $left"
                else -> null
            }
        }
        assertEquals("$screen at twice the text size", emptyList<String>(), cut)
    }

    private fun opens(label: Int) = SemanticsMatcher("opens \"${context.getString(label)}\"") {
        it.config.getOrNull(SemanticsActions.OnClick)?.label == context.getString(label)
    }

    /** The colours text is shown in, each with what is behind it. */
    private fun textPairs(scheme: ColorScheme): Map<String, Pair<Color, Color>> = with(scheme) {
        mapOf(
            "text" to (onSurface to surface),
            "text in dialogs" to (onSurfaceVariant to surfaceContainerHigh),
            "dialog titles" to (onSurface to surfaceContainerHigh),
            "text buttons" to (primary to surface),
            "dialog buttons" to (primary to surfaceContainerHigh),
            "buttons" to (onPrimary to primary),
            "Info" to (onSecondaryContainer to secondaryContainer),
            "Warning" to (onTertiaryContainer to tertiaryContainer),
            "High and isolation" to (onErrorContainer to errorContainer),
            "Critical" to (onError to error),
            "errors" to (error to surface),
        )
    }

    /** WCAG 2.2's contrast ratio, from 1 (none) to 21 (black on white). */
    private fun contrast(a: Color, b: Color): Double {
        val (light, dark) = listOf(a.luminance(), b.luminance()).sortedDescending()
        return (light + 0.05) / (dark + 0.05)
    }
}
