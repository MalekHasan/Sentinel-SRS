// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.ExportFormat
import io.github.malekhasan.sentinel.core.ExportKind
import io.github.malekhasan.sentinel.core.FirewallRule
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.RuleAction
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.LocalDate
import org.json.JSONArray
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * SRS §12.3 on a device (ADR-0033): the history is written a page at a time into one
 * document the user chose, and the screen warns that the file holds sensitive data
 * before the user chooses where it goes (SRS §15.2).
 */
@RunWith(AndroidJUnit4::class)
class ExportTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        History.wipe(context)
        history = History.get(context)
    }

    @After
    fun tearDown() {
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
    }

    /** Pages of any size make the document one page makes: one JSON array, or one CSV table. */
    @Test
    fun pagesMakeOneDocument() {
        repeat(5) { i -> history.setFirewallRule(FirewallRule("org.example.app$i", null, RuleAction.BLOCK)) }
        val now = System.currentTimeMillis()
        for (format in ExportFormat.entries) {
            val whole = export(ExportKind.ACTIONS, format, now, pageSize = 100u)
            for (size in listOf(1u, 2u, 3u)) {
                assertEquals("$format in pages of $size", whole, export(ExportKind.ACTIONS, format, now, size))
            }
        }
        val records = JSONArray(export(ExportKind.ACTIONS, ExportFormat.JSON, now))
        assertEquals("one record per action", 5, records.length())
        val lines = export(ExportKind.ACTIONS, ExportFormat.CSV, now).split("\r\n").filter { it.isNotEmpty() }
        assertEquals("a header and a line per action: $lines", 6, lines.size)
        assertTrue(lines.first(), lines.first().startsWith("id,at,actor"))
    }

    /** The range reaches back from now: a day, a week, or everything kept. */
    @Test
    fun theRangeReachesBackFromNow() {
        history.openGap(null, "test")
        val alerts = history.alerts(false, 100u).size
        assertTrue("an alert to export", alerts > 0)
        val now = System.currentTimeMillis()
        val later = now + 2 * 24 * 60 * 60 * 1000L
        fun count(range: HistoryExport.Range, at: Long) =
            JSONArray(export(ExportKind.ALERTS, ExportFormat.JSON, at, range = range)).length()
        assertEquals("the last day, now", alerts, count(HistoryExport.Range.DAY, now))
        assertEquals("the last day, two days later", 0, count(HistoryExport.Range.DAY, later))
        assertEquals("the last week, two days later", alerts, count(HistoryExport.Range.WEEK, later))
        assertEquals("everything, two days later", alerts, count(HistoryExport.Range.ALL, later))
    }

    /** Saving writes the document and says how large it is; a document that cannot be
     *  written says so. */
    @Test
    fun savingWritesTheDocumentOrSaysItFailed() {
        repeat(3) { i -> history.setFirewallRule(FirewallRule("org.example.app$i", null, RuleAction.BLOCK)) }
        val choice = HistoryExport.Choice(ExportKind.ACTIONS, ExportFormat.CSV, HistoryExport.Range.ALL)
        val file = File(context.cacheDir, "export-test.csv")
        try {
            HistoryExport.save(context, Uri.fromFile(file), choice)
            val saved = waitForEnd()
            assertTrue("saved: $saved", saved is HistoryExport.State.Saved)
            val text = file.readText()
            assertEquals(text.toByteArray().size.toLong(), (saved as HistoryExport.State.Saved).bytes)
            assertEquals(4, text.split("\r\n").count { it.isNotEmpty() })
        } finally {
            file.delete()
        }

        HistoryExport.save(context, Uri.parse("content://${context.packageName}.nothing/document"), choice)
        assertEquals(HistoryExport.State.Failed, waitForEnd())
    }

    @Test
    fun theFileNameSaysWhatAndWhen() {
        val day = LocalDate.of(2026, 10, 20)
        val connections = HistoryExport.Choice(ExportKind.FLOWS, ExportFormat.CSV, HistoryExport.Range.ALL)
        assertEquals("sentinel-connections-2026-10-20.csv", HistoryExport.fileName(connections, day))
        val alerts = HistoryExport.Choice(ExportKind.ALERTS, ExportFormat.JSON, HistoryExport.Range.DAY)
        assertEquals("sentinel-alerts-2026-10-20.json", HistoryExport.fileName(alerts, day))
    }

    /** SRS §15.2: the warning comes before the picker, and nothing is saved without it. */
    @Test
    fun theWarningComesBeforeTheFileIsChosen() {
        var saved: HistoryExport.Choice? = null
        val first = HistoryExport.Choice(ExportKind.FLOWS, ExportFormat.CSV, HistoryExport.Range.ALL)
        compose.setContent {
            SentinelTheme {
                var choice by remember { mutableStateOf(first) }
                ExportContent(
                    choice,
                    HistoryExport.State.Idle,
                    onChoice = { choice = it },
                    onBack = {},
                    onSave = { saved = choice },
                )
            }
        }
        compose.onNodeWithText(context.getString(R.string.export_kind_actions)).performScrollTo().performClick()
        compose.onNodeWithText(context.getString(R.string.export_range_week)).performScrollTo().performClick()
        compose.onNodeWithText(context.getString(R.string.export_format_json)).performScrollTo().performClick()

        compose.onNodeWithText(context.getString(R.string.export_action)).performScrollTo().performClick()
        compose.onNodeWithText(context.getString(R.string.export_warning_text)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.export_warning_cancel)).performClick()
        assertNull("cancelled", saved)

        compose.onNodeWithText(context.getString(R.string.export_action)).performScrollTo().performClick()
        compose.onNodeWithText(context.getString(R.string.export_warning_confirm)).performClick()
        val chosen = HistoryExport.Choice(ExportKind.ACTIONS, ExportFormat.JSON, HistoryExport.Range.WEEK)
        assertEquals(chosen, saved)
    }

    @Test
    fun whileSavingAnotherExportWaits() {
        val choice = HistoryExport.Choice(ExportKind.FLOWS, ExportFormat.CSV, HistoryExport.Range.ALL)
        compose.setContent {
            SentinelTheme {
                ExportContent(choice, HistoryExport.State.Saving, onChoice = {}, onBack = {}, onSave = {})
            }
        }
        compose.onNodeWithText(context.getString(R.string.export_action)).performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText(context.getString(R.string.export_saving)).performScrollTo().assertIsDisplayed()
    }

    @Test
    fun theMainScreenOpensIt() {
        var shown = false
        compose.setContent {
            SentinelTheme {
                MonitorContent(
                    coreVersion = "0.0.1",
                    status = Monitor.Status.OFF,
                    snapshot = null,
                    flows = emptyList(),
                    gaps = emptyList(),
                    away = emptyList(),
                    alerts = emptyList(),
                    onStart = {},
                    onStop = {},
                    onShowLive = {},
                    onOpenApp = {},
                    onOpenAlert = {},
                    onWipe = {},
                    onShowExport = { shown = true },
                )
            }
        }
        compose.onNodeWithText(context.getString(R.string.export_open)).performScrollTo().performClick()
        assertEquals(true, shown)
    }

    private fun export(
        kind: ExportKind,
        format: ExportFormat,
        now: Long,
        pageSize: UInt = 100u,
        range: HistoryExport.Range = HistoryExport.Range.ALL,
    ): String {
        val out = ByteArrayOutputStream()
        val choice = HistoryExport.Choice(kind, format, range)
        val written = HistoryExport.write(history, out, choice, now, pageSize)
        assertEquals("bytes counted", out.size().toLong(), written)
        return out.toString(Charsets.UTF_8.name())
    }

    private fun waitForEnd(): HistoryExport.State {
        val until = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < until) {
            val state = HistoryExport.states.value
            if (state != HistoryExport.State.Saving) return state
            Thread.sleep(50)
        }
        error("the export did not end within 10 s")
    }
}
