// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertRule
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class GapLogTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    @After
    fun wipe() = History.wipe(context)

    @Test
    fun opensOneGapAtATimeAndClosesIt() {
        GapLog.open(context, 1_000, "engine stopped")
        GapLog.open(context, 2_000, "revoked") // already open: not a second gap
        assertEquals(listOf(GapLog.Gap(1_000, null, "engine stopped")), GapLog.recent(context, 10))

        GapLog.closeOpen(context, 3_000)
        GapLog.closeOpen(context, 4_000) // nothing open: no change
        GapLog.open(context, null, "closed without warning")
        assertEquals(
            listOf(
                GapLog.Gap(null, null, "closed without warning"),
                GapLog.Gap(1_000, 3_000, "engine stopped"),
            ),
            GapLog.recent(context, 10),
        )
    }

    /**
     * SP-03: each report heard is written down; an engine silent for 30 s opens a gap from
     * its last report, with its alert. The record of the last report goes with the history.
     */
    @Test
    fun aSilentEngineOpensAGapFromItsLastReport() {
        assertFalse(Heartbeat.check(context, ageMillis = 4_000, nowMillis = 100_000))
        assertEquals(emptyList<GapLog.Gap>(), GapLog.recent(context, 10))
        assertEquals(96_000L, Heartbeat.lastHeard(context))

        assertTrue(Heartbeat.check(context, ageMillis = Heartbeat.SILENT_AFTER_MILLIS, nowMillis = 130_000))
        val reason = context.getString(R.string.gap_engine_silent)
        assertEquals(listOf(GapLog.Gap(100_000, null, reason)), GapLog.recent(context, 10))
        assertEquals("not heard from since", 96_000L, Heartbeat.lastHeard(context))
        val alerts = History.get(context).alerts(true, 10u)
        assertEquals(listOf(AlertRule.MONITORING_INTERRUPTED), alerts.map { it.rule })

        History.wipe(context)
        assertNull("the last report goes with the history", Heartbeat.lastHeard(context))
    }

    /**
     * SP-03: the gap a dead process left begins when Android recorded its exit; with no
     * record, or only an earlier exit's, when the engine was last heard from.
     */
    @Test
    fun aGapAfterDeathBeginsNoEarlierThanTheLastReport() {
        val killed = 5_000L to "killed"
        assertEquals(killed, GapLog.exitGap(killed, lastHeard = 4_000, unknown = "?"))
        assertEquals(killed, GapLog.exitGap(killed, lastHeard = null, unknown = "?"))
        assertEquals(4_000L to "?", GapLog.exitGap(3_000L to "earlier", lastHeard = 4_000, unknown = "?"))
        assertEquals(4_000L to "?", GapLog.exitGap(null, lastHeard = 4_000, unknown = "?"))
        assertEquals(null to "?", GapLog.exitGap(null, lastHeard = null, unknown = "?"))
    }

    /** Gaps are in the encrypted history: their text is not readable on disk. */
    @Test
    fun gapsAreStoredEncrypted() {
        val marker = "gap-marker-${System.nanoTime()}"
        GapLog.open(context, 1_000, marker)
        val files = context.noBackupFilesDir.listFiles().orEmpty()
            .filter { it.name.startsWith("history.db") }
        assertTrue("no history files", files.isNotEmpty())
        val needle = marker.toByteArray()
        files.forEach { file ->
            val bytes = file.readBytes()
            val found = (0..bytes.size - needle.size).any { start ->
                needle.indices.all { bytes[start + it] == needle[it] }
            }
            assertFalse("${file.name} contains the gap text in the clear", found)
        }
    }
}
