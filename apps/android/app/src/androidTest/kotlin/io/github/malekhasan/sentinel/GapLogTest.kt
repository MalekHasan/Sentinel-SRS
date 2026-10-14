// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
