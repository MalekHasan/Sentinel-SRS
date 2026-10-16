// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** ADR-0009: the history key is random, created once, and stored only wrapped. */
@RunWith(AndroidJUnit4::class)
class HistoryKeyTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val stored = File(context.noBackupFilesDir, "history.key")

    @Before
    @After
    fun wipe() = History.wipe(context)

    @Test
    fun keyIsCreatedOnceAndStoredOnlyWrapped() {
        val first = HistoryKey.load(context)
        assertEquals(32, first.size)
        assertArrayEquals("the same key every time", first, HistoryKey.load(context))

        val onDisk = stored.readBytes()
        val inTheClear = (0..onDisk.size - first.size).any { start ->
            first.indices.all { onDisk[start + it] == first[it] }
        }
        assertFalse("the raw key is on disk", inTheClear)

        HistoryKey.delete(context)
        assertFalse(stored.exists())
        assertFalse("a new key after delete", first.contentEquals(HistoryKey.load(context)))
    }

    /** Wiping deletes the database and the key; the next history starts empty. */
    @Test
    fun wipeDeletesTheHistoryAndItsKey() {
        History.get(context).openGap(1_000, "before wipe")
        History.wipe(context)
        val left = context.noBackupFilesDir.listFiles().orEmpty()
            .filter { it.name.startsWith("history.") }
        assertEquals("files left: $left", emptyList<File>(), left)
        assertEquals(emptyList<Any>(), History.get(context).recentGaps(10u))
    }
}
