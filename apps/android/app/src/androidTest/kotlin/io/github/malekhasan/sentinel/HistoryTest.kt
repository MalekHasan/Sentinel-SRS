// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * THREAT-MODEL-A T4 and T6 on a device: a history that cannot be read is replaced by a
 * new one, and the new one says so with an alert. The old one is set aside with its key
 * until the wipe (audit A-06). A history opened for the first time says nothing.
 */
@RunWith(AndroidJUnit4::class)
class HistoryTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun wipe() = History.wipe(context)

    @Test
    fun aNewHistorySaysNothing() {
        History.wipe(context)
        val alerts = History.get(context).alerts(false, 100u)
        val anew = alerts.filter { it.rule == AlertRule.HISTORY_STARTED_ANEW }
        assertTrue("no alert in a first history: $anew", anew.isEmpty())
    }

    /** As when someone changes the file, or Android loses the key: the old history cannot be opened. */
    @Test
    fun aHistoryThatCannotBeReadIsReplacedAndSaysSo() {
        History.wipe(context)
        val garbage = ByteArray(8_192).also { SecureRandom().nextBytes(it) }
        File(context.noBackupFilesDir, "history.db").writeBytes(garbage)

        val history = History.get(context)
        val alerts = history.alerts(true, 100u).filter { it.rule == AlertRule.HISTORY_STARTED_ANEW }
        assertEquals("one alert says the history was started anew: $alerts", 1, alerts.size)
        assertEquals(AlertSeverity.WARNING, alerts.single().severity)
        assertTrue("the new history works", history.recentFlows(10u).isEmpty())
        assertTrue(
            "the old one is set aside, not deleted",
            garbage.contentEquals(File(context.noBackupFilesDir, "history.db.unreadable").readBytes()),
        )
        assertTrue(File(context.noBackupFilesDir, "history.key.unreadable").exists())
        assertWipeDeletesEverything()
    }

    /** As after a Keystore reset: the key that wraps the history's key is gone. */
    @Test
    fun aHistoryWhoseKeyIsGoneIsReplacedAndSaysSo() {
        History.wipe(context)
        HistoryKey.load(context)
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("sentinel-history-key")

        val history = History.get(context)
        val alerts = history.alerts(true, 100u).filter { it.rule == AlertRule.HISTORY_STARTED_ANEW }
        assertEquals("one alert says the history was started anew: $alerts", 1, alerts.size)
        assertTrue("the old key is set aside", File(context.noBackupFilesDir, "history.key.unreadable").exists())
        assertWipeDeletesEverything()
    }

    /** The wipe deletes the history, its key and what was set aside (SRS §13.2). */
    private fun assertWipeDeletesEverything() {
        History.wipe(context)
        val left = context.noBackupFilesDir.listFiles().orEmpty().filter { it.name.startsWith("history.") }
        assertEquals("files left: $left", emptyList<File>(), left)
    }
}
