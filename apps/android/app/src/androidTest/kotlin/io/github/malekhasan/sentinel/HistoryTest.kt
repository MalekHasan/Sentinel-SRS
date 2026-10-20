// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import java.io.File
import java.security.SecureRandom
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * THREAT-MODEL-A T4 and T6 on a device: a history that cannot be read is replaced by a
 * new one, and the new one says so with an alert. A history opened for the first time
 * says nothing.
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
    }
}
