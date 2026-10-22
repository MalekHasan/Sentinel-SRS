// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotSelected
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * SRS §13.2 on a device (audit finding A-07, ADR-0039): how long connections are kept is
 * a setting on the main screen, and choosing applies every retention period at once.
 */
@RunWith(AndroidJUnit4::class)
class RetentionTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val now = System.currentTimeMillis()

    @Before
    @After
    fun wipe() = History.wipe(context)

    /**
     * The choices, the one in force, and how long the rest of the history is kept. A
     * shorter time is asked first, and Cancel keeps the one in force; a longer one is not.
     */
    @Test
    fun theMainScreenOffersHowLongConnectionsAreKept() {
        val chosen = mutableListOf<UInt>()
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
                    keepFlowsDays = 30u,
                    onKeepFlowsDays = { chosen += it },
                )
            }
        }
        fun days(n: Int) = context.resources.getQuantityString(R.plurals.retention_days, n, n)
        compose.onNodeWithText(context.getString(R.string.retention_title)).performScrollTo().assertIsDisplayed()
        compose.onNode(hasText(days(30)) and isSelectable()).performScrollTo().assertIsSelected()
        compose.onNodeWithText(context.getString(R.string.retention_text)).performScrollTo().assertIsDisplayed()
        compose.onNode(hasText(days(7)) and isSelectable()).performScrollTo().assertIsNotSelected().performClick()
        compose.onNodeWithText(context.getString(R.string.retention_shorter_text)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.retention_shorter_cancel)).performClick()
        assertTrue("cancelled", chosen.isEmpty())

        compose.onNode(hasText(days(7)) and isSelectable()).performScrollTo().performClick()
        compose.onNodeWithText(context.getString(R.string.retention_shorter_change)).performClick()
        assertEquals(listOf(7u), chosen)

        compose.onNode(hasText(days(90)) and isSelectable()).performScrollTo().performClick()
        assertEquals("not asked", listOf(7u, 90u), chosen)
    }

    /**
     * Audit A-27: deleting the history is offered whenever monitoring is off, also with
     * no connection or gap to show, since alerts, rules and the journal go with it.
     */
    @Test
    fun theWipeIsOfferedWheneverMonitoringIsOff() {
        var status by mutableStateOf(Monitor.Status.OFF)
        var asked = 0
        compose.setContent {
            SentinelTheme {
                MonitorContent(
                    coreVersion = "0.0.1",
                    status = status,
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
                    onWipe = { asked++ },
                )
            }
        }
        val wipe = context.getString(R.string.wipe_action)
        compose.onNodeWithText(wipe).performScrollTo().assertIsDisplayed().performClick()
        assertEquals(1, asked)

        status = Monitor.Status.ON
        compose.waitForIdle()
        compose.onNodeWithText(wipe).assertDoesNotExist()
    }

    /**
     * Thirty days until chosen otherwise; a choice outside 1 to 365 days is refused; a
     * choice is kept and applies the periods at once, so that a gap that ended more
     * than 90 days ago goes, and one within them stays.
     */
    @Test
    fun aChoiceIsKeptAndAppliesTheRetentionPeriods() {
        assertEquals(30u, flowKeepDays(context))
        assertFalse(setFlowKeepDays(context, 0u))
        assertFalse(setFlowKeepDays(context, 366u))
        assertEquals(30u, flowKeepDays(context))

        val history = History.get(context)
        history.openGap(now - 100 * DAY, "old")
        history.closeGap(now - 91 * DAY)
        history.openGap(now - 10 * DAY, "recent")
        history.closeGap(now - 9 * DAY)

        assertTrue(setFlowKeepDays(context, 7u))
        assertEquals(7u, flowKeepDays(context))
        assertEquals(listOf("recent"), history.recentGaps(10u).map { it.reason })
    }

    private companion object {
        const val DAY = 24 * 60 * 60 * 1000L
    }
}
