// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertFeedback
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.HeldAccess
import io.github.malekhasan.sentinel.core.SpecialAccess
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AL-05 on a device (audit A-08): what the user allowed is listed, and taking it back
 * brings its alerts again.
 */
@RunWith(AndroidJUnit4::class)
class AllowedTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    @After
    fun wipe() = History.wipe(context)

    @Test
    fun whatWasAllowedIsListedAndCanBeTakenBack() {
        val history = History.get(context)
        val held = listOf(HeldAccess(app = APP, access = SpecialAccess.ACCESSIBILITY, preinstalled = false))
        fun accessAlerts() = history.alerts(true, 10u).filter { it.rule == AlertRule.SPECIAL_ACCESS }
        // Turned off, then on again: reported again, unless allowed.
        fun offAndOn() {
            history.checkAccess(emptyList())
            history.checkAccess(held)
        }

        history.checkAccess(held)
        val alert = accessAlerts().single()
        assertTrue(alert.canAllow)
        assertTrue(history.setFeedback(alert.id, AlertFeedback.ALLOWED))
        offAndOn()
        assertTrue("allowed", accessAlerts().isEmpty())

        compose.setContent { SentinelTheme { AllowedScreen(onBack = {}) } }
        waitUntilShown(context.getString(R.string.alert_special_access_title))
        compose.onNodeWithText(APP).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.allowed_explainer)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.allowed_take_back)).performClick()
        waitUntilShown(context.getString(R.string.allowed_taken_back, isolate(APP)))
        compose.onNodeWithText(context.getString(R.string.allowed_empty)).assertIsDisplayed()

        assertTrue(history.allowed().isEmpty())
        assertNull("the alert no longer says it is allowed", history.alert(alert.id)?.feedback)
        offAndOn()
        assertEquals("taken back", 1, accessAlerts().size)
    }

    @Test
    fun theMainScreenOpensWhatWasAllowed() {
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
                    onShowAllowed = { shown = true },
                )
            }
        }
        compose.onNodeWithText(context.getString(R.string.allowed_action)).performScrollTo().performClick()
        assertTrue(shown)
    }

    private fun waitUntilShown(text: String) {
        compose.waitUntil(5_000) { compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }
    }

    private companion object {
        /** Not installed, so the screen shows its package name. */
        const val APP = "org.example.allowed"
    }
}
