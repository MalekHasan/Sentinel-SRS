// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.Build
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.HardeningItem
import io.github.malekhasan.sentinel.core.HardeningStatus
import io.github.malekhasan.sentinel.core.HardeningStep
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * MS-12 on a device (ADR-0026): the hardening checklist reads what Android reports, and
 * the screen shows each step with where it stands and a way to its settings.
 */
@RunWith(AndroidJUnit4::class)
class HardeningTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun theChecklistReadsWhatAndroidReports() {
        val facts = Hardening.facts(context)
        assertEquals(shell("getprop ro.build.version.security_patch").trim(), facts.securityPatch)
        assertEquals(shell("settings get global adb_enabled").trim() == "1", facts.usbDebugging)
        assertEquals(Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA, facts.advancedProtectionAvailable)

        val items = Hardening.items(context)
        assertEquals(HardeningStep.entries.toList(), items.map { it.step })
        val status = items.associate { it.step to it.status }
        assertEquals(
            if (facts.usbDebugging) HardeningStatus.TO_DO else HardeningStatus.DONE,
            status[HardeningStep.USB_DEBUGGING],
        )
        assertEquals(
            if (facts.screenLock) HardeningStatus.DONE else HardeningStatus.TO_DO,
            status[HardeningStep.SCREEN_LOCK],
        )
        if (!facts.advancedProtectionAvailable) {
            assertEquals(HardeningStatus.NOT_AVAILABLE, status[HardeningStep.ADVANCED_PROTECTION])
        }
        assertEquals(HardeningStatus.CHECK_YOURSELF, status[HardeningStep.UNKNOWN_APPS])
        assertEquals(HardeningStatus.CHECK_YOURSELF, status[HardeningStep.MESSAGING_APPS])
    }

    @Test
    fun eachStepSaysWhereItStandsAndOpensItsSettings() {
        val opened = mutableListOf<HardeningStep>()
        val items = listOf(
            HardeningItem(HardeningStep.ADVANCED_PROTECTION, HardeningStatus.NOT_AVAILABLE),
            HardeningItem(HardeningStep.SECURITY_UPDATE, HardeningStatus.TO_DO),
            HardeningItem(HardeningStep.SCREEN_LOCK, HardeningStatus.DONE),
            HardeningItem(HardeningStep.UNKNOWN_APPS, HardeningStatus.CHECK_YOURSELF),
        )
        compose.setContent {
            SentinelTheme { HardeningChecklist(items, "2023-02-05", onBack = {}, onOpen = { opened += it }) }
        }
        compose.onNodeWithText(context.getString(R.string.hardening_title)).assertIsDisplayed()
        // Not on this version of Android: nothing to open.
        val advanced = hardeningRowTag(HardeningStep.ADVANCED_PROTECTION)
        compose.onNodeWithTag(advanced).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.hardening_status_not_available)).assertIsDisplayed()
        // The update's date is shown.
        compose.onNodeWithText(context.getString(R.string.hardening_security_patch, isolate("2023-02-05")))
            .performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.hardening_status_to_do)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.hardening_status_check)).performScrollTo().assertIsDisplayed()
        // Three steps can be opened; the first is the security update.
        val open = context.getString(R.string.hardening_open_settings)
        compose.onAllNodesWithText(open).assertCountEquals(3)
        compose.onAllNodesWithText(open).onFirst().performScrollTo().performClick()
        assertEquals(listOf(HardeningStep.SECURITY_UPDATE), opened)
    }

    @Test
    fun theMainScreenOpensTheChecklist() {
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
                    onShowHardening = { shown = true },
                )
            }
        }
        compose.onNodeWithText(context.getString(R.string.hardening_action)).performScrollTo().performClick()
        assertEquals(true, shown)
    }
}
