// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.Build
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * SP-03 on a device (ADR-0030): the steps that keep monitoring running read what Android
 * reports, and the screen shows this phone maker's own steps.
 */
@RunWith(AndroidJUnit4::class)
class KeepRunningTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun optimiseAgain() {
        shell("cmd deviceidle whitelist -${context.packageName}")
    }

    @Test
    fun makersAreKnownByTheirNames() {
        val makers = mapOf(
            "samsung" to KeepRunning.Maker.SAMSUNG,
            "Xiaomi" to KeepRunning.Maker.XIAOMI,
            "Redmi" to KeepRunning.Maker.XIAOMI,
            "POCO" to KeepRunning.Maker.XIAOMI,
            "HUAWEI" to KeepRunning.Maker.HUAWEI,
            "HONOR" to KeepRunning.Maker.HUAWEI,
            "OnePlus" to KeepRunning.Maker.ONEPLUS,
            "OPPO" to KeepRunning.Maker.OPPO,
            "realme" to KeepRunning.Maker.OPPO,
            "vivo" to KeepRunning.Maker.VIVO,
            "iQOO" to KeepRunning.Maker.VIVO,
            "Google" to KeepRunning.Maker.GOOGLE,
            "Fairphone" to KeepRunning.Maker.OTHER,
            "" to KeepRunning.Maker.OTHER,
        )
        makers.forEach { (name, maker) -> assertEquals(name, maker, KeepRunning.maker(name)) }
    }

    /** Battery optimisation as Android reports it; always-on cannot be read while monitoring is off. */
    @Test
    fun theStepsReadWhatAndroidReports() {
        fun done() = KeepRunning.items(context).associate { it.step to it.done }
        shell("cmd deviceidle whitelist -${context.packageName}")
        assertEquals(false, done()[KeepRunning.Step.BATTERY])
        shell("cmd deviceidle whitelist +${context.packageName}")
        assertEquals(true, done()[KeepRunning.Step.BATTERY])

        assertEquals(KeepRunning.Step.entries.toList(), KeepRunning.items(context).map { it.step })
        assertEquals("nothing restricts the app under test", true, done()[KeepRunning.Step.BACKGROUND])
        assertEquals(null, done()[KeepRunning.Step.ALWAYS_ON])
    }

    @Test
    fun theScreenShowsWhereEachStepStandsAndThisPhonesMaker() {
        val opened = mutableListOf<KeepRunning.Step>()
        var appSettings = 0
        val maker = KeepRunning.maker(Build.MANUFACTURER)
        compose.setContent {
            SentinelTheme {
                KeepRunningContent(
                    items = listOf(
                        KeepRunning.Item(KeepRunning.Step.BATTERY, done = false),
                        KeepRunning.Item(KeepRunning.Step.BACKGROUND, done = true),
                        KeepRunning.Item(KeepRunning.Step.ALWAYS_ON, done = null),
                    ),
                    maker = maker,
                    onBack = {},
                    onOpen = { opened += it },
                    onOpenAppSettings = { appSettings++ },
                )
            }
        }
        compose.onNodeWithText(context.getString(R.string.keep_running_title)).assertIsDisplayed()
        compose.onNodeWithTag(keepRunningRowTag(KeepRunning.Step.BATTERY)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.hardening_status_to_do)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.hardening_status_done)).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.keep_running_status_while_monitoring))
            .performScrollTo().assertIsDisplayed()
        // Each of Android's steps opens its settings.
        val open = context.getString(R.string.hardening_open_settings)
        compose.onAllNodesWithText(open).assertCountEquals(3)
        compose.onNode(hasText(context.getString(R.string.keep_running_always_on_text)))
            .performScrollTo().assertIsDisplayed()
        compose.onAllNodesWithText(open)[2].performScrollTo().performClick()
        assertEquals(listOf(KeepRunning.Step.ALWAYS_ON), opened)
        // This phone maker's own steps, and Sentinel's page in Android's settings.
        compose.onNodeWithText(context.getString(makerSteps(maker))).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.keep_running_open_app_settings))
            .performScrollTo().performClick()
        assertEquals(1, appSettings)
    }

    @Test
    fun theMainScreenOpensTheSteps() {
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
                    onShowKeepRunning = { shown = true },
                )
            }
        }
        compose.onNodeWithText(context.getString(R.string.keep_running_action)).performScrollTo().performClick()
        assertEquals(true, shown)
    }
}
