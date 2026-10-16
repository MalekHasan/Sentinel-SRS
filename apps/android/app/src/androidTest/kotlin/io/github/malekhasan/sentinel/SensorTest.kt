// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.NotificationManager
import android.hardware.camera2.CameraManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.SensorKind
import io.github.malekhasan.sentinel.core.SensorUse
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * SE-01 basic, SE-03 and SE-04 on a device (ADR-0027): the probe (`apps/android/probe`)
 * records from the microphone or opens a camera while monitoring runs. Each use is
 * recorded within 2 s with the app on screen as the guess, a notification shows while it
 * lasts, and use with the screen off raises a High alert.
 */
@RunWith(AndroidJUnit4::class)
class SensorTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val notifications = context.getSystemService(NotificationManager::class.java)
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        wakeAndUnlock()
        History.wipe(context)
        history = History.get(context)
        Probe(history).install()
        shell("pm grant ${Probe.PACKAGE} android.permission.RECORD_AUDIO")
        shell("pm grant ${Probe.PACKAGE} android.permission.CAMERA")
        // Usage access, so that Sentinel can guess from the app on screen.
        shell("appops set ${context.packageName} GET_USAGE_STATS allow")
        startMonitoring()
    }

    @After
    fun tearDown() {
        // Other tests need the screen on and unlocked.
        wakeAndUnlock()
        stopMonitoring()
        shell("appops set ${context.packageName} GET_USAGE_STATS default")
        Probe.uninstall()
    }

    @Test
    fun microphoneUseIsRecordedWithinTwoSecondsAndShownWhileItLasts() {
        shell("am start -W -n ${Probe.PACKAGE}/.RecordActivity --ei seconds 4")
        waitFor("the microphone use to be recorded", timeoutMillis = 2_000) { open(SensorKind.MICROPHONE) != null }
        val use = checkNotNull(open(SensorKind.MICROPHONE))
        assertEquals(Probe.PACKAGE, use.guess)
        assertTrue(use.userPresent)
        // SE-03: shown while in use, gone after.
        waitFor("the in-use notification", timeoutMillis = 1_000) { inUseShown() }
        waitFor("the microphone use to end", timeoutMillis = 10_000) {
            uses(SensorKind.MICROPHONE).single().endedMs != null
        }
        waitFor("the in-use notification to go") { !inUseShown() }
        assertEquals(emptyList<HistoryAlert>(), sensorAlerts())
    }

    @Test
    fun microphoneUseWithTheScreenOffRaisesAHighAlert() {
        shell("am start -W -n ${Probe.PACKAGE}/.RecordActivity --ei seconds 8")
        waitFor("the microphone use to be recorded", timeoutMillis = 2_000) { open(SensorKind.MICROPHONE) != null }
        val started = checkNotNull(open(SensorKind.MICROPHONE)).startedMs
        shell("input keyevent KEYCODE_SLEEP")
        waitFor("an alert about the microphone", timeoutMillis = 5_000) { sensorAlerts().isNotEmpty() }
        val alert = sensorAlerts().single()
        assertEquals(AlertSeverity.HIGH, alert.severity)
        assertEquals(
            listOf(AlertEvidence.Sensor(sensor = SensorKind.MICROPHONE, startedMs = started, guess = Probe.PACKAGE)),
            alert.evidence,
        )
        assertEquals(listOf(AlertAction.OpenPrivacySettings), alert.actions)
        assertFalse(uses(SensorKind.MICROPHONE).single().userPresent)
    }

    @Test
    fun cameraUseIsRecorded() {
        val cameras = context.getSystemService(CameraManager::class.java)
        assertTrue("the emulator has no camera", cameras.cameraIdList.isNotEmpty())
        shell("am start -W -n ${Probe.PACKAGE}/.CameraActivity --ei seconds 3")
        waitFor("the camera use to be recorded", timeoutMillis = 3_000) { open(SensorKind.CAMERA) != null }
        assertEquals(Probe.PACKAGE, checkNotNull(open(SensorKind.CAMERA)).guess)
        waitFor("the in-use notification", timeoutMillis = 1_000) { inUseShown() }
        waitFor("the camera use to end", timeoutMillis = 10_000) { uses(SensorKind.CAMERA).single().endedMs != null }
    }

    private fun uses(sensor: SensorKind): List<SensorUse> = history.recentSensorUses(20u).filter { it.sensor == sensor }

    private fun open(sensor: SensorKind): SensorUse? = uses(sensor).firstOrNull { it.endedMs == null }

    private fun inUseShown(): Boolean = notifications.activeNotifications.any { it.id == SensorWatch.NOTIFICATION_ID }

    private fun sensorAlerts(): List<HistoryAlert> =
        history.alerts(false, 100u).filter { it.rule == AlertRule.SENSOR_WHILE_AWAY }

    private fun wakeAndUnlock() {
        shell("input keyevent KEYCODE_WAKEUP")
        shell("wm dismiss-keyguard")
    }
}
