// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.SpecialAccess
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * ID-12 on a device (ADR-0024): an app that did not come with the phone and gains
 * accessibility, notification or device admin access raises a High alert about it. The
 * app is the probe (`apps/android/probe`), whose inert components the tests turn on as
 * Android's shell user would.
 */
@RunWith(AndroidJUnit4::class)
class SpecialAccessTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var history: HistoryStore
    private var accessibilityBefore: String? = null

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        History.wipe(context)
        history = History.get(context)
        accessibilityBefore =
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        Probe(history).install()
        // What the phone's apps hold is known before the probe gains anything.
        checkNotNull(AccessGrants.check(context))
        assertEquals(emptyList<HistoryAlert>(), accessAlerts())
    }

    @After
    fun tearDown() {
        stopMonitoring()
        shell("cmd notification disallow_listener $LISTENER")
        if (accessibilityBefore.isNullOrEmpty()) {
            shell("settings delete secure ${Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES}")
        } else {
            shell("settings put secure ${Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES} $accessibilityBefore")
        }
        // An app cannot be uninstalled while it is a device admin.
        shell("dpm remove-active-admin --user current $ADMIN")
        Probe.uninstall()
    }

    @Test
    fun notificationAccessRaisesAnAlertWithinFiveSeconds() {
        startMonitoring()
        shell("cmd notification allow_listener $LISTENER")
        val alert = alertWithin(SpecialAccess.NOTIFICATION_LISTENER)
        assertEquals(AlertSeverity.HIGH, alert.severity)
        assertEquals(
            listOf(
                AlertAction.OpenAccessSettings(access = SpecialAccess.NOTIFICATION_LISTENER),
                AlertAction.BlockApp(app = Probe.PACKAGE),
                AlertAction.OpenApp(app = Probe.PACKAGE),
            ),
            alert.actions,
        )
        // While it is held, checking again raises nothing.
        assertEquals(0u, checkNotNull(AccessGrants.check(context)).gained)
        assertEquals(listOf(alert.id), accessAlerts().map { it.id })
    }

    @Test
    fun accessibilityAccessRaisesAnAlertWithinFiveSeconds() {
        startMonitoring()
        shell("settings put secure ${Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES} $WATCHER")
        alertWithin(SpecialAccess.ACCESSIBILITY)
    }

    @Test
    fun aDeviceAdminIsFoundAtTheNextCheck() {
        val said = shell("dpm set-active-admin --user current $ADMIN")
        assertTrue("dpm set-active-admin: $said", said.contains("Success"))
        val check = checkNotNull(AccessGrants.check(context))
        assertEquals(1u, check.gained)
        val alert = accessAlerts().single()
        assertEquals(AlertEvidence.Access(access = SpecialAccess.DEVICE_ADMIN), alert.evidence[1])
        val settings = AlertAction.OpenAccessSettings(access = SpecialAccess.DEVICE_ADMIN)
        assertTrue("${alert.actions}", settings in alert.actions)
    }

    /** The one alert about the probe gaining [access], raised within 5 s. */
    private fun alertWithin(access: SpecialAccess): HistoryAlert {
        waitFor("an alert about the probe's special access", timeoutMillis = 5_000) { accessAlerts().isNotEmpty() }
        val alert = accessAlerts().single()
        assertEquals(
            listOf(AlertEvidence.App(app = Probe.PACKAGE), AlertEvidence.Access(access = access)),
            alert.evidence,
        )
        return alert
    }

    /** The alerts about the probe's special access. */
    private fun accessAlerts(): List<HistoryAlert> = history.alerts(false, 100u).filter {
        it.rule == AlertRule.SPECIAL_ACCESS && it.evidence.first() == AlertEvidence.App(app = Probe.PACKAGE)
    }

    private companion object {
        const val LISTENER = "${Probe.PACKAGE}/${Probe.PACKAGE}.Listener"
        const val WATCHER = "${Probe.PACKAGE}/${Probe.PACKAGE}.Watcher"
        const val ADMIN = "${Probe.PACKAGE}/${Probe.PACKAGE}.Admin"
    }
}
