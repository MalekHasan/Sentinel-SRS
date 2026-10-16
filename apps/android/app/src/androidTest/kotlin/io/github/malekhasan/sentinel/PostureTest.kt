// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The probe's test certificate authority (`apps/android/probe/src/main/res/raw/test_ca.der`). */
private const val TEST_CA = "0d21c5b162bae01a6141f680834a9a89f7a677b6ae988ef60b7389a3a6892c6f"
private const val TEST_CA_SUBJECT = "CN=Sentinel test CA,O=Sentinel device tests"

/**
 * ID-03 and ID-10 on a device (ADR-0025): a certificate authority added to the trusted
 * ones raises a High alert at once while monitoring runs, and wireless debugging is read
 * as Android reports it. Android lets an app add a certificate without the user only as
 * device owner, so the probe (`apps/android/probe`) is made one for the test.
 */
@RunWith(AndroidJUnit4::class)
class PostureTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        History.wipe(context)
        history = History.get(context)
        Probe(history).install()
    }

    @After
    fun tearDown() {
        stopMonitoring()
        shell("am broadcast -n $CERTIFICATES -a $REMOVE")
        // The device owner can be removed from the shell only because the probe is test-only.
        shell("dpm remove-active-admin --user 0 $ADMIN")
        Probe.uninstall()
    }

    @Test
    fun aCertificateAddedRaisesAnAlertWithinFiveSeconds() {
        // The phone's own settings are known first: nothing on, nothing added.
        Posture.check(context)
        assertEquals(emptyList<HistoryAlert>(), alerts(AlertRule.NEW_ROOT_CERTIFICATE))
        startMonitoring()
        val owner = shell("dpm set-device-owner $ADMIN")
        assertTrue("dpm set-device-owner: $owner", owner.contains("Success"))
        val added = shell("am broadcast -n $CERTIFICATES -a $ADD")
        assertTrue("adding the certificate: $added", added.contains("result=-1"))

        waitFor("an alert about the added certificate", timeoutMillis = 5_000) {
            alerts(AlertRule.NEW_ROOT_CERTIFICATE).isNotEmpty()
        }
        val alert = alerts(AlertRule.NEW_ROOT_CERTIFICATE).single()
        assertEquals(AlertSeverity.HIGH, alert.severity)
        assertEquals(
            listOf(AlertEvidence.Certificate(sha256 = TEST_CA, subject = TEST_CA_SUBJECT)),
            alert.evidence,
        )
        assertEquals(listOf(AlertAction.OpenCertificateSettings), alert.actions)
        // While it stays trusted, checking again raises nothing.
        Posture.check(context)
        assertEquals(listOf(alert.id), alerts(AlertRule.NEW_ROOT_CERTIFICATE).map { it.id })
    }

    @Test
    fun wirelessDebuggingIsReadAsAndroidReportsIt() {
        val on = shell("settings get global ${Posture.WIRELESS_DEBUGGING}").trim() == "1"
        assertEquals(on, Posture.read(context).wirelessDebugging)
        Posture.check(context)
        assertEquals(if (on) 1 else 0, alerts(AlertRule.REMOTE_ACCESS_EXPOSED).size)
    }

    private fun alerts(rule: AlertRule): List<HistoryAlert> = history.alerts(false, 100u).filter { it.rule == rule }

    private companion object {
        const val ADMIN = "${Probe.PACKAGE}/${Probe.PACKAGE}.Admin"
        const val CERTIFICATES = "${Probe.PACKAGE}/${Probe.PACKAGE}.Certificates"
        const val ADD = "${Probe.PACKAGE}.ADD_CERTIFICATE"
        const val REMOVE = "${Probe.PACKAGE}.REMOVE_CERTIFICATE"
    }
}
