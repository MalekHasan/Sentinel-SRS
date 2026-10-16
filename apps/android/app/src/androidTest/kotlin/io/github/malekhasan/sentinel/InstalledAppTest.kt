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
import io.github.malekhasan.sentinel.core.IndicatorSighting
import io.github.malekhasan.sentinel.core.IndicatorThreat
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The SHA-256 of the probe's signing certificate (apps/android/probe/test-signing.p12). */
private const val PROBE_CERTIFICATE = "be9200574eb6aa1083aa108b7e50625edc2c86787593ad5b35a68c110284b64f"

/**
 * ID-13 on a device (ADR-0023): an installed app that the indicator list names, by its
 * package name or by its signing certificate, raises a Critical alert about it: when a
 * list comes into force, and when the app is installed while monitoring runs. The app is
 * the probe (`apps/android/probe`); test list 4 names its package, list 5 its
 * certificate ([TestFeed]).
 */
@RunWith(AndroidJUnit4::class)
class InstalledAppTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        Probe.uninstall()
        History.wipe(context)
        history = History.get(context)
        TestFeed.clear()
    }

    @After
    fun tearDown() {
        stopMonitoring()
        Probe.uninstall()
        TestFeed.clear()
    }

    @Test
    fun anAppWithAListedPackageIsFoundWhenTheListArrives() {
        Probe(history).install()
        // The installed apps are checked as the list comes into force.
        TestFeed.install(4)
        val alert = knownIndicatorAlerts().single()
        assertEquals(AlertSeverity.CRITICAL, alert.severity)
        assertEquals(AlertEvidence.App(app = Probe.PACKAGE), alert.evidence.first())
        val indicator = alert.evidence.filterIsInstance<AlertEvidence.Indicator>().single()
        assertEquals(Probe.PACKAGE, indicator.indicator)
        assertEquals(Probe.PACKAGE, indicator.seen)
        assertEquals(IndicatorSighting.INSTALLED_PACKAGE, indicator.sighting)
        assertEquals(IndicatorThreat.STALKERWARE, indicator.threat)
        assertEquals("Sentinel test indicators", indicator.source)
        assertTrue("${alert.actions}", AlertAction.BlockApp(app = Probe.PACKAGE) in alert.actions)

        // Still installed: checking again raises nothing new, and the result counts it.
        assertEquals(0u, checkNotNull(InstalledApps.check(context)).raised)
        assertEquals(listOf(alert.id), knownIndicatorAlerts().map { it.id })
        assertEquals(1uL, History.knownTraces(context)?.alerts)
    }

    @Test
    fun anAppSignedWithAListedCertificateIsFound() {
        Probe(history).install()
        TestFeed.install(5)
        val alert = knownIndicatorAlerts().single()
        assertEquals(AlertEvidence.App(app = Probe.PACKAGE), alert.evidence.first())
        val indicator = alert.evidence.filterIsInstance<AlertEvidence.Indicator>().single()
        assertEquals(PROBE_CERTIFICATE, indicator.indicator)
        assertEquals(PROBE_CERTIFICATE, indicator.seen)
        assertEquals(IndicatorSighting.SIGNING_CERTIFICATE, indicator.sighting)
    }

    @Test
    fun anAppInstalledWhileMonitoringIsFoundAtOnce() {
        TestFeed.install(4)
        startMonitoring()
        assertEquals(emptyList<HistoryAlert>(), knownIndicatorAlerts())
        Probe(history).install()
        waitFor("an alert about the probe") { knownIndicatorAlerts().isNotEmpty() }
        assertEquals(AlertEvidence.App(app = Probe.PACKAGE), knownIndicatorAlerts().single().evidence.first())
    }

    private fun knownIndicatorAlerts(): List<HistoryAlert> =
        history.alerts(false, 100u).filter { it.rule == AlertRule.KNOWN_INDICATOR }
}
