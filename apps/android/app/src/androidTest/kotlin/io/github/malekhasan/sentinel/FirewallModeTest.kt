// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.FirewallMode
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * CM-08 on a device (ADR-0016), with an app installed while the test runs: the probe
 * (`apps/android/probe`), which connects to the test server when started. Block-unknown
 * stops it until it is allowed, as the alert for its first connection offers; Watch
 * only lets it through from the next connection; apps installed before the mode was
 * turned on are never stopped by it.
 */
@RunWith(AndroidJUnit4::class)
class FirewallModeTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var history: HistoryStore
    private lateinit var probe: Probe

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        Probe.uninstall()
        History.wipe(context)
        history = History.get(context)
        probe = Probe(history)
        startMonitoring()
    }

    @After
    fun tearDown() {
        stopMonitoring()
        history.setFirewallMode(FirewallMode.MONITOR)
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
        Probe.uninstall()
    }

    @Test
    fun blockUnknownStopsAnAppInstalledSinceUntilItIsAllowed() {
        val (host, port) = testServer()
        assertEquals(FirewallMode.MONITOR, history.firewallMode())
        switchTo(FirewallMode.BLOCK_UNKNOWN)
        assertNotNull("Sentinel was installed before: it gets through", answer(host, port))

        probe.install()
        Probe.assertBlocked(probe.run(host, port))
        assertEquals("stored as blocked", 1, probe.flows(host, port).count { it.blocked })
        // Its first connection raises the "new app" alert, which says it was blocked and
        // offers to allow it (CM-04 too: an app installed after the history began).
        var alert: HistoryAlert? = null
        waitFor("the new app's alert") {
            alert = history.alerts(true, 10u).firstOrNull { it.rule == AlertRule.FIRST_NETWORK_USE }
            alert != null
        }
        val raised = checkNotNull(alert)
        assertTrue("${raised.evidence}", AlertEvidence.App(Probe.PACKAGE) in raised.evidence)
        assertTrue("${raised.evidence}", AlertEvidence.NewAppBlocked in raised.evidence)
        assertEquals(AlertAction.AllowApp(Probe.PACKAGE), raised.actions.first())

        // What the alert's action does.
        assertTrue(allowApp(context, Probe.PACKAGE))
        Probe.assertAnswered(probe.run(host, port))
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
        Probe.assertBlocked(probe.run(host, port))

        // Watch only lets it through at once.
        switchTo(FirewallMode.MONITOR)
        Probe.assertAnswered(probe.run(host, port))
        // Turned on again, Block-unknown counts from then: the probe was installed before.
        switchTo(FirewallMode.BLOCK_UNKNOWN)
        Probe.assertAnswered(probe.run(host, port))

        stopMonitoring()
        val flows = probe.flows(host, port)
        assertEquals("stored as blocked: $flows", 2, flows.count { it.blocked })
        assertEquals("stored as allowed: $flows", 3, flows.count { !it.blocked })
    }

    /** CM-08's "takes effect within 1 s": the mode is in force when the call returns. */
    private fun switchTo(mode: FirewallMode) {
        val started = SystemClock.elapsedRealtime()
        history.setFirewallMode(mode)
        val took = SystemClock.elapsedRealtime() - started
        assertTrue("switching to $mode took $took ms", took < 1_000)
        assertEquals(mode, history.firewallMode())
    }
}
