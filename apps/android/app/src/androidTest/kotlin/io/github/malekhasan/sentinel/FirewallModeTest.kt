// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.FirewallMode
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryFlow
import io.github.malekhasan.sentinel.core.HistoryStore
import java.io.IOException
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
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        uninstallProbe()
        History.wipe(context)
        history = History.get(context)
        startMonitoring()
    }

    @After
    fun tearDown() {
        stopMonitoring()
        history.setFirewallMode(FirewallMode.MONITOR)
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
        uninstallProbe()
    }

    @Test
    fun blockUnknownStopsAnAppInstalledSinceUntilItIsAllowed() {
        val (host, port) = testServer()
        assertEquals(FirewallMode.MONITOR, history.firewallMode())
        switchTo(FirewallMode.BLOCK_UNKNOWN)
        assertNotNull("Sentinel was installed before: it gets through", answer(host, port))

        installProbe()
        assertBlocked(runProbe(host, port))
        assertEquals("stored as blocked", 1, probeFlows(host, port).count { it.blocked })
        // Its first connection raises the "new app" alert, which says it was blocked and
        // offers to allow it (CM-04 too: an app installed after the history began).
        var alert: HistoryAlert? = null
        waitFor("the new app's alert") {
            alert = history.alerts(true, 10u).firstOrNull { it.rule == AlertRule.FIRST_NETWORK_USE }
            alert != null
        }
        val raised = checkNotNull(alert)
        assertTrue("${raised.evidence}", AlertEvidence.App(PROBE) in raised.evidence)
        assertTrue("${raised.evidence}", AlertEvidence.NewAppBlocked in raised.evidence)
        assertEquals(AlertAction.AllowApp(PROBE), raised.actions.first())

        // What the alert's action does.
        assertTrue(allowApp(context, PROBE))
        assertAnswered(runProbe(host, port))
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
        assertBlocked(runProbe(host, port))

        // Watch only lets it through at once.
        switchTo(FirewallMode.MONITOR)
        assertAnswered(runProbe(host, port))
        // Turned on again, Block-unknown counts from then: the probe was installed before.
        switchTo(FirewallMode.BLOCK_UNKNOWN)
        assertAnswered(runProbe(host, port))

        stopMonitoring()
        val flows = probeFlows(host, port)
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

    private fun assertBlocked(said: String) =
        assertTrue("the probe got through: $said", ANSWERED.find(said) == null)

    private fun assertAnswered(said: String) =
        assertNotNull("the probe was stopped: $said", ANSWERED.find(said))

    /** The probe's connections to the test server, as the history keeps them. */
    private fun probeFlows(host: String, port: Int): List<HistoryFlow> =
        history.recentFlows(100u).filter { it.app == PROBE && it.remoteIp == host && it.remotePort.toInt() == port }

    /**
     * Installs the probe as Android's shell user would with `pm install`, fed the APK the
     * test APK carries (see app/build.gradle.kts), so that its install time is now.
     */
    private fun installProbe() {
        val apk = try {
            instrumentation.context.assets.open("probe.apk").use { it.readBytes() }
        } catch (e: IOException) {
            throw AssertionError("probe.apk is missing from the test APK's assets", e)
        }
        val (output, input) = instrumentation.uiAutomation.executeShellCommandRw("pm install -t -S ${apk.size}")
        ParcelFileDescriptor.AutoCloseOutputStream(input).use { it.write(apk) }
        val said = ParcelFileDescriptor.AutoCloseInputStream(output).use { String(it.readBytes()) }
        assertTrue("pm install: $said", said.contains("Success"))
    }

    private fun uninstallProbe() {
        shell("pm uninstall $PROBE")
    }

    /**
     * Starts the probe, which opens one connection to [host]:[port] and logs what it got,
     * and returns that line once the history has recorded the connection as ended. A
     * rule changed while it is still open would decide it again (ADR-0015).
     */
    private fun runProbe(host: String, port: Int): String {
        val before = probeFlows(host, port).size
        shell("logcat -c")
        shell("am start -W -n $PROBE/.ConnectActivity --es host $host --ei port $port")
        var said: String? = null
        waitFor("the probe to say what it got") {
            said = shell("logcat -d -s SentinelProbe:I").lines().lastOrNull { "$host:$port " in it }
            said != null
        }
        waitFor("the probe's connection to be recorded as ended") {
            probeFlows(host, port).let { flows -> flows.size > before && flows.all { it.endedMs != null } }
        }
        return checkNotNull(said)
    }

    private companion object {
        const val PROBE = "io.github.malekhasan.sentinel.probe"

        /** What the probe logs when the server answered. */
        val ANSWERED = Regex("answered with [1-9][0-9]* bytes")
    }
}
