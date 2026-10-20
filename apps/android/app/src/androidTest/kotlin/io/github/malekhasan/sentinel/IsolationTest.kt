// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.HistoryStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * RA-03 on a device (ADR-0017): isolating the phone leaves the internet to Sentinel
 * itself, DNS through the tunnel's resolver and the apps a rule allows as a whole, at
 * once and across a restart of monitoring, until it ends. The other app is the probe
 * ([Probe]).
 */
@RunWith(AndroidJUnit4::class)
class IsolationTest {
    @get:Rule
    val compose = createComposeRule()

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
    }

    @After
    fun tearDown() {
        endIsolation(context)
        stopMonitoring()
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
        Probe.uninstall()
    }

    @Test
    fun isolationLeavesTheInternetToSentinelDnsAndAllowedApps() {
        startMonitoring()
        probe.install()
        val (host, port) = testServer()
        Probe.assertAnswered(probe.run(host, port))

        val started = SystemClock.elapsedRealtime()
        assertTrue(isolatePhone(context))
        val took = SystemClock.elapsedRealtime() - started
        assertTrue("isolating took $took ms", took < 1_000)
        assertNotNull(history.isolatedSinceMs())
        assertNotNull("Sentinel itself", answer(host, port))
        assertTrue("DNS", dnsAnswered("localhost"))
        Probe.assertBlocked(probe.run(host, port))

        // Kept when monitoring starts again.
        stopMonitoring()
        startMonitoring()
        Probe.assertBlocked(probe.run(host, port))

        // An app allowed as a whole keeps the internet; without the rule it loses it again.
        assertTrue(allowApp(context, Probe.PACKAGE))
        Probe.assertAnswered(probe.run(host, port))
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
        Probe.assertBlocked(probe.run(host, port))

        assertTrue(endIsolation(context))
        assertNull(history.isolatedSinceMs())
        Probe.assertAnswered(probe.run(host, port))

        stopMonitoring()
        val flows = probe.flows(host, port)
        assertEquals("stored as blocked: $flows", 3, flows.count { it.blocked })
        assertEquals("stored as allowed: $flows", 3, flows.count { !it.blocked })
    }

    /**
     * Audit finding A-01: port 53 on a server of the app's choosing is not DNS isolation
     * lets through, as the app could send it anything. Here that server answers plain
     * HTTP.
     */
    @Test
    fun isolationBlocksPort53OnAnotherServer() {
        startMonitoring()
        probe.install()
        val host = testServerOnPort53()
        assertNotNull("no test server answers on $host:53", answer(host, 53))
        Probe.assertAnswered(probe.run(host, 53))

        assertTrue(isolatePhone(context))
        Probe.assertBlocked(probe.run(host, 53))
        assertTrue("DNS through the tunnel's resolver", dnsAnswered("localhost"))
        assertTrue("stored as blocked", probe.flows(host, 53).first().blocked)
    }

    /** One tap isolates while monitoring runs; the banner says since when and ends it. */
    @Test
    fun theMainScreenIsolatesAndEndsIsolation() {
        var isolations = 0
        var ends = 0
        var since by mutableStateOf<Long?>(null)
        compose.setContent {
            SentinelTheme {
                MonitorContent(
                    coreVersion = "0.0.1",
                    status = Monitor.Status.ON,
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
                    isolatedSince = since,
                    onIsolate = { isolations++ },
                    onEndIsolation = { ends++ },
                )
            }
        }
        compose.onNodeWithText(context.getString(R.string.isolation_start_text)).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.isolation_start)).performScrollTo().performClick()
        assertEquals(1, isolations)

        since = System.currentTimeMillis()
        compose.waitForIdle()
        compose.onNodeWithText(context.getString(R.string.isolation_title)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.isolation_start)).assertDoesNotExist()
        compose.onNodeWithText(context.getString(R.string.isolation_end)).performClick()
        assertEquals(1, ends)
    }
}
