// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.FlowOwner
import io.github.malekhasan.sentinel.core.HistoryAlert
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * CM-04 on a device. An app is new to the network only if it was installed after the
 * history began, by the install time Android keeps. Sentinel itself was installed before
 * its history began, so its own connections through the tunnel raise no "new app"
 * alert, even right after a wipe.
 *
 * That an app installed after the history began does raise one, with where it went, is
 * checked in the core (`writes_flows_to_the_history` runs the packet engine): on a device
 * it would need a second app installed during the test (ADR-0013).
 */
@RunWith(AndroidJUnit4::class)
class FirstSeenTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun setUp() = grantMonitoringPermissions()

    @After
    fun tearDown() = stopMonitoring()

    @Test
    fun installTimesComeFromThePackageManager() {
        val names = AppNames(context)
        @Suppress("DEPRECATION")
        val expected = context.packageManager.getPackageInfo(context.packageName, 0).firstInstallTime
        assertTrue("installed at $expected", expected > 0)
        assertEquals(expected, names.installedAt(context.packageName))
        assertEquals("asked once, then remembered", expected, names.installedAt(context.packageName))
        assertNull(names.installedAt("android.uid.system:1000"))
        assertNull(names.installedAt("org.example.not.installed"))
    }

    /**
     * Audit A-09: the owner of a UID that several packages share lists them all, so that
     * a rule about any of them applies to its connections. Android's own UIDs keep no
     * install time, so they are never new. An app's own UID lists none.
     */
    @Test
    fun ownersOfSharedUidsListTheirPackages() {
        val names = AppNames(context)
        val system = names.ownerOf(Process.SYSTEM_UID)
        assertEquals(context.packageManager.getNameForUid(Process.SYSTEM_UID), system.app)
        assertTrue("${system.packages}", "android" in system.packages && system.packages.size > 1)
        assertNull(system.installedMs)
        assertTrue(system.system)

        val own = FlowOwner(
            Process.myUid(), context.packageName, names.installedAt(context.packageName), false, emptyList(),
        )
        assertEquals(own, names.ownerOf(Process.myUid()))
        assertEquals(FlowOwner(-1, null, null, false, emptyList()), names.ownerOf(-1))
    }

    /**
     * Audit A-36: what is known of an app is forgotten once a package is removed or
     * installed. Android gives a removed app's UID to the next app installed, which must
     * not be taken for it, and an app installed again is new by its new install time.
     * A UID Android names no package for is named so that a rule can block it (audit
     * A-37).
     */
    @Test
    fun whatIsKnownOfAnAppIsForgottenOnceItIsRemovedOrInstalledAgain() {
        val history = History.get(context)
        val probe = Probe(history)
        Probe.uninstall()
        probe.install()
        try {
            val names = AppNames(context)
            val uid = context.packageManager.getPackageUid(Probe.PACKAGE, 0)
            val owner = names.ownerOf(uid)
            assertEquals(Probe.PACKAGE, owner.app)
            val installed = checkNotNull(owner.installedMs)

            Probe.uninstall()
            val unnamed = names.packageFor(uid)
            assertEquals("uid:$uid", unnamed)
            assertNull(names.installedAt(Probe.PACKAGE))
            assertTrue("a rule can block it", blockApp(context, checkNotNull(unnamed)))

            probe.install()
            val again = context.packageManager.getPackageUid(Probe.PACKAGE, 0)
            assertEquals(Probe.PACKAGE, names.packageFor(again))
            val reinstalled = checkNotNull(names.installedAt(Probe.PACKAGE))
            assertTrue("installed again at $reinstalled, first at $installed", reinstalled > installed)
        } finally {
            Probe.uninstall()
            history.firewallRules().forEach { history.removeFirewallRule(it.key) }
        }
    }

    @Test
    fun anAppInstalledBeforeTheHistoryBeganIsNotNew() {
        History.wipe(context)
        val history = History.get(context)
        val installed = checkNotNull(AppNames(context).installedAt(context.packageName))
        assertTrue("installed at $installed, history began ${history.beganMs()}", installed < history.beganMs())

        startMonitoring()
        val (host, port) = testServer()
        Socket().use { socket ->
            socket.connect(InetSocketAddress(InetAddress.getByName(host), port), 10_000)
            socket.soTimeout = 10_000
            socket.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".toByteArray())
            assertTrue("no answer", socket.getInputStream().readBytes().isNotEmpty())
        }
        stopMonitoring()

        waitFor("the connection in the history") { history.appSummary(context.packageName, 10u) != null }
        val aboutThisApp = history.alerts(false, 100u).filter { alert: HistoryAlert ->
            alert.rule == AlertRule.FIRST_NETWORK_USE &&
                AlertEvidence.App(app = context.packageName) in alert.evidence
        }
        assertEquals(emptyList<HistoryAlert>(), aboutThisApp)
    }
}
