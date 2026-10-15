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
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** CM-07's limit: a change is found within this time. */
private const val WITHIN_MS = 5_000L

/**
 * CM-07 on a device: while monitoring runs, changing the proxy for the whole phone or
 * the Private DNS provider raises a Warning alert within 5 seconds, with the setting
 * before and after. The settings are changed as `adb shell settings` would, and put
 * back afterwards.
 *
 * A change of the network's own DNS servers needs a network that changes them, which
 * the emulator cannot do; the core's tests cover that rule.
 */
@RunWith(AndroidJUnit4::class)
class NetworkSettingsTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val restore = mutableListOf<String>()
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        History.wipe(context)
        history = History.get(context)
        startMonitoring()
        waitFor("the network settings as they are") { history.lastNetworkState() != null }
    }

    @After
    fun tearDown() {
        restore.forEach { shell(it) }
        stopMonitoring()
    }

    @Test
    fun aProxyForTheWholePhoneRaisesAnAlertWithinFiveSeconds() {
        assertEquals("no proxy before the test", null, history.lastNetworkState()?.proxy)
        restore += "settings put global http_proxy :0"
        restore += "settings delete global http_proxy"
        shell("settings put global http_proxy 192.0.2.10:3128")

        val alert = alertWithin(AlertRule.PROXY_CHANGED)
        assertEquals(AlertSeverity.WARNING, alert.severity)
        assertEquals(listOf(AlertEvidence.Proxy(before = null, after = "192.0.2.10:3128")), alert.evidence)
        assertEquals(listOf<AlertAction>(AlertAction.OpenNetworkSettings), alert.actions)
    }

    @Test
    fun anotherPrivateDnsProviderRaisesAnAlertWithinFiveSeconds() {
        val before = history.lastNetworkState()?.privateDns
        for (key in listOf("private_dns_specifier", "private_dns_mode")) {
            val value = shell("settings get global $key").trim()
            restore += if (value == "null") "settings delete global $key" else "settings put global $key $value"
        }
        // Put back the mode before the name.
        restore.reverse()
        shell("settings put global private_dns_specifier dns.sentinel.test")
        shell("settings put global private_dns_mode hostname")

        val alert = alertWithin(AlertRule.PRIVATE_DNS_CHANGED)
        assertEquals(AlertSeverity.WARNING, alert.severity)
        assertEquals(listOf(AlertEvidence.PrivateDns(before = before, after = "dns.sentinel.test")), alert.evidence)
    }

    private fun alertWithin(rule: AlertRule): HistoryAlert {
        var found: HistoryAlert? = null
        waitFor("a ${rule.name} alert", timeoutMillis = WITHIN_MS) {
            found = history.alerts(true, 10u).firstOrNull { it.rule == rule }
            found != null
        }
        return checkNotNull(found)
    }
}
