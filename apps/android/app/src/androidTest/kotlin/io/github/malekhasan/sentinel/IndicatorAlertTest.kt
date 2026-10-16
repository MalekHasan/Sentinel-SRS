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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The domain indicator planted in every test list ([TestFeed]). */
private const val PLANTED = "planted.sentinel-test.example"

/** ID-13's limit: a planted indicator alerts within 5 s. */
private const val WITHIN_MILLIS = 5_000L

/**
 * ID-13 on a device (ADR-0020): with the signed test list in force, traffic that names
 * its planted indicator raises a Critical alert within 5 s, about the app, with what was
 * seen and the indicator's provenance. Nothing is blocked, and an app that keeps using
 * the server raises one alert, not one per lookup.
 *
 * The lookups and connections are this app's own, through the tunnel. A connection to an
 * address on the list is checked in the core (`a_known_address_raises_an_alert_within_
 * five_seconds` runs the packet engine): the list refuses the private addresses a test
 * server has here.
 */
@RunWith(AndroidJUnit4::class)
class IndicatorAlertTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        History.wipe(context)
        history = History.get(context)
        TestFeed.install(1)
    }

    @After
    fun tearDown() {
        stopMonitoring()
        TestFeed.clear()
    }

    @Test
    fun aLookupOfAPlantedNameRaisesACriticalAlertWithinFiveSeconds() {
        startMatching()
        val alert = lookUp("cdn.$PLANTED") { sent -> alertWithin(WITHIN_MILLIS, since = sent) }

        assertEquals(AlertSeverity.CRITICAL, alert.severity)
        assertEquals(AlertEvidence.App(app = context.packageName), alert.evidence.first())
        assertEquals(
            AlertEvidence.Indicator(
                indicator = PLANTED,
                seen = "cdn.$PLANTED",
                sighting = IndicatorSighting.DNS_QUERY,
                family = "Sentinel test",
                threat = IndicatorThreat.SPYWARE,
                source = "Sentinel test indicators",
                date = "2026-10-16",
                report = "https://github.com/MalekHasan/Sentinel-SRS/blob/main/docs/adr/0019-indicator-feed-on-android.md",
            ),
            alert.evidence.filterIsInstance<AlertEvidence.Indicator>().single(),
        )
        assertTrue("${alert.actions}", AlertAction.BlockApp(app = context.packageName) in alert.actions)

        // The same indicator again, and a name above it that is not on the list. An answer
        // means the engine has seen the lookup; stopping sends what it still holds.
        assertTrue(dnsAnswered(PLANTED))
        assertTrue(dnsAnswered("sentinel-test.example"))
        stopMonitoring()
        assertEquals(listOf(alert.id), knownIndicatorAlerts().map { it.id })
    }

    @Test
    fun aServerNameUnderAPlantedNameRaisesOneAlertAndIsNotBlocked() {
        startMatching()
        val (host, port) = testServer()
        val sent = System.currentTimeMillis()
        assertNotNull("not blocked", answer(host, port, clientHello("x.$PLANTED") + END))
        val alert = alertWithin(WITHIN_MILLIS, since = sent)
        assertEquals(AlertEvidence.App(app = context.packageName), alert.evidence.first())
        val seen = alert.evidence.filterIsInstance<AlertEvidence.Indicator>().single()
        assertEquals(IndicatorSighting.SERVER_NAME, seen.sighting)
        assertEquals("x.$PLANTED", seen.seen)

        assertNotNull(answer(host, port, clientHello(PLANTED) + END))
        assertTrue(dnsAnswered(PLANTED))
        stopMonitoring()
        assertEquals("one alert per app and indicator", 1, knownIndicatorAlerts().size)
    }

    /** Starts monitoring and waits until the engine matches traffic against the list. */
    private fun startMatching() {
        startMonitoring()
        waitFor("the engine to match against the list") { Monitor.matchesIndicators }
    }

    /** The known-indicator alert, stored at most [timeoutMillis] after [since]. */
    private fun alertWithin(timeoutMillis: Long, since: Long): HistoryAlert {
        var found: HistoryAlert? = null
        waitFor("a known-indicator alert", since + timeoutMillis - System.currentTimeMillis()) {
            found = knownIndicatorAlerts().firstOrNull()
            found != null
        }
        val alert = checkNotNull(found)
        val took = alert.createdMs - since
        assertTrue("raised $took ms after the traffic", took in 0 until timeoutMillis)
        return alert
    }

    private fun knownIndicatorAlerts(): List<HistoryAlert> =
        history.alerts(false, 100u).filter { it.rule == AlertRule.KNOWN_INDICATOR }

    /**
     * Sends one lookup of [name] to the tunnel's resolver, then runs [whileOpen] with the
     * time it was sent. The socket stays open meanwhile, as a resolver's does while it
     * waits for the answer: Android names a UDP socket's owner only while it exists.
     */
    private fun <T> lookUp(name: String, whileOpen: (sent: Long) -> T): T {
        val resolver = InetAddress.getByName(SentinelVpnService.TUNNEL_DNS)
        val query = dnsQuery(0x1d01, name)
        return DatagramSocket().use { socket ->
            val sent = System.currentTimeMillis()
            socket.send(DatagramPacket(query, query.size, resolver, 53))
            whileOpen(sent)
        }
    }

    private companion object {
        val END = "\r\n\r\n".toByteArray()
    }
}
