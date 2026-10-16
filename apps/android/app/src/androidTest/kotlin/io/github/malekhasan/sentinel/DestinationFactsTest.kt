// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * DT-01 and DT-02 on a device: with an IP database in place, the history keeps each
 * destination's network, owner and country, with the source of each.
 *
 * Uses the IP database of the test indicator list ([TestFeed]), which places 10.0.2.0/24
 * (the emulator's view of the test machine) in AS64500 "SENTINEL-TEST-NET" and in Jordan.
 * Needs the HTTP server described at [testServer] at one of those addresses, as on the
 * emulator.
 */
@RunWith(AndroidJUnit4::class)
class DestinationFactsTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        TestFeed.install(1)
    }

    @After
    fun tearDown() {
        stopMonitoring()
        TestFeed.clear()
    }

    @Test
    fun eachDestinationKeepsItsNetworkAndCountryWithTheirSources() {
        val (host, port) = testServer()
        val server = InetAddress.getByName(host)
        assumeTrue("the test database covers 10.0.2.0/24 only", server.hostAddress?.startsWith("10.0.2.") == true)
        History.wipe(context)
        startMonitoring()
        waitFor("the IP database to load") { Monitor.ipSources != null }
        assertEquals("IPtoASN test data", Monitor.ipSources?.network)

        Socket().use { socket ->
            socket.connect(InetSocketAddress(server, port), 10_000)
            socket.soTimeout = 10_000
            socket.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".toByteArray())
            assertTrue("no answer", socket.getInputStream().readBytes().isNotEmpty())
        }
        stopMonitoring()

        val app = checkNotNull(History.get(context).appSummary(context.packageName, 10u))
        val destination = app.destinations.single { it.destination == server.hostAddress }
        assertEquals(64_500u, destination.asn)
        assertEquals("SENTINEL-TEST-NET", destination.networkOwner)
        assertEquals("IPtoASN test data", destination.networkSource)
        assertEquals("JO", destination.country)
        assertEquals("DB-IP Lite test data", destination.countrySource)
    }
}
