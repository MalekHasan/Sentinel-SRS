// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.CategoryFact
import io.github.malekhasan.sentinel.core.CompanyFact
import io.github.malekhasan.sentinel.core.NameSource
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The name the test connection gives in its TLS ClientHello. */
private const val NAME = "pixel.g.ads.sentinel.test"

/**
 * DT-06 on a device: with a tracker list in place, the history keeps each named
 * destination's company and kind of service, with the lists that say so, and adds up the
 * companies per app.
 *
 * Uses the tracker list of the test indicator list ([TestFeed]), in which the app tracker
 * list names g.ads.sentinel.test
 * and its owner, and Tracker Radar gives ads.sentinel.test its categories. The test
 * connects to the HTTP server described at [testServer] with a TLS ClientHello naming
 * [NAME], so the engine learns the name from the connection itself.
 */
@RunWith(AndroidJUnit4::class)
class TrackerListTest {
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
    fun namedDestinationsKeepTheirCompanyAndKindWithTheirSources() {
        History.wipe(context)
        startMonitoring()
        waitFor("the tracker list to load") { Monitor.trackerSources != null }
        assertEquals(listOf("Tracker Radar test data", "App tracker list test data"), Monitor.trackerSources)

        val (host, port) = testServer()
        Socket().use { socket ->
            socket.connect(InetSocketAddress(InetAddress.getByName(host), port), 10_000)
            socket.soTimeout = 10_000
            // The HTTP server answers the ClientHello and blank line with "400 Bad request"
            // and closes the connection.
            socket.getOutputStream().write(clientHello(NAME) + "\r\n\r\n".toByteArray())
            assertTrue("no answer", socket.getInputStream().readBytes().isNotEmpty())
        }
        stopMonitoring()

        val app = checkNotNull(History.get(context).appSummary(context.packageName, 10u))
        val destination = app.destinations.single { it.destination == NAME }
        assertEquals(NameSource.SNI, destination.nameSource)
        assertEquals(
            CompanyFact(
                company = "Sentinel Test Ads (apps)",
                listedDomain = "g.ads.sentinel.test",
                sources = listOf("App tracker list test data"),
            ),
            destination.company,
        )
        assertEquals(
            CategoryFact(
                categories = listOf("Advertising", "Analytics"),
                listedDomain = "ads.sentinel.test",
                sources = listOf("Tracker Radar test data"),
            ),
            destination.categories,
        )
        val company = app.companies.single { it.company == "Sentinel Test Ads (apps)" }
        assertEquals(listOf("Advertising", "Analytics"), company.categories)
        assertEquals(1u, company.destinations)
    }
}
