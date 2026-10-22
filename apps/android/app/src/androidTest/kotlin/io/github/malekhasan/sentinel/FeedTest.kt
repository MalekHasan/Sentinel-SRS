// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.net.Uri
import android.os.SystemClock
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.IndicatorFeed.Outcome
import io.github.malekhasan.sentinel.core.FeedSource
import io.github.malekhasan.sentinel.core.FeedStatus
import io.github.malekhasan.sentinel.core.KnownTraces
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

private const val INDICATORS = "indicators-sentinel-test.json"
private const val DAY = 24 * 60 * 60 * 1000L

/**
 * MS-10 and SP-04 on a device (ADR-0019): the app fetches the indicator list where it is
 * published, installs it only when it is signed, newer and complete, keeps it up to date,
 * never lets a bad list replace a good one, removes a list that changed on the phone, and
 * the main screen says which list is in use. The lists are [TestFeed]'s, served by a
 * server inside this test on the phone's own loopback address.
 */
@RunWith(AndroidJUnit4::class)
class FeedTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var server: ListServer

    @Before
    fun setUp() {
        TestFeed.clear()
        server = ListServer()
    }

    @After
    fun tearDown() {
        server.close()
        TestFeed.clear()
    }

    @Test
    fun aListIsDownloadedKeptUpToDateAndNeverReplacedByABadOne() {
        assertEquals("nothing published", Outcome.NOT_FOUND, update())

        server.files = list(1)
        assertEquals(Outcome.INSTALLED, update())
        assertEquals(1L, version())
        val status = checkNotNull(IndicatorFeed.states.value.status)
        assertEquals(listOf("Sentinel test indicators"), status.sources.map { it.name })
        assertEquals(1u, status.indicators)
        assertTrue(checkNotNull(IndicatorFeed.file(context, "ip.db")).isFile)
        assertEquals(Outcome.UP_TO_DATE, update())

        server.files = list(2)
        assertEquals(Outcome.INSTALLED, update())
        assertEquals(2L, version())

        // None of these may replace the list in force.
        server.files = list(1)
        assertEquals("older", Outcome.REFUSED, update())
        val changed = String(list(3).getValue(INDICATORS)).replace("planted", "plantee").toByteArray()
        server.files = list(3) + (INDICATORS to changed)
        assertEquals("changed after signing", Outcome.REFUSED, update())
        server.files = list(3) + ("ip.db" to list(3).getValue("ip.db") + byteArrayOf(0))
        assertEquals("larger than listed", Outcome.REFUSED, update())
        server.files = list(3) - "trackers.db"
        assertEquals("a file missing", Outcome.INCOMPLETE, update())
        assertEquals(2L, version())
        assertEquals(Outcome.INCOMPLETE, IndicatorFeed.states.value.last)

        server.files = list(3)
        assertEquals(Outcome.INSTALLED, update())
        assertEquals(3L, version())
        assertEquals("the requests name no phone", setOf("Sentinel"), server.userAgents)
    }

    /** Audit A-22: a list that arrives too slowly is given up, and the list in force
     *  stays. Updating is free again at once, so a folder can be imported instead. */
    @Test
    fun aListThatArrivesTooSlowlyIsGivenUp() {
        server.files = list(1)
        assertEquals(Outcome.INSTALLED, update())
        server.files = list(2)
        server.slow = setOf("ip.db")
        // A short pace, so that the test does not wait minutes.
        val pace = IndicatorFeed.Pace(graceMillis = 1_000, minBytesPerSecond = 1L shl 20)
        val started = SystemClock.elapsedRealtime()
        assertEquals(Outcome.UNREACHABLE, IndicatorFeed.update(context, IndicatorFeed.HttpSource(server.base), pace))
        val took = SystemClock.elapsedRealtime() - started
        assertTrue("gave up after $took ms", took < 10_000)
        assertEquals(1L, version())
        assertFalse(IndicatorFeed.states.value.busy)

        server.slow = emptySet()
        assertEquals(Outcome.INSTALLED, update())
        assertEquals(2L, version())
    }

    /** SP-04: the list in force is checked again; one that changed is removed at once. */
    @Test
    fun aListChangedOnThePhoneIsRemovedAtTheNextCheck() {
        TestFeed.install(1)
        assertNotNull(IpData.open(context))
        checkNotNull(IndicatorFeed.file(context, "ip.db")).appendBytes(byteArrayOf(0))

        IndicatorFeed.recheck(context)
        assertEquals(Outcome.REMOVED, IndicatorFeed.states.value.last)
        assertNull(IndicatorFeed.states.value.status)
        assertNull(IndicatorFeed.file(context, "ip.db"))
        assertNull(IpData.open(context))
    }

    /** The main screen says which list is in use, from when, whether it is out of date,
     *  what the last check found, and how to get a new one. */
    @Test
    fun theMainScreenSaysWhichListIsInUse() {
        var feed by mutableStateOf(IndicatorFeed.State())
        var checks = 0
        var imports = 0
        compose.setContent {
            SentinelTheme {
                MonitorContent(
                    coreVersion = "0.0.1",
                    status = Monitor.Status.OFF,
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
                    feed = feed,
                    onCheckFeed = { checks++ },
                    onImportFeed = { imports++ },
                )
            }
        }
        fun shown(text: String) = compose.onNodeWithText(text).performScrollTo().assertIsDisplayed()
        fun absent(id: Int) = compose.onNodeWithText(context.getString(id)).assertDoesNotExist()

        shown(context.getString(R.string.feed_none))
        compose.onNodeWithText(context.getString(R.string.feed_check)).performScrollTo().performClick()
        compose.onNodeWithText(context.getString(R.string.feed_import)).performScrollTo().performClick()
        assertEquals(1 to 1, checks to imports)

        val now = System.currentTimeMillis()
        val status = FeedStatus(
            version = 3u,
            createdMs = now - DAY,
            expiresMs = now + 13 * DAY,
            sources = listOf(
                FeedSource("sentinel-test", "Sentinel test indicators", "https://example.org", "CC0", 3u),
            ),
            indicators = 3u,
            skipped = 0u,
        )
        feed = IndicatorFeed.State(status = status, last = Outcome.INSTALLED)
        compose.waitForIdle()
        val dates = DateFormat.getDateInstance(DateFormat.MEDIUM, context.resources.configuration.locales[0])
        shown(context.getString(R.string.feed_installed, dates.format(Date(status.createdMs)), "3"))
        shown(context.resources.getQuantityString(R.plurals.feed_indicators, 3, 3, isolate("Sentinel test indicators")))
        shown(context.getString(R.string.feed_outcome_installed))
        absent(R.string.feed_none)
        compose.onNodeWithText(context.getString(R.string.feed_expired, dates.format(Date(status.expiresMs))))
            .assertDoesNotExist()

        val expired = status.copy(expiresMs = now - DAY)
        feed = IndicatorFeed.State(status = expired, busy = true)
        compose.waitForIdle()
        shown(context.getString(R.string.feed_expired, dates.format(Date(expired.expiresMs))))
        shown(context.getString(R.string.feed_checking))
        absent(R.string.feed_check)

        feed = IndicatorFeed.State(available = false)
        compose.waitForIdle()
        shown(context.getString(R.string.feed_no_keys))
        absent(R.string.feed_check)
        absent(R.string.feed_explainer)
    }

    /** MS-15: "Known traces found" or "No known traces found", with the date of the list,
     *  and what a "not found" cannot say. Nothing is said before the history has been
     *  checked against the list in force, without a list, or for a list without
     *  indicators (audit A-24). */
    @Test
    fun theResultSaysWhetherKnownTracesWereFoundAndWithWhichList() {
        val now = System.currentTimeMillis()
        val status = FeedStatus(
            version = 3u,
            createdMs = now - DAY,
            expiresMs = now + 13 * DAY,
            sources = listOf(FeedSource("sentinel-test", "Sentinel test indicators", "https://example.org", "CC0", 3u)),
            indicators = 3u,
            skipped = 0u,
        )
        var feed by mutableStateOf(IndicatorFeed.State(status = status))
        var traces by mutableStateOf<KnownTraces?>(null)
        compose.setContent {
            SentinelTheme {
                Column(Modifier.verticalScroll(rememberScrollState())) { IndicatorList(feed, {}, {}, traces) }
            }
        }
        val dates = DateFormat.getDateInstance(DateFormat.MEDIUM, context.resources.configuration.locales[0])
        val listDate = dates.format(Date(status.createdMs))
        fun shown(text: String) = compose.onNodeWithText(text).performScrollTo().assertIsDisplayed()
        fun absent(id: Int) = compose.onNodeWithText(context.getString(id)).assertDoesNotExist()
        val results = listOf(R.string.feed_result_found, R.string.feed_result_none, R.string.feed_result_pending)

        results.forEach(::absent)

        val checkedBefore = KnownTraces(alerts = 0u, checkedVersion = 2u, sinceMs = now - 10 * DAY)
        traces = checkedBefore
        compose.waitForIdle()
        shown(context.getString(R.string.feed_result_pending))
        absent(R.string.feed_result_none)

        traces = checkedBefore.copy(checkedVersion = 3u)
        compose.waitForIdle()
        shown(context.getString(R.string.feed_result_none))
        shown(context.getString(R.string.feed_result_none_text, dates.format(Date(now - 10 * DAY)), listDate))
        shown(context.getString(R.string.feed_result_limits))
        absent(R.string.feed_result_found)

        // A list without indicators looked for nothing.
        feed = IndicatorFeed.State(status = status.copy(indicators = 0u))
        compose.waitForIdle()
        results.forEach(::absent)
        absent(R.string.feed_result_limits)
        feed = IndicatorFeed.State(status = status)

        // A trace found stays found, whatever the check says.
        traces = checkedBefore.copy(alerts = 2u)
        compose.waitForIdle()
        shown(context.getString(R.string.feed_result_found))
        shown(context.resources.getQuantityString(R.plurals.feed_result_found_text, 2, 2, listDate))
        absent(R.string.feed_result_none)
        absent(R.string.feed_result_limits)

        feed = IndicatorFeed.State()
        compose.waitForIdle()
        results.forEach(::absent)
    }

    private fun update(): Outcome = IndicatorFeed.update(context, IndicatorFeed.HttpSource(server.base))

    private fun version(): Long? = IndicatorFeed.states.value.status?.version?.toLong()

    /** Every file of test list [version], by name. */
    private fun list(version: Int): Map<String, ByteArray> =
        listOf("manifest.dsse.json", INDICATORS, "ip.db", "trackers.db")
            .associateWith { TestFeed.bytes(version, it) }

    /** Serves [files] over plain HTTP on the phone's loopback address, one request at a time;
     *  those in [slow] a byte every 50 ms. */
    private class ListServer : AutoCloseable {
        private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val base = "http://127.0.0.1:${socket.localPort}/"

        @Volatile
        var files: Map<String, ByteArray> = emptyMap()

        @Volatile
        var slow: Set<String> = emptySet()
        val userAgents: MutableSet<String> = ConcurrentHashMap.newKeySet()

        init {
            Thread({
                while (true) {
                    val client = try {
                        socket.accept()
                    } catch (e: IOException) {
                        return@Thread
                    }
                    try {
                        client.use(::answer)
                    } catch (e: IOException) {
                        // The app gave up on a slow file.
                    }
                }
            }, "feed-test-server").apply { isDaemon = true }.start()
        }

        private fun answer(client: Socket) {
            val input = client.getInputStream().bufferedReader(Charsets.ISO_8859_1)
            val request = input.readLine() ?: return
            while (true) {
                val header = input.readLine()
                if (header.isNullOrEmpty()) break
                if (header.startsWith("User-Agent:", ignoreCase = true)) {
                    userAgents += header.substringAfter(':').trim()
                }
            }
            val path = Uri.decode(request.split(' ').getOrElse(1) { "/" }.removePrefix("/"))
            val body = files[path]
            val out = client.getOutputStream()
            val head = if (body == null) "404 Not Found" else "200 OK"
            out.write("HTTP/1.1 $head\r\nContent-Length: ${body?.size ?: 0}\r\nConnection: close\r\n\r\n".toByteArray())
            if (body != null && path in slow) {
                for (byte in body) {
                    out.write(byte.toInt())
                    out.flush()
                    Thread.sleep(50)
                }
            } else {
                body?.let(out::write)
            }
            out.flush()
        }

        override fun close() {
            socket.close()
        }
    }
}
