// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.FirewallRule
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.RuleAction
import io.github.malekhasan.sentinel.core.RuleDestination
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * CM-10 on a device (ADR-0015): firewall rules kept in the history stop this app's own
 * connections through the tunnel, by address when they start, by the TLS server name,
 * and at the DNS lookup, and removing a rule lets them through again. A rule made while
 * a connection is open ends it.
 *
 * The connections go to the test server described at [testServer], which answers any
 * request, so an answer means the connection got through.
 */
@RunWith(AndroidJUnit4::class)
class FirewallTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        History.wipe(context)
        history = History.get(context)
        startMonitoring()
    }

    @After
    fun tearDown() {
        stopMonitoring()
        // Leave no rule behind for the next test.
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
    }

    /**
     * Each time monitoring starts, the first connection is already subject to the rules.
     * Repeated across restarts: a blocked request was once answered because it went
     * around the tunnel while Android swapped the old one for the new (see
     * [stopMonitoring]).
     */
    @Test
    fun aBlockedAddressIsNotReachedUntilTheRuleIsRemoved() {
        val (host, port) = testServer()
        val address = checkNotNull(InetAddress.getByName(host).hostAddress)
        repeat(TRIES) { attempt ->
            if (attempt > 0) {
                stopMonitoring()
                startMonitoring()
            }
            val key = history.setFirewallRule(
                FirewallRule(context.packageName, RuleDestination.Network(address), RuleAction.BLOCK),
            )
            assertEquals(listOf(key), history.firewallRules().map { it.key })
            val blocked = answer(host, port, REQUEST)
            if (blocked != null) {
                // Say what the engine saw, to tell a wrong owner from a wrong address.
                stopMonitoring()
                val seen = history.recentFlows(100u).filter { it.remoteIp == address }
                    .map { "${it.app} ${it.proto} ${it.remoteIp}:${it.remotePort} blocked=${it.blocked}" }
                fail("try ${attempt + 1}: blocked by address, but the server answered; rule $key; flows: $seen")
            }
            assertTrue(history.removeFirewallRule(key))
            assertNotNull("try ${attempt + 1}: allowed again", answer(host, port, REQUEST))
        }

        stopMonitoring()
        val flows = history.recentFlows(100u).filter { it.remoteIp == address && it.remotePort.toInt() == port }
        assertEquals("stored as blocked: $flows", TRIES, flows.count { it.blocked })
        assertEquals("stored as allowed: $flows", TRIES, flows.count { !it.blocked })
    }

    /** RA-01: a rule blocking the app ends its connection that is already open. */
    @Test
    fun aRuleMadeWhileAConnectionIsOpenEndsIt() {
        val (host, port) = testServer()
        val address = checkNotNull(InetAddress.getByName(host).hostAddress)
        Socket().use { socket ->
            socket.connect(InetSocketAddress(address, port), 5_000)
            socket.soTimeout = 5_000
            // An unfinished request: the server waits for the rest, so the connection stays open.
            socket.getOutputStream().write("GET / HTTP/1.0\r\n".toByteArray())
            socket.getOutputStream().flush()
            val blocked = SystemClock.elapsedRealtime()
            val ruleMs = System.currentTimeMillis()
            history.setFirewallRule(FirewallRule(context.packageName, null, RuleAction.BLOCK))
            val ended = closes(socket)
            val took = SystemClock.elapsedRealtime() - blocked
            if (!ended || took >= 1_000) {
                // Say what the engine saw: no flow means the connection went around the
                // tunnel, no app that its owner was not found, and an end long after the
                // rule that it was applied late rather than not at all.
                socket.soTimeout = 15_000
                val late = if (ended || closes(socket)) {
                    "${SystemClock.elapsedRealtime() - blocked} ms"
                } else {
                    "never"
                }
                stopMonitoring()
                val seen = history.recentFlows(100u)
                    .filter { it.remoteIp == address && it.remotePort.toInt() == port }
                    .map { "${it.app} blocked=${it.blocked} ended=+${it.endedMs?.minus(ruleMs)} ms" }
                fail(
                    (if (ended) "ended after $took ms" else "the connection is still open after $took ms") +
                        "; it ended: $late; flows: $seen",
                )
            }
        }
        stopMonitoring()
        val flows = history.recentFlows(100u).filter { it.remoteIp == address && it.remotePort.toInt() == port }
        assertTrue("stored as blocked: $flows", flows.any { it.blocked })
    }

    @Test
    fun aBlockedServerNameIsNotReached() {
        history.setFirewallRule(FirewallRule(null, RuleDestination.Domain(BLOCKED), RuleAction.BLOCK))
        val (host, port) = testServer()
        assertNull("blocked by name", answer(host, port, clientHello("x.$BLOCKED") + END))
        assertNotNull("another name gets through", answer(host, port, clientHello("allowed.sentinel.test") + END))
    }

    @Test
    fun aBlockedNameGetsNoSuchNameAtOnce() {
        // localhost resolves anywhere, so "no such name" can only come from the rule.
        history.setFirewallRule(FirewallRule(null, RuleDestination.Domain("localhost"), RuleAction.BLOCK))
        val blocked = checkNotNull(lookup(0x5e10, "localhost")) { "no answer to the blocked lookup" }
        assertEquals("NXDOMAIN", 3, blocked.rcode)
        assertEquals("no addresses", 0, blocked.answers)

        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
        val allowed = checkNotNull(lookup(0x5e11, "localhost")) { "no answer once the rule is gone" }
        // Otherwise the network's resolver could have said the same, and the rule proved nothing.
        assertTrue(
            "the network's resolver answers differently: rcode ${allowed.rcode}, ${allowed.answers} answers",
            allowed.rcode != 3 || allowed.answers > 0,
        )
    }

    /** Whether [socket]'s connection is closed or reset within its read timeout. */
    private fun closes(socket: Socket): Boolean = try {
        socket.getInputStream().read() == -1
    } catch (timeout: SocketTimeoutException) {
        false
    } catch (reset: IOException) {
        true
    }

    private class Reply(val rcode: Int, val answers: Int)

    /** Asks the tunnel's resolver for [name]; null if nothing answers within 2 s, twice. */
    private fun lookup(id: Int, name: String): Reply? {
        val resolver = InetAddress.getByName(SentinelVpnService.TUNNEL_DNS)
        repeat(2) {
            DatagramSocket().use { socket ->
                socket.soTimeout = 2_000
                val query = dnsQuery(id, name)
                socket.send(DatagramPacket(query, query.size, resolver, 53))
                val buffer = ByteArray(512)
                val reply = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(reply)
                } catch (timeout: SocketTimeoutException) {
                    return@use
                }
                val replyId = (buffer[0].toInt() and 0xFF shl 8) or (buffer[1].toInt() and 0xFF)
                if (reply.length >= 12 && replyId == id) {
                    val answers = (buffer[6].toInt() and 0xFF shl 8) or (buffer[7].toInt() and 0xFF)
                    return Reply(rcode = buffer[3].toInt() and 0x0F, answers = answers)
                }
            }
        }
        return null
    }

    private companion object {
        const val TRIES = 5
        const val BLOCKED = "blocked.sentinel.test"
        val END = "\r\n\r\n".toByteArray()
    }
}
