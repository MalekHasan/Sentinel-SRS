// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

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
 * and at the DNS lookup, and removing a rule lets them through again.
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

    @Test
    fun aBlockedAddressIsNotReachedUntilTheRuleIsRemoved() {
        val (host, port) = testServer()
        val address = checkNotNull(InetAddress.getByName(host).hostAddress)
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
            fail("blocked by address, but the server answered (${blocked.size} bytes); rule $key; flows: $seen")
        }
        assertTrue(history.removeFirewallRule(key))
        assertNotNull("allowed again", answer(host, port, REQUEST))

        stopMonitoring()
        val flows = history.recentFlows(100u).filter { it.remoteIp == address && it.remotePort.toInt() == port }
        assertTrue("stored as blocked: $flows", flows.any { it.blocked })
        assertTrue("stored as allowed: $flows", flows.any { !it.blocked })
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

    /** What the test server sent back, or null if the connection was refused or closed. */
    private fun answer(host: String, port: Int, request: ByteArray): ByteArray? = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(InetAddress.getByName(host), port), 5_000)
            socket.soTimeout = 5_000
            socket.getOutputStream().write(request)
            socket.getInputStream().readBytes().takeIf { it.isNotEmpty() }
        }
    } catch (e: IOException) {
        null
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
        const val BLOCKED = "blocked.sentinel.test"
        val REQUEST = "GET / HTTP/1.0\r\n\r\n".toByteArray()
        val END = "\r\n\r\n".toByteArray()
    }
}
