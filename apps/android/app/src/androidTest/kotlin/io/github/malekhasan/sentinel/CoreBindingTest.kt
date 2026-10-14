// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.malekhasan.sentinel.core.coreVersion
import io.github.malekhasan.sentinel.core.serverNameFromClientHello
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** A0 Spike 2: the Rust core loads on the device and its engine code runs there. */
@RunWith(AndroidJUnit4::class)
class CoreBindingTest {
    @Test
    fun nativeLibraryLoads() {
        assertTrue(coreVersion().isNotEmpty())
    }

    @Test
    fun serverNameIsReadFromClientHello() {
        assertEquals("example.org", serverNameFromClientHello(clientHello("Example.ORG")))
    }

    @Test
    fun plainHttpHasNoServerName() {
        assertNull(serverNameFromClientHello("GET / HTTP/1.1\r\n".toByteArray()))
    }

    /** A minimal TLS ClientHello carrying one server_name extension. */
    private fun clientHello(name: String): ByteArray {
        fun ByteArrayOutputStream.u16(v: Int) { write(v shr 8 and 0xFF); write(v and 0xFF) }
        val host = name.toByteArray()
        val sni = ByteArrayOutputStream().apply {
            u16(host.size + 3); write(0); u16(host.size); write(host)
        }.toByteArray()
        val ext = ByteArrayOutputStream().apply { u16(0x0000); u16(sni.size); write(sni) }.toByteArray()
        val body = ByteArrayOutputStream().apply {
            write(byteArrayOf(3, 3)); write(ByteArray(32)) // version, random
            write(0) // no session id
            u16(2); u16(0x1301) // one cipher suite
            write(1); write(0) // null compression
            u16(ext.size); write(ext)
        }.toByteArray()
        val handshake = ByteArrayOutputStream().apply {
            write(1); write(0); u16(body.size); write(body)
        }.toByteArray()
        return ByteArrayOutputStream().apply {
            write(0x16); write(3); write(1); u16(handshake.size); write(handshake)
        }.toByteArray()
    }
}
