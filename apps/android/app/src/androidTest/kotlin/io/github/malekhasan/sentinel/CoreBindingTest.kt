// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.malekhasan.sentinel.core.coreVersion
import io.github.malekhasan.sentinel.core.serverNameFromClientHello
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
}
