// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.test.platform.app.InstrumentationRegistry
import java.io.FileNotFoundException
import org.junit.Assert.assertEquals

/**
 * The signed indicator lists in the test APK's `assets/feed/v1` to `v5`, built by
 * `apps/android/scripts/make-test-feed.sh` (ADR-0019). Each holds the test indicators
 * (`indicators-sentinel-test.json`), the test IP database (`ip.db`, which places
 * 10.0.2.0/24 in AS64500 "SENTINEL-TEST-NET" and in Jordan) and the test tracker list
 * (`trackers.db`). Every list names the planted domain `planted.sentinel-test.example`.
 * Lists 2 and 3 add a package and a certificate no app has; list 4 adds the probe's
 * package and list 5 the probe's signing certificate (ADR-0023). Debug builds trust the
 * key that signed them, whose secret no longer exists.
 */
internal object TestFeed {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    /** List [version], read from the test assets the way a folder or a server is read. */
    fun source(version: Int): IndicatorFeed.BundleSource = IndicatorFeed.BundleSource { path ->
        try {
            instrumentation.context.assets.open("feed/v$version/$path")
        } catch (e: FileNotFoundException) {
            null
        }
    }

    /** File [path] of list [version]. */
    fun bytes(version: Int, path: String): ByteArray =
        instrumentation.context.assets.open("feed/v$version/$path").use { it.readBytes() }

    /** Removes every installed list, as on a new phone. */
    fun clear() {
        IndicatorFeed.dir(context).deleteRecursively()
        IndicatorFeed.recheck(context)
    }

    /** Puts list [version] in force, in place of any other, the way the app installs one. */
    fun install(version: Int) {
        clear()
        assertEquals(IndicatorFeed.Outcome.INSTALLED, IndicatorFeed.update(context, source(version)))
    }
}
