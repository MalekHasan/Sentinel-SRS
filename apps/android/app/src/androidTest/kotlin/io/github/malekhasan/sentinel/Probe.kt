// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.HistoryFlow
import io.github.malekhasan.sentinel.core.HistoryStore
import java.io.IOException
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue

/**
 * The probe (`apps/android/probe`): a second app the device tests install while they
 * run, which opens one connection where it is told. Its connections are read back from
 * [history].
 */
internal class Probe(private val history: HistoryStore) {
    /**
     * Installs the probe as Android's shell user would with `pm install`, fed the APK the
     * test APK carries (see app/build.gradle.kts), so that its install time is now.
     */
    fun install() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val apk = try {
            instrumentation.context.assets.open("probe.apk").use { it.readBytes() }
        } catch (e: IOException) {
            throw AssertionError("probe.apk is missing from the test APK's assets", e)
        }
        val (output, input) = instrumentation.uiAutomation.executeShellCommandRw("pm install -t -S ${apk.size}")
        ParcelFileDescriptor.AutoCloseOutputStream(input).use { it.write(apk) }
        val said = ParcelFileDescriptor.AutoCloseInputStream(output).use { String(it.readBytes()) }
        assertTrue("pm install: $said", said.contains("Success"))
    }

    /** The probe's connections to [host]:[port], as the history keeps them, newest first. */
    fun flows(host: String, port: Int): List<HistoryFlow> =
        history.recentFlows(100u).filter { it.app == PACKAGE && it.remoteIp == host && it.remotePort.toInt() == port }

    /**
     * Starts the probe, which opens one connection to [host]:[port] and logs what it got,
     * and returns that line once the history has recorded the connection as ended. A
     * rule changed while it is still open would decide it again (ADR-0015).
     */
    fun run(host: String, port: Int): String {
        val before = flows(host, port).size
        shell("logcat -c")
        shell("am start -W -n $PACKAGE/.ConnectActivity --es host $host --ei port $port")
        var said: String? = null
        waitFor("the probe to say what it got") {
            said = shell("logcat -d -s SentinelProbe:I").lines().lastOrNull { "$host:$port " in it }
            said != null
        }
        waitFor("the probe's connection to be recorded as ended") {
            flows(host, port).let { flows -> flows.size > before && flows.all { it.endedMs != null } }
        }
        return checkNotNull(said)
    }

    companion object {
        const val PACKAGE = "io.github.malekhasan.sentinel.probe"

        /** What the probe logs when the server answered. */
        private val ANSWERED = Regex("answered with [1-9][0-9]* bytes")

        fun uninstall() {
            shell("pm uninstall $PACKAGE")
        }

        fun assertBlocked(said: String) =
            assertTrue("the probe got through: $said", ANSWERED.find(said) == null)

        fun assertAnswered(said: String) =
            assertNotNull("the probe was stopped: $said", ANSWERED.find(said))
    }
}
