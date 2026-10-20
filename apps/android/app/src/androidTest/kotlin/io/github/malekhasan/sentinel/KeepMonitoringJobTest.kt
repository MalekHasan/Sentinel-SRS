// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.job.JobScheduler
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * SP-02 on a device (ADR-0038): the job that starts monitoring again when Android leaves
 * the service without a process. That case itself is checked from outside the app, by
 * scripts/restart-after-kill.sh in CI, as these tests die with the process.
 */
@RunWith(AndroidJUnit4::class)
class KeepMonitoringJobTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val scheduler = checkNotNull(context.getSystemService(JobScheduler::class.java))

    @Before
    fun grantPermissions() = grantMonitoringPermissions()

    @After
    fun stop() {
        stopMonitoring()
        KeepMonitoringJob.disarm(context)
    }

    /** While monitoring runs the job waits, moved ahead at each heartbeat check; Stop cancels it. */
    @Test
    fun armedWhileMonitoringRunsAndCancelledByStop() {
        startMonitoring()
        waitFor("the job to be armed") { scheduler.getPendingJob(KeepMonitoringJob.JOB_ID) != null }
        stopMonitoring()
        assertNull("cancelled by Stop", scheduler.getPendingJob(KeepMonitoringJob.JOB_ID))
    }

    /**
     * Monitoring the user stopped stays off when the job runs; monitoring still wanted but
     * not running, as when Android left the service without its process, starts again.
     */
    @Test
    fun startsMonitoringThatIsWantedButDoesNotRun() {
        startMonitoring()
        stopMonitoring()
        KeepMonitoringJob.arm(context)
        runJob()
        SystemClock.sleep(2_000)
        assertEquals("stopped by the user", Monitor.Status.OFF, Monitor.status.value)

        // As the process that died while monitoring left it.
        GapLog.setMonitoringWanted(context, true)
        KeepMonitoringJob.arm(context)
        runJob()
        waitFor("monitoring to start again") { Monitor.status.value == Monitor.Status.ON }
    }

    /** Runs the job now, as Android does once its time has come. */
    private fun runJob() {
        shell("cmd jobscheduler run -f ${context.packageName} ${KeepMonitoringJob.JOB_ID}")
    }
}
