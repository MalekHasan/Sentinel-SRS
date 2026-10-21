// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * Starts monitoring again when Android does not, after Sentinel's process died (SP-02,
 * ADR-0038).
 *
 * The VPN service is sticky, so Android starts it again. But when the process dies,
 * Android's VPN also lets go of the service, and when that comes first, Android 14 can
 * leave the service started with no process and nothing to start it again.
 *
 * While monitoring runs, every heartbeat check moves this job [AFTER_MILLIS] ahead
 * ([arm]). When the process dies the checks stop, and the job runs: it starts monitoring
 * if the user still wants it, Android's VPN consent still holds, and it does not run.
 * Monitoring that ends cancels the job ([disarm]).
 */
class KeepMonitoringJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        if (GapLog.monitoringWanted(this) && Monitor.status.value == Monitor.Status.OFF &&
            VpnService.prepare(this) == null
        ) {
            Log.i(TAG, "monitoring is wanted but does not run: starting it")
            try {
                startForegroundService(
                    Intent(this, SentinelVpnService::class.java).setAction(SentinelVpnService.ACTION_START),
                )
            } catch (e: IllegalStateException) {
                // Android may refuse a start from the background; the next app start resumes.
                Log.w(TAG, "monitoring could not be started", e)
            }
        }
        return false
    }

    override fun onStopJob(params: JobParameters): Boolean = false

    companion object {
        private const val TAG = "SentinelKeepMonitoring"
        internal const val JOB_ID = 7_002

        /** As long as the heartbeat waits before it calls an engine silent (ADR-0029). */
        const val AFTER_MILLIS = Heartbeat.SILENT_AFTER_MILLIS

        /** Runs the job [AFTER_MILLIS] from now, unless armed again or cancelled before. */
        fun arm(context: Context) {
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, KeepMonitoringJob::class.java))
                .setMinimumLatency(AFTER_MILLIS)
                .build()
            context.getSystemService(JobScheduler::class.java)?.schedule(job)
        }

        fun disarm(context: Context) {
            context.getSystemService(JobScheduler::class.java)?.cancel(JOB_ID)
        }
    }
}
