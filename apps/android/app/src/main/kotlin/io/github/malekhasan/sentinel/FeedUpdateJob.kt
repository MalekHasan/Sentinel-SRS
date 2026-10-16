// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context

/**
 * Looks for a newer indicator list where the feed is published, every few hours while
 * the phone has a network (SRS MS-10, ADR-0019), whether monitoring runs or not.
 */
class FeedUpdateJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        Thread({
            val outcome = IndicatorFeed.checkPublished(applicationContext)
            // Try again soon when the list could not be reached; otherwise wait a period.
            jobFinished(params, outcome == IndicatorFeed.Outcome.UNREACHABLE)
        }, "sentinel-feed-update").start()
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = true

    companion object {
        private const val JOB_ID = 7_001
        private const val FLEX_MILLIS = 60 * 60 * 1000L

        /** Schedules the job, unless it already is. */
        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            if (scheduler.getPendingJob(JOB_ID) != null) return
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, FeedUpdateJob::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                // In the last hour of each period: the first run comes hours after the
                // job is scheduled. Opening the app checks at once when a check is due.
                .setPeriodic(IndicatorFeed.CHECK_EVERY_MILLIS, FLEX_MILLIS)
                .build()
            scheduler.schedule(job)
        }
    }
}
