// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import android.util.Log

/**
 * Monitoring gaps (SRS SP-03, NF-07): times when the user had turned monitoring on but
 * Sentinel was not watching traffic. Android sends traffic outside the tunnel whenever
 * the engine is gone (it fails open), so every such stop must be recorded and shown.
 *
 * Stored in the encrypted history (ADR-0009). A failure to record is logged, never
 * thrown: it must not stop the VPN service.
 */
object GapLog {
    /** Times are Unix milliseconds; `null` means unknown (start) or still open (end). */
    data class Gap(val startMillis: Long?, val endMillis: Long?, val reason: String)

    private const val TAG = "SentinelGaps"
    private const val PREFS = "monitor"
    private const val WANTED = "wanted"
    private val lock = Any()
    private var exitChecked = false

    /** Whether the user wants monitoring on. Only the user's own Stop clears it. */
    fun setMonitoringWanted(context: Context, wanted: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(WANTED, wanted)
            .apply()
    }

    /**
     * Call once when the process starts. If monitoring was wanted, the previous process
     * ended while monitoring (killed, crashed or updated): record that as a gap.
     */
    fun recordUnexpectedExit(context: Context) {
        synchronized(lock) {
            if (exitChecked) return
            exitChecked = true
        }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(WANTED, false)) return
        val (start, reason) = exitGap(
            lastExit(context), Heartbeat.lastHeard(context), context.getString(R.string.gap_process_other),
        )
        open(context, start, reason)
    }

    /**
     * When the gap a dead process left began, and why (SP-03): when it ended, if Android
     * recorded that [exit]; else when the engine was last heard from. An exit recorded
     * before the engine was last heard from is an earlier one: Android did not record
     * this one.
     */
    fun exitGap(exit: Pair<Long, String>?, lastHeard: Long?, unknown: String): Pair<Long?, String> =
        if (exit != null && (lastHeard == null || exit.first >= lastHeard)) exit else (lastHeard to unknown)

    /** Start a gap, unless one is already open. */
    fun open(context: Context, startMillis: Long?, reason: String) {
        safely("open a gap") { History.get(context).openGap(startMillis, reason) }
    }

    /** Monitoring is back: close the open gap, if any. */
    fun closeOpen(context: Context, endMillis: Long) {
        safely("close a gap") { History.get(context).closeGap(endMillis) }
    }

    /** The most recent gaps, newest first. */
    fun recent(context: Context, limit: Int): List<Gap> =
        safely("read gaps") {
            History.get(context).recentGaps(limit.toUInt()).map {
                Gap(it.startedMs, it.endedMs, it.reason)
            }
        } ?: emptyList()

    /** The process's last exit Android recorded: when, and why. */
    private fun lastExit(context: Context): Pair<Long, String>? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val manager = context.getSystemService(ActivityManager::class.java)
            val exit = manager.getHistoricalProcessExitReasons(context.packageName, 0, 1)
                .firstOrNull()
            if (exit != null) {
                val reason = when (exit.reason) {
                    ApplicationExitInfo.REASON_LOW_MEMORY -> R.string.gap_process_low_memory
                    ApplicationExitInfo.REASON_CRASH,
                    ApplicationExitInfo.REASON_CRASH_NATIVE,
                    ApplicationExitInfo.REASON_ANR -> R.string.gap_process_crash
                    ApplicationExitInfo.REASON_USER_REQUESTED,
                    ApplicationExitInfo.REASON_USER_STOPPED -> R.string.gap_process_force_stop
                    else -> R.string.gap_process_other
                }
                return exit.timestamp to context.getString(reason)
            }
        }
        return null
    }

    private fun <T> safely(what: String, action: () -> T): T? =
        try {
            action()
        } catch (e: Exception) {
            Log.w(TAG, "could not $what", e)
            null
        }
}
