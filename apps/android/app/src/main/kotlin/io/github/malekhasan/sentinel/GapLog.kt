// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import java.io.File

/**
 * Monitoring gaps (SRS SP-03, NF-07): times when the user had turned monitoring on but
 * Sentinel was not watching traffic. Android sends traffic outside the tunnel whenever
 * the engine is gone (it fails open), so every such stop must be recorded and shown.
 *
 * Kept in a small private file until the encrypted store arrives (Sprint 2).
 */
object GapLog {
    /** Times are Unix milliseconds; `null` means unknown (start) or still open (end). */
    data class Gap(val startMillis: Long?, val endMillis: Long?, val reason: String)

    private const val FILE = "gaps.tsv"
    private const val PREFS = "monitor"
    private const val WANTED = "wanted"
    private const val MAX_ENTRIES = 200
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
        val (start, reason) = lastExit(context)
        open(context, start, reason)
    }

    /** Start a gap, unless one is already open. */
    fun open(context: Context, startMillis: Long?, reason: String) {
        synchronized(lock) {
            val gaps = read(context)
            if (gaps.lastOrNull()?.let { it.endMillis == null } == true) return
            write(context, gaps + Gap(startMillis, null, reason))
        }
    }

    /** Monitoring is back: close the open gap, if any. */
    fun closeOpen(context: Context, endMillis: Long) {
        synchronized(lock) {
            val gaps = read(context)
            val last = gaps.lastOrNull() ?: return
            if (last.endMillis != null) return
            write(context, gaps.dropLast(1) + last.copy(endMillis = endMillis))
        }
    }

    /** Delete the whole gap history. */
    fun clear(context: Context) {
        synchronized(lock) { file(context).delete() }
    }

    /** The most recent gaps, newest first. */
    fun recent(context: Context, limit: Int): List<Gap> =
        synchronized(lock) { read(context).takeLast(limit).reversed() }

    private fun lastExit(context: Context): Pair<Long?, String> {
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
        return null to context.getString(R.string.gap_process_other)
    }

    private fun file(context: Context) = File(context.filesDir, FILE)

    private fun read(context: Context): List<Gap> {
        val file = file(context)
        if (!file.exists()) return emptyList()
        return file.readLines().mapNotNull { line ->
            val parts = line.split('\t', limit = 3)
            if (parts.size != 3) null else Gap(parts[0].toLongOrNull(), parts[1].toLongOrNull(), parts[2])
        }
    }

    private fun write(context: Context, gaps: List<Gap>) {
        val text = gaps.takeLast(MAX_ENTRIES).joinToString(separator = "") { gap ->
            val reason = gap.reason.replace('\t', ' ').replace('\n', ' ')
            "${gap.startMillis ?: "-"}\t${gap.endMillis ?: "-"}\t$reason\n"
        }
        val file = file(context)
        val tmp = File(file.path + ".tmp")
        tmp.writeText(text)
        tmp.renameTo(file)
    }
}
