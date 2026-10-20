// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.util.Log
import java.io.File
import java.io.IOException

/**
 * The engine's heartbeat (SP-03, ADR-0029). The engine reports every 10 s that it runs;
 * while monitoring runs, the service checks every [EVERY_MILLIS] when it last did
 * ([check]). Silent for [SILENT_AFTER_MILLIS], it has stopped or hangs: a gap opens from
 * its last report, with its alert, and the service starts a new engine.
 *
 * Each report heard is also written down ([lastHeard]), so that when the process dies
 * without warning, the gap it leaves begins no earlier than the engine was last heard from.
 */
object Heartbeat {
    /** How often the service checks, as often as the engine reports. */
    const val EVERY_MILLIS = 10_000L

    /** Three reports missed: the engine has stopped or hangs. */
    const val SILENT_AFTER_MILLIS = 3 * EVERY_MILLIS

    private const val TAG = "SentinelHeartbeat"
    private const val FILE = "heartbeat"

    /**
     * Whether the engine, which last reported [ageMillis] ago by the clock that stands
     * still in sleep, has gone silent. If it has, a gap opens from its last report;
     * if not, the report is written down.
     */
    fun check(context: Context, ageMillis: Long, nowMillis: Long): Boolean {
        val heard = nowMillis - ageMillis
        if (ageMillis >= SILENT_AFTER_MILLIS) {
            GapLog.open(context, heard, context.getString(R.string.gap_engine_silent))
            return true
        }
        // Not synced to storage: the kernel keeps the write when the process dies, which
        // is all this is for, and a sync every 10 s would cost battery (NF-03).
        try {
            file(context).writeText(heard.toString())
        } catch (e: IOException) {
            Log.w(TAG, "the heartbeat cannot be written", e)
        }
        return false
    }

    /** When the engine was last heard from (Unix ms), or `null` if never or unreadable. */
    fun lastHeard(context: Context): Long? =
        try {
            file(context).takeIf { it.exists() }?.readText()?.toLongOrNull()
        } catch (e: IOException) {
            Log.w(TAG, "the last heartbeat cannot be read", e)
            null
        }

    /** Deletes the record of the last report, with the history it belongs to. */
    fun forget(context: Context) {
        file(context).delete()
    }

    private fun file(context: Context) = File(context.noBackupFilesDir, FILE)
}
