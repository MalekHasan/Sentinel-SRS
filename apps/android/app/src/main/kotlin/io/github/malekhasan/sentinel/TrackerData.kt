// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.util.Log
import io.github.malekhasan.sentinel.core.TrackerDatabase
import io.github.malekhasan.sentinel.core.TrackerDatabaseException

/**
 * The tracker list (SRS DT-06, ADR-0010): which company each destination belongs to and
 * what kind of service it is. Like the IP database, it arrives as a file of the signed
 * indicator feed (ADR-0019); until a list with one is installed there is none, and
 * destinations show no company or category.
 */
object TrackerData {
    private const val TAG = "SentinelTrackerData"

    /** Its name in the feed. */
    private const val FILE = "trackers.db"

    /** The tracker list of the list in force, or null if there is none or it cannot be
     *  used. Reads the whole file, so call it off the main thread. */
    fun open(context: Context): TrackerDatabase? {
        val file = IndicatorFeed.file(context, FILE) ?: return null
        return try {
            TrackerDatabase.open(file.path)
        } catch (e: TrackerDatabaseException) {
            Log.w(TAG, "the tracker list cannot be used", e)
            null
        }
    }
}
