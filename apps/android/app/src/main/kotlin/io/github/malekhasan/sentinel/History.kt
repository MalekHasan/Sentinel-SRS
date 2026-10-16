// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.util.Log
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.HuntReport
import io.github.malekhasan.sentinel.core.KnownTraces
import io.github.malekhasan.sentinel.core.wipeHistory
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** The encrypted local history (SRS §13, ADR-0009), opened once per process. */
object History {
    private const val TAG = "SentinelHistory"
    private const val FILE = "history.db"

    /** Flows older than this are rolled up into daily totals (SRS §13.2 default). */
    const val KEEP_DAYS = 30u

    @Volatile
    private var store: HistoryStore? = null

    private val checks = MutableStateFlow(0)

    /** Counts the checks against a list, of the history or of installed apps, so the
     *  result shown follows them. */
    val hunts: StateFlow<Int> = checks.asStateFlow()

    /** A check against a list ended. */
    internal fun checked() = checks.update { it + 1 }

    fun get(context: Context): HistoryStore =
        store ?: synchronized(this) {
            store ?: open(context.applicationContext).also {
                // Every new alert may become a notification (AL-06).
                it.setAlertListener(AlertNotifier.Listener(context.applicationContext))
                store = it
            }
        }

    /**
     * Check the history against the indicator list in force, once per list (MS-02,
     * ADR-0021): connections made before the list arrived that it names raise alerts.
     * Reads the whole history, so never on the main thread. Null when there is no list,
     * the history was already checked against it, or the check failed.
     */
    fun hunt(context: Context): HuntReport? {
        val feed = IndicatorFeed.get(context) ?: return null
        return try {
            get(context).hunt(feed)?.also { checked() }
        } catch (e: Exception) {
            // HistoryException, or the history could not be opened at all.
            Log.w(TAG, "the history could not be checked against the indicator list", e)
            null
        }
    }

    /** What the history says about known traces (MS-15), or null if it cannot be read. */
    fun knownTraces(context: Context): KnownTraces? =
        try {
            get(context).knownTraces()
        } catch (e: Exception) {
            null
        }

    /**
     * One-tap wipe (SRS §13.2): delete the database and its key. Only while monitoring
     * is off, because the engine writes to the open database.
     */
    fun wipe(context: Context) = synchronized(this) {
        check(Monitor.status.value == Monitor.Status.OFF) { "stop monitoring before deleting the history" }
        store?.close()
        store = null
        deleteFiles(context.applicationContext)
    }

    private fun open(context: Context): HistoryStore {
        val path = path(context)
        return try {
            openWith(path, HistoryKey.load(context))
        } catch (e: Exception) {
            // The key is gone (for example, the Keystore was reset) or the file is
            // damaged: the old history can never be read. Start a new one.
            Log.w(TAG, "the history cannot be opened; starting a new one", e)
            deleteFiles(context)
            openWith(path, HistoryKey.load(context))
        }
    }

    private fun openWith(path: String, key: ByteArray): HistoryStore =
        try {
            HistoryStore.open(path, key)
        } finally {
            key.fill(0)
        }

    private fun deleteFiles(context: Context) {
        wipeHistory(path(context))
        HistoryKey.delete(context)
    }

    private fun path(context: Context) = File(context.noBackupFilesDir, FILE).path
}
