// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.util.Log
import io.github.malekhasan.sentinel.core.HistoryException
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.HuntReport
import io.github.malekhasan.sentinel.core.KnownTraces
import io.github.malekhasan.sentinel.core.setAsideHistory
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

    /** How often the retention periods are applied while monitoring runs (ADR-0039). */
    const val RETAIN_EVERY_MILLIS = 24 * 60 * 60 * 1000L

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
            store ?: open(context.applicationContext).let { (opened, anew) ->
                // Every new alert may become a notification (AL-06).
                opened.setAlertListener(AlertNotifier.Listener(context.applicationContext))
                store = opened
                // The old history cannot be read: say so in the new one (THREAT-MODEL-A T6).
                if (anew) {
                    try {
                        opened.startedAnew()
                    } catch (e: Exception) {
                        Log.w(TAG, "could not say that the history was started anew", e)
                    }
                }
                opened
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

    /**
     * Apply the retention periods of SRS §13.2 (ADR-0039), on a thread of its own: flows
     * kept past the user's choice are rolled up into daily totals, and older records of
     * every other kind are deleted.
     */
    fun retain(history: HistoryStore) {
        Thread({
            try {
                history.applyRetention(System.currentTimeMillis())
            } catch (e: Exception) {
                // HistoryException, or the history was closed by a wipe meanwhile.
                Log.w(TAG, "retention failed", e)
            }
        }, "sentinel-retention").start()
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
        Heartbeat.forget(context.applicationContext)
    }

    /**
     * The history, and whether it had to be started anew because the old one can never be
     * read: its key is gone, or the key does not open it (THREAT-MODEL-A T4, T6). The old
     * one is set aside with its key, not deleted, until the next wipe (audit A-06).
     *
     * Any other failure, such as a Keystore or disk error that may pass or a history from a
     * newer Sentinel, is thrown, and the next [get] tries again. Starting anew would delete
     * the history's evidence, firewall rules and isolation for good.
     */
    private fun open(context: Context): Pair<HistoryStore, Boolean> {
        val path = path(context)
        try {
            return openWith(path, HistoryKey.load(context)) to false
        } catch (e: HistoryKey.Lost) {
            Log.w(TAG, "the history's key cannot be read; starting a new history", e)
        } catch (e: HistoryException.WrongKey) {
            Log.w(TAG, "the key does not open the history; starting a new one", e)
        }
        setAsideHistory(path)
        HistoryKey.setAside(context)
        return openWith(path, HistoryKey.load(context)) to true
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
