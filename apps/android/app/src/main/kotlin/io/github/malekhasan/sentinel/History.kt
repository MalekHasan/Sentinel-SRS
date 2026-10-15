// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.util.Log
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.wipeHistory
import java.io.File

/** The encrypted local history (SRS §13, ADR-0009), opened once per process. */
object History {
    private const val TAG = "SentinelHistory"
    private const val FILE = "history.db"

    /** Flows older than this are rolled up into daily totals (SRS §13.2 default). */
    const val KEEP_DAYS = 30u

    @Volatile
    private var store: HistoryStore? = null

    fun get(context: Context): HistoryStore =
        store ?: synchronized(this) {
            store ?: open(context.applicationContext).also {
                // Every new alert may become a notification (AL-06).
                it.setAlertListener(AlertNotifier.Listener(context.applicationContext))
                store = it
            }
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
