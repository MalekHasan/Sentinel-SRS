// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.util.Log
import io.github.malekhasan.sentinel.core.IpDatabase
import io.github.malekhasan.sentinel.core.IpDatabaseException
import java.io.File

/**
 * The offline IP database (SRS DT-01, ADR-0010): the network, its owner and the
 * approximate country of each destination. It arrives as a file of the signed feed
 * (Sprint 7); until a feed is installed there is none, and destinations show no network
 * or country.
 */
object IpData {
    private const val TAG = "SentinelIpData"

    /** Where the feed puts the database. */
    fun file(context: Context): File = File(File(context.noBackupFilesDir, "feed"), "ip.db")

    /** The database, or null if there is none or it cannot be used. Reads the whole
     *  file, so call it off the main thread. */
    fun open(context: Context): IpDatabase? {
        val file = file(context)
        if (!file.isFile) return null
        return try {
            IpDatabase.open(file.path)
        } catch (e: IpDatabaseException) {
            Log.w(TAG, "the IP database cannot be used", e)
            null
        }
    }
}
