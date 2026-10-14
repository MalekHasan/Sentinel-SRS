// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * Turns the Linux UID that owns a connection into a package name. Android 11+ hides
 * other packages unless the app may see all of them (`QUERY_ALL_PACKAGES`, see
 * PLAY-POLICY.md), which a monitor needs.
 */
class AppNames(context: Context) {
    private val packages = context.packageManager
    private val cache = ConcurrentHashMap<Int, String>()

    /**
     * The package that owns [uid], or Android's name for a shared or system UID (for
     * example `android.uid.system:1000`). Null when the owner is unknown (-1).
     */
    fun packageFor(uid: Int): String? {
        if (uid < 0) return null
        return cache.getOrPut(uid) {
            val owners = packages.getPackagesForUid(uid)
            when {
                owners?.size == 1 -> owners[0]
                else -> packages.getNameForUid(uid) ?: owners?.minOrNull() ?: "uid $uid"
            }
        }
    }
}
