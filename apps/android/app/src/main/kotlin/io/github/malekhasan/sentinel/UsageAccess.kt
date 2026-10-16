// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Process
import android.provider.Settings

/**
 * Usage access, which the user grants in Android's settings: with it, Sentinel can tell
 * which app is on screen, its best guess at which app uses the microphone or camera
 * (SE-01 basic, AM-15, ADR-0027). Android tells an ordinary app nothing better.
 */
object UsageAccess {
    /** How far back to look for the app on screen. */
    private const val LOOK_BACK_MILLIS = 60 * 60 * 1000L

    /** Whether the user granted Sentinel usage access. */
    fun granted(context: Context): Boolean {
        val ops = context.getSystemService(AppOpsManager::class.java)
        return ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName) ==
            AppOpsManager.MODE_ALLOWED
    }

    /** Android's settings where the user grants it. */
    fun settings(): Intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)

    /**
     * The app last on screen, unless it is Sentinel or the home screen, which use no
     * sensor; null without usage access.
     */
    fun foregroundApp(context: Context): String? {
        if (!granted(context)) return null
        val usage = context.getSystemService(UsageStatsManager::class.java) ?: return null
        val now = System.currentTimeMillis()
        val events = usage.queryEvents(now - LOOK_BACK_MILLIS, now) ?: return null
        val event = UsageEvents.Event()
        var last: String? = null
        while (events.getNextEvent(event)) {
            if (event.eventType == UsageEvents.Event.ACTIVITY_RESUMED) last = event.packageName
        }
        return last?.takeIf { it != context.packageName && it != home(context) }
    }

    private fun home(context: Context): String? = context.packageManager.resolveActivity(
        Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME),
        PackageManager.MATCH_DEFAULT_ONLY,
    )?.activityInfo?.packageName
}
