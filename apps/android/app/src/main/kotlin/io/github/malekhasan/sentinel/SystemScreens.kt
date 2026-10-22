// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

/**
 * [screen], one of Android's own screens, made to open in an app that came with the
 * phone and in no other; null when none of those has it (audit A-40).
 *
 * Any app can claim the name of a screen. For a name Android does not publish, such as
 * the Settings app's list of trusted certificates, a phone whose own Settings lacks it
 * would open the claimer's screen as if it were Android's; for a published one, Android
 * would offer the claimer beside its own. Sentinel sends the user to these screens to
 * take access away from spyware, which could show one that only seems to.
 */
fun Context.systemScreen(screen: Intent): Intent? {
    // As Android picks a screen for a name, from the apps that came with the phone only.
    val flags = PackageManager.MATCH_SYSTEM_ONLY or PackageManager.MATCH_DEFAULT_ONLY
    val found = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        packageManager.queryIntentActivities(screen, PackageManager.ResolveInfoFlags.of(flags.toLong()))
    } else {
        @Suppress("DEPRECATION")
        packageManager.queryIntentActivities(screen, flags)
    }
    val activity = found.firstOrNull()?.activityInfo ?: return null
    return Intent(screen).setClassName(activity.packageName, activity.name)
}

/**
 * Opens [screen] in an app that came with the phone, as [systemScreen] finds it.
 *
 * @throws ActivityNotFoundException when none has it, as [Context.startActivity] does.
 */
fun Context.startSystemScreen(screen: Intent) =
    startActivity(systemScreen(screen) ?: throw ActivityNotFoundException("no app of the phone's opens $screen"))
