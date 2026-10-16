// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.util.Log
import io.github.malekhasan.sentinel.core.AccessCheck
import io.github.malekhasan.sentinel.core.HeldAccess
import io.github.malekhasan.sentinel.core.SpecialAccess

/**
 * The special access apps hold on this phone: accessibility services, device admin apps
 * and notification access (ID-12, ADR-0024). An app that gains any of them, and did not
 * come with the phone, raises a High alert.
 */
object AccessGrants {
    private const val TAG = "SentinelAccess"

    /**
     * The secure setting that lists the notification listeners turned on. Android has no
     * public way to ask which other apps have notification access; androidx's
     * NotificationManagerCompat reads this setting too.
     */
    const val NOTIFICATION_LISTENERS = "enabled_notification_listeners"

    /** Every special access an app holds now. */
    fun held(context: Context): List<HeldAccess> {
        val resolver = context.contentResolver
        val accessibility =
            components(Settings.Secure.getString(resolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES))
        val listeners = components(Settings.Secure.getString(resolver, NOTIFICATION_LISTENERS))
        val admins = context.getSystemService(DevicePolicyManager::class.java)?.activeAdmins.orEmpty()
        val packages = context.packageManager
        return listOf(
            SpecialAccess.ACCESSIBILITY to accessibility,
            SpecialAccess.NOTIFICATION_LISTENER to listeners,
            SpecialAccess.DEVICE_ADMIN to admins,
        ).flatMap { (access, components) ->
            components.map { it.packageName }.distinct().map { app ->
                HeldAccess(app, access, preinstalled(packages, app))
            }
        }
    }

    /**
     * Check the special access apps hold against what they held at the last check. Null
     * if the check failed.
     */
    fun check(context: Context): AccessCheck? = try {
        History.get(context).checkAccess(held(context))
    } catch (e: Exception) {
        // HistoryException, or the history could not be opened at all.
        Log.w(TAG, "the special access apps hold could not be checked", e)
        null
    }

    /** Android's settings for [access], where it can be turned off. */
    fun settings(access: SpecialAccess): Intent = Intent(
        when (access) {
            SpecialAccess.ACCESSIBILITY -> Settings.ACTION_ACCESSIBILITY_SETTINGS
            SpecialAccess.NOTIFICATION_LISTENER -> Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS
            // There is no public screen for device admin apps; they are listed under security.
            SpecialAccess.DEVICE_ADMIN -> Settings.ACTION_SECURITY_SETTINGS
        },
    )

    /** Components as Android's settings list them: `package/class`, separated by colons. */
    private fun components(setting: String?): List<ComponentName> =
        setting.orEmpty().split(':').mapNotNull { ComponentName.unflattenFromString(it.trim()) }

    /** Whether [app] came with the phone, on its system image. */
    private fun preinstalled(packages: PackageManager, app: String): Boolean = try {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packages.getApplicationInfo(app, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            packages.getApplicationInfo(app, 0)
        }
        info.flags and ApplicationInfo.FLAG_SYSTEM != 0
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }
}
