// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import java.util.concurrent.ConcurrentHashMap

/**
 * Turns the Linux UID that owns a connection into a package name. Android 11+ hides
 * other packages unless the app may see all of them (`QUERY_ALL_PACKAGES`, see
 * PLAY-POLICY.md), which a monitor needs.
 */
class AppNames(context: Context) {
    private val packages = context.packageManager
    private val cache = ConcurrentHashMap<Int, String>()
    private val labels = ConcurrentHashMap<String, String>()
    private val installed = ConcurrentHashMap<String, Long>()
    private val system = ConcurrentHashMap<String, Boolean>()

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

    /**
     * When [packageName] was first installed, in Unix milliseconds, or null when it is
     * not an installed app (a shared or system UID). Updates keep the first install
     * time. Asks the package manager once per package.
     */
    fun installedAt(packageName: String): Long? = installed[packageName] ?: try {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packages.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packages.getPackageInfo(packageName, 0)
        }
        info.firstInstallTime.also { installed[packageName] = it }
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    /**
     * Whether [uid] belongs to the system: one of Android's own UIDs, or [packageName]
     * came with the phone (`FLAG_SYSTEM`, kept through updates). Their regular check-ins
     * are not flagged (DL-04). Asks the package manager once per package.
     */
    fun isSystem(uid: Int, packageName: String?): Boolean {
        if (uid in 0 until Process.FIRST_APPLICATION_UID) return true
        val name = packageName ?: return false
        return system.getOrPut(name) {
            try {
                val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    packages.getApplicationInfo(name, PackageManager.ApplicationInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    packages.getApplicationInfo(name, 0)
                }
                (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    /**
     * The name the user knows [packageName] by, or [packageName] itself when it is not
     * an installed app (a shared or system UID). Asks the package manager once per
     * package, so call it off the main thread.
     */
    fun labelFor(packageName: String): String = labels.getOrPut(packageName) {
        try {
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packages.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                packages.getApplicationInfo(packageName, 0)
            }
            packages.getApplicationLabel(info).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            packageName
        }
    }
}
