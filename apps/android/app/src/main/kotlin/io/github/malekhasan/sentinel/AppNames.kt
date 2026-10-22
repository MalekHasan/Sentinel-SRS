// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import io.github.malekhasan.sentinel.core.FlowOwner
import java.util.concurrent.ConcurrentHashMap

/**
 * Turns the Linux UID that owns a connection into a package name. Android 11+ hides
 * other packages unless the app may see all of them (`QUERY_ALL_PACKAGES`, see
 * PLAY-POLICY.md), which a monitor needs.
 */
class AppNames(context: Context) {
    private val packages = context.packageManager
    private val labels = ConcurrentHashMap<String, String>()

    /**
     * What is known of the installed packages, by UID and by package. Android gives a
     * removed app's UID to the next app installed, and an app installed again has a new
     * install time, so all of it is forgotten once any package is added, removed or
     * updated (audit A-36). Otherwise a new app would be taken for the one whose UID it
     * got, with its rules, and let through during isolation like it. Android counts
     * these changes before the app changed can run, and each lookup asks for the count,
     * so a UID asked about after a change is never named from before it. Labels are
     * kept: they are only shown.
     */
    private class Known(val changes: Int) {
        val owners = ConcurrentHashMap<Int, String>()
        val shared = ConcurrentHashMap<Int, List<String>>()
        val installed = ConcurrentHashMap<String, Long>()
        val system = ConcurrentHashMap<String, Boolean>()
    }

    @Volatile
    private var known = Known(0)

    /** What is known now, after forgetting it all if a package changed since. */
    private fun known(): Known {
        val current = known
        val changed = packages.getChangedPackages(current.changes) ?: return current
        synchronized(this) {
            if (known === current) known = Known(changed.sequenceNumber)
            return known
        }
    }

    /**
     * The package that owns [uid], or Android's name for a shared or system UID (for
     * example `android.uid.system:1000`), or `uid:` and the UID when Android names none.
     * Null when the owner is unknown (-1).
     */
    fun packageFor(uid: Int): String? = packageFor(uid, known())

    private fun packageFor(uid: Int, known: Known): String? {
        if (uid < 0) return null
        return known.owners.getOrPut(uid) {
            val owners = packages.getPackagesForUid(uid)
            when {
                owners?.size == 1 -> owners[0]
                // Without a space, so that a rule can name it (audit A-37).
                else -> packages.getNameForUid(uid) ?: owners?.minOrNull() ?: "uid:$uid"
            }
        }
    }

    /**
     * Who owns a connection by [uid], for the firewall and the history. A UID that several
     * packages share (`sharedUserId`) lists them all: the network cannot tell them apart,
     * so a rule about any of them applies to all, and the UID is new when one of them is,
     * by its newest install time. Android's own UIDs have no install time, as before
     * (audit A-09). A system app's regular check-ins are not flagged (DL-04).
     */
    fun ownerOf(uid: Int): FlowOwner {
        val known = known()
        val app = packageFor(uid, known)
        val packages = sharedPackagesFor(uid, known)
        val ofSystem = isSystem(uid, app, known)
        val installed = when {
            packages.isEmpty() -> app?.let { installedAt(it, known) }
            ofSystem -> null
            else -> packages.mapNotNull { installedAt(it, known) }.maxOrNull()
        }
        return FlowOwner(uid, app, installed, ofSystem, packages)
    }

    /**
     * Every package of [uid] when several share it, sorted; empty when it is one
     * package's own or not known.
     */
    fun sharedPackagesFor(uid: Int): List<String> = sharedPackagesFor(uid, known())

    private fun sharedPackagesFor(uid: Int, known: Known): List<String> {
        if (uid < 0) return emptyList()
        return known.shared.getOrPut(uid) {
            packages.getPackagesForUid(uid)?.takeIf { it.size > 1 }?.sorted().orEmpty()
        }
    }

    /**
     * When [packageName] was first installed, in Unix milliseconds, or null when it is
     * not an installed app (a shared or system UID). Updates keep the first install
     * time. Asks the package manager once per package until a package changes.
     */
    fun installedAt(packageName: String): Long? = installedAt(packageName, known())

    private fun installedAt(packageName: String, known: Known): Long? = known.installed[packageName] ?: try {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packages.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packages.getPackageInfo(packageName, 0)
        }
        info.firstInstallTime.also { known.installed[packageName] = it }
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    /**
     * Whether [uid] belongs to the system: one of Android's own UIDs, or [packageName]
     * came with the phone (`FLAG_SYSTEM`, kept through updates). Their regular check-ins
     * are not flagged (DL-04). Asks the package manager once per package until a
     * package changes.
     */
    fun isSystem(uid: Int, packageName: String?): Boolean = isSystem(uid, packageName, known())

    private fun isSystem(uid: Int, packageName: String?, known: Known): Boolean {
        if (uid in 0 until Process.FIRST_APPLICATION_UID) return true
        val name = packageName ?: return false
        return known.system.getOrPut(name) {
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
