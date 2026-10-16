// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import io.github.malekhasan.sentinel.core.AppCheck
import io.github.malekhasan.sentinel.core.InstalledApp
import java.security.MessageDigest

/**
 * The apps installed on this phone, checked against the package names and signing
 * certificates of the indicator list in force (ID-13, ADR-0023). Reading every app's
 * certificates takes a moment, so never on the main thread.
 */
object InstalledApps {
    private const val TAG = "SentinelApps"

    /** Every installed app, with the SHA-256 of each certificate it is signed with. */
    fun list(context: Context): List<InstalledApp> {
        val packages = context.packageManager
        val installed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packages.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
            )
        } else {
            @Suppress("DEPRECATION")
            packages.getInstalledPackages(PackageManager.GET_SIGNING_CERTIFICATES)
        }
        return installed.map { InstalledApp(it.packageName, certificates(it), it.lastUpdateTime) }
    }

    /**
     * Check every installed app against the list in force. Each app and indicator found
     * raises a Critical alert, once while the app stays installed. Null if there is no
     * list in force or the check failed.
     */
    fun check(context: Context): AppCheck? {
        val feed = IndicatorFeed.get(context) ?: return null
        return try {
            History.get(context).checkApps(feed, list(context))?.also { History.checked() }
        } catch (e: Exception) {
            // HistoryException, or the history or the package list could not be read.
            Log.w(TAG, "installed apps could not be checked against the indicator list", e)
            null
        }
    }

    /**
     * The certificates the app is signed with: all of them when it has several signers,
     * else its current one and those it rotated from.
     */
    private fun certificates(info: PackageInfo): List<String> {
        val signing = info.signingInfo ?: return emptyList()
        val signatures = if (signing.hasMultipleSigners()) {
            signing.apkContentsSigners
        } else {
            signing.signingCertificateHistory
        }
        return signatures.orEmpty().map { sha256(it.toByteArray()) }.distinct()
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
}
