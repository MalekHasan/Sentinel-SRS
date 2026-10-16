// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.util.Log
import io.github.malekhasan.sentinel.core.DevicePosture
import io.github.malekhasan.sentinel.core.UserCertificate
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate

/**
 * Device settings that open the phone to someone else (ADR-0025): wireless debugging
 * (ID-03) and the certificate authorities the user added (ID-10).
 */
object Posture {
    private const val TAG = "SentinelPosture"

    /**
     * The global setting that says whether wireless debugging is on (Android 11 and
     * later). Android has no public name for it; apps may read it.
     */
    const val WIRELESS_DEBUGGING = "adb_wifi_enabled"

    /** The settings as they are now. */
    fun read(context: Context): DevicePosture = DevicePosture(
        wirelessDebugging = Settings.Global.getInt(context.contentResolver, WIRELESS_DEBUGGING, 0) == 1,
        userCertificates = userCertificates(),
    )

    /** Tell the history what the settings are now; a change for the worse raises an alert. */
    fun check(context: Context) {
        try {
            History.get(context).postureSeen(read(context))
        } catch (e: Exception) {
            // HistoryException, or the history or the trusted certificates could not be read.
            Log.w(TAG, "the device settings could not be checked", e)
        }
    }

    /**
     * Android's trusted certificates, on the user's tab, where one can be removed. Not
     * every phone opens that screen by name, so security settings are the fallback.
     */
    fun openCertificates(context: Context) {
        try {
            context.startActivity(Intent(TRUSTED_CREDENTIALS_USER))
        } catch (e: ActivityNotFoundException) {
            context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
        } catch (e: SecurityException) {
            context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
        }
    }

    /**
     * The certificate authorities the user added: in Android's CA store, under aliases
     * that start with `user:`; the phone's own start with `system:`.
     */
    private fun userCertificates(): List<UserCertificate> {
        val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        return store.aliases().toList().filter { it.startsWith("user:") }.mapNotNull { alias ->
            (store.getCertificate(alias) as? X509Certificate)?.let {
                UserCertificate(sha256(it.encoded), it.subjectX500Principal.name)
            }
        }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    /** The Settings app's screen of trusted certificates, on the user's tab. */
    private const val TRUSTED_CREDENTIALS_USER = "com.android.settings.TRUSTED_CREDENTIALS_USER"
}
