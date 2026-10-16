// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.ContentObserver
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.security.KeyChain
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Watches the device's settings while monitoring runs:
 * - the special access apps hold (ID-12, ADR-0024): at once when accessibility services
 *   or notification access change, and every minute for device admin apps, which
 *   Android announces to no other app;
 * - wireless debugging (ID-03) and the trusted certificates (ID-10, ADR-0025): at once
 *   when either changes.
 */
class DeviceWatch(private val context: Context) {
    private val main = Handler(Looper.getMainLooper())

    // One check at a time, off the main thread: reading the settings, the admins, the
    // certificates and the history takes a moment.
    private val checks: ExecutorService = Executors.newSingleThreadExecutor { Thread(it, "sentinel-device-check") }

    private val accessChanged = object : ContentObserver(main) {
        override fun onChange(selfChange: Boolean) = checkSoon(AccessGrants::check)
    }

    private val postureChanged = object : ContentObserver(main) {
        override fun onChange(selfChange: Boolean) = checkSoon(Posture::check)
    }

    private val certificatesChanged = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) = checkSoon(Posture::check)
    }

    private val poll = object : Runnable {
        override fun run() {
            checkSoon(AccessGrants::check)
            main.postDelayed(this, POLL_MILLIS)
        }
    }

    /** Checks now, then whenever the settings may have changed. */
    fun start() {
        val resolver = context.contentResolver
        resolver.registerContentObserver(
            Settings.Secure.getUriFor(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES), false, accessChanged,
        )
        resolver.registerContentObserver(
            Settings.Secure.getUriFor(AccessGrants.NOTIFICATION_LISTENERS), false, accessChanged,
        )
        resolver.registerContentObserver(Settings.Global.getUriFor(Posture.WIRELESS_DEBUGGING), false, postureChanged)
        // Sent by the system only, when a certificate is added to or removed from the
        // trusted ones.
        val trustStore = IntentFilter(KeyChain.ACTION_TRUST_STORE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(certificatesChanged, trustStore, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(certificatesChanged, trustStore)
        }
        checkSoon(Posture::check)
        poll.run()
    }

    fun stop() {
        context.contentResolver.unregisterContentObserver(accessChanged)
        context.contentResolver.unregisterContentObserver(postureChanged)
        context.unregisterReceiver(certificatesChanged)
        main.removeCallbacks(poll)
        checks.shutdown()
    }

    private fun checkSoon(check: (Context) -> Any?) {
        if (!checks.isShutdown) checks.execute { check(context.applicationContext) }
    }

    companion object {
        /** How often device admin apps are checked. */
        const val POLL_MILLIS = 60_000L
    }
}
