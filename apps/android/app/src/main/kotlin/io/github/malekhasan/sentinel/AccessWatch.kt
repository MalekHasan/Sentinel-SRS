// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.database.ContentObserver
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Checks the special access apps hold while monitoring runs (ID-12, ADR-0024): at once
 * when accessibility services or notification access change, and every minute for
 * device admin apps, which Android announces to no other app.
 */
class AccessWatch(private val context: Context) {
    private val main = Handler(Looper.getMainLooper())

    // One check at a time, off the main thread: reading the settings, the admins and
    // the history takes a moment.
    private val checks: ExecutorService = Executors.newSingleThreadExecutor { Thread(it, "sentinel-access-check") }

    private val changed = object : ContentObserver(main) {
        override fun onChange(selfChange: Boolean) = checkSoon()
    }

    private val poll = object : Runnable {
        override fun run() {
            checkSoon()
            main.postDelayed(this, POLL_MILLIS)
        }
    }

    /** Checks now, then whenever the access may have changed. */
    fun start() {
        val resolver = context.contentResolver
        resolver.registerContentObserver(
            Settings.Secure.getUriFor(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES), false, changed,
        )
        resolver.registerContentObserver(Settings.Secure.getUriFor(AccessGrants.NOTIFICATION_LISTENERS), false, changed)
        poll.run()
    }

    fun stop() {
        context.contentResolver.unregisterContentObserver(changed)
        main.removeCallbacks(poll)
        checks.shutdown()
    }

    private fun checkSoon() {
        if (!checks.isShutdown) checks.execute { AccessGrants.check(context.applicationContext) }
    }

    companion object {
        /** How often device admin apps are checked. */
        const val POLL_MILLIS = 60_000L
    }
}
