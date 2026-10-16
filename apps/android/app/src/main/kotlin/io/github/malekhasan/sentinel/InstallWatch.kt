// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build

/**
 * Checks the installed apps against the indicator list again whenever an app is
 * installed or updated (ID-13, ADR-0023), so that stalkerware put on the phone while
 * monitoring runs is found at once.
 *
 * Android announces installs only to receivers registered while running, so the
 * monitoring service holds one of these while it runs.
 */
class InstallWatch(private val context: Context) {
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            // Reading every app's certificates takes a moment: not on the main thread.
            Thread({ InstalledApps.check(context.applicationContext) }, "sentinel-app-check").start()
        }
    }

    fun start() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        // These come only from the system; no other app may send them here.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
    }

    fun stop() {
        context.unregisterReceiver(receiver)
    }
}
