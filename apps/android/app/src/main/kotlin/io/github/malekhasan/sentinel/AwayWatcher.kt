// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.PowerManager

/**
 * Tells when the user is away from the phone: the screen is off, or the lock screen is
 * up (SRS CM-06). Traffic in those times is counted apart, because an app that sends
 * data while nobody is looking deserves a closer look.
 *
 * Android announces screen changes only to receivers registered while running, so the
 * monitoring service holds one of these while it runs. [onChange] runs on the main
 * thread, at [start] and whenever the answer may have changed.
 */
class AwayWatcher(private val context: Context, private val onChange: (Boolean) -> Unit) {
    private val power = context.getSystemService(PowerManager::class.java)
    private val keyguard = context.getSystemService(KeyguardManager::class.java)

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) = publish()
    }

    fun start() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            // The lock screen was dismissed.
            addAction(Intent.ACTION_USER_PRESENT)
        }
        // These come only from the system; no other app may send them here.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
        publish()
    }

    fun stop() {
        context.unregisterReceiver(receiver)
    }

    /** Away while the screen is off or the lock screen shows. */
    fun isAway(): Boolean = !power.isInteractive || keyguard.isKeyguardLocked

    private fun publish() = onChange(isAway())
}
