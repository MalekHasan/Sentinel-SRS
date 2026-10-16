// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel.probe

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Adds the test certificate authority (`res/raw/test_ca.der`) to the phone's trusted ones,
 * or removes it, as the device tests ask (ID-10). Android lets only a device owner do
 * this without the user, so the tests first make the probe one. Nobody holds the
 * certificate's key: it was deleted once the certificate was made.
 */
class Certificates : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val policy = context.getSystemService(DevicePolicyManager::class.java)
        val admin = ComponentName(context, Admin::class.java)
        val certificate = context.resources.openRawResource(R.raw.test_ca).use { it.readBytes() }
        val done = try {
            when (intent.action) {
                ACTION_ADD -> policy.installCaCert(admin, certificate)
                ACTION_REMOVE -> {
                    policy.uninstallCaCert(admin, certificate)
                    true
                }
                else -> false
            }
        } catch (e: SecurityException) {
            // The probe is not device owner.
            Log.w(TAG, "${intent.action}: not device owner", e)
            false
        }
        Log.i(TAG, "${intent.action}: $done")
        resultCode = if (done) Activity.RESULT_OK else Activity.RESULT_CANCELED
    }

    companion object {
        private const val TAG = "SentinelProbe"
        const val ACTION_ADD = "io.github.malekhasan.sentinel.probe.ADD_CERTIFICATE"
        const val ACTION_REMOVE = "io.github.malekhasan.sentinel.probe.REMOVE_CERTIFICATE"
    }
}
