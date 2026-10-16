// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel.probe

import android.accessibilityservice.AccessibilityService
import android.app.admin.DeviceAdminReceiver
import android.service.notification.NotificationListenerService
import android.view.accessibility.AccessibilityEvent

// The special access stalkerware asks for (ID-12), which the device tests turn on for
// the probe as Android's shell user would. None of them does anything.

/** An accessibility service. */
class Watcher : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit

    override fun onInterrupt() = Unit
}

/** A notification listener. */
class Listener : NotificationListenerService()

/** A device admin receiver, with no policies. */
class Admin : DeviceAdminReceiver()
