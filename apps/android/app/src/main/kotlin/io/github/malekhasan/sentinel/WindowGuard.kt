// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.Activity
import android.os.Build
import android.view.View
import android.view.Window
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.window.DialogWindowProvider

/**
 * Keeps other apps from acting on Sentinel's screens through the person holding the
 * phone (audit A-17, THREAT-MODEL-A E7). Spyware often holds accessibility access or
 * draws over other apps; Sentinel's buttons allow apps, take back blocks, end isolation
 * and wipe the history.
 * - A touch made while another app's window covers Sentinel's is dropped, so an overlay
 *   cannot get the user to tap a button it hides (tapjacking).
 * - From Android 12, other apps' overlays are hidden while Sentinel's window shows.
 * - From Android 14, Sentinel's screens are data-sensitive: accessibility services that
 *   are not accessibility tools, as spyware's are not, can neither read them nor press
 *   their buttons. TalkBack, Switch Access and other tools still can (SRS §12.4).
 */
fun Activity.guardWindow() = window.guard()

/** Guards the window of the dialog it is called in, as [guardWindow] does an activity's. */
@Composable
fun GuardDialogWindow() {
    val window = (LocalView.current.parent as? DialogWindowProvider)?.window
    SideEffect { window?.guard() }
}

private fun Window.guard() {
    decorView.filterTouchesWhenObscured = true
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        setHideOverlayWindows(true)
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
    }
}
