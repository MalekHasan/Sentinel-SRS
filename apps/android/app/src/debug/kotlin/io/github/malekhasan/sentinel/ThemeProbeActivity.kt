// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color

/**
 * Debug builds only: Sentinel's theme on a screen that sets its own content, as
 * [MainActivity] does, reporting the surface colour it shows (AccessibilityTest).
 *
 * When the colour contrast changes, Android makes the system's colours anew and may
 * recreate the open screen. A screen whose content a test set comes back empty; this one
 * comes back in the colours the new contrast calls for.
 */
class ThemeProbeActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SentinelTheme {
                val shown = MaterialTheme.colorScheme.surface
                SideEffect { surface = shown }
            }
        }
    }

    companion object {
        /** The surface colour the screen last showed. */
        @Volatile
        var surface: Color? = null
    }
}
