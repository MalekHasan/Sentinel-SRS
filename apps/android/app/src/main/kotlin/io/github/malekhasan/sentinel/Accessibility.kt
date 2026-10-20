// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.UiModeManager
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.foundation.clickable
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics

// Accessibility (SRS §12.4, ADR-0037): headings and announcements for TalkBack, and
// colours that follow Android's contrast setting.

/** A screen's or a section's title, which TalkBack users can move between. */
fun Modifier.asHeading(): Modifier = semantics { heading() }

/** A status that changes while the screen is open; TalkBack reads it out when it does. */
fun Modifier.announced(): Modifier = semantics { liveRegion = LiveRegionMode.Polite }

/**
 * A row that opens something when tapped. TalkBack says what ("double-tap to [label]"),
 * and the row is at least 48 dp high, so a finger finds it (WCAG 2.5.8).
 */
fun Modifier.opens(label: String, enabled: Boolean = true, onClick: () -> Unit): Modifier =
    clickable(enabled = enabled, onClickLabel = label, onClick = onClick).minimumInteractiveComponentSize()

/** Android's contrast level from which Sentinel uses its high-contrast colours: "medium" and up. */
const val HIGH_CONTRAST_LEVEL = 0.5f

/**
 * Sentinel's colours: Material's own, which meet WCAG AA, or, when the user asked
 * Android for more contrast, colours whose text stands out at least 7:1 (WCAG AAA).
 */
fun sentinelColors(dark: Boolean, highContrast: Boolean): ColorScheme = when {
    highContrast && dark -> HIGH_CONTRAST_DARK
    highContrast -> HIGH_CONTRAST_LIGHT
    dark -> darkColorScheme()
    else -> lightColorScheme()
}

/**
 * Whether the user asked Android for more contrast (Settings, Display, Colour contrast),
 * followed as it changes. Android lets apps read it from Android 14 on.
 */
@Composable
fun highContrast(): Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && contrastLevel() >= HIGH_CONTRAST_LEVEL

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Composable
private fun contrastLevel(): Float {
    val context = LocalContext.current
    val modes = remember(context) { context.getSystemService(UiModeManager::class.java) }
    var level by remember(modes) { mutableFloatStateOf(modes?.contrast ?: 0f) }
    DisposableEffect(modes) {
        val listener = UiModeManager.ContrastChangeListener { level = it }
        modes?.addContrastChangeListener(context.mainExecutor, listener)
        onDispose { modes?.removeContrastChangeListener(listener) }
    }
    return level
}

private val HIGH_CONTRAST_LIGHT = lightColorScheme(
    primary = Color(0xFF3A2A80),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF3A2A80),
    onPrimaryContainer = Color.White,
    secondary = Color(0xFF2E2A3B),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE6DEF6),
    onSecondaryContainer = Color.Black,
    tertiary = Color(0xFF4A1530),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFFE1EA),
    onTertiaryContainer = Color.Black,
    error = Color(0xFF8C1D18),
    onError = Color.White,
    errorContainer = Color(0xFFFFE4E0),
    onErrorContainer = Color.Black,
    background = Color.White,
    onBackground = Color.Black,
    surface = Color.White,
    onSurface = Color.Black,
    onSurfaceVariant = Color(0xFF1F1B24),
    outline = Color(0xFF2B2730),
)

private val HIGH_CONTRAST_DARK = darkColorScheme(
    primary = Color(0xFFE3D9FF),
    onPrimary = Color.Black,
    primaryContainer = Color(0xFFE3D9FF),
    onPrimaryContainer = Color.Black,
    secondary = Color(0xFFEDE6F7),
    onSecondary = Color.Black,
    secondaryContainer = Color(0xFF2A2535),
    onSecondaryContainer = Color.White,
    tertiary = Color(0xFFFFE1EA),
    onTertiary = Color.Black,
    tertiaryContainer = Color(0xFF3D1A28),
    onTertiaryContainer = Color.White,
    error = Color(0xFFFFD1CB),
    onError = Color.Black,
    errorContainer = Color(0xFF5E0F0A),
    onErrorContainer = Color.White,
    background = Color.Black,
    onBackground = Color.White,
    surface = Color.Black,
    onSurface = Color.White,
    onSurfaceVariant = Color(0xFFEFE9F4),
    outline = Color(0xFFE6E0EC),
)
