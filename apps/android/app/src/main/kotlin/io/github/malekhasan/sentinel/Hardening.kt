// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.security.advancedprotection.AdvancedProtectionManager
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.HardeningFacts
import io.github.malekhasan.sentinel.core.HardeningItem
import io.github.malekhasan.sentinel.core.HardeningStatus
import io.github.malekhasan.sentinel.core.HardeningStep
import io.github.malekhasan.sentinel.core.hardeningChecklist
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Test tag of one step's row in the checklist. */
fun hardeningRowTag(step: HardeningStep): String = "hardening-${step.name}"

/**
 * The hardening checklist (MS-12, ADR-0026): steps that make this phone harder to spy on,
 * each with where it stands when the phone lets Sentinel read it, else a check for the
 * user, and a way to Android's settings for it.
 */
object Hardening {
    /** What Sentinel can read about this phone. */
    fun facts(context: Context): HardeningFacts {
        val available = Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA
        return HardeningFacts(
            advancedProtectionAvailable = available,
            advancedProtection = if (available) advancedProtection(context) else null,
            securityPatch = Build.VERSION.SECURITY_PATCH.takeIf { it.isNotBlank() },
            screenLock = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true,
            usbDebugging = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1,
        )
    }

    /** The checklist as of today. */
    fun items(context: Context): List<HardeningItem> = hardeningChecklist(facts(context))

    /**
     * Android's settings for [step]: the screen named for it, else the nearest one, in an
     * app that came with the phone (audit A-40).
     */
    fun openSettings(context: Context, step: HardeningStep) {
        val screens = when (step) {
            // Advanced Protection is in Android's security settings.
            HardeningStep.ADVANCED_PROTECTION -> listOf(Settings.ACTION_SECURITY_SETTINGS)
            // Not every maker opens system updates by this name.
            HardeningStep.SECURITY_UPDATE -> listOf(SYSTEM_UPDATE_SETTINGS, Settings.ACTION_DEVICE_INFO_SETTINGS)
            HardeningStep.SCREEN_LOCK ->
                listOf(DevicePolicyManager.ACTION_SET_NEW_PASSWORD, Settings.ACTION_SECURITY_SETTINGS)
            HardeningStep.USB_DEBUGGING -> listOf(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
            HardeningStep.UNKNOWN_APPS -> listOf(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
            HardeningStep.MESSAGING_APPS -> listOf(Settings.ACTION_APPLICATION_SETTINGS)
        } + Settings.ACTION_SETTINGS
        for (screen in screens) {
            try {
                context.startSystemScreen(Intent(screen))
                return
            } catch (e: ActivityNotFoundException) {
                // Try the next one.
            } catch (e: SecurityException) {
                // Try the next one.
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.BAKLAVA)
    private fun advancedProtection(context: Context): Boolean? = try {
        context.getSystemService(AdvancedProtectionManager::class.java)?.isAdvancedProtectionEnabled
    } catch (e: SecurityException) {
        null
    }

    /** The system update screen, which Android does not name publicly. */
    private const val SYSTEM_UPDATE_SETTINGS = "android.settings.SYSTEM_UPDATE_SETTINGS"
}

/** The checklist, read again whenever the screen is [visible] (the user may be back from the settings). */
@Composable
fun HardeningScreen(visible: Boolean, onBack: () -> Unit) {
    val context = LocalContext.current
    var items by remember { mutableStateOf(emptyList<HardeningItem>()) }
    LaunchedEffect(visible) {
        if (visible) items = withContext(Dispatchers.IO) { Hardening.items(context) }
    }
    HardeningChecklist(
        items,
        securityPatch = Build.VERSION.SECURITY_PATCH.takeIf { it.isNotBlank() },
        onBack = onBack,
        onOpen = { Hardening.openSettings(context, it) },
    )
}

/** The checklist's content; [securityPatch] is the date of the security update installed. */
@Composable
fun HardeningChecklist(
    items: List<HardeningItem>,
    securityPatch: String?,
    onBack: () -> Unit,
    onOpen: (HardeningStep) -> Unit,
) {
    // A handful of steps: no lazy list needed.
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
        Text(
            stringResource(R.string.hardening_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.asHeading(),
        )
        Text(stringResource(R.string.hardening_explainer), style = MaterialTheme.typography.bodyMedium)
        items.forEach { item -> HardeningRow(item, securityPatch, onOpen) }
    }
}

@Composable
private fun HardeningRow(item: HardeningItem, securityPatch: String?, onOpen: (HardeningStep) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(hardeningRowTag(item.step)),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            stringResource(stepTitle(item.step)),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.asHeading(),
        )
        Text(stringResource(statusText(item.status)), style = MaterialTheme.typography.labelLarge)
        if (item.step == HardeningStep.SECURITY_UPDATE && securityPatch != null) {
            Text(
                stringResource(R.string.hardening_security_patch, isolate(securityPatch)),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Text(stringResource(stepText(item.step)), style = MaterialTheme.typography.bodySmall)
        if (item.status != HardeningStatus.NOT_AVAILABLE) {
            OutlinedButton(onClick = { onOpen(item.step) }) { Text(stringResource(R.string.hardening_open_settings)) }
        }
    }
}

fun stepTitle(step: HardeningStep): Int = when (step) {
    HardeningStep.ADVANCED_PROTECTION -> R.string.hardening_advanced_protection_title
    HardeningStep.SECURITY_UPDATE -> R.string.hardening_security_update_title
    HardeningStep.SCREEN_LOCK -> R.string.hardening_screen_lock_title
    HardeningStep.USB_DEBUGGING -> R.string.hardening_usb_debugging_title
    HardeningStep.UNKNOWN_APPS -> R.string.hardening_unknown_apps_title
    HardeningStep.MESSAGING_APPS -> R.string.hardening_messaging_apps_title
}

fun stepText(step: HardeningStep): Int = when (step) {
    HardeningStep.ADVANCED_PROTECTION -> R.string.hardening_advanced_protection_text
    HardeningStep.SECURITY_UPDATE -> R.string.hardening_security_update_text
    HardeningStep.SCREEN_LOCK -> R.string.hardening_screen_lock_text
    HardeningStep.USB_DEBUGGING -> R.string.hardening_usb_debugging_text
    HardeningStep.UNKNOWN_APPS -> R.string.hardening_unknown_apps_text
    HardeningStep.MESSAGING_APPS -> R.string.hardening_messaging_apps_text
}

fun statusText(status: HardeningStatus): Int = when (status) {
    HardeningStatus.DONE -> R.string.hardening_status_done
    HardeningStatus.TO_DO -> R.string.hardening_status_to_do
    HardeningStatus.CHECK_YOURSELF -> R.string.hardening_status_check
    HardeningStatus.NOT_AVAILABLE -> R.string.hardening_status_not_available
}
