// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.ActivityManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
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
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Test tag of one step's row. */
fun keepRunningRowTag(step: KeepRunning.Step): String = "keep-running-${step.name}"

/** Test tag of the phone maker's steps. */
const val KEEP_RUNNING_MAKER_TAG = "keep-running-maker"

/**
 * Keeping monitoring running (SP-03, ADR-0030). To save battery, Android stops apps it
 * takes to be idle, and some phone makers stop them far more often. While Sentinel is
 * stopped it sees nothing, and the time is a gap. These are the steps that keep it
 * running: Android's own, each with where it stands when Sentinel can read it, and the
 * phone maker's, which Sentinel cannot read.
 */
object KeepRunning {
    enum class Step {
        /** Not optimised for battery: Android's Doze leaves it alone. */
        BATTERY,

        /** Background use not restricted for Sentinel. */
        BACKGROUND,

        /** Always-on VPN: Android starts Sentinel at boot and again if it stops. */
        ALWAYS_ON,
    }

    /** Makers whose own battery settings stop background apps, and everyone else. */
    enum class Maker { SAMSUNG, XIAOMI, HUAWEI, ONEPLUS, OPPO, VIVO, GOOGLE, OTHER }

    /** A step and whether it is done; `null` when Sentinel cannot see it now. */
    data class Item(val step: Step, val done: Boolean?)

    /** The maker named [manufacturer] (`Build.MANUFACTURER`), with its other brands. */
    fun maker(manufacturer: String): Maker = when (manufacturer.trim().lowercase(Locale.ROOT)) {
        "samsung" -> Maker.SAMSUNG
        "xiaomi", "redmi", "poco" -> Maker.XIAOMI
        "huawei", "honor" -> Maker.HUAWEI
        "oneplus" -> Maker.ONEPLUS
        "oppo", "realme" -> Maker.OPPO
        "vivo", "iqoo" -> Maker.VIVO
        "google" -> Maker.GOOGLE
        else -> Maker.OTHER
    }

    /** Where each of Android's steps stands on this phone. */
    fun items(context: Context): List<Item> {
        val power = context.getSystemService(PowerManager::class.java)
        val activities = context.getSystemService(ActivityManager::class.java)
        return listOf(
            Item(Step.BATTERY, power?.isIgnoringBatteryOptimizations(context.packageName)),
            Item(Step.BACKGROUND, activities?.isBackgroundRestricted?.not()),
            // Only the running VPN service can ask.
            Item(Step.ALWAYS_ON, Monitor.alwaysOn),
        )
    }

    /** Android's settings for [step], else the nearest screen that opens. */
    fun openSettings(context: Context, step: Step) = open(
        context,
        when (step) {
            Step.BATTERY -> listOf(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS), appSettings(context))
            Step.BACKGROUND -> listOf(appSettings(context))
            Step.ALWAYS_ON -> listOf(Intent(Settings.ACTION_VPN_SETTINGS))
        },
    )

    /** Sentinel's own page in Android's settings, where makers put their battery settings. */
    fun openAppSettings(context: Context) = open(context, listOf(appSettings(context)))

    /** The first of [screens] that opens, in an app that came with the phone (audit A-40). */
    private fun open(context: Context, screens: List<Intent>) {
        for (screen in screens + Intent(Settings.ACTION_SETTINGS)) {
            try {
                context.startSystemScreen(screen)
                return
            } catch (e: ActivityNotFoundException) {
                // Try the next one.
            } catch (e: SecurityException) {
                // Try the next one.
            }
        }
    }

    private fun appSettings(context: Context) =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
}

/** The steps, read again whenever the screen is [visible] (the user may be back from the settings). */
@Composable
fun KeepRunningScreen(visible: Boolean, onBack: () -> Unit) {
    val context = LocalContext.current
    var items by remember { mutableStateOf(emptyList<KeepRunning.Item>()) }
    LaunchedEffect(visible) {
        if (visible) items = withContext(Dispatchers.IO) { KeepRunning.items(context) }
    }
    KeepRunningContent(
        items,
        maker = KeepRunning.maker(Build.MANUFACTURER),
        onBack = onBack,
        onOpen = { KeepRunning.openSettings(context, it) },
        onOpenAppSettings = { KeepRunning.openAppSettings(context) },
    )
}

/** The screen's content: Android's steps in [items], then [maker]'s. */
@Composable
fun KeepRunningContent(
    items: List<KeepRunning.Item>,
    maker: KeepRunning.Maker,
    onBack: () -> Unit,
    onOpen: (KeepRunning.Step) -> Unit,
    onOpenAppSettings: () -> Unit,
) {
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
            stringResource(R.string.keep_running_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.asHeading(),
        )
        Text(stringResource(R.string.keep_running_explainer), style = MaterialTheme.typography.bodyMedium)
        items.forEach { item -> KeepRunningRow(item, onOpen) }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .testTag(KEEP_RUNNING_MAKER_TAG),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                stringResource(R.string.keep_running_maker_title),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.asHeading(),
            )
            Text(stringResource(makerSteps(maker)), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.keep_running_maker_note), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = onOpenAppSettings) {
                Text(stringResource(R.string.keep_running_open_app_settings))
            }
        }
    }
}

@Composable
private fun KeepRunningRow(item: KeepRunning.Item, onOpen: (KeepRunning.Step) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(keepRunningRowTag(item.step)),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            stringResource(keepRunningTitle(item.step)),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.asHeading(),
        )
        val status = when (item.done) {
            true -> R.string.hardening_status_done
            false -> R.string.hardening_status_to_do
            null -> if (item.step == KeepRunning.Step.ALWAYS_ON) {
                R.string.keep_running_status_while_monitoring
            } else {
                R.string.hardening_status_check
            }
        }
        Text(stringResource(status), style = MaterialTheme.typography.labelLarge)
        Text(stringResource(keepRunningText(item.step)), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { onOpen(item.step) }) { Text(stringResource(R.string.hardening_open_settings)) }
    }
}

fun keepRunningTitle(step: KeepRunning.Step): Int = when (step) {
    KeepRunning.Step.BATTERY -> R.string.keep_running_battery_title
    KeepRunning.Step.BACKGROUND -> R.string.keep_running_background_title
    KeepRunning.Step.ALWAYS_ON -> R.string.keep_running_always_on_title
}

fun keepRunningText(step: KeepRunning.Step): Int = when (step) {
    KeepRunning.Step.BATTERY -> R.string.keep_running_battery_text
    KeepRunning.Step.BACKGROUND -> R.string.keep_running_background_text
    KeepRunning.Step.ALWAYS_ON -> R.string.keep_running_always_on_text
}

fun makerSteps(maker: KeepRunning.Maker): Int = when (maker) {
    KeepRunning.Maker.SAMSUNG -> R.string.keep_running_maker_samsung
    KeepRunning.Maker.XIAOMI -> R.string.keep_running_maker_xiaomi
    KeepRunning.Maker.HUAWEI -> R.string.keep_running_maker_huawei
    KeepRunning.Maker.ONEPLUS -> R.string.keep_running_maker_oneplus
    KeepRunning.Maker.OPPO -> R.string.keep_running_maker_oppo
    KeepRunning.Maker.VIVO -> R.string.keep_running_maker_vivo
    KeepRunning.Maker.GOOGLE -> R.string.keep_running_maker_google
    KeepRunning.Maker.OTHER -> R.string.keep_running_maker_other
}
