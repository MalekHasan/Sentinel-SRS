// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.net.InetAddresses
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.AppAccess
import io.github.malekhasan.sentinel.core.FirewallMode
import io.github.malekhasan.sentinel.core.FirewallRule
import io.github.malekhasan.sentinel.core.HistoryRule
import io.github.malekhasan.sentinel.core.RuleAction
import io.github.malekhasan.sentinel.core.RuleDestination
import java.util.Locale

private const val TAG = "SentinelFirewall"

/** The firewall mode in force (CM-08), or null if the history cannot be read. */
fun firewallMode(context: Context): FirewallMode? =
    try {
        History.get(context).firewallMode()
    } catch (e: Exception) {
        Log.w(TAG, "the firewall mode cannot be read", e)
        null
    }

/**
 * Puts [mode] in force for connections from now on (CM-08, ADR-0016). Returns whether
 * it was kept. Call off the main thread.
 */
fun setFirewallMode(context: Context, mode: FirewallMode): Boolean =
    try {
        History.get(context).setFirewallMode(mode)
        true
    } catch (e: Exception) {
        Log.w(TAG, "the firewall mode cannot be set", e)
        false
    }

/**
 * Lets [app] use the internet: a firewall rule allowing the whole app, which also lets
 * a new app through Block-unknown (CM-08, CM-10). Returns whether it was kept. Call off
 * the main thread.
 */
fun allowApp(context: Context, app: String): Boolean =
    keepRule(context, FirewallRule(app, null, RuleAction.ALLOW))

/**
 * Stops [app] using the internet, its open connections included: a firewall rule
 * blocking the whole app (RA-01). Returns whether it was kept. Call off the main thread.
 */
fun blockApp(context: Context, app: String): Boolean =
    keepRule(context, FirewallRule(app, null, RuleAction.BLOCK))

/** Keeps [rule], replacing one about the same app and destination. Call off the main thread. */
fun keepRule(context: Context, rule: FirewallRule): Boolean =
    try {
        History.get(context).setFirewallRule(rule)
        true
    } catch (e: Exception) {
        Log.w(TAG, "the rule cannot be kept", e)
        false
    }

/** Removes the rule with [key]. Call off the main thread. */
fun removeRule(context: Context, key: String): Boolean =
    try {
        History.get(context).removeFirewallRule(key)
    } catch (e: Exception) {
        Log.w(TAG, "the rule cannot be removed", e)
        false
    }

/** When isolation began (RA-03), or null if the phone is not isolated or the history cannot be read. */
fun isolatedSince(context: Context): Long? =
    try {
        History.get(context).isolatedSinceMs()
    } catch (e: Exception) {
        Log.w(TAG, "isolation cannot be read", e)
        null
    }

/**
 * Isolates the phone (RA-03): only DNS, Sentinel itself and the apps a rule allows as a
 * whole keep the internet, open connections included. Returns whether it took. Call off
 * the main thread.
 */
fun isolatePhone(context: Context): Boolean =
    try {
        History.get(context).isolate(context.packageName)
        true
    } catch (e: Exception) {
        Log.w(TAG, "the phone cannot be isolated", e)
        false
    }

/** Ends isolation. Returns whether it took. Call off the main thread. */
fun endIsolation(context: Context): Boolean =
    try {
        History.get(context).endIsolation()
        true
    } catch (e: Exception) {
        Log.w(TAG, "isolation cannot be ended", e)
        false
    }

/** Whether [app] may use the network as a whole, or null if the history cannot be read. */
fun appAccess(context: Context, app: String, installedMs: Long?): AppAccess? =
    try {
        History.get(context).appAccess(app, installedMs)
    } catch (e: Exception) {
        Log.w(TAG, "the app's access cannot be read", e)
        null
    }

/** The firewall rules in force, newest first, or none if the history cannot be read. */
fun firewallRules(context: Context): List<HistoryRule> =
    try {
        History.get(context).firewallRules()
    } catch (e: Exception) {
        Log.w(TAG, "the rules cannot be read", e)
        emptyList()
    }

/** The rule destination for one of the app detail screen's destinations: a name or an address. */
fun destinationOf(destination: String): RuleDestination =
    if (InetAddresses.isNumericAddress(destination)) {
        RuleDestination.Network(destination)
    } else {
        RuleDestination.Domain(destination.lowercase(Locale.ROOT).trimEnd('.'))
    }

/** The firewall's modes, each with what it does, as a choice of one (CM-08). */
@Composable
fun FirewallModeChoice(mode: FirewallMode?, onMode: (FirewallMode) -> Unit) {
    Text(stringResource(R.string.firewall_title), style = MaterialTheme.typography.titleSmall)
    Column(Modifier.selectableGroup(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        FirewallMode.entries.forEach { option ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .selectable(
                        selected = option == mode,
                        enabled = mode != null,
                        role = Role.RadioButton,
                        onClick = { onMode(option) },
                    )
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = option == mode, onClick = null, enabled = mode != null)
                Column(Modifier.padding(start = 12.dp)) {
                    Text(stringResource(modeName(option)), style = MaterialTheme.typography.bodyLarge)
                    Text(stringResource(modeText(option)), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

private fun modeName(mode: FirewallMode): Int = when (mode) {
    FirewallMode.MONITOR -> R.string.firewall_mode_monitor
    FirewallMode.BLOCK_UNKNOWN -> R.string.firewall_mode_block_unknown
}

private fun modeText(mode: FirewallMode): Int = when (mode) {
    FirewallMode.MONITOR -> R.string.firewall_mode_monitor_text
    FirewallMode.BLOCK_UNKNOWN -> R.string.firewall_mode_block_unknown_text
}
