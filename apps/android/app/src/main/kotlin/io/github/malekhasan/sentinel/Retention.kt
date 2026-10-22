// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

private const val TAG = "SentinelRetention"

/** The choices offered for how long flows are kept, in days; the history takes 1 to 365. */
val KEEP_FLOWS_CHOICES = listOf(1u, 7u, 30u, 90u, 365u)

/** How many days flows are kept before they are rolled up (SRS §13.2), or null if the history cannot be read. */
fun flowKeepDays(context: Context): UInt? =
    try {
        History.get(context).flowKeepDays()
    } catch (e: Exception) {
        Log.w(TAG, "how long flows are kept cannot be read", e)
        null
    }

/**
 * Keeps flows [days] days from now on, and applies the retention periods at once, so
 * that a shorter choice takes effect now (SRS §13.2, ADR-0039). Returns whether it was
 * kept. Call off the main thread.
 */
fun setFlowKeepDays(context: Context, days: UInt): Boolean =
    try {
        val history = History.get(context)
        history.setFlowKeepDays(days).also { kept ->
            if (kept) history.applyRetention(System.currentTimeMillis())
        }
    } catch (e: Exception) {
        Log.w(TAG, "how long flows are kept cannot be set", e)
        false
    }

/**
 * How long flows are kept, as a choice, and how long the rest of the history is. A
 * shorter time turns older flows into daily totals at once, for good, so it is asked
 * first; a tap while scrolling must not cost the user their history.
 */
@Composable
fun KeepFlowsChoice(days: UInt?, onDays: (UInt) -> Unit) {
    var shorter by remember { mutableStateOf<UInt?>(null) }
    shorter?.let { chosen ->
        ShorterKeepQuestion(
            chosen,
            onChange = {
                shorter = null
                onDays(chosen)
            },
            onCancel = { shorter = null },
        )
    }
    Text(
        stringResource(R.string.retention_title),
        style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.asHeading(),
    )
    Column(Modifier.selectableGroup(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        KEEP_FLOWS_CHOICES.forEach { option ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .selectable(
                        selected = option == days,
                        enabled = days != null,
                        role = Role.RadioButton,
                        onClick = {
                            if (days != null && option < days) {
                                shorter = option
                            } else if (option != days) {
                                onDays(option)
                            }
                        },
                    )
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = option == days, onClick = null, enabled = days != null)
                Text(
                    keepDays(option),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(start = 12.dp),
                )
            }
        }
    }
    Text(stringResource(R.string.retention_text), style = MaterialTheme.typography.bodySmall)
}

/** Whether to keep flows a shorter time, [days], which turns older ones into daily totals now. */
@Composable
fun ShorterKeepQuestion(days: UInt, onChange: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.retention_shorter_title, keepDays(days))) },
        text = { Text(stringResource(R.string.retention_shorter_text)) },
        confirmButton = {
            TextButton(onClick = onChange) { Text(stringResource(R.string.retention_shorter_change)) }
        },
        dismissButton = {
            TextButton(onClick = onCancel) { Text(stringResource(R.string.retention_shorter_cancel)) }
        },
    )
}

@Composable
private fun keepDays(days: UInt): String = pluralStringResource(R.plurals.retention_days, days.toInt(), days.toInt())
