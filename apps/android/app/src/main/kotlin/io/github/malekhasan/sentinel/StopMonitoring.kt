// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource

/**
 * Where the monitoring notification's Stop leads: a question, so that monitoring stops
 * only when the person holding the unlocked phone says so (THREAT-MODEL-A E6, audit
 * finding A-02).
 *
 * An app with notification access can fire a notification's actions itself, without a
 * tap and without unlocking. Were Stop to reach the service, such an app could turn
 * monitoring off unseen, and a stop the user asked for leaves no gap. Firing it now only
 * asks. Not exported: no other app can open this but through the notification.
 */
class StopMonitoringActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SentinelTheme {
                StopMonitoringQuestion(
                    onStop = {
                        startService(
                            Intent(this, SentinelVpnService::class.java)
                                .setAction(SentinelVpnService.ACTION_STOP),
                        )
                        finish()
                    },
                    onKeep = ::finish,
                )
            }
        }
    }
}

/** Whether to stop monitoring: Stop, or keep it running. */
@Composable
fun StopMonitoringQuestion(onStop: () -> Unit, onKeep: () -> Unit) {
    AlertDialog(
        onDismissRequest = onKeep,
        title = { Text(stringResource(R.string.stop_title)) },
        text = { Text(stringResource(R.string.stop_text)) },
        confirmButton = {
            TextButton(onClick = onStop) { Text(stringResource(R.string.action_stop)) }
        },
        dismissButton = {
            TextButton(onClick = onKeep) { Text(stringResource(R.string.stop_keep)) }
        },
    )
}
