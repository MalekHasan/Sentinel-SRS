// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.SensorKind
import io.github.malekhasan.sentinel.core.SensorUse
import java.text.DateFormat
import java.util.Date

/** Test tag of the main screen's microphone and camera section. */
const val SENSORS_TAG = "sensors"

/** Sensor uses shown on the main screen. */
private const val SENSORS_SHOWN = 5u

private const val TAG = "SentinelSensors"

/** The most recent microphone and camera uses, newest first, or none if the history cannot be read. */
fun recentSensorUses(context: Context): List<SensorUse> =
    try {
        History.get(context).recentSensorUses(SENSORS_SHOWN)
    } catch (e: Exception) {
        Log.w(TAG, "the sensor uses cannot be read", e)
        emptyList()
    }

/**
 * The main screen's record of microphone and camera use (SE-01 basic): each use with its
 * times, whether the screen was off or locked, and the app on screen as a guess, labelled
 * as one. Without usage access, it offers it ([onUsageAccess]).
 */
@Composable
fun SensorUses(
    uses: List<SensorUse>,
    usageAccess: Boolean,
    labelFor: (String) -> String,
    onUsageAccess: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SENSORS_TAG),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            stringResource(R.string.sensors_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.asHeading(),
        )
        if (uses.isEmpty()) {
            Text(stringResource(R.string.sensors_empty), style = MaterialTheme.typography.bodySmall)
        }
        uses.forEach { SensorUseRow(it, labelFor) }
        if (!usageAccess) {
            Text(stringResource(R.string.sensors_usage_access), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = onUsageAccess) { Text(stringResource(R.string.sensors_usage_access_action)) }
        }
    }
}

@Composable
private fun SensorUseRow(use: SensorUse, labelFor: (String) -> String) {
    val locale = LocalConfiguration.current.locales[0]
    val format = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, locale)
    val time = DateFormat.getTimeInstance(DateFormat.SHORT, locale)
    val sensor = stringResource(sensorName(use.sensor))
    val ended = use.endedMs
    Text(
        if (ended == null) {
            stringResource(R.string.sensor_use_open, sensor, format.format(Date(use.startedMs)))
        } else {
            stringResource(
                R.string.sensor_use_closed, sensor, format.format(Date(use.startedMs)), time.format(Date(ended)),
            )
        },
        style = MaterialTheme.typography.bodyMedium,
    )
    val guess = use.guess
    Text(
        if (guess == null) {
            stringResource(R.string.sensor_use_no_guess)
        } else {
            stringResource(R.string.sensor_use_guess, isolate(labelFor(guess)))
        },
        style = MaterialTheme.typography.bodySmall,
    )
    if (!use.userPresent) {
        Text(stringResource(R.string.sensor_use_away), style = MaterialTheme.typography.bodySmall)
    }
}

fun sensorName(sensor: SensorKind): Int = when (sensor) {
    SensorKind.MICROPHONE -> R.string.sensor_microphone
    SensorKind.CAMERA -> R.string.sensor_camera
}
