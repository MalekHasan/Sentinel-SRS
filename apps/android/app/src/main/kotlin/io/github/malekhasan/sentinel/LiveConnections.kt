// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.icu.text.ListFormatter
import android.os.SystemClock
import android.text.format.Formatter
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.LiveApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/** An app's open connections, with the name the user knows the app by. */
data class LiveRow(val app: LiveApp, val label: String?)

/** How often the live view refreshes while it is on screen (CM-03: at least every 1 s). */
private const val REFRESH_MILLIS = 1_000L

/** Test tag of the live view's list. */
const val LIVE_LIST_TAG = "live-connections"

/** Stable across refreshes, so rows keep their place while the order changes. */
fun liveRowKey(app: LiveApp): String = "${app.uid}:${app.app}"

/** Open connections grouped by app, busiest first (SRS CM-03). */
@Composable
fun LiveConnectionsScreen(visible: Boolean, onBack: () -> Unit, onOpenApp: (String) -> Unit) {
    val context = LocalContext.current
    val names = remember(context) { AppNames(context) }
    val status by Monitor.status.collectAsState()
    var rows by remember { mutableStateOf(emptyList<LiveRow>()) }

    LaunchedEffect(visible, status) {
        if (status != Monitor.Status.ON) rows = emptyList()
        // Only while on screen: nothing asks the engine when no one is looking.
        while (visible && status == Monitor.Status.ON) {
            val started = SystemClock.uptimeMillis()
            rows = withContext(Dispatchers.IO) {
                Monitor.liveApps().map { LiveRow(it, it.app?.let(names::labelFor)) }
            }
            delay(REFRESH_MILLIS - (SystemClock.uptimeMillis() - started))
        }
    }
    LiveConnections(status, rows, onBack, onOpenApp)
}

@Composable
fun LiveConnections(
    status: Monitor.Status,
    rows: List<LiveRow>,
    onBack: () -> Unit,
    onOpenApp: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .testTag(LIVE_LIST_TAG),
        contentPadding = PaddingValues(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
        }
        item {
            Text(stringResource(R.string.live_title), style = MaterialTheme.typography.headlineSmall)
        }
        item {
            val explanation = when {
                status != Monitor.Status.ON -> R.string.live_off
                rows.isEmpty() -> R.string.live_empty
                else -> R.string.live_explainer
            }
            Text(stringResource(explanation), style = MaterialTheme.typography.bodyMedium)
        }
        items(rows, key = { liveRowKey(it.app) }) { row -> LiveAppRow(row, onOpenApp) }
    }
}

@Composable
private fun LiveAppRow(row: LiveRow, onOpenApp: (String) -> Unit) {
    val context = LocalContext.current
    val app = row.app
    val packageName = app.app
    Column(
        modifier = Modifier
            .fillMaxWidth()
            // Connections whose owner is unknown have no app to open.
            .clickable(enabled = packageName != null) { packageName?.let(onOpenApp) },
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            row.label ?: stringResource(R.string.unknown_app),
            style = MaterialTheme.typography.titleSmall,
        )
        if (packageName != null && packageName != row.label) {
            Text(packageName, style = MaterialTheme.typography.labelSmall)
        }
        val open = app.openFlows.toInt()
        Text(
            pluralStringResource(R.plurals.live_open_flows, open, open),
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            stringResource(
                R.string.live_traffic,
                Formatter.formatShortFileSize(context, app.bytesUp.toLong()),
                Formatter.formatShortFileSize(context, app.bytesDown.toLong()),
            ),
            style = MaterialTheme.typography.bodySmall,
        )
        if (app.topDestinations.isNotEmpty()) {
            Text(
                stringResource(
                    R.string.live_destinations,
                    ListFormatter.getInstance().format(app.topDestinations),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
