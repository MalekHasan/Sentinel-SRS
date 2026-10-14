// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.text.format.DateUtils
import android.text.format.Formatter
import android.util.Log
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
import io.github.malekhasan.sentinel.core.HistoryApp
import io.github.malekhasan.sentinel.core.HistoryDestination
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private const val TAG = "SentinelAppDetail"

/** Destinations listed; the screen says how many more there are. */
private const val DESTINATIONS_SHOWN = 100u

/** How often the screen reloads while monitoring adds to the history. */
private const val REFRESH_MILLIS = 1_000L

/** Test tag of the app detail list. */
const val APP_DETAIL_TAG = "app-detail"

/** What the app detail screen shows about one app. */
data class AppDetails(
    val label: String,
    /** Null when the history has nothing about the app. */
    val history: HistoryApp?,
    /** Its connections open right now. */
    val openFlows: Int,
)

/** One app's destinations, data sent and when it was first seen (SRS §12.2). */
@Composable
fun AppDetailScreen(app: String, visible: Boolean, onBack: () -> Unit) {
    val context = LocalContext.current
    val names = remember(context) { AppNames(context) }
    val status by Monitor.status.collectAsState()
    var details by remember(app) { mutableStateOf<AppDetails?>(null) }

    LaunchedEffect(app, visible, status) {
        suspend fun load() = withContext(Dispatchers.IO) {
            AppDetails(
                label = names.labelFor(app),
                history = appSummary(context, app),
                openFlows = Monitor.liveApps().filter { it.app == app }.sumOf { it.openFlows.toInt() },
            )
        }
        details = load()
        // Only while on screen and monitoring adds to the history.
        while (visible && status == Monitor.Status.ON) {
            delay(REFRESH_MILLIS)
            details = load()
        }
    }
    AppDetail(app, details, onBack)
}

private fun appSummary(context: Context, app: String): HistoryApp? =
    try {
        History.get(context).appSummary(app, DESTINATIONS_SHOWN)
    } catch (e: Exception) {
        Log.w(TAG, "the history cannot be read", e)
        null
    }

@Composable
fun AppDetail(app: String, details: AppDetails?, onBack: () -> Unit) {
    val context = LocalContext.current
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .testTag(APP_DETAIL_TAG),
        contentPadding = PaddingValues(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(details?.label ?: app, style = MaterialTheme.typography.headlineSmall)
                if (details != null && details.label != app) {
                    Text(app, style = MaterialTheme.typography.labelMedium)
                }
            }
        }
        if (details == null) return@LazyColumn
        if (details.openFlows > 0) {
            item {
                Text(
                    pluralStringResource(R.plurals.live_open_flows, details.openFlows, details.openFlows),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        val history = details.history
        if (history == null) {
            item {
                Text(stringResource(R.string.app_detail_nothing), style = MaterialTheme.typography.bodyMedium)
            }
            return@LazyColumn
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                val format = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                Text(
                    stringResource(R.string.app_detail_first_seen, format.format(Date(history.firstSeenMs))),
                    style = MaterialTheme.typography.bodyMedium,
                )
                val flows = history.flows.toInt()
                Text(
                    pluralStringResource(R.plurals.history_connections, flows, flows),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(
                        R.string.traffic,
                        Formatter.formatShortFileSize(context, history.bytesUp),
                        Formatter.formatShortFileSize(context, history.bytesDown),
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(
                        R.string.app_detail_away,
                        Formatter.formatShortFileSize(context, history.bytesUpAway),
                        Formatter.formatShortFileSize(context, history.bytesDownAway),
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(stringResource(R.string.app_detail_open_note), style = MaterialTheme.typography.bodySmall)
            }
        }
        item {
            Text(stringResource(R.string.app_detail_destinations_title), style = MaterialTheme.typography.titleSmall)
        }
        items(history.destinations, key = { it.destination }) { DestinationRow(it) }
        val total = history.destinationCount.toInt()
        if (total > history.destinations.size) {
            item {
                Text(
                    stringResource(R.string.app_detail_destinations_shown, history.destinations.size, total),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun DestinationRow(destination: HistoryDestination) {
    val context = LocalContext.current
    val flows = destination.flows.toInt()
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(destination.destination, style = MaterialTheme.typography.titleSmall)
        Text(
            pluralStringResource(R.plurals.connections, flows, flows),
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            stringResource(
                R.string.traffic,
                Formatter.formatShortFileSize(context, destination.bytesUp),
                Formatter.formatShortFileSize(context, destination.bytesDown),
            ),
            style = MaterialTheme.typography.bodySmall,
        )
        if (destination.bytesUpAway + destination.bytesDownAway > 0) {
            Text(
                stringResource(
                    R.string.app_detail_away,
                    Formatter.formatShortFileSize(context, destination.bytesUpAway),
                    Formatter.formatShortFileSize(context, destination.bytesDownAway),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        val lastSeen = DateUtils.getRelativeTimeSpanString(
            destination.lastSeenMs, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS,
        )
        Text(
            stringResource(R.string.app_detail_last_seen, lastSeen.toString()),
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
