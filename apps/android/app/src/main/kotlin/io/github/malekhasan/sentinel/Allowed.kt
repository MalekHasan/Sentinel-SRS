// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AllowedRule
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "SentinelAllowed"

/** Test tag of the list of what the user allowed. */
const val ALLOWED_LIST_TAG = "allowed"

/** What the user allowed (AL-05), newest first; empty if the history cannot be read. */
fun allowedAlerts(context: Context): List<AllowedRule> =
    try {
        History.get(context).allowed()
    } catch (e: Exception) {
        Log.w(TAG, "what was allowed cannot be read", e)
        emptyList()
    }

/** Takes back what the user allowed for [app] and [rule]. Returns whether it was allowed. */
fun takeBackAllowed(context: Context, rule: AlertRule, app: String): Boolean =
    try {
        History.get(context).takeBackAllowed(rule, app)
    } catch (e: Exception) {
        Log.w(TAG, "what was allowed cannot be taken back", e)
        false
    }

/** A rule the user allowed for an app, with the name the user knows the app by. */
data class AllowedRow(val allowed: AllowedRule, val appLabel: String)

/**
 * Every alert the user allowed: one kind of alert about one app each, newest first, each
 * with Take back (AL-05, audit A-08). Allowing is for good, so it must not stay hidden.
 */
@Composable
fun AllowedScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val names = remember(context) { AppNames(context) }
    val scope = rememberCoroutineScope()
    var rows by remember { mutableStateOf(emptyList<AllowedRow>()) }
    // The app whose alerts the last Take back brought back.
    var takenBack by remember { mutableStateOf<String?>(null) }
    // Bumped after a Take back so the list reloads.
    var generation by remember { mutableIntStateOf(0) }

    LaunchedEffect(generation) {
        rows = withContext(Dispatchers.IO) {
            allowedAlerts(context).map { AllowedRow(it, names.labelFor(it.app)) }
        }
    }
    AllowedList(rows, takenBack, onBack, onTakeBack = { row ->
        scope.launch {
            if (withContext(Dispatchers.IO) { takeBackAllowed(context, row.allowed.rule, row.allowed.app) }) {
                takenBack = row.appLabel
            }
            generation++
        }
    })
}

/** The list's content; [takenBack] is the app the last Take back was for, if any. */
@Composable
fun AllowedList(
    rows: List<AllowedRow>,
    takenBack: String? = null,
    onBack: () -> Unit,
    onTakeBack: (AllowedRow) -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .testTag(ALLOWED_LIST_TAG),
        contentPadding = PaddingValues(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
        }
        item {
            Text(
                stringResource(R.string.allowed_title),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.asHeading(),
            )
        }
        item {
            val explanation = if (rows.isEmpty()) R.string.allowed_empty else R.string.allowed_explainer
            Text(stringResource(explanation), style = MaterialTheme.typography.bodyMedium)
        }
        if (takenBack != null) {
            item {
                Text(
                    stringResource(R.string.allowed_taken_back, isolate(takenBack)),
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.announced(),
                )
            }
        }
        items(rows, key = { "${it.allowed.rule}/${it.allowed.app}" }) { row -> AllowedRowView(row, onTakeBack) }
    }
}

@Composable
private fun AllowedRowView(row: AllowedRow, onTakeBack: (AllowedRow) -> Unit) {
    val format = DateFormat.getDateTimeInstance(
        DateFormat.SHORT, DateFormat.SHORT, LocalConfiguration.current.locales[0],
    )
    Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(titleRes(row.allowed.rule)), style = MaterialTheme.typography.titleSmall)
        Text(row.appLabel, style = MaterialTheme.typography.bodyMedium)
        Text(
            stringResource(R.string.allowed_since, format.format(Date(row.allowed.createdMs))),
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedButton(onClick = { onTakeBack(row) }) { Text(stringResource(R.string.allowed_take_back)) }
    }
}
