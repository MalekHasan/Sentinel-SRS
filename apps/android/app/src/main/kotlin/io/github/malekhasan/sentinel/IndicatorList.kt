// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.icu.text.ListFormatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.FeedStatus
import io.github.malekhasan.sentinel.core.KnownTraces
import java.text.DateFormat
import java.util.Date

/**
 * The indicator list on the main screen (SRS MS-10, ADR-0019): which list is in force,
 * from when and from whom, whether it is out of date, what the last check found, and how
 * to get a new one. Then the result (MS-15, ADR-0022): known traces found or not, with
 * the list's date, and what a "not found" cannot say.
 */
@Composable
fun IndicatorList(
    state: IndicatorFeed.State,
    onCheck: () -> Unit,
    onImport: () -> Unit,
    traces: KnownTraces? = null,
) {
    val locale = LocalConfiguration.current.locales[0]
    val format = DateFormat.getDateInstance(DateFormat.MEDIUM, locale)
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(R.string.feed_title), style = MaterialTheme.typography.titleMedium)
        val status = state.status
        when {
            !state.available -> Text(stringResource(R.string.feed_no_keys), style = MaterialTheme.typography.bodyMedium)
            status == null -> Text(stringResource(R.string.feed_none), style = MaterialTheme.typography.bodyMedium)
            else -> {
                Text(
                    stringResource(
                        R.string.feed_installed,
                        format.format(Date(status.createdMs)),
                        status.version.toString(),
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
                val count = status.indicators.toInt()
                Text(
                    pluralStringResource(
                        R.plurals.feed_indicators,
                        count,
                        count,
                        ListFormatter.getInstance(locale).format(status.sources.map { isolate(it.name) }),
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (System.currentTimeMillis() >= status.expiresMs) {
                    Text(
                        stringResource(R.string.feed_expired, format.format(Date(status.expiresMs))),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                traces?.let { TraceResult(status, it, format) }
            }
        }
        state.last?.let { Text(stringResource(outcomeText(it)), style = MaterialTheme.typography.bodySmall) }
        if (state.available) {
            if (state.busy) {
                Text(stringResource(R.string.feed_checking), style = MaterialTheme.typography.bodySmall)
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onCheck) { Text(stringResource(R.string.feed_check)) }
                    OutlinedButton(onClick = onImport) { Text(stringResource(R.string.feed_import)) }
                }
            }
            Text(stringResource(R.string.feed_explainer), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * MS-15: "Known traces found" whenever an alert named one, open or dismissed, else "No
 * known traces found" once the history was checked against the list in force, with the
 * list's date and the limits of such a result (SRS §8A.3).
 */
@Composable
private fun TraceResult(status: FeedStatus, traces: KnownTraces, format: DateFormat) {
    val listDate = format.format(Date(status.createdMs))
    when {
        traces.alerts > 0uL -> {
            Text(
                stringResource(R.string.feed_result_found),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.error,
            )
            val count = traces.alerts.toInt()
            Text(
                pluralStringResource(R.plurals.feed_result_found_text, count, count, listDate),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        traces.checkedVersion == status.version -> {
            Text(stringResource(R.string.feed_result_none), style = MaterialTheme.typography.titleSmall)
            Text(
                stringResource(R.string.feed_result_none_text, format.format(Date(traces.sinceMs)), listDate),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(stringResource(R.string.feed_result_limits), style = MaterialTheme.typography.bodySmall)
        }
        else -> Text(stringResource(R.string.feed_result_pending), style = MaterialTheme.typography.bodyMedium)
    }
}

/** What the last check or update found, in one sentence. */
fun outcomeText(outcome: IndicatorFeed.Outcome): Int = when (outcome) {
    IndicatorFeed.Outcome.INSTALLED -> R.string.feed_outcome_installed
    IndicatorFeed.Outcome.UP_TO_DATE -> R.string.feed_outcome_up_to_date
    IndicatorFeed.Outcome.REFUSED -> R.string.feed_outcome_refused
    IndicatorFeed.Outcome.NOT_FOUND -> R.string.feed_outcome_not_found
    IndicatorFeed.Outcome.INCOMPLETE -> R.string.feed_outcome_incomplete
    IndicatorFeed.Outcome.UNREACHABLE -> R.string.feed_outcome_unreachable
    IndicatorFeed.Outcome.FAILED -> R.string.feed_outcome_failed
    IndicatorFeed.Outcome.REMOVED -> R.string.feed_outcome_removed
}
