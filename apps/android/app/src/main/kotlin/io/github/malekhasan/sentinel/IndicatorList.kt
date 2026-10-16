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
import java.text.DateFormat
import java.util.Date

/**
 * The indicator list on the main screen (SRS MS-10, ADR-0019): which list is in force,
 * from when and from whom, whether it is out of date, what the last check found, and how
 * to get a new one.
 */
@Composable
fun IndicatorList(state: IndicatorFeed.State, onCheck: () -> Unit, onImport: () -> Unit) {
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
