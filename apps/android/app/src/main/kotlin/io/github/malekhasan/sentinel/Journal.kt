// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.widget.Toast
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
import io.github.malekhasan.sentinel.core.FirewallMode
import io.github.malekhasan.sentinel.core.FirewallRule
import io.github.malekhasan.sentinel.core.JournalEntry
import io.github.malekhasan.sentinel.core.JournalState
import io.github.malekhasan.sentinel.core.RuleAction
import io.github.malekhasan.sentinel.core.RuleDestination
import io.github.malekhasan.sentinel.core.UndoResult
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Test tag of the journal's list. */
const val JOURNAL_LIST_TAG = "journal"

/** Test tag of one action's row in the journal. */
fun journalRowTag(id: Long): String = "journal-$id"

/** Actions listed, newest first. */
private const val JOURNAL_SHOWN = 100u

/** An action from the journal, with the name the user knows its rule's app by. */
data class JournalRow(val entry: JournalEntry, val appLabel: String?)

/** What the user changed in the firewall, newest first, each with Undo (SRS §9, ADR-0018). */
@Composable
fun JournalScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val names = remember(context) { AppNames(context) }
    val scope = rememberCoroutineScope()
    var rows by remember { mutableStateOf(emptyList<JournalRow>()) }
    // Bumped after an undo so the list reloads.
    var generation by remember { mutableIntStateOf(0) }

    LaunchedEffect(generation) {
        rows = withContext(Dispatchers.IO) {
            journal(context, JOURNAL_SHOWN).map { entry ->
                JournalRow(entry, ruleOf(entry)?.app?.let(names::labelFor))
            }
        }
    }
    Journal(rows, onBack, onUndo = { id ->
        scope.launch {
            val result = withContext(Dispatchers.IO) { undoAction(context, id) }
            val said = when (result) {
                UndoResult.UNDONE -> R.string.journal_undo_done
                UndoResult.CHANGED_SINCE -> R.string.journal_changed_since
                else -> R.string.journal_cannot_undo
            }
            Toast.makeText(context, context.getString(said), Toast.LENGTH_LONG).show()
            generation++
        }
    })
}

@Composable
fun Journal(rows: List<JournalRow>, onBack: () -> Unit, onUndo: (Long) -> Unit) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .testTag(JOURNAL_LIST_TAG),
        contentPadding = PaddingValues(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
        }
        item {
            Text(stringResource(R.string.journal_title), style = MaterialTheme.typography.headlineSmall)
        }
        item {
            val explanation = if (rows.isEmpty()) R.string.journal_empty else R.string.journal_explainer
            Text(stringResource(explanation), style = MaterialTheme.typography.bodyMedium)
        }
        items(rows, key = { it.entry.id }) { row -> JournalRowView(row, onUndo) }
    }
}

@Composable
private fun JournalRowView(row: JournalRow, onUndo: (Long) -> Unit) {
    val entry = row.entry
    val format = DateFormat.getDateTimeInstance(
        DateFormat.SHORT, DateFormat.SHORT, LocalConfiguration.current.locales[0],
    )
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(journalRowTag(entry.id)),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(describeAction(row), style = MaterialTheme.typography.titleSmall)
        Text(format.format(Date(entry.atMs)), style = MaterialTheme.typography.bodySmall)
        if (entry.alertId != null) {
            Text(stringResource(R.string.journal_from_alert), style = MaterialTheme.typography.bodySmall)
        }
        val undone = entry.undoneMs
        when {
            undone != null -> Text(
                stringResource(R.string.journal_undone, format.format(Date(undone))),
                style = MaterialTheme.typography.bodySmall,
            )
            entry.canUndo -> OutlinedButton(onClick = { onUndo(entry.id) }) {
                Text(stringResource(R.string.journal_undo))
            }
        }
    }
}

/** What an action did, in one sentence. */
@Composable
fun describeAction(row: JournalRow): String {
    val entry = row.entry
    return when (val after = entry.after) {
        is JournalState.Rule -> {
            val kept = after.rule
            if (kept != null) {
                describeRule(kept, row.appLabel)
            } else {
                val removed = (entry.before as? JournalState.Rule)?.rule
                stringResource(
                    R.string.journal_rule_removed,
                    removed?.let { describeRule(it, row.appLabel) } ?: isolate(after.key),
                )
            }
        }
        is JournalState.Mode -> stringResource(
            R.string.journal_mode,
            stringResource(
                when (after.mode) {
                    FirewallMode.MONITOR -> R.string.firewall_mode_monitor
                    FirewallMode.BLOCK_UNKNOWN -> R.string.firewall_mode_block_unknown
                },
            ),
        )
        is JournalState.Isolation -> stringResource(
            if (after.sinceMs != null) R.string.journal_isolated else R.string.journal_isolation_ended,
        )
    }
}

@Composable
private fun describeRule(rule: FirewallRule, appLabel: String?): String {
    val app = rule.app?.let { isolate(appLabel ?: it) }
    val place = when (val destination = rule.destination) {
        null -> null
        is RuleDestination.Domain -> isolate(destination.name)
        is RuleDestination.Network -> isolate(destination.range)
        is RuleDestination.Company -> stringResource(R.string.journal_company, isolate(destination.name))
    }
    val block = rule.action == RuleAction.BLOCK
    return when {
        place == null -> stringResource(
            if (block) R.string.journal_block_app else R.string.journal_allow_app, app.orEmpty(),
        )
        app == null -> stringResource(
            if (block) R.string.journal_block_everywhere else R.string.journal_allow_everywhere, place,
        )
        else -> stringResource(
            if (block) R.string.journal_block_for_app else R.string.journal_allow_for_app, place, app,
        )
    }
}

/** The rule an action kept or removed, if it was about a rule. */
private fun ruleOf(entry: JournalEntry): FirewallRule? =
    (entry.after as? JournalState.Rule)?.rule ?: (entry.before as? JournalState.Rule)?.rule
