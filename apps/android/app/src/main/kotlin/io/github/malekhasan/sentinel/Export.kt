// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.text.format.Formatter
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.ExportFormat
import io.github.malekhasan.sentinel.core.ExportKind
import io.github.malekhasan.sentinel.core.HistoryStore
import java.io.OutputStream
import java.time.LocalDate
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Export of the history to a file the user chooses (SRS §12.3, ADR-0033). Only ever at
 * the user's request, after a warning that the file holds sensitive data (SRS §15.2).
 * The file goes where the user picks in Android's document picker, so Sentinel needs no
 * storage permission, and it is written a page at a time straight into that document:
 * no whole export is held in memory, and Sentinel keeps no plain-text copy.
 */
object HistoryExport {
    private const val TAG = "SentinelExport"

    /** Records asked of the core at a time. */
    private const val PAGE = 500u

    /** How far back an export reaches. */
    enum class Range(val millis: Long?) {
        DAY(24 * 60 * 60 * 1000L),
        WEEK(7 * 24 * 60 * 60 * 1000L),

        /** Everything the history keeps: connections in full for 30 days (SRS §13.2). */
        ALL(null),
    }

    data class Choice(val kind: ExportKind, val format: ExportFormat, val range: Range)

    sealed interface State {
        data object Idle : State
        data object Saving : State
        data class Saved(val bytes: Long) : State
        data object Failed : State
    }

    private val current = MutableStateFlow<State>(State.Idle)

    /** Where the last export stands. */
    val states: StateFlow<State> = current.asStateFlow()

    fun mimeType(format: ExportFormat): String = when (format) {
        ExportFormat.JSON -> "application/json"
        ExportFormat.CSV -> "text/csv"
    }

    /** The name the picker suggests: `sentinel-connections-2026-10-20.csv`. */
    fun fileName(choice: Choice, today: LocalDate): String {
        val kind = when (choice.kind) {
            ExportKind.FLOWS -> "connections"
            ExportKind.ALERTS -> "alerts"
            ExportKind.ACTIONS -> "actions"
        }
        val extension = when (choice.format) {
            ExportFormat.JSON -> "json"
            ExportFormat.CSV -> "csv"
        }
        return "sentinel-$kind-$today.$extension"
    }

    /**
     * Writes [choice] into the document at [uri], which the user just created, on a
     * thread of its own; [states] follows it. A document left unfinished is deleted.
     */
    fun save(context: Context, uri: Uri, choice: Choice) {
        val app = context.applicationContext
        current.value = State.Saving
        Thread({
            current.value = try {
                val document = checkNotNull(app.contentResolver.openOutputStream(uri, "w")) { "no document" }
                val bytes = document.use { out ->
                    write(History.get(app), out.buffered(), choice, System.currentTimeMillis())
                }
                State.Saved(bytes)
            } catch (e: Exception) {
                // HistoryException, IOException, or the document is gone.
                Log.w(TAG, "the export could not be written", e)
                runCatching { DocumentsContract.deleteDocument(app.contentResolver, uri) }
                State.Failed
            }
        }, "sentinel-export").start()
    }

    /**
     * Writes [choice] as of [nowMs] to [out], [pageSize] records at a time, and returns
     * the bytes written. The pages, in order, are one document (ADR-0033).
     */
    fun write(
        history: HistoryStore,
        out: OutputStream,
        choice: Choice,
        nowMs: Long,
        pageSize: UInt = PAGE,
    ): Long {
        val from = choice.range.millis?.let { nowMs - it } ?: 0L
        // The end is exclusive: what happened in this very millisecond is included.
        val to = nowMs + 1
        var after: Long? = null
        var written = 0L
        do {
            val page = history.exportPage(choice.kind, choice.format, from, to, after, pageSize)
            val bytes = page.text.toByteArray(Charsets.UTF_8)
            out.write(bytes)
            written += bytes.size
            after = page.next
        } while (after != null)
        out.flush()
        return written
    }
}

/** The export screen, with Android's document picker for where the file goes. */
@Composable
fun ExportScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val state by HistoryExport.states.collectAsState()
    var kind by rememberSaveable { mutableStateOf(ExportKind.FLOWS) }
    var format by rememberSaveable { mutableStateOf(ExportFormat.CSV) }
    var range by rememberSaveable { mutableStateOf(HistoryExport.Range.ALL) }
    val choice = HistoryExport.Choice(kind, format, range)
    // The choice cannot change while the picker is open, so it is the one to write.
    val created: (Uri?) -> Unit = { uri -> if (uri != null) HistoryExport.save(context, uri, choice) }
    val json = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(HistoryExport.mimeType(ExportFormat.JSON)), created,
    )
    val csv = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(HistoryExport.mimeType(ExportFormat.CSV)), created,
    )
    ExportContent(
        choice = choice,
        state = state,
        onChoice = {
            kind = it.kind
            format = it.format
            range = it.range
        },
        onBack = onBack,
        onSave = {
            val name = HistoryExport.fileName(choice, LocalDate.now())
            when (choice.format) {
                ExportFormat.JSON -> json.launch(name)
                ExportFormat.CSV -> csv.launch(name)
            }
        },
    )
}

/** The screen's content: what to export, the warning, and how the last export went. */
@Composable
fun ExportContent(
    choice: HistoryExport.Choice,
    state: HistoryExport.State,
    onChoice: (HistoryExport.Choice) -> Unit,
    onBack: () -> Unit,
    onSave: () -> Unit,
) {
    val context = LocalContext.current
    var warning by remember { mutableStateOf(false) }
    if (warning) {
        AlertDialog(
            onDismissRequest = { warning = false },
            title = { Text(stringResource(R.string.export_warning_title)) },
            text = { Text(stringResource(R.string.export_warning_text)) },
            confirmButton = {
                TextButton(onClick = {
                    warning = false
                    onSave()
                }) { Text(stringResource(R.string.export_warning_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { warning = false }) {
                    Text(stringResource(R.string.export_warning_cancel))
                }
            },
        )
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
        Text(stringResource(R.string.export_title), style = MaterialTheme.typography.headlineSmall)
        Text(stringResource(R.string.export_explainer), style = MaterialTheme.typography.bodyMedium)
        Options(
            R.string.export_what,
            ExportKind.entries,
            choice.kind,
            name = ::kindName,
            onPick = { onChoice(choice.copy(kind = it)) },
        )
        Options(
            R.string.export_range,
            HistoryExport.Range.entries,
            choice.range,
            name = ::rangeName,
            onPick = { onChoice(choice.copy(range = it)) },
        )
        Text(stringResource(R.string.export_range_note), style = MaterialTheme.typography.bodySmall)
        Options(
            R.string.export_format,
            ExportFormat.entries,
            choice.format,
            name = ::formatName,
            onPick = { onChoice(choice.copy(format = it)) },
        )
        Button(onClick = { warning = true }, enabled = state != HistoryExport.State.Saving) {
            Text(stringResource(R.string.export_action))
        }
        when (state) {
            HistoryExport.State.Idle -> {}
            HistoryExport.State.Saving -> Text(stringResource(R.string.export_saving))
            is HistoryExport.State.Saved -> Text(
                stringResource(
                    R.string.export_saved,
                    isolate(Formatter.formatShortFileSize(context, state.bytes)),
                ),
            )
            HistoryExport.State.Failed -> Text(stringResource(R.string.export_failed))
        }
    }
}

/** A choice of one of [options], under [title]. */
@Composable
private fun <T> Options(title: Int, options: List<T>, selected: T, name: (T) -> Int, onPick: (T) -> Unit) {
    Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
    Column(Modifier.selectableGroup(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        options.forEach { option ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .selectable(
                        selected = option == selected,
                        role = Role.RadioButton,
                        onClick = { onPick(option) },
                    )
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = option == selected, onClick = null)
                Text(
                    stringResource(name(option)),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(start = 12.dp),
                )
            }
        }
    }
}

private fun kindName(kind: ExportKind): Int = when (kind) {
    ExportKind.FLOWS -> R.string.export_kind_flows
    ExportKind.ALERTS -> R.string.export_kind_alerts
    ExportKind.ACTIONS -> R.string.export_kind_actions
}

private fun rangeName(range: HistoryExport.Range): Int = when (range) {
    HistoryExport.Range.DAY -> R.string.export_range_day
    HistoryExport.Range.WEEK -> R.string.export_range_week
    HistoryExport.Range.ALL -> R.string.export_range_all
}

private fun formatName(format: ExportFormat): Int = when (format) {
    ExportFormat.JSON -> R.string.export_format_json
    ExportFormat.CSV -> R.string.export_format_csv
}
