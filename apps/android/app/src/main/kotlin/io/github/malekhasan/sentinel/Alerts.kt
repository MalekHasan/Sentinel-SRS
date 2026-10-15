// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.text.format.DateUtils
import android.util.Log
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.HistoryAlert
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "SentinelAlerts"

/** Test tag of the alert detail screen. */
const val ALERT_DETAIL_TAG = "alert-detail"

/** Test tag of a severity badge. */
fun severityTag(severity: AlertSeverity): String = "severity-${severity.name}"

/** An alert and the names of the apps it mentions. */
data class AlertDetails(val alert: HistoryAlert, val appLabels: Map<String, String>)

/** The most recent open alerts, newest first, or none if the history cannot be read. */
fun openAlerts(context: Context, limit: UInt): List<HistoryAlert> =
    try {
        History.get(context).alerts(true, limit)
    } catch (e: Exception) {
        Log.w(TAG, "the alerts cannot be read", e)
        emptyList()
    }

/** One alert, loaded from the history, with the names of its apps (AL-02). */
@Composable
fun AlertDetailScreen(id: Long, onBack: () -> Unit, onAction: (AlertAction) -> Unit) {
    val context = LocalContext.current
    val names = remember(context) { AppNames(context) }
    val scope = rememberCoroutineScope()
    var details by remember(id) { mutableStateOf<AlertDetails?>(null) }

    LaunchedEffect(id) {
        details = withContext(Dispatchers.IO) {
            try {
                History.get(context).alert(id)?.let { alert ->
                    AlertDetails(alert, appsIn(alert).associateWith(names::labelFor))
                }
            } catch (e: Exception) {
                Log.w(TAG, "the alert cannot be read", e)
                null
            }
        }
    }
    AlertDetail(
        details = details,
        onBack = onBack,
        onAction = onAction,
        onDismiss = {
            scope.launch {
                withContext(Dispatchers.IO) {
                    runCatching { History.get(context).dismissAlert(id) }
                        .onFailure { Log.w(TAG, "the alert cannot be dismissed", it) }
                }
                onBack()
            }
        },
    )
}

private fun appsIn(alert: HistoryAlert): List<String> =
    alert.evidence.filterIsInstance<AlertEvidence.App>().map { it.app } +
        alert.actions.filterIsInstance<AlertAction.OpenApp>().map { it.app }

/**
 * An alert in the order AL-02 asks for: how severe it is, a plain title and a
 * one-sentence explanation, then the evidence, then what the user can do.
 */
@Composable
fun AlertDetail(
    details: AlertDetails?,
    onBack: () -> Unit,
    onAction: (AlertAction) -> Unit,
    onDismiss: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp)
            .testTag(ALERT_DETAIL_TAG),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
        if (details == null) return@Column
        val alert = details.alert
        val label = { app: String -> details.appLabels[app] ?: app }
        SeverityBadge(alert.severity)
        Text(alertTitle(alert), style = MaterialTheme.typography.headlineSmall)
        Text(alertExplanation(alert), style = MaterialTheme.typography.bodyLarge)
        Text(raisedWhen(alert), style = MaterialTheme.typography.bodySmall)

        Text(stringResource(R.string.alert_evidence_title), style = MaterialTheme.typography.titleSmall)
        alert.evidence.forEach { evidence ->
            Text(describeEvidence(evidence, label), style = MaterialTheme.typography.bodyMedium)
        }

        if (alert.actions.isNotEmpty()) {
            Text(stringResource(R.string.alert_actions_title), style = MaterialTheme.typography.titleSmall)
            alert.actions.forEach { action ->
                Button(onClick = { onAction(action) }) { Text(actionLabel(action, label)) }
            }
        }
        if (alert.open) {
            OutlinedButton(onClick = onDismiss) { Text(stringResource(R.string.alert_dismiss)) }
        } else {
            Text(stringResource(R.string.alert_dismissed), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** One alert in a list: its severity, title and when it was raised. */
@Composable
fun AlertRow(alert: HistoryAlert, onOpen: (Long) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onOpen(alert.id) },
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        SeverityBadge(alert.severity)
        Text(alertTitle(alert), style = MaterialTheme.typography.titleSmall)
        Text(raisedWhen(alert), style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * How severe an alert is (AL-01): its name on a colour of its own, so the four never
 * look alike and never rely on colour alone.
 */
@Composable
fun SeverityBadge(severity: AlertSeverity) {
    val (container, content) = severityColors(severity)
    Surface(
        color = container,
        contentColor = content,
        shape = MaterialTheme.shapes.small,
        modifier = Modifier.testTag(severityTag(severity)),
    ) {
        Text(
            severityName(severity),
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
        )
    }
}

@Composable
private fun severityColors(severity: AlertSeverity): Pair<Color, Color> =
    with(MaterialTheme.colorScheme) {
        when (severity) {
            AlertSeverity.INFO -> secondaryContainer to onSecondaryContainer
            AlertSeverity.WARNING -> tertiaryContainer to onTertiaryContainer
            AlertSeverity.HIGH -> errorContainer to onErrorContainer
            AlertSeverity.CRITICAL -> error to onError
        }
    }

@Composable
private fun severityName(severity: AlertSeverity): String = stringResource(severityNameRes(severity))

fun severityNameRes(severity: AlertSeverity): Int = when (severity) {
    AlertSeverity.INFO -> R.string.severity_info
    AlertSeverity.WARNING -> R.string.severity_warning
    AlertSeverity.HIGH -> R.string.severity_high
    AlertSeverity.CRITICAL -> R.string.severity_critical
}

/** The alert's title in the screen's language (AL-02). */
@Composable
fun alertTitle(alert: HistoryAlert): String = stringResource(titleRes(alert.rule))

/** The alert's one-sentence explanation in the screen's language (AL-02). */
@Composable
fun alertExplanation(alert: HistoryAlert): String = stringResource(explanationRes(alert.rule))

fun titleRes(rule: AlertRule): Int = when (rule) {
    AlertRule.MONITORING_INTERRUPTED -> R.string.alert_monitoring_interrupted_title
}

fun explanationRes(rule: AlertRule): Int = when (rule) {
    AlertRule.MONITORING_INTERRUPTED -> R.string.alert_monitoring_interrupted_text
}

@Composable
private fun raisedWhen(alert: HistoryAlert): String =
    DateUtils.getRelativeTimeSpanString(
        alert.createdMs, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS,
    ).toString()

@Composable
private fun describeEvidence(evidence: AlertEvidence, label: (String) -> String): String =
    when (evidence) {
        is AlertEvidence.Gap -> {
            val format = DateFormat.getDateTimeInstance(
                DateFormat.SHORT, DateFormat.SHORT, LocalConfiguration.current.locales[0],
            )
            val start = evidence.startedMs?.let { format.format(Date(it)) }
                ?: stringResource(R.string.gap_time_unknown)
            stringResource(R.string.alert_evidence_gap, start, isolate(evidence.reason))
        }
        is AlertEvidence.App -> stringResource(R.string.alert_evidence_app, isolate(label(evidence.app)))
    }

@Composable
private fun actionLabel(action: AlertAction, label: (String) -> String): String =
    when (action) {
        is AlertAction.StartMonitoring -> stringResource(R.string.alert_action_start_monitoring)
        is AlertAction.OpenApp -> stringResource(R.string.alert_action_open_app, isolate(label(action.app)))
    }
