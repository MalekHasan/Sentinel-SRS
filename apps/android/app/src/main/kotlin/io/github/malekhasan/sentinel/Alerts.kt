// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.icu.text.ListFormatter
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertFeedback
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.IndicatorSighting
import io.github.malekhasan.sentinel.core.IndicatorThreat
import java.text.DateFormat
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.time.format.FormatStyle
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

    suspend fun load() = withContext(Dispatchers.IO) {
        try {
            History.get(context).alert(id)?.let { alert ->
                AlertDetails(alert, appsIn(alert).associateWith(names::labelFor))
            }
        } catch (e: Exception) {
            Log.w(TAG, "the alert cannot be read", e)
            null
        }
    }
    LaunchedEffect(id) { details = load() }
    AlertDetail(
        details = details,
        onBack = onBack,
        onAction = onAction,
        onFeedback = { feedback ->
            scope.launch {
                withContext(Dispatchers.IO) {
                    runCatching { History.get(context).setFeedback(id, feedback) }
                        .onFailure { Log.w(TAG, "the feedback cannot be saved", it) }
                }
                details = load()
            }
        },
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
        alert.actions.filterIsInstance<AlertAction.OpenApp>().map { it.app } +
        alert.actions.filterIsInstance<AlertAction.AllowApp>().map { it.app } +
        alert.actions.filterIsInstance<AlertAction.BlockApp>().map { it.app }

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
    onFeedback: (AlertFeedback?) -> Unit = {},
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
        Feedback(alert, onFeedback)
    }
}

/**
 * What the user thinks of the alert (AL-05): not useful, or fine to allow from now on,
 * and how to take it back. A Critical alert cannot be allowed (ADR-0012).
 */
@Composable
private fun Feedback(alert: HistoryAlert, onFeedback: (AlertFeedback?) -> Unit) {
    Text(stringResource(R.string.alert_feedback_title), style = MaterialTheme.typography.titleSmall)
    when (alert.feedback) {
        null -> {
            OutlinedButton(onClick = { onFeedback(AlertFeedback.NOT_USEFUL) }) {
                Text(stringResource(R.string.alert_feedback_not_useful))
            }
            if (alert.severity != AlertSeverity.CRITICAL) {
                OutlinedButton(onClick = { onFeedback(AlertFeedback.ALLOWED) }) {
                    Text(stringResource(R.string.alert_feedback_allow))
                }
            }
        }
        AlertFeedback.NOT_USEFUL -> {
            Text(stringResource(R.string.alert_feedback_was_not_useful), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = { onFeedback(null) }) { Text(stringResource(R.string.alert_feedback_undo)) }
        }
        AlertFeedback.ALLOWED -> {
            Text(stringResource(R.string.alert_feedback_was_allowed), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = { onFeedback(null) }) { Text(stringResource(R.string.alert_feedback_undo)) }
        }
    }
    Text(stringResource(R.string.alert_feedback_note), style = MaterialTheme.typography.bodySmall)
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
fun alertTitle(alert: HistoryAlert): String = stringResource(titleRes(alert))

/** The alert's one-sentence explanation in the screen's language (AL-02). */
@Composable
fun alertExplanation(alert: HistoryAlert): String = stringResource(explanationRes(alert))

/** Whether Block-unknown kept the app the alert is about off the network (CM-08). */
private fun HistoryAlert.blocked(): Boolean = evidence.any { it is AlertEvidence.NewAppBlocked }

/** The alert's title: its rule's, or a blocked new app's. */
fun titleRes(alert: HistoryAlert): Int =
    if (alert.rule == AlertRule.FIRST_NETWORK_USE && alert.blocked()) {
        R.string.alert_first_network_use_blocked_title
    } else {
        titleRes(alert.rule)
    }

/** The alert's explanation: its rule's, or a blocked new app's. */
fun explanationRes(alert: HistoryAlert): Int =
    if (alert.rule == AlertRule.FIRST_NETWORK_USE && alert.blocked()) {
        R.string.alert_first_network_use_blocked_text
    } else {
        explanationRes(alert.rule)
    }

fun titleRes(rule: AlertRule): Int = when (rule) {
    AlertRule.MONITORING_INTERRUPTED -> R.string.alert_monitoring_interrupted_title
    AlertRule.FIRST_NETWORK_USE -> R.string.alert_first_network_use_title
    AlertRule.NEW_DESTINATION -> R.string.alert_new_destination_title
    AlertRule.DNS_SERVERS_CHANGED -> R.string.alert_dns_servers_changed_title
    AlertRule.PRIVATE_DNS_CHANGED -> R.string.alert_private_dns_changed_title
    AlertRule.PROXY_CHANGED -> R.string.alert_proxy_changed_title
    AlertRule.KNOWN_INDICATOR -> R.string.alert_known_indicator_title
}

fun explanationRes(rule: AlertRule): Int = when (rule) {
    AlertRule.MONITORING_INTERRUPTED -> R.string.alert_monitoring_interrupted_text
    AlertRule.FIRST_NETWORK_USE -> R.string.alert_first_network_use_text
    AlertRule.NEW_DESTINATION -> R.string.alert_new_destination_text
    AlertRule.DNS_SERVERS_CHANGED -> R.string.alert_dns_servers_changed_text
    AlertRule.PRIVATE_DNS_CHANGED -> R.string.alert_private_dns_changed_text
    AlertRule.PROXY_CHANGED -> R.string.alert_proxy_changed_text
    AlertRule.KNOWN_INDICATOR -> R.string.alert_known_indicator_text
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
        is AlertEvidence.Destinations -> {
            val listed = ListFormatter.getInstance(LocalConfiguration.current.locales[0])
                .format(evidence.destinations.map(::isolate))
            val more = evidence.more.toInt()
            listOfNotNull(
                stringResource(R.string.alert_evidence_destinations, listed),
                if (more > 0) pluralStringResource(R.plurals.alert_evidence_more_destinations, more, more) else null,
            ).joinToString(" ")
        }
        is AlertEvidence.DnsServers -> stringResource(
            R.string.alert_evidence_dns_servers, settingValue(evidence.before), settingValue(evidence.after),
        )
        is AlertEvidence.PrivateDns -> stringResource(
            R.string.alert_evidence_private_dns,
            settingValue(listOfNotNull(evidence.before)),
            settingValue(listOfNotNull(evidence.after)),
        )
        is AlertEvidence.Proxy -> stringResource(
            R.string.alert_evidence_proxy,
            settingValue(listOfNotNull(evidence.before)),
            settingValue(listOfNotNull(evidence.after)),
        )
        is AlertEvidence.NewAppBlocked -> stringResource(R.string.alert_evidence_new_app_blocked)
        is AlertEvidence.Indicator -> listOf(
            stringResource(
                when (evidence.sighting) {
                    IndicatorSighting.DNS_QUERY -> R.string.alert_evidence_indicator_dns
                    IndicatorSighting.SERVER_NAME -> R.string.alert_evidence_indicator_tls
                    IndicatorSighting.ADDRESS -> R.string.alert_evidence_indicator_address
                },
                isolate(evidence.seen),
            ),
            stringResource(
                R.string.alert_evidence_indicator_listed,
                isolate(evidence.indicator),
                isolate(evidence.family),
                stringResource(
                    when (evidence.threat) {
                        IndicatorThreat.SPYWARE -> R.string.alert_threat_spyware
                        IndicatorThreat.STALKERWARE -> R.string.alert_threat_stalkerware
                    },
                ),
            ),
            stringResource(
                R.string.alert_evidence_indicator_source,
                isolate(evidence.source),
                reportDate(evidence.date),
                isolate(evidence.report),
            ),
        ).joinToString(" ")
    }

/** A report's date, `YYYY-MM-DD` in the indicator list, as the user's language writes it. */
@Composable
private fun reportDate(date: String): String {
    val locale = LocalConfiguration.current.locales[0]
    return try {
        LocalDate.parse(date).format(DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(locale))
    } catch (e: DateTimeParseException) {
        isolate(date)
    }
}

/** A network setting's values as written, each kept left to right, or "none". */
@Composable
private fun settingValue(values: List<String>): String =
    if (values.isEmpty()) {
        stringResource(R.string.alert_setting_none)
    } else {
        ListFormatter.getInstance(LocalConfiguration.current.locales[0]).format(values.map(::isolate))
    }

@Composable
private fun actionLabel(action: AlertAction, label: (String) -> String): String =
    when (action) {
        is AlertAction.StartMonitoring -> stringResource(R.string.alert_action_start_monitoring)
        is AlertAction.OpenApp -> stringResource(R.string.alert_action_open_app, isolate(label(action.app)))
        is AlertAction.OpenNetworkSettings -> stringResource(R.string.alert_action_open_network_settings)
        is AlertAction.AllowApp -> stringResource(R.string.alert_action_allow_app, isolate(label(action.app)))
        is AlertAction.BlockApp -> stringResource(R.string.alert_action_block_app, isolate(label(action.app)))
    }
